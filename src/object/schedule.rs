//! Schedule object type.
//!
//! A schedule (ASHRAE 135 clause 12.24) commands a value that changes with the
//! time of day and the day of the week. Its `Present_Value` is whatever the
//! schedule says right now, and it writes that value to the objects listed in
//! `List_Of_Object_Property_References` at `Priority_For_Writing`.
//!
//! Three sources are consulted in order: an `Exception_Schedule` entry covering
//! today, then today's `Weekly_Schedule` day, then `Schedule_Default`. Outside
//! `Effective_Period` the schedule does nothing but report its default.
//!
//! The object does not read a clock or reach other objects; see
//! [`value_at`](Schedule::value_at) and the `schedule` module for that.

use crate::object::{
    BacnetObject, ObjectError, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
    Reliability, Result,
};
use crate::property::{
    DailyScheduleValue, DateRangeValue, ObjectPropertyReference, SpecialEventPeriod,
    SpecialEventValue, TimeValueValue, ANY, UNSPECIFIED_YEAR,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec, vec::Vec};

/// Days in a Weekly_Schedule, Monday first.
pub const DAYS_PER_WEEK: usize = 7;

/// The lowest BACnet command priority, used unless configured otherwise.
pub const DEFAULT_PRIORITY_FOR_WRITING: u8 = 16;

/// Schedule object.
#[derive(Debug, Clone, PartialEq)]
pub struct Schedule {
    /// Object identifier.
    pub identifier: ObjectIdentifier,
    /// Object name.
    pub object_name: String,
    /// Description.
    pub description: String,
    /// The value the schedule currently commands.
    pub present_value: PropertyValue,
    /// The value used when nothing else applies.
    pub schedule_default: PropertyValue,
    /// The span the schedule is active over.
    pub effective_period: DateRangeValue,
    /// One day of time/value pairs per weekday, Monday first.
    pub weekly_schedule: [DailyScheduleValue; DAYS_PER_WEEK],
    /// Dated overrides, highest priority (lowest number) first at evaluation.
    pub exception_schedule: Vec<SpecialEventValue>,
    /// Where `Present_Value` is written when it changes.
    pub list_of_object_property_references: Vec<ObjectPropertyReference>,
    /// The command priority used for those writes, 1-16.
    pub priority_for_writing: u8,
    /// Reliability of the schedule itself.
    pub reliability: Reliability,
    /// Whether the schedule is decoupled from its targets.
    pub out_of_service: bool,
}

/// A date range that is always in effect: both endpoints unspecified.
fn always() -> DateRangeValue {
    DateRangeValue {
        start: (UNSPECIFIED_YEAR, ANY, ANY, ANY),
        end: (UNSPECIFIED_YEAR, ANY, ANY, ANY),
    }
}

impl Schedule {
    /// Create a schedule that is always in effect, commands nothing, and drives
    /// no targets.
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::Schedule, instance),
            object_name,
            description: String::new(),
            present_value: PropertyValue::Null,
            schedule_default: PropertyValue::Null,
            effective_period: always(),
            weekly_schedule: core::array::from_fn(|_| DailyScheduleValue {
                time_values: Vec::new(),
            }),
            exception_schedule: Vec::new(),
            list_of_object_property_references: Vec::new(),
            priority_for_writing: DEFAULT_PRIORITY_FOR_WRITING,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
        }
    }

    /// Set the value used outside the weekly and exception schedules. The
    /// schedule starts out commanding it.
    pub fn with_default(mut self, value: PropertyValue) -> Self {
        self.present_value = value.clone();
        self.schedule_default = value;
        self
    }

    /// Set the description, which some clients require before they will accept
    /// a schedule object at all.
    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    /// Set all seven days at once, Monday first.
    pub fn with_weekly_schedule(mut self, days: [DailyScheduleValue; DAYS_PER_WEEK]) -> Self {
        self.weekly_schedule = days;
        self
    }

    /// Add a dated override.
    pub fn with_exception(mut self, event: SpecialEventValue) -> Self {
        self.exception_schedule.push(event);
        self
    }

    /// Narrow the span the schedule is active over.
    pub fn with_effective_period(mut self, period: DateRangeValue) -> Self {
        self.effective_period = period;
        self
    }

    /// Drive `property` of `object` from this schedule.
    pub fn with_target(mut self, object: ObjectIdentifier, property: PropertyIdentifier) -> Self {
        self.list_of_object_property_references
            .push(ObjectPropertyReference {
                object_identifier: object,
                property_identifier: property,
                array_index: None,
            });
        self
    }

    /// Set the command priority used when writing to targets.
    pub fn with_priority_for_writing(mut self, priority: u8) -> Self {
        self.priority_for_writing = priority;
        self
    }

    /// The value this schedule commands at `date` and `time`.
    ///
    /// `date` is (year, month, day, weekday) with weekday 1 for Monday.
    /// `calendar_covers` answers whether a referenced Calendar object includes
    /// the date; the schedule cannot reach other objects itself.
    pub fn value_at(
        &self,
        date: (u16, u8, u8, u8),
        time: (u8, u8, u8, u8),
        calendar_covers: &dyn Fn(ObjectIdentifier) -> bool,
    ) -> PropertyValue {
        if !self.effective_period.contains(date) {
            return self.schedule_default.clone();
        }

        let today = self
            .active_exception(date, calendar_covers)
            .map(|event| event.time_values.as_slice())
            .or_else(|| Some(self.weekday(date)?.time_values.as_slice()));

        today
            .and_then(|values| value_at_time(values, time))
            .unwrap_or_else(|| self.schedule_default.clone())
    }

    /// The exception covering `date`, or `None`. Lower `priority` wins; the
    /// first entry wins a tie, which is the order the schedule was written in.
    fn active_exception(
        &self,
        date: (u16, u8, u8, u8),
        calendar_covers: &dyn Fn(ObjectIdentifier) -> bool,
    ) -> Option<&SpecialEventValue> {
        self.exception_schedule
            .iter()
            .filter(|event| match &event.period {
                SpecialEventPeriod::CalendarEntry(entry) => entry.matches(date),
                SpecialEventPeriod::CalendarReference(calendar) => calendar_covers(*calendar),
            })
            .min_by_key(|event| event.priority)
    }

    /// Today's entry in the Weekly_Schedule, or `None` when the weekday is
    /// unspecified.
    fn weekday(&self, date: (u16, u8, u8, u8)) -> Option<&DailyScheduleValue> {
        let index = usize::from(date.3.checked_sub(1)?);
        self.weekly_schedule.get(index)
    }

    fn status_flags(&self) -> Vec<bool> {
        vec![
            false,
            self.reliability != Reliability::NoFaultDetected,
            false,
            self.out_of_service,
        ]
    }
}

/// The value of the latest time/value pair at or before `time`.
///
/// The list is nominally in ascending time order, but the latest matching entry
/// is taken rather than the last one, so an out-of-order list still resolves.
fn value_at_time(values: &[TimeValueValue], time: (u8, u8, u8, u8)) -> Option<PropertyValue> {
    values
        .iter()
        .filter(|entry| entry.time <= time)
        .max_by_key(|entry| entry.time)
        .map(|entry| (*entry.value).clone())
}

fn expect_string(value: PropertyValue) -> Result<String> {
    match value {
        PropertyValue::CharacterString(text) => Ok(text),
        _ => Err(ObjectError::InvalidPropertyType),
    }
}

impl BacnetObject for Schedule {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.clone()))
            }
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(u32::from(ObjectType::Schedule)))
            }
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            PropertyIdentifier::PresentValue => Ok(self.present_value.clone()),
            PropertyIdentifier::ScheduleDefault => Ok(self.schedule_default.clone()),
            PropertyIdentifier::EffectivePeriod => {
                Ok(PropertyValue::DateRange(self.effective_period))
            }
            PropertyIdentifier::WeeklySchedule => Ok(PropertyValue::Array(
                self.weekly_schedule
                    .iter()
                    .cloned()
                    .map(PropertyValue::DailySchedule)
                    .collect(),
            )),
            PropertyIdentifier::ExceptionSchedule => Ok(PropertyValue::Array(
                self.exception_schedule
                    .iter()
                    .cloned()
                    .map(PropertyValue::SpecialEvent)
                    .collect(),
            )),
            PropertyIdentifier::ListOfObjectPropertyReferences => Ok(PropertyValue::List(
                self.list_of_object_property_references
                    .iter()
                    .cloned()
                    .map(PropertyValue::ObjectPropertyReference)
                    .collect(),
            )),
            PropertyIdentifier::PriorityForWriting => {
                Ok(PropertyValue::Unsigned(self.priority_for_writing.into()))
            }
            PropertyIdentifier::StatusFlags => Ok(PropertyValue::BitString(self.status_flags())),
            PropertyIdentifier::Reliability => {
                Ok(PropertyValue::Enumerated(self.reliability.into()))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            _ => Err(ObjectError::UnknownProperty),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                self.object_name = expect_string(value)?;
                Ok(())
            }
            PropertyIdentifier::Description => {
                self.description = expect_string(value)?;
                Ok(())
            }
            // Writable only while decoupled, so an operator can park the
            // schedule on a value without the next tick overwriting it.
            PropertyIdentifier::PresentValue => {
                if !self.out_of_service {
                    return Err(ObjectError::WriteAccessDenied);
                }
                self.present_value = value;
                Ok(())
            }
            PropertyIdentifier::ScheduleDefault => {
                self.schedule_default = value;
                Ok(())
            }
            PropertyIdentifier::EffectivePeriod => match value {
                PropertyValue::DateRange(period) => {
                    self.effective_period = period;
                    Ok(())
                }
                // A client that sends the two dates as plain application values
                // means the same thing.
                PropertyValue::List(dates) | PropertyValue::Array(dates) => {
                    match dates.as_slice() {
                        [PropertyValue::Date(sy, sm, sd, sw), PropertyValue::Date(ey, em, ed, ew)] =>
                        {
                            self.effective_period = DateRangeValue {
                                start: (*sy, *sm, *sd, *sw),
                                end: (*ey, *em, *ed, *ew),
                            };
                            Ok(())
                        }
                        _ => Err(ObjectError::InvalidValue(
                            "Effective_Period must be two dates".to_string(),
                        )),
                    }
                }
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::WeeklySchedule => match value {
                PropertyValue::Array(days) | PropertyValue::List(days) => {
                    if days.len() != DAYS_PER_WEEK {
                        return Err(ObjectError::InvalidValue(
                            "Weekly_Schedule must have exactly 7 days".to_string(),
                        ));
                    }
                    let mut week: [DailyScheduleValue; DAYS_PER_WEEK] =
                        core::array::from_fn(|_| DailyScheduleValue {
                            time_values: Vec::new(),
                        });
                    for (slot, day) in week.iter_mut().zip(days) {
                        match day {
                            PropertyValue::DailySchedule(day) => *slot = day,
                            _ => return Err(ObjectError::InvalidPropertyType),
                        }
                    }
                    self.weekly_schedule = week;
                    Ok(())
                }
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::ExceptionSchedule => match value {
                PropertyValue::Array(events) | PropertyValue::List(events) => events
                    .into_iter()
                    .map(|event| match event {
                        PropertyValue::SpecialEvent(event) => Ok(event),
                        _ => Err(ObjectError::InvalidPropertyType),
                    })
                    .collect::<Result<Vec<SpecialEventValue>>>()
                    .map(|events| self.exception_schedule = events),
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::ListOfObjectPropertyReferences => match value {
                PropertyValue::List(references) | PropertyValue::Array(references) => references
                    .into_iter()
                    .map(|reference| match reference {
                        PropertyValue::ObjectPropertyReference(reference) => Ok(reference),
                        _ => Err(ObjectError::InvalidPropertyType),
                    })
                    .collect::<Result<Vec<ObjectPropertyReference>>>()
                    .map(|references| self.list_of_object_property_references = references),
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::PriorityForWriting => match value {
                PropertyValue::Unsigned(priority) if (1..=16).contains(&priority) => {
                    self.priority_for_writing = priority as u8;
                    Ok(())
                }
                PropertyValue::Unsigned(_) => Err(ObjectError::InvalidValue(
                    "Priority_For_Writing must be 1-16".to_string(),
                )),
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::OutOfService => match value {
                PropertyValue::Boolean(flag) => {
                    self.out_of_service = flag;
                    Ok(())
                }
                _ => Err(ObjectError::InvalidPropertyType),
            },
            // Writable so a simulated schedule can be driven into a fault state.
            PropertyIdentifier::Reliability => match value {
                PropertyValue::Enumerated(raw) => {
                    self.reliability = Reliability::from(raw);
                    Ok(())
                }
                _ => Err(ObjectError::InvalidPropertyType),
            },
            _ => Err(ObjectError::PropertyNotWritable),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        match property {
            PropertyIdentifier::PresentValue => self.out_of_service,
            PropertyIdentifier::ObjectName
            | PropertyIdentifier::Description
            | PropertyIdentifier::ScheduleDefault
            | PropertyIdentifier::EffectivePeriod
            | PropertyIdentifier::WeeklySchedule
            | PropertyIdentifier::ExceptionSchedule
            | PropertyIdentifier::ListOfObjectPropertyReferences
            | PropertyIdentifier::PriorityForWriting
            | PropertyIdentifier::OutOfService
            | PropertyIdentifier::Reliability => true,
            _ => false,
        }
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::Description,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::EffectivePeriod,
            PropertyIdentifier::WeeklySchedule,
            PropertyIdentifier::ExceptionSchedule,
            PropertyIdentifier::ScheduleDefault,
            PropertyIdentifier::ListOfObjectPropertyReferences,
            PropertyIdentifier::PriorityForWriting,
            PropertyIdentifier::StatusFlags,
            PropertyIdentifier::Reliability,
            PropertyIdentifier::OutOfService,
        ]
    }

    fn is_out_of_service(&self) -> bool {
        self.out_of_service
    }

    fn schedule_mut(&mut self) -> Option<&mut Schedule> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::CalendarEntryValue;

    /// 2026-07-30 is a Thursday, BACnet weekday 4.
    const THURSDAY: (u16, u8, u8, u8) = (2026, 7, 30, 4);
    /// 2026-08-01 is a Saturday, BACnet weekday 6.
    const SATURDAY: (u16, u8, u8, u8) = (2026, 8, 1, 6);

    fn never_a_calendar(_: ObjectIdentifier) -> bool {
        false
    }

    fn time_value(hour: u8, value: f32) -> TimeValueValue {
        TimeValueValue {
            time: (hour, 0, 0, 0),
            value: Box::new(PropertyValue::Real(value)),
        }
    }

    /// Weekdays run 21 degrees from 06:00 and 18 from 18:00; the weekend is bare.
    fn office_hours() -> Schedule {
        let weekday = DailyScheduleValue {
            time_values: vec![time_value(6, 21.0), time_value(18, 18.0)],
        };
        let empty = DailyScheduleValue {
            time_values: Vec::new(),
        };
        let days = core::array::from_fn(|day| {
            if day < 5 {
                weekday.clone()
            } else {
                empty.clone()
            }
        });

        Schedule::new(1, "Office hours".to_string())
            .with_description("Zone temperature setpoint schedule".to_string())
            .with_default(PropertyValue::Real(16.0))
            .with_weekly_schedule(days)
    }

    #[test]
    fn the_weekly_schedule_holds_a_value_until_the_next_entry() {
        let schedule = office_hours();

        assert_eq!(
            schedule.value_at(THURSDAY, (5, 59, 0, 0), &never_a_calendar),
            PropertyValue::Real(16.0),
            "before the first entry, the default applies"
        );
        assert_eq!(
            schedule.value_at(THURSDAY, (6, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(21.0)
        );
        assert_eq!(
            schedule.value_at(THURSDAY, (17, 59, 0, 0), &never_a_calendar),
            PropertyValue::Real(21.0)
        );
        assert_eq!(
            schedule.value_at(THURSDAY, (23, 59, 0, 0), &never_a_calendar),
            PropertyValue::Real(18.0)
        );
    }

    #[test]
    fn a_day_with_no_entries_falls_back_to_the_default() {
        let schedule = office_hours();

        assert_eq!(
            schedule.value_at(SATURDAY, (12, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(16.0)
        );
    }

    #[test]
    fn an_exception_overrides_the_weekly_schedule_for_that_day() {
        let schedule = office_hours().with_exception(SpecialEventValue {
            period: SpecialEventPeriod::CalendarEntry(CalendarEntryValue::Date(
                UNSPECIFIED_YEAR,
                7,
                30,
                ANY,
            )),
            time_values: vec![time_value(0, 15.0)],
            priority: 8,
        });

        assert_eq!(
            schedule.value_at(THURSDAY, (12, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(15.0)
        );
        assert_eq!(
            schedule.value_at((2026, 7, 29, 3), (12, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(21.0),
            "the day before is unaffected"
        );
    }

    #[test]
    fn the_lowest_numbered_exception_priority_wins() {
        let today = |priority, value| SpecialEventValue {
            period: SpecialEventPeriod::CalendarEntry(CalendarEntryValue::Date(
                UNSPECIFIED_YEAR,
                7,
                30,
                ANY,
            )),
            time_values: vec![time_value(0, value)],
            priority,
        };
        let schedule = office_hours()
            .with_exception(today(10, 15.0))
            .with_exception(today(3, 12.0))
            .with_exception(today(7, 14.0));

        assert_eq!(
            schedule.value_at(THURSDAY, (12, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(12.0)
        );
    }

    /// An exception with no time values means "nothing is scheduled today",
    /// which is how a holiday shuts the weekly profile off.
    #[test]
    fn an_empty_exception_suppresses_the_weekly_schedule() {
        let schedule = office_hours().with_exception(SpecialEventValue {
            period: SpecialEventPeriod::CalendarEntry(CalendarEntryValue::Date(
                UNSPECIFIED_YEAR,
                7,
                30,
                ANY,
            )),
            time_values: Vec::new(),
            priority: 8,
        });

        assert_eq!(
            schedule.value_at(THURSDAY, (12, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(16.0)
        );
    }

    #[test]
    fn an_exception_can_defer_to_a_calendar_object() {
        let holidays = ObjectIdentifier::new(ObjectType::Calendar, 1);
        let schedule = office_hours().with_exception(SpecialEventValue {
            period: SpecialEventPeriod::CalendarReference(holidays),
            time_values: vec![time_value(0, 10.0)],
            priority: 8,
        });

        assert_eq!(
            schedule.value_at(THURSDAY, (12, 0, 0, 0), &|calendar| calendar == holidays),
            PropertyValue::Real(10.0)
        );
        assert_eq!(
            schedule.value_at(THURSDAY, (12, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(21.0),
            "the calendar does not cover today"
        );
    }

    #[test]
    fn outside_the_effective_period_only_the_default_applies() {
        let schedule = office_hours().with_effective_period(DateRangeValue {
            start: (2026, 1, 1, ANY),
            end: (2026, 6, 30, ANY),
        });

        assert_eq!(
            schedule.value_at(THURSDAY, (12, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(16.0)
        );
        assert_eq!(
            schedule.value_at((2026, 6, 30, 2), (12, 0, 0, 0), &never_a_calendar),
            PropertyValue::Real(21.0),
            "the last effective day still runs"
        );
    }

    #[test]
    fn description_is_writable_and_read_back() {
        let mut schedule = Schedule::new(1, "S".to_string());
        assert!(schedule.is_property_writable(PropertyIdentifier::Description));

        schedule
            .set_property(
                PropertyIdentifier::Description,
                PropertyValue::CharacterString("Heating".to_string()),
            )
            .unwrap();

        assert_eq!(
            schedule
                .get_property(PropertyIdentifier::Description)
                .unwrap(),
            PropertyValue::CharacterString("Heating".to_string())
        );
    }

    #[test]
    fn present_value_is_writable_only_while_out_of_service() {
        let mut schedule = office_hours();
        assert!(!schedule.is_property_writable(PropertyIdentifier::PresentValue));
        assert!(matches!(
            schedule.set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(30.0)),
            Err(ObjectError::WriteAccessDenied)
        ));

        schedule
            .set_property(
                PropertyIdentifier::OutOfService,
                PropertyValue::Boolean(true),
            )
            .unwrap();

        assert!(schedule.is_property_writable(PropertyIdentifier::PresentValue));
        schedule
            .set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(30.0))
            .unwrap();
        assert_eq!(
            schedule
                .get_property(PropertyIdentifier::PresentValue)
                .unwrap(),
            PropertyValue::Real(30.0)
        );
    }

    #[test]
    fn the_weekly_schedule_round_trips_through_its_property() {
        let source = office_hours();
        let mut target = Schedule::new(2, "Copy".to_string());

        let week = source
            .get_property(PropertyIdentifier::WeeklySchedule)
            .unwrap();
        target
            .set_property(PropertyIdentifier::WeeklySchedule, week)
            .unwrap();

        assert_eq!(target.weekly_schedule, source.weekly_schedule);
    }

    #[test]
    fn a_weekly_schedule_of_the_wrong_length_is_rejected() {
        let mut schedule = Schedule::new(1, "S".to_string());

        assert!(matches!(
            schedule.set_property(
                PropertyIdentifier::WeeklySchedule,
                PropertyValue::Array(vec![PropertyValue::DailySchedule(DailyScheduleValue {
                    time_values: Vec::new(),
                })]),
            ),
            Err(ObjectError::InvalidValue(_))
        ));
    }

    #[test]
    fn priority_for_writing_stays_within_the_command_range() {
        let mut schedule = Schedule::new(1, "S".to_string());

        schedule
            .set_property(
                PropertyIdentifier::PriorityForWriting,
                PropertyValue::Unsigned(8),
            )
            .unwrap();
        assert_eq!(schedule.priority_for_writing, 8);

        assert!(matches!(
            schedule.set_property(
                PropertyIdentifier::PriorityForWriting,
                PropertyValue::Unsigned(17),
            ),
            Err(ObjectError::InvalidValue(_))
        ));
    }

    #[test]
    fn effective_period_also_accepts_two_plain_dates() {
        let mut schedule = Schedule::new(1, "S".to_string());

        schedule
            .set_property(
                PropertyIdentifier::EffectivePeriod,
                PropertyValue::List(vec![
                    PropertyValue::Date(2026, 1, 1, ANY),
                    PropertyValue::Date(2026, 12, 31, ANY),
                ]),
            )
            .unwrap();

        assert_eq!(
            schedule
                .get_property(PropertyIdentifier::EffectivePeriod)
                .unwrap(),
            PropertyValue::DateRange(DateRangeValue {
                start: (2026, 1, 1, ANY),
                end: (2026, 12, 31, ANY),
            })
        );
    }
}
