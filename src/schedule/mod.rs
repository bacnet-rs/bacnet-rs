//! Schedule engine.
//!
//! Schedule objects decide *what* they command at a given moment (see
//! [`Schedule::value_at`]); this module decides *when* to ask, refreshes the
//! Calendar objects their exceptions point at, and pushes the result to the
//! objects each schedule drives.
//!
//! Calendars are refreshed first, so a schedule evaluated later in the same
//! tick sees today's answer rather than yesterday's.
//!
//! Like [`EventEngine`](crate::event::EventEngine), the engine takes the date
//! and time as arguments rather than reading a clock, which keeps the
//! resolution rules testable and leaves the caller owning its time source.

use crate::object::{
    database::ObjectDatabase, schedule::Schedule, ObjectIdentifier, ObjectType, PropertyValue,
};
use crate::property::ObjectPropertyReference;

use std::collections::HashSet;

/// One write a schedule issued to a target.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduledWrite {
    /// The schedule that issued it.
    pub schedule: ObjectIdentifier,
    /// The property it was written to.
    pub target: ObjectPropertyReference,
    /// The value written.
    pub value: PropertyValue,
    /// The command priority used.
    pub priority: u8,
    /// Whether the hosted database accepted the write. A schedule may name a
    /// property on another device, which only the caller can reach.
    pub applied: bool,
}

/// Drives every Schedule object in a database.
#[derive(Debug, Default)]
pub struct ScheduleEngine {
    /// Schedules that have written to their targets at least once.
    ///
    /// Without this a schedule whose stored Present_Value already matches what
    /// the first tick computes would never write, leaving its targets at
    /// whatever they held at startup.
    primed: HashSet<ObjectIdentifier>,
}

impl ScheduleEngine {
    /// Create an engine that has driven nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Refresh every Calendar, then evaluate every Schedule and write to the
    /// targets of those whose value changed.
    ///
    /// `date` is (year, month, day, weekday) with weekday 1 for Monday; `time`
    /// is (hour, minute, second, hundredths).
    pub fn tick(
        &mut self,
        database: &ObjectDatabase,
        date: (u16, u8, u8, u8),
        time: (u8, u8, u8, u8),
    ) -> Vec<ScheduledWrite> {
        let active_calendars = refresh_calendars(database, date);

        database
            .get_objects_by_type(ObjectType::Schedule)
            .into_iter()
            .flat_map(|identifier| {
                self.evaluate_schedule(database, identifier, date, time, &active_calendars)
            })
            .collect()
    }

    /// Evaluate one schedule, committing and distributing a new value.
    ///
    /// The schedule's lock is released before the targets are written, so a
    /// schedule driving another object cannot deadlock against it.
    fn evaluate_schedule(
        &mut self,
        database: &ObjectDatabase,
        identifier: ObjectIdentifier,
        date: (u16, u8, u8, u8),
        time: (u8, u8, u8, u8),
        active_calendars: &HashSet<ObjectIdentifier>,
    ) -> Vec<ScheduledWrite> {
        let first_tick = !self.primed.contains(&identifier);

        let committed = database
            .with_object_mut(identifier, |object| {
                let schedule: &mut Schedule = object.schedule_mut()?;
                if schedule.out_of_service {
                    return None;
                }

                let value =
                    schedule.value_at(date, time, &|calendar| active_calendars.contains(&calendar));
                if value == schedule.present_value && !first_tick {
                    return None;
                }
                schedule.present_value = value.clone();

                Some((
                    value,
                    schedule.list_of_object_property_references.clone(),
                    schedule.priority_for_writing,
                ))
            })
            .flatten();

        let Some((value, targets, priority)) = committed else {
            return Vec::new();
        };
        self.primed.insert(identifier);

        targets
            .into_iter()
            .map(|target| {
                let applied = database
                    .set_property_with_priority(
                        target.object_identifier,
                        target.property_identifier,
                        value.clone(),
                        Some(priority),
                    )
                    .is_ok();
                ScheduledWrite {
                    schedule: identifier,
                    target,
                    value: value.clone(),
                    priority,
                    applied,
                }
            })
            .collect()
    }
}

/// Recompute every Calendar's Present_Value, returning those covering `date`.
fn refresh_calendars(
    database: &ObjectDatabase,
    date: (u16, u8, u8, u8),
) -> HashSet<ObjectIdentifier> {
    database
        .get_objects_by_type(ObjectType::Calendar)
        .into_iter()
        .filter(|identifier| {
            database
                .with_object_mut(*identifier, |object| {
                    object.calendar_mut().is_some_and(|calendar| {
                        calendar.refresh(date);
                        calendar.present_value
                    })
                })
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{AnalogValue, Calendar, Device, PropertyIdentifier, Reliability, Schedule};
    use crate::property::{
        CalendarEntryValue, DailyScheduleValue, DateRangeValue, SpecialEventPeriod,
        SpecialEventValue, TimeValueValue, ANY, UNSPECIFIED_YEAR,
    };
    use std::sync::Arc;

    /// 2026-07-30 is a Thursday, BACnet weekday 4.
    const THURSDAY: (u16, u8, u8, u8) = (2026, 7, 30, 4);
    /// 2026-08-01 is a Saturday, BACnet weekday 6.
    const SATURDAY: (u16, u8, u8, u8) = (2026, 8, 1, 6);

    const SETPOINT: u32 = 1;
    const SCHEDULE: u32 = 1;
    const CALENDAR: u32 = 1;

    fn setpoint() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::AnalogValue, SETPOINT)
    }

    fn schedule_id() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::Schedule, SCHEDULE)
    }

    fn calendar_id() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::Calendar, CALENDAR)
    }

    fn time_value(hour: u8, value: f32) -> TimeValueValue {
        TimeValueValue {
            time: (hour, 0, 0, 0),
            value: Box::new(PropertyValue::Real(value)),
        }
    }

    /// Weekdays run 21 from 06:00 and 18 from 18:00; the weekend is bare, so it
    /// falls back to the 16 degree default.
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

        Schedule::new(SCHEDULE, "Office hours".to_string())
            .with_default(PropertyValue::Real(16.0))
            .with_weekly_schedule(days)
            .with_target(setpoint(), PropertyIdentifier::PresentValue)
    }

    fn database_with(schedule: Schedule) -> Arc<ObjectDatabase> {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        let mut value = AnalogValue::new(SETPOINT, "Zone setpoint".to_string());
        value.present_value = 0.0;
        database.add_object(Box::new(value)).unwrap();
        database.add_object(Box::new(schedule)).unwrap();
        database
    }

    fn present_value(database: &ObjectDatabase, identifier: ObjectIdentifier) -> PropertyValue {
        database
            .get_property(identifier, PropertyIdentifier::PresentValue)
            .unwrap()
    }

    #[test]
    fn the_first_tick_primes_the_target_even_when_the_value_is_unchanged() {
        let database = database_with(office_hours());
        let mut engine = ScheduleEngine::new();

        // 05:00 on a weekday resolves to the default, which the schedule
        // already reports; the target has never heard it.
        let writes = engine.tick(&database, THURSDAY, (5, 0, 0, 0));

        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].value, PropertyValue::Real(16.0));
        assert!(writes[0].applied);
        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(16.0)
        );
    }

    #[test]
    fn an_unchanged_value_writes_nothing_after_the_first_tick() {
        let database = database_with(office_hours());
        let mut engine = ScheduleEngine::new();

        assert_eq!(engine.tick(&database, THURSDAY, (7, 0, 0, 0)).len(), 1);
        assert!(engine.tick(&database, THURSDAY, (8, 0, 0, 0)).is_empty());
        assert!(engine.tick(&database, THURSDAY, (17, 59, 0, 0)).is_empty());
    }

    #[test]
    fn crossing_a_time_value_writes_the_new_value_to_the_target() {
        let database = database_with(office_hours());
        let mut engine = ScheduleEngine::new();

        engine.tick(&database, THURSDAY, (7, 0, 0, 0));
        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(21.0)
        );

        let writes = engine.tick(&database, THURSDAY, (18, 0, 0, 0));

        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].value, PropertyValue::Real(18.0));
        assert_eq!(writes[0].priority, 16);
        assert_eq!(writes[0].target.object_identifier, setpoint());
        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(18.0)
        );
        assert_eq!(
            present_value(&database, schedule_id()),
            PropertyValue::Real(18.0),
            "the schedule reports what it commands"
        );
    }

    #[test]
    fn a_bare_weekend_falls_back_to_the_default() {
        let database = database_with(office_hours());
        let mut engine = ScheduleEngine::new();

        engine.tick(&database, THURSDAY, (12, 0, 0, 0));
        engine.tick(&database, SATURDAY, (12, 0, 0, 0));

        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(16.0)
        );
    }

    #[test]
    fn the_configured_priority_reaches_the_target() {
        let database = database_with(office_hours().with_priority_for_writing(8));
        let mut engine = ScheduleEngine::new();

        let writes = engine.tick(&database, THURSDAY, (7, 0, 0, 0));

        assert_eq!(writes[0].priority, 8);
        // Priority 8 leaves 1-7 free to override the schedule.
        database
            .set_property_with_priority(
                setpoint(),
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(30.0),
                Some(4),
            )
            .unwrap();
        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(30.0)
        );
    }

    #[test]
    fn a_calendar_reference_is_resolved_from_the_database() {
        let holiday = office_hours().with_exception(SpecialEventValue {
            period: SpecialEventPeriod::CalendarReference(calendar_id()),
            time_values: vec![time_value(0, 10.0)],
            priority: 8,
        });
        let database = database_with(holiday);
        database
            .add_object(Box::new(
                Calendar::new(CALENDAR, "Holidays".to_string()).with_entry(
                    CalendarEntryValue::DateRange(DateRangeValue {
                        start: (2026, 7, 6, ANY),
                        end: (2026, 7, 31, ANY),
                    }),
                ),
            ))
            .unwrap();
        let mut engine = ScheduleEngine::new();

        engine.tick(&database, THURSDAY, (12, 0, 0, 0));

        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(10.0),
            "30 July is inside the shutdown"
        );
        assert_eq!(
            present_value(&database, calendar_id()),
            PropertyValue::Boolean(true),
            "the calendar was refreshed before the schedule was evaluated"
        );

        // A date outside the shutdown falls back to the weekly schedule.
        engine.tick(&database, (2026, 8, 6, 4), (12, 0, 0, 0));
        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(21.0)
        );
        assert_eq!(
            present_value(&database, calendar_id()),
            PropertyValue::Boolean(false)
        );
    }

    #[test]
    fn an_inline_exception_overrides_the_weekly_schedule() {
        let database = database_with(office_hours().with_exception(SpecialEventValue {
            period: SpecialEventPeriod::CalendarEntry(CalendarEntryValue::Date(
                UNSPECIFIED_YEAR,
                7,
                30,
                ANY,
            )),
            time_values: Vec::new(),
            priority: 8,
        }));
        let mut engine = ScheduleEngine::new();

        engine.tick(&database, THURSDAY, (12, 0, 0, 0));

        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(16.0),
            "an empty exception means nothing is scheduled today"
        );
    }

    #[test]
    fn an_out_of_service_schedule_stops_driving_its_target() {
        let database = database_with(office_hours());
        let mut engine = ScheduleEngine::new();
        engine.tick(&database, THURSDAY, (7, 0, 0, 0));

        database
            .set_property(
                schedule_id(),
                PropertyIdentifier::OutOfService,
                PropertyValue::Boolean(true),
            )
            .unwrap();

        assert!(engine.tick(&database, THURSDAY, (18, 0, 0, 0)).is_empty());
        assert_eq!(
            present_value(&database, setpoint()),
            PropertyValue::Real(21.0),
            "the target keeps what it was last told"
        );
    }

    #[test]
    fn a_target_the_database_does_not_hold_is_reported_unapplied() {
        let elsewhere = ObjectIdentifier::new(ObjectType::AnalogValue, 99);
        let database =
            database_with(office_hours().with_target(elsewhere, PropertyIdentifier::PresentValue));
        let mut engine = ScheduleEngine::new();

        let writes = engine.tick(&database, THURSDAY, (7, 0, 0, 0));

        assert_eq!(writes.len(), 2);
        assert!(writes[0].applied, "the local setpoint");
        assert!(!writes[1].applied, "the absent object");
    }

    #[test]
    fn objects_that_are_not_schedules_are_ignored() {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        database
            .add_object(Box::new(AnalogValue::new(SETPOINT, "Value".to_string())))
            .unwrap();
        let mut engine = ScheduleEngine::new();

        assert!(engine.tick(&database, THURSDAY, (12, 0, 0, 0)).is_empty());
    }

    #[test]
    fn a_faulted_schedule_still_reports_its_status_flags() {
        let database = database_with(office_hours());
        database
            .set_property(
                schedule_id(),
                PropertyIdentifier::Reliability,
                PropertyValue::Enumerated(u32::from(Reliability::ConfigurationError)),
            )
            .unwrap();

        assert_eq!(
            database
                .get_property(schedule_id(), PropertyIdentifier::StatusFlags)
                .unwrap(),
            PropertyValue::BitString(vec![false, true, false, false])
        );
    }
}
