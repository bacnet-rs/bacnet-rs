//! Calendar object type.
//!
//! A calendar (ASHRAE 135 clause 12.6) is a named list of dates — holidays,
//! shutdown weeks, every last Friday of the month — that schedules point at
//! through a `calendarReference` special event, so several schedules can share
//! one list.
//!
//! `Present_Value` is true while today is in `Date_List`. The object does not
//! read a clock; [`covers`](Calendar::covers) answers for a supplied date and
//! [`refresh`](Calendar::refresh) commits the answer, which is what the
//! schedule engine calls each tick.

use crate::object::{
    BacnetObject, ObjectError, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
    Result,
};
use crate::property::CalendarEntryValue;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

/// Calendar object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Calendar {
    /// Object identifier.
    pub identifier: ObjectIdentifier,
    /// Object name.
    pub object_name: String,
    /// Description.
    pub description: String,
    /// The dates this calendar covers.
    pub date_list: Vec<CalendarEntryValue>,
    /// Whether the last refreshed date was one of them.
    pub present_value: bool,
}

impl Calendar {
    /// Create an empty calendar, which covers no date at all.
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::Calendar, instance),
            object_name,
            description: String::new(),
            date_list: Vec::new(),
            present_value: false,
        }
    }

    /// Set the description, which some clients require before they will accept
    /// a calendar object at all.
    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    /// Add a date, range or recurring pattern to the list.
    pub fn with_entry(mut self, entry: CalendarEntryValue) -> Self {
        self.date_list.push(entry);
        self
    }

    /// Whether any entry covers `date`, given as (year, month, day, weekday)
    /// with weekday 1 for Monday.
    pub fn covers(&self, date: (u16, u8, u8, u8)) -> bool {
        self.date_list.iter().any(|entry| entry.matches(date))
    }

    /// Recompute `Present_Value` for `date` and report whether it changed.
    pub fn refresh(&mut self, date: (u16, u8, u8, u8)) -> bool {
        let present_value = self.covers(date);
        let changed = present_value != self.present_value;
        self.present_value = present_value;
        changed
    }
}

impl BacnetObject for Calendar {
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
                Ok(PropertyValue::Enumerated(u32::from(ObjectType::Calendar)))
            }
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Boolean(self.present_value)),
            PropertyIdentifier::DateList => Ok(PropertyValue::List(
                self.date_list
                    .iter()
                    .copied()
                    .map(PropertyValue::CalendarEntry)
                    .collect(),
            )),
            _ => Err(ObjectError::UnknownProperty),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => match value {
                PropertyValue::CharacterString(name) => {
                    self.object_name = name;
                    Ok(())
                }
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::Description => match value {
                PropertyValue::CharacterString(text) => {
                    self.description = text;
                    Ok(())
                }
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::DateList => match value {
                PropertyValue::List(entries) | PropertyValue::Array(entries) => entries
                    .into_iter()
                    .map(|entry| match entry {
                        PropertyValue::CalendarEntry(entry) => Ok(entry),
                        // A bare date is the commonest thing an operator writes.
                        PropertyValue::Date(year, month, day, weekday) => {
                            Ok(CalendarEntryValue::Date(year, month, day, weekday))
                        }
                        _ => Err(ObjectError::InvalidPropertyType),
                    })
                    .collect::<Result<Vec<CalendarEntryValue>>>()
                    .map(|entries| self.date_list = entries),
                _ => Err(ObjectError::InvalidPropertyType),
            },
            _ => Err(ObjectError::PropertyNotWritable),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::Description
                | PropertyIdentifier::DateList
        )
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::Description,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::DateList,
        ]
    }

    fn calendar_mut(&mut self) -> Option<&mut Calendar> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::{DateRangeValue, ANY, UNSPECIFIED_YEAR};

    fn holidays() -> Calendar {
        Calendar::new(1, "Norwegian holidays".to_string())
            .with_description("Days the building runs unoccupied".to_string())
            // Christmas Eve, every year.
            .with_entry(CalendarEntryValue::Date(UNSPECIFIED_YEAR, 12, 24, ANY))
            // The summer shutdown.
            .with_entry(CalendarEntryValue::DateRange(DateRangeValue {
                start: (2026, 7, 6, ANY),
                end: (2026, 7, 26, ANY),
            }))
    }

    #[test]
    fn a_date_inside_any_entry_is_covered() {
        let calendar = holidays();

        assert!(calendar.covers((2026, 12, 24, 4)));
        assert!(calendar.covers((2030, 12, 24, 2)), "wildcard year");
        assert!(calendar.covers((2026, 7, 6, 1)), "first shutdown day");
        assert!(calendar.covers((2026, 7, 26, 7)), "last shutdown day");
        assert!(!calendar.covers((2026, 7, 27, 1)));
        assert!(!calendar.covers((2026, 12, 25, 5)));
    }

    #[test]
    fn refresh_reports_only_the_transitions() {
        let mut calendar = holidays();
        assert!(!calendar.present_value);

        assert!(calendar.refresh((2026, 12, 24, 4)), "entered a holiday");
        assert!(calendar.present_value);
        assert!(!calendar.refresh((2026, 12, 24, 4)), "still the same day");

        assert!(calendar.refresh((2026, 12, 25, 5)), "left the holiday");
        assert!(!calendar.present_value);
    }

    #[test]
    fn present_value_reads_back_as_a_boolean() {
        let mut calendar = holidays();
        calendar.refresh((2026, 12, 24, 4));

        assert_eq!(
            calendar
                .get_property(PropertyIdentifier::PresentValue)
                .unwrap(),
            PropertyValue::Boolean(true)
        );
    }

    #[test]
    fn the_date_list_round_trips_through_its_property() {
        let source = holidays();
        let mut target = Calendar::new(2, "Copy".to_string());
        assert!(target.is_property_writable(PropertyIdentifier::DateList));

        let list = source.get_property(PropertyIdentifier::DateList).unwrap();
        target
            .set_property(PropertyIdentifier::DateList, list)
            .unwrap();

        assert_eq!(target.date_list, source.date_list);
    }

    #[test]
    fn a_list_of_plain_dates_is_accepted_as_calendar_entries() {
        let mut calendar = Calendar::new(1, "Holidays".to_string());

        calendar
            .set_property(
                PropertyIdentifier::DateList,
                PropertyValue::List(vec![PropertyValue::Date(2026, 5, 17, ANY)]),
            )
            .unwrap();

        assert_eq!(
            calendar.date_list,
            vec![CalendarEntryValue::Date(2026, 5, 17, ANY)]
        );
        assert!(calendar.covers((2026, 5, 17, 7)));
    }

    #[test]
    fn present_value_is_not_writable() {
        let mut calendar = holidays();
        assert!(!calendar.is_property_writable(PropertyIdentifier::PresentValue));
        assert!(matches!(
            calendar.set_property(
                PropertyIdentifier::PresentValue,
                PropertyValue::Boolean(true)
            ),
            Err(ObjectError::PropertyNotWritable)
        ));
    }
}
