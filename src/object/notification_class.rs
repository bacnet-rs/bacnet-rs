//! Notification Class object type.
//!
//! A notification class (ASHRAE 135 clause 12.21) decides, for each of the three
//! event transitions, how urgent a notification is, whether an operator must
//! acknowledge it, and which devices receive it. Intrinsic-reporting objects point
//! at one through their `Notification_Class` property.
//!
//! `Recipient_List` is writable: a recipient — typically a gateway — registers
//! itself by writing its own device identifier into the list.

use crate::object::{
    intrinsic::{EventTransition, EventTransitionBits},
    BacnetObject, ObjectError, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
    Result,
};
use crate::property::{DestinationValue, Recipient};

#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec, vec::Vec};

/// The lowest BACnet notification priority, used as the default.
pub const DEFAULT_PRIORITY: u32 = 255;

/// Notification Class object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationClass {
    /// Object identifier.
    pub identifier: ObjectIdentifier,
    /// Object name.
    pub object_name: String,
    /// Description.
    pub description: String,
    /// Notification priority per transition, ordered to-offnormal, to-fault,
    /// to-normal. 1–255, where lower is more urgent.
    pub priority: [u32; 3],
    /// Which transitions require operator acknowledgement.
    pub ack_required: EventTransitionBits,
    /// Where notifications are sent.
    pub recipient_list: Vec<DestinationValue>,
}

impl NotificationClass {
    /// Create a notification class that sends every transition at the lowest
    /// priority, requires no acknowledgement, and has no recipients yet.
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::NotificationClass, instance),
            object_name,
            description: String::new(),
            priority: [DEFAULT_PRIORITY; 3],
            ack_required: EventTransitionBits::none(),
            recipient_list: Vec::new(),
        }
    }

    /// Set the per-transition priorities (to-offnormal, to-fault, to-normal).
    pub fn with_priority(mut self, to_offnormal: u32, to_fault: u32, to_normal: u32) -> Self {
        self.priority = [to_offnormal, to_fault, to_normal];
        self
    }

    /// Set which transitions require acknowledgement.
    pub fn with_ack_required(mut self, ack_required: EventTransitionBits) -> Self {
        self.ack_required = ack_required;
        self
    }

    /// Add a recipient device that receives every transition at all times.
    pub fn with_recipient(mut self, device: ObjectIdentifier, process_identifier: u32) -> Self {
        self.recipient_list.push(DestinationValue {
            valid_days: vec![true; 7],
            from_time: (0, 0, 0, 0),
            to_time: (23, 59, 59, 99),
            recipient: Recipient::Device(device),
            process_identifier,
            issue_confirmed_notifications: false,
            transitions: EventTransitionBits::all().to_bits(),
        });
        self
    }

    /// Notification priority for `transition`.
    pub fn priority_for(&self, transition: EventTransition) -> u32 {
        self.priority[transition.bit_index()]
    }

    /// Whether `transition` requires operator acknowledgement.
    pub fn ack_required_for(&self, transition: EventTransition) -> bool {
        self.ack_required.contains(transition)
    }

    /// Recipients subscribed to `transition`.
    ///
    /// Time-of-day and day-of-week filtering is deliberately not applied here:
    /// the caller knows the current time and can filter further if it needs to.
    pub fn recipients_for(
        &self,
        transition: EventTransition,
    ) -> impl Iterator<Item = &DestinationValue> {
        let index = transition.bit_index();
        self.recipient_list
            .iter()
            .filter(move |destination| destination.transitions.get(index).copied().unwrap_or(false))
    }
}

impl BacnetObject for NotificationClass {
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
            PropertyIdentifier::ObjectType => Ok(PropertyValue::Enumerated(u32::from(
                ObjectType::NotificationClass,
            ))),
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            // A notification class reports its own instance number here.
            PropertyIdentifier::NotificationClass => {
                Ok(PropertyValue::Unsigned(self.identifier.instance.into()))
            }
            PropertyIdentifier::Priority => Ok(PropertyValue::Array(
                self.priority
                    .iter()
                    .map(|&priority| PropertyValue::Unsigned(priority.into()))
                    .collect(),
            )),
            PropertyIdentifier::AckRequired => {
                Ok(PropertyValue::BitString(self.ack_required.to_bits()))
            }
            PropertyIdentifier::RecipientList => Ok(PropertyValue::List(
                self.recipient_list
                    .iter()
                    .cloned()
                    .map(PropertyValue::Destination)
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
            PropertyIdentifier::Priority => match value {
                PropertyValue::Array(entries) | PropertyValue::List(entries) => {
                    if entries.len() != 3 {
                        return Err(ObjectError::InvalidValue(
                            "Priority must have exactly 3 entries".to_string(),
                        ));
                    }

                    let mut priority = [DEFAULT_PRIORITY; 3];
                    for (slot, entry) in priority.iter_mut().zip(entries) {
                        match entry {
                            PropertyValue::Unsigned(raw) => {
                                *slot = u32::try_from(raw)
                                    .map_err(|_| ObjectError::InvalidPropertyType)?
                            }
                            _ => return Err(ObjectError::InvalidPropertyType),
                        }
                    }
                    self.priority = priority;
                    Ok(())
                }
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::AckRequired => match value {
                PropertyValue::BitString(bits) => {
                    self.ack_required = EventTransitionBits::from_bits(&bits);
                    Ok(())
                }
                _ => Err(ObjectError::InvalidPropertyType),
            },
            PropertyIdentifier::RecipientList => match value {
                PropertyValue::List(entries) | PropertyValue::Array(entries) => entries
                    .into_iter()
                    .map(|entry| match entry {
                        PropertyValue::Destination(destination) => Ok(destination),
                        _ => Err(ObjectError::InvalidPropertyType),
                    })
                    .collect::<Result<Vec<DestinationValue>>>()
                    .map(|recipients| self.recipient_list = recipients),
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
                | PropertyIdentifier::Priority
                | PropertyIdentifier::AckRequired
                | PropertyIdentifier::RecipientList
        )
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::Description,
            PropertyIdentifier::NotificationClass,
            PropertyIdentifier::Priority,
            PropertyIdentifier::AckRequired,
            PropertyIdentifier::RecipientList,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::Device, 5777)
    }

    #[test]
    fn reports_its_own_instance_as_notification_class() {
        let class = NotificationClass::new(3, "NC-3".to_string());
        assert_eq!(
            class
                .get_property(PropertyIdentifier::NotificationClass)
                .unwrap(),
            PropertyValue::Unsigned(3)
        );
    }

    #[test]
    fn priority_and_ack_are_read_per_transition() {
        let class = NotificationClass::new(1, "NC".to_string())
            .with_priority(90, 10, 200)
            .with_ack_required(EventTransitionBits {
                to_offnormal: false,
                to_fault: true,
                to_normal: false,
            });

        assert_eq!(class.priority_for(EventTransition::ToOffnormal), 90);
        assert_eq!(class.priority_for(EventTransition::ToFault), 10);
        assert_eq!(class.priority_for(EventTransition::ToNormal), 200);

        assert!(!class.ack_required_for(EventTransition::ToOffnormal));
        assert!(class.ack_required_for(EventTransition::ToFault));
    }

    #[test]
    fn priority_property_round_trips() {
        let mut class = NotificationClass::new(1, "NC".to_string());
        class
            .set_property(
                PropertyIdentifier::Priority,
                PropertyValue::Array(vec![
                    PropertyValue::Unsigned(90),
                    PropertyValue::Unsigned(10),
                    PropertyValue::Unsigned(200),
                ]),
            )
            .unwrap();

        assert_eq!(class.priority, [90, 10, 200]);
        assert_eq!(
            class.get_property(PropertyIdentifier::Priority).unwrap(),
            PropertyValue::Array(vec![
                PropertyValue::Unsigned(90),
                PropertyValue::Unsigned(10),
                PropertyValue::Unsigned(200),
            ])
        );
    }

    #[test]
    fn priority_rejects_wrong_length() {
        let mut class = NotificationClass::new(1, "NC".to_string());
        assert!(matches!(
            class.set_property(
                PropertyIdentifier::Priority,
                PropertyValue::Array(vec![PropertyValue::Unsigned(1)])
            ),
            Err(ObjectError::InvalidValue(_))
        ));
    }

    #[test]
    fn recipient_list_is_writable_so_a_gateway_can_register_itself() {
        let mut class = NotificationClass::new(1, "NC".to_string());
        assert!(class.is_property_writable(PropertyIdentifier::RecipientList));

        let registered = NotificationClass::new(1, "NC".to_string()).with_recipient(gateway(), 777);
        let list = registered
            .get_property(PropertyIdentifier::RecipientList)
            .unwrap();

        class
            .set_property(PropertyIdentifier::RecipientList, list)
            .unwrap();

        assert_eq!(class.recipient_list.len(), 1);
        assert_eq!(class.recipient_list[0].process_identifier, 777);
        assert_eq!(
            class.recipient_list[0].recipient,
            Recipient::Device(gateway())
        );
    }

    #[test]
    fn recipients_are_filtered_by_transition() {
        let mut class = NotificationClass::new(1, "NC".to_string()).with_recipient(gateway(), 777);
        // Subscribe this recipient to to-fault only.
        class.recipient_list[0].transitions = vec![false, true, false];

        assert_eq!(class.recipients_for(EventTransition::ToFault).count(), 1);
        assert_eq!(
            class.recipients_for(EventTransition::ToOffnormal).count(),
            0
        );
        assert_eq!(class.recipients_for(EventTransition::ToNormal).count(), 0);
    }
}
