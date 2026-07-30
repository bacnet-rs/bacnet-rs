//! Binary Object Types Implementation
//!
//! This module implements the Binary Input, Binary Output, and Binary Value object types
//! as defined in ASHRAE 135. These objects represent binary (two-state) values in BACnet.

use crate::object::{
    event_state::EventState,
    intrinsic::{
        intrinsic_get, intrinsic_property_list, intrinsic_set, status_flags_bits, AlarmEvaluation,
        AlarmTrigger, IntrinsicReporting,
    },
    reliability::Reliability,
    write_priority_slot, BacnetObject, ObjectError, ObjectIdentifier, ObjectType,
    PropertyIdentifier, PropertyValue, Result,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Binary values enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BinaryPV {
    Inactive = 0,
    Active = 1,
}

impl From<bool> for BinaryPV {
    fn from(value: bool) -> Self {
        if value {
            BinaryPV::Active
        } else {
            BinaryPV::Inactive
        }
    }
}

impl From<BinaryPV> for bool {
    fn from(value: BinaryPV) -> Self {
        value == BinaryPV::Active
    }
}

fn commandable_binary(value: PropertyValue) -> Result<Option<BinaryPV>> {
    match value {
        PropertyValue::Enumerated(0) => Ok(Some(BinaryPV::Inactive)),
        PropertyValue::Enumerated(1) => Ok(Some(BinaryPV::Active)),
        PropertyValue::Enumerated(_) => Err(ObjectError::InvalidValue(
            "Binary value must be 0 or 1".to_string(),
        )),
        PropertyValue::Null => Ok(None),
        _ => Err(ObjectError::InvalidPropertyType),
    }
}

/// Polarity enumeration
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Polarity {
    Normal = 0,
    Reverse = 1,
}

impl TryFrom<u32> for Polarity {
    type Error = ObjectError;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Polarity::Normal),
            1 => Ok(Polarity::Reverse),
            _ => Err(ObjectError::InvalidValue(
                "Polarity must be 0 or 1".to_string(),
            )),
        }
    }
}

/// Read an alarm property from a binary object.
///
/// Returns `None` when the object has no intrinsic reporting configured, or when
/// `property` is not an alarm property.
fn binary_alarm_get(
    alarm_value: BinaryPV,
    alarm: Option<&IntrinsicReporting>,
    property: PropertyIdentifier,
) -> Option<Result<PropertyValue>> {
    let alarm = alarm?;

    match property {
        PropertyIdentifier::AlarmValue => Some(Ok(PropertyValue::Enumerated(alarm_value as u32))),
        _ => intrinsic_get(alarm, property),
    }
}

/// Write an alarm property on a binary object. `None` follows the same
/// convention as [`binary_alarm_get`].
fn binary_alarm_set(
    alarm_value: &mut BinaryPV,
    alarm: Option<&mut IntrinsicReporting>,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Option<Result<()>> {
    let alarm = alarm?;

    match property {
        PropertyIdentifier::AlarmValue => Some(match value {
            PropertyValue::Enumerated(0) => {
                *alarm_value = BinaryPV::Inactive;
                Ok(())
            }
            PropertyValue::Enumerated(1) => {
                *alarm_value = BinaryPV::Active;
                Ok(())
            }
            PropertyValue::Boolean(active) => {
                *alarm_value = BinaryPV::from(active);
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        }),
        _ => intrinsic_set(alarm, property, value),
    }
}

/// Alarm properties a binary object exposes, given its configuration.
fn binary_alarm_property_list(alarm: Option<&IntrinsicReporting>) -> Vec<PropertyIdentifier> {
    if alarm.is_none() {
        return Vec::new();
    }

    let mut properties = vec![PropertyIdentifier::AlarmValue];
    properties.extend(intrinsic_property_list());
    properties
}

/// Whether a binary alarm property accepts writes.
fn binary_alarm_writable(property: PropertyIdentifier, alarm_configured: bool) -> bool {
    alarm_configured
        && matches!(
            property,
            PropertyIdentifier::AlarmValue
                | PropertyIdentifier::NotificationClass
                | PropertyIdentifier::TimeDelay
                | PropertyIdentifier::TimeDelayNormal
                | PropertyIdentifier::EventEnable
                | PropertyIdentifier::NotifyType
                | PropertyIdentifier::EventDetectionEnable
        )
}

/// Run CHANGE_OF_STATE for a binary object.
///
/// The object is off-normal while Present_Value equals Alarm_Value; an
/// unreliable object goes to fault, which takes precedence.
fn evaluate_binary(
    present_value: BinaryPV,
    alarm_value: BinaryPV,
    reliability: Reliability,
    alarm: Option<&IntrinsicReporting>,
) -> Option<AlarmEvaluation> {
    let alarm = alarm?;
    if !alarm.event_detection_enable {
        return None;
    }

    if reliability != Reliability::NoFaultDetected {
        return Some(AlarmEvaluation {
            desired_state: EventState::Fault,
            trigger: AlarmTrigger::ReliabilityChange { reliability },
        });
    }

    let desired_state = if present_value == alarm_value {
        EventState::Offnormal
    } else {
        EventState::Normal
    };

    Some(AlarmEvaluation {
        desired_state,
        trigger: AlarmTrigger::BinaryChange {
            active: present_value == BinaryPV::Active,
        },
    })
}

/// The intrinsic reporting trait methods shared by all binary object types.
macro_rules! binary_intrinsic_methods {
    () => {
        fn intrinsic(&self) -> Option<&IntrinsicReporting> {
            self.alarm.as_ref()
        }

        fn intrinsic_mut(&mut self) -> Option<&mut IntrinsicReporting> {
            self.alarm.as_mut()
        }

        fn evaluate_alarm(&self) -> Option<AlarmEvaluation> {
            evaluate_binary(
                self.present_value,
                self.alarm_value,
                self.reliability,
                self.alarm.as_ref(),
            )
        }

        fn apply_event_state(&mut self, state: EventState) {
            self.event_state = state;
        }

        fn is_out_of_service(&self) -> bool {
            self.out_of_service
        }
    };
}

/// Binary Input object
#[derive(Debug, Clone)]
pub struct BinaryInput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Polarity
    pub polarity: Polarity,
    /// Inactive text
    pub inactive_text: String,
    /// Active text
    pub active_text: String,
    /// Change of value time
    pub change_of_state_time: Option<crate::object::Time>,
    /// Change of state count
    pub change_of_state_count: u32,
    /// Time of state count reset
    pub time_of_state_count_reset: Option<crate::object::Time>,
    /// Present value that puts the object into an off-normal event state.
    pub alarm_value: BinaryPV,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Binary Output object
#[derive(Debug, Clone)]
pub struct BinaryOutput {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Polarity
    pub polarity: Polarity,
    /// Inactive text
    pub inactive_text: String,
    /// Active text
    pub active_text: String,
    /// Priority array (16 levels)
    pub priority_array: [Option<BinaryPV>; 16],
    /// Relinquish default
    pub relinquish_default: BinaryPV,
    /// Minimum off time
    pub minimum_off_time: u32,
    /// Minimum on time
    pub minimum_on_time: u32,
    /// Present value that puts the object into an off-normal event state.
    pub alarm_value: BinaryPV,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

/// Binary Value object
#[derive(Debug, Clone)]
pub struct BinaryValue {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: String,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Whether an operator has overridden the point. The other Status_Flags
    /// bits are derived from Event_State, Reliability and Out_Of_Service.
    pub overridden: bool,
    /// Event state
    pub event_state: EventState,
    /// Reliability
    pub reliability: Reliability,
    /// Out of service
    pub out_of_service: bool,
    /// Inactive text
    pub inactive_text: String,
    /// Active text
    pub active_text: String,
    /// Priority array (16 levels)
    pub priority_array: [Option<BinaryPV>; 16],
    /// Relinquish default
    pub relinquish_default: BinaryPV,
    /// Present value that puts the object into an off-normal event state.
    pub alarm_value: BinaryPV,
    /// Intrinsic reporting state; `None` when event detection is not configured.
    pub alarm: Option<IntrinsicReporting>,
}

impl BinaryInput {
    /// Create a new Binary Input object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryInput, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            device_type: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            polarity: Polarity::Normal,
            inactive_text: "INACTIVE".to_string(),
            active_text: "ACTIVE".to_string(),
            change_of_state_time: None,
            change_of_state_count: 0,
            time_of_state_count_reset: None,
            alarm_value: BinaryPV::Active,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_STATE reporting through `notification_class`, alarming
    /// when Present_Value equals `alarm_value`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_value: BinaryPV,
    ) -> Self {
        self.alarm_value = alarm_value;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Set the present value and update change of state
    pub fn set_present_value(&mut self, value: BinaryPV) {
        if value != self.present_value {
            self.present_value = value;
            self.change_of_state_count += 1;
            // In a real implementation, would set change_of_state_time to current time
        }
    }

    /// Status flags as individual booleans, in the in-alarm / fault /
    /// overridden / out-of-service order.
    ///
    /// Derived from Event_State, Reliability, Out_Of_Service and
    /// [`overridden`](Self::overridden); set those to change what this reports.
    pub fn get_status_flags(&self) -> (bool, bool, bool, bool) {
        let bits = status_flags_bits(
            self.event_state,
            self.reliability,
            self.out_of_service,
            self.overridden,
        );
        (bits[0], bits[1], bits[2], bits[3])
    }
}

impl BinaryOutput {
    /// Create a new Binary Output object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryOutput, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            device_type: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            polarity: Polarity::Normal,
            inactive_text: "INACTIVE".to_string(),
            active_text: "ACTIVE".to_string(),
            priority_array: [None; 16],
            relinquish_default: BinaryPV::Inactive,
            minimum_off_time: 0,
            minimum_on_time: 0,
            alarm_value: BinaryPV::Active,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_STATE reporting through `notification_class`, alarming
    /// when Present_Value equals `alarm_value`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_value: BinaryPV,
    ) -> Self {
        self.alarm_value = alarm_value;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<BinaryPV>) -> Result<()> {
        self.present_value = write_priority_slot(
            &mut self.priority_array,
            priority,
            value,
            self.relinquish_default,
        )?;
        Ok(())
    }

    /// Get the effective priority level for current present value
    pub fn get_effective_priority(&self) -> Option<u8> {
        for (i, priority_value) in self.priority_array.iter().enumerate() {
            if priority_value.is_some() {
                return Some((i + 1) as u8);
            }
        }
        None
    }
}

impl BinaryValue {
    /// Create a new Binary Value object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryValue, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            overridden: false,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            inactive_text: "INACTIVE".to_string(),
            active_text: "ACTIVE".to_string(),
            priority_array: [None; 16],
            relinquish_default: BinaryPV::Inactive,
            alarm_value: BinaryPV::Active,
            alarm: None,
        }
    }

    /// Enable CHANGE_OF_STATE reporting through `notification_class`, alarming
    /// when Present_Value equals `alarm_value`.
    pub fn with_intrinsic_reporting(
        mut self,
        notification_class: u32,
        alarm_value: BinaryPV,
    ) -> Self {
        self.alarm_value = alarm_value;
        self.alarm = Some(IntrinsicReporting::new(notification_class));
        self
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<BinaryPV>) -> Result<()> {
        self.present_value = write_priority_slot(
            &mut self.priority_array,
            priority,
            value,
            self.relinquish_default,
        )?;
        Ok(())
    }
}

impl BacnetObject for BinaryInput {
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
                ObjectType::BinaryInput,
            ))),
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::Enumerated(self.present_value as u32))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            PropertyIdentifier::StatusFlags => Ok(PropertyValue::BitString(status_flags_bits(
                self.event_state,
                self.reliability,
                self.out_of_service,
                self.overridden,
            ))),
            PropertyIdentifier::EventState => Ok(PropertyValue::Enumerated(
                u16::from(self.event_state).into(),
            )),
            PropertyIdentifier::Reliability => {
                Ok(PropertyValue::Enumerated(self.reliability.into()))
            }
            PropertyIdentifier::InactiveText => {
                Ok(PropertyValue::CharacterString(self.inactive_text.clone()))
            }
            PropertyIdentifier::ActiveText => {
                Ok(PropertyValue::CharacterString(self.active_text.clone()))
            }
            _ => binary_alarm_get(self.alarm_value, self.alarm.as_ref(), property)
                .unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::Description => {
                if let PropertyValue::CharacterString(text) = value {
                    self.description = text;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            // Writable so a simulated device can be driven into a fault state.
            PropertyIdentifier::Reliability => {
                if let PropertyValue::Enumerated(raw) = value {
                    self.reliability = Reliability::from(raw);
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::OutOfService => {
                if let PropertyValue::Boolean(oos) = value {
                    self.out_of_service = oos;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            _ => binary_alarm_set(&mut self.alarm_value, self.alarm.as_mut(), property, value)
                .unwrap_or(Err(ObjectError::PropertyNotWritable)),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::Description
                | PropertyIdentifier::OutOfService
                | PropertyIdentifier::Reliability
        ) || binary_alarm_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut properties = vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::Description,
            PropertyIdentifier::StatusFlags,
            PropertyIdentifier::EventState,
            PropertyIdentifier::Reliability,
            PropertyIdentifier::InactiveText,
            PropertyIdentifier::ActiveText,
        ];
        properties.extend(binary_alarm_property_list(self.alarm.as_ref()));
        properties
    }

    /// An input reflects a physical contact, so its Present_Value has no
    /// priority array and is simply what the source last read.
    fn set_sourced_value(&mut self, value: PropertyValue) -> Result<()> {
        // Null relinquishes a commandable object; an input has nothing to
        // relinquish to, so it is not a value a source can supply.
        match commandable_binary(value)? {
            Some(state) => {
                self.present_value = state;
                Ok(())
            }
            None => Err(ObjectError::InvalidPropertyType),
        }
    }

    binary_intrinsic_methods!();
}

impl BacnetObject for BinaryOutput {
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
                ObjectType::BinaryOutput,
            ))),
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::Enumerated(self.present_value as u32))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            PropertyIdentifier::StatusFlags => Ok(PropertyValue::BitString(status_flags_bits(
                self.event_state,
                self.reliability,
                self.out_of_service,
                self.overridden,
            ))),
            PropertyIdentifier::EventState => Ok(PropertyValue::Enumerated(
                u16::from(self.event_state).into(),
            )),
            PropertyIdentifier::Reliability => {
                Ok(PropertyValue::Enumerated(self.reliability.into()))
            }
            PropertyIdentifier::InactiveText => {
                Ok(PropertyValue::CharacterString(self.inactive_text.clone()))
            }
            PropertyIdentifier::ActiveText => {
                Ok(PropertyValue::CharacterString(self.active_text.clone()))
            }
            PropertyIdentifier::PriorityArray => {
                let array: Vec<PropertyValue> = self
                    .priority_array
                    .iter()
                    .map(|&v| match v {
                        Some(val) => PropertyValue::Enumerated(val as u32),
                        None => PropertyValue::Null,
                    })
                    .collect();
                Ok(PropertyValue::Array(array))
            }
            _ => binary_alarm_get(self.alarm_value, self.alarm.as_ref(), property)
                .unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::Description => {
                if let PropertyValue::CharacterString(text) = value {
                    self.description = text;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            // Writable so a simulated device can be driven into a fault state.
            PropertyIdentifier::Reliability => {
                if let PropertyValue::Enumerated(raw) = value {
                    self.reliability = Reliability::from(raw);
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::PresentValue => {
                self.set_property_with_priority(property, value, None)
            }
            PropertyIdentifier::OutOfService => {
                if let PropertyValue::Boolean(oos) = value {
                    self.out_of_service = oos;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            _ => binary_alarm_set(&mut self.alarm_value, self.alarm.as_mut(), property, value)
                .unwrap_or(Err(ObjectError::PropertyNotWritable)),
        }
    }

    fn set_property_with_priority(
        &mut self,
        property: PropertyIdentifier,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<()> {
        if property != PropertyIdentifier::PresentValue {
            return self.set_property(property, value);
        }

        self.write_priority(priority.unwrap_or(16), commandable_binary(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::Description
                | PropertyIdentifier::PresentValue
                | PropertyIdentifier::OutOfService
                | PropertyIdentifier::Reliability
        ) || binary_alarm_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut properties = vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::Description,
            PropertyIdentifier::StatusFlags,
            PropertyIdentifier::EventState,
            PropertyIdentifier::Reliability,
            PropertyIdentifier::InactiveText,
            PropertyIdentifier::ActiveText,
        ];
        properties.extend(binary_alarm_property_list(self.alarm.as_ref()));
        properties
    }

    binary_intrinsic_methods!();
}

impl BacnetObject for BinaryValue {
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
                ObjectType::BinaryValue,
            ))),
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::Enumerated(self.present_value as u32))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::Description => {
                Ok(PropertyValue::CharacterString(self.description.clone()))
            }
            PropertyIdentifier::StatusFlags => Ok(PropertyValue::BitString(status_flags_bits(
                self.event_state,
                self.reliability,
                self.out_of_service,
                self.overridden,
            ))),
            PropertyIdentifier::EventState => Ok(PropertyValue::Enumerated(
                u16::from(self.event_state).into(),
            )),
            PropertyIdentifier::Reliability => {
                Ok(PropertyValue::Enumerated(self.reliability.into()))
            }
            PropertyIdentifier::InactiveText => {
                Ok(PropertyValue::CharacterString(self.inactive_text.clone()))
            }
            PropertyIdentifier::ActiveText => {
                Ok(PropertyValue::CharacterString(self.active_text.clone()))
            }
            PropertyIdentifier::PriorityArray => {
                let array: Vec<PropertyValue> = self
                    .priority_array
                    .iter()
                    .map(|&v| match v {
                        Some(val) => PropertyValue::Enumerated(val as u32),
                        None => PropertyValue::Null,
                    })
                    .collect();
                Ok(PropertyValue::Array(array))
            }
            _ => binary_alarm_get(self.alarm_value, self.alarm.as_ref(), property)
                .unwrap_or(Err(ObjectError::UnknownProperty)),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::Description => {
                if let PropertyValue::CharacterString(text) = value {
                    self.description = text;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            // Writable so a simulated device can be driven into a fault state.
            PropertyIdentifier::Reliability => {
                if let PropertyValue::Enumerated(raw) = value {
                    self.reliability = Reliability::from(raw);
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::PresentValue => {
                self.set_property_with_priority(property, value, None)
            }
            PropertyIdentifier::OutOfService => {
                if let PropertyValue::Boolean(oos) = value {
                    self.out_of_service = oos;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            _ => binary_alarm_set(&mut self.alarm_value, self.alarm.as_mut(), property, value)
                .unwrap_or(Err(ObjectError::PropertyNotWritable)),
        }
    }

    fn set_property_with_priority(
        &mut self,
        property: PropertyIdentifier,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<()> {
        if property != PropertyIdentifier::PresentValue {
            return self.set_property(property, value);
        }

        self.write_priority(priority.unwrap_or(16), commandable_binary(value)?)
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::Description
                | PropertyIdentifier::PresentValue
                | PropertyIdentifier::OutOfService
                | PropertyIdentifier::Reliability
        ) || binary_alarm_writable(property, self.alarm.is_some())
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        let mut properties = vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::PriorityArray,
            PropertyIdentifier::Description,
            PropertyIdentifier::StatusFlags,
            PropertyIdentifier::EventState,
            PropertyIdentifier::Reliability,
            PropertyIdentifier::InactiveText,
            PropertyIdentifier::ActiveText,
        ];
        properties.extend(binary_alarm_property_list(self.alarm.as_ref()));
        properties
    }

    binary_intrinsic_methods!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_pv_conversions() {
        assert_eq!(BinaryPV::from(true), BinaryPV::Active);
        assert_eq!(BinaryPV::from(false), BinaryPV::Inactive);
        assert!(bool::from(BinaryPV::Active));
        assert!(!bool::from(BinaryPV::Inactive));
    }

    #[test]
    fn test_binary_input_creation() {
        let bi = BinaryInput::new(1, "Door Switch".to_string());
        assert_eq!(bi.identifier.instance, 1);
        assert_eq!(bi.object_name, "Door Switch");
        assert_eq!(bi.present_value, BinaryPV::Inactive);
        assert_eq!(bi.change_of_state_count, 0);
    }

    #[test]
    fn test_binary_input_change_of_state() {
        let mut bi = BinaryInput::new(1, "Test".to_string());

        bi.set_present_value(BinaryPV::Active);
        assert_eq!(bi.present_value, BinaryPV::Active);
        assert_eq!(bi.change_of_state_count, 1);

        bi.set_present_value(BinaryPV::Active); // Same value, no change
        assert_eq!(bi.change_of_state_count, 1);

        bi.set_present_value(BinaryPV::Inactive);
        assert_eq!(bi.change_of_state_count, 2);
    }

    #[test]
    fn test_binary_output_priority() {
        let mut bo = BinaryOutput::new(1, "Fan Control".to_string());

        // Write to priority 8
        bo.write_priority(8, Some(BinaryPV::Active)).unwrap();
        assert_eq!(bo.present_value, BinaryPV::Active);
        assert_eq!(bo.get_effective_priority(), Some(8));

        // Write to higher priority 3
        bo.write_priority(3, Some(BinaryPV::Inactive)).unwrap();
        assert_eq!(bo.present_value, BinaryPV::Inactive);
        assert_eq!(bo.get_effective_priority(), Some(3));

        // Release priority 3
        bo.write_priority(3, None).unwrap();
        assert_eq!(bo.present_value, BinaryPV::Active);
        assert_eq!(bo.get_effective_priority(), Some(8));
    }

    #[test]
    fn binary_property_writes_preserve_priority_and_relinquish() {
        let mut output = BinaryOutput::new(1, "Fan Control".to_string());
        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Enumerated(1),
                Some(3),
            )
            .unwrap();
        assert_eq!(output.priority_array[2], Some(BinaryPV::Active));
        output
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Null,
                Some(3),
            )
            .unwrap();
        assert_eq!(output.priority_array[2], None);

        let mut value = BinaryValue::new(2, "Occupancy".to_string());
        value
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Enumerated(1),
                Some(4),
            )
            .unwrap();
        assert_eq!(value.priority_array[3], Some(BinaryPV::Active));
        value
            .set_property_with_priority(
                PropertyIdentifier::PresentValue,
                PropertyValue::Null,
                Some(4),
            )
            .unwrap();
        assert_eq!(value.priority_array[3], None);
    }

    #[test]
    fn test_binary_object_properties() {
        let mut bv = BinaryValue::new(1, "Test Value".to_string());

        // Test property access
        let name = bv.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Test Value");
        } else {
            panic!("Expected CharacterString");
        }

        // Test property modification
        bv.set_property(
            PropertyIdentifier::PresentValue,
            PropertyValue::Enumerated(1),
        )
        .unwrap();
        assert_eq!(bv.present_value, BinaryPV::Active);

        // Test invalid binary value
        let result = bv.set_property(
            PropertyIdentifier::PresentValue,
            PropertyValue::Enumerated(2),
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_source_drives_an_input_but_cannot_relinquish_it() {
        let mut input = BinaryInput::new(1, "Door contact".to_string());

        input
            .set_sourced_value(PropertyValue::Enumerated(1))
            .unwrap();
        assert_eq!(input.present_value, BinaryPV::Active);

        // Null relinquishes a commandable object; an input has no priority array
        // to relinquish to, so there is nothing for it to mean.
        assert!(matches!(
            input.set_sourced_value(PropertyValue::Null),
            Err(ObjectError::InvalidPropertyType)
        ));
        assert_eq!(input.present_value, BinaryPV::Active);
    }
}
