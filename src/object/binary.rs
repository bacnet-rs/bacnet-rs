//! Binary Object Types Implementation
//!
//! This module implements the Binary Input, Binary Output, and Binary Value object types
//! as defined in ASHRAE 135. These objects represent binary (two-state) values in BACnet.

use crate::object::{
    object_name::ObjectName, BacnetObject, EventState, ObjectError, ObjectIdentifier, ObjectType,
    PropertyIdentifier, PropertyValue, Reliability, Result,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

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

/// Polarity enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Polarity {
    Normal = 0,
    Reverse = 1,
}

/// Binary Input object
#[derive(Debug, Clone)]
pub struct BinaryInput<O> {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: O,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Status flags (4 bits: in_alarm, fault, overridden, out_of_service)
    pub status_flags: u8,
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
}

/// Binary Output object
#[derive(Debug, Clone)]
pub struct BinaryOutput<O> {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: O,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Device type
    pub device_type: String,
    /// Status flags
    pub status_flags: u8,
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
}

/// Binary Value object
#[derive(Debug, Clone)]
pub struct BinaryValue<O> {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name
    pub object_name: O,
    /// Present value
    pub present_value: BinaryPV,
    /// Description
    pub description: String,
    /// Status flags
    pub status_flags: u8,
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
}

impl<O> BinaryInput<O> {
    /// Create a new Binary Input object
    pub fn new(instance: u32, object_name: O) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryInput, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            device_type: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            polarity: Polarity::Normal,
            inactive_text: "INACTIVE".to_string(),
            active_text: "ACTIVE".to_string(),
            change_of_state_time: None,
            change_of_state_count: 0,
            time_of_state_count_reset: None,
        }
    }

    /// Set the present value and update change of state
    pub fn set_present_value(&mut self, value: BinaryPV) {
        if value != self.present_value {
            self.present_value = value;
            self.change_of_state_count += 1;
            // In a real implementation, would set change_of_state_time to current time
        }
    }

    /// Get status flags as individual booleans
    pub fn get_status_flags(&self) -> (bool, bool, bool, bool) {
        (
            (self.status_flags & 0x08) != 0, // in_alarm
            (self.status_flags & 0x04) != 0, // fault
            (self.status_flags & 0x02) != 0, // overridden
            (self.status_flags & 0x01) != 0, // out_of_service
        )
    }

    /// Set status flags from individual booleans
    pub fn set_status_flags(
        &mut self,
        in_alarm: bool,
        fault: bool,
        overridden: bool,
        out_of_service: bool,
    ) {
        self.status_flags = 0;
        if in_alarm {
            self.status_flags |= 0x08;
        }
        if fault {
            self.status_flags |= 0x04;
        }
        if overridden {
            self.status_flags |= 0x02;
        }
        if out_of_service {
            self.status_flags |= 0x01;
        }
    }
}

impl<O> BinaryOutput<O> {
    /// Create a new Binary Output object
    pub fn new(instance: u32, object_name: O) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryOutput, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            device_type: String::new(),
            status_flags: 0,
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
        }
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<BinaryPV>) -> Result<()> {
        if !(1..=16).contains(&priority) {
            return Err(ObjectError::InvalidValue(
                "Priority must be 1-16".to_string(),
            ));
        }
        self.priority_array[(priority - 1) as usize] = value;
        self.update_present_value();
        Ok(())
    }

    /// Update present value based on priority array
    fn update_present_value(&mut self) {
        // Find highest priority non-null value
        if let Some(value) = self.priority_array.iter().flatten().next() {
            self.present_value = *value;
            return;
        }
        // If all priorities are null, use relinquish default
        self.present_value = self.relinquish_default;
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

impl<O> BinaryValue<O> {
    /// Create a new Binary Value object
    pub fn new(instance: u32, object_name: O) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::BinaryValue, instance),
            object_name,
            present_value: BinaryPV::Inactive,
            description: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            inactive_text: "INACTIVE".to_string(),
            active_text: "ACTIVE".to_string(),
            priority_array: [None; 16],
            relinquish_default: BinaryPV::Inactive,
        }
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<BinaryPV>) -> Result<()> {
        if !(1..=16).contains(&priority) {
            return Err(ObjectError::InvalidValue(
                "Priority must be 1-16".to_string(),
            ));
        }
        self.priority_array[(priority - 1) as usize] = value;
        self.update_present_value();
        Ok(())
    }

    /// Update present value based on priority array
    fn update_present_value(&mut self) {
        // Find highest priority non-null value
        if let Some(value) = self.priority_array.iter().flatten().next() {
            self.present_value = *value;
            return;
        }
        // If all priorities are null, use relinquish default
        self.present_value = self.relinquish_default;
    }
}

impl<O> BacnetObject for BinaryInput<O>
where
    O: ObjectName,
{
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn object_name(&self) -> &dyn ObjectName {
        &self.object_name
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.to_string()))
            }
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(ObjectType::BinaryInput as u32))
            }
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::Enumerated(self.present_value as u32))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            _ => Err(ObjectError::UnknownProperty),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name
                        .update(&name)
                        .map_err(|_| ObjectError::InvalidValue(name))
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
            _ => Err(ObjectError::PropertyNotWritable),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName | PropertyIdentifier::OutOfService
        )
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::OutOfService,
        ]
    }
}

impl<O> BacnetObject for BinaryOutput<O>
where
    O: ObjectName,
{
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn object_name(&self) -> &dyn ObjectName {
        &self.object_name
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.to_string()))
            }
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(ObjectType::BinaryOutput as u32))
            }
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::Enumerated(self.present_value as u32))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
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
            _ => Err(ObjectError::UnknownProperty),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name
                        .update(&name)
                        .map_err(|_| ObjectError::InvalidValue(name))
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::PresentValue => {
                if let PropertyValue::Enumerated(val) = value {
                    let binary_val = match val {
                        0 => BinaryPV::Inactive,
                        1 => BinaryPV::Active,
                        _ => {
                            return Err(ObjectError::InvalidValue(
                                "Binary value must be 0 or 1".to_string(),
                            ))
                        }
                    };
                    // Write to priority 8 (manual operator) by default
                    self.write_priority(8, Some(binary_val))
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
            _ => Err(ObjectError::PropertyNotWritable),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::PresentValue
                | PropertyIdentifier::OutOfService
        )
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::PriorityArray,
        ]
    }
}

impl<O> BacnetObject for BinaryValue<O>
where
    O: ObjectName,
{
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn object_name(&self) -> &dyn ObjectName {
        &self.object_name
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.to_string()))
            }
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(ObjectType::BinaryValue as u32))
            }
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::Enumerated(self.present_value as u32))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
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
            _ => Err(ObjectError::UnknownProperty),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name
                        .update(&name)
                        .map_err(|_| ObjectError::InvalidValue(name))
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::PresentValue => {
                if let PropertyValue::Enumerated(val) = value {
                    let binary_val = match val {
                        0 => BinaryPV::Inactive,
                        1 => BinaryPV::Active,
                        _ => {
                            return Err(ObjectError::InvalidValue(
                                "Binary value must be 0 or 1".to_string(),
                            ))
                        }
                    };
                    // Write to priority 8 (manual operator) by default
                    self.write_priority(8, Some(binary_val))
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
            _ => Err(ObjectError::PropertyNotWritable),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::PresentValue
                | PropertyIdentifier::OutOfService
        )
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::PriorityArray,
        ]
    }
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
}
