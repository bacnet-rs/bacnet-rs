//! Multi-state Object Types Implementation
//!
//! This module implements the Multi-state Input, Multi-state Output, and Multi-state Value
//! object types as defined in ASHRAE 135. These objects represent multi-position values.

use crate::object::{
    object_name::ObjectName, BacnetObject, EventState, GetObjectIdentifier, ObjectError,
    ObjectType, PropertyIdentifier, PropertyValue, Reliability, Result,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// Multi-state Input object
#[derive(Debug, Clone)]
pub struct MultiStateInput<O> {
    /// Object instance number
    pub instance: u32,
    /// Object name
    pub object_name: O,
    /// Present value (state 1..N)
    pub present_value: u32,
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
    /// Number of states
    pub number_of_states: u32,
    /// State text array
    pub state_text: Vec<String>,
}

/// Multi-state Output object
#[derive(Debug, Clone)]
pub struct MultiStateOutput<O> {
    /// Object instance number
    pub instance: u32,
    /// Object name
    pub object_name: O,
    /// Present value (state 1..N)
    pub present_value: u32,
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
    /// Number of states
    pub number_of_states: u32,
    /// State text array
    pub state_text: Vec<String>,
    /// Priority array (16 levels)
    pub priority_array: [Option<u32>; 16],
    /// Relinquish default
    pub relinquish_default: u32,
}

/// Multi-state Value object
#[derive(Debug, Clone)]
pub struct MultiStateValue<O> {
    /// Object instance number
    pub instance: u32,
    /// Object name
    pub object_name: O,
    /// Present value (state 1..N)
    pub present_value: u32,
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
    /// Number of states
    pub number_of_states: u32,
    /// State text array
    pub state_text: Vec<String>,
    /// Priority array (16 levels)
    pub priority_array: [Option<u32>; 16],
    /// Relinquish default
    pub relinquish_default: u32,
}

impl<O> MultiStateInput<O> {
    /// Create a new Multi-state Input object
    pub fn new(instance: u32, object_name: O, number_of_states: u32) -> Self {
        let mut state_text = Vec::with_capacity(number_of_states as usize);
        for i in 1..=number_of_states {
            state_text.push(format!("State {}", i));
        }

        Self {
            instance,
            object_name,
            present_value: 1,
            description: String::new(),
            device_type: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            number_of_states,
            state_text,
        }
    }

    /// Set the present value (validates range)
    pub fn set_present_value(&mut self, value: u32) -> Result<()> {
        if value < 1 || value > self.number_of_states {
            return Err(ObjectError::InvalidValue(format!(
                "Value must be between 1 and {}",
                self.number_of_states
            )));
        }
        self.present_value = value;
        Ok(())
    }

    /// Get the current state text
    pub fn get_state_text(&self) -> Option<&str> {
        if self.present_value > 0 && self.present_value <= self.state_text.len() as u32 {
            Some(&self.state_text[(self.present_value - 1) as usize])
        } else {
            None
        }
    }

    /// Set state text for a specific state
    pub fn set_state_text(&mut self, state: u32, text: String) -> Result<()> {
        if state < 1 || state > self.number_of_states {
            return Err(ObjectError::InvalidValue(format!(
                "State must be between 1 and {}",
                self.number_of_states
            )));
        }
        self.state_text[(state - 1) as usize] = text;
        Ok(())
    }
}

impl<O> MultiStateOutput<O> {
    /// Create a new Multi-state Output object
    pub fn new(instance: u32, object_name: O, number_of_states: u32) -> Self {
        let mut state_text = Vec::with_capacity(number_of_states as usize);
        for i in 1..=number_of_states {
            state_text.push(format!("State {}", i));
        }

        Self {
            instance,
            object_name,
            present_value: 1,
            description: String::new(),
            device_type: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            number_of_states,
            state_text,
            priority_array: [None; 16],
            relinquish_default: 1,
        }
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<u32>) -> Result<()> {
        if !(1..=16).contains(&priority) {
            return Err(ObjectError::InvalidValue(
                "Priority must be 1-16".to_string(),
            ));
        }

        if let Some(val) = value {
            if val < 1 || val > self.number_of_states {
                return Err(ObjectError::InvalidValue(format!(
                    "Value must be between 1 and {}",
                    self.number_of_states
                )));
            }
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

impl<O> MultiStateValue<O> {
    /// Create a new Multi-state Value object
    pub fn new(instance: u32, object_name: O, number_of_states: u32) -> Self {
        let mut state_text = Vec::with_capacity(number_of_states as usize);
        for i in 1..=number_of_states {
            state_text.push(format!("State {}", i));
        }

        Self {
            instance,
            object_name,
            present_value: 1,
            description: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            number_of_states,
            state_text,
            priority_array: [None; 16],
            relinquish_default: 1,
        }
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<u32>) -> Result<()> {
        if !(1..=16).contains(&priority) {
            return Err(ObjectError::InvalidValue(
                "Priority must be 1-16".to_string(),
            ));
        }

        if let Some(val) = value {
            if val < 1 || val > self.number_of_states {
                return Err(ObjectError::InvalidValue(format!(
                    "Value must be between 1 and {}",
                    self.number_of_states
                )));
            }
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

impl<O> GetObjectIdentifier for MultiStateInput<O> {
    fn instance(&self) -> u32 {
        self.instance
    }
    fn object_type(&self) -> ObjectType {
        ObjectType::MultiStateInput
    }
}

impl<O> BacnetObject for MultiStateInput<O>
where
    O: ObjectName,
{
    fn object_name(&self) -> &dyn ObjectName {
        &self.object_name
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier()))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.to_string()))
            }
            PropertyIdentifier::ObjectType => Ok(PropertyValue::Enumerated(
                ObjectType::MultiStateInput as u32,
            )),
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::UnsignedInteger(self.present_value))
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

impl<O> GetObjectIdentifier for MultiStateOutput<O> {
    fn instance(&self) -> u32 {
        self.instance
    }
    fn object_type(&self) -> ObjectType {
        ObjectType::MultiStateOutput
    }
}

impl<O> BacnetObject for MultiStateOutput<O>
where
    O: ObjectName,
{
    fn object_name(&self) -> &dyn ObjectName {
        &self.object_name
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier()))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.to_string()))
            }
            PropertyIdentifier::ObjectType => Ok(PropertyValue::Enumerated(
                ObjectType::MultiStateOutput as u32,
            )),
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::UnsignedInteger(self.present_value))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::PriorityArray => {
                let array: Vec<PropertyValue> = self
                    .priority_array
                    .iter()
                    .map(|&v| match v {
                        Some(val) => PropertyValue::UnsignedInteger(val),
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
                if let PropertyValue::UnsignedInteger(val) = value {
                    // Write to priority 8 (manual operator) by default
                    self.write_priority(8, Some(val))
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

impl<O> GetObjectIdentifier for MultiStateValue<O> {
    fn instance(&self) -> u32 {
        self.instance
    }
    fn object_type(&self) -> ObjectType {
        ObjectType::MultiStateValue
    }
}

impl<O> BacnetObject for MultiStateValue<O>
where
    O: ObjectName,
{
    fn object_name(&self) -> &dyn ObjectName {
        &self.object_name
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier()))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.to_string()))
            }
            PropertyIdentifier::ObjectType => Ok(PropertyValue::Enumerated(
                ObjectType::MultiStateValue as u32,
            )),
            PropertyIdentifier::PresentValue => {
                Ok(PropertyValue::UnsignedInteger(self.present_value))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::PriorityArray => {
                let array: Vec<PropertyValue> = self
                    .priority_array
                    .iter()
                    .map(|&v| match v {
                        Some(val) => PropertyValue::UnsignedInteger(val),
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
                if let PropertyValue::UnsignedInteger(val) = value {
                    // Write to priority 8 (manual operator) by default
                    self.write_priority(8, Some(val))
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
    fn test_multistate_input_creation() {
        let msi = MultiStateInput::new(1, "Mode Selector".to_string(), 5);
        assert_eq!(msi.identifier().instance, 1);
        assert_eq!(msi.object_name, "Mode Selector");
        assert_eq!(msi.number_of_states, 5);
        assert_eq!(msi.present_value, 1);
        assert_eq!(msi.state_text.len(), 5);
    }

    #[test]
    fn test_multistate_state_text() {
        let mut msi = MultiStateInput::new(1, "Mode".to_string(), 3);

        // Set custom state text
        msi.set_state_text(1, "OFF".to_string()).unwrap();
        msi.set_state_text(2, "AUTO".to_string()).unwrap();
        msi.set_state_text(3, "MANUAL".to_string()).unwrap();

        assert_eq!(msi.get_state_text(), Some("OFF"));

        msi.set_present_value(2).unwrap();
        assert_eq!(msi.get_state_text(), Some("AUTO"));

        // Test invalid state
        assert!(msi.set_present_value(4).is_err());
    }

    #[test]
    fn test_multistate_output_priority() {
        let mut mso = MultiStateOutput::new(1, "Sequence Control".to_string(), 4);

        // Write to priority 8
        mso.write_priority(8, Some(3)).unwrap();
        assert_eq!(mso.present_value, 3);
        assert_eq!(mso.get_effective_priority(), Some(8));

        // Write to higher priority 3
        mso.write_priority(3, Some(2)).unwrap();
        assert_eq!(mso.present_value, 2);
        assert_eq!(mso.get_effective_priority(), Some(3));

        // Test invalid value
        assert!(mso.write_priority(3, Some(5)).is_err());

        // Release priority 3
        mso.write_priority(3, None).unwrap();
        assert_eq!(mso.present_value, 3); // Back to priority 8 value
    }

    #[test]
    fn test_multistate_properties() {
        let mut msv = MultiStateValue::new(1, "Operating Mode".to_string(), 4);

        // Test property access
        let name = msv.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Operating Mode");
        } else {
            panic!("Expected CharacterString");
        }

        // Test property modification
        msv.set_property(
            PropertyIdentifier::PresentValue,
            PropertyValue::UnsignedInteger(3),
        )
        .unwrap();
        assert_eq!(msv.present_value, 3);
    }
}
