//! Analog Object Types Implementation
//!
//! This module implements the Analog Input, Analog Output, and Analog Value object types
//! as defined in ASHRAE 135. These objects represent analog (continuous) values in BACnet.

use crate::object::{
    object_name::ObjectName, BacnetObject, GetObjectIdentifier, ObjectError, ObjectType,
    PropertyIdentifier, PropertyValue, Result,
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// Analog Input object
///
/// `O` is the [`ObjectName`](object_name::ObjectName)
#[derive(Debug, Clone)]
pub struct AnalogInput<O> {
    /// Object instance number
    pub instance: u32,
    /// Object name
    pub object_name: O,
    /// Present value
    pub present_value: f32,
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
    /// Units
    pub units: EngineeringUnits,
    /// Minimum present value
    pub min_pres_value: Option<f32>,
    /// Maximum present value
    pub max_pres_value: Option<f32>,
    /// Resolution
    pub resolution: Option<f32>,
    /// COV increment
    pub cov_increment: Option<f32>,
}

/// Analog Output object
#[derive(Debug, Clone)]
pub struct AnalogOutput<O> {
    /// Object instance number
    pub instance: u32,
    /// Object name
    pub object_name: O,
    /// Present value
    pub present_value: f32,
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
    /// Units
    pub units: EngineeringUnits,
    /// Minimum present value
    pub min_pres_value: Option<f32>,
    /// Maximum present value
    pub max_pres_value: Option<f32>,
    /// Resolution
    pub resolution: Option<f32>,
    /// Priority array (16 levels)
    pub priority_array: [Option<f32>; 16],
    /// Relinquish default
    pub relinquish_default: f32,
    /// COV increment
    pub cov_increment: Option<f32>,
}

/// Analog Value object
#[derive(Debug, Clone)]
pub struct AnalogValue<O> {
    /// Object instance number
    pub instance: u32,
    /// Object name
    pub object_name: O,
    /// Present value
    pub present_value: f32,
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
    /// Units
    pub units: EngineeringUnits,
    /// Priority array (16 levels)
    pub priority_array: [Option<f32>; 16],
    /// Relinquish default
    pub relinquish_default: f32,
    /// COV increment
    pub cov_increment: Option<f32>,
}

/// Event state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EventState {
    Normal = 0,
    Fault = 1,
    Offnormal = 2,
    HighLimit = 3,
    LowLimit = 4,
    LifeSafetyAlarm = 5,
}

/// Reliability enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Reliability {
    NoFaultDetected = 0,
    NoSensor = 1,
    OverRange = 2,
    UnderRange = 3,
    OpenLoop = 4,
    ShortedLoop = 5,
    NoOutput = 6,
    UnreliableOther = 7,
    ProcessError = 8,
    MultiStateFault = 9,
    ConfigurationError = 10,
}

/// Engineering Units enumeration (subset)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EngineeringUnits {
    NoUnits = 95,
    Percent = 98,
    DegreesCelsius = 62,
    DegreesFahrenheit = 64,
    DegreesKelvin = 63,
    Volts = 5,
    Millivolts = 124,
    Amperes = 2,
    Milliamperes = 119,
    Ohms = 4,
    Watts = 47,
    Kilowatts = 48,
    Pascals = 53,
    Kilopascals = 54,
    MetersPerSecond = 74,
    KilometersPerHour = 75,
    CubicMetersPerSecond = 85,
    LitersPerSecond = 126,
}

impl<O> AnalogInput<O> {
    /// Create a new Analog Input object
    pub fn new(instance: u32, object_name: O) -> Self {
        Self {
            instance,
            object_name,
            present_value: 0.0,
            description: String::new(),
            device_type: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            min_pres_value: None,
            max_pres_value: None,
            resolution: None,
            cov_increment: None,
        }
    }

    /// Set the present value
    pub fn set_present_value(&mut self, value: f32) {
        self.present_value = value;
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

impl<O> AnalogOutput<O> {
    /// Create a new Analog Output object
    pub fn new(instance: u32, object_name: O) -> Self {
        Self {
            instance,
            object_name,
            present_value: 0.0,
            description: String::new(),
            device_type: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            min_pres_value: None,
            max_pres_value: None,
            resolution: None,
            priority_array: [None; 16],
            relinquish_default: 0.0,
            cov_increment: None,
        }
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<f32>) -> Result<()> {
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

impl<O> AnalogValue<O> {
    /// Create a new Analog Value object
    pub fn new(instance: u32, object_name: O) -> Self {
        Self {
            instance,
            object_name,
            present_value: 0.0,
            description: String::new(),
            status_flags: 0,
            event_state: EventState::Normal,
            reliability: Reliability::NoFaultDetected,
            out_of_service: false,
            units: EngineeringUnits::NoUnits,
            priority_array: [None; 16],
            relinquish_default: 0.0,
            cov_increment: None,
        }
    }

    /// Write to priority array at specified priority level (1-16)
    pub fn write_priority(&mut self, priority: u8, value: Option<f32>) -> Result<()> {
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

impl<O> GetObjectIdentifier for AnalogInput<O> {
    fn instance(&self) -> u32 {
        self.instance
    }
    fn object_type(&self) -> ObjectType {
        ObjectType::AnalogInput
    }
}

impl<O> BacnetObject for AnalogInput<O>
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
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(ObjectType::AnalogInput as u32))
            }
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(self.present_value)),
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

impl<O> GetObjectIdentifier for AnalogOutput<O> {
    fn instance(&self) -> u32 {
        self.instance
    }
    fn object_type(&self) -> ObjectType {
        ObjectType::AnalogOutput
    }
}

impl<O> BacnetObject for AnalogOutput<O>
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
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(ObjectType::AnalogOutput as u32))
            }
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(self.present_value)),
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::PriorityArray => {
                let array: Vec<PropertyValue> = self
                    .priority_array
                    .iter()
                    .map(|&v| match v {
                        Some(val) => PropertyValue::Real(val),
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
                if let PropertyValue::Real(val) = value {
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

impl<O> GetObjectIdentifier for AnalogValue<O> {
    fn instance(&self) -> u32 {
        self.instance
    }
    fn object_type(&self) -> ObjectType {
        ObjectType::AnalogValue
    }
}

impl<O> BacnetObject for AnalogValue<O>
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
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(ObjectType::AnalogValue as u32))
            }
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(self.present_value)),
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(self.out_of_service)),
            PropertyIdentifier::PriorityArray => {
                let array: Vec<PropertyValue> = self
                    .priority_array
                    .iter()
                    .map(|&v| match v {
                        Some(val) => PropertyValue::Real(val),
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
                if let PropertyValue::Real(val) = value {
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
    fn test_analog_input_creation() {
        let ai = AnalogInput::new(1, "Temperature Sensor".to_string());
        assert_eq!(ai.identifier().instance, 1);
        assert_eq!(ai.object_name, "Temperature Sensor");
        assert_eq!(ai.present_value, 0.0);
        assert!(!ai.out_of_service);
    }

    #[test]
    fn test_analog_output_priority() {
        let mut ao = AnalogOutput::new(1, "Damper Position".to_string());

        // Write to priority 8
        ao.write_priority(8, Some(75.0)).unwrap();
        assert_eq!(ao.present_value, 75.0);
        assert_eq!(ao.get_effective_priority(), Some(8));

        // Write to higher priority 3
        ao.write_priority(3, Some(50.0)).unwrap();
        assert_eq!(ao.present_value, 50.0);
        assert_eq!(ao.get_effective_priority(), Some(3));

        // Release priority 3
        ao.write_priority(3, None).unwrap();
        assert_eq!(ao.present_value, 75.0);
        assert_eq!(ao.get_effective_priority(), Some(8));

        // Release all priorities
        ao.write_priority(8, None).unwrap();
        assert_eq!(ao.present_value, ao.relinquish_default);
        assert_eq!(ao.get_effective_priority(), None);
    }

    #[test]
    fn test_analog_object_properties() {
        let mut av = AnalogValue::new(1, "Test Value".to_string());

        // Test property access
        let name = av.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Test Value");
        } else {
            panic!("Expected CharacterString");
        }

        // Test property modification
        av.set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(42.5))
            .unwrap();
        assert_eq!(av.present_value, 42.5);

        // Test writable properties
        assert!(av.is_property_writable(PropertyIdentifier::PresentValue));
        assert!(!av.is_property_writable(PropertyIdentifier::ObjectIdentifier));
    }

    #[test]
    fn test_status_flags() {
        let mut ai = AnalogInput::new(1, "Test".to_string());

        ai.set_status_flags(true, false, true, false);
        let (in_alarm, fault, overridden, out_of_service) = ai.get_status_flags();
        assert!(in_alarm);
        assert!(!fault);
        assert!(overridden);
        assert!(!out_of_service);
        assert_eq!(ai.status_flags, 0x0A); // 1010 in binary
    }
}
