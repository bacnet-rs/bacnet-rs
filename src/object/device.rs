//! Device Object and Object Functions API
//!
//! This module implements the BACnet Device object and provides an extensible
//! API for registering and managing object type implementations.
//!
//! # Overview
//!
//! The Device Object API provides:
//! - Centralized registry of object function handlers by type
//! - Plugin-style architecture for custom object implementations
//! - Function dispatch for property operations
//! - Object instance management and validation
//!
//! This architecture mirrors the C reference implementation's `Device_Object_Functions_Find()`
//! and `Device_Object_Functions()` APIs (bacnet-stack commit 5b7932ee6).

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use crate::object::{ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue, Result};

/// Object function handlers for a specific object type
///
/// This structure provides a function pointer table for all operations
/// that can be performed on objects of a specific type.
#[derive(Clone)]
pub struct ObjectFunctions {
    /// The object type these functions handle
    pub object_type: ObjectType,

    /// Count the number of instances of this object type
    pub count: fn() -> usize,

    /// Convert index to instance number
    pub index_to_instance: fn(usize) -> Option<u32>,

    /// Check if an instance number is valid
    pub valid_instance: fn(u32) -> bool,

    /// Get the object name for an instance
    pub object_name: fn(u32) -> Option<String>,

    /// Read a property from an object instance
    pub read_property: fn(u32, PropertyIdentifier) -> Result<PropertyValue>,

    /// Write a property to an object instance
    pub write_property: fn(u32, PropertyIdentifier, PropertyValue) -> Result<()>,

    /// Check if a property is writable
    pub is_property_writable: fn(u32, PropertyIdentifier) -> bool,

    /// Get the list of properties for an object instance
    pub property_list: fn(u32) -> Vec<PropertyIdentifier>,
}

impl core::fmt::Debug for ObjectFunctions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectFunctions")
            .field("object_type", &self.object_type)
            .field("count", &"fn()")
            .field("index_to_instance", &"fn(usize) -> Option<u32>")
            .field("valid_instance", &"fn(u32) -> bool")
            .field("object_name", &"fn(u32) -> Option<String>")
            .field(
                "read_property",
                &"fn(u32, PropertyIdentifier) -> Result<PropertyValue>",
            )
            .field(
                "write_property",
                &"fn(u32, PropertyIdentifier, PropertyValue) -> Result<()>",
            )
            .field(
                "is_property_writable",
                &"fn(u32, PropertyIdentifier) -> bool",
            )
            .field("property_list", &"fn(u32) -> Vec<PropertyIdentifier>")
            .finish()
    }
}

/// Device Object that manages all object types and instances
///
/// The Device Object maintains a registry of object function handlers and
/// provides centralized dispatch for all object operations.
#[derive(Debug, Clone)]
pub struct DeviceObject {
    /// Object function registry indexed by object type
    object_table: Vec<ObjectFunctions>,

    /// Device instance number
    device_instance: u32,

    /// Device object identifier
    device_identifier: String,

    /// Device name
    device_name: String,

    /// Device description
    device_description: String,

    /// Vendor identifier
    vendor_identifier: u16,

    /// Vendor name
    vendor_name: String,

    /// Model name
    model_name: String,

    /// Firmware revision
    firmware_revision: String,

    /// Application software version
    application_software_version: String,

    /// Protocol version (1 for BACnet)
    protocol_version: u8,

    /// Protocol revision (ASHRAE 135 revision number)
    protocol_revision: u8,
}

impl DeviceObject {
    /// Create a new Device Object
    ///
    /// # Arguments
    ///
    /// * `device_instance` - The device instance number (0-4194302)
    /// * `device_name` - The name of this device
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let device = DeviceObject::new(12345, "BACnet Device".to_string());
    /// ```
    pub fn new(device_instance: u32, device_name: String) -> Self {
        Self {
            object_table: Vec::new(),
            device_instance,
            device_identifier: format!("Device-{}", device_instance),
            device_name,
            device_description: String::new(),
            vendor_identifier: 0,
            vendor_name: String::from("Unknown"),
            model_name: String::from("BACnet-RS Device"),
            firmware_revision: String::from("1.0"),
            application_software_version: String::from("1.0"),
            protocol_version: 1,
            protocol_revision: 30, // Protocol Revision 30 (latest)
        }
    }

    /// Find object functions for a specific object type
    ///
    /// Returns a reference to the `ObjectFunctions` for the specified type,
    /// or `None` if no handler is registered for that type.
    ///
    /// This mirrors the C reference implementation's `Device_Object_Functions_Find()`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if let Some(funcs) = device.find_object_functions(ObjectType::AnalogInput) {
    ///     let count = (funcs.count)();
    ///     println!("Found {} analog inputs", count);
    /// }
    /// ```
    pub fn find_object_functions(&self, object_type: ObjectType) -> Option<&ObjectFunctions> {
        self.object_table
            .iter()
            .find(|f| f.object_type == object_type)
    }

    /// Get the entire object function table
    ///
    /// Returns a slice containing all registered object function handlers.
    ///
    /// This mirrors the C reference implementation's `Device_Object_Functions()`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// for funcs in device.object_functions() {
    ///     let count = (funcs.count)();
    ///     println!("{:?}: {} instances", funcs.object_type, count);
    /// }
    /// ```
    pub fn object_functions(&self) -> &[ObjectFunctions] {
        &self.object_table
    }

    /// Register object functions for a specific object type
    ///
    /// Adds or replaces the object function handler for the specified type.
    /// This allows for custom object implementations and overriding default behavior.
    ///
    /// # Arguments
    ///
    /// * `functions` - The object function handlers to register
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Register custom Analog Input implementation
    /// device.register_object_functions(ObjectFunctions {
    ///     object_type: ObjectType::AnalogInput,
    ///     count: my_ai_count,
    ///     index_to_instance: my_ai_index,
    ///     valid_instance: my_ai_valid,
    ///     object_name: my_ai_name,
    ///     read_property: my_ai_read,
    ///     write_property: my_ai_write,
    ///     is_property_writable: my_ai_writable,
    ///     property_list: my_ai_props,
    /// });
    /// ```
    pub fn register_object_functions(&mut self, functions: ObjectFunctions) {
        // Remove existing entry if present
        self.object_table
            .retain(|f| f.object_type != functions.object_type);
        // Add new entry
        self.object_table.push(functions);
    }

    /// Get the device instance number
    pub fn device_instance(&self) -> u32 {
        self.device_instance
    }

    /// Get the device name
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Get the device identifier string
    pub fn device_identifier(&self) -> &str {
        &self.device_identifier
    }

    /// Get the application software version
    pub fn application_software_version(&self) -> &str {
        &self.application_software_version
    }

    /// Get the protocol version
    pub fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    /// Get the protocol revision
    pub fn protocol_revision(&self) -> u8 {
        self.protocol_revision
    }

    /// Set the device description
    pub fn set_device_description(&mut self, description: String) {
        self.device_description = description;
    }

    /// Set vendor information
    pub fn set_vendor_info(&mut self, vendor_id: u16, vendor_name: String) {
        self.vendor_identifier = vendor_id;
        self.vendor_name = vendor_name;
    }

    /// Set model information
    pub fn set_model_info(&mut self, model_name: String, firmware_revision: String) {
        self.model_name = model_name;
        self.firmware_revision = firmware_revision;
    }

    /// Read a property from any object managed by this device
    ///
    /// # Arguments
    ///
    /// * `object_id` - The object identifier (type + instance)
    /// * `property` - The property identifier
    ///
    /// # Returns
    ///
    /// The property value, or an error if the object or property is not found
    pub fn read_object_property(
        &self,
        object_id: ObjectIdentifier,
        property: PropertyIdentifier,
    ) -> Result<PropertyValue> {
        // Find the object functions for this type
        if let Some(funcs) = self.find_object_functions(object_id.object_type) {
            // Validate the instance
            if !(funcs.valid_instance)(object_id.instance) {
                return Err(crate::object::ObjectError::InstanceNotFound);
            }
            // Read the property
            (funcs.read_property)(object_id.instance, property)
        } else {
            Err(crate::object::ObjectError::TypeNotSupported)
        }
    }

    /// Write a property to any object managed by this device
    ///
    /// # Arguments
    ///
    /// * `object_id` - The object identifier (type + instance)
    /// * `property` - The property identifier
    /// * `value` - The value to write
    ///
    /// # Returns
    ///
    /// Ok(()) on success, or an error if the object, property is not found or not writable
    pub fn write_object_property(
        &self,
        object_id: ObjectIdentifier,
        property: PropertyIdentifier,
        value: PropertyValue,
    ) -> Result<()> {
        // Find the object functions for this type
        if let Some(funcs) = self.find_object_functions(object_id.object_type) {
            // Validate the instance
            if !(funcs.valid_instance)(object_id.instance) {
                return Err(crate::object::ObjectError::InstanceNotFound);
            }
            // Check if writable
            if !(funcs.is_property_writable)(object_id.instance, property) {
                return Err(crate::object::ObjectError::PropertyNotWritable);
            }
            // Write the property
            (funcs.write_property)(object_id.instance, property, value)
        } else {
            Err(crate::object::ObjectError::TypeNotSupported)
        }
    }

    /// Get the total object count across all types
    pub fn total_object_count(&self) -> usize {
        self.object_table.iter().map(|funcs| (funcs.count)()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock functions for testing
    fn mock_count() -> usize {
        2
    }

    fn mock_index_to_instance(index: usize) -> Option<u32> {
        match index {
            0 => Some(1),
            1 => Some(2),
            _ => None,
        }
    }

    fn mock_valid_instance(instance: u32) -> bool {
        instance == 1 || instance == 2
    }

    fn mock_object_name(instance: u32) -> Option<String> {
        if mock_valid_instance(instance) {
            Some(format!("Test Object {}", instance))
        } else {
            None
        }
    }

    fn mock_read_property(_instance: u32, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(42.0)),
            _ => Err(crate::object::ObjectError::UnknownProperty),
        }
    }

    fn mock_write_property(
        _instance: u32,
        _property: PropertyIdentifier,
        _value: PropertyValue,
    ) -> Result<()> {
        Ok(())
    }

    fn mock_is_writable(_instance: u32, property: PropertyIdentifier) -> bool {
        property == PropertyIdentifier::PresentValue
    }

    fn mock_property_list(_instance: u32) -> Vec<PropertyIdentifier> {
        vec![PropertyIdentifier::PresentValue]
    }

    #[test]
    fn test_device_object_creation() {
        let device = DeviceObject::new(123, "Test Device".to_string());
        assert_eq!(device.device_instance(), 123);
        assert_eq!(device.device_name(), "Test Device");
        assert_eq!(device.total_object_count(), 0);
    }

    #[test]
    fn test_register_object_functions() {
        let mut device = DeviceObject::new(123, "Test Device".to_string());

        let functions = ObjectFunctions {
            object_type: ObjectType::AnalogInput,
            count: mock_count,
            index_to_instance: mock_index_to_instance,
            valid_instance: mock_valid_instance,
            object_name: mock_object_name,
            read_property: mock_read_property,
            write_property: mock_write_property,
            is_property_writable: mock_is_writable,
            property_list: mock_property_list,
        };

        device.register_object_functions(functions);

        assert_eq!(device.total_object_count(), 2);
        assert!(device
            .find_object_functions(ObjectType::AnalogInput)
            .is_some());
    }

    #[test]
    fn test_find_object_functions() {
        let mut device = DeviceObject::new(123, "Test Device".to_string());

        let functions = ObjectFunctions {
            object_type: ObjectType::AnalogInput,
            count: mock_count,
            index_to_instance: mock_index_to_instance,
            valid_instance: mock_valid_instance,
            object_name: mock_object_name,
            read_property: mock_read_property,
            write_property: mock_write_property,
            is_property_writable: mock_is_writable,
            property_list: mock_property_list,
        };

        device.register_object_functions(functions);

        // Should find registered type
        assert!(device
            .find_object_functions(ObjectType::AnalogInput)
            .is_some());

        // Should not find unregistered type
        assert!(device
            .find_object_functions(ObjectType::AnalogOutput)
            .is_none());
    }

    #[test]
    fn test_read_object_property() {
        let mut device = DeviceObject::new(123, "Test Device".to_string());

        let functions = ObjectFunctions {
            object_type: ObjectType::AnalogInput,
            count: mock_count,
            index_to_instance: mock_index_to_instance,
            valid_instance: mock_valid_instance,
            object_name: mock_object_name,
            read_property: mock_read_property,
            write_property: mock_write_property,
            is_property_writable: mock_is_writable,
            property_list: mock_property_list,
        };

        device.register_object_functions(functions);

        let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
        let result = device.read_object_property(object_id, PropertyIdentifier::PresentValue);

        assert!(result.is_ok());
        if let Ok(PropertyValue::Real(val)) = result {
            assert_eq!(val, 42.0);
        } else {
            panic!("Expected Real property value");
        }
    }
}
