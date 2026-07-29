//! BACnet Object Types and Property Management
//!
//! This module defines BACnet object types and their properties according to ASHRAE Standard 135.
//! Objects are the fundamental modeling concept in BACnet, representing physical and logical
//! entities in building automation systems such as sensors, actuators, controllers, and data points.
//!
//! # Overview
//!
//! BACnet objects are the core abstraction for all entities in a BACnet system. Each object consists of:
//!
//! - **Object Identifier**: A unique 32-bit identifier combining object type and instance number
//! - **Properties**: A collection of named values that describe the object's state, configuration, and behavior
//! - **Required Properties**: Properties that must be present in all instances of an object type
//! - **Optional Properties**: Properties that may be present depending on the implementation
//!
//! # Object Hierarchy
//!
//! Objects are organized into categories based on their function:
//!
//! ## Input Objects
//! - [`AnalogInput`](ObjectType::AnalogInput): Represents analog sensor readings (temperature, pressure, etc.)
//! - [`BinaryInput`](ObjectType::BinaryInput): Represents digital sensor states (on/off, open/closed)
//! - [`MultiStateInput`](ObjectType::MultiStateInput): Represents enumerated sensor states
//!
//! ## Output Objects  
//! - [`AnalogOutput`](ObjectType::AnalogOutput): Controls analog actuators (valve position, damper angle)
//! - [`BinaryOutput`](ObjectType::BinaryOutput): Controls digital actuators (pumps, fans, lights)
//! - [`MultiStateOutput`](ObjectType::MultiStateOutput): Controls multi-position actuators
//!
//! ## Value Objects
//! - [`AnalogValue`](ObjectType::AnalogValue): Software variables for calculations and setpoints
//! - [`BinaryValue`](ObjectType::BinaryValue): Software flags and status indicators
//! - [`MultiStateValue`](ObjectType::MultiStateValue): Software enumerated values
//!
//! ## System Objects
//! - [`Device`](ObjectType::Device): Represents a BACnet device (required in every device)
//! - [`Schedule`](ObjectType::Schedule): Time-based control schedules
//! - [`Calendar`](ObjectType::Calendar): Date-based event definitions
//! - [`TrendLog`](ObjectType::TrendLog): Historical data logging
//!
//! # Property System
//!
//! Properties are the attributes that describe an object's state and behavior. Common properties include:
//!
//! - **Present Value**: The current value or state of the object
//! - **Object Name**: A human-readable name for the object
//! - **Description**: Additional descriptive text
//! - **Units**: Engineering units for analog values
//! - **Reliability**: Indicates if the value is reliable
//!
//! # Examples
//!
//! ## Creating Object Identifiers
//!
//! ```rust
//! use bacnet_rs::object::{ObjectIdentifier, ObjectType};
//!
//! // Create an object identifier for analog input #1
//! let temp_sensor = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
//! assert_eq!(temp_sensor.object_type, ObjectType::AnalogInput);
//! assert_eq!(temp_sensor.instance, 1);
//!
//! // Create device object (instance 123456)
//! let device = ObjectIdentifier::new(ObjectType::Device, 123456);
//! assert!(device.is_valid());
//! ```
//!
//! ## Working with Properties
//!
//! ```rust
//! use bacnet_rs::object::{PropertyIdentifier, PropertyValue};
//!
//! // Property identifiers for common properties
//! let present_value = PropertyIdentifier::PresentValue;
//! let object_name = PropertyIdentifier::ObjectName;
//! let units = PropertyIdentifier::OutputUnits;
//!
//! // Property values can represent different data types
//! let temperature = PropertyValue::Real(23.5);
//! let name = PropertyValue::CharacterString("Temperature Sensor".to_string());
//! let unit_enum = PropertyValue::Enumerated(64); // Degrees Celsius
//! ```
//!
//! ## Object Database Usage
//!
//! ```rust,no_run
//! use bacnet_rs::object::{database::ObjectDatabase, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue, analog::AnalogInput, Device};
//!
//! // Create a device and object database
//! let device = Device::new(12345, "BACnet Device".to_string());
//! let mut db = ObjectDatabase::new(device);
//!
//! // Create an analog input object
//! let mut ai = AnalogInput::new(1, "Room Temperature".to_string());
//! ai.set_present_value(23.5);
//! let obj_id = ai.identifier;
//!
//! // Add the object to the database
//! db.add_object(Box::new(ai)).expect("Failed to add object");
//!
//! // Set properties
//! db.set_property(obj_id, PropertyIdentifier::ObjectName,
//!     PropertyValue::CharacterString("Room Temperature".to_string()))
//!     .expect("Failed to set property");
//!
//! // Read properties
//! let name = db.get_property(obj_id, PropertyIdentifier::ObjectName)
//!     .expect("Property not found");
//! ```
//!
//! # Standards Compliance
//!
//! This implementation follows ASHRAE Standard 135-2020 and includes:
//!
//! - All standard object types defined in the specification
//! - Complete property identifier enumeration
//! - Proper object identifier encoding/decoding
//! - Thread-safe object database implementation

use bitflags::bitflags;
use core::fmt::Display;
#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// Result type for object operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, ObjectError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, ObjectError>;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::property::{BacnetValue, PropertyValue};

/// Errors that can occur with object operations
#[derive(Debug)]
pub enum ObjectError {
    /// Object not found
    NotFound,
    /// Object instance not found
    InstanceNotFound,
    /// Object type not supported
    TypeNotSupported,
    /// Property not found
    PropertyNotFound,
    /// Unknown property
    UnknownProperty,
    /// Property not writable
    PropertyNotWritable,
    /// An array index was used with a property that is not an array.
    PropertyIsNotArray,
    /// An array index was outside the property's bounds.
    InvalidArrayIndex,
    /// The requested optional behavior is not implemented.
    OptionalFunctionalityNotSupported,
    /// Invalid property type
    InvalidPropertyType,
    /// Invalid property value
    InvalidValue(String),
    /// Write access denied
    WriteAccessDenied,
    /// Invalid object configuration
    InvalidConfiguration(String),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectError::NotFound => write!(f, "Object not found"),
            ObjectError::InstanceNotFound => write!(f, "Object instance not found"),
            ObjectError::TypeNotSupported => write!(f, "Object type not supported"),
            ObjectError::PropertyNotFound => write!(f, "Property not found"),
            ObjectError::UnknownProperty => write!(f, "Unknown property"),
            ObjectError::PropertyNotWritable => write!(f, "Property not writable"),
            ObjectError::PropertyIsNotArray => write!(f, "Property is not an array"),
            ObjectError::InvalidArrayIndex => write!(f, "Invalid array index"),
            ObjectError::OptionalFunctionalityNotSupported => {
                write!(f, "Optional functionality not supported")
            }
            ObjectError::InvalidPropertyType => write!(f, "Invalid property type"),
            ObjectError::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
            ObjectError::WriteAccessDenied => write!(f, "Write access denied"),
            ObjectError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl Error for ObjectError {}

/// Object identifier (type + instance number)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier {
    pub object_type: ObjectType,
    pub instance: u32,
}

impl ObjectIdentifier {
    /// Create a new object identifier
    pub fn new(object_type: ObjectType, instance: u32) -> Self {
        Self {
            object_type,
            instance,
        }
    }

    /// Check if instance number is valid (0-4194302)
    pub fn is_valid(&self) -> bool {
        self.instance <= 0x3FFFFF
    }
}

impl From<u32> for ObjectIdentifier {
    /// Convert from 32-bit object identifier.
    /// See clause 20.2.14 of the BACnet specification.
    fn from(value: u32) -> Self {
        let object_type = (value >> 22) & 0x3FF;
        let object_type = object_type.into();
        let instance = value & 0x3FFFFF;
        Self::new(object_type, instance)
    }
}

impl TryFrom<ObjectIdentifier> for u32 {
    type Error = EncodingError;

    fn try_from(value: ObjectIdentifier) -> std::result::Result<Self, Self::Error> {
        let object_type: u32 = value.object_type.into();

        if object_type > 0x3FF || value.instance > 0x3FFFFF {
            Err(EncodingError::ValueOutOfRange)
        } else {
            Ok((object_type << 22) | (value.instance & 0x3FFFFF))
        }
    }
}

/// Trait for all BACnet objects
pub trait BacnetObject: Send + Sync {
    /// Get the object identifier
    fn identifier(&self) -> ObjectIdentifier;

    /// Get a property value
    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue>;

    /// Set a property value
    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()>;

    /// Set a property with the optional BACnet command priority supplied by a
    /// WriteProperty request.
    fn set_property_with_priority(
        &mut self,
        property: PropertyIdentifier,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<()> {
        self.set_property(property, value)
    }

    /// Check if property is writable
    fn is_property_writable(&self, property: PropertyIdentifier) -> bool;

    /// Get list of all properties
    fn property_list(&self) -> Vec<PropertyIdentifier>;

    /// The object's intrinsic reporting state, when event detection is configured.
    ///
    /// Objects that do not participate in alarming keep the default `None`.
    fn intrinsic(&self) -> Option<&intrinsic::IntrinsicReporting> {
        None
    }

    /// Mutable access to the intrinsic reporting state, for transition bookkeeping.
    fn intrinsic_mut(&mut self) -> Option<&mut intrinsic::IntrinsicReporting> {
        None
    }

    /// Run this object's event algorithm against its current value.
    ///
    /// Returns `None` when the object has no event detection configured.
    fn evaluate_alarm(&self) -> Option<intrinsic::AlarmEvaluation> {
        None
    }

    /// Commit a confirmed transition, updating Event_State and Status_Flags.
    fn apply_event_state(&mut self, _state: EventState) {}

    /// Set the value this object reflects from whatever drives it.
    ///
    /// This is the hosting application's path, not the network's, and it
    /// deliberately bypasses [`is_property_writable`](Self::is_property_writable).
    /// An Analog Input's Present_Value is read-only to clients precisely because
    /// it belongs to the sensor behind it — but something has to be able to say
    /// what the sensor reads, and for a hosted device that is the application.
    /// bacnet-stack draws the same line with its `*_Present_Value_Set` entry
    /// points.
    ///
    /// Objects with nothing behind them keep the default and report the write as
    /// unsupported.
    fn set_sourced_value(&mut self, _value: PropertyValue) -> Result<()> {
        Err(ObjectError::OptionalFunctionalityNotSupported)
    }

    /// Whether the object is decoupled from its physical point.
    fn is_out_of_service(&self) -> bool {
        false
    }
}

/// Update one slot in a BACnet command priority array and return the resulting
/// effective value. Priority 1 is the highest; the relinquish default is used
/// when every slot is null.
pub(crate) fn write_priority_slot<T: Copy>(
    priority_array: &mut [Option<T>; 16],
    priority: u8,
    value: Option<T>,
    relinquish_default: T,
) -> Result<T> {
    if !(1..=16).contains(&priority) {
        return Err(ObjectError::InvalidValue(
            "Priority must be 1-16".to_string(),
        ));
    }

    priority_array[usize::from(priority - 1)] = value;
    Ok(priority_array
        .iter()
        .flatten()
        .next()
        .copied()
        .unwrap_or(relinquish_default))
}

/// BACnet date representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub year: u16,   // 1900-2155, 255 = unspecified
    pub month: u8,   // 1-12, 13 = odd months, 14 = even months, 255 = unspecified
    pub day: u8,     // 1-31, 32 = last day of month, 255 = unspecified
    pub weekday: u8, // 1-7 (Mon-Sun), 255 = unspecified
}

/// BACnet time representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    pub hour: u8,       // 0-23, 255 = unspecified
    pub minute: u8,     // 0-59, 255 = unspecified
    pub second: u8,     // 0-59, 255 = unspecified
    pub hundredths: u8, // 0-99, 255 = unspecified
}

/// Device object implementation
#[derive(Debug, Clone)]
pub struct Device {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name (required property)
    pub object_name: String,
    /// Object type (always Device)
    pub object_type: ObjectType,
    /// System status
    pub system_status: DeviceStatus,
    /// Vendor name
    pub vendor_name: String,
    /// Vendor identifier
    pub vendor_identifier: u16,
    /// Model name
    pub model_name: String,
    /// Firmware revision
    pub firmware_revision: String,
    /// Application software version
    pub application_software_version: String,
    /// Protocol version (always 1)
    pub protocol_version: u8,
    /// Protocol revision
    pub protocol_revision: u8,
    /// Protocol services supported
    pub protocol_services_supported: ProtocolServicesSupported,
    /// Object types supported
    pub object_types_supported: Vec<ObjectType>,
    /// Maximum APDU length accepted
    pub max_apdu_length_accepted: u16,
    /// Segmentation support
    pub segmentation_supported: Segmentation,
    /// APDU response timeout in milliseconds
    pub apdu_timeout: u32,
    /// Number of APDU retries
    pub number_of_apdu_retries: u8,
    /// Device address binding (for routing)
    pub device_address_binding: Vec<AddressBinding>,
    /// Database revision
    pub database_revision: u32,
}

impl Device {
    /// Create a new Device object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::Device, instance),
            object_name,
            object_type: ObjectType::Device,
            system_status: DeviceStatus::Operational,
            vendor_name: String::from("BACnet-RS"),
            vendor_identifier: 999, // Reserved for ASHRAE - appropriate for open-source implementations
            model_name: String::from("Rust BACnet Device"),
            firmware_revision: String::from("1.0.0"),
            application_software_version: String::from(env!("CARGO_PKG_VERSION")),
            protocol_version: 1,
            protocol_revision: 22, // Current BACnet protocol revision
            protocol_services_supported: ProtocolServicesSupported::hosted_object_services(),
            object_types_supported: vec![ObjectType::Device],
            max_apdu_length_accepted: 1476,
            segmentation_supported: Segmentation::NoSegmentation,
            apdu_timeout: 3_000,
            number_of_apdu_retries: 3,
            device_address_binding: Vec::new(),
            database_revision: 1,
        }
    }

    /// Add an object type to the supported list
    pub fn add_supported_object_type(&mut self, object_type: ObjectType) {
        if !self.object_types_supported.contains(&object_type) {
            self.object_types_supported.push(object_type);
        }
    }

    /// Get the vendor information for this device
    pub fn get_vendor_info(&self) -> Option<crate::vendor::VendorInfo> {
        crate::vendor::get_vendor_info(self.vendor_identifier)
    }

    /// Get the official vendor name from the vendor ID
    pub fn get_official_vendor_name(&self) -> Option<&'static str> {
        crate::vendor::get_vendor_name(self.vendor_identifier)
    }

    /// Set vendor information using an official vendor ID
    pub fn set_vendor_by_id(&mut self, vendor_id: u16) -> Result<()> {
        if let Some(vendor_info) = crate::vendor::get_vendor_info(vendor_id) {
            self.vendor_identifier = vendor_id;
            self.vendor_name = vendor_info.name.to_string();
            Ok(())
        } else {
            Err(ObjectError::InvalidPropertyType)
        }
    }

    /// Set vendor information with custom name (preserves vendor ID)
    pub fn set_vendor_name(&mut self, name: String) {
        self.vendor_name = name;
    }

    /// Check if the current vendor ID is officially assigned
    pub fn is_vendor_id_official(&self) -> bool {
        crate::vendor::is_vendor_id_assigned(self.vendor_identifier)
            && !crate::vendor::is_vendor_id_reserved(self.vendor_identifier)
    }

    /// Check if the current vendor ID is reserved for testing
    pub fn is_vendor_id_test(&self) -> bool {
        crate::vendor::is_vendor_id_reserved(self.vendor_identifier)
    }

    /// Get a formatted string showing vendor information
    pub fn format_vendor_display(&self) -> String {
        crate::vendor::format_vendor_display(self.vendor_identifier)
    }
}

impl BacnetObject for Device {
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
                Ok(PropertyValue::Enumerated(u32::from(self.object_type)))
            }
            PropertyIdentifier::SystemStatus => {
                Ok(PropertyValue::Enumerated(self.system_status as u32))
            }
            PropertyIdentifier::VendorName => {
                Ok(PropertyValue::CharacterString(self.vendor_name.clone()))
            }
            PropertyIdentifier::VendorIdentifier => {
                Ok(PropertyValue::Unsigned(self.vendor_identifier.into()))
            }
            PropertyIdentifier::ModelName => {
                Ok(PropertyValue::CharacterString(self.model_name.clone()))
            }
            PropertyIdentifier::FirmwareRevision => Ok(PropertyValue::CharacterString(
                self.firmware_revision.clone(),
            )),
            PropertyIdentifier::ApplicationSoftwareVersion => Ok(PropertyValue::CharacterString(
                self.application_software_version.clone(),
            )),
            PropertyIdentifier::ProtocolVersion => {
                Ok(PropertyValue::Unsigned(self.protocol_version.into()))
            }
            PropertyIdentifier::ProtocolRevision => {
                Ok(PropertyValue::Unsigned(self.protocol_revision.into()))
            }
            PropertyIdentifier::ProtocolServicesSupported => Ok(PropertyValue::BitString(
                self.protocol_services_supported
                    .to_bool_vec_for_revision(self.protocol_revision),
            )),
            PropertyIdentifier::ProtocolObjectTypesSupported => {
                Ok(PropertyValue::BitString(object_types_supported_bit_string(
                    &self.object_types_supported,
                    self.protocol_revision,
                )))
            }
            PropertyIdentifier::MaxApduLengthAccepted => Ok(PropertyValue::Unsigned(
                self.max_apdu_length_accepted.into(),
            )),
            PropertyIdentifier::SegmentationSupported => Ok(PropertyValue::Enumerated(
                self.segmentation_supported as u32,
            )),
            PropertyIdentifier::ApduTimeout => {
                Ok(PropertyValue::Unsigned(self.apdu_timeout.into()))
            }
            PropertyIdentifier::NumberOfApduRetries => {
                Ok(PropertyValue::Unsigned(self.number_of_apdu_retries.into()))
            }
            PropertyIdentifier::DeviceAddressBinding => Ok(PropertyValue::List(
                self.device_address_binding
                    .iter()
                    .map(|binding| {
                        PropertyValue::AddressBinding(crate::property::AddressBindingValue {
                            device_identifier: binding.device_identifier,
                            address: crate::property::BacnetAddress {
                                network: binding.network_number,
                                mac_address: binding.mac_address.clone(),
                            },
                        })
                    })
                    .collect(),
            )),
            PropertyIdentifier::DatabaseRevision => {
                Ok(PropertyValue::Unsigned(self.database_revision.into()))
            }
            _ => Err(ObjectError::UnknownProperty),
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
            PropertyIdentifier::ApduTimeout => {
                if let PropertyValue::Unsigned(timeout) = value {
                    self.apdu_timeout = timeout
                        .try_into()
                        .map_err(|_| ObjectError::InvalidPropertyType)?;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::NumberOfApduRetries => {
                if let PropertyValue::Unsigned(retries) = value {
                    self.number_of_apdu_retries = retries
                        .try_into()
                        .map_err(|_| ObjectError::InvalidPropertyType)?;
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
                | PropertyIdentifier::ApduTimeout
                | PropertyIdentifier::NumberOfApduRetries
        )
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::SystemStatus,
            PropertyIdentifier::VendorName,
            PropertyIdentifier::VendorIdentifier,
            PropertyIdentifier::ModelName,
            PropertyIdentifier::FirmwareRevision,
            PropertyIdentifier::ApplicationSoftwareVersion,
            PropertyIdentifier::ProtocolVersion,
            PropertyIdentifier::ProtocolRevision,
            PropertyIdentifier::ProtocolServicesSupported,
            PropertyIdentifier::ProtocolObjectTypesSupported,
            PropertyIdentifier::MaxApduLengthAccepted,
            PropertyIdentifier::SegmentationSupported,
            PropertyIdentifier::ApduTimeout,
            PropertyIdentifier::NumberOfApduRetries,
            PropertyIdentifier::DeviceAddressBinding,
            PropertyIdentifier::DatabaseRevision,
        ]
    }
}

/// Device status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceStatus {
    Operational = 0,
    OperationalReadOnly = 1,
    DownloadRequired = 2,
    DownloadInProgress = 3,
    NonOperational = 4,
    BackupInProgress = 5,
}

/// Segmentation support enumeration
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Segmentation {
    Both = 0,
    Transmit = 1,
    Receive = 2,
    NoSegmentation = 3,
}

impl TryFrom<u32> for Segmentation {
    type Error = ObjectError;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Both),
            1 => Ok(Self::Transmit),
            2 => Ok(Self::Receive),
            3 => Ok(Self::NoSegmentation),
            _ => Err(ObjectError::InvalidConfiguration(format!(
                "Unknown segmentation: {}",
                value
            ))),
        }
    }
}

impl Display for Segmentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Both => write!(f, "Both"),
            Self::Transmit => write!(f, "Transmit"),
            Self::Receive => write!(f, "Receive"),
            Self::NoSegmentation => write!(f, "None"),
        }
    }
}

bitflags! {
    /// Protocol services supported bitfield
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, Clone, Default, Eq, PartialEq)]
    pub struct ProtocolServicesSupported: u64 {
        const ACKNOWLEDGE_ALARM = 1 << 0;
        const CONFIRMED_COV_NOTIFICATION = 1 << 1;
        const CONFIRMED_EVENT_NOTIFICATION = 1 << 2;
        const GET_ALARM_SUMMARY = 1 << 3;
        const GET_ENROLLMENT_SUMMARY = 1 << 4;
        const SUBSCRIBE_COV = 1 << 5;
        const ATOMIC_READ_FILE = 1 << 6;
        const ATOMIC_WRITE_FILE = 1 << 7;
        const ADD_LIST_ELEMENT = 1 << 8;
        const REMOVE_LIST_ELEMENT = 1 << 9;
        const CREATE_OBJECT = 1 << 10;
        const DELETE_OBJECT = 1 << 11;
        const READ_PROPERTY = 1 << 12;
        const READ_PROPERTY_CONDITIONAL = 1 << 13;
        const READ_PROPERTY_MULTIPLE = 1 << 14;
        const WRITE_PROPERTY = 1 << 15;
        const WRITE_PROPERTY_MULTIPLE = 1 << 16;
        const DEVICE_COMMUNICATION_CONTROL = 1 << 17;
        const CONFIRMED_PRIVATE_TRANSFER = 1 << 18;
        const CONFIRMED_TEXT_MESSAGE = 1 << 19;
        const REINITIALIZE_DEVICE = 1 << 20;
        const VT_OPEN = 1 << 21;
        const VT_CLOSE = 1 << 22;
        const VT_DATA = 1 << 23;
        const AUTHENTICATE = 1 << 24;
        const REQUEST_KEY = 1 << 25;
        const I_AM = 1 << 26;
        const I_HAVE = 1 << 27;
        const UNCONFIRMED_COV_NOTIFICATION = 1 << 28;
        const UNCONFIRMED_EVENT_NOTIFICATION = 1 << 29;
        const UNCONFIRMED_PRIVATE_TRANSFER = 1 << 30;
        const UNCONFIRMED_TEXT_MESSAGE = 1 << 31;
        const TIME_SYNCHRONIZATION = 1 << 32;
        const WHO_HAS = 1 << 33;
        const WHO_IS = 1 << 34;
        const READ_RANGE = 1 << 35;
        const UTC_TIME_SYNCHRONIZATION = 1 << 36;
        const LIFE_SAFETY_OPERATION = 1 << 37;
        const SUBSCRIBE_COV_PROPERTY = 1 << 38;
        const GET_EVENT_INFORMATION = 1 << 39;
        const WRITE_GROUP = 1 << 40;
        const SUBSCRIBE_COV_PROPERTY_MULTIPLE = 1 << 41;
        const CONFIRMED_COV_NOTIFICATION_MULTIPLE = 1 << 42;
        const UNCONFIRMED_COV_NOTIFICATION_MULTIPLE = 1 << 43;
        const CONFIRMED_AUDIT_NOTIFICATION = 1 << 44;
        const AUDIT_LOG_QUERY = 1 << 45;
        const UNCONFIRMED_AUDIT_NOTIFICATION = 1 << 46;
        const WHO_AM_I = 1 << 47;
        const YOU_ARE = 1 << 48;
        const AUTH_REQUEST = 1 << 49;
    }
}

impl ProtocolServicesSupported {
    /// Services executed by the hosted object server.
    pub fn hosted_object_services() -> Self {
        Self::READ_PROPERTY
            | Self::READ_PROPERTY_MULTIPLE
            | Self::WRITE_PROPERTY
            | Self::I_AM
            | Self::WHO_IS
    }

    pub fn to_bool_vec(&self) -> Vec<bool> {
        self.to_bool_vec_with_len(50)
    }

    /// Encode only the service bits defined by the advertised protocol revision.
    pub fn to_bool_vec_for_revision(&self, protocol_revision: u8) -> Vec<bool> {
        self.to_bool_vec_with_len(protocol_service_bit_count(protocol_revision))
    }

    fn to_bool_vec_with_len(&self, bit_count: usize) -> Vec<bool> {
        (0..bit_count)
            .map(|bit| (self.bits() & (1_u64 << bit)) != 0)
            .collect()
    }
}

impl From<Vec<bool>> for ProtocolServicesSupported {
    fn from(value: Vec<bool>) -> Self {
        let bits = value
            .into_iter()
            .take(50)
            .enumerate()
            .fold(0_u64, |bits, (index, enabled)| {
                bits | (u64::from(enabled) << index)
            });
        ProtocolServicesSupported::from_bits_retain(bits)
    }
}

/// Number of service bits defined by each BACnet protocol revision.
pub fn protocol_service_bit_count(protocol_revision: u8) -> usize {
    match protocol_revision {
        0 => 35,
        1 => 37,
        2..=13 => 40,
        14..=17 => 41,
        18..=19 => 44,
        20..=23 => 47,
        24..=28 => 49,
        _ => 50,
    }
}

/// Build the Protocol_Object_Types_Supported bit string for a device.
pub fn object_types_supported_bit_string(
    object_types: &[ObjectType],
    protocol_revision: u8,
) -> Vec<bool> {
    let bit_count = protocol_object_type_bit_count(protocol_revision);
    let mut bits = vec![false; bit_count];
    for object_type in object_types {
        let index = u32::from(*object_type) as usize;
        if let Some(bit) = bits.get_mut(index) {
            *bit = true;
        }
    }
    bits
}

/// Number of standard object-type bits defined by each protocol revision.
pub fn protocol_object_type_bit_count(protocol_revision: u8) -> usize {
    match protocol_revision {
        0 => 18,
        1 => 21,
        2..=3 => 23,
        4 => 25,
        5 => 30,
        6..=8 => 31,
        9 => 38,
        10..=12 => 51,
        13 => 53,
        14..=15 => 55,
        16 => 56,
        17 => 57,
        18..=19 => 60,
        20..=23 => 63,
        _ => 65,
    }
}

/// Address binding for device routing
#[derive(Debug, Clone)]
pub struct AddressBinding {
    pub device_identifier: ObjectIdentifier,
    pub network_number: u16,
    pub mac_address: Vec<u8>,
}

/// Analog object types (AI, AO, AV)
pub mod analog;
/// Binary object types (BI, BO, BV)
pub mod binary;
/// Object database for managing BACnet objects
#[cfg(feature = "std")]
pub mod database;
/// Device object and object functions API
pub mod device;
/// Engineering units enumeration
pub mod engineering_units;
/// File object type
pub mod file;
/// Intrinsic reporting (alarm and event) state shared by alarm-capable objects
pub mod intrinsic;
/// Multi-state object types (MSI, MSO, MSV)
pub mod multistate;
/// Notification Class object type
pub mod notification_class;

pub mod event_state;
pub mod object_type;
pub mod reliability;
pub use object_type::ObjectType;
pub mod property_identifier;
pub use property_identifier::PropertyIdentifier;

pub use analog::{AnalogInput, AnalogOutput, AnalogValue};
pub use binary::{BinaryInput, BinaryOutput, BinaryPV, BinaryValue, Polarity};
pub use device::{DeviceObject, ObjectFunctions};
pub use engineering_units::EngineeringUnits;
pub use event_state::EventState;
pub use file::{File, FileAccessMethod};
pub use intrinsic::{
    EventTransition, EventTransitionBits, IntrinsicReporting, NotifyType, UNSPECIFIED_TIMESTAMP,
};
pub use multistate::{MultiStateInput, MultiStateOutput, MultiStateValue};
pub use notification_class::NotificationClass;
pub use reliability::Reliability;

#[cfg(feature = "std")]
pub use database::{DatabaseBuilder, DatabaseStatistics, ObjectDatabase};

use crate::EncodingError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_creation() {
        let device = Device::new(123, "Test Device".to_string());
        assert_eq!(device.identifier.instance, 123);
        assert_eq!(device.object_name, "Test Device");
        assert_eq!(device.object_type, ObjectType::Device);
    }

    #[test]
    fn test_device_properties() {
        let mut device = Device::new(456, "Property Test".to_string());

        // Test getting properties
        let name = device.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Property Test");
        } else {
            panic!("Expected CharacterString");
        }

        // Test setting properties
        device
            .set_property(
                PropertyIdentifier::ObjectName,
                PropertyValue::CharacterString("New Name".to_string()),
            )
            .unwrap();

        let name = device.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "New Name");
        } else {
            panic!("Expected CharacterString");
        }

        assert_eq!(
            device
                .get_property(PropertyIdentifier::ApduTimeout)
                .unwrap(),
            PropertyValue::Unsigned(3_000)
        );
        assert_eq!(
            device
                .get_property(PropertyIdentifier::NumberOfApduRetries)
                .unwrap(),
            PropertyValue::Unsigned(3)
        );
        assert_eq!(
            device
                .get_property(PropertyIdentifier::DeviceAddressBinding)
                .unwrap(),
            PropertyValue::List(Vec::new())
        );
        assert!(!device.is_property_writable(PropertyIdentifier::DatabaseRevision));
        assert!(matches!(
            device.set_property(
                PropertyIdentifier::DatabaseRevision,
                PropertyValue::Unsigned(42)
            ),
            Err(ObjectError::PropertyNotWritable)
        ));
    }

    #[test]
    fn test_protocol_services_supported() {
        let services = ProtocolServicesSupported::ACKNOWLEDGE_ALARM
            | ProtocolServicesSupported::READ_PROPERTY
            | ProtocolServicesSupported::WRITE_PROPERTY;

        let bools = services.to_bool_vec();
        let services_new = ProtocolServicesSupported::from(bools);
        assert_eq!(services, services_new);
    }

    #[test]
    fn hosted_device_capabilities_match_protocol_revision_22() {
        let device = Device::new(123, "Test Device".to_string());

        let PropertyValue::BitString(services) = device
            .get_property(PropertyIdentifier::ProtocolServicesSupported)
            .unwrap()
        else {
            panic!("expected protocol services bit string")
        };
        assert_eq!(services.len(), 47);
        assert_eq!(
            services
                .iter()
                .enumerate()
                .filter_map(|(index, enabled)| enabled.then_some(index))
                .collect::<Vec<_>>(),
            vec![12, 14, 15, 26, 34]
        );

        let PropertyValue::BitString(object_types) = device
            .get_property(PropertyIdentifier::ProtocolObjectTypesSupported)
            .unwrap()
        else {
            panic!("expected protocol object types bit string")
        };
        assert_eq!(object_types.len(), 63);
        assert!(object_types[u32::from(ObjectType::Device) as usize]);
        assert_eq!(device.segmentation_supported, Segmentation::NoSegmentation);
    }

    #[test]
    fn device_address_binding_encodes_nonempty_bindings() {
        let mut device = Device::new(123, "Test Device".to_string());
        let remote_device = ObjectIdentifier::new(ObjectType::Device, 456);
        device.device_address_binding.push(AddressBinding {
            device_identifier: remote_device,
            network_number: 416,
            mac_address: vec![192, 168, 1, 10, 0xBA, 0xC0],
        });

        assert_eq!(
            device
                .get_property(PropertyIdentifier::DeviceAddressBinding)
                .unwrap(),
            PropertyValue::List(vec![PropertyValue::AddressBinding(
                crate::property::AddressBindingValue {
                    device_identifier: remote_device,
                    address: crate::property::BacnetAddress {
                        network: 416,
                        mac_address: vec![192, 168, 1, 10, 0xBA, 0xC0],
                    },
                }
            )])
        );
    }
}
