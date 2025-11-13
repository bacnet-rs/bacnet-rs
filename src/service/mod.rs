//! BACnet Application Layer Services
//!
//! This module implements BACnet application layer services as defined in ASHRAE Standard 135.
//! Services are the fundamental communication primitives that enable devices to interact in a
//! BACnet network, providing standardized operations for reading data, writing values, receiving
//! notifications, and managing devices.
//!
//! # Overview
//!
//! BACnet services define the application-level protocols for device communication. They abstract
//! the underlying network complexity and provide a consistent interface for building automation
//! operations. Each service defines:
//!
//! - **Request Structure**: Parameters needed to invoke the service
//! - **Response Structure**: Data returned by the service
//! - **Error Handling**: Standardized error codes and descriptions
//! - **Encoding Rules**: How requests and responses are serialized
//!
//! # Service Categories
//!
//! BACnet services are organized into functional groups:
//!
//! ## Alarm and Event Services
//! Handle alarm conditions and event notifications:
//! - **AcknowledgeAlarm**: Acknowledge alarm conditions
//! - **ConfirmedEventNotification**: Reliable event notifications
//! - **UnconfirmedEventNotification**: Best-effort event notifications
//! - **GetAlarmSummary**: Retrieve active alarms
//! - **GetEventInformation**: Get detailed event information
//!
//! ## File Access Services
//! Provide file system operations for devices that support file access:
//! - **AtomicReadFile**: Read file contents atomically
//! - **AtomicWriteFile**: Write file contents atomically
//! - **CreateObject**: Create new objects (including file objects)
//! - **DeleteObject**: Remove objects from the device
//!
//! ## Object Access Services
//! Core services for reading and writing object properties:
//! - **ReadProperty**: Read a single property value
//! - **ReadPropertyMultiple**: Read multiple properties efficiently
//! - **WriteProperty**: Write a single property value
//! - **WritePropertyMultiple**: Write multiple properties efficiently
//!
//! ## Remote Device Management Services
//! Enable device configuration and management:
//! - **DeviceCommunicationControl**: Enable/disable device communication
//! - **ConfirmedPrivateTransfer**: Vendor-specific communications
//! - **UnconfirmedPrivateTransfer**: Vendor-specific notifications
//! - **ReinitializeDevice**: Restart or reconfigure devices
//!
//! ## Virtual Terminal Services
//! Support text-based terminal access:
//! - **VTOpen**: Open virtual terminal session
//! - **VTClose**: Close virtual terminal session
//! - **VTData**: Exchange terminal data
//!
//! ## Remote Device Discovery
//! Services for network discovery and device identification:
//! - **WhoIs**: Discover devices on the network
//! - **IHave**: Announce object availability
//! - **WhoHas**: Search for specific objects
//! - **IAm**: Device identification response
//!
//! # Service Types
//!
//! BACnet services are classified by their reliability requirements:
//!
//! ## Confirmed Services
//! These services require acknowledgment from the recipient and provide reliable delivery:
//! - Use sequence numbers for duplicate detection
//! - Support segmentation for large messages
//! - Provide error responses for failed operations
//! - Include timeout and retry mechanisms
//!
//! ## Unconfirmed Services  
//! These services are "fire-and-forget" with no acknowledgment:
//! - Lower overhead and faster transmission
//! - No delivery guarantee
//! - Suitable for periodic updates and notifications
//! - No error reporting mechanism
//!
//! # Examples
//!
//! ## Reading a Property
//!
//! ```rust
//! use bacnet_rs::service::{ConfirmedServiceChoice, ReadPropertyRequest};
//! use bacnet_rs::object::{ObjectIdentifier, ObjectType, PropertyIdentifier};
//!
//! // Create a read property request
//! let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
//! let request = ReadPropertyRequest::new(object_id, PropertyIdentifier::PresentValue.into());
//!
//! // This would be sent as a confirmed service
//! let service_choice = ConfirmedServiceChoice::ReadProperty;
//! ```
//!
//! ## Device Discovery
//!
//! ```rust
//! use bacnet_rs::service::{UnconfirmedServiceChoice, WhoIsRequest};
//!
//! // Create a Who-Is request to discover all devices
//! let who_is = WhoIsRequest::new();
//!
//! // This would be sent as an unconfirmed service
//! let service_choice = UnconfirmedServiceChoice::WhoIs;
//! ```
//!
//! ## Reading Multiple Properties
//!
//! ```rust
//! use bacnet_rs::service::{ConfirmedServiceChoice, ReadPropertyMultipleRequest, ReadAccessSpecification, PropertyReference};
//! use bacnet_rs::object::{ObjectIdentifier, ObjectType, PropertyIdentifier};
//!
//! // Create a read property multiple request
//! let object_id = ObjectIdentifier::new(ObjectType::Device, 12345);
//! let property_refs = vec![
//!     PropertyReference::new(PropertyIdentifier::ObjectName.into()),
//!     PropertyReference::new(70), // ModelName
//!     PropertyReference::new(PropertyIdentifier::VendorName.into()),
//! ];
//! let spec = ReadAccessSpecification::new(object_id, property_refs);
//!
//! let request = ReadPropertyMultipleRequest::new(vec![spec]);
//!
//! let service_choice = ConfirmedServiceChoice::ReadPropertyMultiple;
//! ```
//!
//! # Error Handling
//!
//! Services can fail for various reasons, and BACnet defines standardized error responses:
//!
//! ```rust
//! use bacnet_rs::service::ServiceError;
//!
//! // Example error handling
//! let error = ServiceError::InvalidParameters("Missing required property".to_string());
//!
//! match error {
//!     ServiceError::UnsupportedService => println!("Service not supported"),
//!     ServiceError::InvalidParameters(msg) => println!("Invalid parameters: {}", msg),
//!     ServiceError::Timeout => println!("Request timed out"),
//!     ServiceError::EncodingError(msg) => println!("Encoding error: {}", msg),
//!     _ => println!("Other error: {:?}", error),
//! }
//! ```
//!
//! # Protocol Integration
//!
//! Services integrate with the lower protocol layers:
//!
//! 1. **Application Layer**: Services define the high-level operations
//! 2. **Transport Layer**: Handles reliability, segmentation, and flow control
//! 3. **Network Layer**: Provides routing and addressing
//! 4. **Data Link Layer**: Manages frame transmission and media access
//!
//! This layered approach allows services to work across different network types
//! and provides a consistent programming interface regardless of the underlying
//! communication technology.

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

/// Result type for service operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, ServiceError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, ServiceError>;

/// Errors that can occur during service operations
#[derive(Debug)]
pub enum ServiceError {
    /// Service is not supported
    UnsupportedService,
    /// Invalid service parameters
    InvalidParameters(String),
    /// Service timeout
    Timeout,
    /// Service rejected by remote device
    Rejected(RejectReason),
    /// Service aborted by remote device
    Aborted(AbortReason),
    /// Encoding/decoding error
    EncodingError(String),
    /// Unsupported service choice
    UnsupportedServiceChoice(u8),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::UnsupportedService => write!(f, "Service not supported"),
            ServiceError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            ServiceError::Timeout => write!(f, "Service timeout"),
            ServiceError::Rejected(reason) => write!(f, "Service rejected: {:?}", reason),
            ServiceError::Aborted(reason) => write!(f, "Service aborted: {:?}", reason),
            ServiceError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            ServiceError::UnsupportedServiceChoice(choice) => {
                write!(f, "Unsupported service choice: {}", choice)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for ServiceError {}

/// Confirmed service choices
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfirmedServiceChoice {
    // Alarm and Event Services
    AcknowledgeAlarm = 0,
    ConfirmedEventNotification = 2,
    GetAlarmSummary = 3,
    GetEnrollmentSummary = 4,
    GetEventInformation = 29,

    // File Access Services
    AtomicReadFile = 6,
    AtomicWriteFile = 7,

    // Object Access Services
    AddListElement = 8,
    RemoveListElement = 9,
    CreateObject = 10,
    DeleteObject = 11,
    ReadProperty = 12,
    ReadPropertyMultiple = 14,
    WriteProperty = 15,
    WritePropertyMultiple = 16,

    // Remote Device Management Services
    DeviceCommunicationControl = 17,
    ReinitializeDevice = 20,

    // Virtual Terminal Services
    VtOpen = 21,
    VtClose = 22,
    VtData = 23,

    // Security Services
    Authenticate = 24,
    RequestKey = 25,

    // Other Services
    ReadRange = 26,
    SubscribeCOV = 5,
    SubscribeCOVProperty = 28,

    // Protocol Revision 30 - Security Services
    AuthRequest = 34,
}

impl TryFrom<u8> for ConfirmedServiceChoice {
    type Error = ServiceError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::AcknowledgeAlarm),
            2 => Ok(Self::ConfirmedEventNotification),
            3 => Ok(Self::GetAlarmSummary),
            4 => Ok(Self::GetEnrollmentSummary),
            29 => Ok(Self::GetEventInformation),
            6 => Ok(Self::AtomicReadFile),
            7 => Ok(Self::AtomicWriteFile),
            8 => Ok(Self::AddListElement),
            9 => Ok(Self::RemoveListElement),
            10 => Ok(Self::CreateObject),
            11 => Ok(Self::DeleteObject),
            12 => Ok(Self::ReadProperty),
            14 => Ok(Self::ReadPropertyMultiple),
            15 => Ok(Self::WriteProperty),
            16 => Ok(Self::WritePropertyMultiple),
            17 => Ok(Self::DeviceCommunicationControl),
            20 => Ok(Self::ReinitializeDevice),
            21 => Ok(Self::VtOpen),
            22 => Ok(Self::VtClose),
            23 => Ok(Self::VtData),
            24 => Ok(Self::Authenticate),
            25 => Ok(Self::RequestKey),
            26 => Ok(Self::ReadRange),
            5 => Ok(Self::SubscribeCOV),
            28 => Ok(Self::SubscribeCOVProperty),
            34 => Ok(Self::AuthRequest),
            _ => Err(ServiceError::UnsupportedServiceChoice(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnconfirmedServiceChoice {
    IAm = 0,
    IHave = 1,
    UnconfirmedCOVNotification = 2,
    UnconfirmedEventNotification = 3,
    UnconfirmedPrivateTransfer = 4,
    UnconfirmedTextMessage = 5,
    TimeSynchronization = 6,
    WhoHas = 7,
    WhoIs = 8,
    UtcTimeSynchronization = 9,
    WriteGroup = 10,
    UnconfirmedCOVNotificationMultiple = 11,
    UnconfirmedAuditNotification = 12,
    WhoAmI = 13,
    YouAre = 14,
}

impl TryFrom<u8> for UnconfirmedServiceChoice {
    type Error = ServiceError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::IAm),
            1 => Ok(Self::IHave),
            2 => Ok(Self::UnconfirmedCOVNotification),
            3 => Ok(Self::UnconfirmedEventNotification),
            4 => Ok(Self::UnconfirmedPrivateTransfer),
            5 => Ok(Self::UnconfirmedTextMessage),
            6 => Ok(Self::TimeSynchronization),
            7 => Ok(Self::WhoHas),
            8 => Ok(Self::WhoIs),
            9 => Ok(Self::UtcTimeSynchronization),
            10 => Ok(Self::WriteGroup),
            11 => Ok(Self::UnconfirmedCOVNotificationMultiple),
            12 => Ok(Self::UnconfirmedAuditNotification),
            13 => Ok(Self::WhoAmI),
            14 => Ok(Self::YouAre),
            _ => Err(ServiceError::UnsupportedServiceChoice(value)),
        }
    }
}

/// Reject reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Other = 0,
    BufferOverflow = 1,
    InconsistentParameters = 2,
    InvalidParameterDataType = 3,
    InvalidTag = 4,
    MissingRequiredParameter = 5,
    ParameterOutOfRange = 6,
    TooManyArguments = 7,
    UndefinedEnumeration = 8,
    UnrecognizedService = 9,
}

/// Abort reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    Other = 0,
    BufferOverflow = 1,
    InvalidApduInThisState = 2,
    PreemptedByHigherPriorityTask = 3,
    SegmentationNotSupported = 4,
}

use crate::encoding::{
    decode_context_enumerated, decode_context_object_id, decode_context_unsigned,
    decode_enumerated, decode_object_identifier, decode_unsigned, encode_context_enumerated,
    encode_context_object_id, encode_context_unsigned, encode_enumerated, encode_object_identifier,
    encode_unsigned, Result as EncodingResult,
};
use crate::object::{ObjectIdentifier, PropertyValue};

/// Special array index value indicating all elements
pub const BACNET_ARRAY_ALL: u32 = 0xFFFFFFFF;

/// Who-Is request (unconfirmed service)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WhoIsRequest {
    /// Low limit of device instance range (optional)
    pub device_instance_range_low_limit: Option<u32>,
    /// High limit of device instance range (optional)
    pub device_instance_range_high_limit: Option<u32>,
}

impl WhoIsRequest {
    /// Create a new Who-Is request for all devices
    pub fn new() -> Self {
        Self {
            device_instance_range_low_limit: None,
            device_instance_range_high_limit: None,
        }
    }

    /// Create a new Who-Is request for a specific device
    pub fn for_device(device_instance: u32) -> Self {
        Self {
            device_instance_range_low_limit: Some(device_instance),
            device_instance_range_high_limit: Some(device_instance),
        }
    }

    /// Create a new Who-Is request for a range of devices
    pub fn for_range(low: u32, high: u32) -> Self {
        Self {
            device_instance_range_low_limit: Some(low),
            device_instance_range_high_limit: Some(high),
        }
    }

    /// Encode the Who-Is request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // Both low and high limits must be present together, or both absent
        // This matches bacnet-stack behavior
        if let (Some(low), Some(high)) = (
            self.device_instance_range_low_limit,
            self.device_instance_range_high_limit,
        ) {
            // Context tag 0 - low limit
            let low_bytes = encode_context_unsigned(low, 0)?;
            buffer.extend_from_slice(&low_bytes);

            // Context tag 1 - high limit
            let high_bytes = encode_context_unsigned(high, 1)?;
            buffer.extend_from_slice(&high_bytes);
        }
        // If only one limit is present, encode nothing (broadcast to all)

        Ok(())
    }

    /// Decode a Who-Is request
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut request = WhoIsRequest::new();
        let mut pos = 0;

        // Try to decode context tag 0 (low limit)
        if pos < data.len() {
            match decode_context_unsigned(&data[pos..], 0) {
                Ok((low, consumed)) => {
                    request.device_instance_range_low_limit = Some(low);
                    pos += consumed;

                    // If we have low limit, we must have high limit
                    if pos < data.len() {
                        match decode_context_unsigned(&data[pos..], 1) {
                            Ok((high, _consumed)) => {
                                request.device_instance_range_high_limit = Some(high);
                            }
                            Err(_) => {
                                // Invalid format - low without high
                                return Err(crate::encoding::EncodingError::InvalidFormat(
                                    "Who-Is request has low limit without high limit".to_string(),
                                ));
                            }
                        }
                    }
                }
                Err(_) => {
                    // No device range specified - broadcast to all
                }
            }
        }

        Ok(request)
    }

    /// Check if this request matches a device instance
    pub fn matches(&self, device_instance: u32) -> bool {
        match (
            self.device_instance_range_low_limit,
            self.device_instance_range_high_limit,
        ) {
            (None, None) => true, // Matches all devices
            (Some(low), Some(high)) => device_instance >= low && device_instance <= high,
            (Some(low), None) => device_instance >= low,
            (None, Some(high)) => device_instance <= high,
        }
    }
}

/// I-Am response (unconfirmed service)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAmRequest {
    /// Device object identifier
    pub device_identifier: ObjectIdentifier,
    /// Maximum APDU length accepted
    pub max_apdu_length_accepted: u32,
    /// Segmentation supported
    pub segmentation_supported: u32,
    /// Vendor identifier
    pub vendor_identifier: u32,
}

impl IAmRequest {
    /// Create a new I-Am request
    pub fn new(
        device_identifier: ObjectIdentifier,
        max_apdu_length_accepted: u32,
        segmentation_supported: u32,
        vendor_identifier: u32,
    ) -> Self {
        Self {
            device_identifier,
            max_apdu_length_accepted,
            segmentation_supported,
            vendor_identifier,
        }
    }

    /// Encode the I-Am request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // Device identifier (object identifier) - application tag
        encode_object_identifier(
            buffer,
            self.device_identifier.object_type as u16,
            self.device_identifier.instance,
        )?;

        // Maximum APDU length accepted - application tag
        encode_unsigned(buffer, self.max_apdu_length_accepted)?;

        // Segmentation supported - application tag (enumerated)
        encode_enumerated(buffer, self.segmentation_supported)?;

        // Vendor identifier - application tag
        encode_unsigned(buffer, self.vendor_identifier)?;

        Ok(())
    }

    /// Decode an I-Am request
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut pos = 0;

        // Decode device identifier - application tag
        let ((object_type, instance), consumed) = decode_object_identifier(&data[pos..])?;
        let device_identifier = ObjectIdentifier {
            object_type: crate::object::ObjectType::try_from(object_type)
                .unwrap_or(crate::object::ObjectType::Device),
            instance,
        };
        pos += consumed;

        // Decode max APDU length accepted - application tag
        let (max_apdu_length_accepted, consumed) = decode_unsigned(&data[pos..])?;
        pos += consumed;

        // Decode segmentation supported - application tag (enumerated)
        let (segmentation_supported, consumed) = decode_enumerated(&data[pos..])?;
        pos += consumed;

        // Decode vendor identifier - application tag
        let (vendor_identifier, _consumed) = decode_unsigned(&data[pos..])?;

        Ok(IAmRequest::new(
            device_identifier,
            max_apdu_length_accepted,
            segmentation_supported,
            vendor_identifier,
        ))
    }
}

/// Read Property request (confirmed service)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPropertyRequest {
    /// Object identifier to read from
    pub object_identifier: ObjectIdentifier,
    /// Property identifier to read
    pub property_identifier: u32,
    /// Property array index (optional)
    pub property_array_index: Option<u32>,
}

impl ReadPropertyRequest {
    /// Create a new Read Property request
    pub fn new(object_identifier: ObjectIdentifier, property_identifier: u32) -> Self {
        Self {
            object_identifier,
            property_identifier,
            property_array_index: None,
        }
    }

    /// Create a new Read Property request with array index
    pub fn with_array_index(
        object_identifier: ObjectIdentifier,
        property_identifier: u32,
        array_index: u32,
    ) -> Self {
        Self {
            object_identifier,
            property_identifier,
            property_array_index: Some(array_index),
        }
    }

    /// Encode the Read Property request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // Object identifier - context tag 0
        let obj_id_bytes = encode_context_object_id(
            self.object_identifier.object_type as u16,
            self.object_identifier.instance,
            0,
        )?;
        buffer.extend_from_slice(&obj_id_bytes);

        // Property identifier - context tag 1 (as enumerated)
        let prop_id_bytes = encode_context_enumerated(self.property_identifier, 1)?;
        buffer.extend_from_slice(&prop_id_bytes);

        // Property array index - context tag 2 (optional)
        if let Some(array_index) = self.property_array_index {
            let array_bytes = encode_context_unsigned(array_index, 2)?;
            buffer.extend_from_slice(&array_bytes);
        }

        Ok(())
    }
}

/// Read Property response (confirmed service)
#[derive(Debug, Clone)]
pub struct ReadPropertyResponse {
    /// Object identifier that was read
    pub object_identifier: ObjectIdentifier,
    /// Property identifier that was read
    pub property_identifier: u32,
    /// Property array index (optional)
    pub property_array_index: Option<u32>,
    /// Property value
    pub property_value: Vec<u8>, // Raw encoded property value
}

impl ReadPropertyResponse {
    /// Create a new Read Property response
    pub fn new(
        object_identifier: ObjectIdentifier,
        property_identifier: u32,
        property_value: Vec<u8>,
    ) -> Self {
        Self {
            object_identifier,
            property_identifier,
            property_array_index: None,
            property_value,
        }
    }

    /// Decode a Read Property response
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut pos = 0;

        // Decode object identifier - context tag 0
        let ((object_type, instance), consumed) = decode_context_object_id(&data[pos..], 0)?;
        let object_identifier = ObjectIdentifier {
            object_type: crate::object::ObjectType::try_from(object_type)
                .unwrap_or(crate::object::ObjectType::Device),
            instance,
        };
        pos += consumed;

        // Decode property identifier - context tag 1
        let (property_identifier, consumed) = decode_context_enumerated(&data[pos..], 1)?;
        pos += consumed;

        // Property array index - context tag 2 (optional)
        let property_array_index = match decode_context_unsigned(&data[pos..], 2) {
            Ok((array_index, consumed)) => {
                pos += consumed;
                if array_index == BACNET_ARRAY_ALL {
                    None
                } else {
                    Some(array_index)
                }
            }
            Err(_) => None,
        };

        // Property value - context tag 3 (opening tag)
        if pos >= data.len() || data[pos] != 0x3E {
            return Err(crate::encoding::EncodingError::InvalidTag);
        }
        pos += 1;

        // Find closing tag
        let value_start = pos;
        let mut value_end = pos;
        while value_end < data.len() {
            if data[value_end] == 0x3F {
                break;
            }
            value_end += 1;
        }

        if value_end >= data.len() {
            return Err(crate::encoding::EncodingError::InvalidTag);
        }

        let property_value = data[value_start..value_end].to_vec();

        Ok(ReadPropertyResponse {
            object_identifier,
            property_identifier,
            property_array_index,
            property_value,
        })
    }
}

/// Write Property request (confirmed service)
#[derive(Debug, Clone)]
pub struct WritePropertyRequest {
    /// Object identifier to write to
    pub object_identifier: ObjectIdentifier,
    /// Property identifier to write
    pub property_identifier: u32,
    /// Property array index (optional)
    pub property_array_index: Option<u32>,
    /// Property value to write
    pub property_value: Vec<u8>, // Raw encoded property value
    /// Priority (optional, 1-16)
    pub priority: Option<u8>,
}

impl WritePropertyRequest {
    /// Create a new Write Property request
    pub fn new(
        object_identifier: ObjectIdentifier,
        property_identifier: u32,
        property_value: Vec<u8>,
    ) -> Self {
        Self {
            object_identifier,
            property_identifier,
            property_array_index: None,
            property_value,
            priority: None,
        }
    }

    /// Create a new Write Property request with priority
    pub fn with_priority(
        object_identifier: ObjectIdentifier,
        property_identifier: u32,
        property_value: Vec<u8>,
        priority: u8,
    ) -> Self {
        Self {
            object_identifier,
            property_identifier,
            property_array_index: None,
            property_value,
            priority: Some(priority),
        }
    }

    /// Create a new Write Property request with array index
    pub fn with_array_index(
        object_identifier: ObjectIdentifier,
        property_identifier: u32,
        array_index: u32,
        property_value: Vec<u8>,
    ) -> Self {
        Self {
            object_identifier,
            property_identifier,
            property_array_index: Some(array_index),
            property_value,
            priority: None,
        }
    }

    /// Encode the Write Property request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // Object identifier - context tag 0
        let object_id = crate::util::encode_object_id(
            self.object_identifier.object_type as u16,
            self.object_identifier.instance,
        )
        .ok_or(crate::encoding::EncodingError::InvalidFormat(
            "Invalid object identifier".to_string(),
        ))?;
        buffer.push(0x0C); // Context tag 0, length 4
        buffer.extend_from_slice(&object_id.to_be_bytes());

        // Property identifier - context tag 1
        buffer.push(0x19); // Context tag 1, length 1
        buffer.push(self.property_identifier as u8);

        // Property array index - context tag 2 (optional)
        if let Some(array_index) = self.property_array_index {
            buffer.push(0x29); // Context tag 2, length 1
            buffer.push(array_index as u8);
        }

        // Property value - context tag 3 (opening tag)
        buffer.push(0x3E); // Context tag 3, opening tag
        buffer.extend_from_slice(&self.property_value);
        buffer.push(0x3F); // Context tag 3, closing tag

        // Priority - context tag 4 (optional)
        if let Some(priority) = self.priority {
            buffer.push(0x49); // Context tag 4, length 1
            buffer.push(priority);
        }

        Ok(())
    }

    /// Decode a Write Property request
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut pos = 0;

        // Decode object identifier - context tag 0
        if pos + 5 > data.len() || data[pos] != 0x0C {
            return Err(crate::encoding::EncodingError::InvalidTag);
        }
        pos += 1;

        let object_id_bytes = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
        let object_id = u32::from_be_bytes(object_id_bytes);
        let (object_type, instance) = crate::util::decode_object_id(object_id);
        let object_identifier = ObjectIdentifier {
            object_type: crate::object::ObjectType::try_from(object_type)
                .unwrap_or(crate::object::ObjectType::Device),
            instance,
        };
        pos += 4;

        // Decode property identifier - context tag 1
        if pos + 2 > data.len() || data[pos] != 0x19 {
            return Err(crate::encoding::EncodingError::InvalidTag);
        }
        pos += 1;
        let property_identifier = data[pos] as u32;
        pos += 1;

        // Property array index - context tag 2 (optional)
        let property_array_index = if pos < data.len() && data[pos] == 0x29 {
            pos += 1;
            let array_index = data[pos] as u32;
            pos += 1;
            Some(array_index)
        } else {
            None
        };

        // Property value - context tag 3 (opening tag)
        if pos >= data.len() || data[pos] != 0x3E {
            return Err(crate::encoding::EncodingError::InvalidTag);
        }
        pos += 1;

        // Find closing tag
        let value_start = pos;
        let mut value_end = pos;
        while value_end < data.len() {
            if data[value_end] == 0x3F {
                break;
            }
            value_end += 1;
        }

        if value_end >= data.len() {
            return Err(crate::encoding::EncodingError::InvalidTag);
        }

        let property_value = data[value_start..value_end].to_vec();
        pos = value_end + 1;

        // Priority - context tag 4 (optional)
        let priority = if pos < data.len() && data[pos] == 0x49 {
            pos += 1;
            if pos < data.len() {
                Some(data[pos])
            } else {
                None
            }
        } else {
            None
        };

        Ok(WritePropertyRequest {
            object_identifier,
            property_identifier,
            property_array_index,
            property_value,
            priority,
        })
    }
}

/// Read Property Multiple request (confirmed service)
#[derive(Debug, Clone)]
pub struct ReadPropertyMultipleRequest {
    /// List of objects and properties to read
    pub read_access_specifications: Vec<ReadAccessSpecification>,
}

#[derive(Debug, Clone)]
pub struct ReadAccessSpecification {
    /// Object identifier
    pub object_identifier: ObjectIdentifier,
    /// List of properties to read
    pub property_references: Vec<PropertyReference>,
}

#[derive(Debug, Clone)]
pub struct PropertyReference {
    /// Property identifier
    pub property_identifier: u32,
    /// Property array index (optional)
    pub property_array_index: Option<u32>,
}

impl ReadPropertyMultipleRequest {
    /// Create a new Read Property Multiple request
    pub fn new(read_access_specifications: Vec<ReadAccessSpecification>) -> Self {
        Self {
            read_access_specifications,
        }
    }

    /// Add a read access specification
    pub fn add_specification(&mut self, spec: ReadAccessSpecification) {
        self.read_access_specifications.push(spec);
    }
}

impl ReadAccessSpecification {
    /// Create a new read access specification
    pub fn new(
        object_identifier: ObjectIdentifier,
        property_references: Vec<PropertyReference>,
    ) -> Self {
        Self {
            object_identifier,
            property_references,
        }
    }

    /// Add a property reference
    pub fn add_property(&mut self, property_reference: PropertyReference) {
        self.property_references.push(property_reference);
    }
}

impl PropertyReference {
    /// Create a new property reference
    pub fn new(property_identifier: u32) -> Self {
        Self {
            property_identifier,
            property_array_index: None,
        }
    }

    /// Create a new property reference with array index
    pub fn with_array_index(property_identifier: u32, array_index: u32) -> Self {
        Self {
            property_identifier,
            property_array_index: Some(array_index),
        }
    }
}

/// Subscribe COV request (confirmed service)
#[derive(Debug, Clone)]
pub struct SubscribeCovRequest {
    /// Subscriber process identifier
    pub subscriber_process_identifier: u32,
    /// Monitored object identifier
    pub monitored_object_identifier: ObjectIdentifier,
    /// Issue confirmed notifications
    pub issue_confirmed_notifications: Option<bool>,
    /// Lifetime (seconds, 0 = permanent)
    pub lifetime: Option<u32>,
}

impl SubscribeCovRequest {
    /// Create a new Subscribe COV request
    pub fn new(
        subscriber_process_identifier: u32,
        monitored_object_identifier: ObjectIdentifier,
    ) -> Self {
        Self {
            subscriber_process_identifier,
            monitored_object_identifier,
            issue_confirmed_notifications: None,
            lifetime: None,
        }
    }

    /// Create a new Subscribe COV request with confirmation preference
    pub fn with_confirmation(
        subscriber_process_identifier: u32,
        monitored_object_identifier: ObjectIdentifier,
        issue_confirmed_notifications: bool,
    ) -> Self {
        Self {
            subscriber_process_identifier,
            monitored_object_identifier,
            issue_confirmed_notifications: Some(issue_confirmed_notifications),
            lifetime: None,
        }
    }

    /// Create a new Subscribe COV request with lifetime
    pub fn with_lifetime(
        subscriber_process_identifier: u32,
        monitored_object_identifier: ObjectIdentifier,
        lifetime: u32,
    ) -> Self {
        Self {
            subscriber_process_identifier,
            monitored_object_identifier,
            issue_confirmed_notifications: None,
            lifetime: Some(lifetime),
        }
    }

    /// Encode the Subscribe COV request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // Subscriber process identifier - context tag 0
        buffer.push(0x09); // Context tag 0, length 1
        buffer.push(self.subscriber_process_identifier as u8);

        // Monitored object identifier - context tag 1
        let object_id = crate::util::encode_object_id(
            self.monitored_object_identifier.object_type as u16,
            self.monitored_object_identifier.instance,
        )
        .ok_or(crate::encoding::EncodingError::InvalidFormat(
            "Invalid object identifier".to_string(),
        ))?;
        buffer.push(0x1C); // Context tag 1, length 4
        buffer.extend_from_slice(&object_id.to_be_bytes());

        // Issue confirmed notifications - context tag 2 (optional)
        if let Some(confirmed) = self.issue_confirmed_notifications {
            buffer.push(0x22); // Context tag 2, length 2
            buffer.push(if confirmed { 1 } else { 0 });
        }

        // Lifetime - context tag 3 (optional)
        if let Some(lifetime) = self.lifetime {
            buffer.push(0x39); // Context tag 3, length 1
            buffer.push(lifetime as u8);
        }

        Ok(())
    }
}

/// Subscribe COV Property request (confirmed service)
#[derive(Debug, Clone)]
pub struct SubscribeCovPropertyRequest {
    /// Subscriber process identifier
    pub subscriber_process_identifier: u32,
    /// Monitored object identifier
    pub monitored_object_identifier: ObjectIdentifier,
    /// Issue confirmed notifications
    pub issue_confirmed_notifications: Option<bool>,
    /// Lifetime (seconds, 0 = permanent)
    pub lifetime: Option<u32>,
    /// Monitored property reference
    pub monitored_property: PropertyReference,
    /// COV increment (optional)
    pub cov_increment: Option<f32>,
}

impl SubscribeCovPropertyRequest {
    /// Create a new Subscribe COV Property request
    pub fn new(
        subscriber_process_identifier: u32,
        monitored_object_identifier: ObjectIdentifier,
        monitored_property: PropertyReference,
    ) -> Self {
        Self {
            subscriber_process_identifier,
            monitored_object_identifier,
            issue_confirmed_notifications: None,
            lifetime: None,
            monitored_property,
            cov_increment: None,
        }
    }

    /// Set COV increment
    pub fn with_cov_increment(mut self, increment: f32) -> Self {
        self.cov_increment = Some(increment);
        self
    }
}

/// COV Notification request (unconfirmed service)
#[derive(Debug, Clone)]
pub struct CovNotificationRequest {
    /// Subscriber process identifier
    pub subscriber_process_identifier: u32,
    /// Initiating device identifier
    pub initiating_device_identifier: ObjectIdentifier,
    /// Monitored object identifier
    pub monitored_object_identifier: ObjectIdentifier,
    /// Time remaining (seconds)
    pub time_remaining: u32,
    /// List of values (property-value pairs)
    pub list_of_values: Vec<PropertyValue>,
}

impl CovNotificationRequest {
    /// Create a new COV Notification request
    pub fn new(
        subscriber_process_identifier: u32,
        initiating_device_identifier: ObjectIdentifier,
        monitored_object_identifier: ObjectIdentifier,
        time_remaining: u32,
        list_of_values: Vec<PropertyValue>,
    ) -> Self {
        Self {
            subscriber_process_identifier,
            initiating_device_identifier,
            monitored_object_identifier,
            time_remaining,
            list_of_values,
        }
    }

    /// Encode the COV Notification request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // Subscriber process identifier - context tag 0
        buffer.push(0x09); // Context tag 0, length 1
        buffer.push(self.subscriber_process_identifier as u8);

        // Initiating device identifier - context tag 1
        let device_id = crate::util::encode_object_id(
            self.initiating_device_identifier.object_type as u16,
            self.initiating_device_identifier.instance,
        )
        .ok_or(crate::encoding::EncodingError::InvalidFormat(
            "Invalid device identifier".to_string(),
        ))?;
        buffer.push(0x1C); // Context tag 1, length 4
        buffer.extend_from_slice(&device_id.to_be_bytes());

        // Monitored object identifier - context tag 2
        let object_id = crate::util::encode_object_id(
            self.monitored_object_identifier.object_type as u16,
            self.monitored_object_identifier.instance,
        )
        .ok_or(crate::encoding::EncodingError::InvalidFormat(
            "Invalid object identifier".to_string(),
        ))?;
        buffer.push(0x2C); // Context tag 2, length 4
        buffer.extend_from_slice(&object_id.to_be_bytes());

        // Time remaining - context tag 3
        buffer.push(0x39); // Context tag 3, length 1
        buffer.push(self.time_remaining as u8);

        // List of values would be encoded here in a real implementation
        // This is complex as it involves encoding property-value pairs

        Ok(())
    }
}

/// COV Subscription information
#[derive(Debug, Clone)]
pub struct CovSubscription {
    /// Subscriber process identifier
    pub subscriber_process_identifier: u32,
    /// Subscriber device identifier
    pub subscriber_device_identifier: ObjectIdentifier,
    /// Monitored object identifier
    pub monitored_object_identifier: ObjectIdentifier,
    /// Monitored property (for COV Property subscriptions)
    pub monitored_property: Option<PropertyReference>,
    /// Issue confirmed notifications
    pub issue_confirmed_notifications: bool,
    /// Lifetime (seconds, 0 = permanent)
    pub lifetime: u32,
    /// Remaining time (seconds)
    pub time_remaining: u32,
    /// COV increment (for analog properties)
    pub cov_increment: Option<f32>,
}

impl CovSubscription {
    /// Create a new COV subscription
    pub fn new(
        subscriber_process_identifier: u32,
        subscriber_device_identifier: ObjectIdentifier,
        monitored_object_identifier: ObjectIdentifier,
        lifetime: u32,
    ) -> Self {
        Self {
            subscriber_process_identifier,
            subscriber_device_identifier,
            monitored_object_identifier,
            monitored_property: None,
            issue_confirmed_notifications: false,
            lifetime,
            time_remaining: lifetime,
            cov_increment: None,
        }
    }

    /// Check if subscription has expired
    pub fn is_expired(&self) -> bool {
        self.lifetime > 0 && self.time_remaining == 0
    }

    /// Update time remaining (should be called periodically)
    pub fn update_time(&mut self, elapsed_seconds: u32) {
        if self.lifetime > 0 {
            self.time_remaining = self.time_remaining.saturating_sub(elapsed_seconds);
        }
    }
}

/// COV Subscription manager
#[derive(Debug, Default)]
pub struct CovSubscriptionManager {
    /// List of active subscriptions
    subscriptions: Vec<CovSubscription>,
}

impl CovSubscriptionManager {
    /// Create a new COV subscription manager
    pub fn new() -> Self {
        Self {
            subscriptions: Vec::new(),
        }
    }

    /// Add a new subscription
    pub fn add_subscription(&mut self, subscription: CovSubscription) {
        // Remove any existing subscription for the same object and subscriber
        self.subscriptions.retain(|s| {
            !(s.subscriber_device_identifier == subscription.subscriber_device_identifier
                && s.subscriber_process_identifier == subscription.subscriber_process_identifier
                && s.monitored_object_identifier == subscription.monitored_object_identifier)
        });

        self.subscriptions.push(subscription);
    }

    /// Remove a subscription
    pub fn remove_subscription(
        &mut self,
        subscriber_device: ObjectIdentifier,
        subscriber_process: u32,
        monitored_object: ObjectIdentifier,
    ) {
        self.subscriptions.retain(|s| {
            !(s.subscriber_device_identifier == subscriber_device
                && s.subscriber_process_identifier == subscriber_process
                && s.monitored_object_identifier == monitored_object)
        });
    }

    /// Get all subscriptions for a monitored object
    pub fn get_subscriptions_for_object(
        &self,
        object_id: ObjectIdentifier,
    ) -> Vec<&CovSubscription> {
        self.subscriptions
            .iter()
            .filter(|s| s.monitored_object_identifier == object_id && !s.is_expired())
            .collect()
    }

    /// Remove expired subscriptions
    pub fn cleanup_expired(&mut self) {
        self.subscriptions.retain(|s| !s.is_expired());
    }

    /// Update all subscription timers
    pub fn update_timers(&mut self, elapsed_seconds: u32) {
        for subscription in &mut self.subscriptions {
            subscription.update_time(elapsed_seconds);
        }
    }

    /// Get total number of active subscriptions
    pub fn active_count(&self) -> usize {
        self.subscriptions
            .iter()
            .filter(|s| !s.is_expired())
            .count()
    }
}

/// Atomic Read File request (confirmed service)
#[derive(Debug, Clone)]
pub struct AtomicReadFileRequest {
    /// File object identifier
    pub file_identifier: ObjectIdentifier,
    /// Access method specification
    pub access_method: FileAccessMethod,
}

/// File access method for atomic read/write
#[derive(Debug, Clone)]
pub enum FileAccessMethod {
    /// Stream access - read/write bytes at position
    StreamAccess {
        /// File position to start reading/writing
        file_start_position: i32,
        /// Number of octets to read (for read operations)
        requested_octet_count: u32,
    },
    /// Record access - read/write records
    RecordAccess {
        /// Starting record number
        file_start_record: i32,
        /// Number of records to read (for read operations)
        requested_record_count: u32,
    },
}

impl AtomicReadFileRequest {
    /// Create a new Atomic Read File request with stream access
    pub fn new_stream_access(
        file_identifier: ObjectIdentifier,
        start_position: i32,
        octet_count: u32,
    ) -> Self {
        Self {
            file_identifier,
            access_method: FileAccessMethod::StreamAccess {
                file_start_position: start_position,
                requested_octet_count: octet_count,
            },
        }
    }

    /// Create a new Atomic Read File request with record access
    pub fn new_record_access(
        file_identifier: ObjectIdentifier,
        start_record: i32,
        record_count: u32,
    ) -> Self {
        Self {
            file_identifier,
            access_method: FileAccessMethod::RecordAccess {
                file_start_record: start_record,
                requested_record_count: record_count,
            },
        }
    }

    /// Encode the Atomic Read File request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // File identifier - context tag 0
        let file_id = crate::util::encode_object_id(
            self.file_identifier.object_type as u16,
            self.file_identifier.instance,
        )
        .ok_or(crate::encoding::EncodingError::InvalidFormat(
            "Invalid file identifier".to_string(),
        ))?;
        buffer.push(0x0C); // Context tag 0, length 4
        buffer.extend_from_slice(&file_id.to_be_bytes());

        // Access method - context tag 1 (opening tag)
        buffer.push(0x1E); // Context tag 1, opening tag

        match &self.access_method {
            FileAccessMethod::StreamAccess {
                file_start_position,
                requested_octet_count,
            } => {
                // Stream access - context tag 0 (opening tag)
                buffer.push(0x0E); // Context tag 0, opening tag

                // File start position - context tag 0
                buffer.push(0x09); // Context tag 0, length 1
                buffer.extend_from_slice(&file_start_position.to_be_bytes());

                // Requested octet count - context tag 1
                buffer.push(0x19); // Context tag 1, length 1
                buffer.extend_from_slice(&requested_octet_count.to_be_bytes());

                buffer.push(0x0F); // Context tag 0, closing tag
            }
            FileAccessMethod::RecordAccess {
                file_start_record,
                requested_record_count,
            } => {
                // Record access - context tag 1 (opening tag)
                buffer.push(0x1E); // Context tag 1, opening tag

                // File start record - context tag 0
                buffer.push(0x09); // Context tag 0, length 1
                buffer.extend_from_slice(&file_start_record.to_be_bytes());

                // Requested record count - context tag 1
                buffer.push(0x19); // Context tag 1, length 1
                buffer.extend_from_slice(&requested_record_count.to_be_bytes());

                buffer.push(0x1F); // Context tag 1, closing tag
            }
        }

        buffer.push(0x1F); // Context tag 1, closing tag

        Ok(())
    }
}

/// Atomic Read File response (confirmed service)
#[derive(Debug, Clone)]
pub struct AtomicReadFileResponse {
    /// End of file flag
    pub end_of_file: bool,
    /// Access method and data
    pub access_method_result: FileAccessMethodResult,
}

/// File access method result for atomic read response
#[derive(Debug, Clone)]
pub enum FileAccessMethodResult {
    /// Stream access result
    StreamAccess {
        /// File position after read
        file_start_position: i32,
        /// File data read
        file_data: Vec<u8>,
    },
    /// Record access result
    RecordAccess {
        /// Starting record number
        file_start_record: i32,
        /// Number of records returned
        record_count: u32,
        /// Record data
        file_record_data: Vec<Vec<u8>>,
    },
}

impl AtomicReadFileResponse {
    /// Create a new stream access response
    pub fn new_stream_access(end_of_file: bool, start_position: i32, data: Vec<u8>) -> Self {
        Self {
            end_of_file,
            access_method_result: FileAccessMethodResult::StreamAccess {
                file_start_position: start_position,
                file_data: data,
            },
        }
    }

    /// Create a new record access response
    pub fn new_record_access(end_of_file: bool, start_record: i32, records: Vec<Vec<u8>>) -> Self {
        let record_count = records.len() as u32;
        Self {
            end_of_file,
            access_method_result: FileAccessMethodResult::RecordAccess {
                file_start_record: start_record,
                record_count,
                file_record_data: records,
            },
        }
    }
}

/// Atomic Write File request (confirmed service)
#[derive(Debug, Clone)]
pub struct AtomicWriteFileRequest {
    /// File object identifier
    pub file_identifier: ObjectIdentifier,
    /// Access method and data
    pub access_method: FileWriteAccessMethod,
}

/// File write access method for atomic write
#[derive(Debug, Clone)]
pub enum FileWriteAccessMethod {
    /// Stream access - write bytes at position
    StreamAccess {
        /// File position to start writing
        file_start_position: i32,
        /// Data to write
        file_data: Vec<u8>,
    },
    /// Record access - write records
    RecordAccess {
        /// Starting record number
        file_start_record: i32,
        /// Number of records to write
        record_count: u32,
        /// Record data to write
        file_record_data: Vec<Vec<u8>>,
    },
}

impl AtomicWriteFileRequest {
    /// Create a new Atomic Write File request with stream access
    pub fn new_stream_access(
        file_identifier: ObjectIdentifier,
        start_position: i32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            file_identifier,
            access_method: FileWriteAccessMethod::StreamAccess {
                file_start_position: start_position,
                file_data: data,
            },
        }
    }

    /// Create a new Atomic Write File request with record access
    pub fn new_record_access(
        file_identifier: ObjectIdentifier,
        start_record: i32,
        records: Vec<Vec<u8>>,
    ) -> Self {
        let record_count = records.len() as u32;
        Self {
            file_identifier,
            access_method: FileWriteAccessMethod::RecordAccess {
                file_start_record: start_record,
                record_count,
                file_record_data: records,
            },
        }
    }

    /// Encode the Atomic Write File request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        // File identifier - context tag 0
        let file_id = crate::util::encode_object_id(
            self.file_identifier.object_type as u16,
            self.file_identifier.instance,
        )
        .ok_or(crate::encoding::EncodingError::InvalidFormat(
            "Invalid file identifier".to_string(),
        ))?;
        buffer.push(0x0C); // Context tag 0, length 4
        buffer.extend_from_slice(&file_id.to_be_bytes());

        // Access method - context tag 1 (opening tag)
        buffer.push(0x1E); // Context tag 1, opening tag

        match &self.access_method {
            FileWriteAccessMethod::StreamAccess {
                file_start_position,
                file_data,
            } => {
                // Stream access - context tag 0 (opening tag)
                buffer.push(0x0E); // Context tag 0, opening tag

                // File start position - context tag 0
                buffer.push(0x09); // Context tag 0, length 1
                buffer.extend_from_slice(&file_start_position.to_be_bytes());

                // File data - context tag 1 (opening tag)
                buffer.push(0x1E); // Context tag 1, opening tag
                buffer.extend_from_slice(file_data);
                buffer.push(0x1F); // Context tag 1, closing tag

                buffer.push(0x0F); // Context tag 0, closing tag
            }
            FileWriteAccessMethod::RecordAccess {
                file_start_record,
                record_count: _,
                file_record_data,
            } => {
                // Record access - context tag 1 (opening tag)
                buffer.push(0x1E); // Context tag 1, opening tag

                // File start record - context tag 0
                buffer.push(0x09); // Context tag 0, length 1
                buffer.extend_from_slice(&file_start_record.to_be_bytes());

                // Record count - context tag 1
                let record_count = file_record_data.len() as u32;
                buffer.push(0x19); // Context tag 1, length 1
                buffer.extend_from_slice(&record_count.to_be_bytes());

                // File record data - context tag 2 (opening tag)
                buffer.push(0x2E); // Context tag 2, opening tag
                for record in file_record_data {
                    // Each record as octet string
                    buffer.push(0x65); // Application tag 6 (OctetString), length depends on record size
                    buffer.push(record.len() as u8);
                    buffer.extend_from_slice(record);
                }
                buffer.push(0x2F); // Context tag 2, closing tag

                buffer.push(0x1F); // Context tag 1, closing tag
            }
        }

        buffer.push(0x1F); // Context tag 1, closing tag

        Ok(())
    }
}

/// Atomic Write File response (confirmed service)
#[derive(Debug, Clone)]
pub struct AtomicWriteFileResponse {
    /// File start position (for stream access) or start record (for record access)
    pub file_start_position: i32,
}

/// Time Synchronization request (unconfirmed service)
#[derive(Debug, Clone)]
pub struct TimeSynchronizationRequest {
    /// Date and time to synchronize to
    pub date_time: BacnetDateTime,
}

/// UTC Time Synchronization request (unconfirmed service)
#[derive(Debug, Clone)]
pub struct UtcTimeSynchronizationRequest {
    /// UTC date and time to synchronize to
    pub utc_date_time: BacnetDateTime,
}

/// BACnet Date and Time structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacnetDateTime {
    /// Date component
    pub date: crate::object::Date,
    /// Time component
    pub time: crate::object::Time,
}

impl BacnetDateTime {
    /// Create a new BACnet DateTime from Date and Time components
    pub fn new(date: crate::object::Date, time: crate::object::Time) -> Self {
        Self { date, time }
    }

    /// Create from current system time (requires std feature)
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        use chrono::{Datelike, Local, Timelike};

        let now = Local::now();
        let year = now.year() as u16;
        let month = now.month() as u8;
        let day = now.day() as u8;
        let weekday = now.weekday().number_from_monday() as u8; // BACnet uses 1=Monday
        let hour = now.hour() as u8;
        let minute = now.minute() as u8;
        let second = now.second() as u8;
        let hundredths = (now.nanosecond() / 10_000_000) as u8;

        let date = crate::object::Date {
            year,
            month,
            day,
            weekday,
        };
        let time = crate::object::Time {
            hour,
            minute,
            second,
            hundredths,
        };
        Self::new(date, time)
    }

    /// Create unspecified time (all 255 values)
    pub fn unspecified() -> Self {
        Self {
            date: crate::object::Date {
                year: 255,
                month: 255,
                day: 255,
                weekday: 255,
            },
            time: crate::object::Time {
                hour: 255,
                minute: 255,
                second: 255,
                hundredths: 255,
            },
        }
    }

    /// Check if this datetime is unspecified
    pub fn is_unspecified(&self) -> bool {
        self.date.year == 255
            && self.date.month == 255
            && self.date.day == 255
            && self.date.weekday == 255
            && self.time.hour == 255
            && self.time.minute == 255
            && self.time.second == 255
            && self.time.hundredths == 255
    }

    /// Encode BACnet DateTime
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        use crate::encoding::{encode_date, encode_time};

        // Encode date
        encode_date(
            buffer,
            self.date.year,
            self.date.month,
            self.date.day,
            self.date.weekday,
        )?;

        // Encode time
        encode_time(
            buffer,
            self.time.hour,
            self.time.minute,
            self.time.second,
            self.time.hundredths,
        )?;

        Ok(())
    }

    /// Decode BACnet DateTime
    pub fn decode(data: &[u8]) -> EncodingResult<(Self, usize)> {
        use crate::encoding::{decode_date, decode_time};

        // Decode date (4 bytes)
        let ((year, month, day, weekday), consumed_date) = decode_date(data)?;

        // Decode time (4 bytes)
        let ((hour, minute, second, hundredths), consumed_time) =
            decode_time(&data[consumed_date..])?;

        let datetime = BacnetDateTime {
            date: crate::object::Date {
                year,
                month,
                day,
                weekday,
            },
            time: crate::object::Time {
                hour,
                minute,
                second,
                hundredths,
            },
        };

        Ok((datetime, consumed_date + consumed_time))
    }
}

impl TimeSynchronizationRequest {
    /// Create a new Time Synchronization request
    pub fn new(date_time: BacnetDateTime) -> Self {
        Self { date_time }
    }

    /// Create Time Synchronization request with current time
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        Self::new(BacnetDateTime::now())
    }

    /// Encode the Time Synchronization request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        self.date_time.encode(buffer)
    }

    /// Decode a Time Synchronization request
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let (date_time, _consumed) = BacnetDateTime::decode(data)?;
        Ok(Self::new(date_time))
    }
}

impl UtcTimeSynchronizationRequest {
    /// Create a new UTC Time Synchronization request
    pub fn new(utc_date_time: BacnetDateTime) -> Self {
        Self { utc_date_time }
    }

    /// Create UTC Time Synchronization request with current UTC time
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        use chrono::{Datelike, Timelike, Utc};

        let now = Utc::now();
        let year = now.year() as u16;
        let month = now.month() as u8;
        let day = now.day() as u8;
        let weekday = now.weekday().number_from_monday() as u8;
        let hour = now.hour() as u8;
        let minute = now.minute() as u8;
        let second = now.second() as u8;
        let hundredths = (now.nanosecond() / 10_000_000) as u8;

        let date = crate::object::Date {
            year,
            month,
            day,
            weekday,
        };
        let time = crate::object::Time {
            hour,
            minute,
            second,
            hundredths,
        };
        let utc_date_time = BacnetDateTime::new(date, time);
        Self::new(utc_date_time)
    }

    /// Encode the UTC Time Synchronization request
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        self.utc_date_time.encode(buffer)
    }

    /// Decode a UTC Time Synchronization request
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let (utc_date_time, _consumed) = BacnetDateTime::decode(data)?;
        Ok(Self::new(utc_date_time))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectIdentifier, ObjectType};

    #[test]
    fn test_whois_request() {
        // Test Who-Is for all devices
        let whois_all = WhoIsRequest::new();
        assert!(whois_all.matches(123));
        assert!(whois_all.matches(456));

        // Test Who-Is for specific device
        let whois_specific = WhoIsRequest::for_device(123);
        assert!(whois_specific.matches(123));
        assert!(!whois_specific.matches(124));

        // Test Who-Is for range
        let whois_range = WhoIsRequest::for_range(100, 200);
        assert!(whois_range.matches(150));
        assert!(!whois_range.matches(50));
        assert!(!whois_range.matches(250));
    }

    #[test]
    fn test_whois_encoding() {
        let mut buffer = Vec::new();

        // Test encoding Who-Is for all devices
        let whois_all = WhoIsRequest::new();
        whois_all.encode(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 0); // No parameters for all devices

        // Test encoding Who-Is for specific device
        buffer.clear();
        let whois_specific = WhoIsRequest::for_device(123);
        whois_specific.encode(&mut buffer).unwrap();
        assert!(!buffer.is_empty());

        // Test decoding
        let decoded = WhoIsRequest::decode(&buffer).unwrap();
        assert_eq!(decoded, whois_specific);
    }

    #[test]
    fn test_iam_request() {
        let device_id = ObjectIdentifier::new(ObjectType::Device, 123);
        let iam = IAmRequest::new(device_id, 1476, 0, 999);

        assert_eq!(iam.device_identifier.instance, 123);
        assert_eq!(iam.max_apdu_length_accepted, 1476);
        assert_eq!(iam.vendor_identifier, 999);
    }

    #[test]
    fn test_read_property_request() {
        let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
        let read_prop = ReadPropertyRequest::new(object_id, 85); // Present Value

        assert_eq!(read_prop.object_identifier.instance, 1);
        assert_eq!(read_prop.property_identifier, 85);
        assert_eq!(read_prop.property_array_index, None);

        let read_prop_array = ReadPropertyRequest::with_array_index(object_id, 85, 0);
        assert_eq!(read_prop_array.property_array_index, Some(0));
    }

    #[test]
    fn test_write_property_request() {
        let object_id = ObjectIdentifier::new(ObjectType::AnalogOutput, 1);
        let property_value = vec![0x44, 0x42, 0x20, 0x00, 0x00]; // Real 40.0
        let write_prop = WritePropertyRequest::new(object_id, 85, property_value.clone());

        assert_eq!(write_prop.object_identifier.instance, 1);
        assert_eq!(write_prop.property_identifier, 85);
        assert_eq!(write_prop.property_value, property_value);
        assert_eq!(write_prop.priority, None);

        // Test with priority
        let write_prop_priority =
            WritePropertyRequest::with_priority(object_id, 85, property_value.clone(), 8);
        assert_eq!(write_prop_priority.priority, Some(8));

        // Test encoding/decoding
        let mut buffer = Vec::new();
        write_prop.encode(&mut buffer).unwrap();
        assert!(!buffer.is_empty());

        let decoded = WritePropertyRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.object_identifier.instance, 1);
        assert_eq!(decoded.property_identifier, 85);
        assert_eq!(decoded.property_value, property_value);
    }

    #[test]
    fn test_read_property_multiple_request() {
        let object_id1 = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
        let object_id2 = ObjectIdentifier::new(ObjectType::BinaryInput, 2);

        let prop_ref1 = PropertyReference::new(85); // Present Value
        let prop_ref2 = PropertyReference::new(77); // Object Name
        let prop_ref3 = PropertyReference::with_array_index(87, 8); // Priority Array[8]

        let spec1 = ReadAccessSpecification::new(object_id1, vec![prop_ref1, prop_ref2]);
        let spec2 = ReadAccessSpecification::new(object_id2, vec![prop_ref3]);

        let rpm_request = ReadPropertyMultipleRequest::new(vec![spec1, spec2]);

        assert_eq!(rpm_request.read_access_specifications.len(), 2);
        assert_eq!(
            rpm_request.read_access_specifications[0]
                .property_references
                .len(),
            2
        );
        assert_eq!(
            rpm_request.read_access_specifications[1]
                .property_references
                .len(),
            1
        );
        assert_eq!(
            rpm_request.read_access_specifications[1].property_references[0].property_array_index,
            Some(8)
        );
    }

    #[test]
    fn test_subscribe_cov_request() {
        let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
        let cov_req = SubscribeCovRequest::new(123, object_id);

        assert_eq!(cov_req.subscriber_process_identifier, 123);
        assert_eq!(cov_req.monitored_object_identifier.instance, 1);
        assert_eq!(cov_req.issue_confirmed_notifications, None);
        assert_eq!(cov_req.lifetime, None);

        // Test with confirmation
        let cov_confirmed = SubscribeCovRequest::with_confirmation(123, object_id, true);
        assert_eq!(cov_confirmed.issue_confirmed_notifications, Some(true));

        // Test with lifetime
        let cov_lifetime = SubscribeCovRequest::with_lifetime(123, object_id, 3600);
        assert_eq!(cov_lifetime.lifetime, Some(3600));

        // Test encoding
        let mut buffer = Vec::new();
        cov_req.encode(&mut buffer).unwrap();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_cov_subscription_manager() {
        let mut manager = CovSubscriptionManager::new();

        let device_id = ObjectIdentifier::new(ObjectType::Device, 1);
        let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);

        let subscription = CovSubscription::new(123, device_id, object_id, 3600);
        manager.add_subscription(subscription);

        assert_eq!(manager.active_count(), 1);

        let subscriptions = manager.get_subscriptions_for_object(object_id);
        assert_eq!(subscriptions.len(), 1);
        assert_eq!(subscriptions[0].subscriber_process_identifier, 123);

        // Test time updates
        manager.update_timers(1800); // 30 minutes
        let subscriptions = manager.get_subscriptions_for_object(object_id);
        assert_eq!(subscriptions[0].time_remaining, 1800);

        // Test expiration
        manager.update_timers(1800); // Another 30 minutes
        assert_eq!(manager.active_count(), 0);

        manager.cleanup_expired();
        assert_eq!(manager.subscriptions.len(), 0);
    }

    #[test]
    fn test_cov_notification_request() {
        let device_id = ObjectIdentifier::new(ObjectType::Device, 1);
        let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
        let values = vec![
            crate::object::PropertyValue::Real(25.5), // Present Value
            crate::object::PropertyValue::Boolean(false), // Status Flags
        ];

        let notification = CovNotificationRequest::new(123, device_id, object_id, 3600, values);

        assert_eq!(notification.subscriber_process_identifier, 123);
        assert_eq!(notification.initiating_device_identifier, device_id);
        assert_eq!(notification.monitored_object_identifier, object_id);
        assert_eq!(notification.time_remaining, 3600);
        assert_eq!(notification.list_of_values.len(), 2);

        // Test encoding
        let mut buffer = Vec::new();
        notification.encode(&mut buffer).unwrap();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_atomic_read_file_request() {
        let file_id = ObjectIdentifier::new(ObjectType::File, 1);

        // Test stream access
        let read_stream = AtomicReadFileRequest::new_stream_access(file_id, 0, 1024);
        match &read_stream.access_method {
            FileAccessMethod::StreamAccess {
                file_start_position,
                requested_octet_count,
            } => {
                assert_eq!(*file_start_position, 0);
                assert_eq!(*requested_octet_count, 1024);
            }
            _ => panic!("Expected StreamAccess"),
        }

        // Test record access
        let read_record = AtomicReadFileRequest::new_record_access(file_id, 5, 10);
        match &read_record.access_method {
            FileAccessMethod::RecordAccess {
                file_start_record,
                requested_record_count,
            } => {
                assert_eq!(*file_start_record, 5);
                assert_eq!(*requested_record_count, 10);
            }
            _ => panic!("Expected RecordAccess"),
        }

        // Test encoding
        let mut buffer = Vec::new();
        read_stream.encode(&mut buffer).unwrap();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_atomic_read_file_response() {
        // Test stream access response
        let data = vec![1, 2, 3, 4, 5];
        let response_stream = AtomicReadFileResponse::new_stream_access(false, 0, data.clone());
        assert!(!response_stream.end_of_file);

        match &response_stream.access_method_result {
            FileAccessMethodResult::StreamAccess {
                file_start_position,
                file_data,
            } => {
                assert_eq!(*file_start_position, 0);
                assert_eq!(*file_data, data);
            }
            _ => panic!("Expected StreamAccess result"),
        }

        // Test record access response
        let records = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let response_record = AtomicReadFileResponse::new_record_access(true, 10, records.clone());
        assert!(response_record.end_of_file);

        match &response_record.access_method_result {
            FileAccessMethodResult::RecordAccess {
                file_start_record,
                record_count,
                file_record_data,
            } => {
                assert_eq!(*file_start_record, 10);
                assert_eq!(*record_count, 3);
                assert_eq!(*file_record_data, records);
            }
            _ => panic!("Expected RecordAccess result"),
        }
    }

    #[test]
    fn test_atomic_write_file_request() {
        let file_id = ObjectIdentifier::new(ObjectType::File, 1);

        // Test stream access
        let data = vec![65, 66, 67, 68]; // "ABCD"
        let write_stream = AtomicWriteFileRequest::new_stream_access(file_id, 100, data.clone());
        match &write_stream.access_method {
            FileWriteAccessMethod::StreamAccess {
                file_start_position,
                file_data,
            } => {
                assert_eq!(*file_start_position, 100);
                assert_eq!(*file_data, data);
            }
            _ => panic!("Expected StreamAccess"),
        }

        // Test record access
        let records = vec![
            b"Record 1".to_vec(),
            b"Record 2".to_vec(),
            b"Record 3".to_vec(),
        ];
        let write_record = AtomicWriteFileRequest::new_record_access(file_id, 5, records.clone());
        match &write_record.access_method {
            FileWriteAccessMethod::RecordAccess {
                file_start_record,
                record_count,
                file_record_data,
            } => {
                assert_eq!(*file_start_record, 5);
                assert_eq!(*record_count, 3);
                assert_eq!(*file_record_data, records);
            }
            _ => panic!("Expected RecordAccess"),
        }

        // Test encoding
        let mut buffer = Vec::new();
        write_stream.encode(&mut buffer).unwrap();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_atomic_write_file_response() {
        let response = AtomicWriteFileResponse {
            file_start_position: 150,
        };
        assert_eq!(response.file_start_position, 150);
    }

    #[test]
    fn test_bacnet_datetime() {
        // Test creating specific datetime
        let date = crate::object::Date {
            year: 2024,
            month: 3,
            day: 15,
            weekday: 5,
        };
        let time = crate::object::Time {
            hour: 14,
            minute: 30,
            second: 45,
            hundredths: 50,
        };
        let datetime = BacnetDateTime::new(date, time);
        assert_eq!(datetime.date.year, 2024);
        assert_eq!(datetime.date.month, 3);
        assert_eq!(datetime.date.day, 15);
        assert_eq!(datetime.date.weekday, 5); // Friday
        assert_eq!(datetime.time.hour, 14);
        assert_eq!(datetime.time.minute, 30);
        assert_eq!(datetime.time.second, 45);
        assert_eq!(datetime.time.hundredths, 50);

        // Test unspecified datetime
        let unspecified = BacnetDateTime::unspecified();
        assert!(unspecified.is_unspecified());
        assert_eq!(unspecified.date.year, 255);
        assert_eq!(unspecified.time.hour, 255);

        // Test encoding/decoding
        let mut buffer = Vec::new();
        datetime.encode(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 10); // 1 byte tag + 4 bytes date + 1 byte tag + 4 bytes time

        let (decoded, consumed) = BacnetDateTime::decode(&buffer).unwrap();
        assert_eq!(consumed, 10);
        assert_eq!(decoded, datetime);
    }

    #[test]
    fn test_time_synchronization_request() {
        let date = crate::object::Date {
            year: 2024,
            month: 6,
            day: 20,
            weekday: 4,
        };
        let time = crate::object::Time {
            hour: 10,
            minute: 15,
            second: 30,
            hundredths: 25,
        };
        let datetime = BacnetDateTime::new(date, time);
        let time_sync = TimeSynchronizationRequest::new(datetime);

        assert_eq!(time_sync.date_time, datetime);

        // Test encoding/decoding
        let mut buffer = Vec::new();
        time_sync.encode(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 10);

        let decoded = TimeSynchronizationRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.date_time, datetime);
    }

    #[test]
    fn test_utc_time_synchronization_request() {
        let date = crate::object::Date {
            year: 2024,
            month: 6,
            day: 20,
            weekday: 4,
        };
        let time = crate::object::Time {
            hour: 18,
            minute: 45,
            second: 15,
            hundredths: 75,
        };
        let utc_datetime = BacnetDateTime::new(date, time);
        let utc_sync = UtcTimeSynchronizationRequest::new(utc_datetime);

        assert_eq!(utc_sync.utc_date_time, utc_datetime);

        // Test encoding/decoding
        let mut buffer = Vec::new();
        utc_sync.encode(&mut buffer).unwrap();
        assert_eq!(buffer.len(), 10);

        let decoded = UtcTimeSynchronizationRequest::decode(&buffer).unwrap();
        assert_eq!(decoded.utc_date_time, utc_datetime);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_time_synchronization_now() {
        // Test creating time sync with current time
        let now_sync = TimeSynchronizationRequest::now();
        assert!(!now_sync.date_time.is_unspecified());

        let utc_now_sync = UtcTimeSynchronizationRequest::now();
        assert!(!utc_now_sync.utc_date_time.is_unspecified());

        // The current time should be reasonable
        assert!(now_sync.date_time.date.year >= 2024);
        assert!(now_sync.date_time.date.month >= 1 && now_sync.date_time.date.month <= 12);
        assert!(now_sync.date_time.date.day >= 1 && now_sync.date_time.date.day <= 31);
        assert!(now_sync.date_time.time.hour <= 23);
        assert!(now_sync.date_time.time.minute <= 59);
        assert!(now_sync.date_time.time.second <= 59);
        assert!(now_sync.date_time.time.hundredths <= 99);
    }
}
