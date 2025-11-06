//! BACnet Client Utilities
//!
//! This module provides high-level client utilities for common BACnet operations
//! such as device discovery, object enumeration, and property reading.

#[cfg(feature = "std")]
use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap as HashMap, string::String, vec::Vec};

use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType},
    service::{
        ConfirmedServiceChoice, IAmRequest, PropertyReference, ReadAccessSpecification,
        ReadPropertyMultipleRequest, UnconfirmedServiceChoice, WhoIsRequest,
    },
};

/// High-level BACnet client for device communication
#[cfg(feature = "std")]
pub struct BacnetClient {
    socket: UdpSocket,
    timeout: Duration,
}

/// Discovered BACnet device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: u32,
    pub address: SocketAddr,
    pub vendor_id: u32,
    pub vendor_name: String,
    pub max_apdu: u32,
    pub segmentation: u32,
}

/// Object information with common properties
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub object_identifier: ObjectIdentifier,
    pub object_name: Option<String>,
    pub description: Option<String>,
    pub present_value: Option<PropertyValue>,
    pub units: Option<String>,
    pub status_flags: Option<Vec<bool>>,
}

/// Decoded property values
#[derive(Debug, Clone)]
pub enum PropertyValue {
    Real(f32),
    Boolean(bool),
    Unsigned(u32),
    Signed(i32),
    CharacterString(String),
    Enumerated(u32),
    Null,
}

#[cfg(feature = "std")]
impl BacnetClient {
    /// Create a new BACnet client
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;

        Ok(Self {
            socket,
            timeout: Duration::from_secs(5),
        })
    }

    /// Discover a device by IP address
    pub fn discover_device(
        &self,
        target_addr: SocketAddr,
    ) -> Result<DeviceInfo, Box<dyn std::error::Error>> {
        // Send Who-Is request
        let whois = WhoIsRequest::new();
        let mut buffer = Vec::new();
        whois.encode(&mut buffer)?;

        // Create and send message
        let message =
            self.create_unconfirmed_message(UnconfirmedServiceChoice::WhoIs as u8, &buffer);
        self.socket.send_to(&message, target_addr)?;

        // Wait for I-Am response
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if source == target_addr {
                        if let Some(device_info) =
                            self.parse_iam_response(&recv_buffer[..len], source)
                        {
                            return Ok(device_info);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Err("Device discovery timeout".into())
    }

    /// Read the device's object list
    pub fn read_object_list(
        &self,
        target_addr: SocketAddr,
        device_id: u32,
    ) -> Result<Vec<ObjectIdentifier>, Box<dyn std::error::Error>> {
        let device_object = ObjectIdentifier::new(ObjectType::Device, device_id);
        let property_ref = PropertyReference::new(76); // Object_List property
        let read_spec = ReadAccessSpecification::new(device_object, vec![property_ref]);
        let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

        let invoke_id = 1;
        let response_data = self.send_confirmed_request(
            target_addr,
            invoke_id,
            ConfirmedServiceChoice::ReadPropertyMultiple,
            &self.encode_rpm_request(&rpm_request)?,
        )?;

        self.parse_object_list_response(&response_data)
    }

    /// Read properties for multiple objects
    pub fn read_objects_properties(
        &self,
        target_addr: SocketAddr,
        objects: &[ObjectIdentifier],
    ) -> Result<Vec<ObjectInfo>, Box<dyn std::error::Error>> {
        let mut objects_info = Vec::new();
        let batch_size = 5;

        for (batch_idx, chunk) in objects.chunks(batch_size).enumerate() {
            let mut read_specs = Vec::new();

            for obj in chunk {
                let mut property_refs = Vec::new();

                // Always read basic properties
                property_refs.push(PropertyReference::new(77)); // Object_Name
                property_refs.push(PropertyReference::new(28)); // Description

                // Add Present_Value for input/output/value objects
                match obj.object_type {
                    ObjectType::AnalogInput
                    | ObjectType::AnalogOutput
                    | ObjectType::AnalogValue
                    | ObjectType::BinaryInput
                    | ObjectType::BinaryOutput
                    | ObjectType::BinaryValue
                    | ObjectType::MultiStateInput
                    | ObjectType::MultiStateOutput
                    | ObjectType::MultiStateValue => {
                        property_refs.push(PropertyReference::new(85)); // Present_Value
                        property_refs.push(PropertyReference::new(111)); // Status_Flags
                    }
                    _ => {}
                }

                // Add Units for analog objects
                match obj.object_type {
                    ObjectType::AnalogInput
                    | ObjectType::AnalogOutput
                    | ObjectType::AnalogValue => {
                        property_refs.push(PropertyReference::new(117)); // Units
                    }
                    _ => {}
                }

                read_specs.push(ReadAccessSpecification::new(*obj, property_refs));
            }

            let rpm_request = ReadPropertyMultipleRequest::new(read_specs);
            let invoke_id = (batch_idx + 2) as u8;

            match self.send_confirmed_request(
                target_addr,
                invoke_id,
                ConfirmedServiceChoice::ReadPropertyMultiple,
                &self.encode_rpm_request(&rpm_request)?,
            ) {
                Ok(response_data) => {
                    match self.parse_rpm_response(&response_data, chunk) {
                        Ok(mut batch_info) => objects_info.append(&mut batch_info),
                        Err(_) => {
                            // Add objects with minimal info on parse failure
                            for obj in chunk {
                                objects_info.push(ObjectInfo {
                                    object_identifier: *obj,
                                    object_name: None,
                                    description: None,
                                    present_value: None,
                                    units: None,
                                    status_flags: None,
                                });
                            }
                        }
                    }
                }
                Err(_) => {
                    // Add objects with minimal info on communication failure
                    for obj in chunk {
                        objects_info.push(ObjectInfo {
                            object_identifier: *obj,
                            object_name: None,
                            description: None,
                            present_value: None,
                            units: None,
                            status_flags: None,
                        });
                    }
                }
            }

            // Small delay between requests
            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(objects_info)
    }

    /// Create an unconfirmed message
    fn create_unconfirmed_message(&self, service_choice: u8, service_data: &[u8]) -> Vec<u8> {
        // Create NPDU
        let mut npdu = Npdu::new();
        npdu.control.expecting_reply = false;
        npdu.control.priority = 0;
        let npdu_buffer = npdu.encode();

        // Create unconfirmed service request APDU
        let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
        apdu.push(service_choice);
        apdu.extend_from_slice(service_data);

        // Combine NPDU and APDU
        let mut message = npdu_buffer;
        message.extend_from_slice(&apdu);

        // Wrap in BVLC header for BACnet/IP (unicast)
        let mut bvlc_message = vec![0x81, 0x0A, 0x00, 0x00];
        bvlc_message.extend_from_slice(&message);

        // Update BVLC length
        let total_len = bvlc_message.len() as u16;
        bvlc_message[2] = (total_len >> 8) as u8;
        bvlc_message[3] = (total_len & 0xFF) as u8;

        bvlc_message
    }

    /// Send a confirmed request and wait for response
    fn send_confirmed_request(
        &self,
        target_addr: SocketAddr,
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let apdu = Apdu::ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: true,
            max_segments: MaxSegments::Unspecified,
            max_response_size: MaxApduSize::Up1476,
            invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice,
            service_data: service_data.to_vec(),
        };

        let apdu_data = apdu.encode();
        let mut npdu = Npdu::new();
        npdu.control.expecting_reply = true;
        npdu.control.priority = 0;
        let npdu_data = npdu.encode();

        let mut message = npdu_data;
        message.extend_from_slice(&apdu_data);

        let mut bvlc_message = vec![0x81, 0x0A, 0x00, 0x00];
        bvlc_message.extend_from_slice(&message);

        let total_len = bvlc_message.len() as u16;
        bvlc_message[2] = (total_len >> 8) as u8;
        bvlc_message[3] = (total_len & 0xFF) as u8;

        self.socket.send_to(&bvlc_message, target_addr)?;

        // Wait for response
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if source == target_addr {
                        if let Some(response_data) =
                            self.process_confirmed_response(&recv_buffer[..len], invoke_id)
                        {
                            return Ok(response_data);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Err("Request timeout".into())
    }

    /// Parse I-Am response
    fn parse_iam_response(&self, data: &[u8], source: SocketAddr) -> Option<DeviceInfo> {
        // Check BVLC header
        if data.len() < 4 || data[0] != 0x81 {
            return None;
        }

        let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
        if data.len() != bvlc_length as usize {
            return None;
        }

        // Decode NPDU
        let npdu_start = 4;
        let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

        // Decode APDU
        let apdu_start = npdu_start + npdu_len;
        let apdu = &data[apdu_start..];

        if apdu.len() < 2 || apdu[0] != 0x10 || apdu[1] != UnconfirmedServiceChoice::IAm as u8 {
            return None;
        }

        match IAmRequest::decode(&apdu[2..]) {
            Ok(iam) => {
                let vendor_name = crate::vendor::get_vendor_name(iam.vendor_identifier as u16)
                    .unwrap_or("Unknown Vendor")
                    .to_string();

                Some(DeviceInfo {
                    device_id: iam.device_identifier.instance,
                    address: source,
                    vendor_id: iam.vendor_identifier,
                    vendor_name,
                    max_apdu: iam.max_apdu_length_accepted,
                    segmentation: iam.segmentation_supported,
                })
            }
            Err(_) => None,
        }
    }

    /// Process confirmed response
    fn process_confirmed_response(&self, data: &[u8], expected_invoke_id: u8) -> Option<Vec<u8>> {
        // Check BVLC header
        if data.len() < 4 || data[0] != 0x81 {
            return None;
        }

        let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
        if data.len() != bvlc_length as usize {
            return None;
        }

        // Decode NPDU and APDU
        let npdu_start = 4;
        let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

        let apdu_start = npdu_start + npdu_len;
        let apdu = Apdu::decode(&data[apdu_start..]).ok()?;

        match apdu {
            Apdu::ComplexAck {
                invoke_id,
                service_data,
                ..
            } => {
                if invoke_id == expected_invoke_id {
                    Some(service_data)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Encode ReadPropertyMultiple request
    fn encode_rpm_request(
        &self,
        request: &ReadPropertyMultipleRequest,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();

        for spec in &request.read_access_specifications {
            // Object identifier - context tag 0
            let object_id: u32 = spec.object_identifier.into();
            buffer.push(0x0C);
            buffer.extend_from_slice(&object_id.to_be_bytes());

            // Property references - context tag 1
            buffer.push(0x1E);
            for prop_ref in &spec.property_references {
                buffer.push(0x09);
                buffer.push(prop_ref.property_identifier as u8);

                if let Some(array_index) = prop_ref.property_array_index {
                    buffer.push(0x19);
                    buffer.push(array_index as u8);
                }
            }
            buffer.push(0x1F);
        }

        Ok(buffer)
    }

    /// Parse object list response
    fn parse_object_list_response(
        &self,
        data: &[u8],
    ) -> Result<Vec<ObjectIdentifier>, Box<dyn std::error::Error>> {
        let mut objects = Vec::new();
        let mut pos = 0;

        // Scan for object identifiers (0xC4 tag)
        while pos + 5 <= data.len() {
            if data[pos] == 0xC4 {
                pos += 1;
                let obj_id_bytes = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
                let obj_id = u32::from_be_bytes(obj_id_bytes);

                if let Ok(identifier) = ObjectIdentifier::try_from(obj_id) {
                    // Skip device object itself
                    if identifier.object_type != ObjectType::Device {
                        objects.push(identifier);
                    }
                }

                pos += 4;
            } else {
                pos += 1;
            }
        }

        Ok(objects)
    }

    /// Parse ReadPropertyMultiple response
    fn parse_rpm_response(
        &self,
        data: &[u8],
        objects: &[ObjectIdentifier],
    ) -> Result<Vec<ObjectInfo>, Box<dyn std::error::Error>> {
        let mut objects_info = Vec::new();

        // Simple implementation - create ObjectInfo for each requested object
        for obj in objects {
            let mut object_info = ObjectInfo {
                object_identifier: *obj,
                object_name: None,
                description: None,
                present_value: None,
                units: None,
                status_flags: None,
            };

            // Parse properties from response data
            // This is a simplified implementation - in practice you'd need more robust parsing
            if let Some(PropertyValue::CharacterString(s)) = extract_property_value(data, 77) {
                object_info.object_name = Some(s);
            }

            if let Some(PropertyValue::CharacterString(s)) = extract_property_value(data, 28) {
                object_info.description = Some(s);
            }

            if let Some(value) = extract_property_value(data, 85) {
                object_info.present_value = Some(value);
            }

            objects_info.push(object_info);
        }

        Ok(objects_info)
    }
}

/// Extract property value from encoded data (simplified implementation)
fn extract_property_value(_data: &[u8], _property_id: u32) -> Option<PropertyValue> {
    // This would need a full implementation based on BACnet encoding rules
    // For now, return None as a placeholder
    None
}

/// Get object type display name
pub fn get_object_type_name(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Device => "Device",
        ObjectType::AnalogInput => "Analog Input",
        ObjectType::AnalogOutput => "Analog Output",
        ObjectType::AnalogValue => "Analog Value",
        ObjectType::BinaryInput => "Binary Input",
        ObjectType::BinaryOutput => "Binary Output",
        ObjectType::BinaryValue => "Binary Value",
        ObjectType::MultiStateInput => "Multi-State Input",
        ObjectType::MultiStateOutput => "Multi-State Output",
        ObjectType::MultiStateValue => "Multi-State Value",
        ObjectType::Calendar => "Calendar",
        ObjectType::Command => "Command",
        ObjectType::EventEnrollment => "Event Enrollment",
        ObjectType::File => "File",
        ObjectType::Group => "Group",
        ObjectType::Loop => "Loop",
        ObjectType::NotificationClass => "Notification Class",
        ObjectType::Program => "Program",
        ObjectType::Schedule => "Schedule",
        ObjectType::Averaging => "Averaging",
        ObjectType::TrendLog => "Trend Log",
        ObjectType::LifeSafetyPoint => "Life Safety Point",
        ObjectType::LifeSafetyZone => "Life Safety Zone",
        ObjectType::Accumulator => "Accumulator",
        ObjectType::PulseConverter => "Pulse Converter",
        ObjectType::EventLog => "Event Log",
        ObjectType::GlobalGroup => "Global Group",
        ObjectType::TrendLogMultiple => "Trend Log Multiple",
        ObjectType::LoadControl => "Load Control",
        ObjectType::StructuredView => "Structured View",
        ObjectType::AccessDoor => "Access Door",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_type_names() {
        assert_eq!(
            get_object_type_name(ObjectType::AnalogInput),
            "Analog Input"
        );
        assert_eq!(get_object_type_name(ObjectType::Device), "Device");
        assert_eq!(
            get_object_type_name(ObjectType::BinaryOutput),
            "Binary Output"
        );
    }

    #[test]
    fn test_object_id_encoding() {
        let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 123);
        let encoded: u32 = object_id.into();
        let decoded = ObjectIdentifier::try_from(encoded).unwrap();
        assert_eq!(decoded.object_type, ObjectType::AnalogInput);
        assert_eq!(decoded.instance, 123);

        let object_id = ObjectIdentifier::new(ObjectType::Device, 5047);
        let encoded: u32 = object_id.into();
        let decoded = ObjectIdentifier::try_from(encoded).unwrap();
        assert_eq!(decoded.object_type, ObjectType::Device);
        assert_eq!(decoded.instance, 5047);
    }
}
