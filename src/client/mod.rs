//! BACnet Client Utilities
//!
//! This module provides high-level client utilities for common BACnet operations
//! such as device discovery, object enumeration, and property reading.
//!
//! The entry point is [`BacnetClient`]. Construct one with [`BacnetClient::new`]
//! for defaults, or with [`BacnetClient::builder`] to customize the local
//! interface, port, timeout, and retries. All methods return [`ClientError`] on
//! failure.

mod config;
mod error;
mod transaction;

pub use config::{ClientBuilder, ClientConfig, DEFAULT_HOST, DEFAULT_TIMEOUT};
pub use error::ClientError;

use transaction::InvokeIdAllocator;

#[cfg(feature = "std")]
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap as HashMap, string::String, vec::Vec};

#[cfg(feature = "std")]
use crate::object::AnalogInput;
use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    datalink::bip::BACNET_IP_PORT,
    encoding::decode_object_identifier,
    network::Npdu,
    object::{EngineeringUnits, ObjectIdentifier, ObjectType, PropertyIdentifier, Segmentation},
    property::{encode_property_value, PropertyValue},
    service::{
        AbortReason, ConfirmedServiceChoice, IAmRequest, PropertyReference, PropertyResultValue,
        ReadAccessResult, ReadAccessSpecification, ReadPropertyMultipleRequest,
        ReadPropertyMultipleResponse, ReadPropertyRequest, ReadPropertyResponse,
        UnconfirmedServiceChoice, WhoIsRequest, WritePropertyRequest,
    },
};

/// BVLC function code: Original-Unicast-NPDU.
const BVLC_ORIGINAL_UNICAST: u8 = 0x0A;
/// BVLC function code: Original-Broadcast-NPDU (local subnet broadcast).
const BVLC_ORIGINAL_BROADCAST: u8 = 0x0B;

/// High-level BACnet client for device communication
#[cfg(feature = "std")]
pub struct BacnetClient {
    socket: UdpSocket,
    timeout: Duration,
    /// Number of retries after an initial timeout (reserved for future use by
    /// the request paths; not yet applied by the existing methods).
    #[allow(dead_code)]
    retries: u8,
    /// Allocates invoke IDs for confirmed-request transactions.
    invoke_ids: InvokeIdAllocator,
}

/// Discovered BACnet device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: u32,
    pub address: SocketAddr,
    pub vendor_id: u16,
    pub vendor_name: String,
    pub max_apdu: u32,
    pub segmentation: Segmentation,
}

/// Object information with common properties
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub object_identifier: ObjectIdentifier,
    pub object_name: Option<String>,
    pub description: Option<String>,
    pub present_value: Option<PropertyValue>,
    pub units: Option<EngineeringUnits>,
    pub status_flags: Option<Vec<bool>>,
}

/// Result of a verified write (see [`BacnetClient::write_property_verified`]).
///
/// A BACnet `SimpleAck` only confirms the device *accepted* the WriteProperty
/// request — not that the value became effective. For commandable objects the
/// `Present_Value` is resolved from the priority array, so an accepted write can
/// still be overridden by a higher-priority slot (or the property may not be
/// commandable at the chosen priority). This type makes that difference visible.
#[derive(Debug, Clone, PartialEq)]
pub enum WriteOutcome {
    /// The device acknowledged the write and a read-back confirms the value.
    Verified,
    /// The device acknowledged the write, but reading the property back shows a
    /// different value — the write did not take effect.
    NotEffective {
        /// The value the property actually holds after the write.
        read_back: PropertyValue,
    },
}

#[cfg(feature = "std")]
impl BacnetClient {
    /// Create a new BACnet client with default configuration.
    ///
    /// Binds to all interfaces on an OS-assigned ephemeral port with a 5 second
    /// timeout. Use [`BacnetClient::builder`] to customize.
    pub fn new() -> Result<Self, ClientError> {
        Self::from_config(ClientConfig::default())
    }

    /// Create a new BACnet client with a specific local socket address (any
    /// type implementing [`ToSocketAddrs`]).
    pub fn new_with_local_addr<A: ToSocketAddrs>(addr: A) -> Result<Self, ClientError> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(DEFAULT_TIMEOUT))?;

        Ok(Self {
            socket,
            timeout: DEFAULT_TIMEOUT,
            retries: 0,
            invoke_ids: InvokeIdAllocator::new(),
        })
    }

    /// Begin building a client with custom configuration.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// The per-request timeout this client is configured with.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The local socket address the client is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, ClientError> {
        Ok(self.socket.local_addr()?)
    }

    /// Construct a client from a fully-specified [`ClientConfig`], binding the
    /// UDP socket.
    pub(crate) fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
        let socket = UdpSocket::bind(config.bind_addr())?;
        socket.set_read_timeout(Some(config.timeout))?;

        Ok(Self {
            socket,
            timeout: config.timeout,
            retries: config.retries,
            invoke_ids: InvokeIdAllocator::new(),
        })
    }

    /// Discover a device by IP address
    pub fn discover_device(&self, target_addr: SocketAddr) -> Result<DeviceInfo, ClientError> {
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
                // A per-recv socket timeout is WouldBlock on Unix and TimedOut
                // on Windows; both mean "nothing yet", so keep waiting until our
                // own deadline elapses.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(ClientError::Timeout)
    }

    /// Broadcast a Who-Is on the local subnet and collect every device that
    /// answers with an I-Am, until the configured timeout elapses.
    ///
    /// `low_limit` and `high_limit` bound the device-instance range; pass both
    /// to target a range, or `None`/`None` to ask every device. Results are
    /// de-duplicated by device id.
    ///
    /// Unlike [`discover_device`](Self::discover_device) (which unicasts to a
    /// single known address), this reaches all devices on the local network.
    pub fn who_is(
        &self,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let broadcast = SocketAddr::from(([255, 255, 255, 255], BACNET_IP_PORT));
        self.who_is_to(broadcast, low_limit, high_limit)
    }

    /// Send a Who-Is to a specific address (broadcast or unicast) and collect
    /// all I-Am replies until the timeout elapses.
    ///
    /// This is the explicit-target form of [`who_is`](Self::who_is); use it for
    /// subnet-directed broadcasts (e.g. `192.168.1.255:47808`) or to query a
    /// BBMD/foreign-device peer directly.
    pub fn who_is_to(
        &self,
        target_addr: SocketAddr,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        // Enable broadcast so sends to a broadcast address are permitted.
        self.socket.set_broadcast(true)?;

        let whois = match (low_limit, high_limit) {
            (Some(low), Some(high)) => WhoIsRequest::for_range(low, high),
            _ => WhoIsRequest::new(),
        };
        let mut buffer = Vec::new();
        whois.encode(&mut buffer)?;

        let message = self.create_unconfirmed_bvlc(
            UnconfirmedServiceChoice::WhoIs as u8,
            &buffer,
            BVLC_ORIGINAL_BROADCAST,
        );
        self.socket.send_to(&message, target_addr)?;

        // Collect every distinct device that replies before the timeout.
        let mut devices = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if let Some(info) = self.parse_iam_response(&recv_buffer[..len], source) {
                        if seen.insert(info.device_id) {
                            devices.push(info);
                        }
                    }
                }
                // A per-recv socket timeout is WouldBlock on Unix and TimedOut
                // on Windows; both mean "nothing yet", so keep waiting until our
                // own deadline elapses.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(devices)
    }

    /// Read the device's object list
    pub fn read_object_list(
        &self,
        target_addr: SocketAddr,
        device_id: u32,
    ) -> Result<Vec<ObjectIdentifier>, ClientError> {
        let device_object = ObjectIdentifier::new(ObjectType::Device, device_id);
        let property_ref = PropertyReference::new(PropertyIdentifier::ObjectList); // Object_List property
        let read_spec = ReadAccessSpecification::new(device_object, vec![property_ref]);
        let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

        let response_data = self.send_confirmed_request(
            target_addr,
            ConfirmedServiceChoice::ReadPropertyMultiple,
            &self.encode_rpm_request(&rpm_request)?,
        )?;

        // The Object_List property comes back as a list of object identifiers
        // inside the ReadPropertyMultiple result. Prefer the structured decoder;
        // the device object itself is dropped.
        let mut objects = Vec::new();
        if let Ok(response) = ReadPropertyMultipleResponse::decode(&response_data) {
            for access in response.read_access_results {
                for result in access.results {
                    if let PropertyResultValue::Value(values) = result.value {
                        for value in values {
                            if let PropertyValue::ObjectIdentifier(oid) = value {
                                if oid.object_type != ObjectType::Device {
                                    objects.push(oid);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Backstop: if the structured decode produced nothing (e.g. an encoding
        // variant it doesn't yet fully handle), scan the raw response for object
        // identifiers so discovery still works.
        if objects.is_empty() {
            objects = Self::scan_object_identifiers(&response_data);
        }

        Ok(objects)
    }

    /// Scan a raw response buffer for application-tagged object identifiers
    /// (tag `0xC4`), skipping the device object. Used as a fallback when the
    /// structured ReadPropertyMultiple decoder yields nothing.
    fn scan_object_identifiers(data: &[u8]) -> Vec<ObjectIdentifier> {
        let mut objects = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            // 0xC4 is the application tag for a 4-byte object identifier.
            if data[pos] == 0xC4 {
                match decode_object_identifier(&data[pos..]) {
                    Ok((identifier, consumed)) => {
                        if identifier.object_type != ObjectType::Device {
                            objects.push(identifier);
                        }
                        pos += consumed;
                    }
                    Err(_) => pos += 1,
                }
            } else {
                pos += 1;
            }
        }

        objects
    }

    /// Read properties for multiple objects
    pub fn read_objects_properties(
        &self,
        target_addr: SocketAddr,
        objects: &[ObjectIdentifier],
    ) -> Result<Vec<ObjectInfo>, ClientError> {
        let mut objects_info = Vec::new();
        let batch_size = 5;

        for chunk in objects.chunks(batch_size) {
            let mut read_specs = Vec::new();

            for obj in chunk {
                let pr = match obj.object_type {
                    ObjectType::AnalogInput => PropertyReferenceVector::analog_input(),
                    ObjectType::AnalogOutput => PropertyReferenceVector::analog_output(),
                    ObjectType::AnalogValue => PropertyReferenceVector::analog_value(),
                    ObjectType::BinaryInput => PropertyReferenceVector::binary_input(),
                    ObjectType::BinaryOutput => PropertyReferenceVector::binary_output(),
                    ObjectType::BinaryValue => PropertyReferenceVector::binary_value(),
                    ObjectType::Calendar => PropertyReferenceVector::calendar(),
                    ObjectType::Command => PropertyReferenceVector::command(),
                    ObjectType::Device => PropertyReferenceVector::device(),
                    ObjectType::EventEnrollment => PropertyReferenceVector::event_enrollment(),
                    ObjectType::File => PropertyReferenceVector::file(),
                    ObjectType::Group => PropertyReferenceVector::group(),
                    ObjectType::Loop => PropertyReferenceVector::r#loop(),
                    ObjectType::MultiStateInput => PropertyReferenceVector::multistate_input(),
                    ObjectType::MultiStateOutput => PropertyReferenceVector::multistate_output(),
                    ObjectType::NotificationClass => PropertyReferenceVector::notification_class(),
                    ObjectType::Program => PropertyReferenceVector::program(),
                    ObjectType::Schedule => PropertyReferenceVector::schedule(),
                    ObjectType::Averaging => PropertyReferenceVector::averaging(),
                    ObjectType::MultiStateValue => PropertyReferenceVector::multistate_value(),
                    ObjectType::TrendLog => PropertyReferenceVector::trend_log(),
                    ObjectType::LifeSafetyPoint => PropertyReferenceVector::life_safety_point(),
                    ObjectType::LifeSafetyZone => PropertyReferenceVector::life_safety_zone(),
                    ObjectType::Accumulator => todo!(),
                    ObjectType::PulseConverter => PropertyReferenceVector::pulse_converter(),
                    ObjectType::EventLog => PropertyReferenceVector::event_log(),
                    ObjectType::GlobalGroup => todo!(),
                    ObjectType::TrendLogMultiple => todo!(),
                    ObjectType::LoadControl => todo!(),
                    ObjectType::StructuredView => todo!(),
                    ObjectType::AccessDoor => PropertyReferenceVector::access_door(),
                    ObjectType::Timer => todo!(),
                    ObjectType::AccessCredential => todo!(),
                    ObjectType::AccessPoint => todo!(),
                    ObjectType::AccessRights => todo!(),
                    ObjectType::AccessUser => todo!(),
                    ObjectType::AccessZone => todo!(),
                    ObjectType::CredentialDataInput => todo!(),
                    ObjectType::BitstringValue => todo!(),
                    ObjectType::CharacterstringValue => todo!(),
                    ObjectType::DatepatternValue => todo!(),
                    ObjectType::DateValue => todo!(),
                    ObjectType::DatetimepatternValue => todo!(),
                    ObjectType::DatetimeValue => todo!(),
                    ObjectType::IntegerValue => todo!(),
                    ObjectType::LargeAnalogValue => todo!(),
                    ObjectType::OctetstringValue => todo!(),
                    ObjectType::PositiveIntegerValue => todo!(),
                    ObjectType::TimepatternValue => todo!(),
                    ObjectType::TimeValue => todo!(),
                    ObjectType::NotificationForwarder => todo!(),
                    ObjectType::AlertEnrollment => todo!(),
                    ObjectType::Channel => todo!(),
                    ObjectType::LightingOutput => todo!(),
                    ObjectType::BinaryLightingOutput => todo!(),
                    ObjectType::NetworkPort => todo!(),
                    ObjectType::ElevatorGroup => todo!(),
                    ObjectType::Escalator => todo!(),
                    ObjectType::Lift => todo!(),
                    ObjectType::Staging => todo!(),
                    ObjectType::AuditLog => todo!(),
                    ObjectType::AuditReporter => todo!(),
                    ObjectType::Color => todo!(),
                    ObjectType::ColorTemperature => todo!(),
                    ObjectType::Custom(object_type_value) => todo!(),
                    ObjectType::Reserved(object_type_value) => todo!(),
                };

                read_specs.push(ReadAccessSpecification::new(*obj, pr.vec));
            }

            let rpm_request = ReadPropertyMultipleRequest::new(read_specs);

            match self.send_confirmed_request(
                target_addr,
                ConfirmedServiceChoice::ReadPropertyMultiple,
                &self.encode_rpm_request(&rpm_request)?,
            ) {
                Ok(response_data) => {
                    match ReadPropertyMultipleResponse::decode(&response_data) {
                        Ok(response) => {
                            for access in response.read_access_results {
                                objects_info.push(Self::object_info_from_access(access));
                            }
                        }
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

    /// Read a property of an object and return all decoded values.
    ///
    /// Most properties decode to a single value; arrays and lists (e.g.
    /// `Object_List`, `Priority_Array`) decode to several, so the full set is
    /// returned. Returns [`ClientError::PropertyError`] if the device reports
    /// the property as unknown, or [`ClientError::Timeout`] if there is no
    /// response.
    pub fn read_property(
        &self,
        target_addr: SocketAddr,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
    ) -> Result<Vec<PropertyValue>, ClientError> {
        let request = ReadPropertyRequest::new(object, property);
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;

        let response_data = self.send_confirmed_request(
            target_addr,
            ConfirmedServiceChoice::ReadProperty,
            &service_data,
        )?;

        Ok(ReadPropertyResponse::decode(&response_data)?.property_values)
    }

    /// Write a single property of an object.
    ///
    /// `priority` is the BACnet command priority (1-16) for commandable
    /// properties such as Present_Value; pass `None` to omit it. A successful
    /// write is acknowledged with a SimpleAck; a device-side failure surfaces as
    /// [`ClientError::PropertyError`] / [`ClientError::Rejected`] /
    /// [`ClientError::Abort`].
    pub fn write_property(
        &self,
        target_addr: SocketAddr,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        value: &PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), ClientError> {
        let mut encoded_value = Vec::new();
        encode_property_value(value, &mut encoded_value)?;

        let property_id: u32 = property.into();
        let request = match priority {
            Some(p) => WritePropertyRequest::with_priority(object, property_id, encoded_value, p),
            None => WritePropertyRequest::new(object, property_id, encoded_value),
        };

        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;

        // A successful WriteProperty is a SimpleAck (empty service data); any
        // Error/Reject/Abort is surfaced as a typed error by the request path.
        self.send_confirmed_request(
            target_addr,
            ConfirmedServiceChoice::WriteProperty,
            &service_data,
        )?;

        Ok(())
    }

    /// Write a property and then read it back to confirm it took effect.
    ///
    /// This is the safe way to command a value: it returns
    /// - `Err(..)` if the device *refused* the write (Error/Reject/Abort) or a
    ///   transfer failed;
    /// - `Ok(WriteOutcome::Verified)` if the read-back matches `value`;
    /// - `Ok(WriteOutcome::NotEffective { read_back })` if the device
    ///   acknowledged the write but the property still reports a different value
    ///   (e.g. a higher-priority command is winning, or the property is not
    ///   commandable at this priority).
    ///
    /// Floating-point values are compared with a small tolerance.
    ///
    /// A device commonly returns the SimpleAck *before* `Present_Value` reflects
    /// the new command (priority-array resolution can lag), so the read-back is
    /// polled a few times before concluding the write did not take effect.
    pub fn write_property_verified(
        &self,
        target_addr: SocketAddr,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        value: &PropertyValue,
        priority: Option<u8>,
    ) -> Result<WriteOutcome, ClientError> {
        /// How many times to read back before concluding the write didn't take.
        const VERIFY_ATTEMPTS: u32 = 4;
        /// Delay between read-back attempts, giving the device time to apply the
        /// command to `Present_Value`.
        const VERIFY_DELAY: Duration = Duration::from_millis(150);

        self.write_property(target_addr, object, property, value, priority)?;

        let mut read_back = Vec::new();
        for attempt in 0..VERIFY_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(VERIFY_DELAY);
            }
            read_back = self.read_property(target_addr, object, property)?;
            if read_back.iter().any(|v| values_equivalent(value, v)) {
                return Ok(WriteOutcome::Verified);
            }
        }

        // Not verified: report the value the property actually holds.
        let read_back = read_back.into_iter().next().unwrap_or(PropertyValue::Null);
        Ok(WriteOutcome::NotEffective { read_back })
    }

    /// Create an unconfirmed message
    fn create_unconfirmed_message(&self, service_choice: u8, service_data: &[u8]) -> Vec<u8> {
        self.create_unconfirmed_bvlc(service_choice, service_data, BVLC_ORIGINAL_UNICAST)
    }

    /// Build a BACnet/IP frame for an unconfirmed request, wrapped with the
    /// given BVLC function (`0x0A` unicast or `0x0B` broadcast).
    fn create_unconfirmed_bvlc(
        &self,
        service_choice: u8,
        service_data: &[u8],
        bvlc_function: u8,
    ) -> Vec<u8> {
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

        // Wrap in BVLC header for BACnet/IP
        let mut bvlc_message = vec![0x81, bvlc_function, 0x00, 0x00];
        bvlc_message.extend_from_slice(&message);

        // Update BVLC length
        let total_len = bvlc_message.len() as u16;
        bvlc_message[2] = (total_len >> 8) as u8;
        bvlc_message[3] = (total_len & 0xFF) as u8;

        bvlc_message
    }

    /// Send a confirmed request and wait for the matching response.
    ///
    /// A fresh invoke ID is allocated for the transaction. Returns the
    /// ComplexAck service data on success, an empty `Vec` for a SimpleAck, or a
    /// typed [`ClientError`] if the device responds with Error/Reject/Abort or
    /// the request times out.
    fn send_confirmed_request(
        &self,
        target_addr: SocketAddr,
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let invoke_id = self.invoke_ids.next_id();
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
                        // A matching Error/Reject/Abort surfaces as Err here; an
                        // unrelated frame yields None so we keep waiting.
                        if let Some(response_data) =
                            self.interpret_confirmed_response(&recv_buffer[..len], invoke_id)?
                        {
                            return Ok(response_data);
                        }
                    }
                }
                // A per-recv socket timeout is WouldBlock on Unix and TimedOut
                // on Windows; both mean "nothing yet", so keep waiting until our
                // own deadline elapses.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(ClientError::Timeout)
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
                let vendor_name = crate::vendor::get_vendor_name(iam.vendor_identifier)
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

    /// Interpret a received datalink frame as a response to `expected_invoke_id`.
    ///
    /// Returns:
    /// - `Ok(Some(data))` for the matching ComplexAck (service data) or
    ///   SimpleAck (empty),
    /// - `Err(..)` when the device returned a matching Error / Reject / Abort,
    /// - `Ok(None)` when the frame is unrelated (wrong invoke ID, not a
    ///   response, or unparseable) and the caller should keep waiting.
    ///
    /// `Ok(None)` (rather than an error) is deliberate: this is called from a
    /// per-request receive loop with a single transaction in flight, so frames
    /// that don't match are simply other traffic on the socket and must be
    /// skipped, not treated as failures. If this ever moves behind a shared
    /// event loop that demultiplexes all incoming messages, that loop would need
    /// to dispatch frames to the waiting transaction by invoke ID instead of
    /// dropping non-matching ones here.
    fn interpret_confirmed_response(
        &self,
        data: &[u8],
        expected_invoke_id: u8,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        // Check BVLC header
        if data.len() < 4 || data[0] != 0x81 {
            return Ok(None);
        }

        let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
        if data.len() != bvlc_length as usize {
            return Ok(None);
        }

        // Decode NPDU and APDU; a frame we can't parse is simply not our reply.
        let npdu_start = 4;
        let (_npdu, npdu_len) = match Npdu::decode(&data[npdu_start..]) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(None),
        };

        let apdu_start = npdu_start + npdu_len;
        let apdu = match Apdu::decode(&data[apdu_start..]) {
            Ok(apdu) => apdu,
            Err(_) => return Ok(None),
        };

        match apdu {
            Apdu::ComplexAck {
                invoke_id,
                service_data,
                ..
            } if invoke_id == expected_invoke_id => Ok(Some(service_data)),
            Apdu::SimpleAck { invoke_id, .. } if invoke_id == expected_invoke_id => {
                Ok(Some(Vec::new()))
            }
            Apdu::Error {
                invoke_id,
                error_class,
                error_code,
                ..
            } if invoke_id == expected_invoke_id => Err(ClientError::PropertyError {
                class: error_class as u32,
                code: error_code as u32,
            }),
            Apdu::Reject {
                invoke_id,
                reject_reason,
            } if invoke_id == expected_invoke_id => Err(ClientError::Rejected(reject_reason)),
            Apdu::Abort {
                invoke_id,
                abort_reason,
                ..
            } if invoke_id == expected_invoke_id => {
                Err(ClientError::Abort(AbortReason::from(abort_reason)))
            }
            _ => Ok(None),
        }
    }

    /// Encode ReadPropertyMultiple request
    fn encode_rpm_request(
        &self,
        request: &ReadPropertyMultipleRequest,
    ) -> Result<Vec<u8>, ClientError> {
        let mut buffer = Vec::new();

        request.encode(&mut buffer)?;

        Ok(buffer)
    }

    /// Map a decoded ReadPropertyMultiple result for a single object into the
    /// client's [`ObjectInfo`] view, pulling out the common properties.
    ///
    /// Per-property errors (`PropertyResultValue::Error`) are skipped, leaving
    /// that field `None`.
    fn object_info_from_access(access: ReadAccessResult) -> ObjectInfo {
        let mut info = ObjectInfo {
            object_identifier: access.object_identifier,
            object_name: None,
            description: None,
            present_value: None,
            units: None,
            status_flags: None,
        };

        for result in access.results {
            let values = match result.value {
                PropertyResultValue::Value(values) => values,
                PropertyResultValue::Error(..) => continue,
            };
            let first = values.into_iter().next();

            match result.property_identifier {
                PropertyIdentifier::ObjectName => {
                    if let Some(PropertyValue::CharacterString(s)) = first {
                        info.object_name = Some(s);
                    }
                }
                PropertyIdentifier::Description => {
                    if let Some(PropertyValue::CharacterString(s)) = first {
                        info.description = Some(s);
                    }
                }
                PropertyIdentifier::PresentValue => {
                    info.present_value = first;
                }
                PropertyIdentifier::Units => {
                    if let Some(PropertyValue::Enumerated(units_id)) = first {
                        info.units = Some(EngineeringUnits::from(units_id));
                    }
                }
                PropertyIdentifier::StatusFlags => {
                    if let Some(PropertyValue::BitString(bits)) = first {
                        info.status_flags = Some(bits);
                    }
                }
                _ => {}
            }
        }

        info
    }
}

// adds all the applicable properties for the given object
struct PropertyReferenceVector {
    vec: Vec<PropertyReference>,
}

impl PropertyReferenceVector {
    fn analog_input() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::DeviceType),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::UpdateInterval),
                PropertyReference::new(PropertyIdentifier::Units),
                PropertyReference::new(PropertyIdentifier::MinPresValue),
                PropertyReference::new(PropertyIdentifier::MaxPresValue),
                PropertyReference::new(PropertyIdentifier::Resolution),
                PropertyReference::new(PropertyIdentifier::CovIncrement),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::HighLimit),
                PropertyReference::new(PropertyIdentifier::LowLimit),
                PropertyReference::new(PropertyIdentifier::Deadband),
                PropertyReference::new(PropertyIdentifier::LimitEnable),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::InterfaceValue),
                PropertyReference::new(PropertyIdentifier::FaultHighLimit),
                PropertyReference::new(PropertyIdentifier::FaultLowLimit),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn analog_output() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::DeviceType),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::Units),
                PropertyReference::new(PropertyIdentifier::MinPresValue),
                PropertyReference::new(PropertyIdentifier::MaxPresValue),
                PropertyReference::new(PropertyIdentifier::Resolution),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::CovIncrement),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::HighLimit),
                PropertyReference::new(PropertyIdentifier::LowLimit),
                PropertyReference::new(PropertyIdentifier::Deadband),
                PropertyReference::new(PropertyIdentifier::LimitEnable),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::InterfaceValue),
                PropertyReference::new(PropertyIdentifier::CurrentCommandPriority),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::ValueSourceArray),
                PropertyReference::new(PropertyIdentifier::LastCommandTime),
                PropertyReference::new(PropertyIdentifier::CommandTimeArray),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn analog_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::Units),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::CovIncrement),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::HighLimit),
                PropertyReference::new(PropertyIdentifier::LowLimit),
                PropertyReference::new(PropertyIdentifier::Deadband),
                PropertyReference::new(PropertyIdentifier::LimitEnable),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::MinPresValue),
                PropertyReference::new(PropertyIdentifier::MaxPresValue),
                PropertyReference::new(PropertyIdentifier::Resolution),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::FaultHighLimit),
                PropertyReference::new(PropertyIdentifier::FaultLowLimit),
                PropertyReference::new(PropertyIdentifier::CurrentCommandPriority),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::ValueSourceArray),
                PropertyReference::new(PropertyIdentifier::LastCommandTime),
                PropertyReference::new(PropertyIdentifier::CommandTimeArray),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn averaging() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::MinimumValue),
                PropertyReference::new(PropertyIdentifier::MinimumValueTimestamp),
                PropertyReference::new(PropertyIdentifier::AverageValue),
                PropertyReference::new(PropertyIdentifier::VarianceValue),
                PropertyReference::new(PropertyIdentifier::MaximumValue),
                PropertyReference::new(PropertyIdentifier::MaximumValueTimestamp),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::AttemptedSamples),
                PropertyReference::new(PropertyIdentifier::ValidSamples),
                PropertyReference::new(PropertyIdentifier::ObjectPropertyReference),
                PropertyReference::new(PropertyIdentifier::WindowInterval),
                PropertyReference::new(PropertyIdentifier::WindowSamples),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn binary_input() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::DeviceType),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::Polarity),
                PropertyReference::new(PropertyIdentifier::InactiveText),
                PropertyReference::new(PropertyIdentifier::ActiveText),
                PropertyReference::new(PropertyIdentifier::ChangeOfStateTime),
                PropertyReference::new(PropertyIdentifier::ChangeOfStateCount),
                PropertyReference::new(PropertyIdentifier::TimeOfStateCountReset),
                PropertyReference::new(PropertyIdentifier::ElapsedActiveTime),
                PropertyReference::new(PropertyIdentifier::TimeOfActiveTimeReset),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::AlarmValue),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::InterfaceValue),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn binary_output() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::DeviceType),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::Polarity),
                PropertyReference::new(PropertyIdentifier::InactiveText),
                PropertyReference::new(PropertyIdentifier::ActiveText),
                PropertyReference::new(PropertyIdentifier::ChangeOfStateTime),
                PropertyReference::new(PropertyIdentifier::ChangeOfStateCount),
                PropertyReference::new(PropertyIdentifier::TimeOfStateCountReset),
                PropertyReference::new(PropertyIdentifier::ElapsedActiveTime),
                PropertyReference::new(PropertyIdentifier::TimeOfActiveTimeReset),
                PropertyReference::new(PropertyIdentifier::MinimumOffTime),
                PropertyReference::new(PropertyIdentifier::MinimumOnTime),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::FeedbackValue),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::InterfaceValue),
                PropertyReference::new(PropertyIdentifier::CurrentCommandPriority),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::ValueSourceArray),
                PropertyReference::new(PropertyIdentifier::LastCommandTime),
                PropertyReference::new(PropertyIdentifier::CommandTimeArray),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn binary_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::InactiveText),
                PropertyReference::new(PropertyIdentifier::ActiveText),
                PropertyReference::new(PropertyIdentifier::ChangeOfStateTime),
                PropertyReference::new(PropertyIdentifier::ChangeOfStateCount),
                PropertyReference::new(PropertyIdentifier::TimeOfStateCountReset),
                PropertyReference::new(PropertyIdentifier::ElapsedActiveTime),
                PropertyReference::new(PropertyIdentifier::TimeOfActiveTimeReset),
                PropertyReference::new(PropertyIdentifier::MinimumOffTime),
                PropertyReference::new(PropertyIdentifier::MinimumOnTime),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::AlarmValue),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::CurrentCommandPriority),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::ValueSourceArray),
                PropertyReference::new(PropertyIdentifier::LastCommandTime),
                PropertyReference::new(PropertyIdentifier::CommandTimeArray),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn calendar() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::DateList),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn command() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::InProcess),
                PropertyReference::new(PropertyIdentifier::AllWritesSuccessful),
                PropertyReference::new(PropertyIdentifier::Action),
                PropertyReference::new(PropertyIdentifier::ActionText),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn device() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::SystemStatus),
                PropertyReference::new(PropertyIdentifier::VendorName),
                PropertyReference::new(PropertyIdentifier::VendorIdentifier),
                PropertyReference::new(PropertyIdentifier::ModelName),
                PropertyReference::new(PropertyIdentifier::FirmwareRevision),
                PropertyReference::new(PropertyIdentifier::ApplicationSoftwareVersion),
                PropertyReference::new(PropertyIdentifier::Location),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::ProtocolVersion),
                PropertyReference::new(PropertyIdentifier::ProtocolRevision),
                PropertyReference::new(PropertyIdentifier::ProtocolServicesSupported),
                PropertyReference::new(PropertyIdentifier::ProtocolObjectTypesSupported),
                PropertyReference::new(PropertyIdentifier::ObjectList),
                PropertyReference::new(PropertyIdentifier::StructuredObjectList),
                PropertyReference::new(PropertyIdentifier::MaxApduLengthAccepted),
                PropertyReference::new(PropertyIdentifier::SegmentationSupported),
                PropertyReference::new(PropertyIdentifier::MaxSegmentsAccepted),
                PropertyReference::new(PropertyIdentifier::VtClassesSupported),
                PropertyReference::new(PropertyIdentifier::ActiveVtSessions),
                PropertyReference::new(PropertyIdentifier::LocalTime),
                PropertyReference::new(PropertyIdentifier::LocalDate),
                PropertyReference::new(PropertyIdentifier::UtcOffset),
                PropertyReference::new(PropertyIdentifier::DaylightSavingsStatus),
                PropertyReference::new(PropertyIdentifier::ApduSegmentTimeout),
                PropertyReference::new(PropertyIdentifier::ApduTimeout),
                PropertyReference::new(PropertyIdentifier::NumberOfApduRetries),
                PropertyReference::new(PropertyIdentifier::TimeSynchronizationRecipients),
                PropertyReference::new(PropertyIdentifier::MaxManager),
                PropertyReference::new(PropertyIdentifier::MaxInfoFrames),
                PropertyReference::new(PropertyIdentifier::DeviceAddressBinding),
                PropertyReference::new(PropertyIdentifier::DatabaseRevision),
                PropertyReference::new(PropertyIdentifier::ConfigurationFiles),
                PropertyReference::new(PropertyIdentifier::LastRestoreTime),
                PropertyReference::new(PropertyIdentifier::BackupFailureTimeout),
                PropertyReference::new(PropertyIdentifier::BackupPreparationTime),
                PropertyReference::new(PropertyIdentifier::RestorePreparationTime),
                PropertyReference::new(PropertyIdentifier::RestoreCompletionTime),
                PropertyReference::new(PropertyIdentifier::BackupAndRestoreState),
                PropertyReference::new(PropertyIdentifier::ActiveCovSubscriptions),
                PropertyReference::new(PropertyIdentifier::LastRestartReason),
                PropertyReference::new(PropertyIdentifier::TimeOfDeviceRestart),
                PropertyReference::new(PropertyIdentifier::RestartNotificationRecipients),
                PropertyReference::new(PropertyIdentifier::UtcTimeSynchronizationRecipients),
                PropertyReference::new(PropertyIdentifier::TimeSynchronizationInterval),
                PropertyReference::new(PropertyIdentifier::AlignIntervals),
                PropertyReference::new(PropertyIdentifier::IntervalOffset),
                PropertyReference::new(PropertyIdentifier::SerialNumber),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::ActiveCovMultipleSubscriptions),
                PropertyReference::new(PropertyIdentifier::AuditNotificationRecipient),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::DeviceUuid),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::DeployedProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn event_enrollment() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::EventType),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventParameters),
                PropertyReference::new(PropertyIdentifier::ObjectPropertyReference),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::FaultType),
                PropertyReference::new(PropertyIdentifier::FaultParameters),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn file() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::FileType),
                PropertyReference::new(PropertyIdentifier::FileSize),
                PropertyReference::new(PropertyIdentifier::ModificationDate),
                PropertyReference::new(PropertyIdentifier::Archive),
                PropertyReference::new(PropertyIdentifier::ReadOnly),
                PropertyReference::new(PropertyIdentifier::FileAccessMethod),
                PropertyReference::new(PropertyIdentifier::RecordCount),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn group() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::ListOfGroupMembers),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn life_safety_point() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::TrackingValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::DeviceType),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::Mode),
                PropertyReference::new(PropertyIdentifier::AcceptedModes),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::LifeSafetyAlarmValues),
                PropertyReference::new(PropertyIdentifier::AlarmValues),
                PropertyReference::new(PropertyIdentifier::FaultValues),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::Silenced),
                PropertyReference::new(PropertyIdentifier::OperationExpected),
                PropertyReference::new(PropertyIdentifier::MaintenanceRequired),
                PropertyReference::new(PropertyIdentifier::Setting),
                PropertyReference::new(PropertyIdentifier::DirectReading),
                PropertyReference::new(PropertyIdentifier::Units),
                PropertyReference::new(PropertyIdentifier::MemberOf),
                PropertyReference::new(PropertyIdentifier::FloorNumber),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn life_safety_zone() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::TrackingValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::DeviceType),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::Mode),
                PropertyReference::new(PropertyIdentifier::AcceptedModes),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::LifeSafetyAlarmValues),
                PropertyReference::new(PropertyIdentifier::AlarmValues),
                PropertyReference::new(PropertyIdentifier::FaultValues),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::Silenced),
                PropertyReference::new(PropertyIdentifier::OperationExpected),
                PropertyReference::new(PropertyIdentifier::MaintenanceRequired),
                PropertyReference::new(PropertyIdentifier::ZoneMembers),
                PropertyReference::new(PropertyIdentifier::MemberOf),
                PropertyReference::new(PropertyIdentifier::FloorNumber),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn r#loop() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::UpdateInterval),
                PropertyReference::new(PropertyIdentifier::OutputUnits),
                PropertyReference::new(PropertyIdentifier::ManipulatedVariableReference),
                PropertyReference::new(PropertyIdentifier::ControlledVariableReference),
                PropertyReference::new(PropertyIdentifier::ControlledVariableValue),
                PropertyReference::new(PropertyIdentifier::ControlledVariableUnits),
                PropertyReference::new(PropertyIdentifier::SetpointReference),
                PropertyReference::new(PropertyIdentifier::Setpoint),
                PropertyReference::new(PropertyIdentifier::Action),
                PropertyReference::new(PropertyIdentifier::ProportionalConstant),
                PropertyReference::new(PropertyIdentifier::ProportionalConstantUnits),
                PropertyReference::new(PropertyIdentifier::IntegralConstant),
                PropertyReference::new(PropertyIdentifier::IntegralConstantUnits),
                PropertyReference::new(PropertyIdentifier::DerivativeConstant),
                PropertyReference::new(PropertyIdentifier::DerivativeConstantUnits),
                PropertyReference::new(PropertyIdentifier::Bias),
                PropertyReference::new(PropertyIdentifier::MaximumOutput),
                PropertyReference::new(PropertyIdentifier::MinimumOutput),
                PropertyReference::new(PropertyIdentifier::PriorityForWriting),
                PropertyReference::new(PropertyIdentifier::CovIncrement),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::ErrorLimit),
                PropertyReference::new(PropertyIdentifier::Deadband),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::LowDiffLimit),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn multistate_input() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::DeviceType),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::NumberOfStates),
                PropertyReference::new(PropertyIdentifier::StateText),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::AlarmValues),
                PropertyReference::new(PropertyIdentifier::FaultValues),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::InterfaceValue),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn multistate_output() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::DeviceType),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::NumberOfStates),
                PropertyReference::new(PropertyIdentifier::StateText),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::FeedbackValue),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::InterfaceValue),
                PropertyReference::new(PropertyIdentifier::CurrentCommandPriority),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::ValueSourceArray),
                PropertyReference::new(PropertyIdentifier::LastCommandTime),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn multistate_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::NumberOfStates),
                PropertyReference::new(PropertyIdentifier::StateText),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::AlarmValues),
                PropertyReference::new(PropertyIdentifier::FaultValues),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::CurrentCommandPriority),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::ValueSourceArray),
                PropertyReference::new(PropertyIdentifier::LastCommandTime),
                PropertyReference::new(PropertyIdentifier::CommandTimeArray),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn notification_class() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::Priority),
                PropertyReference::new(PropertyIdentifier::AckRequired),
                PropertyReference::new(PropertyIdentifier::RecipientList),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn program() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::ProgramState),
                PropertyReference::new(PropertyIdentifier::ProgramChange),
                PropertyReference::new(PropertyIdentifier::ReasonForHalt),
                PropertyReference::new(PropertyIdentifier::DescriptionOfHalt),
                PropertyReference::new(PropertyIdentifier::ProgramLocation),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::InstanceOf),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn pulse_converter() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::InputReference),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::Units),
                PropertyReference::new(PropertyIdentifier::ScaleFactor),
                PropertyReference::new(PropertyIdentifier::AdjustValue),
                PropertyReference::new(PropertyIdentifier::Count),
                PropertyReference::new(PropertyIdentifier::UpdateTime),
                PropertyReference::new(PropertyIdentifier::CountChangeTime),
                PropertyReference::new(PropertyIdentifier::CountBeforeChange),
                PropertyReference::new(PropertyIdentifier::CovIncrement),
                PropertyReference::new(PropertyIdentifier::CovPeriod),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::HighLimit),
                PropertyReference::new(PropertyIdentifier::LowLimit),
                PropertyReference::new(PropertyIdentifier::Deadband),
                PropertyReference::new(PropertyIdentifier::LimitEnable),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn schedule() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::EffectivePeriod),
                PropertyReference::new(PropertyIdentifier::WeeklySchedule),
                PropertyReference::new(PropertyIdentifier::ExceptionSchedule),
                PropertyReference::new(PropertyIdentifier::ScheduleDefault),
                PropertyReference::new(PropertyIdentifier::ListOfObjectPropertyReferences),
                PropertyReference::new(PropertyIdentifier::PriorityForWriting),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn trend_log() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::Enable),
                PropertyReference::new(PropertyIdentifier::StartTime),
                PropertyReference::new(PropertyIdentifier::StopTime),
                PropertyReference::new(PropertyIdentifier::LogDeviceObjectProperty),
                PropertyReference::new(PropertyIdentifier::LogInterval),
                PropertyReference::new(PropertyIdentifier::CovResubscriptionInterval),
                PropertyReference::new(PropertyIdentifier::ClientCovIncrement),
                PropertyReference::new(PropertyIdentifier::StopWhenFull),
                PropertyReference::new(PropertyIdentifier::BufferSize),
                PropertyReference::new(PropertyIdentifier::LogBuffer),
                PropertyReference::new(PropertyIdentifier::RecordCount),
                PropertyReference::new(PropertyIdentifier::TotalRecordCount),
                PropertyReference::new(PropertyIdentifier::LoggingType),
                PropertyReference::new(PropertyIdentifier::AlignIntervals),
                PropertyReference::new(PropertyIdentifier::IntervalOffset),
                PropertyReference::new(PropertyIdentifier::Trigger),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::NotificationThreshold),
                PropertyReference::new(PropertyIdentifier::RecordsSinceNotification),
                PropertyReference::new(PropertyIdentifier::LastNotifyRecord),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn access_door() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::DoorStatus),
                PropertyReference::new(PropertyIdentifier::LockStatus),
                PropertyReference::new(PropertyIdentifier::SecuredStatus),
                PropertyReference::new(PropertyIdentifier::DoorMembers),
                PropertyReference::new(PropertyIdentifier::DoorPulseTime),
                PropertyReference::new(PropertyIdentifier::DoorExtendedPulseTime),
                PropertyReference::new(PropertyIdentifier::DoorUnlockDelayTime),
                PropertyReference::new(PropertyIdentifier::DoorOpenTooLongTime),
                PropertyReference::new(PropertyIdentifier::DoorAlarmState),
                PropertyReference::new(PropertyIdentifier::MaskedAlarmValues),
                PropertyReference::new(PropertyIdentifier::MaintenanceRequired),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::AlarmValues),
                PropertyReference::new(PropertyIdentifier::FaultValues),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::CurrentCommandPriority),
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::ValueSourceArray),
                PropertyReference::new(PropertyIdentifier::LastCommandTime),
                PropertyReference::new(PropertyIdentifier::CommandTimeArray),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn event_log() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::Enable),
                PropertyReference::new(PropertyIdentifier::StartTime),
                PropertyReference::new(PropertyIdentifier::StopTime),
                PropertyReference::new(PropertyIdentifier::StopWhenFull),
                PropertyReference::new(PropertyIdentifier::BufferSize),
                PropertyReference::new(PropertyIdentifier::LogBuffer),
                PropertyReference::new(PropertyIdentifier::RecordCount),
                PropertyReference::new(PropertyIdentifier::TotalRecordCount),
                PropertyReference::new(PropertyIdentifier::NotificationThreshold),
                PropertyReference::new(PropertyIdentifier::RecordsSinceNotification),
                PropertyReference::new(PropertyIdentifier::LastNotifyRecord),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }
}

/// Compare a written value against a read-back value when verifying a write,
/// tolerating floating-point rounding for Real/Double (including a Real written
/// value read back as a Double, or vice versa).
#[cfg(feature = "std")]
fn values_equivalent(written: &PropertyValue, read_back: &PropertyValue) -> bool {
    const REAL_TOLERANCE: f64 = 1e-3;
    match (written, read_back) {
        (PropertyValue::Real(a), PropertyValue::Real(b)) => {
            (f64::from(*a) - f64::from(*b)).abs() <= REAL_TOLERANCE
        }
        (PropertyValue::Double(a), PropertyValue::Double(b)) => (a - b).abs() <= REAL_TOLERANCE,
        (PropertyValue::Real(a), PropertyValue::Double(b)) => {
            (f64::from(*a) - b).abs() <= REAL_TOLERANCE
        }
        (PropertyValue::Double(a), PropertyValue::Real(b)) => {
            (a - f64::from(*b)).abs() <= REAL_TOLERANCE
        }
        (a, b) => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_id_encoding() {
        let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 123);
        let encoded: u32 = match object_id.try_into() {
            Ok(value) => value,
            Err(_) => panic!("Object identifier encoding failed"),
        };
        let decoded = ObjectIdentifier::from(encoded);
        assert_eq!(decoded.object_type, ObjectType::AnalogInput);
        assert_eq!(decoded.instance, 123);

        let object_id = ObjectIdentifier::new(ObjectType::Device, 5047);
        let encoded: u32 = match object_id.try_into() {
            Ok(value) => value,
            Err(_) => panic!("Object identifier encoding failed"),
        };
        let decoded = ObjectIdentifier::from(encoded);
        assert_eq!(decoded.object_type, ObjectType::Device);
        assert_eq!(decoded.instance, 5047);
    }

    #[test]
    fn test_config_defaults() {
        let config = ClientConfig::default();
        assert_eq!(config.host, DEFAULT_HOST);
        assert_eq!(config.port, 0);
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.retries, 0);
        assert_eq!(config.bind_addr(), "0.0.0.0:0");
    }

    #[test]
    fn test_builder_sets_fields() {
        // Bind to loopback on an OS-assigned port so the test is hermetic.
        let client = BacnetClient::builder()
            .local_addr("127.0.0.1")
            .port(0)
            .timeout(Duration::from_millis(250))
            .retries(3)
            .build()
            .expect("client should bind");

        assert_eq!(client.timeout(), Duration::from_millis(250));
        assert_eq!(client.retries, 3);

        let local = client.local_addr().expect("local addr");
        assert!(local.ip().is_loopback());
        assert_ne!(local.port(), 0, "OS should assign a real port");
    }

    #[test]
    fn test_new_uses_defaults() {
        let client = BacnetClient::new().expect("client should bind");
        assert_eq!(client.timeout(), DEFAULT_TIMEOUT);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(ClientError::Timeout.to_string(), "request timed out");

        // Known class + code are named, with the raw numbers retained.
        let known = ClientError::PropertyError { class: 1, code: 31 };
        assert_eq!(
            known.to_string(),
            "unknown-object (class object[1], code 31)"
        );

        // Property/write-access-denied — the case seen against real hardware.
        let denied = ClientError::PropertyError { class: 2, code: 40 };
        assert_eq!(
            denied.to_string(),
            "write-access-denied (class property[2], code 40)"
        );

        // Unknown code falls back to the numeric form.
        let unknown = ClientError::PropertyError {
            class: 2,
            code: 222,
        };
        assert_eq!(
            unknown.to_string(),
            "BACnet error (class property[2], code 222)"
        );
    }
}
