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
    network::{NetworkAddress, NetworkLayerMessage, NetworkMessageType, Npdu},
    object::{EngineeringUnits, ObjectIdentifier, ObjectType, PropertyIdentifier, Segmentation},
    property::{encode_property_value, PropertyValue},
    service::{
        ConfirmedServiceChoice, IAmRequest, PropertyReference, PropertyResultValue,
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
    /// UDP address of the device, or of the BACnet router used as its next hop.
    pub address: SocketAddr,
    /// BACnet source network/address from a routed I-Am response.
    ///
    /// This is `None` for directly connected BACnet/IP devices. For a routed
    /// device it must be used as DNET/DADR on subsequent requests.
    pub route: Option<NetworkAddress>,
    pub vendor_id: u16,
    pub vendor_name: String,
    pub max_apdu: u32,
    pub segmentation: Segmentation,
}

impl DeviceInfo {
    /// Return the complete destination needed for subsequent requests.
    pub fn target(&self) -> BacnetTarget {
        self.into()
    }
}

/// A BACnet router discovered through I-Am-Router-To-Network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRouter {
    /// UDP address to use as the next hop.
    pub address: SocketAddr,
    /// BACnet network numbers advertised by this router.
    pub networks: Vec<u16>,
}

/// Physical next hop plus an optional BACnet network-layer destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacnetTarget {
    pub address: SocketAddr,
    pub route: Option<NetworkAddress>,
}

impl BacnetTarget {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            route: None,
        }
    }

    pub fn routed(address: SocketAddr, route: NetworkAddress) -> Self {
        Self {
            address,
            route: Some(route),
        }
    }
}

impl From<SocketAddr> for BacnetTarget {
    fn from(address: SocketAddr) -> Self {
        Self::new(address)
    }
}

impl From<&DeviceInfo> for BacnetTarget {
    fn from(device: &DeviceInfo) -> Self {
        Self {
            address: device.address,
            route: device.route.clone(),
        }
    }
}

impl From<&BacnetTarget> for BacnetTarget {
    fn from(target: &BacnetTarget) -> Self {
        target.clone()
    }
}

struct DecodedBacnetIpFrame<'a> {
    source: SocketAddr,
    npdu: Npdu,
    payload: &'a [u8],
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

    /// Discover every BACnet router visible through the limited IP broadcast.
    pub fn who_is_router(
        &self,
        destination_network: Option<u16>,
    ) -> Result<Vec<DiscoveredRouter>, ClientError> {
        let broadcast = SocketAddr::from(([255, 255, 255, 255], BACNET_IP_PORT));
        self.who_is_router_to(broadcast, destination_network)
    }

    /// Send Who-Is-Router-To-Network to an explicit UDP destination.
    ///
    /// With `destination_network = None`, all receiving routers may respond
    /// with their reachable networks. With a network number, only routers that
    /// can reach that network should respond.
    pub fn who_is_router_to(
        &self,
        target_addr: SocketAddr,
        destination_network: Option<u16>,
    ) -> Result<Vec<DiscoveredRouter>, ClientError> {
        self.socket.set_broadcast(true)?;
        let frame =
            self.create_who_is_router_frame(destination_network, is_broadcast_target(target_addr));
        self.socket.send_to(&frame, target_addr)?;
        self.collect_router_responses()
    }

    /// Send a Who-Is to a specific address (broadcast or unicast) and collect
    /// all I-Am replies until the timeout elapses.
    ///
    /// This is the explicit-target form of [`who_is`](Self::who_is); use it for
    /// subnet-directed broadcasts (e.g. `192.168.1.255:47808`) or to query a
    /// BBMD/foreign-device peer directly.
    ///
    /// Broadcast targets (the limited broadcast `255.255.255.255` or a local
    /// interface's subnet broadcast) are sent as a global-broadcast NPDU in an
    /// Original-Broadcast-NPDU BVLC, matching the reference bacnet-stack;
    /// anything else is sent as a plain unicast frame.
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

        let message = self.create_unconfirmed_frame(
            UnconfirmedServiceChoice::WhoIs as u8,
            &buffer,
            is_broadcast_target(target_addr),
        );
        self.socket.send_to(&message, target_addr)?;

        self.collect_iam_responses()
    }

    /// Send Who-Is through a known BACnet router to every station on a
    /// downstream BACnet network and collect the resulting I-Am responses.
    ///
    /// The UDP datagram is unicast to `router_addr`; `destination_network` is
    /// encoded as DNET with an empty DADR, which is a broadcast on that BACnet
    /// network. Pass both instance limits to restrict the scan, or neither to
    /// discover every device on the network.
    pub fn who_is_network(
        &self,
        router_addr: SocketAddr,
        destination_network: u16,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        // Permit either a unicast router address or a subnet broadcast address.
        self.socket.set_broadcast(true)?;

        let whois = match (low_limit, high_limit) {
            (Some(low), Some(high)) => WhoIsRequest::for_range(low, high),
            _ => WhoIsRequest::new(),
        };
        let mut service_data = Vec::new();
        whois.encode(&mut service_data)?;

        let message = self.create_who_is_network_frame(destination_network, &service_data);
        self.socket.send_to(&message, router_addr)?;

        self.collect_iam_responses()
    }

    /// Read the device's object list
    pub fn read_object_list<T>(
        &self,
        target: T,
        device_id: u32,
    ) -> Result<Vec<ObjectIdentifier>, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let device_object = ObjectIdentifier::new(ObjectType::Device, device_id);
        let property_ref = PropertyReference::new(PropertyIdentifier::ObjectList); // Object_List property
        let read_spec = ReadAccessSpecification::new(device_object, vec![property_ref]);
        let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

        let response_data = self.send_confirmed_request(
            &target,
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
    pub fn read_objects_properties<T>(
        &self,
        target: T,
        objects: &[ObjectIdentifier],
    ) -> Result<Vec<ObjectInfo>, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
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
                    ObjectType::Accumulator => PropertyReferenceVector::accumulator(),
                    ObjectType::PulseConverter => PropertyReferenceVector::pulse_converter(),
                    ObjectType::EventLog => PropertyReferenceVector::event_log(),
                    ObjectType::GlobalGroup => PropertyReferenceVector::global_group(),
                    ObjectType::TrendLogMultiple => PropertyReferenceVector::trend_log_multiple(),
                    ObjectType::LoadControl => PropertyReferenceVector::load_control(),
                    ObjectType::StructuredView => PropertyReferenceVector::structured_view(),
                    ObjectType::AccessDoor => PropertyReferenceVector::access_door(),
                    ObjectType::Timer => PropertyReferenceVector::timer(),
                    ObjectType::AccessCredential => PropertyReferenceVector::access_credential(),
                    ObjectType::AccessPoint => PropertyReferenceVector::access_point(),
                    ObjectType::AccessRights => PropertyReferenceVector::access_rights(),
                    ObjectType::AccessUser => PropertyReferenceVector::access_user(),
                    ObjectType::AccessZone => PropertyReferenceVector::access_zone(),
                    ObjectType::CredentialDataInput => {
                        PropertyReferenceVector::credential_data_input()
                    }
                    ObjectType::BitstringValue => PropertyReferenceVector::bit_string_value(),
                    ObjectType::CharacterstringValue => {
                        PropertyReferenceVector::character_string_value()
                    }
                    ObjectType::DatepatternValue => PropertyReferenceVector::date_pattern_value(),
                    ObjectType::DateValue => PropertyReferenceVector::date_value(),
                    ObjectType::DatetimepatternValue => {
                        PropertyReferenceVector::date_time_pattern_value()
                    }
                    ObjectType::DatetimeValue => PropertyReferenceVector::datetime_value(),
                    ObjectType::IntegerValue => PropertyReferenceVector::integer_value(),
                    ObjectType::LargeAnalogValue => PropertyReferenceVector::large_analog_value(),
                    ObjectType::OctetstringValue => PropertyReferenceVector::octet_string_value(),
                    ObjectType::PositiveIntegerValue => {
                        PropertyReferenceVector::positive_integer_value()
                    }
                    ObjectType::TimepatternValue => PropertyReferenceVector::time_pattern_value(),
                    ObjectType::TimeValue => PropertyReferenceVector::time_value(),
                    ObjectType::NotificationForwarder => {
                        PropertyReferenceVector::notification_forwarder()
                    }
                    ObjectType::AlertEnrollment => PropertyReferenceVector::alert_enrollment(),
                    ObjectType::Channel => PropertyReferenceVector::channel(),
                    ObjectType::LightingOutput => PropertyReferenceVector::lighting_output(),
                    ObjectType::BinaryLightingOutput => {
                        PropertyReferenceVector::binary_lighting_output()
                    }
                    ObjectType::NetworkPort => PropertyReferenceVector::network_port(),
                    ObjectType::ElevatorGroup => PropertyReferenceVector::elevator_group(),
                    ObjectType::Escalator => PropertyReferenceVector::escalator(),
                    ObjectType::Lift => PropertyReferenceVector::lift(),
                    ObjectType::Staging => PropertyReferenceVector::staging(),
                    ObjectType::AuditLog => PropertyReferenceVector::audit_log(),
                    ObjectType::AuditReporter => PropertyReferenceVector::audit_reporter(),
                    ObjectType::Color => todo!(),
                    ObjectType::ColorTemperature => todo!(),
                    ObjectType::Custom(object_type_value) => todo!(),
                    ObjectType::Reserved(object_type_value) => todo!(),
                };

                read_specs.push(ReadAccessSpecification::new(*obj, pr.vec));
            }

            let rpm_request = ReadPropertyMultipleRequest::new(read_specs);

            match self.send_confirmed_request(
                &target,
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
    pub fn read_property<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
    ) -> Result<Vec<PropertyValue>, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let request = ReadPropertyRequest::new(object, property);
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;

        let response_data = self.send_confirmed_request(
            &target,
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
    pub fn write_property<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        value: &PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
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
            &target,
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
    pub fn write_property_verified<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        value: &PropertyValue,
        priority: Option<u8>,
    ) -> Result<WriteOutcome, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        /// How many times to read back before concluding the write didn't take.
        const VERIFY_ATTEMPTS: u32 = 4;
        /// Delay between read-back attempts, giving the device time to apply the
        /// command to `Present_Value`.
        const VERIFY_DELAY: Duration = Duration::from_millis(150);

        let target = target.into();
        self.write_property(&target, object, property, value, priority)?;

        let mut read_back = Vec::new();
        for attempt in 0..VERIFY_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(VERIFY_DELAY);
            }
            read_back = self.read_property(&target, object, property)?;
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
        self.create_unconfirmed_frame(service_choice, service_data, false)
    }

    /// Build a BACnet/IP frame for an unconfirmed request.
    ///
    /// `broadcast` selects the frame shape as a pair, matching YABE: a broadcast carries a global-broadcast NPDU
    ///
    /// (DNET `0xFFFF`, hop count 255) inside an Original-Broadcast-NPDU BVLC,
    /// while a unicast carries a plain local NPDU inside Original-Unicast-NPDU.
    fn create_unconfirmed_frame(
        &self,
        service_choice: u8,
        service_data: &[u8],
        broadcast: bool,
    ) -> Vec<u8> {
        let (npdu, bvlc_function) = if broadcast {
            (Npdu::global_broadcast(), BVLC_ORIGINAL_BROADCAST)
        } else {
            let mut npdu = Npdu::new();
            npdu.control.expecting_reply = false;
            npdu.control.priority = 0;
            (npdu, BVLC_ORIGINAL_UNICAST)
        };

        self.create_unconfirmed_frame_with_npdu(service_choice, service_data, npdu, bvlc_function)
    }

    /// Build an unconfirmed BACnet/IP frame from an explicitly addressed NPDU.
    fn create_unconfirmed_frame_with_npdu(
        &self,
        service_choice: u8,
        service_data: &[u8],
        npdu: Npdu,
        bvlc_function: u8,
    ) -> Vec<u8> {
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

    /// Build a Who-Is whose NPDU destination is a broadcast on `network`.
    fn create_who_is_network_frame(&self, network: u16, service_data: &[u8]) -> Vec<u8> {
        // The IP packet is unicast to the known router. The NPDU destination,
        // not the BVLC function or IP address, asks the router to broadcast the
        // Who-Is on the downstream BACnet network. An empty DADR means every
        // station on DNET.
        let mut npdu = Npdu::new();
        npdu.set_destination(NetworkAddress::new(network, Vec::new()));
        npdu.hop_count = Some(255);

        self.create_unconfirmed_frame_with_npdu(
            UnconfirmedServiceChoice::WhoIs as u8,
            service_data,
            npdu,
            BVLC_ORIGINAL_UNICAST,
        )
    }

    /// Build a Who-Is-Router-To-Network network-layer message.
    fn create_who_is_router_frame(
        &self,
        destination_network: Option<u16>,
        broadcast: bool,
    ) -> Vec<u8> {
        let mut npdu = Npdu::new();
        npdu.control.network_message = true;

        let message_data = destination_network.map(|network| network.to_be_bytes().to_vec());
        let network_message =
            NetworkLayerMessage::new(NetworkMessageType::WhoIsRouterToNetwork, message_data);

        let mut payload = npdu.encode();
        payload.extend_from_slice(&network_message.encode());
        Self::wrap_bvlc(
            if broadcast {
                BVLC_ORIGINAL_BROADCAST
            } else {
                BVLC_ORIGINAL_UNICAST
            },
            &payload,
        )
    }

    fn wrap_bvlc(function: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = 4 + payload.len();
        let mut frame = Vec::with_capacity(total_len);
        frame.extend_from_slice(&[0x81, function, (total_len >> 8) as u8, total_len as u8]);
        frame.extend_from_slice(payload);
        frame
    }

    /// Collect and de-duplicate I-Am responses until the client timeout.
    fn collect_iam_responses(&self) -> Result<Vec<DeviceInfo>, ClientError> {
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
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }

        Ok(devices)
    }

    fn collect_router_responses(&self) -> Result<Vec<DiscoveredRouter>, ClientError> {
        let mut routers: Vec<DiscoveredRouter> = Vec::new();
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if let Some(response) =
                        self.parse_i_am_router_response(&recv_buffer[..len], source)
                    {
                        if let Some(existing) = routers
                            .iter_mut()
                            .find(|router| router.address == response.address)
                        {
                            for network in response.networks {
                                if !existing.networks.contains(&network) {
                                    existing.networks.push(network);
                                }
                            }
                            existing.networks.sort_unstable();
                        } else {
                            routers.push(response);
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }

        routers.sort_by_key(|router| router.address);
        Ok(routers)
    }

    /// Send a confirmed request and wait for the matching response.
    ///
    /// A fresh invoke ID is allocated for the transaction. Returns the
    /// ComplexAck service data on success, an empty `Vec` for a SimpleAck, or a
    /// typed [`ClientError`] if the device responds with Error/Reject/Abort or
    /// the request times out.
    fn send_confirmed_request(
        &self,
        target: &BacnetTarget,
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
        let bvlc_message = self.create_confirmed_frame(target, &apdu_data);

        self.socket.send_to(&bvlc_message, target.address)?;

        // Wait for response
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if source == target.address {
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

    fn create_confirmed_frame(&self, target: &BacnetTarget, apdu_data: &[u8]) -> Vec<u8> {
        let mut npdu = Npdu::new();
        npdu.control.expecting_reply = true;
        npdu.control.priority = 0;
        if let Some(route) = &target.route {
            npdu.set_destination(route.clone());
            npdu.hop_count = Some(255);
        }
        let npdu_data = npdu.encode();

        let mut message = npdu_data;
        message.extend_from_slice(apdu_data);
        Self::wrap_bvlc(BVLC_ORIGINAL_UNICAST, &message)
    }

    /// Parse I-Am response
    fn parse_iam_response(&self, data: &[u8], source: SocketAddr) -> Option<DeviceInfo> {
        let frame = Self::decode_bacnet_ip_frame(data, source)?;
        let apdu = frame.payload;

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
                    address: frame.source,
                    route: frame.npdu.source,
                    vendor_id: iam.vendor_identifier,
                    vendor_name,
                    max_apdu: iam.max_apdu_length_accepted,
                    segmentation: iam.segmentation_supported,
                })
            }
            Err(_) => None,
        }
    }

    fn parse_i_am_router_response(
        &self,
        data: &[u8],
        source: SocketAddr,
    ) -> Option<DiscoveredRouter> {
        let frame = Self::decode_bacnet_ip_frame(data, source)?;
        if !frame.npdu.is_network_message() {
            return None;
        }

        let message = NetworkLayerMessage::decode(frame.payload).ok()?;
        if message.message_type != NetworkMessageType::IAmRouterToNetwork {
            return None;
        }

        let bytes = message.data().unwrap_or_default();
        if bytes.len() % 2 != 0 {
            return None;
        }
        let mut networks: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect();
        networks.sort_unstable();
        networks.dedup();

        Some(DiscoveredRouter {
            address: frame.source,
            networks,
        })
    }

    fn decode_bacnet_ip_frame(
        data: &[u8],
        udp_source: SocketAddr,
    ) -> Option<DecodedBacnetIpFrame<'_>> {
        if data.len() < 6 || data[0] != 0x81 {
            return None;
        }
        let bvlc_length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() != bvlc_length {
            return None;
        }

        // Forwarded-NPDU carries the original B/IP source between the BVLC
        // header and NPDU. Other NPDU-bearing BVLC functions start at byte 4.
        let (npdu_start, source) = if data[1] == 0x04 {
            if data.len() < 12 {
                return None;
            }
            let source = SocketAddr::from((
                [data[4], data[5], data[6], data[7]],
                u16::from_be_bytes([data[8], data[9]]),
            ));
            (10, source)
        } else {
            (4, udp_source)
        };

        let (npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;
        let payload_start = npdu_start + npdu_len;
        if payload_start > data.len() {
            return None;
        }

        Some(DecodedBacnetIpFrame {
            source,
            npdu,
            payload: &data[payload_start..],
        })
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
        let frame = match Self::decode_bacnet_ip_frame(data, SocketAddr::from(([0, 0, 0, 0], 0))) {
            Some(frame) => frame,
            None => return Ok(None),
        };
        let apdu = match Apdu::decode(frame.payload) {
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
            } if invoke_id == expected_invoke_id => Err(ClientError::Abort(abort_reason)),
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

    fn load_control() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StateDescription),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::RequestedShedLevel),
                PropertyReference::new(PropertyIdentifier::StartTime),
                PropertyReference::new(PropertyIdentifier::ShedDuration),
                PropertyReference::new(PropertyIdentifier::DutyWindow),
                PropertyReference::new(PropertyIdentifier::Enable),
                PropertyReference::new(PropertyIdentifier::FullDutyBaseline),
                PropertyReference::new(PropertyIdentifier::ExpectedShedLevel),
                PropertyReference::new(PropertyIdentifier::ActualShedLevel),
                PropertyReference::new(PropertyIdentifier::ShedLevels),
                PropertyReference::new(PropertyIdentifier::ShedLevelDescriptions),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
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
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn structured_view() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::NodeType),
                PropertyReference::new(PropertyIdentifier::NodeSubtype),
                PropertyReference::new(PropertyIdentifier::SubordinateList),
                PropertyReference::new(PropertyIdentifier::SubordinateAnnotations),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::SubordinateTags),
                PropertyReference::new(PropertyIdentifier::SubordinateNodeTypes),
                PropertyReference::new(PropertyIdentifier::SubordinateRelationships),
                PropertyReference::new(PropertyIdentifier::DefaultSubordinateRelationship),
                PropertyReference::new(PropertyIdentifier::Represents),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn trend_log_multiple() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::Enable),
                PropertyReference::new(PropertyIdentifier::StartTime),
                PropertyReference::new(PropertyIdentifier::StopTime),
                PropertyReference::new(PropertyIdentifier::LogDeviceObjectProperty),
                PropertyReference::new(PropertyIdentifier::LoggingType),
                PropertyReference::new(PropertyIdentifier::LogInterval),
                PropertyReference::new(PropertyIdentifier::AlignIntervals),
                PropertyReference::new(PropertyIdentifier::IntervalOffset),
                PropertyReference::new(PropertyIdentifier::Trigger),
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
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn access_point() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::AuthenticationStatus),
                PropertyReference::new(PropertyIdentifier::ActiveAuthenticationPolicy),
                PropertyReference::new(PropertyIdentifier::NumberOfAuthenticationPolicies),
                PropertyReference::new(PropertyIdentifier::AuthenticationPolicyList),
                PropertyReference::new(PropertyIdentifier::AuthenticationPolicyNames),
                PropertyReference::new(PropertyIdentifier::AuthorizationMode),
                PropertyReference::new(PropertyIdentifier::VerificationTime),
                PropertyReference::new(PropertyIdentifier::Lockout),
                PropertyReference::new(PropertyIdentifier::LockoutRelinquishTime),
                PropertyReference::new(PropertyIdentifier::FailedAttempts),
                PropertyReference::new(PropertyIdentifier::FailedAttemptEvents),
                PropertyReference::new(PropertyIdentifier::MaxFailedAttempts),
                PropertyReference::new(PropertyIdentifier::FailedAttemptsTime),
                PropertyReference::new(PropertyIdentifier::ThreatLevel),
                PropertyReference::new(PropertyIdentifier::OccupancyUpperLimitEnforced),
                PropertyReference::new(PropertyIdentifier::OccupancyLowerLimitEnforced),
                PropertyReference::new(PropertyIdentifier::OccupancyCountAdjust),
                PropertyReference::new(PropertyIdentifier::AccompanimentTime),
                PropertyReference::new(PropertyIdentifier::AccessEvent),
                PropertyReference::new(PropertyIdentifier::AccessEventTag),
                PropertyReference::new(PropertyIdentifier::AccessEventTime),
                PropertyReference::new(PropertyIdentifier::AccessEventCredential),
                PropertyReference::new(PropertyIdentifier::AccessEventAuthenticationFactor),
                PropertyReference::new(PropertyIdentifier::AccessDoors),
                PropertyReference::new(PropertyIdentifier::PriorityForWriting),
                PropertyReference::new(PropertyIdentifier::MusterPoint),
                PropertyReference::new(PropertyIdentifier::ZoneTo),
                PropertyReference::new(PropertyIdentifier::ZoneFrom),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::TransactionNotificationClass),
                PropertyReference::new(PropertyIdentifier::AccessAlarmEvents),
                PropertyReference::new(PropertyIdentifier::AccessTransactionEvents),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn access_zone() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::GlobalIdentifier),
                PropertyReference::new(PropertyIdentifier::OccupancyState),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::OccupancyCount),
                PropertyReference::new(PropertyIdentifier::OccupancyCountEnable),
                PropertyReference::new(PropertyIdentifier::AdjustValue),
                PropertyReference::new(PropertyIdentifier::OccupancyUpperLimit),
                PropertyReference::new(PropertyIdentifier::OccupancyLowerLimit),
                PropertyReference::new(PropertyIdentifier::CredentialsInZone),
                PropertyReference::new(PropertyIdentifier::LastCredentialAdded),
                PropertyReference::new(PropertyIdentifier::LastCredentialAddedTime),
                PropertyReference::new(PropertyIdentifier::LastCredentialRemoved),
                PropertyReference::new(PropertyIdentifier::LastCredentialRemovedTime),
                PropertyReference::new(PropertyIdentifier::PassbackMode),
                PropertyReference::new(PropertyIdentifier::PassbackTimeout),
                PropertyReference::new(PropertyIdentifier::EntryPoints),
                PropertyReference::new(PropertyIdentifier::ExitPoints),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::AlarmValues),
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

    fn access_user() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::GlobalIdentifier),
                PropertyReference::new(PropertyIdentifier::OccupancyState),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::UserType),
                PropertyReference::new(PropertyIdentifier::UserName),
                PropertyReference::new(PropertyIdentifier::UserExternalIdentifier),
                PropertyReference::new(PropertyIdentifier::UserInformationReference),
                PropertyReference::new(PropertyIdentifier::Members),
                PropertyReference::new(PropertyIdentifier::MemberOf),
                PropertyReference::new(PropertyIdentifier::Credentials),
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

    fn access_rights() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::GlobalIdentifier),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::Enable),
                PropertyReference::new(PropertyIdentifier::NegativeAccessRules),
                PropertyReference::new(PropertyIdentifier::PositiveAccessRules),
                PropertyReference::new(PropertyIdentifier::Accompaniment),
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

    fn access_credential() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::GlobalIdentifier),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::CredentialStatus),
                PropertyReference::new(PropertyIdentifier::ReasonForDisable),
                PropertyReference::new(PropertyIdentifier::AuthenticationFactors),
                PropertyReference::new(PropertyIdentifier::ActivationTime),
                PropertyReference::new(PropertyIdentifier::ExpirationTime),
                PropertyReference::new(PropertyIdentifier::CredentialDisable),
                PropertyReference::new(PropertyIdentifier::DaysRemaining),
                PropertyReference::new(PropertyIdentifier::UsesRemaining),
                PropertyReference::new(PropertyIdentifier::AbsenteeLimit),
                PropertyReference::new(PropertyIdentifier::BelongsTo),
                PropertyReference::new(PropertyIdentifier::AssignedAccessRights),
                PropertyReference::new(PropertyIdentifier::LastAccessPoint),
                PropertyReference::new(PropertyIdentifier::LastAccessEvent),
                PropertyReference::new(PropertyIdentifier::LastUseTime),
                PropertyReference::new(PropertyIdentifier::TraceFlag),
                PropertyReference::new(PropertyIdentifier::ThreatAuthority),
                PropertyReference::new(PropertyIdentifier::ExtendedTimeEnable),
                PropertyReference::new(PropertyIdentifier::AuthorizationExemptions),
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

    fn credential_data_input() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::SupportedFormats),
                PropertyReference::new(PropertyIdentifier::SupportedFormatClasses),
                PropertyReference::new(PropertyIdentifier::UpdateTime),
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

    fn character_string_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
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

    fn datetime_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::IsUtc),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

    fn large_analog_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
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

    fn bit_string_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::BitText),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::AlarmValues),
                PropertyReference::new(PropertyIdentifier::BitMask),
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

    fn octet_string_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
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

    fn time_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

    fn integer_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
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

    fn positive_integer_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
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

    fn date_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

    fn date_time_pattern_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::IsUtc),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

    fn time_pattern_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

    fn date_pattern_value() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

    fn global_group() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::GroupMembers),
                PropertyReference::new(PropertyIdentifier::GroupMemberNames),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::MemberStatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::UpdateInterval),
                PropertyReference::new(PropertyIdentifier::RequestedUpdateInterval),
                PropertyReference::new(PropertyIdentifier::CovResubscriptionInterval),
                PropertyReference::new(PropertyIdentifier::ClientCovIncrement),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
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
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::CovuPeriod),
                PropertyReference::new(PropertyIdentifier::CovuRecipients),
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

    fn notification_forwarder() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::RecipientList),
                PropertyReference::new(PropertyIdentifier::SubscribedRecipients),
                PropertyReference::new(PropertyIdentifier::ProcessIdentifierFilter),
                PropertyReference::new(PropertyIdentifier::PortFilter),
                PropertyReference::new(PropertyIdentifier::LocalForwardingOnly),
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

    fn alert_enrollment() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn channel() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::LastPriority),
                PropertyReference::new(PropertyIdentifier::WriteStatus),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::ListOfObjectPropertyReferences),
                PropertyReference::new(PropertyIdentifier::ExecutionDelay),
                PropertyReference::new(PropertyIdentifier::AllowGroupDelayInhibit),
                PropertyReference::new(PropertyIdentifier::ChannelNumber),
                PropertyReference::new(PropertyIdentifier::ControlGroups),
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
                PropertyReference::new(PropertyIdentifier::ValueSource),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn lighting_output() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::TrackingValue),
                PropertyReference::new(PropertyIdentifier::LightingCommand),
                PropertyReference::new(PropertyIdentifier::InProgress),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::BlinkWarnEnable),
                PropertyReference::new(PropertyIdentifier::EgressTime),
                PropertyReference::new(PropertyIdentifier::EgressActive),
                PropertyReference::new(PropertyIdentifier::DefaultFadeTime),
                PropertyReference::new(PropertyIdentifier::DefaultRampRate),
                PropertyReference::new(PropertyIdentifier::DefaultStepIncrement),
                PropertyReference::new(PropertyIdentifier::Transition),
                PropertyReference::new(PropertyIdentifier::FeedbackValue),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::Power),
                PropertyReference::new(PropertyIdentifier::InstantaneousPower),
                PropertyReference::new(PropertyIdentifier::MinActualValue),
                PropertyReference::new(PropertyIdentifier::MaxActualValue),
                PropertyReference::new(PropertyIdentifier::LightingCommandDefaultPriority),
                PropertyReference::new(PropertyIdentifier::CovIncrement),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

    fn binary_lighting_output() -> Self {
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
                PropertyReference::new(PropertyIdentifier::BlinkWarnEnable),
                PropertyReference::new(PropertyIdentifier::EgressTime),
                PropertyReference::new(PropertyIdentifier::EgressActive),
                PropertyReference::new(PropertyIdentifier::FeedbackValue),
                PropertyReference::new(PropertyIdentifier::PriorityArray),
                PropertyReference::new(PropertyIdentifier::RelinquishDefault),
                PropertyReference::new(PropertyIdentifier::Power),
                PropertyReference::new(PropertyIdentifier::Polarity),
                PropertyReference::new(PropertyIdentifier::ElapsedActiveTime),
                PropertyReference::new(PropertyIdentifier::TimeOfActiveTimeReset),
                PropertyReference::new(PropertyIdentifier::StrikeCount),
                PropertyReference::new(PropertyIdentifier::TimeOfStrikeCountReset),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

    fn network_port() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::NetworkType),
                PropertyReference::new(PropertyIdentifier::ProtocolLevel),
                PropertyReference::new(PropertyIdentifier::ReferencePort),
                PropertyReference::new(PropertyIdentifier::NetworkNumber),
                PropertyReference::new(PropertyIdentifier::NetworkNumberQuality),
                PropertyReference::new(PropertyIdentifier::ChangesPending),
                PropertyReference::new(PropertyIdentifier::Command),
                PropertyReference::new(PropertyIdentifier::MacAddress),
                PropertyReference::new(PropertyIdentifier::ApduLength),
                PropertyReference::new(PropertyIdentifier::LinkSpeed),
                PropertyReference::new(PropertyIdentifier::LinkSpeeds),
                PropertyReference::new(PropertyIdentifier::LinkSpeedAutonegotiate),
                PropertyReference::new(PropertyIdentifier::NetworkInterfaceName),
                PropertyReference::new(PropertyIdentifier::BacnetIpMode),
                PropertyReference::new(PropertyIdentifier::IpAddress),
                PropertyReference::new(PropertyIdentifier::BacnetIpUdpPort),
                PropertyReference::new(PropertyIdentifier::IpSubnetMask),
                PropertyReference::new(PropertyIdentifier::IpDefaultGateway),
                PropertyReference::new(PropertyIdentifier::BacnetIpMulticastAddress),
                PropertyReference::new(PropertyIdentifier::IpDnsServer),
                PropertyReference::new(PropertyIdentifier::IpDhcpEnable),
                PropertyReference::new(PropertyIdentifier::IpDhcpLeaseTime),
                PropertyReference::new(PropertyIdentifier::IpDhcpLeaseTimeRemaining),
                PropertyReference::new(PropertyIdentifier::IpDhcpServer),
                PropertyReference::new(PropertyIdentifier::BacnetIpNatTraversal),
                PropertyReference::new(PropertyIdentifier::BacnetIpGlobalAddress),
                PropertyReference::new(PropertyIdentifier::BbmdBroadcastDistributionTable),
                PropertyReference::new(PropertyIdentifier::BbmdAcceptFdRegistrations),
                PropertyReference::new(PropertyIdentifier::BbmdForeignDeviceTable),
                PropertyReference::new(PropertyIdentifier::FdBbmdAddress),
                PropertyReference::new(PropertyIdentifier::FdSubscriptionLifetime),
                PropertyReference::new(PropertyIdentifier::BacnetIpv6Mode),
                PropertyReference::new(PropertyIdentifier::Ipv6Address),
                PropertyReference::new(PropertyIdentifier::Ipv6PrefixLength),
                PropertyReference::new(PropertyIdentifier::BacnetIpv6UdpPort),
                PropertyReference::new(PropertyIdentifier::Ipv6DefaultGateway),
                PropertyReference::new(PropertyIdentifier::BacnetIpv6MulticastAddress),
                PropertyReference::new(PropertyIdentifier::Ipv6DnsServer),
                PropertyReference::new(PropertyIdentifier::Ipv6AutoAddressingEnable),
                PropertyReference::new(PropertyIdentifier::Ipv6DhcpLeaseTime),
                PropertyReference::new(PropertyIdentifier::Ipv6DhcpLeaseTimeRemaining),
                PropertyReference::new(PropertyIdentifier::Ipv6DhcpServer),
                PropertyReference::new(PropertyIdentifier::Ipv6ZoneIndex),
                PropertyReference::new(PropertyIdentifier::MaxManager),
                PropertyReference::new(PropertyIdentifier::MaxInfoFrames),
                PropertyReference::new(PropertyIdentifier::SubordinateProxyEnable),
                PropertyReference::new(PropertyIdentifier::ManualSubordinateAddressBinding),
                PropertyReference::new(PropertyIdentifier::AutoSubordinateDiscovery),
                PropertyReference::new(PropertyIdentifier::SubordinateAddressBinding),
                PropertyReference::new(PropertyIdentifier::VirtualMacAddressTable),
                PropertyReference::new(PropertyIdentifier::RoutingTable),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventState),
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

    fn timer() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::TimerState),
                PropertyReference::new(PropertyIdentifier::TimerRunning),
                PropertyReference::new(PropertyIdentifier::UpdateTime),
                PropertyReference::new(PropertyIdentifier::LastStateChange),
                PropertyReference::new(PropertyIdentifier::ExpirationTime),
                PropertyReference::new(PropertyIdentifier::InitialTimeout),
                PropertyReference::new(PropertyIdentifier::DefaultTimeout),
                PropertyReference::new(PropertyIdentifier::MinPresValue),
                PropertyReference::new(PropertyIdentifier::MaxPresValue),
                PropertyReference::new(PropertyIdentifier::Resolution),
                PropertyReference::new(PropertyIdentifier::StateChangeValues),
                PropertyReference::new(PropertyIdentifier::ListOfObjectPropertyReferences),
                PropertyReference::new(PropertyIdentifier::PriorityForWriting),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::AlarmValues),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
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

    fn elevator_group() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::MachineRoomId),
                PropertyReference::new(PropertyIdentifier::GroupId),
                PropertyReference::new(PropertyIdentifier::GroupMembers),
                PropertyReference::new(PropertyIdentifier::GroupMode),
                PropertyReference::new(PropertyIdentifier::LandingCalls),
                PropertyReference::new(PropertyIdentifier::LandingCallControl),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn lift() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::ElevatorGroup),
                PropertyReference::new(PropertyIdentifier::GroupId),
                PropertyReference::new(PropertyIdentifier::InstallationId),
                PropertyReference::new(PropertyIdentifier::FloorText),
                PropertyReference::new(PropertyIdentifier::CarDoorText),
                PropertyReference::new(PropertyIdentifier::AssignedLandingCalls),
                PropertyReference::new(PropertyIdentifier::MakingCarCall),
                PropertyReference::new(PropertyIdentifier::RegisteredCarCall),
                PropertyReference::new(PropertyIdentifier::CarPosition),
                PropertyReference::new(PropertyIdentifier::CarMovingDirection),
                PropertyReference::new(PropertyIdentifier::CarAssignedDirection),
                PropertyReference::new(PropertyIdentifier::CarDoorStatus),
                PropertyReference::new(PropertyIdentifier::CarDoorCommand),
                PropertyReference::new(PropertyIdentifier::CarDoorZone),
                PropertyReference::new(PropertyIdentifier::CarMode),
                PropertyReference::new(PropertyIdentifier::CarLoad),
                PropertyReference::new(PropertyIdentifier::CarLoadUnits),
                PropertyReference::new(PropertyIdentifier::NextStoppingFloor),
                PropertyReference::new(PropertyIdentifier::PassengerAlarm),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::EnergyMeter),
                PropertyReference::new(PropertyIdentifier::EnergyMeterRef),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::CarDriveStatus),
                PropertyReference::new(PropertyIdentifier::FaultSignals),
                PropertyReference::new(PropertyIdentifier::LandingDoorStatus),
                PropertyReference::new(PropertyIdentifier::HigherDeck),
                PropertyReference::new(PropertyIdentifier::LowerDeck),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
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

    fn escalator() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::ElevatorGroup),
                PropertyReference::new(PropertyIdentifier::GroupId),
                PropertyReference::new(PropertyIdentifier::InstallationId),
                PropertyReference::new(PropertyIdentifier::PowerMode),
                PropertyReference::new(PropertyIdentifier::OperationDirection),
                PropertyReference::new(PropertyIdentifier::EscalatorMode),
                PropertyReference::new(PropertyIdentifier::EnergyMeter),
                PropertyReference::new(PropertyIdentifier::EnergyMeterRef),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::FaultSignals),
                PropertyReference::new(PropertyIdentifier::PassengerAlarm),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
                PropertyReference::new(PropertyIdentifier::TimeDelayNormal),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibit),
                PropertyReference::new(PropertyIdentifier::EventAlgorithmInhibitRef),
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

    fn accumulator() -> Self {
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
                PropertyReference::new(PropertyIdentifier::Scale),
                PropertyReference::new(PropertyIdentifier::Units),
                PropertyReference::new(PropertyIdentifier::Prescale),
                PropertyReference::new(PropertyIdentifier::MaxPresValue),
                PropertyReference::new(PropertyIdentifier::ValueChangeTime),
                PropertyReference::new(PropertyIdentifier::ValueBeforeChange),
                PropertyReference::new(PropertyIdentifier::ValueSet),
                PropertyReference::new(PropertyIdentifier::LoggingRecord),
                PropertyReference::new(PropertyIdentifier::LoggingObject),
                PropertyReference::new(PropertyIdentifier::PulseRate),
                PropertyReference::new(PropertyIdentifier::HighLimit),
                PropertyReference::new(PropertyIdentifier::LowLimit),
                PropertyReference::new(PropertyIdentifier::LimitMonitoringInterval),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::TimeDelay),
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

    fn staging() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::PresentValue),
                PropertyReference::new(PropertyIdentifier::PresentStage),
                PropertyReference::new(PropertyIdentifier::Stages),
                PropertyReference::new(PropertyIdentifier::StageNames),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::OutOfService),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::Units),
                PropertyReference::new(PropertyIdentifier::TargetReferences),
                PropertyReference::new(PropertyIdentifier::PriorityForWriting),
                PropertyReference::new(PropertyIdentifier::DefaultPresentValue),
                PropertyReference::new(PropertyIdentifier::MinPresValue),
                PropertyReference::new(PropertyIdentifier::MaxPresValue),
                PropertyReference::new(PropertyIdentifier::CovIncrement),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
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

    fn audit_reporter() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::AuditLevel),
                PropertyReference::new(PropertyIdentifier::AuditSourceReporter),
                PropertyReference::new(PropertyIdentifier::AuditableOperations),
                PropertyReference::new(PropertyIdentifier::AuditPriorityFilter),
                PropertyReference::new(PropertyIdentifier::IssueConfirmedNotifications),
                PropertyReference::new(PropertyIdentifier::MonitoredObjects),
                PropertyReference::new(PropertyIdentifier::MaximumSendDelay),
                PropertyReference::new(PropertyIdentifier::SendNow),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
                PropertyReference::new(PropertyIdentifier::ReliabilityEvaluationInhibit),
                PropertyReference::new(PropertyIdentifier::PropertyList),
                PropertyReference::new(PropertyIdentifier::Tags),
                PropertyReference::new(PropertyIdentifier::ProfileLocation),
                PropertyReference::new(PropertyIdentifier::ProfileName),
            ],
        }
    }

    fn audit_log() -> Self {
        Self {
            vec: vec![
                PropertyReference::new(PropertyIdentifier::ObjectIdentifier),
                PropertyReference::new(PropertyIdentifier::ObjectName),
                PropertyReference::new(PropertyIdentifier::ObjectType),
                PropertyReference::new(PropertyIdentifier::Description),
                PropertyReference::new(PropertyIdentifier::StatusFlags),
                PropertyReference::new(PropertyIdentifier::EventState),
                PropertyReference::new(PropertyIdentifier::Reliability),
                PropertyReference::new(PropertyIdentifier::Enable),
                PropertyReference::new(PropertyIdentifier::BufferSize),
                PropertyReference::new(PropertyIdentifier::LogBuffer),
                PropertyReference::new(PropertyIdentifier::RecordCount),
                PropertyReference::new(PropertyIdentifier::TotalRecordCount),
                PropertyReference::new(PropertyIdentifier::MemberOf),
                PropertyReference::new(PropertyIdentifier::DeleteOnForward),
                PropertyReference::new(PropertyIdentifier::IssueConfirmedNotifications),
                PropertyReference::new(PropertyIdentifier::EventDetectionEnable),
                PropertyReference::new(PropertyIdentifier::NotificationClass),
                PropertyReference::new(PropertyIdentifier::EventEnable),
                PropertyReference::new(PropertyIdentifier::AckedTransitions),
                PropertyReference::new(PropertyIdentifier::NotifyType),
                PropertyReference::new(PropertyIdentifier::EventTimeStamps),
                PropertyReference::new(PropertyIdentifier::EventMessageTexts),
                PropertyReference::new(PropertyIdentifier::EventMessageTextsConfig),
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

/// Whether a Who-Is target should be framed as a broadcast.
///
/// True for the IPv4 limited broadcast (`255.255.255.255`) and for the
/// subnet-directed broadcast address of any local interface. A directed
/// broadcast for a *remote* subnet can't be recognized without that subnet's
/// mask, so it falls back to unicast framing; IPv6 has no broadcast at all.
#[cfg(feature = "std")]
fn is_broadcast_target(addr: SocketAddr) -> bool {
    let std::net::IpAddr::V4(ip) = addr.ip() else {
        return false;
    };
    if ip.is_broadcast() {
        return true;
    }
    if_addrs::get_if_addrs()
        .map(|interfaces| {
            interfaces.iter().any(|iface| match &iface.addr {
                if_addrs::IfAddr::V4(v4) => v4.broadcast == Some(ip),
                _ => false,
            })
        })
        .unwrap_or(false)
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

    /// Loopback-bound client for frame-construction tests.
    fn test_client() -> BacnetClient {
        BacnetClient::builder()
            .local_addr("127.0.0.1")
            .port(0)
            .build()
            .expect("client should bind")
    }

    #[test]
    fn test_broadcast_whois_frame_matches_reference_stack() {
        // The frame YABE sends for a global
        // Who-Is (issue #58): Original-Broadcast-NPDU BVLC around an NPDU
        // with DNET 0xFFFF, DLEN 0, hop count 255.
        let client = test_client();
        let frame =
            client.create_unconfirmed_frame(UnconfirmedServiceChoice::WhoIs as u8, &[], true);
        assert_eq!(
            frame,
            [
                0x81, 0x0B, 0x00, 0x0C, // BVLC: Original-Broadcast-NPDU, length 12
                0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, // NPDU: dest DNET 0xFFFF, hop 255
                0x10, 0x08, // APDU: Unconfirmed-Request, Who-Is
            ]
        );
    }

    #[test]
    fn test_unicast_whois_frame_uses_local_npdu() {
        let client = test_client();
        let frame =
            client.create_unconfirmed_frame(UnconfirmedServiceChoice::WhoIs as u8, &[], false);
        assert_eq!(
            frame,
            [
                0x81, 0x0A, 0x00, 0x08, // BVLC: Original-Unicast-NPDU, length 8
                0x01, 0x00, // NPDU: no destination
                0x10, 0x08, // APDU: Unconfirmed-Request, Who-Is
            ]
        );
    }

    #[test]
    fn test_network_whois_unicasts_to_router_with_downstream_broadcast_npdu() {
        let client = test_client();
        let frame = client.create_who_is_network_frame(200, &[]);

        assert_eq!(
            frame,
            [
                0x81, 0x0A, 0x00, 0x0C, // BVLC: Original-Unicast-NPDU, length 12
                0x01, 0x20, 0x00, 0xC8, 0x00, 0xFF, // NPDU: DNET 200 broadcast
                0x10, 0x08, // APDU: Unconfirmed-Request, Who-Is
            ]
        );
    }

    #[test]
    fn test_network_whois_preserves_device_instance_range() {
        let client = test_client();
        let request = WhoIsRequest::for_range(100, 200);
        let mut service_data = Vec::new();
        request.encode(&mut service_data).unwrap();

        let frame = client.create_who_is_network_frame(300, &service_data);
        let (npdu, npdu_len) = Npdu::decode(&frame[4..]).unwrap();
        assert_eq!(npdu.destination, Some(NetworkAddress::new(300, Vec::new())));

        let apdu = &frame[4 + npdu_len..];
        assert_eq!(apdu[..2], [0x10, UnconfirmedServiceChoice::WhoIs as u8]);
        assert_eq!(WhoIsRequest::decode(&apdu[2..]).unwrap(), request);
    }

    #[test]
    fn test_who_is_router_frames_encode_optional_network() {
        let client = test_client();

        assert_eq!(
            client.create_who_is_router_frame(None, true),
            [
                0x81, 0x0B, 0x00, 0x07, // BVLC Original-Broadcast-NPDU
                0x01, 0x80, // NPDU network-layer message
                0x00, // Who-Is-Router-To-Network, all networks
            ]
        );
        assert_eq!(
            client.create_who_is_router_frame(Some(200), false),
            [
                0x81, 0x0A, 0x00, 0x09, // BVLC Original-Unicast-NPDU
                0x01, 0x80, // NPDU network-layer message
                0x00, 0x00, 0xC8, // Who-Is-Router-To-Network 200
            ]
        );
    }

    #[test]
    fn test_i_am_router_response_decodes_advertised_networks() {
        let client = test_client();
        let frame = [
            0x81, 0x0A, 0x00, 0x0B, // BVLC Original-Unicast-NPDU
            0x01, 0x80, // NPDU network-layer message
            0x01, // I-Am-Router-To-Network
            0x00, 0xC8, // network 200
            0x01, 0x2C, // network 300
        ];
        let source = "192.0.2.10:47808".parse().unwrap();

        let router = client.parse_i_am_router_response(&frame, source).unwrap();
        assert_eq!(
            router,
            DiscoveredRouter {
                address: source,
                networks: vec![200, 300],
            }
        );
    }

    #[test]
    fn test_routed_i_am_preserves_router_and_npdu_source() {
        let client = test_client();
        let route = NetworkAddress::new(200, vec![5]);
        let mut npdu = Npdu::new();
        npdu.set_source(route.clone());

        let iam = IAmRequest::new(
            ObjectIdentifier::new(ObjectType::Device, 1234),
            1476,
            Segmentation::NoSegmentation,
            1,
        );
        let mut service_data = Vec::new();
        iam.encode(&mut service_data).unwrap();
        let mut payload = npdu.encode();
        payload.extend_from_slice(&[0x10, UnconfirmedServiceChoice::IAm as u8]);
        payload.extend_from_slice(&service_data);
        let frame = BacnetClient::wrap_bvlc(BVLC_ORIGINAL_UNICAST, &payload);
        let router: SocketAddr = "192.0.2.10:47808".parse().unwrap();

        let device = client.parse_iam_response(&frame, router).unwrap();
        assert_eq!(device.device_id, 1234);
        assert_eq!(device.address, router);
        assert_eq!(device.route, Some(route));
    }

    #[test]
    fn test_confirmed_request_to_routed_device_encodes_dnet_and_dadr() {
        let client = test_client();
        let target = BacnetTarget::routed(
            "192.0.2.10:47808".parse().unwrap(),
            NetworkAddress::new(200, vec![5]),
        );
        let frame = client.create_confirmed_frame(&target, &[0xAA, 0xBB]);

        assert_eq!(frame[1], BVLC_ORIGINAL_UNICAST);
        let (npdu, npdu_len) = Npdu::decode(&frame[4..]).unwrap();
        assert!(npdu.control.expecting_reply);
        assert_eq!(npdu.destination, target.route);
        assert_eq!(npdu.hop_count, Some(255));
        assert_eq!(&frame[4 + npdu_len..], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_is_broadcast_target() {
        assert!(is_broadcast_target(
            "255.255.255.255:47808".parse().unwrap()
        ));
        assert!(!is_broadcast_target("127.0.0.1:47808".parse().unwrap()));
        assert!(!is_broadcast_target("10.161.1.211:47808".parse().unwrap()));
        // IPv6 has no broadcast.
        assert!(!is_broadcast_target("[::1]:47808".parse().unwrap()));
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
