//! BACnet Client Utilities
//!
//! This module exposes BACnet protocol operations such as discovery,
//! ReadProperty, ReadPropertyMultiple, and WriteProperty. Convenience methods
//! that return typed results still issue one documented protocol transaction;
//! fallback and retry strategies across different services belong to callers.
//!
//! The entry point is [`BacnetClient`]. Construct one with [`BacnetClient::new`]
//! for defaults, or with [`BacnetClient::builder`] to customize the local
//! interface, port, timeout, and retries. All methods return [`ClientError`] on
//! failure.

#[cfg(feature = "async")]
mod async_client;
mod config;
mod error;
mod transaction;

#[cfg(feature = "async")]
pub use async_client::AsyncBacnetClient;
pub use config::{ClientBuilder, ClientConfig, DEFAULT_HOST, DEFAULT_TIMEOUT};
pub use error::ClientError;

use transaction::InvokeIdAllocator;

#[cfg(feature = "std")]
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap as HashMap, string::String, vec::Vec};

use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    datalink::bip::BACNET_IP_PORT,
    network::{NetworkAddress, NetworkLayerMessage, NetworkMessageType, Npdu},
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier, Segmentation},
    property::{encode_property_value, PropertyValue},
    service::{
        ConfirmedServiceChoice, IAmRequest, PropertyReference, PropertyResult, PropertyResultValue,
        ReadAccessSpecification, ReadPropertyMultipleRequest, ReadPropertyMultipleResponse,
        ReadPropertyRequest, ReadPropertyResponse, UnconfirmedServiceChoice, WhoIsRequest,
        WritePropertyRequest,
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
    /// Number of retries after an initial timeout.
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

/// Decoded result of one RPM `ALL` request for a BACnet object.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectSnapshot {
    pub object_identifier: ObjectIdentifier,
    pub properties: Vec<PropertyReadResult>,
}

/// Value or BACnet property-level error returned for one property.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyReadResult {
    pub property_identifier: PropertyIdentifier,
    pub outcome: PropertyReadOutcome,
}

/// Outcome of reading an individual property in an object snapshot.
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyReadOutcome {
    Value(Vec<PropertyValue>),
    Error {
        class: u32,
        code: u32,
    },
    /// The property responded, but its value encoding is not yet supported by
    /// the generic decoder.
    DecodeError(String),
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
            create_unconfirmed_frame(UnconfirmedServiceChoice::WhoIs as u8, &buffer, false);
        self.socket.send_to(&message, target_addr)?;

        // Wait for I-Am response
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if source == target_addr {
                        if let Some(device_info) = parse_iam_response(&recv_buffer[..len], source) {
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
            create_who_is_router_frame(destination_network, is_broadcast_target(target_addr));
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

        let message = create_unconfirmed_frame(
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

        let message = create_who_is_network_frame(destination_network, &service_data);
        self.socket.send_to(&message, router_addr)?;

        self.collect_iam_responses()
    }

    /// Read the device's complete Object_List in one RP transaction.
    ///
    /// Errors such as APDU-too-long are returned directly. No indexed or RPM
    /// fallback is attempted. The Device object is retained because it is part
    /// of the BACnet array.
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
        self.read_property(&target, device_object, PropertyIdentifier::ObjectList)?
            .into_iter()
            .map(decode_object_list_value)
            .collect()
    }

    /// Read every property exposed by an object.
    ///
    /// This issues exactly one ReadPropertyMultiple request with the `ALL`
    /// selector. It does not fall back to Property_List or individual RP calls.
    /// BACnet errors for individual properties remain in the snapshot.
    pub fn read_object_properties<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
    ) -> Result<ObjectSnapshot, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();

        let properties = self.read_all_properties_rpm(&target, object)?;

        Ok(ObjectSnapshot {
            object_identifier: object,
            properties,
        })
    }

    fn read_all_properties_rpm(
        &self,
        target: &BacnetTarget,
        object: ObjectIdentifier,
    ) -> Result<Vec<PropertyReadResult>, ClientError> {
        let request = ReadPropertyMultipleRequest::new(vec![ReadAccessSpecification::new(
            object,
            vec![PropertyReference::new(PropertyIdentifier::All)],
        )]);
        let response = self.read_property_multiple(target, &request)?;
        let access = response
            .read_access_results
            .into_iter()
            .find(|access| access.object_identifier == object)
            .ok_or_else(|| ClientError::Decode(format!("RPM response omitted {object:?}")))?;

        Ok(access
            .results
            .into_iter()
            .map(property_read_result)
            .collect())
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
        Ok(self
            .read_property_response(&target, object, property, None)?
            .property_values)
    }

    /// Read one explicit array index with a single ReadProperty transaction.
    pub fn read_property_at<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: u32,
    ) -> Result<Vec<PropertyValue>, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        Ok(self
            .read_property_response(&target, object, property, Some(array_index))?
            .property_values)
    }

    /// Execute exactly one ReadPropertyMultiple request.
    ///
    /// Per-property BACnet errors remain in the returned response. This method
    /// does not retry with ReadProperty or alter the requested references.
    pub fn read_property_multiple<T>(
        &self,
        target: T,
        request: &ReadPropertyMultipleRequest,
    ) -> Result<ReadPropertyMultipleResponse, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let response_data = self.send_confirmed_request(
            &target,
            ConfirmedServiceChoice::ReadPropertyMultiple,
            &self.encode_rpm_request(request)?,
        )?;
        Ok(ReadPropertyMultipleResponse::decode(&response_data)?)
    }

    fn read_property_response(
        &self,
        target: &BacnetTarget,
        object: ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<ReadPropertyResponse, ClientError> {
        let request = match array_index {
            Some(index) => ReadPropertyRequest::with_array_index(object, property, index),
            None => ReadPropertyRequest::new(object, property),
        };
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;

        let response_data = self.send_confirmed_request(
            target,
            ConfirmedServiceChoice::ReadProperty,
            &service_data,
        )?;
        let response = ReadPropertyResponse::decode(&response_data)?;
        if response.object_identifier != object
            || response.property_identifier != property
            || response.property_array_index != array_index
        {
            return Err(ClientError::Decode(format!(
                "ReadProperty response did not match {object:?} {property:?}[{array_index:?}]"
            )));
        }

        Ok(response)
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
}

/// Build a BACnet/IP frame for an unconfirmed request.
///
/// `broadcast` selects the frame shape as a pair, matching YABE: a broadcast carries a global-broadcast NPDU
///
/// (DNET `0xFFFF`, hop count 255) inside an Original-Broadcast-NPDU BVLC,
/// while a unicast carries a plain local NPDU inside Original-Unicast-NPDU.
#[cfg(feature = "std")]
fn create_unconfirmed_frame(service_choice: u8, service_data: &[u8], broadcast: bool) -> Vec<u8> {
    let (npdu, bvlc_function) = if broadcast {
        (Npdu::global_broadcast(), BVLC_ORIGINAL_BROADCAST)
    } else {
        let mut npdu = Npdu::new();
        npdu.control.expecting_reply = false;
        npdu.control.priority = 0;
        (npdu, BVLC_ORIGINAL_UNICAST)
    };

    create_unconfirmed_frame_with_npdu(service_choice, service_data, npdu, bvlc_function)
}

/// Build an unconfirmed BACnet/IP frame from an explicitly addressed NPDU.
#[cfg(feature = "std")]
fn create_unconfirmed_frame_with_npdu(
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
#[cfg(feature = "std")]
fn create_who_is_network_frame(network: u16, service_data: &[u8]) -> Vec<u8> {
    // The IP packet is unicast to the known router. The NPDU destination,
    // not the BVLC function or IP address, asks the router to broadcast the
    // Who-Is on the downstream BACnet network. An empty DADR means every
    // station on DNET.
    let mut npdu = Npdu::new();
    npdu.set_destination(NetworkAddress::new(network, Vec::new()));
    npdu.hop_count = Some(255);

    create_unconfirmed_frame_with_npdu(
        UnconfirmedServiceChoice::WhoIs as u8,
        service_data,
        npdu,
        BVLC_ORIGINAL_UNICAST,
    )
}

/// Build a Who-Is-Router-To-Network network-layer message.
#[cfg(feature = "std")]
fn create_who_is_router_frame(destination_network: Option<u16>, broadcast: bool) -> Vec<u8> {
    let mut npdu = Npdu::new();
    npdu.control.network_message = true;

    let message_data = destination_network.map(|network| network.to_be_bytes().to_vec());
    let network_message =
        NetworkLayerMessage::new(NetworkMessageType::WhoIsRouterToNetwork, message_data);

    let mut payload = npdu.encode();
    payload.extend_from_slice(&network_message.encode());
    wrap_bvlc(
        if broadcast {
            BVLC_ORIGINAL_BROADCAST
        } else {
            BVLC_ORIGINAL_UNICAST
        },
        &payload,
    )
}

#[cfg(feature = "std")]
fn wrap_bvlc(function: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 4 + payload.len();
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&[0x81, function, (total_len >> 8) as u8, total_len as u8]);
    frame.extend_from_slice(payload);
    frame
}

#[cfg(feature = "std")]
impl BacnetClient {
    /// Collect and de-duplicate I-Am responses until the client timeout.
    fn collect_iam_responses(&self) -> Result<Vec<DeviceInfo>, ClientError> {
        let mut devices = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if let Some(info) = parse_iam_response(&recv_buffer[..len], source) {
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
                    if let Some(response) = parse_i_am_router_response(&recv_buffer[..len], source)
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

        let mut recv_buffer = [0u8; 1500];
        for _attempt in 0..=self.retries {
            self.socket.send_to(&bvlc_message, target.address)?;
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
                    // on Windows; both mean this attempt received nothing useful.
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break
                    }
                    Err(e) => return Err(e.into()),
                }
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
        wrap_bvlc(BVLC_ORIGINAL_UNICAST, &message)
    }
}

/// Parse I-Am response
#[cfg(feature = "std")]
fn parse_iam_response(data: &[u8], source: SocketAddr) -> Option<DeviceInfo> {
    let frame = decode_bacnet_ip_frame(data, source)?;
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

#[cfg(feature = "std")]
fn parse_i_am_router_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredRouter> {
    let frame = decode_bacnet_ip_frame(data, source)?;
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
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    networks.sort_unstable();
    networks.dedup();

    Some(DiscoveredRouter {
        address: frame.source,
        networks,
    })
}

#[cfg(feature = "std")]
fn decode_bacnet_ip_frame(data: &[u8], udp_source: SocketAddr) -> Option<DecodedBacnetIpFrame<'_>> {
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

#[cfg(feature = "std")]
impl BacnetClient {
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
        let frame = match decode_bacnet_ip_frame(data, SocketAddr::from(([0, 0, 0, 0], 0))) {
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
                class: error_class,
                code: error_code,
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
}

#[cfg(feature = "std")]
fn property_read_result(result: PropertyResult) -> PropertyReadResult {
    let outcome = match result.value {
        PropertyResultValue::Value(values) => PropertyReadOutcome::Value(values),
        PropertyResultValue::Error(class, code) => PropertyReadOutcome::Error { class, code },
    };
    PropertyReadResult {
        property_identifier: result.property_identifier,
        outcome,
    }
}

#[cfg(feature = "std")]
fn decode_object_list_value(value: PropertyValue) -> Result<ObjectIdentifier, ClientError> {
    match value {
        PropertyValue::ObjectIdentifier(identifier) => Ok(identifier),
        value => Err(ClientError::Decode(format!(
            "Object_List contained {value:?} instead of an object identifier"
        ))),
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
        let frame = create_unconfirmed_frame(UnconfirmedServiceChoice::WhoIs as u8, &[], true);
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
        let frame = create_unconfirmed_frame(UnconfirmedServiceChoice::WhoIs as u8, &[], false);
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
        let frame = create_who_is_network_frame(200, &[]);

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
        let request = WhoIsRequest::for_range(100, 200);
        let mut service_data = Vec::new();
        request.encode(&mut service_data).unwrap();

        let frame = create_who_is_network_frame(300, &service_data);
        let (npdu, npdu_len) = Npdu::decode(&frame[4..]).unwrap();
        assert_eq!(npdu.destination, Some(NetworkAddress::new(300, Vec::new())));

        let apdu = &frame[4 + npdu_len..];
        assert_eq!(apdu[..2], [0x10, UnconfirmedServiceChoice::WhoIs as u8]);
        assert_eq!(WhoIsRequest::decode(&apdu[2..]).unwrap(), request);
    }

    #[test]
    fn test_who_is_router_frames_encode_optional_network() {
        assert_eq!(
            create_who_is_router_frame(None, true),
            [
                0x81, 0x0B, 0x00, 0x07, // BVLC Original-Broadcast-NPDU
                0x01, 0x80, // NPDU network-layer message
                0x00, // Who-Is-Router-To-Network, all networks
            ]
        );
        assert_eq!(
            create_who_is_router_frame(Some(200), false),
            [
                0x81, 0x0A, 0x00, 0x09, // BVLC Original-Unicast-NPDU
                0x01, 0x80, // NPDU network-layer message
                0x00, 0x00, 0xC8, // Who-Is-Router-To-Network 200
            ]
        );
    }

    #[test]
    fn test_i_am_router_response_decodes_advertised_networks() {
        let frame = [
            0x81, 0x0A, 0x00, 0x0B, // BVLC Original-Unicast-NPDU
            0x01, 0x80, // NPDU network-layer message
            0x01, // I-Am-Router-To-Network
            0x00, 0xC8, // network 200
            0x01, 0x2C, // network 300
        ];
        let source = "192.0.2.10:47808".parse().unwrap();

        let router = parse_i_am_router_response(&frame, source).unwrap();
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
        let frame = wrap_bvlc(BVLC_ORIGINAL_UNICAST, &payload);
        let router: SocketAddr = "192.0.2.10:47808".parse().unwrap();

        let device = parse_iam_response(&frame, router).unwrap();
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
