//! Concurrent asynchronous BACnet/IP client.
//!
//! One endpoint task owns the UDP socket, receives every datagram, and routes
//! confirmed responses to callers through per-transaction one-shot channels.
//! Cloned client handles submit commands through a bounded queue; requests are
//! sent without waiting for earlier transactions to complete. Discovery
//! (Who-Is, Who-Is-Router-To-Network) registers a response sink with the
//! endpoint, which forwards matching unconfirmed frames until the timeout
//! window closes.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::{sleep_until, Instant},
};

use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    datalink::bip::BACNET_IP_PORT,
    network::Npdu,
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier},
    property::{encode_property_value, PropertyValue},
    service::{
        AbortReason, ConfirmedServiceChoice, PropertyReference, ReadAccessSpecification,
        ReadPropertyMultipleRequest, ReadPropertyMultipleResponse, ReadPropertyRequest,
        ReadPropertyResponse, UnconfirmedServiceChoice, WhoIsRequest, WritePropertyRequest,
    },
};

use super::{
    create_unconfirmed_frame, create_who_is_network_frame, create_who_is_router_frame,
    decode_bacnet_ip_frame, decode_object_list_value, is_broadcast_target,
    parse_i_am_router_response, parse_iam_response, property_read_result, BacnetTarget,
    ClientConfig, ClientError, DeviceInfo, DiscoveredRouter, ObjectSnapshot, PropertyReadResult,
    BVLC_ORIGINAL_UNICAST,
};

const COMMAND_QUEUE_CAPACITY: usize = 256;
const MAX_BACNET_IP_FRAME: usize = 65_535;

/// Cloneable handle to a concurrent BACnet/IP endpoint.
///
/// The handle does not own or receive from the UDP socket. All clones submit
/// work to one endpoint task, which permits unrelated requests to remain in
/// flight at the same time without competing for datagrams.
#[derive(Clone)]
pub struct AsyncBacnetClient {
    commands: mpsc::Sender<EndpointCommand>,
    local_addr: SocketAddr,
}

impl AsyncBacnetClient {
    /// Bind using the default client configuration.
    pub async fn new() -> Result<Self, ClientError> {
        Self::from_config(ClientConfig::default()).await
    }

    /// Bind a concurrent client using an explicit configuration.
    pub async fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
        let socket = UdpSocket::bind(config.bind_addr()).await?;
        Self::from_socket(socket, config.timeout, config.retries)
    }

    /// Build a client around an already-bound Tokio UDP socket.
    pub fn from_socket(
        socket: UdpSocket,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ClientError> {
        let local_addr = socket.local_addr()?;
        // Discovery may target broadcast addresses.
        socket.set_broadcast(true)?;
        let (commands, receiver) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        tokio::spawn(Endpoint::new(socket, receiver, timeout, retries).run());
        Ok(Self {
            commands,
            local_addr,
        })
    }

    /// Address of the endpoint's single UDP socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Broadcast a Who-Is on the local subnet and collect every device that
    /// answers with an I-Am, until the configured timeout elapses.
    ///
    /// Results are de-duplicated by device id.
    pub async fn who_is(
        &self,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let broadcast = SocketAddr::from(([255, 255, 255, 255], BACNET_IP_PORT));
        self.who_is_to(broadcast, low_limit, high_limit).await
    }

    /// Send a Who-Is to a specific address (broadcast or unicast) and collect
    /// all I-Am replies until the timeout elapses.
    ///
    /// Broadcast targets are framed as a global-broadcast NPDU inside an
    /// Original-Broadcast-NPDU BVLC, matching the sync client.
    pub async fn who_is_to(
        &self,
        target_addr: SocketAddr,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let frame = create_unconfirmed_frame(
            UnconfirmedServiceChoice::WhoIs as u8,
            &encode_who_is(low_limit, high_limit)?,
            is_broadcast_target(target_addr),
        );
        self.discover_devices(frame, target_addr).await
    }

    /// Send Who-Is through a known BACnet router to every station on a
    /// downstream BACnet network and collect the resulting I-Am responses.
    pub async fn who_is_network(
        &self,
        router_addr: SocketAddr,
        destination_network: u16,
        low_limit: Option<u32>,
        high_limit: Option<u32>,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let frame = create_who_is_network_frame(
            destination_network,
            &encode_who_is(low_limit, high_limit)?,
        );
        self.discover_devices(frame, router_addr).await
    }

    /// Discover every BACnet router visible through the limited IP broadcast.
    pub async fn who_is_router(
        &self,
        destination_network: Option<u16>,
    ) -> Result<Vec<DiscoveredRouter>, ClientError> {
        let broadcast = SocketAddr::from(([255, 255, 255, 255], BACNET_IP_PORT));
        self.who_is_router_to(broadcast, destination_network).await
    }

    /// Send Who-Is-Router-To-Network to an explicit UDP destination and
    /// collect I-Am-Router-To-Network responses until the timeout elapses.
    pub async fn who_is_router_to(
        &self,
        target_addr: SocketAddr,
        destination_network: Option<u16>,
    ) -> Result<Vec<DiscoveredRouter>, ClientError> {
        let frame =
            create_who_is_router_frame(destination_network, is_broadcast_target(target_addr));
        let (sink, mut responses) = mpsc::unbounded_channel();
        self.commands
            .send(EndpointCommand::DiscoverRouters {
                frame,
                destination: target_addr,
                sink,
            })
            .await
            .map_err(|_| ClientError::EndpointClosed)?;

        let mut routers: Vec<DiscoveredRouter> = Vec::new();
        while let Some(response) = responses.recv().await {
            let response = response?;
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
        routers.sort_by_key(|router| router.address);
        Ok(routers)
    }

    async fn discover_devices(
        &self,
        frame: Vec<u8>,
        destination: SocketAddr,
    ) -> Result<Vec<DeviceInfo>, ClientError> {
        let (sink, mut responses) = mpsc::unbounded_channel();
        self.commands
            .send(EndpointCommand::DiscoverDevices {
                frame,
                destination,
                sink,
            })
            .await
            .map_err(|_| ClientError::EndpointClosed)?;

        let mut devices = Vec::new();
        let mut seen = HashSet::new();
        while let Some(device) = responses.recv().await {
            let device = device?;
            if seen.insert(device.device_id) {
                devices.push(device);
            }
        }
        Ok(devices)
    }

    async fn send_confirmed_request(
        &self,
        target: &BacnetTarget,
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(EndpointCommand::Confirmed {
                target: target.clone(),
                service_choice,
                service_data,
                response,
            })
            .await
            .map_err(|_| ClientError::EndpointClosed)?;
        receiver.await.map_err(|_| ClientError::EndpointClosed)?
    }

    /// Read a property and return every decoded value in its response.
    pub async fn read_property<T>(
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
            .read_property_response(&target, object, property, None)
            .await?
            .property_values)
    }

    /// Read one explicit array index with a single ReadProperty transaction.
    pub async fn read_property_at<T>(
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
            .read_property_response(&target, object, property, Some(array_index))
            .await?
            .property_values)
    }

    async fn read_property_response(
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
        let response_data = self
            .send_confirmed_request(target, ConfirmedServiceChoice::ReadProperty, service_data)
            .await?;
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

    /// Execute one ReadPropertyMultiple request.
    pub async fn read_property_multiple<T>(
        &self,
        target: T,
        request: &ReadPropertyMultipleRequest,
    ) -> Result<ReadPropertyMultipleResponse, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;
        let response_data = self
            .send_confirmed_request(
                &target,
                ConfirmedServiceChoice::ReadPropertyMultiple,
                service_data,
            )
            .await?;
        Ok(ReadPropertyMultipleResponse::decode(&response_data)?)
    }

    /// Write one property and await its SimpleAck.
    pub async fn write_property<T>(
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
        let request = match priority {
            Some(priority) => WritePropertyRequest::with_priority(
                object,
                property.into(),
                encoded_value,
                priority,
            ),
            None => WritePropertyRequest::new(object, property.into(), encoded_value),
        };
        let mut service_data = Vec::new();
        request.encode(&mut service_data)?;
        self.send_confirmed_request(&target, ConfirmedServiceChoice::WriteProperty, service_data)
            .await?;
        Ok(())
    }

    /// Read the complete Device Object_List.
    pub async fn read_object_list<T>(
        &self,
        target: T,
        device_id: u32,
    ) -> Result<Vec<ObjectIdentifier>, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        self.read_property(
            target,
            ObjectIdentifier::new(ObjectType::Device, device_id),
            PropertyIdentifier::ObjectList,
        )
        .await?
        .into_iter()
        .map(decode_object_list_value)
        .collect()
    }

    /// Read every property exposed by an object with one RPM `ALL` request.
    ///
    /// The returned snapshot retains per-property BACnet errors. No fallback
    /// request is issued when RPM fails or the response is too large.
    pub async fn read_object_properties<T>(
        &self,
        target: T,
        object: ObjectIdentifier,
    ) -> Result<ObjectSnapshot, ClientError>
    where
        T: Into<BacnetTarget>,
    {
        let target = target.into();
        let properties = self.read_all_properties_rpm(&target, object).await?;
        Ok(ObjectSnapshot {
            object_identifier: object,
            properties,
        })
    }

    async fn read_all_properties_rpm(
        &self,
        target: &BacnetTarget,
        object: ObjectIdentifier,
    ) -> Result<Vec<PropertyReadResult>, ClientError> {
        let request = ReadPropertyMultipleRequest::new(vec![ReadAccessSpecification::new(
            object,
            vec![PropertyReference::new(PropertyIdentifier::All)],
        )]);
        let response = self.read_property_multiple(target, &request).await?;
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
}

enum EndpointCommand {
    Confirmed {
        target: BacnetTarget,
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
    },
    DiscoverDevices {
        frame: Vec<u8>,
        destination: SocketAddr,
        sink: mpsc::UnboundedSender<Result<DeviceInfo, ClientError>>,
    },
    DiscoverRouters {
        frame: Vec<u8>,
        destination: SocketAddr,
        sink: mpsc::UnboundedSender<Result<DiscoveredRouter, ClientError>>,
    },
}

/// One in-progress discovery: responses are forwarded to `sink` until
/// `deadline`, when dropping the sender closes the caller's channel.
struct ActiveDiscovery<T> {
    sink: mpsc::UnboundedSender<Result<T, ClientError>>,
    deadline: Instant,
}

struct PendingTransaction {
    peer: SocketAddr,
    service_choice: ConfirmedServiceChoice,
    frame: Arc<[u8]>,
    retries_remaining: u8,
    deadline: Instant,
    response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
}

struct Endpoint {
    socket: UdpSocket,
    commands: mpsc::Receiver<EndpointCommand>,
    pending: HashMap<u8, PendingTransaction>,
    device_discoveries: Vec<ActiveDiscovery<DeviceInfo>>,
    router_discoveries: Vec<ActiveDiscovery<DiscoveredRouter>>,
    next_invoke_id: u8,
    timeout: Duration,
    retries: u8,
    receive_buffer: Vec<u8>,
}

impl Endpoint {
    fn new(
        socket: UdpSocket,
        commands: mpsc::Receiver<EndpointCommand>,
        timeout: Duration,
        retries: u8,
    ) -> Self {
        Self {
            socket,
            commands,
            pending: HashMap::new(),
            device_discoveries: Vec::new(),
            router_discoveries: Vec::new(),
            next_invoke_id: 0,
            timeout,
            retries,
            receive_buffer: vec![0; MAX_BACNET_IP_FRAME],
        }
    }

    async fn run(mut self) {
        loop {
            self.remove_cancelled();
            let next_deadline = self
                .pending
                .values()
                .map(|pending| pending.deadline)
                .chain(self.device_discoveries.iter().map(|d| d.deadline))
                .chain(self.router_discoveries.iter().map(|d| d.deadline))
                .min();
            let timeout_at = next_deadline.unwrap_or_else(|| {
                Instant::now()
                    .checked_add(Duration::from_secs(86_400))
                    .unwrap_or_else(Instant::now)
            });

            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(command) => self.handle_command(command).await,
                    None => break,
                },
                received = self.socket.recv_from(&mut self.receive_buffer) => {
                    match received {
                        Ok((length, source)) => self.handle_packet(length, source),
                        Err(error) => {
                            self.fail_all(|| ClientError::Io(std::io::Error::new(error.kind(), error.to_string())));
                            break;
                        }
                    }
                }
                _ = sleep_until(timeout_at), if next_deadline.is_some() => {
                    self.handle_timeouts().await;
                }
            }
        }
        self.fail_all(|| ClientError::EndpointClosed);
    }

    async fn handle_command(&mut self, command: EndpointCommand) {
        match command {
            EndpointCommand::Confirmed {
                target,
                service_choice,
                service_data,
                response,
            } => {
                self.handle_confirmed_command(target, service_choice, service_data, response)
                    .await;
            }
            EndpointCommand::DiscoverDevices {
                frame,
                destination,
                sink,
            } => {
                if let Some(discovery) = self.start_discovery(&frame, destination, sink).await {
                    self.device_discoveries.push(discovery);
                }
            }
            EndpointCommand::DiscoverRouters {
                frame,
                destination,
                sink,
            } => {
                if let Some(discovery) = self.start_discovery(&frame, destination, sink).await {
                    self.router_discoveries.push(discovery);
                }
            }
        }
    }

    /// Send a discovery frame and open its response window. A failed send is
    /// reported through the sink instead, and no window is opened.
    async fn start_discovery<T>(
        &mut self,
        frame: &[u8],
        destination: SocketAddr,
        sink: mpsc::UnboundedSender<Result<T, ClientError>>,
    ) -> Option<ActiveDiscovery<T>> {
        if sink.is_closed() {
            return None;
        }
        if let Err(error) = self.socket.send_to(frame, destination).await {
            let _ = sink.send(Err(ClientError::Io(error)));
            return None;
        }
        Some(ActiveDiscovery {
            sink,
            deadline: Instant::now() + self.timeout,
        })
    }

    async fn handle_confirmed_command(
        &mut self,
        target: BacnetTarget,
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, ClientError>>,
    ) {
        if response.is_closed() {
            return;
        }
        // A cancelled request may have released an invoke ID while the endpoint
        // was asleep in select. Reclaim those slots before admitting new work.
        self.remove_cancelled();
        let Some(invoke_id) = self.reserve_invoke_id() else {
            let _ = response.send(Err(ClientError::TooManyTransactions));
            return;
        };
        let frame: Arc<[u8]> =
            build_confirmed_frame(&target, invoke_id, service_choice, service_data).into();
        self.pending.insert(
            invoke_id,
            PendingTransaction {
                peer: target.address,
                service_choice,
                frame: Arc::clone(&frame),
                retries_remaining: self.retries,
                deadline: Instant::now() + self.timeout,
                response,
            },
        );
        if let Err(error) = self.socket.send_to(&frame, target.address).await {
            if let Some(pending) = self.pending.remove(&invoke_id) {
                let _ = pending.response.send(Err(ClientError::Io(error)));
            }
        }
    }

    fn reserve_invoke_id(&mut self) -> Option<u8> {
        for _ in 0..=u8::MAX {
            let invoke_id = self.next_invoke_id;
            self.next_invoke_id = self.next_invoke_id.wrapping_add(1);
            if !self.pending.contains_key(&invoke_id) {
                return Some(invoke_id);
            }
        }
        None
    }

    fn handle_packet(&mut self, length: usize, source: SocketAddr) {
        let apdu = {
            let data = &self.receive_buffer[..length];
            let Some(frame) = decode_bacnet_ip_frame(data, source) else {
                return;
            };

            if frame.npdu.is_network_message() {
                if !self.router_discoveries.is_empty() {
                    if let Some(router) = parse_i_am_router_response(data, source) {
                        for discovery in &self.router_discoveries {
                            let _ = discovery.sink.send(Ok(router.clone()));
                        }
                    }
                }
                return;
            }

            // Unconfirmed-Request PDU: only I-Am matters, for device discovery.
            if frame.payload.first() == Some(&0x10) {
                if !self.device_discoveries.is_empty() {
                    if let Some(device) = parse_iam_response(data, source) {
                        for discovery in &self.device_discoveries {
                            let _ = discovery.sink.send(Ok(device.clone()));
                        }
                    }
                }
                return;
            }

            let Ok(apdu) = Apdu::decode(frame.payload) else {
                return;
            };
            apdu
        };
        let invoke_id = match &apdu {
            Apdu::ComplexAck { invoke_id, .. }
            | Apdu::SimpleAck { invoke_id, .. }
            | Apdu::Error { invoke_id, .. }
            | Apdu::Reject { invoke_id, .. }
            | Apdu::Abort { invoke_id, .. } => *invoke_id,
            _ => return,
        };
        let Some(pending) = self.pending.get(&invoke_id) else {
            return;
        };
        if pending.peer != source || !response_matches_service(&apdu, pending.service_choice) {
            return;
        }
        let result = response_result(apdu);
        if let Some(pending) = self.pending.remove(&invoke_id) {
            let _ = pending.response.send(result);
        }
    }

    async fn handle_timeouts(&mut self) {
        let now = Instant::now();
        // An expired discovery window simply closes its sink, which ends the
        // caller's collection loop.
        self.device_discoveries.retain(|d| d.deadline > now);
        self.router_discoveries.retain(|d| d.deadline > now);
        let expired = self
            .pending
            .iter()
            .filter_map(|(invoke_id, pending)| (pending.deadline <= now).then_some(*invoke_id))
            .collect::<Vec<_>>();
        for invoke_id in expired {
            let Some(pending) = self.pending.get_mut(&invoke_id) else {
                continue;
            };
            if pending.response.is_closed() {
                self.pending.remove(&invoke_id);
                continue;
            }
            if pending.retries_remaining == 0 {
                if let Some(pending) = self.pending.remove(&invoke_id) {
                    let _ = pending.response.send(Err(ClientError::Timeout));
                }
                continue;
            }
            pending.retries_remaining -= 1;
            pending.deadline = Instant::now() + self.timeout;
            let frame = Arc::clone(&pending.frame);
            let peer = pending.peer;
            if let Err(error) = self.socket.send_to(&frame, peer).await {
                if let Some(pending) = self.pending.remove(&invoke_id) {
                    let _ = pending.response.send(Err(ClientError::Io(error)));
                }
            }
        }
    }

    fn remove_cancelled(&mut self) {
        self.pending
            .retain(|_, pending| !pending.response.is_closed());
        self.device_discoveries
            .retain(|discovery| !discovery.sink.is_closed());
        self.router_discoveries
            .retain(|discovery| !discovery.sink.is_closed());
    }

    fn fail_all<F>(&mut self, mut error: F)
    where
        F: FnMut() -> ClientError,
    {
        for (_, pending) in self.pending.drain() {
            let _ = pending.response.send(Err(error()));
        }
        for discovery in self.device_discoveries.drain(..) {
            let _ = discovery.sink.send(Err(error()));
        }
        for discovery in self.router_discoveries.drain(..) {
            let _ = discovery.sink.send(Err(error()));
        }
    }
}

fn encode_who_is(low_limit: Option<u32>, high_limit: Option<u32>) -> Result<Vec<u8>, ClientError> {
    let whois = match (low_limit, high_limit) {
        (Some(low), Some(high)) => WhoIsRequest::for_range(low, high),
        _ => WhoIsRequest::new(),
    };
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;
    Ok(buffer)
}

fn build_confirmed_frame(
    target: &BacnetTarget,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: Vec<u8>,
) -> Vec<u8> {
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
        service_data,
    };
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    if let Some(route) = &target.route {
        npdu.set_destination(route.clone());
        npdu.hop_count = Some(255);
    }
    let mut payload = npdu.encode();
    payload.extend_from_slice(&apdu.encode());
    let total_length = payload.len() + 4;
    let mut frame = Vec::with_capacity(total_length);
    frame.extend_from_slice(&[
        0x81,
        BVLC_ORIGINAL_UNICAST,
        (total_length >> 8) as u8,
        total_length as u8,
    ]);
    frame.extend_from_slice(&payload);
    frame
}

fn response_matches_service(apdu: &Apdu, expected: ConfirmedServiceChoice) -> bool {
    match apdu {
        Apdu::ComplexAck { service_choice, .. } | Apdu::Error { service_choice, .. } => {
            *service_choice == expected
        }
        Apdu::SimpleAck { service_choice, .. } => *service_choice == expected as u8,
        Apdu::Reject { .. } | Apdu::Abort { .. } => true,
        _ => false,
    }
}

fn response_result(apdu: Apdu) -> Result<Vec<u8>, ClientError> {
    match apdu {
        Apdu::ComplexAck { service_data, .. } => Ok(service_data),
        Apdu::SimpleAck { .. } => Ok(Vec::new()),
        Apdu::Error {
            error_class,
            error_code,
            ..
        } => Err(ClientError::PropertyError {
            class: error_class,
            code: error_code,
        }),
        Apdu::Reject { reject_reason, .. } => Err(ClientError::Rejected(reject_reason)),
        Apdu::Abort { abort_reason, .. } => {
            Err(ClientError::Abort(AbortReason::from(abort_reason)))
        }
        _ => Err(ClientError::NoResponse),
    }
}
