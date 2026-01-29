//! BACnet Network Layer Module
//!
//! This module implements the network layer functionality for BACnet according to ASHRAE 135.
//! The network layer provides routing capabilities and enables communication between different
//! BACnet networks.
//!
//! # Overview
//!
//! The network layer is responsible for:
//! - Routing messages between different BACnet networks
//! - Network address translation
//! - Broadcast management
//! - Router discovery and management
//! - Network layer protocol messages (Who-Is-Router-To-Network, I-Am-Router-To-Network, etc.)
//!
//! # Network Layer Protocol Data Unit (NPDU)
//!
//! The NPDU contains:
//! - Protocol version
//! - Control information (priority, data expecting reply, etc.)
//! - Destination network address (DNET, DADR)
//! - Source network address (SNET, SADR)
//! - Hop count for routing
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::network::*;
//!
//! // Example of creating a network message
//! let npdu = Npdu {
//!     version: 1,
//!     control: NpduControl::default(),
//!     destination: None,
//!     source: None,
//!     hop_count: None,
//! };
//! ```

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

#[cfg(feature = "std")]
use std::collections::{BTreeMap, BTreeSet};

/// Result type for network operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, NetworkError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, NetworkError>;

/// Errors that can occur in network operations
#[derive(Debug)]
pub enum NetworkError {
    /// Invalid NPDU format
    InvalidNpdu(String),
    /// Routing error
    RoutingError(String),
    /// Network unreachable
    NetworkUnreachable(u16),
    /// Hop count exceeded
    HopCountExceeded,
    /// Invalid network address
    InvalidAddress,
    /// Unsupported network message type
    UnsupportedNetworkMessageType(u8),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::InvalidNpdu(msg) => write!(f, "Invalid NPDU: {}", msg),
            NetworkError::RoutingError(msg) => write!(f, "Routing error: {}", msg),
            NetworkError::NetworkUnreachable(net) => write!(f, "Network {} unreachable", net),
            NetworkError::HopCountExceeded => write!(f, "Hop count exceeded"),
            NetworkError::InvalidAddress => write!(f, "Invalid network address"),
            NetworkError::UnsupportedNetworkMessageType(msg) => {
                write!(f, "Unsupported network message type: {}", msg)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for NetworkError {}

/// Network layer message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkMessageType {
    WhoIsRouterToNetwork = 0x00,
    IAmRouterToNetwork = 0x01,
    ICouldBeRouterToNetwork = 0x02,
    RejectMessageToNetwork = 0x03,
    RouterBusyToNetwork = 0x04,
    RouterAvailableToNetwork = 0x05,
    InitializeRoutingTable = 0x06,
    InitializeRoutingTableAck = 0x07,
    EstablishConnectionToNetwork = 0x08,
    DisconnectConnectionToNetwork = 0x09,
    WhatIsNetworkNumber = 0x12,
    NetworkNumberIs = 0x13,
}

impl TryFrom<u8> for NetworkMessageType {
    type Error = NetworkError;

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::WhoIsRouterToNetwork),
            0x01 => Ok(Self::IAmRouterToNetwork),
            0x02 => Ok(Self::ICouldBeRouterToNetwork),
            0x03 => Ok(Self::RejectMessageToNetwork),
            0x04 => Ok(Self::RouterBusyToNetwork),
            0x05 => Ok(Self::RouterAvailableToNetwork),
            0x06 => Ok(Self::InitializeRoutingTable),
            0x07 => Ok(Self::InitializeRoutingTableAck),
            0x08 => Ok(Self::EstablishConnectionToNetwork),
            0x09 => Ok(Self::DisconnectConnectionToNetwork),
            0x12 => Ok(Self::WhatIsNetworkNumber),
            0x13 => Ok(Self::NetworkNumberIs),
            _ => Err(NetworkError::UnsupportedNetworkMessageType(value)),
        }
    }
}

/// NPDU control flags
#[derive(Debug, Clone, Copy, Default)]
pub struct NpduControl {
    /// Network layer message
    pub network_message: bool,
    /// Destination specifier present
    pub destination_present: bool,
    /// Source specifier present
    pub source_present: bool,
    /// Data expecting reply
    pub expecting_reply: bool,
    /// Network priority (0-3)
    pub priority: u8,
}

impl NpduControl {
    /// Create control byte from flags
    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.network_message {
            byte |= 0x80;
        }
        if self.destination_present {
            byte |= 0x20;
        }
        if self.source_present {
            byte |= 0x08;
        }
        if self.expecting_reply {
            byte |= 0x04;
        }
        byte |= self.priority & 0x03;
        byte
    }

    /// Parse control byte into flags
    pub fn from_byte(byte: u8) -> Self {
        Self {
            network_message: (byte & 0x80) != 0,
            destination_present: (byte & 0x20) != 0,
            source_present: (byte & 0x08) != 0,
            expecting_reply: (byte & 0x04) != 0,
            priority: byte & 0x03,
        }
    }
}

/// Network address (network number + MAC address)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkAddress {
    /// Network number (0 = local network, 65535 = broadcast)
    pub network: u16,
    /// MAC address on that network
    pub address: Vec<u8>,
}

impl NetworkAddress {
    /// Create a new network address
    pub fn new(network: u16, address: Vec<u8>) -> Self {
        Self { network, address }
    }

    /// Check if this is a broadcast address
    pub fn is_broadcast(&self) -> bool {
        self.network == 0xFFFF
    }

    /// Check if this is a local network address
    pub fn is_local(&self) -> bool {
        self.network == 0
    }
}

/// Network Protocol Data Unit (NPDU)
#[derive(Debug, Clone)]
pub struct Npdu {
    /// Protocol version (always 1)
    pub version: u8,
    /// Control information
    pub control: NpduControl,
    /// Destination network address
    pub destination: Option<NetworkAddress>,
    /// Source network address
    pub source: Option<NetworkAddress>,
    /// Hop count (only present if destination is present)
    pub hop_count: Option<u8>,
}

impl Npdu {
    /// Create a new NPDU with default values
    pub fn new() -> Self {
        Self {
            version: 1,
            control: NpduControl::default(),
            destination: None,
            source: None,
            hop_count: None,
        }
    }

    /// Create NPDU for global broadcast (matching YABE/bacnet-stack)
    pub fn global_broadcast() -> Self {
        Self {
            version: 1,
            control: NpduControl {
                network_message: false,
                destination_present: true,
                source_present: false,
                expecting_reply: false, // YABE uses 0x20 (no expecting_reply bit)
                priority: 0,
            },
            destination: Some(NetworkAddress {
                network: 0xFFFF,
                address: vec![],
            }),
            source: None,
            hop_count: Some(255),
        }
    }

    /// Check if this is a network layer message
    pub fn is_network_message(&self) -> bool {
        self.control.network_message
    }

    /// Set source address
    pub fn set_source(&mut self, source: NetworkAddress) {
        self.source = Some(source);
        self.control.source_present = true;
    }

    /// Set destination address
    pub fn set_destination(&mut self, destination: NetworkAddress) {
        self.destination = Some(destination);
        self.control.destination_present = true;
    }
}

/// Router information
#[derive(Debug, Clone)]
pub struct RouterInfo {
    /// Networks this router can reach
    pub networks: Vec<u16>,
    /// Router's address
    pub address: NetworkAddress,
    /// Performance index (lower is better)
    pub performance_index: Option<u8>,
}

impl Npdu {
    /// Encode NPDU to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Version
        buffer.push(self.version);

        // Control byte
        buffer.push(self.control.to_byte());

        // Destination network address
        if let Some(ref dest) = self.destination {
            buffer.extend_from_slice(&dest.network.to_be_bytes());
            buffer.push(dest.address.len() as u8);
            buffer.extend_from_slice(&dest.address);
        }

        // Source network address
        if let Some(ref src) = self.source {
            buffer.extend_from_slice(&src.network.to_be_bytes());
            buffer.push(src.address.len() as u8);
            buffer.extend_from_slice(&src.address);
        }

        // Hop count (only if destination is present)
        if self.destination.is_some() {
            buffer.push(self.hop_count.unwrap_or(255));
        }

        buffer
    }

    /// Decode NPDU from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 2 {
            return Err(NetworkError::InvalidNpdu("NPDU too short".to_string()));
        }

        let mut pos = 0;

        // Version
        let version = data[pos];
        pos += 1;

        if version != 1 {
            return Err(NetworkError::InvalidNpdu(format!(
                "Invalid NPDU version: {}",
                version
            )));
        }

        // Control byte
        let control = NpduControl::from_byte(data[pos]);
        pos += 1;

        // Destination network address
        let destination = if control.destination_present {
            if pos + 3 > data.len() {
                return Err(NetworkError::InvalidNpdu(
                    "Invalid destination address".to_string(),
                ));
            }

            let network = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;

            let addr_len = data[pos] as usize;
            pos += 1;

            if pos + addr_len > data.len() {
                return Err(NetworkError::InvalidNpdu(
                    "Invalid destination address length".to_string(),
                ));
            }

            let address = data[pos..pos + addr_len].to_vec();
            pos += addr_len;

            Some(NetworkAddress::new(network, address))
        } else {
            None
        };

        // Source network address
        let source = if control.source_present {
            if pos + 3 > data.len() {
                return Err(NetworkError::InvalidNpdu(
                    "Invalid source address".to_string(),
                ));
            }

            let network = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;

            let addr_len = data[pos] as usize;
            pos += 1;

            if pos + addr_len > data.len() {
                return Err(NetworkError::InvalidNpdu(
                    "Invalid source address length".to_string(),
                ));
            }

            let address = data[pos..pos + addr_len].to_vec();
            pos += addr_len;

            Some(NetworkAddress::new(network, address))
        } else {
            None
        };

        // Hop count (only if destination is present)
        let hop_count = if destination.is_some() {
            if pos >= data.len() {
                return Err(NetworkError::InvalidNpdu("Missing hop count".to_string()));
            }
            let hc = data[pos];
            pos += 1;
            Some(hc)
        } else {
            None
        };

        let npdu = Npdu {
            version,
            control,
            destination,
            source,
            hop_count,
        };

        Ok((npdu, pos))
    }
}

impl Default for Npdu {
    fn default() -> Self {
        Self::new()
    }
}

/// Network layer message handling
pub struct NetworkLayerMessage {
    /// Message type
    pub message_type: NetworkMessageType,
    /// Message data
    pub data: Option<Vec<u8>>,
}

impl NetworkLayerMessage {
    /// Create a new network layer message
    pub fn new(message_type: NetworkMessageType, data: Option<Vec<u8>>) -> Self {
        Self { message_type, data }
    }

    /// Encode network layer message
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![self.message_type as u8];

        if let Some(data) = &self.data {
            buffer.extend_from_slice(data);
        }

        buffer
    }

    /// Decode network layer message
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(NetworkError::InvalidNpdu(
                "Empty network message".to_string(),
            ));
        }

        let message_type = data[0].try_into()?;

        let message_data = if data.len() > 1 {
            Some(data[1..].to_vec())
        } else {
            None
        };

        Ok(NetworkLayerMessage::new(message_type, message_data))
    }

    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }
}

/// Basic routing table implementation
#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// Router entries
    pub entries: Vec<RouterInfo>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a router entry
    pub fn add_router(&mut self, router: RouterInfo) {
        // Remove existing entry for the same address
        self.entries.retain(|r| r.address != router.address);
        self.entries.push(router);
    }

    /// Find route to network
    pub fn find_route(&self, network: u16) -> Option<&RouterInfo> {
        self.entries.iter().find(|r| r.networks.contains(&network))
    }

    /// Remove router by address
    pub fn remove_router(&mut self, address: &NetworkAddress) {
        self.entries.retain(|r| &r.address != address);
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Network layer router manager for handling routing operations
#[derive(Debug)]
pub struct RouterManager {
    /// Local network number
    pub local_network: u16,
    /// Routing table
    pub routing_table: RoutingTable,
    /// Maximum hop count allowed
    pub max_hop_count: u8,
    /// Router busy status per network
    pub busy_networks: Vec<u16>,
    /// Performance metrics
    pub performance_metrics: RouterPerformanceMetrics,
}

/// Router performance metrics
#[derive(Debug, Clone, Default)]
pub struct RouterPerformanceMetrics {
    /// Total messages routed
    pub messages_routed: u64,
    /// Total routing errors
    pub routing_errors: u64,
    /// Messages dropped due to hop count
    pub hop_count_exceeded: u64,
    /// Network unreachable count
    pub network_unreachable_count: u64,
}

impl RouterManager {
    /// Create a new router manager
    pub fn new(local_network: u16) -> Self {
        Self {
            local_network,
            routing_table: RoutingTable::new(),
            max_hop_count: 255,
            busy_networks: Vec::new(),
            performance_metrics: RouterPerformanceMetrics::default(),
        }
    }

    /// Process a routing request
    pub fn route_message(&mut self, npdu: &mut Npdu) -> Result<Option<NetworkAddress>> {
        // Check if this is a local message
        if let Some(ref dest) = npdu.destination {
            if dest.network == self.local_network || dest.network == 0 {
                return Ok(None); // Local delivery
            }

            // Check hop count
            if let Some(hops) = npdu.hop_count {
                if hops == 0 {
                    self.performance_metrics.hop_count_exceeded += 1;
                    return Err(NetworkError::HopCountExceeded);
                }
                npdu.hop_count = Some(hops - 1);
            }

            // Check if network is busy
            if self.busy_networks.contains(&dest.network) {
                return Err(NetworkError::RoutingError("Network busy".to_string()));
            }

            // Find route
            if let Some(router) = self.routing_table.find_route(dest.network) {
                self.performance_metrics.messages_routed += 1;
                Ok(Some(router.address.clone()))
            } else {
                self.performance_metrics.network_unreachable_count += 1;
                Err(NetworkError::NetworkUnreachable(dest.network))
            }
        } else {
            Ok(None) // No destination specified
        }
    }

    /// Process network layer messages
    pub fn process_network_message(
        &mut self,
        message: &NetworkLayerMessage,
    ) -> Result<Option<NetworkLayerMessage>> {
        match message.message_type {
            NetworkMessageType::WhoIsRouterToNetwork => {
                self.handle_who_is_router_to_network(message.data())
            }
            NetworkMessageType::IAmRouterToNetwork => {
                self.handle_i_am_router_to_network(message.data())
            }
            NetworkMessageType::RouterBusyToNetwork => {
                self.handle_router_busy_to_network(message.data())
            }
            NetworkMessageType::RouterAvailableToNetwork => {
                self.handle_router_available_to_network(message.data())
            }
            NetworkMessageType::WhatIsNetworkNumber => self.handle_what_is_network_number(),
            _ => Ok(None), // Other messages not handled here
        }
    }

    /// Handle Who-Is-Router-To-Network message
    fn handle_who_is_router_to_network(
        &self,
        data: Option<&[u8]>,
    ) -> Result<Option<NetworkLayerMessage>> {
        // If we know routes to the requested networks, respond with I-Am-Router-To-Network
        if let Some(data) = data {
            if data.len() >= 2 {
                let requested_network = u16::from_be_bytes([data[0], data[1]]);
                if self.routing_table.find_route(requested_network).is_some() {
                    let response_data = vec![data[0], data[1]]; // Echo the network number
                    return Ok(Some(NetworkLayerMessage::new(
                        NetworkMessageType::IAmRouterToNetwork,
                        Some(response_data),
                    )));
                }
            }
        }
        Ok(None)
    }

    /// Handle I-Am-Router-To-Network message
    fn handle_i_am_router_to_network(
        &mut self,
        data: Option<&[u8]>,
    ) -> Result<Option<NetworkLayerMessage>> {
        // Parse networks this router can reach
        let mut pos = 0;
        let mut networks = Vec::new();

        if let Some(data) = data {
            while pos + 1 < data.len() {
                let network = u16::from_be_bytes([data[pos], data[pos + 1]]);
                networks.push(network);
                pos += 2;
            }
        }

        // Add router to routing table (would need router address from NPDU source)
        // This is a simplified implementation

        Ok(None)
    }

    /// Handle Router-Busy-To-Network message
    fn handle_router_busy_to_network(
        &mut self,
        data: Option<&[u8]>,
    ) -> Result<Option<NetworkLayerMessage>> {
        if let Some(data) = data {
            if data.len() >= 2 {
                let network = u16::from_be_bytes([data[0], data[1]]);
                if !self.busy_networks.contains(&network) {
                    self.busy_networks.push(network);
                }
            }
        }
        Ok(None)
    }

    /// Handle Router-Available-To-Network message
    fn handle_router_available_to_network(
        &mut self,
        data: Option<&[u8]>,
    ) -> Result<Option<NetworkLayerMessage>> {
        if let Some(data) = data {
            if data.len() >= 2 {
                let network = u16::from_be_bytes([data[0], data[1]]);
                self.busy_networks.retain(|&n| n != network);
            }
        }
        Ok(None)
    }

    /// Handle What-Is-Network-Number message
    fn handle_what_is_network_number(&self) -> Result<Option<NetworkLayerMessage>> {
        let response_data = self.local_network.to_be_bytes().to_vec();
        Ok(Some(NetworkLayerMessage::new(
            NetworkMessageType::NetworkNumberIs,
            Some(response_data),
        )))
    }

    /// Add a discovered router
    pub fn add_discovered_router(
        &mut self,
        networks: Vec<u16>,
        address: NetworkAddress,
        performance_index: Option<u8>,
    ) {
        let router = RouterInfo {
            networks,
            address,
            performance_index,
        };
        self.routing_table.add_router(router);
    }

    /// Set network busy status
    pub fn set_network_busy(&mut self, network: u16, busy: bool) {
        if busy {
            if !self.busy_networks.contains(&network) {
                self.busy_networks.push(network);
            }
        } else {
            self.busy_networks.retain(|&n| n != network);
        }
    }

    /// Get router statistics
    pub fn get_performance_metrics(&self) -> &RouterPerformanceMetrics {
        &self.performance_metrics
    }

    /// Reset performance metrics
    pub fn reset_performance_metrics(&mut self) {
        self.performance_metrics = RouterPerformanceMetrics::default();
    }
}

/// Network path discovery for finding optimal routes
#[derive(Debug)]
pub struct PathDiscovery {
    /// Known network topology
    pub network_topology: Vec<NetworkLink>,
    /// Path cache for faster lookups
    pub path_cache: Vec<(u16, Vec<u16>)>, // (destination_network, path)
}

/// Network link information
#[derive(Debug, Clone)]
pub struct NetworkLink {
    /// Source network
    pub source_network: u16,
    /// Destination network
    pub destination_network: u16,
    /// Cost metric (lower is better)
    pub cost: u16,
    /// Router address
    pub router_address: NetworkAddress,
}

impl PathDiscovery {
    /// Create a new path discovery instance
    pub fn new() -> Self {
        Self {
            network_topology: Vec::new(),
            path_cache: Vec::new(),
        }
    }

    /// Add a network link
    pub fn add_link(&mut self, link: NetworkLink) {
        // Remove existing link between same networks
        self.network_topology.retain(|l| {
            !(l.source_network == link.source_network
                && l.destination_network == link.destination_network)
        });
        self.network_topology.push(link);
        // Clear cache as topology changed
        self.path_cache.clear();
    }

    /// Find optimal path to destination network using Dijkstra's algorithm
    pub fn find_path(&mut self, source: u16, destination: u16) -> Option<Vec<u16>> {
        // Check cache first
        if let Some((_, path)) = self
            .path_cache
            .iter()
            .find(|(dest, _)| *dest == destination)
        {
            return Some(path.clone());
        }

        // Simple implementation of shortest path finding
        let path = self.dijkstra_shortest_path(source, destination);

        // Cache the result
        if let Some(ref p) = path {
            self.path_cache.push((destination, p.clone()));
        }

        path
    }

    /// Dijkstra's shortest path algorithm (simplified)
    fn dijkstra_shortest_path(&self, source: u16, destination: u16) -> Option<Vec<u16>> {
        if source == destination {
            return Some(vec![source]);
        }

        let mut distances: BTreeMap<u16, u16> = BTreeMap::new();
        let mut previous: BTreeMap<u16, u16> = BTreeMap::new();
        let mut unvisited: BTreeSet<u16> = BTreeSet::new();

        // Initialize distances
        for link in &self.network_topology {
            distances.insert(link.source_network, u16::MAX);
            distances.insert(link.destination_network, u16::MAX);
            unvisited.insert(link.source_network);
            unvisited.insert(link.destination_network);
        }

        distances.insert(source, 0);

        while !unvisited.is_empty() {
            // Find unvisited node with minimum distance
            let current = *unvisited
                .iter()
                .min_by_key(|&&node| distances.get(&node).unwrap_or(&u16::MAX))
                .unwrap();

            if *distances.get(&current).unwrap_or(&u16::MAX) == u16::MAX {
                break; // No more reachable nodes
            }

            unvisited.remove(&current);

            if current == destination {
                // Reconstruct path
                let mut path = Vec::new();
                let mut current_node = destination;
                while let Some(&prev) = previous.get(&current_node) {
                    path.push(current_node);
                    current_node = prev;
                }
                path.push(source);
                path.reverse();
                return Some(path);
            }

            // Update distances to neighbors
            for link in &self.network_topology {
                if link.source_network == current {
                    let neighbor = link.destination_network;
                    if unvisited.contains(&neighbor) {
                        let new_distance = distances[&current].saturating_add(link.cost);
                        if new_distance < *distances.get(&neighbor).unwrap_or(&u16::MAX) {
                            distances.insert(neighbor, new_distance);
                            previous.insert(neighbor, current);
                        }
                    }
                }
            }
        }

        None // No path found
    }

    /// Clear the path cache
    pub fn clear_cache(&mut self) {
        self.path_cache.clear();
    }

    /// Get network topology
    pub fn get_topology(&self) -> &[NetworkLink] {
        &self.network_topology
    }
}

impl Default for PathDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Network diagnostics for monitoring network health
#[derive(Debug, Default)]
pub struct NetworkDiagnostics {
    /// Network reachability status
    pub network_status: Vec<(u16, NetworkStatus)>,
    /// Router health information
    pub router_health: Vec<(NetworkAddress, RouterHealth)>,
    /// Network latency measurements
    pub latency_measurements: Vec<(u16, u32)>, // (network, latency_ms)
}

/// Network status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkStatus {
    Reachable,
    Unreachable,
    Degraded,
    Unknown,
}

/// Router health information
#[derive(Debug, Clone)]
pub struct RouterHealth {
    /// Router is responding
    pub responsive: bool,
    /// Last response time
    #[cfg(feature = "std")]
    pub last_response: Option<std::time::Instant>,
    /// Error count
    pub error_count: u32,
    /// Performance index
    pub performance_index: u8,
}

impl NetworkDiagnostics {
    /// Create new network diagnostics
    pub fn new() -> Self {
        Self::default()
    }

    /// Update network status
    pub fn update_network_status(&mut self, network: u16, status: NetworkStatus) {
        if let Some((_, existing_status)) = self
            .network_status
            .iter_mut()
            .find(|(net, _)| *net == network)
        {
            *existing_status = status;
        } else {
            self.network_status.push((network, status));
        }
    }

    /// Update router health
    pub fn update_router_health(&mut self, address: NetworkAddress, health: RouterHealth) {
        if let Some((_, existing_health)) = self
            .router_health
            .iter_mut()
            .find(|(addr, _)| *addr == address)
        {
            *existing_health = health;
        } else {
            self.router_health.push((address, health));
        }
    }

    /// Record latency measurement
    pub fn record_latency(&mut self, network: u16, latency_ms: u32) {
        if let Some((_, existing_latency)) = self
            .latency_measurements
            .iter_mut()
            .find(|(net, _)| *net == network)
        {
            *existing_latency = latency_ms;
        } else {
            self.latency_measurements.push((network, latency_ms));
        }
    }

    /// Get network status
    pub fn get_network_status(&self, network: u16) -> NetworkStatus {
        self.network_status
            .iter()
            .find(|(net, _)| *net == network)
            .map(|(_, status)| *status)
            .unwrap_or(NetworkStatus::Unknown)
    }

    /// Get router health
    pub fn get_router_health(&self, address: &NetworkAddress) -> Option<&RouterHealth> {
        self.router_health
            .iter()
            .find(|(addr, _)| addr == address)
            .map(|(_, health)| health)
    }

    /// Get average latency for a network
    pub fn get_average_latency(&self, network: u16) -> Option<u32> {
        self.latency_measurements
            .iter()
            .find(|(net, _)| *net == network)
            .map(|(_, latency)| *latency)
    }

    /// Get unhealthy networks
    pub fn get_unhealthy_networks(&self) -> Vec<u16> {
        self.network_status
            .iter()
            .filter(|(_, status)| {
                matches!(status, NetworkStatus::Unreachable | NetworkStatus::Degraded)
            })
            .map(|(network, _)| *network)
            .collect()
    }

    /// Get network health summary
    pub fn get_health_summary(&self) -> NetworkHealthSummary {
        let total_networks = self.network_status.len();
        let reachable_count = self
            .network_status
            .iter()
            .filter(|(_, status)| matches!(status, NetworkStatus::Reachable))
            .count();
        let unreachable_count = self
            .network_status
            .iter()
            .filter(|(_, status)| matches!(status, NetworkStatus::Unreachable))
            .count();
        let degraded_count = self
            .network_status
            .iter()
            .filter(|(_, status)| matches!(status, NetworkStatus::Degraded))
            .count();

        NetworkHealthSummary {
            total_networks,
            reachable_count,
            unreachable_count,
            degraded_count,
            average_latency: self.calculate_average_latency(),
        }
    }

    /// Calculate average latency across all networks
    fn calculate_average_latency(&self) -> Option<f32> {
        if self.latency_measurements.is_empty() {
            return None;
        }

        let total: u32 = self
            .latency_measurements
            .iter()
            .map(|(_, latency)| *latency)
            .sum();
        Some(total as f32 / self.latency_measurements.len() as f32)
    }
}

/// Network health summary
#[derive(Debug, Clone)]
pub struct NetworkHealthSummary {
    /// Total number of known networks
    pub total_networks: usize,
    /// Number of reachable networks
    pub reachable_count: usize,
    /// Number of unreachable networks
    pub unreachable_count: usize,
    /// Number of degraded networks
    pub degraded_count: usize,
    /// Average latency across all networks
    pub average_latency: Option<f32>,
}

/// Network layer message handler
#[derive(Debug)]
pub struct NetworkLayerHandler {
    /// Local network number
    pub local_network: u16,
    /// Router information cache
    pub routers: Vec<RouterInfo>,
    /// Network message processors
    _processors: NetworkMessageProcessors,
    /// Network statistics
    pub stats: NetworkStatistics,
}

// Type aliases for complex function pointer types
type WhoIsRouterHandler = fn(&NetworkAddress, Option<u16>) -> Option<NetworkLayerMessage>;
type IAmRouterHandler = fn(&NetworkAddress, &[u16]) -> Option<NetworkLayerMessage>;

/// Network message processors
#[derive(Debug, Default)]
struct NetworkMessageProcessors {
    /// Process Who-Is-Router-To-Network messages
    _who_is_router_handler: Option<WhoIsRouterHandler>,
    /// Process I-Am-Router-To-Network messages
    _i_am_router_handler: Option<IAmRouterHandler>,
}

impl NetworkLayerHandler {
    /// Create a new network layer handler
    pub fn new(local_network: u16) -> Self {
        Self {
            local_network,
            routers: Vec::new(),
            _processors: NetworkMessageProcessors::default(),
            stats: NetworkStatistics::default(),
        }
    }

    /// Process an incoming NPDU
    pub fn process_npdu(
        &mut self,
        npdu: &Npdu,
        source_address: &NetworkAddress,
    ) -> Result<Option<NetworkResponse>> {
        self.stats.record_received();

        if npdu.is_network_message() {
            self.process_network_message(npdu, source_address)
        } else {
            // Regular application layer message
            Ok(Some(NetworkResponse::ApplicationData))
        }
    }

    /// Process a network layer message
    fn process_network_message(
        &mut self,
        _npdu: &Npdu,
        _source_address: &NetworkAddress,
    ) -> Result<Option<NetworkResponse>> {
        // Network messages have their type in the first byte after the NPDU header
        // This would need to be implemented based on the actual message content
        Ok(None)
    }

    /// Send Who-Is-Router-To-Network message
    pub fn who_is_router(&mut self, _network: Option<u16>) -> Npdu {
        self.stats.record_sent();

        let mut npdu = Npdu::new();
        npdu.control.network_message = true;
        npdu.control.priority = 3; // Normal priority

        // Message content would include the network number if specified
        npdu
    }

    /// Send I-Am-Router-To-Network message
    pub fn i_am_router(&mut self, _networks: &[u16]) -> Npdu {
        self.stats.record_sent();

        let mut npdu = Npdu::new();
        npdu.control.network_message = true;
        npdu.control.priority = 3;

        // Message content would include the list of networks
        npdu
    }

    /// Update router information
    pub fn update_router(&mut self, router_info: RouterInfo) {
        // Check if router already exists
        if let Some(existing) = self
            .routers
            .iter_mut()
            .find(|r| r.address == router_info.address)
        {
            existing.networks = router_info.networks;
            existing.performance_index = router_info.performance_index;
        } else {
            self.routers.push(router_info);
        }
    }

    /// Find best router for a network
    pub fn find_router(&self, network: u16) -> Option<&RouterInfo> {
        self.routers
            .iter()
            .filter(|r| r.networks.contains(&network))
            .min_by_key(|r| r.performance_index.unwrap_or(255))
    }
}

/// Network layer response types
#[derive(Debug)]
pub enum NetworkResponse {
    /// Application layer data (pass through)
    ApplicationData,
    /// Network layer message response
    NetworkMessage(Npdu),
    /// Routing table update
    RoutingUpdate(Vec<RouterInfo>),
}

/// Network priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkPriority {
    /// Life Safety messages (highest priority)
    LifeSafety = 3,
    /// Critical Equipment messages
    CriticalEquipment = 2,
    /// Urgent messages
    Urgent = 1,
    /// Normal messages (lowest priority)
    Normal = 0,
}

impl NetworkPriority {
    /// Convert to NPDU priority bits
    pub fn to_bits(self) -> u8 {
        self as u8
    }

    /// Create from NPDU priority bits
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            3 => NetworkPriority::LifeSafety,
            2 => NetworkPriority::CriticalEquipment,
            1 => NetworkPriority::Urgent,
            _ => NetworkPriority::Normal,
        }
    }
}

/// Network layer statistics
#[derive(Debug, Default)]
pub struct NetworkStatistics {
    /// Total NPDUs received
    pub npdus_received: u64,
    /// Total NPDUs sent
    pub npdus_sent: u64,
    /// Routing failures
    pub routing_failures: u64,
    /// Messages forwarded
    pub messages_forwarded: u64,
    /// Network layer errors
    pub network_errors: u64,
    /// Last update time
    #[cfg(feature = "std")]
    pub last_update: Option<std::time::Instant>,
}

impl NetworkStatistics {
    /// Update statistics for received NPDU
    pub fn record_received(&mut self) {
        self.npdus_received += 1;
        #[cfg(feature = "std")]
        {
            self.last_update = Some(std::time::Instant::now());
        }
    }

    /// Update statistics for sent NPDU
    pub fn record_sent(&mut self) {
        self.npdus_sent += 1;
        #[cfg(feature = "std")]
        {
            self.last_update = Some(std::time::Instant::now());
        }
    }

    /// Record a routing failure
    pub fn record_routing_failure(&mut self) {
        self.routing_failures += 1;
        self.network_errors += 1;
    }

    /// Record a forwarded message
    pub fn record_forwarded(&mut self) {
        self.messages_forwarded += 1;
    }
}

/// Broadcast distribution table (BDT) entry
#[derive(Debug, Clone)]
pub struct BdtEntry {
    /// Broadcast distribution mask (network numbers)
    pub networks: Vec<u16>,
    /// Address to send broadcasts
    pub address: NetworkAddress,
    /// Entry is valid
    pub valid: bool,
}

/// Broadcast distribution table manager
#[derive(Debug)]
pub struct BroadcastDistributionTable {
    /// BDT entries
    entries: Vec<BdtEntry>,
    /// Maximum number of entries
    max_entries: usize,
}

impl BroadcastDistributionTable {
    /// Create a new BDT
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Add or update a BDT entry
    pub fn update_entry(&mut self, entry: BdtEntry) -> Result<()> {
        // Check if entry already exists
        if let Some(existing) = self.entries.iter_mut().find(|e| e.address == entry.address) {
            *existing = entry;
        } else if self.entries.len() < self.max_entries {
            self.entries.push(entry);
        } else {
            return Err(NetworkError::InvalidNpdu("BDT full".to_string()));
        }
        Ok(())
    }

    /// Remove a BDT entry
    pub fn remove_entry(&mut self, address: &NetworkAddress) {
        self.entries.retain(|e| e.address != *address);
    }

    /// Get addresses for broadcasting to a network
    pub fn get_broadcast_addresses(&self, network: u16) -> Vec<&NetworkAddress> {
        self.entries
            .iter()
            .filter(|e| e.valid && e.networks.contains(&network))
            .map(|e| &e.address)
            .collect()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Foreign device table (FDT) entry
#[derive(Debug, Clone)]
pub struct FdtEntry {
    /// Foreign device address
    pub address: NetworkAddress,
    /// Time-to-live (seconds)
    pub ttl: u16,
    /// Remaining time (seconds)
    pub remaining_time: u16,
    /// Registration timestamp
    #[cfg(feature = "std")]
    pub registered_at: std::time::Instant,
}

/// Foreign device table manager
#[derive(Debug)]
pub struct ForeignDeviceTable {
    /// FDT entries
    entries: Vec<FdtEntry>,
    /// Maximum number of entries
    max_entries: usize,
}

impl ForeignDeviceTable {
    /// Create a new FDT
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Register a foreign device
    pub fn register(&mut self, address: NetworkAddress, ttl: u16) -> Result<()> {
        // Check if already registered
        if let Some(existing) = self.entries.iter_mut().find(|e| e.address == address) {
            existing.ttl = ttl;
            existing.remaining_time = ttl;
            #[cfg(feature = "std")]
            {
                existing.registered_at = std::time::Instant::now();
            }
        } else if self.entries.len() < self.max_entries {
            self.entries.push(FdtEntry {
                address,
                ttl,
                remaining_time: ttl,
                #[cfg(feature = "std")]
                registered_at: std::time::Instant::now(),
            });
        } else {
            return Err(NetworkError::InvalidNpdu("FDT full".to_string()));
        }
        Ok(())
    }

    /// Delete a foreign device
    pub fn delete(&mut self, address: &NetworkAddress) -> Result<()> {
        self.entries.retain(|e| e.address != *address);
        Ok(())
    }

    /// Update remaining times (called periodically)
    pub fn update_times(&mut self, elapsed_seconds: u16) {
        self.entries.retain_mut(|entry| {
            if entry.remaining_time > elapsed_seconds {
                entry.remaining_time -= elapsed_seconds;
                true
            } else {
                false // Remove expired entries
            }
        });
    }

    /// Get all active foreign devices
    pub fn get_active_devices(&self) -> Vec<&NetworkAddress> {
        self.entries.iter().map(|e| &e.address).collect()
    }

    /// Check if a device is registered
    pub fn is_registered(&self, address: &NetworkAddress) -> bool {
        self.entries.iter().any(|e| e.address == *address)
    }
}

/// Network security manager
#[derive(Debug)]
pub struct NetworkSecurityManager {
    /// Allowed source networks
    allowed_networks: Vec<u16>,
    /// Blocked source networks
    blocked_networks: Vec<u16>,
    /// Allow broadcasts
    allow_broadcasts: bool,
    /// Security statistics
    security_stats: SecurityStatistics,
}

/// Security statistics
#[derive(Debug, Default)]
pub struct SecurityStatistics {
    /// Messages accepted
    pub accepted: u64,
    /// Messages rejected
    pub rejected: u64,
    /// Blocked network attempts
    pub blocked_attempts: u64,
}

impl NetworkSecurityManager {
    /// Create a new security manager
    pub fn new() -> Self {
        Self {
            allowed_networks: Vec::new(),
            blocked_networks: Vec::new(),
            allow_broadcasts: true,
            security_stats: SecurityStatistics::default(),
        }
    }

    /// Check if a message should be accepted
    pub fn check_message(&mut self, npdu: &Npdu) -> bool {
        // Check source network if present
        if let Some(ref source) = npdu.source {
            if self.blocked_networks.contains(&source.network) {
                self.security_stats.blocked_attempts += 1;
                self.security_stats.rejected += 1;
                return false;
            }

            if !self.allowed_networks.is_empty() && !self.allowed_networks.contains(&source.network)
            {
                self.security_stats.rejected += 1;
                return false;
            }
        }

        // Check broadcast permission
        if !self.allow_broadcasts {
            if let Some(ref dest) = npdu.destination {
                if dest.is_broadcast() {
                    self.security_stats.rejected += 1;
                    return false;
                }
            }
        }

        self.security_stats.accepted += 1;
        true
    }

    /// Add allowed network
    pub fn allow_network(&mut self, network: u16) {
        if !self.allowed_networks.contains(&network) {
            self.allowed_networks.push(network);
        }
    }

    /// Block a network
    pub fn block_network(&mut self, network: u16) {
        if !self.blocked_networks.contains(&network) {
            self.blocked_networks.push(network);
        }
        // Remove from allowed if present
        self.allowed_networks.retain(|&n| n != network);
    }

    /// Set broadcast permission
    pub fn set_allow_broadcasts(&mut self, allow: bool) {
        self.allow_broadcasts = allow;
    }

    /// Get security statistics
    pub fn get_stats(&self) -> &SecurityStatistics {
        &self.security_stats
    }

    /// Reset security statistics
    pub fn reset_stats(&mut self) {
        self.security_stats = SecurityStatistics::default();
    }
}

impl Default for NetworkSecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npdu_control() {
        let control = NpduControl {
            network_message: true,
            destination_present: false,
            source_present: true,
            expecting_reply: false,
            priority: 2,
        };

        let byte = control.to_byte();
        let decoded = NpduControl::from_byte(byte);

        assert_eq!(control.network_message, decoded.network_message);
        assert_eq!(control.destination_present, decoded.destination_present);
        assert_eq!(control.source_present, decoded.source_present);
        assert_eq!(control.expecting_reply, decoded.expecting_reply);
        assert_eq!(control.priority, decoded.priority);
    }

    #[test]
    fn test_npdu_encode_decode_basic() {
        let npdu = Npdu::new();
        let encoded = npdu.encode();
        let (decoded, consumed) = Npdu::decode(&encoded).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(consumed, 2); // version + control
        assert_eq!(decoded.destination, None);
        assert_eq!(decoded.source, None);
    }

    #[test]
    fn test_npdu_with_destination() {
        let mut npdu = Npdu::new();
        npdu.control.destination_present = true;
        npdu.destination = Some(NetworkAddress::new(100, vec![192, 168, 1, 1]));
        npdu.hop_count = Some(5);

        let encoded = npdu.encode();
        let (decoded, _) = Npdu::decode(&encoded).unwrap();

        assert_eq!(decoded.destination.as_ref().unwrap().network, 100);
        assert_eq!(
            decoded.destination.as_ref().unwrap().address,
            vec![192, 168, 1, 1]
        );
        assert_eq!(decoded.hop_count, Some(5));
    }

    #[test]
    fn test_network_message() {
        let message = NetworkLayerMessage::new(
            NetworkMessageType::WhoIsRouterToNetwork,
            vec![0x00, 0x64].into(), // Network 100
        );

        let encoded = message.encode();
        let decoded = NetworkLayerMessage::decode(&encoded).unwrap();

        assert_eq!(
            decoded.message_type,
            NetworkMessageType::WhoIsRouterToNetwork
        );
        assert_eq!(decoded.data, vec![0x00, 0x64].into());
    }

    #[test]
    fn test_routing_table() {
        let mut table = RoutingTable::new();

        let router = RouterInfo {
            networks: vec![100, 200],
            address: NetworkAddress::new(0, vec![192, 168, 1, 1]),
            performance_index: Some(10),
        };

        table.add_router(router);

        assert!(table.find_route(100).is_some());
        assert!(table.find_route(200).is_some());
        assert!(table.find_route(300).is_none());
    }

    #[test]
    fn test_router_manager() {
        let mut manager = RouterManager::new(1);

        // Add a router for network 100
        manager.add_discovered_router(
            vec![100],
            NetworkAddress::new(0, vec![192, 168, 1, 1]),
            Some(10),
        );

        // Test routing a message to network 100
        let mut npdu = Npdu::new();
        npdu.destination = Some(NetworkAddress::new(100, vec![10, 0, 0, 1]));
        npdu.hop_count = Some(5);

        let result = manager.route_message(&mut npdu).unwrap();
        assert!(result.is_some());
        assert_eq!(npdu.hop_count, Some(4)); // Hop count decremented

        // Test local message routing
        let mut local_npdu = Npdu::new();
        local_npdu.destination = Some(NetworkAddress::new(1, vec![10, 0, 0, 1]));
        let local_result = manager.route_message(&mut local_npdu).unwrap();
        assert!(local_result.is_none()); // Local delivery

        // Test hop count exceeded
        let mut hopless_npdu = Npdu::new();
        hopless_npdu.destination = Some(NetworkAddress::new(100, vec![10, 0, 0, 1]));
        hopless_npdu.hop_count = Some(0);
        assert!(manager.route_message(&mut hopless_npdu).is_err());

        // Test network unreachable
        let mut unreachable_npdu = Npdu::new();
        unreachable_npdu.destination = Some(NetworkAddress::new(999, vec![10, 0, 0, 1]));
        assert!(manager.route_message(&mut unreachable_npdu).is_err());
    }

    #[test]
    fn test_router_manager_network_messages() {
        let mut manager = RouterManager::new(1);

        // Add router for network 100
        manager.add_discovered_router(
            vec![100],
            NetworkAddress::new(0, vec![192, 168, 1, 1]),
            Some(10),
        );

        // Test Who-Is-Router-To-Network
        let who_is_msg = NetworkLayerMessage::new(
            NetworkMessageType::WhoIsRouterToNetwork,
            vec![0x00, 0x64].into(), // Network 100
        );
        let response = manager.process_network_message(&who_is_msg).unwrap();
        assert!(response.is_some());
        if let Some(resp) = response {
            assert_eq!(resp.message_type, NetworkMessageType::IAmRouterToNetwork);
            assert_eq!(resp.data, vec![0x00, 0x64].into());
        }

        // Test What-Is-Network-Number
        let what_is_msg = NetworkLayerMessage::new(NetworkMessageType::WhatIsNetworkNumber, None);
        let response = manager.process_network_message(&what_is_msg).unwrap();
        assert!(response.is_some());
        if let Some(resp) = response {
            assert_eq!(resp.message_type, NetworkMessageType::NetworkNumberIs);
            assert_eq!(resp.data, vec![0x00, 0x01].into()); // Network 1
        }

        // Test Router-Busy-To-Network
        let busy_msg = NetworkLayerMessage::new(
            NetworkMessageType::RouterBusyToNetwork,
            vec![0x00, 0x64].into(), // Network 100
        );
        manager.process_network_message(&busy_msg).unwrap();
        assert!(manager.busy_networks.contains(&100));

        // Test Router-Available-To-Network
        let available_msg = NetworkLayerMessage::new(
            NetworkMessageType::RouterAvailableToNetwork,
            vec![0x00, 0x64].into(), // Network 100
        );
        manager.process_network_message(&available_msg).unwrap();
        assert!(!manager.busy_networks.contains(&100));
    }

    #[test]
    fn test_path_discovery() {
        let mut discovery = PathDiscovery::new();

        // Create a simple network topology: 1 -> 2 -> 3
        discovery.add_link(NetworkLink {
            source_network: 1,
            destination_network: 2,
            cost: 10,
            router_address: NetworkAddress::new(0, vec![192, 168, 1, 1]),
        });

        discovery.add_link(NetworkLink {
            source_network: 2,
            destination_network: 3,
            cost: 15,
            router_address: NetworkAddress::new(0, vec![192, 168, 2, 1]),
        });

        // Find path from 1 to 3
        let path = discovery.find_path(1, 3);
        assert!(path.is_some());
        assert_eq!(path.unwrap(), vec![1, 2, 3]);

        // Test path to same network
        let same_path = discovery.find_path(1, 1);
        assert_eq!(same_path.unwrap(), vec![1]);

        // Test path to unreachable network
        let no_path = discovery.find_path(1, 999);
        assert!(no_path.is_none());

        // Test cache functionality
        let cached_path = discovery.find_path(1, 3);
        assert!(cached_path.is_some());
    }

    #[test]
    fn test_network_diagnostics() {
        let mut diagnostics = NetworkDiagnostics::new();

        // Update network status
        diagnostics.update_network_status(100, NetworkStatus::Reachable);
        diagnostics.update_network_status(200, NetworkStatus::Unreachable);
        diagnostics.update_network_status(300, NetworkStatus::Degraded);

        assert_eq!(
            diagnostics.get_network_status(100),
            NetworkStatus::Reachable
        );
        assert_eq!(
            diagnostics.get_network_status(200),
            NetworkStatus::Unreachable
        );
        assert_eq!(diagnostics.get_network_status(999), NetworkStatus::Unknown);

        // Record latency measurements
        diagnostics.record_latency(100, 50);
        diagnostics.record_latency(200, 100);
        diagnostics.record_latency(300, 200);

        assert_eq!(diagnostics.get_average_latency(100), Some(50));
        assert_eq!(diagnostics.get_average_latency(200), Some(100));

        // Test unhealthy networks
        let unhealthy = diagnostics.get_unhealthy_networks();
        assert_eq!(unhealthy.len(), 2);
        assert!(unhealthy.contains(&200));
        assert!(unhealthy.contains(&300));

        // Test health summary
        let summary = diagnostics.get_health_summary();
        assert_eq!(summary.total_networks, 3);
        assert_eq!(summary.reachable_count, 1);
        assert_eq!(summary.unreachable_count, 1);
        assert_eq!(summary.degraded_count, 1);
        assert!(summary.average_latency.is_some());
        let avg = summary.average_latency.unwrap();
        assert!((avg - 116.67).abs() < 0.1); // (50 + 100 + 200) / 3
    }

    #[test]
    fn test_router_health() {
        let mut diagnostics = NetworkDiagnostics::new();
        let router_addr = NetworkAddress::new(0, vec![192, 168, 1, 1]);

        let health = RouterHealth {
            responsive: true,
            #[cfg(feature = "std")]
            last_response: Some(std::time::Instant::now()),
            error_count: 5,
            performance_index: 10,
        };

        diagnostics.update_router_health(router_addr.clone(), health);

        let retrieved_health = diagnostics.get_router_health(&router_addr);
        assert!(retrieved_health.is_some());
        assert!(retrieved_health.unwrap().responsive);
        assert_eq!(retrieved_health.unwrap().error_count, 5);
        assert_eq!(retrieved_health.unwrap().performance_index, 10);
    }

    #[test]
    fn test_network_address_properties() {
        let local_addr = NetworkAddress::new(0, vec![192, 168, 1, 1]);
        assert!(local_addr.is_local());
        assert!(!local_addr.is_broadcast());

        let broadcast_addr = NetworkAddress::new(0xFFFF, vec![]);
        assert!(broadcast_addr.is_broadcast());
        assert!(!broadcast_addr.is_local());

        let remote_addr = NetworkAddress::new(100, vec![10, 0, 0, 1]);
        assert!(!remote_addr.is_local());
        assert!(!remote_addr.is_broadcast());
    }

    #[test]
    fn test_performance_metrics() {
        let mut manager = RouterManager::new(1);

        // Add a router
        manager.add_discovered_router(
            vec![100],
            NetworkAddress::new(0, vec![192, 168, 1, 1]),
            Some(10),
        );

        // Route some messages to generate metrics
        let mut npdu1 = Npdu::new();
        npdu1.destination = Some(NetworkAddress::new(100, vec![10, 0, 0, 1]));
        npdu1.hop_count = Some(5);
        manager.route_message(&mut npdu1).unwrap();

        let mut npdu2 = Npdu::new();
        npdu2.destination = Some(NetworkAddress::new(100, vec![10, 0, 0, 2]));
        npdu2.hop_count = Some(1);
        manager.route_message(&mut npdu2).unwrap();

        // Try routing to unreachable network
        let mut npdu3 = Npdu::new();
        npdu3.destination = Some(NetworkAddress::new(999, vec![10, 0, 0, 1]));
        let _ = manager.route_message(&mut npdu3);

        // Try with hop count 0
        let mut npdu4 = Npdu::new();
        npdu4.destination = Some(NetworkAddress::new(100, vec![10, 0, 0, 1]));
        npdu4.hop_count = Some(0);
        let _ = manager.route_message(&mut npdu4);

        let metrics = manager.get_performance_metrics();
        assert_eq!(metrics.messages_routed, 2);
        assert_eq!(metrics.network_unreachable_count, 1);
        assert_eq!(metrics.hop_count_exceeded, 1);

        // Test reset
        manager.reset_performance_metrics();
        let reset_metrics = manager.get_performance_metrics();
        assert_eq!(reset_metrics.messages_routed, 0);
        assert_eq!(reset_metrics.network_unreachable_count, 0);
        assert_eq!(reset_metrics.hop_count_exceeded, 0);
    }
}
