//! BACnet Transport Layer Module
//!
//! This module provides transport layer functionality for BACnet communication.
//! While BACnet doesn't have a traditional transport layer like TCP/UDP, this module
//! handles transport-related concerns such as connection management, flow control,
//! and reliable delivery mechanisms.
//!
//! # Overview
//!
//! The transport layer handles:
//! - BACnet/IP specific transport (UDP port 47808)
//! - BACnet Virtual Link Layer (BVLL) for BACnet/IP
//! - Foreign Device Registration
//! - Broadcast Distribution Table (BDT) management
//! - Connection-oriented transports (BACnet/SC)
//!
//! # BACnet/IP
//!
//! BACnet/IP uses UDP as its transport with BVLL providing:
//! - Original-Unicast-NPDU
//! - Original-Broadcast-NPDU
//! - Forwarded-NPDU
//! - Register-Foreign-Device
//! - Distribute-Broadcast-To-Network
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::transport::*;
//!
//! // Example of creating a BACnet/IP transport
//! // let transport = BacnetIpTransport::new("0.0.0.0:47808")?;
//! ```

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

#[cfg(not(feature = "std"))]
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::Duration;

/// Result type for transport operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, TransportError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, TransportError>;

/// Errors that can occur in transport operations
#[derive(Debug)]
pub enum TransportError {
    /// I/O error
    #[cfg(feature = "std")]
    IoError(std::io::Error),
    /// Invalid BVLL format
    InvalidBvll(String),
    /// Foreign device registration failed
    RegistrationFailed,
    /// Transport not connected
    NotConnected,
    /// Invalid transport configuration
    InvalidConfiguration(String),
    /// Request timeout
    Timeout(String),
    /// Request not found
    RequestNotFound(u8),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            TransportError::IoError(e) => write!(f, "I/O error: {}", e),
            TransportError::InvalidBvll(msg) => write!(f, "Invalid BVLL: {}", msg),
            TransportError::RegistrationFailed => write!(f, "Foreign device registration failed"),
            TransportError::NotConnected => write!(f, "Transport not connected"),
            TransportError::InvalidConfiguration(msg) => {
                write!(f, "Invalid configuration: {}", msg)
            }
            TransportError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            TransportError::RequestNotFound(invoke_id) => {
                write!(f, "Request not found: invoke ID {}", invoke_id)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for TransportError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for TransportError {
    fn from(error: std::io::Error) -> Self {
        TransportError::IoError(error)
    }
}

// The BVLL header and function codes are the datalink layer's types; the
// transport layer reuses them rather than defining duplicates (they were
// previously duplicated here as `BvllHeader`/`BvllFunction`).
pub use crate::datalink::bip::{BvlcFunction, BvlcHeader};

/// Foreign device registration info
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct ForeignDeviceRegistration {
    /// BBMD (BACnet Broadcast Management Device) address
    pub bbmd_address: SocketAddr,
    /// Time-to-live in seconds
    pub ttl: u16,
    /// Last registration time
    pub last_registration: Instant,
}

/// Broadcast distribution table entry
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct BdtEntry {
    /// IP address
    pub address: IpAddr,
    /// Port number
    pub port: u16,
    /// Broadcast mask
    pub mask: IpAddr,
}

/// Common trait for BACnet transports
#[cfg(feature = "std")]
pub trait Transport: Send + Sync {
    /// Send data to a specific address
    fn send(&mut self, data: &[u8], dest: &SocketAddr) -> Result<()>;

    /// Receive data with source address
    fn receive(&mut self) -> Result<(Vec<u8>, SocketAddr)>;

    /// Receive data with timeout
    fn receive_timeout(&mut self, timeout: Duration) -> Result<(Vec<u8>, SocketAddr)>;

    /// Send confirmed request with timeout tracking
    fn send_confirmed_request(
        &mut self,
        dest: SocketAddr,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<u8>;

    /// Check for timed out requests
    fn check_timeouts(&mut self) -> Vec<u8>;

    /// Complete a request (remove from timeout tracking)
    fn complete_request(&mut self, invoke_id: u8) -> Option<Duration>;

    /// Get local address
    fn local_address(&self) -> Result<SocketAddr>;

    /// Check if transport is connected/ready
    fn is_connected(&self) -> bool;
}

/// BACnet/IP transport configuration
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct BacnetIpConfig {
    /// Local bind address
    pub bind_address: SocketAddr,
    /// Enable broadcast reception
    pub broadcast_enabled: bool,
    /// Foreign device registration
    pub foreign_device: Option<ForeignDeviceRegistration>,
    /// Broadcast distribution table
    pub bdt: Vec<BdtEntry>,
    /// Receive buffer size
    pub buffer_size: usize,
    /// Socket read timeout
    pub read_timeout: Option<Duration>,
    /// Socket write timeout
    pub write_timeout: Option<Duration>,
    /// Request timeout for confirmed services
    pub request_timeout: Duration,
    /// Foreign device registration timeout
    pub registration_timeout: Duration,
}

#[cfg(feature = "std")]
impl Default for BacnetIpConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:47808"
                .parse()
                .expect("hardcoded address should be valid"),
            broadcast_enabled: true,
            foreign_device: None,
            bdt: Vec::new(),
            buffer_size: 1500,
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            request_timeout: Duration::from_secs(10),
            registration_timeout: Duration::from_secs(30),
        }
    }
}

/// BACnet/IP specific constants
pub mod constants {
    use super::Duration;

    /// Default BACnet/IP UDP port
    pub const BACNET_IP_PORT: u16 = 0xBAC0; // 47808

    /// Maximum BVLL length
    pub const MAX_BVLL_LENGTH: usize = 1497;

    /// BVLL header size
    pub const BVLL_HEADER_SIZE: usize = 4;

    /// Default foreign device TTL (seconds)
    pub const DEFAULT_FD_TTL: u16 = 900; // 15 minutes

    /// Default request timeout
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Default socket read timeout
    pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

    /// Default socket write timeout
    pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

    /// Default foreign device registration timeout
    pub const DEFAULT_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);

    /// Maximum number of concurrent requests
    pub const MAX_CONCURRENT_REQUESTS: usize = 255;
}

/// BVLL message containing header and data
#[derive(Debug, Clone)]
pub struct BvllMessage {
    /// BVLL header (see [`BvlcHeader`] in the datalink layer)
    pub header: BvlcHeader,
    /// Message data (NPDU)
    pub data: Vec<u8>,
}

impl BvllMessage {
    /// Create a new BVLL message
    pub fn new(function: BvlcFunction, data: Vec<u8>) -> Self {
        let length = (constants::BVLL_HEADER_SIZE + data.len()) as u16;
        Self {
            header: BvlcHeader::new(function, length),
            data,
        }
    }

    /// Encode BVLL message to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut result = self.header.encode();
        result.extend_from_slice(&self.data);
        result
    }

    /// Decode BVLL message from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        let header =
            BvlcHeader::decode(data).map_err(|e| TransportError::InvalidBvll(e.to_string()))?;

        if data.len() < header.length as usize {
            return Err(TransportError::InvalidBvll("Message too short".into()));
        }

        let message_data = data[constants::BVLL_HEADER_SIZE..header.length as usize].to_vec();

        Ok(Self {
            header,
            data: message_data,
        })
    }
}

#[cfg(feature = "std")]
use std::net::UdpSocket;

/// Timeout manager for handling request timeouts
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct TimeoutManager {
    /// Active timeouts keyed by invoke ID
    timeouts: HashMap<u8, (Instant, Duration)>,
    /// Next available invoke ID
    next_invoke_id: u8,
}

#[cfg(feature = "std")]
impl TimeoutManager {
    /// Create new timeout manager
    pub fn new() -> Self {
        Self {
            timeouts: HashMap::new(),
            next_invoke_id: 1,
        }
    }

    /// Start tracking a new request
    pub fn start_request(&mut self, timeout: Duration) -> u8 {
        let invoke_id = self.next_invoke_id;
        self.next_invoke_id = self.next_invoke_id.wrapping_add(1);
        if self.next_invoke_id == 0 {
            self.next_invoke_id = 1; // Skip 0 as it's often reserved
        }

        self.timeouts.insert(invoke_id, (Instant::now(), timeout));
        invoke_id
    }

    /// Complete a request
    pub fn complete_request(&mut self, invoke_id: u8) -> Option<Duration> {
        self.timeouts
            .remove(&invoke_id)
            .map(|(start_time, _)| start_time.elapsed())
    }

    /// Check for timed out requests
    pub fn check_timeouts(&mut self) -> Vec<u8> {
        let mut timed_out = Vec::new();
        let now = Instant::now();

        self.timeouts.retain(|&invoke_id, (start_time, timeout)| {
            if now.duration_since(*start_time) > *timeout {
                timed_out.push(invoke_id);
                false
            } else {
                true
            }
        });

        timed_out
    }

    /// Get number of active requests
    pub fn active_count(&self) -> usize {
        self.timeouts.len()
    }

    /// Get remaining time for a request
    pub fn remaining_time(&self, invoke_id: u8) -> Option<Duration> {
        self.timeouts.get(&invoke_id).map(|(start_time, timeout)| {
            let elapsed = start_time.elapsed();
            if elapsed < *timeout {
                *timeout - elapsed
            } else {
                Duration::from_secs(0)
            }
        })
    }

    /// Clear all timeouts
    pub fn clear(&mut self) {
        self.timeouts.clear();
    }

    /// Get all active invoke IDs
    pub fn active_invoke_ids(&self) -> Vec<u8> {
        self.timeouts.keys().copied().collect()
    }
}

#[cfg(feature = "std")]
impl Default for TimeoutManager {
    fn default() -> Self {
        Self::new()
    }
}

/// BACnet/IP transport implementation
#[cfg(feature = "std")]
pub struct BacnetIpTransport {
    /// UDP socket
    socket: UdpSocket,
    /// Configuration
    config: BacnetIpConfig,
    /// Receive buffer
    buffer: Vec<u8>,
    /// Active request timeouts
    active_requests: std::collections::HashMap<u8, (Instant, Duration)>,
    /// Next invoke ID for confirmed requests
    next_invoke_id: u8,
}

#[cfg(feature = "std")]
impl BacnetIpTransport {
    /// Create a new BACnet/IP transport
    pub fn new(config: BacnetIpConfig) -> Result<Self> {
        let socket = UdpSocket::bind(config.bind_address)?;

        // Enable broadcast if configured
        if config.broadcast_enabled {
            socket.set_broadcast(true)?;
        }

        // Set socket timeouts
        socket.set_read_timeout(config.read_timeout)?;
        socket.set_write_timeout(config.write_timeout)?;

        let buffer = vec![0u8; config.buffer_size];

        Ok(Self {
            socket,
            config,
            buffer,
            active_requests: HashMap::new(),
            next_invoke_id: 1,
        })
    }

    /// Create with default configuration
    pub fn new_default(bind_addr: &str) -> Result<Self> {
        let config = BacnetIpConfig {
            bind_address: bind_addr
                .parse()
                .map_err(|_| TransportError::InvalidConfiguration("Invalid bind address".into()))?,
            ..Default::default()
        };
        Self::new(config)
    }

    /// Send a BVLL message
    pub fn send_bvll(&mut self, message: BvllMessage, dest: SocketAddr) -> Result<()> {
        let encoded = message.encode();
        self.socket.send_to(&encoded, dest)?;
        Ok(())
    }

    /// Send NPDU as original unicast
    pub fn send_npdu_unicast(&mut self, npdu: &[u8], dest: SocketAddr) -> Result<()> {
        let message = BvllMessage::new(BvlcFunction::OriginalUnicastNpdu, npdu.to_vec());
        self.send_bvll(message, dest)
    }

    /// Send NPDU as original broadcast
    pub fn send_npdu_broadcast(&mut self, npdu: &[u8], dest: SocketAddr) -> Result<()> {
        let message = BvllMessage::new(BvlcFunction::OriginalBroadcastNpdu, npdu.to_vec());
        self.send_bvll(message, dest)
    }

    /// Receive a BVLL message
    pub fn receive_bvll(&mut self) -> Result<(BvllMessage, SocketAddr)> {
        let (len, src) = self.socket.recv_from(&mut self.buffer)?;
        let message = BvllMessage::decode(&self.buffer[..len])?;
        Ok((message, src))
    }

    /// Receive a BVLL message with custom timeout
    pub fn receive_bvll_timeout(&mut self, timeout: Duration) -> Result<(BvllMessage, SocketAddr)> {
        // Temporarily set socket timeout
        let original_timeout = self.socket.read_timeout()?;
        self.socket.set_read_timeout(Some(timeout))?;

        let result = self.receive_bvll();

        // Restore original timeout
        self.socket.set_read_timeout(original_timeout)?;

        result
    }

    /// Register as foreign device with BBMD
    pub fn register_foreign_device(&mut self, bbmd_addr: SocketAddr, ttl: u16) -> Result<()> {
        let mut data = Vec::new();
        data.extend_from_slice(&ttl.to_be_bytes());

        let message = BvllMessage::new(BvlcFunction::RegisterForeignDevice, data);
        self.send_bvll(message, bbmd_addr)?;

        // Wait for registration confirmation with timeout
        let start_time = Instant::now();
        while start_time.elapsed() < self.config.registration_timeout {
            if let Ok((response, src)) = self.receive_bvll_timeout(Duration::from_millis(100)) {
                if src == bbmd_addr && response.header.function == BvlcFunction::Result {
                    // Check result code
                    if !response.data.is_empty() {
                        let result_code = u16::from_be_bytes([response.data[0], response.data[1]]);
                        if result_code == 0 {
                            // Registration successful
                            self.config.foreign_device = Some(ForeignDeviceRegistration {
                                bbmd_address: bbmd_addr,
                                ttl,
                                last_registration: Instant::now(),
                            });
                            return Ok(());
                        } else {
                            return Err(TransportError::RegistrationFailed);
                        }
                    }
                }
            }
        }

        // Timeout - assume success for compatibility
        self.config.foreign_device = Some(ForeignDeviceRegistration {
            bbmd_address: bbmd_addr,
            ttl,
            last_registration: Instant::now(),
        });

        Ok(())
    }

    /// Send heartbeat to maintain foreign device registration
    pub fn send_foreign_device_heartbeat(&mut self) -> Result<()> {
        if let Some(ref fd_reg) = self.config.foreign_device {
            let elapsed = fd_reg.last_registration.elapsed().as_secs() as u16;
            if elapsed >= fd_reg.ttl / 2 {
                // Re-register when half TTL has elapsed
                self.register_foreign_device(fd_reg.bbmd_address, fd_reg.ttl)?;
            }
        }
        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &BacnetIpConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: BacnetIpConfig) -> Result<()> {
        // Validate new configuration
        if config.bind_address != self.config.bind_address {
            return Err(TransportError::InvalidConfiguration(
                "Cannot change bind address on existing transport".into(),
            ));
        }

        // Update socket timeouts if they changed
        if config.read_timeout != self.config.read_timeout {
            self.socket.set_read_timeout(config.read_timeout)?;
        }
        if config.write_timeout != self.config.write_timeout {
            self.socket.set_write_timeout(config.write_timeout)?;
        }

        self.config = config;
        Ok(())
    }

    /// Send confirmed request with timeout tracking
    pub fn send_confirmed_request(
        &mut self,
        dest: SocketAddr,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<u8> {
        let invoke_id = self.next_invoke_id;
        self.next_invoke_id = self.next_invoke_id.wrapping_add(1);
        if self.next_invoke_id == 0 {
            self.next_invoke_id = 1; // Skip 0 as it's often reserved
        }

        let request_timeout = timeout.unwrap_or(self.config.request_timeout);
        self.active_requests
            .insert(invoke_id, (Instant::now(), request_timeout));

        // Send the request
        self.send_npdu_unicast(data, dest)?;

        Ok(invoke_id)
    }

    /// Check for timed out requests
    pub fn check_timeouts(&mut self) -> Vec<u8> {
        let mut timed_out = Vec::new();
        let now = Instant::now();

        self.active_requests
            .retain(|&invoke_id, (start_time, timeout)| {
                if now.duration_since(*start_time) > *timeout {
                    timed_out.push(invoke_id);
                    false // Remove from active requests
                } else {
                    true // Keep in active requests
                }
            });

        timed_out
    }

    /// Complete a request (remove from timeout tracking)
    pub fn complete_request(&mut self, invoke_id: u8) -> Option<Duration> {
        self.active_requests
            .remove(&invoke_id)
            .map(|(start_time, _)| start_time.elapsed())
    }

    /// Get active request count
    pub fn active_request_count(&self) -> usize {
        self.active_requests.len()
    }

    /// Get requests by remaining time
    pub fn get_requests_by_remaining_time(&self) -> Vec<(u8, Duration)> {
        let now = Instant::now();
        let mut requests: Vec<(u8, Duration)> = self
            .active_requests
            .iter()
            .map(|(&invoke_id, (start_time, timeout))| {
                let elapsed = now.duration_since(*start_time);
                if elapsed < *timeout {
                    (invoke_id, *timeout - elapsed)
                } else {
                    (invoke_id, Duration::from_secs(0))
                }
            })
            .collect();

        // Sort by remaining time (shortest first)
        requests.sort_by_key(|(_, remaining)| *remaining);
        requests
    }
}

#[cfg(feature = "std")]
impl Transport for BacnetIpTransport {
    fn send(&mut self, data: &[u8], dest: &SocketAddr) -> Result<()> {
        self.send_npdu_unicast(data, *dest)
    }

    fn receive(&mut self) -> Result<(Vec<u8>, SocketAddr)> {
        let (message, src) = self.receive_bvll()?;
        Ok((message.data, src))
    }

    fn receive_timeout(&mut self, timeout: Duration) -> Result<(Vec<u8>, SocketAddr)> {
        let (message, src) = self.receive_bvll_timeout(timeout)?;
        Ok((message.data, src))
    }

    fn send_confirmed_request(
        &mut self,
        dest: SocketAddr,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<u8> {
        self.send_confirmed_request(dest, data, timeout)
    }

    fn check_timeouts(&mut self) -> Vec<u8> {
        self.check_timeouts()
    }

    fn complete_request(&mut self, invoke_id: u8) -> Option<Duration> {
        self.complete_request(invoke_id)
    }

    fn local_address(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    fn is_connected(&self) -> bool {
        true // UDP is connectionless
    }
}

/// BDT (Broadcast Distribution Table) management
#[cfg(feature = "std")]
#[derive(Default)]
pub struct BroadcastManager {
    /// BDT entries
    bdt: Vec<BdtEntry>,
}

#[cfg(feature = "std")]
impl BroadcastManager {
    /// Create new broadcast manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Add BDT entry
    pub fn add_bdt_entry(&mut self, entry: BdtEntry) {
        self.bdt.push(entry);
    }

    /// Remove BDT entry
    pub fn remove_bdt_entry(&mut self, address: IpAddr) {
        self.bdt.retain(|entry| entry.address != address);
    }

    /// Get all BDT entries
    pub fn get_bdt_entries(&self) -> &[BdtEntry] {
        &self.bdt
    }

    /// Encode BDT for transmission
    pub fn encode_bdt(&self) -> Vec<u8> {
        let mut data = Vec::new();

        for entry in &self.bdt {
            match entry.address {
                IpAddr::V4(addr) => {
                    data.extend_from_slice(&addr.octets());
                    data.extend_from_slice(&entry.port.to_be_bytes());

                    if let IpAddr::V4(mask) = entry.mask {
                        data.extend_from_slice(&mask.octets());
                    } else {
                        data.extend_from_slice(&[255, 255, 255, 255]); // Default mask
                    }
                }
                IpAddr::V6(_) => {
                    // IPv6 support would go here
                    // For now, skip IPv6 entries
                }
            }
        }

        data
    }

    /// Decode BDT from received data
    #[allow(clippy::manual_is_multiple_of)]
    pub fn decode_bdt(&mut self, data: &[u8]) -> Result<()> {
        self.bdt.clear();

        let entry_size = 10; // 4 bytes IP + 2 bytes port + 4 bytes mask
        if data.len() % entry_size != 0 {
            return Err(TransportError::InvalidBvll(
                "Invalid BDT data length".into(),
            ));
        }

        for chunk in data.chunks_exact(entry_size) {
            let ip_bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
            let address = IpAddr::V4(ip_bytes.into());

            let port = u16::from_be_bytes([chunk[4], chunk[5]]);

            let mask_bytes = [chunk[6], chunk[7], chunk[8], chunk[9]];
            let mask = IpAddr::V4(mask_bytes.into());

            self.bdt.push(BdtEntry {
                address,
                port,
                mask,
            });
        }

        Ok(())
    }
}

/// Timeout configuration for different operation types
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Socket read operations
    pub read_timeout: Duration,
    /// Socket write operations  
    pub write_timeout: Duration,
    /// Confirmed service requests
    pub request_timeout: Duration,
    /// Foreign device registration
    pub registration_timeout: Duration,
    /// Device discovery (Who-Is)
    pub discovery_timeout: Duration,
    /// Property read operations
    pub property_read_timeout: Duration,
    /// File transfer operations
    pub file_transfer_timeout: Duration,
}

#[cfg(feature = "std")]
impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            registration_timeout: Duration::from_secs(30),
            discovery_timeout: Duration::from_secs(3),
            property_read_timeout: Duration::from_secs(5),
            file_transfer_timeout: Duration::from_secs(60),
        }
    }
}

/// Timeout utilities for BACnet operations
#[cfg(feature = "std")]
pub mod timeout_utils {
    use super::*;

    /// Wait for a condition with timeout
    pub fn wait_for_condition<F>(
        condition: F,
        timeout: Duration,
        check_interval: Duration,
    ) -> Result<()>
    where
        F: Fn() -> bool,
    {
        let start = Instant::now();

        while start.elapsed() < timeout {
            if condition() {
                return Ok(());
            }

            std::thread::sleep(check_interval);
        }

        Err(TransportError::Timeout(
            "Condition not met within timeout".into(),
        ))
    }

    /// Execute operation with retry and exponential backoff
    pub fn retry_with_backoff<F, T, E>(
        mut operation: F,
        max_attempts: u32,
        initial_delay: Duration,
        max_delay: Duration,
        backoff_multiplier: f64,
    ) -> std::result::Result<T, E>
    where
        F: FnMut() -> std::result::Result<T, E>,
    {
        let mut delay = initial_delay;

        let mut last_error = None;
        for attempt in 0..max_attempts {
            match operation() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < max_attempts - 1 {
                        std::thread::sleep(delay);
                        delay = std::cmp::min(
                            Duration::from_millis(
                                (delay.as_millis() as f64 * backoff_multiplier) as u64,
                            ),
                            max_delay,
                        );
                    }
                }
            }
        }

        Err(last_error.expect("retry loop should have at least one error"))
    }

    /// Create timeout-aware operation
    pub fn with_timeout<F, T>(operation: F, timeout: Duration) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let start = Instant::now();
        let result = operation();

        if start.elapsed() > timeout {
            Err(TransportError::Timeout(format!(
                "Operation took {:.2}s, timeout was {:.2}s",
                start.elapsed().as_secs_f64(),
                timeout.as_secs_f64()
            )))
        } else {
            result
        }
    }

    /// Calculate adaptive timeout based on historical performance
    pub fn calculate_adaptive_timeout(
        recent_times: &[Duration],
        base_timeout: Duration,
        safety_factor: f64,
    ) -> Duration {
        if recent_times.is_empty() {
            return base_timeout;
        }

        // Calculate average and standard deviation
        let avg = recent_times.iter().sum::<Duration>() / recent_times.len() as u32;

        let variance: f64 = recent_times
            .iter()
            .map(|t| {
                let diff = t.as_secs_f64() - avg.as_secs_f64();
                diff * diff
            })
            .sum::<f64>()
            / recent_times.len() as f64;

        let std_dev = variance.sqrt();

        // Use average + (safety_factor * std_dev), but at least base_timeout
        let adaptive_secs = avg.as_secs_f64() + (safety_factor * std_dev);
        let adaptive_timeout = Duration::from_secs_f64(adaptive_secs);

        std::cmp::max(adaptive_timeout, base_timeout)
    }
}

/// BACnet/SC (Secure Connect) Support Planning
///
/// BACnet/SC is defined in ASHRAE 135-2020 and provides secure WebSocket-based
/// communication for BACnet. This would be a future enhancement to the transport layer.
///
/// Key BACnet/SC Features to Implement:
///
/// 1. **WebSocket Transport**: TLS-secured WebSocket connections (wss://)
/// 2. **Node Authentication**: X.509 certificates and certificate authorities
/// 3. **Hub and Direct Connect**: Support for hub-based and direct node connections
/// 4. **Message Encryption**: All messages encrypted using TLS
/// 5. **Connection Management**: Automatic reconnection and connection state tracking
/// 6. **Discovery**: Integration with DNS-SD for automatic node discovery
///
/// Implementation Plan:
///
/// ```rust
/// // Future BACnet/SC structures (not implemented yet)
///
/// #[cfg(feature = "bacnet-sc")]
/// pub struct BacnetScConfig {
///     pub certificate_path: PathBuf,
///     pub private_key_path: PathBuf,
///     pub ca_certificates: Vec<PathBuf>,
///     pub hub_uri: Option<String>,
///     pub node_uuid: String,
///     pub max_connections: usize,
/// }
///
/// #[cfg(feature = "bacnet-sc")]
/// pub struct BacnetScTransport {
///     config: BacnetScConfig,
///     connections: HashMap<String, WebSocketConnection>,
///     hub_connection: Option<WebSocketConnection>,
/// }
///
/// #[cfg(feature = "bacnet-sc")]
/// pub enum BacnetScMessage {
///     Advertisement(NodeAdvertisement),
///     Connect(ConnectRequest),
///     Disconnect(DisconnectRequest),
///     Data(EncryptedData),
///     Heartbeat,
/// }
/// ```
///
/// Dependencies needed for BACnet/SC:
/// - tokio-tungstenite (WebSocket client/server)
/// - rustls (TLS implementation)
/// - webpki (Certificate validation)
/// - serde_json (JSON message serialization)
/// - uuid (Node identification)
///
/// Security Considerations:
/// - Certificate validation and revocation checking
/// - Secure random number generation
/// - Protection against replay attacks
/// - Rate limiting and DoS protection
///
/// This would require a separate feature flag and significant additional dependencies,
/// so it's planned for a future major version.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bvll_header_encode_decode() {
        let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 100);
        let encoded = header.encode();

        assert_eq!(encoded[0], 0x81); // BACnet/IP
        assert_eq!(encoded[1], 0x0A); // Original-Unicast-NPDU
        assert_eq!(encoded[2], 0x00); // Length high byte
        assert_eq!(encoded[3], 0x64); // Length low byte (100)

        let decoded = BvlcHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.bvlc_type, header.bvlc_type);
        assert_eq!(decoded.function as u8, header.function as u8);
        assert_eq!(decoded.length, header.length);
    }

    #[test]
    fn test_bvll_message_encode_decode() {
        let test_data = vec![0x01, 0x02, 0x03, 0x04];
        let message = BvllMessage::new(BvlcFunction::OriginalBroadcastNpdu, test_data.clone());

        let encoded = message.encode();
        assert_eq!(encoded.len(), 4 + test_data.len()); // Header + data

        let decoded = BvllMessage::decode(&encoded).unwrap();
        assert_eq!(
            decoded.header.function as u8,
            BvlcFunction::OriginalBroadcastNpdu as u8
        );
        assert_eq!(decoded.data, test_data);
    }

    #[test]
    fn test_bvll_function_decode() {
        // Test all BVLL function codes
        let test_cases = [
            (0x00, BvlcFunction::Result),
            (0x0A, BvlcFunction::OriginalUnicastNpdu),
            (0x0B, BvlcFunction::OriginalBroadcastNpdu),
            (0x05, BvlcFunction::RegisterForeignDevice),
        ];

        for (code, expected) in test_cases.iter() {
            let data = [0x81, *code, 0x00, 0x04];
            let header = BvlcHeader::decode(&data).unwrap();
            assert_eq!(header.function as u8, *expected as u8);
        }
    }

    #[test]
    fn test_broadcast_manager() {
        let mut manager = BroadcastManager::new();

        let entry = BdtEntry {
            address: "192.168.1.1".parse().unwrap(),
            port: 47808,
            mask: "255.255.255.0".parse().unwrap(),
        };

        manager.add_bdt_entry(entry.clone());
        assert_eq!(manager.get_bdt_entries().len(), 1);

        let encoded = manager.encode_bdt();
        assert_eq!(encoded.len(), 10); // 4 + 2 + 4 bytes per entry

        let mut new_manager = BroadcastManager::new();
        new_manager.decode_bdt(&encoded).unwrap();

        let decoded_entries = new_manager.get_bdt_entries();
        assert_eq!(decoded_entries.len(), 1);
        assert_eq!(decoded_entries[0].address, entry.address);
        assert_eq!(decoded_entries[0].port, entry.port);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_bacnet_ip_config_default() {
        let config = BacnetIpConfig::default();
        assert_eq!(config.bind_address.port(), constants::BACNET_IP_PORT);
        assert!(config.broadcast_enabled);
        assert!(config.foreign_device.is_none());
        assert_eq!(config.buffer_size, 1500);
        assert_eq!(config.read_timeout, Some(constants::DEFAULT_READ_TIMEOUT));
        assert_eq!(config.write_timeout, Some(constants::DEFAULT_WRITE_TIMEOUT));
        assert_eq!(config.request_timeout, constants::DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(
            config.registration_timeout,
            constants::DEFAULT_REGISTRATION_TIMEOUT
        );
    }

    #[test]
    fn test_invalid_bvll_decode() {
        // Test too short header
        let short_data = [0x81, 0x0A];
        assert!(BvlcHeader::decode(&short_data).is_err());

        // Test invalid BVLL type
        let invalid_type = [0x82, 0x0A, 0x00, 0x04];
        assert!(BvlcHeader::decode(&invalid_type).is_err());

        // Test invalid function code
        let invalid_function = [0x81, 0xFF, 0x00, 0x04];
        assert!(BvlcHeader::decode(&invalid_function).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_timeout_tracking() {
        let config = BacnetIpConfig::default();
        let mut transport = BacnetIpTransport::new(config).unwrap();

        // Test invoke ID generation
        let target = "127.0.0.1:47808".parse().unwrap();
        let data = &[0x01, 0x02, 0x03];

        let invoke_id1 = transport
            .send_confirmed_request(target, data, None)
            .unwrap();
        let invoke_id2 = transport
            .send_confirmed_request(target, data, None)
            .unwrap();

        assert_ne!(invoke_id1, invoke_id2);
        assert_eq!(transport.active_request_count(), 2);

        // Test request completion
        let elapsed = transport.complete_request(invoke_id1);
        assert!(elapsed.is_some());
        assert_eq!(transport.active_request_count(), 1);

        // Test completing non-existent request
        let elapsed = transport.complete_request(255);
        assert!(elapsed.is_none());
    }

    #[test]
    fn test_timeout_constants() {
        assert_eq!(constants::DEFAULT_REQUEST_TIMEOUT.as_secs(), 10);
        assert_eq!(constants::DEFAULT_READ_TIMEOUT.as_secs(), 5);
        assert_eq!(constants::DEFAULT_WRITE_TIMEOUT.as_secs(), 5);
        assert_eq!(constants::DEFAULT_REGISTRATION_TIMEOUT.as_secs(), 30);
        assert_eq!(constants::MAX_CONCURRENT_REQUESTS, 255);
    }
}
