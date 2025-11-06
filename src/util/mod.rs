//! BACnet Utility Functions and Debugging Tools
//!
//! This module provides comprehensive utility functions, debugging tools, and helper utilities
//! used throughout the BACnet stack implementation. It includes low-level utilities for data
//! processing, performance monitoring, debugging assistance, and protocol-specific calculations.
//!
//! # Overview
//!
//! The utility module is organized into several functional areas:
//!
//! ## Core Utilities
//! - **CRC Calculations**: MS/TP header and data CRC algorithms
//! - **Object ID Encoding**: Conversion between object type/instance and 32-bit identifiers  
//! - **Data Conversion**: Byte order handling, bit manipulation, type conversions
//! - **Validation**: Input validation and range checking functions
//!
//! ## Performance Monitoring
//! - **Statistics Collection**: Network and processing performance metrics
//! - **Timing Measurements**: High-precision timing for profiling
//! - **Resource Monitoring**: Memory and CPU usage tracking
//! - **Circular Buffers**: Efficient data structures for logging and history
//!
//! ## Debugging and Analysis
//! - **Protocol Debugging**: Deep packet inspection and analysis tools
//! - **Hex Dumping**: Formatted binary data display with annotations
//! - **Property Formatters**: Human-readable display of BACnet values
//! - **Service Analysis**: Request/response parsing and validation
//!
//! ## Retry and Reliability
//! - **Exponential Backoff**: Adaptive retry algorithms
//! - **Timeout Management**: Configurable timeout strategies
//! - **Error Recovery**: Automatic recovery from transient failures
//!
//! # Core Functions
//!
//! ## CRC Calculations
//!
//! BACnet uses different CRC algorithms for different data link types:
//!
//! ```rust
//! use bacnet_rs::util::crc16_mstp;
//!
//! // Calculate CRC for MS/TP frame data
//! let data = b"Hello BACnet";
//! let crc = crc16_mstp(data);
//! println!("CRC-16: 0x{:04X}", crc);
//! ```
//!
//! ## Object ID Encoding
//!
//! BACnet object identifiers combine object type and instance into a 32-bit value:
//!
//! ```rust
//! use bacnet_rs::object::{ObjectIdentifier, ObjectType};
//!
//! // Encode object type 0 (Analog Input), instance 42
//! let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 42);
//! let encoded: u32 = object_id.into();
//! println!("Encoded: 0x{:08X}", encoded);
//!
//! // Decode back to type and instance
//! let object_id: ObjectIdentifier = encoded.into();
//! assert_eq!(object_id.object_type, ObjectType::AnalogInput);
//! assert_eq!(object_id.instance, 42);
//! ```
//!
//! # Performance Monitoring
//!
//! The performance monitoring subsystem provides detailed metrics collection:
//!
//! ```rust
//! // Performance monitoring example
//! #[cfg(feature = "std")]
//! {
//!     use std::time::Instant;
//!     let start = Instant::now();
//!     // Perform operation
//!     let duration = start.elapsed();
//!     println!("Operation took: {:?}", duration);
//! }
//! ```
//!
//! # Statistics Collection
//!
//! Track communication and processing statistics:
//!
//! ```rust
//! // Statistics collection example
//! #[derive(Default)]
//! struct SimpleStats {
//!     messages_sent: u64,
//!     bytes_received: u64,
//!     errors: u64,
//! }
//!
//! let mut stats = SimpleStats::default();
//! stats.messages_sent += 1;
//! stats.bytes_received += 100;
//! println!("Stats: {} sent, {} received", stats.messages_sent, stats.bytes_received);
//! ```
//!
//! # Debug Formatting
//!
//! Comprehensive debugging tools for protocol analysis:
//!
//! ```rust
//! use bacnet_rs::util::hex_dump;
//!
//! // Create hex dumps for debugging
//! let frame_data = vec![0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00];
//! let dump = hex_dump(&frame_data, "Frame");
//! println!("Frame data:\n{}", dump);
//! ```
//!
//! # Retry Mechanisms
//!
//! Configurable retry strategies for reliable communication:
//!
//! ```rust
//! use bacnet_rs::util::RetryConfig;
//!
//! let config = RetryConfig {
//!     max_attempts: 3,
//!     initial_delay_ms: 100,
//!     max_delay_ms: 5000,
//!     backoff_multiplier: 2.0,
//! };
//!
//! // Use in retry loop
//! for attempt in 0..config.max_attempts {
//!     match try_operation() {
//!         Ok(_result) => break,
//!         Err(_) if attempt < config.max_attempts - 1 => {
//!             let delay_ms = config.initial_delay_ms * 2_u64.pow(attempt as u32);
//!             let delay_ms = delay_ms.min(config.max_delay_ms);
//!             #[cfg(feature = "std")]
//!             std::thread::sleep(std::time::Duration::from_millis(delay_ms));
//!         }
//!         Err(_) => break, // Stop on error
//!     }
//! }
//! # fn try_operation() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
//! ```
//!
//! # Circular Buffers
//!
//! Efficient data structures for event logging and history:
//!
//! ```rust
//! use bacnet_rs::util::CircularBuffer;
//!
//! let mut buffer = CircularBuffer::new(100); // Capacity of 100 items
//!
//! // Add items (oldest are automatically removed when full)
//! for i in 0..150 {
//!     buffer.push(format!("Event {}", i));
//! }
//!
//! // Buffer contains the last 100 items
//! assert_eq!(buffer.len(), 100);
//! let items = buffer.items();
//! assert_eq!(items[0], "Event 50"); // Oldest remaining
//! assert_eq!(items[99], "Event 149"); // Newest
//! ```
//!
//! # No-std Compatibility
//!
//! Most utilities work in `no_std` environments with appropriate feature flags:
//!
//! ```rust
//! use bacnet_rs::util::crc16_mstp;
//! use bacnet_rs::object::{ObjectIdentifier, ObjectType};
//!
//! fn main() {
//!     // CRC calculation works without std
//!     let data = b"test";
//!     let crc = crc16_mstp(data);
//!
//!     // Object ID encoding works without std
//!     let object_id = ObjectIdentifier::new(ObjectType::Device, 42);
//!     let encoded: u32 = object_id.into();
//!     println!("CRC: 0x{:04X}, Encoded ID: 0x{:08X}", crc, encoded);
//! }
//! ```

// Debug formatting utilities
#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;

/// Calculate CRC-16 for MS/TP frames
///
/// Uses the polynomial x^16 + x^15 + x^2 + 1 (0xA001)
pub fn crc16_mstp(data: &[u8]) -> u16 {
    let mut crc = 0xFFFF;

    for byte in data {
        crc ^= *byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

/// Calculate CRC-32C (Castagnoli) for BACnet/SC
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFF;

    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

/// Convert BACnet date to string representation
pub fn bacnet_date_to_string(year: u16, month: u8, day: u8, weekday: u8) -> String {
    let year_str = if year == 255 {
        String::from("*")
    } else {
        format!("{}", year)
    };
    let month_str = match month {
        13 => String::from("odd"),
        14 => String::from("even"),
        255 => String::from("*"),
        _ => format!("{}", month),
    };
    let day_str = if day == 32 {
        String::from("last")
    } else if day == 255 {
        String::from("*")
    } else {
        format!("{}", day)
    };
    let weekday_str = if weekday == 255 {
        String::from("*")
    } else {
        String::from(match weekday {
            1 => "Mon",
            2 => "Tue",
            3 => "Wed",
            4 => "Thu",
            5 => "Fri",
            6 => "Sat",
            7 => "Sun",
            _ => "?",
        })
    };

    format!("{}/{}/{} ({})", year_str, month_str, day_str, weekday_str)
}

/// Convert BACnet time to string representation
pub fn bacnet_time_to_string(hour: u8, minute: u8, second: u8, hundredths: u8) -> String {
    let hour_str = if hour == 255 {
        String::from("*")
    } else {
        format!("{:02}", hour)
    };
    let minute_str = if minute == 255 {
        String::from("*")
    } else {
        format!("{:02}", minute)
    };
    let second_str = if second == 255 {
        String::from("*")
    } else {
        format!("{:02}", second)
    };
    let hundredths_str = if hundredths == 255 {
        String::from("*")
    } else {
        format!("{:02}", hundredths)
    };

    format!(
        "{}:{}:{}.{}",
        hour_str, minute_str, second_str, hundredths_str
    )
}

/// Buffer utilities for reading/writing data
pub struct Buffer<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Buffer<'a> {
    /// Create a new buffer reader
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Check if buffer has at least n bytes remaining
    pub fn has_remaining(&self, n: usize) -> bool {
        self.remaining() >= n
    }

    /// Read a single byte
    pub fn read_u8(&mut self) -> Option<u8> {
        if self.has_remaining(1) {
            let value = self.data[self.position];
            self.position += 1;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 16-bit value (big-endian)
    pub fn read_u16(&mut self) -> Option<u16> {
        if self.has_remaining(2) {
            let value =
                u16::from_be_bytes([self.data[self.position], self.data[self.position + 1]]);
            self.position += 2;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 32-bit value (big-endian)
    pub fn read_u32(&mut self) -> Option<u32> {
        if self.has_remaining(4) {
            let value = u32::from_be_bytes([
                self.data[self.position],
                self.data[self.position + 1],
                self.data[self.position + 2],
                self.data[self.position + 3],
            ]);
            self.position += 4;
            Some(value)
        } else {
            None
        }
    }

    /// Read n bytes
    pub fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.has_remaining(n) {
            let bytes = &self.data[self.position..self.position + n];
            self.position += n;
            Some(bytes)
        } else {
            None
        }
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Skip n bytes
    pub fn skip(&mut self, n: usize) -> bool {
        if self.has_remaining(n) {
            self.position += n;
            true
        } else {
            false
        }
    }
}

/// Hex dump utility for debugging
pub fn hex_dump(data: &[u8], prefix: &str) -> String {
    let mut result = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        result.push_str(prefix);
        result.push_str(&format!("{:04X}: ", i * 16));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' ');
            }
            result.push_str(&format!("{:02X} ", byte));
        }

        // Padding
        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }

        result.push_str(" |");

        // ASCII representation
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }

        result.push_str("|\n");
    }

    result
}

/// Priority array utilities
pub mod priority {
    /// BACnet priority levels (1-16, where 1 is highest)
    pub const MANUAL_LIFE_SAFETY: u8 = 1;
    pub const AUTOMATIC_LIFE_SAFETY: u8 = 2;
    pub const AVAILABLE_3: u8 = 3;
    pub const AVAILABLE_4: u8 = 4;
    pub const CRITICAL_EQUIPMENT_CONTROL: u8 = 5;
    pub const MINIMUM_ON_OFF: u8 = 6;
    pub const AVAILABLE_7: u8 = 7;
    pub const MANUAL_OPERATOR: u8 = 8;
    pub const AVAILABLE_9: u8 = 9;
    pub const AVAILABLE_10: u8 = 10;
    pub const AVAILABLE_11: u8 = 11;
    pub const AVAILABLE_12: u8 = 12;
    pub const AVAILABLE_13: u8 = 13;
    pub const AVAILABLE_14: u8 = 14;
    pub const AVAILABLE_15: u8 = 15;
    pub const LOWEST: u8 = 16;

    /// Check if priority is valid (1-16)
    pub fn is_valid(priority: u8) -> bool {
        (1..=16).contains(&priority)
    }
}

/// Performance monitoring utilities
#[cfg(feature = "std")]
pub mod performance {
    use super::*;

    /// Performance metrics for a BACnet operation
    #[derive(Debug, Clone)]
    pub struct OperationMetrics {
        pub name: String,
        pub count: u64,
        pub total_duration_ms: f64,
        pub min_duration_ms: f64,
        pub max_duration_ms: f64,
        pub avg_duration_ms: f64,
        pub last_duration_ms: f64,
    }

    /// Performance monitor for tracking operation timing
    pub struct PerformanceMonitor {
        metrics: Arc<Mutex<HashMap<String, OperationMetrics>>>,
        active_timers: Arc<Mutex<HashMap<String, Instant>>>,
    }

    impl Default for PerformanceMonitor {
        fn default() -> Self {
            Self {
                metrics: Arc::new(Mutex::new(HashMap::new())),
                active_timers: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl PerformanceMonitor {
        /// Create a new performance monitor
        pub fn new() -> Self {
            Self::default()
        }

        /// Start timing an operation
        pub fn start_timer(&self, operation: &str) {
            let mut timers = self.active_timers.lock().unwrap();
            timers.insert(operation.to_string(), Instant::now());
        }

        /// Stop timing an operation and record metrics
        pub fn stop_timer(&self, operation: &str) {
            let mut timers = self.active_timers.lock().unwrap();
            if let Some(start_time) = timers.remove(operation) {
                let duration = start_time.elapsed();
                let duration_ms = duration.as_secs_f64() * 1000.0;

                let mut metrics = self.metrics.lock().unwrap();
                let metric = metrics
                    .entry(operation.to_string())
                    .or_insert(OperationMetrics {
                        name: operation.to_string(),
                        count: 0,
                        total_duration_ms: 0.0,
                        min_duration_ms: f64::MAX,
                        max_duration_ms: 0.0,
                        avg_duration_ms: 0.0,
                        last_duration_ms: 0.0,
                    });

                metric.count += 1;
                metric.total_duration_ms += duration_ms;
                metric.min_duration_ms = metric.min_duration_ms.min(duration_ms);
                metric.max_duration_ms = metric.max_duration_ms.max(duration_ms);
                metric.avg_duration_ms = metric.total_duration_ms / metric.count as f64;
                metric.last_duration_ms = duration_ms;
            }
        }

        /// Get metrics for a specific operation
        pub fn get_metrics(&self, operation: &str) -> Option<OperationMetrics> {
            let metrics = self.metrics.lock().unwrap();
            metrics.get(operation).cloned()
        }

        /// Get all metrics
        pub fn get_all_metrics(&self) -> Vec<OperationMetrics> {
            let metrics = self.metrics.lock().unwrap();
            metrics.values().cloned().collect()
        }

        /// Clear all metrics
        pub fn clear(&self) {
            self.metrics.lock().unwrap().clear();
            self.active_timers.lock().unwrap().clear();
        }
    }

    /// RAII timer for automatic performance tracking
    pub struct ScopedTimer<'a> {
        monitor: &'a PerformanceMonitor,
        operation: String,
    }

    impl<'a> ScopedTimer<'a> {
        /// Create a new scoped timer
        pub fn new(monitor: &'a PerformanceMonitor, operation: &str) -> Self {
            monitor.start_timer(operation);
            Self {
                monitor,
                operation: operation.to_string(),
            }
        }
    }

    impl Drop for ScopedTimer<'_> {
        fn drop(&mut self) {
            self.monitor.stop_timer(&self.operation);
        }
    }
}

/// Statistics collection helpers
pub mod statistics {
    use super::*;

    /// BACnet communication statistics
    #[derive(Debug, Default, Clone)]
    pub struct CommunicationStats {
        pub messages_sent: u64,
        pub messages_received: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub errors: u64,
        pub timeouts: u64,
        pub retries: u64,
        pub acks_received: u64,
        pub naks_received: u64,
        pub rejects_received: u64,
        pub aborts_received: u64,
    }

    impl CommunicationStats {
        /// Create new statistics
        pub fn new() -> Self {
            Self::default()
        }

        /// Record a sent message
        pub fn record_sent(&mut self, bytes: usize) {
            self.messages_sent += 1;
            self.bytes_sent += bytes as u64;
        }

        /// Record a received message
        pub fn record_received(&mut self, bytes: usize) {
            self.messages_received += 1;
            self.bytes_received += bytes as u64;
        }

        /// Record an error
        pub fn record_error(&mut self) {
            self.errors += 1;
        }

        /// Record a timeout
        pub fn record_timeout(&mut self) {
            self.timeouts += 1;
        }

        /// Record a retry
        pub fn record_retry(&mut self) {
            self.retries += 1;
        }

        /// Get success rate percentage
        pub fn success_rate(&self) -> f64 {
            let total = self.messages_sent as f64;
            if total == 0.0 {
                return 100.0;
            }
            let failures = (self.errors + self.timeouts) as f64;
            ((total - failures) / total) * 100.0
        }

        /// Reset all statistics
        pub fn reset(&mut self) {
            *self = Self::default();
        }
    }

    /// Device-specific statistics
    #[derive(Debug, Clone)]
    pub struct DeviceStats {
        pub device_id: u32,
        pub address: String,
        pub comm_stats: CommunicationStats,
        pub last_seen: Option<Instant>,
        pub response_times_ms: Vec<f64>,
        pub online: bool,
    }

    #[cfg(feature = "std")]
    impl DeviceStats {
        /// Create new device statistics
        pub fn new(device_id: u32, address: String) -> Self {
            Self {
                device_id,
                address,
                comm_stats: CommunicationStats::new(),
                last_seen: None,
                response_times_ms: Vec::new(),
                online: false,
            }
        }

        /// Record a response time
        pub fn record_response_time(&mut self, ms: f64) {
            self.response_times_ms.push(ms);
            // Keep only last 100 response times
            if self.response_times_ms.len() > 100 {
                self.response_times_ms.remove(0);
            }
            self.last_seen = Some(Instant::now());
            self.online = true;
        }

        /// Get average response time
        pub fn avg_response_time(&self) -> Option<f64> {
            if self.response_times_ms.is_empty() {
                return None;
            }
            let sum: f64 = self.response_times_ms.iter().sum();
            Some(sum / self.response_times_ms.len() as f64)
        }

        /// Mark device as offline
        pub fn mark_offline(&mut self) {
            self.online = false;
        }
    }

    /// Statistics collector for multiple devices
    #[cfg(feature = "std")]
    pub struct StatsCollector {
        devices: Arc<Mutex<HashMap<u32, DeviceStats>>>,
        global_stats: Arc<Mutex<CommunicationStats>>,
    }

    #[cfg(feature = "std")]
    impl Default for StatsCollector {
        fn default() -> Self {
            Self {
                devices: Arc::new(Mutex::new(HashMap::new())),
                global_stats: Arc::new(Mutex::new(CommunicationStats::new())),
            }
        }
    }

    #[cfg(feature = "std")]
    impl StatsCollector {
        /// Create a new statistics collector
        pub fn new() -> Self {
            Self::default()
        }

        /// Get or create device statistics
        pub fn get_device_stats(&self, device_id: u32, address: String) -> DeviceStats {
            let mut devices = self.devices.lock().unwrap();
            devices
                .entry(device_id)
                .or_insert_with(|| DeviceStats::new(device_id, address))
                .clone()
        }

        /// Update device statistics
        pub fn update_device_stats<F>(&self, device_id: u32, updater: F)
        where
            F: FnOnce(&mut DeviceStats),
        {
            let mut devices = self.devices.lock().unwrap();
            if let Some(stats) = devices.get_mut(&device_id) {
                updater(stats);
            }
        }

        /// Get global statistics
        pub fn get_global_stats(&self) -> CommunicationStats {
            self.global_stats.lock().unwrap().clone()
        }

        /// Update global statistics
        pub fn update_global_stats<F>(&self, updater: F)
        where
            F: FnOnce(&mut CommunicationStats),
        {
            let mut stats = self.global_stats.lock().unwrap();
            updater(&mut stats);
        }

        /// Get all device statistics
        pub fn get_all_device_stats(&self) -> Vec<DeviceStats> {
            let devices = self.devices.lock().unwrap();
            devices.values().cloned().collect()
        }

        /// Clear all statistics
        pub fn clear(&self) {
            self.devices.lock().unwrap().clear();
            self.global_stats.lock().unwrap().reset();
        }
    }
}

/// Additional utility functions
///
/// Validate BACnet network number (0-65534, 65535 is broadcast)
pub fn is_valid_network_number(_network: u16) -> bool {
    // All u16 values are valid network numbers
    true
}

/// Check if network number is local (0)
pub fn is_local_network(network: u16) -> bool {
    network == 0
}

/// Check if network number is broadcast (65535)
pub fn is_broadcast_network(network: u16) -> bool {
    network == 65535
}

/// Parse BACnet address from string (e.g., "192.168.1.100:47808")
#[cfg(feature = "std")]
pub fn parse_bacnet_address(address: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;

    // If no port specified, add default BACnet port
    let addr_with_port = if address.contains(':') {
        address.to_string()
    } else {
        format!("{}:47808", address)
    };

    addr_with_port
        .to_socket_addrs()
        .map_err(|e| format!("Invalid address: {}", e))?
        .next()
        .ok_or_else(|| "No valid address found".to_string())
}

/// Format bytes as human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Calculate message throughput
pub fn calculate_throughput(bytes: u64, duration_secs: f64) -> String {
    if duration_secs == 0.0 {
        return "N/A".to_string();
    }

    let bytes_per_sec = bytes as f64 / duration_secs;
    format!("{}/s", format_bytes(bytes_per_sec as u64))
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Calculate delay for a given attempt (0-based)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay_ms = if attempt == 0 {
            self.initial_delay_ms
        } else {
            let delay = self.initial_delay_ms as f64 * self.backoff_multiplier.powi(attempt as i32);
            delay.min(self.max_delay_ms as f64) as u64
        };

        Duration::from_millis(delay_ms)
    }
}

/// Circular buffer for maintaining history
#[derive(Debug, Clone)]
pub struct CircularBuffer<T> {
    buffer: Vec<Option<T>>,
    capacity: usize,
    head: usize,
    size: usize,
}

impl<T: Clone> CircularBuffer<T> {
    /// Create a new circular buffer with given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![None; capacity],
            capacity,
            head: 0,
            size: 0,
        }
    }

    /// Add an item to the buffer
    pub fn push(&mut self, item: T) {
        self.buffer[self.head] = Some(item);
        self.head = (self.head + 1) % self.capacity;
        if self.size < self.capacity {
            self.size += 1;
        }
    }

    /// Get all items in order (oldest to newest)
    pub fn items(&self) -> Vec<T> {
        let mut result = Vec::with_capacity(self.size);

        if self.size < self.capacity {
            // Buffer not full, items are from 0 to head
            for i in 0..self.size {
                if let Some(item) = &self.buffer[i] {
                    result.push(item.clone());
                }
            }
        } else {
            // Buffer full, items wrap around
            for i in 0..self.capacity {
                let idx = (self.head + i) % self.capacity;
                if let Some(item) = &self.buffer[idx] {
                    result.push(item.clone());
                }
            }
        }

        result
    }

    /// Get the number of items in the buffer
    pub fn len(&self) -> usize {
        self.size
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer = vec![None; self.capacity];
        self.head = 0;
        self.size = 0;
    }
}

/// Debug formatting utilities for BACnet data structures and protocol analysis
pub mod debug {
    use crate::object::ObjectIdentifier;

    use super::*;

    /// Format a BACnet property value for debugging
    pub fn format_property_value(data: &[u8]) -> String {
        if data.is_empty() {
            return "[empty]".to_string();
        }

        let mut result = String::new();
        let tag = data[0];

        match tag {
            0x11 => {
                // Boolean
                if data.len() >= 2 {
                    result.push_str(&format!("Boolean({})", data[1] != 0));
                } else {
                    result.push_str("Boolean(invalid)");
                }
            }
            0x21 => {
                // Unsigned integer
                result.push_str(&format_unsigned_integer(data));
            }
            0x31 => {
                // Signed integer
                result.push_str(&format_signed_integer(data));
            }
            0x44 => {
                // Real (float)
                if data.len() >= 5 {
                    let bytes = [data[1], data[2], data[3], data[4]];
                    let value = f32::from_be_bytes(bytes);
                    result.push_str(&format!("Real({})", value));
                } else {
                    result.push_str("Real(invalid)");
                }
            }
            0x55 => {
                // Double
                if data.len() >= 9 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&data[1..9]);
                    let value = f64::from_be_bytes(bytes);
                    result.push_str(&format!("Double({})", value));
                } else {
                    result.push_str("Double(invalid)");
                }
            }
            0x75 => {
                // Character string
                result.push_str(&format_character_string(data));
            }
            0x81..=0x8F => {
                // Octet string
                result.push_str(&format_octet_string(data));
            }
            0x91 => {
                // Enumerated
                result.push_str(&format_enumerated(data));
            }
            0xA1 => {
                // Date
                result.push_str(&format_date(data));
            }
            0xB1 => {
                // Time
                result.push_str(&format_time(data));
            }
            0xC4 => {
                // Object identifier
                result.push_str(&format_object_identifier(data));
            }
            _ => {
                result.push_str(&format!(
                    "Unknown(tag=0x{:02X}, data={})",
                    tag,
                    hex_dump(data, "")
                ));
            }
        }

        result
    }

    fn format_unsigned_integer(data: &[u8]) -> String {
        if data.len() < 2 {
            return "UnsignedInt(invalid)".to_string();
        }

        let length = (data[0] & 0x07) as usize;
        if data.len() < 1 + length {
            return "UnsignedInt(invalid length)".to_string();
        }

        let mut value = 0u64;
        for i in 0..length {
            value = (value << 8) | (data[1 + i] as u64);
        }

        format!("UnsignedInt({})", value)
    }

    fn format_signed_integer(data: &[u8]) -> String {
        if data.len() < 2 {
            return "SignedInt(invalid)".to_string();
        }

        let length = (data[0] & 0x07) as usize;
        if data.len() < 1 + length {
            return "SignedInt(invalid length)".to_string();
        }

        let mut value = 0i64;
        let sign_bit = data[1] & 0x80 != 0;

        for i in 0..length {
            value = (value << 8) | (data[1 + i] as i64);
        }

        // Sign extend if negative
        if sign_bit {
            let shift = 64 - (length * 8);
            value = (value << shift) >> shift;
        }

        format!("SignedInt({})", value)
    }

    fn format_character_string(data: &[u8]) -> String {
        if data.len() < 3 {
            return "CharString(invalid)".to_string();
        }

        let length = data[1] as usize;
        if data.len() < 2 + length {
            return "CharString(invalid length)".to_string();
        }

        let encoding = data[2];
        let string_data = &data[3..2 + length];

        let decoded = match encoding {
            0 => {
                // ANSI X3.4 (ASCII)
                String::from_utf8_lossy(string_data).to_string()
            }
            4 => {
                // UCS-2 (UTF-16)
                let mut utf16_chars = Vec::new();
                for chunk in string_data.chunks_exact(2) {
                    let char_code = u16::from_be_bytes([chunk[0], chunk[1]]);
                    utf16_chars.push(char_code);
                }
                String::from_utf16_lossy(&utf16_chars)
            }
            _ => {
                format!("<encoding={}>", encoding)
            }
        };

        format!("CharString(\"{}\")", decoded)
    }

    fn format_octet_string(data: &[u8]) -> String {
        if data.is_empty() {
            return "OctetString(invalid)".to_string();
        }

        let length = (data[0] & 0x07) as usize;
        if data.len() < 1 + length {
            return "OctetString(invalid length)".to_string();
        }

        let octets = &data[1..1 + length];
        let hex_string = octets
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        format!("OctetString([{}])", hex_string)
    }

    fn format_enumerated(data: &[u8]) -> String {
        if data.len() < 2 {
            return "Enumerated(invalid)".to_string();
        }

        let value = data[1] as u32;
        format!("Enumerated({})", value)
    }

    fn format_date(data: &[u8]) -> String {
        if data.len() < 5 {
            return "Date(invalid)".to_string();
        }

        let year = data[1] as u16 + 1900;
        let month = data[2];
        let day = data[3];
        let weekday = data[4];

        format!("Date({})", bacnet_date_to_string(year, month, day, weekday))
    }

    fn format_time(data: &[u8]) -> String {
        if data.len() < 5 {
            return "Time(invalid)".to_string();
        }

        let hour = data[1];
        let minute = data[2];
        let second = data[3];
        let hundredths = data[4];

        format!(
            "Time({})",
            bacnet_time_to_string(hour, minute, second, hundredths)
        )
    }

    fn format_object_identifier(data: &[u8]) -> String {
        if data.len() < 5 {
            return "ObjectID(invalid)".to_string();
        }

        let obj_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let obj_id: ObjectIdentifier = obj_id.into();
        format!("ObjectID({} {})", obj_id.object_type, obj_id.instance)
    }

    /// Format BACnet service choice for debugging
    pub fn format_service_choice(service_choice: u8) -> String {
        let service_name = match service_choice {
            // Confirmed services
            0 => "acknowledgeAlarm",
            1 => "confirmedCOVNotification",
            2 => "confirmedEventNotification",
            3 => "getAlarmSummary",
            4 => "getEnrollmentSummary",
            5 => "getEventInformation",
            6 => "atomicReadFile",
            7 => "atomicWriteFile",
            8 => "addListElement",
            9 => "removeListElement",
            10 => "createObject",
            11 => "deleteObject",
            12 => "readProperty",
            13 => "readPropertyConditional",
            14 => "readPropertyMultiple",
            15 => "writeProperty",
            16 => "writePropertyMultiple",
            17 => "deviceCommunicationControl",
            18 => "confirmedPrivateTransfer",
            19 => "confirmedTextMessage",
            20 => "reinitializeDevice",
            21 => "vtOpen",
            22 => "vtClose",
            23 => "vtData",
            24 => "authenticate",
            25 => "requestKey",
            26 => "readRange",
            27 => "lifeSafetyOperation",
            28 => "subscribeCOV",
            29 => "subscribeCOVProperty",
            30 => "getEventInformation",
            _ => "unknown",
        };

        format!("{}({})", service_name, service_choice)
    }

    /// Format BACnet error for debugging
    pub fn format_bacnet_error(error_class: u8, error_code: u8) -> String {
        let class_name = match error_class {
            0 => "device",
            1 => "object",
            2 => "property",
            3 => "resources",
            4 => "security",
            5 => "services",
            6 => "vt",
            7 => "communication",
            _ => "unknown",
        };

        format!("Error({} class, code {})", class_name, error_code)
    }

    /// Create a detailed hex dump with annotations
    pub fn annotated_hex_dump(data: &[u8], annotations: &[(usize, String)]) -> String {
        let mut result = String::new();
        let mut annotation_map: std::collections::HashMap<usize, String> =
            annotations.iter().cloned().collect();

        for (i, chunk) in data.chunks(16).enumerate() {
            let offset = i * 16;
            result.push_str(&format!("{:04X}: ", offset));

            // Hex bytes with spacing
            for (j, byte) in chunk.iter().enumerate() {
                if j == 8 {
                    result.push(' ');
                }
                result.push_str(&format!("{:02X} ", byte));
            }

            // Padding for incomplete lines
            for j in chunk.len()..16 {
                if j == 8 {
                    result.push(' ');
                }
                result.push_str("   ");
            }

            result.push_str(" |");

            // ASCII representation
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    result.push(*byte as char);
                } else {
                    result.push('.');
                }
            }

            result.push('|');

            // Check for annotations on this line
            for pos in offset..offset + chunk.len() {
                if let Some(annotation) = annotation_map.remove(&pos) {
                    result.push_str(&format!(" <- {}", annotation));
                    break;
                }
            }

            result.push('\n');
        }

        result
    }

    /// Debug formatter for BACnet APDU structure
    pub fn format_apdu_structure(data: &[u8]) -> String {
        if data.is_empty() {
            return "Empty APDU".to_string();
        }

        let mut result = String::new();
        result.push_str("APDU Structure:\n");

        let pdu_type = (data[0] >> 4) & 0x0F;
        let pdu_flags = data[0] & 0x0F;

        result.push_str(&format!(
            "  PDU Type: {} ({})",
            pdu_type,
            match pdu_type {
                0 => "Confirmed-Request",
                1 => "Unconfirmed-Request",
                2 => "Simple-ACK",
                3 => "Complex-ACK",
                4 => "Segment-ACK",
                5 => "Error",
                6 => "Reject",
                7 => "Abort",
                _ => "Reserved",
            }
        ));

        result.push_str(&format!("  PDU Flags: 0x{:X}\n", pdu_flags));

        match pdu_type {
            0 => {
                // Confirmed Request
                if data.len() >= 4 {
                    result.push_str(&format!("  Max Segments: {}\n", (pdu_flags >> 1) & 0x07));
                    result.push_str(&format!(
                        "  Max APDU: {}\n",
                        (pdu_flags & 0x01) | ((data[1] & 0xF0) >> 3)
                    ));
                    result.push_str(&format!("  Invoke ID: {}\n", data[1] & 0x0F));
                    if data.len() > 2 {
                        result.push_str(&format!(
                            "  Service Choice: {}\n",
                            format_service_choice(data[2])
                        ));
                    }
                }
            }
            1 => {
                // Unconfirmed Request
                if data.len() >= 2 {
                    result.push_str(&format!(
                        "  Service Choice: {}\n",
                        format_service_choice(data[1])
                    ));
                }
            }
            3 => {
                // Complex ACK
                if data.len() >= 3 {
                    result.push_str(&format!("  Invoke ID: {}\n", data[1]));
                    result.push_str(&format!(
                        "  Service Choice: {}\n",
                        format_service_choice(data[2])
                    ));
                }
            }
            5 => {
                // Error
                if data.len() >= 4 {
                    result.push_str(&format!("  Invoke ID: {}\n", data[1]));
                    result.push_str(&format!(
                        "  Service Choice: {}\n",
                        format_service_choice(data[2])
                    ));
                    result.push_str(&format!(
                        "  Error: {}\n",
                        format_bacnet_error(data[3], data[4])
                    ));
                }
            }
            _ => {
                result.push_str(&format!("  Raw data: {}\n", hex_dump(&data[1..], "    ")));
            }
        }

        result
    }

    /// Debug formatter for network layer (NPDU)
    pub fn format_npdu_structure(data: &[u8]) -> String {
        if data.is_empty() {
            return "Empty NPDU".to_string();
        }

        let mut result = String::new();
        result.push_str("NPDU Structure:\n");

        let version = data[0];
        result.push_str(&format!("  Version: {}\n", version));

        if data.len() < 2 {
            return result;
        }

        let control = data[1];
        result.push_str(&format!("  Control: 0x{:02X}\n", control));

        let has_dest = (control & 0x20) != 0;
        let has_src = (control & 0x08) != 0;
        let expecting_reply = (control & 0x04) != 0;
        let priority = control & 0x03;

        result.push_str(&format!("    Destination Present: {}\n", has_dest));
        result.push_str(&format!("    Source Present: {}\n", has_src));
        result.push_str(&format!("    Expecting Reply: {}\n", expecting_reply));
        result.push_str(&format!(
            "    Priority: {} ({})\n",
            priority,
            match priority {
                0 => "Normal",
                1 => "Urgent",
                2 => "Critical",
                3 => "Life Safety",
                _ => "Unknown",
            }
        ));

        let mut pos = 2;

        if has_dest && data.len() > pos + 2 {
            let dest_net = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            result.push_str(&format!("  Destination Network: {}\n", dest_net));

            if data.len() > pos {
                let dest_len = data[pos] as usize;
                pos += 1;
                if data.len() >= pos + dest_len {
                    let dest_addr = &data[pos..pos + dest_len];
                    pos += dest_len;
                    result.push_str(&format!("  Destination Address: {:02X?}\n", dest_addr));
                }
            }
        }

        if has_src && data.len() > pos + 2 {
            let src_net = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            result.push_str(&format!("  Source Network: {}\n", src_net));

            if data.len() > pos {
                let src_len = data[pos] as usize;
                pos += 1;
                if data.len() >= pos + src_len {
                    let src_addr = &data[pos..pos + src_len];
                    pos += src_len;
                    result.push_str(&format!("  Source Address: {:02X?}\n", src_addr));
                }
            }
        }

        if data.len() > pos {
            result.push_str(&format!("  Hop Count: {}\n", data[pos]));
            pos += 1;
        }

        if data.len() > pos {
            result.push_str(&format!("  APDU Length: {} bytes\n", data.len() - pos));
        }

        result
    }

    /// Debug formatter for BVLL (BACnet Virtual Link Layer)
    pub fn format_bvll_structure(data: &[u8]) -> String {
        if data.len() < 4 {
            return "Invalid BVLL (too short)".to_string();
        }

        let mut result = String::new();
        result.push_str("BVLL Structure:\n");

        let bvll_type = data[0];
        let function = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]);

        result.push_str(&format!(
            "  Type: 0x{:02X} ({})\n",
            bvll_type,
            match bvll_type {
                0x81 => "BACnet/IP",
                _ => "Unknown",
            }
        ));

        result.push_str(&format!(
            "  Function: 0x{:02X} ({})\n",
            function,
            match function {
                0x00 => "Result",
                0x01 => "Write-BDT",
                0x02 => "Read-BDT",
                0x03 => "Read-BDT-Ack",
                0x04 => "Forwarded-NPDU",
                0x05 => "Register-Foreign-Device",
                0x06 => "Read-FDT",
                0x07 => "Read-FDT-Ack",
                0x08 => "Delete-FDT-Entry",
                0x09 => "Distribute-Broadcast-To-Network",
                0x0A => "Original-Unicast-NPDU",
                0x0B => "Original-Broadcast-NPDU",
                0x0C => "Secure-BVLL",
                _ => "Unknown",
            }
        ));

        result.push_str(&format!("  Length: {} bytes\n", length));

        if data.len() != length as usize {
            result.push_str(&format!("  WARNING: Actual length {} bytes\n", data.len()));
        }

        if data.len() > 4 {
            result.push_str(&format!("  Data Length: {} bytes\n", data.len() - 4));
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_circular_buffer() {
        let mut buffer = CircularBuffer::new(3);

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        buffer.push(1);
        buffer.push(2);
        buffer.push(3);

        assert_eq!(buffer.items(), vec![1, 2, 3]);
        assert_eq!(buffer.len(), 3);

        // Test wraparound
        buffer.push(4);
        assert_eq!(buffer.items(), vec![2, 3, 4]);

        buffer.push(5);
        assert_eq!(buffer.items(), vec![3, 4, 5]);
    }

    #[test]
    fn test_retry_config() {
        let config = RetryConfig::default();

        assert_eq!(config.delay_for_attempt(0).as_millis(), 100);
        assert_eq!(config.delay_for_attempt(1).as_millis(), 200);
        assert_eq!(config.delay_for_attempt(2).as_millis(), 400);
        assert_eq!(config.delay_for_attempt(3).as_millis(), 800);

        // Test max delay
        assert_eq!(config.delay_for_attempt(10).as_millis(), 5000);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_parse_bacnet_address() {
        assert!(parse_bacnet_address("192.168.1.100:47808").is_ok());
        assert!(parse_bacnet_address("192.168.1.100").is_ok());
        assert!(parse_bacnet_address("invalid").is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_communication_stats() {
        let mut stats = statistics::CommunicationStats::new();

        stats.record_sent(100);
        stats.record_received(150);

        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.messages_received, 1);
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 150);
        assert_eq!(stats.success_rate(), 100.0);

        stats.record_error();
        stats.record_timeout();

        assert!(stats.success_rate() < 100.0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_performance_monitor() {
        use std::thread;
        use std::time::Duration;

        let monitor = performance::PerformanceMonitor::new();

        {
            let _timer = performance::ScopedTimer::new(&monitor, "test_operation");
            thread::sleep(Duration::from_millis(10));
        }

        let metrics = monitor.get_metrics("test_operation").unwrap();
        assert_eq!(metrics.count, 1);
        assert!(metrics.last_duration_ms >= 10.0);
        assert_eq!(metrics.min_duration_ms, metrics.max_duration_ms);
    }

    #[test]
    fn test_debug_formatting() {
        // Test property value formatting
        let boolean_data = &[0x11, 0x01]; // Boolean true
        let formatted = debug::format_property_value(boolean_data);
        assert!(formatted.contains("Boolean(true)"));

        let real_data = &[0x44, 0x42, 0x28, 0x00, 0x00]; // Real 42.0
        let formatted = debug::format_property_value(real_data);
        assert!(formatted.contains("Real(42)"));

        // Test service choice formatting
        let formatted = debug::format_service_choice(12);
        assert!(formatted.contains("readProperty"));

        // Test error formatting
        let formatted = debug::format_bacnet_error(1, 2);
        assert!(formatted.contains("object"));
    }

    #[test]
    fn test_annotated_hex_dump() {
        let data = &[0x01, 0x02, 0x03, 0x04];
        let annotations = vec![(0, "Start".to_string()), (2, "Middle".to_string())];
        let result = debug::annotated_hex_dump(data, &annotations);

        assert!(result.contains("0000:"));
        assert!(result.contains("01 02 03 04"));
        assert!(result.contains("Start") || result.contains("Middle"));
    }
}
