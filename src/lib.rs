//! # BACnet-RS: A Complete BACnet Protocol Stack Implementation in Rust
//!
//! BACnet-RS is a comprehensive implementation of the BACnet (Building Automation and Control Networks)
//! protocol stack written in Rust. It provides a complete, standards-compliant BACnet implementation
//! suitable for both embedded systems and full-featured applications.
//!
//! ## Features
//!
//! - **Complete Protocol Stack**: Full implementation of BACnet layers (Application, Network, Data Link)
//! - **Multiple Data Link Support**: BACnet/IP, Ethernet, MS/TP, and more
//! - **Standards Compliant**: Implements ASHRAE Standard 135-2020
//! - **No-std Compatible**: Works in embedded environments without heap allocation
//! - **Async Support**: Optional async/await support with Tokio integration
//! - **Comprehensive Services**: Read/Write properties, Who-Is/I-Am, object discovery, and more
//! - **Debugging Tools**: Built-in protocol analyzers and debug formatters
//! - **Performance Monitoring**: Statistics collection and performance metrics
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use bacnet_rs::client::BacnetClient;
//! use std::net::{SocketAddr, IpAddr, Ipv4Addr};
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a BACnet client
//!     let client = BacnetClient::new()?;
//!
//!     // Discover a device at a specific address
//!     let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 47808);
//!     let device = client.discover_device(target_addr)?;
//!     println!("Found device: {}", device.vendor_name);
//!
//!     // Read object list from the device
//!     let objects = client.read_object_list(target_addr, device.device_id)?;
//!     println!("Device has {} objects", objects.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! The library is organized into several key modules:
//!
//! - [`datalink`]: Data link layer implementations (BACnet/IP, Ethernet, MS/TP)
//! - [`network`]: Network layer for routing and addressing
//! - [`transport`]: Transport layer with reliability and flow control
//! - [`service`]: BACnet services (confirmed and unconfirmed)
//! - [`object`]: BACnet object types and property handling
//! - [`client`]: High-level client API for applications
//! - [`util`]: Utilities for CRC, encoding, and debugging
//!
//! ## Data Link Types
//!
//! BACnet-RS supports multiple data link layer protocols:
//!
//! - **BACnet/IP**: UDP-based communication over IP networks (most common)
//! - **BACnet/Ethernet**: Direct Ethernet frame communication
//! - **MS/TP**: Master-Slave Token Passing over RS-485 serial networks
//! - **Point-to-Point**: Direct serial communication
//!
//! ## Examples
//!
//! The crate includes comprehensive examples in the `examples/` directory:
//!
//! - **Basic Examples**: Simple device creation and communication
//! - **Networking Examples**: Who-Is scans, transport demonstrations
//! - **Object Examples**: Device and object discovery, property reading
//! - **Debugging Examples**: Protocol analysis and debug formatting
//!
//! Run examples with:
//! ```bash
//! cargo run --example whois_scan
//! cargo run --example device_objects
//! ```
//!
//! ## Features
//!
//! - `std` (default): Enable standard library support
//! - `async` (default): Enable async/await support with Tokio
//! - `serde` (default): Enable serialization support
//! - `no-std`: Disable standard library for embedded use
//!
//! ## License
//!
//! Licensed under either of
//! - Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
//! - MIT License ([LICENSE-MIT](LICENSE-MIT))
//!
//! at your option.

#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(missing_docs)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Application layer protocol services and message handling
pub mod app;

/// Data link layer implementations for various BACnet physical networks
pub mod datalink;

/// BACnet encoding and decoding utilities for application tags and values
pub mod encoding;

/// Network layer for BACnet routing, addressing, and message forwarding
pub mod network;

/// BACnet object definitions, properties, and type system
pub mod object;

/// BACnet service definitions for confirmed and unconfirmed operations
pub mod service;

/// Transport layer providing reliability, segmentation, and flow control
pub mod transport;

/// Utility functions for CRC calculations, debugging, and performance monitoring
pub mod util;

/// BACnet vendor identification and device information
pub mod vendor;

/// High-level client API for BACnet communication (requires std feature)
#[cfg(feature = "std")]
pub mod client;

/// Property value decoders for various BACnet data types
pub mod property;

// Re-export main types for convenient access
pub use datalink::{DataLink, DataLinkAddress, DataLinkType};
pub use encoding::{ApplicationTag, EncodingError};
pub use object::{BacnetObject, ObjectType, PropertyIdentifier};
pub use service::{ConfirmedServiceChoice, ServiceError, UnconfirmedServiceChoice};
pub use vendor::{format_vendor_display, get_vendor_info, get_vendor_name, VendorInfo};

/// BACnet protocol version as defined in ASHRAE 135
pub const BACNET_PROTOCOL_VERSION: u8 = 1;

/// Maximum Application Protocol Data Unit size in bytes
/// This is the largest APDU that can be transmitted in a single BACnet message
pub const BACNET_MAX_APDU: usize = 1476;

/// Maximum Message Protocol Data Unit size in bytes  
/// This includes the NPDU header and APDU payload
pub const BACNET_MAX_MPDU: usize = 1497;

#[cfg(test)]
mod tests {
    use crate::object::ObjectIdentifier;
    use crate::util::crc16_mstp;
    use crate::{ApplicationTag, EncodingError, ObjectType};

    #[cfg(not(feature = "std"))]
    use alloc::format;

    #[test]
    fn test_no_std_types() {
        // Test that our types work in both std and no-std environments
        let tag = ApplicationTag::Boolean;
        assert_eq!(tag as u8, 1);

        let obj_type = ObjectType::AnalogInput;
        assert_eq!(u16::from(obj_type), 0);

        let obj_id = ObjectIdentifier::new(ObjectType::Device, 123);
        assert_eq!(obj_id.instance, 123);
        assert!(obj_id.is_valid());
    }

    #[test]
    fn test_encoding_error() {
        let err = EncodingError::BufferOverflow;
        // In no-std, we can still format errors
        let _ = format!("{:?}", err);
    }

    #[test]
    fn test_util_functions() {
        // Test CRC calculation
        let data = b"test";
        let crc = crc16_mstp(data);
        assert_ne!(crc, 0);
    }
}
