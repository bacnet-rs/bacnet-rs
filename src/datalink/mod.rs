//! BACnet Data Link Layer Module
//!
//! This module implements the data link layer functionality for BACnet communication protocol,
//! providing support for various data link protocols used in building automation networks.
//! The data link layer sits between the physical layer and the network layer in the BACnet
//! protocol stack, handling frame-level communication.
//!
//! # Overview
//!
//! The data link layer is responsible for:
//! - **Frame Assembly/Disassembly**: Constructing and parsing protocol-specific frames
//! - **Address Management**: Handling different address formats (IP, MAC, MS/TP station)
//! - **Error Detection**: CRC calculation and verification for data integrity
//! - **Media Access Control**: Managing access to shared communication media
//! - **Multi-Protocol Support**: Abstracting differences between various data link types
//!
//! # Supported Data Link Types
//!
//! ## BACnet/IP (Annex J)
//! - UDP/IP based communication on port 47808 (0xBAC0)
//! - BVLC (BACnet Virtual Link Control) for broadcast management
//! - Foreign device registration and BBMD support
//! - Most common in modern installations
//!
//! ## BACnet/Ethernet (ISO 8802-3)
//! - Direct Ethernet frame communication
//! - Uses Ethernet type 0x82DC for BACnet
//! - LLC header for protocol identification
//! - Suitable for high-speed local networks
//!
//! ## MS/TP (Master-Slave/Token-Passing)
//! - RS-485 based serial communication
//! - Token-passing for media access control
//! - Supports up to 128 masters and 127 slaves
//! - Common in field-level devices
//!
//! ## PTP (Point-to-Point)
//! - Direct serial connection between two devices
//! - Simplified protocol without token passing
//! - Used for device configuration and testing
//!
//! ## ARCnet
//! - Legacy token-passing network
//! - Less common in modern installations
//!
//! # Architecture
//!
//! The module uses a trait-based design with the [`DataLink`] trait providing a common
//! interface for all data link implementations. This allows upper layers to work with
//! any data link type transparently.
//!
//! # Examples
//!
//! ## Creating a BACnet/IP Data Link
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # {
//! use bacnet_rs::datalink::{BacnetIpDataLink, DataLink, DataLinkAddress};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a BACnet/IP data link on the default port
//! let mut data_link = BacnetIpDataLink::new("0.0.0.0:47808")?;
//!
//! // Send a frame to a specific IP address
//! let frame_data = vec![0x01, 0x02, 0x03, 0x04];
//! let dest_addr = "192.168.1.100:47808".parse()?;
//! data_link.send_frame(&frame_data, &DataLinkAddress::Ip(dest_addr))?;
//!
//! // Send a broadcast frame
//! data_link.send_frame(&frame_data, &DataLinkAddress::Broadcast)?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## Working with Different Data Link Types
//!
//! ```no_run
//! use bacnet_rs::datalink::{DataLink, DataLinkType, DataLinkAddress};
//!
//! fn process_frame(data_link: &mut dyn DataLink) -> Result<(), Box<dyn std::error::Error>> {
//!     // The function works with any data link type
//!     match data_link.link_type() {
//!         DataLinkType::BacnetIp => println!("Using BACnet/IP"),
//!         DataLinkType::Ethernet => println!("Using Ethernet"),
//!         DataLinkType::MsTP => println!("Using MS/TP"),
//!         _ => println!("Using other data link type"),
//!     }
//!
//!     // Receive a frame
//!     match data_link.receive_frame() {
//!         Ok((frame_data, source_addr)) => {
//!             println!("Received {} bytes from {:?}", frame_data.len(), source_addr);
//!         }
//!         Err(e) => println!("No frame received: {:?}", e),
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Feature Flags
//!
//! - `std`: Enables standard library features and network implementations (enabled by default)
//! - Without `std`: Provides no_std compatible core functionality

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// Result type for data link operations.
///
/// This type alias provides a convenient way to work with data link operation results,
/// automatically using the appropriate [`DataLinkError`] type for the error case.
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::Result;
///
/// fn parse_frame(data: &[u8]) -> Result<Vec<u8>> {
///     if data.is_empty() {
///         return Err(bacnet_rs::datalink::DataLinkError::InvalidFrame);
///     }
///     Ok(data.to_vec())
/// }
/// ```
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, DataLinkError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, DataLinkError>;

/// Errors that can occur during data link layer operations.
///
/// This enum represents all possible error conditions that can arise when working
/// with the data link layer, including I/O errors, protocol violations, and
/// validation failures.
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::{DataLinkError, Result};
///
/// fn validate_frame_size(size: usize) -> Result<()> {
///     if size > 1500 {
///         return Err(DataLinkError::InvalidFrame);
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub enum DataLinkError {
    /// Network I/O error occurred.
    ///
    /// This variant wraps standard I/O errors that occur during network operations,
    /// such as socket errors, timeouts, or connection failures.
    #[cfg(feature = "std")]
    IoError(std::io::Error),

    /// Invalid frame format detected.
    ///
    /// This error indicates that a received frame does not conform to the expected
    /// format for the data link type, such as invalid headers, incorrect frame
    /// structure, or protocol violations.
    InvalidFrame,

    /// CRC check failed during frame validation.
    ///
    /// This error occurs when the calculated CRC/checksum does not match the
    /// expected value, indicating data corruption during transmission.
    CrcError,

    /// Address resolution or validation failed.
    ///
    /// This error includes various address-related issues such as invalid address
    /// formats, unreachable destinations, or address conflicts. The string provides
    /// additional context about the specific issue.
    AddressError(String),

    /// Unsupported data link type for the requested operation.
    ///
    /// This error occurs when attempting to use a data link type that is not
    /// supported by the current implementation or when mixing incompatible
    /// address types with data link types.
    UnsupportedType,
}

impl fmt::Display for DataLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            DataLinkError::IoError(e) => write!(f, "I/O error: {}", e),
            DataLinkError::InvalidFrame => write!(f, "Invalid frame format"),
            DataLinkError::CrcError => write!(f, "CRC check failed"),
            DataLinkError::AddressError(msg) => write!(f, "Address error: {}", msg),
            DataLinkError::UnsupportedType => write!(f, "Unsupported data link type"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for DataLinkError {}

/// BACnet data link layer types supported by this implementation.
///
/// This enum identifies the different data link technologies that can be used
/// for BACnet communication. Each type has different characteristics in terms
/// of speed, cost, wiring requirements, and typical use cases.
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::DataLinkType;
///
/// fn get_default_port(link_type: DataLinkType) -> Option<u16> {
///     match link_type {
///         DataLinkType::BacnetIp => Some(47808),
///         _ => None,
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLinkType {
    /// BACnet/IP (Annex J).
    ///
    /// Uses UDP/IP for communication, typically on port 47808. This is the most
    /// common data link type in modern BACnet installations, providing good
    /// performance and easy integration with existing IP networks.
    BacnetIp,

    /// BACnet/Ethernet (ISO 8802-3).
    ///
    /// Direct Ethernet frame communication using Ethernet type 0x82DC. Provides
    /// high performance on local networks but requires Ethernet infrastructure
    /// and may need special permissions for raw socket access.
    Ethernet,

    /// MS/TP (Master-Slave/Token-Passing).
    ///
    /// Serial communication over RS-485, using a token-passing protocol for
    /// media access control. Common in field-level devices due to low cost
    /// and long cable runs. Supports data rates from 9600 to 115200 bps.
    MsTP,

    /// PTP (Point-to-Point).
    ///
    /// Direct serial connection between two devices, typically used for device
    /// configuration, testing, or isolated connections. Simpler than MS/TP as
    /// it doesn't require token passing.
    PointToPoint,

    /// ARCnet.
    ///
    /// Legacy token-passing network technology. While still supported by the
    /// BACnet standard, it is rarely used in new installations. Included for
    /// compatibility with older systems.
    Arcnet,
}

/// Common trait for all data link layer implementations.
///
/// This trait provides a unified interface for different data link technologies,
/// allowing upper protocol layers to work with any data link type transparently.
/// All data link implementations must provide frame sending/receiving capabilities,
/// type identification, and local address information.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow use in multi-threaded contexts.
/// Internal synchronization may be required for shared resources.
///
/// # Examples
///
/// ## Implementing a Custom Data Link
///
/// ```
/// use bacnet_rs::datalink::{DataLink, DataLinkType, DataLinkAddress, Result};
///
/// struct CustomDataLink {
///     // Implementation details
/// }
///
/// impl DataLink for CustomDataLink {
///     fn send_frame(&mut self, frame: &[u8], dest: &DataLinkAddress) -> Result<()> {
///         // Send frame to destination
///         Ok(())
///     }
///
///     fn receive_frame(&mut self) -> Result<(Vec<u8>, DataLinkAddress)> {
///         // Receive and return frame with source address
///         Ok((vec![0x01, 0x02], DataLinkAddress::Broadcast))
///     }
///
///     fn link_type(&self) -> DataLinkType {
///         DataLinkType::PointToPoint
///     }
///
///     fn local_address(&self) -> DataLinkAddress {
///         DataLinkAddress::Broadcast
///     }
/// }
/// ```
///
/// ## Using the Trait
///
/// ```
/// # #[cfg(feature = "std")]
/// # {
/// use bacnet_rs::datalink::{DataLink, DataLinkAddress};
///
/// fn send_broadcast(data_link: &mut dyn DataLink, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
///     data_link.send_frame(data, &DataLinkAddress::Broadcast)?;
///     Ok(())
/// }
/// # }
/// ```
pub trait DataLink: Send + Sync {
    /// Send a frame to the specified destination address.
    ///
    /// This method takes the frame data (typically an NPDU) and sends it to the
    /// specified destination using the appropriate data link protocol. The frame
    /// data should not include data link headers, as these will be added by the
    /// implementation.
    ///
    /// # Arguments
    ///
    /// * `frame` - The frame data to send (NPDU layer and above)
    /// * `dest` - The destination address in the appropriate format for this data link type
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The destination address type is incompatible with this data link type
    /// - Network I/O errors occur
    /// - The frame is too large for the data link type
    fn send_frame(&mut self, frame: &[u8], dest: &DataLinkAddress) -> Result<()>;

    /// Receive a frame from the data link.
    ///
    /// This method blocks until a frame is received or an error occurs. The returned
    /// frame data excludes data link headers, containing only the NPDU and above.
    /// The source address is provided to identify the sender.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - The received frame data (NPDU layer and above)
    /// - The source address of the frame
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No frame is available (timeout)
    /// - Network I/O errors occur
    /// - The received frame is invalid or corrupted
    ///
    /// # Note
    ///
    /// Implementations may use timeouts to prevent indefinite blocking.
    fn receive_frame(&mut self) -> Result<(Vec<u8>, DataLinkAddress)>;

    /// Get the data link type of this implementation.
    ///
    /// This method returns the specific type of data link technology used by
    /// this implementation, allowing upper layers to make data link-specific
    /// decisions if necessary.
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::{DataLink, DataLinkType};
    ///
    /// fn is_ip_based(data_link: &dyn DataLink) -> bool {
    ///     data_link.link_type() == DataLinkType::BacnetIp
    /// }
    /// ```
    fn link_type(&self) -> DataLinkType;

    /// Get the local address of this data link.
    ///
    /// Returns the address that identifies this device on the data link network.
    /// The format depends on the data link type:
    /// - BACnet/IP: IP address and port
    /// - Ethernet: MAC address
    /// - MS/TP: Station address (0-254)
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "std")]
    /// # {
    /// use bacnet_rs::datalink::{DataLink, DataLinkAddress};
    ///
    /// fn print_local_address(data_link: &dyn DataLink) {
    ///     match data_link.local_address() {
    ///         DataLinkAddress::Ip(addr) => println!("IP: {}", addr),
    ///         DataLinkAddress::Ethernet(mac) => println!("MAC: {:02X?}", mac),
    ///         DataLinkAddress::MsTP(station) => println!("MS/TP Station: {}", station),
    ///         _ => println!("Other address type"),
    ///     }
    /// }
    /// # }
    /// ```
    fn local_address(&self) -> DataLinkAddress;
}

/// Data link layer address representation.
///
/// This enum provides a unified way to represent addresses across different
/// data link types. Each variant corresponds to the addressing scheme used
/// by a specific data link technology.
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::DataLinkAddress;
/// # #[cfg(feature = "std")]
/// # {
/// use std::net::SocketAddr;
///
/// // IP address for BACnet/IP
/// let ip_addr: SocketAddr = "192.168.1.100:47808".parse().unwrap();
/// let addr = DataLinkAddress::Ip(ip_addr);
///
/// // MAC address for Ethernet
/// let mac_addr = DataLinkAddress::Ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
///
/// // MS/TP station address
/// let mstp_addr = DataLinkAddress::MsTP(42);
///
/// // Broadcast to all devices
/// let broadcast = DataLinkAddress::Broadcast;
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataLinkAddress {
    /// IP address and port for BACnet/IP communication.
    ///
    /// Used with BACnet/IP data links. The port is typically 47808 (0xBAC0)
    /// but can be different for non-standard configurations or when multiple
    /// BACnet networks share the same IP network.
    #[cfg(feature = "std")]
    Ip(SocketAddr),

    /// Ethernet MAC address for direct Ethernet communication.
    ///
    /// Used with BACnet/Ethernet data links. The 6-byte array represents
    /// a standard 48-bit MAC address. Special addresses include:
    /// - `FF:FF:FF:FF:FF:FF` - Ethernet broadcast
    /// - `01:00:5E:xx:xx:xx` - IPv4 multicast range
    Ethernet([u8; 6]),

    /// MS/TP station address.
    ///
    /// Used with MS/TP data links. Valid ranges:
    /// - 0-127: Master nodes (can initiate communication)
    /// - 128-254: Slave nodes (only respond to requests)
    /// - 255: Broadcast address
    MsTP(u8),

    /// Broadcast address for sending to all devices.
    ///
    /// This is a logical broadcast that is translated to the appropriate
    /// physical broadcast address for each data link type:
    /// - BACnet/IP: UDP broadcast or multicast
    /// - Ethernet: FF:FF:FF:FF:FF:FF
    /// - MS/TP: Station address 255
    Broadcast,
}

/// BACnet/IP (Annex J) implementation.
///
/// This module provides BACnet communication over IP networks using UDP port 47808.
/// It includes BVLC (BACnet Virtual Link Control) for broadcast management, foreign
/// device registration, and BBMD (BACnet Broadcast Management Device) support.
pub mod bip;

/// BACnet/Ethernet (ISO 8802-3) implementation.
///
/// This module provides direct Ethernet frame communication for BACnet, using
/// Ethernet type 0x82DC and LLC headers for protocol identification. It offers
/// high performance on local networks.
pub mod ethernet;

/// MS/TP (Master-Slave/Token-Passing) implementation.
///
/// This module provides BACnet communication over RS-485 serial links using a
/// token-passing protocol. It's commonly used for field-level devices due to
/// its low cost and ability to support long cable runs.
pub mod mstp;

/// Frame validation and analysis utilities.
///
/// This module provides comprehensive validation functions for all supported
/// data link types, including structure validation, CRC verification, and
/// pattern detection for troubleshooting.
pub mod validation;

#[cfg(feature = "std")]
pub use bip::BacnetIpDataLink;

#[cfg(feature = "std")]
pub use ethernet::EthernetDataLink;

#[cfg(feature = "std")]
pub use mstp::MstpDataLink;
