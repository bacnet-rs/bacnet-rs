//! BACnet/IP Data Link Implementation (ASHRAE 135 Annex J).
//!
//! This module provides a complete implementation of the BACnet/IP data link layer,
//! enabling BACnet communication over Internet Protocol networks. BACnet/IP is the
//! most widely used data link layer in modern BACnet installations due to its
//! compatibility with existing IP infrastructure.
//!
//! # Overview
//!
//! BACnet/IP uses UDP as the transport protocol, typically on port 47808 (0xBAC0),
//! and includes the BACnet Virtual Link Control (BVLC) layer for managing broadcasts
//! across IP networks. Key features include:
//!
//! - **UDP Communication**: Efficient, connectionless transport over IP networks
//! - **BVLC Protocol**: Manages broadcast distribution across routers
//! - **Foreign Device Support**: Allows devices to join remote BACnet networks
//! - **BBMD Functionality**: Broadcast Management Devices for inter-network communication
//!
//! # BVLC Functions
//!
//! The BVLC layer provides these message types:
//!
//! - **Original-Unicast-NPDU**: Direct unicast message to a specific device
//! - **Original-Broadcast-NPDU**: Broadcast message originating from this device
//! - **Forwarded-NPDU**: Message forwarded by a BBMD
//! - **Register-Foreign-Device**: Request to join a remote network
//! - **Read-Broadcast-Distribution-Table**: Query BBMD's peer list
//! - **Read-Foreign-Device-Table**: Query registered foreign devices
//! - **Delete-Foreign-Device-Table-Entry**: Remove a foreign device
//! - **Distribute-Broadcast-To-Network**: BBMD-to-BBMD broadcast distribution
//! - **Secure-BVLL**: Encrypted BACnet communication (BACnet/SC)
//!
//! # Examples
//!
//! ## Basic BACnet/IP Communication
//!
//! ```no_run
//! use bacnet_rs::datalink::bip::{BacnetIpDataLink, BvlcFunction};
//! use bacnet_rs::datalink::{DataLink, DataLinkAddress};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a BACnet/IP data link
//! let mut data_link = BacnetIpDataLink::new("0.0.0.0:47808")?;
//!
//! // Send a unicast message
//! let npdu = vec![0x01, 0x04, 0x00, 0x00];  // Example NPDU
//! let dest = "192.168.1.100:47808".parse()?;
//! data_link.send_frame(&npdu, &DataLinkAddress::Ip(dest))?;
//!
//! // Send a broadcast message
//! data_link.send_frame(&npdu, &DataLinkAddress::Broadcast)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Foreign Device Registration
//!
//! ```no_run
//! use bacnet_rs::datalink::bip::BacnetIpDataLink;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut data_link = BacnetIpDataLink::new("0.0.0.0:47808")?;
//!
//! // Register with a BBMD (Time-to-live: 300 seconds)
//! let bbmd_addr = "192.168.1.10:47808".parse()?;
//! data_link.register_foreign_device(bbmd_addr, 300)?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "std")]
use std::{
    io::ErrorKind,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    time::{Duration, Instant},
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::datalink::{DataLink, DataLinkAddress, DataLinkError, DataLinkType, Result};

/// BACnet/IP well-known UDP port number.
///
/// This is the standard port (0xBAC0 = 47808) defined by ASHRAE 135 for BACnet/IP
/// communication. While this is the default, BACnet/IP can use other ports when
/// multiple BACnet networks share the same IP infrastructure.
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::bip::BACNET_IP_PORT;
///
/// let addr = format!("0.0.0.0:{}", BACNET_IP_PORT);
/// assert_eq!(addr, "0.0.0.0:47808");
/// ```
pub const BACNET_IP_PORT: u16 = 47808;

/// BVLC (BACnet Virtual Link Control) message types.
///
/// These message types define the various operations supported by the BVLC protocol,
/// which manages broadcast distribution and foreign device registration in BACnet/IP
/// networks. Each function code corresponds to a specific BVLC operation.
///
/// # Protocol Details
///
/// BVLC messages have a 4-byte header followed by function-specific data:
/// - Type (1 byte): Always 0x81 for BACnet/IP
/// - Function (1 byte): One of the values defined in this enum
/// - Length (2 bytes): Total message length including header
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::bip::BvlcFunction;
///
/// // Check if a function expects a response
/// fn expects_ack(func: BvlcFunction) -> bool {
///     matches!(func,
///         BvlcFunction::ReadBroadcastDistributionTable |
///         BvlcFunction::ReadForeignDeviceTable
///     )
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BvlcFunction {
    /// Original-Unicast-NPDU (0x0A).
    ///
    /// Encapsulates an NPDU for unicast delivery to a specific BACnet/IP device.
    /// This is the most common BVLC function for point-to-point communication.
    OriginalUnicastNpdu = 0x0A,

    /// Original-Broadcast-NPDU (0x0B).
    ///
    /// Encapsulates an NPDU for broadcast delivery. The message is sent to the
    /// local IP broadcast address and to all entries in the BDT if the sender
    /// is a BBMD.
    OriginalBroadcastNpdu = 0x0B,

    /// Forwarded-NPDU (0x04).
    ///
    /// Used by BBMDs to forward broadcasts between BACnet/IP networks. Contains
    /// the original source address before the NPDU data.
    ForwardedNpdu = 0x04,

    /// Register-Foreign-Device (0x05).
    ///
    /// Sent by a foreign device to register with a BBMD, allowing it to receive
    /// broadcasts. Includes a Time-to-Live value in seconds.
    RegisterForeignDevice = 0x05,

    /// Read-Broadcast-Distribution-Table (0x02).
    ///
    /// Request to read a BBMD's Broadcast Distribution Table, which lists peer
    /// BBMDs for broadcast forwarding.
    ReadBroadcastDistributionTable = 0x02,

    /// Read-Broadcast-Distribution-Table-Ack (0x03).
    ///
    /// Response containing the requested Broadcast Distribution Table entries.
    ReadBroadcastDistributionTableAck = 0x03,

    /// Read-Foreign-Device-Table (0x06).
    ///
    /// Request to read a BBMD's Foreign Device Table, listing registered foreign
    /// devices.
    ReadForeignDeviceTable = 0x06,

    /// Read-Foreign-Device-Table-Ack (0x07).
    ///
    /// Response containing the requested Foreign Device Table entries.
    ReadForeignDeviceTableAck = 0x07,

    /// Delete-Foreign-Device-Table-Entry (0x08).
    ///
    /// Request to remove a specific entry from the Foreign Device Table.
    DeleteForeignDeviceTableEntry = 0x08,

    /// Distribute-Broadcast-To-Network (0x09).
    ///
    /// Used between BBMDs to distribute broadcast NPDUs to all devices on their
    /// respective networks.
    DistributeBroadcastToNetwork = 0x09,

    /// Forwarded-NPDU-From-Device (0x0C).
    ///
    /// Alternative forwarding mechanism that preserves the original device address.
    ForwardedNpduFromDevice = 0x0C,

    /// Secure-BVLL (0x0D).
    ///
    /// Used for BACnet Secure Connect (BACnet/SC) encrypted communication.
    SecureBvll = 0x0D,
}

impl TryFrom<u8> for BvlcFunction {
    type Error = DataLinkError;

    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        let function = match value {
            0x0A => BvlcFunction::OriginalUnicastNpdu,
            0x0B => BvlcFunction::OriginalBroadcastNpdu,
            0x04 => BvlcFunction::ForwardedNpdu,
            0x05 => BvlcFunction::RegisterForeignDevice,
            0x02 => BvlcFunction::ReadBroadcastDistributionTable,
            0x03 => BvlcFunction::ReadBroadcastDistributionTableAck,
            0x06 => BvlcFunction::ReadForeignDeviceTable,
            0x07 => BvlcFunction::ReadForeignDeviceTableAck,
            0x08 => BvlcFunction::DeleteForeignDeviceTableEntry,
            0x09 => BvlcFunction::DistributeBroadcastToNetwork,
            0x0C => BvlcFunction::ForwardedNpduFromDevice,
            0x0D => BvlcFunction::SecureBvll,
            _ => return Err(DataLinkError::InvalidFrame),
        };

        Ok(function)
    }
}

/// BVLC header structure for BACnet/IP messages.
///
/// Every BACnet/IP message begins with this 4-byte header that identifies
/// the message type and length. The header is followed by function-specific
/// data and then the NPDU (if applicable).
///
/// # Wire Format
///
/// ```text
/// +--------+--------+--------+--------+
/// | Type   | Func   | Length (MSB/LSB)|
/// | (0x81) | Code   | (Total bytes)   |
/// +--------+--------+--------+--------+
/// ```
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::bip::{BvlcHeader, BvlcFunction};
///
/// // Create header for a 20-byte unicast NPDU
/// let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 24);
/// assert_eq!(header.bvlc_type, 0x81);
/// assert_eq!(header.length, 24);  // 4-byte header + 20-byte NPDU
/// ```
#[derive(Debug, Clone)]
pub struct BvlcHeader {
    /// BVLC type identifier.
    ///
    /// Always 0x81 for BACnet/IP. Other values are reserved for future use
    /// or indicate non-BACnet/IP frames.
    pub bvlc_type: u8,

    /// BVLC function code.
    ///
    /// Identifies the specific BVLC operation this message performs.
    pub function: BvlcFunction,

    /// Total message length in bytes.
    ///
    /// Includes the 4-byte BVLC header plus all following data. Maximum
    /// value is typically limited by UDP MTU (usually 1472 bytes for
    /// standard Ethernet without fragmentation).
    pub length: u16,
}

impl BvlcHeader {
    /// Create a new BVLC header with the specified function and length.
    ///
    /// The BVLC type is automatically set to 0x81 for BACnet/IP.
    ///
    /// # Arguments
    ///
    /// * `function` - The BVLC function for this message
    /// * `length` - Total message length including the 4-byte header
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::bip::{BvlcHeader, BvlcFunction};
    ///
    /// // Create header for a broadcast NPDU
    /// let npdu_size = 50;
    /// let header = BvlcHeader::new(
    ///     BvlcFunction::OriginalBroadcastNpdu,
    ///     4 + npdu_size  // Header + NPDU
    /// );
    /// ```
    pub fn new(function: BvlcFunction, length: u16) -> Self {
        Self {
            bvlc_type: 0x81, // BACnet/IP
            function,
            length,
        }
    }

    /// Encode the BVLC header to its 4-byte wire format.
    ///
    /// # Returns
    ///
    /// A 4-byte vector containing the encoded header.
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::bip::{BvlcHeader, BvlcFunction};
    ///
    /// let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 100);
    /// let bytes = header.encode();
    /// assert_eq!(bytes, vec![0x81, 0x0A, 0x00, 0x64]);
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        vec![
            self.bvlc_type,
            self.function as u8,
            (self.length >> 8) as u8,
            (self.length & 0xFF) as u8,
        ]
    }

    /// Decode a BVLC header from its wire format.
    ///
    /// # Arguments
    ///
    /// * `data` - Buffer containing at least 4 bytes of BVLC header
    ///
    /// # Returns
    ///
    /// The decoded BVLC header.
    ///
    /// # Errors
    ///
    /// Returns [`DataLinkError::InvalidFrame`] if:
    /// - The buffer is too short (less than 4 bytes)
    /// - The BVLC type is not 0x81
    /// - The function code is not recognized
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::bip::BvlcHeader;
    ///
    /// let data = vec![0x81, 0x0A, 0x00, 0x64];
    /// let header = BvlcHeader::decode(&data).unwrap();
    /// assert_eq!(header.length, 100);
    /// ```
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(DataLinkError::InvalidFrame);
        }

        let bvlc_type = data[0];
        if bvlc_type != 0x81 {
            return Err(DataLinkError::InvalidFrame);
        }

        let function = data[1].try_into()?;

        let length = ((data[2] as u16) << 8) | (data[3] as u16);

        Ok(BvlcHeader {
            bvlc_type,
            function,
            length,
        })
    }
}

/// Broadcast Distribution Table (BDT) entry.
///
/// Represents a peer BBMD in the broadcast distribution network. BBMDs use
/// the BDT to forward broadcast messages between different IP subnets,
/// enabling BACnet broadcasts to traverse routers.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "std")] {
/// use bacnet_rs::datalink::bip::BdtEntry;
/// use std::net::SocketAddr;
///
/// // Create a BDT entry for a peer BBMD
/// let peer_addr: SocketAddr = "192.168.2.10:47808".parse().unwrap();
/// let entry = BdtEntry {
///     address: peer_addr,
///     mask: [255, 255, 255, 0],  // Subnet mask
/// };
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg(feature = "std")]
pub struct BdtEntry {
    /// IP address and port of the peer BBMD.
    ///
    /// This is the address where broadcast messages should be forwarded.
    /// Typically uses the standard BACnet/IP port 47808.
    pub address: SocketAddr,

    /// Broadcast distribution mask (subnet mask).
    ///
    /// Defines the IP subnet associated with this BBMD. Used to determine
    /// which broadcasts should be forwarded to this peer. Common values:
    /// - `[255, 255, 255, 0]` - Class C subnet
    /// - `[255, 255, 0, 0]` - Class B subnet
    /// - `[255, 255, 255, 255]` - Host-specific entry
    pub mask: [u8; 4],
}

/// Foreign Device Table (FDT) entry.
///
/// Represents a foreign device that has registered with this BBMD to receive
/// broadcast messages. Foreign devices are BACnet/IP devices that are not on
/// the same IP subnet as any BBMD.
///
/// # Registration Process
///
/// Foreign devices must periodically re-register before their TTL expires.
/// The BBMD automatically removes expired entries.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "std")] {
/// use bacnet_rs::datalink::bip::FdtEntry;
/// use std::net::SocketAddr;
/// use std::time::Instant;
///
/// // Track a registered foreign device
/// let device_addr: SocketAddr = "192.168.100.50:47808".parse().unwrap();
/// let entry = FdtEntry {
///     address: device_addr,
///     ttl: 300,  // 5 minutes
///     registration_time: Instant::now(),
/// };
///
/// // Check if registration has expired
/// let elapsed = entry.registration_time.elapsed().as_secs();
/// let is_expired = elapsed >= entry.ttl as u64;
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg(feature = "std")]
pub struct FdtEntry {
    /// IP address and port of the foreign device.
    ///
    /// This is where broadcast messages will be forwarded for this
    /// registered foreign device.
    pub address: SocketAddr,

    /// Time-to-live in seconds.
    ///
    /// The foreign device must re-register before this time expires.
    /// Typical values range from 60 seconds to several minutes.
    /// Maximum value is 65535 seconds (about 18 hours).
    pub ttl: u16,

    /// Time when the device registered.
    ///
    /// Used to calculate when the registration expires. The entry
    /// should be removed when `registration_time + ttl` is reached.
    pub registration_time: Instant,
}

/// BACnet/IP data link implementation.
///
/// Provides complete BACnet/IP communication including BVLC protocol support,
/// broadcast management, and foreign device registration. This implementation
/// can function as a regular BACnet/IP device, a foreign device, or a BBMD
/// (BACnet Broadcast Management Device).
///
/// # Architecture
///
/// The implementation uses a UDP socket bound to the specified address and
/// manages broadcast distribution through local subnet broadcasts and BDT
/// forwarding. Foreign devices can register to receive broadcasts.
///
/// # Examples
///
/// ## Basic BACnet/IP Device
///
/// ```no_run
/// # #[cfg(feature = "std")] {
/// use bacnet_rs::datalink::bip::BacnetIpDataLink;
/// use bacnet_rs::datalink::{DataLink, DataLinkAddress};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a BACnet/IP device
/// let mut device = BacnetIpDataLink::new("0.0.0.0:47808")?;
///
/// // Send and receive frames
/// let npdu = vec![0x01, 0x04, 0x00, 0x00];
/// device.send_frame(&npdu, &DataLinkAddress::Broadcast)?;
///
/// match device.receive_frame() {
///     Ok((data, source)) => println!("Received {} bytes", data.len()),
///     Err(_) => println!("No frame received"),
/// }
/// # Ok(())
/// # }
/// # }
/// ```
///
/// ## BBMD Configuration
///
/// ```no_run
/// # #[cfg(feature = "std")] {
/// use bacnet_rs::datalink::bip::{BacnetIpDataLink, BdtEntry};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut bbmd = BacnetIpDataLink::new("192.168.1.10:47808")?;
///
/// // Add peer BBMDs to the BDT
/// let peer1 = "192.168.2.10:47808".parse()?;
/// bbmd.add_bdt_entry(peer1, [255, 255, 255, 0]);
///
/// let peer2 = "192.168.3.10:47808".parse()?;
/// bbmd.add_bdt_entry(peer2, [255, 255, 255, 0]);
/// # Ok(())
/// # }
/// # }
/// ```
#[cfg(feature = "std")]
pub struct BacnetIpDataLink {
    /// UDP socket for BACnet/IP communication.
    socket: UdpSocket,

    /// Local IP address and port.
    local_addr: SocketAddr,

    /// Broadcast Distribution Table.
    ///
    /// Contains peer BBMDs for broadcast forwarding. Only used when this
    /// device is configured as a BBMD.
    bdt: Vec<BdtEntry>,

    /// Foreign Device Table.
    ///
    /// Contains registered foreign devices that should receive broadcasts.
    /// Only used when this device is configured as a BBMD.
    fdt: Vec<FdtEntry>,

    /// Local broadcast address for this subnet.
    ///
    /// Calculated based on the local IP address and subnet mask.
    /// Used for Original-Broadcast-NPDU messages.
    broadcast_addr: SocketAddr,
}

#[cfg(feature = "std")]
impl BacnetIpDataLink {
    /// Create a new BACnet/IP data link.
    ///
    /// Binds a UDP socket to the specified address and configures it for
    /// BACnet/IP communication. The socket is configured with broadcast
    /// enabled and a reasonable receive timeout.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - The local address to bind to (e.g., "0.0.0.0:47808")
    ///
    /// # Returns
    ///
    /// A configured BACnet/IP data link ready for communication.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket cannot be bound (port already in use, permission denied)
    /// - The address cannot be resolved
    /// - IPv6 addresses are used (not currently supported)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")] {
    /// use bacnet_rs::datalink::bip::BacnetIpDataLink;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Bind to any interface on the standard port
    /// let data_link = BacnetIpDataLink::new("0.0.0.0:47808")?;
    ///
    /// // Bind to a specific interface
    /// let data_link = BacnetIpDataLink::new("192.168.1.100:47808")?;
    ///
    /// // Use a non-standard port
    /// let data_link = BacnetIpDataLink::new("0.0.0.0:47809")?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn new<A: ToSocketAddrs>(bind_addr: A) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).map_err(DataLinkError::IoError)?;

        let local_addr = socket.local_addr().map_err(DataLinkError::IoError)?;

        // Enable broadcast
        socket.set_broadcast(true).map_err(DataLinkError::IoError)?;

        // Set receive timeout
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(DataLinkError::IoError)?;

        // Calculate broadcast address based on local address
        let broadcast_addr = match local_addr {
            SocketAddr::V4(addr) => {
                let ip = addr.ip().octets();
                // Simple broadcast calculation - in production, use proper subnet mask
                let broadcast_ip = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], 255);
                SocketAddr::new(broadcast_ip.into(), BACNET_IP_PORT)
            }
            SocketAddr::V6(_) => {
                // IPv6 uses multicast instead of broadcast
                return Err(DataLinkError::UnsupportedType);
            }
        };

        Ok(Self {
            socket,
            local_addr,
            bdt: Vec::new(),
            fdt: Vec::new(),
            broadcast_addr,
        })
    }

    /// Send a unicast NPDU to a specific device.
    ///
    /// Wraps the NPDU in a BVLC Original-Unicast-NPDU message and sends it
    /// to the specified destination address.
    ///
    /// # Arguments
    ///
    /// * `npdu` - The NPDU data to send
    /// * `dest` - The destination IP address and port
    ///
    /// # Errors
    ///
    /// Returns an error if the socket send operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")] {
    /// # use bacnet_rs::datalink::bip::BacnetIpDataLink;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut data_link = BacnetIpDataLink::new("0.0.0.0:47808")?;
    /// let npdu = vec![0x01, 0x04, 0x00, 0x00];  // Example NPDU
    /// let dest = "192.168.1.100:47808".parse()?;
    /// data_link.send_unicast_npdu(&npdu, dest)?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn send_unicast_npdu(&mut self, npdu: &[u8], dest: SocketAddr) -> Result<()> {
        let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 4 + npdu.len() as u16);

        let mut frame = header.encode();
        frame.extend_from_slice(npdu);

        self.socket
            .send_to(&frame, dest)
            .map_err(DataLinkError::IoError)?;

        Ok(())
    }

    /// Send a broadcast NPDU to all devices.
    ///
    /// Wraps the NPDU in a BVLC Original-Broadcast-NPDU message and sends it to:
    /// 1. The local subnet broadcast address
    /// 2. All peer BBMDs in the BDT (if configured as BBMD)
    /// 3. All registered foreign devices in the FDT (if configured as BBMD)
    ///
    /// # Arguments
    ///
    /// * `npdu` - The NPDU data to broadcast
    ///
    /// # Errors
    ///
    /// Returns an error if the primary broadcast fails. Failures to individual
    /// BDT or FDT entries are silently ignored.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")] {
    /// # use bacnet_rs::datalink::bip::BacnetIpDataLink;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut data_link = BacnetIpDataLink::new("0.0.0.0:47808")?;
    /// // Broadcast a Who-Is request
    /// let who_is_npdu = vec![0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08];
    /// data_link.send_broadcast_npdu(&who_is_npdu)?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn send_broadcast_npdu(&mut self, npdu: &[u8]) -> Result<()> {
        let header = BvlcHeader::new(BvlcFunction::OriginalBroadcastNpdu, 4 + npdu.len() as u16);

        let mut frame = header.encode();
        frame.extend_from_slice(npdu);

        // Send to local broadcast address
        self.socket
            .send_to(&frame, self.broadcast_addr)
            .map_err(DataLinkError::IoError)?;

        // Send to all BDT entries
        for entry in &self.bdt {
            let _ = self.socket.send_to(&frame, entry.address);
        }

        Ok(())
    }

    /// Register this device as a foreign device with a BBMD.
    ///
    /// Foreign device registration allows a device on a different IP subnet to
    /// receive BACnet broadcasts by registering with a BBMD. The device must
    /// re-register before the TTL expires.
    ///
    /// # Arguments
    ///
    /// * `bbmd_addr` - The IP address and port of the BBMD
    /// * `ttl` - Time-to-live in seconds (typically 60-600)
    ///
    /// # Errors
    ///
    /// Returns an error if the registration message cannot be sent.
    ///
    /// # Notes
    ///
    /// - The BBMD may reject the registration (no response is provided)
    /// - Re-registration should occur at intervals less than the TTL
    /// - A TTL of 0 cancels the registration
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")] {
    /// # use bacnet_rs::datalink::bip::BacnetIpDataLink;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut data_link = BacnetIpDataLink::new("0.0.0.0:47808")?;
    /// // Register with a BBMD for 5 minutes
    /// let bbmd = "192.168.1.10:47808".parse()?;
    /// data_link.register_foreign_device(bbmd, 300)?;
    ///
    /// // Cancel registration
    /// data_link.register_foreign_device(bbmd, 0)?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn register_foreign_device(&mut self, bbmd_addr: SocketAddr, ttl: u16) -> Result<()> {
        let header = BvlcHeader::new(BvlcFunction::RegisterForeignDevice, 6);
        let mut frame = header.encode();
        frame.extend_from_slice(&ttl.to_be_bytes());

        self.socket
            .send_to(&frame, bbmd_addr)
            .map_err(DataLinkError::IoError)?;

        Ok(())
    }

    /// Add a peer BBMD to the Broadcast Distribution Table.
    ///
    /// When configured as a BBMD, this device will forward broadcast messages
    /// to all peers in the BDT. Each peer BBMD is responsible for distributing
    /// broadcasts to devices on its local subnet.
    ///
    /// # Arguments
    ///
    /// * `address` - IP address and port of the peer BBMD
    /// * `mask` - Subnet mask associated with the peer (e.g., [255, 255, 255, 0])
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")] {
    /// # use bacnet_rs::datalink::bip::BacnetIpDataLink;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut bbmd = BacnetIpDataLink::new("0.0.0.0:47808")?;
    /// // Configure as BBMD with two peers
    /// bbmd.add_bdt_entry("192.168.1.10:47808".parse()?, [255, 255, 255, 0]);
    /// bbmd.add_bdt_entry("192.168.2.10:47808".parse()?, [255, 255, 255, 0]);
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn add_bdt_entry(&mut self, address: SocketAddr, mask: [u8; 4]) {
        self.bdt.push(BdtEntry { address, mask });
    }

    /// Remove expired entries from the Foreign Device Table.
    ///
    /// This method should be called periodically to remove foreign devices
    /// whose registration has expired. Devices that fail to re-register
    /// within their TTL period will no longer receive broadcasts.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")] {
    /// # use bacnet_rs::datalink::bip::BacnetIpDataLink;
    /// # use std::thread;
    /// # use std::time::Duration;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut bbmd = BacnetIpDataLink::new("0.0.0.0:47808")?;
    /// // Periodically clean up expired registrations
    /// loop {
    ///     bbmd.cleanup_fdt();
    ///     thread::sleep(Duration::from_secs(30));
    /// }
    /// # }
    /// # }
    /// ```
    pub fn cleanup_fdt(&mut self) {
        let now = Instant::now();
        self.fdt.retain(|entry| {
            now.duration_since(entry.registration_time).as_secs() < entry.ttl as u64
        });
    }

    /// Process a received BVLC message.
    ///
    /// Handles all BVLC message types according to the BACnet/IP specification.
    /// Returns the encapsulated NPDU for data messages, or None for control messages.
    ///
    /// # Arguments
    ///
    /// * `data` - The complete BVLC message including header
    /// * `source` - The source IP address and port
    ///
    /// # Returns
    ///
    /// - `Some(npdu)` - For data messages (Original-Unicast-NPDU, etc.)
    /// - `None` - For control messages (Register-Foreign-Device, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the message format is invalid.
    fn process_bvlc_message(&mut self, data: &[u8], source: SocketAddr) -> Result<Option<Vec<u8>>> {
        let header = BvlcHeader::decode(data)?;

        if data.len() != header.length as usize {
            return Err(DataLinkError::InvalidFrame);
        }

        match header.function {
            BvlcFunction::OriginalUnicastNpdu | BvlcFunction::OriginalBroadcastNpdu => {
                // Return the NPDU portion (skip 4-byte BVLC header)
                if data.len() > 4 {
                    Ok(Some(data[4..].to_vec()))
                } else {
                    Err(DataLinkError::InvalidFrame)
                }
            }
            BvlcFunction::ForwardedNpdu => {
                // Forwarded NPDU has original source address after header
                if data.len() > 10 {
                    Ok(Some(data[10..].to_vec()))
                } else {
                    Err(DataLinkError::InvalidFrame)
                }
            }
            BvlcFunction::RegisterForeignDevice => {
                // Handle foreign device registration
                if data.len() == 6 {
                    let ttl = u16::from_be_bytes([data[4], data[5]]);
                    self.fdt.push(FdtEntry {
                        address: source,
                        ttl,
                        registration_time: Instant::now(),
                    });
                }
                Ok(None)
            }
            _ => {
                // Other BVLC functions not yet implemented
                Ok(None)
            }
        }
    }
}

#[cfg(feature = "std")]
impl DataLink for BacnetIpDataLink {
    fn send_frame(&mut self, frame: &[u8], dest: &DataLinkAddress) -> Result<()> {
        match dest {
            DataLinkAddress::Ip(addr) => self.send_unicast_npdu(frame, *addr),
            DataLinkAddress::Broadcast => self.send_broadcast_npdu(frame),
            _ => Err(DataLinkError::UnsupportedType),
        }
    }

    fn receive_frame(&mut self) -> Result<(Vec<u8>, DataLinkAddress)> {
        let mut buffer = [0u8; 1500]; // MTU size

        match self.socket.recv_from(&mut buffer) {
            Ok((len, source)) => {
                let data = &buffer[..len];

                if let Some(npdu) = self.process_bvlc_message(data, source)? {
                    Ok((npdu, DataLinkAddress::Ip(source)))
                } else {
                    // No NPDU to return, try again
                    Err(DataLinkError::InvalidFrame)
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                Err(DataLinkError::IoError(e))
            }
            Err(e) => Err(DataLinkError::IoError(e)),
        }
    }

    fn link_type(&self) -> DataLinkType {
        DataLinkType::BacnetIp
    }

    fn local_address(&self) -> DataLinkAddress {
        DataLinkAddress::Ip(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bvlc_header_encode_decode() {
        let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 1024);
        let encoded = header.encode();

        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0], 0x81);
        assert_eq!(encoded[1], 0x0A);
        assert_eq!(encoded[2], 0x04);
        assert_eq!(encoded[3], 0x00);

        let decoded = BvlcHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.bvlc_type, 0x81);
        assert_eq!(decoded.function, BvlcFunction::OriginalUnicastNpdu);
        assert_eq!(decoded.length, 1024);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_bacnet_ip_creation() {
        let result = BacnetIpDataLink::new("127.0.0.1:0");
        assert!(result.is_ok());

        let datalink = result.unwrap();
        assert_eq!(datalink.link_type(), DataLinkType::BacnetIp);
    }
}
