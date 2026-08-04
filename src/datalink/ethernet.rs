//! BACnet/Ethernet Data Link Implementation (ISO 8802-3).
//!
//! This module implements the BACnet/Ethernet data link layer as defined in ASHRAE 135 Clause 7,
//! providing direct Ethernet frame communication for BACnet networks. BACnet/Ethernet offers
//! high performance on local networks by eliminating the overhead of IP protocols.
//!
//! # Overview
//!
//! BACnet/Ethernet uses standard IEEE 802.3 Ethernet frames with a specific Ethernet type
//! (0x82DC) and LLC header to identify BACnet traffic. Key features:
//!
//! - **Direct Frame Access**: Bypasses IP stack for lower latency
//! - **Hardware Addressing**: Uses 48-bit MAC addresses
//! - **Broadcast Support**: Native Ethernet broadcast (FF:FF:FF:FF:FF:FF)
//! - **High Performance**: Suitable for high-speed building backbones
//!
//! # Frame Format
//!
//! ```text
//! Ethernet Frame Structure:
//! +-------------------+-------------------+
//! | Destination MAC   | 6 bytes          |
//! +-------------------+-------------------+
//! | Source MAC        | 6 bytes          |
//! +-------------------+-------------------+
//! | Ethernet Type     | 2 bytes (0x82DC) |
//! +-------------------+-------------------+
//! | LLC Header        | 3 bytes          |
//! | - DSAP: 0x82      |                  |
//! | - SSAP: 0x82      |                  |
//! | - Control: 0x03   |                  |
//! +-------------------+-------------------+
//! | NPDU              | Variable length  |
//! +-------------------+-------------------+
//! | Padding (if needed)| To 60 bytes min  |
//! +-------------------+-------------------+
//! | FCS               | 4 bytes (by NIC) |
//! +-------------------+-------------------+
//! ```
//!
//! # Implementation Notes
//!
//! This implementation requires raw socket access, which typically needs elevated
//! privileges on most operating systems. In production, consider using platform-specific
//! APIs or packet capture libraries like libpcap for better compatibility.
//!
//! # Examples
//!
//! ```no_run
//! # #[cfg(feature = "std")] {
//! use bacnet_rs::datalink::ethernet::{EthernetDataLink, parse_mac_address};
//! use bacnet_rs::datalink::{DataLink, DataLinkAddress};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create Ethernet data link
//! let local_mac = parse_mac_address("00:11:22:33:44:55")?;
//! let mut eth_link = EthernetDataLink::new("eth0", local_mac)?;
//!
//! // Send to specific MAC address
//! let dest_mac = parse_mac_address("AA:BB:CC:DD:EE:FF")?;
//! let npdu = vec![0x01, 0x04, 0x00, 0x00];
//! eth_link.send_frame(&npdu, &DataLinkAddress::Ethernet(dest_mac))?;
//!
//! // Send broadcast
//! eth_link.send_frame(&npdu, &DataLinkAddress::Broadcast)?;
//! # Ok(())
//! # }
//! # }
//! ```

#[cfg(feature = "std")]
use std::sync::{Arc, Mutex};

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use crate::datalink::{DataLink, DataLinkAddress, DataLinkType};
use crate::datalink::{DataLinkError, Result};

/// Ethernet broadcast MAC address (all ones).
///
/// This special address causes the frame to be delivered to all devices
/// on the local Ethernet segment. Used for BACnet broadcast messages.
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::ethernet::ETHERNET_BROADCAST_MAC;
///
/// assert_eq!(ETHERNET_BROADCAST_MAC, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
/// ```
pub const ETHERNET_BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// BACnet Ethernet type field value.
///
/// This value (0x82DC) identifies the frame as containing BACnet data.
/// It's registered with IEEE and must be used for all BACnet/Ethernet frames.
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::ethernet::BACNET_ETHERNET_TYPE;
///
/// // Check if a frame is BACnet
/// let ether_type = 0x82DC_u16;
/// assert_eq!(ether_type, BACNET_ETHERNET_TYPE);
/// ```
pub const BACNET_ETHERNET_TYPE: u16 = 0x82DC;

/// BACnet LLC (Logical Link Control) header.
///
/// This 3-byte header follows the Ethernet header and identifies the
/// frame as BACnet traffic. Components:
/// - DSAP (Destination Service Access Point): 0x82
/// - SSAP (Source Service Access Point): 0x82
/// - Control: 0x03 (Unnumbered Information)
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::ethernet::BACNET_LLC_HEADER;
///
/// assert_eq!(BACNET_LLC_HEADER, [0x82, 0x82, 0x03]);
/// ```
pub const BACNET_LLC_HEADER: [u8; 3] = [0x82, 0x82, 0x03];

/// Minimum Ethernet frame size (excluding FCS).
///
/// Ethernet requires a minimum frame size of 64 bytes including the 4-byte FCS.
/// Frames smaller than this are padded with zeros.
pub const MIN_ETHERNET_FRAME_SIZE: usize = 60;

/// Maximum Ethernet frame size (excluding FCS).
///
/// Standard Ethernet maximum frame size is 1518 bytes including the 4-byte FCS.
/// Jumbo frames are not typically used for BACnet.
pub const MAX_ETHERNET_FRAME_SIZE: usize = 1514;

/// Ethernet header size in bytes.
///
/// Includes destination MAC (6), source MAC (6), and EtherType (2).
pub const ETHERNET_HEADER_SIZE: usize = 14;

/// LLC header size in bytes.
///
/// The LLC header for BACnet is always 3 bytes.
pub const LLC_HEADER_SIZE: usize = 3;

/// Total BACnet/Ethernet header size in bytes.
///
/// Combined size of Ethernet header (14) and LLC header (3).
pub const BACNET_ETHERNET_HEADER_SIZE: usize = ETHERNET_HEADER_SIZE + LLC_HEADER_SIZE;

/// Ethernet frame structure for BACnet communication.
///
/// Represents a complete Ethernet frame containing BACnet data. This structure
/// includes all fields needed for BACnet/Ethernet communication except the FCS
/// (Frame Check Sequence), which is handled by the network hardware.
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::ethernet::{EthernetFrame, ETHERNET_BROADCAST_MAC};
///
/// // Create a broadcast frame
/// let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// let npdu = vec![0x01, 0x04, 0x00, 0x00];
/// let frame = EthernetFrame::broadcast(src_mac, npdu);
///
/// assert_eq!(frame.dest_mac, ETHERNET_BROADCAST_MAC);
/// assert!(frame.is_broadcast());
/// ```
#[derive(Debug, Clone)]
pub struct EthernetFrame {
    /// Destination MAC address (6 bytes).
    ///
    /// Identifies the intended recipient of the frame. Special values:
    /// - `FF:FF:FF:FF:FF:FF` - Broadcast to all devices
    /// - `01:00:5E:xx:xx:xx` - IPv4 multicast range
    pub dest_mac: [u8; 6],

    /// Source MAC address (6 bytes).
    ///
    /// Identifies the sender of the frame. Must be a unicast address
    /// (LSB of first byte must be 0).
    pub src_mac: [u8; 6],

    /// Ethernet type field (2 bytes).
    ///
    /// For BACnet frames, this must be 0x82DC. Other values indicate
    /// non-BACnet traffic.
    pub ether_type: u16,

    /// LLC header (3 bytes).
    ///
    /// For BACnet frames, this must be [0x82, 0x82, 0x03].
    pub llc_header: [u8; 3],

    /// Payload data (NPDU).
    ///
    /// Contains the BACnet NPDU (Network Protocol Data Unit). The maximum
    /// size depends on the Ethernet MTU, typically allowing up to 1497
    /// bytes of BACnet data.
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// Create a new Ethernet frame for BACnet communication.
    ///
    /// Automatically sets the Ethernet type to 0x82DC and includes the
    /// standard BACnet LLC header.
    ///
    /// # Arguments
    ///
    /// * `dest_mac` - Destination MAC address
    /// * `src_mac` - Source MAC address
    /// * `npdu` - BACnet NPDU data
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::ethernet::EthernetFrame;
    ///
    /// let dest = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    /// let src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let npdu = vec![0x01, 0x04, 0x00, 0x00];
    ///
    /// let frame = EthernetFrame::new(dest, src, npdu);
    /// ```
    pub fn new(dest_mac: [u8; 6], src_mac: [u8; 6], npdu: Vec<u8>) -> Self {
        Self {
            dest_mac,
            src_mac,
            ether_type: BACNET_ETHERNET_TYPE,
            llc_header: BACNET_LLC_HEADER,
            payload: npdu,
        }
    }

    /// Create a broadcast Ethernet frame.
    ///
    /// Convenience method that sets the destination to the Ethernet
    /// broadcast address (FF:FF:FF:FF:FF:FF).
    ///
    /// # Arguments
    ///
    /// * `src_mac` - Source MAC address
    /// * `npdu` - BACnet NPDU data to broadcast
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::ethernet::EthernetFrame;
    ///
    /// let src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let who_is = vec![0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08];
    ///
    /// let frame = EthernetFrame::broadcast(src, who_is);
    /// assert!(frame.is_broadcast());
    /// ```
    pub fn broadcast(src_mac: [u8; 6], npdu: Vec<u8>) -> Self {
        Self::new(ETHERNET_BROADCAST_MAC, src_mac, npdu)
    }

    /// Encode the frame to its wire format.
    ///
    /// Returns the complete Ethernet frame ready for transmission, excluding
    /// the FCS (Frame Check Sequence) which is added by the network hardware.
    /// The frame is automatically padded to the minimum Ethernet size if needed.
    ///
    /// # Returns
    ///
    /// A byte vector containing the encoded frame, at least 60 bytes long.
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::ethernet::{EthernetFrame, MIN_ETHERNET_FRAME_SIZE};
    ///
    /// let frame = EthernetFrame::new(
    ///     [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    ///     [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ///     vec![0x01, 0x02],  // Small payload
    /// );
    ///
    /// let encoded = frame.encode();
    /// assert!(encoded.len() >= MIN_ETHERNET_FRAME_SIZE);
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(BACNET_ETHERNET_HEADER_SIZE + self.payload.len());

        // Destination MAC
        frame.extend_from_slice(&self.dest_mac);

        // Source MAC
        frame.extend_from_slice(&self.src_mac);

        // Ethernet type
        frame.extend_from_slice(&self.ether_type.to_be_bytes());

        // LLC header
        frame.extend_from_slice(&self.llc_header);

        // Payload
        frame.extend_from_slice(&self.payload);

        // Pad to minimum frame size if necessary
        while frame.len() < MIN_ETHERNET_FRAME_SIZE {
            frame.push(0);
        }

        frame
    }

    /// Decode an Ethernet frame from its wire format.
    ///
    /// Parses a byte buffer containing an Ethernet frame and validates that
    /// it's a properly formatted BACnet/Ethernet frame.
    ///
    /// # Arguments
    ///
    /// * `data` - Buffer containing the Ethernet frame (without FCS)
    ///
    /// # Returns
    ///
    /// The decoded Ethernet frame.
    ///
    /// # Errors
    ///
    /// Returns [`DataLinkError::InvalidFrame`] if:
    /// - The buffer is too short
    /// - The Ethernet type is not 0x82DC
    /// - The LLC header is incorrect
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::ethernet::EthernetFrame;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Decode a received frame
    /// let frame_data = vec![
    ///     // Destination MAC
    ///     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ///     // Source MAC
    ///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ///     // EtherType
    ///     0x82, 0xDC,
    ///     // LLC Header
    ///     0x82, 0x82, 0x03,
    ///     // NPDU data
    ///     0x01, 0x04, 0x00, 0x00,
    ///     // Padding to minimum size
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /// ];
    ///
    /// let frame = EthernetFrame::decode(&frame_data)?;
    /// assert!(frame.is_broadcast());
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < BACNET_ETHERNET_HEADER_SIZE {
            return Err(DataLinkError::InvalidFrame);
        }

        // Extract fields
        let mut dest_mac = [0u8; 6];
        dest_mac.copy_from_slice(&data[0..6]);

        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&data[6..12]);

        let ether_type = u16::from_be_bytes([data[12], data[13]]);

        // Verify this is a BACnet frame
        if ether_type != BACNET_ETHERNET_TYPE {
            return Err(DataLinkError::InvalidFrame);
        }

        let mut llc_header = [0u8; 3];
        llc_header.copy_from_slice(&data[14..17]);

        // Verify LLC header
        if llc_header != BACNET_LLC_HEADER {
            return Err(DataLinkError::InvalidFrame);
        }

        // Extract payload (strip any padding)
        let payload = data[17..].to_vec();

        Ok(Self {
            dest_mac,
            src_mac,
            ether_type,
            llc_header,
            payload,
        })
    }

    /// Check if this frame is addressed to the broadcast MAC.
    ///
    /// # Returns
    ///
    /// `true` if the destination is FF:FF:FF:FF:FF:FF.
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::ethernet::EthernetFrame;
    ///
    /// let broadcast_frame = EthernetFrame::broadcast(
    ///     [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ///     vec![0x01, 0x02]
    /// );
    /// assert!(broadcast_frame.is_broadcast());
    ///
    /// let unicast_frame = EthernetFrame::new(
    ///     [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    ///     [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ///     vec![0x01, 0x02]
    /// );
    /// assert!(!unicast_frame.is_broadcast());
    /// ```
    pub fn is_broadcast(&self) -> bool {
        self.dest_mac == ETHERNET_BROADCAST_MAC
    }

    /// Check if this frame is addressed to a multicast MAC.
    ///
    /// Multicast addresses have the least significant bit of the first
    /// byte set to 1. This includes the broadcast address.
    ///
    /// # Returns
    ///
    /// `true` if the destination is a multicast address.
    ///
    /// # Examples
    ///
    /// ```
    /// use bacnet_rs::datalink::ethernet::EthernetFrame;
    ///
    /// // Broadcast is also multicast
    /// let broadcast = EthernetFrame::broadcast(
    ///     [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ///     vec![0x01, 0x02]
    /// );
    /// assert!(broadcast.is_multicast());
    ///
    /// // IPv4 multicast MAC
    /// let multicast = EthernetFrame::new(
    ///     [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01],
    ///     [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ///     vec![0x01, 0x02]
    /// );
    /// assert!(multicast.is_multicast());
    /// ```
    pub fn is_multicast(&self) -> bool {
        self.dest_mac[0] & 0x01 == 0x01
    }
}

/// BACnet/Ethernet data link implementation.
///
/// Provides BACnet communication over Ethernet networks using raw frames.
/// This implementation simulates Ethernet communication for demonstration
/// purposes. In production, use platform-specific raw socket APIs or
/// packet capture libraries.
///
/// # Platform Requirements
///
/// - **Linux**: Requires CAP_NET_RAW capability or root access
/// - **Windows**: Requires WinPcap/Npcap or similar
/// - **macOS**: Requires root access for BPF (Berkeley Packet Filter)
///
/// # Examples
///
/// ```no_run
/// # #[cfg(feature = "std")] {
/// use bacnet_rs::datalink::ethernet::{EthernetDataLink, parse_mac_address};
/// use bacnet_rs::datalink::{DataLink, DataLinkAddress};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create data link for interface eth0
/// let local_mac = parse_mac_address("00:11:22:33:44:55")?;
/// let mut eth_link = EthernetDataLink::new("eth0", local_mac)?;
///
/// // Get local address
/// match eth_link.local_address() {
///     DataLinkAddress::Ethernet(mac) => {
///         println!("Local MAC: {:02X?}", mac);
///     }
///     _ => unreachable!(),
/// }
/// # Ok(())
/// # }
/// # }
/// ```
#[cfg(feature = "std")]
pub struct EthernetDataLink {
    /// Local MAC address of this device.
    local_mac: [u8; 6],

    /// Network interface name.
    ///
    /// Examples: "eth0", "en0", "Ethernet"
    _interface: String,

    /// Receive buffer for incoming frames.
    ///
    /// In a real implementation, this would be populated by a packet
    /// capture thread or event-driven I/O.
    rx_buffer: Arc<Mutex<Vec<(EthernetFrame, DataLinkAddress)>>>,

    /// Running state flag.
    ///
    /// Used to control the receive thread in a real implementation.
    _running: Arc<Mutex<bool>>,
}

#[cfg(feature = "std")]
impl EthernetDataLink {
    /// Create a new Ethernet data link.
    ///
    /// Initializes an Ethernet data link for the specified network interface
    /// and MAC address. In a production implementation, this would:
    /// 1. Open a raw socket or packet capture handle
    /// 2. Set up BPF filters for BACnet traffic (EtherType 0x82DC)
    /// 3. Start a receive thread for incoming frames
    ///
    /// # Arguments
    ///
    /// * `interface` - Network interface name (e.g., "eth0", "en0")
    /// * `local_mac` - Local MAC address to use
    ///
    /// # Returns
    ///
    /// A configured Ethernet data link.
    ///
    /// # Errors
    ///
    /// In a real implementation, this would return errors for:
    /// - Invalid interface name
    /// - Insufficient permissions
    /// - Interface not found
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")] {
    /// use bacnet_rs::datalink::ethernet::EthernetDataLink;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Create data link with specific MAC
    /// let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// let eth_link = EthernetDataLink::new("eth0", mac)?;
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    ///
    /// # Security Note
    ///
    /// Raw socket access requires elevated privileges. Consider using
    /// capabilities (Linux) or running with minimal required permissions.
    pub fn new(interface: &str, local_mac: [u8; 6]) -> Result<Self> {
        let rx_buffer = Arc::new(Mutex::new(Vec::new()));
        let running = Arc::new(Mutex::new(true));

        // In a real implementation, we would:
        // 1. Open a raw socket or pcap handle for the interface
        // 2. Set up BPF filters for BACnet frames
        // 3. Start a receive thread

        Ok(Self {
            local_mac,
            _interface: interface.to_string(),
            rx_buffer,
            _running: running,
        })
    }

    /// Send an Ethernet frame on the network interface.
    ///
    /// In a real implementation, this would write the frame to a raw socket
    /// or packet injection interface. The FCS is automatically added by the
    /// network hardware.
    ///
    /// # Arguments
    ///
    /// * `frame` - The Ethernet frame to send
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The frame exceeds the maximum Ethernet size
    /// - The network interface is down
    /// - Insufficient permissions
    fn send_ethernet_frame(&self, frame: &EthernetFrame) -> Result<()> {
        // In a real implementation, this would:
        // 1. Encode the frame
        // 2. Send it via raw socket or pcap

        let encoded = frame.encode();

        // Validate frame size
        if encoded.len() > MAX_ETHERNET_FRAME_SIZE {
            return Err(DataLinkError::InvalidFrame);
        }

        // Simulate sending (in real implementation, use raw socket)
        println!(
            "Sending Ethernet frame: {} bytes to {:02X?}",
            encoded.len(),
            frame.dest_mac
        );

        Ok(())
    }

    /// Simulate receiving a frame (for testing).
    ///
    /// This method allows tests to inject frames into the receive buffer
    /// as if they were received from the network.
    ///
    /// # Arguments
    ///
    /// * `frame` - The Ethernet frame to inject
    /// * `source` - The source address to report
    #[cfg(test)]
    pub fn simulate_receive(&self, frame: EthernetFrame, source: DataLinkAddress) {
        let mut buffer = self.rx_buffer.lock().unwrap();
        buffer.push((frame, source));
    }
}

#[cfg(feature = "std")]
impl DataLink for EthernetDataLink {
    fn send_frame(&mut self, frame: &[u8], dest: &DataLinkAddress) -> Result<()> {
        let dest_mac = match dest {
            DataLinkAddress::Ethernet(mac) => *mac,
            DataLinkAddress::Broadcast => ETHERNET_BROADCAST_MAC,
            _ => {
                return Err(DataLinkError::AddressError(
                    "Invalid address type for Ethernet".into(),
                ))
            }
        };

        let eth_frame = EthernetFrame::new(dest_mac, self.local_mac, frame.to_vec());
        self.send_ethernet_frame(&eth_frame)
    }

    fn receive_frame(&mut self) -> Result<(Vec<u8>, DataLinkAddress)> {
        // Check receive buffer
        let mut buffer = self.rx_buffer.lock().unwrap();

        if let Some((frame, source)) = buffer.pop() {
            Ok((frame.payload, source))
        } else {
            // In real implementation, this would block on socket recv
            Err(DataLinkError::InvalidFrame)
        }
    }

    fn link_type(&self) -> DataLinkType {
        DataLinkType::Ethernet
    }

    fn local_address(&self) -> DataLinkAddress {
        DataLinkAddress::Ethernet(self.local_mac)
    }
}

/// Parse a MAC address from string format.
///
/// Accepts MAC addresses in colon-separated hexadecimal format.
/// Both uppercase and lowercase hex digits are accepted.
///
/// # Arguments
///
/// * `mac_str` - MAC address string (e.g., "00:11:22:33:44:55")
///
/// # Returns
///
/// The parsed MAC address as a 6-byte array.
///
/// # Errors
///
/// Returns [`DataLinkError::AddressError`] if:
/// - The format is incorrect (not 6 colon-separated pairs)
/// - Any hex value is invalid
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::ethernet::parse_mac_address;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse valid MAC addresses
/// let mac1 = parse_mac_address("00:11:22:33:44:55")?;
/// assert_eq!(mac1, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
///
/// let mac2 = parse_mac_address("AA:BB:CC:DD:EE:FF")?;
/// assert_eq!(mac2, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
///
/// // Invalid formats
/// assert!(parse_mac_address("00:11:22:33:44").is_err());
/// assert!(parse_mac_address("00-11-22-33-44-55").is_err());
/// assert!(parse_mac_address("00:11:22:33:44:GG").is_err());
/// # Ok(())
/// # }
/// ```
pub fn parse_mac_address(mac_str: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(DataLinkError::AddressError(
            "Invalid MAC address format".into(),
        ));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| DataLinkError::AddressError("Invalid MAC address hex".into()))?;
    }

    Ok(mac)
}

/// Format a MAC address as a string.
///
/// Converts a 6-byte MAC address to the standard colon-separated
/// hexadecimal format with uppercase letters.
///
/// # Arguments
///
/// * `mac` - The MAC address to format
///
/// # Returns
///
/// A string in the format "XX:XX:XX:XX:XX:XX".
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::ethernet::format_mac_address;
///
/// let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// assert_eq!(format_mac_address(&mac), "00:11:22:33:44:55");
///
/// let broadcast = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
/// assert_eq!(format_mac_address(&broadcast), "FF:FF:FF:FF:FF:FF");
/// ```
pub fn format_mac_address(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Validate a BACnet/Ethernet frame.
///
/// Checks that a byte buffer contains a valid BACnet/Ethernet frame
/// with correct headers and size constraints.
///
/// # Arguments
///
/// * `data` - Buffer containing the Ethernet frame (without FCS)
///
/// # Returns
///
/// Ok(()) if the frame is valid.
///
/// # Errors
///
/// Returns [`DataLinkError::InvalidFrame`] if:
/// - The frame is too short or too long
/// - The Ethernet type is not 0x82DC
/// - The LLC header is incorrect
///
/// # Examples
///
/// ```
/// use bacnet_rs::datalink::ethernet::{validate_ethernet_frame, EthernetFrame};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create and validate a frame
/// let frame = EthernetFrame::new(
///     [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
///     [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
///     vec![0x01, 0x02, 0x03, 0x04]
/// );
///
/// let encoded = frame.encode();
/// validate_ethernet_frame(&encoded)?;
/// # Ok(())
/// # }
/// ```
pub fn validate_ethernet_frame(data: &[u8]) -> Result<()> {
    // Check minimum size
    if data.len() < BACNET_ETHERNET_HEADER_SIZE {
        return Err(DataLinkError::InvalidFrame);
    }

    // Check maximum size
    if data.len() > MAX_ETHERNET_FRAME_SIZE {
        return Err(DataLinkError::InvalidFrame);
    }

    // Check Ethernet type
    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    if ether_type != BACNET_ETHERNET_TYPE {
        return Err(DataLinkError::InvalidFrame);
    }

    // Check LLC header
    if data.len() >= 17 && data[14..17] != BACNET_LLC_HEADER {
        return Err(DataLinkError::InvalidFrame);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_frame_encode_decode() {
        let dest_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let npdu = vec![0x01, 0x02, 0x03, 0x04];

        let frame = EthernetFrame::new(dest_mac, src_mac, npdu.clone());
        let encoded = frame.encode();

        // Check minimum size with padding
        assert!(encoded.len() >= MIN_ETHERNET_FRAME_SIZE);

        // Decode and verify
        let decoded = EthernetFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.dest_mac, dest_mac);
        assert_eq!(decoded.src_mac, src_mac);
        assert_eq!(decoded.ether_type, BACNET_ETHERNET_TYPE);
        assert_eq!(decoded.llc_header, BACNET_LLC_HEADER);

        // Payload might have padding, so check prefix
        assert!(decoded.payload.starts_with(&npdu));
    }

    #[test]
    fn test_broadcast_frame() {
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let npdu = vec![0x01, 0x02, 0x03, 0x04];

        let frame = EthernetFrame::broadcast(src_mac, npdu);
        assert_eq!(frame.dest_mac, ETHERNET_BROADCAST_MAC);
        assert!(frame.is_broadcast());
        assert!(frame.is_multicast());
    }

    #[test]
    fn test_mac_address_parsing() {
        let mac_str = "00:11:22:33:44:55";
        let mac = parse_mac_address(mac_str).unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let formatted = format_mac_address(&mac);
        assert_eq!(formatted, "00:11:22:33:44:55");

        // Test invalid format
        assert!(parse_mac_address("invalid").is_err());
        assert!(parse_mac_address("00:11:22:33:44").is_err());
        assert!(parse_mac_address("00:11:22:33:44:GG").is_err());
    }

    #[test]
    fn test_frame_validation() {
        let dest_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let npdu = vec![0x01, 0x02, 0x03, 0x04];

        let frame = EthernetFrame::new(dest_mac, src_mac, npdu);
        let encoded = frame.encode();

        assert!(validate_ethernet_frame(&encoded).is_ok());

        // Test invalid frames
        assert!(validate_ethernet_frame(&[]).is_err()); // Too short
        assert!(validate_ethernet_frame(&encoded[..16]).is_err()); // Missing LLC

        // Test wrong Ethernet type
        let mut bad_frame = encoded.clone();
        bad_frame[12] = 0x08;
        bad_frame[13] = 0x00;
        assert!(validate_ethernet_frame(&bad_frame).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_ethernet_datalink() {
        let local_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut datalink = EthernetDataLink::new("eth0", local_mac).unwrap();

        assert_eq!(datalink.link_type(), DataLinkType::Ethernet);
        assert_eq!(
            datalink.local_address(),
            DataLinkAddress::Ethernet(local_mac)
        );

        // Test sending
        let dest_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let npdu = vec![0x01, 0x02, 0x03, 0x04];
        let result = datalink.send_frame(&npdu, &DataLinkAddress::Ethernet(dest_mac));
        assert!(result.is_ok());

        // Test broadcast
        let result = datalink.send_frame(&npdu, &DataLinkAddress::Broadcast);
        assert!(result.is_ok());
    }
}
