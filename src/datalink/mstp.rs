//! BACnet MS/TP (Master-Slave/Token-Passing) Data Link Implementation
//!
//! This module implements the BACnet MS/TP data link layer as defined in ASHRAE 135 Clause 9.
//! MS/TP provides multi-drop, half-duplex communication over EIA-485 (RS-485) physical layer.
//!
//! # Overview
//!
//! MS/TP provides:
//! - Token-passing protocol for medium access control
//! - Master and slave node support
//! - Automatic token management
//! - Frame error detection using CRC
//! - Support for up to 128 master nodes (addresses 0-127)
//! - Support for up to 127 slave nodes (addresses 128-254)
//!
//! # Frame Format
//!
//! MS/TP Frame:
//! - Preamble (2 bytes): 0x55, 0xFF
//! - Frame Type (1 byte)
//! - Destination Address (1 byte)
//! - Source Address (1 byte)
//! - Data Length (2 bytes)
//! - Header CRC (1 byte)
//! - Data (0-501 bytes)
//! - Data CRC (2 bytes) - only if data length > 0

#[cfg(feature = "std")]
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use crate::datalink::{DataLink, DataLinkAddress, DataLinkType};
use crate::datalink::{DataLinkError, Result};
use crate::util::crc16_mstp;

/// MS/TP frame preamble bytes
pub const MSTP_PREAMBLE_55: u8 = 0x55;
pub const MSTP_PREAMBLE_FF: u8 = 0xFF;

/// Maximum MS/TP data length
pub const MSTP_MAX_DATA_LENGTH: usize = 501;

/// MS/TP header size (without data)
pub const MSTP_HEADER_SIZE: usize = 8;

/// MS/TP maximum frame size
pub const MSTP_MAX_FRAME_SIZE: usize = MSTP_HEADER_SIZE + MSTP_MAX_DATA_LENGTH + 2;

/// MS/TP frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MstpFrameType {
    /// Token frame
    Token = 0,
    /// Poll For Master frame
    PollForMaster = 1,
    /// Reply To Poll For Master frame
    ReplyToPollForMaster = 2,
    /// Test Request frame
    TestRequest = 3,
    /// Test Response frame
    TestResponse = 4,
    /// BACnet Data Expecting Reply frame
    BacnetDataExpectingReply = 5,
    /// BACnet Data Not Expecting Reply frame
    BacnetDataNotExpectingReply = 6,
    /// Reply Postponed frame
    ReplyPostponed = 7,
}

impl MstpFrameType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Token),
            1 => Some(Self::PollForMaster),
            2 => Some(Self::ReplyToPollForMaster),
            3 => Some(Self::TestRequest),
            4 => Some(Self::TestResponse),
            5 => Some(Self::BacnetDataExpectingReply),
            6 => Some(Self::BacnetDataNotExpectingReply),
            7 => Some(Self::ReplyPostponed),
            _ => None,
        }
    }
}

/// MS/TP frame structure
#[derive(Debug, Clone)]
pub struct MstpFrame {
    /// Frame type
    pub frame_type: MstpFrameType,
    /// Destination address
    pub destination: u8,
    /// Source address
    pub source: u8,
    /// Data length
    pub data_length: u16,
    /// Header CRC
    pub header_crc: u8,
    /// Frame data
    pub data: Vec<u8>,
    /// Data CRC (only present if data_length > 0)
    pub data_crc: Option<u16>,
}

impl MstpFrame {
    /// Create a new MS/TP frame
    pub fn new(
        frame_type: MstpFrameType,
        destination: u8,
        source: u8,
        data: Vec<u8>,
    ) -> Result<Self> {
        if data.len() > MSTP_MAX_DATA_LENGTH {
            return Err(DataLinkError::InvalidFrame);
        }

        let data_length = data.len() as u16;

        // Calculate header CRC (without preamble)
        let header_bytes = [
            frame_type as u8,
            destination,
            source,
            (data_length >> 8) as u8,
            (data_length & 0xFF) as u8,
        ];
        let header_crc = calculate_header_crc(&header_bytes);

        // Calculate data CRC if there's data
        let data_crc = if !data.is_empty() {
            Some(crc16_mstp(&data))
        } else {
            None
        };

        Ok(Self {
            frame_type,
            destination,
            source,
            data_length,
            header_crc,
            data,
            data_crc,
        })
    }

    /// Create a token frame
    pub fn token(destination: u8, source: u8) -> Result<Self> {
        Self::new(MstpFrameType::Token, destination, source, Vec::new())
    }

    /// Create a BACnet data frame
    pub fn bacnet_data(
        destination: u8,
        source: u8,
        data: Vec<u8>,
        expecting_reply: bool,
    ) -> Result<Self> {
        let frame_type = if expecting_reply {
            MstpFrameType::BacnetDataExpectingReply
        } else {
            MstpFrameType::BacnetDataNotExpectingReply
        };
        Self::new(frame_type, destination, source, data)
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(MSTP_HEADER_SIZE + self.data.len() + 2);

        // Preamble
        frame.push(MSTP_PREAMBLE_55);
        frame.push(MSTP_PREAMBLE_FF);

        // Header
        frame.push(self.frame_type as u8);
        frame.push(self.destination);
        frame.push(self.source);
        frame.push((self.data_length >> 8) as u8);
        frame.push((self.data_length & 0xFF) as u8);
        frame.push(self.header_crc);

        // Data
        if !self.data.is_empty() {
            frame.extend_from_slice(&self.data);

            // Data CRC
            if let Some(crc) = self.data_crc {
                frame.push((crc & 0xFF) as u8);
                frame.push((crc >> 8) as u8);
            }
        }

        frame
    }

    /// Decode frame from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < MSTP_HEADER_SIZE {
            return Err(DataLinkError::InvalidFrame);
        }

        // Check preamble
        if data[0] != MSTP_PREAMBLE_55 || data[1] != MSTP_PREAMBLE_FF {
            return Err(DataLinkError::InvalidFrame);
        }

        // Parse header
        let frame_type = MstpFrameType::from_u8(data[2]).ok_or(DataLinkError::InvalidFrame)?;
        let destination = data[3];
        let source = data[4];
        let data_length = ((data[5] as u16) << 8) | (data[6] as u16);
        let header_crc = data[7];

        // Verify header CRC
        let header_bytes = [data[2], data[3], data[4], data[5], data[6]];
        let calculated_crc = calculate_header_crc(&header_bytes);
        if calculated_crc != header_crc {
            return Err(DataLinkError::CrcError);
        }

        // Check frame size
        let expected_size =
            MSTP_HEADER_SIZE + data_length as usize + if data_length > 0 { 2 } else { 0 };
        if data.len() != expected_size {
            return Err(DataLinkError::InvalidFrame);
        }

        // Parse data and CRC if present
        let (frame_data, data_crc) = if data_length > 0 {
            let data_start = MSTP_HEADER_SIZE;
            let data_end = data_start + data_length as usize;
            let frame_data = data[data_start..data_end].to_vec();

            // Get data CRC
            let crc_low = data[data_end];
            let crc_high = data[data_end + 1];
            let data_crc = ((crc_high as u16) << 8) | (crc_low as u16);

            // Verify data CRC
            let calculated_crc = crc16_mstp(&frame_data);
            if calculated_crc != data_crc {
                return Err(DataLinkError::CrcError);
            }

            (frame_data, Some(data_crc))
        } else {
            (Vec::new(), None)
        };

        Ok(Self {
            frame_type,
            destination,
            source,
            data_length,
            header_crc,
            data: frame_data,
            data_crc,
        })
    }

    /// Check if this is a token frame
    pub fn is_token(&self) -> bool {
        self.frame_type == MstpFrameType::Token
    }

    /// Check if this is a data frame
    pub fn is_data(&self) -> bool {
        matches!(
            self.frame_type,
            MstpFrameType::BacnetDataExpectingReply | MstpFrameType::BacnetDataNotExpectingReply
        )
    }
}

/// MS/TP node state
///
/// # Important Implementation Note: WAIT_FOR_REPLY State
///
/// When implementing the state machine, the WAIT_FOR_REPLY state must use a "negative list"
/// approach to handle frame reception (fix from bacnet-stack commit f877ca0eb):
///
/// **Problem:** Previous implementations only accepted specific known reply frame types,
/// which caused segmented Complex-ACK frames and proprietary frames to be dropped.
///
/// **Solution:** Accept any frame that is NOT explicitly a non-reply frame:
/// - Reject only: Token, PollForMaster, ReplyToPollForMaster, TestRequest
/// - Accept everything else as potential replies (including Complex-ACK segments, proprietary frames)
///
/// ```rust,ignore
/// // Correct implementation:
/// match frame.frame_type {
///     // Known non-reply frames - reject
///     MstpFrameType::Token |
///     MstpFrameType::PollForMaster |
///     MstpFrameType::ReplyToPollForMaster |
///     MstpFrameType::TestRequest => {
///         // ReceivedUnexpectedFrame - go to Idle
///         self.state = MstpState::Idle;
///     }
///     // All other frames accepted as replies (including unknown/proprietary)
///     _ => {
///         // ReceivedReply - pass to higher layers
///         self.put_receive(&frame);
///         self.state = MstpState::DoneWithToken;
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MstpState {
    /// Initialize state
    Initialize,
    /// Idle state (no token)
    Idle,
    /// Use token state
    UseToken,
    /// Wait for reply state (after sending a frame expecting reply)
    /// See enum documentation for critical implementation details
    WaitForReply,
    /// Pass token state
    PassToken,
    /// No token state
    NoToken,
    /// Poll for master state
    PollForMaster,
    /// Answer data request state
    AnswerDataRequest,
    /// Done with token state
    DoneWithToken,
}

/// MS/TP master node configuration
#[derive(Debug, Clone)]
pub struct MstpConfig {
    /// Local station address (0-254, 255 is broadcast)
    pub station_address: u8,
    /// Maximum master address (highest master on network)
    pub max_master: u8,
    /// Maximum info frames (number of frames to send when holding token)
    pub max_info_frames: u8,
    /// Token rotation timeout (milliseconds)
    pub token_timeout: u64,
    /// Reply timeout (milliseconds)
    pub reply_timeout: u64,
    /// Usage timeout (milliseconds)
    pub usage_timeout: u64,
}

impl Default for MstpConfig {
    fn default() -> Self {
        Self {
            station_address: 1,
            max_master: 127,
            max_info_frames: 1,
            token_timeout: 500,
            reply_timeout: 255,
            usage_timeout: 50,
        }
    }
}

/// Type alias for receive queue
#[cfg(feature = "std")]
type ReceiveQueue = Arc<Mutex<VecDeque<(Vec<u8>, DataLinkAddress)>>>;

/// MS/TP data link implementation
#[cfg(feature = "std")]
pub struct MstpDataLink {
    /// Configuration
    config: MstpConfig,
    /// Current state
    _state: Arc<Mutex<MstpState>>,
    /// Token holder
    _token_holder: Arc<Mutex<Option<u8>>>,
    /// Next station for token passing
    _next_station: Arc<Mutex<u8>>,
    /// Send queue
    send_queue: Arc<Mutex<VecDeque<(MstpFrame, DataLinkAddress)>>>,
    /// Receive queue
    receive_queue: ReceiveQueue,
    /// Serial port name
    _port_name: String,
    /// Running flag
    _running: Arc<Mutex<bool>>,
}

#[cfg(feature = "std")]
impl MstpDataLink {
    /// Create a new MS/TP data link
    ///
    /// Note: In a real implementation, this would use a serial port library
    /// to communicate over RS-485. This is a simplified simulation.
    pub fn new(port_name: &str, config: MstpConfig) -> Result<Self> {
        let state = Arc::new(Mutex::new(MstpState::Initialize));
        let token_holder = Arc::new(Mutex::new(None));
        let next_station = Arc::new(Mutex::new(
            (config.station_address + 1) % (config.max_master + 1),
        ));
        let send_queue = Arc::new(Mutex::new(VecDeque::new()));
        let receive_queue = Arc::new(Mutex::new(VecDeque::new()));
        let running = Arc::new(Mutex::new(true));

        // In a real implementation, we would:
        // 1. Open serial port with appropriate settings (9600-115200 bps, 8N1)
        // 2. Configure RS-485 transceiver control
        // 3. Start token passing state machine thread

        Ok(Self {
            config,
            _state: state,
            _token_holder: token_holder,
            _next_station: next_station,
            send_queue,
            receive_queue,
            _port_name: port_name.to_string(),
            _running: running,
        })
    }

    /// Send an MS/TP frame
    fn _send_mstp_frame(&self, frame: &MstpFrame) -> Result<()> {
        // In a real implementation, this would:
        // 1. Enable RS-485 transmitter
        // 2. Send frame bytes over serial port
        // 3. Wait for transmission to complete
        // 4. Disable RS-485 transmitter

        let encoded = frame.encode();

        println!(
            "MS/TP: Sending {} frame from {} to {}, {} bytes",
            match frame.frame_type {
                MstpFrameType::Token => "Token",
                MstpFrameType::BacnetDataExpectingReply => "Data (expecting reply)",
                MstpFrameType::BacnetDataNotExpectingReply => "Data (no reply)",
                _ => "Other",
            },
            frame.source,
            frame.destination,
            encoded.len()
        );

        Ok(())
    }

    /// Handle token possession
    fn _handle_token(&mut self) -> Result<()> {
        let mut send_queue = self.send_queue.lock().unwrap();

        // Send up to max_info_frames
        let mut frames_sent = 0;
        while frames_sent < self.config.max_info_frames && !send_queue.is_empty() {
            if let Some((frame, _)) = send_queue.pop_front() {
                self._send_mstp_frame(&frame)?;
                frames_sent += 1;
            }
        }

        // Pass token to next station
        let next = *self._next_station.lock().unwrap();
        let token_frame = MstpFrame::token(next, self.config.station_address)?;
        self._send_mstp_frame(&token_frame)?;

        // Update next station
        let mut next_station = self._next_station.lock().unwrap();
        *next_station = (*next_station + 1) % (self.config.max_master + 1);

        Ok(())
    }

    /// Simulate receiving a frame (for testing)
    #[cfg(test)]
    pub fn simulate_receive(&self, frame: MstpFrame) {
        if frame.is_data() && !frame.data.is_empty() {
            let mut receive_queue = self.receive_queue.lock().unwrap();
            receive_queue.push_back((frame.data.clone(), DataLinkAddress::MsTP(frame.source)));
        }

        if frame.is_token() && frame.destination == self.config.station_address {
            let mut token_holder = self._token_holder.lock().unwrap();
            *token_holder = Some(self.config.station_address);

            let mut state = self._state.lock().unwrap();
            *state = MstpState::UseToken;
        }
    }
}

#[cfg(feature = "std")]
impl DataLink for MstpDataLink {
    fn send_frame(&mut self, frame: &[u8], dest: &DataLinkAddress) -> Result<()> {
        let dest_addr = match dest {
            DataLinkAddress::MsTP(addr) => *addr,
            DataLinkAddress::Broadcast => 255,
            _ => {
                return Err(DataLinkError::AddressError(
                    "Invalid address type for MS/TP".into(),
                ))
            }
        };

        // Create MS/TP frame
        let mstp_frame = MstpFrame::bacnet_data(
            dest_addr,
            self.config.station_address,
            frame.to_vec(),
            false, // For now, assume no reply expected
        )?;

        // Queue frame for sending when we have the token
        let mut send_queue = self.send_queue.lock().unwrap();
        send_queue.push_back((mstp_frame, DataLinkAddress::MsTP(dest_addr)));

        Ok(())
    }

    fn receive_frame(&mut self) -> Result<(Vec<u8>, DataLinkAddress)> {
        let mut receive_queue = self.receive_queue.lock().unwrap();

        if let Some((data, source)) = receive_queue.pop_front() {
            Ok((data, source))
        } else {
            // In real implementation, this would check serial port
            Err(DataLinkError::InvalidFrame)
        }
    }

    fn link_type(&self) -> DataLinkType {
        DataLinkType::MsTP
    }

    fn local_address(&self) -> DataLinkAddress {
        DataLinkAddress::MsTP(self.config.station_address)
    }
}

/// Calculate MS/TP header CRC
fn calculate_header_crc(header: &[u8; 5]) -> u8 {
    let mut crc = 0xFFu8;

    for &byte in header {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x01 != 0 {
                crc = (crc >> 1) ^ 0x55;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

/// Validate MS/TP address
pub fn validate_mstp_address(address: u8) -> Result<()> {
    match address {
        0..=127 => Ok(()),   // Master addresses
        128..=254 => Ok(()), // Slave addresses
        255 => Ok(()),       // Broadcast
                              // Note: Rust's u8 can't be > 255, so this is exhaustive
    }
}

/// Check if address is a master node
pub fn is_master_node(address: u8) -> bool {
    address <= 127
}

/// Check if address is a slave node
pub fn is_slave_node(address: u8) -> bool {
    (128..=254).contains(&address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mstp_frame_encode_decode() {
        // Test token frame
        let token_frame = MstpFrame::token(5, 3).unwrap();
        let encoded = token_frame.encode();
        let decoded = MstpFrame::decode(&encoded).unwrap();

        assert_eq!(decoded.frame_type, MstpFrameType::Token);
        assert_eq!(decoded.destination, 5);
        assert_eq!(decoded.source, 3);
        assert_eq!(decoded.data_length, 0);
        assert!(decoded.data.is_empty());
        assert!(decoded.data_crc.is_none());

        // Test data frame
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let data_frame = MstpFrame::bacnet_data(10, 20, data.clone(), true).unwrap();
        let encoded = data_frame.encode();
        let decoded = MstpFrame::decode(&encoded).unwrap();

        assert_eq!(decoded.frame_type, MstpFrameType::BacnetDataExpectingReply);
        assert_eq!(decoded.destination, 10);
        assert_eq!(decoded.source, 20);
        assert_eq!(decoded.data_length, 4);
        assert_eq!(decoded.data, data);
        assert!(decoded.data_crc.is_some());
    }

    #[test]
    fn test_header_crc() {
        let header = [0x00, 0x05, 0x03, 0x00, 0x00]; // Token frame header
        let crc = calculate_header_crc(&header);

        // Create frame and verify CRC matches
        let frame = MstpFrame::token(5, 3).unwrap();
        assert_eq!(frame.header_crc, crc);
    }

    #[test]
    fn test_frame_validation() {
        // Test invalid preamble
        let mut bad_frame = vec![0x00, 0xFF]; // Wrong first preamble byte
        bad_frame.extend_from_slice(&[0x00, 0x05, 0x03, 0x00, 0x00, 0x00]);
        assert!(MstpFrame::decode(&bad_frame).is_err());

        // Test invalid frame type
        let mut bad_frame = vec![0x55, 0xFF, 0xFF]; // Invalid frame type
        bad_frame.extend_from_slice(&[0x05, 0x03, 0x00, 0x00, 0x00]);
        assert!(MstpFrame::decode(&bad_frame).is_err());

        // Test too short
        let bad_frame = vec![0x55, 0xFF, 0x00];
        assert!(MstpFrame::decode(&bad_frame).is_err());
    }

    #[test]
    fn test_address_validation() {
        assert!(validate_mstp_address(0).is_ok()); // Master
        assert!(validate_mstp_address(127).is_ok()); // Master
        assert!(validate_mstp_address(128).is_ok()); // Slave
        assert!(validate_mstp_address(254).is_ok()); // Slave
        assert!(validate_mstp_address(255).is_ok()); // Broadcast

        assert!(is_master_node(0));
        assert!(is_master_node(127));
        assert!(!is_master_node(128));

        assert!(!is_slave_node(127));
        assert!(is_slave_node(128));
        assert!(is_slave_node(254));
        assert!(!is_slave_node(255));
    }

    #[test]
    fn test_max_data_length() {
        let data = vec![0u8; MSTP_MAX_DATA_LENGTH + 1];
        let result = MstpFrame::bacnet_data(10, 20, data, false);
        assert!(result.is_err());

        let data = vec![0u8; MSTP_MAX_DATA_LENGTH];
        let result = MstpFrame::bacnet_data(10, 20, data, false);
        assert!(result.is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_mstp_datalink() {
        let config = MstpConfig {
            station_address: 5,
            ..Default::default()
        };

        let mut datalink = MstpDataLink::new("COM1", config).unwrap();

        assert_eq!(datalink.link_type(), DataLinkType::MsTP);
        assert_eq!(datalink.local_address(), DataLinkAddress::MsTP(5));

        // Test sending
        let npdu = vec![0x01, 0x02, 0x03, 0x04];
        let result = datalink.send_frame(&npdu, &DataLinkAddress::MsTP(10));
        assert!(result.is_ok());

        // Test broadcast
        let result = datalink.send_frame(&npdu, &DataLinkAddress::Broadcast);
        assert!(result.is_ok());
    }
}
