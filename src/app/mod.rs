//! BACnet Application Layer Module
//!
//! This module implements the application layer functionality for BACnet communication.
//! The application layer is responsible for forming and processing Application Protocol
//! Data Units (APDUs) that carry BACnet services.
//!
//! # Overview
//!
//! The application layer handles:
//! - APDU formation and parsing
//! - Service request/response handling
//! - Segmentation of large messages
//! - Transaction management
//! - Error and reject PDU processing
//!
//! # APDU Types
//!
//! - Confirmed Request PDU
//! - Unconfirmed Request PDU
//! - SimpleACK PDU
//! - ComplexACK PDU
//! - SegmentACK PDU
//! - Error PDU
//! - Reject PDU
//! - Abort PDU
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::app::*;
//! use bacnet_rs::service::UnconfirmedServiceChoice;
//!
//! // Example of creating an APDU
//! let apdu = Apdu::UnconfirmedRequest {
//!     service_choice: UnconfirmedServiceChoice::WhoIs,
//!     service_data: vec![],
//! };
//! ```

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::{fmt, time::Duration};

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(not(feature = "std"))]
use core::time::Duration;

use crate::object::Segmentation;
use crate::service::{AbortReason, ConfirmedServiceChoice, RejectReason, UnconfirmedServiceChoice};

/// Result type for application layer operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, ApplicationError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, ApplicationError>;

/// Errors that can occur in application layer operations
#[derive(Debug)]
pub enum ApplicationError {
    /// Invalid APDU format
    InvalidApdu(String),
    /// Unsupported APDU type
    UnsupportedApduType,
    /// Segmentation error
    SegmentationError(String),
    /// Transaction error
    TransactionError(String),
    /// Service error
    ServiceError(String),
    /// Timeout waiting for response
    Timeout,
    /// Maximum APDU length exceeded
    MaxApduLengthExceeded,
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplicationError::InvalidApdu(msg) => write!(f, "Invalid APDU: {}", msg),
            ApplicationError::UnsupportedApduType => write!(f, "Unsupported APDU type"),
            ApplicationError::SegmentationError(msg) => write!(f, "Segmentation error: {}", msg),
            ApplicationError::TransactionError(msg) => write!(f, "Transaction error: {}", msg),
            ApplicationError::ServiceError(msg) => write!(f, "Service error: {}", msg),
            ApplicationError::Timeout => write!(f, "Application timeout"),
            ApplicationError::MaxApduLengthExceeded => write!(f, "Maximum APDU length exceeded"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for ApplicationError {}

/// APDU types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApduType {
    ConfirmedRequest = 0,
    UnconfirmedRequest = 1,
    SimpleAck = 2,
    ComplexAck = 3,
    SegmentAck = 4,
    Error = 5,
    Reject = 6,
    Abort = 7,
}

/// Application Protocol Data Unit
#[derive(Debug, Clone)]
pub enum Apdu {
    /// Confirmed service request
    ConfirmedRequest {
        segmented: bool,
        more_follows: bool,
        segmented_response_accepted: bool,
        max_segments: MaxSegments,
        max_response_size: MaxApduSize,
        invoke_id: u8,
        sequence_number: Option<u8>,
        proposed_window_size: Option<u8>,
        service_choice: ConfirmedServiceChoice,
        service_data: Vec<u8>,
    },

    /// Unconfirmed service request
    UnconfirmedRequest {
        service_choice: UnconfirmedServiceChoice,
        service_data: Vec<u8>,
    },

    /// Simple acknowledgment
    SimpleAck { invoke_id: u8, service_choice: u8 },

    /// Complex acknowledgment
    ComplexAck {
        segmented: bool,
        more_follows: bool,
        invoke_id: u8,
        sequence_number: Option<u8>,
        proposed_window_size: Option<u8>,
        service_choice: u8,
        service_data: Vec<u8>,
    },

    /// Segment acknowledgment
    SegmentAck {
        negative: bool,
        server: bool,
        invoke_id: u8,
        sequence_number: u8,
        window_size: u8,
    },

    /// Error PDU
    Error {
        invoke_id: u8,
        service_choice: u8,
        error_class: u8,
        error_code: u8,
    },

    /// Reject PDU
    Reject { invoke_id: u8, reject_reason: u8 },

    /// Abort PDU
    Abort {
        server: bool,
        invoke_id: u8,
        abort_reason: u8,
    },
}

/// Maximum segments that can be accepted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxSegments {
    Unspecified = 0,
    Two = 1,
    Four = 2,
    Eight = 3,
    Sixteen = 4,
    ThirtyTwo = 5,
    SixtyFour = 6,
    GreaterThan64 = 7,
}

/// Maximum APDU size that can be accepted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxApduSize {
    Up50 = 0,
    Up128 = 1,
    Up206 = 2,
    Up480 = 3,
    Up1024 = 4,
    Up1476 = 5,
}

impl MaxApduSize {
    /// Get the actual size in bytes
    pub fn size(&self) -> usize {
        match self {
            MaxApduSize::Up50 => 50,
            MaxApduSize::Up128 => 128,
            MaxApduSize::Up206 => 206,
            MaxApduSize::Up480 => 480,
            MaxApduSize::Up1024 => 1024,
            MaxApduSize::Up1476 => 1476,
        }
    }
}

/// Transaction state for confirmed services
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Invoke ID
    pub invoke_id: u8,
    /// Service being invoked
    pub service: u8,
    /// Current state
    pub state: TransactionState,
    /// Timeout for this transaction
    pub timeout: Duration,
    /// Retry count
    pub retries: u8,
}

/// Transaction states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// Waiting for response
    AwaitConfirmation,
    /// Waiting for segment
    AwaitSegment,
    /// Segmented request in progress
    SegmentedRequest,
    /// Segmented response in progress
    SegmentedResponse,
    /// Transaction complete
    Complete,
}

impl Apdu {
    /// Encode APDU to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        match self {
            Apdu::ConfirmedRequest {
                segmented,
                more_follows,
                segmented_response_accepted,
                max_segments,
                max_response_size,
                invoke_id,
                sequence_number,
                proposed_window_size,
                service_choice,
                service_data,
            } => {
                // PDU Type and flags
                let mut pdu_type = (ApduType::ConfirmedRequest as u8) << 4;
                if *segmented {
                    pdu_type |= 0x08;
                }
                if *more_follows {
                    pdu_type |= 0x04;
                }
                if *segmented_response_accepted {
                    pdu_type |= 0x02;
                }
                buffer.push(pdu_type);

                // Max segments and APDU size
                let max_info = ((*max_segments as u8) << 4) | (*max_response_size as u8);
                buffer.push(max_info);

                // Invoke ID
                buffer.push(*invoke_id);

                // Sequence number and window size (if segmented)
                if *segmented {
                    if let Some(seq_num) = sequence_number {
                        buffer.push(*seq_num);
                    }
                    if let Some(window_size) = proposed_window_size {
                        buffer.push(*window_size);
                    }
                }

                // Service choice
                buffer.push(*service_choice as u8);

                // Service data
                buffer.extend_from_slice(service_data);
            }

            Apdu::UnconfirmedRequest {
                service_choice,
                service_data,
            } => {
                // PDU Type
                buffer.push((ApduType::UnconfirmedRequest as u8) << 4);
                // Service choice
                buffer.push(*service_choice as u8);
                // Service data
                buffer.extend_from_slice(service_data);
            }

            Apdu::SimpleAck {
                invoke_id,
                service_choice,
            } => {
                // PDU Type
                buffer.push((ApduType::SimpleAck as u8) << 4);
                // Invoke ID
                buffer.push(*invoke_id);
                // Service choice
                buffer.push(*service_choice);
            }

            Apdu::ComplexAck {
                segmented,
                more_follows,
                invoke_id,
                sequence_number,
                proposed_window_size,
                service_choice,
                service_data,
            } => {
                // PDU Type and flags
                let mut pdu_type = (ApduType::ComplexAck as u8) << 4;
                if *segmented {
                    pdu_type |= 0x08;
                }
                if *more_follows {
                    pdu_type |= 0x04;
                }
                buffer.push(pdu_type);

                // Invoke ID
                buffer.push(*invoke_id);

                // Sequence number and window size (if segmented)
                if *segmented {
                    if let Some(seq_num) = sequence_number {
                        buffer.push(*seq_num);
                    }
                    if let Some(window_size) = proposed_window_size {
                        buffer.push(*window_size);
                    }
                }

                // Service choice
                buffer.push(*service_choice);

                // Service data
                buffer.extend_from_slice(service_data);
            }

            Apdu::SegmentAck {
                negative,
                server,
                invoke_id,
                sequence_number,
                window_size,
            } => {
                // PDU Type and flags
                let mut pdu_type = (ApduType::SegmentAck as u8) << 4;
                if *negative {
                    pdu_type |= 0x02;
                }
                if *server {
                    pdu_type |= 0x01;
                }
                buffer.push(pdu_type);

                // Invoke ID
                buffer.push(*invoke_id);
                // Sequence number
                buffer.push(*sequence_number);
                // Window size
                buffer.push(*window_size);
            }

            Apdu::Error {
                invoke_id,
                service_choice,
                error_class,
                error_code,
            } => {
                // PDU Type
                buffer.push((ApduType::Error as u8) << 4);
                // Invoke ID
                buffer.push(*invoke_id);
                // Service choice
                buffer.push(*service_choice);
                // Error class
                buffer.push(*error_class);
                // Error code
                buffer.push(*error_code);
            }

            Apdu::Reject {
                invoke_id,
                reject_reason,
            } => {
                // PDU Type
                buffer.push((ApduType::Reject as u8) << 4);
                // Invoke ID
                buffer.push(*invoke_id);
                // Reject reason
                buffer.push(*reject_reason);
            }

            Apdu::Abort {
                server,
                invoke_id,
                abort_reason,
            } => {
                // PDU Type and flags
                let mut pdu_type = (ApduType::Abort as u8) << 4;
                if *server {
                    pdu_type |= 0x01;
                }
                buffer.push(pdu_type);

                // Invoke ID
                buffer.push(*invoke_id);
                // Abort reason
                buffer.push(*abort_reason);
            }
        }

        buffer
    }

    /// Decode APDU from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(ApplicationError::InvalidApdu("Empty APDU".to_string()));
        }

        let pdu_type_byte = data[0];
        let pdu_type_raw = (pdu_type_byte >> 4) & 0x0F;
        let pdu_type = match pdu_type_raw {
            0 => ApduType::ConfirmedRequest,
            1 => ApduType::UnconfirmedRequest,
            2 => ApduType::SimpleAck,
            3 => ApduType::ComplexAck,
            4 => ApduType::SegmentAck,
            5 => ApduType::Error,
            6 => ApduType::Reject,
            7 => ApduType::Abort,
            _ => return Err(ApplicationError::UnsupportedApduType),
        };

        match pdu_type {
            ApduType::ConfirmedRequest => {
                if data.len() < 4 {
                    return Err(ApplicationError::InvalidApdu(
                        "Confirmed request too short".to_string(),
                    ));
                }

                let segmented = (pdu_type_byte & 0x08) != 0;
                let more_follows = (pdu_type_byte & 0x04) != 0;
                let segmented_response_accepted = (pdu_type_byte & 0x02) != 0;

                let max_info = data[1];
                let max_segments = match (max_info >> 4) & 0x07 {
                    0 => MaxSegments::Unspecified,
                    1 => MaxSegments::Two,
                    2 => MaxSegments::Four,
                    3 => MaxSegments::Eight,
                    4 => MaxSegments::Sixteen,
                    5 => MaxSegments::ThirtyTwo,
                    6 => MaxSegments::SixtyFour,
                    7 => MaxSegments::GreaterThan64,
                    _ => MaxSegments::Unspecified,
                };

                let max_response_size = match max_info & 0x0F {
                    0 => MaxApduSize::Up50,
                    1 => MaxApduSize::Up128,
                    2 => MaxApduSize::Up206,
                    3 => MaxApduSize::Up480,
                    4 => MaxApduSize::Up1024,
                    5 => MaxApduSize::Up1476,
                    _ => MaxApduSize::Up50,
                };

                let invoke_id = data[2];
                let mut pos = 3;

                let (sequence_number, proposed_window_size) = if segmented {
                    let seq_num = if pos < data.len() {
                        Some(data[pos])
                    } else {
                        None
                    };
                    pos += 1;
                    let win_size = if pos < data.len() {
                        Some(data[pos])
                    } else {
                        None
                    };
                    pos += 1;
                    (seq_num, win_size)
                } else {
                    (None, None)
                };

                if pos >= data.len() {
                    return Err(ApplicationError::InvalidApdu(
                        "Missing service choice".to_string(),
                    ));
                }

                let service_choice = data[pos].try_into().map_err(|_| {
                    ApplicationError::InvalidApdu("Unknown confirmed service choice".to_string())
                })?;
                pos += 1;

                let service_data = if pos < data.len() {
                    data[pos..].to_vec()
                } else {
                    Vec::new()
                };

                Ok(Apdu::ConfirmedRequest {
                    segmented,
                    more_follows,
                    segmented_response_accepted,
                    max_segments,
                    max_response_size,
                    invoke_id,
                    sequence_number,
                    proposed_window_size,
                    service_choice,
                    service_data,
                })
            }

            ApduType::UnconfirmedRequest => {
                if data.len() < 2 {
                    return Err(ApplicationError::InvalidApdu(
                        "Unconfirmed request too short".to_string(),
                    ));
                }

                let service_choice = data[1];
                let service_data = if data.len() > 2 {
                    data[2..].to_vec()
                } else {
                    Vec::new()
                };

                Ok(Apdu::UnconfirmedRequest {
                    service_choice: service_choice.try_into().map_err(|_| {
                        ApplicationError::InvalidApdu(
                            "Unknown unconfirmed service choice".to_string(),
                        )
                    })?,
                    service_data,
                })
            }

            ApduType::SimpleAck => {
                if data.len() < 3 {
                    return Err(ApplicationError::InvalidApdu(
                        "SimpleAck too short".to_string(),
                    ));
                }

                let invoke_id = data[1];
                let service_choice = data[2];

                Ok(Apdu::SimpleAck {
                    invoke_id,
                    service_choice,
                })
            }

            ApduType::ComplexAck => {
                if data.len() < 3 {
                    return Err(ApplicationError::InvalidApdu(
                        "ComplexAck too short".to_string(),
                    ));
                }

                let segmented = (pdu_type_byte & 0x08) != 0;
                let more_follows = (pdu_type_byte & 0x04) != 0;

                let invoke_id = data[1];
                let mut pos = 2;

                let (sequence_number, proposed_window_size) = if segmented {
                    let seq_num = if pos < data.len() {
                        Some(data[pos])
                    } else {
                        None
                    };
                    pos += 1;
                    let win_size = if pos < data.len() {
                        Some(data[pos])
                    } else {
                        None
                    };
                    pos += 1;
                    (seq_num, win_size)
                } else {
                    (None, None)
                };

                if pos >= data.len() {
                    return Err(ApplicationError::InvalidApdu(
                        "Missing service choice".to_string(),
                    ));
                }

                let service_choice = data[pos];
                pos += 1;

                let service_data = if pos < data.len() {
                    data[pos..].to_vec()
                } else {
                    Vec::new()
                };

                Ok(Apdu::ComplexAck {
                    segmented,
                    more_follows,
                    invoke_id,
                    sequence_number,
                    proposed_window_size,
                    service_choice,
                    service_data,
                })
            }

            ApduType::SegmentAck => {
                if data.len() < 4 {
                    return Err(ApplicationError::InvalidApdu(
                        "SegmentAck too short".to_string(),
                    ));
                }

                let negative = (pdu_type_byte & 0x02) != 0;
                let server = (pdu_type_byte & 0x01) != 0;
                let invoke_id = data[1];
                let sequence_number = data[2];
                let window_size = data[3];

                Ok(Apdu::SegmentAck {
                    negative,
                    server,
                    invoke_id,
                    sequence_number,
                    window_size,
                })
            }

            ApduType::Error => {
                if data.len() < 5 {
                    return Err(ApplicationError::InvalidApdu(
                        "Error PDU too short".to_string(),
                    ));
                }

                let invoke_id = data[1];
                let service_choice = data[2];
                let error_class = data[3];
                let error_code = data[4];

                Ok(Apdu::Error {
                    invoke_id,
                    service_choice,
                    error_class,
                    error_code,
                })
            }

            ApduType::Reject => {
                if data.len() < 3 {
                    return Err(ApplicationError::InvalidApdu(
                        "Reject PDU too short".to_string(),
                    ));
                }

                let invoke_id = data[1];
                let reject_reason = data[2];

                Ok(Apdu::Reject {
                    invoke_id,
                    reject_reason,
                })
            }

            ApduType::Abort => {
                if data.len() < 3 {
                    return Err(ApplicationError::InvalidApdu(
                        "Abort PDU too short".to_string(),
                    ));
                }

                let server = (pdu_type_byte & 0x01) != 0;
                let invoke_id = data[1];
                let abort_reason = data[2];

                Ok(Apdu::Abort {
                    server,
                    invoke_id,
                    abort_reason,
                })
            }
        }
    }
}

/// Invoke ID manager for handling transaction IDs
#[derive(Debug)]
pub struct InvokeIdManager {
    next_id: u8,
    active_ids: Vec<u8>,
}

impl InvokeIdManager {
    /// Create a new invoke ID manager
    pub fn new() -> Self {
        Self {
            next_id: 0,
            active_ids: Vec::new(),
        }
    }

    /// Get the next available invoke ID
    pub fn next_id(&mut self) -> Option<u8> {
        let start_id = self.next_id;

        loop {
            if !self.active_ids.contains(&self.next_id) {
                let id = self.next_id;
                self.active_ids.push(id);
                self.next_id = self.next_id.wrapping_add(1);
                return Some(id);
            }

            self.next_id = self.next_id.wrapping_add(1);

            // Prevent infinite loop
            if self.next_id == start_id {
                return None;
            }
        }
    }

    /// Release an invoke ID
    pub fn release_id(&mut self, id: u8) {
        self.active_ids.retain(|&x| x != id);
    }

    /// Check if an invoke ID is active
    pub fn is_active(&self, id: u8) -> bool {
        self.active_ids.contains(&id)
    }
}

impl Default for InvokeIdManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Segmentation information for large APDUs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentationInfo {
    /// More follows flag
    pub more_follows: bool,
    /// Segmented response accepted flag
    pub segmented_response_accepted: bool,
    /// Maximum segments accepted (0 = unspecified, 2-127)
    pub max_segments_accepted: u8,
    /// Maximum APDU length accepted
    pub max_apdu_length_accepted: u16,
    /// Sequence number (0-255)
    pub sequence_number: u8,
    /// Proposed window size (1-127)
    pub proposed_window_size: u8,
}

impl SegmentationInfo {
    /// Create new segmentation info
    pub fn new(
        more_follows: bool,
        segmented_response_accepted: bool,
        max_segments_accepted: u8,
        max_apdu_length_accepted: u16,
        sequence_number: u8,
        proposed_window_size: u8,
    ) -> Self {
        Self {
            more_follows,
            segmented_response_accepted,
            max_segments_accepted,
            max_apdu_length_accepted,
            sequence_number,
            proposed_window_size,
        }
    }

    /// Check if this is the first segment
    pub fn is_first_segment(&self) -> bool {
        self.sequence_number == 0
    }

    /// Check if this is the last segment
    pub fn is_last_segment(&self) -> bool {
        !self.more_follows
    }

    /// Calculate the maximum segment size based on max APDU length
    pub fn max_segment_size(&self) -> usize {
        // Account for APDU header overhead (typically 4-6 bytes)
        (self.max_apdu_length_accepted as usize).saturating_sub(6)
    }
}

/// Segment reassembly buffer for incoming segmented messages
#[derive(Debug)]
pub struct SegmentReassemblyBuffer {
    /// Invoke ID of the segmented message
    pub invoke_id: u8,
    /// Expected total segments (if known)
    pub total_segments: Option<u8>,
    /// Received segments (sequence number -> data)
    pub segments: Vec<(u8, Vec<u8>)>,
    /// Maximum APDU length
    pub max_apdu_length: u16,
    /// Timestamp of last received segment (for timeout handling)
    #[cfg(feature = "std")]
    pub last_activity: std::time::Instant,
}

impl SegmentReassemblyBuffer {
    /// Create a new reassembly buffer
    pub fn new(invoke_id: u8, max_apdu_length: u16) -> Self {
        Self {
            invoke_id,
            total_segments: None,
            segments: Vec::new(),
            max_apdu_length,
            #[cfg(feature = "std")]
            last_activity: std::time::Instant::now(),
        }
    }

    /// Add a segment to the buffer
    pub fn add_segment(&mut self, sequence_number: u8, data: Vec<u8>, is_last: bool) -> Result<()> {
        // Update activity timestamp
        #[cfg(feature = "std")]
        {
            self.last_activity = std::time::Instant::now();
        }

        // If this is the last segment, we know the total count
        if is_last {
            self.total_segments = Some(sequence_number + 1);
        }

        // Check for duplicate segments
        if self.segments.iter().any(|(seq, _)| *seq == sequence_number) {
            return Ok(()); // Ignore duplicates
        }

        // Add the segment
        self.segments.push((sequence_number, data));

        // Sort segments by sequence number
        self.segments.sort_by_key(|(seq, _)| *seq);

        Ok(())
    }

    /// Check if all segments have been received
    pub fn is_complete(&self) -> bool {
        if let Some(total) = self.total_segments {
            self.segments.len() == total as usize
                && self
                    .segments
                    .iter()
                    .enumerate()
                    .all(|(i, (seq, _))| *seq == i as u8)
        } else {
            false
        }
    }

    /// Reassemble the complete message
    pub fn reassemble(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(ApplicationError::SegmentationError(
                "Incomplete segments".to_string(),
            ));
        }

        let mut result = Vec::new();
        for (_, data) in &self.segments {
            result.extend_from_slice(data);
        }

        if result.len() > self.max_apdu_length as usize {
            return Err(ApplicationError::MaxApduLengthExceeded);
        }

        Ok(result)
    }

    /// Get missing segment numbers
    pub fn missing_segments(&self) -> Vec<u8> {
        if let Some(total) = self.total_segments {
            let mut missing = Vec::new();
            for i in 0..total {
                if !self.segments.iter().any(|(seq, _)| *seq == i) {
                    missing.push(i);
                }
            }
            missing
        } else {
            Vec::new()
        }
    }

    /// Check if the buffer has timed out
    #[cfg(feature = "std")]
    pub fn is_timed_out(&self, timeout_duration: std::time::Duration) -> bool {
        self.last_activity.elapsed() > timeout_duration
    }
}

/// Segmentation manager for handling message segmentation
#[derive(Debug)]
pub struct SegmentationManager {
    /// Reassembly buffers for incoming segmented messages
    reassembly_buffers: Vec<SegmentReassemblyBuffer>,
    /// Maximum number of concurrent reassembly operations
    max_concurrent_reassemblies: usize,
    /// Segment timeout duration
    #[cfg(feature = "std")]
    segment_timeout: std::time::Duration,
}

impl SegmentationManager {
    /// Create a new segmentation manager
    pub fn new() -> Self {
        Self {
            reassembly_buffers: Vec::new(),
            max_concurrent_reassemblies: 16,
            #[cfg(feature = "std")]
            segment_timeout: std::time::Duration::from_secs(60),
        }
    }

    /// Split a large message into segments
    pub fn segment_message(
        &self,
        data: &[u8],
        max_segment_size: usize,
        max_segments: u8,
    ) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() {
            return Ok(vec![Vec::new()]);
        }

        let segment_count = data.len().div_ceil(max_segment_size);

        if segment_count > max_segments as usize {
            return Err(ApplicationError::SegmentationError(
                "Message too large for segmentation".to_string(),
            ));
        }

        let mut segments = Vec::new();
        let mut offset = 0;

        for _ in 0..segment_count {
            let end = (offset + max_segment_size).min(data.len());
            segments.push(data[offset..end].to_vec());
            offset = end;
        }

        Ok(segments)
    }

    /// Process an incoming segment
    pub fn process_segment(
        &mut self,
        invoke_id: u8,
        sequence_number: u8,
        data: Vec<u8>,
        more_follows: bool,
        max_apdu_length: u16,
    ) -> Result<Option<Vec<u8>>> {
        // Find or create reassembly buffer
        let buffer_index = self
            .reassembly_buffers
            .iter()
            .position(|buffer| buffer.invoke_id == invoke_id);

        let buffer = if let Some(index) = buffer_index {
            &mut self.reassembly_buffers[index]
        } else {
            // Create new buffer if we have capacity
            if self.reassembly_buffers.len() >= self.max_concurrent_reassemblies {
                // Remove oldest buffer
                self.cleanup_oldest_buffer();
            }

            self.reassembly_buffers
                .push(SegmentReassemblyBuffer::new(invoke_id, max_apdu_length));
            self.reassembly_buffers.last_mut().unwrap()
        };

        // Add the segment
        buffer.add_segment(sequence_number, data, !more_follows)?;

        // Check if reassembly is complete
        if buffer.is_complete() {
            let result = buffer.reassemble()?;
            // Remove the completed buffer
            self.reassembly_buffers.retain(|b| b.invoke_id != invoke_id);
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Get missing segments for a reassembly operation
    pub fn get_missing_segments(&self, invoke_id: u8) -> Vec<u8> {
        self.reassembly_buffers
            .iter()
            .find(|buffer| buffer.invoke_id == invoke_id)
            .map(|buffer| buffer.missing_segments())
            .unwrap_or_default()
    }

    /// Cleanup timed out reassembly buffers
    #[cfg(feature = "std")]
    pub fn cleanup_timed_out_buffers(&mut self) {
        self.reassembly_buffers
            .retain(|buffer| !buffer.is_timed_out(self.segment_timeout));
    }

    /// Remove the oldest reassembly buffer
    fn cleanup_oldest_buffer(&mut self) {
        if !self.reassembly_buffers.is_empty() {
            #[cfg(feature = "std")]
            {
                // Find the buffer with the oldest last_activity
                let oldest_index = self
                    .reassembly_buffers
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, buffer)| buffer.last_activity)
                    .map(|(index, _)| index)
                    .unwrap_or(0);
                self.reassembly_buffers.remove(oldest_index);
            }
            #[cfg(not(feature = "std"))]
            {
                // Without std, just remove the first buffer
                self.reassembly_buffers.remove(0);
            }
        }
    }

    /// Set the segment timeout duration
    #[cfg(feature = "std")]
    pub fn set_segment_timeout(&mut self, timeout: std::time::Duration) {
        self.segment_timeout = timeout;
    }

    /// Get the number of active reassembly operations
    pub fn active_reassemblies(&self) -> usize {
        self.reassembly_buffers.len()
    }
}

impl Default for SegmentationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Application layer service handler
#[derive(Debug)]
pub struct ApplicationLayerHandler {
    /// Device instance for this application
    _device_instance: u32,
    /// Supported services
    supported_services: SupportedServices,
    /// Transaction manager
    transaction_manager: TransactionManager,
    /// Service processors
    service_processors: ServiceProcessors,
    /// Application statistics
    pub stats: ApplicationStatistics,
}

/// Supported services configuration
#[derive(Debug, Clone)]
pub struct SupportedServices {
    /// Confirmed services
    pub confirmed: Vec<ConfirmedServiceChoice>,
    /// Unconfirmed services
    pub unconfirmed: Vec<UnconfirmedServiceChoice>,
}

impl Default for SupportedServices {
    fn default() -> Self {
        Self {
            confirmed: vec![
                ConfirmedServiceChoice::ReadProperty,
                ConfirmedServiceChoice::WriteProperty,
                ConfirmedServiceChoice::ReadPropertyMultiple,
                ConfirmedServiceChoice::SubscribeCOV,
            ],
            unconfirmed: vec![
                UnconfirmedServiceChoice::WhoIs,
                UnconfirmedServiceChoice::IAm,
                UnconfirmedServiceChoice::UnconfirmedEventNotification,
            ],
        }
    }
}

/// Type alias for service processor function
type ServiceProcessor = Box<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync>;

/// Type alias for optional service processor function
type OptionalServiceProcessor = Box<dyn Fn(&[u8]) -> Result<Option<Vec<u8>>> + Send + Sync>;

/// Service processors for handling different service types
#[derive(Default)]
struct ServiceProcessors {
    /// Read property processor
    read_property: Option<ServiceProcessor>,
    /// Write property processor
    write_property: Option<ServiceProcessor>,
    /// Who-Is processor
    who_is: Option<OptionalServiceProcessor>,
}

impl fmt::Debug for ServiceProcessors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceProcessors")
            .field("read_property", &self.read_property.is_some())
            .field("write_property", &self.write_property.is_some())
            .field("who_is", &self.who_is.is_some())
            .finish()
    }
}

impl ApplicationLayerHandler {
    /// Create a new application layer handler
    pub fn new(device_instance: u32) -> Self {
        Self {
            _device_instance: device_instance,
            supported_services: SupportedServices::default(),
            transaction_manager: TransactionManager::new(),
            service_processors: ServiceProcessors::default(),
            stats: ApplicationStatistics::default(),
        }
    }

    /// Process an incoming APDU
    pub fn process_apdu(&mut self, apdu: &Apdu, _source: &[u8]) -> Result<Option<Apdu>> {
        self.stats.apdus_received += 1;

        match apdu {
            Apdu::ConfirmedRequest {
                segmented,
                more_follows,
                segmented_response_accepted,
                max_segments: _,
                max_response_size: _,
                invoke_id,
                sequence_number: _,
                proposed_window_size: _,
                service_choice,
                service_data,
            } => {
                let pdu_flags = PduFlags {
                    segmented: *segmented,
                    more_follows: *more_follows,
                    segmented_response_accepted: *segmented_response_accepted,
                };
                self.process_confirmed_request(pdu_flags, *invoke_id, *service_choice, service_data)
            }
            Apdu::UnconfirmedRequest {
                service_choice,
                service_data,
            } => self.process_unconfirmed_request(*service_choice as u8, service_data),
            Apdu::SimpleAck {
                invoke_id,
                service_choice,
            } => self.process_simple_ack(*invoke_id, *service_choice),
            Apdu::ComplexAck {
                segmented,
                more_follows,
                invoke_id,
                sequence_number: _,
                proposed_window_size: _,
                service_choice,
                service_data,
            } => {
                let pdu_flags = PduFlags {
                    segmented: *segmented,
                    more_follows: *more_follows,
                    segmented_response_accepted: false,
                };
                self.process_complex_ack(pdu_flags, *invoke_id, *service_choice, service_data)
            }
            Apdu::Error {
                invoke_id,
                service_choice,
                error_class,
                error_code,
            } => self.process_error(*invoke_id, *service_choice, *error_class, *error_code),
            Apdu::Reject {
                invoke_id,
                reject_reason,
            } => self.process_reject(*invoke_id, *reject_reason),
            Apdu::Abort {
                server,
                invoke_id,
                abort_reason,
            } => self.process_abort(*server, *invoke_id, *abort_reason),
            _ => {
                self.stats.unknown_apdus += 1;
                Err(ApplicationError::UnsupportedApduType)
            }
        }
    }

    /// Process a confirmed request
    fn process_confirmed_request(
        &mut self,
        _pdu_flags: PduFlags,
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Option<Apdu>> {
        self.stats.confirmed_requests += 1;

        if !self.supported_services.confirmed.contains(&service_choice) {
            return Ok(Some(Apdu::Reject {
                invoke_id,
                reject_reason: RejectReason::UnrecognizedService as u8,
            }));
        }

        // Process based on service type
        match service_choice {
            ConfirmedServiceChoice::ReadProperty => {
                if let Some(ref processor) = self.service_processors.read_property {
                    match processor(service_data) {
                        Ok(response_data) => Ok(Some(Apdu::ComplexAck {
                            segmented: false,
                            more_follows: false,
                            invoke_id,
                            sequence_number: None,
                            proposed_window_size: None,
                            service_choice: service_choice as u8,
                            service_data: response_data,
                        })),
                        Err(_) => {
                            Ok(Some(Apdu::Error {
                                invoke_id,
                                service_choice: service_choice as u8,
                                error_class: 0, // Object
                                error_code: 0,  // Unknown object
                            }))
                        }
                    }
                } else {
                    Ok(Some(Apdu::Abort {
                        server: true,
                        invoke_id,
                        abort_reason: AbortReason::Other as u8,
                    }))
                }
            }
            _ => Ok(Some(Apdu::Reject {
                invoke_id,
                reject_reason: RejectReason::UnrecognizedService as u8,
            })),
        }
    }

    /// Process an unconfirmed request
    fn process_unconfirmed_request(
        &mut self,
        service_choice: u8,
        service_data: &[u8],
    ) -> Result<Option<Apdu>> {
        self.stats.unconfirmed_requests += 1;

        // Unconfirmed requests don't get responses unless it's I-Am for Who-Is
        let service = match service_choice {
            0 => UnconfirmedServiceChoice::IAm,
            1 => UnconfirmedServiceChoice::IHave,
            2 => UnconfirmedServiceChoice::UnconfirmedEventNotification,
            3 => UnconfirmedServiceChoice::UnconfirmedEventNotification,
            4 => UnconfirmedServiceChoice::UnconfirmedPrivateTransfer,
            5 => UnconfirmedServiceChoice::UnconfirmedTextMessage,
            6 => UnconfirmedServiceChoice::TimeSynchronization,
            7 => UnconfirmedServiceChoice::WhoHas,
            8 => UnconfirmedServiceChoice::WhoIs,
            9 => UnconfirmedServiceChoice::UtcTimeSynchronization,
            _ => return Ok(None),
        };

        if service == UnconfirmedServiceChoice::WhoIs {
            if let Some(ref processor) = self.service_processors.who_is {
                if let Ok(Some(response_data)) = processor(service_data) {
                    return Ok(Some(Apdu::UnconfirmedRequest {
                        service_choice: UnconfirmedServiceChoice::IAm,
                        service_data: response_data,
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Process a simple ACK
    fn process_simple_ack(&mut self, invoke_id: u8, _service_choice: u8) -> Result<Option<Apdu>> {
        self.stats.simple_acks += 1;
        self.transaction_manager.complete_transaction(invoke_id);
        Ok(None)
    }

    /// Process a complex ACK
    fn process_complex_ack(
        &mut self,
        _pdu_flags: PduFlags,
        invoke_id: u8,
        _service_choice: u8,
        _service_data: &[u8],
    ) -> Result<Option<Apdu>> {
        self.stats.complex_acks += 1;
        self.transaction_manager.complete_transaction(invoke_id);
        Ok(None)
    }

    /// Process an error PDU
    fn process_error(
        &mut self,
        invoke_id: u8,
        _service_choice: u8,
        error_class: u8,
        error_code: u8,
    ) -> Result<Option<Apdu>> {
        self.stats.errors += 1;
        self.transaction_manager
            .error_transaction(invoke_id, error_class, error_code);
        Ok(None)
    }

    /// Process a reject PDU
    fn process_reject(&mut self, invoke_id: u8, _reject_reason: u8) -> Result<Option<Apdu>> {
        self.stats.rejects += 1;
        self.transaction_manager
            .reject_transaction(invoke_id, _reject_reason);
        Ok(None)
    }

    /// Process an abort PDU
    fn process_abort(
        &mut self,
        _server: bool,
        invoke_id: u8,
        abort_reason: u8,
    ) -> Result<Option<Apdu>> {
        self.stats.aborts += 1;
        self.transaction_manager
            .abort_transaction(invoke_id, abort_reason);
        Ok(None)
    }

    /// Set a service processor
    pub fn set_read_property_handler<F>(&mut self, handler: F)
    where
        F: Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync + 'static,
    {
        self.service_processors.read_property = Some(Box::new(handler));
    }

    /// Set Who-Is processor
    pub fn set_who_is_handler<F>(&mut self, handler: F)
    where
        F: Fn(&[u8]) -> Result<Option<Vec<u8>>> + Send + Sync + 'static,
    {
        self.service_processors.who_is = Some(Box::new(handler));
    }
}

/// Transaction manager for tracking active transactions
#[derive(Debug)]
pub struct TransactionManager {
    /// Active transactions
    transactions: Vec<Transaction>,
    /// Maximum concurrent transactions
    max_transactions: usize,
    /// Transaction timeout
    #[cfg(feature = "std")]
    _timeout: Duration,
}

impl TransactionManager {
    /// Create a new transaction manager
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            max_transactions: 255,
            #[cfg(feature = "std")]
            _timeout: Duration::from_secs(30),
        }
    }

    /// Start a new transaction
    pub fn start_transaction(&mut self, invoke_id: u8, service_choice: u8) -> Result<()> {
        if self.transactions.len() >= self.max_transactions {
            return Err(ApplicationError::TransactionError(
                "Too many active transactions".to_string(),
            ));
        }

        // Check for duplicate invoke ID
        if self
            .transactions
            .iter()
            .any(|t| t.invoke_id == invoke_id && t.state == TransactionState::AwaitConfirmation)
        {
            return Err(ApplicationError::TransactionError(
                "Duplicate invoke ID".to_string(),
            ));
        }

        self.transactions.push(Transaction {
            invoke_id,
            service: service_choice,
            state: TransactionState::AwaitConfirmation,
            timeout: Duration::from_secs(30),
            retries: 0,
        });

        Ok(())
    }

    /// Complete a transaction
    pub fn complete_transaction(&mut self, invoke_id: u8) {
        if let Some(transaction) = self
            .transactions
            .iter_mut()
            .find(|t| t.invoke_id == invoke_id)
        {
            transaction.state = TransactionState::Complete;
        }
    }

    /// Mark transaction as error
    pub fn error_transaction(&mut self, invoke_id: u8, _error_class: u8, _error_code: u8) {
        if let Some(transaction) = self
            .transactions
            .iter_mut()
            .find(|t| t.invoke_id == invoke_id)
        {
            transaction.state = TransactionState::Complete;
        }
    }

    /// Mark transaction as rejected
    pub fn reject_transaction(&mut self, invoke_id: u8, _reject_reason: u8) {
        if let Some(transaction) = self
            .transactions
            .iter_mut()
            .find(|t| t.invoke_id == invoke_id)
        {
            transaction.state = TransactionState::Complete;
        }
    }

    /// Mark transaction as aborted
    pub fn abort_transaction(&mut self, invoke_id: u8, _abort_reason: u8) {
        if let Some(transaction) = self
            .transactions
            .iter_mut()
            .find(|t| t.invoke_id == invoke_id)
        {
            transaction.state = TransactionState::Complete;
        }
    }

    /// Clean up completed transactions
    pub fn cleanup_completed(&mut self) {
        self.transactions
            .retain(|t| t.state != TransactionState::Complete);
    }

    /// Get active transaction count
    pub fn active_count(&self) -> usize {
        self.transactions
            .iter()
            .filter(|t| t.state != TransactionState::Complete)
            .count()
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Application layer statistics
#[derive(Debug, Default)]
pub struct ApplicationStatistics {
    /// Total APDUs received
    pub apdus_received: u64,
    /// Total APDUs sent
    pub apdus_sent: u64,
    /// Confirmed requests received
    pub confirmed_requests: u64,
    /// Unconfirmed requests received
    pub unconfirmed_requests: u64,
    /// Simple ACKs received
    pub simple_acks: u64,
    /// Complex ACKs received
    pub complex_acks: u64,
    /// Errors received
    pub errors: u64,
    /// Rejects received
    pub rejects: u64,
    /// Aborts received
    pub aborts: u64,
    /// Unknown APDU types
    pub unknown_apdus: u64,
    /// Segmentation errors
    pub segmentation_errors: u64,
}

/// Priority queue for application messages
#[derive(Debug)]
pub struct ApplicationPriorityQueue {
    /// High priority queue
    high: Vec<QueuedMessage>,
    /// Normal priority queue
    normal: Vec<QueuedMessage>,
    /// Low priority queue
    low: Vec<QueuedMessage>,
    /// Maximum queue size per priority
    max_queue_size: usize,
}

/// Queued message
#[derive(Debug)]
struct QueuedMessage {
    /// APDU to send
    apdu: Apdu,
    /// Destination address
    destination: Vec<u8>,
    /// Timestamp
    #[cfg(feature = "std")]
    _timestamp: std::time::Instant,
    /// Retry count
    _retry_count: u8,
}

impl ApplicationPriorityQueue {
    /// Create a new priority queue
    pub fn new(max_queue_size: usize) -> Self {
        Self {
            high: Vec::with_capacity(max_queue_size),
            normal: Vec::with_capacity(max_queue_size),
            low: Vec::with_capacity(max_queue_size),
            max_queue_size,
        }
    }

    /// Queue a message
    pub fn enqueue(
        &mut self,
        apdu: Apdu,
        destination: Vec<u8>,
        priority: MessagePriority,
    ) -> Result<()> {
        let queue = match priority {
            MessagePriority::High => &mut self.high,
            MessagePriority::Normal => &mut self.normal,
            MessagePriority::Low => &mut self.low,
        };

        if queue.len() >= self.max_queue_size {
            return Err(ApplicationError::TransactionError("Queue full".to_string()));
        }

        queue.push(QueuedMessage {
            apdu,
            destination,
            #[cfg(feature = "std")]
            _timestamp: std::time::Instant::now(),
            _retry_count: 0,
        });

        Ok(())
    }

    /// Dequeue next message
    pub fn dequeue(&mut self) -> Option<(Apdu, Vec<u8>)> {
        if let Some(msg) = self.high.pop() {
            return Some((msg.apdu, msg.destination));
        }
        if let Some(msg) = self.normal.pop() {
            return Some((msg.apdu, msg.destination));
        }
        if let Some(msg) = self.low.pop() {
            return Some((msg.apdu, msg.destination));
        }
        None
    }

    /// Get total queued messages
    pub fn total_queued(&self) -> usize {
        self.high.len() + self.normal.len() + self.low.len()
    }

    /// Clear all queues
    pub fn clear(&mut self) {
        self.high.clear();
        self.normal.clear();
        self.low.clear();
    }
}

/// Message priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePriority {
    /// High priority (alarms, life safety)
    High,
    /// Normal priority (most messages)
    Normal,
    /// Low priority (non-critical)
    Low,
}

/// PDU flags for segmentation control
#[derive(Debug, Clone, Copy, Default)]
pub struct PduFlags {
    /// Segmented message
    pub segmented: bool,
    /// More segments follow
    pub more_follows: bool,
    /// Segmented response accepted
    pub segmented_response_accepted: bool,
}

/// Application layer configuration
#[derive(Debug, Clone)]
pub struct ApplicationConfig {
    /// Maximum APDU length
    pub max_apdu_length: u16,
    /// Segmentation support
    pub segmentation: Segmentation,
    /// APDU timeout (milliseconds)
    pub apdu_timeout: u16,
    /// Number of APDU retries
    pub apdu_retries: u8,
    /// Maximum segments accepted
    pub max_segments: u8,
    /// Invoke ID start value
    pub invoke_id_start: u8,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            max_apdu_length: 1476,
            segmentation: Segmentation::Both,
            apdu_timeout: 6000,
            apdu_retries: 3,
            max_segments: 64,
            invoke_id_start: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unconfirmed_request_encode_decode() {
        let apdu = Apdu::UnconfirmedRequest {
            service_choice: UnconfirmedServiceChoice::WhoIs, // WhoIs
            service_data: vec![0x08, 0x7B, 0x18, 0x7B],      // Range 123-123
        };

        let encoded = apdu.encode();
        let decoded = Apdu::decode(&encoded).unwrap();

        match decoded {
            Apdu::UnconfirmedRequest {
                service_choice,
                service_data,
            } => {
                assert_eq!(service_choice, UnconfirmedServiceChoice::WhoIs);
                assert_eq!(service_data, vec![0x08, 0x7B, 0x18, 0x7B]);
            }
            _ => panic!("Expected UnconfirmedRequest"),
        }
    }

    #[test]
    fn test_simple_ack_encode_decode() {
        let apdu = Apdu::SimpleAck {
            invoke_id: 42,
            service_choice: 12, // ReadProperty
        };

        let encoded = apdu.encode();
        let decoded = Apdu::decode(&encoded).unwrap();

        match decoded {
            Apdu::SimpleAck {
                invoke_id,
                service_choice,
            } => {
                assert_eq!(invoke_id, 42);
                assert_eq!(service_choice, 12);
            }
            _ => panic!("Expected SimpleAck"),
        }
    }

    #[test]
    fn test_confirmed_request_encode_decode() {
        let apdu = Apdu::ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: true,
            max_segments: MaxSegments::Unspecified,
            max_response_size: MaxApduSize::Up1476,
            invoke_id: 123,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::ReadProperty, // ReadProperty
            service_data: vec![0x0C, 0x02, 0x00, 0x00, 0x08, 0x19, 0x55],
        };

        let encoded = apdu.encode();
        let decoded = Apdu::decode(&encoded).unwrap();

        match decoded {
            Apdu::ConfirmedRequest {
                invoke_id,
                service_choice,
                segmented_response_accepted,
                ..
            } => {
                assert_eq!(invoke_id, 123);
                assert_eq!(service_choice, ConfirmedServiceChoice::ReadProperty);
                assert!(segmented_response_accepted);
            }
            _ => panic!("Expected ConfirmedRequest"),
        }
    }

    #[test]
    fn test_invoke_id_manager() {
        let mut manager = InvokeIdManager::new();

        // Get some IDs
        let id1 = manager.next_id().unwrap();
        let id2 = manager.next_id().unwrap();
        let id3 = manager.next_id().unwrap();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);

        // Check if they're active
        assert!(manager.is_active(id1));
        assert!(manager.is_active(id2));
        assert!(manager.is_active(id3));

        // Release one
        manager.release_id(id2);
        assert!(!manager.is_active(id2));
        assert!(manager.is_active(id1));
        assert!(manager.is_active(id3));
    }

    #[test]
    fn test_max_apdu_size() {
        assert_eq!(MaxApduSize::Up50.size(), 50);
        assert_eq!(MaxApduSize::Up128.size(), 128);
        assert_eq!(MaxApduSize::Up1476.size(), 1476);
    }

    #[test]
    fn test_segmentation_info() {
        let seg_info = SegmentationInfo::new(
            true, // more_follows
            true, // segmented_response_accepted
            64,   // max_segments_accepted
            1476, // max_apdu_length_accepted
            5,    // sequence_number
            10,   // proposed_window_size
        );

        assert!(seg_info.more_follows);
        assert!(seg_info.segmented_response_accepted);
        assert_eq!(seg_info.max_segments_accepted, 64);
        assert_eq!(seg_info.max_apdu_length_accepted, 1476);
        assert_eq!(seg_info.sequence_number, 5);
        assert_eq!(seg_info.proposed_window_size, 10);

        assert!(!seg_info.is_first_segment());
        assert!(!seg_info.is_last_segment());
        assert_eq!(seg_info.max_segment_size(), 1470); // 1476 - 6 bytes overhead

        // Test first segment
        let first_seg = SegmentationInfo::new(false, true, 32, 1024, 0, 8);
        assert!(first_seg.is_first_segment());
        assert!(first_seg.is_last_segment()); // more_follows is false

        // Test last segment
        let last_seg = SegmentationInfo::new(false, true, 16, 480, 3, 5);
        assert!(!last_seg.is_first_segment());
        assert!(last_seg.is_last_segment());
    }

    #[test]
    fn test_segment_reassembly_buffer() {
        let mut buffer = SegmentReassemblyBuffer::new(42, 1024);
        assert_eq!(buffer.invoke_id, 42);
        assert_eq!(buffer.max_apdu_length, 1024);
        assert!(!buffer.is_complete());
        assert_eq!(buffer.missing_segments(), Vec::<u8>::new());

        // Add segments
        buffer.add_segment(0, vec![1, 2, 3], false).unwrap();
        buffer.add_segment(1, vec![4, 5, 6], false).unwrap();
        buffer.add_segment(2, vec![7, 8, 9], true).unwrap(); // Last segment

        assert!(buffer.is_complete());
        assert_eq!(buffer.total_segments, Some(3));

        // Test reassembly
        let reassembled = buffer.reassemble().unwrap();
        assert_eq!(reassembled, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);

        // Test missing segments with incomplete buffer
        let mut incomplete_buffer = SegmentReassemblyBuffer::new(43, 1024);
        incomplete_buffer.add_segment(0, vec![1, 2], false).unwrap();
        incomplete_buffer.add_segment(2, vec![5, 6], true).unwrap(); // Missing segment 1

        assert!(!incomplete_buffer.is_complete());
        assert_eq!(incomplete_buffer.missing_segments(), vec![1]);
    }

    #[test]
    fn test_segmentation_manager() {
        let mut manager = SegmentationManager::new();
        assert_eq!(manager.active_reassemblies(), 0);

        // Test message segmentation
        let large_data = vec![0u8; 100]; // 100 bytes of data
        let segments = manager.segment_message(&large_data, 30, 10).unwrap();
        assert_eq!(segments.len(), 4); // 100 / 30 = 3.33, rounded up to 4
        assert_eq!(segments[0].len(), 30);
        assert_eq!(segments[1].len(), 30);
        assert_eq!(segments[2].len(), 30);
        assert_eq!(segments[3].len(), 10); // Remaining 10 bytes

        // Test segment processing
        let invoke_id = 100;
        let max_apdu = 1024;

        // Process first segment
        let result1 = manager
            .process_segment(invoke_id, 0, vec![1, 2, 3], true, max_apdu)
            .unwrap();
        assert!(result1.is_none()); // Not complete yet
        assert_eq!(manager.active_reassemblies(), 1);

        // Process second segment
        let result2 = manager
            .process_segment(invoke_id, 1, vec![4, 5, 6], false, max_apdu)
            .unwrap();
        assert!(result2.is_some()); // Complete!
        assert_eq!(result2.unwrap(), vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(manager.active_reassemblies(), 0); // Buffer was removed

        // Test missing segments query
        manager
            .process_segment(200, 0, vec![10, 20], true, max_apdu)
            .unwrap();
        manager
            .process_segment(200, 2, vec![50, 60], false, max_apdu)
            .unwrap();
        let missing = manager.get_missing_segments(200);
        assert_eq!(missing, vec![1]);
    }

    #[test]
    fn test_segmentation_error_cases() {
        let manager = SegmentationManager::new();

        // Test message too large for segmentation
        let huge_data = vec![0u8; 1000];
        let result = manager.segment_message(&huge_data, 100, 5); // Only 5 segments allowed
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::SegmentationError(msg) => {
                assert!(msg.contains("too large"));
            }
            _ => panic!("Expected SegmentationError"),
        }

        // Test reassembling incomplete segments
        let mut buffer = SegmentReassemblyBuffer::new(1, 100);
        buffer.add_segment(0, vec![1, 2], false).unwrap();
        // Missing segment 1, but we don't know total count yet
        let result = buffer.reassemble();
        assert!(result.is_err());
        match result.unwrap_err() {
            ApplicationError::SegmentationError(msg) => {
                assert!(msg.contains("Incomplete"));
            }
            _ => panic!("Expected SegmentationError"),
        }
    }

    #[test]
    fn test_segmentation_duplicate_handling() {
        let mut buffer = SegmentReassemblyBuffer::new(1, 1024);

        // Add segment 0
        buffer.add_segment(0, vec![1, 2, 3], false).unwrap();
        assert_eq!(buffer.segments.len(), 1);

        // Add duplicate segment 0 (should be ignored)
        buffer.add_segment(0, vec![4, 5, 6], false).unwrap();
        assert_eq!(buffer.segments.len(), 1);
        assert_eq!(buffer.segments[0].1, vec![1, 2, 3]); // Original data preserved

        // Add segment 1 as last
        buffer.add_segment(1, vec![7, 8, 9], true).unwrap();
        assert_eq!(buffer.segments.len(), 2);
        assert!(buffer.is_complete());

        let reassembled = buffer.reassemble().unwrap();
        assert_eq!(reassembled, vec![1, 2, 3, 7, 8, 9]);
    }
}
