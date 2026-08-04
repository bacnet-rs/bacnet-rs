//! Frame Validation Utilities
//!
//! This module provides comprehensive validation utilities for BACnet data link frames
//! across all supported data link types (BACnet/IP, Ethernet, MS/TP, etc.).
//!
//! # Overview
//!
//! Frame validation includes:
//! - Structure validation (correct headers, sizes)
//! - CRC/checksum verification
//! - Address validation
//! - Protocol-specific checks
//! - Common error detection patterns

use crate::datalink::DataLinkType;
use crate::util::crc16_mstp;

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// Frame validation result with detailed information
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the frame is valid
    pub is_valid: bool,
    /// Data link type detected
    pub link_type: Option<DataLinkType>,
    /// Frame size
    pub frame_size: usize,
    /// Validation errors found
    pub errors: Vec<ValidationError>,
    /// Validation warnings (non-fatal)
    pub warnings: Vec<ValidationWarning>,
}

/// Validation error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Frame too short for any valid protocol
    FrameTooShort { size: usize, minimum: usize },
    /// Frame too long for protocol
    FrameTooLong { size: usize, maximum: usize },
    /// Invalid preamble or magic bytes
    InvalidPreamble { expected: Vec<u8>, found: Vec<u8> },
    /// CRC mismatch
    CrcMismatch { expected: u32, calculated: u32 },
    /// Invalid frame type
    InvalidFrameType { value: u8 },
    /// Invalid address
    InvalidAddress { address: String, reason: String },
    /// Invalid header structure
    InvalidHeader { reason: String },
    /// Payload size mismatch
    PayloadSizeMismatch { declared: usize, actual: usize },
}

/// Validation warning types (non-fatal issues)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationWarning {
    /// Unusual but valid frame size
    UnusualFrameSize { size: usize },
    /// Deprecated frame type
    DeprecatedFrameType { frame_type: u8 },
    /// Non-standard but valid configuration
    NonStandardConfiguration { reason: String },
    /// Potential security issue
    SecurityWarning { reason: String },
}

/// Validate a BACnet/IP frame
pub fn validate_bacnet_ip_frame(data: &[u8]) -> ValidationResult {
    let mut result = ValidationResult {
        is_valid: true,
        link_type: Some(DataLinkType::BacnetIp),
        frame_size: data.len(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Check minimum size (BVLC header)
    if data.len() < 4 {
        result.is_valid = false;
        result.errors.push(ValidationError::FrameTooShort {
            size: data.len(),
            minimum: 4,
        });
        return result;
    }

    // Check BVLC type
    if data[0] != 0x81 {
        result.is_valid = false;
        result.errors.push(ValidationError::InvalidPreamble {
            expected: vec![0x81],
            found: vec![data[0]],
        });
    }

    // Check BVLC function
    let valid_functions = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
    ];
    if !valid_functions.contains(&data[1]) {
        result.is_valid = false;
        result
            .errors
            .push(ValidationError::InvalidFrameType { value: data[1] });
    }

    // Check BVLC length
    let declared_length = ((data[2] as usize) << 8) | (data[3] as usize);
    if declared_length != data.len() {
        result.is_valid = false;
        result.errors.push(ValidationError::PayloadSizeMismatch {
            declared: declared_length,
            actual: data.len(),
        });
    }

    // Check maximum size
    if data.len() > 1497 {
        result.is_valid = false;
        result.errors.push(ValidationError::FrameTooLong {
            size: data.len(),
            maximum: 1497,
        });
    }

    // Warnings for specific functions
    match data[1] {
        0x0C => {
            // Secure BVLL - warn if not using proper security
            result.warnings.push(ValidationWarning::SecurityWarning {
                reason: "Secure BVLL should use proper encryption".into(),
            });
        }
        0x01 | 0x08 => {
            // Write-BDT or Delete-FDT-Entry - potential security risk
            result.warnings.push(ValidationWarning::SecurityWarning {
                reason: "Table modification functions should be authenticated".into(),
            });
        }
        _ => {}
    }

    result
}

/// Validate an Ethernet frame
pub fn validate_ethernet_frame(data: &[u8]) -> ValidationResult {
    let mut result = ValidationResult {
        is_valid: true,
        link_type: Some(DataLinkType::Ethernet),
        frame_size: data.len(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Check minimum size (Ethernet header + LLC)
    if data.len() < 17 {
        result.is_valid = false;
        result.errors.push(ValidationError::FrameTooShort {
            size: data.len(),
            minimum: 17,
        });
        return result;
    }

    // Check maximum size
    if data.len() > 1514 {
        result.is_valid = false;
        result.errors.push(ValidationError::FrameTooLong {
            size: data.len(),
            maximum: 1514,
        });
    }

    // Check Ethernet type for BACnet
    let ether_type = ((data[12] as u16) << 8) | (data[13] as u16);
    if ether_type != 0x82DC {
        result.is_valid = false;
        result.errors.push(ValidationError::InvalidHeader {
            reason: format!(
                "Invalid Ethernet type: 0x{:04X}, expected 0x82DC",
                ether_type
            ),
        });
    }

    // Check LLC header
    if data.len() >= 17 {
        let llc = &data[14..17];
        if llc != [0x82, 0x82, 0x03] {
            result.is_valid = false;
            result.errors.push(ValidationError::InvalidHeader {
                reason: format!("Invalid LLC header: {:02X?}, expected [82, 82, 03]", llc),
            });
        }
    }

    // Check for multicast/broadcast
    if data[0] & 0x01 == 0x01 {
        if data[0..6] == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            // Broadcast - this is fine
        } else {
            // Multicast - warn as BACnet typically uses broadcast
            result
                .warnings
                .push(ValidationWarning::NonStandardConfiguration {
                    reason: "Multicast address used instead of broadcast".into(),
                });
        }
    }

    // Warn about small frames (likely padded)
    if data.len() == 60 {
        result
            .warnings
            .push(ValidationWarning::UnusualFrameSize { size: data.len() });
    }

    result
}

/// Validate an MS/TP frame
pub fn validate_mstp_frame(data: &[u8]) -> ValidationResult {
    let mut result = ValidationResult {
        is_valid: true,
        link_type: Some(DataLinkType::MsTP),
        frame_size: data.len(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Check minimum size (header)
    if data.len() < 8 {
        result.is_valid = false;
        result.errors.push(ValidationError::FrameTooShort {
            size: data.len(),
            minimum: 8,
        });
        return result;
    }

    // Check preamble
    if data[0] != 0x55 || data[1] != 0xFF {
        result.is_valid = false;
        result.errors.push(ValidationError::InvalidPreamble {
            expected: vec![0x55, 0xFF],
            found: vec![data[0], data[1]],
        });
    }

    // Check frame type
    let frame_type = data[2];
    if frame_type > 7 && frame_type < 128 {
        result.is_valid = false;
        result
            .errors
            .push(ValidationError::InvalidFrameType { value: frame_type });
    } else if frame_type >= 128 {
        // Proprietary frame types
        result
            .warnings
            .push(ValidationWarning::NonStandardConfiguration {
                reason: format!("Proprietary frame type: {}", frame_type),
            });
    }

    // Get addresses
    let dest_addr = data[3];
    let src_addr = data[4];

    // Validate addresses
    if src_addr == 255 {
        result.is_valid = false;
        result.errors.push(ValidationError::InvalidAddress {
            address: format!("{}", src_addr),
            reason: "Source address cannot be broadcast (255)".into(),
        });
    }

    // Check for master talking to slave without poll
    if src_addr <= 127 && (128..=254).contains(&dest_addr) && frame_type != 3 {
        result
            .warnings
            .push(ValidationWarning::NonStandardConfiguration {
                reason: "Master communicating with slave without Test Request".into(),
            });
    }

    // Get data length
    let data_length = ((data[5] as u16) << 8) | (data[6] as u16);

    // Check data length
    if data_length > 501 {
        result.is_valid = false;
        result.errors.push(ValidationError::InvalidHeader {
            reason: format!("Data length {} exceeds maximum 501", data_length),
        });
    }

    // Verify header CRC
    let header_crc = data[7];
    let header_bytes = [data[2], data[3], data[4], data[5], data[6]];
    let calculated_crc = calculate_mstp_header_crc(&header_bytes);

    if header_crc != calculated_crc {
        result.is_valid = false;
        result.errors.push(ValidationError::CrcMismatch {
            expected: header_crc as u32,
            calculated: calculated_crc as u32,
        });
    }

    // Check frame size
    let expected_size = 8 + data_length as usize + if data_length > 0 { 2 } else { 0 };
    if data.len() != expected_size {
        result.is_valid = false;
        result.errors.push(ValidationError::PayloadSizeMismatch {
            declared: expected_size,
            actual: data.len(),
        });
    }

    // Verify data CRC if present
    if data_length > 0 && data.len() >= expected_size {
        let data_start = 8;
        let data_end = data_start + data_length as usize;
        let frame_data = &data[data_start..data_end];

        let crc_low = data[data_end];
        let crc_high = data[data_end + 1];
        let received_crc = ((crc_high as u16) << 8) | (crc_low as u16);

        let calculated_crc = crc16_mstp(frame_data);

        if received_crc != calculated_crc {
            result.is_valid = false;
            result.errors.push(ValidationError::CrcMismatch {
                expected: received_crc as u32,
                calculated: calculated_crc as u32,
            });
        }
    }

    result
}

/// Automatically detect and validate frame type
pub fn validate_frame(data: &[u8]) -> ValidationResult {
    if data.is_empty() {
        return ValidationResult {
            is_valid: false,
            link_type: None,
            frame_size: 0,
            errors: vec![ValidationError::FrameTooShort {
                size: 0,
                minimum: 1,
            }],
            warnings: Vec::new(),
        };
    }

    // Try to detect frame type by examining headers

    // Check for MS/TP (starts with 0x55, 0xFF)
    if data.len() >= 2 && data[0] == 0x55 && data[1] == 0xFF {
        return validate_mstp_frame(data);
    }

    // Check for BACnet/IP (starts with 0x81)
    if data[0] == 0x81 {
        return validate_bacnet_ip_frame(data);
    }

    // Check for Ethernet (has BACnet Ethernet type at offset 12-13)
    if data.len() >= 14 {
        let ether_type = ((data[12] as u16) << 8) | (data[13] as u16);
        if ether_type == 0x82DC {
            return validate_ethernet_frame(data);
        }
    }

    // Unknown frame type
    ValidationResult {
        is_valid: false,
        link_type: None,
        frame_size: data.len(),
        errors: vec![ValidationError::InvalidHeader {
            reason: "Unable to determine frame type".into(),
        }],
        warnings: Vec::new(),
    }
}

/// Calculate MS/TP header CRC (for validation)
fn calculate_mstp_header_crc(header: &[u8; 5]) -> u8 {
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

/// Perform deep frame analysis
pub fn analyze_frame(data: &[u8]) -> FrameAnalysis {
    let validation = validate_frame(data);

    FrameAnalysis {
        validation,
        statistics: calculate_frame_statistics(data),
        patterns: detect_patterns(data),
    }
}

/// Frame analysis results
#[derive(Debug, Clone)]
pub struct FrameAnalysis {
    /// Basic validation results
    pub validation: ValidationResult,
    /// Frame statistics
    pub statistics: FrameStatistics,
    /// Detected patterns
    pub patterns: Vec<Pattern>,
}

/// Frame statistics
#[derive(Debug, Clone)]
pub struct FrameStatistics {
    /// Byte value distribution
    pub byte_distribution: [u32; 256],
    /// Entropy estimate (0.0 - 8.0 bits)
    pub entropy: f64,
    /// Number of null bytes
    pub null_bytes: usize,
    /// Number of high bytes (>= 0x80)
    pub high_bytes: usize,
    /// Longest run of same byte
    pub longest_run: (u8, usize),
}

/// Detected patterns in frame
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Padding detected
    Padding {
        start: usize,
        length: usize,
        value: u8,
    },
    /// Repeated sequence
    RepeatedSequence {
        start: usize,
        pattern: Vec<u8>,
        count: usize,
    },
    /// Possible ASCII text
    AsciiText { start: usize, text: String },
    /// Suspicious pattern
    Suspicious { description: String },
}

/// Base-2 logarithm for the entropy calculation.
#[cfg(feature = "std")]
fn log2(x: f64) -> f64 {
    x.log2()
}

/// Base-2 logarithm approximation for builds without std, where `f64::log2`
/// is unavailable. Splits the float into exponent and mantissa and applies a
/// quadratic fit for the mantissa's log2 (max error ~0.01) — plenty for the
/// entropy heuristic this feeds.
#[cfg(not(feature = "std"))]
fn log2(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::NEG_INFINITY;
    }
    let bits = x.to_bits();
    let exponent = (((bits >> 52) & 0x7FF) as i64 - 1023) as f64;
    // Mantissa remapped into [1, 2).
    let m = f64::from_bits((bits & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000);
    let log2_m = (-0.344845 * m + 2.024658) * m - 1.674873;
    exponent + log2_m
}

/// Calculate frame statistics
fn calculate_frame_statistics(data: &[u8]) -> FrameStatistics {
    let mut byte_distribution = [0u32; 256];
    let mut null_bytes = 0;
    let mut high_bytes = 0;

    // Count byte occurrences
    for &byte in data {
        byte_distribution[byte as usize] += 1;
        if byte == 0 {
            null_bytes += 1;
        }
        if byte >= 0x80 {
            high_bytes += 1;
        }
    }

    // Calculate entropy
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for count in byte_distribution.iter() {
        if *count > 0 {
            let probability = *count as f64 / total;
            entropy -= probability * log2(probability);
        }
    }

    // Find longest run
    let mut longest_run = (0u8, 0usize);
    if !data.is_empty() {
        let mut current_byte = data[0];
        let mut current_run = 1;

        for &byte in &data[1..] {
            if byte == current_byte {
                current_run += 1;
            } else {
                if current_run > longest_run.1 {
                    longest_run = (current_byte, current_run);
                }
                current_byte = byte;
                current_run = 1;
            }
        }

        if current_run > longest_run.1 {
            longest_run = (current_byte, current_run);
        }
    }

    FrameStatistics {
        byte_distribution,
        entropy,
        null_bytes,
        high_bytes,
        longest_run,
    }
}

/// Detect patterns in frame data
fn detect_patterns(data: &[u8]) -> Vec<Pattern> {
    let mut patterns = Vec::new();

    // Detect padding
    if data.len() >= 4 {
        let mut i = data.len() - 1;
        let pad_byte = data[i];
        let mut pad_len = 0;

        while i > 0 && data[i] == pad_byte {
            pad_len += 1;
            i -= 1;
        }

        if pad_len >= 4 {
            patterns.push(Pattern::Padding {
                start: i + 1,
                length: pad_len,
                value: pad_byte,
            });
        }
    }

    // Detect ASCII text
    let mut ascii_start = None;
    let mut ascii_bytes = Vec::new();

    for (i, &byte) in data.iter().enumerate() {
        if (0x20..=0x7E).contains(&byte) {
            if ascii_start.is_none() {
                ascii_start = Some(i);
            }
            ascii_bytes.push(byte);
        } else if !ascii_bytes.is_empty() {
            if ascii_bytes.len() >= 4 {
                patterns.push(Pattern::AsciiText {
                    start: ascii_start.unwrap(),
                    text: String::from_utf8_lossy(&ascii_bytes).to_string(),
                });
            }
            ascii_start = None;
            ascii_bytes.clear();
        }
    }

    // Check remaining ASCII
    if ascii_bytes.len() >= 4 {
        patterns.push(Pattern::AsciiText {
            start: ascii_start.unwrap(),
            text: String::from_utf8_lossy(&ascii_bytes).to_string(),
        });
    }

    // Detect suspicious patterns
    if data.len() >= 8 {
        // Check for all zeros (except in padding)
        let non_padding_len = if let Some(Pattern::Padding { start, .. }) = patterns.first() {
            *start
        } else {
            data.len()
        };

        if non_padding_len >= 8 && data[..non_padding_len].iter().all(|&b| b == 0) {
            patterns.push(Pattern::Suspicious {
                description: "Frame contains all zeros".into(),
            });
        }

        // Check for obvious test patterns
        if data.starts_with(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]) {
            patterns.push(Pattern::Suspicious {
                description: "Frame starts with sequential test pattern".into(),
            });
        }
    }

    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bacnet_ip_validation() {
        // Valid frame
        let valid_frame = vec![
            0x81, 0x0A, 0x00, 0x08, // BVLC header
            0x01, 0x00, 0x00, 0x00, // NPDU
        ];
        let result = validate_bacnet_ip_frame(&valid_frame);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());

        // Invalid BVLC type
        let invalid_frame = vec![0x82, 0x0A, 0x00, 0x04];
        let result = validate_bacnet_ip_frame(&invalid_frame);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, ValidationError::InvalidPreamble { .. })));

        // Length mismatch
        let invalid_frame = vec![0x81, 0x0A, 0x00, 0x10, 0x01, 0x02];
        let result = validate_bacnet_ip_frame(&invalid_frame);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, ValidationError::PayloadSizeMismatch { .. })));
    }

    #[test]
    fn test_ethernet_validation() {
        // Valid frame
        let mut valid_frame = vec![0u8; 60];
        // Set Ethernet type
        valid_frame[12] = 0x82;
        valid_frame[13] = 0xDC;
        // Set LLC header
        valid_frame[14] = 0x82;
        valid_frame[15] = 0x82;
        valid_frame[16] = 0x03;

        let result = validate_ethernet_frame(&valid_frame);
        assert!(result.is_valid);

        // Wrong Ethernet type
        valid_frame[12] = 0x08;
        valid_frame[13] = 0x00;
        let result = validate_ethernet_frame(&valid_frame);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_mstp_validation() {
        // Valid token frame
        let frame = vec![
            0x55, 0xFF, // Preamble
            0x00, // Token frame
            0x02, // Destination
            0x01, // Source
            0x00, 0x00, // Data length = 0
            0xFC, // Header CRC (correct value for this header)
        ];

        let result = validate_mstp_frame(&frame);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());

        // Invalid preamble
        let mut invalid_frame = frame.clone();
        invalid_frame[0] = 0xAA;
        let result = validate_mstp_frame(&invalid_frame);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_auto_detection() {
        // MS/TP frame
        let mstp_frame = vec![0x55, 0xFF, 0x00, 0x02, 0x01, 0x00, 0x00, 0xDB];
        let result = validate_frame(&mstp_frame);
        assert_eq!(result.link_type, Some(DataLinkType::MsTP));

        // BACnet/IP frame
        let bip_frame = vec![0x81, 0x0A, 0x00, 0x04];
        let result = validate_frame(&bip_frame);
        assert_eq!(result.link_type, Some(DataLinkType::BacnetIp));

        // Unknown frame
        let unknown_frame = vec![0xFF, 0xFF, 0xFF];
        let result = validate_frame(&unknown_frame);
        assert_eq!(result.link_type, None);
    }

    #[test]
    fn test_pattern_detection() {
        // Frame with padding
        let mut frame = vec![0x01, 0x02, 0x03, 0x04];
        frame.extend_from_slice(&[0x00; 10]);

        let patterns = detect_patterns(&frame);
        assert!(patterns
            .iter()
            .any(|p| matches!(p, Pattern::Padding { .. })));

        // Frame with ASCII text
        let frame = b"Test BACnet Frame";
        let patterns = detect_patterns(frame);
        assert!(patterns
            .iter()
            .any(|p| matches!(p, Pattern::AsciiText { .. })));
    }
}
