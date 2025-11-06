//! BACnet Encoding and Decoding Utilities
//!
//! This module provides comprehensive functionality for encoding and decoding BACnet protocol data
//! according to ASHRAE Standard 135. It handles the serialization and deserialization of all
//! BACnet data types, application tags, and protocol structures.
//!
//! # Overview
//!
//! The BACnet encoding system uses a tag-length-value (TLV) format where each data element
//! consists of:
//!
//! - **Tag**: Identifies the data type and context
//! - **Length**: Specifies the length of the value (for variable-length types)
//! - **Value**: The actual data content
//!
//! This module provides functionality for:
//!
//! - **Primitive Types**: Boolean, Unsigned/Signed integers, Real numbers, Double precision, etc.
//! - **String Types**: Character strings, Bit strings, Octet strings
//! - **Time Types**: Date, Time, DateTime values
//! - **Object Types**: Object identifiers, Property identifiers
//! - **Constructed Types**: Arrays, Lists, Sequences
//! - **Context Tags**: Application-specific encoding contexts
//!
//! # Application Tags
//!
//! BACnet defines standard application tags for common data types:
//!
//! | Tag | Type | Description |
//! |-----|------|-------------|
//! | 0 | Null | No value |
//! | 1 | Boolean | True/False |
//! | 2 | Unsigned Integer | 8, 16, 24, or 32-bit unsigned |
//! | 3 | Signed Integer | 8, 16, 24, or 32-bit signed |
//! | 4 | Real | 32-bit IEEE 754 float |
//! | 5 | Double | 64-bit IEEE 754 double |
//! | 6 | Octet String | Arbitrary byte sequence |
//! | 7 | Character String | Text with encoding indicator |
//! | 8 | Bit String | Bit field with unused bits count |
//! | 9 | Enumerated | Unsigned integer representing enumeration |
//! | 10 | Date | Year, month, day, day-of-week |
//! | 11 | Time | Hour, minute, second, hundredths |
//! | 12 | Object Identifier | Object type and instance |
//!
//! # Examples
//!
//! ## Encoding Basic Types
//!
//! ```rust
//! use bacnet_rs::encoding::{encode_unsigned, encode_real, ApplicationTag};
//!
//! let mut buffer = Vec::new();
//!
//! // Encode an unsigned integer with application tag
//! encode_unsigned(&mut buffer, 42).unwrap();
//!
//! // Encode a real number with application tag
//! encode_real(&mut buffer, 23.5).unwrap();
//!
//! println!("Encoded {} bytes", buffer.len());
//! ```
//!
//! ## Decoding Basic Types
//!
//! ```rust
//! use bacnet_rs::encoding::{decode_unsigned, ApplicationTag};
//!
//! // Sample encoded data (tag + value)
//! let data = vec![0x21, 0x2A]; // Unsigned integer 42
//!
//! // Decode the value
//! let (value, consumed) = decode_unsigned(&data).unwrap();
//! assert_eq!(value, 42);
//! assert_eq!(consumed, 2);
//! ```
//!
//! ## Working with Application Tags
//!
//! ```rust
//! use bacnet_rs::encoding::{ApplicationTag, decode_application_tag};
//!
//! let data = vec![0x21, 0x2A]; // Unsigned integer
//! let (tag, length, consumed) = decode_application_tag(&data).unwrap();
//! assert_eq!(tag, ApplicationTag::UnsignedInt);
//! ```
//!
//! ## Context-Specific Encoding
//!
//! ```rust
//! use bacnet_rs::encoding::{encode_context_unsigned, decode_context_unsigned};
//!
//! // Encode with context tag 3
//! let buffer = encode_context_unsigned(1000, 3).unwrap();
//!
//! // Decode with expected context tag 3
//! let (value, consumed) = decode_context_unsigned(&buffer, 3).unwrap();
//! assert_eq!(value, 1000);
//! ```
//!
//! # Error Handling
//!
//! Encoding operations can fail for several reasons:
//!
//! - **Buffer Overflow**: Output buffer is too small
//! - **Invalid Data**: Input data is malformed or invalid
//! - **Type Mismatch**: Data doesn't match expected type
//! - **Length Error**: Incorrect length fields
//!
//! ```rust
//! use bacnet_rs::encoding::{EncodingError, decode_unsigned};
//!
//! let invalid_data = vec![0x21]; // Missing value byte
//! match decode_unsigned(&invalid_data) {
//!     Ok((value, _)) => println!("Value: {}", value),
//!     Err(EncodingError::BufferUnderflow) => println!("Not enough data"),
//!     Err(e) => println!("Other error: {:?}", e),
//! }
//! ```
//!
//! # Performance Notes
//!
//! - Encoding functions write directly to provided buffers for efficiency
//! - Decoding functions return both the decoded value and bytes consumed
//! - No dynamic allocation is required for basic encoding/decoding operations
//! - Context tag validation is performed during decoding for safety

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::object::ObjectIdentifier;

/// Result type for encoding operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, EncodingError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, EncodingError>;

/// Errors that can occur during encoding/decoding operations
#[derive(Debug, Clone)]
pub enum EncodingError {
    /// Buffer overflow during encoding
    BufferOverflow,
    /// Buffer underflow during decoding
    BufferUnderflow,
    /// Invalid tag number encountered
    InvalidTag,
    /// Invalid length value
    InvalidLength,
    /// Unexpected end of data during decoding
    UnexpectedEndOfData,
    /// Invalid encoding format
    InvalidFormat(String),
    /// Value out of valid range
    ValueOutOfRange,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodingError::BufferOverflow => write!(f, "Buffer overflow during encoding"),
            EncodingError::BufferUnderflow => write!(f, "Buffer underflow during decoding"),
            EncodingError::InvalidTag => write!(f, "Invalid tag number encountered"),
            EncodingError::InvalidLength => write!(f, "Invalid length value"),
            EncodingError::UnexpectedEndOfData => write!(f, "Unexpected end of data"),
            EncodingError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            EncodingError::ValueOutOfRange => write!(f, "Value out of valid range"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for EncodingError {}

/// BACnet application tag numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApplicationTag {
    Null = 0,
    Boolean = 1,
    UnsignedInt = 2,
    SignedInt = 3,
    Real = 4,
    Double = 5,
    OctetString = 6,
    CharacterString = 7,
    BitString = 8,
    Enumerated = 9,
    Date = 10,
    Time = 11,
    ObjectIdentifier = 12,
    Reserved13 = 13,
    Reserved14 = 14,
    Reserved15 = 15,
}

/// Encode a BACnet application tag
pub fn encode_application_tag(
    buffer: &mut Vec<u8>,
    tag: ApplicationTag,
    length: usize,
) -> Result<()> {
    let tag_byte = if length < 5 {
        (tag as u8) << 4 | (length as u8)
    } else {
        (tag as u8) << 4 | 5
    };

    buffer.push(tag_byte);

    if length >= 5 {
        if length < 254 {
            buffer.push(length as u8);
        } else if length < 65536 {
            buffer.push(254);
            buffer.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            buffer.push(255);
            buffer.extend_from_slice(&(length as u32).to_be_bytes());
        }
    }

    Ok(())
}

/// Decode a BACnet application tag
pub fn decode_application_tag(data: &[u8]) -> Result<(ApplicationTag, usize, usize)> {
    if data.is_empty() {
        return Err(EncodingError::InvalidTag);
    }

    let tag_byte = data[0];
    let tag = ApplicationTag::try_from(tag_byte >> 4)?;
    let mut length = (tag_byte & 0x0F) as usize;
    let mut consumed = 1;

    if length == 5 {
        if data.len() < 2 {
            return Err(EncodingError::BufferUnderflow);
        }

        let len_byte = data[1];
        consumed += 1;

        match len_byte {
            0..=253 => {
                length = len_byte as usize;
            }
            254 => {
                if data.len() < 4 {
                    return Err(EncodingError::BufferUnderflow);
                }
                length = u16::from_be_bytes([data[2], data[3]]) as usize;
                consumed += 2;
            }
            255 => {
                if data.len() < 6 {
                    return Err(EncodingError::BufferUnderflow);
                }
                length = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
                consumed += 4;
            }
        }
    }

    Ok((tag, length, consumed))
}

/// Encode a BACnet boolean value
pub fn encode_boolean(buffer: &mut Vec<u8>, value: bool) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Boolean, if value { 1 } else { 0 })?;
    Ok(())
}

/// Decode a BACnet boolean value
pub fn decode_boolean(data: &[u8]) -> Result<(bool, usize)> {
    let (tag, length, consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Boolean {
        return Err(EncodingError::InvalidTag);
    }

    let value = match length {
        0 => false,
        1 => true,
        _ => return Err(EncodingError::InvalidLength),
    };

    Ok((value, consumed))
}

/// Encode a BACnet unsigned integer
pub fn encode_unsigned(buffer: &mut Vec<u8>, value: u32) -> Result<()> {
    let bytes = if value == 0 {
        vec![0]
    } else if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    encode_application_tag(buffer, ApplicationTag::UnsignedInt, bytes.len())?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Decode a BACnet unsigned integer
pub fn decode_unsigned(data: &[u8]) -> Result<(u32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::UnsignedInt {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = match length {
        1 => data[consumed] as u32,
        2 => u16::from_be_bytes([data[consumed], data[consumed + 1]]) as u32,
        3 => {
            let bytes = [0, data[consumed], data[consumed + 1], data[consumed + 2]];
            u32::from_be_bytes(bytes)
        }
        4 => u32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };

    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet signed integer
pub fn encode_signed(buffer: &mut Vec<u8>, value: i32) -> Result<()> {
    let bytes = if (-128..=127).contains(&value) {
        vec![value as u8]
    } else if (-32768..=32767).contains(&value) {
        (value as i16).to_be_bytes().to_vec()
    } else if (-8388608..=8388607).contains(&value) {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    encode_application_tag(buffer, ApplicationTag::SignedInt, bytes.len())?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Decode a BACnet signed integer
pub fn decode_signed(data: &[u8]) -> Result<(i32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::SignedInt {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = match length {
        1 => data[consumed] as i8 as i32,
        2 => i16::from_be_bytes([data[consumed], data[consumed + 1]]) as i32,
        3 => {
            let sign_extend = if data[consumed] & 0x80 != 0 {
                0xFF
            } else {
                0x00
            };
            let bytes = [
                sign_extend,
                data[consumed],
                data[consumed + 1],
                data[consumed + 2],
            ];
            i32::from_be_bytes(bytes)
        }
        4 => i32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };

    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet real (float) value
pub fn encode_real(buffer: &mut Vec<u8>, value: f32) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Real, 4)?;
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a BACnet real (float) value
pub fn decode_real(data: &[u8]) -> Result<(f32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Real {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 {
        return Err(EncodingError::InvalidLength);
    }

    if data.len() < consumed + 4 {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = f32::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
    ]);

    consumed += 4;
    Ok((value, consumed))
}

/// Encode a BACnet octet string
pub fn encode_octet_string(buffer: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::OctetString, value.len())?;
    buffer.extend_from_slice(value);
    Ok(())
}

/// Decode a BACnet octet string
pub fn decode_octet_string(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::OctetString {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = data[consumed..consumed + length].to_vec();
    consumed += length;

    Ok((value, consumed))
}

/// Encode a BACnet character string
pub fn encode_character_string(buffer: &mut Vec<u8>, value: &str) -> Result<()> {
    let string_bytes = value.as_bytes();
    encode_application_tag(
        buffer,
        ApplicationTag::CharacterString,
        string_bytes.len() + 1,
    )?;
    buffer.push(0); // Character set encoding (0 = ANSI X3.4)
    buffer.extend_from_slice(string_bytes);
    Ok(())
}

/// Decode a BACnet character string
pub fn decode_character_string(data: &[u8]) -> Result<(String, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::CharacterString {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length || length == 0 {
        return Err(EncodingError::BufferUnderflow);
    }

    // Skip character set encoding byte
    let _encoding = data[consumed];
    consumed += 1;

    let string_data = &data[consumed..consumed + length - 1];
    let value = String::from_utf8(string_data.to_vec())
        .map_err(|_| EncodingError::InvalidFormat("Invalid UTF-8 string".to_string()))?;

    consumed += length - 1;

    Ok((value, consumed))
}

/// Encode a BACnet enumerated value
pub fn encode_enumerated(buffer: &mut Vec<u8>, value: u32) -> Result<()> {
    let bytes = if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    encode_application_tag(buffer, ApplicationTag::Enumerated, bytes.len())?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Decode a BACnet enumerated value
pub fn decode_enumerated(data: &[u8]) -> Result<(u32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Enumerated {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = match length {
        1 => data[consumed] as u32,
        2 => u16::from_be_bytes([data[consumed], data[consumed + 1]]) as u32,
        3 => {
            let bytes = [0, data[consumed], data[consumed + 1], data[consumed + 2]];
            u32::from_be_bytes(bytes)
        }
        4 => u32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };

    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet date
pub fn encode_date(buffer: &mut Vec<u8>, year: u16, month: u8, day: u8, weekday: u8) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Date, 4)?;
    buffer.push(((year - 1900) % 256) as u8);
    buffer.push(month);
    buffer.push(day);
    buffer.push(weekday);
    Ok(())
}

/// Decode a BACnet date
pub fn decode_date(data: &[u8]) -> Result<((u16, u8, u8, u8), usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Date {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }

    let year = if data[consumed] == 255 {
        255
    } else {
        1900 + data[consumed] as u16
    };
    let month = data[consumed + 1];
    let day = data[consumed + 2];
    let weekday = data[consumed + 3];

    consumed += 4;
    Ok(((year, month, day, weekday), consumed))
}

/// Encode a BACnet time
pub fn encode_time(
    buffer: &mut Vec<u8>,
    hour: u8,
    minute: u8,
    second: u8,
    hundredths: u8,
) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Time, 4)?;
    buffer.push(hour);
    buffer.push(minute);
    buffer.push(second);
    buffer.push(hundredths);
    Ok(())
}

/// Decode a BACnet time
pub fn decode_time(data: &[u8]) -> Result<((u8, u8, u8, u8), usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Time {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }

    let hour = data[consumed];
    let minute = data[consumed + 1];
    let second = data[consumed + 2];
    let hundredths = data[consumed + 3];

    consumed += 4;
    Ok(((hour, minute, second, hundredths), consumed))
}

/// Encode a BACnet object identifier
pub fn encode_object_identifier(buffer: &mut Vec<u8>, object_id: ObjectIdentifier) -> Result<()> {
    if object_id.instance > 0x3FFFFF {
        return Err(EncodingError::ValueOutOfRange);
    }

    let object_id: u32 = object_id.into();
    encode_application_tag(buffer, ApplicationTag::ObjectIdentifier, 4)?;
    buffer.extend_from_slice(&object_id.to_be_bytes());
    Ok(())
}

/// Decode a BACnet object identifier
pub fn decode_object_identifier(data: &[u8]) -> Result<((u16, u32), usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::ObjectIdentifier {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }

    let object_id = u32::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
    ]);

    let object_type = (object_id >> 22) as u16;
    let instance = object_id & 0x3FFFFF;

    consumed += 4;
    Ok(((object_type, instance), consumed))
}

/// Encode a BACnet double (64-bit float)
pub fn encode_double(buffer: &mut Vec<u8>, value: f64) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Double, 8)?;
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a BACnet double (64-bit float)
pub fn decode_double(data: &[u8]) -> Result<(f64, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;

    if tag != ApplicationTag::Double {
        return Err(EncodingError::InvalidTag);
    }

    if length != 8 || data.len() < consumed + 8 {
        return Err(EncodingError::InvalidLength);
    }

    let value = f64::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
        data[consumed + 4],
        data[consumed + 5],
        data[consumed + 6],
        data[consumed + 7],
    ]);

    consumed += 8;
    Ok((value, consumed))
}

/// Encode a context-specific tag
pub fn encode_context_tag(buffer: &mut Vec<u8>, tag_number: u8, length: usize) -> Result<()> {
    if tag_number > 14 {
        return Err(EncodingError::ValueOutOfRange);
    }

    let tag_byte = if length < 5 {
        0x08 | (tag_number << 4) | (length as u8)
    } else {
        0x08 | (tag_number << 4) | 5
    };

    buffer.push(tag_byte);

    if length >= 5 {
        if length < 254 {
            buffer.push(length as u8);
        } else if length < 65536 {
            buffer.push(254);
            buffer.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            buffer.push(255);
            buffer.extend_from_slice(&(length as u32).to_be_bytes());
        }
    }

    Ok(())
}

/// Encode a context-specific unsigned integer
pub fn encode_context_unsigned(value: u32, tag_number: u8) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    // Determine the number of bytes needed for the unsigned value
    let bytes = if value == 0 {
        vec![0]
    } else if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = value.to_be_bytes();
        bytes[1..].to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };

    // Encode the context tag
    encode_context_tag(&mut buffer, tag_number, bytes.len())?;

    // Add the value bytes
    buffer.extend_from_slice(&bytes);

    Ok(buffer)
}

/// Decode a context-specific tag
pub fn decode_context_tag(data: &[u8]) -> Result<(u8, usize, usize)> {
    if data.is_empty() {
        return Err(EncodingError::InvalidTag);
    }

    let tag_byte = data[0];
    if (tag_byte & 0x08) == 0 {
        return Err(EncodingError::InvalidTag);
    }

    let tag_number = (tag_byte >> 4) & 0x0F;
    let mut length = (tag_byte & 0x07) as usize;
    let mut consumed = 1;

    if length == 5 {
        if data.len() < 2 {
            return Err(EncodingError::BufferUnderflow);
        }

        let len_byte = data[1];
        consumed += 1;

        match len_byte {
            0..=253 => {
                length = len_byte as usize;
            }
            254 => {
                if data.len() < 4 {
                    return Err(EncodingError::BufferUnderflow);
                }
                length = u16::from_be_bytes([data[2], data[3]]) as usize;
                consumed += 2;
            }
            255 => {
                if data.len() < 6 {
                    return Err(EncodingError::BufferUnderflow);
                }
                length = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
                consumed += 4;
            }
        }
    }

    Ok((tag_number, length, consumed))
}

/// Decode a context-specific unsigned integer
pub fn decode_context_unsigned(data: &[u8], expected_tag: u8) -> Result<(u32, usize)> {
    let (tag_number, length, tag_consumed) = decode_context_tag(data)?;

    if tag_number != expected_tag {
        return Err(EncodingError::InvalidTag);
    }

    if data.len() < tag_consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = match length {
        0 => 0,
        1 => data[tag_consumed] as u32,
        2 => u16::from_be_bytes([data[tag_consumed], data[tag_consumed + 1]]) as u32,
        3 => {
            let bytes = [
                0,
                data[tag_consumed],
                data[tag_consumed + 1],
                data[tag_consumed + 2],
            ];
            u32::from_be_bytes(bytes)
        }
        4 => u32::from_be_bytes([
            data[tag_consumed],
            data[tag_consumed + 1],
            data[tag_consumed + 2],
            data[tag_consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };

    Ok((value, tag_consumed + length))
}

/// Encode a context-specific enumerated value
pub fn encode_context_enumerated(value: u32, tag_number: u8) -> Result<Vec<u8>> {
    // Enumerated values use the same encoding as unsigned integers
    encode_context_unsigned(value, tag_number)
}

/// Decode a context-specific enumerated value
pub fn decode_context_enumerated(data: &[u8], expected_tag: u8) -> Result<(u32, usize)> {
    // Enumerated values use the same decoding as unsigned integers
    decode_context_unsigned(data, expected_tag)
}

/// Encode a context-specific object identifier
pub fn encode_context_object_id(object_id: ObjectIdentifier, tag_number: u8) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    // Combine object type and instance into 4-byte object identifier
    let object_id: u32 = object_id.into();

    // Encode context tag with length 4
    encode_context_tag(&mut buffer, tag_number, 4)?;

    // Add the object identifier bytes
    buffer.extend_from_slice(&object_id.to_be_bytes());

    Ok(buffer)
}

/// Decode a context-specific object identifier
pub fn decode_context_object_id(
    data: &[u8],
    expected_tag: u8,
) -> Result<(ObjectIdentifier, usize)> {
    let (tag_number, length, tag_consumed) = decode_context_tag(data)?;

    if tag_number != expected_tag {
        return Err(EncodingError::InvalidTag);
    }

    if length != 4 {
        return Err(EncodingError::InvalidLength);
    }

    if data.len() < tag_consumed + 4 {
        return Err(EncodingError::BufferUnderflow);
    }

    let object_id = u32::from_be_bytes([
        data[tag_consumed],
        data[tag_consumed + 1],
        data[tag_consumed + 2],
        data[tag_consumed + 3],
    ]);

    Ok((object_id.into(), tag_consumed + 4))
}

impl TryFrom<u8> for ApplicationTag {
    type Error = EncodingError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(ApplicationTag::Null),
            1 => Ok(ApplicationTag::Boolean),
            2 => Ok(ApplicationTag::UnsignedInt),
            3 => Ok(ApplicationTag::SignedInt),
            4 => Ok(ApplicationTag::Real),
            5 => Ok(ApplicationTag::Double),
            6 => Ok(ApplicationTag::OctetString),
            7 => Ok(ApplicationTag::CharacterString),
            8 => Ok(ApplicationTag::BitString),
            9 => Ok(ApplicationTag::Enumerated),
            10 => Ok(ApplicationTag::Date),
            11 => Ok(ApplicationTag::Time),
            12 => Ok(ApplicationTag::ObjectIdentifier),
            _ => Err(EncodingError::InvalidTag),
        }
    }
}

/// Advanced encoding features and optimizations
pub mod advanced {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::{collections::BTreeMap, vec::Vec};

    /// Buffer manager for efficient encoding/decoding operations
    #[derive(Debug)]
    pub struct BufferManager {
        /// Reusable buffers for encoding operations
        #[cfg(feature = "std")]
        encode_buffers: Vec<Vec<u8>>,
        #[cfg(not(feature = "std"))]
        encode_buffers: alloc::vec::Vec<alloc::vec::Vec<u8>>,
        /// Maximum buffer size to cache
        max_buffer_size: usize,
        /// Statistics for buffer usage
        pub stats: BufferStats,
    }

    /// Buffer usage statistics
    #[derive(Debug, Default)]
    pub struct BufferStats {
        pub total_allocations: u64,
        pub buffer_reuses: u64,
        pub max_buffer_size_used: usize,
        pub total_bytes_encoded: u64,
        pub total_bytes_decoded: u64,
    }

    impl BufferManager {
        /// Create a new buffer manager
        pub fn new(max_buffer_size: usize) -> Self {
            Self {
                encode_buffers: Vec::with_capacity(8),
                max_buffer_size,
                stats: BufferStats::default(),
            }
        }

        /// Get a buffer for encoding, reusing if possible
        pub fn get_encode_buffer(&mut self) -> Vec<u8> {
            if let Some(mut buffer) = self.encode_buffers.pop() {
                buffer.clear();
                self.stats.buffer_reuses += 1;
                buffer
            } else {
                self.stats.total_allocations += 1;
                Vec::with_capacity(256)
            }
        }

        /// Return a buffer for reuse
        pub fn return_buffer(&mut self, buffer: Vec<u8>) {
            self.stats.total_bytes_encoded += buffer.len() as u64;
            if buffer.capacity() <= self.max_buffer_size && self.encode_buffers.len() < 16 {
                self.encode_buffers.push(buffer);
            }
        }

        /// Update decoding statistics
        pub fn update_decode_stats(&mut self, bytes_decoded: usize) {
            self.stats.total_bytes_decoded += bytes_decoded as u64;
        }
    }

    /// Context-specific tag encoding/decoding
    pub mod context {
        use super::*;

        /// Encode a context-specific tag
        pub fn encode_context_tag(
            buffer: &mut Vec<u8>,
            tag_number: u8,
            length: usize,
        ) -> Result<()> {
            if tag_number > 14 {
                return Err(EncodingError::ValueOutOfRange);
            }

            let tag_byte = if length < 5 {
                0x08 | (tag_number << 4) | (length as u8)
            } else {
                0x08 | (tag_number << 4) | 5
            };

            buffer.push(tag_byte);

            if length >= 5 {
                if length < 254 {
                    buffer.push(length as u8);
                } else if length < 65536 {
                    buffer.push(254);
                    buffer.extend_from_slice(&(length as u16).to_be_bytes());
                } else {
                    buffer.push(255);
                    buffer.extend_from_slice(&(length as u32).to_be_bytes());
                }
            }

            Ok(())
        }

        /// Decode a context-specific tag
        pub fn decode_context_tag(data: &[u8]) -> Result<(u8, usize, usize)> {
            if data.is_empty() {
                return Err(EncodingError::InvalidTag);
            }

            let tag_byte = data[0];
            if (tag_byte & 0x08) == 0 {
                return Err(EncodingError::InvalidTag);
            }

            let tag_number = (tag_byte >> 4) & 0x0F;
            let mut length = (tag_byte & 0x07) as usize;
            let mut consumed = 1;

            if length == 5 {
                if data.len() < 2 {
                    return Err(EncodingError::BufferUnderflow);
                }

                let len_byte = data[1];
                consumed += 1;

                match len_byte {
                    0..=253 => {
                        length = len_byte as usize;
                    }
                    254 => {
                        if data.len() < 4 {
                            return Err(EncodingError::BufferUnderflow);
                        }
                        length = u16::from_be_bytes([data[2], data[3]]) as usize;
                        consumed += 2;
                    }
                    255 => {
                        if data.len() < 6 {
                            return Err(EncodingError::BufferUnderflow);
                        }
                        length = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
                        consumed += 4;
                    }
                }
            }

            Ok((tag_number, length, consumed))
        }

        /// Encode opening tag for constructed data
        pub fn encode_opening_tag(buffer: &mut Vec<u8>, tag_number: u8) -> Result<()> {
            if tag_number > 14 {
                return Err(EncodingError::ValueOutOfRange);
            }
            buffer.push(0x0E | (tag_number << 4));
            Ok(())
        }

        /// Encode closing tag for constructed data
        pub fn encode_closing_tag(buffer: &mut Vec<u8>, tag_number: u8) -> Result<()> {
            if tag_number > 14 {
                return Err(EncodingError::ValueOutOfRange);
            }
            buffer.push(0x0F | (tag_number << 4));
            Ok(())
        }
    }

    /// Bit string encoding/decoding utilities
    pub mod bitstring {
        use super::*;

        /// Encode a bit string
        #[allow(clippy::manual_is_multiple_of)]
        pub fn encode_bit_string(buffer: &mut Vec<u8>, bits: &[bool]) -> Result<()> {
            let byte_count = bits.len().div_ceil(8);
            let unused_bits = if bits.len() % 8 == 0 {
                0
            } else {
                8 - (bits.len() % 8)
            };

            encode_application_tag(buffer, ApplicationTag::BitString, byte_count + 1)?;
            buffer.push(unused_bits as u8);

            let mut current_byte = 0u8;
            let mut bit_pos = 0;

            for &bit in bits {
                if bit {
                    current_byte |= 1 << (7 - bit_pos);
                }
                bit_pos += 1;

                if bit_pos == 8 {
                    buffer.push(current_byte);
                    current_byte = 0;
                    bit_pos = 0;
                }
            }

            if bit_pos > 0 {
                buffer.push(current_byte);
            }

            Ok(())
        }

        /// Decode a bit string
        pub fn decode_bit_string(data: &[u8]) -> Result<(Vec<bool>, usize)> {
            let (tag, length, mut consumed) = decode_application_tag(data)?;

            if tag != ApplicationTag::BitString {
                return Err(EncodingError::InvalidTag);
            }

            if length == 0 || data.len() < consumed + length {
                return Err(EncodingError::BufferUnderflow);
            }

            let unused_bits = data[consumed] as usize;
            consumed += 1;

            if unused_bits > 7 {
                return Err(EncodingError::InvalidFormat(
                    "Invalid unused bits count".to_string(),
                ));
            }

            let mut bits = Vec::new();
            let byte_count = length - 1;

            for i in 0..byte_count {
                let byte_val = data[consumed + i];
                let bits_in_byte = if i == byte_count - 1 {
                    8 - unused_bits
                } else {
                    8
                };

                for bit_pos in 0..bits_in_byte {
                    bits.push((byte_val & (1 << (7 - bit_pos))) != 0);
                }
            }

            consumed += byte_count;
            Ok((bits, consumed))
        }
    }

    /// Performance optimization utilities
    pub mod perf {
        use super::*;

        /// Fast path encoder for common data types
        pub struct FastEncoder {
            buffer: Vec<u8>,
        }

        impl FastEncoder {
            /// Create a new fast encoder
            pub fn new(capacity: usize) -> Self {
                Self {
                    buffer: Vec::with_capacity(capacity),
                }
            }

            /// Get the encoded data
            pub fn data(&self) -> &[u8] {
                &self.buffer
            }

            /// Clear the buffer for reuse
            pub fn clear(&mut self) {
                self.buffer.clear();
            }

            /// Fast encode unsigned integer (optimized for common sizes)
            pub fn encode_unsigned_fast(&mut self, value: u32) -> Result<()> {
                match value {
                    0 => {
                        self.buffer.extend_from_slice(&[0x21, 0x00]);
                    }
                    1..=255 => {
                        self.buffer.extend_from_slice(&[0x21, value as u8]);
                    }
                    256..=65535 => {
                        let bytes = (value as u16).to_be_bytes();
                        self.buffer.extend_from_slice(&[0x22]);
                        self.buffer.extend_from_slice(&bytes);
                    }
                    65536..=16777215 => {
                        let bytes = value.to_be_bytes();
                        self.buffer.extend_from_slice(&[0x23]);
                        self.buffer.extend_from_slice(&bytes[1..]);
                    }
                    _ => {
                        let bytes = value.to_be_bytes();
                        self.buffer.extend_from_slice(&[0x24]);
                        self.buffer.extend_from_slice(&bytes);
                    }
                }
                Ok(())
            }

            /// Fast encode boolean
            pub fn encode_boolean_fast(&mut self, value: bool) -> Result<()> {
                self.buffer.push(if value { 0x11 } else { 0x10 });
                Ok(())
            }

            /// Fast encode real (32-bit float)
            pub fn encode_real_fast(&mut self, value: f32) -> Result<()> {
                self.buffer.push(0x44);
                self.buffer.extend_from_slice(&value.to_be_bytes());
                Ok(())
            }
        }
    }

    /// Validation utilities for encoded data
    pub mod validation {
        use super::*;

        /// Validate encoded BACnet data
        pub struct DataValidator {
            /// Maximum allowed tag depth for constructed data
            max_tag_depth: usize,
            /// Maximum allowed string length
            max_string_length: usize,
        }

        impl DataValidator {
            /// Create a new data validator
            pub fn new(max_tag_depth: usize, max_string_length: usize) -> Self {
                Self {
                    max_tag_depth,
                    max_string_length,
                }
            }

            /// Validate a complete BACnet data structure
            pub fn validate(&self, data: &[u8]) -> Result<()> {
                self.validate_recursive(data, 0)
            }

            fn validate_recursive(&self, data: &[u8], depth: usize) -> Result<()> {
                if depth > self.max_tag_depth {
                    return Err(EncodingError::InvalidFormat(
                        "Maximum tag depth exceeded".to_string(),
                    ));
                }

                let mut pos = 0;
                while pos < data.len() {
                    let (tag, length, consumed) = decode_application_tag(&data[pos..])?;
                    pos += consumed;

                    match tag {
                        ApplicationTag::CharacterString => {
                            if length > self.max_string_length {
                                return Err(EncodingError::InvalidFormat(
                                    "String too long".to_string(),
                                ));
                            }
                        }
                        ApplicationTag::OctetString => {
                            if length > self.max_string_length * 2 {
                                return Err(EncodingError::InvalidFormat(
                                    "Octet string too long".to_string(),
                                ));
                            }
                        }
                        _ => {}
                    }

                    pos += length;
                }

                Ok(())
            }
        }
    }
}

/// Encoding stream for efficient multi-value encoding
pub struct EncodingStream {
    buffer: Vec<u8>,
    position: usize,
    max_size: usize,
}

impl EncodingStream {
    /// Create a new encoding stream
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(max_size),
            position: 0,
            max_size,
        }
    }

    /// Encode an application tagged value
    pub fn encode_tagged<T: EncodableValue>(
        &mut self,
        tag: ApplicationTag,
        value: T,
    ) -> Result<()> {
        if self.buffer.len() >= self.max_size {
            return Err(EncodingError::BufferOverflow);
        }
        value.encode_to(tag, &mut self.buffer)
    }

    /// Encode a context tagged value
    pub fn encode_context<T: EncodableValue>(&mut self, tag_number: u8, value: T) -> Result<()> {
        if self.buffer.len() >= self.max_size {
            return Err(EncodingError::BufferOverflow);
        }
        value.encode_context_to(tag_number, &mut self.buffer)
    }

    /// Get the encoded data
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Take the buffer
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }

    /// Clear the stream
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.position = 0;
    }
}

/// Trait for values that can be encoded
pub trait EncodableValue {
    /// Encode with application tag
    fn encode_to(&self, tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()>;

    /// Encode with context tag
    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()>;
}

impl EncodableValue for bool {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_boolean(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        advanced::context::encode_context_tag(buffer, tag_number, if *self { 1 } else { 0 })
    }
}

impl EncodableValue for u32 {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_unsigned(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        let temp_buffer = Vec::new();
        let mut temp = temp_buffer;
        encode_unsigned(&mut temp, *self)?;
        advanced::context::encode_context_tag(buffer, tag_number, temp.len() - 1)?;
        buffer.extend_from_slice(&temp[1..]);
        Ok(())
    }
}

impl EncodableValue for i32 {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_signed(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        let temp_buffer = Vec::new();
        let mut temp = temp_buffer;
        encode_signed(&mut temp, *self)?;
        advanced::context::encode_context_tag(buffer, tag_number, temp.len() - 1)?;
        buffer.extend_from_slice(&temp[1..]);
        Ok(())
    }
}

impl EncodableValue for f32 {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_real(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        advanced::context::encode_context_tag(buffer, tag_number, 4)?;
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl EncodableValue for f64 {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_double(buffer, *self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        advanced::context::encode_context_tag(buffer, tag_number, 8)?;
        buffer.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl EncodableValue for &str {
    fn encode_to(&self, _tag: ApplicationTag, buffer: &mut Vec<u8>) -> Result<()> {
        encode_character_string(buffer, self)
    }

    fn encode_context_to(&self, tag_number: u8, buffer: &mut Vec<u8>) -> Result<()> {
        advanced::context::encode_context_tag(buffer, tag_number, self.len() + 1)?;
        buffer.push(0); // Character set
        buffer.extend_from_slice(self.as_bytes());
        Ok(())
    }
}

/// Decoding stream for efficient multi-value decoding
pub struct DecodingStream<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> DecodingStream<'a> {
    /// Create a new decoding stream
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Check if stream has more data
    pub fn has_data(&self) -> bool {
        self.position < self.data.len()
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Peek at the next tag without consuming
    pub fn peek_tag(&self) -> Result<ApplicationTag> {
        if self.position >= self.data.len() {
            return Err(EncodingError::UnexpectedEndOfData);
        }

        let tag_byte = self.data[self.position];
        let tag = ApplicationTag::try_from(tag_byte >> 4)?;
        Ok(tag)
    }

    /// Decode a boolean
    pub fn decode_boolean(&mut self) -> Result<bool> {
        let (value, consumed) = decode_boolean(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode an unsigned integer
    pub fn decode_unsigned(&mut self) -> Result<u32> {
        let (value, consumed) = decode_unsigned(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a signed integer
    pub fn decode_signed(&mut self) -> Result<i32> {
        let (value, consumed) = decode_signed(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a real number
    pub fn decode_real(&mut self) -> Result<f32> {
        let (value, consumed) = decode_real(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a double
    pub fn decode_double(&mut self) -> Result<f64> {
        let (value, consumed) = decode_double(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a character string
    pub fn decode_character_string(&mut self) -> Result<String> {
        let (value, consumed) = decode_character_string(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode an octet string
    pub fn decode_octet_string(&mut self) -> Result<Vec<u8>> {
        let (value, consumed) = decode_octet_string(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode an enumerated value
    pub fn decode_enumerated(&mut self) -> Result<u32> {
        let (value, consumed) = decode_enumerated(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a date
    pub fn decode_date(&mut self) -> Result<(u16, u8, u8, u8)> {
        let (value, consumed) = decode_date(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode a time
    pub fn decode_time(&mut self) -> Result<(u8, u8, u8, u8)> {
        let (value, consumed) = decode_time(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Decode an object identifier
    pub fn decode_object_identifier(&mut self) -> Result<(u16, u32)> {
        let (value, consumed) = decode_object_identifier(&self.data[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Skip a value
    pub fn skip_value(&mut self) -> Result<()> {
        let (_tag, length, consumed) = decode_application_tag(&self.data[self.position..])?;
        self.position += consumed + length;
        Ok(())
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Set position
    pub fn set_position(&mut self, position: usize) -> Result<()> {
        if position > self.data.len() {
            return Err(EncodingError::ValueOutOfRange);
        }
        self.position = position;
        Ok(())
    }
}

/// Property array encoder
#[derive(Default)]
pub struct PropertyArrayEncoder {
    buffer: Vec<u8>,
    count: usize,
}

impl PropertyArrayEncoder {
    /// Create a new property array encoder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a property value
    pub fn add_property<T: EncodableValue>(&mut self, property_id: u32, value: T) -> Result<()> {
        // Encode property identifier with context tag 0
        advanced::context::encode_context_tag(&mut self.buffer, 0, 4)?;
        self.buffer.extend_from_slice(&property_id.to_be_bytes());

        // Open context tag 1 for value
        advanced::context::encode_opening_tag(&mut self.buffer, 1)?;

        // Encode the value
        value.encode_to(ApplicationTag::Null, &mut self.buffer)?;

        // Close context tag 1
        advanced::context::encode_closing_tag(&mut self.buffer, 1)?;

        self.count += 1;
        Ok(())
    }

    /// Get the encoded data
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the property count
    pub fn count(&self) -> usize {
        self.count
    }

    /// Clear the encoder
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.count = 0;
    }
}

/// Error encoder for BACnet error PDUs
#[derive(Default)]
pub struct ErrorEncoder {
    buffer: Vec<u8>,
}

impl ErrorEncoder {
    /// Create a new error encoder
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode an error class and code
    pub fn encode_error(&mut self, error_class: u32, error_code: u32) -> Result<()> {
        // Error class with context tag 0
        advanced::context::encode_context_tag(
            &mut self.buffer,
            0,
            if error_class <= 0xFF {
                1
            } else if error_class <= 0xFFFF {
                2
            } else {
                4
            },
        )?;
        encode_enumerated(&mut self.buffer, error_class)?;

        // Error code with context tag 1
        advanced::context::encode_context_tag(
            &mut self.buffer,
            1,
            if error_code <= 0xFF {
                1
            } else if error_code <= 0xFFFF {
                2
            } else {
                4
            },
        )?;
        encode_enumerated(&mut self.buffer, error_code)?;

        Ok(())
    }

    /// Get the encoded data
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Clear the encoder
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Encoding performance analyzer
#[derive(Debug, Default)]
pub struct EncodingAnalyzer {
    /// Encoding operation statistics
    pub stats: EncodingStatistics,
    /// Performance benchmarks
    benchmarks: Vec<EncodingBenchmark>,
    /// Error patterns
    error_patterns: Vec<ErrorPattern>,
}

/// Encoding operation statistics
#[derive(Debug, Default)]
pub struct EncodingStatistics {
    /// Total encoding operations
    pub total_encodings: u64,
    /// Total decoding operations
    pub total_decodings: u64,
    /// Total bytes encoded
    pub bytes_encoded: u64,
    /// Total bytes decoded
    pub bytes_decoded: u64,
    /// Encoding errors
    pub encoding_errors: u64,
    /// Decoding errors
    pub decoding_errors: u64,
    /// Average encoding time (microseconds)
    pub avg_encode_time_us: f64,
    /// Average decoding time (microseconds)
    pub avg_decode_time_us: f64,
}

/// Performance benchmark data
#[derive(Debug, Clone)]
struct EncodingBenchmark {
    /// Data type being benchmarked
    _data_type: &'static str,
    /// Data size in bytes
    _size: usize,
    /// Encoding time in microseconds
    _encode_time_us: u64,
    /// Decoding time in microseconds
    _decode_time_us: u64,
    /// Timestamp
    #[cfg(feature = "std")]
    _timestamp: std::time::Instant,
}

/// Error pattern tracking
#[derive(Debug, Clone)]
struct ErrorPattern {
    /// Error type
    error_type: EncodingError,
    /// Frequency count
    count: u32,
    /// Last occurrence
    #[cfg(feature = "std")]
    last_seen: std::time::Instant,
}

impl EncodingAnalyzer {
    /// Create a new encoding analyzer
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an encoding operation
    pub fn record_encoding(&mut self, data_type: &'static str, bytes: usize, duration_us: u64) {
        self.stats.total_encodings += 1;
        self.stats.bytes_encoded += bytes as u64;

        // Update average encoding time
        let total_time = self.stats.avg_encode_time_us * (self.stats.total_encodings - 1) as f64;
        self.stats.avg_encode_time_us =
            (total_time + duration_us as f64) / self.stats.total_encodings as f64;

        // Store benchmark data
        self.benchmarks.push(EncodingBenchmark {
            _data_type: data_type,
            _size: bytes,
            _encode_time_us: duration_us,
            _decode_time_us: 0,
            #[cfg(feature = "std")]
            _timestamp: std::time::Instant::now(),
        });

        // Keep only recent benchmarks (last 1000)
        if self.benchmarks.len() > 1000 {
            self.benchmarks.remove(0);
        }
    }

    /// Record a decoding operation
    pub fn record_decoding(&mut self, _data_type: &'static str, bytes: usize, duration_us: u64) {
        self.stats.total_decodings += 1;
        self.stats.bytes_decoded += bytes as u64;

        // Update average decoding time
        let total_time = self.stats.avg_decode_time_us * (self.stats.total_decodings - 1) as f64;
        self.stats.avg_decode_time_us =
            (total_time + duration_us as f64) / self.stats.total_decodings as f64;
    }

    /// Record an encoding error
    pub fn record_error(&mut self, error: EncodingError) {
        self.stats.encoding_errors += 1;

        // Update error pattern
        if let Some(pattern) = self
            .error_patterns
            .iter_mut()
            .find(|p| std::mem::discriminant(&p.error_type) == std::mem::discriminant(&error))
        {
            pattern.count += 1;
            #[cfg(feature = "std")]
            {
                pattern.last_seen = std::time::Instant::now();
            }
        } else {
            self.error_patterns.push(ErrorPattern {
                error_type: error,
                count: 1,
                #[cfg(feature = "std")]
                last_seen: std::time::Instant::now(),
            });
        }
    }

    /// Get encoding throughput (bytes per second)
    pub fn get_encoding_throughput(&self) -> f64 {
        if self.stats.avg_encode_time_us > 0.0 {
            (self.stats.bytes_encoded as f64 / self.stats.total_encodings as f64)
                / (self.stats.avg_encode_time_us / 1_000_000.0)
        } else {
            0.0
        }
    }

    /// Get decoding throughput (bytes per second)
    pub fn get_decoding_throughput(&self) -> f64 {
        if self.stats.avg_decode_time_us > 0.0 {
            (self.stats.bytes_decoded as f64 / self.stats.total_decodings as f64)
                / (self.stats.avg_decode_time_us / 1_000_000.0)
        } else {
            0.0
        }
    }

    /// Get most common errors
    pub fn get_top_errors(&self, limit: usize) -> Vec<(&EncodingError, u32)> {
        let mut errors: Vec<_> = self
            .error_patterns
            .iter()
            .map(|p| (&p.error_type, p.count))
            .collect();
        errors.sort_by(|a, b| b.1.cmp(&a.1));
        errors.truncate(limit);
        errors
    }

    /// Reset statistics
    pub fn reset(&mut self) {
        self.stats = EncodingStatistics::default();
        self.benchmarks.clear();
        self.error_patterns.clear();
    }
}

/// Encoding cache for frequently used values
#[derive(Debug)]
pub struct EncodingCache {
    /// Cached encoded values
    cache: Vec<CacheEntry>,
    /// Maximum cache size
    max_size: usize,
    /// Cache hit statistics
    pub hits: u64,
    /// Cache miss statistics
    pub misses: u64,
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Hash of the original value
    hash: u64,
    /// Encoded data
    encoded: Vec<u8>,
    /// Access count
    access_count: u32,
    /// Last access time
    #[cfg(feature = "std")]
    last_access: std::time::Instant,
}

impl EncodingCache {
    /// Create a new encoding cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Vec::with_capacity(max_size),
            max_size,
            hits: 0,
            misses: 0,
        }
    }

    /// Get cached encoding if available
    pub fn get(&mut self, hash: u64) -> Option<Vec<u8>> {
        if let Some(entry) = self.cache.iter_mut().find(|e| e.hash == hash) {
            entry.access_count += 1;
            #[cfg(feature = "std")]
            {
                entry.last_access = std::time::Instant::now();
            }
            self.hits += 1;
            Some(entry.encoded.clone())
        } else {
            self.misses += 1;
            None
        }
    }

    /// Store encoded value in cache
    pub fn put(&mut self, hash: u64, encoded: Vec<u8>) {
        // Check if already exists
        if self.cache.iter().any(|e| e.hash == hash) {
            return;
        }

        // Remove least recently used if cache is full
        if self.cache.len() >= self.max_size {
            self.cache.sort_by_key(|e| e.access_count);
            self.cache.remove(0);
        }

        self.cache.push(CacheEntry {
            hash,
            encoded,
            access_count: 1,
            #[cfg(feature = "std")]
            last_access: std::time::Instant::now(),
        });
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.cache.clear();
        self.hits = 0;
        self.misses = 0;
    }

    /// Get cache hit ratio
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total > 0 {
            self.hits as f64 / total as f64
        } else {
            0.0
        }
    }
}

/// Encoding configuration manager
#[derive(Debug, Clone)]
pub struct EncodingConfig {
    /// Use compression for large data
    pub use_compression: bool,
    /// Compression threshold (bytes)
    pub compression_threshold: usize,
    /// Enable caching
    pub enable_caching: bool,
    /// Cache size
    pub cache_size: usize,
    /// Enable performance tracking
    pub enable_performance_tracking: bool,
    /// Validation level
    pub validation_level: ValidationLevel,
    /// Maximum string length
    pub max_string_length: usize,
    /// Maximum array size
    pub max_array_size: usize,
}

/// Validation levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// No validation
    None,
    /// Basic validation
    Basic,
    /// Strict validation
    Strict,
    /// Paranoid validation (slowest)
    Paranoid,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            use_compression: false,
            compression_threshold: 1024,
            enable_caching: true,
            cache_size: 1000,
            enable_performance_tracking: true,
            validation_level: ValidationLevel::Basic,
            max_string_length: 4096,
            max_array_size: 1000,
        }
    }
}

/// High-level encoding manager
#[derive(Debug)]
pub struct EncodingManager {
    /// Configuration
    _config: EncodingConfig,
    /// Performance analyzer
    analyzer: Option<EncodingAnalyzer>,
    /// Encoding cache
    cache: Option<EncodingCache>,
    /// Buffer manager
    buffer_manager: advanced::BufferManager,
}

impl EncodingManager {
    /// Create a new encoding manager
    pub fn new(config: EncodingConfig) -> Self {
        let analyzer = if config.enable_performance_tracking {
            Some(EncodingAnalyzer::new())
        } else {
            None
        };

        let cache = if config.enable_caching {
            Some(EncodingCache::new(config.cache_size))
        } else {
            None
        };

        Self {
            _config: config,
            analyzer,
            cache,
            buffer_manager: advanced::BufferManager::new(8192),
        }
    }

    /// Encode a value with full management features
    pub fn encode<T: EncodableValue>(&mut self, value: T, tag: ApplicationTag) -> Result<Vec<u8>> {
        #[cfg(feature = "std")]
        let start_time = std::time::Instant::now();

        let mut buffer = self.buffer_manager.get_encode_buffer();
        let result = value.encode_to(tag, &mut buffer);

        #[cfg(feature = "std")]
        let duration = start_time.elapsed();

        match result {
            Ok(_) => {
                if let Some(ref mut analyzer) = self.analyzer {
                    #[cfg(feature = "std")]
                    analyzer.record_encoding("generic", buffer.len(), duration.as_micros() as u64);
                    #[cfg(not(feature = "std"))]
                    analyzer.record_encoding("generic", buffer.len(), 0);
                }

                let result_buffer = buffer.clone();
                self.buffer_manager.return_buffer(buffer);
                Ok(result_buffer)
            }
            Err(e) => {
                if let Some(ref mut analyzer) = self.analyzer {
                    analyzer.record_error(e.clone());
                }
                self.buffer_manager.return_buffer(buffer);
                Err(e)
            }
        }
    }

    /// Decode a value with full management features
    pub fn decode<T>(
        &mut self,
        data: &[u8],
        decoder: impl Fn(&[u8]) -> Result<(T, usize)>,
    ) -> Result<T> {
        #[cfg(feature = "std")]
        let start_time = std::time::Instant::now();

        let result = decoder(data);

        #[cfg(feature = "std")]
        let duration = start_time.elapsed();

        match result {
            Ok((value, consumed)) => {
                if let Some(ref mut analyzer) = self.analyzer {
                    #[cfg(feature = "std")]
                    analyzer.record_decoding("generic", consumed, duration.as_micros() as u64);
                    #[cfg(not(feature = "std"))]
                    analyzer.record_decoding("generic", consumed, 0);
                }
                Ok(value)
            }
            Err(e) => {
                if let Some(ref mut analyzer) = self.analyzer {
                    analyzer.record_error(e.clone());
                }
                Err(e)
            }
        }
    }

    /// Get performance statistics
    pub fn get_stats(&self) -> Option<&EncodingStatistics> {
        self.analyzer.as_ref().map(|a| &a.stats)
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> Option<(u64, u64, f64)> {
        self.cache
            .as_ref()
            .map(|c| (c.hits, c.misses, c.hit_ratio()))
    }

    /// Reset all statistics
    pub fn reset_stats(&mut self) {
        if let Some(ref mut analyzer) = self.analyzer {
            analyzer.reset();
        }
        if let Some(ref mut cache) = self.cache {
            cache.clear();
        }
    }
}

impl Default for EncodingManager {
    fn default() -> Self {
        Self::new(EncodingConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use crate::ObjectType;

    use super::*;

    #[test]
    fn test_encode_decode_boolean() {
        let mut buffer = Vec::new();

        // Test true
        encode_boolean(&mut buffer, true).unwrap();
        let (value, consumed) = decode_boolean(&buffer).unwrap();
        assert!(value);
        assert_eq!(consumed, 1);

        // Test false
        buffer.clear();
        encode_boolean(&mut buffer, false).unwrap();
        let (value, consumed) = decode_boolean(&buffer).unwrap();
        assert!(!value);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_encode_decode_unsigned() {
        let mut buffer = Vec::new();
        let test_values = [0, 255, 65535, 16777215, 4294967295];

        for &test_value in &test_values {
            buffer.clear();
            encode_unsigned(&mut buffer, test_value).unwrap();
            let (value, _) = decode_unsigned(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_signed() {
        let mut buffer = Vec::new();
        let test_values = [-128, -1, 0, 1, 127, -32768, 32767, -8388608, 8388607];

        for &test_value in &test_values {
            buffer.clear();
            encode_signed(&mut buffer, test_value).unwrap();
            let (value, _) = decode_signed(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_real() {
        let mut buffer = Vec::new();
        let test_values = [
            0.0,
            1.0,
            -1.0,
            std::f32::consts::PI,
            -273.15,
            f32::MAX,
            f32::MIN,
        ];

        for &test_value in &test_values {
            buffer.clear();
            encode_real(&mut buffer, test_value).unwrap();
            let (value, _) = decode_real(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_character_string() {
        let mut buffer = Vec::new();
        let test_strings = ["Hello", "BACnet", "Temperature Sensor", ""];

        for &test_string in &test_strings {
            buffer.clear();
            encode_character_string(&mut buffer, test_string).unwrap();
            let (value, _) = decode_character_string(&buffer).unwrap();
            assert_eq!(value, test_string);
        }
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let mut buffer = Vec::new();
        let test_data = vec![0x01, 0x02, 0x03, 0xFF, 0x00];

        encode_octet_string(&mut buffer, &test_data).unwrap();
        let (decoded, _) = decode_octet_string(&buffer).unwrap();
        assert_eq!(decoded, test_data);
    }

    #[test]
    fn test_encode_decode_enumerated() {
        let mut buffer = Vec::new();
        let test_values = [0, 1, 255, 256, 65535, 65536, 16777215];

        for &test_value in &test_values {
            buffer.clear();
            encode_enumerated(&mut buffer, test_value).unwrap();
            let (value, _) = decode_enumerated(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_date() {
        let mut buffer = Vec::new();

        encode_date(&mut buffer, 2024, 3, 15, 5).unwrap(); // Friday, March 15, 2024
        let ((year, month, day, weekday), _) = decode_date(&buffer).unwrap();
        assert_eq!(year, 2024);
        assert_eq!(month, 3);
        assert_eq!(day, 15);
        assert_eq!(weekday, 5);
    }

    #[test]
    fn test_encode_decode_time() {
        let mut buffer = Vec::new();

        encode_time(&mut buffer, 14, 30, 45, 50).unwrap(); // 14:30:45.50
        let ((hour, minute, second, hundredths), _) = decode_time(&buffer).unwrap();
        assert_eq!(hour, 14);
        assert_eq!(minute, 30);
        assert_eq!(second, 45);
        assert_eq!(hundredths, 50);
    }

    #[test]
    fn test_encode_decode_object_identifier() {
        let mut buffer = Vec::new();

        let object_id = ObjectIdentifier::new(ObjectType::AnalogValue, 12345);
        encode_object_identifier(&mut buffer, object_id).unwrap(); // Analog Value 12345
        let ((object_type, instance), _) = decode_object_identifier(&buffer).unwrap();
        assert_eq!(object_type, 2);
        assert_eq!(instance, 12345);
    }

    #[test]
    fn test_encode_decode_double() {
        let mut buffer = Vec::new();
        let test_values = [
            0.0,
            1.0,
            -1.0,
            std::f64::consts::PI,
            -273.15,
            f64::MAX,
            f64::MIN,
        ];

        for &test_value in &test_values {
            buffer.clear();
            encode_double(&mut buffer, test_value).unwrap();
            let (value, _) = decode_double(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_buffer_manager() {
        use advanced::BufferManager;

        let mut manager = BufferManager::new(1024);

        // Test getting and returning buffers
        let buffer1 = manager.get_encode_buffer();
        let buffer2 = manager.get_encode_buffer();

        assert_eq!(manager.stats.total_allocations, 2);
        assert_eq!(manager.stats.buffer_reuses, 0);

        manager.return_buffer(buffer1);
        let buffer3 = manager.get_encode_buffer();

        assert_eq!(manager.stats.total_allocations, 2);
        assert_eq!(manager.stats.buffer_reuses, 1);

        manager.return_buffer(buffer2);
        manager.return_buffer(buffer3);
    }

    #[test]
    fn test_context_specific_encoding() {
        use advanced::context::*;

        let mut buffer = Vec::new();

        // Test context-specific tag encoding
        encode_context_tag(&mut buffer, 5, 10).unwrap();
        let (tag_number, length, consumed) = decode_context_tag(&buffer).unwrap();

        assert_eq!(tag_number, 5);
        assert_eq!(length, 10);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_opening_closing_tags() {
        use advanced::context::*;

        let mut buffer = Vec::new();

        // Test opening and closing tags
        encode_opening_tag(&mut buffer, 3).unwrap();
        encode_closing_tag(&mut buffer, 3).unwrap();

        assert_eq!(buffer, vec![0x3E, 0x3F]);
    }

    #[test]
    fn test_bit_string_encoding() {
        use advanced::bitstring::*;

        let mut buffer = Vec::new();
        let bits = vec![true, false, true, true, false, false, true, false, true];

        encode_bit_string(&mut buffer, &bits).unwrap();
        let (decoded_bits, _) = decode_bit_string(&buffer).unwrap();

        assert_eq!(decoded_bits, bits);
    }

    #[test]
    fn test_fast_encoder() {
        use advanced::perf::FastEncoder;

        let mut encoder = FastEncoder::new(256);

        // Test fast encoding
        encoder.encode_unsigned_fast(42).unwrap();
        encoder.encode_boolean_fast(true).unwrap();
        encoder.encode_real_fast(std::f32::consts::PI).unwrap();

        let data = encoder.data();
        assert!(!data.is_empty());

        encoder.clear();
        assert_eq!(encoder.data().len(), 0);
    }

    #[test]
    fn test_data_validator() {
        use advanced::validation::DataValidator;

        let validator = DataValidator::new(10, 1000);

        // Test with valid data
        let mut buffer = Vec::new();
        encode_unsigned(&mut buffer, 42).unwrap();
        encode_character_string(&mut buffer, "Hello").unwrap();

        assert!(validator.validate(&buffer).is_ok());
    }

    #[test]
    fn test_encode_decode_performance() {
        let mut buffer = Vec::new();
        let iterations = 1000;

        // Performance test for encoding/decoding
        for i in 0..iterations {
            buffer.clear();
            encode_unsigned(&mut buffer, i).unwrap();
            let (value, _) = decode_unsigned(&buffer).unwrap();
            assert_eq!(value, i);
        }
    }
}
