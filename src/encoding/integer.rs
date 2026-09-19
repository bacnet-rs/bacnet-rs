//! BACnet Unsigned and Signed Integer encoding and decoding.
//!
//! This module implements ASHRAE 135-2024, Clause 20.2's "Encoding of an
//! Unsigned Integer Value" and "Encoding of a Signed Integer Value":
//!
//! - Both are primitive, with at least one contents octet, conveyed most
//!   significant octet first.
//! - Unsigned integers are plain big-endian binary numbers, encoded in the
//!   smallest number of octets possible — the first octet of a multi-octet
//!   encoding is never `0x00`.
//! - Signed integers are big-endian two's-complement, also encoded in the
//!   smallest number of octets possible — the first octet is never `0x00`
//!   unless dropping it would flip the sign (i.e. the next octet's MSB is
//!   1), and never `0xFF` unless dropping it would likewise flip the sign.
//!
//! Both rules reduce to the same two operations regardless of the target
//! width (`u32`/`u64` for unsigned, `i32`/`i64` for signed) or tag class
//! (application or context): find the minimal big-endian byte sequence that
//! round-trips to the value, and its inverse, zero- or sign-extending a
//! byte sequence back to a value. This module implements each operation
//! exactly once; every public function below is a thin wrapper that picks
//! the right width and tag framing.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use super::{
    decode_context_tag, encode_context_tag,
    tag::{ApplicationTagNumber, Tag, TagClass, TagValue},
    EncodingError, Result,
};

/// The minimal big-endian byte sequence encoding `value` as a BACnet
/// unsigned integer (at least 1 octet; no leading `0x00` unless `value` is
/// `0`, in which case a single `0x00` octet is required).
fn minimal_unsigned_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let all = value.to_be_bytes();
    let first_nonzero = all.iter().position(|&b| b != 0).unwrap();
    all[first_nonzero..].to_vec()
}

/// The minimal big-endian two's-complement byte sequence encoding `value`
/// as a BACnet signed integer (at least 1 octet).
fn minimal_signed_bytes(value: i64) -> Vec<u8> {
    let all = value.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let byte = all[start];
        let next_msb_set = all[start + 1] & 0x80 != 0;
        // A leading 0x00 is redundant as long as the next octet's sign bit
        // is also 0 (dropping it doesn't turn the value negative); a
        // leading 0xFF is redundant as long as the next octet's sign bit
        // is also 1 (dropping it doesn't turn the value non-negative).
        let redundant = (byte == 0x00 && !next_msb_set) || (byte == 0xFF && next_msb_set);
        if redundant {
            start += 1;
        } else {
            break;
        }
    }
    all[start..].to_vec()
}

/// Zero-extends `bytes` (1-8 octets, most significant first) into a `u64`.
/// Returns `0` for an empty slice.
fn decode_unsigned_content(bytes: &[u8]) -> u64 {
    let mut value = [0u8; 8];
    value[8 - bytes.len()..].copy_from_slice(bytes);
    u64::from_be_bytes(value)
}

/// Sign-extends `bytes` (1-8 octets, most significant first) into an `i64`.
fn decode_signed_content(bytes: &[u8]) -> i64 {
    let sign_extend = if bytes[0] & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut value = [sign_extend; 8];
    value[8 - bytes.len()..].copy_from_slice(bytes);
    i64::from_be_bytes(value)
}

/// Encode a BACnet unsigned integer
pub fn encode_unsigned(buffer: &mut Vec<u8>, value: u32) -> Result<()> {
    let bytes = minimal_unsigned_bytes(value as u64);
    Tag {
        number: ApplicationTagNumber::UnsignedInt as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(bytes.len() as u32),
    }
    .encode(buffer)?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Encode a BACnet unsigned integer from a `u64`
pub fn encode_unsigned64(buffer: &mut Vec<u8>, value: u64) {
    let bytes = minimal_unsigned_bytes(value);
    Tag {
        number: ApplicationTagNumber::UnsignedInt as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(bytes.len() as u32),
    }
    .encode(buffer)
    .expect("unsigned integer encodings are never longer than 8 octets");
    buffer.extend_from_slice(&bytes);
}

/// Decode a BACnet unsigned integer
pub fn decode_unsigned(data: &[u8]) -> Result<(u32, usize)> {
    let (t, mut consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::UnsignedInt as u32 {
        return Err(EncodingError::InvalidTag);
    }
    let length = t.content_length().unwrap_or(0) as usize;

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    if !(1..=4).contains(&length) {
        return Err(EncodingError::InvalidLength);
    }

    let value = decode_unsigned_content(&data[consumed..consumed + length]) as u32;

    consumed += length;
    Ok((value, consumed))
}

/// Decode a BACnet unsigned integer into a u64
pub fn decode_unsigned64(data: &[u8]) -> Result<(u64, usize)> {
    let (t, mut consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::UnsignedInt as u32 {
        return Err(EncodingError::InvalidTag);
    }
    let length = t.content_length().unwrap_or(0) as usize;

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    if !(1..=8).contains(&length) {
        return Err(EncodingError::InvalidLength);
    }

    let value = decode_unsigned_content(&data[consumed..consumed + length]);

    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet signed integer
pub fn encode_signed(buffer: &mut Vec<u8>, value: i32) -> Result<()> {
    let bytes = minimal_signed_bytes(value as i64);
    Tag {
        number: ApplicationTagNumber::SignedInt as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(bytes.len() as u32),
    }
    .encode(buffer)?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Encode a BACnet signed integer from an `i64`
pub fn encode_signed64(buffer: &mut Vec<u8>, value: i64) {
    let bytes = minimal_signed_bytes(value);
    Tag {
        number: ApplicationTagNumber::SignedInt as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(bytes.len() as u32),
    }
    .encode(buffer)
    .expect("signed integer encodings are never longer than 8 octets");
    buffer.extend_from_slice(&bytes);
}

/// Decode a BACnet signed integer
pub fn decode_signed(data: &[u8]) -> Result<(i32, usize)> {
    let (t, mut consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::SignedInt as u32 {
        return Err(EncodingError::InvalidTag);
    }
    let length = t.content_length().unwrap_or(0) as usize;

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    if !(1..=4).contains(&length) {
        return Err(EncodingError::InvalidLength);
    }

    let value = decode_signed_content(&data[consumed..consumed + length]) as i32;

    consumed += length;
    Ok((value, consumed))
}

/// Decode a BACnet signed integer into an i64
pub fn decode_signed64(data: &[u8]) -> Result<(i64, usize)> {
    let (t, mut consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::SignedInt as u32 {
        return Err(EncodingError::InvalidTag);
    }
    let length = t.content_length().unwrap_or(0) as usize;

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    if !(1..=8).contains(&length) {
        return Err(EncodingError::InvalidLength);
    }

    let value = decode_signed_content(&data[consumed..consumed + length]);

    consumed += length;
    Ok((value, consumed))
}

/// Encode a context-specific unsigned integer
pub fn encode_context_unsigned(value: u32, tag_number: u8) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let bytes = minimal_unsigned_bytes(value as u64);
    encode_context_tag(&mut buffer, tag_number, bytes.len())?;
    buffer.extend_from_slice(&bytes);
    Ok(buffer)
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
    if length > 4 {
        return Err(EncodingError::InvalidLength);
    }

    let value = decode_unsigned_content(&data[tag_consumed..tag_consumed + length]) as u32;

    Ok((value, tag_consumed + length))
}

/// Encode a context-specific signed integer
pub fn encode_context_signed(value: i32, tag_number: u8) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let bytes = minimal_signed_bytes(value as i64);
    encode_context_tag(&mut buffer, tag_number, bytes.len())?;
    buffer.extend_from_slice(&bytes);
    Ok(buffer)
}

/// Decode a context-specific signed integer
pub fn decode_context_signed(data: &[u8], expected_tag: u8) -> Result<(i32, usize)> {
    let (tag_number, length, tag_consumed) = decode_context_tag(data)?;

    if tag_number != expected_tag {
        return Err(EncodingError::InvalidTag);
    }
    if data.len() < tag_consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    if !(1..=4).contains(&length) {
        return Err(EncodingError::InvalidLength);
    }

    let value = decode_signed_content(&data[tag_consumed..tag_consumed + length]) as i32;

    Ok((value, tag_consumed + length))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Worked examples from ASHRAE 135-2024, Clause 20.2 ---

    #[test]
    fn spec_application_unsigned_72() {
        let mut buffer = Vec::new();
        encode_unsigned(&mut buffer, 72).unwrap();
        assert_eq!(buffer, [0x21, 0x48]);
        let (value, consumed) = decode_unsigned(&buffer).unwrap();
        assert_eq!(value, 72);
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn spec_application_signed_72() {
        let mut buffer = Vec::new();
        encode_signed(&mut buffer, 72).unwrap();
        assert_eq!(buffer, [0x31, 0x48]);
        let (value, consumed) = decode_signed(&buffer).unwrap();
        assert_eq!(value, 72);
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn spec_context_unsigned_256() {
        // [0] Unsigned, value 256 -> Encoded Tag X'0A', Data X'0100'
        let buffer = encode_context_unsigned(256, 0).unwrap();
        assert_eq!(buffer, [0x0A, 0x01, 0x00]);
        let (value, consumed) = decode_context_unsigned(&buffer, 0).unwrap();
        assert_eq!(value, 256);
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn spec_context_signed_minus_72() {
        // [5] Integer, value -72 -> Encoded Tag X'59', Data X'B8'
        let buffer = encode_context_signed(-72, 5).unwrap();
        assert_eq!(buffer, [0x59, 0xB8]);
        let (value, consumed) = decode_context_signed(&buffer, 5).unwrap();
        assert_eq!(value, -72);
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn spec_context_signed_minus_72_extended_tag_number() {
        // [33] Integer, value -72 -> Encoded Tag X'F9', Tag Number Extension
        // X'21', Data X'B8'
        let buffer = encode_context_signed(-72, 33).unwrap();
        assert_eq!(buffer, [0xF9, 0x21, 0xB8]);
        let (value, consumed) = decode_context_signed(&buffer, 33).unwrap();
        assert_eq!(value, -72);
        assert_eq!(consumed, buffer.len());
    }

    // --- Unsigned byte-width boundaries ---

    #[test]
    fn unsigned_byte_width_boundaries() {
        let cases: &[(u64, usize)] = &[
            (0, 1),
            (255, 1),
            (256, 2),
            (65535, 2),
            (65536, 3),
            (16_777_215, 3),
            (16_777_216, 4),
            (u32::MAX as u64, 4),
            (u32::MAX as u64 + 1, 5),
            (u64::MAX, 8),
        ];
        for &(value, expected_len) in cases {
            let mut buffer = Vec::new();
            encode_unsigned64(&mut buffer, value);
            let (tag, _) = Tag::decode(&buffer).unwrap();
            assert_eq!(
                tag.content_length(),
                Some(expected_len as u32),
                "value {value} expected {expected_len} content octets, got {buffer:?}"
            );
            let (decoded, consumed) = decode_unsigned64(&buffer).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, buffer.len());
        }
    }

    // --- Signed byte-width boundaries ---

    #[test]
    fn signed_byte_width_boundaries() {
        let cases: &[(i64, usize)] = &[
            (0, 1),
            (127, 1),
            (-128, 1),
            (128, 2),
            (-129, 2),
            (32767, 2),
            (-32768, 2),
            (32768, 3),
            (-32769, 3),
            (8_388_607, 3),
            (-8_388_608, 3),
            (8_388_608, 4),
            (-8_388_609, 4),
            (i32::MAX as i64, 4),
            (i32::MIN as i64, 4),
            (i32::MAX as i64 + 1, 5),
            (i32::MIN as i64 - 1, 5),
            (i64::MAX, 8),
            (i64::MIN, 8),
        ];
        for &(value, expected_len) in cases {
            let mut buffer = Vec::new();
            encode_signed64(&mut buffer, value);
            let (tag, _) = Tag::decode(&buffer).unwrap();
            assert_eq!(
                tag.content_length(),
                Some(expected_len as u32),
                "value {value} expected {expected_len} content octets, got {buffer:?}"
            );
            let (decoded, consumed) = decode_signed64(&buffer).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, buffer.len());
        }
    }

    // --- Round trips ---

    #[test]
    fn test_encode_decode_performance() {
        let mut buffer = Vec::new();
        let iterations = 1000;

        for i in 0..iterations {
            buffer.clear();
            encode_unsigned(&mut buffer, i).unwrap();
            let (value, _) = decode_unsigned(&buffer).unwrap();
            assert_eq!(value, i);
        }
    }

    #[test]
    fn test_context_signed_round_trip() {
        for &value in &[
            0i32,
            1,
            -1,
            127,
            -128,
            128,
            -129,
            32767,
            -32768,
            32768,
            -32769,
            i32::MAX,
            i32::MIN,
        ] {
            let buffer = encode_context_signed(value, 7).unwrap();
            let (decoded, consumed) = decode_context_signed(&buffer, 7).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, buffer.len());
        }
    }

    #[test]
    fn test_encode_decode_i64() {
        let mut buffer = Vec::new();
        let test_values = [
            0,
            1,
            -1,
            -330,
            i32::MAX as i64,
            i32::MIN as i64,
            i32::MAX as i64 + 10,
            i32::MIN as i64 - 10,
            i64::MAX,
            i64::MIN,
            i64::MAX as i32 as i64,
            i64::MIN as i32 as i64,
        ];

        for &test_value in &test_values {
            buffer.clear();
            encode_signed64(&mut buffer, test_value);
            let (value, _) = decode_signed64(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_u64() {
        let mut buffer = Vec::new();
        let test_values = [
            0,
            1,
            255,
            330,
            u32::MAX as u64,
            u32::MIN as u64,
            u32::MAX as u64 + 10,
            u64::MAX,
            u64::MIN,
            u64::MAX as u32 as u64,
            u64::MIN as u32 as u64,
        ];

        for &test_value in &test_values {
            buffer.clear();
            encode_unsigned64(&mut buffer, test_value);
            let (value, _) = decode_unsigned64(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn context_unsigned_zero_length_decodes_as_zero() {
        // Preserves a pre-existing leniency: an absent-content context tag
        // decodes as 0 rather than erroring, unlike application-tagged
        // unsigned (which requires >=1 content octet per spec).
        let data = [0x08]; // context tag 0, length 0
        let (value, consumed) = decode_context_unsigned(&data, 0).unwrap();
        assert_eq!(value, 0);
        assert_eq!(consumed, 1);
    }
}
