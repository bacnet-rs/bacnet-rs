//! BACnet Real and Double encoding and decoding.
//!
//! This module implements ASHRAE 135-2024, Clause 20.2's "Encoding of a
//! Real Number Value" and "Encoding of a Double Precision Real Number
//! Value": both are primitive, fixed-width (4 and 8 contents octets
//! respectively), raw IEEE 754 binary32/binary64 values conveyed most
//! significant octet first. Unlike integers, there is no "minimal length"
//! rule to apply — the width is always exactly 4 or 8 octets — so both
//! encodings reduce to the same "application-tagged, fixed-width, raw
//! bytes" framing, differing only in width and float type. This module
//! implements that framing once; `encode_real`/`decode_real` and
//! `encode_double`/`decode_double` are thin wrappers over it.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{
    tag::{ApplicationTagNumber, Tag, TagClass, TagValue},
    EncodingError, Result,
};

/// Encodes an application-tagged, fixed-width primitive: the given tag
/// number with a primitive content length of `bytes.len()`, followed by
/// `bytes` verbatim.
fn encode_fixed(
    buffer: &mut Vec<u8>,
    tag_number: ApplicationTagNumber,
    bytes: &[u8],
) -> Result<()> {
    Tag {
        number: tag_number as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(bytes.len() as u32),
    }
    .encode(buffer)?;
    buffer.extend_from_slice(bytes);
    Ok(())
}

/// Decodes an application-tagged, fixed-width primitive: validates the tag
/// class, tag number, and that its content length is exactly
/// `expected_len`, then returns the content slice and the number of octets
/// the tag itself occupied (not including the content).
fn decode_fixed(
    data: &[u8],
    tag_number: ApplicationTagNumber,
    expected_len: usize,
) -> Result<(&[u8], usize)> {
    let (t, consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != tag_number as u32 {
        return Err(EncodingError::InvalidTag);
    }
    if t.content_length() != Some(expected_len as u32) {
        return Err(EncodingError::InvalidLength);
    }
    if data.len() < consumed + expected_len {
        return Err(EncodingError::BufferUnderflow);
    }

    Ok((&data[consumed..consumed + expected_len], consumed))
}

/// Encode a BACnet real (32-bit float) value
pub fn encode_real(buffer: &mut Vec<u8>, value: f32) -> Result<()> {
    encode_fixed(buffer, ApplicationTagNumber::Real, &value.to_be_bytes())
}

/// Decode a BACnet real (32-bit float) value
pub fn decode_real(data: &[u8]) -> Result<(f32, usize)> {
    let (content, consumed) = decode_fixed(data, ApplicationTagNumber::Real, 4)?;
    let value = f32::from_be_bytes(content.try_into().unwrap());
    Ok((value, consumed + 4))
}

/// Encode a BACnet double (64-bit float) value
pub fn encode_double(buffer: &mut Vec<u8>, value: f64) -> Result<()> {
    encode_fixed(buffer, ApplicationTagNumber::Double, &value.to_be_bytes())
}

/// Decode a BACnet double (64-bit float) value
pub fn decode_double(data: &[u8]) -> Result<(f64, usize)> {
    let (content, consumed) = decode_fixed(data, ApplicationTagNumber::Double, 8)?;
    let value = f64::from_be_bytes(content.try_into().unwrap());
    Ok((value, consumed + 8))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Worked examples from ASHRAE 135-2024, Clause 20.2 ---

    #[test]
    fn spec_application_real_72() {
        let mut buffer = Vec::new();
        encode_real(&mut buffer, 72.0).unwrap();
        assert_eq!(buffer, [0x44, 0x42, 0x90, 0x00, 0x00]);
        let (value, consumed) = decode_real(&buffer).unwrap();
        assert_eq!(value, 72.0);
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn spec_application_double_72() {
        let mut buffer = Vec::new();
        encode_double(&mut buffer, 72.0).unwrap();
        assert_eq!(
            buffer,
            [0x55, 0x08, 0x40, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        let (value, consumed) = decode_double(&buffer).unwrap();
        assert_eq!(value, 72.0);
        assert_eq!(consumed, buffer.len());
    }

    // --- Special values ---

    #[test]
    fn real_special_values_round_trip() {
        for value in [
            0.0f32,
            -0.0,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::MIN,
            f32::MAX,
            f32::MIN_POSITIVE,
            -1.0,
            core::f32::consts::PI,
        ] {
            let mut buffer = Vec::new();
            encode_real(&mut buffer, value).unwrap();
            let (decoded, consumed) = decode_real(&buffer).unwrap();
            assert_eq!(decoded.to_bits(), value.to_bits(), "value {value}");
            assert_eq!(consumed, buffer.len());
        }
    }

    #[test]
    fn real_nan_round_trips_as_nan() {
        let mut buffer = Vec::new();
        encode_real(&mut buffer, f32::NAN).unwrap();
        let (decoded, _) = decode_real(&buffer).unwrap();
        assert!(decoded.is_nan());
    }

    #[test]
    fn double_special_values_round_trip() {
        for value in [
            0.0f64,
            -0.0,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MIN,
            f64::MAX,
            f64::MIN_POSITIVE,
            -1.0,
            core::f64::consts::PI,
        ] {
            let mut buffer = Vec::new();
            encode_double(&mut buffer, value).unwrap();
            let (decoded, consumed) = decode_double(&buffer).unwrap();
            assert_eq!(decoded.to_bits(), value.to_bits(), "value {value}");
            assert_eq!(consumed, buffer.len());
        }
    }

    #[test]
    fn double_nan_round_trips_as_nan() {
        let mut buffer = Vec::new();
        encode_double(&mut buffer, f64::NAN).unwrap();
        let (decoded, _) = decode_double(&buffer).unwrap();
        assert!(decoded.is_nan());
    }

    // --- Rejections ---

    #[test]
    fn rejects_wrong_tag_class_for_real() {
        // Context tag 4, length 4 (i.e. [4] Real-shaped, not application-tagged)
        let data = [0x4C, 0x42, 0x90, 0x00, 0x00];
        assert!(decode_real(&data).is_err());
    }

    #[test]
    fn rejects_wrong_application_tag_number_for_real() {
        // Application tag 5 (Double), not 4 (Real)
        let data = [0x54, 0x42, 0x90, 0x00, 0x00];
        assert!(decode_real(&data).is_err());
    }

    #[test]
    fn rejects_short_content_for_real() {
        // Application tag 4 (Real) but only 3 content octets
        let data = [0x43, 0x42, 0x90, 0x00];
        assert!(decode_real(&data).is_err());
    }

    #[test]
    fn rejects_wrong_content_length_for_double() {
        // Application tag 5 (Double) but only 4 content octets, not 8
        let data = [0x54, 0x42, 0x90, 0x00, 0x00];
        assert!(decode_double(&data).is_err());
    }

    // --- Pre-existing coverage, moved unchanged ---

    #[test]
    fn test_encode_decode_real() {
        let mut buffer = Vec::new();
        let test_values = [
            0.0,
            1.0,
            -1.0,
            core::f32::consts::PI,
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
    fn test_encode_decode_double() {
        let mut buffer = Vec::new();
        let test_values = [
            0.0,
            1.0,
            -1.0,
            core::f64::consts::PI,
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
}
