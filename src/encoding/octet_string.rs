//! BACnet Octet String encoding and decoding.
//!
//! This module implements ASHRAE 135-2024, Clause 20.2's "Encoding of an
//! Octet String Value": the encoding is primitive, and its contents octets
//! are simply the raw octets of the value, in order, with no minimal-length
//! or byte-order transformation of any kind (unlike Unsigned/Signed
//! Integer's minimal-encoding rule or Real/Double's IEEE 754 layout). All of
//! the actual complexity lives in the general tag-length framing rules
//! (Clause 20.2.1, implemented by [`super::tag::Tag`]), which is why
//! encoding/decoding here is a direct pass-through of the byte slice.
//!
//! Worked example (Clause 20.2): value `X'1234FF'` encodes as
//! Application Tag = Octet String (tag number 6), Encoded Tag = `X'63'`,
//! Encoded Data = `X'1234FF'`.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{
    tag::{ApplicationTagNumber, Tag, TagClass, TagValue},
    EncodingError, Result,
};

/// Encode a BACnet octet string.
pub fn encode_octet_string(buffer: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    Tag {
        number: ApplicationTagNumber::OctetString as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(value.len() as u32),
    }
    .encode(buffer)?;
    buffer.extend_from_slice(value);
    Ok(())
}

/// Decode a BACnet octet string.
pub fn decode_octet_string(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let (t, mut consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::OctetString as u32 {
        return Err(EncodingError::InvalidTag);
    }
    let length = t.content_length().unwrap_or(0) as usize;

    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let value = data[consumed..consumed + length].to_vec();
    consumed += length;

    Ok((value, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "std"))]
    use alloc::vec;

    // --- Worked example from ASHRAE 135-2024, Clause 20.2 ---

    #[test]
    fn spec_application_octet_string() {
        let mut buffer = Vec::new();
        encode_octet_string(&mut buffer, &[0x12, 0x34, 0xFF]).unwrap();
        assert_eq!(buffer, [0x63, 0x12, 0x34, 0xFF]);
        let (value, consumed) = decode_octet_string(&buffer).unwrap();
        assert_eq!(value, [0x12, 0x34, 0xFF]);
        assert_eq!(consumed, buffer.len());
    }

    // --- Edge cases ---

    #[test]
    fn empty_octet_string_round_trips() {
        let mut buffer = Vec::new();
        encode_octet_string(&mut buffer, &[]).unwrap();
        assert_eq!(buffer, [0x60]);
        let (value, consumed) = decode_octet_string(&buffer).unwrap();
        assert!(value.is_empty());
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn length_extension_boundaries_round_trip() {
        // 4 vs 5 octets: the point at which the length field switches from a
        // direct 0-4 value to the "5" marker plus one extra length octet.
        for len in [4usize, 5, 53, 253, 254, 65535, 65536] {
            let data = vec![0xAA; len];
            let mut buffer = Vec::new();
            encode_octet_string(&mut buffer, &data).unwrap();
            let (value, consumed) = decode_octet_string(&buffer).unwrap();
            assert_eq!(value, data, "length {len}");
            assert_eq!(consumed, buffer.len(), "length {len}");
        }
    }

    // --- Rejections ---

    #[test]
    fn rejects_wrong_tag_class() {
        // Context tag 0, length 3 (i.e. [0] octet-string-shaped, not
        // application-tagged).
        let data = [0x03, 0x12, 0x34, 0xFF];
        assert!(decode_octet_string(&data).is_err());
    }

    #[test]
    fn rejects_wrong_application_tag_number() {
        // Application tag 5 (Double), not 6 (Octet String).
        let data = [0x54, 0x12, 0x34, 0xFF, 0x00];
        assert!(decode_octet_string(&data).is_err());
    }

    #[test]
    fn rejects_short_buffer() {
        // Tag claims 3 content octets, but only 2 are present.
        let data = [0x63, 0x12, 0x34];
        assert!(decode_octet_string(&data).is_err());
    }

    // --- Pre-existing coverage, moved unchanged ---

    #[test]
    fn test_encode_decode_octet_string() {
        let mut buffer = Vec::new();
        let test_data = vec![0x01, 0x02, 0x03, 0xFF, 0x00];

        encode_octet_string(&mut buffer, &test_data).unwrap();
        let (decoded, _) = decode_octet_string(&buffer).unwrap();
        assert_eq!(decoded, test_data);
    }
}
