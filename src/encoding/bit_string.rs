//! BACnet Bit String encoding and decoding.
//!
//! This module implements ASHRAE 135-2024, Clause 20.2's "Encoding of a Bit
//! String Value": the encoding is primitive, with an initial contents octet
//! giving the number of unused bits (0-7) in the final subsequent octet,
//! followed by zero or more subsequent octets holding the bits themselves.
//! Bits are packed most-significant-bit first within each octet (bit 7 of
//! the first subsequent octet is the first bit of the string, and so on),
//! with any unused bits in the final octet left zero. An empty bit string
//! has no subsequent octets and an initial octet of zero.
//!
//! Worked example (Clause 20.2): value `B'10101'` encodes as Application
//! Tag = Bit String (tag number 8), Encoded Tag = `X'82'`, Encoded Data =
//! `X'03A8'` (3 unused bits, then `10101000`).

#[cfg(not(feature = "std"))]
use alloc::{string::ToString, vec::Vec};

use super::{
    tag::{ApplicationTagNumber, Tag, TagClass, TagValue},
    EncodingError, Result,
};

/// Encode a BACnet bit string.
#[allow(clippy::manual_is_multiple_of)]
pub fn encode_bit_string(buffer: &mut Vec<u8>, bits: &[bool]) -> Result<()> {
    let byte_count = bits.len().div_ceil(8);
    let unused_bits = if bits.len() % 8 == 0 {
        0
    } else {
        8 - (bits.len() % 8)
    };

    Tag {
        number: ApplicationTagNumber::BitString as u32,
        class: TagClass::Application,
        value: TagValue::Primitive((byte_count + 1) as u32),
    }
    .encode(buffer)?;
    buffer.push(unused_bits as u8);

    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (bit_pos, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - bit_pos);
            }
        }
        buffer.push(byte);
    }

    Ok(())
}

/// Decode a BACnet bit string.
pub fn decode_bit_string(data: &[u8]) -> Result<(Vec<bool>, usize)> {
    let (t, mut consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::BitString as u32 {
        return Err(EncodingError::InvalidTag);
    }
    let length = t.content_length().unwrap_or(0) as usize;

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

    let byte_count = length - 1;
    let mut bits = Vec::with_capacity(byte_count * 8);

    for (i, &byte_val) in data[consumed..consumed + byte_count].iter().enumerate() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "std"))]
    use alloc::vec;

    // --- Worked example from ASHRAE 135-2024, Clause 20.2 ---

    #[test]
    fn spec_application_bit_string() {
        let mut buffer = Vec::new();
        let bits = [true, false, true, false, true];
        encode_bit_string(&mut buffer, &bits).unwrap();
        assert_eq!(buffer, [0x82, 0x03, 0xA8]);
        let (decoded, consumed) = decode_bit_string(&buffer).unwrap();
        assert_eq!(decoded, bits);
        assert_eq!(consumed, buffer.len());
    }

    // --- Edge cases ---

    #[test]
    fn empty_bit_string_round_trips() {
        let mut buffer = Vec::new();
        encode_bit_string(&mut buffer, &[]).unwrap();
        assert_eq!(buffer, [0x81, 0x00]);
        let (decoded, consumed) = decode_bit_string(&buffer).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn byte_boundary_round_trips() {
        // Exactly 8 bits: zero unused bits, exactly one subsequent octet.
        let bits = [true, false, true, true, false, false, true, false];
        let mut buffer = Vec::new();
        encode_bit_string(&mut buffer, &bits).unwrap();
        assert_eq!(buffer[1], 0); // unused bits
        let (decoded, consumed) = decode_bit_string(&buffer).unwrap();
        assert_eq!(decoded, bits);
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn many_bit_lengths_round_trip() {
        for len in 0..=32usize {
            let bits: Vec<bool> = (0..len).map(|i| i % 3 == 0).collect();
            let mut buffer = Vec::new();
            encode_bit_string(&mut buffer, &bits).unwrap();
            let (decoded, consumed) = decode_bit_string(&buffer).unwrap();
            assert_eq!(decoded, bits, "length {len}");
            assert_eq!(consumed, buffer.len(), "length {len}");
        }
    }

    // --- Rejections ---

    #[test]
    fn rejects_wrong_tag_class() {
        // Context tag 0, length 2 (i.e. [0] bit-string-shaped, not
        // application-tagged).
        let data = [0x02, 0x03, 0xA8];
        assert!(decode_bit_string(&data).is_err());
    }

    #[test]
    fn rejects_wrong_application_tag_number() {
        // Application tag 6 (Octet String), not 8 (Bit String).
        let data = [0x62, 0x03, 0xA8];
        assert!(decode_bit_string(&data).is_err());
    }

    #[test]
    fn rejects_zero_length_content() {
        // A bit string must have at least the initial (unused-bits) octet.
        let data = [0x80];
        assert!(decode_bit_string(&data).is_err());
    }

    #[test]
    fn rejects_unused_bits_out_of_range() {
        // Unused bits count of 8 is invalid; must be 0-7.
        let data = [0x82, 0x08, 0xA8];
        assert!(decode_bit_string(&data).is_err());
    }

    #[test]
    fn rejects_short_buffer() {
        // Tag claims 2 content octets, but only 1 is present.
        let data = [0x82, 0x03];
        assert!(decode_bit_string(&data).is_err());
    }

    // --- Pre-existing coverage, moved unchanged ---

    #[test]
    fn test_encode_decode_bit_string() {
        let mut buffer = Vec::new();
        let bits = vec![true, false, true, true, false];

        encode_bit_string(&mut buffer, &bits).unwrap();
        let (decoded_bits, _) = decode_bit_string(&buffer).unwrap();

        assert_eq!(decoded_bits, bits);
    }
}
