//! BACnet Object Identifier encoding and decoding.
//!
//! This module implements ASHRAE 135-2024, Clause 20.2's "Encoding of an
//! Object Identifier Value": the encoding is primitive, with exactly four
//! contents octets holding a 10-bit object type (bits 31-22 of the packed
//! 32-bit value) followed by a 22-bit instance number (bits 21-0), conveyed
//! most significant octet first — no minimal-length rule applies, unlike
//! Unsigned/Signed Integer.
//!
//! The bit-packing itself (10-bit type + 22-bit instance <-> `u32`) is
//! implemented once in [`crate::object::ObjectIdentifier`]'s
//! `TryFrom<ObjectIdentifier> for u32` and `From<u32> for ObjectIdentifier`
//! impls; this module only adds the tag framing (application-tagged or
//! context-tagged) around that packed `u32`.
//!
//! Worked example (Clause 20.2): value `(Binary Input, 15)` encodes as
//! Application Tag = Object Identifier (tag number 12), Encoded Tag =
//! `X'C4'`, Encoded Data = `X'00C0000F'`.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{
    decode_context_tag, encode_context_tag,
    tag::{ApplicationTagNumber, Tag, TagClass, TagValue},
    EncodingError, Result,
};
use crate::object::ObjectIdentifier;

/// Packs an object identifier into its four big-endian contents octets.
fn pack(object_id: ObjectIdentifier) -> Result<[u8; 4]> {
    let value: u32 = object_id.try_into()?;
    Ok(value.to_be_bytes())
}

/// Unpacks four big-endian contents octets into an object identifier.
fn unpack(bytes: [u8; 4]) -> ObjectIdentifier {
    u32::from_be_bytes(bytes).into()
}

/// Encode a BACnet object identifier.
pub fn encode_object_identifier(buffer: &mut Vec<u8>, object_id: ObjectIdentifier) -> Result<()> {
    let bytes = pack(object_id)?;
    Tag {
        number: ApplicationTagNumber::ObjectIdentifier as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(4),
    }
    .encode(buffer)?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Decode a BACnet object identifier.
pub fn decode_object_identifier(data: &[u8]) -> Result<(ObjectIdentifier, usize)> {
    let (t, consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::ObjectIdentifier as u32
    {
        return Err(EncodingError::InvalidTag);
    }
    if t.content_length() != Some(4) || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }

    let bytes = [
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
    ];
    Ok((unpack(bytes), consumed + 4))
}

/// Encode a context-specific object identifier.
pub fn encode_context_object_id(object_id: ObjectIdentifier, tag_number: u8) -> Result<Vec<u8>> {
    let bytes = pack(object_id)?;
    let mut buffer = Vec::new();
    encode_context_tag(&mut buffer, tag_number, 4)?;
    buffer.extend_from_slice(&bytes);
    Ok(buffer)
}

/// Decode a context-specific object identifier.
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

    let bytes = [
        data[tag_consumed],
        data[tag_consumed + 1],
        data[tag_consumed + 2],
        data[tag_consumed + 3],
    ];
    Ok((unpack(bytes), tag_consumed + 4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    // --- Worked example from ASHRAE 135-2024, Clause 20.2 ---

    #[test]
    fn spec_application_object_identifier() {
        let mut buffer = Vec::new();
        let object_id = ObjectIdentifier::new(ObjectType::BinaryInput, 15);
        encode_object_identifier(&mut buffer, object_id).unwrap();
        assert_eq!(buffer, [0xC4, 0x00, 0xC0, 0x00, 0x0F]);
        let (decoded, consumed) = decode_object_identifier(&buffer).unwrap();
        assert_eq!(decoded, object_id);
        assert_eq!(consumed, buffer.len());
    }

    // --- Boundary values ---

    #[test]
    fn instance_boundaries_round_trip() {
        for instance in [0u32, 1, 0x3FFFFE, 0x3FFFFF] {
            let mut buffer = Vec::new();
            let object_id = ObjectIdentifier::new(ObjectType::AnalogValue, instance);
            encode_object_identifier(&mut buffer, object_id).unwrap();
            let (decoded, consumed) = decode_object_identifier(&buffer).unwrap();
            assert_eq!(decoded, object_id, "instance {instance}");
            assert_eq!(consumed, buffer.len());
        }
    }

    #[test]
    fn rejects_instance_out_of_range() {
        let object_id = ObjectIdentifier::new(ObjectType::AnalogValue, 0x400000);
        let mut buffer = Vec::new();
        assert!(encode_object_identifier(&mut buffer, object_id).is_err());
    }

    // --- Context-tagged round trip ---

    #[test]
    fn context_tagged_round_trips() {
        let object_id = ObjectIdentifier::new(ObjectType::Device, 4194302);
        let buffer = encode_context_object_id(object_id, 3).unwrap();
        let (decoded, consumed) = decode_context_object_id(&buffer, 3).unwrap();
        assert_eq!(decoded, object_id);
        assert_eq!(consumed, buffer.len());
    }

    // --- Rejections ---

    #[test]
    fn rejects_wrong_tag_class() {
        // Context tag 0, length 4 (i.e. [0] object-id-shaped, not
        // application-tagged).
        let data = [0x04, 0x00, 0xC0, 0x00, 0x0F];
        assert!(decode_object_identifier(&data).is_err());
    }

    #[test]
    fn rejects_wrong_application_tag_number() {
        // Application tag 11 (Time), not 12 (Object Identifier).
        let data = [0xB4, 0x00, 0xC0, 0x00, 0x0F];
        assert!(decode_object_identifier(&data).is_err());
    }

    #[test]
    fn rejects_short_content() {
        let data = [0xC3, 0x00, 0xC0, 0x00];
        assert!(decode_object_identifier(&data).is_err());
    }

    #[test]
    fn context_decode_rejects_wrong_expected_tag() {
        let object_id = ObjectIdentifier::new(ObjectType::Device, 42);
        let buffer = encode_context_object_id(object_id, 0).unwrap();
        assert!(decode_context_object_id(&buffer, 1).is_err());
    }

    // --- Pre-existing coverage, moved unchanged ---

    #[test]
    fn test_encode_decode_object_identifier() {
        let mut buffer = Vec::new();

        let object_id = ObjectIdentifier::new(ObjectType::AnalogValue, 12345);
        encode_object_identifier(&mut buffer, object_id).unwrap(); // Analog Value 12345
        let (object_id, _) = decode_object_identifier(&buffer).unwrap();
        assert_eq!(object_id.object_type, ObjectType::AnalogValue);
        assert_eq!(object_id.instance, 12345);
    }
}
