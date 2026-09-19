//! BACnet tag encoding and decoding.
//!
//! This module implements the general tag-framing rules of ASHRAE 135-2024,
//! Clause 20.2.1 ("General Rules For Encoding BACnet Tags"). A BACnet tag is
//! the initial octet (plus zero or more conditional extension octets) that
//! precedes every data element in the variable part of a BACnet APDU. It
//! identifies:
//!
//! - the tag **number** (0-254; a datatype for application-class tags, or an
//!   arbitrary context-specific index for context-class tags),
//! - the **class** (application or context-specific), and
//! - whether the following data is **primitive** (with a known length in
//!   octets) or **constructed** (delimited by a matching opening/closing tag
//!   pair).
//!
//! This module deliberately covers only the tag *framing* rules of Clause
//! 20.2.1. The per-datatype content encodings (Real, Date, ObjectIdentifier,
//! etc. — Clauses 20.2.2 through 20.2.14) live alongside the rest of the
//! encoding utilities in [`crate::encoding`].
//!
//! # Layout of the initial octet
//!
//! ```text
//! Bit Number:  7      6    5     4     3     2     1     0
//!            |-----|-----|-----|-----|-----|-----|-----|-----|
//!            |       Tag Number      |Class|Length/Value/Type|
//!            |-----|-----|-----|-----|-----|-----|-----|-----|
//! ```
//!
//! - **Tag Number** (bits 7-4): 0-14 encoded directly; 15-254 encoded as
//!   `1111` followed by one extension octet holding the actual number
//!   (Clause 20.2.1.2). The extension octet value `255` is reserved by
//!   ASHRAE and is never valid.
//! - **Class** (bit 3): `0` = application, `1` = context-specific (Clause
//!   20.2.1.1).
//! - **Length/Value/Type** (bits 2-0, Clause 20.2.1.3): `0`-`4` is the
//!   content length in octets, directly encoded; `5` (`101`) means the
//!   length is encoded in one or more following octets (5-253 in one octet;
//!   254-65535 as marker `254` plus a 16-bit length; 65536-2^32-1 as marker
//!   `255` plus a 32-bit length); `6` (`110`) marks an **opening** tag of
//!   constructed data; `7` (`111`) marks the matching **closing** tag.
//!
//! Note that an application-class Boolean tag is a special case (Clause
//! 20.2.1.3, "Encoding of a Boolean Value"): the value itself (0 = FALSE, 1 =
//! TRUE) is carried directly in the Length/Value/Type field, with no content
//! octets at all. A context-specific Boolean, by contrast, is an ordinary
//! primitive tag with a content length of 1 octet holding the value. Both
//! cases fall out naturally from [`TagValue::Primitive`] without any special
//! casing in this module — it is purely the numeric coincidence that a
//! length of 0 or 1 and a boolean value of 0 or 1 share a representation.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{EncodingError, Result};

/// The class of a BACnet tag (ASHRAE 135-2024, Clause 20.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    /// Identifies a fundamental BACnet datatype (Boolean, Real, Date, ...).
    Application,
    /// Identifies a data element whose datatype is inferred from context.
    Context,
}

/// The application datatypes identified by an application-class tag number
/// (ASHRAE 135-2024, Clause 20.2.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApplicationTagNumber {
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

impl TryFrom<u32> for ApplicationTagNumber {
    type Error = EncodingError;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Null),
            1 => Ok(Self::Boolean),
            2 => Ok(Self::UnsignedInt),
            3 => Ok(Self::SignedInt),
            4 => Ok(Self::Real),
            5 => Ok(Self::Double),
            6 => Ok(Self::OctetString),
            7 => Ok(Self::CharacterString),
            8 => Ok(Self::BitString),
            9 => Ok(Self::Enumerated),
            10 => Ok(Self::Date),
            11 => Ok(Self::Time),
            12 => Ok(Self::ObjectIdentifier),
            13 => Ok(Self::Reserved13),
            14 => Ok(Self::Reserved14),
            15 => Ok(Self::Reserved15),
            _ => Err(EncodingError::InvalidTag),
        }
    }
}

impl From<ApplicationTagNumber> for u32 {
    fn from(value: ApplicationTagNumber) -> Self {
        value as u32
    }
}

/// The Length/Value/Type interpretation of a decoded tag (Clause 20.2.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagValue {
    /// Primitive data follows, `length` octets long.
    ///
    /// For an application-class [`ApplicationTagNumber::Boolean`] tag, this
    /// is the boolean value itself (0 = FALSE, 1 = TRUE) rather than a
    /// length, per the spec's Boolean special case; no content octets
    /// follow such a tag.
    Primitive(u32),
    /// Opening tag of a constructed (tagged) encoding.
    Opening,
    /// Closing tag of a constructed (tagged) encoding.
    Closing,
}

/// A decoded (or to-be-encoded) BACnet tag.
///
/// This represents only the tag itself — the initial octet and any
/// extension octets — not the content octets that follow a primitive tag or
/// the nested tagged elements between an opening and closing tag pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// The tag number, 0-254 (Clause 20.2.1.2).
    pub number: u32,
    /// The tag's class.
    pub class: TagClass,
    /// The tag's Length/Value/Type interpretation.
    pub value: TagValue,
}

/// The largest tag number the encoding allows (Clause 20.2.1.2: "The
/// encoding does not allow, nor does BACnet require, tag numbers larger
/// than 254").
const MAX_TAG_NUMBER: u32 = 254;

/// The extension-octet value reserved by ASHRAE and never a valid tag number.
const RESERVED_TAG_NUMBER_EXTENSION: u8 = 0xFF;

impl Tag {
    /// Creates a primitive tag with the given class, number, and content
    /// length in octets.
    pub fn primitive(class: TagClass, number: u32, length: u32) -> Result<Self> {
        Self::new(class, number, TagValue::Primitive(length))
    }

    /// Creates the opening tag of a constructed encoding.
    ///
    /// Per Clause 20.2.1.3(a), an opening tag's Class field always indicates
    /// context-specific.
    pub fn opening(number: u32) -> Result<Self> {
        Self::new(TagClass::Context, number, TagValue::Opening)
    }

    /// Creates the closing tag of a constructed encoding.
    ///
    /// Per Clause 20.2.1.3(c), a closing tag's Class field always indicates
    /// context-specific, matching its opening tag.
    pub fn closing(number: u32) -> Result<Self> {
        Self::new(TagClass::Context, number, TagValue::Closing)
    }

    fn new(class: TagClass, number: u32, value: TagValue) -> Result<Self> {
        if number > MAX_TAG_NUMBER {
            return Err(EncodingError::ValueOutOfRange);
        }
        Ok(Tag {
            number,
            class,
            value,
        })
    }

    /// True if this is the opening tag of a constructed encoding.
    pub fn is_opening(&self) -> bool {
        matches!(self.value, TagValue::Opening)
    }

    /// True if this is the closing tag of a constructed encoding.
    pub fn is_closing(&self) -> bool {
        matches!(self.value, TagValue::Closing)
    }

    /// True if this tag delimits primitive data.
    pub fn is_primitive(&self) -> bool {
        matches!(self.value, TagValue::Primitive(_))
    }

    /// The content length in octets, if this is a primitive tag.
    ///
    /// For an application-class Boolean tag this returns the encoded value
    /// (0 or 1), not a content length — see [`TagValue::Primitive`].
    pub fn content_length(&self) -> Option<u32> {
        match self.value {
            TagValue::Primitive(length) => Some(length),
            _ => None,
        }
    }

    /// Encodes this tag (initial octet plus any extension octets) onto the
    /// end of `buffer`.
    pub fn encode(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if self.number > MAX_TAG_NUMBER {
            return Err(EncodingError::ValueOutOfRange);
        }

        let class_bit: u8 = match self.class {
            TagClass::Application => 0x00,
            TagClass::Context => 0x08,
        };

        let extended_number = self.number > 14;
        let number_nibble: u8 = if extended_number { 0x0F } else { self.number as u8 };

        let lvt: u8 = match self.value {
            TagValue::Opening => 0b110,
            TagValue::Closing => 0b111,
            TagValue::Primitive(length) if length <= 4 => length as u8,
            TagValue::Primitive(_) => 0b101,
        };

        buffer.push((number_nibble << 4) | class_bit | lvt);

        if extended_number {
            buffer.push(self.number as u8);
        }

        if let TagValue::Primitive(length) = self.value {
            if length > 4 {
                match length {
                    5..=253 => buffer.push(length as u8),
                    254..=65535 => {
                        buffer.push(254);
                        buffer.extend_from_slice(&(length as u16).to_be_bytes());
                    }
                    _ => {
                        buffer.push(255);
                        buffer.extend_from_slice(&length.to_be_bytes());
                    }
                }
            }
        }

        Ok(())
    }

    /// Decodes a tag from the start of `data`, returning the tag and the
    /// number of octets consumed (the tag itself only — not any content
    /// octets that follow a primitive tag).
    pub fn decode(data: &[u8]) -> Result<(Tag, usize)> {
        let initial = *data.first().ok_or(EncodingError::InvalidTag)?;
        let mut consumed = 1;

        let class = if initial & 0x08 != 0 {
            TagClass::Context
        } else {
            TagClass::Application
        };

        let mut number = (initial >> 4) as u32;
        if number == 0x0F {
            let ext = *data.get(consumed).ok_or(EncodingError::BufferUnderflow)?;
            if ext == RESERVED_TAG_NUMBER_EXTENSION {
                return Err(EncodingError::InvalidTag);
            }
            number = ext as u32;
            consumed += 1;
        }

        let lvt = initial & 0x07;
        let value = match lvt {
            6 => TagValue::Opening,
            7 => TagValue::Closing,
            5 => {
                let len_byte = *data.get(consumed).ok_or(EncodingError::BufferUnderflow)?;
                consumed += 1;
                let length = match len_byte {
                    0..=253 => len_byte as u32,
                    254 => {
                        let bytes = data
                            .get(consumed..consumed + 2)
                            .ok_or(EncodingError::BufferUnderflow)?;
                        consumed += 2;
                        u16::from_be_bytes([bytes[0], bytes[1]]) as u32
                    }
                    255 => {
                        let bytes = data
                            .get(consumed..consumed + 4)
                            .ok_or(EncodingError::BufferUnderflow)?;
                        consumed += 4;
                        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                    }
                };
                TagValue::Primitive(length)
            }
            n => TagValue::Primitive(n as u32),
        };

        Ok((
            Tag {
                number,
                class,
                value,
            },
            consumed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn primitive(class: TagClass, number: u32, length: u32) -> Tag {
        Tag::primitive(class, number, length).unwrap()
    }

    fn assert_round_trip(tag: Tag, expected: &[u8]) {
        let mut buffer = Vec::new();
        tag.encode(&mut buffer).unwrap();
        assert_eq!(buffer, expected, "encoding mismatch for {:?}", tag);

        let (decoded, consumed) = Tag::decode(&buffer).unwrap();
        assert_eq!(consumed, buffer.len());
        assert_eq!(decoded, tag);
    }

    // --- Application-class tags (Clause 20.2.1.4 / 20.2.1.6 worked examples) ---

    #[test]
    fn spec_application_null() {
        // "Example: Application-tagged null value" -> X'00'
        assert_round_trip(primitive(TagClass::Application, 0, 0), &[0x00]);
    }

    #[test]
    fn spec_application_boolean_false() {
        // "Example: Application-tagged Boolean value", FALSE -> X'10'
        assert_round_trip(primitive(TagClass::Application, 1, 0), &[0x10]);
    }

    #[test]
    fn spec_application_boolean_true() {
        // Boolean TRUE per the B'001' rule in 20.2.1.3 -> X'11'
        assert_round_trip(primitive(TagClass::Application, 1, 1), &[0x11]);
    }

    #[test]
    fn spec_application_unsigned() {
        // "Example: Application-tagged unsigned integer", value 72 (1 octet) -> X'21'
        assert_round_trip(primitive(TagClass::Application, 2, 1), &[0x21]);
    }

    #[test]
    fn spec_application_signed() {
        // "Example: Application-tagged signed integer", value 72 (1 octet) -> X'31'
        assert_round_trip(primitive(TagClass::Application, 3, 1), &[0x31]);
    }

    #[test]
    fn spec_application_real() {
        // "Example: Application-tagged single precision real" -> X'44'
        assert_round_trip(primitive(TagClass::Application, 4, 4), &[0x44]);
    }

    #[test]
    fn spec_application_double() {
        // "Example: Application-tagged double precision real" -> X'55' + Extended Length X'08'
        assert_round_trip(primitive(TagClass::Application, 5, 8), &[0x55, 0x08]);
    }

    #[test]
    fn spec_application_octet_string() {
        // "Example: Application-tagged octet string", X'1234FF' (3 octets) -> X'63'
        assert_round_trip(primitive(TagClass::Application, 6, 3), &[0x63]);
    }

    #[test]
    fn spec_application_character_string() {
        // "Example: Application-tagged character string": 1 charset octet + 24
        // character octets = 25 -> X'75' + Length Extension X'19'
        assert_round_trip(primitive(TagClass::Application, 7, 25), &[0x75, 0x19]);
    }

    #[test]
    fn spec_application_bit_string() {
        // "Example: Application-tagged bit string", B'10101' -> X'82' (2 content octets)
        assert_round_trip(primitive(TagClass::Application, 8, 2), &[0x82]);
    }

    #[test]
    fn spec_application_enumerated() {
        // "Example: Application-tagged enumeration" -> X'91'
        assert_round_trip(primitive(TagClass::Application, 9, 1), &[0x91]);
    }

    #[test]
    fn spec_application_date() {
        // "Example: Application-tagged specific date value" -> X'A4'
        assert_round_trip(primitive(TagClass::Application, 10, 4), &[0xA4]);
    }

    #[test]
    fn spec_application_time() {
        // "Example: Application-tagged specific time value" -> X'B4'
        assert_round_trip(primitive(TagClass::Application, 11, 4), &[0xB4]);
    }

    #[test]
    fn spec_application_object_identifier() {
        // "Example: Application-tagged object identifier value" -> X'C4'
        assert_round_trip(primitive(TagClass::Application, 12, 4), &[0xC4]);
    }

    // --- Context-specific tags (Clause 20.2.1.6 worked examples) ---

    #[test]
    fn spec_context_null() {
        // "Example: Context-tagged null value", [3] Null -> X'38'
        assert_round_trip(primitive(TagClass::Context, 3, 0), &[0x38]);
    }

    #[test]
    fn spec_context_boolean() {
        // "Example: Context-tagged Boolean value", [6] Boolean FALSE -> X'69' (+ data X'00', not this module's concern)
        assert_round_trip(primitive(TagClass::Context, 6, 1), &[0x69]);
    }

    #[test]
    fn spec_context_boolean_extended_tag_number() {
        // "Example: ... Boolean value with context tag number greater than 14",
        // [27] Boolean FALSE -> X'F9' X'1B'
        assert_round_trip(primitive(TagClass::Context, 27, 1), &[0xF9, 0x1B]);
    }

    #[test]
    fn spec_context_unsigned() {
        // "Example: Context-tagged unsigned integer", [0] value 256 (2 octets) -> X'0A'
        assert_round_trip(primitive(TagClass::Context, 0, 2), &[0x0A]);
    }

    #[test]
    fn spec_context_signed() {
        // "Example: Context-tagged signed integer", [5] value -72 (1 octet) -> X'59'
        assert_round_trip(primitive(TagClass::Context, 5, 1), &[0x59]);
    }

    #[test]
    fn spec_context_signed_extended_tag_number() {
        // "Example: ... signed integer with context tag number greater than 14",
        // [33] value -72 -> X'F9' X'21'
        assert_round_trip(primitive(TagClass::Context, 33, 1), &[0xF9, 0x21]);
    }

    #[test]
    fn spec_context_real() {
        // "Example: Context-tagged single precision real", [0] -> X'0C'
        assert_round_trip(primitive(TagClass::Context, 0, 4), &[0x0C]);
    }

    #[test]
    fn spec_context_double() {
        // "Example: Context-tagged double precision real", [1] -> X'1D' + Length Extension X'08'
        assert_round_trip(primitive(TagClass::Context, 1, 8), &[0x1D, 0x08]);
    }

    #[test]
    fn spec_context_double_extended_tag_number() {
        // "Example: ... double precision real with context tag number greater than 14",
        // [85] -> X'FD' X'55' + Length Extension X'08'
        assert_round_trip(primitive(TagClass::Context, 85, 8), &[0xFD, 0x55, 0x08]);
    }

    #[test]
    fn spec_context_octet_string() {
        // "Example: Context-tagged octet string", [1] X'4321' (2 octets) -> X'1A'
        assert_round_trip(primitive(TagClass::Context, 1, 2), &[0x1A]);
    }

    #[test]
    fn spec_context_character_string() {
        // "Example: Context-tagged character string", [5]: 1 charset octet + 24
        // character octets = 25 -> X'5D' + Length Extension X'19'
        assert_round_trip(primitive(TagClass::Context, 5, 25), &[0x5D, 0x19]);
    }

    #[test]
    fn spec_context_character_string_extended_tag_number() {
        // "Example: ... character string with context tag number greater than 14",
        // [127] -> X'FD' X'7F' + Length Extension X'19'
        assert_round_trip(primitive(TagClass::Context, 127, 25), &[0xFD, 0x7F, 0x19]);
    }

    #[test]
    fn spec_context_bit_string() {
        // "Example: Context-tagged bit string", [0]: 1 unused-bits octet + 1 data
        // octet = 2 -> X'0A'
        assert_round_trip(primitive(TagClass::Context, 0, 2), &[0x0A]);
    }

    // --- Opening / closing tags (Clause 20.2.1.3, constructed data) ---
    //
    // Byte values cross-checked against opening/closing tag pairs used
    // throughout Clause 21/Annex service examples (e.g. "PD Opening/Closing
    // Tag N").

    #[test]
    fn spec_opening_closing_low_numbers() {
        for n in 0..=5u32 {
            let opening = Tag::opening(n).unwrap();
            let closing = Tag::closing(n).unwrap();
            let expected_open = (n as u8) << 4 | 0x0E;
            let expected_close = (n as u8) << 4 | 0x0F;
            assert_round_trip(opening, &[expected_open]);
            assert_round_trip(closing, &[expected_close]);
        }
    }

    #[test]
    fn spec_opening_closing_tag_12() {
        // "PD Opening Tag 12" / "PD Closing Tag 12" -> X'CE' / X'CF'
        assert_round_trip(Tag::opening(12).unwrap(), &[0xCE]);
        assert_round_trip(Tag::closing(12).unwrap(), &[0xCF]);
    }

    #[test]
    fn opening_closing_extended_tag_number() {
        // Not a literal spec example; derived from the general rule (Clause
        // 20.2.1.2's tag-number extension applies uniformly to all tags,
        // including opening/closing per 20.2.1.3(a)/(c)).
        assert_round_trip(Tag::opening(200).unwrap(), &[0xFE, 0xC8]);
        assert_round_trip(Tag::closing(200).unwrap(), &[0xFF, 0xC8]);
    }

    // --- Boundary conditions ---

    #[test]
    fn length_boundary_four_vs_five() {
        assert_round_trip(primitive(TagClass::Context, 0, 4), &[0x0C]);
        assert_round_trip(primitive(TagClass::Context, 0, 5), &[0x0D, 0x05]);
    }

    #[test]
    fn length_boundary_253_vs_254() {
        assert_round_trip(primitive(TagClass::Context, 0, 253), &[0x0D, 253]);
        assert_round_trip(primitive(TagClass::Context, 0, 254), &[0x0D, 254, 0x00, 0xFE]);
    }

    #[test]
    fn length_boundary_65535_vs_65536() {
        assert_round_trip(
            primitive(TagClass::Context, 0, 65535),
            &[0x0D, 254, 0xFF, 0xFF],
        );
        assert_round_trip(
            primitive(TagClass::Context, 0, 65536),
            &[0x0D, 255, 0x00, 0x01, 0x00, 0x00],
        );
    }

    #[test]
    fn tag_number_boundary_14_vs_15() {
        assert_round_trip(primitive(TagClass::Context, 14, 0), &[0xE8]);
        assert_round_trip(primitive(TagClass::Context, 15, 0), &[0xF8, 0x0F]);
    }

    #[test]
    fn tag_number_max_254() {
        assert_round_trip(primitive(TagClass::Context, 254, 0), &[0xF8, 254]);
    }

    #[test]
    fn encode_rejects_tag_number_above_254() {
        assert!(matches!(
            Tag::primitive(TagClass::Context, 255, 0),
            Err(EncodingError::ValueOutOfRange)
        ));
    }

    #[test]
    fn decode_rejects_reserved_extension_octet() {
        // Clause 20.2.1.2: "The value B'11111111' of the subsequent octet is
        // reserved by ASHRAE."
        let data = [0xF8, 0xFF];
        assert!(matches!(Tag::decode(&data), Err(EncodingError::InvalidTag)));
    }

    #[test]
    fn decode_reports_buffer_underflow() {
        assert!(matches!(
            Tag::decode(&[]),
            Err(EncodingError::InvalidTag)
        ));
        // Extended tag number with no extension octet.
        assert!(matches!(
            Tag::decode(&[0xF8]),
            Err(EncodingError::BufferUnderflow)
        ));
        // Extended length (5) with no length octet.
        assert!(matches!(
            Tag::decode(&[0x0D]),
            Err(EncodingError::BufferUnderflow)
        ));
        // 16-bit length extension truncated.
        assert!(matches!(
            Tag::decode(&[0x0D, 254, 0x00]),
            Err(EncodingError::BufferUnderflow)
        ));
        // 32-bit length extension truncated.
        assert!(matches!(
            Tag::decode(&[0x0D, 255, 0x00, 0x00, 0x00]),
            Err(EncodingError::BufferUnderflow)
        ));
    }

    #[test]
    fn opening_and_closing_are_distinguished_from_primitive() {
        let opening = Tag::opening(3).unwrap();
        let closing = Tag::closing(3).unwrap();
        assert!(opening.is_opening());
        assert!(!opening.is_closing());
        assert!(!opening.is_primitive());
        assert_eq!(opening.content_length(), None);

        assert!(closing.is_closing());
        assert!(!closing.is_opening());
        assert_eq!(closing.content_length(), None);
    }

    // --- General round-trip coverage across all tiers ---

    #[test]
    fn round_trip_property_all_tiers() {
        let numbers = [0u32, 1, 14, 15, 100, 254];
        let lengths = [0u32, 1, 4, 5, 100, 253, 254, 1000, 65535, 65536, 70_000];
        for &class in &[TagClass::Application, TagClass::Context] {
            for &number in &numbers {
                for &length in &lengths {
                    let tag = Tag::primitive(class, number, length).unwrap();
                    let mut buffer = Vec::new();
                    tag.encode(&mut buffer).unwrap();
                    let (decoded, consumed) = Tag::decode(&buffer).unwrap();
                    assert_eq!(consumed, buffer.len());
                    assert_eq!(decoded, tag);
                }
            }
        }
    }
}
