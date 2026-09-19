//! BACnet Date and Time encoding and decoding.
//!
//! This module implements ASHRAE 135-2024, Clause 20.2's "Encoding of a
//! Date Value" and "Encoding of a Time Value": both are primitive, with
//! exactly four contents octets, one per field, conveyed as plain binary
//! integers (no minimal-length rule, no byte-order concern beyond the
//! trivial one-octet-per-field layout). They share the same "application-
//! tagged, four raw octets" framing, differing only in tag number and field
//! semantics, so that framing is implemented once here.
//!
//! Date fields: year minus 1900, month (January = 1), day of month, day of
//! week (Monday = 1). A value of `X'FF'` in any field means "unspecified" /
//! wildcard. This crate's [`crate::object::Date::year`] stores the actual
//! calendar year (1900-2154; 2155 is unrepresentable since its wire octet,
//! 255, collides with the sentinel) or `255` for "unspecified" — not the
//! wire's year-minus-1900 — so `encode_date`/`decode_date` convert between
//! the two, taking care to special-case the `255` sentinel rather than
//! subtracting 1900 from it (which would underflow).
//!
//! Time fields: hour (0-23), minute, second, hundredths of a second. `X'FF'`
//! likewise means "unspecified" in any field; no conversion is needed since
//! this crate's [`crate::object::Time`] already stores the raw octet values.
//!
//! Worked examples (Clause 20.2):
//! - Date: January 24, 1991 (Thursday) → Application Tag = Date (tag number
//!   10), Encoded Tag = `X'A4'`, Encoded Data = `X'5B011804'`.
//! - Date pattern: year 1991, month unspecified, day 24, weekday
//!   unspecified → Encoded Tag = `X'A4'`, Encoded Data = `X'5BFF18FF'`.
//! - Time: 17:35:45.17 → Application Tag = Time (tag number 11), Encoded
//!   Tag = `X'B4'`, Encoded Data = `X'11232D11'`.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{
    tag::{ApplicationTagNumber, Tag, TagClass, TagValue},
    EncodingError, Result,
};

/// Sentinel for an unspecified date/time field.
const UNSPECIFIED: u8 = 0xFF;

/// Encodes an application-tagged primitive with exactly four raw contents
/// octets.
fn encode_fixed4(
    buffer: &mut Vec<u8>,
    tag_number: ApplicationTagNumber,
    bytes: [u8; 4],
) -> Result<()> {
    Tag {
        number: tag_number as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(4),
    }
    .encode(buffer)?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Decodes an application-tagged primitive with exactly four raw contents
/// octets, validating the tag class, tag number, and content length.
fn decode_fixed4(data: &[u8], tag_number: ApplicationTagNumber) -> Result<([u8; 4], usize)> {
    let (t, consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != tag_number as u32 {
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
    Ok((bytes, consumed + 4))
}

/// Encode a BACnet date. `year` is the actual calendar year (1900-2154), or
/// `255` to mean "unspecified".
pub fn encode_date(buffer: &mut Vec<u8>, year: u16, month: u8, day: u8, weekday: u8) -> Result<()> {
    let year_octet = if year == UNSPECIFIED as u16 {
        UNSPECIFIED
    } else {
        (year - 1900) as u8
    };
    encode_fixed4(
        buffer,
        ApplicationTagNumber::Date,
        [year_octet, month, day, weekday],
    )
}

/// Decode a BACnet date. The returned year is the actual calendar year
/// (1900-2154), or `255` if the field was unspecified.
pub fn decode_date(data: &[u8]) -> Result<((u16, u8, u8, u8), usize)> {
    let ([year_octet, month, day, weekday], consumed) =
        decode_fixed4(data, ApplicationTagNumber::Date)?;
    let year = if year_octet == UNSPECIFIED {
        UNSPECIFIED as u16
    } else {
        1900 + year_octet as u16
    };
    Ok(((year, month, day, weekday), consumed))
}

/// Encode a BACnet time.
pub fn encode_time(
    buffer: &mut Vec<u8>,
    hour: u8,
    minute: u8,
    second: u8,
    hundredths: u8,
) -> Result<()> {
    encode_fixed4(
        buffer,
        ApplicationTagNumber::Time,
        [hour, minute, second, hundredths],
    )
}

/// Decode a BACnet time.
pub fn decode_time(data: &[u8]) -> Result<((u8, u8, u8, u8), usize)> {
    let (bytes, consumed) = decode_fixed4(data, ApplicationTagNumber::Time)?;
    Ok(((bytes[0], bytes[1], bytes[2], bytes[3]), consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Worked examples from ASHRAE 135-2024, Clause 20.2 ---

    #[test]
    fn spec_application_date_specific() {
        let mut buffer = Vec::new();
        encode_date(&mut buffer, 1991, 1, 24, 4).unwrap(); // Thursday = 4
        assert_eq!(buffer, [0xA4, 0x5B, 0x01, 0x18, 0x04]);
        let ((year, month, day, weekday), consumed) = decode_date(&buffer).unwrap();
        assert_eq!((year, month, day, weekday), (1991, 1, 24, 4));
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn spec_application_date_pattern() {
        // year = 1991, month unspecified, day = 24, weekday unspecified
        let mut buffer = Vec::new();
        encode_date(&mut buffer, 1991, 255, 24, 255).unwrap();
        assert_eq!(buffer, [0xA4, 0x5B, 0xFF, 0x18, 0xFF]);
        let ((year, month, day, weekday), consumed) = decode_date(&buffer).unwrap();
        assert_eq!((year, month, day, weekday), (1991, 255, 24, 255));
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn spec_application_time() {
        let mut buffer = Vec::new();
        encode_time(&mut buffer, 17, 35, 45, 17).unwrap();
        assert_eq!(buffer, [0xB4, 0x11, 0x23, 0x2D, 0x11]);
        let ((hour, minute, second, hundredths), consumed) = decode_time(&buffer).unwrap();
        assert_eq!((hour, minute, second, hundredths), (17, 35, 45, 17));
        assert_eq!(consumed, buffer.len());
    }

    // --- Wildcard / unspecified handling ---

    #[test]
    fn fully_unspecified_date_round_trips_without_overflow() {
        // This is the case that used to panic: year == 255 fed straight
        // into `(year - 1900)` on a u16 underflows.
        let mut buffer = Vec::new();
        encode_date(&mut buffer, 255, 255, 255, 255).unwrap();
        assert_eq!(buffer, [0xA4, 0xFF, 0xFF, 0xFF, 0xFF]);
        let ((year, month, day, weekday), _) = decode_date(&buffer).unwrap();
        assert_eq!((year, month, day, weekday), (255, 255, 255, 255));
    }

    #[test]
    fn fully_unspecified_time_round_trips() {
        let mut buffer = Vec::new();
        encode_time(&mut buffer, 255, 255, 255, 255).unwrap();
        assert_eq!(buffer, [0xB4, 0xFF, 0xFF, 0xFF, 0xFF]);
        let ((hour, minute, second, hundredths), _) = decode_time(&buffer).unwrap();
        assert_eq!((hour, minute, second, hundredths), (255, 255, 255, 255));
    }

    #[test]
    fn date_year_boundaries_round_trip() {
        // 2154 is the highest representable year: its wire octet is 254.
        // 2155 would be 255, which collides with the "unspecified"
        // sentinel, so it is not round-trippable (see
        // `year_2155_collides_with_unspecified_sentinel` below).
        for year in [1900u16, 1991, 2000, 2154] {
            let mut buffer = Vec::new();
            encode_date(&mut buffer, year, 6, 15, 3).unwrap();
            let ((decoded_year, ..), _) = decode_date(&buffer).unwrap();
            assert_eq!(decoded_year, year, "year {year}");
        }
    }

    #[test]
    fn year_2155_collides_with_unspecified_sentinel() {
        let mut buffer = Vec::new();
        encode_date(&mut buffer, 2155, 6, 15, 3).unwrap();
        let ((decoded_year, ..), _) = decode_date(&buffer).unwrap();
        assert_eq!(
            decoded_year, 255,
            "encodes indistinguishably from unspecified"
        );
    }

    // --- Rejections ---

    #[test]
    fn rejects_wrong_tag_class_for_date() {
        // Context tag 0, length 4 (i.e. [0] date-shaped, not
        // application-tagged).
        let data = [0x04, 0x5B, 0x01, 0x18, 0x04];
        assert!(decode_date(&data).is_err());
    }

    #[test]
    fn rejects_wrong_application_tag_number_for_date() {
        // Application tag 11 (Time), not 10 (Date).
        let data = [0xB4, 0x5B, 0x01, 0x18, 0x04];
        assert!(decode_date(&data).is_err());
    }

    #[test]
    fn rejects_short_content_for_date() {
        let data = [0xA3, 0x5B, 0x01, 0x18];
        assert!(decode_date(&data).is_err());
    }

    #[test]
    fn rejects_wrong_application_tag_number_for_time() {
        // Application tag 10 (Date), not 11 (Time).
        let data = [0xA4, 0x11, 0x23, 0x2D, 0x11];
        assert!(decode_time(&data).is_err());
    }

    #[test]
    fn rejects_short_content_for_time() {
        let data = [0xB3, 0x11, 0x23, 0x2D];
        assert!(decode_time(&data).is_err());
    }

    // --- Pre-existing coverage, moved unchanged ---

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
}
