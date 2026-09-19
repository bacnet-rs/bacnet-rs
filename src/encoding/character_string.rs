//! BACnet CharacterString encoding and decoding.
//!
//! This module implements ASHRAE 135-2024, Clause 20.2.9 ("Encoding of a
//! Character String Value") in full: all six character sets the standard
//! defines, not just UTF-8.
//!
//! # Content layout
//!
//! A CharacterString's content is one character-set octet followed by zero
//! or more data octets:
//!
//! | Charset octet | Character set |
//! |---|---|
//! | `0x00` | ISO 10646 (UTF-8) |
//! | `0x01` | IBM/Microsoft DBCS (followed by a 2-octet, big-endian code page number) |
//! | `0x02` | JIS X 0208 |
//! | `0x03` | ISO 10646 (UCS-4) — 4 octets per character, big-endian |
//! | `0x04` | ISO 10646 (UCS-2) — 2 octets per character, big-endian |
//! | `0x05` | ISO 8859-1 |
//!
//! Other charset octet values are reserved by ASHRAE and are rejected.
//!
//! # Lazy conversion
//!
//! Decoding produces a [`CharacterString`] holding the charset and the raw
//! data octets exactly as they appeared on the wire. Decoding only validates
//! the framing (tag, length, charset octet, DBCS code page); the data octets
//! are converted to text only when asked for, via [`CharacterString::to_str`]
//! or [`CharacterString::to_string_lossy`]. Content that isn't valid for its
//! charset is therefore a conversion error, not a decode error.
//!
//! # Decoding legacy charsets
//!
//! DBCS (`0x01`) and JIS X 0208 (`0x02`) are genuine variable-width,
//! code-page-dependent encodings that cannot be hand-rolled from the spec
//! text alone. When this crate's `legacy-charsets` feature is enabled
//! (opt-in — off by default), they are decoded via the `encoding_rs` crate (for
//! Windows/WHATWG code pages such as Shift_JIS, GBK, EUC-KR, Big5, and the
//! `windows-125x` family) and the `oem_cp` crate (for classic single-byte
//! DOS/OEM code pages such as 437 and 850 — the latter is the code page used
//! in the standard's own DBCS worked example). Without that feature, or for
//! a code page neither crate recognizes, only the ASCII-safe byte range
//! (`< 0x80`) is decoded; genuine multi-byte content is reported as an
//! error rather than guessed at.
//!
//! # Encoding
//!
//! New CharacterStrings built from Rust strings are always UTF-8 (`0x00`).
//! Every compliant BACnet implementation must be able to decode UTF-8
//! CharacterStrings, so there is no interoperability reason to create any of
//! the legacy charsets. A decoded [`CharacterString`] in another charset is
//! re-encoded byte for byte in its original charset.

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use super::{
    tag::{ApplicationTagNumber, Tag, TagClass, TagValue},
    EncodingError, Result,
};

#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;
use core::fmt;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::borrow::Cow;

const CHARSET_UTF8: u8 = 0x00;
const CHARSET_DBCS: u8 = 0x01;
const CHARSET_JIS_X0208: u8 = 0x02;
const CHARSET_UCS4: u8 = 0x03;
const CHARSET_UCS2: u8 = 0x04;
const CHARSET_ISO_8859_1: u8 = 0x05;

/// The character set a BACnet CharacterString is encoded in
/// (ASHRAE 135-2024, Clause 20.2.9).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharacterSet {
    /// ISO 10646 (UTF-8).
    Utf8,
    /// IBM/Microsoft DBCS, carrying its 16-bit code page number.
    Dbcs(u16),
    /// JIS X 0208.
    JisX0208,
    /// ISO 10646 (UCS-4).
    Ucs4,
    /// ISO 10646 (UCS-2).
    Ucs2,
    /// ISO 8859-1.
    Iso8859_1,
}

impl CharacterSet {
    /// The charset octet that identifies this character set on the wire.
    pub fn octet(self) -> u8 {
        match self {
            CharacterSet::Utf8 => CHARSET_UTF8,
            CharacterSet::Dbcs(_) => CHARSET_DBCS,
            CharacterSet::JisX0208 => CHARSET_JIS_X0208,
            CharacterSet::Ucs4 => CHARSET_UCS4,
            CharacterSet::Ucs2 => CHARSET_UCS2,
            CharacterSet::Iso8859_1 => CHARSET_ISO_8859_1,
        }
    }

    /// Number of content octets this charset needs ahead of the data: the
    /// charset octet, plus the code page for DBCS.
    fn header_len(self) -> usize {
        match self {
            CharacterSet::Dbcs(_) => 3,
            _ => 1,
        }
    }
}

/// A BACnet CharacterString, stored as its charset and raw data octets.
///
/// Conversion to Rust text happens only on demand — see the module docs.
/// Equality and hashing compare the charset and raw octets, so the same text
/// in two different charsets is not equal.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CharacterString {
    charset: CharacterSet,
    /// Data octets following the charset octet (and, for DBCS, the code page).
    data: Vec<u8>,
}

impl CharacterString {
    /// Creates a CharacterString from a charset and its raw data octets.
    ///
    /// The data is not validated against the charset; invalid content is
    /// reported by [`to_str`](Self::to_str).
    pub fn new(charset: CharacterSet, data: Vec<u8>) -> Self {
        Self { charset, data }
    }

    /// The character set the data octets are encoded in.
    pub fn charset(&self) -> CharacterSet {
        self.charset
    }

    /// The raw data octets, excluding the charset octet and DBCS code page.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Splits into the charset and the raw data octets.
    pub fn into_raw_parts(self) -> (CharacterSet, Vec<u8>) {
        (self.charset, self.data)
    }

    /// Length of the raw data octets.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether there are no data octets.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Length of the encoded content (charset octet, DBCS code page, and
    /// data), i.e. the tag's length value.
    pub fn content_len(&self) -> usize {
        self.charset.header_len() + self.data.len()
    }

    /// Converts to text, failing if the data isn't valid for its charset.
    ///
    /// UTF-8 content is borrowed without allocating; other charsets are
    /// converted into an owned `String`.
    pub fn to_str(&self) -> Result<Cow<'_, str>> {
        let body = self.data.as_slice();
        Ok(match self.charset {
            CharacterSet::Utf8 => Cow::Borrowed(core::str::from_utf8(body).map_err(|_| {
                EncodingError::InvalidFormat("invalid UTF-8 character string".to_string())
            })?),
            CharacterSet::Ucs4 => Cow::Owned(decode_ucs4(body)?),
            CharacterSet::Ucs2 => Cow::Owned(decode_ucs2(body)?),
            CharacterSet::Iso8859_1 => Cow::Owned(decode_iso_8859_1(body)),
            CharacterSet::Dbcs(code_page) => Cow::Owned(decode_legacy_codepage(body, code_page)?),
            CharacterSet::JisX0208 => Cow::Owned(decode_jis_x0208(body)?),
        })
    }

    /// Converts to text, replacing anything invalid for its charset with
    /// U+FFFD.
    ///
    /// For DBCS and JIS X 0208 content that can't be fully decoded, only the
    /// ASCII bytes are kept and every other byte is replaced.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        let body = self.data.as_slice();
        match self.charset {
            CharacterSet::Utf8 => String::from_utf8_lossy(body),
            CharacterSet::Ucs4 => Cow::Owned(
                body.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|chunk| {
                        char::from_u32(u32::from_be_bytes(*chunk))
                            .unwrap_or(char::REPLACEMENT_CHARACTER)
                    })
                    .collect(),
            ),
            CharacterSet::Ucs2 => {
                let units: Vec<u16> = body
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|chunk| u16::from_be_bytes(*chunk))
                    .collect();
                Cow::Owned(String::from_utf16_lossy(&units))
            }
            CharacterSet::Iso8859_1 => Cow::Owned(decode_iso_8859_1(body)),
            CharacterSet::Dbcs(_) | CharacterSet::JisX0208 => match self.to_str() {
                Ok(text) => text,
                Err(_) => Cow::Owned(
                    body.iter()
                        .map(|&b| {
                            if b < 0x80 {
                                b as char
                            } else {
                                char::REPLACEMENT_CHARACTER
                            }
                        })
                        .collect(),
                ),
            },
        }
    }

    /// Encodes as a BACnet application-tagged CharacterString, in this
    /// string's own charset.
    pub fn encode(&self, buffer: &mut Vec<u8>) -> Result<()> {
        Tag {
            number: ApplicationTagNumber::CharacterString as u32,
            class: TagClass::Application,
            value: TagValue::Primitive(self.content_len() as u32),
        }
        .encode(buffer)?;
        self.encode_content(buffer);
        Ok(())
    }

    /// Encodes just the content (charset octet, DBCS code page, and data),
    /// with no tag of its own.
    ///
    /// For callers that build their own tag framing around the content, such
    /// as a context-tagged CharacterString.
    pub fn encode_content(&self, buffer: &mut Vec<u8>) {
        buffer.push(self.charset.octet());
        if let CharacterSet::Dbcs(code_page) = self.charset {
            buffer.extend_from_slice(&code_page.to_be_bytes());
        }
        buffer.extend_from_slice(&self.data);
    }
}

impl From<String> for CharacterString {
    fn from(value: String) -> Self {
        Self::new(CharacterSet::Utf8, value.into_bytes())
    }
}

impl From<&str> for CharacterString {
    fn from(value: &str) -> Self {
        Self::new(CharacterSet::Utf8, value.as_bytes().to_vec())
    }
}

impl TryFrom<CharacterString> for String {
    type Error = EncodingError;

    fn try_from(value: CharacterString) -> Result<Self> {
        match value.charset {
            CharacterSet::Utf8 => String::from_utf8(value.data).map_err(|_| {
                EncodingError::InvalidFormat("invalid UTF-8 character string".to_string())
            }),
            _ => value.to_str().map(Cow::into_owned),
        }
    }
}

impl TryFrom<&CharacterString> for String {
    type Error = EncodingError;

    fn try_from(value: &CharacterString) -> Result<Self> {
        value.to_str().map(Cow::into_owned)
    }
}

impl fmt::Display for CharacterString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

/// Encodes `value` as a BACnet application-tagged CharacterString.
///
/// Always uses charset `0x00` (ISO 10646 UTF-8) — see the module docs for why.
pub fn encode_character_string(buffer: &mut Vec<u8>, value: &str) -> Result<()> {
    Tag {
        number: ApplicationTagNumber::CharacterString as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(value.len() as u32 + 1),
    }
    .encode(buffer)?;
    encode_utf8_content(buffer, value);
    Ok(())
}

/// Encodes just the character-set-octet-plus-data content of a UTF-8
/// CharacterString, with no tag of its own.
///
/// For callers that build their own tag framing around the content, such as
/// a context-tagged CharacterString.
pub fn encode_utf8_content(buffer: &mut Vec<u8>, value: &str) {
    buffer.push(CHARSET_UTF8);
    buffer.extend_from_slice(value.as_bytes());
}

/// Decodes a BACnet application-tagged CharacterString.
///
/// Returns the CharacterString and the number of octets consumed (tag plus
/// content). Only the framing is validated here; the data octets are
/// checked against their charset when converted to text.
pub fn decode_character_string(data: &[u8]) -> Result<(CharacterString, usize)> {
    let (t, consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::CharacterString as u32
    {
        return Err(EncodingError::InvalidTag);
    }
    let length = t.content_length().unwrap_or(0) as usize;

    if length == 0 || data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let content = &data[consumed..consumed + length];
    let charset = match content[0] {
        CHARSET_UTF8 => CharacterSet::Utf8,
        CHARSET_UCS4 => CharacterSet::Ucs4,
        CHARSET_UCS2 => CharacterSet::Ucs2,
        CHARSET_ISO_8859_1 => CharacterSet::Iso8859_1,
        CHARSET_DBCS => {
            if content.len() < 3 {
                return Err(EncodingError::BufferUnderflow);
            }
            CharacterSet::Dbcs(u16::from_be_bytes([content[1], content[2]]))
        }
        CHARSET_JIS_X0208 => CharacterSet::JisX0208,
        reserved => {
            return Err(EncodingError::InvalidFormat(format!(
                "reserved character set 0x{:02X}",
                reserved
            )))
        }
    };

    let body = content[charset.header_len()..].to_vec();
    Ok((CharacterString::new(charset, body), consumed + length))
}

fn decode_ucs4(body: &[u8]) -> Result<String> {
    if !body.len().is_multiple_of(4) {
        return Err(EncodingError::InvalidFormat(
            "UCS-4 character string length is not a multiple of 4".to_string(),
        ));
    }

    body.as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| {
            let scalar = u32::from_be_bytes(*chunk);
            char::from_u32(scalar)
                .ok_or_else(|| EncodingError::InvalidFormat("invalid UCS-4 code point".to_string()))
        })
        .collect()
}

fn decode_ucs2(body: &[u8]) -> Result<String> {
    if !body.len().is_multiple_of(2) {
        return Err(EncodingError::InvalidFormat(
            "UCS-2 character string length is not a multiple of 2".to_string(),
        ));
    }

    let units: Vec<u16> = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_be_bytes(*chunk))
        .collect();

    String::from_utf16(&units)
        .map_err(|_| EncodingError::InvalidFormat("invalid UCS-2 sequence".to_string()))
}

fn decode_iso_8859_1(body: &[u8]) -> String {
    // ISO 8859-1 maps every byte directly to the identical Unicode scalar value.
    body.iter().map(|&b| b as char).collect()
}

/// Decodes `body` assuming it is plain ASCII, for use when a legacy
/// code-page-dependent charset can't be decoded via a real table. `reason`
/// explains why (feature disabled vs. code page/charset not recognized) and
/// is folded into the error on non-ASCII content, rather than guessing at
/// its meaning.
fn decode_ascii_fallback(body: &[u8], charset_description: &str, reason: &str) -> Result<String> {
    if body.iter().all(|&b| b < 0x80) {
        Ok(body.iter().map(|&b| b as char).collect())
    } else {
        Err(EncodingError::InvalidFormat(format!(
            "{} is not supported ({}; non-ASCII bytes present)",
            charset_description, reason
        )))
    }
}

#[cfg(feature = "legacy-charsets")]
fn decode_legacy_codepage(body: &[u8], code_page: u16) -> Result<String> {
    if let Some(encoding) = windows_codepage_encoding(code_page) {
        let (text, _, had_errors) = encoding.decode(body);
        return if had_errors {
            Err(EncodingError::InvalidFormat(format!(
                "invalid bytes for DBCS code page {}",
                code_page
            )))
        } else {
            Ok(text.into_owned())
        };
    }

    if let Some(table) = oem_cp::code_table::DECODING_TABLE_CP_MAP.get(&code_page) {
        return table.decode_string_checked(body).ok_or_else(|| {
            EncodingError::InvalidFormat(format!("invalid bytes for DBCS code page {}", code_page))
        });
    }

    decode_ascii_fallback(
        body,
        &format!("DBCS code page {}", code_page),
        "code page not recognized by the `legacy-charsets` backends",
    )
}

#[cfg(not(feature = "legacy-charsets"))]
fn decode_legacy_codepage(body: &[u8], code_page: u16) -> Result<String> {
    decode_ascii_fallback(
        body,
        &format!("DBCS code page {}", code_page),
        "the `legacy-charsets` feature is not enabled",
    )
}

#[cfg(feature = "legacy-charsets")]
fn decode_jis_x0208(body: &[u8]) -> Result<String> {
    // JIS X 0208 characters are conveyed over the wire via the Shift_JIS
    // transport encoding, the conventional choice for this charset in
    // legacy Windows/BACnet contexts.
    let (text, _, had_errors) = encoding_rs::SHIFT_JIS.decode(body);
    if had_errors {
        Err(EncodingError::InvalidFormat(
            "invalid JIS X 0208 (Shift_JIS) bytes".to_string(),
        ))
    } else {
        Ok(text.into_owned())
    }
}

#[cfg(not(feature = "legacy-charsets"))]
fn decode_jis_x0208(body: &[u8]) -> Result<String> {
    decode_ascii_fallback(
        body,
        "JIS X 0208",
        "the `legacy-charsets` feature is not enabled",
    )
}

/// Maps a Windows/DBCS code page number to the `encoding_rs` static encoding
/// that decodes it, for the code pages `encoding_rs` covers. Numbers it
/// doesn't recognize fall through to `oem_cp`'s classic DOS/OEM tables.
#[cfg(feature = "legacy-charsets")]
fn windows_codepage_encoding(code_page: u16) -> Option<&'static encoding_rs::Encoding> {
    Some(match code_page {
        866 => encoding_rs::IBM866,
        874 => encoding_rs::WINDOWS_874,
        932 => encoding_rs::SHIFT_JIS,
        936 => encoding_rs::GBK,
        949 => encoding_rs::EUC_KR,
        950 => encoding_rs::BIG5,
        1250 => encoding_rs::WINDOWS_1250,
        1251 => encoding_rs::WINDOWS_1251,
        1252 => encoding_rs::WINDOWS_1252,
        1253 => encoding_rs::WINDOWS_1253,
        1254 => encoding_rs::WINDOWS_1254,
        1255 => encoding_rs::WINDOWS_1255,
        1256 => encoding_rs::WINDOWS_1256,
        1257 => encoding_rs::WINDOWS_1257,
        1258 => encoding_rs::WINDOWS_1258,
        20866 => encoding_rs::KOI8_R,
        21866 => encoding_rs::KOI8_U,
        51932 => encoding_rs::EUC_JP,
        54936 => encoding_rs::GB18030,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    fn assert_decodes_to(data: &[u8], expected_text: &str, expected_charset: CharacterSet) {
        let (value, consumed) = decode_character_string(data).unwrap();
        assert_eq!(value.to_str().unwrap(), expected_text);
        assert_eq!(value.charset(), expected_charset);
        assert_eq!(consumed, data.len());
    }

    /// Asserts `data` decodes (framing is fine) but its content can't be
    /// converted to text.
    fn assert_conversion_fails(data: &[u8]) {
        let (value, consumed) = decode_character_string(data).unwrap();
        assert_eq!(consumed, data.len());
        assert!(value.to_str().is_err());
        assert!(String::try_from(&value).is_err());
    }

    /// Asserts decoding then re-encoding `data` reproduces it byte for byte.
    fn assert_round_trips_exactly(data: &[u8]) {
        let (value, _) = decode_character_string(data).unwrap();
        let mut buffer = Vec::new();
        value.encode(&mut buffer).unwrap();
        assert_eq!(buffer, data);
    }

    // --- Worked examples from ASHRAE 135-2024, Clause 20.2.9 ---

    #[test]
    fn spec_utf8_ascii() {
        // "Application-tagged character string": "This is a BACnet string!"
        // Encoded Tag = X'75', Length Extension = X'19', Character Set = X'00'
        let mut data = vec![0x75, 0x19, 0x00];
        data.extend_from_slice(b"This is a BACnet string!");
        assert_decodes_to(&data, "This is a BACnet string!", CharacterSet::Utf8);
        assert_round_trips_exactly(&data);
    }

    #[test]
    fn spec_utf8_non_ascii() {
        // "Application-tagged character string with non-ANSI character": "Français"
        // Encoded Tag = X'75', Length Extension = X'0A', Character Set = X'00'
        // Encoded Data = X'4672616EC3A7616973'
        let mut data = vec![0x75, 0x0A, 0x00];
        data.extend_from_slice(&[0x46, 0x72, 0x61, 0x6E, 0xC3, 0xA7, 0x61, 0x69, 0x73]);
        assert_decodes_to(&data, "Français", CharacterSet::Utf8);
        assert_round_trips_exactly(&data);
    }

    #[test]
    fn spec_dbcs_code_page_850() {
        // "Application-tagged character string (DBCS)": "This is a BACnet String!"
        // (code page 850), Encoded Tag = X'75', Length Extension = X'1B'
        // Encoded Data = X'010352546869732069732061204241436E657420737472696E6721'
        let mut data = vec![0x75, 0x1B, 0x01, 0x03, 0x52];
        data.extend_from_slice(b"This is a BACnet string!");
        assert_decodes_to(&data, "This is a BACnet string!", CharacterSet::Dbcs(850));
        assert_round_trips_exactly(&data);
    }

    #[test]
    #[cfg(feature = "legacy-charsets")]
    fn dbcs_code_page_850_non_ascii_byte() {
        // 0x80 in CP850 is 'Ç' (U+00C7) — distinct from ASCII, so this only
        // passes if the real CP850 table is actually consulted rather than
        // the ASCII-safe fallback.
        let content = [CHARSET_DBCS, 0x03, 0x52, 0x80];
        assert_decodes_to(&wrap_content(&content), "Ç", CharacterSet::Dbcs(850));
    }

    #[test]
    #[cfg(not(feature = "legacy-charsets"))]
    fn dbcs_code_page_850_non_ascii_byte_rejected_without_feature() {
        // Without `legacy-charsets`, only the ASCII-safe fallback is
        // available, so a genuine high-byte CP850 character is an error
        // rather than a guess.
        let content = [CHARSET_DBCS, 0x03, 0x52, 0x80];
        assert_conversion_fails(&wrap_content(&content));
    }

    #[test]
    fn spec_ucs2() {
        // "Application-tagged character string (UCS-2)": "This is a BACnet String!"
        // Encoded Tag = X'75', Length Extension = X'31'
        // Encoded Data = X'0400540068...0067 0021'
        let text = "This is a BACnet string!";
        let mut data = vec![0x75, 0x31, 0x04];
        for unit in text.encode_utf16() {
            data.extend_from_slice(&unit.to_be_bytes());
        }
        assert_decodes_to(&data, text, CharacterSet::Ucs2);
        assert_round_trips_exactly(&data);
    }

    /// Wraps raw CharacterString content (charset octet + data) in a
    /// correctly-encoded application tag, so tests don't hand-compute tag
    /// bytes for anything other than the literal spec examples.
    fn wrap_content(content: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        Tag::primitive(
            TagClass::Application,
            ApplicationTagNumber::CharacterString as u32,
            content.len() as u32,
        )
        .unwrap()
        .encode(&mut data)
        .unwrap();
        data.extend_from_slice(content);
        data
    }

    // --- Round trips for charsets without a literal spec byte example ---

    #[test]
    fn ucs4_round_trip_non_bmp_character() {
        // U+1F600 (an emoji) requires UCS-4; if this were accidentally
        // truncated to 16 bits, this test would fail.
        let text = "hi \u{1F600} bye";
        let mut content = vec![CHARSET_UCS4];
        for c in text.chars() {
            content.extend_from_slice(&(c as u32).to_be_bytes());
        }

        assert_decodes_to(&wrap_content(&content), text, CharacterSet::Ucs4);
        assert_round_trips_exactly(&wrap_content(&content));
    }

    #[test]
    fn iso_8859_1_round_trip_high_byte() {
        // 0xE9 in ISO 8859-1 is 'é' (U+00E9), identical scalar value.
        let content = [CHARSET_ISO_8859_1, b'e', 0xE9];
        assert_decodes_to(&wrap_content(&content), "eé", CharacterSet::Iso8859_1);
        assert_round_trips_exactly(&wrap_content(&content));
    }

    #[test]
    fn empty_string() {
        // Charset octet present, zero data octets following.
        let content = [CHARSET_UTF8];
        assert_decodes_to(&wrap_content(&content), "", CharacterSet::Utf8);
    }

    // --- Framing rejections (decode errors) ---

    #[test]
    fn rejects_reserved_charset() {
        let content = [0x06, b'h', b'i'];
        assert!(decode_character_string(&wrap_content(&content)).is_err());
    }

    #[test]
    fn rejects_dbcs_without_code_page() {
        let content = [CHARSET_DBCS, 0x03];
        assert!(decode_character_string(&wrap_content(&content)).is_err());
    }

    // --- Content rejections (conversion errors) ---

    #[test]
    fn rejects_invalid_utf8() {
        let content = [CHARSET_UTF8, 0xFF, 0xFE];
        assert_conversion_fails(&wrap_content(&content));
    }

    #[test]
    fn rejects_lone_surrogate_in_ucs2() {
        // 0xD800 is a lone high surrogate with no following low surrogate.
        let content = [CHARSET_UCS2, 0xD8, 0x00];
        assert_conversion_fails(&wrap_content(&content));
    }

    #[test]
    fn rejects_surrogate_scalar_in_ucs4() {
        // 0x0000D800 is in the surrogate range, not a valid scalar value.
        let content = [CHARSET_UCS4, 0x00, 0x00, 0xD8, 0x00];
        assert_conversion_fails(&wrap_content(&content));
    }

    #[test]
    fn rejects_non_ascii_dbcs_with_unrecognized_code_page() {
        // Code page 0xFFFF is not a recognized code page under any backend.
        let content = [CHARSET_DBCS, 0xFF, 0xFF, 0x80];
        assert_conversion_fails(&wrap_content(&content));
    }

    #[test]
    fn decodes_ascii_dbcs_with_unrecognized_code_page() {
        // Plain ASCII content is decodable even under an unrecognized code page.
        let content = [CHARSET_DBCS, 0xFF, 0xFF, b'h', b'i'];
        assert_decodes_to(&wrap_content(&content), "hi", CharacterSet::Dbcs(0xFFFF));
    }

    // --- Lossy conversion ---

    #[test]
    fn lossy_replaces_invalid_content() {
        let utf8 = CharacterString::new(CharacterSet::Utf8, vec![b'a', 0xFF, b'b']);
        assert_eq!(utf8.to_string_lossy(), "a\u{FFFD}b");

        let ucs2 = CharacterString::new(CharacterSet::Ucs2, vec![0x00, b'a', 0xD8, 0x00]);
        assert_eq!(ucs2.to_string_lossy(), "a\u{FFFD}");

        let ucs4 = CharacterString::new(CharacterSet::Ucs4, vec![0x00, 0x00, 0xD8, 0x00]);
        assert_eq!(ucs4.to_string_lossy(), "\u{FFFD}");

        let dbcs = CharacterString::new(CharacterSet::Dbcs(0xFFFF), vec![b'a', 0x80]);
        assert_eq!(dbcs.to_string_lossy(), "a\u{FFFD}");
        assert_eq!(dbcs.to_string(), "a\u{FFFD}");
    }

    // --- Conversion avoids work where it can ---

    #[test]
    fn utf8_to_str_borrows() {
        let value = CharacterString::from("borrowed");
        assert!(matches!(value.to_str().unwrap(), Cow::Borrowed("borrowed")));
    }

    #[test]
    fn owned_utf8_try_into_string() {
        let value = CharacterString::from(String::from("owned"));
        assert_eq!(String::try_from(value).unwrap(), "owned");

        let invalid = CharacterString::new(CharacterSet::Utf8, vec![0xFF]);
        assert!(String::try_from(invalid).is_err());

        let ucs2 = CharacterString::new(CharacterSet::Ucs2, vec![0x00, b'x']);
        assert_eq!(String::try_from(ucs2).unwrap(), "x");
    }

    // --- Encoding ---

    #[test]
    fn encode_decode_round_trip() {
        let mut buffer = Vec::new();
        encode_character_string(&mut buffer, "round trip: café 🎉").unwrap();
        let (value, consumed) = decode_character_string(&buffer).unwrap();
        assert_eq!(value.to_str().unwrap(), "round trip: café 🎉");
        assert_eq!(value.charset(), CharacterSet::Utf8);
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn struct_encode_matches_str_encode() {
        let text = "same bytes ✓";
        let mut from_str = Vec::new();
        encode_character_string(&mut from_str, text).unwrap();
        let mut from_struct = Vec::new();
        CharacterString::from(text)
            .encode(&mut from_struct)
            .unwrap();
        assert_eq!(from_struct, from_str);
    }

    #[test]
    fn encode_content_includes_dbcs_code_page() {
        let value = CharacterString::new(CharacterSet::Dbcs(850), b"hi".to_vec());
        let mut buffer = Vec::new();
        value.encode_content(&mut buffer);
        assert_eq!(buffer, [CHARSET_DBCS, 0x03, 0x52, b'h', b'i']);
        assert_eq!(value.content_len(), buffer.len());
    }

    #[test]
    fn equality_compares_raw_bytes_and_charset() {
        let utf8 = CharacterString::from("abc");
        let latin1 = CharacterString::new(CharacterSet::Iso8859_1, b"abc".to_vec());
        assert_ne!(utf8, latin1);
        assert_eq!(utf8.to_str().unwrap(), latin1.to_str().unwrap());
    }
}
