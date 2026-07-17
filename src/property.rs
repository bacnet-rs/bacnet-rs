//! BACnet Property Value Decoders
//!
//! This module provides utilities for decoding BACnet property values
//! from their encoded representations into typed Rust values.

#[cfg(feature = "std")]
use std::fmt::Display;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    encoding::{
        advanced::bitstring::{decode_bit_string, encode_bit_string},
        decode_application_tag, decode_boolean, decode_character_string, decode_date,
        decode_double, decode_enumerated, decode_object_identifier, decode_octet_string,
        decode_real, decode_signed64, decode_time, decode_unsigned64, encode_application_tag,
        encode_boolean, encode_character_string, encode_date, encode_double, encode_enumerated,
        encode_object_identifier, encode_octet_string, encode_real, encode_signed64, encode_time,
        encode_unsigned64, EncodingError,
    },
    object::{EngineeringUnits, ObjectIdentifier},
    ApplicationTag,
};

/// Decoded BACnet property value
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyValue {
    /// Real (float) value
    Real(f32),
    /// Double (float) value
    Double(f64),
    /// Boolean value
    Boolean(bool),
    /// Unsigned integer value
    Unsigned(u64),
    /// Signed integer value
    Signed(i64),
    /// Octet string value
    OctetString(Vec<u8>),
    /// Character string value
    CharacterString(String),
    /// Enumerated value
    Enumerated(u32),
    /// Bit string value
    BitString(Vec<bool>),
    /// Date value (year, month, day, weekday)
    Date(u16, u8, u8, u8),
    /// Time value (hour, minute, second, hundredths)
    Time(u8, u8, u8, u8),
    /// Object identifier value
    ObjectIdentifier(ObjectIdentifier), // (object_type, instance)
    /// An ordered array of property values.
    Array(Vec<PropertyValue>),
    /// An ordered list of property values.
    List(Vec<PropertyValue>),
    /// Null value
    Null,
    /// Unknown/unsupported value type
    Unknown(Vec<u8>),
}

/// General BACnet value name used outside property-specific APIs.
pub type BacnetValue = PropertyValue;

impl PropertyValue {
    /// Get the value as a display string
    pub fn as_display_string(&self) -> String {
        match self {
            PropertyValue::Real(f) => format!("{:.2}", f),
            PropertyValue::Double(f) => format!("{:.2}", f),
            PropertyValue::Boolean(b) => {
                if *b {
                    "True".to_string()
                } else {
                    "False".to_string()
                }
            }
            PropertyValue::Unsigned(u) => u.to_string(),
            PropertyValue::Signed(i) => i.to_string(),
            PropertyValue::CharacterString(s) => s.clone(),
            PropertyValue::Enumerated(e) => format!("Enum({})", e),
            PropertyValue::OctetString(s) => format!("OctetString({:X?})", s),
            PropertyValue::BitString(bits) => {
                let bit_str: String = bits.iter().map(|b| if *b { '1' } else { '0' }).collect();
                format!("Bits({})", bit_str)
            }
            PropertyValue::Date(y, m, d, w) => format!("{:04}-{:02}-{:02} (DoW:{})", y, m, d, w),
            PropertyValue::Time(h, m, s, hs) => format!("{:02}:{:02}:{:02}.{:02}", h, m, s, hs),
            PropertyValue::ObjectIdentifier(id) => {
                format!("Object({}, {})", id.object_type, id.instance)
            }
            PropertyValue::Array(values) => format_collection("Array", values),
            PropertyValue::List(values) => format_collection("List", values),
            PropertyValue::Null => "Null".to_string(),
            PropertyValue::Unknown(_) => "Unknown".to_string(),
        }
    }

    /// Check if this is a numeric value
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            PropertyValue::Real(_) | PropertyValue::Unsigned(_) | PropertyValue::Signed(_)
        )
    }

    /// Get numeric value as f64 if possible
    pub fn as_numeric(&self) -> Option<f64> {
        match self {
            PropertyValue::Real(f) => Some(*f as f64),
            PropertyValue::Unsigned(u) => Some(*u as f64),
            PropertyValue::Signed(i) => Some(*i as f64),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl Display for PropertyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_display_string())
    }
}

/// Decode engineering units enumeration
pub fn decode_units(data: &[u8]) -> Option<(EngineeringUnits, usize)> {
    if let Ok((PropertyValue::Enumerated(units_id), consumed)) = decode_property_value(data) {
        let units = EngineeringUnits::from(units_id);
        Some((units, consumed))
    } else {
        None
    }
}

/// Decode status flags specifically
pub fn decode_status_flags(data: &[u8]) -> Option<(Vec<bool>, usize)> {
    if let Ok((PropertyValue::BitString(bits), consumed)) = decode_property_value(data) {
        // Status flags are typically 4 bits: in-alarm, fault, overridden, out-of-service
        Some((bits, consumed))
    } else {
        None
    }
}

/// Generic property value decoder - tries multiple decoders
pub fn decode_property_value(data: &[u8]) -> Result<(PropertyValue, usize), EncodingError> {
    if data.is_empty() {
        return Err(EncodingError::InvalidTag);
    }

    let (tag, length, consumed) = decode_application_tag(data)?;

    match tag {
        ApplicationTag::Null => Ok((PropertyValue::Null, consumed)),
        ApplicationTag::Boolean => {
            let (value, consumed) = decode_boolean(data)?;
            Ok((PropertyValue::Boolean(value), consumed))
        }
        ApplicationTag::UnsignedInt => {
            let (value, consumed) = decode_unsigned64(data)?;
            Ok((PropertyValue::Unsigned(value), consumed))
        }
        ApplicationTag::SignedInt => {
            let (value, consumed) = decode_signed64(data)?;
            Ok((PropertyValue::Signed(value), consumed))
        }
        ApplicationTag::Real => {
            let (value, consumed) = decode_real(data)?;
            Ok((PropertyValue::Real(value), consumed))
        }
        ApplicationTag::Double => {
            let (value, consumed) = decode_double(data)?;
            Ok((PropertyValue::Double(value), consumed))
        }
        ApplicationTag::OctetString => {
            let (value, consumed) = decode_octet_string(data)?;
            Ok((PropertyValue::OctetString(value), consumed))
        }
        ApplicationTag::CharacterString => {
            let (value, consumed) = decode_character_string(data)?;
            Ok((PropertyValue::CharacterString(value), consumed))
        }
        ApplicationTag::BitString => {
            let (value, consumed) = decode_bit_string(data)?;
            Ok((PropertyValue::BitString(value), consumed))
        }
        ApplicationTag::Enumerated => {
            let (value, consumed) = decode_enumerated(data)?;
            Ok((PropertyValue::Enumerated(value), consumed))
        }
        ApplicationTag::Date => {
            let ((year, month, day, weekday), consumed) = decode_date(data)?;
            Ok((PropertyValue::Date(year, month, day, weekday), consumed))
        }
        ApplicationTag::Time => {
            let ((hour, minute, second, hundredths), consumed) = decode_time(data)?;
            Ok((
                PropertyValue::Time(hour, minute, second, hundredths),
                consumed,
            ))
        }
        ApplicationTag::ObjectIdentifier => {
            let (value, consumed) = decode_object_identifier(data)?;
            Ok((PropertyValue::ObjectIdentifier(value), consumed))
        }
        _ => {
            // Unknown tag - return raw data
            Ok((PropertyValue::Unknown(data.to_vec()), consumed + length))
        }
    }
}

pub fn encode_property_value(
    value: &PropertyValue,
    buffer: &mut Vec<u8>,
) -> Result<(), EncodingError> {
    match value {
        PropertyValue::Real(f) => encode_real(buffer, *f)?,
        PropertyValue::Double(f) => encode_double(buffer, *f)?,
        PropertyValue::Boolean(b) => encode_boolean(buffer, *b)?,
        PropertyValue::Unsigned(u) => encode_unsigned64(buffer, *u),
        PropertyValue::Signed(i) => encode_signed64(buffer, *i),
        PropertyValue::OctetString(s) => encode_octet_string(buffer, s)?,
        PropertyValue::CharacterString(s) => encode_character_string(buffer, s)?,
        PropertyValue::Enumerated(e) => encode_enumerated(buffer, *e),
        PropertyValue::BitString(bits) => encode_bit_string(buffer, bits)?,
        PropertyValue::Date(y, m, d, w) => encode_date(buffer, *y, *m, *d, *w)?,
        PropertyValue::Time(h, m, s, hs) => encode_time(buffer, *h, *m, *s, *hs)?,
        PropertyValue::ObjectIdentifier(id) => encode_object_identifier(buffer, *id)?,
        PropertyValue::Array(values) | PropertyValue::List(values) => {
            for value in values {
                encode_property_value(value, buffer)?;
            }
        }
        PropertyValue::Null => encode_application_tag(buffer, ApplicationTag::Null, 0),
        PropertyValue::Unknown(data) => buffer.extend_from_slice(data),
    }

    Ok(())
}

fn format_collection(name: &str, values: &[PropertyValue]) -> String {
    let values = values
        .iter()
        .map(PropertyValue::as_display_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("{name}([{values}])")
}

#[cfg(test)]
mod tests {
    use crate::object::ObjectType;

    use super::*;

    #[test]
    fn test_decode_real() {
        // Test encoding of 23.5
        let data = [0x44, 0x41, 0xBC, 0x00, 0x00];
        let (value, consumed) = decode_property_value(&data).unwrap();
        assert_eq!(consumed, 5);
        if let PropertyValue::Real(f) = value {
            assert!((f - 23.5).abs() < 0.01);
        } else {
            panic!("Expected Real value");
        }
    }

    #[test]
    fn test_decode_boolean() {
        // Test true
        let data = [0x11];
        let (value, consumed) = decode_property_value(&data).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(value, PropertyValue::Boolean(true));

        // Test false
        let data = [0x10];
        let (value, consumed) = decode_property_value(&data).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(value, PropertyValue::Boolean(false));
    }

    #[test]
    fn test_decode_unsigned() {
        // Test 1-byte unsigned
        let data = [0x21, 0x7B]; // 123
        let (value, consumed) = decode_property_value(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Unsigned(123));

        // Test 2-byte unsigned
        let data = [0x22, 0x01, 0x2C]; // 300
        let (value, consumed) = decode_property_value(&data).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(value, PropertyValue::Unsigned(300));
    }

    #[test]
    fn test_decode_character_string() {
        // Test simple string "Hello"
        let data = [0x75, 0x06, 0x00, b'H', b'e', b'l', b'l', b'o'];
        let (value, consumed) = decode_property_value(&data).unwrap();
        assert_eq!(consumed, 8);
        if let PropertyValue::CharacterString(s) = value {
            assert_eq!(s, "Hello");
        } else {
            panic!("Expected CharacterString value");
        }
    }

    #[test]
    fn test_decode_enumerated() {
        // Test enumerated value 42
        let data = [0x91, 0x2A];
        let (value, consumed) = decode_property_value(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Enumerated(42));
    }

    #[test]
    fn test_decode_object_identifier() {
        // Test device object with instance 123
        let data = [0xC4, 0x02, 0x00, 0x00, 0x7B];
        let (value, consumed) = decode_property_value(&data).unwrap();
        assert_eq!(consumed, 5);
        if let PropertyValue::ObjectIdentifier(obj_id) = value {
            assert_eq!(obj_id.object_type, ObjectType::Device); // Device object type
            assert_eq!(obj_id.instance, 123);
        } else {
            panic!("Expected ObjectIdentifier value");
        }
    }

    #[test]
    fn test_property_value_display() {
        assert_eq!(PropertyValue::Real(23.45).as_display_string(), "23.45");
        assert_eq!(PropertyValue::Boolean(true).as_display_string(), "True");
        assert_eq!(PropertyValue::Unsigned(42).as_display_string(), "42");
        assert_eq!(
            PropertyValue::CharacterString("Test".to_string()).as_display_string(),
            "Test"
        );
    }

    #[test]
    fn test_decode_units() {
        // Test degrees Celsius
        let data = [0x91, 62];
        let (units, consumed) = decode_units(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(units.bacnet_name(), "degrees-celsius");

        // Test square inches
        let data = [0x91, 115];
        let (units, consumed) = decode_units(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(units.bacnet_name(), "square-inches");

        // Test amperes
        let data = [0x91, 3];
        let (units, consumed) = decode_units(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(units.bacnet_name(), "amperes");

        // Test cubic-feet-per-minute
        let data = [0x91, 84];
        let (units, consumed) = decode_units(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(units.bacnet_name(), "cubic-feet-per-minute");
    }
}
