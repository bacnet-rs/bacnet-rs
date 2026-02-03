//! BACnet Property Value Decoders
//!
//! This module provides utilities for decoding BACnet property values
//! from their encoded representations into typed Rust values.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::object::{EngineeringUnits, ObjectType};

/// Decoded BACnet property value
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyValue {
    /// Real (float) value
    Real(f32),
    /// Boolean value
    Boolean(bool),
    /// Unsigned integer value
    Unsigned(u32),
    /// Signed integer value
    Signed(i32),
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
    ObjectIdentifier(u16, u32), // (object_type, instance)
    /// Null value
    Null,
    /// Unknown/unsupported value type
    Unknown(Vec<u8>),
}

impl PropertyValue {
    /// Get the value as a display string
    pub fn as_display_string(&self) -> String {
        match self {
            PropertyValue::Real(f) => format!("{:.2}", f),
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
            PropertyValue::BitString(bits) => {
                let bit_str: String = bits.iter().map(|b| if *b { '1' } else { '0' }).collect();
                format!("Bits({})", bit_str)
            }
            PropertyValue::Date(y, m, d, w) => format!("{:04}-{:02}-{:02} (DoW:{})", y, m, d, w),
            PropertyValue::Time(h, m, s, hs) => format!("{:02}:{:02}:{:02}.{:02}", h, m, s, hs),
            PropertyValue::ObjectIdentifier(t, i) => format!("Object({}, {})", t, i),
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

/// Extract character string from BACnet encoded data
pub fn decode_character_string(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for character string application tag (0x75) or context tag
    let (_tag, mut pos) = if data[0] == 0x75 {
        // Application tag with length in next byte
        (0x75, 1)
    } else if (data[0] & 0xF0) == 0x70 {
        // Context tag for character string
        (data[0], 1)
    } else {
        return None;
    };

    if pos >= data.len() {
        return None;
    }

    let length = data[pos] as usize;
    pos += 1;

    if data.len() < pos + length || length == 0 {
        return None;
    }

    // Skip encoding byte (typically 0 for ANSI X3.4)
    if pos >= data.len() {
        return None;
    }

    let _encoding = data[pos];
    pos += 1;

    if data.len() < pos + length - 1 {
        return None;
    }

    let string_data = &data[pos..pos + length - 1];
    let string = String::from_utf8_lossy(string_data).to_string();

    Some((PropertyValue::CharacterString(string), pos + length - 1))
}

/// Extract real (float) value from BACnet encoded data
pub fn decode_real(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 5 {
        return None;
    }

    // Check for real application tag (0x44)
    if data[0] != 0x44 {
        return None;
    }

    let bytes = [data[1], data[2], data[3], data[4]];
    let value = f32::from_be_bytes(bytes);

    Some((PropertyValue::Real(value), 5))
}

/// Extract boolean value from BACnet encoded data
pub fn decode_boolean(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for boolean application tag (0x11)
    if data[0] != 0x11 {
        return None;
    }

    let value = data[1] != 0;
    Some((PropertyValue::Boolean(value), 2))
}

/// Extract unsigned integer from BACnet encoded data
pub fn decode_unsigned(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for unsigned application tag (0x21, 0x22, 0x23, or 0x24)
    let (_tag, length) = match data[0] {
        0x21 => (0x21, 1), // 1 byte
        0x22 => (0x22, 2), // 2 bytes
        0x23 => (0x23, 3), // 3 bytes
        0x24 => (0x24, 4), // 4 bytes
        _ => return None,
    };

    if data.len() < 1 + length {
        return None;
    }

    let mut value = 0u32;
    for i in 0..length {
        value = (value << 8) | (data[1 + i] as u32);
    }

    Some((PropertyValue::Unsigned(value), 1 + length))
}

/// Extract signed integer from BACnet encoded data  
pub fn decode_signed(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for signed application tag (0x31, 0x32, 0x33, or 0x34)
    let (_tag, length) = match data[0] {
        0x31 => (0x31, 1), // 1 byte
        0x32 => (0x32, 2), // 2 bytes
        0x33 => (0x33, 3), // 3 bytes
        0x34 => (0x34, 4), // 4 bytes
        _ => return None,
    };

    if data.len() < 1 + length {
        return None;
    }

    let mut value = if (data[1] & 0x80) != 0 {
        0xFFFFFFFFu32
    } else {
        0
    }; // Sign extend
    for i in 0..length {
        value = (value << 8) | (data[1 + i] as u32);
    }

    Some((PropertyValue::Signed(value as i32), 1 + length))
}

/// Extract enumerated value from BACnet encoded data
pub fn decode_enumerated(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for enumerated application tag (0x91, 0x92, 0x93, or 0x94)
    let (_tag, length) = match data[0] {
        0x91 => (0x91, 1), // 1 byte
        0x92 => (0x92, 2), // 2 bytes
        0x93 => (0x93, 3), // 3 bytes
        0x94 => (0x94, 4), // 4 bytes
        _ => return None,
    };

    if data.len() < 1 + length {
        return None;
    }

    let mut value = 0u32;
    for i in 0..length {
        value = (value << 8) | (data[1 + i] as u32);
    }

    Some((PropertyValue::Enumerated(value), 1 + length))
}

/// Extract object identifier from BACnet encoded data
pub fn decode_object_identifier(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 5 {
        return None;
    }

    // Check for object identifier application tag (0xC4)
    if data[0] != 0xC4 {
        return None;
    }

    let obj_id_bytes = [data[1], data[2], data[3], data[4]];
    let obj_id = u32::from_be_bytes(obj_id_bytes);
    let object_type = ((obj_id >> 22) & 0x3FF) as u16;
    let instance = obj_id & 0x3FFFFF;

    Some((PropertyValue::ObjectIdentifier(object_type, instance), 5))
}

/// Extract present value based on object type
pub fn decode_present_value(
    data: &[u8],
    object_type: ObjectType,
) -> Option<(PropertyValue, usize)> {
    if data.is_empty() {
        return None;
    }

    match object_type {
        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
            decode_real(data)
        }
        ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue => {
            decode_boolean(data)
        }
        ObjectType::MultiStateInput
        | ObjectType::MultiStateOutput
        | ObjectType::MultiStateValue => decode_unsigned(data),
        _ => None,
    }
}

/// Decode engineering units enumeration
pub fn decode_units(data: &[u8]) -> Option<(EngineeringUnits, usize)> {
    if let Some((PropertyValue::Enumerated(units_id), consumed)) = decode_enumerated(data) {
        let units = EngineeringUnits::from(units_id);
        Some((units, consumed))
    } else {
        None
    }
}

/// Extract bit string (status flags) from BACnet encoded data
pub fn decode_bit_string(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 3 {
        return None;
    }

    // Check for bit string application tag (0x82)
    if data[0] != 0x82 {
        return None;
    }

    let length = data[1] as usize;
    if data.len() < 2 + length {
        return None;
    }

    let unused_bits = data[2];
    let mut bits = Vec::new();

    for byte in data.iter().take(2 + length).skip(3) {
        for bit_pos in (0..8).rev() {
            bits.push((byte & (1 << bit_pos)) != 0);
        }
    }

    // Remove unused bits from the end
    if unused_bits > 0 && unused_bits < 8 {
        let total_bits = bits.len();
        bits.truncate(total_bits - unused_bits as usize);
    }

    Some((PropertyValue::BitString(bits), 2 + length))
}

/// Decode status flags specifically
pub fn decode_status_flags(data: &[u8]) -> Option<(Vec<bool>, usize)> {
    if let Some((PropertyValue::BitString(bits), consumed)) = decode_bit_string(data) {
        // Status flags are typically 4 bits: in-alarm, fault, overridden, out-of-service
        Some((bits, consumed))
    } else {
        None
    }
}

/// Generic property value decoder - tries multiple decoders
pub fn decode_property_value(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.is_empty() {
        return None;
    }

    // Try different decoders based on the tag
    match data[0] {
        0x00 => Some((PropertyValue::Null, 1)),
        0x11 => decode_boolean(data),
        0x21..=0x24 => decode_unsigned(data),
        0x31..=0x34 => decode_signed(data),
        0x44 => decode_real(data),
        0x75 => decode_character_string(data),
        0x82 => decode_bit_string(data),
        0x91..=0x94 => decode_enumerated(data),
        0xC4 => decode_object_identifier(data),
        _ => {
            // Unknown tag - return raw data
            Some((PropertyValue::Unknown(data.to_vec()), data.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_real() {
        // Test encoding of 23.5
        let data = [0x44, 0x41, 0xBC, 0x00, 0x00];
        let (value, consumed) = decode_real(&data).unwrap();
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
        let data = [0x11, 0x01];
        let (value, consumed) = decode_boolean(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Boolean(true));

        // Test false
        let data = [0x11, 0x00];
        let (value, consumed) = decode_boolean(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Boolean(false));
    }

    #[test]
    fn test_decode_unsigned() {
        // Test 1-byte unsigned
        let data = [0x21, 0x7B]; // 123
        let (value, consumed) = decode_unsigned(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Unsigned(123));

        // Test 2-byte unsigned
        let data = [0x22, 0x01, 0x2C]; // 300
        let (value, consumed) = decode_unsigned(&data).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(value, PropertyValue::Unsigned(300));
    }

    #[test]
    fn test_decode_character_string() {
        // Test simple string "Hello"
        let data = [0x75, 0x06, 0x00, b'H', b'e', b'l', b'l', b'o'];
        let (value, consumed) = decode_character_string(&data).unwrap();
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
        let (value, consumed) = decode_enumerated(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Enumerated(42));
    }

    #[test]
    fn test_decode_object_identifier() {
        // Test device object with instance 123
        let data = [0xC4, 0x02, 0x00, 0x00, 0x7B];
        let (value, consumed) = decode_object_identifier(&data).unwrap();
        assert_eq!(consumed, 5);
        if let PropertyValue::ObjectIdentifier(obj_type, instance) = value {
            assert_eq!(obj_type, 8); // Device object type
            assert_eq!(instance, 123);
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
