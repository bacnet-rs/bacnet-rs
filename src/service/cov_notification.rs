//! ConfirmedCOVNotification (service choice 1) and UnconfirmedCOVNotification
//! (service choice 2).
//!
//! Both carry the same parameter list from ASHRAE 135 clause 13.7, so
//! [`CovNotification::encode`] produces the service data for either and the
//! caller picks the APDU type.
//!
//! `listOfValues` is a sequence of `BACnetPropertyValue`, meaning each entry
//! names the property that changed rather than just carrying a bare value. A
//! standard COV notification reports Present_Value together with Status_Flags,
//! so a subscriber learns the value and its reliability in one message.

use crate::encoding::{
    advanced::context::{encode_closing_tag, encode_opening_tag},
    decode_context_object_id, decode_context_unsigned, encode_context_enumerated,
    encode_context_object_id, encode_context_unsigned, EncodingError, Result as EncodingResult,
};
use crate::object::{ObjectIdentifier, PropertyIdentifier};
use crate::property::{decode_property_value, encode_property_value, PropertyValue};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Whether the next tag opens constructed context `tag`.
///
/// `decode_tag` reports both opening and closing tags as a plain context tag, so
/// the length-value nibble - 6 to open, 7 to close - has to be read directly.
fn opens(data: &[u8], tag: u8) -> bool {
    data.first() == Some(&(0x0E | (tag << 4)))
}

/// Whether the next tag closes constructed context `tag`.
fn closes(data: &[u8], tag: u8) -> bool {
    data.first() == Some(&(0x0F | (tag << 4)))
}

/// Whether the next tag is context `tag` carrying a primitive value.
fn is_context(data: &[u8], tag: u8) -> bool {
    match data.first() {
        Some(&byte) => byte & 0x08 != 0 && byte >> 4 == tag && (byte & 0x07) < 6,
        None => false,
    }
}

/// One `BACnetPropertyValue` entry in a COV notification's `listOfValues`.
#[derive(Debug, Clone, PartialEq)]
pub struct CovPropertyValue {
    /// Which property changed.
    pub property_identifier: PropertyIdentifier,
    /// Array index, when the change is to one element.
    pub property_array_index: Option<u32>,
    /// The property's value. More than one application-tagged value can appear,
    /// which is how list- and array-valued properties are carried.
    pub values: Vec<PropertyValue>,
    /// Command priority, when the value came from a commandable object.
    pub priority: Option<u32>,
}

impl CovPropertyValue {
    /// A single-valued entry, which is what Present_Value and Status_Flags use.
    pub fn new(property_identifier: PropertyIdentifier, value: PropertyValue) -> Self {
        Self {
            property_identifier,
            property_array_index: None,
            values: vec![value],
            priority: None,
        }
    }

    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_enumerated(
            self.property_identifier.into(),
            0,
        )?);

        if let Some(index) = self.property_array_index {
            buffer.extend_from_slice(&encode_context_unsigned(index, 1)?);
        }

        encode_opening_tag(buffer, 2)?;
        for value in &self.values {
            encode_property_value(value, buffer)?;
        }
        encode_closing_tag(buffer, 2)?;

        if let Some(priority) = self.priority {
            buffer.extend_from_slice(&encode_context_unsigned(priority, 3)?);
        }

        Ok(())
    }
}

/// A change-of-value notification a device sends to a COV subscriber.
#[derive(Debug, Clone, PartialEq)]
pub struct CovNotification {
    /// The subscriber's process identifier, echoed from its subscription.
    pub subscriber_process_identifier: u32,
    /// The device reporting the change.
    pub initiating_device: ObjectIdentifier,
    /// The object whose property changed.
    pub monitored_object: ObjectIdentifier,
    /// Seconds left on the subscription; 0 means it does not expire.
    pub time_remaining: u32,
    /// The properties that changed, and their values.
    pub list_of_values: Vec<CovPropertyValue>,
}

impl CovNotification {
    /// Encode the service data shared by the confirmed and unconfirmed forms.
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_unsigned(
            self.subscriber_process_identifier,
            0,
        )?);
        buffer.extend_from_slice(&encode_context_object_id(self.initiating_device, 1)?);
        buffer.extend_from_slice(&encode_context_object_id(self.monitored_object, 2)?);
        buffer.extend_from_slice(&encode_context_unsigned(self.time_remaining, 3)?);

        encode_opening_tag(buffer, 4)?;
        for value in &self.list_of_values {
            value.encode(buffer)?;
        }
        encode_closing_tag(buffer, 4)?;

        Ok(())
    }

    /// Decode the service data of either notification form.
    pub fn decode(data: &[u8]) -> EncodingResult<Self> {
        let mut offset = 0;

        let (subscriber_process_identifier, consumed) = decode_context_unsigned(data, 0)?;
        offset += consumed;
        let (initiating_device, consumed) = decode_context_object_id(&data[offset..], 1)?;
        offset += consumed;
        let (monitored_object, consumed) = decode_context_object_id(&data[offset..], 2)?;
        offset += consumed;
        let (time_remaining, consumed) = decode_context_unsigned(&data[offset..], 3)?;
        offset += consumed;

        // listOfValues [4] is constructed; its opening and closing tags bracket a
        // sequence of BACnetPropertyValue with no count to rely on.
        if !opens(&data[offset..], 4) {
            return Err(EncodingError::InvalidTag);
        }
        offset += 1;

        let mut list_of_values = Vec::new();
        loop {
            if closes(&data[offset..], 4) {
                break;
            }

            let (property_identifier, consumed) = decode_context_unsigned(&data[offset..], 0)?;
            offset += consumed;

            let mut property_array_index = None;
            if is_context(&data[offset..], 1) {
                let (index, consumed) = decode_context_unsigned(&data[offset..], 1)?;
                property_array_index = Some(index);
                offset += consumed;
            }

            if !opens(&data[offset..], 2) {
                return Err(EncodingError::InvalidTag);
            }
            offset += 1;

            let mut values = Vec::new();
            loop {
                if closes(&data[offset..], 2) {
                    offset += 1;
                    break;
                }
                let (value, consumed) = decode_property_value(&data[offset..])?;
                values.push(value);
                offset += consumed;
            }

            let mut priority = None;
            if is_context(&data[offset..], 3) {
                let (value, consumed) = decode_context_unsigned(&data[offset..], 3)?;
                priority = Some(value);
                offset += consumed;
            }

            list_of_values.push(CovPropertyValue {
                property_identifier: PropertyIdentifier::from(property_identifier),
                property_array_index,
                values,
                priority,
            });
        }

        Ok(Self {
            subscriber_process_identifier,
            initiating_device,
            monitored_object,
            time_remaining,
            list_of_values,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    fn notification() -> CovNotification {
        CovNotification {
            // Larger than one byte on purpose: the encoding must not assume it fits.
            subscriber_process_identifier: 777,
            initiating_device: ObjectIdentifier::new(ObjectType::Device, 1234),
            monitored_object: ObjectIdentifier::new(ObjectType::AnalogValue, 1),
            time_remaining: 3600,
            list_of_values: vec![
                CovPropertyValue::new(PropertyIdentifier::PresentValue, PropertyValue::Real(21.5)),
                CovPropertyValue::new(
                    PropertyIdentifier::StatusFlags,
                    PropertyValue::BitString(vec![false, false, false, false]),
                ),
            ],
        }
    }

    #[test]
    fn round_trips_through_encode_and_decode() {
        let original = notification();
        let mut encoded = Vec::new();
        original.encode(&mut encoded).expect("encode");

        let decoded = CovNotification::decode(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn multi_byte_identifiers_survive() {
        let original = notification();
        let mut encoded = Vec::new();
        original.encode(&mut encoded).expect("encode");

        // Two payload bytes for 777, and two for 3600.
        assert_eq!(&encoded[..3], &[0x0a, 0x03, 0x09]);
        let decoded = CovNotification::decode(&encoded).expect("decode");
        assert_eq!(decoded.subscriber_process_identifier, 777);
        assert_eq!(decoded.time_remaining, 3600);
    }

    #[test]
    fn field_order_follows_clause_13_7() {
        let mut encoded = Vec::new();
        notification().encode(&mut encoded).expect("encode");

        // [0] pid, [1] initiating device, [2] monitored object, [3] time remaining,
        // then the constructed listOfValues [4].
        assert_eq!(encoded[0] & 0xf0, 0x00);
        assert_eq!(encoded[3], 0x1c);
        assert_eq!(encoded[8], 0x2c);
        assert_eq!(encoded[13] & 0xf0, 0x30);
        assert!(encoded.contains(&0x4e), "listOfValues opening tag");
        assert_eq!(*encoded.last().unwrap(), 0x4f, "listOfValues closing tag");
    }

    #[test]
    fn each_entry_names_its_property() {
        let mut encoded = Vec::new();
        notification().encode(&mut encoded).expect("encode");
        let decoded = CovNotification::decode(&encoded).expect("decode");

        assert_eq!(decoded.list_of_values.len(), 2);
        assert_eq!(
            decoded.list_of_values[0].property_identifier,
            PropertyIdentifier::PresentValue
        );
        assert_eq!(
            decoded.list_of_values[0].values,
            vec![PropertyValue::Real(21.5)]
        );
        assert_eq!(
            decoded.list_of_values[1].property_identifier,
            PropertyIdentifier::StatusFlags
        );
    }

    #[test]
    fn an_array_index_and_priority_are_optional_but_preserved() {
        let mut original = notification();
        original.list_of_values[0].property_array_index = Some(3);
        original.list_of_values[0].priority = Some(8);

        let mut encoded = Vec::new();
        original.encode(&mut encoded).expect("encode");
        let decoded = CovNotification::decode(&encoded).expect("decode");

        assert_eq!(decoded.list_of_values[0].property_array_index, Some(3));
        assert_eq!(decoded.list_of_values[0].priority, Some(8));
        assert_eq!(decoded, original);
    }

    #[test]
    fn an_empty_list_of_values_round_trips() {
        let mut original = notification();
        original.list_of_values.clear();

        let mut encoded = Vec::new();
        original.encode(&mut encoded).expect("encode");
        assert_eq!(CovNotification::decode(&encoded).expect("decode"), original);
    }
}
