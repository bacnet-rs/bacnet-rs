//! ConfirmedEventNotification (service choice 2) and UnconfirmedEventNotification
//! (service choice 3).
//!
//! Both services carry the identical parameter list from ASHRAE 135 clause 13.8,
//! so [`EventNotification::encode`] produces the service data for either; the
//! caller picks the APDU type.
//!
//! Only the `BACnetNotificationParameters` alternatives produced by the intrinsic
//! reporting algorithms in [`crate::event`] are modelled: change-of-state,
//! out-of-range and change-of-reliability.

use crate::encoding::{
    advanced::context::{encode_closing_tag, encode_opening_tag},
    encode_context_enumerated, encode_context_object_id, encode_context_tag,
    encode_context_unsigned, Result as EncodingResult,
};
use crate::object::{intrinsic::NotifyType, EventState, ObjectIdentifier, Reliability};
use crate::property::TimestampValue;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// `BACnetStatusFlags` — in-alarm, fault, overridden, out-of-service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusFlags {
    /// The object is in an off-normal or fault event state.
    pub in_alarm: bool,
    /// The object's value is unreliable.
    pub fault: bool,
    /// The value has been overridden locally.
    pub overridden: bool,
    /// The object is decoupled from the physical point.
    pub out_of_service: bool,
}

impl StatusFlags {
    /// Derive the flags an intrinsic-reporting object reports for `state`.
    pub fn for_event_state(state: EventState, out_of_service: bool) -> Self {
        Self {
            in_alarm: state != EventState::Normal,
            fault: state == EventState::Fault,
            overridden: false,
            out_of_service,
        }
    }

    /// The flags packed in BACnet bit order.
    pub fn to_bits(self) -> [bool; 4] {
        [
            self.in_alarm,
            self.fault,
            self.overridden,
            self.out_of_service,
        ]
    }
}

/// `BACnetEventType` values produced by intrinsic reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// change-of-state (1) — binary and multi-state objects.
    ChangeOfState,
    /// out-of-range (5) — analog objects with limits.
    OutOfRange,
    /// change-of-reliability (19).
    ChangeOfReliability,
}

impl From<EventType> for u32 {
    fn from(value: EventType) -> Self {
        match value {
            EventType::ChangeOfState => 1,
            EventType::OutOfRange => 5,
            EventType::ChangeOfReliability => 19,
        }
    }
}

/// `BACnetPropertyStates` CHOICE, limited to the alternatives change-of-state uses.
///
/// The context tag number *is* the CHOICE discriminator, so these values match
/// the `BACnetPropertyStates` production exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyStates {
    /// boolean-value [0].
    BooleanValue(bool),
    /// binary-value [1] — a `BACnetBinaryPV`, inactive (0) or active (1).
    BinaryValue(bool),
    /// unsigned-value [11] — a multi-state Present_Value.
    UnsignedValue(u32),
}

impl PropertyStates {
    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match *self {
            Self::BooleanValue(value) => encode_context_boolean(buffer, 0, value),
            Self::BinaryValue(active) => {
                buffer.extend_from_slice(&encode_context_enumerated(u32::from(active), 1)?);
                Ok(())
            }
            Self::UnsignedValue(state) => {
                buffer.extend_from_slice(&encode_context_unsigned(state, 11)?);
                Ok(())
            }
        }
    }
}

/// `BACnetNotificationParameters` for the supported event algorithms.
#[derive(Debug, Clone, PartialEq)]
pub enum NotificationParameters {
    /// change-of-state [1].
    ChangeOfState {
        /// The state the object moved to.
        new_state: PropertyStates,
        /// Status flags at the time of the transition.
        status_flags: StatusFlags,
    },
    /// out-of-range [5].
    OutOfRange {
        /// The value that breached the limit.
        exceeding_value: f32,
        /// Status flags at the time of the transition.
        status_flags: StatusFlags,
        /// Configured deadband.
        deadband: f32,
        /// The limit that was breached.
        exceeded_limit: f32,
    },
    /// change-of-reliability [19].
    ChangeOfReliability {
        /// The object's reliability.
        reliability: Reliability,
        /// Status flags at the time of the transition.
        status_flags: StatusFlags,
    },
}

impl NotificationParameters {
    /// The event type this parameter set belongs to.
    pub fn event_type(&self) -> EventType {
        match self {
            Self::ChangeOfState { .. } => EventType::ChangeOfState,
            Self::OutOfRange { .. } => EventType::OutOfRange,
            Self::ChangeOfReliability { .. } => EventType::ChangeOfReliability,
        }
    }

    fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        match self {
            Self::ChangeOfState {
                new_state,
                status_flags,
            } => {
                encode_opening_tag(buffer, 1)?;
                encode_opening_tag(buffer, 0)?;
                new_state.encode(buffer)?;
                encode_closing_tag(buffer, 0)?;
                encode_context_bit_string(buffer, 1, &status_flags.to_bits())?;
                encode_closing_tag(buffer, 1)?;
            }
            Self::OutOfRange {
                exceeding_value,
                status_flags,
                deadband,
                exceeded_limit,
            } => {
                encode_opening_tag(buffer, 5)?;
                encode_context_real(buffer, 0, *exceeding_value)?;
                encode_context_bit_string(buffer, 1, &status_flags.to_bits())?;
                encode_context_real(buffer, 2, *deadband)?;
                encode_context_real(buffer, 3, *exceeded_limit)?;
                encode_closing_tag(buffer, 5)?;
            }
            Self::ChangeOfReliability {
                reliability,
                status_flags,
            } => {
                encode_opening_tag(buffer, 19)?;
                buffer.extend_from_slice(&encode_context_enumerated(u32::from(*reliability), 0)?);
                encode_context_bit_string(buffer, 1, &status_flags.to_bits())?;
                // property-values [2] is required but may be an empty sequence.
                encode_opening_tag(buffer, 2)?;
                encode_closing_tag(buffer, 2)?;
                encode_closing_tag(buffer, 19)?;
            }
        }

        Ok(())
    }
}

/// An event notification a device sends to a notification-class recipient.
#[derive(Debug, Clone, PartialEq)]
pub struct EventNotification {
    /// Recipient's process identifier, from the Recipient_List entry.
    pub process_identifier: u32,
    /// The device reporting the event.
    pub initiating_device: ObjectIdentifier,
    /// The object whose event state changed.
    pub event_object: ObjectIdentifier,
    /// When the transition occurred.
    pub timestamp: TimestampValue,
    /// Instance number of the routing notification class.
    pub notification_class: u32,
    /// Notification priority for this transition (1–255).
    pub priority: u32,
    /// Whether this is an alarm or a plain event.
    pub notify_type: NotifyType,
    /// Whether the recipient must acknowledge.
    pub ack_required: bool,
    /// Event state before the transition.
    pub from_state: EventState,
    /// Event state after the transition.
    pub to_state: EventState,
    /// Optional human-readable message.
    pub message_text: Option<String>,
    /// Algorithm-specific detail.
    pub parameters: NotificationParameters,
}

impl EventNotification {
    /// The event type carried by [`Self::parameters`].
    pub fn event_type(&self) -> EventType {
        self.parameters.event_type()
    }

    /// Encode the service data shared by the confirmed and unconfirmed forms.
    pub fn encode(&self, buffer: &mut Vec<u8>) -> EncodingResult<()> {
        buffer.extend_from_slice(&encode_context_unsigned(self.process_identifier, 0)?);
        buffer.extend_from_slice(&encode_context_object_id(self.initiating_device, 1)?);
        buffer.extend_from_slice(&encode_context_object_id(self.event_object, 2)?);

        encode_opening_tag(buffer, 3)?;
        self.timestamp.encode(buffer)?;
        encode_closing_tag(buffer, 3)?;

        buffer.extend_from_slice(&encode_context_unsigned(self.notification_class, 4)?);
        buffer.extend_from_slice(&encode_context_unsigned(self.priority, 5)?);
        buffer.extend_from_slice(&encode_context_enumerated(self.event_type().into(), 6)?);

        if let Some(text) = &self.message_text {
            encode_context_char_string(buffer, 7, text)?;
        }

        buffer.extend_from_slice(&encode_context_enumerated(self.notify_type.into(), 8)?);

        // ack-required and from-state are only present for alarms and events,
        // never for acknowledgement notifications.
        if self.notify_type != NotifyType::AckNotification {
            encode_context_boolean(buffer, 9, self.ack_required)?;
            buffer.extend_from_slice(&encode_context_enumerated(
                u16::from(self.from_state).into(),
                10,
            )?);
        }

        buffer.extend_from_slice(&encode_context_enumerated(
            u16::from(self.to_state).into(),
            11,
        )?);

        encode_opening_tag(buffer, 12)?;
        self.parameters.encode(buffer)?;
        encode_closing_tag(buffer, 12)?;

        Ok(())
    }
}

/// Encode a REAL under a context tag.
fn encode_context_real(buffer: &mut Vec<u8>, tag: u8, value: f32) -> EncodingResult<()> {
    encode_context_tag(buffer, tag, 4)?;
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Encode a BOOLEAN under a context tag. Unlike the application form, the value
/// is carried in a one-byte payload rather than the tag's length field.
fn encode_context_boolean(buffer: &mut Vec<u8>, tag: u8, value: bool) -> EncodingResult<()> {
    encode_context_tag(buffer, tag, 1)?;
    buffer.push(u8::from(value));
    Ok(())
}

/// Encode a BIT STRING under a context tag.
fn encode_context_bit_string(buffer: &mut Vec<u8>, tag: u8, bits: &[bool]) -> EncodingResult<()> {
    let byte_count = bits.len().div_ceil(8);
    let unused_bits = if bits.len().is_multiple_of(8) {
        0
    } else {
        8 - (bits.len() % 8)
    };

    encode_context_tag(buffer, tag, byte_count + 1)?;
    buffer.push(unused_bits as u8);

    let mut current = 0u8;
    let mut offset = 0;
    for &bit in bits {
        if bit {
            current |= 1 << (7 - offset);
        }
        offset += 1;
        if offset == 8 {
            buffer.push(current);
            current = 0;
            offset = 0;
        }
    }
    if offset > 0 {
        buffer.push(current);
    }

    Ok(())
}

/// Encode a CHARACTER STRING under a context tag, always as UTF-8.
fn encode_context_char_string(buffer: &mut Vec<u8>, tag: u8, text: &str) -> EncodingResult<()> {
    let bytes = text.as_bytes();
    encode_context_tag(buffer, tag, bytes.len() + 1)?;
    buffer.push(0); // ANSI X3.4 / UTF-8
    buffer.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    fn notification(parameters: NotificationParameters) -> EventNotification {
        EventNotification {
            process_identifier: 777,
            initiating_device: ObjectIdentifier::new(ObjectType::Device, 1234),
            event_object: ObjectIdentifier::new(ObjectType::MultiStateValue, 1),
            timestamp: TimestampValue::SequenceNumber(5),
            notification_class: 1,
            priority: 90,
            notify_type: NotifyType::Alarm,
            ack_required: false,
            from_state: EventState::Normal,
            to_state: EventState::Offnormal,
            message_text: None,
            parameters,
        }
    }

    #[test]
    fn change_of_state_reports_event_type_one() {
        let event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(5),
            status_flags: StatusFlags::for_event_state(EventState::Offnormal, false),
        });
        assert_eq!(u32::from(event.event_type()), 1);
    }

    /// The change-of-state parameter block is what alarmsd parses to recover
    /// `event-values.change-of-state.new-state`, so pin its exact bytes.
    #[test]
    fn change_of_state_parameters_match_the_spec_layout() {
        let parameters = NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(5),
            status_flags: StatusFlags {
                in_alarm: true,
                fault: false,
                overridden: false,
                out_of_service: false,
            },
        };

        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).expect("encode");

        assert_eq!(
            encoded,
            vec![
                0x1e, // opening tag [1] change-of-state
                0x0e, // opening tag [0] new-state
                0xb9, 0x05, // context 11 (unsigned-value), length 1, state 5
                0x0f, // closing tag [0]
                0x1a, 0x04, 0x80, // context 1, length 2: 4 unused bits, 0b1000_0000
                0x1f, // closing tag [1]
            ]
        );
    }

    #[test]
    fn out_of_range_parameters_match_the_spec_layout() {
        let parameters = NotificationParameters::OutOfRange {
            exceeding_value: 25.0,
            status_flags: StatusFlags {
                in_alarm: true,
                fault: false,
                overridden: false,
                out_of_service: false,
            },
            deadband: 0.5,
            exceeded_limit: 24.0,
        };

        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).expect("encode");

        let mut expected = vec![0x5e]; // opening tag [5] out-of-range
        expected.push(0x0c); // context 0, length 4
        expected.extend_from_slice(&25.0f32.to_be_bytes());
        expected.extend_from_slice(&[0x1a, 0x04, 0x80]); // status flags
        expected.push(0x2c); // context 2, length 4
        expected.extend_from_slice(&0.5f32.to_be_bytes());
        expected.push(0x3c); // context 3, length 4
        expected.extend_from_slice(&24.0f32.to_be_bytes());
        expected.push(0x5f); // closing tag [5]

        assert_eq!(encoded, expected);
    }

    #[test]
    fn change_of_reliability_carries_an_empty_property_values_sequence() {
        let parameters = NotificationParameters::ChangeOfReliability {
            reliability: Reliability::UnreliableOther,
            status_flags: StatusFlags::for_event_state(EventState::Fault, false),
        };

        let mut encoded = Vec::new();
        parameters.encode(&mut encoded).expect("encode");

        // Opening [19] uses the extended tag-number form, as do its closers.
        assert_eq!(&encoded[..2], &[0xfe, 0x13]);
        assert_eq!(&encoded[encoded.len() - 2..], &[0xff, 0x13]);
        // property-values [2] is present but empty.
        assert!(encoded.windows(2).any(|pair| pair == [0x2e, 0x2f]));
    }

    #[test]
    fn service_data_field_order_follows_clause_13_8() {
        let event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(5),
            status_flags: StatusFlags::for_event_state(EventState::Offnormal, false),
        });

        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");

        // processIdentifier [0] = 777 carries a two-byte payload in the tag length.
        assert_eq!(&encoded[..3], &[0x0a, 0x03, 0x09]);
        // The parameters are wrapped in the eventValues [12] constructed tag.
        assert_eq!(encoded[encoded.len() - 1], 0xcf);
        assert!(encoded.windows(1).any(|byte| byte == [0xce]));
    }

    /// Byte-for-byte against a frame captured from the bacnet-stack reference
    /// implementation:
    ///
    /// ```text
    /// bacuevent --mac <host> 777 8 1234 19 1 5 1 90 1 11 5 1000 "" 0 0 0 2
    /// ```
    ///
    /// The captured datagram was
    /// `810a0034 0100 1003 <service data>`; only the service data is compared
    /// here since BVLC/NPDU/APDU framing is the caller's concern.
    #[test]
    fn matches_a_frame_captured_from_the_reference_implementation() {
        let event = EventNotification {
            process_identifier: 777,
            initiating_device: ObjectIdentifier::new(ObjectType::Device, 1234),
            event_object: ObjectIdentifier::new(ObjectType::MultiStateValue, 1),
            timestamp: TimestampValue::SequenceNumber(5),
            notification_class: 1,
            priority: 90,
            notify_type: NotifyType::Alarm,
            ack_required: false,
            from_state: EventState::Normal,
            to_state: EventState::Offnormal,
            // The reference tool always emits the field, empty in this capture.
            message_text: Some(String::new()),
            parameters: NotificationParameters::ChangeOfState {
                new_state: PropertyStates::UnsignedValue(5),
                status_flags: StatusFlags {
                    in_alarm: true,
                    fault: false,
                    overridden: false,
                    out_of_service: false,
                },
            },
        };

        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");

        let expected = [
            0x0a, 0x03, 0x09, // [0] processIdentifier 777
            0x1c, 0x02, 0x00, 0x04, 0xd2, // [1] initiating device,1234
            0x2c, 0x04, 0xc0, 0x00, 0x01, // [2] event object multi-state-value,1
            0x3e, 0x19, 0x05, 0x3f, // [3] timeStamp sequenceNumber 5
            0x49, 0x01, // [4] notificationClass 1
            0x59, 0x5a, // [5] priority 90
            0x69, 0x01, // [6] eventType change-of-state
            0x79, 0x00, // [7] messageText ""
            0x89, 0x00, // [8] notifyType alarm
            0x99, 0x00, // [9] ackRequired false
            0xa9, 0x00, // [10] fromState normal
            0xb9, 0x02, // [11] toState offnormal
            0xce, // [12] eventValues
            0x1e, 0x0e, 0xb9, 0x05, 0x0f, 0x1a, 0x04, 0x80, 0x1f, 0xcf,
        ];

        assert_eq!(encoded, expected);
    }

    #[test]
    fn ack_notifications_omit_ack_required_and_from_state() {
        let mut event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::BinaryValue(true),
            status_flags: StatusFlags::default(),
        });
        event.notify_type = NotifyType::AckNotification;

        let mut encoded = Vec::new();
        event.encode(&mut encoded).expect("encode");

        // Context tag 9 (0x99) and 10 (0xa9) must not appear as field headers.
        let mut alarm_form = Vec::new();
        notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::BinaryValue(true),
            status_flags: StatusFlags::default(),
        })
        .encode(&mut alarm_form)
        .expect("encode");

        assert!(alarm_form.len() > encoded.len());
    }

    #[test]
    fn message_text_is_optional() {
        let mut event = notification(NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(2),
            status_flags: StatusFlags::default(),
        });

        let mut without = Vec::new();
        event.encode(&mut without).expect("encode");

        event.message_text = Some("Mode fault".to_string());
        let mut with = Vec::new();
        event.encode(&mut with).expect("encode");

        // Tag byte + extended length byte + the UTF-8 marker, then the text.
        assert_eq!(with.len(), without.len() + 3 + "Mode fault".len());
    }
}
