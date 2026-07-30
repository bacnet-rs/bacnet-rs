//! Intrinsic reporting (alarm and event) state shared by alarm-capable objects.
//!
//! ASHRAE 135 clause 13.2 gives every intrinsic-reporting object the same set of
//! alarm properties regardless of which event algorithm it runs. This module holds
//! that shared state once in [`IntrinsicReporting`] and exposes it through
//! [`intrinsic_get`] / [`intrinsic_set`], so each object type adds a single
//! fallthrough arm instead of repeating the property plumbing.
//!
//! Objects carry `alarm: Option<IntrinsicReporting>`; `None` means event detection
//! is not configured and the object behaves exactly as it did before.

use crate::object::{
    event_state::EventState, ObjectError, PropertyIdentifier, PropertyValue, Reliability, Result,
};
use crate::property::TimestampValue;

#[cfg(not(feature = "std"))]
use alloc::{string::ToString, vec, vec::Vec};

/// A BACnet event transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTransition {
    /// Into an off-normal state (off-normal, high-limit or low-limit).
    ToOffnormal,
    /// Into the fault state.
    ToFault,
    /// Back into the normal state.
    ToNormal,
}

impl EventTransition {
    /// The transition implied by entering `state`.
    ///
    /// High-limit and low-limit are off-normal transitions: they share the
    /// `to_offnormal` acknowledgement and priority bucket.
    pub fn for_state(state: EventState) -> Self {
        match state {
            EventState::Normal => Self::ToNormal,
            EventState::Fault => Self::ToFault,
            _ => Self::ToOffnormal,
        }
    }

    /// Index of this transition in a `BACnetEventTransitionBits` bit string.
    pub fn bit_index(self) -> usize {
        match self {
            Self::ToOffnormal => 0,
            Self::ToFault => 1,
            Self::ToNormal => 2,
        }
    }
}

/// `BACnetEventTransitionBits` — a three-bit string ordered to-offnormal,
/// to-fault, to-normal. Used by `Event_Enable`, `Acked_Transitions` and the
/// notification class `Ack_Required`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventTransitionBits {
    /// to-offnormal bit.
    pub to_offnormal: bool,
    /// to-fault bit.
    pub to_fault: bool,
    /// to-normal bit.
    pub to_normal: bool,
}

impl EventTransitionBits {
    /// All three transitions set.
    pub const fn all() -> Self {
        Self {
            to_offnormal: true,
            to_fault: true,
            to_normal: true,
        }
    }

    /// No transitions set.
    pub const fn none() -> Self {
        Self {
            to_offnormal: false,
            to_fault: false,
            to_normal: false,
        }
    }

    /// Whether `transition` is set.
    pub fn contains(&self, transition: EventTransition) -> bool {
        match transition {
            EventTransition::ToOffnormal => self.to_offnormal,
            EventTransition::ToFault => self.to_fault,
            EventTransition::ToNormal => self.to_normal,
        }
    }

    /// Set or clear `transition`.
    pub fn set(&mut self, transition: EventTransition, value: bool) {
        match transition {
            EventTransition::ToOffnormal => self.to_offnormal = value,
            EventTransition::ToFault => self.to_fault = value,
            EventTransition::ToNormal => self.to_normal = value,
        }
    }

    /// The bit string in BACnet order.
    pub fn to_bits(self) -> Vec<bool> {
        vec![self.to_offnormal, self.to_fault, self.to_normal]
    }

    /// Read the bit string in BACnet order. Missing trailing bits read as `false`.
    pub fn from_bits(bits: &[bool]) -> Self {
        Self {
            to_offnormal: bits.first().copied().unwrap_or(false),
            to_fault: bits.get(1).copied().unwrap_or(false),
            to_normal: bits.get(2).copied().unwrap_or(false),
        }
    }
}

/// `BACnetNotifyType` — whether a notification is an alarm, a plain event, or an
/// acknowledgement notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyType {
    /// Alarm (0).
    Alarm,
    /// Event (1).
    Event,
    /// Acknowledgement notification (2).
    AckNotification,
}

impl From<NotifyType> for u32 {
    fn from(value: NotifyType) -> Self {
        match value {
            NotifyType::Alarm => 0,
            NotifyType::Event => 1,
            NotifyType::AckNotification => 2,
        }
    }
}

impl TryFrom<u32> for NotifyType {
    type Error = ObjectError;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Alarm),
            1 => Ok(Self::Event),
            2 => Ok(Self::AckNotification),
            _ => Err(ObjectError::InvalidPropertyType),
        }
    }
}

/// The timestamp BACnet uses for "no transition recorded yet": an unspecified time.
pub const UNSPECIFIED_TIMESTAMP: TimestampValue = TimestampValue::Time(255, 255, 255, 255);

/// What an event algorithm observed, in terms of the object's own value type.
///
/// This stays free of any wire representation so the object layer does not have
/// to depend on the service layer; [`crate::event`] maps it onto
/// `BACnetNotificationParameters`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AlarmTrigger {
    /// CHANGE_OF_STATE on a multi-state object.
    MultistateChange {
        /// The state the object moved to.
        new_state: u32,
    },
    /// CHANGE_OF_STATE on a binary object.
    BinaryChange {
        /// Whether Present_Value is now active.
        active: bool,
    },
    /// OUT_OF_RANGE on an analog object.
    OutOfRange {
        /// The value that breached the limit.
        exceeding_value: f32,
        /// The limit it breached.
        exceeded_limit: f32,
        /// Configured deadband.
        deadband: f32,
    },
    /// CHANGE_OF_RELIABILITY.
    ReliabilityChange {
        /// The object's current reliability.
        reliability: crate::object::Reliability,
    },
}

/// The outcome of running an object's event algorithm against its current value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AlarmEvaluation {
    /// The event state the algorithm currently demands.
    pub desired_state: EventState,
    /// Algorithm-specific detail for the notification.
    pub trigger: AlarmTrigger,
}

/// The four `Status_Flags` bits, in the BACnet in-alarm / fault / overridden /
/// out-of-service order.
///
/// Derived on read rather than stored. Every input is a property an object
/// already carries, and a byte cached alongside them goes stale the moment a
/// client writes one — which is exactly what happened: `Out_Of_Service` and
/// `Reliability` were writable while the cached byte was only recomputed on an
/// event transition, so `Status_Flags` contradicted both.
///
/// `overridden` is the one bit with no other source, so an object has to carry
/// it.
pub fn status_flags_bits(
    event_state: EventState,
    reliability: Reliability,
    out_of_service: bool,
    overridden: bool,
) -> Vec<bool> {
    vec![
        event_state != EventState::Normal,
        // Fault follows Reliability, not just Event_State: an object with event
        // detection disabled stays in the normal state but is still faulted.
        reliability != Reliability::NoFaultDetected || event_state == EventState::Fault,
        overridden,
        out_of_service,
    ]
}

/// Intrinsic reporting configuration and transition bookkeeping.
///
/// The event algorithm itself lives with the object (it depends on the object's
/// value type); this holds only what every algorithm shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrinsicReporting {
    /// Instance number of the notification class object that routes notifications.
    pub notification_class: u32,
    /// Seconds the algorithm's condition must persist before leaving `Normal`.
    pub time_delay: u32,
    /// Seconds the condition must clear before returning to `Normal`.
    /// `None` means reuse [`Self::time_delay`], per clause 12.
    pub time_delay_normal: Option<u32>,
    /// Which transitions generate notifications.
    pub event_enable: EventTransitionBits,
    /// Which transitions have been acknowledged. A set bit means "no ack pending".
    pub acked_transitions: EventTransitionBits,
    /// Whether notifications are alarms or plain events.
    pub notify_type: NotifyType,
    /// Master switch for event detection on this object.
    pub event_detection_enable: bool,
    /// Timestamps of the last to-offnormal, to-fault and to-normal transitions.
    pub event_time_stamps: [TimestampValue; 3],
}

impl IntrinsicReporting {
    /// Configuration reporting all three transitions through `notification_class`
    /// with no dwell time and nothing pending acknowledgement.
    pub fn new(notification_class: u32) -> Self {
        Self {
            notification_class,
            time_delay: 0,
            time_delay_normal: None,
            event_enable: EventTransitionBits::all(),
            acked_transitions: EventTransitionBits::all(),
            notify_type: NotifyType::Alarm,
            event_detection_enable: true,
            event_time_stamps: [
                UNSPECIFIED_TIMESTAMP,
                UNSPECIFIED_TIMESTAMP,
                UNSPECIFIED_TIMESTAMP,
            ],
        }
    }

    /// Seconds the condition must hold before transitioning to `state`.
    pub fn dwell_for(&self, state: EventState) -> u32 {
        if state == EventState::Normal {
            self.time_delay_normal.unwrap_or(self.time_delay)
        } else {
            self.time_delay
        }
    }

    /// Stamp the time of a completed transition.
    ///
    /// This follows the transition itself, so it happens whether or not a
    /// notification is sent. Acknowledgement is tracked separately by
    /// [`Self::await_acknowledgement`].
    pub fn record_transition(&mut self, state: EventState, at: TimestampValue) {
        self.event_time_stamps[EventTransition::for_state(state).bit_index()] = at;
    }

    /// Mark a transition as awaiting operator acknowledgement.
    ///
    /// Only a notification that was actually transmitted can be acknowledged.
    /// Clearing the bit for a transition nobody was told about would leave it
    /// clear forever, and `GetEventInformation` would advertise an outstanding
    /// alarm no client can ever clear.
    pub fn await_acknowledgement(&mut self, state: EventState) {
        self.acked_transitions
            .set(EventTransition::for_state(state), false);
    }

    /// Whether a notification should be sent for entering `state`.
    pub fn notifies(&self, state: EventState) -> bool {
        self.event_detection_enable
            && self
                .event_enable
                .contains(EventTransition::for_state(state))
    }
}

/// Read an intrinsic-reporting property.
///
/// Returns `None` when `property` is not an alarm property, so callers fall
/// through to their own match arms.
pub fn intrinsic_get(
    reporting: &IntrinsicReporting,
    property: PropertyIdentifier,
) -> Option<Result<PropertyValue>> {
    let value = match property {
        PropertyIdentifier::NotificationClass => {
            PropertyValue::Unsigned(reporting.notification_class.into())
        }
        PropertyIdentifier::TimeDelay => PropertyValue::Unsigned(reporting.time_delay.into()),
        PropertyIdentifier::TimeDelayNormal => PropertyValue::Unsigned(
            reporting
                .time_delay_normal
                .unwrap_or(reporting.time_delay)
                .into(),
        ),
        PropertyIdentifier::EventEnable => {
            PropertyValue::BitString(reporting.event_enable.to_bits())
        }
        PropertyIdentifier::AckedTransitions => {
            PropertyValue::BitString(reporting.acked_transitions.to_bits())
        }
        PropertyIdentifier::NotifyType => PropertyValue::Enumerated(reporting.notify_type.into()),
        PropertyIdentifier::EventDetectionEnable => {
            PropertyValue::Boolean(reporting.event_detection_enable)
        }
        PropertyIdentifier::EventTimeStamps => PropertyValue::Array(
            reporting
                .event_time_stamps
                .iter()
                .cloned()
                .map(PropertyValue::Timestamp)
                .collect(),
        ),
        _ => return None,
    };

    Some(Ok(value))
}

/// Write an intrinsic-reporting property.
///
/// Returns `None` when `property` is not an alarm property. `Acked_Transitions`
/// and `Event_Time_Stamps` are read-only: they are maintained by the event
/// algorithm, not by clients.
pub fn intrinsic_set(
    reporting: &mut IntrinsicReporting,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Option<Result<()>> {
    let result = match property {
        PropertyIdentifier::NotificationClass => match value {
            PropertyValue::Unsigned(class) => u32::try_from(class)
                .map(|class| reporting.notification_class = class)
                .map_err(|_| ObjectError::InvalidPropertyType),
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::TimeDelay => match value {
            PropertyValue::Unsigned(delay) => u32::try_from(delay)
                .map(|delay| reporting.time_delay = delay)
                .map_err(|_| ObjectError::InvalidPropertyType),
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::TimeDelayNormal => match value {
            PropertyValue::Unsigned(delay) => u32::try_from(delay)
                .map(|delay| reporting.time_delay_normal = Some(delay))
                .map_err(|_| ObjectError::InvalidPropertyType),
            PropertyValue::Null => {
                reporting.time_delay_normal = None;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::EventEnable => match value {
            PropertyValue::BitString(bits) => {
                reporting.event_enable = EventTransitionBits::from_bits(&bits);
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        // Only alarm and event configure an object. Ack-notification exists on
        // the wire but describes a notification, not a configuration: an object
        // set to it would emit notifications with no ack-required or from-state.
        PropertyIdentifier::NotifyType => match value {
            PropertyValue::Enumerated(raw) => match NotifyType::try_from(raw) {
                Ok(NotifyType::AckNotification) => Err(ObjectError::InvalidValue(
                    "Notify_Type must be alarm or event".to_string(),
                )),
                Ok(kind) => {
                    reporting.notify_type = kind;
                    Ok(())
                }
                Err(error) => Err(error),
            },
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::EventDetectionEnable => match value {
            PropertyValue::Boolean(enabled) => {
                reporting.event_detection_enable = enabled;
                Ok(())
            }
            _ => Err(ObjectError::InvalidPropertyType),
        },
        PropertyIdentifier::AckedTransitions | PropertyIdentifier::EventTimeStamps => {
            Err(ObjectError::PropertyNotWritable)
        }
        _ => return None,
    };

    Some(result)
}

/// Properties contributed by intrinsic reporting, for `property_list`.
pub fn intrinsic_property_list() -> Vec<PropertyIdentifier> {
    vec![
        PropertyIdentifier::NotificationClass,
        PropertyIdentifier::TimeDelay,
        PropertyIdentifier::TimeDelayNormal,
        PropertyIdentifier::EventEnable,
        PropertyIdentifier::AckedTransitions,
        PropertyIdentifier::NotifyType,
        PropertyIdentifier::EventDetectionEnable,
        PropertyIdentifier::EventTimeStamps,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_for_state_buckets_limits_as_offnormal() {
        assert_eq!(
            EventTransition::for_state(EventState::Normal),
            EventTransition::ToNormal
        );
        assert_eq!(
            EventTransition::for_state(EventState::Fault),
            EventTransition::ToFault
        );
        for state in [
            EventState::Offnormal,
            EventState::HighLimit,
            EventState::LowLimit,
        ] {
            assert_eq!(
                EventTransition::for_state(state),
                EventTransition::ToOffnormal
            );
        }
    }

    #[test]
    fn transition_bits_round_trip_in_bacnet_order() {
        let bits = EventTransitionBits {
            to_offnormal: true,
            to_fault: false,
            to_normal: true,
        };
        assert_eq!(bits.to_bits(), vec![true, false, true]);
        assert_eq!(EventTransitionBits::from_bits(&bits.to_bits()), bits);
        // A short bit string reads missing trailing bits as false.
        assert_eq!(
            EventTransitionBits::from_bits(&[true]),
            EventTransitionBits {
                to_offnormal: true,
                to_fault: false,
                to_normal: false,
            }
        );
    }

    #[test]
    fn dwell_falls_back_to_time_delay_for_normal() {
        let mut reporting = IntrinsicReporting::new(1);
        reporting.time_delay = 30;
        assert_eq!(reporting.dwell_for(EventState::Normal), 30);
        assert_eq!(reporting.dwell_for(EventState::Offnormal), 30);

        reporting.time_delay_normal = Some(5);
        assert_eq!(reporting.dwell_for(EventState::Normal), 5);
        assert_eq!(reporting.dwell_for(EventState::Offnormal), 30);
    }

    #[test]
    fn record_transition_stamps_without_touching_acknowledgement() {
        let mut reporting = IntrinsicReporting::new(1);
        let at = TimestampValue::Time(10, 20, 30, 0);

        reporting.record_transition(EventState::Offnormal, at.clone());
        assert_eq!(reporting.event_time_stamps[0], at);
        assert!(
            reporting.acked_transitions.to_offnormal,
            "stamping a transition does not make an ack outstanding"
        );

        reporting.record_transition(EventState::Normal, at.clone());
        assert_eq!(reporting.event_time_stamps[2], at);
    }

    #[test]
    fn await_acknowledgement_clears_only_its_own_transition() {
        let mut reporting = IntrinsicReporting::new(1);

        reporting.await_acknowledgement(EventState::HighLimit);

        assert!(
            !reporting.acked_transitions.to_offnormal,
            "a limit is an off-normal transition"
        );
        assert!(reporting.acked_transitions.to_fault);
        assert!(reporting.acked_transitions.to_normal);
    }

    #[test]
    fn notify_type_rejects_ack_notification_as_a_configuration() {
        let mut reporting = IntrinsicReporting::new(1);

        assert!(matches!(
            intrinsic_set(
                &mut reporting,
                PropertyIdentifier::NotifyType,
                PropertyValue::Enumerated(u32::from(NotifyType::AckNotification)),
            )
            .unwrap(),
            Err(ObjectError::InvalidValue(_))
        ));
        assert_eq!(reporting.notify_type, NotifyType::Alarm, "left unchanged");

        intrinsic_set(
            &mut reporting,
            PropertyIdentifier::NotifyType,
            PropertyValue::Enumerated(u32::from(NotifyType::Event)),
        )
        .unwrap()
        .unwrap();
        assert_eq!(reporting.notify_type, NotifyType::Event);
    }

    #[test]
    fn notifies_honours_event_enable_and_detection() {
        let mut reporting = IntrinsicReporting::new(1);
        assert!(reporting.notifies(EventState::Offnormal));

        reporting.event_enable.to_offnormal = false;
        assert!(!reporting.notifies(EventState::Offnormal));
        assert!(reporting.notifies(EventState::Fault));

        reporting.event_detection_enable = false;
        assert!(!reporting.notifies(EventState::Fault));
    }

    #[test]
    fn alarm_properties_round_trip_through_get_and_set() {
        let mut reporting = IntrinsicReporting::new(7);

        assert_eq!(
            intrinsic_get(&reporting, PropertyIdentifier::NotificationClass)
                .unwrap()
                .unwrap(),
            PropertyValue::Unsigned(7)
        );

        intrinsic_set(
            &mut reporting,
            PropertyIdentifier::TimeDelay,
            PropertyValue::Unsigned(45),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            intrinsic_get(&reporting, PropertyIdentifier::TimeDelay)
                .unwrap()
                .unwrap(),
            PropertyValue::Unsigned(45)
        );

        // Time_Delay_Normal reports Time_Delay until it is set explicitly.
        assert_eq!(
            intrinsic_get(&reporting, PropertyIdentifier::TimeDelayNormal)
                .unwrap()
                .unwrap(),
            PropertyValue::Unsigned(45)
        );

        intrinsic_set(
            &mut reporting,
            PropertyIdentifier::EventEnable,
            PropertyValue::BitString(vec![true, false, false]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            reporting.event_enable,
            EventTransitionBits {
                to_offnormal: true,
                to_fault: false,
                to_normal: false,
            }
        );
    }

    #[test]
    fn non_alarm_property_falls_through() {
        let mut reporting = IntrinsicReporting::new(1);
        assert!(intrinsic_get(&reporting, PropertyIdentifier::PresentValue).is_none());
        assert!(intrinsic_set(
            &mut reporting,
            PropertyIdentifier::PresentValue,
            PropertyValue::Unsigned(1)
        )
        .is_none());
    }

    #[test]
    fn algorithm_maintained_properties_are_read_only() {
        let mut reporting = IntrinsicReporting::new(1);
        assert!(matches!(
            intrinsic_set(
                &mut reporting,
                PropertyIdentifier::AckedTransitions,
                PropertyValue::BitString(vec![true, true, true])
            )
            .unwrap(),
            Err(ObjectError::PropertyNotWritable)
        ));
    }
}
