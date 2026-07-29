//! Intrinsic reporting engine.
//!
//! Objects decide *what* their event algorithm currently demands (see
//! [`BacnetObject::evaluate_alarm`]); this module decides *when* that becomes a
//! transition and turns it into an [`EventNotification`].
//!
//! A transition only commits once the condition has held for the object's
//! `Time_Delay` (or `Time_Delay_Normal` returning to normal). Without that
//! dwell, a value sitting on a limit would emit a notification per tick.
//!
//! The engine takes time as an argument rather than reading a clock, so dwell
//! behaviour is testable and the caller keeps control of its time source.

use crate::object::{
    database::ObjectDatabase,
    intrinsic::{AlarmTrigger, EventTransition},
    notification_class::DEFAULT_PRIORITY,
    EventState, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
};
use crate::property::{DestinationValue, TimestampValue};
use crate::service::event_notification::{
    EventNotification, NotificationParameters, PropertyStates, StatusFlags,
};

use std::collections::HashMap;

/// A notification together with the `Recipient_List` entry it belongs to.
///
/// The engine resolves *which* recipients want a transition and what process
/// identifier each expects; turning the recipient into a network address is the
/// caller's job, since only it owns a socket.
#[derive(Debug, Clone, PartialEq)]
pub struct AddressedNotification {
    /// The notification to send, with this recipient's process identifier.
    pub notification: EventNotification,
    /// The Recipient_List entry that asked for it.
    pub destination: DestinationValue,
}

/// A transition whose condition is waiting out its dwell time.
#[derive(Debug, Clone, Copy)]
struct Pending {
    /// The state the algorithm wants to move to.
    target: EventState,
    /// Engine time, in seconds, when the condition first held.
    since: u64,
}

/// Drives intrinsic reporting across every alarm-capable object in a database.
pub struct EventEngine {
    /// The device whose objects are being evaluated; reported as the
    /// initiating device in notifications.
    device: ObjectIdentifier,
    /// Conditions still waiting out their dwell time, keyed by object.
    pending: HashMap<ObjectIdentifier, Pending>,
}

impl EventEngine {
    /// Create an engine reporting `device_instance` as the initiating device.
    pub fn new(device_instance: u32) -> Self {
        Self {
            device: ObjectIdentifier::new(ObjectType::Device, device_instance),
            pending: HashMap::new(),
        }
    }

    /// Evaluate every alarm-capable object and commit any transition whose dwell
    /// time has elapsed.
    ///
    /// `now_seconds` is a monotonic engine clock used only for dwell arithmetic;
    /// `timestamp` is what goes on the wire. Returns one notification per
    /// committed transition, already addressed to nothing in particular — the
    /// caller resolves recipients from the notification class.
    pub fn tick(
        &mut self,
        database: &ObjectDatabase,
        now_seconds: u64,
        timestamp: TimestampValue,
    ) -> Vec<AddressedNotification> {
        let mut notifications = Vec::new();

        for identifier in database.get_all_objects() {
            notifications.extend(self.evaluate_object(
                database,
                identifier,
                now_seconds,
                timestamp.clone(),
            ));
        }

        notifications
    }

    /// Evaluate one object, committing a transition if its dwell has elapsed.
    fn evaluate_object(
        &mut self,
        database: &ObjectDatabase,
        identifier: ObjectIdentifier,
        now_seconds: u64,
        timestamp: TimestampValue,
    ) -> Vec<AddressedNotification> {
        let Some(state) = database.with_object(identifier, |object| {
            let evaluation = object.evaluate_alarm()?;
            let reporting = object.intrinsic()?;
            let current_state = match object.get_property(PropertyIdentifier::EventState) {
                Ok(PropertyValue::Enumerated(raw)) => EventState::from(raw as u16),
                _ => EventState::Normal,
            };
            Some((
                evaluation,
                current_state,
                reporting.dwell_for(evaluation.desired_state),
                object.is_out_of_service(),
                reporting.notification_class,
                reporting.notify_type,
            ))
        }) else {
            return Vec::new();
        };
        let Some((
            evaluation,
            current_state,
            dwell,
            out_of_service,
            notification_class,
            notify_type,
        )) = state
        else {
            return Vec::new();
        };

        if evaluation.desired_state == current_state {
            self.pending.remove(&identifier);
            return Vec::new();
        }

        // Start, or continue, the dwell for this condition.
        let pending = self.pending.entry(identifier).or_insert(Pending {
            target: evaluation.desired_state,
            since: now_seconds,
        });
        if pending.target != evaluation.desired_state {
            pending.target = evaluation.desired_state;
            pending.since = now_seconds;
        }
        if now_seconds.saturating_sub(pending.since) < u64::from(dwell) {
            return Vec::new();
        }
        self.pending.remove(&identifier);

        let transition = EventTransition::for_state(evaluation.desired_state);
        let (priority, ack_required) =
            notification_class_settings(database, notification_class, transition);

        // Commit the transition itself. Event_State and the timestamp follow the
        // transition, so they are updated whether or not anyone is told.
        let notifies = database
            .with_object_mut(identifier, |object| {
                object.apply_event_state(evaluation.desired_state);
                let reporting = object.intrinsic_mut()?;
                reporting.record_transition(evaluation.desired_state, timestamp.clone());
                Some(reporting.notifies(evaluation.desired_state))
            })
            .flatten();
        let Some(notifies) = notifies else {
            return Vec::new();
        };

        if !notifies {
            return Vec::new();
        }

        let base = EventNotification {
            process_identifier: 0,
            initiating_device: self.device,
            event_object: identifier,
            timestamp,
            notification_class,
            priority,
            notify_type,
            ack_required,
            from_state: current_state,
            to_state: evaluation.desired_state,
            message_text: None,
            parameters: parameters_for(
                evaluation.trigger,
                StatusFlags::for_event_state(evaluation.desired_state, out_of_service),
            ),
        };

        // One notification per subscribed recipient, each carrying the process
        // identifier that recipient registered with.
        let recipients = notification_class_recipients(database, notification_class, transition);

        // Only now is a notification genuinely going out, so only now can an
        // acknowledgement be outstanding. With no recipients nothing is sent and
        // nothing is pending.
        if ack_required && !recipients.is_empty() {
            database.with_object_mut(identifier, |object| {
                if let Some(reporting) = object.intrinsic_mut() {
                    reporting.await_acknowledgement(evaluation.desired_state);
                }
            });
        }

        recipients
            .into_iter()
            .map(|destination| AddressedNotification {
                notification: EventNotification {
                    process_identifier: destination.process_identifier,
                    ..base.clone()
                },
                destination,
            })
            .collect()
    }
}

/// The Recipient_List entries of `instance` that subscribe to `transition`.
///
/// The per-entry day and time window is not applied: it needs a wall clock the
/// engine deliberately does not own, and a recipient that registers itself
/// normally asks for every day and the full day.
fn notification_class_recipients(
    database: &ObjectDatabase,
    instance: u32,
    transition: EventTransition,
) -> Vec<DestinationValue> {
    let identifier = ObjectIdentifier::new(ObjectType::NotificationClass, instance);
    let index = transition.bit_index();

    let Ok(PropertyValue::List(entries)) =
        database.get_property(identifier, PropertyIdentifier::RecipientList)
    else {
        return Vec::new();
    };

    entries
        .into_iter()
        .filter_map(|entry| match entry {
            PropertyValue::Destination(destination) => Some(destination),
            _ => None,
        })
        .filter(|destination| destination.transitions.get(index).copied().unwrap_or(false))
        .collect()
}

/// Look up the priority and acknowledgement policy for `transition`.
///
/// Falls back to the lowest priority and no acknowledgement when the referenced
/// notification class is absent, which keeps a misconfigured object reporting
/// rather than silent.
fn notification_class_settings(
    database: &ObjectDatabase,
    instance: u32,
    transition: EventTransition,
) -> (u32, bool) {
    let identifier = ObjectIdentifier::new(ObjectType::NotificationClass, instance);
    let index = transition.bit_index();

    let priority = database
        .get_property(identifier, PropertyIdentifier::Priority)
        .ok()
        .and_then(|value| match value {
            PropertyValue::Array(entries) => match entries.into_iter().nth(index) {
                Some(PropertyValue::Unsigned(priority)) => Some(priority as u32),
                _ => None,
            },
            _ => None,
        })
        .unwrap_or(DEFAULT_PRIORITY);

    let ack_required = database
        .get_property(identifier, PropertyIdentifier::AckRequired)
        .ok()
        .and_then(|value| match value {
            PropertyValue::BitString(bits) => bits.get(index).copied(),
            _ => None,
        })
        .unwrap_or(false);

    (priority, ack_required)
}

/// Map an algorithm's observation onto the wire parameters for its event type.
fn parameters_for(trigger: AlarmTrigger, status_flags: StatusFlags) -> NotificationParameters {
    match trigger {
        AlarmTrigger::MultistateChange { new_state } => NotificationParameters::ChangeOfState {
            new_state: PropertyStates::UnsignedValue(new_state),
            status_flags,
        },
        AlarmTrigger::BinaryChange { active } => NotificationParameters::ChangeOfState {
            new_state: PropertyStates::BinaryValue(active),
            status_flags,
        },
        AlarmTrigger::OutOfRange {
            exceeding_value,
            exceeded_limit,
            deadband,
        } => NotificationParameters::OutOfRange {
            exceeding_value,
            status_flags,
            deadband,
            exceeded_limit,
        },
        AlarmTrigger::ReliabilityChange { reliability } => {
            NotificationParameters::ChangeOfReliability {
                reliability,
                status_flags,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{
        AnalogValue, BinaryPV, BinaryValue, Device, EventTransitionBits, MultiStateValue,
        NotificationClass,
    };
    use std::sync::Arc;

    const NC: u32 = 1;

    fn stamp() -> TimestampValue {
        TimestampValue::SequenceNumber(1)
    }

    /// The recipient a gateway would register itself as.
    fn gateway() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::Device, 5785)
    }

    fn database() -> Arc<ObjectDatabase> {
        database_with_recipients(true)
    }

    fn database_with_recipients(registered: bool) -> Arc<ObjectDatabase> {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        let mut class = NotificationClass::new(NC, "NC".to_string())
            .with_priority(90, 10, 200)
            .with_ack_required(EventTransitionBits {
                to_offnormal: false,
                to_fault: true,
                to_normal: false,
            });
        if registered {
            class = class.with_recipient(gateway(), 777);
        }
        database.add_object(Box::new(class)).unwrap();
        database
    }

    #[test]
    fn multistate_entering_an_alarm_state_notifies_once() {
        let database = database();
        database
            .add_object(Box::new(
                MultiStateValue::new(1, "Mode".to_string(), 5)
                    .with_intrinsic_reporting(NC, vec![2, 5]),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let mut engine = EventEngine::new(1234);

        // State 1 is not an alarm value.
        assert!(engine.tick(&database, 0, stamp()).is_empty());

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(5),
            )
            .unwrap();

        let notifications = engine.tick(&database, 1, stamp());
        assert_eq!(notifications.len(), 1);
        let notification = &notifications[0].notification;
        assert_eq!(notification.event_object, object);
        assert_eq!(notification.from_state, EventState::Normal);
        assert_eq!(notification.to_state, EventState::Offnormal);
        assert_eq!(notification.priority, 90, "to-offnormal priority");
        assert!(!notification.ack_required);
        assert_eq!(
            notification.parameters,
            NotificationParameters::ChangeOfState {
                new_state: PropertyStates::UnsignedValue(5),
                status_flags: StatusFlags {
                    in_alarm: true,
                    fault: false,
                    overridden: false,
                    out_of_service: false,
                },
            }
        );

        // The condition has not changed, so nothing more is reported.
        assert!(engine.tick(&database, 2, stamp()).is_empty());
    }

    #[test]
    fn returning_to_normal_notifies_with_the_to_normal_priority() {
        let database = database();
        database
            .add_object(Box::new(
                MultiStateValue::new(1, "Mode".to_string(), 5)
                    .with_intrinsic_reporting(NC, vec![2]),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();
        assert_eq!(engine.tick(&database, 0, stamp()).len(), 1);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(1),
            )
            .unwrap();
        let notifications = engine.tick(&database, 1, stamp());
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0].notification.from_state,
            EventState::Offnormal
        );
        assert_eq!(notifications[0].notification.to_state, EventState::Normal);
        assert_eq!(
            notifications[0].notification.priority, 200,
            "to-normal priority"
        );
    }

    #[test]
    fn time_delay_holds_the_transition_until_the_condition_persists() {
        let database = database();
        let mut modes =
            MultiStateValue::new(1, "Mode".to_string(), 5).with_intrinsic_reporting(NC, vec![2]);
        modes.alarm.as_mut().unwrap().time_delay = 30;
        database.add_object(Box::new(modes)).unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();

        assert!(
            engine.tick(&database, 100, stamp()).is_empty(),
            "dwell starts"
        );
        assert!(
            engine.tick(&database, 129, stamp()).is_empty(),
            "29s elapsed"
        );
        assert_eq!(engine.tick(&database, 130, stamp()).len(), 1, "30s elapsed");
    }

    #[test]
    fn a_condition_that_clears_during_its_dwell_never_notifies() {
        let database = database();
        let mut modes =
            MultiStateValue::new(1, "Mode".to_string(), 5).with_intrinsic_reporting(NC, vec![2]);
        modes.alarm.as_mut().unwrap().time_delay = 30;
        database.add_object(Box::new(modes)).unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();
        assert!(engine.tick(&database, 0, stamp()).is_empty());

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(1),
            )
            .unwrap();
        assert!(
            engine.tick(&database, 60, stamp()).is_empty(),
            "condition cleared"
        );
    }

    #[test]
    fn binary_alarm_value_reports_a_binary_property_state() {
        let database = database();
        database
            .add_object(Box::new(
                BinaryValue::new(1, "Pump".to_string())
                    .with_intrinsic_reporting(NC, BinaryPV::Active),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::BinaryValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Enumerated(1),
            )
            .unwrap();

        let notifications = engine.tick(&database, 0, stamp());
        assert_eq!(notifications.len(), 1);
        assert!(matches!(
            notifications[0].notification.parameters,
            NotificationParameters::ChangeOfState {
                new_state: PropertyStates::BinaryValue(true),
                ..
            }
        ));
    }

    #[test]
    fn analog_high_limit_reports_out_of_range_and_honours_the_deadband() {
        let database = database();
        database
            .add_object(Box::new(
                AnalogValue::new(1, "Temp".to_string()).with_out_of_range_reporting(
                    NC,
                    Some(18.0),
                    Some(24.0),
                    0.5,
                ),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(25.0),
            )
            .unwrap();
        let notifications = engine.tick(&database, 0, stamp());
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0].notification.to_state,
            EventState::HighLimit
        );
        assert_eq!(
            notifications[0].notification.parameters,
            NotificationParameters::OutOfRange {
                exceeding_value: 25.0,
                status_flags: StatusFlags {
                    in_alarm: true,
                    fault: false,
                    overridden: false,
                    out_of_service: false,
                },
                deadband: 0.5,
                exceeded_limit: 24.0,
            }
        );

        // Inside the deadband: still above 24.0 - 0.5, so it stays in high-limit.
        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(23.8),
            )
            .unwrap();
        assert!(
            engine.tick(&database, 1, stamp()).is_empty(),
            "within deadband"
        );

        // Past the deadband, it returns to normal.
        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(23.0),
            )
            .unwrap();
        let notifications = engine.tick(&database, 2, stamp());
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].notification.to_state, EventState::Normal);
    }

    #[test]
    fn a_fault_takes_precedence_and_requires_acknowledgement() {
        let database = database();
        database
            .add_object(Box::new(
                MultiStateValue::new(1, "Mode".to_string(), 5)
                    .with_intrinsic_reporting(NC, vec![2]),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::Reliability,
                PropertyValue::Enumerated(u32::from(crate::object::Reliability::MultiStateFault)),
            )
            .unwrap();

        let notifications = engine.tick(&database, 0, stamp());
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].notification.to_state, EventState::Fault);
        assert_eq!(
            notifications[0].notification.priority, 10,
            "to-fault priority"
        );
        assert!(
            notifications[0].notification.ack_required,
            "notification class wants an ack"
        );
    }

    /// Acked_Transitions must only go pending for a notification that was
    /// actually sent: nobody can acknowledge one they never received, so the bit
    /// would stay clear forever and GetEventInformation would advertise an alarm
    /// no client can clear.
    #[test]
    fn a_masked_transition_leaves_no_acknowledgement_outstanding() {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        database
            .add_object(Box::new(
                NotificationClass::new(NC, "NC".to_string())
                    .with_ack_required(EventTransitionBits::all())
                    .with_recipient(gateway(), 777),
            ))
            .unwrap();

        let mut modes =
            MultiStateValue::new(1, "Mode".to_string(), 5).with_intrinsic_reporting(NC, vec![2]);
        modes.alarm.as_mut().unwrap().event_enable = EventTransitionBits {
            to_offnormal: false,
            to_fault: true,
            to_normal: true,
        };
        let object = modes.identifier;
        database.add_object(Box::new(modes)).unwrap();

        let mut engine = EventEngine::new(1234);
        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();

        assert!(engine.tick(&database, 0, stamp()).is_empty(), "masked");
        assert_eq!(
            database
                .get_property(object, PropertyIdentifier::EventState)
                .unwrap(),
            PropertyValue::Enumerated(u16::from(EventState::Offnormal).into()),
            "the transition still happened"
        );
        assert_eq!(
            database
                .get_property(object, PropertyIdentifier::AckedTransitions)
                .unwrap(),
            PropertyValue::BitString(vec![true, true, true]),
            "nothing was sent, so nothing is awaiting acknowledgement"
        );
    }

    #[test]
    fn a_transmitted_transition_does_leave_an_acknowledgement_outstanding() {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        database
            .add_object(Box::new(
                NotificationClass::new(NC, "NC".to_string())
                    .with_ack_required(EventTransitionBits::all())
                    .with_recipient(gateway(), 777),
            ))
            .unwrap();
        database
            .add_object(Box::new(
                MultiStateValue::new(1, "Mode".to_string(), 5)
                    .with_intrinsic_reporting(NC, vec![2]),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);

        let mut engine = EventEngine::new(1234);
        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();

        assert_eq!(engine.tick(&database, 0, stamp()).len(), 1);
        assert_eq!(
            database
                .get_property(object, PropertyIdentifier::AckedTransitions)
                .unwrap(),
            PropertyValue::BitString(vec![false, true, true]),
            "to-offnormal is awaiting acknowledgement"
        );
    }

    /// A recipient needs to know which limit it is recovering from. Reporting the
    /// high limit for a low-limit recovery publishes a threshold that contradicts
    /// the state pair.
    #[test]
    fn a_low_limit_recovery_reports_the_low_limit() {
        let database = database();
        database
            .add_object(Box::new(
                AnalogValue::new(1, "Temp".to_string()).with_out_of_range_reporting(
                    NC,
                    Some(18.0),
                    Some(24.0),
                    0.5,
                ),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(17.0),
            )
            .unwrap();
        let tripped = engine.tick(&database, 0, stamp());
        assert_eq!(tripped[0].notification.to_state, EventState::LowLimit);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(21.0),
            )
            .unwrap();
        let recovered = engine.tick(&database, 1, stamp());

        assert_eq!(recovered[0].notification.to_state, EventState::Normal);
        assert_eq!(
            recovered[0].notification.parameters,
            NotificationParameters::OutOfRange {
                exceeding_value: 21.0,
                status_flags: StatusFlags::default(),
                deadband: 0.5,
                exceeded_limit: 18.0,
            },
            "the low limit is what was breached"
        );
    }

    #[test]
    fn objects_without_reporting_are_ignored() {
        let database = database();
        database
            .add_object(Box::new(MultiStateValue::new(1, "Mode".to_string(), 5)))
            .unwrap();
        let mut engine = EventEngine::new(1234);
        assert!(engine.tick(&database, 0, stamp()).is_empty());
    }

    #[test]
    fn each_notification_carries_the_recipients_process_identifier() {
        let database = database();
        database
            .add_object(Box::new(
                MultiStateValue::new(1, "Mode".to_string(), 5)
                    .with_intrinsic_reporting(NC, vec![2]),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();

        let notifications = engine.tick(&database, 0, stamp());
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0].notification.process_identifier, 777,
            "must echo the process identifier the recipient registered with"
        );
        assert_eq!(
            notifications[0].destination.recipient,
            crate::property::Recipient::Device(gateway())
        );
    }

    /// A device with nobody registered still tracks its own event state; it just
    /// has no one to tell.
    #[test]
    fn with_no_recipients_the_transition_is_applied_but_nothing_is_sent() {
        let database = database_with_recipients(false);
        database
            .add_object(Box::new(
                MultiStateValue::new(1, "Mode".to_string(), 5)
                    .with_intrinsic_reporting(NC, vec![2]),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();

        assert!(engine.tick(&database, 0, stamp()).is_empty());
        assert_eq!(
            database
                .get_property(object, PropertyIdentifier::EventState)
                .unwrap(),
            PropertyValue::Enumerated(u16::from(EventState::Offnormal).into()),
            "event state still advanced"
        );
    }

    #[test]
    fn a_recipient_subscribed_to_one_transition_only_hears_that_one() {
        let database = database();
        let class = ObjectIdentifier::new(ObjectType::NotificationClass, NC);
        // Narrow the registration to to-normal.
        database
            .with_object_mut(class, |object| {
                if let Ok(PropertyValue::List(mut entries)) =
                    object.get_property(PropertyIdentifier::RecipientList)
                {
                    if let Some(PropertyValue::Destination(destination)) = entries.first_mut() {
                        destination.transitions = vec![false, false, true];
                    }
                    let _ = object.set_property(
                        PropertyIdentifier::RecipientList,
                        PropertyValue::List(entries),
                    );
                }
            })
            .unwrap();

        database
            .add_object(Box::new(
                MultiStateValue::new(1, "Mode".to_string(), 5)
                    .with_intrinsic_reporting(NC, vec![2]),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let mut engine = EventEngine::new(1234);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();
        assert!(
            engine.tick(&database, 0, stamp()).is_empty(),
            "not subscribed to to-offnormal"
        );

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(1),
            )
            .unwrap();
        let notifications = engine.tick(&database, 1, stamp());
        assert_eq!(notifications.len(), 1, "subscribed to to-normal");
        assert_eq!(notifications[0].notification.to_state, EventState::Normal);
    }

    #[test]
    fn a_recipient_asking_for_confirmed_delivery_is_reported_as_such() {
        let database = database();
        database
            .add_object(Box::new(
                MultiStateValue::new(1, "Mode".to_string(), 5)
                    .with_intrinsic_reporting(NC, vec![2]),
            ))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);
        let class = ObjectIdentifier::new(ObjectType::NotificationClass, NC);

        database
            .with_object_mut(class, |o| {
                if let Ok(PropertyValue::List(mut entries)) =
                    o.get_property(PropertyIdentifier::RecipientList)
                {
                    if let Some(PropertyValue::Destination(d)) = entries.first_mut() {
                        d.issue_confirmed_notifications = true;
                    }
                    let _ = o.set_property(
                        PropertyIdentifier::RecipientList,
                        PropertyValue::List(entries),
                    );
                }
            })
            .unwrap();

        let mut engine = EventEngine::new(1234);
        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();

        let notifications = engine.tick(&database, 0, stamp());
        assert_eq!(notifications.len(), 1);
        assert!(
            notifications[0].destination.issue_confirmed_notifications,
            "the caller needs this to pick the confirmed service"
        );
    }
}
