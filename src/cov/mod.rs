//! Change-of-value subscriptions and reporting.
//!
//! A subscriber asks the device to tell it when a property changes, instead of
//! polling for it. The device keeps a subscription table, watches the monitored
//! objects, and sends a [`CovNotification`] when a value moves far enough to
//! matter.
//!
//! "Far enough" is what `COV_Increment` decides for analog objects: without it, a
//! noisy sensor would emit a notification per evaluation. Discrete objects have no
//! increment, so any change reports.
//!
//! Like the event engine, time is passed in rather than read from a clock, so
//! subscription lifetimes are testable without sleeping.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use crate::object::{
    database::ObjectDatabase, ObjectIdentifier, PropertyIdentifier, PropertyValue,
};
use crate::service::cov_notification::{CovNotification, CovPropertyValue};

/// What identifies a subscription: the same subscriber may watch several objects,
/// and several subscribers may watch one.
///
/// The monitored property is part of the identity rather than of the subscription
/// body, because SubscribeCOVProperty lets one process watch several properties of
/// the same object at once. Keying without it would make each new property replace
/// the last, and a cancellation take the wrong one away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionKey {
    /// The subscriber's process identifier.
    pub process_identifier: u32,
    /// The object being watched.
    pub monitored_object: ObjectIdentifier,
    /// A single property to watch, for SubscribeCOVProperty. `None` means the
    /// standard set for the object type, which is what plain SubscribeCOV asks
    /// for.
    pub monitored_property: Option<PropertyIdentifier>,
    /// Where the subscriber lives.
    pub address: SocketAddr,
}

/// One live COV subscription.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// What identifies it.
    pub key: SubscriptionKey,
    /// Whether the subscriber wants confirmed notifications.
    pub confirmed: bool,
    /// Engine time in seconds when this expires; `None` never expires.
    pub expires_at: Option<u64>,
    /// Increment supplied with a SubscribeCOVProperty request, overriding the
    /// object's own `COV_Increment`.
    pub cov_increment: Option<f32>,
}

impl Subscription {
    /// Seconds until expiry, which is what a notification reports as
    /// `time_remaining`. A subscription that never expires reports 0.
    pub fn time_remaining(&self, now_seconds: u64) -> u32 {
        match self.expires_at {
            Some(expiry) => expiry
                .saturating_sub(now_seconds)
                .try_into()
                .unwrap_or(u32::MAX),
            None => 0,
        }
    }
}

/// The device's COV subscription table, shared between the request path that
/// maintains it and the reporting path that walks it.
#[derive(Clone, Default)]
pub struct CovSubscriptions {
    subscriptions: Arc<RwLock<HashMap<SubscriptionKey, Subscription>>>,
    /// The engine's clock, so a subscribe request arriving on the request thread
    /// can turn a lifetime into an expiry without reading a wall clock of its own.
    now_seconds: Arc<AtomicU64>,
}

impl CovSubscriptions {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// The engine's current time, as last published by [`CovEngine::tick`].
    pub fn now(&self) -> u64 {
        self.now_seconds.load(Ordering::Relaxed)
    }

    /// Publish the engine's clock for the request path to read.
    pub fn set_now(&self, seconds: u64) {
        self.now_seconds.store(seconds, Ordering::Relaxed);
    }

    /// Turn a requested lifetime into an expiry against the current clock.
    ///
    /// BACnet treats a lifetime of zero as "until cancelled", so it maps to no
    /// expiry rather than immediate death.
    pub fn expiry_for(&self, lifetime: Option<u32>) -> Option<u64> {
        match lifetime {
            None | Some(0) => None,
            Some(seconds) => Some(self.now() + u64::from(seconds)),
        }
    }

    /// Add a subscription, or renew one that already exists.
    ///
    /// Re-subscribing is how BACnet renews a lifetime, so an existing key is
    /// replaced rather than duplicated.
    pub fn subscribe(&self, subscription: Subscription) {
        self.subscriptions
            .write()
            .unwrap()
            .insert(subscription.key, subscription);
    }

    /// Remove a subscription. Returns whether one was there.
    pub fn cancel(&self, key: &SubscriptionKey) -> bool {
        self.subscriptions.write().unwrap().remove(key).is_some()
    }

    /// Drop everything that has expired, returning how many went.
    pub fn expire(&self, now_seconds: u64) -> usize {
        let mut subscriptions = self.subscriptions.write().unwrap();
        let before = subscriptions.len();
        subscriptions.retain(|_, subscription| match subscription.expires_at {
            Some(expiry) => expiry > now_seconds,
            None => true,
        });
        before - subscriptions.len()
    }

    /// Every live subscription.
    pub fn all(&self) -> Vec<Subscription> {
        self.subscriptions
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// How many subscriptions are held.
    pub fn len(&self) -> usize {
        self.subscriptions.read().unwrap().len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A notification and where it goes.
#[derive(Debug, Clone, PartialEq)]
pub struct AddressedCovNotification {
    /// The notification to send.
    pub notification: CovNotification,
    /// The subscriber's address.
    pub address: SocketAddr,
    /// Whether the subscriber asked for confirmed delivery.
    pub confirmed: bool,
}

/// Watches subscribed objects and reports changes.
pub struct CovEngine {
    device: ObjectIdentifier,
    /// The last value reported per subscription and property, which is what a
    /// change is measured against. Keyed by subscription so two subscribers with
    /// different increments are tracked independently.
    reported: HashMap<(SubscriptionKey, PropertyIdentifier), PropertyValue>,
}

impl CovEngine {
    /// Create an engine reporting `device_instance` as the initiating device.
    pub fn new(device_instance: u32) -> Self {
        Self {
            device: ObjectIdentifier::new(crate::object::ObjectType::Device, device_instance),
            reported: HashMap::new(),
        }
    }

    /// Expire stale subscriptions, then report any change worth sending.
    ///
    /// The first evaluation of a new subscription always reports, which gives the
    /// subscriber its initial value the way a real device does.
    pub fn tick(
        &mut self,
        database: &ObjectDatabase,
        subscriptions: &CovSubscriptions,
        now_seconds: u64,
    ) -> Vec<AddressedCovNotification> {
        subscriptions.set_now(now_seconds);
        subscriptions.expire(now_seconds);
        let live = subscriptions.all();

        // Forget tracking state for subscriptions that have gone away, so a
        // resubscribe starts clean rather than comparing against a stale value.
        //
        // Through a set rather than a scan per entry: a device with a gateway
        // subscribed to every point holds a baseline per subscription, and
        // searching the live list for each of them made a tick cost the square of
        // the subscription count — 46ms a second at ten thousand points, on a
        // thread that also has to drive every value and answer every request.
        let live_keys: HashSet<SubscriptionKey> =
            live.iter().map(|subscription| subscription.key).collect();
        self.reported.retain(|(key, _), _| live_keys.contains(key));

        let mut notifications = Vec::new();

        for subscription in live {
            // Read the monitored set once. The same snapshot decides whether to
            // report, goes on the wire, and becomes the next baseline — reading
            // twice could put one value in the decision and another in the
            // notification.
            let observed: Vec<(PropertyIdentifier, PropertyValue)> = self
                .monitored_properties(database, &subscription)
                .into_iter()
                .filter_map(|property| {
                    database
                        .get_property(subscription.key.monitored_object, property)
                        .ok()
                        .map(|value| (property, value))
                })
                .collect();

            let worth_sending = observed.iter().any(|(property, value)| {
                reportable(
                    self.reported.get(&(subscription.key, *property)),
                    value,
                    self.increment_for(database, &subscription, *property),
                )
            });
            if !worth_sending {
                // A property with no baseline always reports, so reaching here
                // means every one of them already has the value the subscriber
                // last received.
                continue;
            }

            // A change to one property reports the whole monitored set, so the
            // subscriber always sees Status_Flags alongside a value — and every
            // value it is told about becomes the new baseline. Leaving one behind
            // would measure the next increment from a value the subscriber
            // already has, and report again below COV_Increment.
            let list_of_values = observed
                .iter()
                .map(|(property, value)| CovPropertyValue::new(*property, value.clone()))
                .collect();
            for (property, value) in observed {
                self.reported.insert((subscription.key, property), value);
            }

            notifications.push(AddressedCovNotification {
                notification: CovNotification {
                    subscriber_process_identifier: subscription.key.process_identifier,
                    initiating_device: self.device,
                    monitored_object: subscription.key.monitored_object,
                    time_remaining: subscription.time_remaining(now_seconds),
                    list_of_values,
                },
                address: subscription.key.address,
                confirmed: subscription.confirmed,
            });
        }

        notifications
    }

    /// Which properties a subscription watches.
    ///
    /// SubscribeCOVProperty names one. Plain SubscribeCOV reports the pair
    /// clause 13.1 defines for the analog, binary and multi-state object types:
    /// Present_Value and Status_Flags.
    ///
    /// Reliability and Event_State are deliberately not included, though a
    /// subscriber might seem to want them. Adding a property widens the
    /// *trigger* as well as the payload, so a device sending them reports
    /// changes the standard says nothing about, and a conformance tool would
    /// flag it. Nothing is lost by leaving them out: Status_Flags carries the
    /// fault bit from Reliability and the in-alarm bit from Event_State, so a
    /// move in either still reports. A subscriber that wants the property
    /// itself can ask for it with SubscribeCOVProperty.
    fn monitored_properties(
        &self,
        _database: &ObjectDatabase,
        subscription: &Subscription,
    ) -> Vec<PropertyIdentifier> {
        match subscription.key.monitored_property {
            Some(property) => vec![property],
            None => vec![
                PropertyIdentifier::PresentValue,
                PropertyIdentifier::StatusFlags,
            ],
        }
    }

    /// The increment a property must move by before it is worth reporting.
    ///
    /// An increment supplied with SubscribeCOVProperty applies to the property
    /// that subscription named, whichever it is — such a subscription watches
    /// exactly one property, so there is nothing else it could mean. The object's
    /// own `COV_Increment` describes Present_Value alone.
    fn increment_for(
        &self,
        database: &ObjectDatabase,
        subscription: &Subscription,
        property: PropertyIdentifier,
    ) -> Option<f32> {
        if let Some(increment) = subscription.cov_increment {
            return Some(increment);
        }
        if property != PropertyIdentifier::PresentValue {
            return None;
        }
        match database.get_property(
            subscription.key.monitored_object,
            PropertyIdentifier::CovIncrement,
        ) {
            Ok(PropertyValue::Real(increment)) => Some(increment),
            _ => None,
        }
    }
}

/// Whether a value has moved enough to report.
///
/// A first observation always reports. An increment only applies to numbers; for
/// anything else, and for a change of value type, any difference reports.
fn reportable(
    previous: Option<&PropertyValue>,
    current: &PropertyValue,
    increment: Option<f32>,
) -> bool {
    let Some(previous) = previous else {
        return true;
    };

    match (previous, current, increment) {
        (PropertyValue::Real(before), PropertyValue::Real(now), Some(increment)) => {
            (now - before).abs() >= increment
        }
        _ => previous != current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{AnalogValue, Device, MultiStateValue, ObjectType};

    fn address() -> SocketAddr {
        "192.168.6.1:47808".parse().unwrap()
    }

    fn analog() -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::AnalogValue, 1)
    }

    fn database() -> Arc<ObjectDatabase> {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        let mut value = AnalogValue::new(1, "Zone temperature".to_string());
        value.present_value = 21.0;
        value.cov_increment = Some(0.5);
        database.add_object(Box::new(value)).unwrap();
        database
    }

    fn subscription(confirmed: bool, lifetime: Option<u64>) -> Subscription {
        Subscription {
            key: SubscriptionKey {
                process_identifier: 777,
                monitored_object: analog(),
                monitored_property: None,
                address: address(),
            },
            confirmed,
            expires_at: lifetime,
            cov_increment: None,
        }
    }

    /// Status_Flags used to be a cached byte only the event engine refreshed, so
    /// a subscriber was never told a point had been taken out of service or gone
    /// unreliable — the engine compared the stale byte against itself.
    #[test]
    fn taking_the_object_out_of_service_reports_to_the_subscriber() {
        let database = database();
        let subscriptions = CovSubscriptions::new();
        subscriptions.subscribe(subscription(false, None));
        let mut engine = CovEngine::new(1234);

        assert_eq!(
            engine.tick(&database, &subscriptions, 0).len(),
            1,
            "initial"
        );
        assert!(engine.tick(&database, &subscriptions, 1).is_empty(), "idle");

        database
            .set_property(
                analog(),
                PropertyIdentifier::OutOfService,
                PropertyValue::Boolean(true),
            )
            .unwrap();

        let notifications = engine.tick(&database, &subscriptions, 2);
        assert_eq!(notifications.len(), 1);
        assert!(
            notifications[0]
                .notification
                .list_of_values
                .iter()
                .any(
                    |entry| entry.property_identifier == PropertyIdentifier::StatusFlags
                        && entry.values
                            == vec![PropertyValue::BitString(vec![false, false, false, true])]
                ),
            "the subscriber is told the point is out of service: {:?}",
            notifications[0].notification.list_of_values
        );

        assert!(
            engine.tick(&database, &subscriptions, 3).is_empty(),
            "and not told twice"
        );
    }

    /// Every value that goes on the wire becomes the new baseline. Otherwise the
    /// increment is measured from a value the subscriber already received, and
    /// the next notification fires below COV_Increment.
    #[test]
    fn a_transmitted_value_becomes_the_baseline_even_when_it_did_not_trigger() {
        let database = database();
        let subscriptions = CovSubscriptions::new();
        subscriptions.subscribe(subscription(false, None));
        let mut engine = CovEngine::new(1234);
        engine.tick(&database, &subscriptions, 0);

        // Below the 0.5 increment, so this alone reports nothing.
        set_present_value(&database, 21.3);
        assert!(engine.tick(&database, &subscriptions, 1).is_empty());

        // Status_Flags moves, which sends the whole set including 21.3.
        database
            .set_property(
                analog(),
                PropertyIdentifier::OutOfService,
                PropertyValue::Boolean(true),
            )
            .unwrap();
        assert_eq!(engine.tick(&database, &subscriptions, 2).len(), 1);

        // 21.3 -> 21.6 is 0.3, under the increment. Measured from the original
        // 21.0 it would look like 0.6 and report.
        set_present_value(&database, 21.6);
        assert!(
            engine.tick(&database, &subscriptions, 3).is_empty(),
            "0.3 above the value the subscriber already has"
        );

        set_present_value(&database, 21.9);
        assert_eq!(
            engine.tick(&database, &subscriptions, 4).len(),
            1,
            "0.6 above it does report"
        );
    }

    fn set_present_value(database: &ObjectDatabase, value: f32) {
        database
            .set_property(
                analog(),
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(value),
            )
            .unwrap();
    }

    #[test]
    fn a_new_subscription_reports_its_initial_value() {
        let database = database();
        let subscriptions = CovSubscriptions::new();
        subscriptions.subscribe(subscription(false, None));
        let mut engine = CovEngine::new(1234);

        let notifications = engine.tick(&database, &subscriptions, 0);
        assert_eq!(notifications.len(), 1, "subscriber needs a starting value");
        assert_eq!(notifications[0].address, address());
        assert_eq!(
            notifications[0].notification.subscriber_process_identifier,
            777
        );

        // Nothing changed, so nothing more is sent.
        assert!(engine.tick(&database, &subscriptions, 1).is_empty());
    }

    #[test]
    fn the_cov_increment_suppresses_changes_that_are_too_small() {
        let database = database();
        let subscriptions = CovSubscriptions::new();
        subscriptions.subscribe(subscription(false, None));
        let mut engine = CovEngine::new(1234);
        assert_eq!(engine.tick(&database, &subscriptions, 0).len(), 1);

        // 0.2 is below the 0.5 increment.
        database
            .set_property(
                analog(),
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(21.2),
            )
            .unwrap();
        assert!(engine.tick(&database, &subscriptions, 1).is_empty());

        // 0.6 clears it.
        database
            .set_property(
                analog(),
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(21.6),
            )
            .unwrap();
        assert_eq!(engine.tick(&database, &subscriptions, 2).len(), 1);
    }

    #[test]
    fn a_notification_reports_the_whole_monitored_set() {
        let database = database();
        let subscriptions = CovSubscriptions::new();
        subscriptions.subscribe(subscription(false, None));
        let mut engine = CovEngine::new(1234);

        let notifications = engine.tick(&database, &subscriptions, 0);
        let reported: Vec<PropertyIdentifier> = notifications[0]
            .notification
            .list_of_values
            .iter()
            .map(|value| value.property_identifier)
            .collect();

        // The exact set, not merely a superset: an extra property widens the
        // trigger as well as the payload, so what is reported is a conformance
        // decision rather than a convenience.
        assert_eq!(
            reported,
            vec![
                PropertyIdentifier::PresentValue,
                PropertyIdentifier::StatusFlags
            ],
            "clause 13.1 pairs the value with its flags, and nothing else"
        );
    }

    #[test]
    fn a_discrete_object_reports_any_change() {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        database
            .add_object(Box::new(MultiStateValue::new(1, "Mode".to_string(), 5)))
            .unwrap();
        let object = ObjectIdentifier::new(ObjectType::MultiStateValue, 1);

        let subscriptions = CovSubscriptions::new();
        let mut key = subscription(false, None);
        key.key.monitored_object = object;
        subscriptions.subscribe(key);

        let mut engine = CovEngine::new(1234);
        assert_eq!(engine.tick(&database, &subscriptions, 0).len(), 1);

        database
            .set_property(
                object,
                PropertyIdentifier::PresentValue,
                PropertyValue::Unsigned(2),
            )
            .unwrap();
        assert_eq!(engine.tick(&database, &subscriptions, 1).len(), 1);
    }

    #[test]
    fn a_subscription_expires_and_stops_reporting() {
        let database = database();
        let subscriptions = CovSubscriptions::new();
        subscriptions.subscribe(subscription(false, Some(60)));
        let mut engine = CovEngine::new(1234);

        assert_eq!(engine.tick(&database, &subscriptions, 0).len(), 1);
        assert_eq!(subscriptions.len(), 1);

        database
            .set_property(
                analog(),
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(30.0),
            )
            .unwrap();
        assert!(engine.tick(&database, &subscriptions, 61).is_empty());
        assert!(subscriptions.is_empty(), "expired subscription was dropped");
    }

    #[test]
    fn time_remaining_counts_down_and_is_zero_when_permanent() {
        let expiring = subscription(false, Some(100));
        assert_eq!(expiring.time_remaining(40), 60);
        assert_eq!(
            expiring.time_remaining(200),
            0,
            "saturates rather than wraps"
        );
        assert_eq!(subscription(false, None).time_remaining(40), 0);
    }

    #[test]
    fn resubscribing_renews_rather_than_duplicating() {
        let subscriptions = CovSubscriptions::new();
        subscriptions.subscribe(subscription(false, Some(60)));
        subscriptions.subscribe(subscription(true, Some(600)));

        assert_eq!(subscriptions.len(), 1);
        let held = &subscriptions.all()[0];
        assert_eq!(held.expires_at, Some(600));
        assert!(held.confirmed, "the renewal's preference wins");
    }

    #[test]
    fn cancelling_removes_the_subscription() {
        let subscriptions = CovSubscriptions::new();
        let held = subscription(false, None);
        subscriptions.subscribe(held.clone());

        assert!(subscriptions.cancel(&held.key));
        assert!(subscriptions.is_empty());
        assert!(!subscriptions.cancel(&held.key), "already gone");
    }

    #[test]
    fn subscribe_cov_property_watches_only_that_property() {
        let database = database();
        let subscriptions = CovSubscriptions::new();
        let mut held = subscription(false, None);
        held.key.monitored_property = Some(PropertyIdentifier::PresentValue);
        held.cov_increment = Some(5.0);
        subscriptions.subscribe(held);

        let mut engine = CovEngine::new(1234);
        let notifications = engine.tick(&database, &subscriptions, 0);
        assert_eq!(notifications[0].notification.list_of_values.len(), 1);

        // The subscription's own increment overrides the object's 0.5.
        database
            .set_property(
                analog(),
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(23.0),
            )
            .unwrap();
        assert!(engine.tick(&database, &subscriptions, 1).is_empty());

        database
            .set_property(
                analog(),
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(27.0),
            )
            .unwrap();
        assert_eq!(engine.tick(&database, &subscriptions, 2).len(), 1);
    }

    /// One process may watch several properties of the same object. Keyed without
    /// the property, the second subscription would replace the first and the
    /// subscriber would silently stop hearing about it.
    #[test]
    fn two_properties_of_one_object_are_separate_subscriptions() {
        let database = database();
        let subscriptions = CovSubscriptions::new();

        let mut value = subscription(false, None);
        value.key.monitored_property = Some(PropertyIdentifier::PresentValue);
        subscriptions.subscribe(value);
        let mut flags = subscription(false, None);
        flags.key.monitored_property = Some(PropertyIdentifier::StatusFlags);
        subscriptions.subscribe(flags);

        assert_eq!(subscriptions.len(), 2);

        let mut engine = CovEngine::new(1234);
        let notifications = engine.tick(&database, &subscriptions, 0);
        assert_eq!(notifications.len(), 2, "each reports its own property");

        set_present_value(&database, 30.0);
        let notifications = engine.tick(&database, &subscriptions, 1);
        assert_eq!(notifications.len(), 1, "only the one watching the value");
        assert_eq!(
            notifications[0].notification.list_of_values[0].property_identifier,
            PropertyIdentifier::PresentValue
        );
    }

    /// An increment given with SubscribeCOVProperty applies to whatever property
    /// that subscription named, not only to Present_Value.
    #[test]
    fn a_subscription_increment_applies_to_the_property_it_named() {
        let database = Arc::new(ObjectDatabase::new(Device::new(1234, "Test".to_string())));
        let value = AnalogValue::new(1, "Zone temperature".to_string())
            .with_out_of_range_reporting(1, Some(15.0), Some(30.0), 1.0);
        database.add_object(Box::new(value)).unwrap();

        let subscriptions = CovSubscriptions::new();
        let mut held = subscription(false, None);
        held.key.monitored_property = Some(PropertyIdentifier::HighLimit);
        held.cov_increment = Some(1.0);
        subscriptions.subscribe(held);

        let mut engine = CovEngine::new(1234);
        assert_eq!(engine.tick(&database, &subscriptions, 0).len(), 1);

        // High_Limit is the monitored property, so the subscription's increment
        // is what it has to move by: 30.0 to 30.4 is not enough.
        set_high_limit(&database, 30.4);
        assert!(engine.tick(&database, &subscriptions, 1).is_empty());

        set_high_limit(&database, 32.0);
        assert_eq!(engine.tick(&database, &subscriptions, 2).len(), 1);
    }

    fn set_high_limit(database: &ObjectDatabase, limit: f32) {
        database
            .set_property(
                analog(),
                PropertyIdentifier::HighLimit,
                PropertyValue::Real(limit),
            )
            .unwrap();
    }

    #[test]
    fn two_subscribers_are_tracked_independently() {
        let database = database();
        let subscriptions = CovSubscriptions::new();
        subscriptions.subscribe(subscription(false, None));
        let mut other = subscription(false, None);
        other.key.process_identifier = 888;
        other.key.address = "192.168.6.2:47808".parse().unwrap();
        subscriptions.subscribe(other);

        let mut engine = CovEngine::new(1234);
        assert_eq!(engine.tick(&database, &subscriptions, 0).len(), 2);

        database
            .set_property(
                analog(),
                PropertyIdentifier::PresentValue,
                PropertyValue::Real(25.0),
            )
            .unwrap();
        assert_eq!(engine.tick(&database, &subscriptions, 1).len(), 2);
    }
}
