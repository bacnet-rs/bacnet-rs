//! Host a BACnet/IP device that performs intrinsic reporting (alarms and events).
//!
//! The device exposes one object per event algorithm, each pointed at a
//! notification class, so a gateway can read the alarm configuration, register
//! itself for notifications, and receive them:
//!
//! - `multi-state-value,1` — CHANGE_OF_STATE, alarms on states 2 and 5
//! - `binary-value,1` — CHANGE_OF_STATE, alarms when Active
//! - `analog-value,1` — OUT_OF_RANGE, limits 18.0 / 24.0 with a 0.5 deadband
//! - `analog-value,2` — CHANGE_OF_RELIABILITY (no limits configured)
//! - `notification-class,1` — priorities 90/10/200, acknowledgement on to-fault
//!
//! Notifications go to whoever has written themselves into the notification
//! class's `Recipient_List`, using the process identifier and the
//! confirmed/unconfirmed choice from their own entry. The device learns a
//! recipient's address from the WriteProperty that registers it.
//!
//! The device also serves `SubscribeCOV`, so a subscriber can watch
//! Present_Value instead of polling it. Analog objects honour `COV_Increment`
//! (0.5 on `analog-value,1`), so small movements do not report.
//!
//! Runtime state — registrations, present values, event states and learned
//! addresses — is persisted, so a restart resumes rather than resets. Set
//! `ALARM_DEVICE_STATE` to choose the file; the default is printed at startup.
//!
//! ```text
//! cargo run --example alarm_device -- 0.0.0.0:47808 1234
//!
//! # Read the multistate alarm configuration (object type 19, instance 1).
//! BACNET_IFACE=lo bacrp -t 7F:00:00:02:BA:C0 1234 19 1 7    # Alarm_Values
//! BACNET_IFACE=lo bacrp -t 7F:00:00:02:BA:C0 1234 19 1 110  # State_Text
//!
//! # Start over from defaults.
//! rm "$ALARM_DEVICE_STATE"
//! ```

use std::{
    collections::HashMap,
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use bacnet_rs::{
    cov::CovEngine,
    event::EventEngine,
    object::{
        database::ObjectDatabase, AnalogValue, BinaryPV, BinaryValue, Device, EventState,
        EventTransitionBits, MultiStateValue, NotificationClass, ObjectIdentifier, ObjectType,
        PropertyIdentifier, PropertyValue,
    },
    property::{DestinationValue, TimestampValue},
    server::{AddressCache, BacnetIpServer, NotificationTarget},
};
use serde::{Deserialize, Serialize};

/// Instance number of the notification class every alarming object reports through.
const NOTIFICATION_CLASS: u32 = 1;

/// Everything that must survive a restart.
///
/// Only runtime state is persisted; the object set and its alarm limits come from
/// the code below, so editing them takes effect on the next start.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
struct PersistedState {
    /// Recipients that registered themselves for notifications.
    recipients: Vec<DestinationValue>,
    /// Learned device-to-address bindings, as `instance -> "ip:port"`.
    bindings: HashMap<u32, String>,
    /// Present values, keyed `"object-type,instance"`.
    present_values: HashMap<String, f64>,
    /// Event states, so a restart does not re-announce a standing alarm.
    event_states: HashMap<String, u16>,
}

fn state_path() -> PathBuf {
    env::var("ALARM_DEVICE_STATE")
        .map(PathBuf::from)
        // temp_dir resolves per platform, so this works on Windows too.
        .unwrap_or_else(|_| env::temp_dir().join("bacnet-rs-alarm-device-state.json"))
}

fn object_key(identifier: ObjectIdentifier) -> String {
    format!("{:?},{}", identifier.object_type, identifier.instance)
}

fn load_state(path: &PathBuf) -> PersistedState {
    match fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|error| {
            eprintln!("ignoring unreadable state file {}: {error}", path.display());
            PersistedState::default()
        }),
        Err(_) => PersistedState::default(),
    }
}

/// Write the snapshot, via a temporary file so a crash mid-write cannot leave a
/// truncated state file behind.
fn save_state(path: &PathBuf, state: &PersistedState) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    fs::rename(&temporary, path)
}

/// Snapshot the parts of the running device that are worth keeping.
fn snapshot(database: &ObjectDatabase, addresses: &AddressCache) -> PersistedState {
    let mut state = PersistedState {
        bindings: addresses
            .bindings()
            .into_iter()
            .map(|(device, address)| (device.instance, address.to_string()))
            .collect(),
        ..PersistedState::default()
    };

    for identifier in database.get_all_objects() {
        if let Ok(PropertyValue::List(entries)) =
            database.get_property(identifier, PropertyIdentifier::RecipientList)
        {
            state.recipients = entries
                .into_iter()
                .filter_map(|entry| match entry {
                    PropertyValue::Destination(destination) => Some(destination),
                    _ => None,
                })
                .collect();
        }

        let key = object_key(identifier);
        match database.get_property(identifier, PropertyIdentifier::PresentValue) {
            Ok(PropertyValue::Unsigned(value)) => {
                state.present_values.insert(key.clone(), value as f64);
            }
            Ok(PropertyValue::Real(value)) => {
                state.present_values.insert(key.clone(), value as f64);
            }
            Ok(PropertyValue::Enumerated(value)) => {
                state.present_values.insert(key.clone(), value as f64);
            }
            _ => {}
        }
        if let Ok(PropertyValue::Enumerated(event_state)) =
            database.get_property(identifier, PropertyIdentifier::EventState)
        {
            state.event_states.insert(key, event_state as u16);
        }
    }

    state
}

/// Put a loaded snapshot back into the running device.
fn restore_state(database: &ObjectDatabase, addresses: &AddressCache, state: &PersistedState) {
    for (instance, address) in &state.bindings {
        if let Ok(address) = address.parse::<SocketAddr>() {
            addresses.learn(
                ObjectIdentifier::new(ObjectType::Device, *instance),
                address,
            );
        }
    }

    if !state.recipients.is_empty() {
        let class = ObjectIdentifier::new(ObjectType::NotificationClass, NOTIFICATION_CLASS);
        let entries = state
            .recipients
            .iter()
            .cloned()
            .map(PropertyValue::Destination)
            .collect();
        let _ = database.set_property(
            class,
            PropertyIdentifier::RecipientList,
            PropertyValue::List(entries),
        );
    }

    for identifier in database.get_all_objects() {
        let key = object_key(identifier);

        if let Some(&value) = state.present_values.get(&key) {
            // Match the shape the object expects, rather than guessing from the value.
            let restored = match database.get_property(identifier, PropertyIdentifier::PresentValue)
            {
                Ok(PropertyValue::Unsigned(_)) => Some(PropertyValue::Unsigned(value as u64)),
                Ok(PropertyValue::Real(_)) => Some(PropertyValue::Real(value as f32)),
                Ok(PropertyValue::Enumerated(_)) => Some(PropertyValue::Enumerated(value as u32)),
                _ => None,
            };
            if let Some(restored) = restored {
                let _ =
                    database.set_property(identifier, PropertyIdentifier::PresentValue, restored);
            }
        }

        // Restoring the event state is what stops a standing alarm being
        // re-announced as a fresh transition on every restart.
        if let Some(&event_state) = state.event_states.get(&key) {
            database.with_object_mut(identifier, |object| {
                object.apply_event_state(EventState::from(event_state));
            });
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let bind_address = args.next().unwrap_or_else(|| "0.0.0.0:47808".to_string());
    let device_instance = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1234);

    let mut device = Device::new(device_instance, "Alarm test device".to_string());
    device.vendor_identifier = 1;
    device.model_name = "bacnet-rs alarm device".to_string();

    let database = Arc::new(ObjectDatabase::new(device));

    // CHANGE_OF_STATE on a multi-state object: states 2 and 5 are alarm states.
    let mut modes = MultiStateValue::new(1, "Operating mode".to_string(), 5)
        .with_intrinsic_reporting(NOTIFICATION_CLASS, vec![2, 5]);
    modes.description = "Multistate alarm test object".to_string();
    for (state, text) in [
        (1, "Off"),
        (2, "Fault"),
        (3, "Manual"),
        (4, "Auto"),
        (5, "Error"),
    ] {
        modes.state_text[state - 1] = text.to_string();
    }
    database.add_object(Box::new(modes))?;

    // CHANGE_OF_STATE on a binary object: Active is the alarm state.
    let mut running = BinaryValue::new(1, "Pump running".to_string())
        .with_intrinsic_reporting(NOTIFICATION_CLASS, BinaryPV::Active);
    running.description = "Binary alarm test object".to_string();
    database.add_object(Box::new(running))?;

    // OUT_OF_RANGE on an analog object.
    let mut temperature = AnalogValue::new(1, "Zone temperature".to_string())
        .with_out_of_range_reporting(NOTIFICATION_CLASS, Some(18.0), Some(24.0), 0.5);
    temperature.description = "Analog limit alarm test object".to_string();
    temperature.present_value = 21.0;
    // Without an increment every read reports, which makes a COV subscriber as
    // noisy as polling.
    temperature.cov_increment = Some(0.5);
    database.add_object(Box::new(temperature))?;

    // CHANGE_OF_RELIABILITY on an analog object with no limits configured.
    let mut sensor = AnalogValue::new(2, "Outdoor sensor".to_string())
        .with_intrinsic_reporting(NOTIFICATION_CLASS);
    sensor.description = "Reliability alarm test object".to_string();
    sensor.present_value = 7.5;
    database.add_object(Box::new(sensor))?;

    // Routes notifications; recipients register themselves by writing Recipient_List.
    database.add_object(Box::new(
        NotificationClass::new(NOTIFICATION_CLASS, "Alarm class".to_string())
            .with_priority(90, 10, 200)
            .with_ack_required(EventTransitionBits {
                to_offnormal: false,
                to_fault: true,
                to_normal: false,
            }),
    ))?;

    let server = BacnetIpServer::bind(&bind_address, Arc::clone(&database))?;
    let addresses = server.object_service().addresses().clone();
    let subscriptions = server.object_service().subscriptions().clone();

    let path = state_path();
    let restored = load_state(&path);
    let had_state = restored != PersistedState::default();
    restore_state(&database, &addresses, &restored);

    println!("Hosting alarm device {device_instance} on {bind_address}");
    println!("  notifications routed through notification-class,{NOTIFICATION_CLASS}");
    println!("  state file: {}", path.display());
    println!("  COV subscriptions accepted; notifications follow COV_Increment");
    if had_state {
        println!(
            "  resumed: {} recipient(s), {} binding(s)",
            restored.recipients.len(),
            restored.bindings.len()
        );
    } else {
        println!("  no previous state; starting from defaults");
    }

    // Intrinsic reporting runs alongside the request loop: the engine owns the
    // dwell timers and the notifier its own socket handle, so evaluating and
    // sending never blocks `serve_once`.
    let engine_database = Arc::clone(&database);
    let engine_addresses = addresses.clone();
    let engine_subscriptions = subscriptions.clone();
    let notifier = server.notifier()?;
    thread::spawn(move || {
        let mut engine = EventEngine::new(device_instance);
        let mut cov = CovEngine::new(device_instance);
        let started = Instant::now();
        let mut last_saved = restored;

        loop {
            let now_seconds = started.elapsed().as_secs();

            // COV reporting shares the tick: a subscriber watching an alarming
            // object hears about the value change and the event separately.
            for addressed in cov.tick(&engine_database, &engine_subscriptions, now_seconds) {
                println!(
                    "cov: {:?} -> {} pid {} ({} value(s), {})",
                    addressed.notification.monitored_object,
                    addressed.address,
                    addressed.notification.subscriber_process_identifier,
                    addressed.notification.list_of_values.len(),
                    if addressed.confirmed {
                        "confirmed"
                    } else {
                        "unconfirmed"
                    },
                );
                // A COV subscriber is always one device: it gave its address when
                // it subscribed.
                if let Err(error) = notifier.send_cov_notification(
                    NotificationTarget::Unicast(addressed.address),
                    &addressed.notification,
                    addressed.confirmed,
                ) {
                    eprintln!("failed to send COV notification: {error}");
                }
            }

            for addressed in engine.tick(
                &engine_database,
                now_seconds,
                TimestampValue::SequenceNumber(now_seconds as u32),
            ) {
                let notification = &addressed.notification;
                let confirmed = addressed.destination.issue_confirmed_notifications;

                match engine_addresses.resolve(&addressed.destination.recipient) {
                    Some(target) => {
                        println!(
                            "event: {:?} {:?} -> {:?} (priority {}, ack {}) -> {target} pid {} {}",
                            notification.event_object,
                            notification.from_state,
                            notification.to_state,
                            notification.priority,
                            notification.ack_required,
                            notification.process_identifier,
                            if confirmed {
                                "confirmed"
                            } else {
                                "unconfirmed"
                            },
                        );
                        if let Err(error) =
                            notifier.send_event_notification(target, notification, confirmed)
                        {
                            eprintln!("failed to send notification: {error}");
                        }
                    }
                    None => eprintln!(
                        "no address known for {:?}; notification dropped",
                        addressed.destination.recipient
                    ),
                }
            }

            // Persist only when something actually moved, so an idle device does
            // not rewrite the file every second.
            let current = snapshot(&engine_database, &engine_addresses);
            if current != last_saved {
                if let Err(error) = save_state(&path, &current) {
                    eprintln!("failed to save state: {error}");
                }
                last_saved = current;
            }

            thread::sleep(Duration::from_secs(1));
        }
    });

    let mut server = server;
    loop {
        server.serve_once()?;
    }
}
