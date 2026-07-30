//! Host a small BACnet/IP device backed by an `ObjectDatabase`.
//!
//! This example exercises the current hosted-server profile. It is useful for
//! development and interoperability testing, but is not a formal BACnet PICS or
//! a certification claim.
//!
//! The server accepts BACnet/IP original unicast, original broadcast, and
//! Forwarded-NPDU messages using protocol version 1, revision 22. It executes Who-Is, ReadProperty,
//! ReadPropertyMultiple, and WriteProperty, and emits I-Am responses. RPM
//! supports explicit properties and the `All` selector; `Required` and
//! `Optional` selectors are not implemented yet.
//!
//! The hosted Device object advertises its actual services and the object types
//! present in the database. A sample Device_Address_Binding exercises
//! constructed-value encoding. The server advertises and enforces no
//! segmentation.
//!
//! The Analog Value is commandable. Present_Value accepts priorities 1 through
//! 16, defaults to priority 16, and accepts Null to relinquish a priority slot.
//! Indexed property writes are not implemented and return
//! optional-functionality-not-supported.
//!
//! A Schedule drives that Analog Value from a weekly profile, stepping aside on
//! the days listed by a Calendar object. A background thread ticks the schedule
//! engine once a second against the local clock, so Present_Value follows the
//! wall clock while the request loop keeps serving.
//!
//! COV subscriptions, event reporting, acting as a BBMD or foreign device, and
//! segmented requests or responses are outside this profile.
//!
//! ```text
//! cargo run --example hosted_device -- 127.0.0.2:47808 1234
//!
//! # Generate an EPICS using ReadPropertyMultiple.
//! BACNET_IFACE=lo bacepics -v -p 47809 \
//!     -t 7F:00:00:02:BA:C0 1234
//!
//! # Start an RP-only profile to exercise bacepics' ReadProperty fallback.
//! cargo run --example hosted_device -- 127.0.0.2:47808 1234 --rp-only
//! BACNET_IFACE=lo bacepics -v -p 47809 \
//!     -t 7F:00:00:02:BA:C0 1234
//! ```

use std::{env, sync::Arc, thread, time::Duration};

use bacnet_rs::{
    object::{
        database::ObjectDatabase, AddressBinding, AnalogValue, Calendar, Device, ObjectIdentifier,
        ObjectType, PropertyIdentifier, PropertyValue, ProtocolServicesSupported, Schedule,
    },
    property::{
        CalendarEntryValue, DailyScheduleValue, SpecialEventPeriod, SpecialEventValue,
        TimeValueValue, ANY, UNSPECIFIED_YEAR,
    },
    schedule::ScheduleEngine,
    server::BacnetIpServer,
};
use chrono::{Datelike, Local, Timelike};

const HOLIDAY_CALENDAR: u32 = 1;

/// A BACnet date: year, month, day, weekday, with weekday 1 for Monday.
type Date = (u16, u8, u8, u8);
/// A BACnet time: hour, minute, second, hundredths.
type Time = (u8, u8, u8, u8);

fn time_value(hour: u8, value: f32) -> TimeValueValue {
    TimeValueValue {
        time: (hour, 0, 0, 0),
        value: Box::new(PropertyValue::Real(value)),
    }
}

/// Occupied from 06:00 to 18:00 on weekdays; nothing scheduled at the weekend,
/// so those days fall back to the setback default.
fn office_hours(setpoint: ObjectIdentifier) -> Schedule {
    let weekday = DailyScheduleValue {
        time_values: vec![time_value(6, 21.0), time_value(18, 18.0)],
    };
    let weekend = DailyScheduleValue {
        time_values: Vec::new(),
    };
    let days = std::array::from_fn(|day| {
        if day < 5 {
            weekday.clone()
        } else {
            weekend.clone()
        }
    });

    Schedule::new(1, "Occupied temperature schedule".to_string())
        .with_description("Weekday setpoint profile with a holiday exception".to_string())
        .with_default(PropertyValue::Real(16.0))
        .with_weekly_schedule(days)
        // On a day the calendar covers, hold the setback all day.
        .with_exception(SpecialEventValue {
            period: SpecialEventPeriod::CalendarReference(ObjectIdentifier::new(
                ObjectType::Calendar,
                HOLIDAY_CALENDAR,
            )),
            time_values: vec![time_value(0, 16.0)],
            priority: 8,
        })
        .with_target(setpoint, PropertyIdentifier::PresentValue)
}

fn holidays() -> Calendar {
    Calendar::new(HOLIDAY_CALENDAR, "Holidays".to_string())
        .with_description("Days the building runs unoccupied".to_string())
        // Christmas Eve and Norwegian Constitution Day, every year.
        .with_entry(CalendarEntryValue::Date(UNSPECIFIED_YEAR, 12, 24, ANY))
        .with_entry(CalendarEntryValue::Date(UNSPECIFIED_YEAR, 5, 17, ANY))
}

/// The local clock as the BACnet date and time the engine expects, with weekday
/// 1 for Monday.
fn now() -> (Date, Time) {
    let now = Local::now();
    let date = (
        now.year() as u16,
        now.month() as u8,
        now.day() as u8,
        now.weekday().number_from_monday() as u8,
    );
    let time = (
        now.hour() as u8,
        now.minute() as u8,
        now.second() as u8,
        (now.timestamp_subsec_millis() / 10) as u8,
    );
    (date, time)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let bind_address = args.next().unwrap_or_else(|| "0.0.0.0:47808".to_string());
    let device_instance = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1234);
    let rp_only = args.any(|argument| argument == "--rp-only");

    let mut device = Device::new(device_instance, "Hosted BACnet device".to_string());
    device.vendor_identifier = 1;
    device.model_name = "bacnet-rs hosted device".to_string();
    device.device_address_binding.push(AddressBinding {
        device_identifier: ObjectIdentifier::new(ObjectType::Device, 5678),
        network_number: 416,
        mac_address: vec![192, 168, 1, 10, 0xBA, 0xC0],
    });
    if rp_only {
        device.protocol_services_supported = ProtocolServicesSupported::READ_PROPERTY
            | ProtocolServicesSupported::I_AM
            | ProtocolServicesSupported::WHO_IS;
    }

    let database = Arc::new(ObjectDatabase::new(device));
    let mut setpoint = AnalogValue::new(1, "Zone temperature setpoint".to_string());
    setpoint.description = "Example commandable analog value".to_string();
    setpoint.present_value = 21.5;
    let setpoint_identifier = setpoint.identifier;
    database.add_object(Box::new(setpoint))?;
    database.add_object(Box::new(holidays()))?;
    database.add_object(Box::new(office_hours(setpoint_identifier)))?;

    // Scheduling runs alongside the request loop. The engine only touches the
    // database, so evaluating a schedule never blocks `serve_once`.
    let schedule_database = Arc::clone(&database);
    thread::spawn(move || {
        let mut engine = ScheduleEngine::new();
        loop {
            let (date, time) = now();
            for write in engine.tick(&schedule_database, date, time) {
                println!(
                    "schedule: {:?} -> {:?}.{:?} = {} at priority {}{}",
                    write.schedule,
                    write.target.object_identifier,
                    write.target.property_identifier,
                    write.value,
                    write.priority,
                    if write.applied { "" } else { " (not applied)" },
                );
            }
            thread::sleep(Duration::from_secs(1));
        }
    });

    let mut server = BacnetIpServer::bind(&bind_address, database)?;
    println!("Hosting BACnet device {device_instance} on {bind_address}");

    loop {
        server.serve_once()?;
    }
}
