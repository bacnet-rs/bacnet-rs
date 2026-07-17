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
//! present in the database. A sample Device_Address_Binding and a Schedule
//! object exercise constructed-value encoding. The server advertises and
//! enforces no segmentation.
//!
//! The Analog Value is commandable. Present_Value accepts priorities 1 through
//! 16, defaults to priority 16, and accepts Null to relinquish a priority slot.
//! Indexed property writes are not implemented and return
//! optional-functionality-not-supported.
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

use std::{env, sync::Arc};

use bacnet_rs::{
    object::{
        database::ObjectDatabase, AddressBinding, AnalogValue, BacnetObject, Device, ObjectError,
        ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue, ProtocolServicesSupported,
    },
    property::{DailyScheduleValue, ObjectPropertyReference, TimeValueValue},
    server::BacnetIpServer,
};

struct ExampleSchedule {
    identifier: ObjectIdentifier,
    target: ObjectIdentifier,
}

impl ExampleSchedule {
    fn new(instance: u32, target: ObjectIdentifier) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::Schedule, instance),
            target,
        }
    }

    fn weekly_schedule(&self) -> Vec<PropertyValue> {
        let weekday = DailyScheduleValue {
            time_values: vec![
                TimeValueValue {
                    time: (6, 0, 0, 0),
                    value: Box::new(PropertyValue::Real(21.0)),
                },
                TimeValueValue {
                    time: (18, 0, 0, 0),
                    value: Box::new(PropertyValue::Real(18.0)),
                },
            ],
        };
        let weekend = DailyScheduleValue {
            time_values: vec![TimeValueValue {
                time: (8, 0, 0, 0),
                value: Box::new(PropertyValue::Real(19.0)),
            }],
        };

        (0..7)
            .map(|day| {
                PropertyValue::DailySchedule(if day < 5 {
                    weekday.clone()
                } else {
                    weekend.clone()
                })
            })
            .collect()
    }
}

impl BacnetObject for ExampleSchedule {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(
        &self,
        property: PropertyIdentifier,
    ) -> bacnet_rs::object::Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => Ok(PropertyValue::CharacterString(
                "Occupied temperature schedule".to_string(),
            )),
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(ObjectType::Schedule.into()))
            }
            PropertyIdentifier::PresentValue => Ok(PropertyValue::Real(21.0)),
            PropertyIdentifier::EffectivePeriod => Ok(PropertyValue::List(vec![
                PropertyValue::Date(255, 255, 255, 255),
                PropertyValue::Date(255, 255, 255, 255),
            ])),
            PropertyIdentifier::WeeklySchedule => Ok(PropertyValue::Array(self.weekly_schedule())),
            PropertyIdentifier::ScheduleDefault => Ok(PropertyValue::Real(18.0)),
            PropertyIdentifier::ListOfObjectPropertyReferences => Ok(PropertyValue::List(vec![
                PropertyValue::ObjectPropertyReference(ObjectPropertyReference {
                    object_identifier: self.target,
                    property_identifier: PropertyIdentifier::PresentValue,
                    array_index: None,
                }),
            ])),
            PropertyIdentifier::PriorityForWriting => Ok(PropertyValue::Unsigned(16)),
            PropertyIdentifier::StatusFlags => {
                Ok(PropertyValue::BitString(vec![false, false, false, false]))
            }
            PropertyIdentifier::OutOfService => Ok(PropertyValue::Boolean(false)),
            PropertyIdentifier::Reliability => Ok(PropertyValue::Enumerated(0)),
            _ => Err(ObjectError::UnknownProperty),
        }
    }

    fn set_property(
        &mut self,
        _property: PropertyIdentifier,
        _value: PropertyValue,
    ) -> bacnet_rs::object::Result<()> {
        Err(ObjectError::PropertyNotWritable)
    }

    fn is_property_writable(&self, _property: PropertyIdentifier) -> bool {
        false
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::PresentValue,
            PropertyIdentifier::EffectivePeriod,
            PropertyIdentifier::WeeklySchedule,
            PropertyIdentifier::ScheduleDefault,
            PropertyIdentifier::ListOfObjectPropertyReferences,
            PropertyIdentifier::PriorityForWriting,
            PropertyIdentifier::StatusFlags,
            PropertyIdentifier::OutOfService,
            PropertyIdentifier::Reliability,
        ]
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
    database.add_object(Box::new(ExampleSchedule::new(1, setpoint_identifier)))?;

    let mut server = BacnetIpServer::bind(&bind_address, database)?;
    println!("Hosting BACnet device {device_instance} on {bind_address}");

    loop {
        server.serve_once()?;
    }
}
