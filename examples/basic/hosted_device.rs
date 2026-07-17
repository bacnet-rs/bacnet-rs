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
//! present in the database. It also exposes Object_List, Property_List,
//! APDU_Timeout, Number_Of_APDU_Retries, an empty Device_Address_Binding, and a
//! live Database_Revision. The server advertises and enforces no segmentation.
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
//! # Read every exposed Device and Analog Value property with bacnet-stack.
//! BACNET_IFACE=lo BACNET_IP_PORT=47808 bacrpm \
//!     1234 8 1234 8 --mac 127.0.0.2:47808
//! BACNET_IFACE=lo BACNET_IP_PORT=47808 bacrpm \
//!     1234 2 1 8 --mac 127.0.0.2:47808
//!
//! # Or read selected properties from the Analog Value.
//! BACNET_IFACE=lo BACNET_IP_PORT=47808 bacrpm \
//!     1234 2 1 77,85 --mac 127.0.0.2:47808
//! ```

use std::{env, sync::Arc};

use bacnet_rs::{
    object::{database::ObjectDatabase, AnalogValue, Device},
    server::BacnetIpServer,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let bind_address = args.next().unwrap_or_else(|| "0.0.0.0:47808".to_string());
    let device_instance = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1234);

    let mut device = Device::new(device_instance, "Hosted BACnet device".to_string());
    device.vendor_identifier = 1;
    device.model_name = "bacnet-rs hosted device".to_string();

    let database = Arc::new(ObjectDatabase::new(device));
    let mut setpoint = AnalogValue::new(1, "Zone temperature setpoint".to_string());
    setpoint.description = "Example commandable analog value".to_string();
    setpoint.present_value = 21.5;
    database.add_object(Box::new(setpoint))?;

    let mut server = BacnetIpServer::bind(&bind_address, database)?;
    println!("Hosting BACnet device {device_instance} on {bind_address}");

    loop {
        server.serve_once()?;
    }
}
