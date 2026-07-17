//! Read/Write Property with the high-level client
//!
//! Demonstrates the typed `BacnetClient` API: device discovery, targeted
//! single-property reads, and an optional commanded write (with priority).
//!
//! Usage:
//!   # discover the device and read its first present-value point
//!   read_write_property <ip[:port]>
//!
//!   # read one specific object's Present_Value
//!   read_write_property <ip[:port]> <object_type> <instance>
//!
//!   # write Present_Value, then read it back (priority defaults to 8; "none" omits it)
//!   read_write_property <ip[:port]> <object_type> <instance> <real-value> [priority|none]
//!
//!   # relinquish a commanded slot (write Null at the given priority)
//!   read_write_property <ip[:port]> <object_type> <instance> relinquish [priority]
//!
//! <object_type> accepts names or short forms: analogValue/av, analogInput/ai,
//! analogOutput/ao, binaryValue/bv, binaryInput/bi, binaryOutput/bo,
//! multiStateValue/msv, multiStateInput/msi, multiStateOutput/mso.
//!
//! Examples:
//!   cargo run --example read_write_property 10.161.1.211
//!   cargo run --example read_write_property 10.161.1.211 analogValue 4
//!   cargo run --example read_write_property 10.161.1.211 analogValue 4 3.0
//!   cargo run --example read_write_property 10.161.1.211 analogValue 4 3.0 none

use bacnet_rs::{
    client::BacnetClient,
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier},
    property::PropertyValue,
};
use std::env;
use std::net::SocketAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example CLI parsing only — not a security boundary.
    let args: Vec<String> = env::args().collect(); // nosemgrep: rust.lang.security.args.args
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <ip[:port]> [<object_type> <instance> [<value> [priority|none]]]",
            args[0]
        );
        std::process::exit(1);
    }

    let target_addr = parse_addr(&args[1])?;
    let client = BacnetClient::new()?;

    // No object specified: discover the device and read its first point.
    if args.len() == 2 {
        return discover_and_read_first(&client, target_addr);
    }

    // Targeted mode needs at least <object_type> <instance>.
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <ip[:port]> <object_type> <instance> [<value> [priority|none]]",
            args[0]
        );
        std::process::exit(1);
    }

    let object_type = parse_object_type(&args[2]).ok_or_else(|| {
        format!(
            "unknown object type '{}' (try analogValue, binaryValue, ...)",
            args[2]
        )
    })?;
    let instance: u32 = args[3].parse()?;
    let object = ObjectIdentifier::new(object_type, instance);

    // Always show the current value first.
    print!("{} {} Present_Value (read): ", object_type, instance);
    match client.read_property(target_addr, object, PropertyIdentifier::PresentValue) {
        Ok(values) => println!("{}", show_values(&values)),
        Err(e) => println!("<read failed: {e}>"),
    }

    // If a value was supplied, write it (or relinquish) and confirm.
    if let Some(value_arg) = args.get(4) {
        let priority = match args.get(5).map(|s| s.to_ascii_lowercase()) {
            None => Some(8),
            Some(s) if s == "none" => None,
            Some(s) => Some(s.parse()?),
        };

        // "relinquish" / "null" releases the slot by writing Null at that priority.
        if value_arg.eq_ignore_ascii_case("relinquish") || value_arg.eq_ignore_ascii_case("null") {
            return relinquish(&client, target_addr, object, priority);
        }

        let value: f32 = value_arg.parse()?;
        println!("Writing Present_Value = {value} (priority {priority:?})...");
        // The client exposes the two protocol operations separately. This
        // example chooses one read-back; applications own delay/retry policy.
        match client.write_property(
            target_addr,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(value),
            priority,
        ) {
            Ok(()) => {
                println!("  Write acknowledged.");
                match client.read_property(target_addr, object, PropertyIdentifier::PresentValue) {
                    Ok(read_back) => println!("  Read-back: {}", show_values(&read_back)),
                    Err(error) => println!("  Read-back failed: {error}"),
                }
            }
            // The typed error tells us exactly why the device refused (e.g.
            // not writable) instead of hanging until timeout.
            Err(e) => println!("  Write REFUSED by device: {e}"),
        }
    }

    Ok(())
}

/// Relinquish a commanded value by writing `Null` at the given priority, then
/// read back the resulting effective value.
fn relinquish(
    client: &BacnetClient,
    target_addr: SocketAddr,
    object: ObjectIdentifier,
    priority: Option<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Relinquishing Present_Value at priority {priority:?} (writing Null)...");
    match client.write_property(
        target_addr,
        object,
        PropertyIdentifier::PresentValue,
        &PropertyValue::Null,
        priority,
    ) {
        Ok(()) => {
            let pv = client.read_property(target_addr, object, PropertyIdentifier::PresentValue)?;
            println!(
                "  Relinquished. Present_Value now reads {}.",
                show_values(&pv)
            );
        }
        Err(e) => println!("  Relinquish REFUSED by device: {e}"),
    }
    Ok(())
}

/// Discover the device at `target_addr` and read the first present-value point.
fn discover_and_read_first(
    client: &BacnetClient,
    target_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Discovering device at {target_addr}...");
    let device = client.discover_device(target_addr)?;
    let device_object = ObjectIdentifier::new(ObjectType::Device, device.device_id);
    println!(
        "Found device {} ({})\n",
        device.device_id, device.vendor_name
    );

    let name = client.read_property(target_addr, device_object, PropertyIdentifier::ObjectName)?;
    println!("Device Object_Name: {}", show_values(&name));

    let objects = client.read_object_list(target_addr, device.device_id)?;
    let Some(point) = objects
        .into_iter()
        .find(|o| has_present_value(o.object_type))
    else {
        println!("\nNo analog/binary/multistate points found on this device.");
        return Ok(());
    };

    println!(
        "\nUsing point {} instance {}",
        point.object_type, point.instance
    );
    let value = client.read_property(target_addr, point, PropertyIdentifier::PresentValue)?;
    println!("  Present_Value (read): {}", show_values(&value));
    Ok(())
}

/// Render the values from a `read_property` result for display: a lone value as
/// itself, multiple values as a bracketed, comma-separated list.
fn show_values(values: &[PropertyValue]) -> String {
    match values {
        [] => "(no value)".to_string(),
        [single] => single.as_display_string(),
        many => {
            let parts: Vec<String> = many.iter().map(|v| v.as_display_string()).collect();
            format!("[{}]", parts.join(", "))
        }
    }
}

/// Parse a bare IP (defaulting to port 47808) or a full `ip:port`.
fn parse_addr(arg: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    if arg.contains(':') {
        arg.parse()
    } else {
        format!("{arg}:47808").parse()
    }
}

/// Map a CLI object-type string (name or short form) to an [`ObjectType`].
fn parse_object_type(s: &str) -> Option<ObjectType> {
    match s.to_ascii_lowercase().as_str() {
        "analoginput" | "ai" => Some(ObjectType::AnalogInput),
        "analogoutput" | "ao" => Some(ObjectType::AnalogOutput),
        "analogvalue" | "av" => Some(ObjectType::AnalogValue),
        "binaryinput" | "bi" => Some(ObjectType::BinaryInput),
        "binaryoutput" | "bo" => Some(ObjectType::BinaryOutput),
        "binaryvalue" | "bv" => Some(ObjectType::BinaryValue),
        "multistateinput" | "msi" => Some(ObjectType::MultiStateInput),
        "multistateoutput" | "mso" => Some(ObjectType::MultiStateOutput),
        "multistatevalue" | "msv" => Some(ObjectType::MultiStateValue),
        _ => None,
    }
}

/// Object types that expose a Present_Value worth reading.
fn has_present_value(object_type: ObjectType) -> bool {
    matches!(
        object_type,
        ObjectType::AnalogInput
            | ObjectType::AnalogOutput
            | ObjectType::AnalogValue
            | ObjectType::BinaryInput
            | ObjectType::BinaryOutput
            | ObjectType::BinaryValue
            | ObjectType::MultiStateInput
            | ObjectType::MultiStateOutput
            | ObjectType::MultiStateValue
    )
}
