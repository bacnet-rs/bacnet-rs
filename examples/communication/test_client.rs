//! Test BACnet Client with Comprehensive Units Support
//!
//! This example tests the high-level BACnet client utilities
//! with comprehensive engineering units support.

use bacnet_rs::client::BacnetClient;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example CLI parsing only — not a security boundary.
    let args: Vec<String> = env::args().collect(); // nosemgrep: rust.lang.security.args.args
    if args.len() != 2 {
        eprintln!("Usage: {} <target_device_ip[:port]>", args[0]);
        eprintln!("Example: {} 10.161.1.211", args[0]);
        eprintln!("Example: {} 10.161.1.211:47808", args[0]);
        std::process::exit(1);
    }

    // Accept either a bare IP (defaulting to the BACnet/IP port 47808) or a
    // full "ip:port" socket address.
    let target = &args[1];
    let target_addr: std::net::SocketAddr = if target.contains(':') {
        target.parse()?
    } else {
        format!("{}:47808", target).parse()?
    };

    println!("BACnet Client Test with Comprehensive Units");
    println!("===========================================\n");

    // Create BACnet client
    let client = BacnetClient::builder().port(0xBAC0).build()?;
    println!("Created BACnet client");

    // Discover device
    println!("Discovering device at {}...", target_addr);
    let device_info = client.discover_device(target_addr)?;

    println!("Found device:");
    println!("  Device ID: {}", device_info.device_id);
    println!(
        "  Vendor: {} (ID: {})",
        device_info.vendor_name, device_info.vendor_id
    );
    println!("  Max APDU: {}", device_info.max_apdu);
    println!("  Address: {}", device_info.address);
    println!();

    // Read object list
    println!("Reading device object list...");
    let objects = client.read_object_list(target_addr, device_info.device_id)?;
    println!("Found {} objects", objects.len());

    // Show first few objects by type
    let mut type_counts = std::collections::HashMap::new();
    for obj in &objects {
        *type_counts.entry(obj.object_type).or_insert(0) += 1;
    }

    println!("\nObject summary:");
    for (obj_type, count) in &type_counts {
        println!("  {}: {} objects", obj_type, count);
    }

    // Read properties for first few objects
    println!("\nReading properties for first 5 objects...");
    let sample_objects = &objects[..std::cmp::min(5, objects.len())];
    let objects_info = client.read_objects_properties(target_addr, sample_objects)?;

    for obj_info in &objects_info {
        println!(
            "\n{} Instance {}:",
            obj_info.object_identifier.object_type, obj_info.object_identifier.instance
        );

        if let Some(name) = &obj_info.object_name {
            println!("  Name: {}", name);
        }

        if let Some(desc) = &obj_info.description {
            println!("  Description: {}", desc);
        }

        if let Some(value) = &obj_info.present_value {
            println!("  Present Value: {:?}", value);
        }

        if let Some(units) = &obj_info.units {
            println!("  Units: {}", units.bacnet_name());
            println!("  Unit ID: {}", u32::from(*units));
        }

        if let Some(flags) = &obj_info.status_flags {
            println!("  Status Flags: {:?}", flags);
        }
    }

    println!("\nBACnet Client Test Complete!");
    Ok(())
}
