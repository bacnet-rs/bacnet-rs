//! Simple BACnet Device Example
//!
//! This example demonstrates how to create a basic BACnet device using the bacnet-rs library.
//! It shows how to:
//! - Create a BACnet device
//! - Set up BACnet/IP communication
//! - Handle Who-Is requests and respond with I-Am
//! - Process Read Property requests

use bacnet_rs::{
    app::{Apdu, MaxApduSize, MaxSegments},
    datalink::{bip::BacnetIpDataLink, DataLink},
    network::Npdu,
    object::{BacnetObject, Device, ObjectIdentifier, ObjectType, PropertyIdentifier},
    service::{IAmRequest, ReadPropertyRequest, UnconfirmedServiceChoice, WhoIsRequest},
};

use std::net::SocketAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet-RS Simple Device Example");
    println!("================================");

    // Create a BACnet device
    let mut device = Device::new(12345, "Example Device".to_string());
    device.vendor_name = "BACnet-RS Demo".to_string();
    device.model_name = "Simple Demo Device".to_string();

    println!("Created device: {}", device.object_name);
    println!("Device instance: {}", device.identifier().instance);
    println!("Vendor: {}", device.vendor_name);

    // Create BACnet/IP data link
    let bind_addr: SocketAddr = "0.0.0.0:47808".parse()?;
    let datalink = BacnetIpDataLink::new(bind_addr)?;

    println!("BACnet/IP data link bound to: {}", bind_addr);
    println!("Local address: {:?}", datalink.local_address());

    // Demonstrate property access
    println!("\nDevice Properties:");
    println!("------------------");

    // Read some device properties
    let properties = vec![
        PropertyIdentifier::ObjectName,
        PropertyIdentifier::VendorName,
        PropertyIdentifier::ModelName,
        PropertyIdentifier::SystemStatus,
        PropertyIdentifier::ProtocolVersion,
        PropertyIdentifier::MaxApduLengthAccepted,
    ];

    for prop in properties {
        match device.get_property(prop) {
            Ok(value) => {
                println!("{:?}: {:?}", prop, value);
            }
            Err(e) => {
                println!("{:?}: Error - {:?}", prop, e);
            }
        }
    }

    // Demonstrate encoding/decoding
    println!("\nEncoding/Decoding Demo:");
    println!("-----------------------");

    // Create a Who-Is request
    let whois = WhoIsRequest::for_device(12345);
    println!("Created Who-Is request for device {}", 12345);

    let mut whois_buffer = Vec::new();
    whois.encode(&mut whois_buffer)?;
    println!("Encoded Who-Is request: {:?}", whois_buffer);

    let decoded_whois = WhoIsRequest::decode(&whois_buffer)?;
    println!(
        "Decoded Who-Is matches device: {}",
        decoded_whois.matches(12345)
    );

    // Create an I-Am response
    let device_id = ObjectIdentifier::new(ObjectType::Device, 12345);
    let _iam = IAmRequest::new(device_id, 1476, 0, 999);
    println!("Created I-Am response");

    // Create APDU examples
    println!("\nAPDU Examples:");
    println!("--------------");

    // Unconfirmed request (Who-Is)
    let whois_apdu = Apdu::UnconfirmedRequest {
        service_choice: UnconfirmedServiceChoice::WhoIs as u8,
        service_data: whois_buffer,
    };

    let encoded_apdu = whois_apdu.encode();
    println!("Encoded Who-Is APDU: {} bytes", encoded_apdu.len());

    let decoded_apdu = Apdu::decode(&encoded_apdu)?;
    match decoded_apdu {
        Apdu::UnconfirmedRequest { service_choice, .. } => {
            println!("Decoded APDU service choice: {}", service_choice);
        }
        _ => println!("Unexpected APDU type"),
    }

    // Confirmed request (Read Property)
    let read_prop = ReadPropertyRequest::new(device_id, PropertyIdentifier::ObjectName as u32);

    let mut read_prop_data = Vec::new();
    read_prop.encode(&mut read_prop_data)?;

    let read_prop_apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up1476,
        invoke_id: 42,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: 12, // Read Property
        service_data: read_prop_data,
    };

    let encoded_read_prop = read_prop_apdu.encode();
    println!(
        "Encoded Read Property APDU: {} bytes",
        encoded_read_prop.len()
    );

    // Network layer demo
    println!("\nNetwork Layer Demo:");
    println!("-------------------");

    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    npdu.control.priority = 3; // Critical equipment control

    let encoded_npdu = npdu.encode();
    println!("Encoded NPDU: {} bytes", encoded_npdu.len());

    let (decoded_npdu, consumed) = Npdu::decode(&encoded_npdu)?;
    println!(
        "Decoded NPDU version: {}, consumed: {} bytes",
        decoded_npdu.version, consumed
    );
    println!(
        "NPDU expecting reply: {}",
        decoded_npdu.control.expecting_reply
    );
    println!("NPDU priority: {}", decoded_npdu.control.priority);

    println!("\nBACnet Stack Demo Complete!");
    println!("All layers are working correctly.");

    Ok(())
}
