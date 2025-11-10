//! BACnet Who-Is Scan Example
//!
//! This example demonstrates how to perform a Who-Is scan to discover
//! BACnet devices on the network using the corrected service layer implementation.

use bacnet_rs::{
    datalink::{bip::BacnetIpDataLink, DataLink, DataLinkAddress},
    network::Npdu,
    object::Segmentation,
    service::{IAmRequest, UnconfirmedServiceChoice, WhoIsRequest},
    vendor::get_vendor_name,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// Structure to hold discovered device information
#[derive(Debug, Clone)]
struct DiscoveredDevice {
    device_id: u32,
    address: SocketAddr,
    vendor_id: u32,
    vendor_name: String,
    max_apdu: u32,
    segmentation: Segmentation,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Who-Is Scan Example");
    println!("========================\n");

    // Create BACnet/IP data link (use 0 to let system choose port)
    println!("Creating BACnet/IP data link...");
    let mut datalink = BacnetIpDataLink::new("0.0.0.0:0")?;

    println!("Data link created successfully");
    println!("Starting Who-Is scan...\n");

    // Create Who-Is request (broadcast to all devices)
    let whois = WhoIsRequest::new();

    // Encode the Who-Is service
    let mut service_data = Vec::new();
    whois.encode(&mut service_data)?;

    // Create APDU (Application Protocol Data Unit)
    let mut apdu_buffer = Vec::new();
    apdu_buffer.push(0x10); // Unconfirmed Request PDU
    apdu_buffer.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu_buffer.extend_from_slice(&service_data);

    // Create NPDU using our corrected global broadcast
    let npdu = Npdu::global_broadcast();

    // Encode NPDU
    let npdu_buffer = npdu.encode();

    // Combine NPDU and APDU
    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu_buffer);

    // Send the Who-Is broadcast
    println!("Sending Who-Is broadcast...");
    match datalink.send_frame(&message, &DataLinkAddress::Broadcast) {
        Ok(_) => println!("Broadcast sent successfully"),
        Err(e) => println!("Warning: Broadcast failed: {:?}", e),
    }

    // Also try specific local subnet broadcasts
    let local_broadcasts = vec![
        "10.161.1.255:47808",
        "192.168.1.255:47808",
        "192.168.0.255:47808",
        "172.16.0.255:47808",
    ];

    for addr_str in &local_broadcasts {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            if datalink
                .send_frame(&message, &DataLinkAddress::Ip(addr))
                .is_ok()
            {
                println!("Sent Who-Is to local broadcast: {}", addr);
            }
        }
    }

    println!("\nListening for I-Am responses...\n");

    // Listen for responses
    let mut discovered_devices: HashMap<u32, DiscoveredDevice> = HashMap::new();
    let scan_duration = Duration::from_secs(5);
    let start_time = Instant::now();

    // Send periodic Who-Is broadcasts
    let mut last_broadcast = Instant::now();

    while start_time.elapsed() < scan_duration {
        // Re-broadcast every 2 seconds
        if last_broadcast.elapsed() > Duration::from_secs(2) {
            println!("Sending periodic Who-Is broadcast...");
            let _ = datalink.send_frame(&message, &DataLinkAddress::Broadcast);
            last_broadcast = Instant::now();
        }

        // Try to receive a response
        match datalink.receive_frame() {
            Ok((data, source)) => {
                // Convert DataLinkAddress to SocketAddr for display
                let source_addr = match source {
                    DataLinkAddress::Ip(addr) => addr,
                    _ => continue, // Skip non-IP addresses
                };

                println!("Received {} bytes from {}", data.len(), source_addr);

                // Process the received message
                if let Some(device) = process_response(&data, source_addr) {
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        discovered_devices.entry(device.device_id)
                    {
                        println!("Discovered new device:");
                        println!("  Device ID: {}", device.device_id);
                        println!("  Address: {}", device.address);
                        println!(
                            "  Vendor: {} (ID: {})",
                            device.vendor_name, device.vendor_id
                        );
                        println!("  Max APDU: {}", device.max_apdu);
                        println!("  Segmentation: {}", device.segmentation);
                        println!();

                        e.insert(device);
                    }
                }
            }
            Err(_) => {
                // Timeout or error - normal during scanning
            }
        }

        // Show progress
        let elapsed = start_time.elapsed().as_secs();
        print!(
            "\rScanning... {} seconds elapsed, {} devices found",
            elapsed,
            discovered_devices.len()
        );
        use std::io::{self, Write};
        io::stdout().flush()?;
    }

    println!("\n\nScan Complete!");
    println!("==============");
    println!("Total devices discovered: {}", discovered_devices.len());

    if !discovered_devices.is_empty() {
        println!("\nDevice Summary:");
        println!("---------------");

        // Sort by device ID
        let mut devices: Vec<_> = discovered_devices.values().collect();
        devices.sort_by_key(|d| d.device_id);

        for device in devices {
            println!(
                "Device {} @ {} - {}",
                device.device_id, device.address, device.vendor_name
            );
        }
    } else {
        println!("\nNo devices found. Possible reasons:");
        println!("- No BACnet devices on the network");
        println!("- Devices are on a different subnet");
        println!("- Firewall blocking BACnet traffic (UDP port 47808)");
        println!("- Devices configured for different port");
    }

    Ok(())
}

/// Process a received message and extract I-Am information
fn process_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
    println!(
        "  Raw data: {:02X?}",
        &data[..std::cmp::min(32, data.len())]
    );

    // The BacnetIpDataLink already strips the BVLC header, so we start with NPDU
    if data.len() < 2 {
        println!("  Too short for NPDU");
        return None;
    }

    // Decode NPDU starting from the beginning of the data
    let (_npdu, npdu_len) = match Npdu::decode(data) {
        Ok(result) => result,
        Err(e) => {
            println!("  Failed to decode NPDU: {:?}", e);
            return None;
        }
    };

    // Skip to APDU
    let apdu_start = npdu_len;
    if data.len() <= apdu_start {
        println!("  Too short for APDU");
        return None;
    }

    let apdu = &data[apdu_start..];

    // Check if this is an unconfirmed I-Am service
    if apdu.len() < 2 || apdu[0] != 0x10 {
        // Unconfirmed Request PDU
        return None;
    }

    let service_choice = apdu[1];
    if service_choice != UnconfirmedServiceChoice::IAm as u8 {
        return None;
    }

    // Decode I-Am request
    if apdu.len() <= 2 {
        return None;
    }

    match IAmRequest::decode(&apdu[2..]) {
        Ok(iam) => {
            let vendor_name = get_vendor_name(iam.vendor_identifier as u16)
                .unwrap_or("Unknown Vendor")
                .to_string();

            Some(DiscoveredDevice {
                device_id: iam.device_identifier.instance,
                address: source,
                vendor_id: iam.vendor_identifier,
                vendor_name,
                max_apdu: iam.max_apdu_length_accepted,
                segmentation: iam.segmentation_supported,
            })
        }
        Err(_) => None,
    }
}
