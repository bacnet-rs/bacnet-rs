//! BACnet Responder Device Example
//!
//! This example creates a simple BACnet device that responds to Who-Is requests
//! with I-Am responses, allowing it to be discovered by the Who-Is scan.

use bacnet_rs::{
    network::Npdu,
    object::Device,
    service::{IAmRequest, UnconfirmedServiceChoice, WhoIsRequest},
};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Responder Device Example");
    println!("==============================\n");

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let device_id: u32 = if args.len() > 1 {
        args[1].parse().unwrap_or(12345)
    } else {
        12345
    };

    // Create device
    let mut device = Device::new(device_id, format!("Test Device {}", device_id));
    device.set_vendor_by_id(260)?; // BACnet Stack at SourceForge
    device.model_name = "Rust BACnet Test Device".to_string();
    device.firmware_revision = "1.0.0".to_string();

    println!("Creating BACnet device:");
    println!("  Device ID: {}", device.identifier.instance);
    println!("  Name: {}", device.object_name);
    println!("  Vendor: {}", device.format_vendor_display());
    println!("  Model: {}", device.model_name);
    println!();

    // Bind to BACnet/IP port
    let bind_addr = "0.0.0.0:47808";
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    println!("Listening on {}...", bind_addr);
    println!("Device is ready to respond to Who-Is requests!");
    println!("Press Ctrl+C to stop.\n");

    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut recv_buffer = [0u8; 1500];
    let mut response_count = 0;

    while running.load(Ordering::SeqCst) {
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                // Process received message
                if let Some(whois) = process_whois(&recv_buffer[..len]) {
                    // Check if this Who-Is is for us
                    if whois.matches(device_id) {
                        println!("Received Who-Is from {} (matches our device)", source);

                        // Send I-Am response
                        if let Ok(response) = create_iam_response(&device, source) {
                            match socket.send_to(&response, source) {
                                Ok(_) => {
                                    response_count += 1;
                                    println!(
                                        "Sent I-Am response #{} to {}",
                                        response_count, source
                                    );
                                }
                                Err(e) => {
                                    eprintln!("Failed to send I-Am: {}", e);
                                }
                            }
                        }
                    } else {
                        println!("Received Who-Is from {} (not for us)", source);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout - continue listening
            }
            Err(e) => {
                eprintln!("Error receiving: {}", e);
            }
        }
    }

    println!("\nShutting down...");
    println!("Total I-Am responses sent: {}", response_count);

    Ok(())
}

/// Process a received message and extract Who-Is information
fn process_whois(data: &[u8]) -> Option<WhoIsRequest> {
    // Check BVLC header
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_function = data[1];
    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);

    if data.len() != bvlc_length as usize {
        return None;
    }

    // Skip BVLC header to get to NPDU
    let npdu_start = match bvlc_function {
        0x0A | 0x0B => 4, // Original-Unicast/Broadcast-NPDU
        0x04 => 10,       // Forwarded-NPDU
        _ => return None,
    };

    if data.len() <= npdu_start {
        return None;
    }

    // Decode NPDU
    let (_npdu, npdu_len) = match Npdu::decode(&data[npdu_start..]) {
        Ok(result) => result,
        Err(_) => return None,
    };

    // Skip to APDU
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }

    let apdu = &data[apdu_start..];

    // Check if this is an unconfirmed Who-Is service
    if apdu.len() < 2 || apdu[0] != 0x10 {
        return None;
    }

    let service_choice = apdu[1];
    if service_choice != UnconfirmedServiceChoice::WhoIs as u8 {
        return None;
    }

    // Decode Who-Is request
    if apdu.len() > 2 {
        WhoIsRequest::decode(&apdu[2..]).ok()
    } else {
        // Empty Who-Is (broadcast to all)
        Some(WhoIsRequest::new())
    }
}

/// Create an I-Am response message
fn create_iam_response<O>(
    device: &Device<O>,
    _destination: SocketAddr,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create I-Am request
    let iam = IAmRequest::new(
        device.identifier,
        1476, // Max APDU length
        0,    // Segmentation: both
        device.vendor_identifier as u32,
    );

    let mut iam_buffer = Vec::new();
    iam.encode(&mut iam_buffer)?;

    // Create NPDU
    let mut npdu = Npdu::new();
    npdu.control.priority = 0; // Normal priority

    let npdu_buffer = npdu.encode();

    // Create unconfirmed service request APDU
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
    apdu.push(UnconfirmedServiceChoice::IAm as u8);
    apdu.extend_from_slice(&iam_buffer);

    // Combine NPDU and APDU
    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu);

    // Wrap in BVLC header for BACnet/IP
    let mut bvlc_message = vec![
        0x81, // BVLC Type
        0x0A, // Original-Unicast-NPDU (unicast response)
        0x00, 0x00, // Length placeholder
    ];
    bvlc_message.extend_from_slice(&message);

    // Update BVLC length
    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;

    Ok(bvlc_message)
}
