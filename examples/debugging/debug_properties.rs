//! Debug Property Reading Example
//!
//! This example reads properties from just one object to debug
//! the response parsing more clearly.

use bacnet_rs::{
    app::{Apdu, MaxApduSize, MaxSegments},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType},
    property::decode_units,
    service::{
        ConfirmedServiceChoice, IAmRequest, PropertyReference, ReadAccessSpecification,
        ReadPropertyMultipleRequest, UnconfirmedServiceChoice, WhoIsRequest,
    },
};
use std::{
    env,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target_device_ip>", args[0]);
        eprintln!("Example: {} 10.161.1.211", args[0]);
        std::process::exit(1);
    }

    let target_ip = &args[1];
    let target_addr: SocketAddr = format!("{}:47808", target_ip).parse()?;

    println!("BACnet Property Reading Debug");
    println!("=============================\n");
    println!("Target device: {}", target_addr);

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Discover device
    println!("Discovering device...");
    let device_id = discover_device_id(&socket, target_addr)?;
    println!("Found device ID: {}", device_id);

    // Test reading properties from a single analog input
    let test_object = ObjectIdentifier::new(ObjectType::AnalogInput, 0);

    println!(
        "\nReading properties from {} Instance {}...",
        get_object_type_name(test_object.object_type),
        test_object.instance
    );

    let property_refs = vec![
        PropertyReference::new(77),  // Object_Name
        PropertyReference::new(28),  // Description
        PropertyReference::new(85),  // Present_Value
        PropertyReference::new(117), // Units
    ];

    let read_spec = ReadAccessSpecification::new(test_object, property_refs);
    let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

    let invoke_id = 1;
    let response_data = send_confirmed_request(
        &socket,
        target_addr,
        invoke_id,
        ConfirmedServiceChoice::ReadPropertyMultiple,
        &encode_rpm_request(&rpm_request)?,
    )?;

    println!("Response received: {} bytes", response_data.len());
    println!(
        "Raw response data (first 100 bytes): {:02X?}",
        &response_data[..std::cmp::min(100, response_data.len())]
    );

    // Try to parse the response
    parse_single_object_response(&response_data)?;

    Ok(())
}

/// Parse a single object response to debug the structure
fn parse_single_object_response(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nParsing response structure:");
    println!("==========================");

    let mut pos = 0;

    while pos < data.len() {
        let byte = data[pos];

        match byte {
            0x0C => {
                println!(
                    "Position {}: Found object identifier context tag (0x0C)",
                    pos
                );
                if pos + 4 < data.len() {
                    let obj_id_bytes = [data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]];
                    let obj_id = u32::from_be_bytes(obj_id_bytes);
                    let (obj_type, instance) = decode_object_id(obj_id);
                    println!("  Object: Type {} Instance {}", obj_type, instance);
                }
                pos += 5;
            }
            0x1E => {
                println!(
                    "Position {}: Found property results opening tag (0x1E)",
                    pos
                );
                pos += 1;
            }
            0x1F => {
                println!(
                    "Position {}: Found property results closing tag (0x1F)",
                    pos
                );
                pos += 1;
            }
            0x09 => {
                println!("Position {}: Found property identifier tag (0x09)", pos);
                if pos + 1 < data.len() {
                    println!("  Property ID: {}", data[pos + 1]);
                }
                pos += 2;
            }
            0x3E => {
                println!("Position {}: Found property value opening tag (0x3E)", pos);
                pos += 1;
            }
            0x3F => {
                println!("Position {}: Found property value closing tag (0x3F)", pos);
                pos += 1;
            }
            0x75 => {
                println!("Position {}: Found character string tag (0x75)", pos);
                if pos + 1 < data.len() {
                    let length = data[pos + 1];
                    println!("  String length: {}", length);
                    if pos + 2 + (length as usize) <= data.len() && length > 0 {
                        let string_data = &data[pos + 3..pos + 2 + (length as usize)]; // Skip encoding byte
                        let string = String::from_utf8_lossy(string_data);
                        println!("  String value: '{}'", string);
                    }
                }
                pos += 1;
            }
            0x44 => {
                println!("Position {}: Found real value tag (0x44)", pos);
                if pos + 4 < data.len() {
                    let bytes = [data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]];
                    let value = f32::from_be_bytes(bytes);
                    println!("  Real value: {}", value);
                }
                pos += 5;
            }
            0x91 => {
                println!("Position {}: Found enumerated tag (0x91)", pos);
                if pos + 1 < data.len() {
                    println!("  Enum value: {}", data[pos + 1]);
                    if let Some((units_name, _)) = decode_units(&data[pos..pos + 2]) {
                        println!("  Units: {}", units_name);
                    }
                }
                pos += 2;
            }
            _ => {
                pos += 1;
            }
        }
    }

    Ok(())
}

/// Rest of the utility functions (same as device_objects.rs)
fn discover_device_id(
    socket: &UdpSocket,
    target_addr: SocketAddr,
) -> Result<u32, Box<dyn std::error::Error>> {
    let whois = WhoIsRequest::new();
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;

    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = false;
    npdu.control.priority = 0;
    let npdu_buffer = npdu.encode();

    let mut apdu = vec![0x10];
    apdu.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu.extend_from_slice(&buffer);

    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu);

    let mut bvlc_message = vec![0x81, 0x0A, 0x00, 0x00];
    bvlc_message.extend_from_slice(&message);

    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;

    socket.send_to(&bvlc_message, target_addr)?;

    let mut recv_buffer = [0u8; 1500];
    let start_time = Instant::now();

    while start_time.elapsed() < Duration::from_secs(3) {
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                if source == target_addr {
                    if let Some(device_id) = process_iam_response(&recv_buffer[..len]) {
                        return Ok(device_id);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(_) => {
                continue;
            }
        }
    }

    Err("Failed to discover device ID".into())
}

fn process_iam_response(data: &[u8]) -> Option<u32> {
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    if data.len() != bvlc_length as usize {
        return None;
    }

    let npdu_start = 4;
    if data.len() <= npdu_start {
        return None;
    }

    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }

    let apdu = &data[apdu_start..];

    if apdu.len() < 2 || apdu[0] != 0x10 {
        return None;
    }

    let service_choice = apdu[1];
    if service_choice != UnconfirmedServiceChoice::IAm as u8 {
        return None;
    }

    if apdu.len() <= 2 {
        return None;
    }

    match IAmRequest::decode(&apdu[2..]) {
        Ok(iam) => Some(iam.device_identifier.instance),
        Err(_) => None,
    }
}

fn send_confirmed_request(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up1476,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice,
        service_data: service_data.to_vec(),
    };

    let apdu_data = apdu.encode();
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    npdu.control.priority = 0;
    let npdu_data = npdu.encode();

    let mut message = npdu_data;
    message.extend_from_slice(&apdu_data);

    let mut bvlc_message = vec![0x81, 0x0A, 0x00, 0x00];
    bvlc_message.extend_from_slice(&message);

    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;

    socket.send_to(&bvlc_message, target_addr)?;

    let mut recv_buffer = [0u8; 1500];
    let start_time = Instant::now();

    while start_time.elapsed() < Duration::from_secs(5) {
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                if source == target_addr {
                    if let Some(response_data) =
                        process_confirmed_response(&recv_buffer[..len], invoke_id)
                    {
                        return Ok(response_data);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(format!("Error receiving response: {}", e).into());
            }
        }
    }

    Err("Timeout waiting for response".into())
}

fn process_confirmed_response(data: &[u8], expected_invoke_id: u8) -> Option<Vec<u8>> {
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    if data.len() != bvlc_length as usize {
        return None;
    }

    let npdu_start = 4;
    if data.len() <= npdu_start {
        return None;
    }

    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }

    let apdu = Apdu::decode(&data[apdu_start..]).ok()?;

    match apdu {
        Apdu::ComplexAck {
            invoke_id,
            service_data,
            ..
        } => {
            if invoke_id == expected_invoke_id {
                Some(service_data)
            } else {
                None
            }
        }
        Apdu::Error {
            invoke_id,
            error_class,
            error_code,
            ..
        } => {
            if invoke_id == expected_invoke_id {
                println!("Error response: class={}, code={}", error_class, error_code);
            }
            None
        }
        _ => None,
    }
}

fn encode_rpm_request(
    request: &ReadPropertyMultipleRequest,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();

    for spec in &request.read_access_specifications {
        let object_id = encode_object_id(
            spec.object_identifier.object_type as u16,
            spec.object_identifier.instance,
        );
        buffer.push(0x0C);
        buffer.extend_from_slice(&object_id.to_be_bytes());

        buffer.push(0x1E);

        for prop_ref in &spec.property_references {
            buffer.push(0x09);
            buffer.push(prop_ref.property_identifier as u8);

            if let Some(array_index) = prop_ref.property_array_index {
                buffer.push(0x19);
                buffer.push(array_index as u8);
            }
        }

        buffer.push(0x1F);
    }

    Ok(buffer)
}

fn encode_object_id(object_type: u16, instance: u32) -> u32 {
    ((object_type as u32) << 22) | (instance & 0x3FFFFF)
}

fn decode_object_id(encoded: u32) -> (u16, u32) {
    let object_type = ((encoded >> 22) & 0x3FF) as u16;
    let instance = encoded & 0x3FFFFF;
    (object_type, instance)
}

fn get_object_type_name(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::AnalogInput => "Analog Input",
        ObjectType::AnalogOutput => "Analog Output",
        ObjectType::AnalogValue => "Analog Value",
        ObjectType::BinaryInput => "Binary Input",
        ObjectType::BinaryOutput => "Binary Output",
        ObjectType::BinaryValue => "Binary Value",
        _ => "Other",
    }
}
