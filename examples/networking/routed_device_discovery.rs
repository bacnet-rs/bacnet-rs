//! BACnet Routed Device Discovery Example
//!
//! This example demonstrates how to discover and read properties from
//! BACnet devices behind routers on different networks.

use bacnet_rs::{
    datalink::bip::{BvlcFunction, BvlcHeader},
    network::{NetworkAddress, Npdu},
    object::{ObjectType, PropertyIdentifier},
    service::{IAmRequest, ReadPropertyResponse, WhoIsRequest},
    vendor::get_vendor_name,
};
use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

const BACNET_PORT: u16 = 0xBAC0; // 47808

#[derive(Debug, Clone)]
struct RemoteDevice {
    device_id: u32,
    network_number: u16,
    mac_address: Vec<u8>,
    socket_addr: SocketAddr,
    #[allow(dead_code)]
    vendor_id: Option<u32>,
    vendor_name: Option<String>,
    object_name: Option<String>,
    model_name: Option<String>,
    description: Option<String>,
    location: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Routed Device Discovery");
    println!("==============================\n");

    // Create UDP socket for BACnet communication
    let socket = match UdpSocket::bind(format!("0.0.0.0:{}", BACNET_PORT)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind to BACnet port {}: {}", BACNET_PORT, e);
            eprintln!("Trying alternative port...");
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => {
                    println!("Bound to alternative port: {}", s.local_addr()?);
                    s
                }
                Err(e) => {
                    eprintln!("Failed to bind to any port: {}", e);
                    return Err(e.into());
                }
            }
        }
    };

    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    println!("Listening on {}", socket.local_addr()?);

    // Discover routers first
    println!("\nStep 1: Discovering BACnet routers...");
    let routers = match discover_routers(&socket) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Router discovery failed: {}", e);
            eprintln!("Continuing with device discovery...");
            HashMap::new()
        }
    };

    if routers.is_empty() {
        println!("No routers found. Trying direct device discovery...");
    } else {
        println!("Found {} router(s):", routers.len());
        for (network, addr) in &routers {
            println!("  - Network {}: Router at {}", network, addr);
        }
    }

    // Discover devices on all networks
    println!("\nStep 2: Discovering devices on all networks...");
    let mut devices = HashMap::new();

    // First, try global broadcast
    discover_devices_global(&socket, &mut devices)?;

    // Then try directed discovery for each known network
    for network in routers.keys() {
        discover_devices_on_network(&socket, *network, &mut devices)?;
    }

    if devices.is_empty() {
        println!("No devices found.");
        return Ok(());
    }

    println!("\nFound {} device(s) across all networks:", devices.len());
    for device in devices.values() {
        println!(
            "  - Device {} on Network {} (MAC: {:02X?})",
            device.device_id, device.network_number, device.mac_address
        );
    }

    // Read properties from all discovered devices
    println!("\nStep 3: Reading properties from all devices...");
    for device in devices.values_mut() {
        println!(
            "\nReading Device {} on Network {}:",
            device.device_id, device.network_number
        );
        read_device_properties(&socket, device);
    }

    // Display summary
    println!("\n\nDevice Discovery Summary");
    println!("========================");
    for device in devices.values() {
        println!("\nDevice ID: {}", device.device_id);
        println!("  Network: {}", device.network_number);
        println!("  MAC Address: {:02X?}", device.mac_address);
        println!("  Socket Address: {}", device.socket_addr);
        if let Some(name) = &device.vendor_name {
            println!("  Vendor: {}", name);
        }
        if let Some(name) = &device.object_name {
            println!("  Object Name: {}", name);
        }
        if let Some(model) = &device.model_name {
            println!("  Model: {}", model);
        }
        if let Some(desc) = &device.description {
            println!("  Description: {}", desc);
        }
        if let Some(loc) = &device.location {
            println!("  Location: {}", loc);
        }
    }

    Ok(())
}

fn discover_routers(
    socket: &UdpSocket,
) -> Result<HashMap<u16, SocketAddr>, Box<dyn std::error::Error>> {
    let mut routers = HashMap::new();

    // Create Who-Is-Router-To-Network NPDU (network layer message)
    let mut npdu = Npdu::new();
    npdu.control.network_message = true;

    // Network message data: message type 0x01 (Who-Is-Router-To-Network)
    let network_msg = vec![0x01];
    let npdu_bytes = encode_npdu_with_data(&npdu, &network_msg);

    // Wrap in BVLC header for broadcast
    let header = BvlcHeader::new(
        BvlcFunction::OriginalBroadcastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send to broadcast address
    if let Err(e) = socket.send_to(&frame, "255.255.255.255:47808") {
        eprintln!("Failed to send broadcast: {}. Trying local subnet...", e);
        // Try local subnet broadcast
        if let Err(e) = socket.send_to(&frame, "192.168.1.255:47808") {
            eprintln!("Failed to send to local subnet: {}", e);
        }
    }

    // Listen for I-Am-Router-To-Network responses
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(2) {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    // Skip BVLC header (4 bytes)
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if npdu.is_network_message() && npdu_data.len() > offset {
                            // Check if this is I-Am-Router-To-Network (0x02)
                            if npdu_data[offset] == 0x02 {
                                // Parse network numbers
                                let mut idx = offset + 1;
                                while idx + 1 < npdu_data.len() {
                                    let network =
                                        u16::from_be_bytes([npdu_data[idx], npdu_data[idx + 1]]);
                                    routers.insert(network, src_addr);
                                    idx += 2;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::TimedOut {
                    eprintln!("Error receiving: {:?}", e);
                }
            }
        }
    }

    Ok(routers)
}

fn discover_devices_global(
    socket: &UdpSocket,
    devices: &mut HashMap<u32, RemoteDevice>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create global Who-Is request
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;

    // Create APDU for unconfirmed request
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU
    apdu.push(0x08); // Service Choice: Who-Is
    apdu.extend_from_slice(&who_is_data);

    // Create NPDU for global broadcast
    let npdu = Npdu::global_broadcast();
    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);

    // Wrap in BVLC header for broadcast
    let header = BvlcHeader::new(
        BvlcFunction::OriginalBroadcastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send to broadcast address
    if let Err(e) = socket.send_to(&frame, "255.255.255.255:47808") {
        eprintln!(
            "Failed to send global broadcast: {}. Trying local subnet...",
            e
        );
        // Try local subnet broadcast
        if let Err(e) = socket.send_to(&frame, "192.168.1.255:47808") {
            eprintln!("Failed to send to local subnet: {}", e);
        }
    }

    // Listen for I-Am responses
    collect_i_am_responses(socket, devices, Duration::from_secs(3))?;

    Ok(())
}

fn discover_devices_on_network(
    socket: &UdpSocket,
    network: u16,
    devices: &mut HashMap<u32, RemoteDevice>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Discovering devices on network {}...", network);

    // Create Who-Is request
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;

    // Create APDU for unconfirmed request
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU
    apdu.push(0x08); // Service Choice: Who-Is
    apdu.extend_from_slice(&who_is_data);

    // Create NPDU with destination network
    let mut npdu = Npdu::new();
    npdu.control.destination_present = true;
    npdu.destination = Some(NetworkAddress {
        network,
        address: vec![], // Empty for broadcast
    });
    npdu.hop_count = Some(255);

    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);

    // Wrap in BVLC header for broadcast
    let header = BvlcHeader::new(
        BvlcFunction::OriginalBroadcastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send to broadcast address (router will forward)
    if let Err(e) = socket.send_to(&frame, "255.255.255.255:47808") {
        eprintln!("Failed to send to network {}: {}", network, e);
    }

    // Listen for I-Am responses
    collect_i_am_responses(socket, devices, Duration::from_secs(2))?;

    Ok(())
}

fn collect_i_am_responses(
    socket: &UdpSocket,
    devices: &mut HashMap<u32, RemoteDevice>,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < timeout {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    // Skip BVLC header (4 bytes)
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            // Check if this is an unconfirmed request
                            if apdu_data.len() > 1 && apdu_data[0] == 0x10 {
                                // Check if service choice is I-Am (0x00)
                                if apdu_data[1] == 0x00 {
                                    // Decode I-Am request
                                    if let Ok(i_am) = IAmRequest::decode(&apdu_data[2..]) {
                                        let device_id = i_am.device_identifier.instance;

                                        // Determine network number and MAC address
                                        let (network_number, mac_address) =
                                            if let Some(src_net) = npdu.source {
                                                (src_net.network, src_net.address)
                                            } else {
                                                // Local network
                                                (0, vec![])
                                            };

                                        let vendor_name =
                                            get_vendor_name(i_am.vendor_identifier as u16);

                                        let device = RemoteDevice {
                                            device_id,
                                            network_number,
                                            mac_address,
                                            socket_addr: src_addr,
                                            vendor_id: Some(i_am.vendor_identifier),
                                            vendor_name: vendor_name.map(|s| s.to_string()),
                                            object_name: None,
                                            model_name: None,
                                            description: None,
                                            location: None,
                                        };

                                        devices.insert(device_id, device);
                                        println!(
                                            "    Found device {} from {}",
                                            device_id, src_addr
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::TimedOut {
                    eprintln!("Error receiving: {:?}", e);
                }
            }
        }
    }

    Ok(())
}

fn read_device_properties(socket: &UdpSocket, device: &mut RemoteDevice) {
    println!("  Reading basic device properties...");

    // First read basic device properties
    let basic_properties = vec![
        (PropertyIdentifier::ObjectName.into(), "Object Name"),
        (PropertyIdentifier::ModelName.into(), "Model Name"),
        (PropertyIdentifier::VendorName.into(), "Vendor Name"),
        (
            PropertyIdentifier::FirmwareRevision.into(),
            "Firmware Revision",
        ),
    ];

    for (property_id, property_name) in basic_properties {
        print!("    Reading {}... ", property_name);

        // Small delay between property reads
        std::thread::sleep(Duration::from_millis(100));

        match read_property(socket, device, property_id) {
            Ok(value) => {
                match property_id {
                    77 => device.object_name = Some(value.clone()), // ObjectName
                    70 => device.model_name = Some(value.clone()),  // ModelName
                    121 => device.vendor_name = Some(value.clone()), // VendorName
                    44 => device.description = Some(value.clone()), // FirmwareRevision
                    _ => {}
                }
                println!("{}", value);
            }
            Err(e) => {
                println!("Failed: {}", e);
            }
        }
    }

    // Now read the Object-List to discover all objects
    println!("  Reading Object-List...");
    std::thread::sleep(Duration::from_millis(200));

    match read_object_list(socket, device) {
        Ok(objects) => {
            println!("    Found {} objects:", objects.len());

            // Read properties for each object
            for (i, obj_id) in objects.iter().enumerate() {
                if i >= 20 {
                    // Limit to first 20 objects to avoid overwhelming output
                    println!(
                        "    ... and {} more objects (truncated)",
                        objects.len() - 20
                    );
                    break;
                }

                println!(
                    "    Object {}: Type={}, Instance={}",
                    i + 1,
                    object_type_name(obj_id.object_type),
                    obj_id.instance
                );

                // Read Object Name for each object
                match read_object_property(
                    socket,
                    device,
                    obj_id,
                    PropertyIdentifier::ObjectName.into(),
                ) {
                    Ok(name) => println!("      Name: {}", name),
                    Err(_) => println!("      Name: <unavailable>"),
                }

                // Read Present Value if it's an I/O object
                if is_io_object(obj_id.object_type) {
                    if let Ok(value) = read_object_property(
                        socket,
                        device,
                        obj_id,
                        PropertyIdentifier::PresentValue.into(),
                    ) {
                        println!("      Present Value: {}", value);
                    }
                }

                std::thread::sleep(Duration::from_millis(50)); // Small delay between objects
            }
        }
        Err(e) => {
            println!("    Failed to read Object-List: {}", e);
        }
    }
}

fn read_property(
    socket: &UdpSocket,
    device: &RemoteDevice,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicU8, Ordering};
    static INVOKE_ID: AtomicU8 = AtomicU8::new(0);

    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0

    // Create ReadProperty request following the official BACnet C stack implementation
    // Reference: bacnet-stack/src/bacnet/rp.c

    let mut apdu = vec![
        0x00,      // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
        0x05,      // encode_max_segs_max_apdu(0, MAX_APDU) - no segmentation, 1476 bytes
        invoke_id, // invoke_id
        0x0C,      // SERVICE_CONFIRMED_READ_PROPERTY (12)
    ];

    // ReadProperty Service Data - following read_property_request_encode()

    // Context tag 0: Object Identifier (BACnetObjectIdentifier)
    // Encode as 4-byte object identifier: (object_type << 22) | instance
    let object_type = ObjectType::Device as u32; // 8
    let object_id = (object_type << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&object_id.to_be_bytes());

    // Context tag 1: Property Identifier (BACnetPropertyIdentifier)
    // Encode as enumerated value
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    } else {
        apdu.push(0x1C); // Context tag [1], length 4
        apdu.extend_from_slice(&property_id.to_be_bytes());
    }

    // Context tag 2: Property Array Index is OPTIONAL
    // We don't include it, meaning we want the entire property (BACNET_ARRAY_ALL)

    // Debug: Print the request
    if device.device_id == 1 {
        // Only debug device 1
        println!("    DEBUG: Invoke ID: {}", invoke_id);
        println!(
            "    DEBUG: Device ID: {}, Property ID: {}",
            device.device_id, property_id
        );
        println!("    DEBUG: Object ID encoded: 0x{:08X}", object_id);
        println!("    DEBUG: Full APDU: {:02X?}", apdu);
    }

    // Create NPDU with proper addressing for routed devices
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;

    if device.network_number != 0 {
        npdu.control.destination_present = true;
        npdu.destination = Some(NetworkAddress {
            network: device.network_number,
            address: device.mac_address.clone(),
        });
        npdu.hop_count = Some(255);
    }

    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);

    // Wrap in BVLC header for unicast
    let header = BvlcHeader::new(
        BvlcFunction::OriginalUnicastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send to device address
    socket.send_to(&frame, device.socket_addr)?;

    // Wait for response
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(5) {
        match socket.recv_from(&mut buffer) {
            Ok((len, _src_addr)) => {
                if len > 4 {
                    // Skip BVLC header (4 bytes)
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            // Check PDU type
                            let pdu_type = (apdu_data[0] & 0xF0) >> 4;
                            let resp_invoke_id = apdu_data[0] & 0x0F;

                            if resp_invoke_id == (invoke_id & 0x0F) {
                                match pdu_type {
                                    0x3 => {
                                        // PDU_TYPE_COMPLEX_ACK
                                        // Complex ACK format: [PDU_TYPE+invoke_id] [service_choice] [service_data...]
                                        if apdu_data.len() >= 2 && apdu_data[1] == 0x0C {
                                            // SERVICE_CONFIRMED_READ_PROPERTY
                                            // Parse ReadProperty-ACK service data starting at byte 2
                                            if let Ok(response) =
                                                ReadPropertyResponse::decode(&apdu_data[2..])
                                            {
                                                return extract_string_value(
                                                    &response.property_value,
                                                );
                                            } else {
                                                // Try manual parsing if decode fails
                                                return parse_read_property_ack_manual(
                                                    &apdu_data[2..],
                                                );
                                            }
                                        }
                                    }
                                    0x5 => {
                                        // Simple ACK
                                        return Err(
                                            "Received Simple ACK instead of Complex ACK".into()
                                        );
                                    }
                                    0x6 => {
                                        // Error
                                        if apdu_data.len() >= 5 {
                                            let _error_choice = apdu_data[1];
                                            let error_class = apdu_data[2] & 0x3F; // Lower 6 bits
                                            let error_code = apdu_data[3];

                                            let error_class_str = match error_class {
                                                0 => "device",
                                                1 => "object",
                                                2 => "property",
                                                3 => "resources",
                                                4 => "security",
                                                5 => "services",
                                                6 => "vt",
                                                7 => "communication",
                                                _ => "unknown",
                                            };

                                            let error_code_str = match (error_class, error_code) {
                                                (2, 0) => "unknown-property",
                                                (2, 1) => "property-not-array",
                                                (2, 2) => "not-settable",
                                                (2, 3) => "invalid-array-index",
                                                _ => "unknown",
                                            };

                                            return Err(format!(
                                                "BACnet Error - Class: {} ({}), Code: {} ({})",
                                                error_class,
                                                error_class_str,
                                                error_code,
                                                error_code_str
                                            )
                                            .into());
                                        }
                                        return Err("BACnet Error (malformed)".into());
                                    }
                                    0x7 => {
                                        // Reject
                                        if apdu_data.len() >= 2 {
                                            let reject_reason = apdu_data[1];
                                            return Err(format!(
                                                "BACnet Reject - Reason: {}",
                                                reject_reason
                                            )
                                            .into());
                                        }
                                        return Err("BACnet Reject".into());
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Err("No response received".into())
}

fn extract_string_value(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok("(empty)".to_string());
    }

    // Simple tag decoding - look for character string tag (0x74)
    if data[0] == 0x74 || data[0] == 0x75 {
        // Character string
        let len = if data[0] == 0x74 {
            data[1] as usize
        } else {
            // Extended length
            ((data[1] as usize) << 8) | (data[2] as usize)
        };

        let start = if data[0] == 0x74 { 2 } else { 3 };
        if data.len() >= start + len {
            return Ok(String::from_utf8_lossy(&data[start..start + len]).to_string());
        }
    }

    // Try unsigned integer
    if (data[0] & 0xF0) == 0x20 {
        let len = (data[0] & 0x07) as usize;
        if len <= 4 && data.len() > len {
            let mut value = 0u32;
            for i in 0..len {
                value = (value << 8) | (data[1 + i] as u32);
            }
            return Ok(value.to_string());
        }
    }

    // Fallback to hex representation
    let hex_str = data
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join("");
    Ok(format!("0x{}", hex_str))
}

// Helper function to encode NPDU with data
fn encode_npdu_with_data(npdu: &Npdu, data: &[u8]) -> Vec<u8> {
    let mut buffer = npdu.encode();
    buffer.extend_from_slice(data);
    buffer
}

// Manual parser for ReadProperty-ACK following BACnet C stack format
fn parse_read_property_ack_manual(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.len() < 6 {
        return Err("ReadProperty-ACK too short".into());
    }

    let mut pos = 0;

    // Skip object identifier (context tag 0) - we already know what we asked for
    if data[pos] == 0x0C && pos + 5 < data.len() {
        pos += 5; // Context tag + 4 bytes object ID
    } else {
        return Err("Invalid object identifier in ReadProperty-ACK".into());
    }

    // Skip property identifier (context tag 1)
    if data[pos] == 0x19 && pos + 2 < data.len() {
        pos += 2; // Context tag + 1 byte property ID
    } else if data[pos] == 0x1A && pos + 3 < data.len() {
        pos += 3; // Context tag + 2 bytes property ID
    } else {
        return Err("Invalid property identifier in ReadProperty-ACK".into());
    }

    // Skip optional property array index (context tag 2) if present
    if pos < data.len() && (data[pos] & 0xF8) == 0x20 {
        let len = (data[pos] & 0x07) as usize;
        pos += 1 + len;
    }

    // Property value is in context tag 3 (opening/closing tags)
    if pos < data.len() && data[pos] == 0x3E {
        // Opening tag [3]
        pos += 1;

        // Find closing tag
        let value_start = pos;
        let mut value_end = pos;
        while value_end < data.len() && data[value_end] != 0x3F {
            // Closing tag [3]
            value_end += 1;
        }

        if value_end < data.len() {
            return extract_string_value(&data[value_start..value_end]);
        }
    }

    Err("Could not parse property value".into())
}

// Structure to represent a BACnet object identifier
#[derive(Debug, Clone, Copy)]
struct BACnetObjectId {
    object_type: ObjectType,
    instance: u32,
}

// Read the Object-List property to get all objects in the device
fn read_object_list(
    socket: &UdpSocket,
    device: &RemoteDevice,
) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    // Read Object-List property (property ID 76)
    match read_property(socket, device, PropertyIdentifier::ObjectList.into()) {
        Ok(_raw_data) => {
            // The Object-List is typically too large to read at once, so we might get an error
            // Let's try reading it with array indices
            read_object_list_with_indices(socket, device)
        }
        Err(_) => {
            // Try reading with array indices if direct read fails
            read_object_list_with_indices(socket, device)
        }
    }
}

// Read Object-List using array indices (more reliable for large lists)
fn read_object_list_with_indices(
    socket: &UdpSocket,
    device: &RemoteDevice,
) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    let mut objects = Vec::new();

    // First try to read index 0 to get the array length
    match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList.into(), 0) {
        Ok(length_str) => {
            if let Ok(length) = length_str.parse::<u32>() {
                println!("    Object-List has {} objects", length);

                // Read each object identifier
                for i in 1..=std::cmp::min(length, 50) {
                    // Limit to first 50 objects
                    match read_property_with_array_index(
                        socket,
                        device,
                        PropertyIdentifier::ObjectList.into(),
                        i,
                    ) {
                        Ok(obj_data) => {
                            if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                                objects.push(obj_id);
                            }
                        }
                        Err(_) => break, // Stop on first error
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        Err(_) => {
            // Fallback: try reading individual indices until we get errors
            for i in 1..=20 {
                // Try first 20 objects
                match read_property_with_array_index(
                    socket,
                    device,
                    PropertyIdentifier::ObjectList.into(),
                    i,
                ) {
                    Ok(obj_data) => {
                        if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                            objects.push(obj_id);
                        }
                    }
                    Err(_) => break, // Stop on first error
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    Ok(objects)
}

// Read a property from a specific object
fn read_object_property(
    socket: &UdpSocket,
    device: &RemoteDevice,
    object_id: &BACnetObjectId,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicU8, Ordering};
    static INVOKE_ID: AtomicU8 = AtomicU8::new(100); // Different counter for object properties

    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 101 } else { invoke_id };

    let mut apdu = vec![
        0x00,      // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
        0x05,      // encode_max_segs_max_apdu(0, MAX_APDU)
        invoke_id, // invoke_id
        0x0C,      // SERVICE_CONFIRMED_READ_PROPERTY
    ];

    // ReadProperty Service Data
    // Context tag 0: Object Identifier
    let object_type = object_id.object_type as u32;
    let obj_id = (object_type << 22) | (object_id.instance & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Context tag 1: Property Identifier
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    } else {
        apdu.push(0x1C); // Context tag [1], length 4
        apdu.extend_from_slice(&property_id.to_be_bytes());
    }

    // Send the request and wait for response (similar to read_property function)
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;

    if device.network_number != 0 {
        npdu.control.destination_present = true;
        npdu.destination = Some(NetworkAddress {
            network: device.network_number,
            address: device.mac_address.clone(),
        });
        npdu.hop_count = Some(255);
    }

    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);

    let header = BvlcHeader::new(
        BvlcFunction::OriginalUnicastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    socket.send_to(&frame, device.socket_addr)?;

    // Wait for response (simplified version)
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(3) {
        match socket.recv_from(&mut buffer) {
            Ok((len, _src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            let pdu_type = (apdu_data[0] & 0xF0) >> 4;
                            let resp_invoke_id = apdu_data[0] & 0x0F;

                            if resp_invoke_id == (invoke_id & 0x0F)
                                && pdu_type == 0x3
                                && apdu_data.len() >= 2
                                && apdu_data[1] == 0x0C
                            {
                                if let Ok(response) = ReadPropertyResponse::decode(&apdu_data[2..])
                                {
                                    return extract_string_value(&response.property_value);
                                } else {
                                    return parse_read_property_ack_manual(&apdu_data[2..]);
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Err("No response received".into())
}

// Read a property with array index
fn read_property_with_array_index(
    socket: &UdpSocket,
    device: &RemoteDevice,
    property_id: u32,
    array_index: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicU8, Ordering};
    static INVOKE_ID: AtomicU8 = AtomicU8::new(200); // Different counter for array properties

    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 201 } else { invoke_id };

    let mut apdu = vec![
        0x00,      // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
        0x05,      // encode_max_segs_max_apdu(0, MAX_APDU)
        invoke_id, // invoke_id
        0x0C,      // SERVICE_CONFIRMED_READ_PROPERTY
    ];

    // ReadProperty Service Data
    // Context tag 0: Object Identifier (Device)
    let object_type = ObjectType::Device as u32;
    let obj_id = (object_type << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Context tag 1: Property Identifier
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    }

    // Context tag 2: Property Array Index
    if array_index <= 255 {
        apdu.push(0x29); // Context tag [2], length 1
        apdu.push(array_index as u8);
    } else {
        apdu.push(0x2A); // Context tag [2], length 2
        apdu.extend_from_slice(&(array_index as u16).to_be_bytes());
    }

    // Send and receive (similar to other functions)
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;

    if device.network_number != 0 {
        npdu.control.destination_present = true;
        npdu.destination = Some(NetworkAddress {
            network: device.network_number,
            address: device.mac_address.clone(),
        });
        npdu.hop_count = Some(255);
    }

    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);
    let header = BvlcHeader::new(
        BvlcFunction::OriginalUnicastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    socket.send_to(&frame, device.socket_addr)?;

    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(3) {
        match socket.recv_from(&mut buffer) {
            Ok((len, _src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            let pdu_type = (apdu_data[0] & 0xF0) >> 4;
                            let resp_invoke_id = apdu_data[0] & 0x0F;

                            if resp_invoke_id == (invoke_id & 0x0F)
                                && pdu_type == 0x3
                                && apdu_data.len() >= 2
                                && apdu_data[1] == 0x0C
                            {
                                if let Ok(response) = ReadPropertyResponse::decode(&apdu_data[2..])
                                {
                                    return extract_string_value(&response.property_value);
                                } else {
                                    return parse_read_property_ack_manual(&apdu_data[2..]);
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Err("No response received".into())
}

// Parse object identifier from hex string representation
fn parse_object_identifier(data: &str) -> Result<BACnetObjectId, Box<dyn std::error::Error>> {
    // Expected format is hex string like "0x02000001" for object ID
    // First, let's try to parse it as hex
    if data.starts_with("0x") && data.len() >= 10 {
        if let Ok(obj_id_value) = u32::from_str_radix(&data[2..], 16) {
            let object_type_num = (obj_id_value >> 22) & 0x3FF; // Upper 10 bits
            let instance = obj_id_value & 0x3FFFFF; // Lower 22 bits

            let object_type =
                ObjectType::try_from(object_type_num as u16).unwrap_or(ObjectType::Device);

            return Ok(BACnetObjectId {
                object_type,
                instance,
            });
        }
    }

    // If we can't parse it, return an error
    Err(format!("Could not parse object identifier: {}", data).into())
}

// Get human-readable object type name
fn object_type_name(obj_type: ObjectType) -> &'static str {
    match obj_type {
        ObjectType::AnalogInput => "Analog Input",
        ObjectType::AnalogOutput => "Analog Output",
        ObjectType::AnalogValue => "Analog Value",
        ObjectType::BinaryInput => "Binary Input",
        ObjectType::BinaryOutput => "Binary Output",
        ObjectType::BinaryValue => "Binary Value",
        ObjectType::Device => "Device",
        ObjectType::MultiStateInput => "Multi-State Input",
        ObjectType::MultiStateOutput => "Multi-State Output",
        ObjectType::MultiStateValue => "Multi-State Value",
        ObjectType::TrendLog => "Trend Log",
        ObjectType::Schedule => "Schedule",
        ObjectType::Calendar => "Calendar",
        _ => "Unknown",
    }
}

// Check if object type typically has Present Value
fn is_io_object(obj_type: ObjectType) -> bool {
    matches!(
        obj_type,
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
