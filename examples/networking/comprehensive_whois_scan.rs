//! Comprehensive BACnet Who-Is Scan
//!
//! This example performs a complete BACnet network scan to discover all devices
//! and their objects, including devices behind routers on different networks.

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
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};

const BACNET_PORT: u16 = 0xBAC0; // 47808

#[derive(Debug, Clone)]
struct BACnetDevice {
    device_id: u32,
    network_number: u16,
    mac_address: Vec<u8>,
    socket_addr: SocketAddr,
    #[allow(dead_code)]
    vendor_id: u32,
    vendor_name: String,
    max_apdu: u32,
    segmentation: u32,
    // Device properties
    object_name: Option<String>,
    model_name: Option<String>,
    firmware_revision: Option<String>,
    // Objects in this device
    objects: Vec<BACnetObject>,
}

#[derive(Debug, Clone)]
struct BACnetObject {
    object_type: ObjectType,
    instance: u32,
    name: Option<String>,
    present_value: Option<String>,
    description: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("===========================================");
    println!("  BACnet Comprehensive Network Scan");
    println!("===========================================\n");

    // Create UDP socket
    let socket = match UdpSocket::bind(format!("0.0.0.0:{}", BACNET_PORT)) {
        Ok(s) => s,
        Err(_) => {
            println!("Standard port busy, using alternative port...");
            UdpSocket::bind("0.0.0.0:0")?
        }
    };

    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    println!("📡 Listening on {}", socket.local_addr()?);
    println!("🔍 Starting network discovery...\n");

    // Step 1: Discover routers
    println!("Step 1: Router Discovery");
    println!("========================");
    let routers = discover_routers(&socket)?;

    if routers.is_empty() {
        println!("ℹ️  No routers found on the network");
    } else {
        println!("🔗 Found {} router(s):", routers.len());
        for (network, addr) in &routers {
            println!("   Network {:>4}: Router at {}", network, addr);
        }
    }

    // Step 2: Discover all devices
    println!("\nStep 2: Device Discovery");
    println!("========================");
    let mut devices = HashMap::new();

    // Global broadcast first
    println!("🌐 Performing global broadcast...");
    discover_devices_global(&socket, &mut devices)?;

    // Then directed discovery for each known network
    for network in routers.keys() {
        println!("🎯 Scanning network {}...", network);
        discover_devices_on_network(&socket, *network, &mut devices)?;
    }

    if devices.is_empty() {
        println!("❌ No BACnet devices found on the network");
        return Ok(());
    }

    println!("\n📱 Discovered {} device(s):", devices.len());
    for device in devices.values() {
        let network_info = if device.network_number == 0 {
            "Local".to_string()
        } else {
            format!("Network {}", device.network_number)
        };
        println!(
            "   Device {:>4}: {} ({})",
            device.device_id, device.vendor_name, network_info
        );
    }

    // Step 3: Read device properties and objects
    println!("\nStep 3: Detailed Device Analysis");
    println!("=================================");

    for device in devices.values_mut() {
        analyze_device(&socket, device)?;
    }

    // Step 4: Display comprehensive summary
    println!("\n");
    println!("===========================================");
    println!("           NETWORK SCAN SUMMARY");
    println!("===========================================");

    display_comprehensive_summary(&devices);

    Ok(())
}

fn discover_routers(
    socket: &UdpSocket,
) -> Result<HashMap<u16, SocketAddr>, Box<dyn std::error::Error>> {
    let mut routers = HashMap::new();

    // Create Who-Is-Router-To-Network NPDU
    let mut npdu = Npdu::new();
    npdu.control.network_message = true;

    let network_msg = vec![0x01]; // Who-Is-Router-To-Network
    let npdu_bytes = encode_npdu_with_data(&npdu, &network_msg);

    let header = BvlcHeader::new(
        BvlcFunction::OriginalBroadcastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send broadcast
    let _ = socket.send_to(&frame, "255.255.255.255:47808");

    // Listen for responses
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(3) {
        if let Ok((len, src_addr)) = socket.recv_from(&mut buffer) {
            if len > 4 {
                let npdu_data = &buffer[4..len];
                if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                    if npdu.is_network_message()
                        && npdu_data.len() > offset
                        && npdu_data[offset] == 0x02
                    {
                        let mut idx = offset + 1;
                        while idx + 1 < npdu_data.len() {
                            let network = u16::from_be_bytes([npdu_data[idx], npdu_data[idx + 1]]);
                            routers.insert(network, src_addr);
                            idx += 2;
                        }
                    }
                }
            }
        }
    }

    Ok(routers)
}

fn discover_devices_global(
    socket: &UdpSocket,
    devices: &mut HashMap<u32, BACnetDevice>,
) -> Result<(), Box<dyn std::error::Error>> {
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;

    let mut apdu = vec![0x10, 0x08]; // Unconfirmed-Request, Who-Is
    apdu.extend_from_slice(&who_is_data);

    let npdu = Npdu::global_broadcast();
    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);

    let header = BvlcHeader::new(
        BvlcFunction::OriginalBroadcastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    let _ = socket.send_to(&frame, "255.255.255.255:47808");

    collect_i_am_responses(socket, devices, Duration::from_secs(5))?;
    Ok(())
}

fn discover_devices_on_network(
    socket: &UdpSocket,
    network: u16,
    devices: &mut HashMap<u32, BACnetDevice>,
) -> Result<(), Box<dyn std::error::Error>> {
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;

    let mut apdu = vec![0x10, 0x08]; // Unconfirmed-Request, Who-Is
    apdu.extend_from_slice(&who_is_data);

    let mut npdu = Npdu::new();
    npdu.control.destination_present = true;
    npdu.destination = Some(NetworkAddress {
        network,
        address: vec![], // Broadcast
    });
    npdu.hop_count = Some(255);

    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);

    let header = BvlcHeader::new(
        BvlcFunction::OriginalBroadcastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    let _ = socket.send_to(&frame, "255.255.255.255:47808");

    collect_i_am_responses(socket, devices, Duration::from_secs(3))?;
    Ok(())
}

fn collect_i_am_responses(
    socket: &UdpSocket,
    devices: &mut HashMap<u32, BACnetDevice>,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < timeout {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            if apdu_data.len() > 1 && apdu_data[0] == 0x10 && apdu_data[1] == 0x00 {
                                if let Ok(i_am) = IAmRequest::decode(&apdu_data[2..]) {
                                    let device_id = i_am.device_identifier.instance;

                                    let (network_number, mac_address) =
                                        if let Some(src_net) = npdu.source {
                                            (src_net.network, src_net.address)
                                        } else {
                                            (0, vec![])
                                        };

                                    let vendor_name =
                                        get_vendor_name(i_am.vendor_identifier as u16)
                                            .unwrap_or("Unknown Vendor");

                                    let device = BACnetDevice {
                                        device_id,
                                        network_number,
                                        mac_address,
                                        socket_addr: src_addr,
                                        vendor_id: i_am.vendor_identifier,
                                        vendor_name: vendor_name.to_string(),
                                        max_apdu: i_am.max_apdu_length_accepted,
                                        segmentation: i_am.segmentation_supported,
                                        object_name: None,
                                        model_name: None,
                                        firmware_revision: None,
                                        objects: Vec::new(),
                                    };

                                    devices.insert(device_id, device);
                                    print!(".");
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::TimedOut {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn analyze_device(
    socket: &UdpSocket,
    device: &mut BACnetDevice,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\n📱 Analyzing Device {} - {}",
        device.device_id, device.vendor_name
    );
    println!(
        "   Network: {}, Address: {}",
        if device.network_number == 0 {
            "Local".to_string()
        } else {
            device.network_number.to_string()
        },
        device.socket_addr
    );

    // Read basic device properties
    println!("   📋 Reading device properties...");

    if let Ok(name) = read_device_property(socket, device, PropertyIdentifier::ObjectName.into()) {
        if let Ok(parsed_name) = parse_string_from_response(&name) {
            // Clean up device names with null bytes and control characters
            let cleaned_name = parsed_name
                .chars()
                .filter(|&c| c != '\0' && !c.is_control())
                .collect::<String>()
                .trim()
                .to_string();
            device.object_name = Some(cleaned_name.clone());
            println!("   Device Name: \"{}\"", cleaned_name);
        } else {
            println!("   Device Name: (unable to decode: {})", name);
        }
    }

    if let Ok(model) = read_device_property(socket, device, PropertyIdentifier::ModelName.into()) {
        if let Ok(parsed_model) = parse_string_from_response(&model) {
            device.model_name = Some(parsed_model);
        }
    }

    if let Ok(firmware) =
        read_device_property(socket, device, PropertyIdentifier::FirmwareRevision.into())
    {
        if let Ok(parsed_firmware) = parse_string_from_response(&firmware) {
            device.firmware_revision = Some(parsed_firmware);
        }
    }

    // Read object list with alternative approaches
    println!("   🔍 Discovering objects...");

    // Try different approaches to read object list
    if let Ok(count) = try_read_object_list_multiple_approaches(socket, device) {
        println!("      Found {} objects using alternative method", count);

        // Read details for each object (limit to avoid overwhelming output)
        if count > 1 {
            // More than just the device object
            println!("      Reading object details...");
            let objects_to_read = device.objects.len(); // Read all objects
            for i in 0..objects_to_read {
                // Read object name
                if let Ok(name) = read_object_property_simple(
                    socket,
                    device,
                    &device.objects[i],
                    PropertyIdentifier::ObjectName.into(),
                ) {
                    if let Ok(parsed_name) = parse_string_from_response(&name) {
                        // Clean up object names - remove null bytes and control characters
                        let cleaned_name = parsed_name
                            .chars()
                            .filter(|&c| c != '\0' && !c.is_control())
                            .collect::<String>()
                            .trim()
                            .to_string();

                        // Validate the name - if it looks like binary garbage, skip it
                        let printable_ratio = cleaned_name
                            .chars()
                            .filter(|&c| {
                                c.is_ascii_alphanumeric()
                                    || c == '.'
                                    || c == '-'
                                    || c == '_'
                                    || c == ' '
                                    || c == '/'
                            })
                            .count() as f32
                            / cleaned_name.len().max(1) as f32;

                        if printable_ratio > 0.7 && !cleaned_name.is_empty() {
                            device.objects[i].name = Some(cleaned_name);
                        } else if !cleaned_name.is_empty()
                            && cleaned_name
                                .chars()
                                .all(|c| c.is_ascii_graphic() || c == ' ')
                        {
                            // Accept names that are all printable ASCII even if they don't meet the ratio test
                            device.objects[i].name = Some(cleaned_name);
                        }
                    }
                }

                // Read present value for I/O objects
                if is_io_object(device.objects[i].object_type) {
                    if let Ok(value) = read_object_property_simple(
                        socket,
                        device,
                        &device.objects[i],
                        PropertyIdentifier::PresentValue.into(),
                    ) {
                        // Special handling for binary objects
                        if let Ok(parsed_value) = parse_value_from_response(&value) {
                            device.objects[i].present_value = Some(parsed_value);
                        }
                    }

                    // Try to read units for analog objects
                    if matches!(
                        device.objects[i].object_type,
                        ObjectType::AnalogInput
                            | ObjectType::AnalogOutput
                            | ObjectType::AnalogValue
                    ) {
                        if let Ok(units) = read_object_property_simple(
                            socket,
                            device,
                            &device.objects[i],
                            PropertyIdentifier::OutputUnits.into(),
                        ) {
                            if let Ok(parsed_units) = parse_units_from_response(&units) {
                                device.objects[i].description =
                                    Some(format!("Units: {}", parsed_units));
                            }
                        }
                    }
                }

                std::thread::sleep(Duration::from_millis(100)); // Small delay between reads
            }
        }
    }

    // match read_object_list(socket, device) {
    //     Ok(object_count) => {
    //         println!("      Found {} objects", object_count);
    //
    //         // Read details for each object (limit to avoid overwhelming output)
    //         let objects_to_read = std::cmp::min(device.objects.len(), 10);
    //         for i in 0..objects_to_read {
    //             // Read object name
    //             if let Ok(name) = read_object_property(socket, device, &device.objects[i], PropertyIdentifier::ObjectName.into()) {
    //                 device.objects[i].name = Some(name);
    //             }
    //
    //             // Read present value for I/O objects
    //             if is_io_object(device.objects[i].object_type) {
    //                 if let Ok(value) = read_object_property(socket, device, &device.objects[i], PropertyIdentifier::PresentValue.into()) {
    //                     device.objects[i].present_value = Some(value);
    //                 }
    //             }
    //
    //             std::thread::sleep(Duration::from_millis(50));
    //         }
    //     }
    //     Err(e) => {
    //         println!("      Failed to read object list: {}", e);
    //     }
    // }

    Ok(())
}

fn read_device_property(
    socket: &UdpSocket,
    device: &BACnetDevice,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(1);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0

    // Create ReadProperty request following the official BACnet C stack implementation
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

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn try_read_object_list_multiple_approaches(
    socket: &UdpSocket,
    device: &mut BACnetDevice,
) -> Result<usize, Box<dyn std::error::Error>> {
    // First try to read the array length (index 0)
    match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList.into(), 0) {
        Ok(length_response) => {
            // Parse the length - it might be a number like "84" or an encoded value
            let length = length_response.parse::<u32>().unwrap_or(100);

            // Read each object identifier by array index
            for i in 1..=std::cmp::min(length, 1000) {
                // Limit to 1000 objects
                match read_property_with_array_index(
                    socket,
                    device,
                    PropertyIdentifier::ObjectList.into(),
                    i,
                ) {
                    Ok(obj_response) => {
                        // Parse different response formats

                        // Format 1: "Object(type,instance)"
                        if let Some(captures) = obj_response
                            .strip_prefix("Object(")
                            .and_then(|s| s.strip_suffix(")"))
                        {
                            let parts: Vec<&str> = captures.split(',').collect();
                            if parts.len() == 2 {
                                if let (Ok(obj_type), Ok(instance)) =
                                    (parts[0].parse::<u16>(), parts[1].parse::<u32>())
                                {
                                    if let Ok(object_type) = ObjectType::try_from(obj_type) {
                                        let obj = BACnetObject {
                                            object_type,
                                            instance,
                                            name: None,
                                            present_value: None,
                                            description: None,
                                        };
                                        device.objects.push(obj);
                                    }
                                }
                            }
                        }

                        // Format 2: "Objects: [TYPE:instance]"
                        if obj_response.starts_with("Objects: [") && obj_response.ends_with("]") {
                            let objects_str = &obj_response[10..obj_response.len() - 1];
                            if let Some(colon_pos) = objects_str.find(':') {
                                let type_str = &objects_str[..colon_pos];
                                let instance_str = &objects_str[colon_pos + 1..];

                                if let Ok(instance) = instance_str.parse::<u32>() {
                                    let object_type = match type_str {
                                        "DEV" => Some(ObjectType::Device),
                                        "AI" => Some(ObjectType::AnalogInput),
                                        "AO" => Some(ObjectType::AnalogOutput),
                                        "AV" => Some(ObjectType::AnalogValue),
                                        "BI" => Some(ObjectType::BinaryInput),
                                        "BO" => Some(ObjectType::BinaryOutput),
                                        "BV" => Some(ObjectType::BinaryValue),
                                        "MSI" => Some(ObjectType::MultiStateInput),
                                        "MSO" => Some(ObjectType::MultiStateOutput),
                                        "MSV" => Some(ObjectType::MultiStateValue),
                                        _ => None,
                                    };

                                    if let Some(obj_type) = object_type {
                                        let obj = BACnetObject {
                                            object_type: obj_type,
                                            instance,
                                            name: None,
                                            present_value: None,
                                            description: None,
                                        };
                                        device.objects.push(obj);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Log error but continue reading other objects
                        println!(
                            "         ⚠️  Failed to read object name at index {}: {:?}",
                            i, e
                        );
                        continue;
                    }
                }
                std::thread::sleep(Duration::from_millis(50)); // Small delay between reads
            }

            if !device.objects.is_empty() {
                return Ok(device.objects.len());
            }
        }
        Err(_) => {
            // Could not read array length, try fallback methods
        }
    }

    // Fallback to other methods
    read_object_list(socket, device)
}

#[allow(dead_code)]
fn read_device_property_simple(
    socket: &UdpSocket,
    device: &BACnetDevice,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(50);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };

    // Simpler APDU construction
    let mut apdu = vec![
        0x00, // Confirmed-Request
        0x05, // Max segments/APDU
        invoke_id, 0x0C, // ReadProperty
    ];

    // Object ID for device
    let obj_id = ((ObjectType::Device as u32) << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Property ID
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

#[allow(dead_code)]
fn read_device_property_alternative(
    socket: &UdpSocket,
    device: &BACnetDevice,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(150);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };

    // Alternative encoding - try different max APDU
    let mut apdu = vec![
        0x00, // Confirmed-Request
        0x00, // No segmentation, 50 byte APDU
        invoke_id, 0x0C, // ReadProperty
    ];

    // Object ID for device
    let obj_id = ((ObjectType::Device as u32) << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Property ID
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_object_list(
    socket: &UdpSocket,
    device: &mut BACnetDevice,
) -> Result<usize, Box<dyn std::error::Error>> {
    // First try to read the entire object list at once
    println!("   🔍 Attempting to read entire object list at once...");
    match read_device_property(socket, device, PropertyIdentifier::ObjectList.into()) {
        Ok(obj_list_data) => {
            println!(
                "   ✅ Received object list response: {} bytes",
                obj_list_data.len()
            );
            match parse_object_list_response(&obj_list_data) {
                Ok(objects) => {
                    println!(
                        "   ✅ Successfully parsed {} objects from bulk read",
                        objects.len()
                    );
                    for obj_id in objects {
                        let obj = BACnetObject {
                            object_type: obj_id.object_type,
                            instance: obj_id.instance,
                            name: None,
                            present_value: None,
                            description: None,
                        };
                        device.objects.push(obj);
                    }
                    return Ok(device.objects.len());
                }
                Err(e) => {
                    println!("   ⚠️  Failed to parse object list: {}", e);
                }
            }
        }
        Err(e) => {
            println!("   ⚠️  Failed to read object list: {}", e);
        }
    }

    // Fallback to reading array length first
    println!("   🔄 Falling back to reading object list by array indices...");
    match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList.into(), 0) {
        Ok(length_str) => {
            if let Ok(length) = length_str.parse::<u32>() {
                println!("   📊 Object list has {} items", length);
                let max_to_read = std::cmp::min(length, 1000);
                println!("   📖 Will attempt to read {} objects", max_to_read);
                let mut successful_reads = 0;
                let mut failed_reads = 0;
                // Read each object identifier
                for i in 1..=max_to_read {
                    if i <= 5 || i == max_to_read || (i % 10 == 0) {
                        println!("      📍 Reading object at index {}...", i);
                    }
                    match read_property_with_array_index(
                        socket,
                        device,
                        PropertyIdentifier::ObjectList.into(),
                        i,
                    ) {
                        Ok(obj_data) => {
                            if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                                let obj = BACnetObject {
                                    object_type: obj_id.object_type,
                                    instance: obj_id.instance,
                                    name: None,
                                    present_value: None,
                                    description: None,
                                };
                                device.objects.push(obj);
                                successful_reads += 1;
                            } else {
                                println!("      ⚠️  Failed to parse object at index {}", i);
                                failed_reads += 1;
                            }
                        }
                        Err(e) => {
                            println!("      ⚠️  Failed to read object at index {}: {}", i, e);
                            failed_reads += 1;
                            // Continue instead of breaking to handle sparse indices
                            continue;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(30));
                }
                println!(
                    "   📊 Read summary: {} successful, {} failed out of {} attempted",
                    successful_reads, failed_reads, max_to_read
                );
                Ok(device.objects.len())
            } else {
                Err("Could not parse object list length".into())
            }
        }
        Err(_) => {
            // Fallback: try reading indices until we get errors
            for i in 1..=20 {
                match read_property_with_array_index(
                    socket,
                    device,
                    PropertyIdentifier::ObjectList.into(),
                    i,
                ) {
                    Ok(obj_data) => {
                        if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                            let obj = BACnetObject {
                                object_type: obj_id.object_type,
                                instance: obj_id.instance,
                                name: None,
                                present_value: None,
                                description: None,
                            };
                            device.objects.push(obj);
                        }
                    }
                    Err(e) => {
                        println!("      ⚠️  Failed to read object at index {}: {}", i, e);
                        // Continue to handle sparse indices
                        continue;
                    }
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            Ok(device.objects.len())
        }
    }
}

fn read_property_with_array_index(
    socket: &UdpSocket,
    device: &BACnetDevice,
    property_id: u32,
    array_index: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(100);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0

    // Create ReadProperty request following the official BACnet C stack implementation
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

    // Context tag 2: Property Array Index (optional)
    if array_index <= 255 {
        apdu.push(0x29); // Context tag [2], length 1
        apdu.push(array_index as u8);
    } else if array_index <= 65535 {
        apdu.push(0x2A); // Context tag [2], length 2
        apdu.extend_from_slice(&(array_index as u16).to_be_bytes());
    } else {
        apdu.push(0x2C); // Context tag [2], length 4
        apdu.extend_from_slice(&array_index.to_be_bytes());
    }

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_object_property_simple(
    socket: &UdpSocket,
    device: &BACnetDevice,
    object: &BACnetObject,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(200);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };

    // Simple APDU construction for object properties
    let mut apdu = vec![
        0x00, // Confirmed-Request
        0x05, // Max segments/APDU
        invoke_id, 0x0C, // ReadProperty
    ];

    // Object ID
    let obj_id = ((object.object_type as u32) << 22) | (object.instance & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Property ID
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

#[allow(dead_code)]
fn read_object_property(
    socket: &UdpSocket,
    device: &BACnetDevice,
    object: &BACnetObject,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(200);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0

    // Create ReadProperty request following the official BACnet C stack implementation
    let mut apdu = vec![
        0x00,      // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
        0x05,      // encode_max_segs_max_apdu(0, MAX_APDU) - no segmentation, 1476 bytes
        invoke_id, // invoke_id
        0x0C,      // SERVICE_CONFIRMED_READ_PROPERTY (12)
    ];

    // ReadProperty Service Data - following read_property_request_encode()

    // Context tag 0: Object Identifier (BACnetObjectIdentifier)
    // Encode as 4-byte object identifier: (object_type << 22) | instance
    let object_id = ((object.object_type as u32) << 22) | (object.instance & 0x3FFFFF);
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

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn send_request_and_get_response(
    socket: &UdpSocket,
    device: &BACnetDevice,
    apdu: &[u8],
    invoke_id: u8,
) -> Result<String, Box<dyn std::error::Error>> {
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

    let npdu_bytes = encode_npdu_with_data(&npdu, apdu);
    let header = BvlcHeader::new(
        BvlcFunction::OriginalUnicastNpdu,
        4 + npdu_bytes.len() as u16,
    );
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    socket.send_to(&frame, device.socket_addr)?;

    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(2) {
        // Shorter timeout for property reads
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];

                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            let pdu_type = (apdu_data[0] & 0xF0) >> 4;
                            let resp_invoke_id = apdu_data[0] & 0x0F;

                            // Some devices don't echo invoke ID correctly, so accept any response from our target device
                            if resp_invoke_id == (invoke_id & 0x0F)
                                || src_addr == device.socket_addr
                            {
                                if pdu_type == 0x3 {
                                    // Complex ACK
                                    if apdu_data.len() >= 2 && apdu_data[1] == 0x0C {
                                        if let Ok(response) =
                                            ReadPropertyResponse::decode(&apdu_data[2..])
                                        {
                                            return decode_bacnet_value(&response.property_value);
                                        }
                                    }
                                    // Try to parse as raw property data
                                    return parse_raw_response(apdu_data);
                                } else if pdu_type == 0x5 {
                                    // Error
                                    return Err("Device returned error".into());
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::TimedOut
                {
                    continue;
                }
            }
        }
    }
    Err("Timeout".into())
}

fn display_comprehensive_summary(devices: &HashMap<u32, BACnetDevice>) {
    let total_objects: usize = devices.values().map(|d| d.objects.len()).sum();

    println!("STATISTICS:");
    println!("   Total Devices: {}", devices.len());
    println!("   Total Objects: {}", total_objects);

    let mut networks: Vec<u16> = devices.values().map(|d| d.network_number).collect();
    networks.sort();
    networks.dedup();
    println!(
        "   Networks: {}",
        if networks.len() == 1 && networks[0] == 0 {
            "Local".to_string()
        } else {
            format!("{:?}", networks)
        }
    );

    println!("\nDEVICE INVENTORY:");
    println!("{}", "=".repeat(80));

    for device in devices.values() {
        let network_info = if device.network_number == 0 {
            "Local".to_string()
        } else {
            format!("Network {}", device.network_number)
        };

        println!(
            "\nDEVICE {} - {} ({})",
            device.device_id, device.vendor_name, network_info
        );
        if let Some(name) = &device.object_name {
            println!("   Name: {}", name);
        }
        if let Some(model) = &device.model_name {
            println!("   Model: {}", model);
        }
        if let Some(firmware) = &device.firmware_revision {
            println!("   Firmware: {}", firmware);
        }
        println!("   Address: {}", device.socket_addr);
        println!(
            "   Max APDU: {}, Segmentation: {}",
            device.max_apdu, device.segmentation
        );

        if !device.objects.is_empty() {
            println!("   OBJECTS ({}):", device.objects.len());

            for (i, obj) in device.objects.iter().enumerate() {
                // No limit - print all objects

                let obj_name = obj.name.as_deref().unwrap_or("<unnamed>");
                let type_name = object_type_name(obj.object_type);

                print!(
                    "      {:2}. {} {} '{}'",
                    i + 1,
                    type_name,
                    obj.instance,
                    obj_name
                );

                if let Some(value) = &obj.present_value {
                    print!(" = {}", value);
                }

                if let Some(description) = &obj.description {
                    if description.starts_with("Units: ") {
                        print!(" {}", description);
                    }
                }

                println!();
            }
        } else {
            println!("   OBJECTS: Unable to read object list");
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("Network scan complete!");
}

// Helper functions (same as previous example)
fn encode_npdu_with_data(npdu: &Npdu, data: &[u8]) -> Vec<u8> {
    let mut buffer = npdu.encode();
    buffer.extend_from_slice(data);
    buffer
}

#[derive(Debug, Clone, Copy)]
struct BACnetObjectId {
    object_type: ObjectType,
    instance: u32,
}

fn parse_object_identifier(data: &str) -> Result<BACnetObjectId, Box<dyn std::error::Error>> {
    if data.starts_with("0x") && data.len() >= 10 {
        if let Ok(obj_id_value) = u32::from_str_radix(&data[2..], 16) {
            let object_type_num = (obj_id_value >> 22) & 0x3FF;
            let instance = obj_id_value & 0x3FFFFF;

            let object_type =
                ObjectType::try_from(object_type_num as u16).unwrap_or(ObjectType::Device);

            return Ok(BACnetObjectId {
                object_type,
                instance,
            });
        }
    }
    Err(format!("Could not parse object identifier: {}", data).into())
}

fn parse_object_list_response(
    data: &str,
) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    // Handle "Objects: [...]" format from parse_raw_response
    if data.starts_with("Objects: [") && data.ends_with("]") {
        return parse_object_identifiers_from_response(data);
    }

    // Try to parse as hex string
    if let Some(hex_str) = data.strip_prefix("0x") {
        if let Ok(bytes) = decode_hex(hex_str) {
            return parse_object_list_from_bytes(&bytes);
        }
    }

    Err("No objects found in response".into())
}

fn parse_object_list_from_bytes(
    data: &[u8],
) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    let mut objects = Vec::new();
    let mut i = 0;

    // Skip any initial context tags
    while i < data.len() && (data[i] == 0x3E || data[i] == 0x30) {
        if data[i] == 0x3E {
            // Context tag with possible extended length
            i += 1;
            while i < data.len() && (data[i] & 0x07) == 0x07 {
                i += 1;
            }
            if i < data.len() {
                i += 1; // Skip the length byte
            }
        } else {
            i += 1;
        }
    }

    // Look for object identifier patterns (C4 XX XX XX XX)
    while i + 4 < data.len() {
        if data[i] == 0xC4 && i + 4 < data.len() {
            let obj_bytes = [data[i + 1], data[i + 2], data[i + 3], data[i + 4]];
            let obj_id_value = u32::from_be_bytes(obj_bytes);
            let object_type_num = (obj_id_value >> 22) & 0x3FF;
            let instance = obj_id_value & 0x3FFFFF;

            if let Ok(object_type) = ObjectType::try_from(object_type_num as u16) {
                objects.push(BACnetObjectId {
                    object_type,
                    instance,
                });
            }
            i += 5;
        } else {
            i += 1;
        }
    }

    Ok(objects)
}

fn parse_object_identifiers_from_response(
    response: &str,
) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    // Handle hex-encoded response
    if let Some(hex_str) = response.strip_prefix("0x") {
        if let Ok(bytes) = decode_hex(hex_str) {
            return parse_object_list_from_bytes(&bytes);
        }
        return Err("Failed to decode hex response".into());
    }

    // Handle "Objects: [...]" format
    if response.starts_with("Objects: [") {
        let objects_str = &response[10..response.len() - 1]; // Remove "Objects: [" and "]"
        let mut objects = Vec::new();

        for obj_str in objects_str.split(", ") {
            if let Some(colon_pos) = obj_str.find(':') {
                let type_str = &obj_str[..colon_pos];
                let instance_str = &obj_str[colon_pos + 1..];

                if let Ok(instance) = instance_str.parse::<u32>() {
                    let object_type = match type_str {
                        "DEV" => ObjectType::Device,
                        "AI" => ObjectType::AnalogInput,
                        "AO" => ObjectType::AnalogOutput,
                        "AV" => ObjectType::AnalogValue,
                        "BI" => ObjectType::BinaryInput,
                        "BO" => ObjectType::BinaryOutput,
                        "BV" => ObjectType::BinaryValue,
                        "MSI" => ObjectType::MultiStateInput,
                        "MSO" => ObjectType::MultiStateOutput,
                        "MSV" => ObjectType::MultiStateValue,
                        "STRUCTURED_VIEW" => ObjectType::StructuredView,
                        "SV" => ObjectType::StructuredView,
                        _ => {
                            println!("      ⚠️  Unknown object type: {}", type_str);
                            continue; // Skip unknown types
                        }
                    };

                    objects.push(BACnetObjectId {
                        object_type,
                        instance,
                    });
                }
            }
        }

        return Ok(objects);
    }

    Err("Unknown response format".into())
}

fn parse_raw_response(apdu_data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    // Keep the original logic but use hex crate for encoding

    // Skip the ACK header and service choice if present
    let start_idx = if apdu_data.len() > 2 && apdu_data[0] == 0x30 && apdu_data[1] == 0x0C {
        2 // Skip complex ACK header
    } else {
        0
    };

    if apdu_data.len() > start_idx {
        let data = &apdu_data[start_idx..];

        // Try to decode as BACnet value
        if let Ok(value) = decode_bacnet_value(data) {
            return Ok(value);
        }
    }

    // Fallback: look for object identifiers in the response (pattern: C4 XX XX XX XX for object IDs)
    let mut objects = Vec::new();
    let mut i = 0;

    while i + 4 < apdu_data.len() {
        if apdu_data[i] == 0xC4 {
            // Object identifier tag
            let obj_bytes = [
                apdu_data[i + 1],
                apdu_data[i + 2],
                apdu_data[i + 3],
                apdu_data[i + 4],
            ];
            let obj_id_value = u32::from_be_bytes(obj_bytes);
            let object_type_num = (obj_id_value >> 22) & 0x3FF;
            let instance = obj_id_value & 0x3FFFFF;

            if let Ok(object_type) = ObjectType::try_from(object_type_num as u16) {
                objects.push(format!("{}:{}", object_type_name(object_type), instance));
            }
            i += 5;
        } else {
            i += 1;
        }
    }

    if !objects.is_empty() {
        Ok(format!("Objects: [{}]", objects.join(", ")))
    } else {
        // Final fallback to hex dump - but try to decode strings first
        if apdu_data.len() > 5 && (apdu_data[0] == 0x30 || apdu_data[0] == 0x3E) {
            // Skip to actual data and try to extract string value
            for i in 0..apdu_data.len() {
                if apdu_data[i] == 0x75 || apdu_data[i] == 0x74 {
                    // Try to decode the value
                    if let Ok(value) = decode_bacnet_value(&apdu_data[i..]) {
                        return Ok(value);
                    }
                    // If decoding fails, fall back to hex using hex crate
                    return Ok(format!("0x{}", hex::encode(&apdu_data[i..])));
                }
            }
        }
        // Use hex crate for final fallback
        Ok(format!("0x{}", hex::encode(apdu_data)))
    }
}

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    hex::decode(hex_str).map_err(|e| e.to_string().into())
}

fn parse_string_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle hex response starting with 0x
    if let Some(hex_str) = response.strip_prefix("0x") {
        if let Ok(bytes) = decode_hex(hex_str) {
            // Try multiple approaches to extract the string

            // Use universal decoder
            return decode_bacnet_value(&bytes);
        }
    }
    // Clean up raw string responses
    Ok(response.trim_end_matches('\0').trim().to_string())
}

fn parse_value_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle hex response starting with 0x
    if let Some(hex_str) = response.strip_prefix("0x") {
        if let Ok(bytes) = decode_hex(hex_str) {
            // Use universal BACnet decoder
            return decode_bacnet_value(&bytes);
        }
    }
    Ok(response.to_string())
}

// Universal BACnet value decoder based on application tag types
fn decode_bacnet_value(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok("(empty)".to_string());
    }

    // Skip BACnet Complex ACK header if present
    let mut idx = 0;
    if data.len() > 2 && data[0] == 0x30 {
        idx = 2;
        // Skip object identifier and property identifier context tags
        while idx < data.len() {
            match data[idx] >> 4 {
                0x0 | 0x1 => idx += 2 + (data[idx] & 0x07) as usize, // Context tags
                _ => break,
            }
        }
    }

    // Skip opening tag if present
    if idx < data.len() && data[idx] == 0x3E {
        idx += 1;
    }

    // Parse BACnet application tags from this position
    if idx < data.len() {
        return parse_bacnet_application_tag(&data[idx..]);
    }

    // Fallback - hex encode
    Ok(format!("0x{}", hex::encode(data)))
}

fn parse_units_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle hex response starting with 0x
    if let Some(hex_str) = response.strip_prefix("0x") {
        if let Ok(bytes) = decode_hex(hex_str) {
            // Use universal decoder - units will be returned as enumerated values
            if let Ok(value) = decode_bacnet_value(&bytes) {
                // Convert common unit enumerations to readable names
                match value.as_str() {
                    "95" => return Ok("degrees-celsius".to_string()),
                    "96" => return Ok("degrees-fahrenheit".to_string()),
                    "98" => return Ok("percent".to_string()),
                    "99" => return Ok("percent-relative-humidity".to_string()),
                    _ => return Ok(value),
                }
            }
        }
    }
    Ok(response.to_string())
}

// Parse BACnet application tags according to the protocol specification
#[allow(clippy::manual_is_multiple_of)]
fn parse_bacnet_application_tag(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("Empty data".into());
    }

    let tag = data[0];
    let tag_number = (tag >> 4) & 0x0F;
    let length_value_type = tag & 0x07;

    // Determine the length of the data
    let (data_len, data_start) = if tag & 0x08 != 0 {
        // Extended tag
        if data.len() < 2 {
            return Err("Incomplete extended tag".into());
        }
        (0, 1) // Extended tags handled differently
    } else if length_value_type <= 4 {
        // Length is in the tag
        (length_value_type as usize, 1)
    } else if length_value_type == 5 {
        // Length in next octet
        if data.len() < 2 {
            return Err("Incomplete length encoding".into());
        }
        let len = data[1] as usize;
        if len == 254 && data.len() >= 4 {
            // 2-byte length
            ((data[2] as usize) << 8 | data[3] as usize, 4)
        } else if len == 255 && data.len() >= 6 {
            // 4-byte length
            (
                (data[2] as usize) << 24
                    | (data[3] as usize) << 16
                    | (data[4] as usize) << 8
                    | data[5] as usize,
                6,
            )
        } else {
            (len, 2)
        }
    } else {
        // Reserved
        return Err("Reserved length encoding".into());
    };

    // Make sure we have enough data
    if data.len() < data_start + data_len {
        return Err("Insufficient data for tag value".into());
    }

    let value_data = &data[data_start..data_start + data_len];

    // Parse based on tag number (BACnet application tags)
    match tag_number {
        0 => {
            // Null
            Ok("null".to_string())
        }
        1 => {
            // Boolean
            if length_value_type == 0 {
                Ok("false".to_string())
            } else {
                Ok("true".to_string())
            }
        }
        2 => {
            // Unsigned Integer
            let mut value = 0u64;
            for &byte in value_data {
                value = (value << 8) | (byte as u64);
            }
            Ok(value.to_string())
        }
        3 => {
            // Signed Integer
            let mut value = 0i64;
            for &byte in value_data {
                value = (value << 8) | (byte as i64);
            }
            // Sign extend if necessary
            if !value_data.is_empty() && value_data.len() < 8 && (value_data[0] & 0x80) != 0 {
                let shift = 64 - (value_data.len() * 8);
                value = (value << shift) >> shift;
            }
            Ok(value.to_string())
        }
        4 => {
            // Real (single precision)
            if value_data.len() == 4 {
                let bytes = [value_data[0], value_data[1], value_data[2], value_data[3]];
                let value = f32::from_be_bytes(bytes);
                if value.is_finite() {
                    Ok(format!("{:.2}", value))
                } else {
                    Ok("NaN".to_string())
                }
            } else {
                Err("Invalid REAL length".into())
            }
        }
        5 => {
            // Double (double precision)
            if value_data.len() == 8 {
                let bytes = [
                    value_data[0],
                    value_data[1],
                    value_data[2],
                    value_data[3],
                    value_data[4],
                    value_data[5],
                    value_data[6],
                    value_data[7],
                ];
                let value = f64::from_be_bytes(bytes);
                if value.is_finite() {
                    Ok(format!("{:.2}", value))
                } else {
                    Ok("NaN".to_string())
                }
            } else {
                Err("Invalid DOUBLE length".into())
            }
        }
        6 => {
            // Octet String
            Ok(format!("0x{}", hex::encode(value_data)))
        }
        7 => {
            // Character String
            // First byte is character set
            if !value_data.is_empty() {
                let charset = value_data[0];
                let string_data = &value_data[1..];
                match charset {
                    0 => {
                        // ANSI X3.4 / UTF-8
                        match std::str::from_utf8(string_data) {
                            Ok(s) => Ok(s.to_string()),
                            Err(_) => {
                                Ok(format!("(invalid UTF-8: 0x{})", hex::encode(string_data)))
                            }
                        }
                    }
                    1 => {
                        // ISO 8859-1
                        Ok(string_data.iter().map(|&b| b as char).collect())
                    }
                    3 | 4 => {
                        // ISO 10646 (UCS-2) or ISO 10646 (UCS-4)
                        if string_data.len() % 2 == 0 {
                            let mut utf16_values = Vec::new();
                            for i in (0..string_data.len()).step_by(2) {
                                let value =
                                    ((string_data[i] as u16) << 8) | (string_data[i + 1] as u16);
                                utf16_values.push(value);
                            }
                            match String::from_utf16(&utf16_values) {
                                Ok(s) => Ok(s),
                                Err(_) => {
                                    Ok(format!("(invalid UTF-16: 0x{})", hex::encode(string_data)))
                                }
                            }
                        } else {
                            Ok(format!(
                                "(odd UTF-16 length: 0x{})",
                                hex::encode(string_data)
                            ))
                        }
                    }
                    _ => Ok(format!(
                        "(charset {}: 0x{})",
                        charset,
                        hex::encode(string_data)
                    )),
                }
            } else {
                Ok("".to_string())
            }
        }
        8 => {
            // Bit String
            if !value_data.is_empty() {
                let unused_bits = value_data[0];
                let bit_data = &value_data[1..];
                Ok(format!(
                    "bits({} unused): 0x{}",
                    unused_bits,
                    hex::encode(bit_data)
                ))
            } else {
                Ok("bits()".to_string())
            }
        }
        9 => {
            // Enumerated
            let mut value = 0u32;
            for &byte in value_data {
                value = (value << 8) | (byte as u32);
            }
            Ok(value.to_string())
        }
        10 => {
            // Date
            if value_data.len() == 4 {
                let year = 1900 + value_data[0] as i32;
                let month = value_data[1];
                let day = value_data[2];
                let dow = value_data[3];
                Ok(format!("{:04}-{:02}-{:02} (dow:{})", year, month, day, dow))
            } else {
                Err("Invalid DATE length".into())
            }
        }
        11 => {
            // Time
            if value_data.len() == 4 {
                let hour = value_data[0];
                let minute = value_data[1];
                let second = value_data[2];
                let hundredths = value_data[3];
                Ok(format!(
                    "{:02}:{:02}:{:02}.{:02}",
                    hour, minute, second, hundredths
                ))
            } else {
                Err("Invalid TIME length".into())
            }
        }
        12 => {
            // BACnetObjectIdentifier
            if value_data.len() == 4 {
                let obj_id = u32::from_be_bytes([
                    value_data[0],
                    value_data[1],
                    value_data[2],
                    value_data[3],
                ]);
                let obj_type = (obj_id >> 22) & 0x3FF;
                let instance = obj_id & 0x3FFFFF;
                Ok(format!("Object({},{})", obj_type, instance))
            } else {
                Err("Invalid ObjectIdentifier length".into())
            }
        }
        _ => {
            // Unknown or reserved tag
            Ok(format!("Tag{}:0x{}", tag_number, hex::encode(value_data)))
        }
    }
}

fn object_type_name(obj_type: ObjectType) -> &'static str {
    match obj_type {
        ObjectType::AnalogInput => "AI",
        ObjectType::AnalogOutput => "AO",
        ObjectType::AnalogValue => "AV",
        ObjectType::BinaryInput => "BI",
        ObjectType::BinaryOutput => "BO",
        ObjectType::BinaryValue => "BV",
        ObjectType::Device => "DEV",
        ObjectType::MultiStateInput => "MSI",
        ObjectType::MultiStateOutput => "MSO",
        ObjectType::MultiStateValue => "MSV",
        ObjectType::TrendLog => "TL",
        ObjectType::Schedule => "SCH",
        ObjectType::Calendar => "CAL",
        _ => "UNK",
    }
}

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
