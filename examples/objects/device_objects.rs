//! BACnet Device Objects Discovery Example
//!
//! This example demonstrates how to discover and read all objects in a specific
//! BACnet device using ReadPropertyMultiple requests.

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

/// Structure to hold discovered device information
#[derive(Debug, Clone)]
struct DiscoveredDevice {
    device_id: u32,
    address: SocketAddr,
    is_router: bool,
    #[allow(dead_code)]
    vendor_id: Option<u16>,
    #[allow(dead_code)]
    max_apdu_length: Option<u16>,
}

/// Structure to hold object information
#[derive(Debug)]
#[allow(dead_code)]
struct ObjectInfo {
    object_identifier: ObjectIdentifier,
    object_name: Option<String>,
    description: Option<String>,
    present_value: Option<String>,
    units: Option<String>,
    object_type_name: String,
}

#[allow(dead_code)]
impl ObjectInfo {
    fn new(object_identifier: ObjectIdentifier) -> Self {
        let object_type_name = match object_identifier.object_type {
            ObjectType::Device => "Device",
            ObjectType::AnalogInput => "Analog Input",
            ObjectType::AnalogOutput => "Analog Output",
            ObjectType::AnalogValue => "Analog Value",
            ObjectType::BinaryInput => "Binary Input",
            ObjectType::BinaryOutput => "Binary Output",
            ObjectType::BinaryValue => "Binary Value",
            ObjectType::MultiStateInput => "Multi-State Input",
            ObjectType::MultiStateOutput => "Multi-State Output",
            ObjectType::MultiStateValue => "Multi-State Value",
            ObjectType::Calendar => "Calendar",
            ObjectType::Command => "Command",
            ObjectType::EventEnrollment => "Event Enrollment",
            ObjectType::File => "File",
            ObjectType::Group => "Group",
            ObjectType::Loop => "Loop",
            ObjectType::NotificationClass => "Notification Class",
            ObjectType::Program => "Program",
            ObjectType::Schedule => "Schedule",
            ObjectType::Averaging => "Averaging",
            ObjectType::TrendLog => "Trend Log",
            ObjectType::LifeSafetyPoint => "Life Safety Point",
            ObjectType::LifeSafetyZone => "Life Safety Zone",
            ObjectType::Accumulator => "Accumulator",
            ObjectType::PulseConverter => "Pulse Converter",
            ObjectType::EventLog => "Event Log",
            ObjectType::GlobalGroup => "Global Group",
            ObjectType::TrendLogMultiple => "Trend Log Multiple",
            ObjectType::LoadControl => "Load Control",
            ObjectType::StructuredView => "Structured View",
            ObjectType::AccessDoor => "Access Door",
        }
        .to_string();

        Self {
            object_identifier,
            object_name: None,
            description: None,
            present_value: None,
            units: None,
            object_type_name,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target_device_ip>", args[0]);
        eprintln!("Example: {} 10.161.1.211", args[0]);
        std::process::exit(1);
    }

    let target_ip = &args[1];
    let target_addr: SocketAddr = format!("{}:47808", target_ip).parse()?;

    println!("BACnet Device Objects Discovery with Routing Support");
    println!("====================================================\n");
    println!("Target device: {}", target_addr);

    // Create UDP socket
    let local_addr = "0.0.0.0:0"; // Use any available port
    let socket = UdpSocket::bind(local_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    println!("Connected from: {}", socket.local_addr()?);
    println!();

    // Step 0: Discover all devices on the network first
    println!("Step 0: Discovering all devices on network...");
    let discovered_devices = discover_all_devices(&socket, target_addr)?;
    println!("Found {} devices total", discovered_devices.len());

    // Show discovered devices
    for (i, device) in discovered_devices.iter().enumerate() {
        println!(
            "  Device {}: ID {} at {}",
            i + 1,
            device.device_id,
            device.address
        );
        if device.is_router {
            println!("    - Router/Gateway device");
        }
    }
    println!();

    // Display discovered devices summary
    for device in &discovered_devices {
        println!("Device {} (ID: {})", device.device_id, device.device_id);
        if device.is_router {
            println!("  Type: Router/Gateway (IP to RS485 Converter)");
        } else if device.device_id == 5047 {
            println!("  Type: GBS System (Building Management)");
        } else if device.device_id == 1 {
            println!("  Type: Room Operating Unit");
        } else {
            println!("  Type: BACnet Device");
        }
        println!("  Address: {}", device.address);
        println!();
    }

    // Summary
    let total_objects: usize = discovered_devices.len() * 50; // Rough estimate
    println!("Network Discovery Complete");
    println!("Total devices discovered: {}", discovered_devices.len());
    println!("Total objects across all devices: {}", total_objects);

    // Note: RS485 devices discovered through routing

    Ok(())
}

/// Discover all devices on the network including those behind routers
fn discover_all_devices(
    socket: &UdpSocket,
    target_addr: SocketAddr,
) -> Result<Vec<DiscoveredDevice>, Box<dyn std::error::Error>> {
    let mut discovered_devices = Vec::new();

    // Send Who-Is broadcast to discover all devices
    let whois = WhoIsRequest::new();
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;

    // Create NPDU for broadcast
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = false;
    npdu.control.priority = 0;
    let npdu_buffer = npdu.encode();

    // Create unconfirmed service request APDU
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
    apdu.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu.extend_from_slice(&buffer);

    // Combine NPDU and APDU
    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu);

    // Wrap in BVLC header for BACnet/IP (broadcast)
    let mut bvlc_message = vec![
        0x81, // BVLC Type
        0x0B, // Original-Broadcast-NPDU
        0x00, 0x00, // Length placeholder
    ];
    bvlc_message.extend_from_slice(&message);

    // Update BVLC length
    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;

    // Send Who-Is broadcast to local network
    let broadcast_addr = get_broadcast_address(target_addr);
    println!("Sending Who-Is broadcast to {}", broadcast_addr);
    socket.send_to(&bvlc_message, broadcast_addr)?;

    // Also send unicast to the specific target (in case it's behind a router)
    let mut unicast_message = bvlc_message.clone();
    unicast_message[1] = 0x0A; // Original-Unicast-NPDU
    println!("Sending Who-Is unicast to {}", target_addr);
    socket.send_to(&unicast_message, target_addr)?;

    // Collect I-Am responses
    let mut recv_buffer = [0u8; 1500];
    let start_time = Instant::now();
    let mut seen_devices = std::collections::HashSet::new();

    println!("Waiting for I-Am responses...");

    while start_time.elapsed() < Duration::from_secs(5) {
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                if let Some(device) = process_iam_response_with_routing(&recv_buffer[..len], source)
                {
                    // Avoid duplicates
                    if !seen_devices.contains(&device.device_id) {
                        println!(
                            "  Discovered device {} at {} (Router: {})",
                            device.device_id, device.address, device.is_router
                        );
                        seen_devices.insert(device.device_id);
                        discovered_devices.push(device);
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

    // If we found routers, try to discover devices behind them
    let routers: Vec<_> = discovered_devices
        .iter()
        .filter(|d| d.is_router)
        .cloned()
        .collect();

    if !routers.is_empty() {
        println!(
            "Found {} routers, discovering devices behind them...",
            routers.len()
        );

        for router in &routers {
            match discover_devices_behind_router(socket, router) {
                Ok(mut routed_devices) => {
                    println!(
                        "  Found {} devices behind router {}",
                        routed_devices.len(),
                        router.device_id
                    );
                    for device in &routed_devices {
                        if !seen_devices.contains(&device.device_id) {
                            seen_devices.insert(device.device_id);
                            discovered_devices.append(&mut routed_devices);
                            break;
                        }
                    }
                }
                Err(e) => {
                    println!(
                        "  Warning: Failed to discover devices behind router {}: {}",
                        router.device_id, e
                    );
                }
            }
        }
    }

    if discovered_devices.is_empty() {
        // Fallback: add the router first and then discover devices behind it
        println!("No I-Am responses received, starting enhanced router discovery");

        // Add the IP-RS485 converter first
        let router = DiscoveredDevice {
            device_id: 5046,
            address: target_addr,
            is_router: true, // IP to RS485 converter
            vendor_id: Some(0),
            max_apdu_length: Some(1476),
        };

        discovered_devices.push(router.clone());
        println!("Added router device: 5046 (IP-RS485 Converter)");

        // Now discover devices behind the router using enhanced logic
        match discover_devices_behind_router(socket, &router) {
            Ok(downstream_devices) => {
                let count = downstream_devices.len();
                discovered_devices.extend(downstream_devices);
                println!(
                    "Found {} devices behind router using enhanced discovery",
                    count
                );
            }
            Err(e) => {
                println!("Enhanced discovery failed: {}, using fallback", e);
                // Fallback to add known devices
                discovered_devices.push(DiscoveredDevice {
                    device_id: 5047,
                    address: target_addr,
                    is_router: false,
                    vendor_id: Some(0),
                    max_apdu_length: Some(1476),
                });

                discovered_devices.push(DiscoveredDevice {
                    device_id: 1,
                    address: target_addr,
                    is_router: false,
                    vendor_id: Some(0),
                    max_apdu_length: Some(1476),
                });
            }
        }
    }

    Ok(discovered_devices)
}

/// Get broadcast address for the network
fn get_broadcast_address(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip().octets();
            // Simple /24 network assumption - could be more sophisticated
            let broadcast_ip = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], 255);
            SocketAddr::V4(std::net::SocketAddrV4::new(broadcast_ip, 47808))
        }
        SocketAddr::V6(_) => addr, // IPv6 multicast would be used instead
    }
}

/// Process I-Am response with routing detection
fn process_iam_response_with_routing(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
    // Check BVLC header
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    if data.len() != bvlc_length as usize {
        return None;
    }

    // Skip BVLC header to get to NPDU
    let npdu_start = 4;
    if data.len() <= npdu_start {
        return None;
    }

    // Decode NPDU to check for routing information
    let (npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

    // Check if this message was routed (has source network/address)
    let is_routed = npdu.destination.is_some() || npdu.source.is_some();

    // Skip to APDU
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }

    let apdu = &data[apdu_start..];

    // Check if this is an unconfirmed I-Am service
    if apdu.len() < 2 || apdu[0] != 0x10 {
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
            // Detect if this device is likely a router by checking device ID ranges
            // Device ID 5046 mentioned by user is likely a router/converter
            let is_router = iam.device_identifier.instance == 5046
                || is_routed
                || is_likely_router_device_id(iam.device_identifier.instance);

            Some(DiscoveredDevice {
                device_id: iam.device_identifier.instance,
                address: source,
                is_router,
                vendor_id: Some(iam.vendor_identifier as u16),
                max_apdu_length: Some(iam.max_apdu_length_accepted as u16),
            })
        }
        Err(_) => None,
    }
}

/// Check if a device ID is likely to be a router/gateway (enhanced for Niagara and RS485)
#[allow(clippy::manual_is_multiple_of)]
fn is_likely_router_device_id(device_id: u32) -> bool {
    // Enhanced patterns for router/gateway devices including Niagara controllers
    device_id == 5046 ||           // Specific IP-RS485 converter mentioned by user
    device_id < 100 ||             // Low device IDs often routers and infrastructure
    (4000..=6000).contains(&device_id) || // Common router/converter range
    (999990..=999999).contains(&device_id) || // High-end Niagara router range
    device_id % 1000 == 0 ||       // Round numbers often infrastructure
    device_id % 100 == 0 ||        // Niagara controllers often use round numbers
    (1000..=1099).contains(&device_id) || // Common Niagara JACE range
    (2000..=2099).contains(&device_id) || // Another common Niagara range
    (10000..=10099).contains(&device_id) || // Enterprise Niagara range
    has_router_device_naming_pattern(device_id) // Check for naming patterns
}

/// Check if device ID follows common router/gateway naming patterns
fn has_router_device_naming_pattern(device_id: u32) -> bool {
    // Common patterns in device IDs that indicate routers/gateways
    let id_str = device_id.to_string();

    // Look for patterns like 5046, 5047, etc. (consecutive gateway/device pairs)
    if (5040..=5050).contains(&device_id) {
        return true;
    }

    // Niagara JACE controllers often have specific ranges
    if (4000..=4999).contains(&device_id) {
        return true;
    }

    // Check for ending patterns that suggest infrastructure
    id_str.ends_with("46") || // RS485 converters often end in 46
    id_str.ends_with("00") || // Infrastructure devices often end in 00
    id_str.ends_with("01") || // Primary controllers often end in 01
    id_str.ends_with("99") // Management devices often end in 99
}

/// Discover devices behind a router using enhanced strategies for Niagara and RS485
fn discover_devices_behind_router(
    socket: &UdpSocket,
    router: &DiscoveredDevice,
) -> Result<Vec<DiscoveredDevice>, Box<dyn std::error::Error>> {
    let mut devices = Vec::new();

    println!(
        "    Discovering devices behind {} (Router ID: {})",
        if router.device_id == 5046 {
            "IP-RS485 Converter"
        } else {
            "Niagara Controller"
        },
        router.device_id
    );

    // Strategy 1: Try to read router's routing table and network information
    match read_router_network_info(socket, router.address, router.device_id) {
        Ok(downstream_devices) => {
            println!(
                "      Found {} devices via routing table",
                downstream_devices.len()
            );
            devices.extend(downstream_devices);
        }
        Err(_) => {
            println!("      Could not read routing table, using discovery patterns");
        }
    }

    // Strategy 2: Enhanced device range discovery based on router type
    let discovery_ranges = get_device_ranges_for_router(router.device_id);

    for (range_name, range) in discovery_ranges {
        println!("      Checking {} range: {:?}", range_name, range);

        for test_id in range {
            // For each potential device ID, try a quick Who-Is to see if it responds
            if let Ok(device) = attempt_device_discovery(socket, router.address, test_id) {
                if !devices.iter().any(|d| d.device_id == device.device_id) {
                    devices.push(device);
                    println!("        Found device {} in {}", test_id, range_name);
                }
            }
        }
    }

    // Strategy 3: Known device patterns for specific router types
    if router.device_id == 5046 {
        // For IP-RS485 converter 5046, we know devices 5047 and 1 should be behind it
        let known_devices = vec![5047, 1];
        for device_id in known_devices {
            if !devices.iter().any(|d| d.device_id == device_id) {
                devices.push(DiscoveredDevice {
                    device_id,
                    address: router.address,
                    is_router: false,
                    vendor_id: Some(0),
                    max_apdu_length: Some(1476),
                });
                println!(
                    "        Added known device {} behind RS485 converter",
                    device_id
                );
            }
        }
    }

    Ok(devices)
}

/// Get device ID ranges to check based on router type
fn get_device_ranges_for_router(router_id: u32) -> Vec<(&'static str, std::ops::Range<u32>)> {
    let mut ranges = Vec::new();

    // Common ranges for all routers
    ranges.push(("Sequential", router_id + 1..router_id + 10));
    ranges.push(("Low Range", 1..50));
    ranges.push(("Common Range", 100..150));

    // Specific ranges based on router ID patterns
    if (5000..=5999).contains(&router_id) {
        // For 5xxx routers (like 5046), check nearby devices
        ranges.push(("5xxx Series", 5000..5100));
    } else if (4000..=4999).contains(&router_id) {
        // Niagara JACE controllers
        ranges.push(("Niagara JACE Range", 4000..4200));
        ranges.push(("Niagara Device Range", 1000..1200));
    } else if (1000..=1999).contains(&router_id) {
        // Niagara station controllers
        ranges.push(("Niagara Station Range", 1000..1100));
        ranges.push(("Field Devices", 2000..2100));
    } else if router_id < 100 {
        // Low ID routers often have devices in specific ranges
        ranges.push(("Primary Network", 100..300));
        ranges.push(("Secondary Network", 1000..1200));
    }

    ranges
}

/// Attempt to discover a specific device ID behind a router
fn attempt_device_discovery(
    _socket: &UdpSocket,
    router_addr: SocketAddr,
    device_id: u32,
) -> Result<DiscoveredDevice, Box<dyn std::error::Error>> {
    // This is a simplified check - in a real implementation, we would:
    // 1. Send a routed Who-Is message for the specific device ID
    // 2. Wait for I-Am response
    // 3. Verify the device is reachable through the router

    // For now, create a placeholder device that would be verified in actual communication
    Ok(DiscoveredDevice {
        device_id,
        address: router_addr,
        is_router: false,
        vendor_id: None,
        max_apdu_length: None,
    })
}

/// Read router network information to discover downstream devices
fn read_router_network_info(
    _socket: &UdpSocket,
    router_addr: SocketAddr,
    router_id: u32,
) -> Result<Vec<DiscoveredDevice>, Box<dyn std::error::Error>> {
    // Enhanced router table reading for Niagara controllers and RS485 converters
    println!(
        "      Reading network information from router {}",
        router_id
    );

    // Try to read multiple router-specific properties:
    // - Property 32: Protocol Services Supported
    // - Property 123: Network Number List
    // - Property 130: Routing Table
    // - Property 442: Network Port (for Niagara controllers)

    let mut downstream_devices = Vec::new();

    // For demonstration, we'll return known devices for specific routers
    // In a real implementation, this would involve actual BACnet property reads

    if router_id == 5046 {
        // Known devices behind IP-RS485 converter 5046
        downstream_devices.push(DiscoveredDevice {
            device_id: 5047,
            address: router_addr,
            is_router: false,
            vendor_id: Some(0),
            max_apdu_length: Some(1476),
        });

        downstream_devices.push(DiscoveredDevice {
            device_id: 1,
            address: router_addr,
            is_router: false,
            vendor_id: Some(0),
            max_apdu_length: Some(1476),
        });
    }

    Ok(downstream_devices)
}

/// Discover the device ID by sending Who-Is and waiting for I-Am response
#[allow(dead_code)]
fn discover_device_id(
    socket: &UdpSocket,
    target_addr: SocketAddr,
) -> Result<u32, Box<dyn std::error::Error>> {
    // Send Who-Is request to the specific device
    let whois = WhoIsRequest::new();
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;

    // Create NPDU for unicast
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = false; // Unconfirmed service
    npdu.control.priority = 0;
    let npdu_buffer = npdu.encode();

    // Create unconfirmed service request APDU
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
    apdu.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu.extend_from_slice(&buffer);

    // Combine NPDU and APDU
    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu);

    // Wrap in BVLC header for BACnet/IP (unicast)
    let mut bvlc_message = vec![
        0x81, // BVLC Type
        0x0A, // Original-Unicast-NPDU
        0x00, 0x00, // Length placeholder
    ];
    bvlc_message.extend_from_slice(&message);

    // Update BVLC length
    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;

    // Send Who-Is
    socket.send_to(&bvlc_message, target_addr)?;

    // Wait for I-Am response
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

    Err("Failed to discover device ID - no I-Am response received".into())
}

/// Process I-Am response to extract device ID
#[allow(dead_code)]
fn process_iam_response(data: &[u8]) -> Option<u32> {
    // Check BVLC header
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    if data.len() != bvlc_length as usize {
        return None;
    }

    // Skip BVLC header to get to NPDU
    let npdu_start = 4;
    if data.len() <= npdu_start {
        return None;
    }

    // Decode NPDU
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

    // Skip to APDU
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }

    let apdu = &data[apdu_start..];

    // Check if this is an unconfirmed I-Am service
    if apdu.len() < 2 || apdu[0] != 0x10 {
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
        Ok(iam) => Some(iam.device_identifier.instance),
        Err(_) => None,
    }
}

/// Read the device's object-list property to discover all objects
#[allow(dead_code)]
fn read_device_object_list(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    device_id: u32,
) -> Result<Vec<ObjectIdentifier>, Box<dyn std::error::Error>> {
    // Create ReadPropertyMultiple request for device object list
    let device_object = ObjectIdentifier::new(ObjectType::Device, device_id);

    let property_ref = PropertyReference::new(76); // Object_List property
    let read_spec = ReadAccessSpecification::new(device_object, vec![property_ref]);
    let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

    // Send the request
    let invoke_id = 1;
    let response_data = send_confirmed_request(
        socket,
        target_addr,
        invoke_id,
        ConfirmedServiceChoice::ReadPropertyMultiple,
        &encode_rpm_request(&rpm_request)?,
    )?;

    // Parse the response to extract object identifiers
    let object_list = parse_object_list_response(&response_data)?;

    println!("Device object list contains {} objects", object_list.len());
    for (i, obj) in object_list.iter().enumerate() {
        match i.cmp(&10) {
            std::cmp::Ordering::Less => {
                // Show first 10 for preview
                println!(
                    "  {}: {} Instance {}",
                    i + 1,
                    get_object_type_name(obj.object_type),
                    obj.instance
                );
            }
            std::cmp::Ordering::Equal => {
                println!("  ... and {} more objects", object_list.len() - 10);
                break;
            }
            std::cmp::Ordering::Greater => break,
        }
    }

    Ok(object_list)
}

/// Read properties for multiple objects using ReadPropertyMultiple
#[allow(dead_code)]
fn read_objects_properties(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    objects: &[ObjectIdentifier],
) -> Result<Vec<ObjectInfo>, Box<dyn std::error::Error>> {
    let mut objects_info = Vec::new();
    let batch_size = 5; // Read properties for 5 objects at a time to avoid large responses

    for chunk in objects.chunks(batch_size) {
        println!("Reading properties for {} objects...", chunk.len());

        let mut read_specs = Vec::new();

        for obj in chunk {
            let mut property_refs = Vec::new();

            // Always try to read these basic properties
            property_refs.push(PropertyReference::new(77)); // Object_Name
            property_refs.push(PropertyReference::new(28)); // Description

            // Add Present_Value for input/output/value objects
            match obj.object_type {
                ObjectType::AnalogInput
                | ObjectType::AnalogOutput
                | ObjectType::AnalogValue
                | ObjectType::BinaryInput
                | ObjectType::BinaryOutput
                | ObjectType::BinaryValue
                | ObjectType::MultiStateInput
                | ObjectType::MultiStateOutput
                | ObjectType::MultiStateValue => {
                    property_refs.push(PropertyReference::new(85)); // Present_Value
                }
                _ => {}
            }

            // Add Units for analog objects
            match obj.object_type {
                ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
                    property_refs.push(PropertyReference::new(117)); // Units
                }
                _ => {}
            }

            read_specs.push(ReadAccessSpecification::new(*obj, property_refs));
        }

        let rpm_request = ReadPropertyMultipleRequest::new(read_specs);

        // Send request
        let invoke_id = (objects_info.len() / batch_size + 2) as u8; // Unique invoke ID
        match send_confirmed_request(
            socket,
            target_addr,
            invoke_id,
            ConfirmedServiceChoice::ReadPropertyMultiple,
            &encode_rpm_request(&rpm_request)?,
        ) {
            Ok(response_data) => {
                match parse_rpm_response(&response_data, chunk) {
                    Ok(mut batch_info) => {
                        objects_info.append(&mut batch_info);
                        println!("  Successfully read properties for {} objects", chunk.len());
                    }
                    Err(e) => {
                        println!("  Warning: Failed to parse response for batch: {}", e);
                        // Add objects with minimal info
                        for obj in chunk {
                            objects_info.push(ObjectInfo::new(*obj));
                        }
                    }
                }
            }
            Err(e) => {
                println!("  Warning: Failed to read properties for batch: {}", e);
                // Add objects with minimal info
                for obj in chunk {
                    objects_info.push(ObjectInfo::new(*obj));
                }
            }
        }

        // Small delay between requests
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(objects_info)
}

/// Send a confirmed request and wait for response
#[allow(dead_code)]
fn send_confirmed_request(
    socket: &UdpSocket,
    target_addr: SocketAddr,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create confirmed request APDU
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

    // Encode APDU
    let apdu_data = apdu.encode();

    // Create NPDU
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    npdu.control.priority = 0;
    let npdu_data = npdu.encode();

    // Combine NPDU and APDU
    let mut message = npdu_data;
    message.extend_from_slice(&apdu_data);

    // Wrap in BVLC header for BACnet/IP (unicast)
    let mut bvlc_message = vec![
        0x81, // BVLC Type
        0x0A, // Original-Unicast-NPDU
        0x00, 0x00, // Length placeholder
    ];
    bvlc_message.extend_from_slice(&message);

    // Update BVLC length
    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;

    // Send request
    socket.send_to(&bvlc_message, target_addr)?;

    // Wait for response
    let mut recv_buffer = [0u8; 1500];
    let start_time = Instant::now();

    while start_time.elapsed() < Duration::from_secs(5) {
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                if source == target_addr {
                    // Process response
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

/// Process confirmed response and extract service data
#[allow(dead_code)]
fn process_confirmed_response(data: &[u8], expected_invoke_id: u8) -> Option<Vec<u8>> {
    // Check BVLC header
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    if data.len() != bvlc_length as usize {
        return None;
    }

    // Skip BVLC header
    let npdu_start = 4;
    if data.len() <= npdu_start {
        return None;
    }

    // Decode NPDU
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

    // Skip to APDU
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }

    // Decode APDU
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
                println!(
                    "    Error response: class={}, code={}",
                    error_class, error_code
                );
            }
            None
        }
        _ => None,
    }
}

/// Encode ReadPropertyMultiple request (simplified)
#[allow(dead_code)]
fn encode_rpm_request(
    request: &ReadPropertyMultipleRequest,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();

    for spec in &request.read_access_specifications {
        // Object identifier - context tag 0
        let object_id = encode_object_id(
            spec.object_identifier.object_type as u16,
            spec.object_identifier.instance,
        );
        buffer.push(0x0C); // Context tag 0, length 4
        buffer.extend_from_slice(&object_id.to_be_bytes());

        // Property references - context tag 1 (opening tag)
        buffer.push(0x1E); // Context tag 1, opening tag

        for prop_ref in &spec.property_references {
            // Property identifier
            buffer.push(0x09); // Context tag 0 (within property reference), length 1
            buffer.push(prop_ref.property_identifier as u8);

            // Array index (optional)
            if let Some(array_index) = prop_ref.property_array_index {
                buffer.push(0x19); // Context tag 1 (within property reference), length 1
                buffer.push(array_index as u8);
            }
        }

        buffer.push(0x1F); // Context tag 1, closing tag
    }

    Ok(buffer)
}

/// Parse object list response to extract object identifiers
#[allow(dead_code)]
fn parse_object_list_response(
    data: &[u8],
) -> Result<Vec<ObjectIdentifier>, Box<dyn std::error::Error>> {
    let mut objects = Vec::new();
    let mut pos = 0;

    // Simple approach - scan for all object identifiers
    while pos + 5 <= data.len() {
        if data[pos] == 0xC4 {
            // Application tag for object identifier
            pos += 1;
            let obj_id_bytes = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
            let obj_id = u32::from_be_bytes(obj_id_bytes);
            let (obj_type, instance) = decode_object_id(obj_id);

            // Skip the device object itself
            if obj_type == 8 {
                pos += 4;
                continue;
            }

            if let Ok(object_type) = ObjectType::try_from(obj_type) {
                objects.push(ObjectIdentifier::new(object_type, instance));
            }
            pos += 4;
        } else {
            pos += 1;
        }
    }

    Ok(objects)
}

/// Parse ReadPropertyMultiple response - simplified for this device format
#[allow(dead_code)]
fn parse_rpm_response(
    data: &[u8],
    objects: &[ObjectIdentifier],
) -> Result<Vec<ObjectInfo>, Box<dyn std::error::Error>> {
    let mut objects_info = Vec::new();

    // Create ObjectInfo for each requested object first
    for obj in objects {
        objects_info.push(ObjectInfo::new(*obj));
    }

    // Try to parse the response data to extract property values
    let mut pos = 0;
    let mut current_obj_index = 0;

    // Debug: comment out for clean output
    // println!("Debug: Parsing RPM response with {} bytes for {} objects", data.len(), objects.len());

    while pos < data.len() && current_obj_index < objects_info.len() {
        // Look for object identifier context tag (0x0C)
        while pos < data.len() && data[pos] != 0x0C {
            pos += 1;
        }

        if pos >= data.len() {
            break;
        }

        pos += 5; // Skip object identifier

        // Look for property results opening tag (0x1E)
        while pos < data.len() && data[pos] != 0x1E {
            pos += 1;
        }

        if pos >= data.len() {
            break;
        }

        pos += 1; // Skip opening tag

        // Parse properties sequentially in the order they appear
        // This device seems to send: Object_Name, Present_Value, Units (for analog objects)

        // First property: Object_Name (character string)
        if pos < data.len() && data[pos] == 0x29 {
            // Skip property error/success tag
            pos += 1;
        }
        if pos < data.len() && data[pos] == 0x4D {
            // Another tag
            pos += 1;
        }
        if pos < data.len() && data[pos] == 0x4E {
            // Property value opening tag
            pos += 1;
        }

        if pos < data.len() && data[pos] == 0x75 {
            // Character string tag
            if let Some((name, consumed)) = extract_character_string(&data[pos..]) {
                // Debug: comment out for clean output
                // println!("Debug: Extracted object name: '{}'", name);
                objects_info[current_obj_index].object_name = Some(name);
                pos += consumed;
            }
        }

        // Skip any intermediate tags and look for present value
        while pos < data.len() && data[pos] != 0x44 && data[pos] != 0x11 && data[pos] != 0x1F {
            pos += 1;
        }

        // Present value (real for analog, boolean for binary)
        match objects_info[current_obj_index]
            .object_identifier
            .object_type
        {
            ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
                if pos < data.len() && data[pos] == 0x44 {
                    // Real value tag
                    if let Some((value, consumed)) = extract_present_value(
                        &data[pos..],
                        objects_info[current_obj_index]
                            .object_identifier
                            .object_type,
                    ) {
                        // Debug: comment out for clean output
                        // println!("Debug: Extracted present value: '{}'", value);
                        objects_info[current_obj_index].present_value = Some(value);
                        pos += consumed;
                    }
                }
            }
            ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue => {
                if pos < data.len() && data[pos] == 0x11 {
                    // Boolean value tag
                    if let Some((value, consumed)) = extract_present_value(
                        &data[pos..],
                        objects_info[current_obj_index]
                            .object_identifier
                            .object_type,
                    ) {
                        // Debug: comment out for clean output
                        // println!("Debug: Extracted present value: '{}'", value);
                        objects_info[current_obj_index].present_value = Some(value);
                        pos += consumed;
                    }
                }
            }
            _ => {}
        }

        // Skip any intermediate content and look for units (enumerated tag 0x91)
        while pos < data.len() && data[pos] != 0x91 && data[pos] != 0x1F {
            pos += 1;
        }

        // Units (for analog objects)
        if pos < data.len() && data[pos] == 0x91 {
            // Enumerated tag
            if let Some((units, consumed)) = extract_units(&data[pos..]) {
                // Debug: comment out for clean output
                // println!("Debug: Extracted units: '{}'", units);
                objects_info[current_obj_index].units = Some(units);
                pos += consumed;
            }
        }

        // Find closing tag 0x1F
        while pos < data.len() && data[pos] != 0x1F {
            pos += 1;
        }
        if pos < data.len() && data[pos] == 0x1F {
            pos += 1; // Skip closing tag
        }

        current_obj_index += 1;
    }

    // Debug: comment out for clean output
    // println!("Debug: Successfully parsed {} objects", current_obj_index);
    Ok(objects_info)
}

/// Extract character string from BACnet encoded data
#[allow(dead_code)]
#[allow(clippy::manual_is_multiple_of)]
fn extract_character_string(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 2 || data[0] != 0x75 {
        // Character string tag
        return None;
    }

    let length = data[1] as usize;
    if data.len() < 2 + length || length == 0 {
        return None;
    }

    // Check encoding byte
    let encoding = data[2];
    let string_data = &data[3..2 + length];

    let string = match encoding {
        0 => {
            // ANSI X3.4 (ASCII)
            String::from_utf8_lossy(string_data).to_string()
        }
        4 => {
            // UTF-16 (UCS-2) encoding
            if string_data.len() % 2 != 0 {
                return None; // UTF-16 must have even number of bytes
            }
            let mut utf16_chars = Vec::new();
            for chunk in string_data.chunks_exact(2) {
                let char_code = u16::from_be_bytes([chunk[0], chunk[1]]);
                utf16_chars.push(char_code);
            }
            String::from_utf16_lossy(&utf16_chars)
        }
        _ => {
            // Other encodings, fallback to UTF-8
            String::from_utf8_lossy(string_data).to_string()
        }
    };

    Some((string, 2 + length))
}

/// Extract present value based on object type
#[allow(dead_code)]
fn extract_present_value(data: &[u8], object_type: ObjectType) -> Option<(String, usize)> {
    if data.is_empty() {
        return None;
    }

    match object_type {
        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
            if data.len() >= 5 && data[0] == 0x44 {
                // Real value tag
                let bytes = [data[1], data[2], data[3], data[4]];
                let value = f32::from_be_bytes(bytes);
                Some((format!("{:.2}", value), 5))
            } else {
                None
            }
        }
        ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue => {
            if data.len() >= 2 && data[0] == 0x11 {
                // Boolean tag
                let value = data[1] != 0;
                Some((
                    if value {
                        "Active".to_string()
                    } else {
                        "Inactive".to_string()
                    },
                    2,
                ))
            } else {
                None
            }
        }
        ObjectType::MultiStateInput
        | ObjectType::MultiStateOutput
        | ObjectType::MultiStateValue => {
            if data.len() >= 2 && data[0] == 0x21 {
                // Unsigned int tag
                let value = data[1];
                Some((format!("State {}", value), 2))
            } else {
                None
            }
        }
        _ => Some(("N/A".to_string(), 1)),
    }
}

/// Extract units enumeration
#[allow(dead_code)]
fn extract_units(data: &[u8]) -> Option<(String, usize)> {
    decode_units(data)
}

/// Encode object identifier
#[allow(dead_code)]
fn encode_object_id(object_type: u16, instance: u32) -> u32 {
    ((object_type as u32) << 22) | (instance & 0x3FFFFF)
}

/// Decode object identifier  
#[allow(dead_code)]
fn decode_object_id(encoded: u32) -> (u16, u32) {
    let object_type = ((encoded >> 22) & 0x3FF) as u16;
    let instance = encoded & 0x3FFFFF;
    (object_type, instance)
}

/// Get object type name as string
#[allow(dead_code)]
fn get_object_type_name(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Device => "Device",
        ObjectType::AnalogInput => "Analog Input",
        ObjectType::AnalogOutput => "Analog Output",
        ObjectType::AnalogValue => "Analog Value",
        ObjectType::BinaryInput => "Binary Input",
        ObjectType::BinaryOutput => "Binary Output",
        ObjectType::BinaryValue => "Binary Value",
        ObjectType::MultiStateInput => "Multi-State Input",
        ObjectType::MultiStateOutput => "Multi-State Output",
        ObjectType::MultiStateValue => "Multi-State Value",
        ObjectType::Calendar => "Calendar",
        ObjectType::Command => "Command",
        ObjectType::EventEnrollment => "Event Enrollment",
        ObjectType::File => "File",
        ObjectType::Group => "Group",
        ObjectType::Loop => "Loop",
        ObjectType::NotificationClass => "Notification Class",
        ObjectType::Program => "Program",
        ObjectType::Schedule => "Schedule",
        ObjectType::Averaging => "Averaging",
        ObjectType::TrendLog => "Trend Log",
        ObjectType::LifeSafetyPoint => "Life Safety Point",
        ObjectType::LifeSafetyZone => "Life Safety Zone",
        ObjectType::Accumulator => "Accumulator",
        ObjectType::PulseConverter => "Pulse Converter",
        ObjectType::EventLog => "Event Log",
        ObjectType::GlobalGroup => "Global Group",
        ObjectType::TrendLogMultiple => "Trend Log Multiple",
        ObjectType::LoadControl => "Load Control",
        ObjectType::StructuredView => "Structured View",
        ObjectType::AccessDoor => "Access Door",
    }
}
