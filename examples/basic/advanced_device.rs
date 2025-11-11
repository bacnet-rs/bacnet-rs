//! Advanced BACnet Device Example
//!
//! This example demonstrates the comprehensive BACnet functionality including:
//! - Device with multiple object types (AI, AO, BI, BO, AV, BV)
//! - Write Property and Read Property Multiple services
//! - COV (Change of Value) subscription management
//! - Priority arrays and commandable objects
//! - Status flags and reliability

use bacnet_rs::{
    app::{Apdu, MaxApduSize, MaxSegments},
    network::Npdu,
    object::{
        AnalogInput, AnalogOutput, AnalogValue, BacnetObject, BinaryInput, BinaryOutput, BinaryPV,
        BinaryValue, Device, EngineeringUnits, ObjectIdentifier, ObjectType, PropertyIdentifier,
    },
    service::{
        ConfirmedServiceChoice, CovSubscription, CovSubscriptionManager, PropertyReference,
        ReadAccessSpecification, ReadPropertyMultipleRequest, SubscribeCovRequest,
        WritePropertyRequest,
    },
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet-RS Advanced Device Example");
    println!("==================================");

    // Create a comprehensive BACnet device
    let mut device = Device::new(54321, "Advanced Demo Device".to_string());
    device.vendor_name = "BACnet-RS Advanced".to_string();
    device.model_name = "Multi-Object Demo Device".to_string();
    device.firmware_revision = "2.0.0".to_string();

    // Create various object types
    let mut ai1 = AnalogInput::new(1, "Temperature Sensor".to_string());
    ai1.present_value = 23.5;
    ai1.units = EngineeringUnits::DegreesCelsius;
    ai1.description = "Room temperature sensor".to_string();

    let mut ao1 = AnalogOutput::new(1, "Damper Position".to_string());
    ao1.units = EngineeringUnits::Percent;
    ao1.relinquish_default = 0.0;
    ao1.description = "VAV damper position control".to_string();

    let mut av1 = AnalogValue::new(1, "Setpoint".to_string());
    av1.present_value = 22.0;
    av1.units = EngineeringUnits::DegreesCelsius;
    av1.description = "Temperature setpoint".to_string();

    let mut bi1 = BinaryInput::new(1, "Occupancy Sensor".to_string());
    bi1.present_value = BinaryPV::Active;
    bi1.active_text = "OCCUPIED".to_string();
    bi1.inactive_text = "VACANT".to_string();

    let mut bo1 = BinaryOutput::new(1, "Fan Control".to_string());
    bo1.active_text = "ON".to_string();
    bo1.inactive_text = "OFF".to_string();
    bo1.relinquish_default = BinaryPV::Inactive;

    let mut bv1 = BinaryValue::new(1, "Override Switch".to_string());
    bv1.active_text = "OVERRIDE".to_string();
    bv1.inactive_text = "AUTO".to_string();

    println!("\nCreated Objects:");
    println!("================");
    println!(
        "Device: {} (Instance: {})",
        device.object_name,
        device.identifier().instance
    );
    println!("AI-1: {} = {:.1}°C", ai1.object_name, ai1.present_value);
    println!("AO-1: {} = {:.1}%", ao1.object_name, ao1.present_value);
    println!("AV-1: {} = {:.1}°C", av1.object_name, av1.present_value);
    println!("BI-1: {} = {:?}", bi1.object_name, bi1.present_value);
    println!("BO-1: {} = {:?}", bo1.object_name, bo1.present_value);
    println!("BV-1: {} = {:?}", bv1.object_name, bv1.present_value);

    // Demonstrate Write Property with Priority
    println!("\nWrite Property Examples:");
    println!("========================");

    // Command the analog output to 75% at priority 8
    ao1.write_priority(8, Some(75.0))?;
    println!("Commanded AO-1 to 75% at priority 8");
    println!("AO-1 Present Value: {:.1}%", ao1.present_value);
    println!(
        "AO-1 Effective Priority: {:?}",
        ao1.get_effective_priority()
    );

    // Override at higher priority 3
    ao1.write_priority(3, Some(100.0))?;
    println!("Override AO-1 to 100% at priority 3");
    println!("AO-1 Present Value: {:.1}%", ao1.present_value);
    println!(
        "AO-1 Effective Priority: {:?}",
        ao1.get_effective_priority()
    );

    // Release priority 3
    ao1.write_priority(3, None)?;
    println!("Released priority 3 override");
    println!(
        "AO-1 Present Value: {:.1}% (back to priority 8)",
        ao1.present_value
    );

    // Command binary output
    bo1.write_priority(8, Some(BinaryPV::Active))?;
    println!("Commanded BO-1 to ON at priority 8");
    println!("BO-1 Present Value: {:?}", bo1.present_value);

    // Demonstrate Read Property Multiple
    println!("\nRead Property Multiple Example:");
    println!("===============================");

    let ai_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
    let ao_id = ObjectIdentifier::new(ObjectType::AnalogOutput, 1);

    let ai_props = vec![
        PropertyReference::new(PropertyIdentifier::ObjectName as u32),
        PropertyReference::new(PropertyIdentifier::PresentValue as u32),
        PropertyReference::new(PropertyIdentifier::OutOfService as u32),
    ];

    let ao_props = vec![
        PropertyReference::new(PropertyIdentifier::ObjectName as u32),
        PropertyReference::new(PropertyIdentifier::PresentValue as u32),
        PropertyReference::new(PropertyIdentifier::PriorityArray as u32),
    ];

    let ai_spec = ReadAccessSpecification::new(ai_id, ai_props);
    let ao_spec = ReadAccessSpecification::new(ao_id, ao_props);

    let rpm_request = ReadPropertyMultipleRequest::new(vec![ai_spec, ao_spec]);
    println!(
        "Created RPM request for {} objects",
        rpm_request.read_access_specifications.len()
    );

    for (i, spec) in rpm_request.read_access_specifications.iter().enumerate() {
        println!(
            "  Object {}: {:?} with {} properties",
            i + 1,
            spec.object_identifier,
            spec.property_references.len()
        );
    }

    // Demonstrate COV Subscriptions
    println!("\nCOV Subscription Example:");
    println!("=========================");

    let mut cov_manager = CovSubscriptionManager::new();

    // Create COV subscriptions
    let device_id = ObjectIdentifier::new(ObjectType::Device, 999); // Subscriber device

    let ai_subscription = CovSubscription::new(123, device_id, ai_id, 3600);
    let ao_subscription = CovSubscription::new(124, device_id, ao_id, 7200);

    cov_manager.add_subscription(ai_subscription);
    cov_manager.add_subscription(ao_subscription);

    println!("Added COV subscriptions for AI-1 and AO-1");
    println!("Active subscriptions: {}", cov_manager.active_count());

    // Simulate time passing
    cov_manager.update_timers(1800); // 30 minutes
    println!("After 30 minutes:");

    let ai_subs = cov_manager.get_subscriptions_for_object(ai_id);
    if !ai_subs.is_empty() {
        println!(
            "  AI-1 subscription time remaining: {} seconds",
            ai_subs[0].time_remaining
        );
    }

    let ao_subs = cov_manager.get_subscriptions_for_object(ao_id);
    if !ao_subs.is_empty() {
        println!(
            "  AO-1 subscription time remaining: {} seconds",
            ao_subs[0].time_remaining
        );
    }

    // Demonstrate Subscribe COV Request
    let cov_request = SubscribeCovRequest::new(123, ai_id);
    let mut cov_buffer = Vec::new();
    cov_request.encode(&mut cov_buffer)?;
    println!("Encoded Subscribe COV request: {} bytes", cov_buffer.len());

    // Demonstrate APDU formation for various services
    println!("\nAPDU Formation Examples:");
    println!("========================");

    // Write Property APDU
    let write_prop = WritePropertyRequest::with_priority(
        ao_id,
        PropertyIdentifier::PresentValue as u32,
        vec![0x44, 0x42, 0x96, 0x00, 0x00], // Real 75.0 encoded
        8,
    );

    let mut write_data = Vec::new();
    write_prop.encode(&mut write_data)?;

    let write_apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up1476,
        invoke_id: 42,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::WriteProperty,
        service_data: write_data,
    };

    let encoded_write = write_apdu.encode();
    println!("Write Property APDU: {} bytes", encoded_write.len());

    // Subscribe COV APDU
    let cov_apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up1476,
        invoke_id: 43,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::SubscribeCOV,
        service_data: cov_buffer,
    };

    let encoded_cov = cov_apdu.encode();
    println!("Subscribe COV APDU: {} bytes", encoded_cov.len());

    // Network layer with priority
    println!("\nNetwork Layer Priority Example:");
    println!("===============================");

    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    npdu.control.priority = 2; // Urgent priority

    let encoded_npdu = npdu.encode();
    println!("NPDU with urgent priority: {} bytes", encoded_npdu.len());

    let (decoded_npdu, _) = Npdu::decode(&encoded_npdu)?;
    println!(
        "Priority level: {} (0=Life Safety, 1=Critical, 2=Urgent, 3=Normal)",
        decoded_npdu.control.priority
    );

    // Object property analysis
    println!("\nObject Property Analysis:");
    println!("=========================");

    println!("Device properties: {}", device.property_list().len());
    println!("Analog Input properties: {}", ai1.property_list().len());
    println!("Analog Output properties: {}", ao1.property_list().len());

    // Test property writability
    println!("Writable properties:");
    for property in &[
        PropertyIdentifier::ObjectName,
        PropertyIdentifier::PresentValue,
        PropertyIdentifier::OutOfService,
    ] {
        println!(
            "  AI-1 {:?}: {}",
            property,
            ai1.is_property_writable(*property)
        );
        println!(
            "  AO-1 {:?}: {}",
            property,
            ao1.is_property_writable(*property)
        );
    }

    println!("\nAdvanced BACnet Stack Demo Complete!");
    println!("All layers and services demonstrated successfully.");
    println!("\nImplemented functionality:");
    println!("- Device, Analog (AI/AO/AV), and Binary (BI/BO/BV) objects");
    println!("- Write Property with priority arrays");
    println!("- Read Property Multiple");
    println!("- COV subscriptions and management");
    println!("- Complete APDU formation for all service types");
    println!("- Network layer with priority handling");
    println!("- Object property management and validation");

    Ok(())
}
