//! Basic Callback Example
//!
//! This example demonstrates how to register callbacks on BACnet objects
//! to be notified when property values change due to remote updates.
//!
//! Run with: `cargo run --example basic_callback`

use bacnet_rs::object::{analog::AnalogInput, BacnetObject, PropertyIdentifier, PropertyValue};

fn main() {
    println!("=== BACnet Object Callbacks Example ===\n");

    // Create an AnalogInput object
    let mut temperature_sensor = AnalogInput::new(1, "Room Temperature".to_string());

    println!("Created AnalogInput: {}", temperature_sensor.object_name);
    println!("Initial value: {:.1}°C\n", temperature_sensor.present_value);

    // Register a callback for PresentValue changes
    temperature_sensor.on_present_value_change(|value| {
        println!("🔔 Callback triggered! New temperature: {:.1}°C", value);
    });

    println!("Registered callback for PresentValue changes\n");

    // Simulate a local update (will NOT trigger callback)
    println!("1. Local update via set_property() - NO callback:");
    temperature_sensor
        .set_property(PropertyIdentifier::PresentValue, PropertyValue::Real(23.5))
        .expect("Failed to set property");
    println!(
        "   Value is now: {:.1}°C\n",
        temperature_sensor.present_value
    );

    // Simulate a remote update (WILL trigger callback)
    println!("2. Remote update via set_property_remote() - WITH callback:");
    temperature_sensor
        .set_property_remote(PropertyIdentifier::PresentValue, PropertyValue::Real(25.0))
        .expect("Failed to set property remotely");
    println!(
        "   Value is now: {:.1}°C\n",
        temperature_sensor.present_value
    );

    // Another remote update
    println!("3. Another remote update:");
    temperature_sensor
        .set_property_remote(PropertyIdentifier::PresentValue, PropertyValue::Real(27.5))
        .expect("Failed to set property remotely");
    println!(
        "   Value is now: {:.1}°C\n",
        temperature_sensor.present_value
    );

    // Register a second callback for OutOfService changes
    println!("4. Registering OutOfService callback:");
    temperature_sensor.on_out_of_service_change(|out_of_service| {
        println!(
            "🔔 Out of service status changed to: {}",
            if out_of_service { "TRUE" } else { "FALSE" }
        );
    });

    temperature_sensor
        .set_property_remote(
            PropertyIdentifier::OutOfService,
            PropertyValue::Boolean(true),
        )
        .expect("Failed to set out of service");
    println!();

    // Clear callbacks
    println!("5. Clearing all callbacks:");
    temperature_sensor.clear_all_callbacks();

    temperature_sensor
        .set_property_remote(PropertyIdentifier::PresentValue, PropertyValue::Real(30.0))
        .expect("Failed to set property remotely");
    println!("   No callback triggered (callbacks were cleared)");
    println!(
        "   Value is now: {:.1}°C\n",
        temperature_sensor.present_value
    );

    println!("=== Example Complete ===");
}
