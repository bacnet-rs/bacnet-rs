//! BACnet Object Database Example
//!
//! This example demonstrates the comprehensive object database functionality
//! including object management, property access, and search capabilities.

use bacnet_rs::object::object_name::{IntoBoxedObjectName, ObjectName};
use bacnet_rs::object::{
    AnalogInput, AnalogValue, BinaryInput, BinaryOutput, BinaryPV, DatabaseBuilder, Device,
    EngineeringUnits, MultiStateValue, ObjectDatabase, ObjectIdentifier, ObjectType,
    PropertyIdentifier, PropertyValue,
};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Object Database Demo");
    println!("===========================\n");

    // Demo 1: Create database with builder
    println!("1. Creating Object Database");
    println!("--------------------------");

    let db = create_sample_database()?;

    let stats = db.statistics();
    println!("Database created with:");
    println!("  Total objects: {}", stats.total_objects);
    println!("  Object types: {}", stats.object_types);
    println!("  Database revision: {}", stats.revision);
    println!();

    // Demo 2: Object operations
    demo_object_operations(&db)?;

    // Demo 3: Property access
    demo_property_access(&db)?;

    // Demo 4: Search capabilities
    demo_search_capabilities(&db)?;

    // Demo 5: Dynamic object management
    demo_dynamic_management(&db)?;

    // Demo 6: Database statistics
    demo_database_statistics(&db)?;

    println!("\nObject Database Demo Complete!");
    Ok(())
}

/// Create a sample database with various object types
fn create_sample_database() -> Result<ObjectDatabase, Box<dyn std::error::Error>> {
    let mut device: Device<Box<dyn ObjectName>> =
        Device::new(1234, Box::new("Demo Controller".to_string()));

    device.vendor_name = "BACnet-RS Demo".to_string();
    device.model_name = "Virtual Device v1.0".to_string();

    // Create analog inputs for temperature sensors
    let mut ai1 = AnalogInput::new(1, "Zone 1 Temperature".to_string());
    ai1.present_value = 22.5;
    ai1.units = EngineeringUnits::DegreesCelsius;
    ai1.description = "Conference Room Temperature".to_string();

    let mut ai2 = AnalogInput::new(2, "Zone 2 Temperature".to_string());
    ai2.present_value = 21.8;
    ai2.units = EngineeringUnits::DegreesCelsius;
    ai2.description = "Office Area Temperature".to_string();

    let mut ai3 = AnalogInput::new(3, "Outside Temperature".to_string());
    ai3.present_value = 15.2;
    ai3.units = EngineeringUnits::DegreesCelsius;
    ai3.description = "Outdoor Air Temperature".to_string();

    // Create analog values for setpoints
    let mut av1 = AnalogValue::new(1, "Zone 1 Setpoint".to_string());
    av1.present_value = 22.0;
    av1.units = EngineeringUnits::DegreesCelsius;

    let mut av2 = AnalogValue::new(2, "Zone 2 Setpoint".to_string());
    av2.present_value = 21.0;
    av2.units = EngineeringUnits::DegreesCelsius;

    // Create binary inputs for status
    let mut bi1 = BinaryInput::new(1, "Zone 1 Occupancy".to_string());
    bi1.present_value = BinaryPV::Active;
    bi1.active_text = "Occupied".to_string();
    bi1.inactive_text = "Unoccupied".to_string();

    let mut bi2 = BinaryInput::new(2, "Fire Alarm".to_string());
    bi2.present_value = BinaryPV::Inactive;
    bi2.active_text = "ALARM".to_string();
    bi2.inactive_text = "Normal".to_string();

    // Create binary outputs for control
    let mut bo1 = BinaryOutput::new(1, "Zone 1 Heating".to_string());
    bo1.present_value = BinaryPV::Active;
    bo1.active_text = "Heating".to_string();
    bo1.inactive_text = "Off".to_string();

    // Create multi-state value for system mode
    let mut msv1 = MultiStateValue::new(1, "System Mode".to_string(), 4);
    msv1.present_value = 2; // Auto mode
    msv1.state_text = vec![
        "Off".to_string(),
        "Heating".to_string(),
        "Cooling".to_string(),
        "Auto".to_string(),
    ];

    // Build database
    let db = DatabaseBuilder::new()
        .with_device(device)
        .add_object(Box::new(ai1))
        .add_object(Box::new(ai2))
        .add_object(Box::new(ai3))
        .add_object(Box::new(av1))
        .add_object(Box::new(av2))
        .add_object(Box::new(bi1))
        .add_object(Box::new(bi2))
        .add_object(Box::new(bo1))
        .add_object(Box::new(msv1))
        .build()?;

    Ok(db)
}

/// Demonstrate object operations
fn demo_object_operations(db: &ObjectDatabase) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n2. Object Operations");
    println!("-------------------");

    // Get device object
    let device_id = db.get_device_id();
    println!(
        "Device: {} (Instance {})",
        match db.get_property(device_id, PropertyIdentifier::ObjectName)? {
            PropertyValue::CharacterString(name) => name,
            _ => "Unknown".to_string(),
        },
        device_id.instance
    );

    // List all objects
    println!("\nAll objects in database:");
    let all_objects = db.get_all_objects();
    for obj_id in &all_objects {
        let name = match db.get_property(*obj_id, PropertyIdentifier::ObjectName)? {
            PropertyValue::CharacterString(n) => n,
            _ => "Unknown".to_string(),
        };
        println!(
            "  {} {} - {}",
            format_object_type(obj_id.object_type),
            obj_id.instance,
            name
        );
    }

    // Get objects by type
    println!("\nAnalog Inputs:");
    let analog_inputs = db.get_objects_by_type(ObjectType::AnalogInput);
    for obj_id in &analog_inputs {
        if let Ok(PropertyValue::CharacterString(name)) =
            db.get_property(*obj_id, PropertyIdentifier::ObjectName)
        {
            if let Ok(PropertyValue::Real(value)) =
                db.get_property(*obj_id, PropertyIdentifier::PresentValue)
            {
                println!("  {} - {}: {:.1}°C", obj_id.instance, name, value);
            }
        }
    }

    Ok(())
}

/// Demonstrate property access
fn demo_property_access(db: &ObjectDatabase) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n3. Property Access");
    println!("-----------------");

    // Read properties
    let ai1_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);

    println!("Reading AI:1 properties:");
    let properties = [
        PropertyIdentifier::ObjectIdentifier,
        PropertyIdentifier::ObjectName,
        PropertyIdentifier::PresentValue,
    ];

    for prop_id in properties {
        if let Ok(value) = db.get_property(ai1_id, prop_id) {
            println!("  {:?}: {}", prop_id, format_property_value(&value));
        }
    }

    // Modify properties
    println!("\nModifying AV:1 present value:");
    let av1_id = ObjectIdentifier::new(ObjectType::AnalogValue, 1);

    let old_value = match db.get_property(av1_id, PropertyIdentifier::PresentValue)? {
        PropertyValue::Real(v) => v,
        _ => 0.0,
    };
    println!("  Old value: {:.1}°C", old_value);

    db.set_property(
        av1_id,
        PropertyIdentifier::PresentValue,
        PropertyValue::Real(23.5),
    )?;

    let new_value = match db.get_property(av1_id, PropertyIdentifier::PresentValue)? {
        PropertyValue::Real(v) => v,
        _ => 0.0,
    };
    println!("  New value: {:.1}°C", new_value);
    println!("  Database revision: {}", db.revision());

    Ok(())
}

/// Demonstrate search capabilities
fn demo_search_capabilities(db: &ObjectDatabase) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n4. Search Capabilities");
    println!("---------------------");

    // Search by name
    println!("Searching for 'Zone 1 Temperature':");
    match db.get_object_by_name("Zone 1 Temperature".into_object_name().as_ref()) {
        Ok(obj_id) => {
            println!(
                "  Found: {} {}",
                format_object_type(obj_id.object_type),
                obj_id.instance
            );
        }
        Err(e) => println!("  Not found: {}", e),
    }

    // Search by property value
    println!("\nSearching for objects with present value = 22.5:");
    let results =
        db.search_by_property(PropertyIdentifier::PresentValue, &PropertyValue::Real(22.5));
    for obj_id in &results {
        if let Ok(PropertyValue::CharacterString(name)) =
            db.get_property(*obj_id, PropertyIdentifier::ObjectName)
        {
            println!(
                "  Found: {} {} - {}",
                format_object_type(obj_id.object_type),
                obj_id.instance,
                name
            );
        }
    }

    // Check existence
    println!("\nExistence checks:");
    let test_id = ObjectIdentifier::new(ObjectType::AnalogInput, 99);
    println!("  AI:99 exists: {}", db.contains(test_id));
    println!(
        "  'Fire Alarm' exists: {}",
        db.contains_name("Fire Alarm".into_object_name().as_ref())
    );

    Ok(())
}

/// Demonstrate dynamic object management
fn demo_dynamic_management(db: &ObjectDatabase) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n5. Dynamic Object Management");
    println!("---------------------------");

    let initial_count = db.object_count();
    println!("Initial object count: {}", initial_count);

    // Add new object
    println!("\nAdding new analog input...");
    let mut ai_new = AnalogInput::new(10, "Dynamic Temperature".to_string());
    ai_new.present_value = 25.0;
    ai_new.units = EngineeringUnits::DegreesCelsius;

    db.add_object(Box::new(ai_new))?;
    println!("  Object added successfully");
    println!("  New object count: {}", db.object_count());
    println!(
        "  Next AI instance: {}",
        db.next_instance(ObjectType::AnalogInput)
    );

    // Try to add duplicate
    println!("\nTrying to add duplicate object...");
    let ai_dup = AnalogInput::new(10, "Duplicate".to_string());
    match db.add_object(Box::new(ai_dup)) {
        Ok(_) => println!("  Unexpected success!"),
        Err(e) => println!("  Expected error: {}", e),
    }

    // Remove object
    println!("\nRemoving BI:2...");
    let bi2_id = ObjectIdentifier::new(ObjectType::BinaryInput, 2);
    db.remove_object(bi2_id)?;
    println!("  Object removed successfully");
    println!("  New object count: {}", db.object_count());

    // Try to remove device (should fail)
    println!("\nTrying to remove device object...");
    let device_id = ObjectIdentifier::new(ObjectType::Device, 5000);
    match db.remove_object(device_id) {
        Ok(_) => println!("  Unexpected success!"),
        Err(e) => println!("  Expected error: {}", e),
    }

    Ok(())
}

/// Demonstrate database statistics
fn demo_database_statistics(db: &ObjectDatabase) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n6. Database Statistics");
    println!("---------------------");

    // Simulate some activity
    thread::sleep(Duration::from_millis(100));

    let stats = db.statistics();
    println!("Current statistics:");
    println!("  Total objects: {}", stats.total_objects);
    println!("  Object types: {}", stats.object_types);
    println!("  Database revision: {}", stats.revision);
    println!("  Last modified: {:?} ago", stats.last_modified.elapsed());

    println!("\nObject counts by type:");
    let mut type_counts: Vec<_> = stats.type_counts.iter().collect();
    type_counts.sort_by_key(|(t, _)| **t as u16);

    for (object_type, count) in type_counts {
        println!("  {}: {}", format_object_type(*object_type), count);
    }

    Ok(())
}

/// Format object type for display
fn format_object_type(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Device => "Device",
        ObjectType::AnalogInput => "AI",
        ObjectType::AnalogOutput => "AO",
        ObjectType::AnalogValue => "AV",
        ObjectType::BinaryInput => "BI",
        ObjectType::BinaryOutput => "BO",
        ObjectType::BinaryValue => "BV",
        ObjectType::MultiStateInput => "MSI",
        ObjectType::MultiStateOutput => "MSO",
        ObjectType::MultiStateValue => "MSV",
        _ => "Unknown",
    }
}

/// Format property value for display
fn format_property_value(value: &PropertyValue) -> String {
    match value {
        PropertyValue::Null => "null".to_string(),
        PropertyValue::Boolean(b) => b.to_string(),
        PropertyValue::UnsignedInteger(u) => u.to_string(),
        PropertyValue::SignedInt(i) => i.to_string(),
        PropertyValue::Real(r) => format!("{:.2}", r),
        PropertyValue::Double(d) => format!("{:.2}", d),
        PropertyValue::CharacterString(s) => format!("\"{}\"", s),
        PropertyValue::Enumerated(e) => format!("Enum({})", e),
        PropertyValue::ObjectIdentifier(id) => format!("{}:{}", id.object_type as u16, id.instance),
        _ => "Complex Value".to_string(),
    }
}
