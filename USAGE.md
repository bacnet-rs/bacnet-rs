# BACnet Stack Usage Guide

This guide demonstrates how to use the `bacnet-rs` library to build BACnet applications in Rust.

## Quick Start

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
bacnet-rs = "0.1.0"

# For async features
bacnet-rs = { version = "0.1.0", features = ["async"] }

# For no-std environments
bacnet-rs = { version = "0.1.0", default-features = false }
```

## Basic Device Setup

### Creating a Simple BACnet Device

```rust
use bacnet_rs::{
    app::{ApplicationLayerHandler, Apdu},
    datalink::bip::BacnetIpDataLink,
    network::{NetworkLayerHandler, Npdu},
    object::{Device, ObjectIdentifier, ObjectType, PropertyIdentifier},
    service::{ConfirmedServiceChoice, UnconfirmedServiceChoice},
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a BACnet device
    let device = Device::new(
        ObjectIdentifier::new(ObjectType::Device, 1234),
        "My BACnet Device".to_string(),
        "Simple Device".to_string(),
    );

    // Set up BACnet/IP datalink
    let local_addr: SocketAddr = "0.0.0.0:47808".parse()?;
    let broadcast_addr: SocketAddr = "255.255.255.255:47808".parse()?;
    let mut datalink = BacnetIpDataLink::new(local_addr, broadcast_addr).await?;

    // Create application layer handler
    let mut app_handler = ApplicationLayerHandler::new(1234);

    // Set up Who-Is response handler
    app_handler.set_who_is_handler(|service_data| {
        // Parse Who-Is request and respond with I-Am if applicable
        Ok(Some(create_i_am_response(1234, "My BACnet Device")))
    });

    // Set up Read Property handler
    app_handler.set_read_property_handler(|service_data| {
        // Parse property request and return property value
        Ok(encode_property_value("Present Value", 23.5))
    });

    println!("BACnet device started on {}", local_addr);

    // Main event loop
    loop {
        // Receive BACnet/IP messages
        if let Ok((npdu_data, source)) = datalink.receive().await {
            // Decode NPDU
            if let Ok(npdu) = Npdu::decode(&npdu_data) {
                // Extract APDU from NPDU payload
                if let Some(apdu_data) = npdu.data {
                    // Decode APDU
                    if let Ok(apdu) = Apdu::decode(&apdu_data) {
                        // Process APDU and get response
                        if let Ok(Some(response_apdu)) = app_handler.process_apdu(&apdu, &source) {
                            // Encode response APDU
                            let response_data = response_apdu.encode();
                            
                            // Create response NPDU
                            let response_npdu = create_response_npdu(&npdu, response_data);
                            
                            // Send response
                            datalink.send(&response_npdu.encode(), &source).await?;
                        }
                    }
                }
            }
        }

        // Handle timeouts and other periodic tasks
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

fn create_i_am_response(device_instance: u32, device_name: &str) -> Vec<u8> {
    // Implementation would encode I-Am service data
    // This is a simplified example
    vec![0x0C, 0x02, 0x00, 0x00, device_instance as u8, 0x22, 0x05, 0x40]
}

fn encode_property_value(property: &str, value: f32) -> Vec<u8> {
    // Implementation would encode the property value according to BACnet encoding rules
    // This is a simplified example
    vec![0x3E, 0x44, value.to_be_bytes()[0], value.to_be_bytes()[1], 
         value.to_be_bytes()[2], value.to_be_bytes()[3], 0x3F]
}

fn create_response_npdu(request_npdu: &Npdu, apdu_data: Vec<u8>) -> Npdu {
    Npdu {
        version: 1,
        control: request_npdu.control,
        destination: request_npdu.source.clone(),
        source: request_npdu.destination.clone(),
        hop_count: None,
        data: Some(apdu_data),
    }
}
```

## Working with BACnet Objects

### Creating and Managing Objects

```rust
use bacnet_rs::object::{
    AnalogInput, AnalogOutput, AnalogValue, BinaryInput, BinaryOutput, BinaryValue,
    Device, ObjectIdentifier, ObjectType, PropertyIdentifier, PropertyValue,
};

fn setup_objects() -> Vec<Box<dyn BacnetObject>> {
    let mut objects: Vec<Box<dyn BacnetObject>> = Vec::new();

    // Create device object
    let device = Device::new(
        ObjectIdentifier::new(ObjectType::Device, 1001),
        "Temperature Controller".to_string(),
        "HVAC Controller v1.0".to_string(),
    );
    objects.push(Box::new(device));

    // Create analog input for temperature sensor
    let mut temp_sensor = AnalogInput::new(
        ObjectIdentifier::new(ObjectType::AnalogInput, 1),
        "Room Temperature".to_string(),
    );
    temp_sensor.set_units(Some(62)); // Degrees Celsius
    temp_sensor.set_present_value(22.5);
    objects.push(Box::new(temp_sensor));

    // Create analog output for heating valve
    let mut heating_valve = AnalogOutput::new(
        ObjectIdentifier::new(ObjectType::AnalogOutput, 1),
        "Heating Valve".to_string(),
    );
    heating_valve.set_units(Some(98)); // Percent
    heating_valve.set_present_value(0.0);
    objects.push(Box::new(heating_valve));

    // Create binary input for window status
    let mut window_sensor = BinaryInput::new(
        ObjectIdentifier::new(ObjectType::BinaryInput, 1),
        "Window Status".to_string(),
    );
    window_sensor.set_present_value(false); // Closed
    objects.push(Box::new(window_sensor));

    // Create analog value for setpoint
    let mut setpoint = AnalogValue::new(
        ObjectIdentifier::new(ObjectType::AnalogValue, 1),
        "Temperature Setpoint".to_string(),
    );
    setpoint.set_units(Some(62)); // Degrees Celsius
    setpoint.set_present_value(21.0);
    objects.push(Box::new(setpoint));

    objects
}

// Update object values
fn update_temperature_sensor(objects: &mut [Box<dyn BacnetObject>], new_temp: f32) {
    if let Some(temp_sensor) = objects.iter_mut()
        .find(|obj| obj.object_identifier().object_type == ObjectType::AnalogInput && 
                    obj.object_identifier().instance == 1) {
        temp_sensor.set_property_value(PropertyIdentifier::PresentValue, PropertyValue::Real(new_temp));
    }
}
```

## Service Implementations

### Implementing Read Property Service

```rust
use bacnet_rs::{
    app::{ApplicationLayerHandler, Apdu, Result as AppResult},
    encoding::{decode_application_unsigned, encode_application_real},
    object::{ObjectIdentifier, PropertyIdentifier},
    service::ConfirmedServiceChoice,
};

struct PropertyDatabase {
    // Your object storage here
    objects: Vec<Box<dyn BacnetObject>>,
}

impl PropertyDatabase {
    fn read_property(
        &self, 
        object_id: ObjectIdentifier, 
        property_id: PropertyIdentifier,
        array_index: Option<u32>
    ) -> AppResult<Vec<u8>> {
        // Find the object
        let object = self.objects.iter()
            .find(|obj| obj.object_identifier() == object_id)
            .ok_or_else(|| ApplicationError::ServiceError("Object not found".to_string()))?;

        // Get the property value
        let property_value = object.get_property_value(property_id, array_index)
            .ok_or_else(|| ApplicationError::ServiceError("Property not found".to_string()))?;

        // Encode the property value
        match property_value {
            PropertyValue::Real(value) => Ok(encode_application_real(value)),
            PropertyValue::Unsigned(value) => Ok(encode_application_unsigned(value)),
            PropertyValue::CharacterString(value) => Ok(encode_application_character_string(&value)),
            PropertyValue::Boolean(value) => Ok(encode_application_boolean(value)),
            _ => Err(ApplicationError::ServiceError("Unsupported property type".to_string())),
        }
    }
}

fn setup_read_property_handler(app_handler: &mut ApplicationLayerHandler, db: &PropertyDatabase) {
    app_handler.set_read_property_handler(move |service_data| {
        // Decode Read Property request
        let (object_id, property_id, array_index) = decode_read_property_request(service_data)?;
        
        // Read the property from database
        db.read_property(object_id, property_id, array_index)
    });
}

fn decode_read_property_request(data: &[u8]) -> AppResult<(ObjectIdentifier, PropertyIdentifier, Option<u32>)> {
    // Implementation would decode the service data according to BACnet encoding rules
    // This is a simplified example
    if data.len() < 6 {
        return Err(ApplicationError::ServiceError("Invalid request data".to_string()));
    }
    
    // Parse object identifier (context tag 0)
    let object_type = ObjectType::try_from(((data[1] as u32) << 14) | ((data[2] as u32) << 6) | ((data[3] as u32) >> 2))?;
    let instance = ((data[3] as u32 & 0x3) << 16) | ((data[4] as u32) << 8) | (data[5] as u32);
    let object_id = ObjectIdentifier::new(object_type, instance);
    
    // Parse property identifier (context tag 1)
    let property_id = PropertyIdentifier::try_from(data[6])?;
    
    // Parse optional array index (context tag 2)
    let array_index = if data.len() > 7 && data[7] == 0x2E {
        Some(data[8] as u32)
    } else {
        None
    };
    
    Ok((object_id, property_id, array_index))
}
```

### Implementing Who-Is/I-Am Services

```rust
use bacnet_rs::{
    app::{Apdu, ApplicationLayerHandler},
    service::UnconfirmedServiceChoice,
};

fn setup_who_is_handler(app_handler: &mut ApplicationLayerHandler, device_instance: u32) {
    app_handler.set_who_is_handler(move |service_data| {
        // Decode Who-Is request
        let (low_limit, high_limit) = if service_data.is_empty() {
            (None, None)
        } else {
            decode_who_is_request(service_data)?
        };

        // Check if our device instance is in range
        let should_respond = match (low_limit, high_limit) {
            (Some(low), Some(high)) => device_instance >= low && device_instance <= high,
            (Some(low), None) => device_instance >= low,
            (None, Some(high)) => device_instance <= high,
            (None, None) => true, // Global Who-Is
        };

        if should_respond {
            Ok(Some(create_i_am_service_data(device_instance)))
        } else {
            Ok(None)
        }
    });
}

fn decode_who_is_request(data: &[u8]) -> AppResult<(Option<u32>, Option<u32>)> {
    // Parse optional low and high limits
    let mut pos = 0;
    let mut low_limit = None;
    let mut high_limit = None;
    
    if pos < data.len() && data[pos] == 0x08 {
        // Context tag 0 - low limit
        pos += 1;
        if pos < data.len() {
            low_limit = Some(data[pos] as u32);
            pos += 1;
        }
    }
    
    if pos < data.len() && data[pos] == 0x18 {
        // Context tag 1 - high limit  
        pos += 1;
        if pos < data.len() {
            high_limit = Some(data[pos] as u32);
        }
    }
    
    Ok((low_limit, high_limit))
}

fn create_i_am_service_data(device_instance: u32) -> Vec<u8> {
    let mut data = Vec::new();
    
    // Device object identifier
    data.push(0xC4); // Application tag 12 (Object Identifier), length 4
    data.extend_from_slice(&encode_object_identifier(ObjectType::Device, device_instance));
    
    // Maximum APDU length
    data.push(0x22); // Application tag 2 (Unsigned Int), length 2
    data.extend_from_slice(&1476u16.to_be_bytes()); // 1476 bytes
    
    // Segmentation support
    data.push(0x91); // Application tag 9 (Enumerated), length 1
    data.push(0x03); // Both segmentation (3)
    
    // Vendor ID
    data.push(0x22); // Application tag 2 (Unsigned Int), length 2
    data.extend_from_slice(&999u16.to_be_bytes()); // Custom vendor ID
    
    data
}

fn encode_object_identifier(object_type: ObjectType, instance: u32) -> [u8; 4] {
    let encoded = ((object_type as u32) << 22) | (instance & 0x3FFFFF);
    encoded.to_be_bytes()
}
```

## Network Configuration

### BACnet/IP Setup

```rust
use bacnet_rs::{
    datalink::bip::{BacnetIpDataLink, BacnetIpConfig},
    network::{NetworkLayerHandler, NetworkConfig},
};
use std::net::{SocketAddr, Ipv4Addr};

async fn setup_bacnet_ip() -> Result<BacnetIpDataLink, Box<dyn std::error::Error>> {
    let config = BacnetIpConfig {
        local_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 47808)),
        broadcast_address: SocketAddr::from((Ipv4Addr::BROADCAST, 47808)),
        
        // Foreign Device Registration (optional)
        bbmd_address: Some(SocketAddr::from(([192, 168, 1, 100], 47808))),
        bbmd_registration_interval: Some(std::time::Duration::from_secs(900)), // 15 minutes
        
        // Network settings
        max_masters: 127,
        max_info_frames: 50,
    };

    BacnetIpDataLink::with_config(config).await
}

// For devices behind NAT or firewalls
async fn setup_foreign_device() -> Result<BacnetIpDataLink, Box<dyn std::error::Error>> {
    let config = BacnetIpConfig {
        local_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 47808)),
        broadcast_address: SocketAddr::from((Ipv4Addr::BROADCAST, 47808)),
        bbmd_address: Some(SocketAddr::from(([203, 0, 113, 10], 47808))), // Public BBMD
        bbmd_registration_interval: Some(std::time::Duration::from_secs(300)),
        max_masters: 127,
        max_info_frames: 50,
    };

    let mut datalink = BacnetIpDataLink::with_config(config).await?;
    
    // Register as foreign device
    datalink.register_foreign_device().await?;
    
    Ok(datalink)
}
```

### Network Routing Setup

```rust
use bacnet_rs::network::{NetworkLayerHandler, RouterManager, NetworkAddress};

fn setup_network_routing() -> NetworkLayerHandler {
    let mut network_handler = NetworkLayerHandler::new();
    
    // Configure as a router between networks 1 and 2
    network_handler.add_route(1, NetworkAddress::from_bytes(&[192, 168, 1, 0]));
    network_handler.add_route(2, NetworkAddress::from_bytes(&[192, 168, 2, 0]));
    
    // Set up router table
    let mut router_manager = RouterManager::new();
    router_manager.add_router(
        NetworkAddress::from_bytes(&[192, 168, 1, 100]), 
        vec![1, 2, 3]
    );
    
    network_handler
}
```

## Error Handling and Logging

### Comprehensive Error Handling

```rust
use bacnet_rs::{
    app::{ApplicationError, ApplicationLayerHandler},
    service::{ServiceError, RejectReason, AbortReason},
};
use log::{error, warn, info, debug};

fn handle_bacnet_errors(app_handler: &mut ApplicationLayerHandler) {
    // Custom error handling
    app_handler.set_error_handler(|error| {
        match error {
            ApplicationError::InvalidApdu(msg) => {
                error!("Invalid APDU received: {}", msg);
                // Could send Reject PDU
            },
            ApplicationError::Timeout => {
                warn!("Transaction timeout occurred");
                // Retry logic here
            },
            ApplicationError::MaxApduLengthExceeded => {
                error!("APDU too large for device capabilities");
                // Send Abort PDU
            },
            _ => {
                error!("Application error: {}", error);
            }
        }
    });
}

// Centralized logging setup
fn setup_logging() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_secs()
        .init();
    
    info!("BACnet stack logging initialized");
}

// Result handling patterns
async fn safe_bacnet_operation() -> Result<(), Box<dyn std::error::Error>> {
    match send_read_property_request().await {
        Ok(response) => {
            info!("Property read successful: {:?}", response);
            Ok(())
        },
        Err(ServiceError::Timeout) => {
            warn!("Read property timed out, retrying...");
            // Implement retry logic
            Err("Timeout after retries".into())
        },
        Err(ServiceError::Rejected(reason)) => {
            error!("Request rejected: {:?}", reason);
            Err(format!("Rejected: {:?}", reason).into())
        },
        Err(e) => {
            error!("Service error: {}", e);
            Err(e.into())
        }
    }
}

async fn send_read_property_request() -> Result<Vec<u8>, ServiceError> {
    // Implementation here
    Ok(vec![])
}
```

## Performance Optimization

### High-Performance Device Implementation

```rust
use bacnet_rs::{
    app::{ApplicationLayerHandler, ApplicationPriorityQueue, MessagePriority},
    encoding::{EncodingManager, EncodingConfig},
    network::NetworkLayerHandler,
};
use tokio::sync::mpsc;

struct HighPerformanceDevice {
    app_handler: ApplicationLayerHandler,
    network_handler: NetworkLayerHandler,
    message_queue: ApplicationPriorityQueue,
    encoding_manager: EncodingManager,
    
    // Performance monitoring
    stats: DeviceStatistics,
}

#[derive(Debug, Default)]
struct DeviceStatistics {
    messages_processed: u64,
    average_response_time: f64,
    errors_count: u64,
    uptime_seconds: u64,
}

impl HighPerformanceDevice {
    fn new(device_instance: u32) -> Self {
        let mut app_handler = ApplicationLayerHandler::new(device_instance);
        
        // Configure for high performance
        let encoding_config = EncodingConfig {
            validation_level: 1, // Basic validation only
            enable_caching: true,
            cache_size: 1000,
            enable_compression: false, // Disable for speed
        };
        
        let encoding_manager = EncodingManager::with_config(encoding_config);
        
        // Large message queue for high throughput
        let message_queue = ApplicationPriorityQueue::new(10000);
        
        Self {
            app_handler,
            network_handler: NetworkLayerHandler::new(),
            message_queue,
            encoding_manager,
            stats: DeviceStatistics::default(),
        }
    }
    
    async fn process_messages_batch(&mut self, batch_size: usize) -> Result<(), Box<dyn std::error::Error>> {
        let start_time = std::time::Instant::now();
        
        for _ in 0..batch_size {
            if let Some((apdu, destination)) = self.message_queue.dequeue() {
                // Process message
                self.stats.messages_processed += 1;
            } else {
                break;
            }
        }
        
        // Update performance stats
        let elapsed = start_time.elapsed();
        self.stats.average_response_time = elapsed.as_secs_f64() / batch_size as f64;
        
        Ok(())
    }
    
    // Non-blocking message handling
    async fn handle_message_async(&mut self, message: Vec<u8>) {
        tokio::spawn(async move {
            // Process message in background
            // This prevents blocking the main event loop
        });
    }
}

// Memory-efficient object storage
use std::collections::HashMap;
use bacnet_rs::object::{ObjectIdentifier, BacnetObject};

struct OptimizedObjectStore {
    objects: HashMap<ObjectIdentifier, Box<dyn BacnetObject>>,
    object_cache: HashMap<ObjectIdentifier, Vec<u8>>, // Cached encoded data
}

impl OptimizedObjectStore {
    fn get_property_cached(&mut self, 
                          object_id: ObjectIdentifier, 
                          property_id: PropertyIdentifier) -> Option<&[u8]> {
        // Return cached data if available
        if let Some(cached) = self.object_cache.get(&object_id) {
            return Some(cached);
        }
        
        // Generate and cache if not available
        if let Some(object) = self.objects.get(&object_id) {
            if let Some(value) = object.get_property_value(property_id, None) {
                let encoded = self.encode_property_value(value);
                self.object_cache.insert(object_id, encoded);
                return self.object_cache.get(&object_id).map(|v| v.as_slice());
            }
        }
        
        None
    }
    
    fn encode_property_value(&self, value: PropertyValue) -> Vec<u8> {
        // Fast encoding implementation
        match value {
            PropertyValue::Real(f) => f.to_be_bytes().to_vec(),
            PropertyValue::Unsigned(u) => u.to_be_bytes().to_vec(),
            _ => vec![], // Simplified
        }
    }
}
```

## Testing

### Unit Testing Examples

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_rs::{
        app::{Apdu, MaxApduSize, MaxSegments},
        service::UnconfirmedServiceChoice,
    };

    #[test]
    fn test_who_is_response() {
        let mut app_handler = ApplicationLayerHandler::new(1234);
        
        app_handler.set_who_is_handler(|_| {
            Ok(Some(vec![0xC4, 0x02, 0x00, 0x04, 0xD2])) // I-Am response
        });

        let who_is_apdu = Apdu::UnconfirmedRequest {
            service_choice: UnconfirmedServiceChoice::WhoIs,
            service_data: vec![],
        };

        let response = app_handler.process_apdu(&who_is_apdu, &[]).unwrap();
        assert!(response.is_some());
        
        match response.unwrap() {
            Apdu::UnconfirmedRequest { service_choice, .. } => {
                assert_eq!(service_choice, UnconfirmedServiceChoice::IAm);
            },
            _ => panic!("Expected I-Am response"),
        }
    }

    #[test]
    fn test_confirmed_request_handling() {
        let mut app_handler = ApplicationLayerHandler::new(5678);
        
        app_handler.set_read_property_handler(|_| {
            Ok(vec![0x44, 0x42, 0x38, 0x00, 0x00]) // Real value 23.0
        });

        let read_property_apdu = Apdu::ConfirmedRequest {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: true,
            max_segments: MaxSegments::Unspecified,
            max_response_size: MaxApduSize::Up1476,
            invoke_id: 42,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: 12, // ReadProperty
            service_data: vec![0x0C, 0x02, 0x00, 0x00, 0x08, 0x19, 0x55], // AI:1, Present Value
        };

        let response = app_handler.process_apdu(&read_property_apdu, &[]).unwrap();
        assert!(response.is_some());
        
        match response.unwrap() {
            Apdu::ComplexAck { invoke_id, service_choice, .. } => {
                assert_eq!(invoke_id, 42);
                assert_eq!(service_choice, 12);
            },
            _ => panic!("Expected ComplexAck response"),
        }
    }

    #[tokio::test]
    async fn test_datalink_communication() {
        let local_addr: SocketAddr = "127.0.0.1:47808".parse().unwrap();
        let broadcast_addr: SocketAddr = "127.0.0.1:47809".parse().unwrap();
        
        // This would require a more complex test setup with actual sockets
        // For integration testing
    }

    #[test]
    fn test_object_property_access() {
        let mut device = Device::new(
            ObjectIdentifier::new(ObjectType::Device, 100),
            "Test Device".to_string(),
            "Test".to_string(),
        );
        
        device.set_property_value(
            PropertyIdentifier::Description, 
            PropertyValue::CharacterString("Updated description".to_string())
        );
        
        let description = device.get_property_value(PropertyIdentifier::Description, None);
        assert!(description.is_some());
        
        match description.unwrap() {
            PropertyValue::CharacterString(s) => {
                assert_eq!(s, "Updated description");
            },
            _ => panic!("Expected string value"),
        }
    }
}
```

## Best Practices

### 1. Resource Management
- Use object pools for frequently allocated objects
- Implement proper cleanup for network resources
- Monitor memory usage in embedded environments

### 2. Security Considerations
- Validate all incoming data before processing
- Implement rate limiting for incoming requests
- Use secure network configurations when possible

### 3. Error Recovery
- Implement robust retry mechanisms
- Handle network disconnections gracefully
- Provide meaningful error messages to users

### 4. Performance Tips
- Cache frequently accessed properties
- Use batch operations when possible
- Minimize memory allocations in hot paths
- Profile your application to identify bottlenecks

This guide provides a comprehensive foundation for using the BACnet stack. For specific use cases or advanced features, refer to the API documentation and examples in the repository.