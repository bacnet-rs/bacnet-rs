//! BACnet Utility Functions Demo
//!
//! This example demonstrates the comprehensive utility functions including
//! performance monitoring, statistics collection, and other helpers.

use bacnet_rs::{
    object::ObjectIdentifier,
    util::{
        self, calculate_throughput, format_bytes,
        performance::{PerformanceMonitor, ScopedTimer},
        statistics::StatsCollector,
        CircularBuffer, RetryConfig,
    },
    ObjectType,
};
use std::{
    thread,
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Utility Functions Demo");
    println!("============================\n");

    // Demo 1: Performance Monitoring
    demo_performance_monitoring()?;

    // Demo 2: Statistics Collection
    demo_statistics_collection()?;

    // Demo 3: Utility Functions
    demo_utility_functions()?;

    // Demo 4: Circular Buffer
    demo_circular_buffer()?;

    // Demo 5: Retry Configuration
    demo_retry_config()?;

    println!("\nUtility Demo Complete!");
    Ok(())
}

/// Demonstrate performance monitoring
fn demo_performance_monitoring() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Performance Monitoring");
    println!("========================");

    let monitor = PerformanceMonitor::new();

    // Simulate various operations with different durations
    for i in 0..5 {
        {
            let _timer = ScopedTimer::new(&monitor, "device_discovery");
            thread::sleep(Duration::from_millis(50 + i * 10));
        }

        {
            let _timer = ScopedTimer::new(&monitor, "property_read");
            thread::sleep(Duration::from_millis(20 + i * 5));
        }

        {
            let _timer = ScopedTimer::new(&monitor, "property_write");
            thread::sleep(Duration::from_millis(30 + i * 7));
        }
    }

    // Display performance metrics
    println!("\nPerformance Metrics:");
    println!("-------------------");

    for metric in monitor.get_all_metrics() {
        println!("  {} ({} calls):", metric.name, metric.count);
        println!("    Average: {:.2} ms", metric.avg_duration_ms);
        println!("    Min: {:.2} ms", metric.min_duration_ms);
        println!("    Max: {:.2} ms", metric.max_duration_ms);
        println!("    Total: {:.2} ms", metric.total_duration_ms);
    }

    println!();
    Ok(())
}

/// Demonstrate statistics collection
fn demo_statistics_collection() -> Result<(), Box<dyn std::error::Error>> {
    println!("2. Statistics Collection");
    println!("=======================");

    let collector = StatsCollector::new();

    // Simulate communication with multiple devices
    let devices = vec![
        (5047, "10.161.1.211:47808"),
        (1234, "192.168.1.100:47808"),
        (9999, "172.16.0.50:47808"),
    ];

    for (device_id, address) in &devices {
        // Get or create device stats
        let _ = collector.get_device_stats(*device_id, address.to_string());

        // Simulate some communication
        for i in 0..10 {
            // Record sent message
            collector.update_device_stats(*device_id, |stats| {
                stats.comm_stats.record_sent(250);
            });
            collector.update_global_stats(|stats| {
                stats.record_sent(250);
            });

            // Simulate response
            if i % 3 != 2 {
                // 2/3 success rate
                let response_time = 20.0 + (i as f64) * 2.5;
                collector.update_device_stats(*device_id, |stats| {
                    stats.comm_stats.record_received(150);
                    stats.record_response_time(response_time);
                });
                collector.update_global_stats(|stats| {
                    stats.record_received(150);
                });
            } else {
                // Simulate timeout
                collector.update_device_stats(*device_id, |stats| {
                    stats.comm_stats.record_timeout();
                });
                collector.update_global_stats(|stats| {
                    stats.record_timeout();
                });
            }
        }
    }

    // Display statistics
    println!("\nGlobal Communication Statistics:");
    println!("-------------------------------");
    let global_stats = collector.get_global_stats();
    println!("  Messages sent: {}", global_stats.messages_sent);
    println!("  Messages received: {}", global_stats.messages_received);
    println!(
        "  Bytes sent: {} ({})",
        global_stats.bytes_sent,
        format_bytes(global_stats.bytes_sent)
    );
    println!(
        "  Bytes received: {} ({})",
        global_stats.bytes_received,
        format_bytes(global_stats.bytes_received)
    );
    println!("  Timeouts: {}", global_stats.timeouts);
    println!("  Success rate: {:.1}%", global_stats.success_rate());

    println!("\nDevice Statistics:");
    println!("-----------------");
    for device in collector.get_all_device_stats() {
        println!("  Device {} ({}):", device.device_id, device.address);
        println!(
            "    Status: {}",
            if device.online { "Online" } else { "Offline" }
        );
        println!("    Success rate: {:.1}%", device.comm_stats.success_rate());
        if let Some(avg_response) = device.avg_response_time() {
            println!("    Avg response time: {:.2} ms", avg_response);
        }
        println!(
            "    Messages: {} sent, {} received",
            device.comm_stats.messages_sent, device.comm_stats.messages_received
        );
    }

    println!();
    Ok(())
}

/// Demonstrate utility functions
fn demo_utility_functions() -> Result<(), Box<dyn std::error::Error>> {
    println!("3. Utility Functions");
    println!("===================");

    // BACnet date/time formatting
    let date_str = util::bacnet_date_to_string(2024, 3, 15, 5);
    println!("  BACnet date: {}", date_str);

    let time_str = util::bacnet_time_to_string(14, 30, 45, 50);
    println!("  BACnet time: {}", time_str);

    // Object ID encoding/decoding
    let instance = 1234;
    let obj_id = ObjectIdentifier::new(ObjectType::AnalogInput, instance);
    let obj_id: u32 = obj_id.into();
    println!("  Encoded object ID: 0x{:08X}", obj_id);
    let decoded_id: ObjectIdentifier = obj_id.into();
    println!(
        "  Decoded: type={}, instance={}",
        decoded_id.object_type, decoded_id.instance
    );

    // Address parsing
    match util::parse_bacnet_address("192.168.1.100") {
        Ok(addr) => println!("  Parsed address: {}", addr),
        Err(e) => println!("  Address parse error: {}", e),
    }

    // Byte formatting
    println!("\n  Byte formatting examples:");
    println!("    {} = {}", 0, format_bytes(0));
    println!("    {} = {}", 1234, format_bytes(1234));
    println!("    {} = {}", 1048576, format_bytes(1048576));
    println!("    {} = {}", 5368709120u64, format_bytes(5368709120));

    // Throughput calculation
    let bytes = 1_000_000u64;
    let duration = 2.5;
    println!(
        "\n  Throughput: {} bytes in {} seconds = {}",
        bytes,
        duration,
        calculate_throughput(bytes, duration)
    );

    // CRC calculations
    let data = b"Hello BACnet";
    let crc16 = util::crc16_mstp(data);
    let crc32 = util::crc32c(data);
    println!(
        "\n  CRC calculations for '{}':",
        String::from_utf8_lossy(data)
    );
    println!("    CRC-16 (MS/TP): 0x{:04X}", crc16);
    println!("    CRC-32C: 0x{:08X}", crc32);

    println!();
    Ok(())
}

/// Demonstrate circular buffer
fn demo_circular_buffer() -> Result<(), Box<dyn std::error::Error>> {
    println!("4. Circular Buffer");
    println!("==================");

    let mut event_log: CircularBuffer<String> = CircularBuffer::new(5);

    // Add events
    let events = vec![
        "Device 5047 discovered",
        "Connected to 10.161.1.211",
        "Read property: Present_Value = 22.9",
        "Device 1234 timeout",
        "Write property successful",
        "Device 5047 went offline",
        "Reconnection attempt 1",
        "Reconnection successful",
    ];

    println!("  Adding {} events to buffer (capacity: 5):", events.len());
    for event in events {
        event_log.push(event.to_string());
        println!("    + {}", event);
    }

    println!("\n  Current buffer contents ({} items):", event_log.len());
    for (i, event) in event_log.items().iter().enumerate() {
        println!("    [{}] {}", i, event);
    }

    println!();
    Ok(())
}

/// Demonstrate retry configuration
fn demo_retry_config() -> Result<(), Box<dyn std::error::Error>> {
    println!("5. Retry Configuration");
    println!("=====================");

    let retry_config = RetryConfig {
        max_attempts: 5,
        initial_delay_ms: 250,
        max_delay_ms: 10000,
        backoff_multiplier: 2.0,
    };

    println!("  Retry configuration:");
    println!("    Max attempts: {}", retry_config.max_attempts);
    println!("    Initial delay: {} ms", retry_config.initial_delay_ms);
    println!("    Max delay: {} ms", retry_config.max_delay_ms);
    println!(
        "    Backoff multiplier: {}",
        retry_config.backoff_multiplier
    );

    println!("\n  Delay progression:");
    for attempt in 0..retry_config.max_attempts {
        let delay = retry_config.delay_for_attempt(attempt);
        println!("    Attempt {}: {} ms", attempt + 1, delay.as_millis());
    }

    // Simulate retry with backoff
    println!("\n  Simulating retry with exponential backoff:");
    let start = Instant::now();

    for attempt in 0..3 {
        println!(
            "    Attempt {} at {:.1}s",
            attempt + 1,
            start.elapsed().as_secs_f64()
        );

        if attempt < 2 {
            let delay = retry_config.delay_for_attempt(attempt);
            println!(
                "    Failed, waiting {} ms before retry...",
                delay.as_millis()
            );
            thread::sleep(delay);
        } else {
            println!("    Success!");
        }
    }

    println!();
    Ok(())
}
