//! BACnet Who-Is Scan Example
//!
//! Discovers BACnet/IP devices on the local network using the high-level
//! [`BacnetClient`]: it broadcasts a Who-Is and collects every I-Am reply.
//!
//! The limited broadcast (255.255.255.255) is tried first; because that is often
//! unroutable on multi-homed / Wi-Fi hosts, several common subnet-directed
//! broadcast addresses are also tried (unreachable ones are skipped). Replies
//! are de-duplicated by device id.
//!
//! For a router-aware discovery example, see `routed_device_discovery`.

use bacnet_rs::client::{BacnetClient, DeviceInfo};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Who-Is Scan Example");
    println!("==========================\n");

    // Bind an ephemeral local port; devices reply unicast to it.
    let client = BacnetClient::builder()
        .port(0xBAC0)
        .timeout(Duration::from_secs(3))
        .build()?;
    println!("Listening on {}\n", client.local_addr()?);

    // Candidate broadcast targets: the limited broadcast reaches the directly
    // attached subnet, and the subnet-directed entries cover common LANs. Ones
    // that aren't routable from this host are skipped automatically.
    let targets = [
        "255.255.255.255:47808",
        "10.161.1.255:47808",
        "192.168.1.255:47808",
        "192.168.0.255:47808",
        "172.16.0.255:47808",
        "172.25.250.255:47808",
    ];

    let mut devices: BTreeMap<u32, DeviceInfo> = BTreeMap::new();
    for target in targets {
        let addr: SocketAddr = target.parse()?;
        match client.who_is_to(addr, None, None) {
            Ok(found) => {
                let fresh: Vec<DeviceInfo> = found
                    .into_iter()
                    .filter(|d| !devices.contains_key(&d.device_id))
                    .collect();
                if !fresh.is_empty() {
                    println!("Replies via {target}:");
                    for d in fresh {
                        println!(
                            "  Device {:>7}  {:<22}  {}  (max APDU {}, {})",
                            d.device_id, d.vendor_name, d.address, d.max_apdu, d.segmentation
                        );
                        devices.insert(d.device_id, d);
                    }
                }
            }
            Err(e) => println!("  skip {target}: {e}"),
        }
    }

    println!("\nScan complete: {} device(s) discovered.", devices.len());

    if devices.is_empty() {
        println!("\nNo devices found. Possible reasons:");
        println!("- No BACnet devices on the network");
        println!("- Devices are on a different subnet (call who_is_to with your subnet broadcast)");
        println!("- Firewall blocking BACnet/IP traffic (UDP port 47808)");
    } else {
        println!("\nDevice Summary:");
        println!("---------------");
        for d in devices.values() {
            println!("Device {} @ {} - {}", d.device_id, d.address, d.vendor_name);
        }
    }

    Ok(())
}
