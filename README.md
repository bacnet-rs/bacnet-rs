# BACnet-RS

A BACnet (Building Automation and Control Networks) protocol stack implementation in Rust.

> **Note:** This library is under active development and not yet production-ready. APIs may change between releases.
> Contributions and feedback are welcome.

## Overview

This library provides an implementation of the BACnet protocol stack in Rust, targeting compliance with ANSI/ASHRAE
Standard 135-2024. It supports multiple data link layers, core BACnet services, and is designed for both embedded and
desktop applications.

## Implementation Status

| Component                  | Status          | Notes                                                                            |
|----------------------------|-----------------|----------------------------------------------------------------------------------|
| **Encoding/Decoding**      | Working         | ASN.1 application and context tags, all primitive types                          |
| **BACnet/IP (Annex J)**    | Working         | BVLC, BBMD, Foreign Device registration                                          |
| **MS/TP (Clause 9)**       | Working         | Frame encoding, CRC, token-passing                                               |
| **Ethernet (Clause 7)**    | Working         | 802.3 frames, LLC headers                                                        |
| **Who-Is / I-Am**          | Working         | Device discovery                                                                 |
| **Read Property**          | Working         | Single property read                                                             |
| **Read Property Multiple** | Working         | Batch property reads                                                             |
| **Write Property**         | Working         | Single property write                                                            |
| **Subscribe COV**          | Working         | Change-of-value subscriptions                                                    |
| **Atomic File Read/Write** | Working         | Stream and record access                                                         |
| **Time Synchronization**   | Working         | Standard and UTC                                                                 |
| **Analog Objects**         | Working         | Input, Output, Value with priority arrays                                        |
| **Binary Objects**         | Working         | Input, Output, Value with priority arrays                                        |
| **Multistate Objects**     | Working         | Input, Output, Value                                                             |
| **File / Device Objects**  | Working         | Basic property support                                                           |
| **Client API**             | Working         | Discovery, broadcast Who-Is, read/write & verified write (BACnet/IP, no routing) |
| **Segmentation**           | Not implemented | Large message segmentation/reassembly                                            |
| **Alarm & Event**          | Not implemented | Intrinsic and algorithmic reporting                                              |
| **Trending**               | Not implemented | Trend log objects                                                                |
| **Scheduling**             | Not implemented | Schedule and calendar objects                                                    |
| **BACnet/SC (Annex AB)**   | Not implemented | Secure Connect                                                                   |

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
bacnet-rs = "0.3"
```

### Feature Flags

- `std` (default): Standard library support with networking capabilities
- `async` (default): Async/await support with Tokio runtime
- `serde` (default): Serialization support for BACnet types

To use without async support:
```toml
bacnet-rs = { version = "0.3", default-features = false, features = ["std"] }
```

## Architecture

The stack is organized into layered modules:

- **Encoding** (`src/encoding/`): BACnet data encoding/decoding, ASN.1 tag handling
- **Datalink** (`src/datalink/`): BACnet/IP, MS/TP, Ethernet implementations
- **Network** (`src/network/`): NPDU handling and routing
- **Service** (`src/service/`): BACnet service request/response implementations
- **Object** (`src/object/`): Standard BACnet object types and database
- **Application** (`src/app/`): APDU handling and segmentation
- **Client** (`src/client/`): High-level BACnet client API

## Examples

The high-level [`BacnetClient`](src/client/mod.rs) is the recommended entry point
for talking to devices. The client-focused examples:

```bash
# Discover every device on the local network (broadcast Who-Is)
cargo run --example whois_scan

# Discover one device, then read its object list and properties
cargo run --example test_client 10.161.1.211

# Read a single property
cargo run --example read_write_property 10.161.1.211 analogValue 4

# Write Present_Value and verify it took effect (priority 8)
cargo run --example read_write_property 10.161.1.211 analogValue 4 5.0 8

# Relinquish a commanded priority slot (write Null)
cargo run --example read_write_property 10.161.1.211 analogValue 4 relinquish 8
```

Lower-level examples (`routed_device_discovery` for network routing, and the
device-side `hosted_device`) drive the data-link or server layers directly for
cases the client does not cover. The `hosted_device` example documents the
server's deliberately small implementation profile and current limitations.

## Contributing

Contributions are welcome. Please open an issue or pull request.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
