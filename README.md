# BACnet-RS

A work-in-progress BACnet (Building Automation and Control Networks) protocol stack implementation in Rust.

## Overview

This library aims to provide a complete implementation of the BACnet protocol stack in Rust, designed as a modern alternative to the official C BACnet stack. It will support multiple data link layers, all standard BACnet services, and aims to be suitable for both embedded and desktop applications.

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
bacnet-rs = "0.2"
```

### Feature Flags

- `std` (default): Standard library support with networking capabilities
- `async` (default): Async/await support with Tokio runtime
- `serde` (default): Serialization support for BACnet types

To use without async support:
```toml
bacnet-rs = { version = "0.2", default-features = false, features = ["std"] }
```

## Architecture

The stack is organized into layered modules:

- **Encoding**: BACnet data encoding/decoding
- **Datalink**: Network transport implementations
- **Network**: NPDU handling and routing
- **Service**: BACnet service implementations
- **Object**: Standard BACnet object types
- **Application**: High-level API

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
