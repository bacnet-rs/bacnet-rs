# Changelog

All notable changes to this project will be documented in this file.

## [0.3.1] - 2026-06-30

This release introduces a synchronous **client API** (`BacnetClient`),
device discovery plus typed read/write, and resolves a
security-audit advisory in the dependency tree.

### Added

- **Client API** (`src/client/`):
  - `BacnetClient` with a builder-based `ClientConfig` (host, port, timeout, retries)
    and a typed `ClientError` returned from every operation
  - `who_is()` / `who_is_to(target, low, high)` device discovery returning `Vec<DeviceInfo>`
  - `read_property()` returning all decoded `PropertyValue`s for the request
  - `write_property()` with optional priority (1–16) for commandable objects
  - `write_property_verified()` returning `WriteOutcome` (`Verified` /
    `NotEffective { read_back }`) confirms a write actually took effect by reading
    the value back, with a short retry loop to absorb device settling time
  - `InvokeIdAllocator` for transaction invoke-ID correlation
  - `timeout()` and `local_addr()` accessors
- `Client::new_with_local_addr` for binding a specific IPv4/IPv6 address and
  ephemeral port (replaces `new_with_local_port`)
- `AbortReason` enumeration (ASHRAE 135 `BACnetAbortReason`) surfaced through
  `ClientError::Abort`, with `Custom`/`Reserved` handling for vendor/reserved codes
- Human-readable decoding of BACnet error class/code pairs in client error messages
- New `read_write_property` example (discover → read → write/verify → relinquish)
  using the client API
- Client integration and device-discovery tests (`tests/client_confirmed.rs`,
  `tests/client_discovery.rs`)

### Changed

- `EngineeringUnits` ordering and documentation aligned with ANSI/ASHRAE
  Standard 135-2024; `micro-siemens` renamed to `microsiemens`
- `AbortReason` is now generated via `generate_custom_enum!` (auto `From`/`Display`
  and `Custom`/`Reserved` variants) instead of a hand-written impl; its `Display`
  output is now PascalCase, consistent with `RejectReason`
- `generate_custom_enum!` no longer emits a module-level `use serde::{...}`; it
  uses fully-qualified paths in its derives so the macro can be invoked more than
  once per module
- `BACNET_IP_PORT` moved into the `datalink::bip` module
- Examples migrated to the high-level client API where applicable; `whois_scan`
  reworked to use `BacnetClient`
- Object-identifier scanning now uses `decode_object_identifier` instead of manual
  byte slicing

### Fixed

- `BvlcFunction` in `datalink::bip` now matches ASHRAE 135 Annex J: `SecureBvll`
  moved from `0x0D` to its standard code `0x0C`, the nonstandard
  `ForwardedNpduFromDevice` variant was removed, and the missing `Result` (`0x00`)
  and `WriteBroadcastDistributionTable` (`0x01`) functions were added
- `who_is`/`who_is_to` now send Who-Is as a global-broadcast NPDU (DNET `0xFFFF`, hop count 255) inside an
  Original-Broadcast-NPDU BVLC when the target is a broadcast address, matching YABE and the reference bacnet-stack;
  unicast targets get a plain local NPDU inside Original-Unicast-NPDU instead of the previous broadcast-BVLC/local-NPDU
  mix (#58)
- Socket receive loops now treat both `WouldBlock` and `TimedOut` as timeouts,
  fixing a cross-platform timeout bug on Windows (`WSAETIMEDOUT`)
- The no-std build (`cargo build --no-default-features`) compiles again — it had
  ~200 accumulated errors: missing `alloc` imports (`Vec`, `String`, `Box`,
  `vec!`, `format!`, `ToString`) across 18 modules, `std::` paths in code shared with no-std (now `core::`), the
  `generate_custom_enum!` macro emitting
  `std::fmt` impls, the std-only `util::statistics` module (uses
  `Instant`/`Arc`/`Mutex`) not being feature-gated, and `f64::powi`/`f64::log2`
  (std-only) used in retry backoff and frame-entropy calculations
- Clippy warnings resolved; conditional logic refactored to `if let` guards

### Removed

- Removed the duplicate `BvllHeader`/`BvllFunction`/`BvllType` types from the
  `transport` module; the transport layer now reuses (and re-exports)
  `datalink::bip::{BvlcHeader, BvlcFunction}` so there is a single BVLL header implementation
- Removed the unused optional `env_logger` dependency, which transitively pulled in
  the unmaintained `proc-macro-error2` crate (RUSTSEC-2026-0173) via `jiff` → `defmt`
- Removed the `advanced_device`, `comprehensive_whois_scan`, `debug_formatter`, and
  `debug_properties` examples and the per-folder example READMEs to streamline the
  example set

## [0.3.0] - 2026-04-13

### Breaking Changes

- `PropertyValue` enum consolidated into a single type in `property.rs`; duplicate in `client.rs` removed
- `PropertyValue::Unsigned` widened from `u32` to `u64`
- `PropertyValue::Signed` widened from `i32` to `i64`
- `PropertyValue::ObjectIdentifier` changed from `(u16, u32)` to `ObjectIdentifier`
- `PropertyReference::new()` takes `PropertyIdentifier` instead of raw `u32`
- `ReadPropertyResponse.property_value` changed from `Vec<u8>` to `Vec<PropertyValue>`
- `ObjectIdentifier.object_type` changed from `u16` to `ObjectType` enum
- `IAmRequest.segmentation_supported` changed to `Segmentation` enum
- `IAmRequest.vendor_identifier` changed to `u16`
- `NetworkLayerMessage::data` changed to `Option<Vec<u8>>`
- `Apdu::ComplexAck` service_choice changed to `ConfirmedServiceChoice`
- `Apdu::Error` now uses `ConfirmedServiceChoice`
- `Apdu::Reject` now uses `RejectReason`
- `ObjectInfo.units` changed from `Option<String>` to `Option<EngineeringUnits>`
- `encode_enumerated` and `encode_application_tag` are now infallible (no longer return `Result`)

### Added

- `generate_custom_enum!` macro for type-safe enums with Custom/Reserved variants
- `ObjectType` enum with full BACnet standard coverage (replaces raw `u16`)
- `PropertyIdentifier` enum with all standard property identifiers
- `EngineeringUnits` rewrite with `bacnet_name()` and `unit_symbol()` per variant (~120 units)
- `EventState`, `Reliability`, `RejectReason` — complete standard enumerations
- `ReadPropertyMultipleResponse`, `ReadAccessResult`, `PropertyResult` structs for RPM response decoding
- `BACnetTag` enum and `decode_tag()` for generic application/context tag decoding
- `encode_unsigned64`, `decode_unsigned64`, `encode_signed64`, `decode_signed64` for 64-bit integers
- `PropertyValue::Double(f64)` and `PropertyValue::OctetString(Vec<u8>)` variants
- `Display` impl for `PropertyValue` (behind `std` feature)
- `encode()`/`decode()` methods on `ReadPropertyMultipleRequest`, `ReadAccessSpecification`, `PropertyReference`,
  `ReadPropertyResponse`
- Serde support (behind `serde` feature) for `NetworkAddress`, `ObjectIdentifier`, `Segmentation`, `Polarity`,
  `PropertyValue`, and all `generate_custom_enum!` types
- `ProtocolServicesSupported` using `bitflags!` macro
- `TryFrom<u8>` for `BvlcFunction` and `NetworkMessageType`
- `TryFrom<u32>` for `Segmentation` and `Polarity`
- `Display` impl for `Segmentation`
- Helper functions `set_source()` and `set_destination()` on `Npdu`
- `NetworkAddress` now implements `Hash`

### Fixed

- `UnconfirmedServiceChoice` conversion from `u8` was incorrect
- `service_choice` was being double-converted in APDU handling
- `Apdu::Error` variant handling was broken
- Removed broken `bincode` dependency
- Pinned `crc` to `3.3.*` for MSRV compatibility

### Changed

- README updated with honest implementation status table and WIP notice
- CI: replaced `cargo install cargo-deny --locked` with `taiki-e/install-action@cargo-deny` (pre-built binary)
- ~450 lines of duplicate/broken unit mapping code removed from `property.rs`
- Duplicate property value decoding functions consolidated into `decode_property_value()`
- `decode_property_value()` now returns `Result` instead of `Option`

## [0.2.2] - 2025-10-02

