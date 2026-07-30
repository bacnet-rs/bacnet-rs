//! Hosted BACnet device support.
//!
//! The server side is split into a protocol-independent object service and a
//! BACnet/IP endpoint. [`ObjectService`] executes decoded BACnet operations
//! against an [`ObjectDatabase`], while [`BacnetIpServer`] owns the UDP socket
//! and handles BVLC, NPDU, and APDU framing. With the `async` feature,
//! `AsyncBacnetIpServer` provides bounded concurrent request handling over a
//! single Tokio UDP socket.

mod address_cache;
mod bip;
mod dispatcher;
mod error;
mod object_service;

pub use address_cache::AddressCache;
#[cfg(feature = "async")]
pub use bip::AsyncBacnetIpServer;
pub use bip::{BacnetIpServer, Notifier, ServedRequest};
pub use dispatcher::{ServerDispatcher, ServerResponse};
pub use error::ServerError;
pub use object_service::ObjectService;
