//! Error types for the high-level BACnet client.
//!
//! The client returns a single, typed [`ClientError`] from all of its public
//! methods. This replaces the previous `Box<dyn std::error::Error>` returns and
//! lets callers match on specific failure modes (timeouts, protocol-level
//! rejects/aborts, per-property errors, etc.) instead of inspecting strings.

use crate::encoding::EncodingError;
use crate::service::{AbortReason, RejectReason};
use crate::util::describe_bacnet_error;
use thiserror::Error;

/// Errors that can occur while using the high-level [`BacnetClient`](super::BacnetClient).
#[derive(Debug, Error)]
pub enum ClientError {
    /// An underlying socket / I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A request could not be encoded, or a response could not be decoded,
    /// using the BACnet encoding rules.
    #[error("encoding error: {0}")]
    Encoding(#[from] EncodingError),

    /// A response was malformed or could not be interpreted.
    #[error("failed to decode response: {0}")]
    Decode(String),

    /// No response was received within the configured timeout.
    #[error("request timed out")]
    Timeout,

    /// A response was expected but the peer returned nothing usable.
    #[error("no response from device")]
    NoResponse,

    /// The remote device rejected the request at the application layer.
    #[error("request rejected: {0}")]
    Rejected(RejectReason),

    /// The remote device aborted the transaction.
    #[error("transaction aborted: {0}")]
    Abort(AbortReason),

    /// The device returned a BACnet `Error` PDU (or a per-property error inside
    /// a ReadPropertyMultiple result), identified by its error class and code.
    #[error("{}", describe_bacnet_error(*class, *code))]
    PropertyError {
        /// BACnet error class.
        class: u32,
        /// BACnet error code.
        code: u32,
    },

    /// A supplied address could not be parsed or resolved.
    #[error("invalid address: {0}")]
    AddressParse(String),
}
