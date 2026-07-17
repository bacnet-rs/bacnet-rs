//! Error types for the high-level BACnet client.
//!
//! The client returns a single, typed [`ClientError`] from all of its public
//! methods. This replaces the previous `Box<dyn std::error::Error>` returns and
//! lets callers match on specific failure modes (timeouts, protocol-level
//! rejects/aborts, per-property errors, etc.) instead of inspecting strings.

use crate::encoding::EncodingError;
use crate::service::{AbortReason, RejectReason};
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

/// Human-readable name for a BACnet error class (ASHRAE 135 `BACnetErrorClass`).
fn error_class_name(class: u32) -> Option<&'static str> {
    Some(match class {
        0 => "device",
        1 => "object",
        2 => "property",
        3 => "resources",
        4 => "security",
        5 => "services",
        6 => "vt",
        7 => "communication",
        _ => return None,
    })
}

/// Human-readable name for the common BACnet error codes (ASHRAE 135
/// `BACnetErrorCode`). Not exhaustive — unknown codes fall back to the number.
fn error_code_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0 => "other",
        9 => "invalid-data-type",
        20 => "no-space-to-write-property",
        23 => "object-deletion-not-permitted",
        27 => "read-access-denied",
        29 => "service-request-denied",
        30 => "timeout",
        31 => "unknown-object",
        32 => "unknown-property",
        37 => "value-out-of-range",
        40 => "write-access-denied",
        42 => "invalid-array-index",
        44 => "not-cov-property",
        45 => "optional-functionality-not-supported",
        47 => "datatype-not-supported",
        50 => "property-is-not-an-array",
        70 => "unknown-device",
        _ => return None,
    })
}

/// Render a BACnet error class/code pair, naming both where known and always
/// including the raw numbers, e.g. `write-access-denied (class property[2], code 40)`.
fn describe_bacnet_error(class: u32, code: u32) -> String {
    let class_label = match error_class_name(class) {
        Some(name) => format!("{name}[{class}]"),
        None => format!("{class}"),
    };
    match error_code_name(code) {
        Some(name) => format!("{name} (class {class_label}, code {code})"),
        None => format!("BACnet error (class {class_label}, code {code})"),
    }
}
