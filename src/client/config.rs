//! Configuration and builder for the high-level BACnet client.
//!
//! [`ClientConfig`] holds the parameters used to construct a
//! [`BacnetClient`](super::BacnetClient): the local interface/port to bind, the
//! per-request timeout, and how many times to retry. Use
//! [`BacnetClient::builder`](super::BacnetClient::builder) to construct a client
//! fluently:
//!
//! ```rust,no_run
//! use bacnet_rs::client::BacnetClient;
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = BacnetClient::builder()
//!     .local_addr("0.0.0.0")
//!     .port(0)
//!     .timeout(Duration::from_secs(3))
//!     .retries(2)
//!     .build()?;
//! # let _ = client;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use super::{BacnetClient, ClientError};

/// Default per-request timeout used when none is configured.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default host to bind to (all interfaces, OS-assigned ephemeral port).
pub const DEFAULT_HOST: &str = "0.0.0.0";

/// Configuration parameters for a [`BacnetClient`](super::BacnetClient).
///
/// Construct one via [`BacnetClient::builder`](super::BacnetClient::builder)
/// rather than directly; the builder applies sensible defaults.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Local host/interface to bind the UDP socket to.
    pub host: String,
    /// Local UDP port to bind. `0` lets the OS assign an ephemeral port.
    pub port: u16,
    /// How long to wait for a response before giving up.
    pub timeout: Duration,
    /// Number of times to retry a request after the first attempt times out.
    pub retries: u8,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: 0,
            timeout: DEFAULT_TIMEOUT,
            retries: 0,
        }
    }
}

impl ClientConfig {
    /// The address string (`host:port`) the socket will bind to.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Fluent builder for a [`BacnetClient`](super::BacnetClient).
///
/// Obtain one from [`BacnetClient::builder`](super::BacnetClient::builder).
#[derive(Debug, Clone, Default)]
pub struct ClientBuilder {
    config: ClientConfig,
}

impl ClientBuilder {
    /// Create a builder with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the local host/interface to bind to (default `"0.0.0.0"`).
    pub fn local_addr(mut self, host: impl Into<String>) -> Self {
        self.config.host = host.into();
        self
    }

    /// Set the local UDP port to bind (default `0`, an OS-assigned port).
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Set the per-request timeout (default 5 seconds).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set the number of retries after an initial timeout (default `0`).
    pub fn retries(mut self, retries: u8) -> Self {
        self.config.retries = retries;
        self
    }

    /// Consume the builder and bind the client's socket.
    pub fn build(self) -> Result<BacnetClient, ClientError> {
        BacnetClient::from_config(self.config)
    }
}
