//! VLESS protocol handler for dae-rs
//!
//! Implements VLESS protocol with XTLS Reality for dae-rs.
//! VLESS is a stateless VPN protocol that uses TLS/XTLS transport.

pub mod config;
pub mod crypto;
pub mod handler;
pub mod protocol;
pub mod server;

// Protocol types
pub use protocol::{
    VlessAddressType, VlessCommand, VlessTargetAddress, VLESS_HEADER_MIN_SIZE,
    VLESS_REQUEST_HEADER_SIZE, VLESS_VERSION,
};

// Configuration
pub use config::{VlessClientConfig, VlessRealityConfig, VlessServerConfig, VlessTlsConfig};

// Handler
pub use handler::VlessHandler;

// Server
pub use server::VlessServer;

// Crypto
pub use crypto::hmac_sha256;

// Relay (from dae-relay)
pub use dae_relay::relay_bidirectional;

use tokio::net::TcpStream;

/// Relay data between client and remote
///
/// This function is a wrapper around `dae_relay::relay_bidirectional`
/// that provides the VLESS-specific interface.
pub async fn relay_data(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    relay_bidirectional(client, remote).await
}
