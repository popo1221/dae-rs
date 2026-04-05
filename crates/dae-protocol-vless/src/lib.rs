//! VLESS protocol handler for dae-rs
//!
//! Implements VLESS protocol with XTLS Reality for dae-rs.
//! VLESS is a stateless VPN protocol that uses TLS/XTLS transport.

pub mod config;
pub mod crypto;
pub mod handler;
pub mod protocol;
pub mod relay;
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

// Relay
pub use relay::relay_data;
