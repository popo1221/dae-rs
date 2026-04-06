//! VLESS protocol module
//!
//! Implements VLESS protocol with XTLS Reality for dae-rs.
//! VLESS is a stateless VPN protocol that uses TLS/XTLS transport.
//!
//! Protocol spec: https://xtls.github.io/
//! Reality spec: https://github.com/XTLS/Xray-core/discussions/716
//!
//! # Module Structure
//!
//! - [`protocol`] - VLESS protocol types and constants
//! - [`config`] - Configuration types
//! - [`handler`] - VLessHandler implementation
//! - [`server`] - VLessServer implementation
//! - [`crypto`] - Cryptographic utilities
//! - [`relay`] - Data relay utilities
//!
//! # VLESS Reality Vision
//!
//! VLESS Reality Vision is a TLS obfuscation protocol that:
//! - Uses X25519 key exchange for perfect forward secrecy
//! - Masks traffic as normal HTTPS to bypass DPI
//! - Works with any TLS-terminated server (nginx, caddy, etc.)
//!
//! # Protocol Flow (Reality Vision)
//!
//! Client -> [X25519 KeyGen] -> [Build Request] -> [TLS ClientHello with Chrome]
//! -> Server -> [Verify and respond] -> [Establish tunnel]

pub mod config;
pub mod crypto;
pub mod handler;
pub mod protocol;
pub mod relay;
pub mod server;
pub mod tls;

// Re-export commonly used types
pub use config::{VlessClientConfig, VlessRealityConfig, VlessServerConfig, VlessTlsConfig};
pub use crypto::hmac_sha256;
pub use handler::VlessHandler;
pub use protocol::{
    VlessAddressType, VlessCommand, VlessTargetAddress, VLESS_HEADER_MIN_SIZE,
    VLESS_REQUEST_HEADER_SIZE, VLESS_VERSION,
};
pub use relay::relay_data;
pub use server::VlessServer;
