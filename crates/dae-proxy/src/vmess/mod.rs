//! VMess protocol handler (V2Ray)
//!
//! Implements VMess AEAD protocol support for dae-rs.
//! VMess is a stateless VPN protocol used by V2Ray.
//! This implementation supports VMess-AEAD-2022.
//!
//! Protocol reference: V2RayAEAD implementation
//!
//! Protocol flow:
//! Client -> dae-rs (VMess server) -> upstream VMess server -> target

pub mod config;
pub mod handler;
pub mod protocol;
pub mod server;

// Re-export public types
pub use config::{VmessClientConfig, VmessTargetAddress};
pub use handler::VmessHandler;
pub use protocol::{VmessAddressType, VmessCommand, VmessSecurity, VmessServerConfig};
pub use server::VmessServer;

// Protocol constants
pub use protocol::{VMESS_AEAD_VERSION, VMESS_VERSION};

#[cfg(test)]
mod tests;
