//! Trojan protocol module
//!
//! Implements Trojan protocol support for dae-rs.
//! Trojan is a VPN protocol that mimics HTTPS traffic.
//!
//! # Module Structure
//!
//! - [`protocol`] - Trojan protocol types and parsing
//! - [`config`] - Configuration types
//! - [`handler`] - TrojanHandler implementation
//! - [`server`] - TrojanServer implementation
//!
//! # Protocol Flow
//!
//! Client -> dae-rs (Trojan client) -> remote Trojan server -> target

pub mod config;
pub mod handler;
pub mod protocol;
pub mod server;

// Re-export commonly used types
pub use config::{TrojanClientConfig, TrojanServerConfig, TrojanTlsConfig};
pub use handler::TrojanHandler;
pub use protocol::{TrojanAddressType, TrojanCommand, TrojanTargetAddress};
pub use server::TrojanServer;
