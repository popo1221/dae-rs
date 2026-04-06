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
//! - [`trojan_go`] - Trojan-go WebSocket transport extensions
//!
//! # Protocol Flow
//!
//! Client -> dae-rs (Trojan client) -> remote Trojan server -> target

pub mod config;
pub mod consts;
pub mod handler;
pub mod protocol;
pub mod server;
pub mod trojan_go;

// Re-export commonly used types
pub use config::{TrojanClientConfig, TrojanServerConfig, TrojanTlsConfig};
pub use handler::TrojanHandler;
pub use protocol::{TrojanAddressType, TrojanCommand, TrojanTargetAddress};
pub use server::TrojanServer;
pub use trojan_go::{TrojanGoMode, TrojanGoWsConfig, TrojanGoWsHandler, TrojanGoWsStream};
