//! dae-protocol-trojan crate
//!
//! Trojan protocol handler extracted from dae-proxy.

pub mod config;
pub mod handler;
pub mod protocol;
pub mod server;
pub mod trojan_go;
pub mod types;

// Re-export types
pub use config::{TrojanClientConfig, TrojanServerConfig, TrojanTlsConfig};
pub use handler::TrojanHandler;
pub use protocol::{TrojanAddressType, TrojanCommand, TrojanTargetAddress};
pub use server::TrojanServer;
pub use trojan_go::{TrojanGoMode, TrojanGoWsConfig, TrojanGoWsHandler, TrojanGoWsStream};
