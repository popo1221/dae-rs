//! dae-protocol-trojan - Trojan protocol implementation for dae-rs
//!
//! This crate provides the Trojan protocol handler for dae-rs.
//! Trojan is a VPN protocol that mimics HTTPS traffic.
//!
//! # Protocol
//!
//! Trojan is a proxy protocol that encapsulates traffic in TLS.
//! The protocol is designed to be indistinguishable from HTTPS traffic.
//!
//! # Security
//!
//! - Uses constant-time password comparison to prevent timing attacks
//! - Supports TLS 1.3 with perfect forward secrecy

pub mod config;
pub mod handler;
pub mod protocol;
pub mod server;

pub use config::{TrojanClientConfig, TrojanServerConfig, TrojanTlsConfig};
pub use handler::TrojanHandler;
pub use protocol::{TrojanAddressType, TrojanCommand, TrojanTargetAddress, TROJAN_CRLF};
pub use server::TrojanServer;
