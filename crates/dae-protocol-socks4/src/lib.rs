//! dae-protocol-socks4 - SOCKS4 and SOCKS4a protocol implementation for dae-rs
//!
//! This crate provides the SOCKS4 and SOCKS4a protocol handlers for dae-rs.
//!
//! # Supported Features
//!
//! - CONNECT command (0x01)
//! - BIND command (0x02)
//! - IPv4 addresses
//! - SOCKS4a extension for domain name resolution
//!
//! # Differences from SOCKS5
//!
//! - SOCKS4 only supports IPv4
//! - SOCKS4a adds domain name resolution support
//! - No authentication support in SOCKS4 (SOCKS4a uses userid for identification)

pub mod handler;

pub use handler::{
    Socks4Command, Socks4Config, Socks4Handler, Socks4Reply, Socks4Request, Socks4Server,
    Socks4Address,
};
