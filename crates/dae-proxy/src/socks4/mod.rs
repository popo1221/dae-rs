//! SOCKS4 protocol handler (RFC 1928 predecessor)
//!
//! Implements SOCKS4 and SOCKS4a proxy server functionality including:
//! - CONNECT command (0x01)
//! - BIND command (0x02)
//! - IPv4 addresses
//! - SOCKS4a extension for domain name resolution
//!
//! # Differences from SOCKS5
//! - SOCKS4 only supports IPv4
//! - SOCKS4a adds domain name resolution support
//! - No authentication support in SOCKS4 (SOCKS4a uses userid for identification)

mod handler;
mod protocol;
mod request;

pub use handler::{Socks4Config, Socks4Server};
pub use protocol::{Socks4Address, Socks4Command, Socks4Reply};
pub use request::Socks4Request;
