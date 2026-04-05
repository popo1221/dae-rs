//! Shadowsocks protocol module
//!
//! This module provides Shadowsocks protocol support.
//!
//! ## Protocol Overview
//!
//! Shadowsocks is an encrypted socks5 proxy protocol designed to bypass
//! network restrictions. It supports various AEAD ciphers.
//!
//! ## Implementation
//!
//! The main Shadowsocks handler implementation is in the parent module's `shadowsocks.rs` file.
//! This module serves as a namespace and for future Shadowsocks-specific extensions.

pub mod handler;

// Re-export common types for convenience
pub use crate::shadowsocks::{ShadowsocksHandler, ShadowsocksServer, SsCipherType};
