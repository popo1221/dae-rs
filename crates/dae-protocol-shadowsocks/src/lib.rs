//! dae-protocol-shadowsocks - Shadowsocks AEAD protocol implementation
//!
//! This crate provides the Shadowsocks AEAD protocol handler for dae-rs.
//!
//! # Supported Ciphers
//!
//! - chacha20-ietf-poly1305
//! - aes-256-gcm
//! - aes-128-gcm
//!
//! # ⚠️ Limitations
//!
//! **Stream ciphers (rc4-md5, aes-ctr, etc.) are not supported.**
//! Only AEAD ciphers are implemented.

pub mod handler;

pub use handler::{
    ShadowsocksConfig, ShadowsocksHandler, ShadowsocksServer, SsCipherType, SsClientConfig,
    SsServerConfig, TargetAddress,
};
