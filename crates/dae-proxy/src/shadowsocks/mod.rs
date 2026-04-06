//! Shadowsocks AEAD protocol handler with plugin support
//!
//! Implements Shadowsocks AEAD protocol support.
//! Supports AEAD ciphers: chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm
//! Implements OTA (One-Time Auth) compatibility mode.
//!
//! # ⚠️ Limitations
//!
//! **Stream ciphers (rc4-md5, aes-ctr, etc.) are not supported.**
//! Only AEAD ciphers are implemented. See GitHub Issue #78 for details.
//!
//! Supports obfuscation plugins:
//! - simple-obfs (HTTP and TLS obfuscation)
//! - v2ray-plugin (WebSocket-based obfuscation)
//!
//! Protocol flow:
//! Client -> [obfs/plugin] -> [Shadowsocks AEAD] -> Server

// Re-export all public types from submodules
pub use config::{SsClientConfig, SsServerConfig};
pub use handler::ShadowsocksHandler;
pub use protocol::{SsCipherType, TargetAddress};
pub use server::ShadowsocksServer;

// Submodules
pub mod aead;
pub mod config;
pub mod handler;
pub mod plugin;
pub mod protocol;
pub mod relay;
pub mod server;
pub mod ssr;
pub mod ssr_types;
