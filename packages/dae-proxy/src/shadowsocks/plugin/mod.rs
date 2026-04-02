//! Shadowsocks plugin modules
//!
//! This module provides obfuscation plugins for Shadowsocks traffic.
//!
//! # Available Plugins
//!
//! - [`obfs`] - simple-obfs plugin (HTTP and TLS obfuscation)
//! - [`v2ray`] - v2ray-plugin for WebSocket-based obfuscation

pub mod obfs;
pub mod v2ray;

pub use obfs::{ObfsConfig, ObfsHttp, ObfsMode, ObfsTls, ObfsStream};
pub use v2ray::{V2rayConfig, V2rayMode, V2rayPlugin, V2rayStream};
