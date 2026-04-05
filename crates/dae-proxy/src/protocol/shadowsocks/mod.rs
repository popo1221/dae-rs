//! Shadowsocks 协议模块
//!
//! 本模块提供 Shadowsocks 协议支持。
//!
//! ## 协议概述
//!
//! Shadowsocks 是一种加密的 SOCKS5 代理协议，设计用于绕过网络限制。
//! 支持多种 AEAD 加密算法。
//!
//! ## 实现说明
//!
//! 主要的 Shadowsocks 处理器实现在父模块的 `shadowsocks.rs` 文件中。
//! 本模块作为命名空间，用于未来 Shadowsocks 特定扩展。

pub mod handler;

// Re-export common types for convenience
pub use crate::shadowsocks::{ShadowsocksHandler, ShadowsocksServer, SsCipherType};
