//! SOCKS5 协议模块
//!
//! 本模块提供 SOCKS5 协议支持，遵循 RFC 1928 标准。
//!
//! ## 协议概述
//!
//! SOCKS5 是一种在 OSI 模型会话层工作的代理协议。
//! 提供认证功能，支持 TCP 和 UDP 流量。
//!
//! ## 实现说明
//!
//! 主要的 SOCKS5 处理器实现在父模块的 `socks5.rs` 文件中。
//! 本模块作为命名空间，用于未来 SOCKS5 特定扩展。

pub mod handler;

// Re-export common types for convenience
pub use dae_protocol_socks5::{Socks5Handler, Socks5Server};
