//! VLESS 协议模块
//!
//! 本模块提供带 XTLS 的 VLESS 协议支持。
//!
//! ## 协议概述
//!
//! VLESS 是一种无状态认证协议，专为跨域通信设计。
//! 支持 XTLS（TLS in TLS）以增强安全性。
//!
//! ## 实现说明
//!
//! 主要的 VLESS 处理器实现在父模块的 `vless.rs` 文件中。
//! 本模块作为命名空间，用于未来 VLESS 特定扩展。

pub mod handler;

// Re-export common types for convenience
pub use crate::vless::{VlessHandler, VlessServer, VlessServerConfig};
