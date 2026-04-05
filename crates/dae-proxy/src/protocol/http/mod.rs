//! HTTP 代理协议模块
//!
//! 本模块提供使用 CONNECT 方法的 HTTP 代理协议支持。
//!
//! ## 协议概述
//!
//! HTTP 代理使用 CONNECT 方法为加密流量建立隧道。
//! 常用于通过代理转发 HTTPS 流量。
//!
//! ## 实现说明
//!
//! 主要的 HTTP 代理处理器实现在父模块的 `http_proxy.rs` 文件中。
//! 本模块作为命名空间，用于未来 HTTP 特定扩展。

pub mod handler;

// Re-export common types for convenience
pub use crate::http_proxy::{HttpProxyHandler, HttpProxyServer};
