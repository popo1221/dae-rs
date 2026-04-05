//! Shadowsocks 插件模块
//!
//! 本模块提供 Shadowsocks 流量的混淆插件：
//!
//! # 可用插件
//!
//! - [`obfs`] - simple-obfs 插件（HTTP 和 TLS 混淆）
//! - [`v2ray`] - v2ray-plugin 用于 WebSocket 混淆传输

pub mod obfs;
pub mod v2ray;

pub use obfs::{ObfsConfig, ObfsHttp, ObfsMode, ObfsStream, ObfsTls};
pub use v2ray::{V2rayConfig, V2rayMode, V2rayPlugin, V2rayStream};
