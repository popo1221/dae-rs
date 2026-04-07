//! Hysteria2 协议实现 crate
//!
//! Hysteria2 是一个高性能、低延迟代理协议。
//! 主要特点包括：
//!
//! - 支持混淆（obfuscation）以绕过 DPI 检测
//! - 带宽拥塞控制
//! - 简单的密码认证机制
//!
//! # 实现说明
//!
//! 当前实现基于 TCP 传输层。
//!
//! # 主要导出
//!
//! - `Hysteria2Config`: 服务器配置
//! - `Hysteria2Error`: 错误类型
//! - `Hysteria2Handler`: 协议处理器
//! - `Hysteria2Server`: 服务器实现

mod errors;
mod hysteria2;

pub use errors::Hysteria2Error;
pub use hysteria2::{Hysteria2Config, Hysteria2Handler, Hysteria2Server};
