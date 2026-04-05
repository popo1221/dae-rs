//! Hysteria2 协议实现 crate
//!
//! Hysteria2 是一个基于 QUIC 的高性能、低延迟代理协议。
//! 主要特点包括：
//!
//! - 基于 QUIC 的传输层，获得更好的性能
//! - 支持混淆（obfuscation）以绕过 DPI 检测
//! - 带宽拥塞控制
//! - 简单的密码认证机制
//!
//! **注意**: QUIC 传输层（`quic` feature）尚未实现。
//! 当前核心协议通过 TCP 工作。QUIC 支持将在未来版本中添加。
//!
//! # 主要导出
//!
//! - `Hysteria2Config`: 服务器配置
//! - `Hysteria2Error`: 错误类型
//! - `Hysteria2Handler`: 协议处理器
//! - `Hysteria2Server`: 服务器实现

mod hysteria2;
#[cfg(feature = "quic")]
mod quic;

pub use hysteria2::{Hysteria2Config, Hysteria2Error, Hysteria2Handler, Hysteria2Server};

// QUIC module exports removed - not yet implemented
// TODO: Implement QUIC transport using quinn when ready
// The following were removed because they returned NotImplemented:
// pub use quic::{CongestionControl, QuicCodec, QuicConfig, QuicConnection, QuicEndpoint, QuicError, QuicStream, QuicUdpSocket};
