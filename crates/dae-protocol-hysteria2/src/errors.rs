//! Hysteria2 错误类型模块
//!
//! 定义了 Hysteria2 协议处理过程中可能发生的各种错误。

use thiserror::Error;

/// Hysteria2 错误类型
///
/// 定义了 Hysteria2 协议处理过程中可能发生的各种错误。
///
/// # 错误类型说明
///
/// - `AuthFailed`: 认证失败（密码错误）
/// - `Protocol`: 协议错误（格式错误、版本不支持等）
/// - `Quic`: QUIC 相关错误
/// - `Io`: IO 错误
/// - `InvalidAddress`: 无效的地址格式
#[derive(Debug, Error)]
pub enum Hysteria2Error {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}
