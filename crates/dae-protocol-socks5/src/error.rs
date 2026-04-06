//! SOCKS5 错误类型定义模块
//!
//! 定义 SOCKS5 协议处理过程中可能出现的各种错误类型。

use thiserror::Error;

/// SOCKS5 错误类型
///
/// 包含 SOCKS5 协议处理过程中可能发生的各种错误。
#[derive(Error, Debug)]
pub enum Socks5Error {
    /// 认证失败
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// 协议错误，接收到的数据不符合 SOCKS5 协议格式
    #[error("protocol error: {0}")]
    Protocol(String),

    /// IO 错误，如网络连接失败、读写错误等
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// 无效请求，解析的请求数据格式正确但内容无效
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// 没有可接受的认证方法
    #[error("no acceptable auth method")]
    NoAcceptableAuth,

    /// 命令不支持
    #[error("command not supported: {0}")]
    CommandNotSupported(String),

    /// 地址类型不支持
    #[error("address type not supported")]
    AddressTypeNotSupported,

    /// 连接不允许（ACL 拒绝）
    #[error("connection not allowed: {0}")]
    ConnectionNotAllowed(String),
}
