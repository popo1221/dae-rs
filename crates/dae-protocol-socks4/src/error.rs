//! SOCKS4 错误类型定义模块
//!
//! 定义 SOCKS4 协议处理过程中可能出现的各种错误类型。

use thiserror::Error;

/// SOCKS4 错误类型
///
/// 包含 SOCKS4 协议处理过程中可能发生的各种错误。
#[derive(Error, Debug)]
pub enum Socks4Error {
    /// 协议错误，通常是收到的数据不符合 SOCKS4 协议格式
    #[error("protocol error: {0}")]
    Protocol(String),

    /// IO 错误，如网络连接失败、读写错误等
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// 无效请求，解析的请求数据格式正确但内容无效
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// 连接失败，无法建立到目标服务器的连接
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// IPv4 限制错误，SOCKS4 仅支持 IPv4 地址
    #[error("IPv4 only: {0}")]
    Ipv4Only(String),
}
