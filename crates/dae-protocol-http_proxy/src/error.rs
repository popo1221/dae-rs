//! HTTP 代理错误类型模块
//!
//! 定义了 HTTP 代理协议处理过程中可能发生的各种错误。

use thiserror::Error;

/// HTTP 代理错误类型
///
/// 包含认证失败、协议错误、IO 错误等多种错误变体。
/// 使用 thiserror 实现，支持 `?` 操作符自动转换。
///
/// # 变体说明
///
/// - `AuthFailed(String)`: 认证失败，参数为失败原因
/// - `Protocol(String)`: 协议错误，参数为错误描述
/// - `Io(std::io::Error)`: IO 错误，从 std::io::Error 自动转换
/// - `InvalidRequest(String)`: 无效请求，参数为请求详情
/// - `HostUnreachable(String)`: 主机不可达，参数为目标地址
/// - `Timeout(String)`: 超时错误，参数为超时上下文
#[derive(Error, Debug)]
pub enum HttpProxyError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("host unreachable: {0}")]
    HostUnreachable(String),

    #[error("timeout: {0}")]
    Timeout(String),
}
