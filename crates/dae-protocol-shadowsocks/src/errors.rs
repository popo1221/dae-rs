//! Shadowsocks 错误类型模块
//!
//! 定义了 Shadowsocks 协议处理过程中可能发生的各种错误。

use thiserror::Error;

/// Shadowsocks 错误类型
///
/// 定义了 Shadowsocks 协议处理过程中可能发生的各种错误。
#[derive(Debug, Error)]
pub enum ShadowsocksError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<ShadowsocksError> for std::io::Error {
    fn from(err: ShadowsocksError) -> std::io::Error {
        match err {
            ShadowsocksError::Io(e) => e,
        }
    }
}
