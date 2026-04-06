//! Trojan 错误类型模块
//!
//! 定义了 Trojan 协议处理过程中可能发生的各种错误。

use thiserror::Error;

/// Trojan 错误类型
///
/// 定义了 Trojan 协议处理过程中可能发生的各种错误。
#[derive(Debug, Error)]
pub enum TrojanError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<TrojanError> for std::io::Error {
    fn from(err: TrojanError) -> std::io::Error {
        match err {
            TrojanError::Io(e) => e,
        }
    }
}
