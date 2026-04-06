//! VLESS 错误类型模块
//!
//! 定义了 VLESS 协议处理过程中可能发生的各种错误。

use thiserror::Error;

/// VLESS 错误类型
///
/// 定义了 VLESS 协议处理过程中可能发生的各种错误。
#[derive(Debug, Error)]
pub enum VlessError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<VlessError> for std::io::Error {
    fn from(err: VlessError) -> std::io::Error {
        match err {
            VlessError::Io(e) => e,
        }
    }
}
