//! VMess 错误类型模块
//!
//! 定义了 VMess 协议处理过程中可能发生的各种错误。

use thiserror::Error;

/// VMess 错误类型
///
/// 定义了 VMess 协议处理过程中可能发生的各种错误。
#[derive(Debug, Error)]
pub enum VmessError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<VmessError> for std::io::Error {
    fn from(err: VmessError) -> std::io::Error {
        match err {
            VmessError::Io(e) => e,
        }
    }
}
