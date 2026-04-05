//! HTTP proxy error types

use thiserror::Error;

/// HTTP proxy error types
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
