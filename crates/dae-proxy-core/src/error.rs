//! Proxy error types

use thiserror::Error;
use dae_core::Error as CoreError;

/// Proxy-specific error type
#[derive(Error, Debug)]
pub enum ProxyError {
    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// Protocol error
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Timeout error
    #[error("timeout error")]
    Timeout,

    /// Authentication error
    #[error("authentication error")]
    Auth,

    /// From core error
    #[error("core error: {0}")]
    Core(#[from] CoreError),
}

impl From<String> for ProxyError {
    fn from(s: String) -> Self {
        ProxyError::Connection(s)
    }
}

impl From<&str> for ProxyError {
    fn from(s: &str) -> Self {
        ProxyError::Connection(s.to_string())
    }
}
