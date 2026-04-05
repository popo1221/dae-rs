//! SOCKS5 error types

use thiserror::Error;

/// SOCKS5 error types
#[derive(Error, Debug)]
pub enum Socks5Error {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("no acceptable auth method")]
    NoAcceptableAuth,

    #[error("command not supported: {0}")]
    CommandNotSupported(String),

    #[error("address type not supported")]
    AddressTypeNotSupported,

    #[error("connection not allowed: {0}")]
    ConnectionNotAllowed(String),
}
