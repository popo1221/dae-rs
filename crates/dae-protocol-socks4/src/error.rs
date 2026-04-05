//! SOCKS4 error types

use thiserror::Error;

/// SOCKS4 error types
#[derive(Error, Debug)]
pub enum Socks4Error {
    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("IPv4 only: {0}")]
    Ipv4Only(String),
}
