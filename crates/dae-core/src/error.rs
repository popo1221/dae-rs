//! Unified error types for dae-rs

use thiserror::Error;

/// Unified error type for dae-rs
///
/// This error type is used across all crates for consistent error handling.
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol error
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Timeout error
    #[error("timeout error")]
    Timeout,

    /// Invalid configuration
    #[error("invalid configuration: {0}")]
    Config(String),

    /// DNS resolution error
    #[error("dns error: {0}")]
    Dns(String),

    /// Authentication error
    #[error("authentication error")]
    Auth,

    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// TLS error
    #[error("tls error: {0}")]
    Tls(String),

    /// eBPF error
    #[error("ebpf error: {0}")]
    Ebpf(String),

    /// Node error
    #[error("node error: {0}")]
    Node(String),

    /// Rule error
    #[error("rule error: {0}")]
    Rule(String),

    /// Unknown/internal error
    #[error("unknown error: {0}")]
    Unknown(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Unknown(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Unknown(s.to_string())
    }
}
