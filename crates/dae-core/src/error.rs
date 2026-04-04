//! Unified error types for dae-rs

use thiserror::Error;
use std::io;
use std::time::Duration;

/// Error codes for programmatic error handling
///
/// These codes provide a machine-readable way to identify error types
/// without needing to pattern match on the error variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// I/O error
    Io,
    /// Protocol error
    Protocol,
    /// Timeout error
    Timeout,
    /// Invalid configuration
    Config,
    /// DNS resolution error
    Dns,
    /// Authentication error
    Auth,
    /// Connection error
    Connection,
    /// TLS error
    Tls,
    /// eBPF error
    Ebpf,
    /// Node error
    Node,
    /// Rule error
    Rule,
    /// Unknown/internal error
    Unknown,
    /// Transport error
    Transport,
    /// Nat error
    Nat,
}

/// Unified error type for dae-rs
///
/// This error type is used across all crates for consistent error handling.
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error
    #[error("io error: {0}")]
    Io(std::io::Error),

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

    /// Transport error
    #[error("transport error: {0}")]
    Transport(String),

    /// NAT error
    #[error("nat error: {0}")]
    Nat(String),

    /// Unknown/internal error
    #[error("unknown error: {0}")]
    Unknown(String),
}

impl Error {
    /// Get the error code for programmatic error handling
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Io(_) => ErrorCode::Io,
            Error::Protocol(_) => ErrorCode::Protocol,
            Error::Timeout => ErrorCode::Timeout,
            Error::Config(_) => ErrorCode::Config,
            Error::Dns(_) => ErrorCode::Dns,
            Error::Auth => ErrorCode::Auth,
            Error::Connection(_) => ErrorCode::Connection,
            Error::Tls(_) => ErrorCode::Tls,
            Error::Ebpf(_) => ErrorCode::Ebpf,
            Error::Node(_) => ErrorCode::Node,
            Error::Rule(_) => ErrorCode::Rule,
            Error::Transport(_) => ErrorCode::Transport,
            Error::Nat(_) => ErrorCode::Nat,
            Error::Unknown(_) => ErrorCode::Unknown,
        }
    }

    /// Check if this is a timeout error
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout)
    }

    /// Check if this is an authentication error
    pub fn is_auth(&self) -> bool {
        matches!(self, Error::Auth)
    }

    /// Check if this is a connection error
    pub fn is_connection(&self) -> bool {
        matches!(self, Error::Connection(_))
    }

    /// Check if this is an I/O error
    pub fn is_io(&self) -> bool {
        matches!(self, Error::Io(_))
    }

    /// Check if this is a protocol error
    pub fn is_protocol(&self) -> bool {
        matches!(self, Error::Protocol(_))
    }

    /// Get the error message if this is a string error
    pub fn message(&self) -> Option<&str> {
        match self {
            Error::Protocol(s) => Some(s),
            Error::Config(s) => Some(s),
            Error::Dns(s) => Some(s),
            Error::Connection(s) => Some(s),
            Error::Tls(s) => Some(s),
            Error::Ebpf(s) => Some(s),
            Error::Node(s) => Some(s),
            Error::Rule(s) => Some(s),
            Error::Transport(s) => Some(s),
            Error::Nat(s) => Some(s),
            Error::Unknown(s) => Some(s),
            _ => None,
        }
    }
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

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::TimedOut => Error::Timeout,
            io::ErrorKind::PermissionDenied => Error::Auth,
            io::ErrorKind::ConnectionRefused => Error::Connection("connection refused".to_string()),
            io::ErrorKind::ConnectionReset => Error::Connection("connection reset".to_string()),
            io::ErrorKind::ConnectionAborted => Error::Connection("connection aborted".to_string()),
            io::ErrorKind::NotConnected => Error::Connection("not connected".to_string()),
            io::ErrorKind::AddrNotAvailable => Error::Connection("address not available".to_string()),
            _ => Error::Io(err),
        }
    }
}

impl From<Duration> for Error {
    fn from(_: Duration) -> Self {
        Error::Timeout
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Error::Timeout
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(io_err) => io_err,
            Error::Timeout => std::io::Error::new(io::ErrorKind::TimedOut, "timeout"),
            Error::Auth => std::io::Error::new(io::ErrorKind::PermissionDenied, "authentication error"),
            Error::Connection(s) => std::io::Error::new(io::ErrorKind::Other, s),
            _ => std::io::Error::new(io::ErrorKind::Other, err.to_string()),
        }
    }
}
