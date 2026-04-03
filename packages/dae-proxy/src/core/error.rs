//! Unified error types for dae-proxy
//!
//! This module provides a centralized error enum used across all dae-proxy modules.

use thiserror::Error;

/// Unified error type for dae-proxy
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol parsing or validation error
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// eBPF subsystem error
    #[error("ebpf error: {0}")]
    Ebpf(String),

    /// Node configuration or selection error
    #[error("node error: {0}")]
    Node(String),

    /// Transport/network error
    #[error("transport error: {0}")]
    Transport(String),

    /// Rule matching or execution error
    #[error("rule error: {0}")]
    Rule(String),

    /// Operation timed out
    #[error("timeout")]
    Timeout,

    /// Connection refused
    #[error("connection refused")]
    ConnectionRefused,

    /// Permission denied
    #[error("permission denied")]
    PermissionDenied,
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Config(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Config(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "test"));
        assert!(format!("{}", err).contains("io error"));

        let err = Error::Protocol("test".to_string());
        assert!(format!("{}", err).contains("protocol error"));

        let err = Error::Config("test".to_string());
        assert!(format!("{}", err).contains("configuration error"));

        let err = Error::Ebpf("test".to_string());
        assert!(format!("{}", err).contains("ebpf error"));

        let err = Error::Node("test".to_string());
        assert!(format!("{}", err).contains("node error"));

        let err = Error::Transport("test".to_string());
        assert!(format!("{}", err).contains("transport error"));

        let err = Error::Rule("test".to_string());
        assert!(format!("{}", err).contains("rule error"));
    }

    #[test]
    fn test_error_timeout() {
        let err = Error::Timeout;
        let display = format!("{}", err);
        assert!(display.contains("timeout"));
    }

    #[test]
    fn test_error_connection_refused() {
        let err = Error::ConnectionRefused;
        let display = format!("{}", err);
        assert!(display.contains("connection refused"));
    }

    #[test]
    fn test_error_permission_denied() {
        let err = Error::PermissionDenied;
        let display = format!("{}", err);
        assert!(display.contains("permission denied"));
    }

    #[test]
    fn test_error_debug() {
        let err = Error::Protocol("test error".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Protocol"));
    }

    #[test]
    fn test_error_from_str() {
        let err: Error = "config error string".into();
        match err {
            Error::Config(s) => assert_eq!(s, "config error string"),
            _ => panic!("Expected Config variant"),
        }
    }

    #[test]
    fn test_error_from_string() {
        let err: Error = String::from("string error").into();
        match err {
            Error::Config(s) => assert_eq!(s, "string error"),
            _ => panic!("Expected Config variant"),
        }
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "io error");
        let err: Error = io_err.into();
        match err {
            Error::Io(_) => {}
            _ => panic!("Expected Io variant"),
        }
    }
}
