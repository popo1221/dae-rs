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
