//! Unified error types for dae-proxy
//!
//! This module provides centralized error types used across all dae-proxy modules.

use thiserror::Error;

/// Proxy error types for connection, authentication, protocol, and dispatch errors
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("connect failed: {0}")]
    Connect(#[from] std::io::Error),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("dispatch error: {0}")]
    Dispatch(String),

    #[error("configuration error: {0}")]
    Config(String),
}

/// Node error types for node-related errors
#[derive(Error, Debug, Clone)]
pub enum NodeError {
    #[error("timeout")]
    Timeout,

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("node not found: {0}")]
    NotFound(String),

    #[error("node unavailable: {0}")]
    Unavailable(String),
}

impl NodeError {
    /// Check if this error indicates a temporary failure that can be retried
    pub fn is_retryable(&self) -> bool {
        matches!(self, NodeError::Timeout)
    }
}

/// Backward-compatible alias for ProxyError
/// All existing code using `Error` will continue to work
pub type Error = ProxyError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_error_connect() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let err: ProxyError = ProxyError::Connect(io_err);
        assert!(format!("{}", err).contains("connect failed"));
    }

    #[test]
    fn test_proxy_error_auth() {
        let err = ProxyError::Auth("invalid token".to_string());
        assert!(format!("{}", err).contains("authentication failed"));
    }

    #[test]
    fn test_proxy_error_protocol() {
        let err = ProxyError::Protocol("invalid header".to_string());
        assert!(format!("{}", err).contains("protocol error"));
    }

    #[test]
    fn test_proxy_error_dispatch() {
        let err = ProxyError::Dispatch("no handler".to_string());
        assert!(format!("{}", err).contains("dispatch error"));
    }

    #[test]
    fn test_node_error_timeout_is_retryable() {
        let err = NodeError::Timeout;
        assert!(err.is_retryable());
    }

    #[test]
    fn test_node_error_connection_failed_not_retryable() {
        let err = NodeError::ConnectionFailed("connection refused".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_node_error_not_found() {
        let err = NodeError::NotFound("node-1".to_string());
        assert!(format!("{}", err).contains("node not found"));
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_node_error_unavailable() {
        let err = NodeError::Unavailable("node-1".to_string());
        assert!(format!("{}", err).contains("node unavailable"));
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_type_alias() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let err: Error = ProxyError::Connect(io_err);
        // Error should be the same as ProxyError
        assert!(format!("{}", err).contains("connect failed"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err: Error = io_err.into();
        match err {
            ProxyError::Connect(_) => {}
            _ => unreachable!("io::Error should convert to ProxyError::Connect"),
        }
    }

    #[test]
    fn test_error_debug() {
        let err = ProxyError::Protocol("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Protocol"));
    }

    #[test]
    fn test_node_error_debug() {
        let err = NodeError::NotFound("test-node".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("NotFound"));
    }

    #[test]
    fn test_node_error_display_timeout() {
        let err = NodeError::Timeout;
        assert_eq!(format!("{}", err), "timeout");
    }

    #[test]
    fn test_node_error_display_connection_failed() {
        let err = NodeError::ConnectionFailed("refused".to_string());
        assert!(format!("{}", err).contains("refused"));
    }

    #[test]
    fn test_node_error_display_unavailable() {
        let err = NodeError::Unavailable("node-1".to_string());
        assert!(format!("{}", err).contains("node unavailable"));
    }
}
