//! Core infrastructure module for dae-proxy
//!
//! This module provides foundational types used across the entire proxy system:
//! - Unified error types
//! - Request context
//! - Result type aliases

pub mod context;
pub mod error;
pub mod result;

pub use context::Context;
pub use error::Error;
pub use result::Result;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    #[test]
    fn test_error_display() {
        let err = Error::Connect(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "test error",
        ));
        assert!(err.to_string().contains("connect failed"));

        let err = Error::Protocol("invalid header".to_string());
        assert!(err.to_string().contains("protocol error"));

        let err = Error::Auth("unauthorized".to_string());
        assert!(err.to_string().contains("authentication failed"));
    }

    #[test]
    fn test_context_in_core_module() {
        let source = SocketAddr::from((IpAddr::from_str("127.0.0.1").unwrap(), 8080));
        let dest = SocketAddr::from((IpAddr::from_str("192.168.1.1").unwrap(), 80));

        let ctx = Context::new(source, dest);
        assert_eq!(ctx.source, source);
        assert_eq!(ctx.destination, dest);
    }

    #[test]
    fn test_result_type() {
        let ok: Result<i32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: Result<i32> = Err(Error::Protocol("test".to_string()));
        assert!(err.is_err());
    }
}
