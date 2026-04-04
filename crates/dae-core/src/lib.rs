//! dae-core - Shared core types for dae-rs
//!
//! This crate provides foundational types used across all dae-rs crates.
//!
//! # Contents
//!
//! - Context: Request context with source/destination info
//! - Error: Unified error type with error codes
//! - Result: Result type alias
//! - Types: Shared type aliases (IpAddr, SocketAddr, Duration, Buffer)

pub mod context;
pub mod error;
pub mod result;
pub mod types;

pub use context::Context;
pub use error::{Error, ErrorCode};
pub use result::Result;
pub use types::{Buffer, Duration, IpAddr, SocketAddr};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::collections::HashMap;

    #[test]
    fn test_error_display() {
        let err = Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "test error",
        ));
        assert!(err.to_string().contains("io error"));

        let err = Error::Protocol("invalid header".to_string());
        assert!(err.to_string().contains("protocol error"));
    }

    #[test]
    fn test_error_code() {
        let err = Error::Timeout;
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(err.is_timeout());

        let err = Error::Auth;
        assert_eq!(err.code(), ErrorCode::Auth);
        assert!(err.is_auth());

        let err = Error::Connection("test".to_string());
        assert_eq!(err.code(), ErrorCode::Connection);
        assert!(err.is_connection());
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let err: Error = io_err.into();
        assert!(err.is_timeout());

        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: Error = io_err.into();
        assert!(err.is_auth());
    }

    #[test]
    fn test_error_from_duration() {
        use std::time::Duration;
        
        let err: Error = Error::from(Duration::from_secs(5));
        assert!(err.is_timeout());
    }

    #[test]
    fn test_context() {
        let source = SocketAddr::from((IpAddr::from_str("127.0.0.1").unwrap(), 8080));
        let dest = SocketAddr::from((IpAddr::from_str("192.168.1.1").unwrap(), 80));

        let ctx = Context::new(source, dest);
        assert_eq!(ctx.source, source);
        assert_eq!(ctx.destination, dest);
        assert!(ctx.metadata.is_empty());
    }

    #[test]
    fn test_context_with_metadata() {
        let source: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dest: SocketAddr = "192.168.1.1:80".parse().unwrap();
        
        let mut metadata = HashMap::new();
        metadata.insert("host".to_string(), "example.com".to_string());
        metadata.insert("protocol".to_string(), "http".to_string());

        let ctx = Context::with_metadata(source, dest, metadata);
        assert_eq!(ctx.source, source);
        assert_eq!(ctx.destination, dest);
        assert_eq!(ctx.get_metadata("host"), Some(&"example.com".to_string()));
        assert_eq!(ctx.get_metadata("protocol"), Some(&"http".to_string()));
        assert_eq!(ctx.get_metadata("nonexistent"), None);
    }

    #[test]
    fn test_context_insert_metadata() {
        let ctx = Context::default();
        let mut ctx = ctx;
        
        ctx.insert_metadata("key1".to_string(), "value1".to_string());
        assert_eq!(ctx.get_metadata("key1"), Some(&"value1".to_string()));
        
        // Test overwrite
        let old = ctx.insert_metadata("key1".to_string(), "value2".to_string());
        assert_eq!(old, Some("value1".to_string()));
        assert_eq!(ctx.get_metadata("key1"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_type_aliases() {
        // Test that type aliases work correctly
        let _addr: IpAddr = "127.0.0.1".parse().unwrap();
        let _sock: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let _dur: Duration = Duration::from_secs(1);
        let _buf: Buffer = bytes::Bytes::from_static(b"hello");
        
        // Verify they are what we expect
        let addr: IpAddr = "::1".parse().unwrap();
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        
        fn returns_error() -> Result<i32> {
            Err(Error::Protocol("test error".to_string()))
        }
        
        assert_eq!(returns_result().unwrap(), 42);
        assert!(returns_error().is_err());
    }
}
