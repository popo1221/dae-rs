//! dae-core - Shared core types for dae-rs
//!
//! This crate provides foundational types used across all dae-rs crates.
//!
//! # Contents
//!
//! - Context: Request context with source/destination info
//! - Error: Unified error type
//! - Result: Result type alias

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
        let err = Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "test error",
        ));
        assert!(err.to_string().contains("io error"));

        let err = Error::Protocol("invalid header".to_string());
        assert!(err.to_string().contains("protocol error"));
    }

    #[test]
    fn test_context() {
        let source = SocketAddr::from((IpAddr::from_str("127.0.0.1").unwrap(), 8080));
        let dest = SocketAddr::from((IpAddr::from_str("192.168.1.1").unwrap(), 80));

        let ctx = Context::new(source, dest);
        assert_eq!(ctx.source, source);
        assert_eq!(ctx.destination, dest);
    }
}
