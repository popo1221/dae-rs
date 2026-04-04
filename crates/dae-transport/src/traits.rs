//! Transport layer traits
//!
//! Core trait for all transport implementations.

use async_trait::async_trait;
use std::fmt::Debug;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Maximum UDP packet size
pub const MAX_UDP_PACKET_SIZE: usize = 65535;

/// Transport error type
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("dial error: {0}")]
    Dial(String),
    
    #[error("tls error: {0}")]
    Tls(String),
    
    #[error("connection closed")]
    ConnectionClosed,
}

/// Transport layer trait - all transport implementations must implement this trait
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    /// Transport type name
    fn name(&self) -> &'static str;

    /// Connect to a remote address
    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream>;

    /// Listen on a local port (for server use)
    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener>;

    /// Whether this transport supports UDP
    fn supports_udp(&self) -> bool {
        false
    }

    /// Get the local address if available
    async fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
}
