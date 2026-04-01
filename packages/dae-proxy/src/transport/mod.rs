//! Transport layer abstraction module
//!
//! Provides a unified interface for different transport protocols:
//! - TCP: Plain TCP connections (default)
//! - WebSocket: WebSocket transport
//! - TLS: TLS/Reality transport
//! - gRPC: gRPC transport (placeholder)

use async_trait::async_trait;
use std::fmt::Debug;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Maximum UDP packet size
pub const MAX_UDP_PACKET_SIZE: usize = 65535;

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

// Re-export all transport types
pub mod tcp;
pub mod ws;
pub mod tls;
pub mod grpc;

pub use tcp::TcpTransport;
pub use ws::{WsTransport, WsConnector, WsStream, WsConfig};
pub use tls::{TlsTransport, TlsConfig, RealityConfig};
pub use grpc::{GrpcTransport, GrpcConfig};
