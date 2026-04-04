//! TCP transport implementation
//!
//! Plain TCP connections without encryption.

use async_trait::async_trait;
use std::fmt::Debug;
use tokio::net::TcpStream;
use crate::traits::Transport;

/// TCP transport - plain TCP connections
#[derive(Debug, Clone, Default)]
pub struct TcpTransport;

impl TcpTransport {
    /// Create a new TCP transport
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream> {
        tokio::net::TcpStream::connect(addr).await
    }

    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_transport_name() {
        let transport = TcpTransport::new();
        assert_eq!(transport.name(), "tcp");
    }
}
