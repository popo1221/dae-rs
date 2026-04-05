//! TCP transport implementation (default)

use super::Transport;
use async_trait::async_trait;
use std::fmt::Debug;
use tokio::net::TcpStream;

/// TCP transport (default implementation)
#[derive(Debug, Default)]
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

    fn supports_udp(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_transport_new() {
        let transport = TcpTransport::new();
        assert_eq!(transport.name(), "tcp");
        assert!(!transport.supports_udp());
    }

    #[test]
    fn test_tcp_transport_debug() {
        let transport = TcpTransport::new();
        let debug_str = format!("{:?}", transport);
        assert!(debug_str.contains("TcpTransport"));
    }

    #[test]
    fn test_tcp_transport_default() {
        let transport = TcpTransport::new();
        assert_eq!(transport.name(), "tcp");
    }
}
