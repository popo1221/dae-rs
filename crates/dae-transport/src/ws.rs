//! WebSocket transport implementation
//!
//! WebSocket transport for protocols that require it.

use async_trait::async_trait;
use std::fmt::Debug;
use tokio::net::TcpStream;
use crate::traits::Transport;

/// WebSocket configuration
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// WebSocket path
    pub path: String,
    /// Additional headers
    pub headers: Vec<(String, String)>,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            headers: Vec::new(),
        }
    }
}

/// WebSocket transport
#[derive(Debug, Clone)]
pub struct WsTransport {
    config: WsConfig,
}

impl WsTransport {
    pub fn new(config: WsConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for WsTransport {
    fn name(&self) -> &'static str {
        "websocket"
    }

    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream> {
        // TODO: Implement WebSocket dial
        TcpStream::connect(addr).await
    }

    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}

/// WebSocket connector
#[derive(Debug, Clone)]
pub struct WsConnector;

impl WsConnector {
    pub fn new() -> Self {
        Self
    }
}

/// WebSocket stream (placeholder)
pub struct WsStream;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_transport_name() {
        let transport = WsTransport::new(WsConfig::default());
        assert_eq!(transport.name(), "websocket");
    }
}
