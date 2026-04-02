//! Trojan-go protocol extensions
//!
//! Implements Trojan-go protocol extensions including WebSocket transport.
//! Trojan-go extends Trojan with WebSocket and TLS obfuscation support.
//!
//! Protocol spec: https://github.com/p4gefau1t/trojan-go

use std::io::ErrorKind;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tracing::{debug, error, info, warn};

use futures_util::{SinkExt, StreamExt};

/// Trojan-go WebSocket mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanGoMode {
    /// Plain WebSocket
    WebSocket,
    /// WebSocket over TLS (WSS)
    WebSocketTLS,
}

impl TrojanGoMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "websocket" | "ws" => Some(TrojanGoMode::WebSocket),
            "wss" | "websocket+tls" => Some(TrojanGoMode::WebSocketTLS),
            _ => None,
        }
    }
}

/// Trojan-go WebSocket configuration
#[derive(Debug, Clone)]
pub struct TrojanGoWsConfig {
    /// WebSocket mode
    pub mode: TrojanGoMode,
    /// WebSocket path
    pub path: String,
    /// Host for HTTP header
    pub host: String,
    /// TLS server name (SNI)
    pub tls_sni: Option<String>,
    /// Skip TLS verification
    pub insecure: bool,
    /// Connection timeout
    pub timeout: Duration,
}

impl Default for TrojanGoWsConfig {
    fn default() -> Self {
        Self {
            mode: TrojanGoMode::WebSocket,
            path: "/".to_string(),
            host: String::new(),
            tls_sni: None,
            insecure: false,
            timeout: Duration::from_secs(30),
        }
    }
}

impl TrojanGoWsConfig {
    pub fn new(mode: TrojanGoMode) -> Self {
        Self {
            mode,
            ..Default::default()
        }
    }

    pub fn websocket() -> Self {
        Self::new(TrojanGoMode::WebSocket)
    }

    pub fn websocket_tls() -> Self {
        Self::new(TrojanGoMode::WebSocketTLS)
    }

    pub fn with_path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    pub fn with_tls_sni(mut self, sni: &str) -> Self {
        self.tls_sni = Some(sni.to_string());
        self
    }
}

/// Trojan-go WebSocket handler
pub struct TrojanGoWsHandler {
    config: TrojanGoWsConfig,
}

impl TrojanGoWsHandler {
    pub fn new(config: TrojanGoWsConfig) -> Self {
        Self { config }
    }

    pub fn new_default() -> Self {
        Self {
            config: TrojanGoWsConfig::default(),
        }
    }

    /// Connect to server with Trojan-go WebSocket transport
    pub async fn connect(
        &self,
        server_addr: &str,
    ) -> std::io::Result<TrojanGoWsStream> {
        let url = self.build_url(server_addr)?;
        debug!("Connecting to {} with Trojan-go WebSocket", url);

        // Connect WebSocket
        let (ws_stream, response) = connect_async(&url)
            .await
            .map_err(|e| std::io::Error::new(
                ErrorKind::Other,
                format!("Trojan-go WebSocket connect error: {}", e),
            ))?;

        // Log response status
        let status = response.status().as_u16();
        debug!("Trojan-go WebSocket connected with status: {}", status);

        info!("Trojan-go WebSocket connected to {}", server_addr);

        Ok(TrojanGoWsStream::new(ws_stream))
    }

    fn build_url(&self, server_addr: &str) -> std::io::Result<String> {
        let host = if self.config.host.is_empty() {
            server_addr.split(':').next().unwrap_or(server_addr)
        } else {
            &self.config.host
        };

        let port = server_addr.split(':').nth(1).unwrap_or(match self.config.mode {
            TrojanGoMode::WebSocket => "80",
            TrojanGoMode::WebSocketTLS => "443",
        });

        let path = if self.config.path.is_empty() {
            "/"
        } else {
            &self.config.path
        };

        match self.config.mode {
            TrojanGoMode::WebSocket => {
                Ok(format!("ws://{}:{}{}", host, port, path))
            }
            TrojanGoMode::WebSocketTLS => {
                let sni = self.config.tls_sni.as_deref().unwrap_or(host);
                Ok(format!("wss://{}:{}{}", sni, port, path))
            }
        }
    }
}

/// Trojan-go WebSocket stream
pub struct TrojanGoWsStream {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
}

impl TrojanGoWsStream {
    pub fn new(
        ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    ) -> Self {
        Self { ws }
    }

    /// Send data through WebSocket
    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        // Trojan-go uses binary WebSocket messages
        self.ws
            .send(Message::Binary(data.to_vec().into()))
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("send error: {}", e)))?;
        Ok(())
    }

    /// Receive data from WebSocket
    pub async fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(msg) = self.ws.next().await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        let len = std::cmp::min(data.len(), buffer.len());
                        buffer[..len].copy_from_slice(&data[..len]);
                        return Ok(len);
                    }
                    Ok(Message::Text(text)) => {
                        // Trojan-go might send text (for WebSocket ping/pong)
                        let bytes = text.into_bytes();
                        let len = std::cmp::min(bytes.len(), buffer.len());
                        buffer[..len].copy_from_slice(&bytes[..len]);
                        return Ok(len);
                    }
                    Ok(Message::Close(_)) => {
                        return Ok(0);
                    }
                    Ok(Message::Ping(data)) => {
                        // Respond to ping with pong
                        if self.ws.send(Message::Pong(data)).await.is_err() {
                            warn!("Failed to send pong");
                        }
                    }
                    Ok(Message::Pong(_)) => {
                        // Ignore pong
                    }
                    Ok(Message::Frame(_)) => {
                        // Ignore frame
                    }
                    Err(e) => {
                        error!("Trojan-go WebSocket error: {}", e);
                        return Err(std::io::Error::new(ErrorKind::Other, format!("recv error: {}", e)));
                    }
                }
            } else {
                return Err(std::io::Error::new(ErrorKind::Other, "stream ended"));
            }
        }
    }

    /// Close the WebSocket connection gracefully
    pub async fn close(&mut self) -> std::io::Result<()> {
        self.ws.close(None).await.map_err(|e| {
            std::io::Error::new(ErrorKind::Other, format!("close error: {}", e))
        })?;
        Ok(())
    }

    /// Get underlying WebSocket stream
    #[allow(dead_code)]
    pub fn into_inner(self) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
        self.ws
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_go_mode_from_str() {
        assert_eq!(TrojanGoMode::from_str("websocket"), Some(TrojanGoMode::WebSocket));
        assert_eq!(TrojanGoMode::from_str("wss"), Some(TrojanGoMode::WebSocketTLS));
        assert_eq!(TrojanGoMode::from_str("unknown"), None);
    }

    #[test]
    fn test_trojan_go_ws_config_builder() {
        let config = TrojanGoWsConfig::websocket()
            .with_path("/trojan")
            .with_host("example.com")
            .with_tls_sni("sni.example.com");

        assert_eq!(config.mode, TrojanGoMode::WebSocket);
        assert_eq!(config.path, "/trojan");
        assert_eq!(config.host, "example.com");
        assert_eq!(config.tls_sni, Some("sni.example.com".to_string()));
    }

    #[test]
    fn test_trojan_go_ws_config_tls() {
        let config = TrojanGoWsConfig::websocket_tls();
        assert_eq!(config.mode, TrojanGoMode::WebSocketTLS);
    }

    #[test]
    fn test_default_config() {
        let config = TrojanGoWsConfig::default();
        assert_eq!(config.mode, TrojanGoMode::WebSocket);
        assert_eq!(config.path, "/");
    }
}
