//! Shadowsocks v2ray-plugin for WebSocket-based obfuscation
//!
//! Implements v2ray-plugin protocol for Shadowsocks traffic obfuscation.
//! v2ray-plugin provides WebSocket-based transport with optional TLS.
//!
//! Note: This is a simplified implementation. Full v2ray-plugin support
//! requires handling WebSocket messages and TLS termination.

use std::io::ErrorKind;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tracing::{debug, info, warn};

use futures_util::{SinkExt, StreamExt};

/// v2ray-plugin WebSocket mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2rayMode {
    /// WebSocket without TLS
    WebSocket,
    /// WebSocket over TLS
    WebSocketTLS,
}

impl V2rayMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "websocket" | "ws" => Some(V2rayMode::WebSocket),
            "websocket+tls" | "wss" | "tls" => Some(V2rayMode::WebSocketTLS),
            _ => None,
        }
    }
}

/// v2ray-plugin configuration
#[derive(Debug, Clone)]
pub struct V2rayConfig {
    /// Plugin mode
    pub mode: V2rayMode,
    /// WebSocket path
    pub path: String,
    /// Host for HTTP header
    pub host: String,
    /// TLS server name (SNI)
    pub tls_server_name: Option<String>,
    /// Skip TLS certificate verification
    pub insecure: bool,
    /// Connection timeout
    pub timeout: Duration,
}

impl V2rayConfig {
    pub fn new(mode: V2rayMode) -> Self {
        Self {
            mode,
            path: "/".to_string(),
            host: String::new(),
            tls_server_name: None,
            insecure: false,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn websocket() -> Self {
        Self::new(V2rayMode::WebSocket)
    }

    pub fn websocket_tls() -> Self {
        Self::new(V2rayMode::WebSocketTLS)
    }

    pub fn with_path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    pub fn with_tls_server_name(mut self, sni: &str) -> Self {
        self.tls_server_name = Some(sni.to_string());
        self
    }

    pub fn with_insecure(mut self) -> Self {
        self.insecure = true;
        self
    }
}

/// v2ray-plugin WebSocket handler
pub struct V2rayPlugin {
    config: V2rayConfig,
}

impl V2rayPlugin {
    pub fn new(config: V2rayConfig) -> Self {
        Self { config }
    }

    /// Connect to server with v2ray-plugin WebSocket obfuscation
    /// Returns a tuple of (WebSocketStream, response)
    #[allow(dead_code)]
    pub async fn connect(
        &self,
        server_addr: &str,
    ) -> std::io::Result<(tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,)> {
        let url = self.build_url(server_addr);
        debug!("Connecting to {} with v2ray-plugin", url);

        // Connect WebSocket
        let (ws_stream, _response) = connect_async(&url)
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("WebSocket connect error: {}", e)))?;

        info!("v2ray-plugin WebSocket connected to {}", server_addr);

        Ok((ws_stream,))
    }

    fn build_url(&self, server_addr: &str) -> String {
        let host = if self.config.host.is_empty() {
            server_addr.split(':').next().unwrap_or(server_addr)
        } else {
            &self.config.host
        };

        match self.config.mode {
            V2rayMode::WebSocket => {
                format!(
                    "ws://{}:{}{}",
                    host,
                    server_addr.split(':').nth(1).unwrap_or("80"),
                    self.config.path
                )
            }
            V2rayMode::WebSocketTLS => {
                let sni = self.config.tls_server_name.as_deref().unwrap_or(host);
                let port = server_addr.split(':').nth(1).unwrap_or("443");
                format!("wss://{}:{}{}", sni, port, self.config.path)
            }
        }
    }
}

/// v2ray-plugin stream handler
pub struct V2rayStream {
    ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
}

impl V2rayStream {
    pub fn new(ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>) -> Self {
        Self { ws }
    }

    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.ws
            .send(Message::Binary(data.to_vec().into()))
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("send error: {}", e)))?;
        Ok(())
    }

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
                        let bytes = text.into_bytes();
                        let len = std::cmp::min(bytes.len(), buffer.len());
                        buffer[..len].copy_from_slice(&bytes[..len]);
                        return Ok(len);
                    }
                    Ok(Message::Close(_)) => return Ok(0),
                    Ok(Message::Ping(data)) => {
                        if self.ws.send(Message::Pong(data)).await.is_err() {
                            return Err(std::io::Error::new(ErrorKind::Other, "pong failed"));
                        }
                    }
                    Ok(Message::Pong(_)) => {}
                    Ok(Message::Frame(_)) => {}
                    Err(e) => {
                        return Err(std::io::Error::new(ErrorKind::Other, format!("recv error: {}", e)));
                    }
                }
            } else {
                return Err(std::io::Error::new(ErrorKind::Other, "stream ended"));
            }
        }
    }

    #[allow(dead_code)]
    pub async fn close(&mut self) -> std::io::Result<()> {
        self.ws
            .close(None)
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("close error: {}", e)))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
        self.ws
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2ray_mode_from_str() {
        assert_eq!(V2rayMode::from_str("websocket"), Some(V2rayMode::WebSocket));
        assert_eq!(V2rayMode::from_str("wss"), Some(V2rayMode::WebSocketTLS));
        assert_eq!(V2rayMode::from_str("tls"), Some(V2rayMode::WebSocketTLS));
        assert_eq!(V2rayMode::from_str("unknown"), None);
    }

    #[test]
    fn test_v2ray_config_builder() {
        let config = V2rayConfig::websocket()
            .with_path("/custom/path")
            .with_host("example.com")
            .with_tls_server_name("sni.example.com")
            .with_insecure();

        assert_eq!(config.mode, V2rayMode::WebSocket);
        assert_eq!(config.path, "/custom/path");
        assert_eq!(config.host, "example.com");
        assert_eq!(config.tls_server_name, Some("sni.example.com".to_string()));
        assert!(config.insecure);
    }

    #[test]
    fn test_v2ray_config_tls() {
        let config = V2rayConfig::websocket_tls();
        assert_eq!(config.mode, V2rayMode::WebSocketTLS);
    }
}
