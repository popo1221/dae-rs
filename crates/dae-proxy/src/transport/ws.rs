//! WebSocket transport implementation
//!
//! Provides WebSocket transport layer for protocols like VLESS, VMess, and Trojan.
//! Supports both client connections and server-side WebSocket handling.

use super::Transport;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Error as IoError, ErrorKind};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;

/// WebSocket stream type alias for client connections (TLS-capable)
pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// WebSocket connection wrapper with read/write/close interface
/// Works with any WebSocketStream stream type
pub struct WsConnection<S> {
    stream: S,
}

impl<S> WsConnection<S> {
    /// Create a new WebSocket connection from a stream
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl WsConnection<WsStream> {
    /// Read data from WebSocket into buffer
    /// Returns number of bytes read, or 0 on close
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Use next() on the stream
            match self.stream.next().await {
                Some(Ok(msg)) => {
                    match msg {
                        tokio_tungstenite::tungstenite::Message::Binary(data) => {
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            return Ok(len);
                        }
                        tokio_tungstenite::tungstenite::Message::Text(text) => {
                            let bytes = text.as_bytes();
                            let len = bytes.len().min(buf.len());
                            buf[..len].copy_from_slice(&bytes[..len]);
                            return Ok(len);
                        }
                        tokio_tungstenite::tungstenite::Message::Close(_) => {
                            return Ok(0);
                        }
                        _ => {
                            // For other message types, continue the loop
                            continue;
                        }
                    }
                }
                Some(Err(e)) => {
                    return Err(IoError::new(ErrorKind::ConnectionAborted, e.to_string()));
                }
                None => {
                    return Err(IoError::new(ErrorKind::ConnectionAborted, "stream ended"));
                }
            }
        }
    }

    /// Write data to WebSocket
    /// Returns number of bytes written
    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                buf.to_vec(),
            ))
            .await
            .map_err(|e| IoError::other(e.to_string()))?;
        Ok(buf.len())
    }

    /// Write text data to WebSocket
    /// Returns number of bytes written
    pub async fn write_text(&mut self, text: &str) -> std::io::Result<usize> {
        self.stream
            .send(tokio_tungstenite::tungstenite::Message::Text(
                text.to_string(),
            ))
            .await
            .map_err(|e| IoError::other(e.to_string()))?;
        Ok(text.len())
    }

    /// Close the WebSocket connection gracefully
    pub async fn close(mut self) -> std::io::Result<()> {
        let _ = self
            .stream
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;
        self.stream
            .close(None)
            .await
            .map_err(|e| IoError::other(e.to_string()))
    }

    /// Get the underlying WebSocket stream
    pub fn into_inner(self) -> WsStream {
        self.stream
    }
}

/// WebSocket connection for server-side (non-TLS)
pub type WsServerConnection = WsConnection<WebSocketStream<TcpStream>>;

/// WebSocket incoming connection handler for server-side
pub struct WsIncoming {
    listener: TcpListener,
}

impl WsIncoming {
    /// Accept a new WebSocket connection
    pub async fn accept(&mut self) -> std::io::Result<WsServerConnection> {
        let (tcp_stream, _) = self.listener.accept().await?;
        let ws_stream = tokio_tungstenite::accept_async(tcp_stream)
            .await
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
        Ok(WsServerConnection::new(ws_stream))
    }
}

/// WebSocket transport configuration
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// Request path
    pub path: String,
    /// Host header
    pub host: String,
    /// Use TLS (wss://)
    pub tls: bool,
    /// Additional HTTP headers
    pub headers: HashMap<String, String>,
    /// Connection timeout
    pub timeout: Duration,
    /// Max frame size
    pub max_frame_size: usize,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: "localhost".to_string(),
            tls: false,
            headers: HashMap::new(),
            timeout: Duration::from_secs(30),
            max_frame_size: 65535,
        }
    }
}

impl WsConfig {
    /// Create a new WebSocket config
    pub fn new(host: &str, path: &str) -> Self {
        Self {
            path: path.to_string(),
            host: host.to_string(),
            ..Default::default()
        }
    }

    /// Enable TLS (wss://)
    pub fn with_tls(mut self) -> Self {
        self.tls = true;
        self
    }

    /// Add a custom HTTP header
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set max frame size
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }
}

/// WebSocket transport
#[derive(Debug, Clone)]
pub struct WsTransport {
    pub config: WsConfig,
}

impl WsTransport {
    /// Create a new WebSocket transport
    pub fn new(host: &str, path: &str) -> Self {
        Self {
            config: WsConfig::new(host, path),
        }
    }

    /// Enable TLS (wss://)
    pub fn tls(self) -> Self {
        Self {
            config: self.config.with_tls(),
        }
    }

    /// Add a custom HTTP header
    pub fn with_header(self, key: &str, value: &str) -> Self {
        Self {
            config: self.config.with_header(key, value),
        }
    }

    /// Set connection timeout
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self {
            config: self.config.with_timeout(timeout),
        }
    }

    /// Set max frame size
    pub fn with_max_frame_size(self, size: usize) -> Self {
        Self {
            config: self.config.with_max_frame_size(size),
        }
    }

    fn url(&self) -> String {
        if self.config.tls {
            format!("wss://{}{}", self.config.host, self.config.path)
        } else {
            format!("ws://{}{}", self.config.host, self.config.path)
        }
    }
}

#[async_trait]
impl Transport for WsTransport {
    fn name(&self) -> &'static str {
        "websocket"
    }

    async fn dial(&self, _addr: &str) -> std::io::Result<TcpStream> {
        // Note: WebSocket requires special handling, use WsConnector::connect() instead
        Err(IoError::other(
            "WebSocket requires special handling, use WsConnector::connect() instead",
        ))
    }

    async fn listen(&self, addr: &str) -> std::io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }
}

/// WebSocket connector for establishing WebSocket connections
#[derive(Debug, Clone)]
pub struct WsConnector {
    pub transport: WsTransport,
}

impl WsConnector {
    /// Create a new WebSocket connector
    pub fn new(transport: WsTransport) -> Self {
        Self { transport }
    }

    /// Connect to the WebSocket server (returns TLS-capable stream)
    pub async fn connect(&self) -> Result<WsStream, Box<dyn std::error::Error + Send + Sync>> {
        use tokio_tungstenite::connect_async;

        let url = self.transport.url();
        let (ws_stream, _) = connect_async(&url).await?;
        Ok(ws_stream)
    }

    /// Connect and return WsConnection wrapper (TLS-capable)
    pub async fn connect_as_connection(
        &self,
    ) -> Result<WsConnection<WsStream>, Box<dyn std::error::Error + Send + Sync>> {
        let stream = self.connect().await?;
        Ok(WsConnection::new(stream))
    }

    /// Connect with custom headers
    pub async fn connect_with_headers(
        &self,
        _headers: &HashMap<String, String>,
    ) -> Result<WsStream, Box<dyn std::error::Error + Send + Sync>> {
        use tokio_tungstenite::connect_async;
        use tungstenite::handshake::client::Request;

        let url = self.transport.url();

        // Build request with custom headers
        let request = Request::builder()
            .uri(url)
            .body(())
            .map_err(|e| IoError::new(ErrorKind::InvalidInput, e.to_string()))?;

        let (ws_stream, _) = connect_async(request).await?;
        Ok(ws_stream)
    }

    /// Accept an incoming WebSocket connection on a TCP stream (server-side)
    pub async fn accept(
        tcp_stream: TcpStream,
    ) -> Result<WsServerConnection, Box<dyn std::error::Error + Send + Sync>> {
        let ws_stream = tokio_tungstenite::accept_async(tcp_stream).await?;
        Ok(WsServerConnection::new(ws_stream))
    }

    /// Create a WebSocket server listener
    pub async fn listen(&self, addr: &str) -> Result<WsIncoming, IoError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(WsIncoming { listener })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_config_default() {
        let config = WsConfig::default();
        assert_eq!(config.path, "/");
        assert_eq!(config.host, "localhost");
        assert!(!config.tls);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_ws_config_builder() {
        let config = WsConfig::new("example.com", "/vless")
            .with_tls()
            .with_header("Origin", "https://example.com")
            .with_timeout(Duration::from_secs(60))
            .with_max_frame_size(32768);

        assert_eq!(config.host, "example.com");
        assert_eq!(config.path, "/vless");
        assert!(config.tls);
        assert_eq!(
            config.headers.get("Origin"),
            Some(&"https://example.com".to_string())
        );
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_frame_size, 32768);
    }

    #[test]
    fn test_ws_transport_url() {
        let transport = WsTransport::new("example.com", "/vless");
        // Without TLS
        assert_eq!(transport.url(), "ws://example.com/vless");

        // With TLS
        let transport_tls = WsTransport::new("example.com", "/vless").tls();
        assert_eq!(transport_tls.url(), "wss://example.com/vless");
    }

    #[test]
    fn test_ws_transport_name() {
        let transport = WsTransport::new("example.com", "/");
        assert_eq!(transport.name(), "websocket");
    }

    #[test]
    fn test_ws_connector_new() {
        let transport = WsTransport::new("example.com", "/");
        let connector = WsConnector::new(transport);
        assert_eq!(connector.transport.config.host, "example.com");
    }

    #[tokio::test]
    async fn test_ws_transport_dial_error() {
        let transport = WsTransport::new("example.com", "/");
        let result = transport.dial("127.0.0.1:8080").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
    }

    #[tokio::test]
    async fn test_ws_transport_listen() {
        let transport = WsTransport::new("localhost", "/");
        let result = transport.listen("127.0.0.1:0").await;
        assert!(result.is_ok());
    }
}
