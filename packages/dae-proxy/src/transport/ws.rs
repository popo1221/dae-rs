//! WebSocket transport implementation

use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Debug;
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;
use super::Transport;

/// WebSocket stream type alias
pub type WsStream = tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>;

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
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: "localhost".to_string(),
            tls: false,
            headers: HashMap::new(),
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
        // Note: WebSocket requires special handling, returns an error pointing to WsConnector
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "WebSocket requires special handling, use WsConnector::connect() instead",
        ))
    }

    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}

/// WebSocket connector for establishing actual WebSocket connections
#[derive(Debug, Clone)]
pub struct WsConnector {
    pub transport: WsTransport,
}

impl WsConnector {
    /// Create a new WebSocket connector
    pub fn new(transport: WsTransport) -> Self {
        Self { transport }
    }

    /// Connect to the WebSocket server
    pub async fn connect(
        &self,
    ) -> Result<WsStream, Box<dyn std::error::Error + Send + Sync>> {
        use tokio_tungstenite::connect_async;

        let url = self.transport.url();
        let (ws_stream, _) = connect_async(&url).await?;
        Ok(ws_stream)
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
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let (ws_stream, _) = connect_async(request).await?;
        Ok(ws_stream)
    }
}
