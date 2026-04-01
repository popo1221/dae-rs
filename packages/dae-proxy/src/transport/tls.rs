//! TLS / Reality transport implementation

use async_trait::async_trait;
use std::fmt::Debug;
use tokio::net::TcpStream;
use super::Transport;

/// TLS ALPN protocols
pub const ALPN_H2: &str = "h2";
pub const ALPN_HTTP11: &str = "http/1.1";

/// TLS transport configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// ALPN protocol list
    pub alpn: Vec<String>,
    /// SNI server name
    pub server_name: String,
    /// Reality configuration
    pub reality: Option<RealityConfig>,
}

impl TlsConfig {
    /// Create a new TLS config with default ALPN
    pub fn new(server_name: &str) -> Self {
        Self {
            alpn: vec![ALPN_H2.to_string(), ALPN_HTTP11.to_string()],
            server_name: server_name.to_string(),
            reality: None,
        }
    }

    /// Add Reality configuration
    pub fn with_reality(mut self, public_key: &[u8], short_id: &[u8]) -> Self {
        self.reality = Some(RealityConfig {
            public_key: public_key.to_vec(),
            short_id: short_id.to_vec(),
        });
        self
    }

    /// Set custom ALPN protocols
    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = alpn;
        self
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::new("localhost")
    }
}

/// Reality configuration (VLESS XTLS/Reality)
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Public key (32 bytes for X25519)
    pub public_key: Vec<u8>,
    /// Short ID (8 bytes, can be empty)
    pub short_id: Vec<u8>,
}

impl RealityConfig {
    /// Create a new Reality config
    pub fn new(public_key: &[u8], short_id: &[u8]) -> Self {
        Self {
            public_key: public_key.to_vec(),
            short_id: short_id.to_vec(),
        }
    }
}

/// TLS transport
#[derive(Debug, Clone)]
pub struct TlsTransport {
    pub config: TlsConfig,
}

impl TlsTransport {
    /// Create a new TLS transport
    pub fn new(server_name: &str) -> Self {
        Self {
            config: TlsConfig::new(server_name),
        }
    }

    /// Create with custom config
    pub fn with_config(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Enable Reality
    pub fn with_reality(self, public_key: &[u8], short_id: &[u8]) -> Self {
        Self {
            config: self.config.with_reality(public_key, short_id),
        }
    }
}

#[async_trait]
impl Transport for TlsTransport {
    fn name(&self) -> &'static str {
        if self.config.reality.is_some() {
            "reality"
        } else {
            "tls"
        }
    }

    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream> {
        // Note: TLS requires rustls or native-tls integration
        // This is a placeholder that establishes TCP connection
        tokio::net::TcpStream::connect(addr).await
    }

    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}
