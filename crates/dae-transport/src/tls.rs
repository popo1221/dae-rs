//! TLS transport implementation
//!
//! TLS transport with Reality protocol support.

use async_trait::async_trait;
use std::fmt::Debug;
use tokio::net::TcpStream;
use crate::traits::Transport;

/// TLS transport configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Server name (SNI)
    pub server_name: String,
    /// Skip TLS verification (for testing only)
    pub skip_verify: bool,
    /// Enable Reality protocol
    pub reality_enabled: bool,
    /// Reality public key (base64)
    pub reality_public_key: Option<String>,
    /// Reality short ID
    pub reality_short_id: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            skip_verify: false,
            reality_enabled: false,
            reality_public_key: None,
            reality_short_id: None,
        }
    }
}

/// TLS transport
#[derive(Debug, Clone)]
pub struct TlsTransport {
    config: TlsConfig,
}

impl TlsTransport {
    /// Create a new TLS transport
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for TlsTransport {
    fn name(&self) -> &'static str {
        "tls"
    }

    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream> {
        let stream = TcpStream::connect(addr).await?;
        
        // TODO: Upgrade to TLS using native-tls or rustls
        // For now, just return the TCP stream
        Ok(stream)
    }

    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}

/// Reality protocol configuration
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Reality public key
    pub public_key: String,
    /// Reality short ID
    pub short_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert!(!config.skip_verify);
        assert!(!config.reality_enabled);
    }
}
