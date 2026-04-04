//! Meek transport implementation
//!
//! Meek obfuscation transport for bypassing censorship.

use async_trait::async_trait;
use std::fmt::Debug;
use tokio::net::TcpStream;
use crate::traits::Transport;

/// Meek tactics (obfuscation strategies)
#[derive(Debug, Clone, Copy)]
pub enum MeekTactic {
    /// Use HTTP padding
    HttpPadding,
    /// Use domain fronting
    DomainFronting,
    /// Use cloud front
    CloudFront,
}

/// Meek configuration
#[derive(Debug, Clone)]
pub struct MeekConfig {
    /// Meek tactic to use
    pub tactic: MeekTactic,
    /// Fronting domain
    pub front_domain: String,
    /// Backend domain
    pub backend_domain: String,
    /// Use TLS
    pub use_tls: bool,
}

impl Default for MeekConfig {
    fn default() -> Self {
        Self {
            tactic: MeekTactic::HttpPadding,
            front_domain: String::new(),
            backend_domain: String::new(),
            use_tls: true,
        }
    }
}

/// Meek transport
#[derive(Debug, Clone)]
pub struct MeekTransport {
    config: MeekConfig,
}

impl MeekTransport {
    pub fn new(config: MeekConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for MeekTransport {
    fn name(&self) -> &'static str {
        "meek"
    }

    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream> {
        // TODO: Implement meek obfuscation
        TcpStream::connect(addr).await
    }

    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meek_transport_name() {
        let transport = MeekTransport::new(MeekConfig::default());
        assert_eq!(transport.name(), "meek");
    }
}
