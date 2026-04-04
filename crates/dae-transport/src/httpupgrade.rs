//! HTTP Upgrade transport implementation
//!
//! HTTP Upgrade transport for protocols like SMTPS and others.

use async_trait::async_trait;
use std::fmt::Debug;
use tokio::net::TcpStream;
use crate::traits::Transport;

/// HTTP Upgrade transport
#[derive(Debug, Clone, Default)]
pub struct HttpUpgradeTransport;

impl HttpUpgradeTransport {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transport for HttpUpgradeTransport {
    fn name(&self) -> &'static str {
        "httpupgrade"
    }

    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }

    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}
