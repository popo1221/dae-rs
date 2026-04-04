//! gRPC transport implementation
//!
//! gRPC transport using HTTP/2.

use async_trait::async_trait;
use std::fmt::Debug;
use tokio::net::TcpStream;
use crate::traits::Transport;

/// gRPC configuration
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// gRPC service name
    pub service_name: String,
    /// HTTP/2 settings
    pub http2_settings: Vec<(String, String)>,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            service_name: String::new(),
            http2_settings: Vec::new(),
        }
    }
}

/// gRPC transport
#[derive(Debug, Clone)]
pub struct GrpcTransport {
    config: GrpcConfig,
}

impl GrpcTransport {
    pub fn new(config: GrpcConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for GrpcTransport {
    fn name(&self) -> &'static str {
        "grpc"
    }

    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream> {
        // TODO: Implement gRPC dial
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
    fn test_grpc_transport_name() {
        let transport = GrpcTransport::new(GrpcConfig::default());
        assert_eq!(transport.name(), "grpc");
    }
}
