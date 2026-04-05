//! Shared types for dae-protocol-trojan
//!
//! This module provides the types needed by the Trojan handler
//! that are shared across the crate.

use tokio::net::TcpStream;

/// Protocol types supported by dae-proxy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Trojan,
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Trojan => write!(f, "trojan"),
        }
    }
}

/// Handler configuration trait
pub trait HandlerConfig: Send + Sync + std::fmt::Debug {}

/// Bidirectional relay trait
#[allow(async_fn_in_trait)]
pub trait BidirectionalRelay: Send + Sync {
    async fn relay_stream(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        dae_relay::relay_bidirectional(client, remote).await
    }
}

// Re-export relay_bidirectional from dae-relay
pub use dae_relay::relay_bidirectional;
