//! Shared types for dae-protocol-trojan
//!
//! This module provides the types needed by the Trojan handler
//! that are shared across the crate.

use std::sync::Arc;
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
        relay_bidirectional(client, remote).await
    }
}

/// Relay data bidirectionally between client and remote TCP streams.
pub async fn relay_bidirectional(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
    let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);

    tokio::try_join!(client_to_remote, remote_to_client)?;
    Ok(())
}
