//! VLESS relay utilities
//!
//! Data relay functionality for VLESS protocol.
//! This module delegates to the shared relay implementation in the protocol module.

use crate::protocol::relay::relay_bidirectional;
use tokio::net::TcpStream;

/// Relay data between client and remote
///
/// This function is a thin wrapper around `protocol::relay::relay_bidirectional`
/// that provides the VLESS-specific interface.
pub async fn relay_data(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    relay_bidirectional(client, remote).await
}
