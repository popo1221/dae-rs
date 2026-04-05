//! Data relay functionality
//!
//! Provides utilities for relaying data between client and server.
//! This module contains helper functions used by ShadowsocksHandler.

use tokio::net::TcpStream;

/// Relay data bidirectionally between two TCP streams.
pub async fn relay_bidirectional(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
    let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);

    tokio::try_join!(client_to_remote, remote_to_client)?;
    Ok(())
}

/// Relay data between Shadowsocks client and server.
pub async fn relay(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    relay_bidirectional(client, remote).await
}
