//! Shared relay utilities for dae-rs protocol handlers
//!
//! This crate provides bidirectional data relay functionality used by
//! multiple protocol handlers (SOCKS5, VLESS, VMess, Trojan, Shadowsocks, HTTP Proxy).

use tokio::net::TcpStream;

/// Relay data bidirectionally between two TCP streams.
///
/// This function concurrently copies data from client to remote and from
/// remote to client using tokio's async I/O primitives.
///
/// # Arguments
///
/// * `client` - The client-side TCP stream
/// * `remote` - The remote-side TCP stream
///
/// # Returns
///
/// Returns `Ok(())` if both directions completed successfully, or an error
/// if either direction failed.
pub async fn relay_bidirectional(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
    let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);

    tokio::try_join!(client_to_remote, remote_to_client)?;
    Ok(())
}
