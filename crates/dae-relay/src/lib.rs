//! Shared relay utilities for dae-rs protocol handlers
//!
//! This crate provides bidirectional data relay functionality used by
//! multiple protocol handlers (SOCKS5, VLESS, VMess, Trojan, Shadowsocks, HTTP Proxy).

use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Statistics for a bidirectional relay operation
#[derive(Debug, Default, Clone)]
pub struct RelayStats {
    /// Bytes transferred from client to remote
    pub bytes_client_to_remote: u64,
    /// Bytes transferred from remote to client
    pub bytes_remote_to_client: u64,
}

impl RelayStats {
    /// Create a new RelayStats with the given byte counts
    pub fn new(bytes_client_to_remote: u64, bytes_remote_to_client: u64) -> Self {
        Self {
            bytes_client_to_remote,
            bytes_remote_to_client,
        }
    }

    /// Total bytes transferred in both directions
    pub fn total_bytes(&self) -> u64 {
        self.bytes_client_to_remote + self.bytes_remote_to_client
    }
}

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

/// Relay data bidirectionally and collect statistics.
///
/// This is a variant of `relay_bidirectional` that tracks the number of bytes
/// transferred in each direction.
///
/// # Arguments
///
/// * `client` - The client-side TCP stream
/// * `remote` - The remote-side TCP stream
///
/// # Returns
///
/// Returns `Ok(RelayStats)` with byte counts, or the first error encountered.
pub async fn relay_bidirectional_with_stats(
    client: TcpStream,
    remote: TcpStream,
) -> std::io::Result<RelayStats> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
    let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);

    let (bytes_client_to_remote, bytes_remote_to_client) =
        tokio::try_join!(client_to_remote, remote_to_client)?;

    Ok(RelayStats::new(
        bytes_client_to_remote,
        bytes_remote_to_client,
    ))
}

/// Get the local socket address of a TcpStream
pub async fn get_local_addr(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    stream.local_addr()
}

/// Get the peer socket address of a TcpStream
pub async fn get_peer_addr(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    stream.peer_addr()
}
