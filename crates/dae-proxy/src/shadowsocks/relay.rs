//! Data relay functionality
//!
//! Provides utilities for relaying data between client and server.
//! This module contains helper functions used by ShadowsocksHandler.

use crate::protocol::relay::relay_bidirectional as relay_tcp;
use tokio::net::TcpStream;

/// Relay data bidirectionally between two TCP streams.
///
/// This is a wrapper around `protocol::relay::relay_bidirectional` that provides
/// the Shadowsocks-specific interface.
pub async fn relay(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    relay_tcp(client, remote).await
}

/// Relay data bidirectionally between two streams (generic version).
///
/// This is a thin wrapper around tokio::io::copy that performs
/// bidirectional copying concurrently. This version works with any
/// AsyncRead + AsyncWrite types and is kept for backward compatibility.
#[allow(dead_code)]
pub async fn relay_bidirectional<R, W>(reader: R, writer: W) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    W: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut r_read, mut r_write) = tokio::io::split(reader);
    let (mut w_read, mut w_write) = tokio::io::split(writer);

    let a = tokio::io::copy(&mut r_read, &mut w_write);
    let b = tokio::io::copy(&mut w_read, &mut r_write);

    tokio::try_join!(a, b)?;
    Ok(())
}
