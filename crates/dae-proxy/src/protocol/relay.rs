//! 双向数据中继工具 - 协议处理器通用模块
//!
//! 本模块提供代理协议中客户端与远程服务器之间双向数据中继的通用接口。
//! 所有代理协议都使用 tokio::io::copy 实现相同的双向中继模式。
//!
//! # 使用示例
//!
//! ```
//! use dae_proxy::protocol::relay::{relay_bidirectional, BidirectionalRelay};
//! use tokio::net::TcpStream;
//!
//! async fn handle_connection(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
//!     relay_bidirectional(client, remote).await
//! }
//! ```

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

/// Trait for types that can relay data bidirectionally between client and remote streams.
///
/// This trait provides a default implementation that uses `tokio::io::copy` to
/// relay data in both directions concurrently. Implementors can override the
/// `relay_stream` method if they need custom behavior (e.g., different error handling,
/// logging, or statistics tracking).
///
/// # Note
///
/// The default implementation uses `tokio::try_join!` to run both copy operations
/// concurrently. If either direction completes with an error, the other will be
/// dropped. For more graceful error handling, override this method.
#[allow(async_fn_in_trait)] // Intentional: trait needs async fn for ergonomic relay implementation
pub trait BidirectionalRelay: Send + Sync {
    /// Relay data between client and remote streams.
    ///
    /// The default implementation splits both streams and copies data bidirectionally
    /// using `tokio::io::copy`. Both copy operations run concurrently.
    async fn relay_stream(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        relay_bidirectional(client, remote).await
    }
}

/// Relay data bidirectionally between client and remote TCP streams.
///
/// This function splits both streams and copies data in both directions concurrently
/// using `tokio::io::copy`. The function waits for both copy operations to complete
/// and returns success only if both succeed.
///
/// # Arguments
///
/// * `client` - The client-side TCP stream
/// * `remote` - The remote-side TCP stream
///
/// # Returns
///
/// Returns `Ok(())` if both copy operations complete successfully, or the
/// first error encountered.
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

/// Relay data from a client to a remote, returning only after the client finishes sending.
///
/// This is a unidirectional relay that copies data from client to remote only.
/// It reads until EOF on the client side before returning.
///
/// # Arguments
///
/// * `client` - The client-side TCP stream (read end)
/// * `remote` - The remote-side TCP stream (write end)
pub async fn relay_unidirectional(
    mut client: TcpStream,
    mut remote: TcpStream,
) -> std::io::Result<u64> {
    let bytes = tokio::io::copy(&mut client, &mut remote).await?;
    Ok(bytes)
}

/// Get the local socket address of a TcpStream
pub async fn get_local_addr(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    stream.local_addr()
}

/// Get the peer socket address of a TcpStream
pub async fn get_peer_addr(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    stream.peer_addr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn create_connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = TcpStream::connect(addr).await.unwrap();
        let remote = tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap()
            .0;

        (client, remote)
    }

    #[tokio::test]
    async fn test_relay_bidirectional() {
        let (client, remote) = create_connected_pair().await;

        // Spawn a task to write to client and read from remote
        let client_write = async {
            let mut client = client;
            client.write_all(b"hello from client").await.unwrap();
            client.shutdown().await.unwrap();
        };

        let remote_read = async {
            let mut remote = remote;
            let mut buf = [0u8; 64];
            let n = remote.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello from client");
        };

        tokio::join!(client_write, remote_read);
    }

    #[tokio::test]
    async fn test_relay_stats_default() {
        let stats = RelayStats::default();
        assert_eq!(stats.bytes_client_to_remote, 0);
        assert_eq!(stats.bytes_remote_to_client, 0);
        assert_eq!(stats.total_bytes(), 0);
    }

    #[tokio::test]
    async fn test_relay_stats_new() {
        let stats = RelayStats::new(100, 200);
        assert_eq!(stats.bytes_client_to_remote, 100);
        assert_eq!(stats.bytes_remote_to_client, 200);
        assert_eq!(stats.total_bytes(), 300);
    }
}
