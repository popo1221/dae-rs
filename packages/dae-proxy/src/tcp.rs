//! TCP forwarding implementation
//!
//! Handles bidirectional TCP traffic relay between client and remote.

use crate::connection::{ConnectionState, SharedConnection};
use crate::connection_pool::{ConnectionKey, SharedConnectionPool};
use crate::ebpf_integration::EbpfSessionHandle;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::timeout as tokio_timeout;
use tracing::{debug, error, info, warn};

/// TCP proxy configuration
#[derive(Debug, Clone)]
pub struct TcpProxyConfig {
    /// Local listen address
    pub listen_addr: SocketAddr,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// TCP keepalive interval
    pub keepalive_interval: Duration,
    /// Inbound buffer size
    pub inbound_buffer_size: usize,
    /// Outbound buffer size
    pub outbound_buffer_size: usize,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            connection_timeout: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(30),
            inbound_buffer_size: 32 * 1024,
            outbound_buffer_size: 32 * 1024,
        }
    }
}

/// TCP proxy that accepts and relays connections
pub struct TcpProxy {
    config: TcpProxyConfig,
    connection_pool: SharedConnectionPool,
    session_handle: Option<Arc<RwLock<EbpfSessionHandle>>>,
}

impl TcpProxy {
    /// Create a new TCP proxy
    pub fn new(config: TcpProxyConfig, connection_pool: SharedConnectionPool) -> Self {
        Self {
            config,
            connection_pool,
            session_handle: None,
        }
    }

    /// Set the eBPF session handle for connection tracking
    pub fn with_session_handle(mut self, handle: Arc<RwLock<EbpfSessionHandle>>) -> Self {
        self.session_handle = Some(handle);
        self
    }

    /// Configure socket with high-performance options
    fn configure_socket(socket: &Socket) -> std::io::Result<()> {
        socket.set_reuse_address(true)?;
        socket.set_nodelay(true)?;
        socket.set_keepalive(true)?;
        Ok(())
    }

    /// Create a TCP listener with socket2 for performance
    pub async fn create_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        Self::configure_socket(&socket)?;
        socket.bind(&addr.into())?;
        socket.listen(128)?;
        
        // Convert to std listener first, then to tokio
        let std_listener: std::net::TcpListener = socket.into();
        std_listener.set_nonblocking(true)?;
        
        TcpListener::from_std(std_listener)
    }

    /// Connect to remote with timeout
    pub async fn connect_remote(addr: SocketAddr) -> std::io::Result<TcpStream> {
        let stream = tokio_timeout(
            Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timeout"))??;
        
        Ok(stream)
    }

    /// Start the TCP proxy
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        let listener = Self::create_listener(self.config.listen_addr).await?;
        info!("TCP proxy listening on {}", self.config.listen_addr);

        loop {
            match listener.accept().await {
                Ok((client, client_addr)) => {
                    let proxy = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_client(client, client_addr).await {
                            error!("TCP relay error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                }
            }
        }
    }

    /// Handle an incoming client connection
    async fn handle_client(
        self: Arc<Self>,
        client: TcpStream,
        client_addr: SocketAddr,
    ) -> std::io::Result<()> {
        let remote_addr = client.peer_addr()?;

        debug!("TCP connection from {} to {}", client_addr, remote_addr);

        // Create connection key
        let key = self.create_connection_key(client_addr, remote_addr);

        // Get or create connection from pool
        let (conn, is_new) = self.connection_pool.get_or_create(key).await;

        if is_new {
            // New connection - update state
            self.update_session_state(&key, ConnectionState::New).await;
            
            // Mark as established
            {
                let mut conn_write = conn.write().await;
                conn_write.establish();
            }
            self.update_session_state(&key, ConnectionState::Active).await;
        }

        // Connect to remote
        let remote = match Self::connect_remote(remote_addr).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to connect to remote {}: {}", remote_addr, e);
                self.connection_pool.remove(&key).await;
                self.update_session_state(&key, ConnectionState::Closed).await;
                return Err(e);
            }
        };

        // Start relay using tokio::io::split
        let result = Self::relay_connection(client, remote, conn.clone(), self.config.connection_timeout, key).await;

        // Cleanup
        self.connection_pool.remove(&key).await;
        self.update_session_state(&key, ConnectionState::Closed).await;

        result
    }

    /// Relay a TCP connection bidirectionally
    async fn relay_connection(
        client: TcpStream,
        remote: TcpStream,
        connection: SharedConnection,
        timeout_duration: Duration,
        key: ConnectionKey,
    ) -> std::io::Result<()> {
        // Split both streams
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut remote_read, mut remote_write) = tokio::io::split(remote);
        
        // Create channels for errors - clone the sender for each task
        let (tx1, mut rx1) = tokio::sync::mpsc::channel::<std::io::Result<()>>(2);
        let tx2 = tx1.clone();
        
        let conn1 = connection.clone();
        let conn2 = connection.clone();
        let timeout_dur = timeout_duration;
        
        // Client to remote
        let send_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match tokio_timeout(timeout_dur, client_read.read(&mut buf)).await {
                    Ok(Ok(0)) => {
                        debug!("EOF on client");
                        let _ = tx1.send(Ok(())).await;
                        break;
                    }
                    Ok(Ok(n)) => {
                        if let Err(e) = remote_write.write_all(&buf[..n]).await {
                            debug!("Write error: {}", e);
                            let _ = tx1.send(Err(e)).await;
                            break;
                        }
                        let mut c = conn1.write().await;
                        c.touch();
                    }
                    Ok(Err(e)) => {
                        debug!("Read error: {}", e);
                        let _ = tx1.send(Err(e)).await;
                        break;
                    }
                    Err(_) => {
                        debug!("Timeout on client read");
                        let _ = tx1.send(Ok(())).await;
                        break;
                    }
                }
            }
        });
        
        // Remote to client
        let recv_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match tokio_timeout(timeout_dur, remote_read.read(&mut buf)).await {
                    Ok(Ok(0)) => {
                        debug!("EOF on remote");
                        let _ = tx2.send(Ok(())).await;
                        break;
                    }
                    Ok(Ok(n)) => {
                        if let Err(e) = client_write.write_all(&buf[..n]).await {
                            debug!("Write error: {}", e);
                            let _ = tx2.send(Err(e)).await;
                            break;
                        }
                        let mut c = conn2.write().await;
                        c.touch();
                    }
                    Ok(Err(e)) => {
                        debug!("Read error: {}", e);
                        let _ = tx2.send(Err(e)).await;
                        break;
                    }
                    Err(_) => {
                        debug!("Timeout on remote read");
                        let _ = tx2.send(Ok(())).await;
                        break;
                    }
                }
            }
        });
        
        // Wait for first result
        let result = rx1.recv().await.unwrap_or(Ok(()));
        
        // Abort handles
        send_handle.abort();
        recv_handle.abort();
        
        // Close connection
        {
            let mut conn = connection.write().await;
            conn.close();
        }
        
        info!("TCP relay completed for {:?}", key);
        result
    }

    /// Create connection key from addresses
    fn create_connection_key(&self, client_addr: SocketAddr, remote_addr: SocketAddr) -> ConnectionKey {
        ConnectionKey::new(client_addr, remote_addr, crate::connection::Protocol::Tcp)
    }

    /// Update session state in eBPF
    async fn update_session_state(&self, key: &ConnectionKey, state: ConnectionState) {
        if let Some(ref handle) = self.session_handle {
            let state_val = match state {
                ConnectionState::New => 0,
                ConnectionState::Active => 1,
                ConnectionState::Closing => 2,
                ConnectionState::Closed => 3,
            };
            if let Ok(handle_write) = handle.try_write() {
                if let Err(e) = handle_write.update_session(key, state_val, 0) {
                    debug!("Failed to update session state: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_proxy_config_default() {
        let config = TcpProxyConfig::default();
        assert_eq!(config.listen_addr.port(), 1080);
        assert_eq!(config.connection_timeout, Duration::from_secs(60));
    }
}
