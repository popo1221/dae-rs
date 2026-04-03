//! UDP forwarding implementation
//!
//! Handles UDP traffic relay with NAT semantics and session management.
//!
//! Note: This is a simplified implementation for Phase 3. Full UDP relay
//! with proper NAT traversal will be implemented in Phase 4.

use crate::connection::ConnectionState;
use crate::connection_pool::{ConnectionKey, SharedConnectionPool};
use crate::ebpf_integration::EbpfSessionHandle;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Container for session data needed for relay
pub struct UdpSessionData {
    pub client_socket: Arc<UdpSocket>,
    pub server_socket: Arc<UdpSocket>,
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub last_activity: std::time::Instant,
    pub state: ConnectionState,
}

impl UdpSessionData {
    /// Create a new UDP session data
    pub fn new(
        client_socket: UdpSocket,
        server_socket: UdpSocket,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Self {
        Self {
            client_socket: Arc::new(client_socket),
            server_socket: Arc::new(server_socket),
            client_addr,
            server_addr,
            last_activity: std::time::Instant::now(),
            state: ConnectionState::Active,
        }
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    /// Check if session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// UDP proxy configuration
#[derive(Debug, Clone)]
pub struct UdpProxyConfig {
    /// Local bind address for client-facing socket
    pub listen_addr: SocketAddr,
    /// Session timeout
    pub session_timeout: Duration,
    /// Per-session timeout
    pub per_session_timeout: Duration,
    /// Maximum packet size
    pub max_packet_size: usize,
}

impl Default for UdpProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            session_timeout: Duration::from_secs(300),
            per_session_timeout: Duration::from_secs(30),
            max_packet_size: 64 * 1024,
        }
    }
}

/// UDP proxy that manages UDP sessions
pub struct UdpProxy {
    config: UdpProxyConfig,
    #[allow(dead_code)]
    connection_pool: SharedConnectionPool,
    sessions: RwLock<HashMap<ConnectionKey, Arc<UdpSessionData>>>,
    session_handle: Option<Arc<RwLock<EbpfSessionHandle>>>,
}

impl UdpProxy {
    /// Create a new UDP proxy
    pub fn new(config: UdpProxyConfig, connection_pool: SharedConnectionPool) -> Self {
        Self {
            config,
            connection_pool,
            sessions: RwLock::new(HashMap::new()),
            session_handle: None,
        }
    }

    /// Set the eBPF session handle
    pub fn with_session_handle(mut self, handle: Arc<RwLock<EbpfSessionHandle>>) -> Self {
        self.session_handle = Some(handle);
        self
    }

    /// Create a UDP socket pair for NAT
    pub async fn create_socket_pair(
        _client_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> std::io::Result<(UdpSocket, UdpSocket)> {
        // Create client-facing socket - bind to random port using tokio
        let client_socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
        // Create server-facing socket - bind to random port
        let server_socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;

        Ok((client_socket, server_socket))
    }

    /// Start the UDP proxy
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        // Create listening socket using tokio directly
        let socket = UdpSocket::bind(self.config.listen_addr).await?;

        info!("UDP proxy listening on {}", self.config.listen_addr);

        // Main loop
        loop {
            let mut buf = vec![0u8; self.config.max_packet_size];
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let packet_data = buf[..len].to_vec();
                    let proxy = self.clone();

                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_packet(packet_data, client_addr).await {
                            debug!("UDP handle error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("UDP recv error: {}", e);
                }
            }
        }
    }

    /// Handle an incoming UDP packet
    async fn handle_packet(
        self: Arc<Self>,
        data: Vec<u8>,
        client_addr: SocketAddr,
    ) -> std::io::Result<()> {
        // Parse destination from packet (simplified)
        let server_addr = self.extract_destination(&data).await?;

        // Create session key
        let key = ConnectionKey::new(client_addr, server_addr, crate::connection::Protocol::Udp);

        // Check if session exists
        {
            let sessions = self.sessions.read().await;
            if let Some(_session) = sessions.get(&key) {
                // Forward to existing session
                drop(sessions);
                self.relay_packet_to_session(key, &data).await?;
                return Ok(());
            }
        }

        // Create new session
        self.create_session(key, client_addr, server_addr, &data)
            .await?;

        Ok(())
    }

    /// Extract destination address from packet
    async fn extract_destination(self: &Arc<Self>, _data: &[u8]) -> std::io::Result<SocketAddr> {
        // Simplified: Return a placeholder
        // Real implementation would parse SOCKS5, HTTP, DNS, etc.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53))
    }

    /// Create a new UDP session
    async fn create_session(
        self: &Arc<Self>,
        key: ConnectionKey,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        initial_data: &[u8],
    ) -> std::io::Result<()> {
        // Create socket pair
        let (client_socket, server_socket) =
            Self::create_socket_pair(client_addr, server_addr).await?;

        let session = Arc::new(UdpSessionData::new(
            client_socket,
            server_socket,
            client_addr,
            server_addr,
        ));

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(key, session.clone());
        }

        // Update eBPF session
        if let Some(ref handle) = self.session_handle {
            if let Ok(handle_write) = handle.try_write() {
                if let Err(e) = handle_write.create_session(&key, 1, 0) {
                    debug!("Failed to create eBPF session: {}", e);
                }
            }
        }

        info!("Created UDP session for {:?}", key);

        // Relay initial packet first
        self.relay_packet_to_session(key, initial_data).await?;

        // Start relay task
        let proxy = self.clone();
        let session_key = key;
        tokio::spawn(async move {
            proxy.session_relay_loop(session, session_key).await;
        });

        Ok(())
    }

    /// Relay packet data to a session
    async fn relay_packet_to_session(
        self: &Arc<Self>,
        key: ConnectionKey,
        data: &[u8],
    ) -> std::io::Result<()> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&key) {
            let server_socket = session.server_socket.clone();
            let server_addr = session.server_addr;

            let len = data.len().min(self.config.max_packet_size);
            if let Err(e) = timeout(
                self.config.per_session_timeout,
                server_socket.send_to(&data[..len], server_addr),
            )
            .await?
            {
                warn!("UDP send error: {}", e);
            }
        }
        Ok(())
    }

    /// Session relay loop - runs in background
    async fn session_relay_loop(self: Arc<Self>, session: Arc<UdpSessionData>, key: ConnectionKey) {
        let per_session_timeout = self.config.per_session_timeout;
        let max_packet = 64 * 1024;

        let client_socket = session.client_socket.clone();
        let server_socket = session.server_socket.clone();
        let server_addr = session.server_addr;
        let client_addr = session.client_addr;

        let mut last_activity = std::time::Instant::now();
        let mut client_buf = vec![0u8; max_packet];
        let mut server_buf = vec![0u8; max_packet];

        loop {
            // Check timeout first
            if last_activity.elapsed() > per_session_timeout {
                debug!("UDP session {:?} timed out", key);
                break;
            }

            tokio::select! {
                // Client -> Server
                result = client_socket.recv_from(&mut client_buf) => {
                    match result {
                        Ok((len, _)) => {
                            last_activity = std::time::Instant::now();

                            if let Err(e) = server_socket.send_to(&client_buf[..len], server_addr).await {
                                warn!("UDP send to server error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("UDP client recv error: {}", e);
                            break;
                        }
                    }
                }

                // Server -> Client
                result = server_socket.recv_from(&mut server_buf) => {
                    match result {
                        Ok((len, _)) => {
                            last_activity = std::time::Instant::now();

                            if let Err(e) = client_socket.send_to(&server_buf[..len], client_addr).await {
                                warn!("UDP send to client error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("UDP server recv error: {}", e);
                            break;
                        }
                    }
                }

                // Periodic timeout check
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    // Just a tick to break out of select periodically
                }
            }
        }

        // Cleanup session
        self.remove_session(&key).await;
    }

    /// Remove a session
    async fn remove_session(self: &Arc<Self>, key: &ConnectionKey) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(key).is_some() {
            debug!("Removed UDP session for {:?}", key);

            // Update eBPF
            if let Some(ref handle) = self.session_handle {
                if let Ok(handle_write) = handle.try_write() {
                    if let Err(e) = handle_write.remove_session(key) {
                        debug!("Failed to remove eBPF session: {}", e);
                    }
                }
            }
        }
    }

    /// Clean up expired sessions
    #[allow(dead_code)]
    async fn cleanup_expired_sessions(self: Arc<Self>) {
        let timeout = self.config.per_session_timeout;

        // Collect expired keys
        let keys_to_remove: Vec<ConnectionKey> = {
            let sessions = self.sessions.read().await;
            let mut keys = Vec::new();
            for (key, session) in sessions.iter() {
                if session.is_expired(timeout) {
                    keys.push(*key);
                }
            }
            keys
        };

        // Remove expired sessions
        if !keys_to_remove.is_empty() {
            let mut sessions = self.sessions.write().await;
            for key in &keys_to_remove {
                sessions.remove(key);
            }
            info!("Cleaned up {} expired UDP sessions", keys_to_remove.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_proxy_config_default() {
        let config = UdpProxyConfig::default();
        assert_eq!(config.listen_addr.port(), 1080);
        assert_eq!(config.session_timeout, Duration::from_secs(300));
        assert_eq!(config.per_session_timeout, Duration::from_secs(30));
        assert_eq!(config.max_packet_size, 64 * 1024);
    }

    #[test]
    fn test_udp_proxy_config_custom() {
        let config = UdpProxyConfig {
            listen_addr: "0.0.0.0:5353".parse().unwrap(),
            session_timeout: Duration::from_secs(600),
            per_session_timeout: Duration::from_secs(60),
            max_packet_size: 32 * 1024,
        };
        assert_eq!(config.listen_addr.port(), 5353);
        assert_eq!(config.session_timeout, Duration::from_secs(600));
        assert_eq!(config.per_session_timeout, Duration::from_secs(60));
        assert_eq!(config.max_packet_size, 32 * 1024);
    }

    #[test]
    fn test_udp_proxy_config_debug() {
        let config = UdpProxyConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("UdpProxyConfig"));
        assert!(debug_str.contains("1080"));
    }
}
