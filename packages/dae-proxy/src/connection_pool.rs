//! Connection pool for managing TCP/UDP connections
//!
//! Provides connection reuse by 4-tuple and expiration management.

use crate::connection::{new_connection, ConnectionState, Protocol, SharedConnection};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Compact IP address storage supporting both IPv4 and IPv6.
///
/// Format: [version: u8][address: 16 bytes]
/// - version 4: bytes 1-4 hold IPv4 address, bytes 5-16 are zero
/// - version 6: bytes 1-16 hold IPv6 address
///
/// This allows ConnectionKey to be used as a HashMap key while supporting
/// both IPv4 (4 bytes) and IPv6 (16 bytes) addresses.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactIp(u128);

impl CompactIp {
    /// Create from a SocketAddr
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(ipv4) => Self::from_ipv4(ipv4),
            IpAddr::V6(ipv6) => Self::from_ipv6(ipv6),
        }
    }

    /// Create from Ipv4Addr
    pub fn from_ipv4(ip: Ipv4Addr) -> Self {
        let octets = ip.octets();
        let bits = u128::from(u32::from_be_bytes(octets));
        // version 4, stored in lower 32 bits
        Self((4u128 << 124) | bits)
    }

    /// Create from Ipv6Addr
    pub fn from_ipv6(ip: Ipv6Addr) -> Self {
        let octets = ip.octets();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&octets);
        // version 6, stored in lower 128 bits
        let bits = u128::from_be_bytes(bytes);
        Self((6u128 << 124) | bits)
    }

    /// Convert to IpAddr
    pub fn to_ip_addr(&self) -> IpAddr {
        let version = self.0 >> 124;
        let bits = self.0 & ((1u128 << 124) - 1);
        match version {
            4 => IpAddr::V4(Ipv4Addr::from(bits as u32)),
            6 => {
                let bytes = bits.to_be_bytes();
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Returns true if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        self.0 >> 124 == 6
    }

    /// Returns true if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        self.0 >> 124 == 4
    }

    /// Extract IPv4 address as u32.
    ///
    /// For IPv4: returns the IPv4 address as u32.
    /// For IPv6: returns the lower 32 bits of the IPv6 address
    /// (useful for IPv4-mapped IPv6 addresses like ::ffff:192.168.1.1).
    pub fn to_u32_lossy(&self) -> u32 {
        (self.0 & ((1u128 << 124) - 1)) as u32
    }
}

impl std::fmt::Debug for CompactIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_ip_addr())
    }
}

impl std::hash::Hash for CompactIp {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Default for CompactIp {
    fn default() -> Self {
        Self::from_ipv4(Ipv4Addr::UNSPECIFIED)
    }
}

/// 4-tuple key for connection identification
///
/// Supports both IPv4 and IPv6 addresses via CompactIp storage.
/// Used as HashMap key in the connection pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionKey {
    pub src_ip: CompactIp,
    pub dst_ip: CompactIp,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl std::hash::Hash for ConnectionKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
        self.proto.hash(state);
    }
}

impl ConnectionKey {
    /// Create a new connection key from addresses and protocol
    ///
    /// Supports both IPv4 and IPv6 addresses. IPv6 addresses are fully
    /// supported in the connection pool.
    pub fn new(src: SocketAddr, dst: SocketAddr, proto: Protocol) -> Self {
        let src_ip = CompactIp::from_socket_addr(src);
        let dst_ip = CompactIp::from_socket_addr(dst);
        let proto = match proto {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
        };
        Self {
            src_ip,
            dst_ip,
            src_port: src.port(),
            dst_port: dst.port(),
            proto,
        }
    }

    /// Create from raw components (for eBPF integration)
    ///
    /// Note: src_ip and dst_ip are interpreted as IPv4 addresses
    /// (lower 32 bits of the CompactIp). This is for backward compatibility
    /// with eBPF which uses u32 IP fields.
    pub fn from_raw(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_ip: CompactIp::from_ipv4(Ipv4Addr::from(src_ip)),
            dst_ip: CompactIp::from_ipv4(Ipv4Addr::from(dst_ip)),
            src_port,
            dst_port,
            proto,
        }
    }

    /// Convert to socket addresses
    pub fn to_socket_addrs(&self) -> Option<(SocketAddr, SocketAddr)> {
        let src = SocketAddr::new(self.src_ip.to_ip_addr(), self.src_port);
        let dst = SocketAddr::new(self.dst_ip.to_ip_addr(), self.dst_port);
        Some((src, dst))
    }

    /// Get protocol from proto number
    pub fn protocol(&self) -> Protocol {
        match self.proto {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Tcp,
        }
    }
}

/// Connection pool for managing active connections
pub struct ConnectionPool {
    /// Map of connection key to connection
    connections: RwLock<HashMap<ConnectionKey, SharedConnection>>,
    /// Connection timeout
    connection_timeout: Duration,
    /// UDP session timeout (shorter than TCP)
    udp_timeout: Duration,
    /// TCP keepalive interval
    tcp_keepalive: Duration,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(
        connection_timeout: Duration,
        udp_timeout: Duration,
        tcp_keepalive: Duration,
    ) -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            connection_timeout,
            udp_timeout,
            tcp_keepalive,
        }
    }

    /// Get a connection by key, or create a new one
    ///
    /// Uses double-checked locking: first acquires a read lock to check if the
    /// connection exists (fast path for cache hits), then only acquires a write
    /// lock when a new connection needs to be created (cache miss).
    /// This reduces lock contention in high-concurrency scenarios.
    pub async fn get_or_create(&self, key: ConnectionKey) -> (SharedConnection, bool) {
        // Fast path: try read lock first (cache hit)
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&key) {
                debug!("Reusing existing connection for {:?}", key);
                // Need to update last_access, must upgrade to write on the connection itself
                let mut conn_write = conn.write().await;
                conn_write.touch();
                return (conn.clone(), false);
            }
        }
        // Slow path: cache miss — acquire write lock and create
        let mut connections = self.connections.write().await;
        // Double-check after acquiring write lock (another task may have created it)
        if let Some(conn) = connections.get(&key) {
            debug!("Reusing existing connection for {:?} (after write lock)", key);
            let mut conn_write = conn.write().await;
            conn_write.touch();
            return (conn.clone(), false);
        }

        let (src, dst) = key.to_socket_addrs().unwrap_or_else(|| {
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
        });

        let conn = new_connection(src, dst, key.protocol(), self.tcp_keepalive);
        connections.insert(key, conn.clone());

        debug!("Created new connection for {:?}", key);
        (conn, true)
    }

    /// Remove a connection from the pool
    pub async fn remove(&self, key: &ConnectionKey) -> bool {
        let mut connections = self.connections.write().await;
        if connections.remove(key).is_some() {
            debug!("Removed connection for {:?}", key);
            true
        } else {
            false
        }
    }

    /// Get a connection by key
    pub async fn get(&self, key: &ConnectionKey) -> Option<SharedConnection> {
        let connections = self.connections.read().await;
        connections.get(key).cloned()
    }

    /// Clean up expired connections
    pub async fn cleanup_expired(&self) -> usize {
        let mut connections = self.connections.write().await;
        let mut removed = 0;

        let timeout = self.connection_timeout;

        connections.retain(|key, conn| {
            let keep = {
                let conn_read = conn.blocking_read();
                if conn_read.protocol() == Protocol::Udp {
                    !conn_read.is_expired(self.udp_timeout)
                } else {
                    !conn_read.is_expired(timeout)
                }
            };

            if !keep {
                debug!("Expiring connection for {:?}", key);
                removed += 1;
            }
            keep
        });

        if removed > 0 {
            info!("Cleaned up {} expired connections", removed);
        }

        removed
    }

    /// Get count of active connections
    pub async fn len(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    /// Check if pool is empty
    pub async fn is_empty(&self) -> bool {
        let connections = self.connections.read().await;
        connections.is_empty()
    }

    /// Update connection state
    pub async fn update_state(&self, key: &ConnectionKey, state: ConnectionState) {
        if let Some(conn) = self.get(key).await {
            let mut conn_write = conn.write().await;
            conn_write.set_state(state);
            conn_write.touch();
        }
    }

    /// Close all connections gracefully
    pub async fn close_all(&self) {
        let mut connections = self.connections.write().await;

        for (key, conn) in connections.drain() {
            let mut conn_write = conn.write().await;
            conn_write.start_close();
            debug!("Closing connection for {:?}", key);
        }

        info!("All connections closed");
    }
}

/// Shared connection pool type
pub type SharedConnectionPool = Arc<ConnectionPool>;

/// Create a new shared connection pool
pub fn new_connection_pool(
    connection_timeout: Duration,
    udp_timeout: Duration,
    tcp_keepalive: Duration,
) -> SharedConnectionPool {
    Arc::new(ConnectionPool::new(
        connection_timeout,
        udp_timeout,
        tcp_keepalive,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool_create_get_remove() {
        let pool = new_connection_pool(
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(10),
        );

        let key = ConnectionKey::from_raw(
            u32::from_le_bytes([127, 0, 0, 1]),
            u32::from_le_bytes([8, 8, 8, 8]),
            12345,
            80,
            6,
        );

        // Create a new connection
        let (conn, created) = pool.get_or_create(key).await;
        assert!(created);

        // Get same connection (should reuse)
        let (conn2, created2) = pool.get_or_create(key).await;
        assert!(!created2);
        assert!(Arc::ptr_eq(&conn, &conn2));

        // Remove connection
        assert!(pool.remove(&key).await);
        assert!(!pool.remove(&key).await);

        // Pool is empty
        assert!(pool.is_empty().await);
    }

    #[tokio::test]
    async fn test_connection_key_from_raw() {
        let key = ConnectionKey::from_raw(0x0100007f, 0x08080808, 80, 443, 6);
        assert_eq!(key.protocol(), Protocol::Tcp);
    }
}
