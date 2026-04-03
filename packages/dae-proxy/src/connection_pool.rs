//! Connection pool for managing TCP/UDP connections
//!
//! Provides connection reuse by 4-tuple and expiration management.

use crate::connection::{new_connection, ConnectionState, Protocol, SharedConnection};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// 4-tuple key for connection identification
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl ConnectionKey {
    /// Create a new connection key from addresses and protocol
    ///
    /// # IPv6 Limitation
    /// IPv6 addresses are currently NOT fully supported. When an IPv6 address is
    /// encountered, a warning is logged and the connection key is created with
    /// null values (0.0.0.0:0). This means connection pooling will NOT work
    /// correctly for IPv6 connections.
    ///
    /// See GitHub Issue #60 for tracking the IPv6 support implementation.
    pub fn new(src: SocketAddr, dst: SocketAddr, proto: Protocol) -> Self {
        let (src_ip, dst_ip) = match (src.ip(), dst.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => (src.into(), dst.into()),
            (IpAddr::V6(_), _) => {
                warn!("IPv6 address detected in connection pool — IPv6 is not yet supported. See issue #60.");
                (0, 0)
            }
            _ => (0, 0),
        };
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
    pub fn from_raw(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        }
    }

    /// Convert to socket addresses
    ///
    /// # Limitation
    /// Only supports IPv4. If the connection key was created from an IPv6
    /// address (src_ip/dst_ip == 0), this returns 0.0.0.0 addresses.
    pub fn to_socket_addrs(&self) -> Option<(SocketAddr, SocketAddr)> {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(self.src_ip)), self.src_port);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(self.dst_ip)), self.dst_port);
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
