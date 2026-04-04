//! Connection pool for connection reuse
//!
//! Manages a pool of connections keyed by 4-tuple (src_ip, dst_ip, src_port, dst_port)
//! with expiration and background cleanup.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use std::hash::{Hash, Hasher};
use tokio::time::sleep;

use crate::{Protocol, SharedConnection};

/// Connection key for pool lookup
#[derive(Debug, Clone, Copy)]
pub struct ConnectionKey {
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol
    pub protocol: Protocol,
}

impl ConnectionKey {
    /// Create a new connection key
    pub fn new(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, protocol: Protocol) -> Self {
        Self {
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            protocol,
        }
    }
}

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
            && self.protocol == other.protocol
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash only the essential parts
        match (&self.src_ip, &self.dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                src.octets().hash(state);
                dst.octets().hash(state);
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                src.octets().hash(state);
                dst.octets().hash(state);
            }
            _ => {}
        }
        self.src_port.hash(state);
        self.dst_port.hash(state);
        (self.protocol as u8).hash(state);
    }
}

/// Connection pool statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionPoolStats {
    /// Total connections in pool
    pub total: usize,
    /// Active connections (currently transferring data)
    pub active: usize,
    /// Idle connections (established but not currently active)
    pub idle: usize,
}

/// Connection entry with metadata for pool management
struct PoolEntry {
    connection: SharedConnection,
    last_checked: Instant,
}

/// Connection pool for managing and reusing connections
pub struct ConnectionPool {
    /// Connections indexed by key
    connections: RwLock<HashMap<ConnectionKey, PoolEntry>>,
    /// Connection timeout
    timeout: Duration,
    /// Maximum connections allowed (0 = unlimited)
    max_connections: usize,
    /// Stop signal for cleanup task
    cleanup_stopped: RwLock<bool>,
}

impl ConnectionPool {
    /// Create a new connection pool with default limits
    pub fn new(timeout: Duration) -> Self {
        Self::with_limits(timeout, 0, 10000)
    }

    /// Create a new connection pool with custom limits
    ///
    /// # Arguments
    /// * `timeout` - Idle timeout after which connections are removed
    /// * `max_connections` - Maximum total connections (0 = unlimited)
    /// * `cleanup_interval` - Interval between cleanup runs in seconds
    pub fn with_limits(timeout: Duration, max_connections: usize, _cleanup_interval: u64) -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            timeout,
            max_connections,
            cleanup_stopped: RwLock::new(false),
        }
    }

    /// Get a connection from the pool
    pub async fn get(&self, key: &ConnectionKey) -> Option<SharedConnection> {
        let conns = self.connections.read().await;
        conns.get(key).map(|entry| entry.connection.clone())
    }

    /// Insert a connection into the pool
    ///
    /// Returns false if pool is at capacity
    pub async fn insert(&self, key: ConnectionKey, conn: SharedConnection) -> bool {
        let mut conns = self.connections.write().await;

        // Check capacity if limit is set
        if self.max_connections > 0 && conns.len() >= self.max_connections {
            return false;
        }

        conns.insert(
            key,
            PoolEntry {
                connection: conn,
                last_checked: Instant::now(),
            },
        );
        true
    }

    /// Remove a connection from the pool
    pub async fn remove(&self, key: &ConnectionKey) -> Option<SharedConnection> {
        let mut conns = self.connections.write().await;
        conns.remove(key).map(|entry| entry.connection)
    }

    /// Get the number of connections in the pool
    pub async fn len(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Check if the pool is empty
    pub async fn is_empty(&self) -> bool {
        self.connections.read().await.is_empty()
    }

    /// Get pool statistics
    pub async fn stats(&self) -> ConnectionPoolStats {
        let conns = self.connections.read().await;
        let mut total = 0;
        let mut active = 0;
        let mut idle = 0;

        for entry in conns.values() {
            total += 1;
            let state = entry.connection.read().await.state();
            if state.is_active() {
                active += 1;
            } else {
                idle += 1;
            }
        }

        ConnectionPoolStats { total, active, idle }
    }

    /// Get the timeout duration
    #[allow(dead_code)]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Get the max connections limit
    #[allow(dead_code)]
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Start the cleanup loop to remove expired connections
    ///
    /// This runs indefinitely until stop_cleanup() is called or the pool is dropped.
    /// Call this as a background task.
    pub async fn cleanup_loop(&self) {
        let cleanup_interval = Duration::from_secs(10);

        loop {
            sleep(cleanup_interval).await;

            // Check if we should stop
            {
                let stopped = self.cleanup_stopped.read().await;
                if *stopped {
                    break;
                }
            }

            self.cleanup_expired().await;
        }
    }

    /// Stop the cleanup loop
    pub async fn stop_cleanup(&self) {
        let mut stopped = self.cleanup_stopped.write().await;
        *stopped = true;
    }

    /// Cleanup expired connections
    pub async fn cleanup_expired(&self) -> usize {
        let mut conns = self.connections.write().await;
        let mut removed = 0;

        conns.retain(|_key, entry| {
            // Check if connection is in a terminal state or expired
            let is_expired = match entry.connection.try_read() {
                Ok(guard) => {
                    let state = guard.state();
                    // Remove if closed or if idle time exceeds timeout
                    state.is_terminal() || entry.last_checked.elapsed() >= self.timeout
                }
                Err(_) => {
                    // Couldn't acquire lock, be conservative and keep it
                    false
                }
            };

            if is_expired {
                removed += 1;
                false // remove
            } else {
                true // keep
            }
        });

        removed
    }
}

/// Shared connection pool type
pub type SharedConnectionPool = Arc<ConnectionPool>;

/// Create a new connection pool
pub fn new_connection_pool(timeout: Duration) -> SharedConnectionPool {
    Arc::new(ConnectionPool::new(timeout))
}

/// Create a new connection pool with limits
#[allow(dead_code)]
pub fn new_connection_pool_with_limits(
    timeout: Duration,
    max_connections: usize,
    cleanup_interval: u64,
) -> SharedConnectionPool {
    Arc::new(ConnectionPool::with_limits(
        timeout,
        max_connections,
        cleanup_interval,
    ))
}
