//! Connection pool for connection reuse
//!
//! Manages a pool of connections keyed by 4-tuple (src_ip, dst_ip, src_port, dst_port)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use std::hash::{Hash, Hasher};

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

/// Connection pool for managing and reusing connections
pub struct ConnectionPool {
    /// Connections indexed by key
    connections: RwLock<HashMap<ConnectionKey, SharedConnection>>,
    /// Connection timeout
    timeout: Duration,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(timeout: Duration) -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            timeout,
        }
    }

    /// Get a connection from the pool
    pub async fn get(&self, key: &ConnectionKey) -> Option<SharedConnection> {
        let conns = self.connections.read().await;
        conns.get(key).cloned()
    }

    /// Insert a connection into the pool
    pub async fn insert(&self, key: ConnectionKey, conn: SharedConnection) {
        let mut conns = self.connections.write().await;
        conns.insert(key, conn);
    }

    /// Remove a connection from the pool
    pub async fn remove(&self, key: &ConnectionKey) -> Option<SharedConnection> {
        let mut conns = self.connections.write().await;
        conns.remove(key)
    }

    /// Get the number of connections in the pool
    pub async fn len(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Check if the pool is empty
    pub async fn is_empty(&self) -> bool {
        self.connections.read().await.is_empty()
    }
}

/// Shared connection pool type
pub type SharedConnectionPool = Arc<ConnectionPool>;

/// Create a new connection pool
pub fn new_connection_pool(timeout: Duration) -> SharedConnectionPool {
    Arc::new(ConnectionPool::new(timeout))
}
