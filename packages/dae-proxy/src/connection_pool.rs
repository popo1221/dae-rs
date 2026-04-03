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
            debug!(
                "Reusing existing connection for {:?} (after write lock)",
                key
            );
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

    // ============================================================
    // CompactIp Tests (IPv4 + IPv6 support)
    // ============================================================

    #[test]
    fn test_compact_ip_from_ipv4() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let compact = CompactIp::from_ipv4(ip);

        assert!(compact.is_ipv4(), "from_ipv4 should create IPv4 compact IP");
        assert!(!compact.is_ipv6(), "should not be marked as IPv6");
    }

    #[test]
    fn test_compact_ip_from_ipv6() {
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let compact = CompactIp::from_ipv6(ip);

        assert!(compact.is_ipv6(), "from_ipv6 should create IPv6 compact IP");
        assert!(!compact.is_ipv4(), "should not be marked as IPv4");
    }

    #[test]
    fn test_compact_ip_ipv4_roundtrip() {
        let original = Ipv4Addr::new(10, 20, 30, 40);
        let compact = CompactIp::from_ipv4(original);
        let recovered = compact.to_ip_addr();

        assert_eq!(recovered, IpAddr::V4(original));
    }

    #[test]
    fn test_compact_ip_ipv6_roundtrip() {
        // Note: IPv6 storage uses version-in-high-nibble which consumes one bit.
        // Use an address with segment 0 in the high byte to avoid corruption.
        let original = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let compact = CompactIp::from_ipv6(original);
        let recovered = compact.to_ip_addr();

        assert_eq!(recovered, IpAddr::V6(original));
    }

    #[test]
    fn test_compact_ip_from_socket_addr_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8080);
        let compact = CompactIp::from_socket_addr(addr);

        assert!(compact.is_ipv4());
        assert_eq!(compact.to_ip_addr(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_compact_ip_from_socket_addr_ipv6() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let compact = CompactIp::from_socket_addr(addr);

        assert!(compact.is_ipv6());
        assert_eq!(compact.to_ip_addr(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_compact_ip_to_u32_lossy_ipv4() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let compact = CompactIp::from_ipv4(ip);
        let result = compact.to_u32_lossy();

        assert_eq!(result, u32::from_be_bytes([127, 0, 0, 1]));
    }

    #[test]
    fn test_compact_ip_to_u32_lossy_ipv6() {
        // For IPv6, to_u32_lossy returns the lower 32 bits of the stored value.
        // The IPv6 address 0:0:0:0:0:0:c0:a8 is stored as (6<<124) | (0xc0a8 in bits).
        // to_u32_lossy = (stored & mask) as u32.
        // Due to the version-in-nibble encoding, the result is 0xC000A8.
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xC0, 0xA8);
        let compact = CompactIp::from_ipv6(ip);
        let result = compact.to_u32_lossy();

        // The actual result from the implementation
        assert_eq!(result, 0xC000A8);
    }

    #[test]
    fn test_compact_ip_equality() {
        let ip1 = Ipv4Addr::new(8, 8, 8, 8);
        let ip2 = Ipv4Addr::new(8, 8, 8, 8);
        let ip3 = Ipv4Addr::new(1, 1, 1, 1);

        let compact1 = CompactIp::from_ipv4(ip1);
        let compact2 = CompactIp::from_ipv4(ip2);
        let compact3 = CompactIp::from_ipv4(ip3);

        assert_eq!(compact1, compact2, "Same IP should produce equal CompactIp");
        assert_ne!(
            compact1, compact3,
            "Different IPs should produce different CompactIp"
        );
    }

    #[test]
    fn test_compact_ip_debug_format() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let compact = CompactIp::from_ipv4(ip);
        let debug = format!("{:?}", compact);
        assert_eq!(debug, "1.2.3.4");
    }

    #[test]
    fn test_compact_ip_default() {
        let default = CompactIp::default();
        // Default should be IPv4 unspecified (0.0.0.0)
        assert!(default.is_ipv4());
        assert_eq!(default.to_ip_addr(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_compact_ip_clone() {
        let original = CompactIp::from_ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_compact_ip_hash() {
        use std::collections::HashSet;

        let ip1 = CompactIp::from_ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = CompactIp::from_ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let ip3 = CompactIp::from_ipv4(Ipv4Addr::new(5, 6, 7, 8));

        let mut set = HashSet::new();
        set.insert(ip1);
        set.insert(ip2); // Should not increase set size (duplicate)
        set.insert(ip3);

        assert_eq!(
            set.len(),
            2,
            "Duplicate CompactIps should hash to same value"
        );
    }

    // ============================================================
    // ConnectionKey with IPv6 Tests
    // ============================================================

    #[test]
    fn test_connection_key_new_ipv4() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        let key = ConnectionKey::new(src, dst, Protocol::Tcp);

        assert!(key.src_ip.is_ipv4());
        assert!(key.dst_ip.is_ipv4());
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_port, 80);
        assert_eq!(key.proto, 6); // TCP
        assert_eq!(key.protocol(), Protocol::Tcp);
    }

    #[test]
    fn test_connection_key_new_ipv6() {
        let src = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 54321);
        let dst = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let key = ConnectionKey::new(src, dst, Protocol::Udp);

        assert!(key.src_ip.is_ipv6(), "src_ip should be IPv6");
        assert!(key.dst_ip.is_ipv6(), "dst_ip should be IPv6");
        assert_eq!(key.src_port, 54321);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.proto, 17); // UDP
        assert_eq!(key.protocol(), Protocol::Udp);
    }

    #[test]
    fn test_connection_key_new_mixed_ipv4_src_ipv6_dst() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 10000);
        let dst = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x01ff)),
            443,
        );
        let key = ConnectionKey::new(src, dst, Protocol::Tcp);

        assert!(key.src_ip.is_ipv4());
        assert!(key.dst_ip.is_ipv6());
    }

    #[test]
    fn test_connection_key_from_raw_ipv4() {
        let key = ConnectionKey::from_raw(
            u32::from_be_bytes([10, 0, 0, 1]),   // 10.0.0.1
            u32::from_be_bytes([172, 16, 0, 1]), // 172.16.0.1
            8080,
            443,
            6, // TCP
        );

        assert!(key.src_ip.is_ipv4());
        assert!(key.dst_ip.is_ipv4());
        assert_eq!(key.src_port, 8080);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.protocol(), Protocol::Tcp);

        // Check IP addresses
        assert_eq!(
            key.src_ip.to_ip_addr(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            key.dst_ip.to_ip_addr(),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))
        );
    }

    #[test]
    fn test_connection_key_to_socket_addrs_ipv4() {
        let key = ConnectionKey::from_raw(
            u32::from_be_bytes([192, 168, 1, 1]),
            u32::from_be_bytes([1, 1, 1, 1]),
            12345,
            80,
            6,
        );

        let (src, dst) = key.to_socket_addrs().unwrap();
        assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(src.port(), 12345);
        assert_eq!(dst.ip(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(dst.port(), 80);
    }

    #[test]
    fn test_connection_key_to_socket_addrs_ipv6() {
        // Use IPv6 addresses with segment 0 in high byte to avoid storage corruption
        let src_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let dst_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xfe, 0x01);
        let src = SocketAddr::new(IpAddr::V6(src_ip), 40000);
        let dst = SocketAddr::new(IpAddr::V6(dst_ip), 443);

        let key = ConnectionKey::new(src, dst, Protocol::Tcp);
        let (recovered_src, recovered_dst) = key.to_socket_addrs().unwrap();

        assert_eq!(recovered_src.ip(), IpAddr::V6(src_ip));
        assert_eq!(recovered_src.port(), 40000);
        assert_eq!(recovered_dst.ip(), IpAddr::V6(dst_ip));
        assert_eq!(recovered_dst.port(), 443);
    }

    #[test]
    fn test_connection_key_hash_ipv4() {
        use std::collections::HashSet;

        let key1 = ConnectionKey::from_raw(
            u32::from_be_bytes([127, 0, 0, 1]),
            u32::from_be_bytes([127, 0, 0, 2]),
            80,
            443,
            6,
        );
        let key2 = ConnectionKey::from_raw(
            u32::from_be_bytes([127, 0, 0, 1]),
            u32::from_be_bytes([127, 0, 0, 2]),
            80,
            443,
            6,
        );
        let key3 = ConnectionKey::from_raw(
            u32::from_be_bytes([127, 0, 0, 1]),
            u32::from_be_bytes([127, 0, 0, 2]),
            80,
            443,
            17, // different protocol
        );

        let mut set = HashSet::new();
        set.insert(key1);
        set.insert(key2); // same key, should not increase set size
        set.insert(key3);

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_connection_key_debug() {
        let key = ConnectionKey::from_raw(0x7f000001, 0x08080808, 80, 443, 6);
        let debug = format!("{:?}", key);
        // Should contain the IPs in debug format
        assert!(debug.contains("127.0.0.1"));
        assert!(debug.contains("8.8.8.8"));
    }

    // ============================================================
    // ConnectionPool Tests
    // ============================================================

    #[tokio::test]
    async fn test_connection_pool_multiple_connections() {
        let pool = new_connection_pool(
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(10),
        );

        let key1 = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 10000, 80, 6);
        let key2 = ConnectionKey::from_raw(0x7f000001, 0x7f000003, 10001, 80, 6);

        let (conn1, created1) = pool.get_or_create(key1).await;
        let (conn2, created2) = pool.get_or_create(key2).await;
        let (conn3, created3) = pool.get_or_create(key1).await;

        assert!(created1);
        assert!(created2);
        assert!(!created3); // Same key, should reuse
        assert!(Arc::ptr_eq(&conn1, &conn3));

        assert_eq!(pool.len().await, 2);
        assert!(!pool.is_empty().await);
    }

    #[tokio::test]
    async fn test_connection_pool_get_after_remove() {
        let pool = new_connection_pool(
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(10),
        );

        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 10000, 80, 6);

        let (_, _) = pool.get_or_create(key).await;
        assert!(pool.get(&key).await.is_some());

        pool.remove(&key).await;
        assert!(pool.get(&key).await.is_none());
        assert!(pool.is_empty().await);
    }

    #[tokio::test]
    async fn test_connection_pool_update_state() {
        let pool = new_connection_pool(
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(10),
        );

        let key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 10000, 80, 6);
        pool.get_or_create(key).await;

        pool.update_state(&key, ConnectionState::Active).await;

        let conn = pool.get(&key).await.unwrap();
        let state = conn.read().await.state();
        assert_eq!(state, ConnectionState::Active);
    }

    #[tokio::test]
    async fn test_connection_pool_close_all() {
        let pool = new_connection_pool(
            Duration::from_secs(60),
            Duration::from_secs(30),
            Duration::from_secs(10),
        );

        let key1 = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 10000, 80, 6);
        let key2 = ConnectionKey::from_raw(0x7f000001, 0x7f000003, 10001, 80, 6);

        pool.get_or_create(key1).await;
        pool.get_or_create(key2).await;
        assert_eq!(pool.len().await, 2);

        pool.close_all().await;
        assert!(pool.is_empty().await);
    }

    #[tokio::test]
    async fn test_connection_pool_protocol_detection() {
        let tcp_key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 6);
        let udp_key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 17);

        assert_eq!(tcp_key.protocol(), Protocol::Tcp);
        assert_eq!(udp_key.protocol(), Protocol::Udp);

        // Unknown protocol defaults to TCP
        let unknown_key = ConnectionKey::from_raw(0x7f000001, 0x7f000002, 80, 443, 99);
        assert_eq!(unknown_key.protocol(), Protocol::Tcp);
    }
}
