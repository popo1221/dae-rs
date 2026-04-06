//! Connection management for dae-proxy
//!
//! Tracks individual TCP/UDP connections with state and timing information.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tokio::time::{Duration, Interval};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// New connection, not yet established
    #[default]
    New,
    /// Connection is active and transferring data
    Active,
    /// Connection is being closed gracefully
    Closing,
    /// Connection has been closed
    Closed,
}

/// Protocol type for the connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

/// A tracked connection with state and timing
pub struct Connection {
    /// Source socket address
    src_addr: SocketAddr,
    /// Destination socket address
    dst_addr: SocketAddr,
    /// Protocol type
    protocol: Protocol,
    /// Connection state
    state: ConnectionState,
    /// When the connection was created
    created_at: Instant,
    /// Last activity timestamp
    last_activity: Instant,
    /// Keepalive interval (for future TCP keepalive support)
    #[allow(dead_code)]
    keepalive_interval: Duration,
    /// Keepalive timer (for future TCP keepalive support)
    #[allow(dead_code)]
    keepalive_timer: Option<Interval>,
}

impl Connection {
    /// Create a new connection
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        protocol: Protocol,
        keepalive_interval: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            src_addr,
            dst_addr,
            protocol,
            state: ConnectionState::New,
            created_at: now,
            last_activity: now,
            keepalive_interval,
            keepalive_timer: None,
        }
    }

    /// Get source address
    pub fn src_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Get destination address
    pub fn dst_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    /// Get protocol
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Get current state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Set state
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if connection has timed out
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Get age of connection
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Mark connection as established
    pub fn establish(&mut self) {
        self.state = ConnectionState::Active;
        self.touch();
    }

    /// Initiate graceful close
    pub fn start_close(&mut self) {
        self.state = ConnectionState::Closing;
        self.touch();
    }

    /// Mark connection as closed
    pub fn close(&mut self) {
        self.state = ConnectionState::Closed;
        self.touch();
    }

    /// Check if connection is active
    pub fn is_active(&self) -> bool {
        self.state == ConnectionState::Active
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .field("protocol", &self.protocol)
            .field("state", &self.state)
            .field("age", &self.age())
            .field("idle", &self.idle_time())
            .finish()
    }
}

/// Wrapper for Arc<dyn Connection> to allow type erasure for storage
pub type SharedConnection = Arc<RwLock<Connection>>;

/// Create a new shared connection
pub fn new_connection(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    protocol: Protocol,
    keepalive_interval: Duration,
) -> SharedConnection {
    Arc::new(RwLock::new(Connection::new(
        src_addr,
        dst_addr,
        protocol,
        keepalive_interval,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_default() {
        assert_eq!(ConnectionState::default(), ConnectionState::New);
    }

    #[test]
    fn test_protocol_default() {
        assert_eq!(Protocol::default(), Protocol::Tcp);
    }

    #[test]
    fn test_connection_state_all_variants() {
        assert_eq!(ConnectionState::New, ConnectionState::New);
        assert_eq!(ConnectionState::Active, ConnectionState::Active);
        assert_eq!(ConnectionState::Closing, ConnectionState::Closing);
        assert_eq!(ConnectionState::Closed, ConnectionState::Closed);
    }

    #[test]
    fn test_protocol_all_variants() {
        assert_eq!(Protocol::Tcp, Protocol::Tcp);
        assert_eq!(Protocol::Udp, Protocol::Udp);
    }

    #[test]
    fn test_connection_new_ipv4() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        assert_eq!(conn.src_addr(), src);
        assert_eq!(conn.dst_addr(), dst);
        assert_eq!(conn.protocol(), Protocol::Tcp);
        assert_eq!(conn.state(), ConnectionState::New);
        assert!(!conn.is_active());
    }

    #[test]
    fn test_connection_new_ipv6() {
        let src: SocketAddr = "[::1]:8080".parse().unwrap();
        let dst: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();
        let conn = Connection::new(src, dst, Protocol::Udp, Duration::from_secs(60));

        assert_eq!(conn.protocol(), Protocol::Udp);
        assert_eq!(conn.state(), ConnectionState::New);
    }

    #[test]
    fn test_connection_state_transitions() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let mut conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        assert_eq!(conn.state(), ConnectionState::New);

        conn.establish();
        assert_eq!(conn.state(), ConnectionState::Active);
        assert!(conn.is_active());

        conn.start_close();
        assert_eq!(conn.state(), ConnectionState::Closing);
        assert!(!conn.is_active());

        conn.close();
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert!(!conn.is_active());
    }

    #[test]
    fn test_connection_set_state() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let mut conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        conn.set_state(ConnectionState::Active);
        assert_eq!(conn.state(), ConnectionState::Active);

        conn.set_state(ConnectionState::Closed);
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[test]
    fn test_connection_touch_updates_activity() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let mut conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        let initial_idle = conn.idle_time();
        std::thread::sleep(Duration::from_millis(10));
        conn.touch();
        let new_idle = conn.idle_time();

        // After touch, idle time should be very small
        assert!(new_idle < initial_idle + Duration::from_millis(50));
    }

    #[test]
    fn test_connection_age() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        // Age should be very small initially
        let age = conn.age();
        assert!(age < Duration::from_secs(1));
    }

    #[test]
    fn test_connection_is_expired_after_wait() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        // Immediately after creation, should not be expired
        assert!(!conn.is_expired(Duration::from_secs(30)));

        // Wait for timeout to pass
        std::thread::sleep(Duration::from_millis(15));
        // Now with a very short timeout it should be expired
        assert!(conn.is_expired(Duration::from_millis(10)));
    }

    #[test]
    fn test_connection_debug_format() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("Connection"));
        assert!(debug_str.contains("192.168.1.100"));
        assert!(debug_str.contains("8.8.8.8"));
        assert!(debug_str.contains("Tcp"));
    }

    #[tokio::test]
    async fn test_new_connection_shared() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let shared = new_connection(src, dst, Protocol::Tcp, Duration::from_secs(30));

        // Verify we can read from the shared connection
        let conn = shared.read().await;
        assert_eq!(conn.src_addr(), src);
        assert_eq!(conn.dst_addr(), dst);
        assert_eq!(conn.protocol(), Protocol::Tcp);
    }

    #[tokio::test]
    async fn test_connection_write_and_read_state() {
        let src: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let shared = new_connection(src, dst, Protocol::Udp, Duration::from_secs(30));

        {
            let mut conn = shared.write().await;
            conn.establish();
        }

        {
            let conn = shared.read().await;
            assert!(conn.is_active());
            assert_eq!(conn.protocol(), Protocol::Udp);
        }
    }

    #[tokio::test]
    async fn test_src_addr_getter() {
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));
        assert_eq!(conn.src_addr(), src);
    }

    #[tokio::test]
    async fn test_dst_addr_getter() {
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let conn = Connection::new(src, dst, Protocol::Udp, Duration::from_secs(60));
        assert_eq!(conn.dst_addr(), dst);
    }

    #[tokio::test]
    async fn test_idle_time_after_touch() {
        let src: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        // Initial idle time should be very small
        let initial_idle = conn.idle_time();
        assert!(initial_idle < Duration::from_millis(10));

        // Wait a bit then touch
        tokio::time::sleep(Duration::from_millis(50)).await;
        conn.touch();

        // After touch, idle_time should be small again
        let new_idle = conn.idle_time();
        assert!(new_idle < Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_establish_sets_active() {
        let src: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        assert_eq!(conn.state(), ConnectionState::New);
        conn.establish();
        assert_eq!(conn.state(), ConnectionState::Active);
        assert!(conn.is_active());
    }

    #[tokio::test]
    async fn test_start_close_sets_closing() {
        let src: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        conn.establish();
        assert!(conn.is_active());

        conn.start_close();
        assert_eq!(conn.state(), ConnectionState::Closing);
        assert!(!conn.is_active());
    }

    #[tokio::test]
    async fn test_close_sets_closed() {
        let src: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        conn.establish();
        conn.close();
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert!(!conn.is_active());
    }

    #[tokio::test]
    async fn test_is_active_only_when_established() {
        let src: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));

        // Initially not active
        assert!(!conn.is_active());

        // After establish, is active
        conn.establish();
        assert!(conn.is_active());

        // After start_close, not active
        conn.start_close();
        assert!(!conn.is_active());

        // After close, not active
        conn.close();
        assert!(!conn.is_active());
    }

    #[tokio::test]
    async fn test_protocol_getter() {
        let src: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();

        let tcp_conn = Connection::new(src, dst, Protocol::Tcp, Duration::from_secs(30));
        assert_eq!(tcp_conn.protocol(), Protocol::Tcp);

        let udp_conn = Connection::new(src, dst, Protocol::Udp, Duration::from_secs(60));
        assert_eq!(udp_conn.protocol(), Protocol::Udp);
    }
}
