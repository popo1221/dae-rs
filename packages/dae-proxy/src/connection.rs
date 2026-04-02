//! Connection management for dae-proxy
//!
//! Tracks individual TCP/UDP connections with state and timing information.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tokio::time::{Duration, Interval};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// New connection, not yet established
    New,
    /// Connection is active and transferring data
    Active,
    /// Connection is being closed gracefully
    Closing,
    /// Connection has been closed
    Closed,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::New
    }
}

/// Protocol type for the connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Tcp
    }
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
