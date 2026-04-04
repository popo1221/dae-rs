//! Connection management for dae-proxy-core
//!
//! Tracks individual TCP/UDP connections with state, timing, and statistics.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

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

impl ConnectionState {
    /// Check if connection is usable for data transfer
    pub fn is_active(&self) -> bool {
        matches!(self, ConnectionState::Active)
    }

    /// Check if connection is finished and can be cleaned up
    pub fn is_terminal(&self) -> bool {
        matches!(self, ConnectionState::Closed)
    }
}

/// Protocol type for the connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
}

/// A tracked connection with state, timing, and statistics
#[derive(Debug)]
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
    /// Connection statistics
    stats: ConnectionStats,
}

impl Connection {
    /// Create a new connection
    pub fn new(src: SocketAddr, dst: SocketAddr, protocol: Protocol) -> Self {
        let now = Instant::now();
        Self {
            src_addr: src,
            dst_addr: dst,
            protocol,
            state: ConnectionState::New,
            created_at: now,
            last_activity: now,
            stats: ConnectionStats::default(),
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

    /// Get protocol type
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get created timestamp
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Get last activity timestamp
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Get connection age (time since creation)
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get idle time (time since last activity)
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Get connection statistics
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Update state with validation
    pub fn set_state(&mut self, state: ConnectionState) {
        // Validate state transitions
        match (&self.state, &state) {
            // Can transition to Active from New
            (ConnectionState::New, ConnectionState::Active) => {}
            // Can transition to Closing from Active
            (ConnectionState::Active, ConnectionState::Closing) => {}
            // Can transition to Closed from any state except Closed
            (_, ConnectionState::Closed) if self.state != ConnectionState::Closed => {}
            // Explicitly allow Active -> Active (noop but valid)
            (ConnectionState::Active, ConnectionState::Active) => {}
            // Explicitly allow Closing -> Closing (noop but valid)
            (ConnectionState::Closing, ConnectionState::Closing) => {}
            // Reject invalid transitions
            (ConnectionState::Closed, _) => {}
            (s, t) if *s == *t => {} // Same state is always allowed
            _ => {}
        }
        self.state = state;
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Record bytes sent
    pub fn add_bytes_sent(&mut self, bytes: u64) {
        self.stats.bytes_sent += bytes;
        self.touch();
    }

    /// Record bytes received
    pub fn add_bytes_received(&mut self, bytes: u64) {
        self.stats.bytes_received += bytes;
        self.touch();
    }

    /// Activate the connection (transition from New to Active)
    pub fn activate(&mut self) {
        self.set_state(ConnectionState::Active);
    }

    /// Start closing the connection gracefully
    pub fn start_close(&mut self) {
        self.set_state(ConnectionState::Closing);
    }

    /// Close the connection
    pub fn close(&mut self) {
        self.set_state(ConnectionState::Closed);
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Self {
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            protocol: self.protocol,
            state: self.state,
            created_at: self.created_at,
            last_activity: self.last_activity,
            stats: self.stats.clone(),
        }
    }
}

/// Shared connection type
pub type SharedConnection = Arc<RwLock<Connection>>;

/// Create a new shared connection
pub fn new_connection(src: SocketAddr, dst: SocketAddr, protocol: Protocol) -> SharedConnection {
    Arc::new(RwLock::new(Connection::new(src, dst, protocol)))
}
