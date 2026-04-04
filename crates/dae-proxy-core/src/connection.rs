//! Connection management for dae-proxy-core
//!
//! Tracks individual TCP/UDP connections with state and timing information.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
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

    /// Update state
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Shared connection type
pub type SharedConnection = Arc<RwLock<Connection>>;

/// Create a new shared connection
pub fn new_connection(src: SocketAddr, dst: SocketAddr, protocol: Protocol) -> SharedConnection {
    Arc::new(RwLock::new(Connection::new(src, dst, protocol)))
}
