//! TCP session handling for TUN proxy

use std::time::{Duration, Instant};

/// TCP session state for TUN proxy
#[derive(Debug, Clone)]
pub enum TcpSessionState {
    /// Waiting for connection setup
    SynSent,
    /// Connection established
    Established,
    /// Fin sent
    FinWait,
    /// Session closed
    Closed,
}

/// TCP session for TUN transparent proxy
pub struct TcpTunSession {
    /// Session state
    pub state: TcpSessionState,
    /// Last activity time
    pub last_activity: Instant,
    /// Client-side TUN sequence
    pub client_seq: u32,
    /// Server-side TUN sequence
    pub server_seq: u32,
    /// Client-side acknowledgment
    pub client_ack: u32,
    /// Server-side acknowledgment
    pub server_ack: u32,
}

impl TcpTunSession {
    /// Create a new TCP session
    pub fn new() -> Self {
        Self {
            state: TcpSessionState::SynSent,
            last_activity: Instant::now(),
            client_seq: 0,
            server_seq: 0,
            client_ack: 0,
            server_ack: 0,
        }
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

impl Default for TcpTunSession {
    fn default() -> Self {
        Self::new()
    }
}
