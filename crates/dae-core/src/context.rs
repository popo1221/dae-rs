//! Context - Request context with source and destination information

use std::net::SocketAddr;

/// Request context containing source and destination information
///
/// This is the fundamental context type passed through the proxy pipeline.
/// It contains the source (client) and destination (target) socket addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Source socket address (client side)
    pub source: SocketAddr,
    /// Destination socket address (target server)
    pub destination: SocketAddr,
}

impl Context {
    /// Create a new context with source and destination
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            source,
            destination,
        }
    }

    /// Create a context with default addresses (for testing)
    pub fn default_context() -> Self {
        Self {
            source: "127.0.0.1:0".parse().unwrap(),
            destination: "127.0.0.1:0".parse().unwrap(),
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::default_context()
    }
}
