//! Context - Request context with source and destination information

use std::collections::HashMap;
use std::net::SocketAddr;

/// Request context containing source and destination information
///
/// This is the fundamental context type passed through the proxy pipeline.
/// It contains the source (client) and destination (target) socket addresses,
/// along with optional metadata for carrying additional information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Source socket address (client side)
    pub source: SocketAddr,
    /// Destination socket address (target server)
    pub destination: SocketAddr,
    /// Additional metadata for carrying extra information
    pub metadata: HashMap<String, String>,
}

impl Context {
    /// Create a new context with source and destination
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            source,
            destination,
            metadata: HashMap::new(),
        }
    }

    /// Create a context with additional metadata
    ///
    /// # Arguments
    ///
    /// * `source` - Source socket address
    /// * `destination` - Destination socket address  
    /// * `metadata` - Initial metadata entries
    pub fn with_metadata(
        source: SocketAddr,
        destination: SocketAddr,
        metadata: HashMap<String, String>,
    ) -> Self {
        Self {
            source,
            destination,
            metadata,
        }
    }

    /// Get a value from the metadata by key
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Insert a metadata entry
    ///
    /// Returns the old value if the key was already present
    pub fn insert_metadata(&mut self, key: String, value: String) -> Option<String> {
        self.metadata.insert(key, value)
    }

    /// Create a context with default addresses (for testing)
    #[allow(dead_code)]
    pub fn default_context() -> Self {
        Self {
            source: "127.0.0.1:0".parse().unwrap(),
            destination: "127.0.0.1:0".parse().unwrap(),
            metadata: HashMap::new(),
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::default_context()
    }
}
