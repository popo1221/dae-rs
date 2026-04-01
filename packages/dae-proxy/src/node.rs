//! Node types and identifiers for dae-proxy
//!
//! This module provides node-related types used in proxy routing decisions.

/// Node identifier - uniquely identifies a proxy node in the configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub usize);

impl NodeId {
    /// Create a new NodeId
    pub fn new(id: usize) -> Self {
        Self(id)
    }
    
    /// Get the inner value
    pub fn inner(&self) -> usize {
        self.0
    }
}

impl From<usize> for NodeId {
    fn from(id: usize) -> Self {
        Self(id)
    }
}

impl From<NodeId> for usize {
    fn from(id: NodeId) -> Self {
        id.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node#{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id() {
        let id = NodeId::new(42);
        assert_eq!(id.inner(), 42);
        assert_eq!(id.to_string(), "Node#42");
        
        let id2 = NodeId::from(100);
        assert_eq!(id2.inner(), 100);
        
        let usizes: usize = id.into();
        assert_eq!(usizes, 42);
    }
}
