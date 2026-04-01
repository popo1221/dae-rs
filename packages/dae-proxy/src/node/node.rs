//! Node trait and types for dae-proxy node management
//!
//! This module defines the core Node trait that all proxy node types implement.

use async_trait::async_trait;

/// Node ID type - uniquely identifies a node in the configuration
pub type NodeId = String;

/// Node trait - all node types implement this trait
///
/// This trait defines the common interface for all proxy nodes,
/// including direct routing nodes and upstream proxy nodes.
#[async_trait]
pub trait Node: Send + Sync {
    /// Get the node's unique identifier
    fn id(&self) -> &NodeId;
    
    /// Get the node's display name
    fn name(&self) -> &str;
    
    /// Get the protocol name this node uses
    fn protocol(&self) -> &'static str;
    
    /// Ping the node and return latency in milliseconds
    async fn ping(&self) -> Result<u32, NodeError>;
    
    /// Check if the node is currently available
    async fn is_available(&self) -> bool;
}

/// Node errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum NodeError {
    #[error("timeout")]
    Timeout,
    
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("node unavailable")]
    Unavailable,
}

impl NodeError {
    /// Check if this error indicates a temporary failure
    pub fn is_retryable(&self) -> bool {
        matches!(self, NodeError::Timeout)
    }
}
