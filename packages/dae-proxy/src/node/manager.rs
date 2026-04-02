//! NodeManager trait for node lifecycle management
//!
//! This module defines the NodeManager trait for managing
//! node registration, selection, and latency tracking.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

pub use super::node::{Node, NodeError, NodeId};

/// Selection policy for node selection
#[derive(Debug, Clone)]
pub enum SelectionPolicy {
    /// Select the node with lowest latency
    LowestLatency,
    /// Select a specific node by ID
    Specific(NodeId),
    /// Select a random available node
    Random,
    /// Select nodes in round-robin fashion
    RoundRobin,
    /// Prefer direct routing (no proxy)
    PreferDirect,
}

/// NodeManager trait - manages node lifecycle and selection
///
/// This trait provides the core functionality for:
/// - Node registration and lookup
/// - Node selection based on policies
/// - Latency tracking and updates
/// - Health state management
#[async_trait]
pub trait NodeManager: Send + Sync {
    /// Select a node based on the given policy
    async fn select(&self, policy: &SelectionPolicy) -> Option<Arc<dyn Node>>;

    /// Get a specific node by ID
    fn get(&self, id: &NodeId) -> Option<Arc<dyn Node>>;

    /// Get all registered nodes
    async fn all_nodes(&self) -> Vec<Arc<dyn Node>>;

    /// Get all available (online) nodes
    async fn available_nodes(&self) -> Vec<Arc<dyn Node>>;

    /// Update the latency for a specific node
    async fn update_latency(&self, node_id: &NodeId, latency: u32);

    /// Mark a node as offline
    async fn set_offline(&self, node_id: &NodeId);

    /// Get the latency for a specific node (if known)
    fn get_latency(&self, node_id: &NodeId) -> Option<u32>;

    /// Run latency tests for all nodes and return results
    async fn run_latency_test(&self) -> HashMap<NodeId, u32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selection_policy_lowest_latency() {
        let policy = SelectionPolicy::LowestLatency;
        assert!(matches!(policy, SelectionPolicy::LowestLatency));
    }

    #[test]
    fn test_selection_policy_specific() {
        let policy = SelectionPolicy::Specific("node1".to_string());
        assert!(matches!(policy, SelectionPolicy::Specific(_)));
        if let SelectionPolicy::Specific(id) = policy {
            assert_eq!(id, "node1");
        }
    }

    #[test]
    fn test_selection_policy_random() {
        let policy = SelectionPolicy::Random;
        assert!(matches!(policy, SelectionPolicy::Random));
    }

    #[test]
    fn test_selection_policy_round_robin() {
        let policy = SelectionPolicy::RoundRobin;
        assert!(matches!(policy, SelectionPolicy::RoundRobin));
    }

    #[test]
    fn test_selection_policy_prefer_direct() {
        let policy = SelectionPolicy::PreferDirect;
        assert!(matches!(policy, SelectionPolicy::PreferDirect));
    }

    #[test]
    fn test_selection_policy_clone() {
        let policy1 = SelectionPolicy::Specific("node1".to_string());
        let policy2 = policy1.clone();

        if let SelectionPolicy::Specific(id1) = policy1 {
            if let SelectionPolicy::Specific(id2) = policy2 {
                assert_eq!(id1, id2);
            } else {
                panic!("Expected Specific");
            }
        } else {
            panic!("Expected Specific");
        }
    }
}
