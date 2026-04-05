//! Node selector implementations
//!
//! This module provides the NodeSelector trait and implementations
//! for various node selection strategies.

use async_trait::async_trait;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use super::manager::{ConnectionFingerprint, SelectionPolicy};
use super::node::Node;

/// NodeSelector trait - implements selection logic for nodes
///
/// This trait allows for pluggable selection strategies
/// that can be configured at runtime.
#[async_trait]
pub trait NodeSelector: Send + Sync {
    /// Select a node from the given list based on policy
    async fn select(
        &self,
        nodes: &[Arc<dyn Node>],
        policy: &SelectionPolicy,
    ) -> Option<Arc<dyn Node>>;
}

/// Default node selector implementation
pub struct DefaultNodeSelector {
    /// Round-robin counter (atomic for thread safety)
    rr_counter: Arc<AtomicU32>,
}

impl DefaultNodeSelector {
    pub fn new() -> Self {
        Self {
            rr_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Get a clone of the round-robin counter (for external sync)
    pub fn rr_counter(&self) -> Arc<AtomicU32> {
        self.rr_counter.clone()
    }
}

impl Default for DefaultNodeSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NodeSelector for DefaultNodeSelector {
    async fn select(
        &self,
        nodes: &[Arc<dyn Node>],
        policy: &SelectionPolicy,
    ) -> Option<Arc<dyn Node>> {
        match policy {
            SelectionPolicy::LowestLatency => self.select_lowest_latency(nodes).await,
            SelectionPolicy::Specific(node_id) => self.select_specific(nodes, node_id).await,
            SelectionPolicy::Random => self.select_random(nodes).await,
            SelectionPolicy::RoundRobin => self.select_round_robin(nodes).await,
            SelectionPolicy::PreferDirect => self.select_prefer_direct(nodes).await,
            SelectionPolicy::ConsistentHashing(fp) => self.select_consistent_hash(nodes, fp).await,
            SelectionPolicy::StickySession(fp) => self.select_sticky_session(nodes, fp).await,
            SelectionPolicy::UrlHash(fp) => self.select_url_hash(nodes, fp).await,
        }
    }
}

impl DefaultNodeSelector {
    /// Select node with lowest latency
    async fn select_lowest_latency(&self, nodes: &[Arc<dyn Node>]) -> Option<Arc<dyn Node>> {
        let mut available_nodes = Vec::new();

        for node in nodes.iter() {
            if node.is_available().await {
                available_nodes.push(node.clone());
            }
        }

        if available_nodes.is_empty() {
            return None;
        }

        // Sort by ping latency (lowest first)
        let mut with_latency: Vec<_> = available_nodes
            .iter()
            .map(|n| async { (n.clone(), n.ping().await.ok()) })
            .collect::<Vec<_>>();

        // Collect all ping results
        let mut results = Vec::new();
        for f in with_latency.drain(..) {
            results.push(f.await);
        }

        // Sort by latency, putting None (unreachable) at the end
        results.sort_by(|a, b| match (a.1, b.1) {
            (Some(lat_a), Some(lat_b)) => lat_a.cmp(&lat_b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });

        results.first().map(|(n, _)| n.clone())
    }

    /// Select a specific node by ID
    async fn select_specific(
        &self,
        nodes: &[Arc<dyn Node>],
        node_id: &str,
    ) -> Option<Arc<dyn Node>> {
        for node in nodes.iter() {
            if node.id() == node_id && node.is_available().await {
                return Some(node.clone());
            }
        }
        None
    }

    /// Select a random available node
    async fn select_random(&self, nodes: &[Arc<dyn Node>]) -> Option<Arc<dyn Node>> {
        use rand::seq::SliceRandom;

        // Collect availability for all nodes
        let availability: Vec<bool> =
            futures::future::join_all(nodes.iter().map(|n| n.is_available())).await;

        let available: Vec<_> = nodes
            .iter()
            .zip(availability.iter())
            .filter(|&(_, &is_avail)| is_avail)
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>();

        if available.is_empty() {
            return None;
        }

        let mut rng = rand::thread_rng();
        available.choose(&mut rng).cloned()
    }

    /// Select first available node (fallback for round-robin)
    async fn select_first_available(&self, nodes: &[Arc<dyn Node>]) -> Option<Arc<dyn Node>> {
        for node in nodes.iter() {
            if node.is_available().await {
                return Some(node.clone());
            }
        }
        None
    }

    /// Prefer direct routing, fallback to any available
    async fn select_prefer_direct(&self, nodes: &[Arc<dyn Node>]) -> Option<Arc<dyn Node>> {
        // First try direct
        for node in nodes.iter() {
            if node.protocol() == "direct" && node.is_available().await {
                return Some(node.clone());
            }
        }

        // Fallback to any available
        self.select_first_available(nodes).await
    }

    /// Select node using round-robin with atomic counter
    async fn select_round_robin(&self, nodes: &[Arc<dyn Node>]) -> Option<Arc<dyn Node>> {
        let available = self.collect_available(nodes).await;
        if available.is_empty() {
            return None;
        }

        let count = available.len() as u32;
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % count;
        Some(available[idx as usize].clone())
    }

    /// Select node using consistent hashing (ketama-like)
    /// Same fingerprint always routes to the same node (or next available)
    async fn select_consistent_hash(
        &self,
        nodes: &[Arc<dyn Node>],
        fp: &ConnectionFingerprint,
    ) -> Option<Arc<dyn Node>> {
        let available = self.collect_available(nodes).await;
        if available.is_empty() {
            return None;
        }

        let count = available.len() as u64;
        let hash = fp.hash();

        // Try the hash position first, then wrap around
        let mut idx = (hash % count) as usize;
        for _ in 0..count {
            if available[idx].is_available().await {
                return Some(available[idx].clone());
            }
            idx = (idx + 1) % count as usize;
        }

        None
    }

    /// Select node using sticky session (based on source IP hash)
    async fn select_sticky_session(
        &self,
        nodes: &[Arc<dyn Node>],
        fp: &ConnectionFingerprint,
    ) -> Option<Arc<dyn Node>> {
        let available = self.collect_available(nodes).await;
        if available.is_empty() {
            return None;
        }

        let count = available.len() as u64;
        let hash = fp.hash();
        let idx = (hash % count) as usize;

        // Sticky: always try the same index first
        if available[idx].is_available().await {
            return Some(available[idx].clone());
        }

        // Fallback to consistent hash if primary is down
        drop(available);
        self.select_consistent_hash(nodes, fp).await
    }

    /// Select node using URL hash
    async fn select_url_hash(
        &self,
        nodes: &[Arc<dyn Node>],
        fp: &ConnectionFingerprint,
    ) -> Option<Arc<dyn Node>> {
        // URL hash uses the same mechanism as consistent hash
        // The fingerprint's url field carries the hash input
        self.select_consistent_hash(nodes, fp).await
    }

    /// Collect available nodes
    async fn collect_available(&self, nodes: &[Arc<dyn Node>]) -> Vec<Arc<dyn Node>> {
        let availability: Vec<bool> =
            futures::future::join_all(nodes.iter().map(|n| n.is_available())).await;

        nodes
            .iter()
            .zip(availability.iter())
            .filter(|&(_, &is_avail)| is_avail)
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Node, NodeId};
    use async_trait::async_trait;
    use std::sync::Arc;

    struct MockNode {
        id: NodeId,
        name: String,
        protocol: &'static str,
        available: bool,
    }

    #[async_trait]
    impl Node for MockNode {
        fn id(&self) -> &NodeId {
            &self.id
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn protocol(&self) -> &'static str {
            self.protocol
        }
        async fn ping(&self) -> Result<u32, crate::node::NodeError> {
            Ok(100)
        }
        async fn is_available(&self) -> bool {
            self.available
        }
    }

    #[tokio::test]
    async fn test_specific_selection() {
        let selector = DefaultNodeSelector::new();
        let node: Arc<dyn Node> = Arc::new(MockNode {
            id: "node1".into(),
            name: "Test Node".into(),
            protocol: "vmess",
            available: true,
        });

        let result = selector
            .select(&[node.clone()], &SelectionPolicy::Specific("node1".into()))
            .await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().id(), "node1");
    }
}
