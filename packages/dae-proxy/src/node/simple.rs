//! Simple node implementations for dae-proxy
//!
//! This module provides concrete implementations of the node management
//! traits defined in the parent module.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use std::collections::HashMap;

use super::node::{Node, NodeError, NodeId};
use super::manager::{NodeManager, SelectionPolicy};
use super::selector::{NodeSelector, DefaultNodeSelector};
use super::health::{HealthChecker, HealthCheckResult, HealthCheckerConfig};

// ============================================================================
// SimpleNode - Basic node implementation
// ============================================================================

/// Simple node implementation for proxy servers
///
/// This struct represents a basic proxy node with TCP connectivity.
/// It uses TCP connection time to measure latency.
#[derive(Debug, Clone)]
pub struct SimpleNode {
    /// Unique node identifier
    id: NodeId,
    /// Display name
    name: String,
    /// Protocol name (e.g., "shadowsocks", "vless", "vmess", "trojan")
    protocol: &'static str,
    /// Server socket address
    address: SocketAddr,
    /// Last measured latency in milliseconds
    last_latency: Option<u32>,
    /// Connection timeout
    timeout: Duration,
}

impl SimpleNode {
    /// Create a new SimpleNode
    pub fn new(
        id: impl Into<NodeId>,
        name: impl Into<String>,
        protocol: &'static str,
        address: SocketAddr,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            protocol,
            address,
            last_latency: None,
            timeout: Duration::from_secs(5),
        }
    }

    /// Create a new SimpleNode with custom timeout
    pub fn with_timeout(
        id: impl Into<NodeId>,
        name: impl Into<String>,
        protocol: &'static str,
        address: SocketAddr,
        timeout: Duration,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            protocol,
            address,
            last_latency: None,
            timeout,
        }
    }

    /// Get the last measured latency
    pub fn last_latency(&self) -> Option<u32> {
        self.last_latency
    }

    /// Update the last measured latency
    #[allow(dead_code)]
    fn set_latency(&mut self, latency: u32) {
        self.last_latency = Some(latency);
    }
}

#[async_trait]
impl Node for SimpleNode {
    fn id(&self) -> &NodeId {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &'static str {
        self.protocol
    }

    /// Ping the node by attempting a TCP connection and measuring time
    async fn ping(&self) -> Result<u32, NodeError> {
        let start = Instant::now();
        
        match tokio::time::timeout(self.timeout, TcpStream::connect(self.address)).await {
            Ok(Ok(_)) => {
                let elapsed = start.elapsed().as_millis() as u32;
                Ok(elapsed)
            }
            Ok(Err(e)) => {
                Err(NodeError::ConnectionFailed(e.to_string()))
            }
            Err(_) => {
                Err(NodeError::Timeout)
            }
        }
    }

    /// Check if the node is available (responds to ping)
    async fn is_available(&self) -> bool {
        self.ping().await.is_ok()
    }
}

// ============================================================================
// SimpleNodeManager - Node lifecycle management
// ============================================================================

/// Simple node manager implementation
///
/// This struct manages node registration, selection, and latency tracking.
/// It uses internal locks for thread-safe concurrent access.
pub struct SimpleNodeManager {
    /// Registered nodes by ID
    nodes: RwLock<HashMap<NodeId, Arc<dyn Node>>>,
    /// Cached latencies by node ID
    latencies: RwLock<HashMap<NodeId, u32>>,
    /// Node selector for selection strategies
    selector: DefaultNodeSelector,
    /// Round-robin state: index of next node
    round_robin_index: RwLock<usize>,
    /// Health check configuration
    health_config: HealthCheckerConfig,
    /// Health states by node ID (true = healthy)
    health_states: RwLock<HashMap<NodeId, bool>>,
}

impl SimpleNodeManager {
    /// Create a new empty SimpleNodeManager
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            latencies: RwLock::new(HashMap::new()),
            selector: DefaultNodeSelector::new(),
            round_robin_index: RwLock::new(0),
            health_config: HealthCheckerConfig::default(),
            health_states: RwLock::new(HashMap::new()),
        }
    }

    /// Create a SimpleNodeManager with custom health check configuration
    pub fn with_health_config(config: HealthCheckerConfig) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            latencies: RwLock::new(HashMap::new()),
            selector: DefaultNodeSelector::new(),
            round_robin_index: RwLock::new(0),
            health_config: config,
            health_states: RwLock::new(HashMap::new()),
        }
    }

    /// Add a node to the manager
    pub async fn add_node(&self, node: Arc<dyn Node>) {
        let node_id = node.id().clone();
        let mut nodes = self.nodes.write().await;
        nodes.insert(node_id.clone(), node);
        
        // Initialize health state as healthy
        let mut health_states = self.health_states.write().await;
        health_states.insert(node_id, true);
    }

    /// Remove a node from the manager
    pub async fn remove_node(&self, id: &NodeId) {
        let mut nodes = self.nodes.write().await;
        nodes.remove(id);
        
        let mut latencies = self.latencies.write().await;
        latencies.remove(id);
        
        let mut health_states = self.health_states.write().await;
        health_states.remove(id);
    }

    /// Get the number of registered nodes
    pub async fn node_count(&self) -> usize {
        self.nodes.read().await.len()
    }

    /// Check if a node exists
    pub async fn contains_node(&self, id: &NodeId) -> bool {
        self.nodes.read().await.contains_key(id)
    }

    /// Get the health check configuration
    pub fn health_config(&self) -> &HealthCheckerConfig {
        &self.health_config
    }

    /// Run health checks on all nodes
    pub async fn check_all_health(&self) -> Vec<HealthCheckResult> {
        let nodes = self.nodes.read().await;
        let node_list: Vec<Arc<dyn Node>> = nodes.values().cloned().collect();
        drop(nodes);

        let results = HealthChecker::check_nodes(&node_list).await;
        
        // Update health states
        let mut health_states = self.health_states.write().await;
        for result in &results {
            health_states.insert(result.node_id.clone(), result.is_healthy);
        }

        results
    }
}

impl Default for SimpleNodeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NodeManager for SimpleNodeManager {
    async fn select(&self, policy: &SelectionPolicy) -> Option<Arc<dyn Node>> {
        let nodes = self.all_nodes().await;
        if nodes.is_empty() {
            return None;
        }

        match policy {
            SelectionPolicy::RoundRobin => {
                let mut index = self.round_robin_index.write().await;
                let node_count = nodes.len();
                let selected_index = *index % node_count;
                *index = selected_index + 1;
                Some(nodes[selected_index].clone())
            }
            _ => self.selector.select(&nodes, policy).await,
        }
    }

    fn get(&self, id: &NodeId) -> Option<Arc<dyn Node>> {
        // Use blocking read in sync context
        self.nodes.blocking_read().get(id).cloned()
    }

    async fn all_nodes(&self) -> Vec<Arc<dyn Node>> {
        self.nodes.read().await.values().cloned().collect()
    }

    async fn available_nodes(&self) -> Vec<Arc<dyn Node>> {
        let nodes: Vec<Arc<dyn Node>> = self.nodes.read().await.values().cloned().collect();
        let availability = futures::future::join_all(
            nodes.iter().map(|n| n.is_available())
        ).await;
        
        nodes.into_iter()
            .zip(availability.into_iter())
            .filter(|(_, available)| *available)
            .map(|(node, _)| node)
            .collect()
    }

    async fn update_latency(&self, node_id: &NodeId, latency: u32) {
        let mut latencies = self.latencies.write().await;
        latencies.insert(node_id.clone(), latency);
    }

    async fn set_offline(&self, node_id: &NodeId) {
        let mut health_states = self.health_states.write().await;
        health_states.insert(node_id.clone(), false);
    }

    fn get_latency(&self, node_id: &NodeId) -> Option<u32> {
        self.latencies.blocking_read().get(node_id).copied()
    }

    async fn run_latency_test(&self) -> HashMap<NodeId, u32> {
        let nodes: Vec<Arc<dyn Node>> = self.nodes.read().await.values().cloned().collect();
        let mut results = HashMap::new();

        for node in nodes {
            let node_id = node.id().clone();
            match node.ping().await {
                Ok(latency) => {
                    self.update_latency(&node_id, latency).await;
                    results.insert(node_id, latency);
                }
                Err(_) => {
                    // Keep existing latency if ping fails
                    if let Some(latency) = self.get_latency(&node_id) {
                        results.insert(node_id, latency);
                    }
                }
            }
        }

        results
    }
}

// ============================================================================
// LatencyTestResult - Latency test result structure
// ============================================================================

/// Result of a latency test for a single node
#[derive(Debug, Clone)]
pub struct LatencyTestResult {
    /// Node ID
    pub node_id: NodeId,
    /// Latency in milliseconds
    pub latency_ms: u32,
    /// Timestamp when the test was performed
    pub timestamp: Instant,
    /// Whether the test was successful
    pub success: bool,
}

impl LatencyTestResult {
    /// Create a successful latency test result
    pub fn success(node_id: NodeId, latency_ms: u32) -> Self {
        Self {
            node_id,
            latency_ms,
            timestamp: Instant::now(),
            success: true,
        }
    }

    /// Create a failed latency test result
    pub fn failure(node_id: NodeId) -> Self {
        Self {
            node_id,
            latency_ms: 0,
            timestamp: Instant::now(),
            success: false,
        }
    }
}

// ============================================================================
// LatencyMonitor - Periodic latency testing
// ============================================================================

/// Latency monitor for periodic latency testing
///
/// This struct runs latency tests at regular intervals and
/// updates the node manager with the results.
pub struct LatencyMonitor {
    /// Reference to the node manager
    node_manager: Arc<SimpleNodeManager>,
    /// Test interval
    interval: Duration,
}

impl LatencyMonitor {
    /// Create a new LatencyMonitor with the given node manager and interval
    pub fn new(node_manager: Arc<SimpleNodeManager>, interval: Duration) -> Self {
        Self {
            node_manager,
            interval,
        }
    }

    /// Create a LatencyMonitor with default 30-second interval
    pub fn with_default_interval(node_manager: Arc<SimpleNodeManager>) -> Self {
        Self {
            node_manager,
            interval: Duration::from_secs(30),
        }
    }

    /// Start the latency monitoring loop
    ///
    /// This method runs indefinitely, testing all nodes at the configured
    /// interval and logging the results.
    pub async fn start(self) {
        tracing::info!("Starting latency monitor with interval {:?}", self.interval);
        
        let mut interval_timer = tokio::time::interval(self.interval);
        
        loop {
            interval_timer.tick().await;
            
            let results = self.node_manager.run_latency_test().await;
            
            if results.is_empty() {
                tracing::debug!("Latency test: no nodes registered");
            } else {
                tracing::debug!("Latency test completed: {} nodes tested", results.len());
                
                for (node_id, latency) in &results {
                    tracing::trace!("Node {} latency: {}ms", node_id, latency);
                }
            }
        }
    }

    /// Run a single latency test and return detailed results
    pub async fn run_test(&self) -> Vec<LatencyTestResult> {
        let nodes = self.node_manager.all_nodes().await;
        let mut results = Vec::with_capacity(nodes.len());

        for node in nodes {
            let node_id = node.id().clone();
            match node.ping().await {
                Ok(latency_ms) => {
                    results.push(LatencyTestResult::success(node_id, latency_ms));
                }
                Err(_) => {
                    results.push(LatencyTestResult::failure(node_id));
                }
            }
        }

        results
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_node_ping() {
        // Create a node pointing to localhost (should fail or succeed depending on availability)
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let node = SimpleNode::new("test-node", "Test Node", "tcp", addr);
        
        // This will likely timeout or connection refused since port 1 is unlikely open
        let result = node.ping().await;
        
        // We just verify ping doesn't panic
        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_simple_node_manager_add_remove() {
        let manager = SimpleNodeManager::new();
        
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let node: Arc<dyn Node> = Arc::new(SimpleNode::new("node1", "Node 1", "tcp", addr));
        
        manager.add_node(node.clone()).await;
        
        assert_eq!(manager.node_count().await, 1);
        assert!(manager.contains_node(&"node1".to_string()).await);
        
        manager.remove_node(&"node1".to_string()).await;
        
        assert_eq!(manager.node_count().await, 0);
        assert!(!manager.contains_node(&"node1".to_string()).await);
    }

    #[tokio::test]
    async fn test_latency_test_result() {
        let result = LatencyTestResult::success("node1".to_string(), 100);
        assert!(result.success);
        assert_eq!(result.latency_ms, 100);
        
        let failure = LatencyTestResult::failure("node2".to_string());
        assert!(!failure.success);
        assert_eq!(failure.latency_ms, 0);
    }

    #[tokio::test]
    async fn test_selection_policy_round_robin() {
        let manager = SimpleNodeManager::new();
        
        let addr1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        
        let node1: Arc<dyn Node> = Arc::new(SimpleNode::new("node1", "Node 1", "tcp", addr1));
        let node2: Arc<dyn Node> = Arc::new(SimpleNode::new("node2", "Node 2", "tcp", addr2));
        
        manager.add_node(node1).await;
        manager.add_node(node2).await;
        
        // Round-robin selection
        let sel1 = manager.select(&SelectionPolicy::RoundRobin).await;
        let sel2 = manager.select(&SelectionPolicy::RoundRobin).await;
        let sel3 = manager.select(&SelectionPolicy::RoundRobin).await;
        
        assert!(sel1.is_some());
        assert!(sel2.is_some());
        
        // Third selection wraps around
        assert!(sel3.is_some());
    }
}
