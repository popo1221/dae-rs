//! Node Store - Zed 风格的节点管理命名
//!
//! 本模块遵循 Zed 的命名约定，`*Store` 表示本地/远程操作的抽象。
//!
//! # 架构设计 (Zed 模式)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      NodeStore Trait                         │
//! │  (abstract interface for node operations)                   │
//! └─────────────────────────────────────────────────────────────┘
//!         ▲                    │                    ▲
//!         │                    │                    │
//!    ┌────┴─────┐        ┌──────┴──────┐       ┌──────┴──────┐
//!    │ Simple   │        │ Health      │       │ RoundRobin  │
//!    │ NodeStore│        │ NodeStore   │       │ NodeStore   │
//!    └──────────┘        └─────────────┘       └─────────────┘
//! ```
//!
//! # 命名规范 (Zed 模式)
//!
//! - **NodeStore**: 节点操作的抽象接口
//! - **NodeManager**: 管理生命周期的具体实现
//! - **NodeHandle**: 托管实体的引用
//! - **NodeState**: 不可变的状态快照

use std::sync::Arc;

/// 节点存储 trait - 定义节点选择操作的接口
///
/// 遵循 Zed 的命名约定，`*Store` 表示本地/远程操作的抽象。
pub trait NodeStore: Send + Sync {
    /// Select a node based on the selection policy
    fn select(&self) -> Option<Arc<dyn Node>>;

    /// Get all available nodes
    fn all(&self) -> Vec<Arc<dyn Node>>;

    /// Get the number of available nodes
    fn len(&self) -> usize;

    /// Check if there are any nodes
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 节点管理器 - 节点生命周期管理的具体实现
///
/// 管理节点的创建、健康监控和生命周期。
pub trait NodeManager: NodeStore {
    /// Add a new node
    fn add_node(&mut self, node: Arc<dyn Node>) -> Result<(), NodeError>;

    /// Remove a node by ID
    fn remove_node(&mut self, id: &NodeId) -> Result<(), NodeError>;

    /// Update node health status
    fn update_health(&mut self, id: &NodeId, healthy: bool) -> Result<(), NodeError>;

    /// Reload configuration
    fn reload(&mut self, config: NodeManagerConfig) -> Result<(), NodeError>;
}

/// NodeManager 配置
///
/// 配置节点管理器的行为参数。
#[derive(Debug, Clone)]
pub struct NodeManagerConfig {
    /// Selection policy
    pub policy: SelectionPolicy,
    /// Health check interval in seconds
    pub health_check_interval_secs: u64,
    /// Timeout for node health checks
    pub health_check_timeout_secs: u64,
}

impl Default for NodeManagerConfig {
    fn default() -> Self {
        Self {
            policy: SelectionPolicy::LowestLatency,
            health_check_interval_secs: 60,
            health_check_timeout_secs: 5,
        }
    }
}

/// NodeHandle - reference to a managed node entity
///
/// Like Zed's Entity model, a Handle provides a reference to a managed entity.
#[derive(Debug, Clone)]
pub struct NodeHandle {
    id: String,
    name: String,
    address: String,
    port: u16,
}

impl NodeHandle {
    pub fn new(id: String, name: String, address: String, port: u16) -> Self {
        Self {
            id,
            name,
            address,
            port,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// NodeState - immutable snapshot of node state
///
/// Like Zed's state snapshots, this provides an immutable view of node state.
#[derive(Debug, Clone)]
pub struct NodeState {
    pub id: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub healthy: bool,
    pub latency_ms: Option<u32>,
    pub last_check: std::time::Instant,
}

impl NodeState {
    pub fn new(id: String, name: String, address: String, port: u16) -> Self {
        Self {
            id,
            name,
            address,
            port,
            healthy: true,
            latency_ms: None,
            last_check: std::time::Instant::now(),
        }
    }

    pub fn with_health(mut self, healthy: bool) -> Self {
        self.healthy = healthy;
        self.last_check = std::time::Instant::now();
        self
    }

    pub fn with_latency(mut self, latency_ms: u32) -> Self {
        self.latency_ms = Some(latency_ms);
        self.last_check = std::time::Instant::now();
        self
    }
}

/// Re-export for convenience
pub use crate::node::{Node, NodeError, NodeId, SelectionPolicy};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_handle_creation() {
        let handle = NodeHandle::new(
            "node-1".to_string(),
            "test-node".to_string(),
            "192.168.1.1".to_string(),
            443,
        );

        assert_eq!(handle.name(), "test-node");
        assert_eq!(handle.address(), "192.168.1.1");
        assert_eq!(handle.port(), 443);
    }

    #[test]
    fn test_node_state_builder() {
        let state = NodeState::new(
            "node-1".to_string(),
            "test-node".to_string(),
            "192.168.1.1".to_string(),
            443,
        )
        .with_health(true)
        .with_latency(100);

        assert!(state.healthy);
        assert_eq!(state.latency_ms, Some(100));
    }

    #[test]
    fn test_node_manager_config_default() {
        let config = NodeManagerConfig::default();
        assert_eq!(config.health_check_interval_secs, 60);
        assert_eq!(config.health_check_timeout_secs, 5);
    }
}
