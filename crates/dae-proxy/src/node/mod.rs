//! dae-proxy 节点管理模块
//!
//! 本模块提供节点抽象、节点选择和健康检查功能，遵循 Zed 的 Store 模式设计。
//!
//! # 架构设计 (Zed 风格)
//!
//! - `node`: 核心 Node trait 和 NodeId 类型
//! - `manager`: NodeManager trait 用于节点生命周期管理
//! - `selector`: NodeSelector 实现（遵循 *Store 命名规范）
//! - `health`: HealthChecker 用于可用性监控
//! - `simple`: 具体实现（SimpleNode、SimpleNodeManager、LatencyMonitor）
//!
//! # 命名规范 (Zed 模式)
//!
//! 遵循 Zed 的命名约定：
//! - `*Store`: 操作的抽象接口（如 `NodeSelector` -> `NodeStore`）
//! - `*Manager`: 管理生命周期的具体实现
//! - `*Handle`: 托管实体的引用

pub mod capability;
pub mod hash;
pub mod health;
pub mod manager;
#[allow(clippy::module_inception)]
pub mod node;
pub mod selector;
pub mod simple;

// Node Store - Zed-inspired naming for node management
pub mod store;

// Re-export hash algorithms
pub use hash::{fnv1a_hash, sip_hash, Fnv1aHasher, SipHasher};

// Re-export common types
pub use capability::{
    infer_capabilities, CapabilityDetectionResult, CapabilityFilter, DetectionMethod,
    NodeCapabilities,
};
pub use health::{HealthCheckResult, HealthChecker, HealthCheckerConfig};
pub use manager::{NodeManager, SelectionPolicy};
pub use node::{Node, NodeError, NodeId};
pub use selector::{DefaultNodeSelector, NodeSelector};

// Re-export simple module types
pub use simple::{LatencyMonitor, LatencyTestResult, SimpleNode, SimpleNodeManager};

// Re-export NodeStore types (Zed-inspired)
pub use store::{NodeHandle, NodeManagerConfig, NodeState, NodeStore as NodeStoreTrait};

// Type aliases following Zed's naming conventions

/// NodeStore - type alias for NodeSelector following Zed naming conventions
///
/// This is an alias to follow Zed's naming convention where `*Store` indicates
/// an abstraction over local/remote operations. In Zed, this pattern is used
/// for things like `LanguageStore`, `ProjectStore`, etc.
///
/// The trait itself is defined in `selector` module as `NodeSelector`.
pub type NodeStore = dyn NodeSelector;
