//!
//! Node management module for dae-proxy
//!
//! This module provides node abstraction, selection, and health checking
//! for the proxy system, following Zed's Store pattern for local/remote abstraction.
//!
//! # Architecture (Zed-inspired)
//!
//! - `node`: Core Node trait and NodeId type
//! - `manager`: NodeManager trait for node lifecycle
//! - `selector`: NodeSelector implementations (following *Store naming)
//! - `health`: HealthChecker for availability monitoring
//! - `simple`: Concrete implementations (SimpleNode, SimpleNodeManager, LatencyMonitor)
//!
//! # Naming Conventions (Zed Pattern)
//!
//! Following Zed's conventions:
//! - `*Store`: Abstract interface for operations (like `NodeSelector` -> `NodeStore`)
//! - `*Manager`: Concrete implementation managing lifecycle
//! - `*Handle`: Reference to a managed entity

pub mod node;
pub mod manager;
pub mod selector;
pub mod health;
pub mod simple;

// Node Store - Zed-inspired naming for node management
pub mod store;

// Re-export common types
pub use node::{Node, NodeId, NodeError};
pub use manager::{NodeManager, SelectionPolicy};
pub use selector::{NodeSelector, DefaultNodeSelector};
pub use health::{HealthChecker, HealthCheckerConfig, HealthCheckResult};

// Re-export simple module types
pub use simple::{
    SimpleNode,
    SimpleNodeManager,
    LatencyTestResult,
    LatencyMonitor,
};

// Re-export NodeStore types (Zed-inspired)
pub use store::{
    NodeStore as NodeStoreTrait,
    NodeHandle,
    NodeState,
    NodeManagerConfig,
};

// Type aliases following Zed's naming conventions

/// NodeStore - type alias for NodeSelector following Zed naming conventions
///
/// This is an alias to follow Zed's naming convention where `*Store` indicates
/// an abstraction over local/remote operations. In Zed, this pattern is used
/// for things like `LanguageStore`, `ProjectStore`, etc.
///
/// The trait itself is defined in `selector` module as `NodeSelector`.
pub type NodeStore = dyn NodeSelector;
