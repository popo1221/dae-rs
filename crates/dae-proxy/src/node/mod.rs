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
