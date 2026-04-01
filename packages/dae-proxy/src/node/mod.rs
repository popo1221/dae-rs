//! Node management module for dae-proxy
//!
//! This module provides node abstraction, selection, and health checking
//! for the proxy system.
//!
//! # Architecture
//!
//! - `node`: Core Node trait and NodeId type
//! - `manager`: NodeManager trait for node lifecycle
//! - `selector`: NodeSelector implementations
//! - `health`: HealthChecker for availability monitoring
//! - `simple`: Concrete implementations (SimpleNode, SimpleNodeManager, LatencyMonitor)

pub mod node;
pub mod manager;
pub mod selector;
pub mod health;
pub mod simple;

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
