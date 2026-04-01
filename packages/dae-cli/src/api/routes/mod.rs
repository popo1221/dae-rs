//! API route handlers
//!
//! This module exports all route handlers for the REST API

pub mod nodes;
pub mod rules;
pub mod config;
pub mod stats;

// Re-export route functions for use in server
pub use nodes::{list_nodes, get_node, test_node};
pub use rules::{list_rules, rules_summary};
pub use config::{get_config, update_config};
pub use stats::{get_stats, health_check};
