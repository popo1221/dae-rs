//! API route handlers
//!
//! This module exports all route handlers for the REST API

pub mod config;
pub mod nodes;
pub mod rules;
pub mod stats;

// Re-export route functions for use in server
pub use config::{get_config, update_config};
pub use nodes::{get_node, list_nodes, test_node};
pub use rules::{list_rules, rules_summary};
pub use stats::{get_stats, health_check};
