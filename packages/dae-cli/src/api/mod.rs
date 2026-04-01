//! REST API module for dae-rs
//!
//! This module provides a REST API control plane for managing nodes, rules, and configuration.
//!
//! # Endpoints
//!
//! - `GET /api/nodes` - List all nodes
//! - `GET /api/nodes/:id` - Get specific node
//! - `POST /api/nodes/:id/test` - Test node latency
//! - `GET /api/rules` - List all rules
//! - `GET /api/rules/summary` - Get rules summary
//! - `GET /api/config` - Get current configuration
//! - `PUT /api/config` - Update configuration
//! - `GET /api/stats` - Get statistics
//! - `GET /api/health` - Health check

pub mod server;
pub mod routes;
pub mod models;

pub use server::{ApiServer, ApiError, AppState};
pub use models::*;
