//! dae-api - REST API server for dae-rs
//!
//! This crate provides a standalone REST API server for managing
//! nodes, rules, and configuration in dae-rs.
//!
//! # Features
//!
//! - RESTful API with Axum
//! - WebSocket support for real-time updates
//! - CORS support
//! - Optional integration with dae-cli
//!
//! # Standalone Usage
//!
//! ```ignore
//! use dae_api::{ApiServer, AppState};
//! use dae_proxy::{Proxy, ProxyConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let state = AppState::new();
//!     let app = ApiServer::new_with_state(8080, state);
//!     app.start().await;
//! }
//! ```
//!
//! # CLI Integration
//!
//! When used with dae-cli, enable with the `--api` flag or use the `api` subcommand.

pub mod models;
pub mod routes;
pub mod server;
pub mod websocket;

pub use models::*;
pub use server::{ApiError, ApiServer, AppState};
