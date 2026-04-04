//! dae-proxy-core - Core proxy functionality for dae-rs
//!
//! This crate provides the core TCP/UDP forwarding infrastructure.
//!
//! # Contents
//!
//! - Connection: Connection tracking with state management
//! - ConnectionPool: Connection reuse by 4-tuple with expiration
//! - Handler: Unified protocol handler trait

pub mod connection;
pub mod connection_pool;
pub mod handler;
pub mod error;

pub use connection::{Connection, ConnectionState, Protocol, SharedConnection};
pub use connection_pool::{ConnectionKey, ConnectionPool, SharedConnectionPool};
pub use handler::{Handler, HandlerConfig};
pub use error::ProxyError;

// Re-export from dae-core
pub use dae_core::{Context, Error, Result};

// Re-export connection constructors
pub use connection::new_connection;
