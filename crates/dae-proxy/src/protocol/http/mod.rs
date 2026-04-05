//! HTTP proxy protocol module
//!
//! This module provides HTTP proxy protocol support using the CONNECT method.
//!
//! ## Protocol Overview
//!
//! HTTP proxy uses the CONNECT method to establish a tunnel for encrypted traffic.
//! It is commonly used for HTTPS traffic through proxies.
//!
//! ## Implementation
//!
//! The main HTTP proxy handler implementation is in the parent module's `http_proxy.rs` file.
//! This module serves as a namespace and for future HTTP-specific extensions.

pub mod handler;

// Re-export common types for convenience
pub use crate::http_proxy::{HttpProxyHandler, HttpProxyServer};
