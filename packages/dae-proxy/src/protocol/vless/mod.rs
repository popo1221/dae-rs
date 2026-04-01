//! VLESS protocol module
//!
//! This module provides VLESS protocol support with XTLS.
//!
//! ## Protocol Overview
//!
//! VLESS is a stateless authentication protocol designed for cross-breach
//! communication. It supports XTLS (TLS in TLS) for enhanced security.
//!
//! ## Implementation
//!
//! The main VLESS handler implementation is in the parent module's `vless.rs` file.
//! This module serves as a namespace and for future VLESS-specific extensions.

pub mod handler;

// Re-export common types for convenience
pub use crate::vless::{VlessHandler, VlessServer, VlessServerConfig};
