//! SOCKS5 protocol module
//!
//! This module provides SOCKS5 protocol support as defined in RFC 1928.
//!
//! ## Protocol Overview
//!
//! SOCKS5 is a proxy protocol that operates at the session layer of the OSI model.
//! It provides authentication and support for both TCP and UDP traffic.
//!
//! ## Implementation
//!
//! The main SOCKS5 handler implementation is in the parent module's `socks5.rs` file.
//! This module serves as a namespace and for future SOCKS5-specific extensions.

pub mod handler;

// Re-export common types for convenience
pub use crate::socks5::{Socks5Handler, Socks5Server};
