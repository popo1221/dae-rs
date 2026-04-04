//! Shared types for dae-rs
//!
//! This module re-exports commonly used types with type aliases for consistency
//! across the dae-rs workspace.

// IP address types
pub type IpAddr = std::net::IpAddr;
pub type SocketAddr = std::net::SocketAddr;

// Duration and time types
pub type Duration = std::time::Duration;

// Buffer types
pub type Buffer = bytes::Bytes;
