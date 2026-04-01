//! dae-ebpf-common - Shared eBPF types for dae-rs
//!
//! This crate contains shared type definitions used by both:
//! - Kernel eBPF programs (dae-xdp)
//! - User-space loader (dae-ebpf)

#![no_std]

pub mod config;
pub mod direct;
pub mod routing;
pub mod session;
pub mod stats;

// Re-export commonly used types
pub use config::{ConfigEntry, GLOBAL_CONFIG_KEY};
pub use routing::{RoutingEntry, action};
pub use session::{SessionEntry, SessionKey, state};
pub use stats::{StatsEntry, idx};
