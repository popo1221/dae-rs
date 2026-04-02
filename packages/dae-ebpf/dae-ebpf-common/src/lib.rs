//! dae-ebpf-common - Shared eBPF types for dae-rs
//!
//! This crate contains shared type definitions used by both:
//! - Kernel eBPF programs (dae-xdp)
//! - User-space loader (dae-ebpf)

#![no_std]
// Allow strict clippy lints for eBPF code patterns
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::needless_range_loop)]

pub mod config;
pub mod direct;
pub mod routing;
pub mod session;
pub mod stats;

// Re-export commonly used types
pub use config::{ConfigEntry, GLOBAL_CONFIG_KEY};
pub use routing::{action, RoutingEntry};
pub use session::{state, SessionEntry, SessionKey};
pub use stats::{idx, StatsEntry};
