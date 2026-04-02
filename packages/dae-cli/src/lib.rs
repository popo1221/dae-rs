//! dae-cli library
//!
//! This library provides the CLI interface for dae-rs

// API module is now in dae-api crate and optionally re-exported
#[cfg(feature = "api")]
pub use dae_api;
