//!
//! Hysteria2 protocol implementation
//!
//! Hysteria2 is a powerful, lightning fast and reliable proxy built on top of QUIC.
//! It provides aggressive acceleration for proxy connections with features like:
//! - QUIC-based transport for better performance
//! - Obfuscation support to bypass DPI
//! - Bandwidth congestion control
//! - Simple authentication via password

pub mod hysteria2;
pub mod quic;

pub use hysteria2::{Hysteria2Handler, Hysteria2Server, Hysteria2Config, Hysteria2Error};
