//!
//! Hysteria2 protocol implementation
//!
//! Hysteria2 is a powerful, lightning fast and reliable proxy built on top of QUIC.
//! It provides aggressive acceleration for proxy connections with features like:
//! - QUIC-based transport for better performance
//! - Obfuscation support to bypass DPI
//! - Bandwidth congestion control
//! - Simple authentication via password
//!
//! **Note:** The QUIC transport layer (`quic` feature) is not yet implemented.
//! The core Hysteria2 protocol works over TCP. QUIC support will be added in a future release.

mod hysteria2;
#[cfg(feature = "quic")]
mod quic;

pub use hysteria2::{Hysteria2Config, Hysteria2Error, Hysteria2Handler, Hysteria2Server};

// QUIC module exports removed - not yet implemented
// TODO: Implement QUIC transport using quinn when ready
// The following were removed because they returned NotImplemented:
// pub use quic::{CongestionControl, QuicCodec, QuicConfig, QuicConnection, QuicEndpoint, QuicError, QuicStream, QuicUdpSocket};
