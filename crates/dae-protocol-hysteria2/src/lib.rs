//!
//! Hysteria2 protocol implementation
//!
//! Hysteria2 is a powerful, lightning fast and reliable proxy built on top of QUIC.
//! It provides aggressive acceleration for proxy connections with features like:
//! - QUIC-based transport for better performance
//! - Obfuscation support to bypass DPI
//! - Bandwidth congestion control
//! - Simple authentication via password

mod hysteria2;
#[cfg(feature = "quic")]
mod quic;

pub use hysteria2::{Hysteria2Config, Hysteria2Error, Hysteria2Handler, Hysteria2Server};

#[cfg(feature = "quic")]
pub use quic::{CongestionControl, QuicCodec, QuicConfig, QuicConnection, QuicEndpoint, QuicError, QuicStream, QuicUdpSocket};
