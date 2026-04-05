//! TUIC protocol module
//!
//! TUIC is a QUIC-based proxy protocol that provides low-latency, high-performance
//! proxy capabilities using the QUIC transport protocol.
//!
//! Protocol reference: https://github.com/tuic-org/tuic

pub mod codec;
pub mod tuic;

pub use codec::{TuicCodec, TuicCommand};
pub use tuic::{TuicClient, TuicCommandType, TuicConfig, TuicError, TuicHandler, TuicServer};
