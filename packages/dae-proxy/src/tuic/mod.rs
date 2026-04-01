//! TUIC protocol module
//!
//! TUIC is a QUIC-based proxy protocol that provides low-latency, high-performance
//! proxy capabilities using the QUIC transport protocol.
//!
//! Protocol reference: https://github.com/tuic-org/tuic

pub mod tuic;
pub mod codec;

pub use tuic::{TuicHandler, TuicServer, TuicClient, TuicConfig, TuicError, TuicCommandType};
pub use codec::{TuicCodec, TuicCommand};
