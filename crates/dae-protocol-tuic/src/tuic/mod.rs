//! TUIC protocol module
//!
//! TUIC is a QUIC-based proxy protocol.

pub mod codec;
pub mod tuic_impl;

// Re-exports for convenience
pub use codec::TuicCodec;
pub use tuic_impl::{TuicCommand, TuicClient, TuicCommandType, TuicConfig, TuicError, TuicHandler, TuicServer};
