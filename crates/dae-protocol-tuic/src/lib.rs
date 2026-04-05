//! dae-protocol-tuic crate
//!
//! TUIC protocol handler extracted from dae-proxy.

pub mod tuic;

// Re-exports from the tuic module
pub use tuic::{TuicCodec, TuicCommand, TuicClient, TuicCommandType, TuicConfig, TuicError, TuicHandler, TuicServer};
