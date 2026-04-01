//! Juicity protocol module
//!
//! Implements Juicity protocol support for dae-rs.
//! Juicity is a UDP-based proxy protocol designed for high performance.
//!
//! Protocol reference: https://github.com/juicity/juicity
//!
//! Protocol flow:
//! Client -> dae-rs (Juicity client) -> remote Juicity server -> target

pub mod codec;
pub mod juicity;

pub use juicity::{JuicityConfig, JuicityHandler, JuicityServer, JuicityClient, JuicityError};
pub use codec::{JuicityCodec, JuicityFrame, JuicityCommand};
