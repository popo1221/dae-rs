//! Juicity protocol handler
//!
//! Implements Juicity protocol support for dae-rs.
//! Juicity is a UDP-based proxy protocol designed for high performance.
//!
//! Protocol reference: https://github.com/juicity/juicity
//!
//! Protocol flow:
//! Client -> dae-rs (Juicity client) -> remote Juicity server -> target

mod codec;
mod juicity;

pub use codec::{JuicityAddress, JuicityCodec, JuicityCommand, JuicityFrame};
pub use juicity::{
    CongestionControl, JuicityClient, JuicityConfig, JuicityConnection, JuicityError,
    JuicityHandler, JuicityServer,
};
