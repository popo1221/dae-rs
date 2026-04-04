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
#[allow(clippy::module_inception)]
pub mod juicity;

pub use codec::{JuicityAddress, JuicityCodec, JuicityCommand, JuicityFrame};
pub use juicity::{
    CongestionControl, JuicityClient, JuicityConfig, JuicityConnection, JuicityError,
    JuicityHandler, JuicityServer,
};
