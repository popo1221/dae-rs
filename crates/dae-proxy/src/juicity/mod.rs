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
pub mod config;
pub mod types;

pub use codec::{JuicityAddress, JuicityCodec, JuicityCommand, JuicityFrame};
pub use config::JuicityConfig;
pub use juicity::{
    JuicityClient, JuicityConnection, JuicityHandler, JuicityServer,
};
pub use types::{CongestionControl, JuicityError};
