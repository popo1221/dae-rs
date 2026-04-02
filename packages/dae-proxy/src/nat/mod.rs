//! NAT (Network Address Translation) module
//!
//! Provides various NAT implementations for proxy protocols.
//!
//! # Available NAT Types
//!
//! - [`full_cone`] - Full-Cone NAT (NAT1) implementation
//!
//! # NAT Types
//!
//! Full-Cone NAT allows any external host to send packets to an internal host
//! once an internal host sends a packet to that external host.

pub mod full_cone;

pub use full_cone::{
    FullConeNat, FullConeNatConfig, FullConeNatUdpHandler, NatMapping, NatStats,
};
