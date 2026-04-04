//! dae-protocol-vless - VLESS protocol implementation with Reality support
//!
//! Implements VLESS protocol with XTLS Reality for dae-rs.
//! VLESS is a stateless VPN protocol that uses TLS/XTLS transport.
//!
//! Protocol spec: https://xtls.github.io/
//! Reality spec: https://github.com/XTLS/Xray-core/discussions/716
//!
//! # VLESS Reality Vision
//!
//! VLESS Reality Vision is a TLS obfuscation protocol that:
//! - Uses X25519 key exchange for perfect forward secrecy
//! - Masks traffic as normal HTTPS to bypass DPI
//! - Works with any TLS-terminated server (nginx, caddy, etc.)
//!
//! # Protocol Flow (Reality Vision)
//!
//! Client -> [X25519 KeyGen] -> [Build Request] -> [TLS ClientHello with Chrome]
//! -> Server -> [Verify and respond] -> [Establish tunnel]

mod handler;
mod types;

pub use handler::VlessHandler;
pub use types::*;
