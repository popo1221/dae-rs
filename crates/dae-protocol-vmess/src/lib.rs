//! dae-protocol-vmess - VMess AEAD-2022 protocol implementation for dae-rs
//!
//! This crate provides the VMess protocol handler for dae-rs.
//!
//! VMess is a stateless VPN protocol used by V2Ray with AEAD-2022 support.
//!
//! # Contents
//!
//! - VmessHandler: Protocol handler implementing the Handler trait
//! - VmessConfig: Handler configuration
//! - VmessTargetAddress: VMess target address parsing/serialization
//! - VmessSecurity: VMess AEAD security type definitions

pub mod handler;

pub use handler::{VmessHandler, VmessConfig, VmessServerConfig, VmessTargetAddress, VmessSecurity, VmessAddressType, VmessCommand};
