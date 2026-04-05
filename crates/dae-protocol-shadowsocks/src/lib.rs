//! dae-protocol-shadowsocks crate
//!
//! Shadowsocks AEAD protocol handler extracted from dae-proxy.

pub mod aead;
pub mod config;
pub mod handler;
pub mod plugin;
pub mod protocol;
pub mod server;
pub mod ssr;

// Re-export all public types from submodules
pub use config::{SsClientConfig, SsServerConfig};
pub use handler::ShadowsocksHandler;
pub use plugin::{
    ObfsConfig, ObfsHttp, ObfsMode, ObfsStream, ObfsTls, V2rayConfig, V2rayMode, V2rayPlugin,
    V2rayStream,
};
pub use protocol::{SsCipherType, TargetAddress};
pub use server::ShadowsocksServer;
pub use ssr::{SsrClientConfig, SsrHandler, SsrObfs, SsrObfsHandler, SsrProtocol, SsrServerConfig};

// Re-export relay from dae-relay for backward compatibility
pub use dae_relay::relay_bidirectional;
