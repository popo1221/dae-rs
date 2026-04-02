//! Shadowsocks protocol placeholder handler
//!
//! This file provides a placeholder for future Shadowsocks-specific handler implementations.
//! The main Shadowsocks logic is in `../../shadowsocks.rs`.

use crate::core::{Context, Result as ProxyResult};
use crate::protocol::ProtocolHandler;
use async_trait::async_trait;

/// Shadowsocks protocol handler
///
/// This is a placeholder struct that wraps the main Shadowsocks handler
/// for integration with the protocol registry.
#[derive(Debug)]
pub struct ShadowsocksProtocolHandler {
    // Future: Shadowsocks-specific configuration
}

impl ShadowsocksProtocolHandler {
    /// Create a new Shadowsocks protocol handler
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for ShadowsocksProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolHandler for ShadowsocksProtocolHandler {
    fn name(&self) -> &'static str {
        "shadowsocks"
    }

    async fn handle_inbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // Delegate to the main Shadowsocks handler
        // This is a placeholder for protocol-specific inbound handling
        tracing::debug!(
            request_id = ctx.request_id,
            source = %ctx.source,
            destination = %ctx.destination,
            "shadowsocks inbound handler placeholder"
        );
        Ok(())
    }

    async fn handle_outbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // Delegate to the main Shadowsocks handler
        // This is a placeholder for protocol-specific outbound handling
        tracing::debug!(
            request_id = ctx.request_id,
            source = %ctx.source,
            destination = %ctx.destination,
            "shadowsocks outbound handler placeholder"
        );
        Ok(())
    }
}
