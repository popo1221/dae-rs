//! SOCKS5 protocol placeholder handler
//!
//! This file provides a placeholder for future SOCKS5-specific handler implementations.
//! The main SOCKS5 logic is in `../../socks5.rs`.

use async_trait::async_trait;
use crate::core::{Context, Result as ProxyResult};
use crate::protocol::ProtocolHandler;

/// SOCKS5 protocol handler
///
/// This is a placeholder struct that wraps the main SOCKS5 handler
/// for integration with the protocol registry.
#[derive(Debug)]
pub struct Socks5ProtocolHandler {
    // Future: SOCKS5-specific configuration
}

impl Socks5ProtocolHandler {
    /// Create a new SOCKS5 protocol handler
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Socks5ProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolHandler for Socks5ProtocolHandler {
    fn name(&self) -> &'static str {
        "socks5"
    }

    async fn handle_inbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // Delegate to the main SOCKS5 handler
        // This is a placeholder for protocol-specific inbound handling
        tracing::debug!(
            request_id = ctx.request_id,
            source = %ctx.source,
            destination = %ctx.destination,
            "socks5 inbound handler placeholder"
        );
        Ok(())
    }

    async fn handle_outbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // Delegate to the main SOCKS5 handler
        // This is a placeholder for protocol-specific outbound handling
        tracing::debug!(
            request_id = ctx.request_id,
            source = %ctx.source,
            destination = %ctx.destination,
            "socks5 outbound handler placeholder"
        );
        Ok(())
    }
}
