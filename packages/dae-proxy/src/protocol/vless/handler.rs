//! VLESS protocol placeholder handler
//!
//! This file provides a placeholder for future VLESS-specific handler implementations.
//! The main VLESS logic is in `../../vless.rs`.

use crate::core::{Context, Result as ProxyResult};
use crate::protocol::ProtocolHandler;
use async_trait::async_trait;

/// VLESS protocol handler
///
/// This is a placeholder struct that wraps the main VLESS handler
/// for integration with the protocol registry.
#[derive(Debug)]
pub struct VlessProtocolHandler {
    // Future: VLESS-specific configuration
}

impl VlessProtocolHandler {
    /// Create a new VLESS protocol handler
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for VlessProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolHandler for VlessProtocolHandler {
    fn name(&self) -> &'static str {
        "vless"
    }

    async fn handle_inbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // Delegate to the main VLESS handler
        // This is a placeholder for protocol-specific inbound handling
        tracing::debug!(
            request_id = ctx.request_id,
            source = %ctx.source,
            destination = %ctx.destination,
            "vless inbound handler placeholder"
        );
        Ok(())
    }

    async fn handle_outbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // Delegate to the main VLESS handler
        // This is a placeholder for protocol-specific outbound handling
        tracing::debug!(
            request_id = ctx.request_id,
            source = %ctx.source,
            destination = %ctx.destination,
            "vless outbound handler placeholder"
        );
        Ok(())
    }
}
