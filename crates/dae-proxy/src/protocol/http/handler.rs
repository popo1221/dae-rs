//! HTTP protocol placeholder handler
//!
//! This file provides a placeholder for future HTTP-specific handler implementations.
//! The main HTTP logic is in `../../http_proxy.rs`.

use crate::core::{Context, Result as ProxyResult};
use crate::protocol::ProtocolHandler;
use async_trait::async_trait;

/// HTTP protocol handler
///
/// This is a placeholder struct that wraps the main HTTP proxy handler
/// for integration with the protocol registry.
#[derive(Debug)]
pub struct HttpProtocolHandler {
    // Future: HTTP-specific configuration
}

impl HttpProtocolHandler {
    /// Create a new HTTP protocol handler
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for HttpProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolHandler for HttpProtocolHandler {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn handle_inbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // Delegate to the main HTTP proxy handler
        // This is a placeholder for protocol-specific inbound handling
        tracing::debug!(
            request_id = ctx.request_id,
            source = %ctx.source,
            destination = %ctx.destination,
            "http inbound handler placeholder"
        );
        Ok(())
    }

    async fn handle_outbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // Delegate to the main HTTP proxy handler
        // This is a placeholder for protocol-specific outbound handling
        tracing::debug!(
            request_id = ctx.request_id,
            source = %ctx.source,
            destination = %ctx.destination,
            "http outbound handler placeholder"
        );
        Ok(())
    }
}
