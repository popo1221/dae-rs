//! SOCKS5 协议占位处理器
//!
//! 本文件为未来的 SOCKS5 特定处理器实现提供占位符。
//! 主要的 SOCKS5 逻辑在 `../../socks5.rs` 中。

use crate::core::{Context, Result as ProxyResult};
use crate::protocol::ProtocolHandler;
use async_trait::async_trait;

/// SOCKS5 协议处理器
///
/// 这是一个占位结构体，用于与协议注册表集成。
/// 主要的 SOCKS5 逻辑在 `../../socks5.rs` 中。
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
