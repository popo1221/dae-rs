//! Shadowsocks 协议占位处理器
//!
//! 本文件为未来的 Shadowsocks 特定处理器实现提供占位符。
//! 主要的 Shadowsocks 逻辑在 `../../shadowsocks.rs` 中。

use crate::core::{Context, Result as ProxyResult};
use crate::protocol::ProtocolHandler;
use async_trait::async_trait;

/// Shadowsocks 协议处理器
///
/// 这是一个占位结构体，用于与协议注册表集成。
/// 主要的 Shadowsocks 逻辑在 `../../shadowsocks.rs` 中。
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
