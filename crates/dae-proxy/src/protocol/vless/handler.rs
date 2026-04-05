//! VLESS 协议占位处理器
//!
//! 本文件为未来的 VLESS 特定处理器实现提供占位符。
//! 主要的 VLESS 逻辑在 `../../vless.rs` 中。

use crate::core::{Context, Result as ProxyResult};
use crate::protocol::ProtocolHandler;
use async_trait::async_trait;

/// VLESS 协议处理器
///
/// 这是一个占位结构体，用于与协议注册表集成。
/// 主要的 VLESS 逻辑在 `../../vless.rs` 中。
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
