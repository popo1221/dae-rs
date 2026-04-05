//! HTTP 协议占位处理器
//!
//! 本文件为未来的 HTTP 特定处理器实现提供占位符。
//! 主要的 HTTP 逻辑在 `../../http_proxy.rs` 中。

use crate::core::{Context, Result as ProxyResult};
use crate::protocol::ProtocolHandler;
use async_trait::async_trait;

/// HTTP 协议处理器
///
/// 这是一个占位结构体，用于与协议注册表集成。
/// 主要的 HTTP 代理逻辑在 `../../http_proxy.rs` 中。
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
