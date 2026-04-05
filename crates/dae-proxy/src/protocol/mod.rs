//! dae-proxy 协议抽象层
//!
//! 本模块提供两种处理器 trait 系统，用于处理不同代理协议的入站和出站连接。
//!
//! # 架构设计 (Zed 风格)
//!
//! ## 1. Handler Trait (推荐)
//! [`Handler`] trait 是推荐的接口方式，遵循 Zed 的设计理念：
//! - `handle(conn: Connection)` - 单方法处理连接
//! - 内置统计追踪 via [`HandlerStats`]
//! - 热重载支持 via [`Handler::reload()`]
//!
//! ## 2. ProtocolHandler Trait (遗留接口)
//! [`ProtocolHandler`] trait 是旧版接口，使用 Context 模式：
//! - `handle_inbound()` 和 `handle_outbound()` 方法
//! - 更复杂但更灵活
//! - 为向后兼容而保留；新代码应使用 Handler
//!
//! # 模块结构
//! - [`simple_handler`] - 已废弃，提供不含 Debug bound 的简单 Handler
//! - [`unified_handler`] - 规范 Handler trait，功能完整
//! - 协议实现: http, shadowsocks, socks5, vless

use crate::core::{Context, Result as ProxyResult};
use async_trait::async_trait;

/// 协议处理器 trait - 所有协议实现必须实现此 trait
///
/// 此 trait 定义了处理特定代理协议入站和出站连接的接口。
/// 每个代理协议（如 SOCKS5、HTTP、Trojan 等）都需要实现此 trait。
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Returns the protocol name
    fn name(&self) -> &'static str;

    /// Handle inbound connection (client -> proxy)
    async fn handle_inbound(&self, ctx: &mut Context) -> ProxyResult<()>;

    /// Handle outbound connection (proxy -> remote)
    async fn handle_outbound(&self, ctx: &mut Context) -> ProxyResult<()>;
}

/// 代理支持的协议类型
///
/// 包含所有 dae-proxy 支持的代理协议类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    /// SOCKS4/SOCKS4a protocol
    Socks4,
    /// SOCKS5 protocol (RFC 1928)
    Socks5,
    /// HTTP proxy protocol (CONNECT tunnel)
    Http,
    /// Shadowsocks protocol
    Shadowsocks,
    /// VLESS protocol (XTLS)
    Vless,
    /// VMess protocol
    Vmess,
    /// Trojan protocol
    Trojan,
    /// TUIC protocol
    Tuic,
    /// Juicity protocol
    Juicity,
    /// Hysteria2 protocol
    Hysteria2,
}

#[allow(clippy::should_implement_trait)]
impl ProtocolType {
    /// Returns the protocol name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolType::Socks4 => "socks4",
            ProtocolType::Socks5 => "socks5",
            ProtocolType::Http => "http",
            ProtocolType::Shadowsocks => "shadowsocks",
            ProtocolType::Vless => "vless",
            ProtocolType::Vmess => "vmess",
            ProtocolType::Trojan => "trojan",
            ProtocolType::Tuic => "tuic",
            ProtocolType::Juicity => "juicity",
            ProtocolType::Hysteria2 => "hysteria2",
        }
    }

    /// Get protocol type from string name
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "socks4" | "socks4a" => Some(ProtocolType::Socks4),
            "socks5" | "socks" => Some(ProtocolType::Socks5),
            "http" | "https" => Some(ProtocolType::Http),
            "shadowsocks" | "ss" => Some(ProtocolType::Shadowsocks),
            "vless" => Some(ProtocolType::Vless),
            "vmess" => Some(ProtocolType::Vmess),
            "trojan" => Some(ProtocolType::Trojan),
            "tuic" => Some(ProtocolType::Tuic),
            "juicity" => Some(ProtocolType::Juicity),
            "hysteria2" | "h2" => Some(ProtocolType::Hysteria2),
            _ => None,
        }
    }
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// Re-export handler module and its types
pub mod handler;
pub use handler::ProtocolRegistry;

// Handler trait implementations (Zed-inspired)
//
// See module-level documentation at the top of this file for architecture overview.
//
// - [`Handler`] (from unified_handler): Recommended, connection-centric interface
// - [`ProtocolHandler`]: Legacy, Context-based interface (deprecated)
// - [`ProtocolHandlerAdapter`]: Bridge ProtocolHandler -> Handler for compatibility
#[deprecated(since = "0.1.0", note = "Use unified_handler instead")]
pub mod simple_handler;
pub mod unified_handler;

// Re-export Handler from unified_handler (the canonical Handler trait)
// unified_handler::Handler is preferred over simple_handler::Handler because:
// 1. HandlerConfig includes Debug bound for better ergonomics
// 2. Provides ProtocolHandlerAdapter for backward compatibility
// 3. Handler trait is more complete
pub use unified_handler::{Handler, HandlerConfig, HandlerStats, HandlerStatsExt};

// backward compatibility alias - simple_handler is deprecated
#[allow(deprecated)]
pub use simple_handler::{
    HandlerStats as SimpleHandlerStats, HandlerStatsExt as SimpleHandlerStatsExt,
};

// Protocol submodules for future expansion
pub mod http;
pub mod relay;
pub mod shadowsocks;
pub mod socks5;
pub mod vless;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_type_as_str() {
        assert_eq!(ProtocolType::Socks5.as_str(), "socks5");
        assert_eq!(ProtocolType::Http.as_str(), "http");
        assert_eq!(ProtocolType::Shadowsocks.as_str(), "shadowsocks");
        assert_eq!(ProtocolType::Vless.as_str(), "vless");
        assert_eq!(ProtocolType::Vmess.as_str(), "vmess");
        assert_eq!(ProtocolType::Trojan.as_str(), "trojan");
    }

    #[test]
    fn test_protocol_type_from_str() {
        assert_eq!(ProtocolType::from_str("socks5"), Some(ProtocolType::Socks5));
        assert_eq!(ProtocolType::from_str("SOCKS5"), Some(ProtocolType::Socks5));
        assert_eq!(ProtocolType::from_str("http"), Some(ProtocolType::Http));
        assert_eq!(
            ProtocolType::from_str("ss"),
            Some(ProtocolType::Shadowsocks)
        );
        assert_eq!(ProtocolType::from_str("vless"), Some(ProtocolType::Vless));
        assert_eq!(ProtocolType::from_str("unknown"), None);
    }

    #[test]
    fn test_protocol_type_display() {
        assert_eq!(format!("{}", ProtocolType::Socks5), "socks5");
        assert_eq!(format!("{}", ProtocolType::Vmess), "vmess");
    }
}
