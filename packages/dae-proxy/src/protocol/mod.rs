//!
//! Protocol abstraction layer for dae-proxy
//!
//! This module provides a unified interface for handling various proxy protocols.
//! Each protocol implementation (SOCKS5, HTTP, Shadowsocks, VLESS, VMess, Trojan, etc.)
//! must implement the [`ProtocolHandler`] trait.

use crate::core::{Context, Result as ProxyResult};
use async_trait::async_trait;

/// Protocol handler trait - all protocol implementations must implement this trait
///
/// This trait defines the interface for handling inbound and outbound connections
/// for a specific proxy protocol.
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Returns the protocol name
    fn name(&self) -> &'static str;

    /// Handle inbound connection (client -> proxy)
    async fn handle_inbound(&self, ctx: &mut Context) -> ProxyResult<()>;

    /// Handle outbound connection (proxy -> remote)
    async fn handle_outbound(&self, ctx: &mut Context) -> ProxyResult<()>;
}

/// Protocol types supported by the proxy
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
// # Unified Handler Architecture
//
// The `simple_handler` module provides the Handler trait - a simpler alternative
// to ProtocolHandler that works directly with Connections.
//
// The `unified_handler` module provides a single unified Handler trait
// that all protocol handlers should eventually implement.
//
// For backward compatibility, existing ProtocolHandler implementations
// can use ProtocolHandlerAdapter from unified_handler.
pub mod simple_handler;
pub mod unified_handler;

// Re-export Handler from simple_handler for backward compatibility
pub use simple_handler::{Handler, HandlerConfig, HandlerStats, HandlerStatsExt};

// Protocol submodules for future expansion
pub mod http;
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
