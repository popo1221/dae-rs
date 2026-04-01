//! Protocol abstraction layer
//!
//! This module provides protocol type definitions and registry
//! for proxy protocol handlers.

use std::collections::HashMap;
use std::sync::Arc;

/// Protocol type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Http,
    Socks5,
    Shadowsocks,
    VLess,
    Trojan,
    Vmess,
}

impl ProtocolType {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolType::Http => "HTTP",
            ProtocolType::Socks5 => "SOCKS5",
            ProtocolType::Shadowsocks => "Shadowsocks",
            ProtocolType::VLess => "VLESS",
            ProtocolType::Trojan => "Trojan",
            ProtocolType::Vmess => "VMess",
        }
    }
}

/// Protocol handler trait
pub trait ProtocolHandler: Send + Sync {
    /// Get the protocol type
    fn protocol_type(&self) -> ProtocolType;
    
    /// Handle a new connection (takes raw connection info)
    fn handle(&self, local_addr: &str, remote_addr: &str);
}

/// Protocol registry for managing protocol handlers
pub struct ProtocolRegistry {
    handlers: HashMap<ProtocolType, Arc<dyn ProtocolHandler>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }
    
    pub fn register(&mut self, handler: Arc<dyn ProtocolHandler>) {
        self.handlers.insert(handler.protocol_type(), handler);
    }
    
    pub fn get(&self, protocol: ProtocolType) -> Option<Arc<dyn ProtocolHandler>> {
        self.handlers.get(&protocol).cloned()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
