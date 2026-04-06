//! Protocol handler registry
//!
//! This module provides the [`ProtocolRegistry`] which maintains a collection
//! of registered protocol handlers. It allows dynamic registration and lookup
//! of protocol handlers at runtime.

use crate::protocol::{ProtocolHandler, ProtocolType};
use std::collections::HashMap;
use std::sync::Arc;

/// Protocol handler registry
///
/// Maintains a mapping of [`ProtocolType`] to registered [`ProtocolHandler`] implementations.
/// Handlers can be registered at startup and looked up when processing connections.
#[derive(Default)]
pub struct ProtocolRegistry {
    handlers: HashMap<ProtocolType, Arc<dyn ProtocolHandler>>,
}

impl ProtocolRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a protocol handler
    ///
    /// # Arguments
    /// * `protocol` - The protocol type to register
    /// * `handler` - The handler implementation
    pub fn register<H: ProtocolHandler + 'static>(&mut self, protocol: ProtocolType, handler: H) {
        self.handlers.insert(protocol, Arc::new(handler));
    }

    /// Get a registered handler by protocol type
    ///
    /// # Arguments
    /// * `protocol` - The protocol type to look up
    ///
    /// Returns the handler if found, None otherwise.
    pub fn get(&self, protocol: ProtocolType) -> Option<Arc<dyn ProtocolHandler>> {
        self.handlers.get(&protocol).cloned()
    }

    /// Check if a protocol handler is registered
    ///
    /// # Arguments
    /// * `protocol` - The protocol type to check
    ///
    /// Returns true if a handler is registered for this protocol.
    pub fn contains(&self, protocol: ProtocolType) -> bool {
        self.handlers.contains_key(&protocol)
    }

    /// Unregister a protocol handler
    ///
    /// # Arguments
    /// * `protocol` - The protocol type to unregister
    ///
    /// Returns the unregistered handler if it existed.
    pub fn unregister(&mut self, protocol: ProtocolType) -> Option<Arc<dyn ProtocolHandler>> {
        self.handlers.remove(&protocol)
    }

    /// Get the number of registered handlers
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Get an iterator over all registered protocol types
    pub fn protocols(&self) -> impl Iterator<Item = ProtocolType> + '_ {
        self.handlers.keys().copied()
    }
}

impl std::fmt::Debug for ProtocolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolRegistry")
            .field("handlers", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Context, Result as ProxyResult};
    use async_trait::async_trait;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;

    struct TestHandler {
        name: &'static str,
    }

    #[async_trait]
    impl ProtocolHandler for TestHandler {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn handle_inbound(&self, _ctx: &mut Context) -> ProxyResult<()> {
            Ok(())
        }

        async fn handle_outbound(&self, _ctx: &mut Context) -> ProxyResult<()> {
            Ok(())
        }
    }



    #[test]
    fn test_registry_new() {
        let registry = ProtocolRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = ProtocolRegistry::new();

        let handler = TestHandler { name: "test" };
        registry.register(ProtocolType::Socks5, handler);

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.contains(ProtocolType::Socks5));

        let retrieved = registry.get(ProtocolType::Socks5);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name(), "test");
    }

    #[test]
    fn test_registry_get_nonexistent() {
        let registry = ProtocolRegistry::new();
        let retrieved = registry.get(ProtocolType::Http);
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_registry_unregister() {
        let mut registry = ProtocolRegistry::new();

        let handler = TestHandler { name: "test" };
        registry.register(ProtocolType::Socks5, handler);

        let removed = registry.unregister(ProtocolType::Socks5);
        assert!(removed.is_some());
        assert!(registry.is_empty());
        assert!(registry.get(ProtocolType::Socks5).is_none());
    }

    #[test]
    fn test_registry_multiple_protocols() {
        let mut registry = ProtocolRegistry::new();

        registry.register(ProtocolType::Socks5, TestHandler { name: "socks5" });
        registry.register(ProtocolType::Http, TestHandler { name: "http" });
        registry.register(ProtocolType::Shadowsocks, TestHandler { name: "ss" });

        assert_eq!(registry.len(), 3);

        let protocols: Vec<_> = registry.protocols().collect();
        assert!(protocols.contains(&ProtocolType::Socks5));
        assert!(protocols.contains(&ProtocolType::Http));
        assert!(protocols.contains(&ProtocolType::Shadowsocks));
    }

    #[test]
    fn test_registry_override() {
        let mut registry = ProtocolRegistry::new();

        registry.register(ProtocolType::Socks5, TestHandler { name: "first" });
        registry.register(ProtocolType::Socks5, TestHandler { name: "second" });

        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get(ProtocolType::Socks5).unwrap().name(), "second");
    }

    #[test]
    fn test_registry_debug() {
        let mut registry = ProtocolRegistry::new();
        registry.register(ProtocolType::Socks5, TestHandler { name: "test" });

        let debug_str = format!("{registry:?}");
        assert!(debug_str.contains("ProtocolRegistry"));
    }
}
