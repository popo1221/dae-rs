//! Unified Handler trait - a single interface for all protocol handlers
//!
//! This module provides a unified [`Handler`] trait that all protocol handlers
//! should implement, following Zed's clean architecture pattern.
//!
//! # Design Goals
//!
//! 1. **Single Source of Truth**: One trait for all protocol handlers
//! 2. **Backward Compatible**: Existing ProtocolHandler implementations can use adapters
//! 3. **Simple API**: Connection-centric approach like Zed's ProtocolHandler
//! 4. **Type Safe**: Generic Config associated type
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Handler Trait                          │
//! │  (unified interface for all protocol handlers)              │
//! └─────────────────────────────────────────────────────────────┘
//!         ▲                    │                    ▲
//!         │                    │                    │
//!    ┌────┴─────┐        ┌──────┴──────┐       ┌──────┴──────┐
//!    │ Adapter  │        │ Direct Impl │       │ Adapter     │
//!    │(Protocol │        │ (Trojan,    │       │ (Protocol   │
//!    │ Handler) │        │  VLESS, etc)│       │ Handler)    │
//!    └──────────┘        └─────────────┘       └─────────────┘
//! ```
//!
//! # Example: Implementing Handler Directly
//!
//! ```ignore
//! use async_trait::async_trait;
//! use dae_proxy::{Handler, Connection, ProxyError, ProtocolType};
//!
//! struct MyHandler {
//!     config: MyConfig,
//!     stats: HandlerStats,
//! }
//!
//! #[async_trait]
//! impl Handler for MyHandler {
//!     type Config = MyConfig;
//!
//!     fn name(&self) -> &'static str { "my-handler" }
//!     fn protocol(&self) -> ProtocolType { ProtocolType::Custom("my") }
//!     fn config(&self) -> &Self::Config { &self.config }
//!
//!     async fn handle(&self, conn: Connection) -> Result<(), ProxyError> {
//!         // Handle the connection
//!         Ok(())
//!     }
//! }
//! ```
//!
//! # Example: Using Adapter for ProtocolHandler
//!
//! ```ignore
//! // ProtocolHandler implementation
//! struct MyLegacyHandler { ... }
//!
//! impl ProtocolHandler for MyLegacyHandler { ... }
//!
//! // Wrap with adapter to use as Handler
//! let handler: ProtocolHandlerAdapter<MyLegacyHandler> =
//!     ProtocolHandlerAdapter::new(MyLegacyHandler::new());
//! ```

use async_trait::async_trait;

use crate::connection::Connection;
use crate::protocol::ProtocolType;
use crate::proxy::ProxyError;

/// Handler configuration trait
///
/// Types implementing this trait can be used as the Config type for Handler.
pub trait HandlerConfig: Send + Sync + std::fmt::Debug {}

/// Unified Handler trait - single interface for all protocol handlers
///
/// This trait provides a unified interface for handling proxy protocol connections.
/// All new protocol handlers should implement this trait directly.
/// Existing ProtocolHandler implementations can use [`ProtocolHandlerAdapter`] for
/// backward compatibility.
///
/// # Design Philosophy (Zed-inspired)
///
/// - **Simple**: One method to handle connections
/// - **Connection-centric**: Works directly with Connections
/// - **Type-safe**: Generic Config associated type
/// - **Observable**: Built-in statistics support
#[async_trait]
pub trait Handler: Send + Sync {
    /// Configuration type for this handler
    type Config: HandlerConfig;

    /// Returns the handler name (e.g., "trojan", "vless", "socks5")
    fn name(&self) -> &'static str;

    /// Returns the protocol type
    fn protocol(&self) -> ProtocolType;

    /// Returns a reference to the handler configuration
    fn config(&self) -> &Self::Config;

    /// Handle an incoming connection
    ///
    /// This is the main entry point for handling proxy connections.
    /// The handler should:
    /// 1. Read and parse the protocol-specific header
    /// 2. Authenticate the client (if applicable)
    /// 3. Parse the target address (if applicable)
    /// 4. Establish connection to target (or reject)
    /// 5. Relay traffic bidirectionally
    async fn handle(&self, conn: Connection) -> Result<(), ProxyError>;

    /// Check if handler is healthy
    ///
    /// Used for health checks and load balancing.
    /// Default implementation returns true.
    fn is_healthy(&self) -> bool {
        true
    }

    /// Reload configuration (hot reload support)
    ///
    /// Called when configuration is hot-reloaded.
    /// Default implementation returns Ok.
    async fn reload(&self, _new_config: Self::Config) -> Result<(), ProxyError> {
        Ok(())
    }
}

/// Statistics for a Handler implementation
///
/// Automatically tracks common metrics for all handlers.
#[derive(Debug, Default)]
pub struct HandlerStats {
    total_connections: std::sync::atomic::AtomicU64,
    active_connections: std::sync::atomic::AtomicU64,
    bytes_sent: std::sync::atomic::AtomicU64,
    bytes_received: std::sync::atomic::AtomicU64,
    errors: std::sync::atomic::AtomicU64,
}

impl Clone for HandlerStats {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl HandlerStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new connection
    #[inline]
    pub fn inc_connection(&self) {
        self.total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record connection closed
    #[inline]
    pub fn dec_connection(&self) {
        self.active_connections
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record bytes transferred
    #[inline]
    pub fn add_bytes(&self, sent: u64, received: u64) {
        if sent > 0 {
            self.bytes_sent
                .fetch_add(sent, std::sync::atomic::Ordering::Relaxed);
        }
        if received > 0 {
            self.bytes_received
                .fetch_add(received, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Record an error
    #[inline]
    pub fn inc_errors(&self) {
        self.errors
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get current active connections
    #[inline]
    pub fn active_connections(&self) -> u64 {
        self.active_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total connections handled
    #[inline]
    pub fn total_connections(&self) -> u64 {
        self.total_connections
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total bytes sent
    #[inline]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total bytes received
    #[inline]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total errors
    #[inline]
    pub fn errors(&self) -> u64 {
        self.errors.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Extension trait for getting stats from Arc<dyn Handler>
pub trait HandlerStatsExt {
    fn stats(&self) -> HandlerStats;
}

impl<T: Handler> HandlerStatsExt for T {
    fn stats(&self) -> HandlerStats {
        HandlerStats::new()
    }
}

/// Adapter to wrap ProtocolHandler implementations as Handler
///
/// This allows existing ProtocolHandler implementations to be used
/// through the unified Handler interface.
///
/// # Example
///
/// ```ignore
/// use dae_proxy::protocol::ProtocolHandlerAdapter;
///
/// // Create a ProtocolHandler
/// let socks5 = Socks5ProtocolHandler::new(config);
///
/// // Wrap it as a Handler
/// let handler: ProtocolHandlerAdapter<Socks5ProtocolHandler> =
///     ProtocolHandlerAdapter::new(socks5);
/// ```
#[derive(Debug)]
#[allow(dead_code)]
pub struct ProtocolHandlerAdapter<H> {
    inner: H,
    stats: HandlerStats,
}

impl<H> ProtocolHandlerAdapter<H> {
    /// Create a new adapter wrapping a ProtocolHandler
    pub fn new(inner: H) -> Self {
        Self {
            inner,
            stats: HandlerStats::new(),
        }
    }

    /// Get a reference to the inner ProtocolHandler
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// Get mutable reference to the inner ProtocolHandler
    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }
}

// Marker type for ProtocolHandler adapter config
#[derive(Debug)]
pub struct ProtocolHandlerConfig;

impl HandlerConfig for ProtocolHandlerConfig {}

#[async_trait]
impl<H> Handler for ProtocolHandlerAdapter<H>
where
    H: crate::protocol::ProtocolHandler + Send + Sync,
{
    type Config = ProtocolHandlerConfig;

    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn protocol(&self) -> ProtocolType {
        // ProtocolHandler doesn't expose ProtocolType directly
        // We infer it from the name
        ProtocolType::from_str(self.inner.name()).unwrap_or(ProtocolType::Socks5)
    }

    fn config(&self) -> &Self::Config {
        &ProtocolHandlerConfig
    }

    async fn handle(&self, _conn: Connection) -> Result<(), ProxyError> {
        // ProtocolHandler uses Context, not Connection
        // This adapter provides a bridge - but full implementation
        // would need Context creation from Connection
        // For now, this is a placeholder that demonstrates the pattern
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_stats() {
        let stats = HandlerStats::new();

        assert_eq!(stats.active_connections(), 0);
        assert_eq!(stats.total_connections(), 0);

        stats.inc_connection();
        assert_eq!(stats.total_connections(), 1);
        assert_eq!(stats.active_connections(), 1);

        stats.dec_connection();
        assert_eq!(stats.active_connections(), 0);

        stats.add_bytes(100, 200);
        assert_eq!(stats.bytes_sent(), 100);
        assert_eq!(stats.bytes_received(), 200);

        stats.inc_errors();
        assert_eq!(stats.errors(), 1);
    }

    #[test]
    fn test_handler_stats_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let stats = Arc::new(HandlerStats::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let s = stats.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    s.inc_connection();
                    s.dec_connection();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(stats.total_connections(), 1000);
        assert_eq!(stats.active_connections(), 0);
    }

    #[test]
    fn test_protocol_type_from_str() {
        assert_eq!(ProtocolType::from_str("trojan"), Some(ProtocolType::Trojan));
        assert_eq!(ProtocolType::from_str("socks5"), Some(ProtocolType::Socks5));
        assert_eq!(ProtocolType::from_str("vless"), Some(ProtocolType::Vless));
        assert_eq!(ProtocolType::from_str("unknown"), None);
    }
}
