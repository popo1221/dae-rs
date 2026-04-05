//! Unified Handler trait - a single interface for all protocol handlers
//!
//! This module provides a unified [`Handler`] trait that all protocol handlers
//! should implement.
//!
//! # Design Goals
//!
//! 1. **Single Source of Truth**: One trait for all protocol handlers
//! 2. **Stream-centric**: Works directly with TcpStream for simplicity
//! 3. **Simple API**: Single handle method with Arc<Self> pattern
//! 4. **Type Safe**: Generic Config associated type
//!
//! # Architecture
//!
//! All protocol handlers (Trojan, VLESS, VMess, SOCKS5, etc.) implement the
//! unified `Handler` trait using the `Arc<Self>` + `TcpStream` pattern:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Handler Trait                          │
//! │  async fn handle(self: Arc<Self>, stream: TcpStream)       │
//! └─────────────────────────────────────────────────────────────┘
//!         ▲                    │                    ▲
//!         │                    │                    │
//!    ┌────┴─────┐        ┌──────┴──────┐       ┌──────┴──────┐
//!    │ Trojan   │        │   VLESS     │       │   VMess     │
//!    │ Handler  │        │   Handler   │       │   Handler   │
//!    └──────────┘        └─────────────┘       └─────────────┘
//! ```
//!
//! # Example: Implementing Handler
//!
//! ```ignore
//! use async_trait::async_trait;
//! use dae_proxy::{Handler, ProxyError, ProtocolType};
//! use std::sync::Arc;
//! use tokio::net::TcpStream;
//!
//! struct MyHandler {
//!     config: MyConfig,
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
//!     async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
//!         // Handle the connection
//!         Ok(())
//!     }
//! }
//! ```

use async_trait::async_trait;
use std::sync::Arc;
use tokio::net::TcpStream;

use crate::protocol::ProtocolType;

/// Handler configuration trait
///
/// Types implementing this trait can be used as the Config type for Handler.
pub trait HandlerConfig: Send + Sync + std::fmt::Debug {}

/// Unified Handler trait - single interface for all protocol handlers
///
/// This trait provides a unified interface for handling proxy protocol connections.
/// All protocol handlers (Trojan, VLESS, VMess, SOCKS5, etc.) implement this trait.
///
/// # Design Philosophy
///
/// - **Simple**: One method to handle connections
/// - **Stream-centric**: Works directly with TcpStream
/// - **Arc<Self> pattern**: Enables shared ownership for connection handling
/// - **Type-safe**: Generic Config associated type
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
    ///
    /// # Arguments
    /// * `self` - Arc<Self> enabling shared ownership during async operations
    /// * `stream` - The TCP stream for the incoming connection
    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()>;

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
    async fn reload(&self, _new_config: Self::Config) -> std::io::Result<()> {
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
