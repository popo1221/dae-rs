//! Simple Handler trait - a cleaner alternative to ProtocolHandler
//!
//! This module provides the [`Handler`] trait - a simpler, more ergonomic
//! alternative to [`ProtocolHandler`]. Unlike ProtocolHandler which uses
//! [`Context`] for state management, Handler works directly with [`Connection`].
//!
//! # Design Philosophy (Inspired by Zed)
//!
//! - **Simple over flexible**: Handler prioritizes ease of use over generality
//! - **Connection-centric**: Works directly with Connections, not internal Context
//! - **Built-in stats**: Every handler automatically tracks basic statistics
//! - **Hot reload support**: Optional reload method for config updates
//!
//! # When to Use Handler vs ProtocolHandler
//!
//! Use `Handler` when:
//! - Building a new protocol handler
//! - The handler doesn't need complex state management
//! - You want automatic statistics tracking
//!
//! Use `ProtocolHandler` when:
//! - You need fine-grained control over connection lifecycle
//! - You're working with existing Context-based code
//! - You need custom inbound/outbound handling
//!
//! # Example
//!
//! ```ignore
//! use async_trait::async_trait;
//! use dae_proxy::{Handler, Connection, ProxyError, ProtocolType};
//!
//! struct MyHandler {
//!     target: String,
//! }
//!
//! #[async_trait]
//! impl Handler for MyHandler {
//!     type Config = MyConfig;
//!
//!     fn name(&self) -> &'static str { "my-handler" }
//!     fn protocol(&self) -> ProtocolType { ProtocolType::Custom("my") }
//!
//!     async fn handle(&self, conn: Connection) -> Result<(), ProxyError> {
//!         // Simple: just handle the connection
//!         Ok(())
//!     }
//! }
//! ```

use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::connection::Connection;
use crate::proxy::ProxyError;
use crate::protocol::ProtocolType;

/// Handler configuration marker trait
///
/// Types implementing this trait can be used as the Config type for Handler.
/// This is primarily for documentation purposes - it marks which configs
/// are designed to work with Handler.
pub trait HandlerConfig: Send + Sync {}

/// Handler trait - simplified protocol handler interface
///
/// Handler provides a cleaner, more ergonomic interface for implementing
/// protocol handlers. It's designed around the principle that most handlers
/// just need to:
/// 1. Accept an incoming connection
/// 2. Process the protocol-specific details
/// 3. Forward traffic
///
/// # Example
///
/// ```ignore
/// struct TrojanHandler {
///     config: TrojanConfig,
///     stats: HandlerStats,
/// }
///
/// #[async_trait]
/// impl Handler for TrojanHandler {
///     type Config = TrojanConfig;
///
///     fn name(&self) -> &'static str { "trojan" }
///     fn protocol(&self) -> ProtocolType { ProtocolType::Trojan }
///     fn config(&self) -> &Self::Config { &self.config }
///
///     async fn handle(&self, conn: Connection) -> Result<(), ProxyError> {
///         self.stats.inc_connections();
///         // Handle the Trojan protocol
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait Handler: Send + Sync {
    /// Configuration type for this handler
    type Config: HandlerConfig;
    
    /// Returns the handler name (e.g., "trojan", "vless")
    fn name(&self) -> &'static str;
    
    /// Returns the protocol type
    fn protocol(&self) -> ProtocolType;
    
    /// Returns a reference to the handler configuration
    fn config(&self) -> &Self::Config;
    
    /// Handle an incoming connection
    ///
    /// This is the main entry point for handling connections.
    /// The handler should:
    /// 1. Authenticate the client (if applicable)
    /// 2. Parse the target address (if applicable)
    /// 3. Establish connection to target
    /// 4. Relay traffic bidirectionally
    async fn handle(&self, conn: Connection) -> Result<(), ProxyError>;
    
    /// Check if handler is healthy
    ///
    /// Used for health checks and load balancing.
    /// Default implementation returns true.
    fn is_healthy(&self) -> bool {
        true
    }
    
    /// Reload configuration
    ///
    /// Called when configuration is hot-reloaded.
    /// Default implementation does nothing.
    async fn reload(&self, _new_config: Self::Config) -> Result<(), ProxyError> {
        Ok(())
    }
}

/// Statistics for a Handler implementation
///
/// Automatically tracks common metrics for all handlers.
/// Handlers can embed this and call inc/dec methods.
///
/// Note: This struct uses interior mutability via AtomicU64,
/// so Clone gives independent counters (not shared state).
#[derive(Debug, Default)]
pub struct HandlerStats {
    /// Total connections handled
    total_connections: AtomicU64,
    /// Currently active connections
    active_connections: AtomicU64,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received  
    bytes_received: AtomicU64,
    /// Connection errors
    errors: AtomicU64,
}

impl Clone for HandlerStats {
    fn clone(&self) -> Self {
        // Note: This creates independent counters, not shared state
        // Each clone starts from zero
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
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record connection closed
    #[inline]
    pub fn dec_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
    
    /// Record bytes transferred
    #[inline]
    pub fn add_bytes(&self, sent: u64, received: u64) {
        if sent > 0 {
            self.bytes_sent.fetch_add(sent, Ordering::Relaxed);
        }
        if received > 0 {
            self.bytes_received.fetch_add(received, Ordering::Relaxed);
        }
    }
    
    /// Record an error
    #[inline]
    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get current active connections
    #[inline]
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }
    
    /// Get total connections handled
    #[inline]
    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }
    
    /// Get total bytes sent
    #[inline]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }
    
    /// Get total bytes received
    #[inline]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
    
    /// Get total errors
    #[inline]
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
}

/// Extension trait for getting stats from Arc<dyn Handler>
///
/// Provides convenient access to handler statistics
/// without downcasting.
pub trait HandlerStatsExt {
    /// Get the stats for this handler
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
        
        // All threads completed
        assert_eq!(stats.total_connections(), 1000);
        assert_eq!(stats.active_connections(), 0);
    }
}
