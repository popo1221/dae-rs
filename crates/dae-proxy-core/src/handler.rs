//! Handler trait for protocol handlers
//!
//! This module provides the unified Handler trait that all protocol
//! implementations must implement.

use async_trait::async_trait;
use crate::{Context, Result};

/// Handler configuration trait
///
/// Types implementing this trait can be used as the Config type for Handler.
pub trait HandlerConfig: Send + Sync + std::fmt::Debug {}

/// Unified Handler trait - single interface for all protocol handlers
///
/// This trait defines the interface for handling connections in the proxy.
/// All protocol implementations (SOCKS5, VLESS, VMess, etc.) must implement this trait.
#[async_trait]
pub trait Handler: Send + Sync {
    /// Returns the handler name
    fn name(&self) -> &'static str;

    /// Handle a connection
    async fn handle(&self, ctx: &mut Context) -> Result<()>;
}
