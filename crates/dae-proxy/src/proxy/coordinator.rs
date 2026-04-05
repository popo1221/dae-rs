//! Coordinator module - manages connection coordination, broadcast channel, and shutdown signals
//!
//! This module handles the coordination aspects of the proxy including:
//! - Shutdown signal broadcast channel
//! - Running state management

use tokio::sync::broadcast;

/// Coordinator state for managing proxy lifecycle coordination
pub(crate) struct Coordinator {
    /// Broadcast channel for sending shutdown signals
    pub(crate) shutdown_tx: broadcast::Sender<()>,
}

impl Coordinator {
    /// Create a new coordinator with a shutdown broadcast channel
    pub(crate) fn new() -> (Self, broadcast::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        (Self { shutdown_tx }, shutdown_rx)
    }

    /// Send shutdown signal to all subscribers
    pub(crate) fn send_shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new().0
    }
}
