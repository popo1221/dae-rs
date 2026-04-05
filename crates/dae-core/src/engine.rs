//! Core engine module

use std::sync::Arc;
use tokio::sync::RwLock;

/// Main engine state
pub struct Engine {
    state: Arc<RwLock<EngineState>>,
}

#[derive(Debug, Clone, Default)]
pub struct EngineState {
    pub running: bool,
    pub processed_count: u64,
}

impl Engine {
    /// Create a new engine instance
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(EngineState::default())),
        }
    }

    /// Start the engine
    pub async fn start(&self) {
        let mut state = self.state.write().await;
        state.running = true;
        tracing::info!("dae-rs engine started");
    }

    /// Stop the engine
    pub async fn stop(&self) {
        let mut state = self.state.write().await;
        state.running = false;
        tracing::info!("dae-rs engine stopped");
    }

    /// Check if engine is running
    pub async fn is_running(&self) -> bool {
        self.state.read().await.running
    }

    /// Increment processed count
    pub async fn increment(&self) {
        self.state.write().await.processed_count += 1;
    }

    /// Get current state
    pub async fn state(&self) -> EngineState {
        self.state.read().await.clone()
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_start_stop() {
        let engine = Engine::new();
        assert!(!engine.is_running().await);

        engine.start().await;
        assert!(engine.is_running().await);

        engine.stop().await;
        assert!(!engine.is_running().await);
    }
}
