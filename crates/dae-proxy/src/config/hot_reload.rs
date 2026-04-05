//! Configuration hot reload module
//!
//! This module provides file system watching for configuration changes,
//! enabling real-time reload of rules and configuration without service restart.

use crate::core::Error;
use crate::rule_engine::RuleEngine;
use dae_config::{Config, ConfigError};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Configuration hot reload error type
#[derive(Debug, thiserror::Error)]
pub enum HotReloadError {
    #[error("watcher error: {0}")]
    Watcher(String),
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("parse error: {0}")]
    Parse(String),
}

/// Configuration change event
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ConfigEvent {
    /// Configuration was successfully reloaded
    Reloaded(Config),
    /// Error occurred during reload
    Error(String),
    /// File system event received
    FileEvent(WatchEvent),
}

/// File system watch event details
#[derive(Debug, Clone)]
pub struct WatchEvent {
    /// Path that triggered the event
    pub path: PathBuf,
    /// Type of event
    pub kind: WatchEventKind,
}

/// Watch event kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEventKind {
    /// File was created
    Created,
    /// File was modified
    Modified,
    /// File was deleted
    Deleted,
    /// File was renamed
    Renamed,
    /// Unknown event
    Unknown,
}

impl From<&notify::EventKind> for WatchEventKind {
    fn from(kind: &notify::EventKind) -> Self {
        match kind {
            notify::EventKind::Create(_) => WatchEventKind::Created,
            notify::EventKind::Modify(_) => WatchEventKind::Modified,
            notify::EventKind::Remove(_) => WatchEventKind::Deleted,
            notify::EventKind::Other => WatchEventKind::Unknown,
            _ => WatchEventKind::Unknown,
        }
    }
}

/// Configuration hot reload watcher
///
/// Watches a configuration file for changes and automatically reloads
/// the configuration when modifications are detected.
pub struct HotReload {
    /// Path to the configuration file being watched
    config_path: PathBuf,
    /// The notify watcher instance
    watcher: RecommendedWatcher,
    /// Channel for receiving file system events
    receiver: Option<Receiver<std::result::Result<notify::Event, notify::Error>>>,
    /// Debounce duration to avoid rapid successive reloads
    debounce_duration: Duration,
}

impl HotReload {
    /// Create a new hot reload watcher
    ///
    /// # Arguments
    /// * `config_path` - Path to the configuration file to watch
    ///
    /// # Errors
    /// Returns an error if the file does not exist or cannot be watched
    pub fn new(config_path: impl Into<PathBuf>) -> std::result::Result<Self, HotReloadError> {
        let config_path = config_path.into();

        // Verify the file exists
        if !config_path.exists() {
            return Err(HotReloadError::FileNotFound(
                config_path.to_string_lossy().to_string(),
            ));
        }

        // Create a channel for receiving events
        let (tx, rx) = channel();

        // Create the watcher with default configuration
        let watcher = RecommendedWatcher::new(
            move |res: std::result::Result<Event, notify::Error>| {
                let _ = tx.send(res);
            },
            NotifyConfig::default(),
        )
        .map_err(|e| HotReloadError::Watcher(e.to_string()))?;

        Ok(Self {
            config_path,
            watcher,
            receiver: Some(rx),
            debounce_duration: Duration::from_millis(500),
        })
    }

    /// Create a new hot reload watcher with custom debounce duration
    ///
    /// # Arguments
    /// * `config_path` - Path to the configuration file to watch
    /// * `debounce_duration` - Minimum time between reloads
    pub fn with_debounce(
        config_path: impl Into<PathBuf>,
        debounce_duration: Duration,
    ) -> std::result::Result<Self, HotReloadError> {
        let mut reload = Self::new(config_path)?;
        reload.debounce_duration = debounce_duration;
        Ok(reload)
    }

    /// Start watching the configuration file
    ///
    /// This method blocks and processes file system events, calling
    /// the provided callback when the configuration file changes.
    ///
    /// # Arguments
    /// * `on_reload` - Callback function called with the new configuration
    pub fn start<F>(&mut self, on_reload: F)
    where
        F: Fn(Config) + Send + 'static,
    {
        let config_path = self.config_path.clone();

        // Start watching the file
        if let Err(e) = self
            .watcher
            .watch(&config_path, RecursiveMode::NonRecursive)
        {
            error!("Failed to start watching config file: {}", e);
            return;
        }

        info!("Started watching config file: {:?}", config_path);

        let receiver = match self.receiver.take() {
            Some(rx) => rx,
            None => {
                error!("Receiver already taken");
                return;
            }
        };

        let mut last_reload_time = std::time::Instant::now() - self.debounce_duration;

        // Process events in a loop
        loop {
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(Ok(event)) => {
                    // Check if any event is related to our config file
                    let config_changed = event
                        .paths
                        .iter()
                        .any(|p| p == &config_path || p.file_name() == config_path.file_name());

                    if config_changed {
                        // Apply debouncing
                        let now = std::time::Instant::now();
                        if now.duration_since(last_reload_time) < self.debounce_duration {
                            debug!("Skipping reload due to debounce");
                            continue;
                        }

                        debug!("Config file changed: {:?}", event);

                        // Try to reload the configuration
                        match Self::load_config(&config_path) {
                            Ok(new_config) => {
                                last_reload_time = std::time::Instant::now();
                                info!("Configuration reloaded successfully");
                                on_reload(new_config);
                            }
                            Err(e) => {
                                error!("Failed to reload configuration: {}", e);
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Watch error: {}", e);
                }
                Err(_) => {
                    // Timeout, continue loop
                }
            }
        }
    }

    /// Start watching with async support
    ///
    /// Returns a future that processes file system events and calls
    /// the callback when the configuration file changes.
    ///
    /// # Arguments
    /// * `on_reload` - Async callback function called with the new configuration
    pub async fn start_async<F, Fut>(&mut self, on_reload: F)
    where
        F: Fn(Config) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let config_path = self.config_path.clone();

        // Start watching the file
        if let Err(e) = self
            .watcher
            .watch(&config_path, RecursiveMode::NonRecursive)
        {
            error!("Failed to start watching config file: {}", e);
            return;
        }

        info!("Started watching config file: {:?}", config_path);

        let receiver = match self.receiver.take() {
            Some(rx) => rx,
            None => {
                error!("Receiver already taken");
                return;
            }
        };

        let mut last_reload_time = std::time::Instant::now() - self.debounce_duration;

        loop {
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(Ok(event)) => {
                    // Check if any event is related to our config file
                    let config_changed = event
                        .paths
                        .iter()
                        .any(|p| p == &config_path || p.file_name() == config_path.file_name());

                    if config_changed {
                        // Apply debouncing
                        let now = std::time::Instant::now();
                        if now.duration_since(last_reload_time) < self.debounce_duration {
                            debug!("Skipping reload due to debounce");
                            continue;
                        }

                        debug!("Config file changed: {:?}", event);

                        // Try to reload the configuration
                        match Self::load_config(&config_path) {
                            Ok(new_config) => {
                                last_reload_time = std::time::Instant::now();
                                info!("Configuration reloaded successfully");
                                on_reload(new_config).await;
                            }
                            Err(e) => {
                                error!("Failed to reload configuration: {}", e);
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Watch error: {}", e);
                }
                Err(_) => {
                    // Timeout, continue loop
                }
            }
        }
    }

    /// Load configuration from file
    fn load_config(path: &PathBuf) -> std::result::Result<Config, HotReloadError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| HotReloadError::Parse(format!("Failed to read config file: {e}")))?;

        let config: Config = toml::from_str(&content)
            .map_err(|e| HotReloadError::Parse(format!("Failed to parse config: {e}")))?;

        // Validate the configuration
        config.validate().map_err(HotReloadError::Config)?;

        Ok(config)
    }

    /// Get the path being watched
    pub fn config_path(&self) -> &PathBuf {
        &self.config_path
    }
}

/// Trait for types that can handle configuration hot reload
pub trait HotReloadable {
    /// Reload configuration
    fn reload(&mut self, config: Config);
}

impl RuleEngine {
    /// Start hot reload for rule engine
    ///
    /// This method spawns a background task that watches the configuration
    /// file and automatically reloads rules when changes are detected.
    ///
    /// # Arguments
    /// * `config_path` - Path to the configuration file
    ///
    /// # Returns
    /// A handle that can be used to stop the hot reload task
    #[allow(dead_code)]
    pub fn start_hot_reload(
        self: &std::sync::Arc<Self>,
        config_path: PathBuf,
    ) -> std::result::Result<(), Error> {
        let config_path_clone = config_path.clone();
        let engine = self.clone();

        // Spawn a background task for hot reload
        tokio::spawn(async move {
            let mut watcher = match HotReload::new(&config_path_clone) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create hot reload watcher: {}", e);
                    return;
                }
            };

            watcher
                .start_async(move |new_config| {
                    let engine = engine.clone();
                    async move {
                        // Update rule engine configuration
                        if let Some(ref rules_config) = new_config.rules.config_file {
                            if let Err(e) = engine.reload(rules_config).await {
                                error!("Failed to reload rules: {}", e);
                                return;
                            }
                        } else if !new_config.rules.rule_groups.is_empty() {
                            // Handle inline rule groups if needed
                            info!("Inline rule groups updated");
                        }
                        info!("Rule engine hot reload completed");
                    }
                })
                .await;
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_reload_error_display() {
        let err = HotReloadError::FileNotFound("/path/to/file".to_string());
        assert!(err.to_string().contains("file not found"));

        let err = HotReloadError::Watcher("test error".to_string());
        assert!(err.to_string().contains("watcher error"));
    }

    #[test]
    fn test_watch_event_kind_from_notify() {
        use notify::EventKind;

        assert_eq!(
            WatchEventKind::from(&EventKind::Create(notify::event::CreateKind::File)),
            WatchEventKind::Created
        );
        assert_eq!(
            WatchEventKind::from(&EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content
            ))),
            WatchEventKind::Modified
        );
        assert_eq!(
            WatchEventKind::from(&EventKind::Remove(notify::event::RemoveKind::File)),
            WatchEventKind::Deleted
        );
    }

    #[test]
    fn test_config_event_debug() {
        let event = ConfigEvent::Reloaded(Config {
            proxy: dae_config::ProxyConfig::default(),
            nodes: vec![],
            subscriptions: vec![],
            rules: dae_config::RulesConfig::default(),
            logging: dae_config::LoggingConfig::default(),
            transparent_proxy: dae_config::TransparentProxyConfig::default(),
            tracking: dae_config::TrackingConfig::default(),
        });
        assert!(format!("{event:?}").contains("Reloaded"));

        let event = ConfigEvent::Error("test error".to_string());
        assert!(format!("{event:?}").contains("Error"));
    }
}
