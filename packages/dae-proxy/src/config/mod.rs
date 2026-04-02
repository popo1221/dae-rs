//! Configuration module for dae-proxy
//!
//! This module provides configuration management including:
//! - Hot reload support for configuration files
//! - File system watching for real-time updates

pub mod hot_reload;

pub use hot_reload::{
    ConfigEvent, HotReload, HotReloadError, HotReloadable, WatchEvent, WatchEventKind,
};
