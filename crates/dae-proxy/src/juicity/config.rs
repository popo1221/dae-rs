//! Juicity configuration module
//!
//! Contains configuration types for the Juicity protocol.

use std::time::Duration;

use super::types::CongestionControl;

/// Juicity configuration
#[derive(Debug, Clone)]
pub struct JuicityConfig {
    /// Authentication token
    pub token: String,
    /// Server name for TLS SNI
    pub server_name: String,
    /// Server address (IP or domain)
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// Congestion control algorithm
    pub congestion_control: CongestionControl,
    /// Connection timeout
    pub timeout: Duration,
}

impl Default for JuicityConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            server_name: String::new(),
            server_addr: "127.0.0.1".to_string(),
            server_port: 443,
            congestion_control: CongestionControl::Bbr,
            timeout: Duration::from_secs(30),
        }
    }
}
