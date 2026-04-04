//! SOCKS5 protocol handler
//!
//! Implementation of SOCKS5 protocol (RFC 1928)

use async_trait::async_trait;
use dae_proxy_core::{Context, Handler, HandlerConfig, Result};

/// SOCKS5 authentication methods
#[derive(Debug, Clone, Copy)]
pub enum AuthMethod {
    /// No authentication
    NoAuth = 0x00,
    /// Username/password authentication
    UserPass = 0x02,
    /// No acceptable methods
    NoAcceptable = 0xFF,
}

/// SOCKS5 command types
#[derive(Debug, Clone, Copy)]
pub enum Command {
    /// Connect to a remote host
    Connect = 0x01,
    /// Bind a port for incoming connections
    Bind = 0x02,
    /// Associate UDP port
    UdpAssociate = 0x03,
}

/// SOCKS5 address types
#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    /// IPv4 address
    IPv4 = 0x01,
    /// Domain name
    Domain = 0x03,
    /// IPv6 address
    IPv6 = 0x04,
}

/// SOCKS5 reply codes
#[derive(Debug, Clone, Copy)]
pub enum ReplyCode {
    Success = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressNotSupported = 0x08,
}

/// SOCKS5 handler configuration
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// Whether to require authentication
    pub require_auth: bool,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            require_auth: false,
        }
    }
}

impl HandlerConfig for Socks5Config {}

/// SOCKS5 protocol handler
pub struct Socks5Handler {
    config: Socks5Config,
}

impl Socks5Handler {
    /// Create a new SOCKS5 handler
    pub fn new(config: Socks5Config) -> Self {
        Self { config }
    }

    /// Get the configuration
    pub fn config(&self) -> &Socks5Config {
        &self.config
    }
}

impl Default for Socks5Handler {
    fn default() -> Self {
        Self::new(Socks5Config::default())
    }
}

#[async_trait]
impl Handler for Socks5Handler {
    fn name(&self) -> &'static str {
        "socks5"
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        // TODO: Implement SOCKS5 protocol handling
        // 1. Greeting and authentication negotiation
        // 2. Connection request parsing
        // 3. Connect to target
        // 4. Send reply
        tracing::info!(
            "SOCKS5 handling connection from {} to {}",
            ctx.source,
            ctx.destination
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_name() {
        let handler = Socks5Handler::default();
        assert_eq!(handler.name(), "socks5");
    }

    #[test]
    fn test_config_default() {
        let config = Socks5Config::default();
        assert!(!config.require_auth);
    }
}
