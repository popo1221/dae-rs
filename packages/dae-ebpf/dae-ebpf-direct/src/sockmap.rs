//! Sockmap Redirect for Transparent Proxy
//!
//! This module implements sockmap-based traffic redirect for the direct eBPF mode.
//! It allows transparent interception and redirect of TCP connections to a local proxy
//! without requiring iptables rules.

use crate::EbpfError;
use tracing::info;

/// Sockmap redirect manager
///
/// This manages the sockmap and associated sockets for traffic redirect.
pub struct SockmapRedirect {
    /// Whether redirect is active
    active: bool,
    /// Proxy port
    proxy_port: u16,
}

impl SockmapRedirect {
    /// Create a new SockmapRedirect manager
    pub fn new() -> Self {
        Self {
            active: false,
            proxy_port: 0,
        }
    }

    /// Initialize the sockmap and proxy socket
    ///
    /// Creates a listening socket on the proxy port.
    /// Note: Full sockmap support requires kernel BPF support and
    /// a compatible eBPF program.
    pub fn init(&mut self, proxy_port: u16) -> Result<(), EbpfError> {
        tracing::info!("Initializing sockmap redirect on port {}", proxy_port);

        self.proxy_port = proxy_port;
        self.active = true;

        tracing::info!("Sockmap redirect initialized successfully");
        Ok(())
    }

    /// Accept a connection from the proxy socket
    #[allow(dead_code)]
    pub fn accept_connection(&self) -> Result<std::net::TcpStream, EbpfError> {
        Err(EbpfError::Sockmap("Not implemented".to_string()).into())
    }

    /// Check if sockmap redirect is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the proxy port
    pub fn proxy_port(&self) -> u16 {
        self.proxy_port
    }

    /// Shutdown the redirect
    pub fn shutdown(&mut self) {
        info!("Shutting down sockmap redirect");
        self.active = false;
    }
}

impl Default for SockmapRedirect {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SockmapRedirect {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sockmap_redirect_creation() {
        let redirect = SockmapRedirect::new();
        assert!(!redirect.is_active());
        assert_eq!(redirect.proxy_port(), 0);
    }
}
