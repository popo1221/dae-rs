//! Protocol dispatcher for SOCKS5 and HTTP proxy
//!
//! Detects incoming protocol based on first bytes and routes
//! to the appropriate handler.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, error};

/// Protocol types detected by the dispatcher
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedProtocol {
    /// SOCKS5 protocol (starts with 0x05)
    Socks5,
    /// HTTP CONNECT method
    HttpConnect,
    /// Other HTTP methods (GET, POST, HEAD, etc.)
    HttpOther,
    /// Unknown/unsupported protocol
    Unknown,
}

impl DetectedProtocol {
    /// Detect protocol from first bytes
    pub fn detect(first_bytes: &[u8]) -> Self {
        if first_bytes.is_empty() {
            return DetectedProtocol::Unknown;
        }

        match first_bytes[0] {
            // SOCKS5 starts with version 0x05
            0x05 => DetectedProtocol::Socks5,
            // HTTP methods start with ASCII letters
            b'A'..=b'Z' => {
                // Check if it's a CONNECT request
                let first_str = String::from_utf8_lossy(first_bytes);
                if first_str.starts_with("CONNECT ") {
                    DetectedProtocol::HttpConnect
                } else if first_str.starts_with("GET ")
                    || first_str.starts_with("POST ")
                    || first_str.starts_with("HEAD ")
                    || first_str.starts_with("PUT ")
                    || first_str.starts_with("DELETE ")
                    || first_str.starts_with("OPTIONS ")
                    || first_str.starts_with("PATCH ")
                    || first_str.starts_with("TRACE ")
                {
                    DetectedProtocol::HttpOther
                } else {
                    DetectedProtocol::Unknown
                }
            }
            _ => DetectedProtocol::Unknown,
        }
    }
}

/// Protocol dispatcher configuration
#[derive(Debug, Clone)]
pub struct ProtocolDispatcherConfig {
    /// SOCKS5 server address (if None, SOCKS5 is disabled)
    pub socks5_addr: Option<SocketAddr>,
    /// HTTP proxy server address (if None, HTTP is disabled)
    pub http_addr: Option<SocketAddr>,
}

impl Default for ProtocolDispatcherConfig {
    fn default() -> Self {
        Self {
            socks5_addr: Some(SocketAddr::from(([127, 0, 0, 1], 1080))),
            http_addr: Some(SocketAddr::from(([127, 0, 0, 1], 8080))),
        }
    }
}

/// Protocol dispatcher that routes connections to appropriate handlers
pub struct ProtocolDispatcher {
    config: ProtocolDispatcherConfig,
    socks5_handler: Option<Arc<crate::socks5::Socks5Handler>>,
    http_handler: Option<Arc<crate::http_proxy::HttpProxyHandler>>,
}

impl ProtocolDispatcher {
    /// Create a new protocol dispatcher
    pub fn new(config: ProtocolDispatcherConfig) -> Self {
        Self {
            config,
            socks5_handler: None,
            http_handler: None,
        }
    }

    /// Create with SOCKS5 handler
    pub fn with_socks5_handler(mut self, handler: Arc<crate::socks5::Socks5Handler>) -> Self {
        self.socks5_handler = Some(handler);
        self
    }

    /// Create with HTTP handler
    pub fn with_http_handler(mut self, handler: Arc<crate::http_proxy::HttpProxyHandler>) -> Self {
        self.http_handler = Some(handler);
        self
    }

    /// Set SOCKS5 handler
    pub fn set_socks5_handler(&mut self, handler: Arc<crate::socks5::Socks5Handler>) {
        self.socks5_handler = Some(handler);
    }

    /// Set HTTP handler
    pub fn set_http_handler(&mut self, handler: Arc<crate::http_proxy::HttpProxyHandler>) {
        self.http_handler = Some(handler);
    }

    /// Handle an incoming connection by detecting and routing to appropriate protocol
    pub async fn handle_connection(self: Arc<Self>, client: TcpStream) -> std::io::Result<()> {
        let addr = client
            .peer_addr()
            .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));

        // Peek at first few bytes to detect protocol
        let mut peek_buf = [0u8; 16];
        let n = match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.peek(&mut peek_buf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("Failed to peek client bytes from {}: {}", addr, e);
                return Err(e);
            }
            Err(_) => {
                debug!("Protocol detection timeout for {}", addr);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "protocol detection timeout",
                ));
            }
        };

        if n == 0 {
            debug!("Client {} closed connection during peek", addr);
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }

        let protocol = DetectedProtocol::detect(&peek_buf[..n]);
        debug!("Detected protocol {:?} from {}", protocol, addr);

        match protocol {
            DetectedProtocol::Socks5 => {
                if let Some(ref handler) = self.socks5_handler {
                    handler.clone().handle(client).await
                } else {
                    self.reject_unknown(client, "SOCKS5 not enabled").await
                }
            }
            DetectedProtocol::HttpConnect | DetectedProtocol::HttpOther => {
                if let Some(ref handler) = self.http_handler {
                    handler.clone().handle(client).await
                } else {
                    self.reject_unknown(client, "HTTP proxy not enabled").await
                }
            }
            DetectedProtocol::Unknown => self.reject_unknown(client, "unsupported protocol").await,
        }
    }

    /// Reject connection with unknown protocol
    async fn reject_unknown(&self, mut client: TcpStream, reason: &str) -> std::io::Result<()> {
        debug!("Rejecting unknown protocol: {}", reason);
        let response = format!(
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nX-Error: {reason}\r\n\r\n"
        );
        client.write_all(response.as_bytes()).await?;
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, reason))
    }

    /// Get SOCKS5 listen address if configured
    pub fn socks5_addr(&self) -> Option<SocketAddr> {
        self.config.socks5_addr
    }

    /// Get HTTP listen address if configured
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.config.http_addr
    }
}

/// Combined proxy server that handles both SOCKS5 and HTTP on separate ports
pub struct CombinedProxyServer {
    #[allow(dead_code)]
    config: ProtocolDispatcherConfig,
    socks5_server: Option<Arc<crate::socks5::Socks5Server>>,
    http_server: Option<Arc<crate::http_proxy::HttpProxyServer>>,
}

impl CombinedProxyServer {
    /// Create a new combined proxy server
    pub async fn new(config: ProtocolDispatcherConfig) -> std::io::Result<Self> {
        let mut server = Self {
            config: config.clone(),
            socks5_server: None,
            http_server: None,
        };

        // Create SOCKS5 server if configured
        if let Some(addr) = config.socks5_addr {
            let s5_server = crate::socks5::Socks5Server::new(addr).await?;
            server.socks5_server = Some(Arc::new(s5_server));
        }

        // Create HTTP server if configured
        if let Some(addr) = config.http_addr {
            let http_server = crate::http_proxy::HttpProxyServer::new(addr).await?;
            server.http_server = Some(Arc::new(http_server));
        }

        Ok(server)
    }

    /// Start all servers
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        let mut handles = Vec::new();

        // Start SOCKS5 server
        if let Some(ref server) = self.socks5_server {
            let srv = server.clone();
            let handle = tokio::spawn(async move { srv.start().await });
            handles.push(handle);
        }

        // Start HTTP server
        if let Some(ref server) = self.http_server {
            let srv = server.clone();
            let handle = tokio::spawn(async move { srv.start().await });
            handles.push(handle);
        }

        // Wait for all servers
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Server task panicked: {}", e);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_socks5() {
        assert_eq!(DetectedProtocol::detect(&[0x05]), DetectedProtocol::Socks5);
        assert_eq!(
            DetectedProtocol::detect(&[0x05, 0x01, 0x00]),
            DetectedProtocol::Socks5
        );
    }

    #[test]
    fn test_detect_http_connect() {
        assert_eq!(
            DetectedProtocol::detect(b"CONNECT example.com:443 HTTP/1.1"),
            DetectedProtocol::HttpConnect
        );
    }

    #[test]
    fn test_detect_http_get() {
        assert_eq!(
            DetectedProtocol::detect(b"GET / HTTP/1.1"),
            DetectedProtocol::HttpOther
        );
        assert_eq!(
            DetectedProtocol::detect(b"POST /api HTTP/1.0"),
            DetectedProtocol::HttpOther
        );
    }

    #[test]
    fn test_detect_unknown() {
        assert_eq!(DetectedProtocol::detect(&[0x00]), DetectedProtocol::Unknown);
        assert_eq!(DetectedProtocol::detect(&[]), DetectedProtocol::Unknown);
        assert_eq!(
            DetectedProtocol::detect(b"\xff\xfe"),
            DetectedProtocol::Unknown
        );
    }

    #[test]
    fn test_detect_http_head() {
        assert_eq!(
            DetectedProtocol::detect(b"HEAD / HTTP/1.1"),
            DetectedProtocol::HttpOther
        );
    }

    #[test]
    fn test_detect_http_options() {
        assert_eq!(
            DetectedProtocol::detect(b"OPTIONS / HTTP/1.1"),
            DetectedProtocol::HttpOther
        );
    }

    #[test]
    fn test_detect_http_delete() {
        assert_eq!(
            DetectedProtocol::detect(b"DELETE /api HTTP/1.1"),
            DetectedProtocol::HttpOther
        );
    }

    #[test]
    fn test_detect_http_put() {
        assert_eq!(
            DetectedProtocol::detect(b"PUT /file HTTP/1.1"),
            DetectedProtocol::HttpOther
        );
    }

    #[test]
    fn test_detect_http_patch() {
        assert_eq!(
            DetectedProtocol::detect(b"PATCH /api HTTP/1.1"),
            DetectedProtocol::HttpOther
        );
    }

    #[test]
    fn test_detect_empty_data() {
        assert_eq!(DetectedProtocol::detect(&[]), DetectedProtocol::Unknown);
    }

    #[test]
    fn test_detect_socks5_variants() {
        assert_eq!(DetectedProtocol::detect(&[0x05, 0x00]), DetectedProtocol::Socks5);
        assert_eq!(DetectedProtocol::detect(&[0x05, 0xFF, 0x00]), DetectedProtocol::Socks5);
    }

    #[test]
    fn test_detect_http_connect_with_port() {
        assert_eq!(
            DetectedProtocol::detect(b"CONNECT api.example.com:8443 HTTP/1.1"),
            DetectedProtocol::HttpConnect
        );
    }

    #[test]
    fn test_detect_http_get_with_path() {
        assert_eq!(
            DetectedProtocol::detect(b"GET /api/v1/users HTTP/1.1"),
            DetectedProtocol::HttpOther
        );
    }
}
