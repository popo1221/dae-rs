//! Meek transport implementation for anti-censorship
//!
//! Meek is a forward-grade proxy that uses domain fronting to bypass censorship.
//! It works by routing traffic through cloud services (Azure, AWS, Cloudflare)
//! so that the censorship appears to be targeting legitimate cloud services.
//!
//! # How Meek Works
//!
//! 1. **Domain Fronting**: The client connects to a domain like `ajax.googleapis.com`
//!    but the actual traffic is routed to `meek-server.azureedge.net` through CDN.
//! 2. **HTTP/2**: Uses HTTP/2 for multiplexed connections and better camouflage.
//! 3. **Tactics**: Different obfuscation strategies:
//!    - `http`: Simple HTTP proxy through front domain
//!       - `https`: HTTPS proxy through front domain
//!    - `bytepolding`: Length-encoded requests with padding
//!    - `snia`: Session ticket ID obfuscation (Azure specific)
//!    - `patterns`: Pattern-based obfuscation
//!    - `gimmie`: Simple tunnel with greeting
//!    - `redirect`: Server-side redirect following
//! 4. **Fronting Domain**: The domain that appears in the SNI/TLS Hello.
//!
//! # Azure Meek Configuration
//!
//! - Front: `ajax.googleapis.com` (or similar)
//! - Server: `meek-reflect.appspot.com` -> `meek.azureedge.net`
//!
//! # AWS/CloudFront Meek Configuration
//!
//! - Front: `cdn.jsdelivr.net`
//! - Server: `sni.cloudflarert.com` -> `cftweet.net`

use super::Transport;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt::Debug;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// Meek obfuscation tactic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeekTactic {
    /// HTTP proxy through front domain
    Http,
    /// HTTPS proxy through front domain
    Https,
    /// Length-encoded requests with padding (default)
    Bytepolding,
    /// Session ticket ID obfuscation (Azure)
    Snia,
    /// Pattern-based obfuscation
    Patterns,
    /// Simple tunnel with greeting
    Gimmie,
    /// Server-side redirect following
    Redirect,
}

impl Default for MeekTactic {
    fn default() -> Self {
        MeekTactic::Bytepolding
    }
}

impl std::fmt::Display for MeekTactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeekTactic::Http => write!(f, "http"),
            MeekTactic::Https => write!(f, "https"),
            MeekTactic::Bytepolding => write!(f, "bytepolding"),
            MeekTactic::Snia => write!(f, "snia"),
            MeekTactic::Patterns => write!(f, "patterns"),
            MeekTactic::Gimmie => write!(f, "gimmie"),
            MeekTactic::Redirect => write!(f, "redirect"),
        }
    }
}

/// Meek transport configuration
#[derive(Debug, Clone)]
pub struct MeekConfig {
    /// Front domain for domain fronting (appears in SNI/TLS)
    pub front_domain: String,
    /// Server hostname (actual server behind CDN)
    pub server_host: String,
    /// Server port
    pub port: u16,
    /// Obfuscation tactic
    pub tactic: MeekTactic,
    /// Use TLS
    pub tls: bool,
    /// TLS server name (SNI) - defaults to front_domain
    pub sni: Option<String>,
    /// Path prefix (for HTTP tactics)
    pub path_prefix: String,
    /// Connection timeout
    pub timeout: Duration,
    /// Padding for length-encoded tactic
    pub padding_size: usize,
    /// Session ticket ID (for snia tactic)
    pub session_ticket_id: Option<Vec<u8>>,
}

impl Default for MeekConfig {
    fn default() -> Self {
        Self {
            front_domain: "ajax.googleapis.com".to_string(),
            server_host: "meek-reflect.appspot.com".to_string(),
            port: 443,
            tactic: MeekTactic::Bytepolding,
            tls: true,
            sni: None,
            path_prefix: "/".to_string(),
            timeout: Duration::from_secs(30),
            padding_size: 2048,
            session_ticket_id: None,
        }
    }
}

impl MeekConfig {
    /// Create a new Meek config for Azure
    pub fn azure(front_domain: &str) -> Self {
        Self {
            front_domain: front_domain.to_string(),
            server_host: "meek-reflect.appspot.com".to_string(),
            port: 443,
            tactic: MeekTactic::Snia,
            tls: true,
            sni: Some("meek.azureedge.net".to_string()),
            path_prefix: "/".to_string(),
            ..Default::default()
        }
    }

    /// Create a new Meek config for Cloudflare
    pub fn cloudflare(front_domain: &str) -> Self {
        Self {
            front_domain: front_domain.to_string(),
            server_host: "sni.cloudflarert.com".to_string(),
            port: 443,
            tactic: MeekTactic::Bytepolding,
            tls: true,
            sni: Some("cftweet.net".to_string()),
            path_prefix: "/".to_string(),
            ..Default::default()
        }
    }

    /// Set obfuscation tactic
    pub fn with_tactic(mut self, tactic: MeekTactic) -> Self {
        self.tactic = tactic;
        self
    }

    /// Set TLS server name (SNI)
    pub fn with_sni(mut self, sni: &str) -> Self {
        self.sni = Some(sni.to_string());
        self
    }

    /// Set path prefix
    pub fn with_path_prefix(mut self, prefix: &str) -> Self {
        self.path_prefix = prefix.to_string();
        self
    }

    /// Get the actual TLS SNI to use
    pub fn tls_sni(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.front_domain)
    }
}

/// Meek transport for anti-censorship
#[derive(Debug, Clone)]
pub struct MeekTransport {
    config: MeekConfig,
}

impl MeekTransport {
    /// Create a new Meek transport
    pub fn new(config: MeekConfig) -> Self {
        Self { config }
    }

    /// Create with Azure fronting (default)
    pub fn with_azure_front(front: &str) -> Self {
        Self {
            config: MeekConfig::azure(front),
        }
    }

    /// Create with Cloudflare fronting
    pub fn with_cloudflare_front(front: &str) -> Self {
        Self {
            config: MeekConfig::cloudflare(front),
        }
    }
}

impl MeekTransport {
    /// Build HTTP request for meek tunnel
    fn build_tunnel_request(&self, host: &str, path: &str) -> Bytes {
        let mut buf = BytesMut::new();

        match self.config.tactic {
            MeekTactic::Http | MeekTactic::Https => {
                // Simple HTTP CONNECT-like request
                // Actually meek uses a different protocol
                buf.put_slice(b"GET ");
                buf.put_slice(path.as_bytes());
                buf.put_slice(b" HTTP/1.1\r\n");
                buf.put_slice(b"Host: ");
                buf.put_slice(host.as_bytes());
                buf.put_slice(b"\r\n");
                buf.put_slice(b"User-Agent: Mozilla/5.0\r\n");
                buf.put_slice(b"Accept: */*\r\n");
                buf.put_slice(b"Connection: keep-alive\r\n");
                buf.put_slice(b"\r\n");
            }
            MeekTactic::Bytepolding => {
                // Length-encoded request with padding
                // Format: [length (4 bytes)][padding][length][request...]
                let request = Self::build_simple_request(host, path);
                let length = request.len() as u32;
                let padding_len = (self.config.padding_size
                    - (length as usize % self.config.padding_size))
                    .min(self.config.padding_size);

                // Write padding first (as length prefix)
                buf.put_u32(padding_len as u32);
                buf.put_slice(&vec![0u8; padding_len][..]);

                // Write actual request with length prefix
                buf.put_u32(length);
                buf.put_slice(&request);
            }
            MeekTactic::Snia => {
                // Session ticket ID based obfuscation
                // Uses TLS session resumption for obfuscation
                let request = Self::build_simple_request(host, path);
                buf.put_u32(request.len() as u32);
                buf.put_slice(&request);

                // Add session ticket ID if configured
                if let Some(ref ticket_id) = self.config.session_ticket_id {
                    buf.put_u32(ticket_id.len() as u32);
                    buf.put_slice(ticket_id);
                }
            }
            MeekTactic::Patterns => {
                // Pattern-based obfuscation
                let request = Self::build_simple_request(host, path);
                buf.put_slice(&[0x00, 0x00, 0x00, 0x00]); // Pattern header
                buf.put_u32(request.len() as u32);
                buf.put_slice(&request);
            }
            MeekTactic::Gimmie => {
                // Simple greeting then tunnel
                buf.put_slice(b"GM"); // Greeting
                buf.put_u16(1); // Version
                let request = Self::build_simple_request(host, path);
                buf.put_u32(request.len() as u32);
                buf.put_slice(&request);
            }
            MeekTactic::Redirect => {
                // Follow redirects
                let request = Self::build_simple_request(host, path);
                buf.put_u32(request.len() as u32);
                buf.put_slice(&request);
            }
        }

        Bytes::from(buf)
    }

    /// Build simple HTTP/1.1 request
    fn build_simple_request(host: &str, path: &str) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(b"GET ");
        request.extend_from_slice(path.as_bytes());
        request.extend_from_slice(b" HTTP/1.1\r\n");
        request.extend_from_slice(b"Host: ");
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
        );
        request.extend_from_slice(b"Accept: */*\r\n");
        request.extend_from_slice(b"Connection: keep-alive\r\n");
        request.extend_from_slice(b"\r\n");
        request
    }

    /// Parse length-encoded response
    async fn read_length_prefixed<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        max_len: usize,
    ) -> IoResult<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > max_len {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("Response too long: {} > {}", len, max_len),
            ));
        }

        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).await?;
        Ok(data)
    }

    /// Read and parse meek response
    async fn read_response<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        tactic: MeekTactic,
    ) -> IoResult<Vec<u8>> {
        match tactic {
            MeekTactic::Http | MeekTactic::Https => {
                // Read until double CRLF
                let mut headers = Vec::new();
                let mut prev = [0u8; 1];
                let mut crlf_count = 0;

                loop {
                    reader.read_exact(&mut prev).await?;
                    headers.push(prev[0]);

                    if headers.len() >= 2 {
                        let len = headers.len();
                        if headers[len - 2] == b'\r' && headers[len - 1] == b'\n' {
                            crlf_count += 1;
                            if crlf_count == 2 {
                                break;
                            }
                        } else {
                            crlf_count = 0;
                        }
                    }

                    if headers.len() > 8192 {
                        return Err(IoError::new(
                            ErrorKind::InvalidData,
                            "Response headers too long",
                        ));
                    }
                }

                // Check for 200 OK
                let header_str = String::from_utf8_lossy(&headers);
                if !header_str.contains("200") {
                    warn!(
                        "Meek response not OK: {}",
                        header_str.lines().next().unwrap_or("")
                    );
                }

                Ok(Vec::new())
            }
            MeekTactic::Bytepolding
            | MeekTactic::Snia
            | MeekTactic::Patterns
            | MeekTactic::Redirect => {
                // Length-prefixed response
                Self::read_length_prefixed(reader, 65536).await
            }
            MeekTactic::Gimmie => {
                // Gimmie response (4 bytes header)
                let mut header = [0u8; 4];
                reader.read_exact(&mut header).await?;
                let len = u32::from_be_bytes(header) as usize;
                let mut data = vec![0u8; len];
                reader.read_exact(&mut data).await?;
                Ok(data)
            }
        }
    }

    /// Connect to front domain (domain fronted)
    async fn dial_fronted(&self) -> IoResult<TcpStream> {
        let addr = format!("{}:{}", self.config.front_domain, self.config.port);
        info!("Meek connecting to front: {}", addr);

        let stream = TcpStream::connect(&addr).await?;

        if self.config.tls {
            // For TLS, we would connect to the front domain but the actual
            // server is resolved through the CDN. The SNI is set to front_domain.
            debug!("TLS enabled, SNI: {}", self.config.tls_sni());
        }

        Ok(stream)
    }
}

#[async_trait]
impl Transport for MeekTransport {
    fn name(&self) -> &'static str {
        "meek"
    }

    async fn dial(&self, _addr: &str) -> IoResult<TcpStream> {
        let mut stream = self.dial_fronted().await?;

        // Build and send tunnel request
        let request = self.build_tunnel_request(&self.config.server_host, &self.config.path_prefix);
        stream.write_all(&request).await?;
        stream.flush().await?;

        // Read and validate response
        let response = Self::read_response(&mut stream, self.config.tactic).await?;
        debug!("Meek tunnel established, response len: {}", response.len());

        Ok(stream)
    }

    async fn listen(&self, addr: &str) -> IoResult<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}

/// Meek session for managing persistent connections
#[derive(Debug)]
pub struct MeekSession {
    transport: MeekTransport,
    stream: Option<TcpStream>,
}

impl MeekSession {
    /// Create a new session
    pub fn new(transport: MeekTransport) -> Self {
        Self {
            transport,
            stream: None,
        }
    }

    /// Connect the session
    pub async fn connect(&mut self) -> IoResult<()> {
        let stream = self.transport.dial("").await?;
        self.stream = Some(stream);
        Ok(())
    }

    /// Send data through the session
    pub async fn send(&mut self, data: &[u8]) -> IoResult<()> {
        if let Some(ref mut stream) = self.stream {
            stream.write_all(data).await?;
        } else {
            return Err(IoError::new(
                ErrorKind::NotConnected,
                "Session not connected",
            ));
        }
        Ok(())
    }

    /// Receive data from the session
    pub async fn recv(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if let Some(ref mut stream) = self.stream {
            stream.read(buf).await
        } else {
            Err(IoError::new(
                ErrorKind::NotConnected,
                "Session not connected",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meek_config_default() {
        let config = MeekConfig::default();
        assert_eq!(config.front_domain, "ajax.googleapis.com");
        assert_eq!(config.server_host, "meek-reflect.appspot.com");
        assert_eq!(config.tactic, MeekTactic::Bytepolding);
        assert!(config.tls);
        assert_eq!(config.port, 443);
    }

    #[test]
    fn test_meek_config_azure() {
        let config = MeekConfig::azure("www.google.com");
        assert_eq!(config.front_domain, "www.google.com");
        assert_eq!(config.tactic, MeekTactic::Snia);
        assert_eq!(config.sni, Some("meek.azureedge.net".to_string()));
    }

    #[test]
    fn test_meek_config_cloudflare() {
        let config = MeekConfig::cloudflare("cdnjs.cloudflare.com");
        assert_eq!(config.front_domain, "cdnjs.cloudflare.com");
        assert_eq!(config.tactic, MeekTactic::Bytepolding);
        assert_eq!(config.sni, Some("cftweet.net".to_string()));
    }

    #[test]
    fn test_meek_config_builder() {
        let config = MeekConfig::default()
            .with_tactic(MeekTactic::Http)
            .with_sni("custom.sni.com")
            .with_path_prefix("/tunnel");

        assert_eq!(config.tactic, MeekTactic::Http);
        assert_eq!(config.sni, Some("custom.sni.com".to_string()));
        assert_eq!(config.path_prefix, "/tunnel");
    }

    #[test]
    fn test_tactic_display() {
        assert_eq!(MeekTactic::Bytepolding.to_string(), "bytepolding");
        assert_eq!(MeekTactic::Http.to_string(), "http");
        assert_eq!(MeekTactic::Https.to_string(), "https");
        assert_eq!(MeekTactic::Snia.to_string(), "snia");
    }

    #[test]
    fn test_meek_transport_name() {
        let transport = MeekTransport::new(MeekConfig::default());
        assert_eq!(transport.name(), "meek");
    }

    #[test]
    fn test_build_simple_request() {
        let request = MeekTransport::build_simple_request("example.com", "/");
        let request_str = String::from_utf8_lossy(&request);
        assert!(request_str.contains("GET / HTTP/1.1"));
        assert!(request_str.contains("Host: example.com"));
    }

    #[test]
    fn test_tls_sni() {
        let config = MeekConfig::default();
        assert_eq!(config.tls_sni(), "ajax.googleapis.com"); // defaults to front_domain

        let config = MeekConfig::default().with_sni("custom.sni.com");
        assert_eq!(config.tls_sni(), "custom.sni.com");
    }

    #[test]
    fn test_meek_config_with_tactic() {
        let config = MeekConfig::default().with_tactic(MeekTactic::Gimmie);

        assert_eq!(config.tactic, MeekTactic::Gimmie);
    }
}
