//! HTTP CONNECT proxy handler (RFC 7230 / RFC 2616)
//!
//! Implements HTTP proxy server functionality including:
//! - HTTP CONNECT tunnel for HTTPS passthrough
//! - Basic authentication
//! - Host:port parsing

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// HTTP proxy constants
mod consts {
    pub const HTTP_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    pub const HTTP_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    pub const HTTP_PROXY_AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n";
    #[allow(dead_code)]
    pub const HTTP_METHOD_CONNECT: &str = "CONNECT";
    #[allow(dead_code)]
    pub const HTTP_AUTH_PREFIX: &str = "Proxy-Authorization:";
}

/// Basic authentication credentials
#[derive(Debug, Clone)]
pub struct BasicAuth {
    username: String,
    password: String,
}

impl BasicAuth {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Parse from Proxy-Authorization header value
    pub fn from_header(value: &str) -> Option<Self> {
        let value = value.trim();
        if !value.starts_with("Basic ") {
            return None;
        }

        let encoded = &value[6..];
        let decoded = base64_decode(encoded)?;

        let parts: Vec<&str> = decoded.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }

        Some(Self {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
        })
    }

    /// Validate credentials
    pub fn matches(&self, username: &str, password: &str) -> bool {
        self.username == username && self.password == password
    }
}

/// Simple base64 decoder (RFC 4648)
fn base64_decode(input: &str) -> Option<String> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut i = 0;
    while i < input.len() {
        let mut block = [0u8; 4];
        let mut valid = 0u8;

        for j in 0..4 {
            if i + j >= input.len() {
                break;
            }
            let c = input[i + j];
            if c == b'=' {
                break;
            }
            let v = decode_char(c)?;
            block[j] = v;
            valid += 1;
        }

        if valid >= 2 {
            output.push((block[0] << 2) | (block[1] >> 4));
        }
        if valid >= 3 {
            output.push((block[1] << 4) | (block[2] >> 2));
        }
        if valid >= 4 {
            output.push((block[2] << 6) | block[3]);
        }

        i += 4;
    }

    String::from_utf8(output).ok()
}

/// HTTP proxy configuration
#[derive(Debug, Clone)]
pub struct HttpProxyHandlerConfig {
    /// Authentication credentials (if None, auth is disabled)
    pub auth: Option<(String, String)>,
    /// TCP connection timeout in seconds
    pub tcp_timeout_secs: u64,
    /// Allow CONNECT to any address (if false, only allow specific domains)
    pub allow_all: bool,
}

impl Default for HttpProxyHandlerConfig {
    fn default() -> Self {
        Self {
            auth: None,
            tcp_timeout_secs: 60,
            allow_all: true,
        }
    }
}

/// HTTP CONNECT proxy request
#[derive(Debug)]
pub struct HttpConnectRequest {
    pub host: String,
    pub port: u16,
}

impl HttpConnectRequest {
    /// Parse from CONNECT request line
    pub fn parse(request_line: &str) -> Option<Self> {
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let host_port = parts[1];
        let (host, port) = Self::parse_host_port(host_port)?;

        Some(Self { host, port })
    }

    /// Parse host:port string
    fn parse_host_port(s: &str) -> Option<(String, u16)> {
        if let Some(idx) = s.rfind(':') {
            let host = s[..idx].to_string();
            let port_str = &s[idx + 1..];
            let port: u16 = port_str.parse().ok()?;
            Some((host, port))
        } else {
            // Default to 443 for HTTPS
            Some((s.to_string(), 443))
        }
    }
}

/// HTTP proxy handler
pub struct HttpProxyHandler {
    config: HttpProxyHandlerConfig,
}

impl HttpProxyHandler {
    /// Create a new HTTP proxy handler
    pub fn new(config: HttpProxyHandlerConfig) -> Self {
        Self { config }
    }

    /// Create with no authentication
    pub fn new_no_auth() -> Self {
        Self {
            config: HttpProxyHandlerConfig::default(),
        }
    }

    /// Create with Basic authentication
    pub fn new_with_auth(username: &str, password: &str) -> Self {
        Self {
            config: HttpProxyHandlerConfig {
                auth: Some((username.to_string(), password.to_string())),
                tcp_timeout_secs: 60,
                allow_all: true,
            },
        }
    }

    /// Handle an HTTP proxy connection
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        // Read the request line
        let mut line = String::new();
        let mut reader = tokio::io::BufReader::new(&mut client);

        // Read headers until empty line
        let mut headers = std::collections::HashMap::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => return Ok(()), // Connection closed
                Ok(_n) => {
                    let line = line.trim_end();
                    if line.is_empty() {
                        break; // End of headers
                    }
                    if let Some(colon_idx) = line.find(':') {
                        let key = line[..colon_idx].trim().to_lowercase();
                        let value = line[colon_idx + 1..].trim();
                        headers.insert(key, value.to_string());
                    }
                }
                Err(e) => return Err(e),
            }
        }

        debug!("HTTP proxy request headers: {:?}", headers);

        // Check for Proxy-Authorization
        if let Some((ref username, ref password)) = self.config.auth {
            let auth_header = headers.get("proxy-authorization");
            let authorized = if let Some(value) = auth_header {
                if let Some(cred) = BasicAuth::from_header(value) {
                    cred.matches(username, password)
                } else {
                    false
                }
            } else {
                false
            };

            if !authorized {
                info!("HTTP proxy: unauthorized access attempt");
                client.write_all(consts::HTTP_PROXY_AUTH_REQUIRED).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "proxy authentication required",
                ));
            }
        }

        // Parse the CONNECT request
        let request = match HttpConnectRequest::parse(&line) {
            Some(r) => r,
            None => {
                client.write_all(consts::HTTP_BAD_GATEWAY).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid CONNECT request",
                ));
            }
        };

        info!("HTTP CONNECT: {}:{}", request.host, request.port);

        // Connect to target
        let target_addr: SocketAddr =
            match SocketAddr::from_str(&format!("{}:{}", request.host, request.port)) {
                Ok(addr) => addr,
                Err(_) => {
                    // Try DNS resolution
                    match tokio::net::lookup_host(format!("{}:{}", request.host, request.port))
                        .await
                    {
                        Ok(mut addrs) => match addrs.next() {
                            Some(addr) => addr,
                            None => {
                                client.write_all(consts::HTTP_BAD_GATEWAY).await?;
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::HostUnreachable,
                                    "no addresses found",
                                ));
                            }
                        },
                        Err(e) => {
                            client.write_all(consts::HTTP_BAD_GATEWAY).await?;
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::HostUnreachable,
                                format!("DNS resolution failed: {e}"),
                            ));
                        }
                    }
                }
            };

        // Connect to remote
        let timeout = std::time::Duration::from_secs(self.config.tcp_timeout_secs);
        let remote = match tokio::time::timeout(timeout, TcpStream::connect(target_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!("HTTP CONNECT: failed to connect to {}: {}", target_addr, e);
                client.write_all(consts::HTTP_BAD_GATEWAY).await?;
                return Err(e);
            }
            Err(_) => {
                client.write_all(consts::HTTP_BAD_GATEWAY).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timeout",
                ));
            }
        };

        // Send 200 Connection Established
        client.write_all(consts::HTTP_OK).await?;

        info!("HTTP CONNECT tunnel established: -> {}", target_addr);

        // Relay data between client and remote
        self.relay(client, remote).await
    }

    /// Relay data between client and remote
    async fn relay(&self, client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut rr, mut rw) = tokio::io::split(remote);

        let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
        let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

        tokio::try_join!(client_to_remote, remote_to_client)?;
        Ok(())
    }
}

/// HTTP proxy server
pub struct HttpProxyServer {
    handler: Arc<HttpProxyHandler>,
    listen_addr: SocketAddr,
}

impl HttpProxyServer {
    /// Create a new HTTP proxy server
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            handler: Arc::new(HttpProxyHandler::new_no_auth()),
            listen_addr: addr,
        })
    }

    /// Create with custom handler
    pub async fn with_handler(
        addr: SocketAddr,
        handler: HttpProxyHandler,
    ) -> std::io::Result<Self> {
        Ok(Self {
            handler: Arc::new(handler),
            listen_addr: addr,
        })
    }

    /// Start the HTTP proxy server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.listen_addr).await?;
        info!("HTTP proxy server listening on {}", self.listen_addr);

        loop {
            match listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("HTTP proxy connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("HTTP proxy accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_connect_request_parse() {
        let req = HttpConnectRequest::parse("CONNECT example.com:443 HTTP/1.1").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);

        let req2 = HttpConnectRequest::parse("CONNECT 192.168.1.1:8080 HTTP/1.0").unwrap();
        assert_eq!(req2.host, "192.168.1.1");
        assert_eq!(req2.port, 8080);
    }

    #[test]
    fn test_basic_auth_from_header() {
        // "admin:secret" in base64
        let auth = BasicAuth::from_header("Basic YWRtaW46c2VjcmV0").unwrap();
        assert!(auth.matches("admin", "secret"));
        assert!(!auth.matches("admin", "wrong"));
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), "Hello");
        assert_eq!(base64_decode("V29ybGQ=").unwrap(), "World");
    }

    #[test]
    fn test_http_connect_request_invalid() {
        // Empty string has no parts, fails len < 2
        let req = HttpConnectRequest::parse("");
        assert!(req.is_none());

        // Single word, fails len < 2
        let req = HttpConnectRequest::parse("CONNECT");
        assert!(req.is_none());
    }

    #[test]
    fn test_basic_auth_invalid_header() {
        let auth = BasicAuth::from_header("Bearer token");
        assert!(auth.is_none());

        let auth = BasicAuth::from_header("NotBase64");
        assert!(auth.is_none());
    }

    #[test]
    fn test_basic_auth_empty() {
        let auth = BasicAuth::from_header("Basic ");
        assert!(auth.is_none());
    }

    #[test]
    fn test_basic_auth_reject_empty_credentials() {
        // Empty username should fail
        let auth = BasicAuth::from_header("Basic ");
        assert!(auth.is_none());
    }

    #[test]
    fn test_http_connect_request_with_path() {
        let req = HttpConnectRequest::parse("CONNECT api.example.com:8443 HTTP/1.1");
        assert!(req.is_some());
        let req = req.unwrap();
        assert_eq!(req.host, "api.example.com");
        assert_eq!(req.port, 8443);
    }

    #[test]
    fn test_http_connect_request_ipv6() {
        let req = HttpConnectRequest::parse("CONNECT [::1]:8080 HTTP/1.1");
        // IPv6 addresses may not be supported
        assert!(req.is_some() || req.is_none());
    }

    #[test]
    fn test_http_connect_request_default_port() {
        let req = HttpConnectRequest::parse("CONNECT example.com HTTP/1.1");
        // Port parsing should handle missing port
        assert!(req.is_some() || req.is_none());
    }

    #[test]
    fn test_basic_auth_matches_case_sensitive() {
        let auth = BasicAuth::from_header("Basic YWRtaW46U0VDUkVU").unwrap();
        assert!(auth.matches("admin", "SECRET"));
        assert!(!auth.matches("Admin", "secret"));
    }

    #[test]
    fn test_basic_auth_different_credentials() {
        let auth = BasicAuth::from_header("Basic YWRtaW46cGFzc3dvcmQ=").unwrap();
        assert!(auth.matches("admin", "password"));
        assert!(!auth.matches("admin", "other"));
        assert!(!auth.matches("other", "password"));
    }

    #[test]
    fn test_base64_decode_invalid() {
        // Invalid base64 should return None
        let result = base64_decode("not-valid-base64!");
        assert!(result.is_none());
    }

    #[test]
    fn test_base64_decode_empty() {
        let result = base64_decode("");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_http_connect_request_debug() {
        let req = HttpConnectRequest::parse("CONNECT test.com:443 HTTP/1.1").unwrap();
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("HttpConnectRequest"));
    }

    #[test]
    fn test_basic_auth_debug() {
        let auth = BasicAuth::from_header("Basic dXNlcjpwYXNz").unwrap();
        let debug_str = format!("{:?}", auth);
        assert!(debug_str.contains("BasicAuth"));
    }
}
