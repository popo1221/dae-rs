//! HTTP CONNECT proxy handler (RFC 7230 / RFC 2616)
//!
//! Implements HTTP proxy server functionality including:
//! - HTTP CONNECT tunnel for HTTPS passthrough
//! - Basic authentication
//! - Host:port parsing

mod auth;
mod parser;

pub use auth::BasicAuth;
pub use parser::HttpConnectRequest;

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
    #[allow(clippy::incompatible_msrv)]
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
        dae_relay::relay_bidirectional(client, remote).await
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
