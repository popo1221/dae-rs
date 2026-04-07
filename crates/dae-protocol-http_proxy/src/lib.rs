//! HTTP CONNECT proxy handler (RFC 7230 / RFC 2616)
//!
//! Implements HTTP proxy server functionality including:
//! - HTTP CONNECT tunnel for HTTPS passthrough
//! - Basic authentication
//! - Host:port parsing

mod auth;
mod error;
mod parser;

pub use auth::BasicAuth;
pub use error::HttpProxyError;
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

/// HTTP 代理服务器配置
///
/// 包含代理服务器运行时所需的所有配置参数，包括认证信息、超时设置等。
///
/// # 字段说明
///
/// - `auth`: 认证凭证元组 `(用户名, 密码)`。若为 `None`，则不启用认证。
/// - `tcp_timeout_secs`: TCP 连接超时时间（秒），默认 60 秒。
/// - `allow_all`: 是否允许 CONNECT 到任意地址。若为 `false`，则只允许特定域名。
///
/// # 示例
///
/// ```rust
/// use dae_protocol_http_proxy::HttpProxyHandlerConfig;
///
/// // 无认证配置
/// let config = HttpProxyHandlerConfig::default();
///
/// // 带认证配置
/// let config = HttpProxyHandlerConfig {
///     auth: Some(("admin".to_string(), "secret".to_string())),
///     tcp_timeout_secs: 30,
///     allow_all: true,
/// };
/// ```
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

/// HTTP 代理处理器
///
/// 负责处理 HTTP CONNECT 代理连接，实现 HTTP 隧道功能。
/// 该处理器支持 Basic 认证，并能在客户端和远程服务器之间转发数据。
///
/// # 工作流程
///
/// 1. 读取客户端的 HTTP CONNECT 请求头
/// 2. 验证 Proxy-Authorization 认证头（如果配置了认证）
/// 3. 解析 CONNECT 请求中的目标主机和端口
/// 4. 建立到目标服务器的 TCP 连接
/// 5. 发送 HTTP 200 响应表示连接建立
/// 6. 在客户端和远程服务器之间双向转发数据
///
/// # 安全说明
///
/// - 认证使用 constant-time 比较防止时序攻击
/// - 建议配合 TLS 使用，因为明文传输的认证信息存在风险
pub struct HttpProxyHandler {
    config: HttpProxyHandlerConfig,
}

impl HttpProxyHandler {
    /// 创建新的 HTTP 代理处理器
    ///
    /// # 参数
    ///
    /// - `config`: HTTP 代理处理器配置
    ///
    /// # 返回值
    ///
    /// 返回配置好的 `HttpProxyHandler` 实例
    pub fn new(config: HttpProxyHandlerConfig) -> Self {
        Self { config }
    }

    /// 创建不带认证的 HTTP 代理处理器
    ///
    /// # 返回值
    ///
    /// 返回使用默认配置（无认证）的 `HttpProxyHandler` 实例
    pub fn new_no_auth() -> Self {
        Self {
            config: HttpProxyHandlerConfig::default(),
        }
    }

    /// 创建带 Basic 认证的 HTTP 代理处理器
    ///
    /// # 参数
    ///
    /// - `username`: Basic 认证用户名
    /// - `password`: Basic 认证密码
    ///
    /// # 返回值
    ///
    /// 返回配置了 Basic 认证的 `HttpProxyHandler` 实例
    pub fn new_with_auth(username: &str, password: &str) -> Self {
        Self {
            config: HttpProxyHandlerConfig {
                auth: Some((username.to_string(), password.to_string())),
                tcp_timeout_secs: 60,
                allow_all: true,
            },
        }
    }

    /// 处理 HTTP 代理连接
    ///
    /// 这是 HTTP 代理处理器的核心方法，处理一个完整的 HTTP CONNECT 会话。
    ///
    /// # 参数
    ///
    /// - `self`: 处理器实例的 Arc 引用
    /// - `client`: 客户端 TCP 流
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 连接正常关闭
    /// - `Err(std::io::Error)`: 处理过程中发生错误
    ///
    /// # 错误类型
    ///
    /// - `PermissionDenied`: 认证失败
    /// - `InvalidInput`: 无效的 CONNECT 请求
    /// - `HostUnreachable`: 无法连接到目标主机
    /// - `TimedOut`: 连接超时
    ///
    /// # 注意
    ///
    /// 此方法会消耗 `self`（通过 Arc），处理完成后会通过 `dae_relay::relay_bidirectional`
    /// 在客户端和远程之间转发数据。
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

/// HTTP 代理服务器
///
/// 封装了监听端口和处理器，用于接收和管理 HTTP 代理客户端连接。
/// 服务器在接收到新连接后会 spawn 一个异步任务来处理每个客户端。
///
/// # 使用示例
///
/// ```rust,ignore
/// let server = HttpProxyServer::new(addr).await?;
/// server.start().await?;
/// ```
pub struct HttpProxyServer {
    handler: Arc<HttpProxyHandler>,
    listen_addr: SocketAddr,
}

impl HttpProxyServer {
    /// 创建新的 HTTP 代理服务器（无认证）
    ///
    /// # 参数
    ///
    /// - `addr`: 服务器监听地址
    ///
    /// # 返回值
    ///
    /// - `Ok(HttpProxyServer)`: 服务器创建成功
    /// - `Err(std::io::Error)`: 绑定端口失败
    ///
    /// # 注意
    ///
    /// 此方法创建的服务器不启用认证，任何客户端都可以连接。
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            handler: Arc::new(HttpProxyHandler::new_no_auth()),
            listen_addr: addr,
        })
    }

    /// 使用自定义处理器创建 HTTP 代理服务器
    ///
    /// # 参数
    ///
    /// - `addr`: 服务器监听地址
    /// - `handler`: 自定义的 HTTP 代理处理器
    ///
    /// # 返回值
    ///
    /// - `Ok(HttpProxyServer)`: 服务器创建成功
    /// - `Err(std::io::Error)`: 绑定端口失败
    ///
    /// # 示例
    ///
    /// ```rust,ignore
    /// let handler = HttpProxyHandler::new_with_auth("admin", "secret");
    /// let server = HttpProxyServer::with_handler(addr, handler).await?;
    /// ```
    pub async fn with_handler(
        addr: SocketAddr,
        handler: HttpProxyHandler,
    ) -> std::io::Result<Self> {
        Ok(Self {
            handler: Arc::new(handler),
            listen_addr: addr,
        })
    }

    /// 启动 HTTP 代理服务器
    ///
    /// 开始监听并接受客户端连接。每个新连接都会由独立的异步任务处理。
    /// 此方法会一直运行直到发生致命错误或被取消。
    ///
    /// # 参数
    ///
    /// - `self`: 服务器实例的 Arc 引用
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 服务器正常关闭（通常不会发生）
    /// - `Err(std::io::Error)`: 接受连接时发生错误
    ///
    /// # 注意
    ///
    /// - 服务器绑定的是 `self.listen_addr`
    /// - 每个连接的错误只记录日志，不会导致服务器停止
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

/// HTTP tracking information for protocol-specific tracking
#[derive(Debug, Default, Clone)]
pub struct HttpTrackingInfo {
    /// HTTP method (CONNECT, GET, POST, etc.)
    pub method: String,
    /// Target host
    pub host: String,
    /// Target path (if available)
    pub path: String,
    /// Inbound bytes
    pub bytes_in: u64,
    /// Outbound bytes
    pub bytes_out: u64,
}

impl HttpTrackingInfo {
    /// Create a new HTTP tracking info
    pub fn new() -> Self {
        Self::default()
    }

    /// Set method
    pub fn with_method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }

    /// Set host
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    /// Set path
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    /// Set bytes transferred
    pub fn with_bytes(mut self, bytes_in: u64, bytes_out: u64) -> Self {
        self.bytes_in = bytes_in;
        self.bytes_out = bytes_out;
        self
    }
}

impl HttpProxyHandler {
    /// Handle HTTP proxy connection with protocol tracking
    ///
    /// This method extends `handle` by capturing protocol-specific
    /// tracking information including HTTP method, host, and path.
    ///
    /// # Returns
    ///
    /// - `Ok(((), HttpTrackingInfo))`: Success with tracking info
    /// - `Err(std::io::Error)`: Connection error
    #[allow(dead_code)]
    pub async fn handle_with_tracking(
        self: Arc<Self>,
        mut client: TcpStream,
    ) -> std::io::Result<((), HttpTrackingInfo)> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        // Read the request line
        let mut line = String::new();
        let mut reader = tokio::io::BufReader::new(&mut client);

        // Read headers until empty line
        let mut headers = std::collections::HashMap::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => return Ok(((), HttpTrackingInfo::default())),
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

        // Parse the request line to extract method and path
        let request_line = line.clone();
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        let method = if parts.is_empty() {
            "UNKNOWN".to_string()
        } else {
            parts[0].to_string()
        };
        let path = if parts.len() > 1 {
            parts[1].to_string()
        } else {
            String::new()
        };

        // Parse the CONNECT request or other methods
        let request = match HttpConnectRequest::parse(&line) {
            Some(r) => r,
            None => {
                client.write_all(consts::HTTP_BAD_GATEWAY).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid HTTP request",
                ));
            }
        };

        info!("HTTP {}: {}:{}", method, request.host, request.port);

        // Build tracking info
        let mut tracking_info = HttpTrackingInfo::new()
            .with_method(&method)
            .with_host(&request.host)
            .with_path(&path);

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

        // Relay with stats
        let stats = match dae_relay::relay_bidirectional_with_stats(client, remote).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        tracking_info =
            tracking_info.with_bytes(stats.bytes_remote_to_client, stats.bytes_client_to_remote);

        Ok(((), tracking_info))
    }
}
