//! Juicity 协议处理器实现模块
//!
//! 实现了 Juicity 协议的核心功能：
//! - Juicity 配置管理
//! - TCP 握手处理
//! - UDP 数据报处理
//! - 连接和会话管理
//!
//! Juicity 是一个 UDP 代理协议，设计用于高性能场景。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use super::types::{JuicityAddress, JuicityCommand, JuicityFrame};
use super::codec::JuicityCodec;
use dae_protocol_core::{Handler, HandlerConfig, ProtocolType};

/// Juicity 错误类型
///
/// 定义了 Juicity 协议处理过程中可能发生的各种错误。
///
/// # 错误类型说明
///
/// - `Io`: IO 错误
/// - `InvalidHeader`: 无效的协议头
/// - `InvalidToken`: 无效的令牌
/// - `ConnectionNotFound`: 连接不存在
/// - `SessionExpired`: 会话过期
/// - `Timeout`: 操作超时
/// - `Protocol`: 协议错误
#[derive(Debug, thiserror::Error)]
pub enum JuicityError {
    /// IO 错误
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// 无效的协议头
    #[error("Invalid header")]
    InvalidHeader,

    /// 无效的令牌
    #[error("Invalid token")]
    InvalidToken,

    /// 连接不存在
    #[error("Connection not found: {0}")]
    ConnectionNotFound(u32),

    /// 会话过期
    #[error("Session expired")]
    SessionExpired,

    /// 操作超时
    #[error("Timeout")]
    Timeout,

    /// 协议错误
    #[error("Protocol error: {0}")]
    Protocol(String),
}

impl From<tokio::time::error::Elapsed> for JuicityError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        JuicityError::Timeout
    }
}

/// Juicity 配置
///
/// 配置 Juicity 代理客户端或服务器的运行参数。
///
/// # 字段说明
///
/// - `token`: 认证令牌
/// - `server_name`: TLS SNI 服务器名称
/// - `server_addr`: 服务器地址（IP 或域名）
/// - `server_port`: 服务器端口
/// - `congestion_control`: 拥塞控制算法
/// - `timeout`: 连接超时时间
///
/// # 示例
///
/// ```rust
/// use dae_protocol_juicity::{JuicityConfig, CongestionControl};
/// use std::time::Duration;
///
/// let config = JuicityConfig {
///     token: "your_token".to_string(),
///     server_name: "example.com".to_string(),
///     server_addr: "127.0.0.1".to_string(),
///     server_port: 443,
///     congestion_control: CongestionControl::Bbr,
///     timeout: Duration::from_secs(30),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct JuicityConfig {
    /// 认证令牌
    pub token: String,
    /// TLS SNI 服务器名称
    pub server_name: String,
    /// 服务器地址（IP 或域名）
    pub server_addr: String,
    /// 服务器端口
    pub server_port: u16,
    /// 拥塞控制算法
    pub congestion_control: CongestionControl,
    /// 连接超时时间
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

/// Juicity 拥塞控制算法
///
/// 定义了 Juicity 支持的拥塞控制算法。
///
/// # 算法说明
///
/// - `Bbr`: Google BBR 算法，适合高延迟高带宽网络
/// - `Cubic`: 标准 CUBIC 算法，Linux 默认
/// - `Reno`: 标准 Reno 算法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControl {
    /// Google BBR 算法
    Bbr,
    /// 标准 CUBIC 算法
    Cubic,
    /// 标准 Reno 算法
    Reno,
}

impl CongestionControl {
    /// Parse from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "bbr" => Some(CongestionControl::Bbr),
            "cubic" => Some(CongestionControl::Cubic),
            "reno" => Some(CongestionControl::Reno),
            _ => None,
        }
    }

    /// Convert to protocol byte
    pub fn to_byte(self) -> u8 {
        match self {
            CongestionControl::Bbr => 0x01,
            CongestionControl::Cubic => 0x02,
            CongestionControl::Reno => 0x03,
        }
    }
}

/// Juicity connection state
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Connection {
    /// Connection ID
    id: u32,
    /// Session ID
    session_id: u32,
    /// Remote address
    remote_addr: SocketAddr,
    /// Last activity time
    last_activity: std::time::Instant,
    /// Is UDP relay
    is_udp: bool,
}

#[allow(dead_code)]
impl Connection {
    fn new(id: u32, session_id: u32, remote_addr: SocketAddr, is_udp: bool) -> Self {
        Self {
            id,
            session_id,
            remote_addr,
            last_activity: std::time::Instant::now(),
            is_udp,
        }
    }

    fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Juicity 处理器
///
/// 负责处理 Juicity 客户端连接的核心处理器。
/// 支持 TCP 握手和 UDP 数据报处理。
///
/// # 工作流程
///
/// 1. 读取初始握手（魔术头 + 版本 + 令牌 + 拥塞控制）
/// 2. 验证令牌
/// 3. 发送握手响应
/// 4. 根据类型处理 TCP 或 UDP 数据
pub struct JuicityHandler {
    config: JuicityConfig,
}

impl JuicityHandler {
    /// 创建新的 Juicity 处理器
    ///
    /// # 参数
    ///
    /// - `config`: Juicity 配置
    ///
    /// # 返回值
    ///
    /// 返回配置好的 `JuicityHandler` 实例
    pub fn new(config: JuicityConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建处理器
    ///
    /// # 返回值
    ///
    /// 返回使用默认配置的 `JuicityHandler` 实例
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: JuicityConfig::default(),
        }
    }

    /// 获取协议名称
    ///
    /// # 返回值
    ///
    /// 返回协议名称字符串 `"juicity"`
    pub fn name(&self) -> &'static str {
        "juicity"
    }

    /// Validate token (simple check - in real implementation would use proper crypto)
    fn validate_token(&self, token: &str) -> bool {
        // In production, this should use constant-time comparison
        token == self.config.token
    }

    /// Generate a new connection ID
    fn new_connection_id() -> u32 {
        use rand::Rng;
        rand::thread_rng().r#gen()
    }

    /// Generate a new session ID
    fn new_session_id() -> u32 {
        use rand::Rng;
        rand::thread_rng().r#gen()
    }

    /// 处理 Juicity TCP 客户端连接
    ///
    /// 处理 Juicity 协议的 TCP 握手和后续数据中继。
    ///
    /// # 参数
    ///
    /// - `self`: 处理器实例的 Arc 引用
    /// - `client`: 客户端 TCP 流
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 处理成功
    /// - `Err(JuicityError)`: 处理失败
    ///
    /// # 握手格式
    ///
    /// [2 字节魔术头 0xCAFE][1 字节版本][32 字节令牌][1 字节拥塞控制]
    pub async fn handle_tcp(self: Arc<Self>, mut client: TcpStream) -> Result<(), JuicityError> {
        let client_addr = client.peer_addr()?;
        debug!("Juicity TCP connection from {}", client_addr);

        // Read initial handshake
        // Juicity TCP handshake:
        // [4 bytes magic][1 byte version][32 bytes token][1 byte congestion control]
        let mut header = [0u8; 38];
        client.read_exact(&mut header).await?;

        // Validate magic number (0xCAFE)
        let magic = u16::from_be_bytes([header[0], header[1]]);
        if magic != 0xCAFE {
            return Err(JuicityError::InvalidHeader);
        }

        // Version
        let version = header[2];
        if version != 0x01 {
            return Err(JuicityError::Protocol(format!(
                "Unsupported version: {version}"
            )));
        }

        // Token (32 bytes)
        let token =
            String::from_utf8(header[3..35].to_vec()).map_err(|_| JuicityError::InvalidToken)?;

        if !self.validate_token(&token) {
            return Err(JuicityError::InvalidToken);
        }

        // Congestion control preference
        let _cc = header[35];

        // Send acknowledgment
        let response = [0xCA, 0xFE, 0x01, 0x00]; // magic + version + success
        client.write_all(&response).await?;

        debug!("Juicity handshake successful from {}", client_addr);

        // For TCP, the rest is just relay
        // In a full implementation, we would parse the target from additional headers
        // and relay between client and remote server

        // For now, just relay data
        self.relay_tcp(client).await
    }

    /// Relay TCP data between client and server
    async fn relay_tcp(&self, client: TcpStream) -> Result<(), JuicityError> {
        let remote_addr = format!("{}:{}", self.config.server_addr, self.config.server_port);

        let remote =
            tokio::time::timeout(self.config.timeout, TcpStream::connect(&remote_addr)).await??;

        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut rr, mut rw) = tokio::io::split(remote);

        let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
        let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

        tokio::try_join!(client_to_remote, remote_to_client)?;
        Ok(())
    }

    /// Handle UDP traffic
    #[allow(dead_code)]
    pub async fn handle_udp(self: Arc<Self>, socket: UdpSocket) -> Result<(), JuicityError> {
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        // Local bind address for server communication
        let local_addr = socket.local_addr()?;
        info!("Juicity UDP handler listening on {}", local_addr);

        loop {
            let (n, client_addr) =
                match tokio::time::timeout(self.config.timeout, socket.recv_from(&mut buf)).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => {
                        warn!("UDP recv error: {}", e);
                        continue;
                    }
                    Err(_) => {
                        // Timeout, continue to next iteration
                        continue;
                    }
                };

            if n == 0 {
                continue;
            }

            // Decode the packet
            let frame = match JuicityCodec::decode(&buf[..n]) {
                Some(f) => f,
                None => {
                    debug!("Invalid Juicity frame from {}", client_addr);
                    continue;
                }
            };

            debug!(
                "Juicity UDP: {} cmd={:?} conn_id={} from {}",
                client_addr, frame.command, frame.connection_id, client_addr
            );

            match frame.command {
                JuicityCommand::Open => {
                    // Handle new connection request
                    if let Some(addr) = frame.address {
                        let port = addr.port();
                        info!(
                            "Juicity Open: conn_id={} -> {}:{}",
                            frame.connection_id, addr, port
                        );
                        // In a full implementation, would connect to target and relay
                    }
                }
                JuicityCommand::Send => {
                    // Handle data send
                    debug!(
                        "Juicity Send: conn_id={} seq={} size={}",
                        frame.connection_id,
                        frame.sequence,
                        frame.payload.len()
                    );
                }
                JuicityCommand::Close => {
                    // Handle connection close
                    debug!("Juicity Close: conn_id={}", frame.connection_id);
                }
                JuicityCommand::Ping => {
                    // Respond with Pong
                    let pong = JuicityFrame::new_pong(frame.connection_id, frame.session_id);
                    let response = JuicityCodec::encode(&pong);
                    if let Err(e) = socket.send_to(&response, &client_addr).await {
                        debug!("Failed to send pong: {}", e);
                    }
                }
                JuicityCommand::Pong => {
                    // Heartbeat response, update connection state
                    debug!("Juicity Pong: conn_id={}", frame.connection_id);
                }
            }
        }
    }
}

/// Juicity 服务器
///
/// 用于接收和管理 Juicity 客户端连接的服务器。
///
/// # 注意
///
/// 当前实现是占位符，完整的服务器功能尚未实现。
pub struct JuicityServer {
    #[allow(dead_code)]
    handler: Arc<JuicityHandler>,
    listen_addr: SocketAddr,
}

impl JuicityServer {
    /// Create a new Juicity server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            handler: Arc::new(JuicityHandler::new_default()),
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    #[allow(dead_code)]
    pub async fn with_config(config: JuicityConfig) -> std::io::Result<Self> {
        Ok(Self {
            handler: Arc::new(JuicityHandler::new(config)),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        })
    }

    /// Get the listen address
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Start the server (placeholder for future implementation)
    #[allow(dead_code)]
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("Juicity server starting on {}", self.listen_addr);
        // Server implementation would go here
        // For now, just sleep indefinitely
        std::future::pending().await
    }
}

/// Juicity 客户端
///
/// 用于连接到远程 Juicity 服务器的客户端。
///
/// # 注意
///
/// 当前实现是占位符，完整的客户端功能尚未实现。
pub struct JuicityClient {
    config: JuicityConfig,
}

impl JuicityClient {
    /// Create a new Juicity client
    #[allow(dead_code)]
    pub fn new(config: JuicityConfig) -> Self {
        Self { config }
    }

    /// Connect to a remote Juicity server (placeholder)
    #[allow(dead_code)]
    pub async fn connect(
        &self,
        _target: JuicityAddress,
    ) -> Result<JuicityConnection, JuicityError> {
        let remote_addr = format!("{}:{}", self.config.server_addr, self.config.server_port);
        info!("Connecting to Juicity server at {}", remote_addr);

        // In a full implementation, this would establish the connection
        Ok(JuicityConnection {
            connection_id: JuicityHandler::new_connection_id(),
            session_id: JuicityHandler::new_session_id(),
            socket: None,
        })
    }
}

/// Juicity 连接句柄
///
/// 表示一个活跃的 Juicity 连接。
///
/// # 字段说明
///
/// - `connection_id`: 连接 ID
/// - `session_id`: 会话 ID
/// - `socket`: UDP 套接字（可选）
pub struct JuicityConnection {
    connection_id: u32,
    session_id: u32,
    socket: Option<UdpSocket>,
}

impl JuicityConnection {
    /// Send data through the connection
    #[allow(dead_code)]
    pub async fn send(&self, data: &[u8]) -> Result<(), JuicityError> {
        let frame = JuicityFrame::new_send(
            self.connection_id,
            self.session_id,
            0, // sequence
            data.to_vec(),
        );
        let encoded = JuicityCodec::encode(&frame);

        if let Some(ref socket) = self.socket {
            socket.send(&encoded).await?;
        }

        Ok(())
    }

    /// Receive data from the connection
    #[allow(dead_code)]
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, JuicityError> {
        if let Some(ref socket) = self.socket {
            let (n, _) = socket.recv_from(buf).await?;
            Ok(n)
        } else {
            Err(JuicityError::ConnectionNotFound(self.connection_id))
        }
    }

    /// Close the connection
    #[allow(dead_code)]
    pub async fn close(self) -> Result<(), JuicityError> {
        let frame = JuicityFrame::new_close(self.connection_id, self.session_id);
        let encoded = JuicityCodec::encode(&frame);

        if let Some(ref socket) = self.socket {
            socket.send(&encoded).await?;
        }

        Ok(())
    }
}

/// 实现 Handler trait for JuicityHandler
#[async_trait]
impl Handler for JuicityHandler {
    type Config = JuicityConfig;

    fn name(&self) -> &'static str {
        "juicity"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Juicity
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, _stream: TcpStream) -> std::io::Result<()> {
        // Juicity uses UDP primarily
        Ok(())
    }
}

/// JuicityConfig 实现 HandlerConfig trait
impl HandlerConfig for JuicityConfig {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_control_from_str() {
        assert_eq!(
            CongestionControl::from_str("bbr"),
            Some(CongestionControl::Bbr)
        );
        assert_eq!(
            CongestionControl::from_str("BBR"),
            Some(CongestionControl::Bbr)
        );
        assert_eq!(
            CongestionControl::from_str("cubic"),
            Some(CongestionControl::Cubic)
        );
        assert_eq!(
            CongestionControl::from_str("reno"),
            Some(CongestionControl::Reno)
        );
        assert_eq!(CongestionControl::from_str("unknown"), None);
    }

    #[test]
    fn test_congestion_control_to_byte() {
        assert_eq!(CongestionControl::Bbr.to_byte(), 0x01);
        assert_eq!(CongestionControl::Cubic.to_byte(), 0x02);
        assert_eq!(CongestionControl::Reno.to_byte(), 0x03);
    }

    #[test]
    fn test_default_config() {
        let config = JuicityConfig::default();
        assert_eq!(config.server_addr, "127.0.0.1");
        assert_eq!(config.server_port, 443);
        assert_eq!(config.congestion_control, CongestionControl::Bbr);
    }

    #[test]
    fn test_validate_token() {
        let config = JuicityConfig {
            token: "test_token_123".to_string(),
            ..Default::default()
        };
        let handler = JuicityHandler::new(config);

        assert!(handler.validate_token("test_token_123"));
        assert!(!handler.validate_token("wrong_token"));
        assert!(!handler.validate_token(""));
    }

    #[test]
    fn test_handler_name() {
        let handler = JuicityHandler::new_default();
        assert_eq!(handler.name(), "juicity");
    }

    #[test]
    fn test_connection_ids_unique() {
        let id1 = JuicityHandler::new_connection_id();
        let id2 = JuicityHandler::new_connection_id();
        // Note: There's a very small chance they could be equal, but extremely unlikely
        assert_ne!(id1, id2);
    }
}
