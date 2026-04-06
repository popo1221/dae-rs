//! TUIC 协议类型定义
//!
//! 所有 TUIC 协议相关的类型都在这里定义，以避免循环依赖。
//!
//! # 主要类型
//!
//! - 命令类型 (`TuicCommandType`)
//! - 命令消息 (`TuicCommand`)
//! - 配置 (`TuicConfig`)
//! - 错误 (`TuicError`)
//! - 会话 (`TuicSession`)
//! - 服务器/客户端 (`TuicServer`, `TuicClient`)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use dae_protocol_core::{Handler, HandlerConfig, ProtocolType};

/// 上下文类型（占位符）
///
/// 当前实现中未使用，保留作为未来扩展。
///
/// # 注意
///
/// 此类型是一个存根，未来可能会用于传递连接上下文信息。
#[derive(Debug, Clone)]
pub struct Context {
    _private: (),
}

/// Proxy result type
pub type ProxyResult = std::result::Result<(), TuicError>;

/// TUIC 协议版本常量
///
/// 当前支持的 TUIC 协议版本为 0x05。
///
/// # 版本历史
///
/// - 0x05: 当前版本
pub const TUIC_VERSION: u8 = 0x05;

/// TUIC 命令类型
///
/// 定义了 TUIC 协议中使用的各种命令类型。
///
/// # 命令类型说明
///
/// - `Auth`: 认证（0x01）
/// - `Connect`: 连接（0x02）
/// - `Disconnect`: 断开连接（0x03）
/// - `Heartbeat`: 心跳（0x04）
/// - `UdpPacket`: UDP 数据包（0x05）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TuicCommandType {
    Auth = 0x01,
    Connect = 0x02,
    Disconnect = 0x03,
    Heartbeat = 0x04,
    UdpPacket = 0x05,
}

impl TuicCommandType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(TuicCommandType::Auth),
            0x02 => Some(TuicCommandType::Connect),
            0x03 => Some(TuicCommandType::Disconnect),
            0x04 => Some(TuicCommandType::Heartbeat),
            0x05 => Some(TuicCommandType::UdpPacket),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// TUIC 认证请求
///
/// 客户端在建立连接时发送的认证信息。
///
/// # 字段说明
///
/// - `version`: 协议版本
/// - `uuid`: 用户 UUID
/// - `token`: 认证令牌
///
/// # 消息格式
///
/// [1 字节版本][36 字节 UUID][2 字节令牌长度][令牌]
#[derive(Debug, Clone)]
pub struct TuicAuthRequest {
    pub version: u8,
    pub uuid: String,
    pub token: String,
}

/// TUIC 连接请求
///
/// 客户端请求建立到目标地址的连接。
///
/// # 字段说明
///
/// - `addr_type`: 地址类型（0x01=IPv4, 0x02=域名, 0x03=IPv6）
/// - `host`: 目标主机
/// - `port`: 目标端口
/// - `session_id`: 会话 ID
#[derive(Debug, Clone)]
pub struct TuicConnectRequest {
    pub addr_type: u8,
    pub host: String,
    pub port: u16,
    pub session_id: u64,
}

/// TUIC 心跳请求
///
/// 用于保持连接活跃的心跳消息。
///
/// # 字段说明
///
/// - `timestamp`: 客户端发送的时间戳
#[derive(Debug, Clone)]
pub struct TuicHeartbeatRequest {
    pub timestamp: i64,
}

/// TUIC 协议命令
///
/// 表示 TUIC 协议中的各种命令消息。
///
/// # 变体说明
///
/// - `Auth`: 认证请求
/// - `Connect`: 连接请求
/// - `ConnectResponse`: 连接响应（会话ID, 是否成功）
/// - `Disconnect`: 断开连接（会话ID）
/// - `Heartbeat`: 心跳请求
/// - `HeartbeatResponse`: 心跳响应（时间戳）
/// - `UdpPacket`: UDP 数据包（会话ID, 数据）
#[derive(Debug, Clone)]
pub enum TuicCommand {
    Auth(TuicAuthRequest),
    Connect(TuicConnectRequest),
    ConnectResponse(u64, bool),
    Disconnect(u64),
    Heartbeat(TuicHeartbeatRequest),
    HeartbeatResponse(i64),
    UdpPacket(u64, Vec<u8>),
}

/// TUIC 配置
///
/// 配置 TUIC 代理客户端或服务器的运行参数。
///
/// # 字段说明
///
/// - `token`: 认证令牌
/// - `uuid`: 用户 UUID
/// - `server_name`: TLS SNI 服务器名称
/// - `congestion_control`: 拥塞控制算法（默认 "bbr"）
/// - `max_idle_timeout`: 最大空闲超时时间（秒）
/// - `max_udp_packet_size`: 最大 UDP 数据包大小
/// - `flow_control_window`: 流控制窗口大小
///
/// # 示例
///
/// ```rust
/// use dae_protocol_tuic::TuicConfig;
///
/// let config = TuicConfig::new(
///     "your_token".to_string(),
///     "your_uuid".to_string(),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct TuicConfig {
    pub token: String,
    pub uuid: String,
    pub server_name: String,
    pub congestion_control: String,
    pub max_idle_timeout: u32,
    pub max_udp_packet_size: u32,
    pub flow_control_window: u32,
}

impl Default for TuicConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            uuid: String::new(),
            server_name: "tuic.cloud".to_string(),
            congestion_control: "bbr".to_string(),
            max_idle_timeout: 15,
            max_udp_packet_size: 1400,
            flow_control_window: 8388608,
        }
    }
}

impl TuicConfig {
    /// 创建新的 TUIC 配置
    ///
    /// # 参数
    ///
    /// - `token`: 认证令牌
    /// - `uuid`: 用户 UUID
    ///
    /// # 返回值
    ///
    /// 返回配置好的 `TuicConfig` 实例
    pub fn new(token: String, uuid: String) -> Self {
        Self { token, uuid, ..Default::default() }
    }

    /// 验证配置是否有效
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 配置有效
    /// - `Err(TuicError)`: 配置无效（token 或 uuid 为空）
    pub fn validate(&self) -> Result<(), TuicError> {
        if self.token.is_empty() {
            return Err(TuicError::InvalidConfig("token cannot be empty".to_string()));
        }
        if self.uuid.is_empty() {
            return Err(TuicError::InvalidConfig("uuid cannot be empty".to_string()));
        }
        Ok(())
    }
}

/// TUIC 错误类型
///
/// 定义了 TUIC 协议处理过程中可能发生的各种错误。
///
/// # 错误类型说明
///
/// - `Io`: IO 错误
/// - `InvalidProtocol`: 无效的协议数据
/// - `InvalidCommand`: 无效的命令
/// - `AuthFailed`: 认证失败
/// - `InvalidConfig`: 无效的配置
/// - `Timeout`: 超时
/// - `NotConnected`: 未连接
#[derive(Debug, thiserror::Error)]
pub enum TuicError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid protocol: {0}")]
    InvalidProtocol(String),
    #[error("Invalid command: {0}")]
    InvalidCommand(String),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Timeout")]
    Timeout,
    #[error("Not connected")]
    NotConnected,
}

/// TUIC 会话
///
/// 表示一个活跃的 TUIC 连接会话。
///
/// # 字段说明
///
/// - `session_id`: 会话唯一标识
/// - `remote`: 客户端远程地址
/// - `target_addr`: 目标地址（可选）
/// - `connected`: 是否已连接
/// - `last_heartbeat`: 最后心跳时间
#[derive(Debug, Clone)]
pub struct TuicSession {
    pub session_id: u64,
    pub remote: SocketAddr,
    pub target_addr: Option<(String, u16)>,
    pub connected: bool,
    pub last_heartbeat: i64,
}

impl TuicSession {
    /// 创建新的 TUIC 会话
    ///
    /// # 参数
    ///
    /// - `session_id`: 会话 ID
    /// - `remote`: 客户端远程地址
    ///
    /// # 返回值
    ///
    /// 返回新的 `TuicSession` 实例
    pub fn new(session_id: u64, remote: SocketAddr) -> Self {
        Self {
            session_id,
            remote,
            target_addr: None,
            connected: false,
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }
}

/// TUIC 服务器
///
/// 用于接收和管理 TUIC 客户端连接的服务器。
///
/// # 功能
///
/// - 管理多个活跃会话
/// - 处理客户端认证
/// - 处理连接和断开请求
/// - 心跳保活
///
/// # 使用示例
///
/// ```rust,ignore
/// let server = TuicServer::new(config)?;
/// server.listen(addr).await?;
/// ```
#[derive(Debug, Clone)]
pub struct TuicServer {
    config: TuicConfig,
    sessions: Arc<RwLock<HashMap<u64, TuicSession>>>,
}

impl TuicServer {
    /// 创建新的 TUIC 服务器
    ///
    /// # 参数
    ///
    /// - `config`: TUIC 配置
    ///
    /// # 返回值
    ///
    /// - `Ok(TuicServer)`: 服务器创建成功
    /// - `Err(TuicError)`: 配置无效或创建失败
    ///
    /// # 注意
    ///
    /// 此方法会自动验证配置
    pub fn new(config: TuicConfig) -> Result<Self, TuicError> {
        config.validate()?;
        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 获取服务器配置
    ///
    /// # 返回值
    ///
    /// 返回对服务器配置的引用
    pub fn config(&self) -> &TuicConfig {
        &self.config
    }

    /// 启动服务器监听
    ///
    /// 开始监听指定地址并接受客户端连接。
    /// 每个新连接都会由独立的异步任务处理。
    ///
    /// # 参数
    ///
    /// - `addr`: 要监听的地址
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 服务器正常关闭（通常不会发生）
    /// - `Err(TuicError)`: 发生错误
    ///
    /// # 注意
    ///
    /// 此方法会一直运行直到发生致命错误
    pub async fn listen(&self, addr: SocketAddr) -> Result<(), TuicError> {
        info!("TUIC server listening on {}", addr);
        let listener = TcpListener::bind(addr).await?;
        loop {
            match listener.accept().await {
                Ok((stream, remote)) => {
                    let config = self.config.clone();
                    let sessions = self.sessions.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, remote, config, sessions).await {
                            error!("TUIC client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("TUIC accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    remote: SocketAddr,
    config: TuicConfig,
    sessions: Arc<RwLock<HashMap<u64, TuicSession>>>,
) -> Result<(), TuicError> {
    use super::codec::TuicCodec;
    use super::tuic_impl::TuicCommand;

    debug!("New TUIC connection from {}", remote);

    let auth_request = match TuicCodec::read_auth_request(&mut stream).await {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to read auth request: {}", e);
            return Err(e);
        }
    };

    if auth_request.token != config.token || auth_request.uuid != config.uuid {
        error!("Authentication failed for UUID: {}", auth_request.uuid);
        TuicCodec::write_auth_response(&mut stream, false).await?;
        return Err(TuicError::AuthFailed("Invalid credentials".to_string()));
    }

    TuicCodec::write_auth_response(&mut stream, true).await?;
    info!("TUIC client authenticated: {}", auth_request.uuid);

    loop {
        match TuicCodec::read_command(&mut stream).await {
            Ok(command) => {
                match command {
                    TuicCommand::Connect(connect) => {
                        debug!("Connect request: {}:{} session={}", connect.host, connect.port, connect.session_id);
                        let mut session = TuicSession::new(connect.session_id, remote);
                        session.target_addr = Some((connect.host.clone(), connect.port));
                        session.connected = true;
                        sessions.write().await.insert(connect.session_id, session.clone());
                        TuicCodec::write_connect_response(&mut stream, connect.session_id, true).await?;
                        handle_tcp_relay(stream, session).await?;
                        break;
                    }
                    TuicCommand::Heartbeat(heartbeat) => {
                        debug!("Heartbeat: timestamp={}", heartbeat.timestamp);
                        TuicCodec::write_heartbeat_response(&mut stream, heartbeat.timestamp).await?;
                    }
                    TuicCommand::Disconnect(session_id) => {
                        debug!("Disconnect: session_id={}", session_id);
                        sessions.write().await.remove(&session_id);
                        break;
                    }
                    _ => {
                        warn!("Unexpected command type");
                    }
                }
            }
            Err(e) => {
                error!("Command read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_tcp_relay(mut client_stream: TcpStream, session: TuicSession) -> Result<(), TuicError> {
    if let Some((host, port)) = session.target_addr {
        let target: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|e| TuicError::InvalidProtocol(format!("Invalid target address: {}", e)))?;
        let mut target_stream = TcpStream::connect(target).await?;
        let (mut cr, mut cw) = client_stream.split();
        let (mut tr, mut tw) = target_stream.split();
        tokio::io::copy(&mut cr, &mut tw).await?;
        tokio::io::copy(&mut tr, &mut cw).await?;
    }
    Ok(())
}

/// TUIC 客户端
///
/// 用于连接到远程 TUIC 服务器的客户端。
///
/// # 功能
///
/// - 连接到服务器并认证
/// - 发起到目标地址的连接
/// - 管理客户端会话
pub struct TuicClient {
    config: TuicConfig,
    server_addr: SocketAddr,
}

impl TuicClient {
    /// 创建新的 TUIC 客户端
    ///
    /// # 参数
    ///
    /// - `config`: TUIC 配置
    /// - `server_addr`: 服务器地址
    ///
    /// # 返回值
    ///
    /// 返回新的 `TuicClient` 实例
    pub fn new(config: TuicConfig, server_addr: SocketAddr) -> Self {
        Self { config, server_addr }
    }

    /// 连接到 TUIC 服务器
    ///
    /// 建立到服务器的 TCP 连接并完成认证。
    ///
    /// # 返回值
    ///
    /// - `Ok(TuicClientSession)`: 连接成功
    /// - `Err(TuicError)`: 连接或认证失败
    ///
    /// # 协议流程
    ///
    /// 1. 建立 TCP 连接到服务器
    /// 2. 发送认证请求
    /// 3. 读取认证响应
    /// 4. 如果认证失败，返回错误
    pub async fn connect(&self) -> Result<TuicClientSession, TuicError> {
        use super::codec::TuicCodec;
        use super::tuic_impl::TuicAuthRequest;
        let mut stream = TcpStream::connect(self.server_addr).await?;
        let auth_request = TuicAuthRequest {
            version: TUIC_VERSION,
            uuid: self.config.uuid.clone(),
            token: self.config.token.clone(),
        };
        TuicCodec::write_auth_request(&mut stream, &auth_request).await?;
        let auth_success = TuicCodec::read_auth_response(&mut stream).await?;
        if !auth_success {
            return Err(TuicError::AuthFailed("Server rejected authentication".to_string()));
        }
        info!("TUIC client connected to server");
        Ok(TuicClientSession { stream, server_addr: self.server_addr, session_id: 0 })
    }

    /// 连接到目标地址
    ///
    /// 通过已建立的服务器连接，发起到目标地址的连接请求。
    ///
    /// # 参数
    ///
    /// - `session`: 客户端会话
    /// - `host`: 目标主机
    /// - `port`: 目标端口
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 连接成功
    /// - `Err(TuicError)`: 连接失败
    ///
    /// # 注意
    ///
    /// 必须先调用 `connect()` 建立服务器连接
    pub async fn connect_target(&self, session: &mut TuicClientSession, host: String, port: u16) -> Result<(), TuicError> {
        use super::codec::TuicCodec;
        use super::tuic_impl::TuicConnectRequest;
        let session_id = rand::random::<u64>();
        session.session_id = session_id;
        let connect_request = TuicConnectRequest {
            addr_type: if host.parse::<std::net::IpAddr>().is_ok() { 0x01 } else { 0x02 },
            host,
            port,
            session_id,
        };
        TuicCodec::write_connect_request(&mut session.stream, &connect_request).await?;
        let success = TuicCodec::read_connect_response(&mut session.stream).await?;
        if !success {
            return Err(TuicError::InvalidProtocol("Connect rejected".to_string()));
        }
        Ok(())
    }
}

/// TUIC 客户端会话
///
/// 表示客户端到服务器的活动连接。
///
/// # 字段说明
///
/// - `stream`: TCP 流
/// - `server_addr`: 服务器地址
/// - `session_id`: 会话 ID
#[derive(Debug)]
pub struct TuicClientSession {
    pub stream: TcpStream,
    pub server_addr: SocketAddr,
    pub session_id: u64,
}

/// TUIC 处理器
///
/// 提供 TUIC 协议入站/出站处理能力。
///
/// # 注意
///
/// 当前实现是占位符，完整处理逻辑待实现。
#[derive(Debug, Clone)]
pub struct TuicHandler {
    #[allow(dead_code)]
    config: TuicConfig,
}

impl TuicHandler {
    /// 创建新的 TUIC 处理器
    ///
    /// # 参数
    ///
    /// - `config`: TUIC 配置
    ///
    /// # 返回值
    ///
    /// 返回新的 `TuicHandler` 实例
    pub fn new(config: TuicConfig) -> Self {
        Self { config }
    }

    /// 处理入站连接
    ///
    /// 处理来自客户端的入站连接请求。
    ///
    /// # 参数
    ///
    /// - `self`: 处理器引用
    /// - `_ctx`: 上下文（当前未使用）
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 处理成功
    /// - `Err(TuicError)`: 处理失败
    ///
    /// # 注意
    ///
    /// 当前实现是占位符
    pub async fn handle_inbound(&self, _ctx: &mut Context) -> ProxyResult {
        debug!("TUIC handler processing inbound connection");
        Ok(())
    }

    /// 处理出站连接
    ///
    /// 处理出站（到远程服务器）的连接请求。
    ///
    /// # 参数
    ///
    /// - `self`: 处理器引用
    /// - `_ctx`: 上下文（当前未使用）
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 处理成功
    /// - `Err(TuicError)`: 处理失败
    ///
    /// # 注意
    ///
    /// 当前实现是占位符
    pub async fn handle_outbound(&self, _ctx: &mut Context) -> ProxyResult {
        debug!("TUIC handler processing outbound connection");
        Ok(())
    }
}

/// 实现 Handler trait for TuicHandler
#[async_trait]
impl Handler for TuicHandler {
    type Config = TuicConfig;

    fn name(&self) -> &'static str {
        "tuic"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Tuic
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, _stream: TcpStream) -> std::io::Result<()> {
        // TUIC uses QUIC, not raw TCP
        Ok(())
    }
}

/// TuicConfig 实现 HandlerConfig trait
impl HandlerConfig for TuicConfig {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_command_type_conversion() {
        assert_eq!(TuicCommandType::from_u8(0x01), Some(TuicCommandType::Auth));
        assert_eq!(TuicCommandType::from_u8(0x02), Some(TuicCommandType::Connect));
        assert_eq!(TuicCommandType::from_u8(0x03), Some(TuicCommandType::Disconnect));
        assert_eq!(TuicCommandType::from_u8(0x04), Some(TuicCommandType::Heartbeat));
        assert_eq!(TuicCommandType::from_u8(0xFF), None);
        assert_eq!(TuicCommandType::Auth.as_u8(), 0x01);
        assert_eq!(TuicCommandType::Connect.as_u8(), 0x02);
    }

    #[test]
    fn test_tuic_config_validation() {
        let valid = TuicConfig::new("token123".to_string(), "uuid456".to_string());
        assert!(valid.validate().is_ok());
        let empty_token = TuicConfig::new("".to_string(), "uuid456".to_string());
        assert!(empty_token.validate().is_err());
        let empty_uuid = TuicConfig::new("token123".to_string(), "".to_string());
        assert!(empty_uuid.validate().is_err());
    }

    #[test]
    fn test_tuic_session() {
        let session = TuicSession::new(12345, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(session.session_id, 12345);
        assert!(!session.connected);
    }

    #[test]
    fn test_tuic_error_display() {
        let err = TuicError::InvalidProtocol("bad proto".to_string());
        assert!(format!("{}", err).contains("bad proto"));
    }
}
