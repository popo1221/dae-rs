//! TUIC 协议常量与核心类型
//!
//! 包含 TUIC 协议的基本常量、命令类型和错误定义。

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
pub const TUIC_VERSION: u8 = 0x05;

/// TUIC 命令类型
///
/// 定义了 TUIC 协议中使用的各种命令类型。
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
#[derive(Debug, Clone)]
pub struct TuicAuthRequest {
    pub version: u8,
    pub uuid: String,
    pub token: String,
}

/// TUIC 连接请求
///
/// 客户端请求建立到目标地址的连接。
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
#[derive(Debug, Clone)]
pub struct TuicHeartbeatRequest {
    pub timestamp: i64,
}

/// TUIC 协议命令
///
/// 表示 TUIC 协议中的各种命令消息。
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

/// TUIC 错误类型
///
/// 定义了 TUIC 协议处理过程中可能发生的各种错误。
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
