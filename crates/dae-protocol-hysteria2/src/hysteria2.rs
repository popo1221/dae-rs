//! Hysteria2 协议处理器模块
//!
//! 实现了 Hysteria2 代理协议的核心功能，包括：
//! - Hysteria2 配置管理
//! - 客户端 Hello 消息解析
//! - 服务器 Hello 消息生成
//! - 密码认证验证
//! - UDP 数据报中继
//!
//! # Hysteria2 协议文档
//!
//! - 使用 QUIC (RFC 9000) 作为底层传输协议
//! - 通过密码（共享密钥）进行认证
//! - 支持混淆以绕过深度包检测
//! - 基于带宽的拥塞控制
//!
//! # 协议流程
//!
//! 1. 客户端发送 Hello 消息，包含认证帧
//! 2. 服务器验证密码
//! 3. 客户端和服务器交换 UDP 数据报
//! 4. 每个数据报包含多路复用的流数据

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use dae_protocol_core::{Handler, HandlerConfig, ProtocolType};
use dae_relay::RelayStats;

/// Hysteria2 服务器配置
///
/// 配置 Hysteria2 代理服务器的运行参数。
///
/// # 字段说明
///
/// - `password`: 认证密码，用于验证客户端身份
/// - `server_name`: TLS SNI 服务器名称
/// - `obfuscate_password`: 混淆密码（可选），用于绕过 DPI
/// - `listen_addr`: 监听地址
/// - `bandwidth_limit`: 带宽限制（bps），0 表示无限制
/// - `idle_timeout`: QUIC 最大空闲超时时间
/// - `udp_enabled`: 是否启用 UDP 中继
///
/// # 示例
///
/// ```rust,ignore
/// use hysteria2::{Hysteria2Config, Hysteria2Server};
/// use std::net::SocketAddr;
/// use std::time::Duration;
///
/// let config = Hysteria2Config {
///     password: "your_password".to_string(),
///     server_name: "example.com".to_string(),
///     obfuscate_password: Some("obfs_password".to_string()),
///     listen_addr: "0.0.0.0:8123".parse().unwrap(),
///     bandwidth_limit: 0,
///     idle_timeout: Duration::from_secs(30),
///     udp_enabled: true,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Hysteria2Config {
    /// 认证密码，用于验证客户端身份
    pub password: String,
    /// TLS SNI 服务器名称
    pub server_name: String,
    /// 混淆密码（可选），用于绕过 DPI 检测
    pub obfuscate_password: Option<String>,
    /// 监听地址
    pub listen_addr: SocketAddr,
    /// 带宽限制（bps），0 表示无限制
    pub bandwidth_limit: u64,
    /// QUIC 最大空闲超时时间
    pub idle_timeout: Duration,
    /// 是否启用 UDP 中继
    pub udp_enabled: bool,
}

impl Default for Hysteria2Config {
    fn default() -> Self {
        Self {
            password: String::new(),
            server_name: String::new(),
            obfuscate_password: None,
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8123),
            bandwidth_limit: 0,
            idle_timeout: Duration::from_secs(30),
            udp_enabled: true,
        }
    }
}

/// Hysteria2 错误类型
///
/// 定义了 Hysteria2 协议处理过程中可能发生的各种错误。
///
/// # 错误类型说明
///
/// - `AuthFailed`: 认证失败（密码错误）
/// - `Protocol`: 协议错误（格式错误、版本不支持等）
/// - `Quic`: QUIC 相关错误
/// - `Io`: IO 错误
/// - `InvalidAddress`: 无效的地址格式
#[derive(Debug, thiserror::Error)]
pub enum Hysteria2Error {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}

/// Hysteria2 帧类型
///
/// 定义了 Hysteria2 协议中使用的各种帧类型。
/// 每个帧类型对应一个字节值，用于协议通信。
///
/// # 帧类型说明
///
/// - `ClientHello`: 客户端你好消息（0x01）
/// - `ServerHello`: 服务器你好消息（0x02）
/// - `UdpPacket`: UDP 数据包（0x03）
/// - `Heartbeat`: 心跳消息（0x04）
/// - `Disconnect`: 断开连接消息（0x05）
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Hysteria2FrameType {
    /// 客户端 Hello 消息
    ClientHello = 0x01,
    /// 服务器 Hello 消息
    ServerHello = 0x02,
    /// UDP 数据包
    UdpPacket = 0x03,
    /// 心跳消息
    Heartbeat = 0x04,
    /// 断开连接消息
    Disconnect = 0x05,
}

/// Hysteria2 地址类型
///
/// 表示 Hysteria2 协议中支持的地址类型。
/// 可以是 IPv4、IPv6 或域名地址。
///
/// # 地址类型
///
/// - `Ip(IpAddr)`: IP 地址（IPv4 或 IPv6）
/// - `Domain(String, u16)`: 域名地址和端口
///
/// # 字节编码格式
///
/// - `0x01`: IPv4，后跟 4 字节 IP + 2 字节端口
/// - `0x02`: 域名，后跟 1 字节长度 + 域名字节 + 2 字节端口
/// - `0x03`: IPv6，后跟 16 字节 IP + 2 字节端口
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hysteria2Address {
    /// IPv4 地址
    Ip(IpAddr),
    /// 域名和端口
    Domain(String, u16),
}

impl Hysteria2Address {
    /// 从字节数组解析地址
    ///
    /// 根据地址类型字节解析完整的地址信息。
    ///
    /// # 参数
    ///
    /// - `data`: 包含地址数据的字节数组
    ///
    /// # 返回值
    ///
    /// - `Ok((Hysteria2Address, usize))`: 解析成功，返回地址和消耗的字节数
    /// - `Err(Hysteria2Error)`: 解析失败
    ///
    /// # 支持的地址类型
    ///
    /// - `0x01`: IPv4（需要 7 字节）
    /// - `0x02`: 域名（长度可变）
    /// - `0x03`: IPv6（需要 19 字节）
    pub fn parse(data: &[u8]) -> Result<(Self, usize), Hysteria2Error> {
        if data.is_empty() {
            return Err(Hysteria2Error::InvalidAddress("Empty data".to_string()));
        }

        let addr_type = data[0];
        match addr_type {
            0x01 => {
                // IPv4
                if data.len() < 7 {
                    return Err(Hysteria2Error::InvalidAddress(
                        "IPv4 requires 7 bytes".to_string(),
                    ));
                }
                let ip = IpAddr::V4(Ipv4Addr::new(data[1], data[2], data[3], data[4]));
                let _port = u16::from_be_bytes([data[5], data[6]]);
                Ok((Hysteria2Address::Ip(ip), 7))
            }
            0x02 => {
                // Domain
                if data.len() < 2 {
                    return Err(Hysteria2Error::InvalidAddress(
                        "Domain requires length byte".to_string(),
                    ));
                }
                let domain_len = data[1] as usize;
                if data.len() < 2 + domain_len + 2 {
                    return Err(Hysteria2Error::InvalidAddress(
                        "Domain data too short".to_string(),
                    ));
                }
                let domain = String::from_utf8_lossy(&data[2..2 + domain_len]).to_string();
                let port = u16::from_be_bytes([data[2 + domain_len], data[2 + domain_len + 1]]);
                Ok((Hysteria2Address::Domain(domain, port), 2 + domain_len + 2))
            }
            0x03 => {
                // IPv6
                if data.len() < 19 {
                    return Err(Hysteria2Error::InvalidAddress(
                        "IPv6 requires 19 bytes".to_string(),
                    ));
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([data[1], data[2]]),
                    u16::from_be_bytes([data[3], data[4]]),
                    u16::from_be_bytes([data[5], data[6]]),
                    u16::from_be_bytes([data[7], data[8]]),
                    u16::from_be_bytes([data[9], data[10]]),
                    u16::from_be_bytes([data[11], data[12]]),
                    u16::from_be_bytes([data[13], data[14]]),
                    u16::from_be_bytes([data[15], data[16]]),
                ));
                let _port = u16::from_be_bytes([data[17], data[18]]);
                Ok((Hysteria2Address::Ip(ip), 19))
            }
            _ => Err(Hysteria2Error::InvalidAddress(format!(
                "Unknown address type: {addr_type}"
            ))),
        }
    }
}

/// Hysteria2 客户端 Hello 消息
///
/// 客户端在建立连接时发送的第一个消息，包含认证信息。
///
/// # 字段说明
///
/// - `version`: 协议版本（Hysteria2 应为 2）
/// - `password`: 认证密码（UTF-8 编码）
/// - `local_addr`: 请求的本地地址（可选）
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Hysteria2ClientHello {
    /// 协议版本（Hysteria2 应为 2）
    pub version: u8,
    /// 认证密码（UTF-8 编码）
    pub password: String,
    /// 请求的本地地址（可选）
    pub local_addr: Option<Hysteria2Address>,
}

/// Hysteria2 服务器 Hello 消息
///
/// 服务器响应客户端 Hello 的消息，表示认证结果和会话信息。
///
/// # 字段说明
///
/// - `version`: 协议版本（应为 2）
/// - `auth_ok`: 认证是否成功
/// - `session_id`: 服务器分配的会话 ID
#[derive(Debug, Clone)]
pub struct Hysteria2ServerHello {
    /// 协议版本（应为 2）
    pub version: u8,
    /// 认证是否成功
    pub auth_ok: bool,
    /// 服务器分配的会话 ID
    pub session_id: u64,
}

/// Hysteria2 处理器
///
/// 负责处理 Hysteria2 客户端连接的核心处理器。
/// 管理认证、协议解析和数据转发。
///
/// # 工作流程
///
/// 1. 读取并解析客户端 Hello 消息
/// 2. 验证密码认证
/// 3. 发送服务器 Hello 响应
/// 4. 处理 UDP 数据报中继
pub struct Hysteria2Handler {
    config: Hysteria2Config,
}

impl Hysteria2Handler {
    /// 创建新的 Hysteria2 处理器
    ///
    /// # 参数
    ///
    /// - `config`: Hysteria2 配置
    ///
    /// # 返回值
    ///
    /// 返回配置好的 `Hysteria2Handler` 实例
    pub fn new(config: Hysteria2Config) -> Self {
        Self { config }
    }

    /// 处理到来的 Hysteria2 客户端连接
    ///
    /// 处理一个完整的 Hysteria2 客户端会话。
    ///
    /// # 参数
    ///
    /// - `self`: 处理器引用
    /// - `stream`: 客户端 TCP 流
    ///
    /// # 返回值
    ///
    /// - `Ok(RelayStats)`: 处理成功完成，包含字节统计
    /// - `Err(Hysteria2Error)`: 处理过程中发生错误
    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<RelayStats, Hysteria2Error> {
        // Read client hello
        let mut hello_buf = [0u8; 1024];
        let n = stream.read(&mut hello_buf).await?;
        if n == 0 {
            return Err(Hysteria2Error::Protocol(
                "Connection closed during hello".to_string(),
            ));
        }

        // Parse client hello
        let client_hello = self.parse_client_hello(&hello_buf[..n])?;

        // Validate password
        if client_hello.password != self.config.password {
            return Err(Hysteria2Error::AuthFailed("Invalid password".to_string()));
        }

        // Send server hello
        let server_hello = Hysteria2ServerHello {
            version: 2,
            auth_ok: true,
            session_id: rand::random(),
        };
        self.send_server_hello(&mut stream, &server_hello).await?;

        // Handle the UDP relay
        let stats = if self.config.udp_enabled {
            self.handle_udp_relay(stream, client_hello.local_addr)
                .await?
        } else {
            RelayStats::default()
        };

        Ok(stats)
    }

    /// Handle with tracking for protocol-specific stats
    pub async fn handle_with_tracking(
        self: Arc<Self>,
        stream: TcpStream,
    ) -> std::io::Result<RelayStats> {
        self.handle_connection(stream)
            .await
            .map_err(std::io::Error::other)
    }

    fn parse_client_hello(&self, data: &[u8]) -> Result<Hysteria2ClientHello, Hysteria2Error> {
        if data.is_empty() {
            return Err(Hysteria2Error::Protocol("Empty hello data".to_string()));
        }

        let frame_type = data[0];
        if frame_type != Hysteria2FrameType::ClientHello as u8 {
            return Err(Hysteria2Error::Protocol(format!(
                "Expected ClientHello (0x01), got 0x{frame_type:02x}"
            )));
        }

        if data.len() < 3 {
            return Err(Hysteria2Error::Protocol(
                "ClientHello too short".to_string(),
            ));
        }

        let version = data[1];
        if version != 2 {
            return Err(Hysteria2Error::Protocol(format!(
                "Unsupported Hysteria2 version: {version}"
            )));
        }

        let password_len = data[2] as usize;
        if data.len() < 3 + password_len {
            return Err(Hysteria2Error::Protocol(
                "Password data too short".to_string(),
            ));
        }

        let password = String::from_utf8_lossy(&data[3..3 + password_len]).to_string();

        let local_addr = if data.len() > 3 + password_len {
            let (_, _size) = Hysteria2Address::parse(&data[3 + password_len..])?;
            // For now, skip local_addr parsing - it requires more complex handling
            None
        } else {
            None
        };

        Ok(Hysteria2ClientHello {
            version,
            password,
            local_addr,
        })
    }

    async fn send_server_hello(
        &self,
        stream: &mut TcpStream,
        hello: &Hysteria2ServerHello,
    ) -> Result<(), Hysteria2Error> {
        let mut buf = Vec::new();
        buf.push(Hysteria2FrameType::ServerHello as u8);
        buf.push(hello.version);
        buf.push(if hello.auth_ok { 0x01 } else { 0x00 });
        buf.extend_from_slice(&hello.session_id.to_be_bytes());

        stream.write_all(&buf).await?;
        Ok(())
    }

    async fn handle_udp_relay(
        &self,
        _stream: TcpStream,
        _local_addr: Option<Hysteria2Address>,
    ) -> Result<RelayStats, Hysteria2Error> {
        // UDP relay implementation would go here
        // This involves setting up UDP hole punching and relay
        // Hysteria2 uses QUIC, so byte tracking is done at QUIC level
        warn!("UDP relay not yet fully implemented - requires QUIC integration");
        Ok(RelayStats::default())
    }
}

/// Hysteria2 服务器
///
/// 用于接收和管理 Hysteria2 客户端连接的服务器。
/// 在接收到新连接后会 spawn 异步任务处理每个客户端。
///
/// # 使用示例
///
/// ```rust,ignore
/// let server = Hysteria2Server::new(config).await?;
/// server.serve().await?;
/// ```
pub struct Hysteria2Server {
    config: Hysteria2Config,
    listener: Option<TcpListener>,
}

impl Hysteria2Server {
    /// 创建新的 Hysteria2 服务器
    ///
    /// # 参数
    ///
    /// - `config`: Hysteria2 配置
    ///
    /// # 返回值
    ///
    /// - `Ok(Hysteria2Server)`: 服务器创建成功
    /// - `Err(Hysteria2Error)`: 绑定端口失败
    pub async fn new(config: Hysteria2Config) -> Result<Self, Hysteria2Error> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        info!("Hysteria2 server listening on {}", config.listen_addr);

        Ok(Self {
            config,
            listener: Some(listener),
        })
    }

    /// 启动服务器
    ///
    /// 开始监听并接受客户端连接。
    /// 此方法会一直运行直到发生致命错误或被取消。
    ///
    /// # 返回值
    ///
    /// - `Ok(())`: 服务器正常关闭
    /// - `Err(Hysteria2Error)`: 发生错误
    pub async fn serve(self) -> Result<(), Hysteria2Error> {
        let listener = self
            .listener
            .ok_or_else(|| Hysteria2Error::Protocol("Server already started".to_string()))?;

        let handler = Arc::new(Hysteria2Handler::new(self.config));

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(stream).await {
                            error!("Hysteria2 connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// 实现 Handler trait for Hysteria2Handler
#[async_trait]
impl Handler for Hysteria2Handler {
    type Config = Hysteria2Config;

    fn name(&self) -> &'static str {
        "hysteria2"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Hysteria2
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    /// Handle connection (required by Handler trait)
    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        // Delegate to handle_with_tracking and ignore stats
        let _stats = self.handle_with_tracking(stream).await?;
        Ok(())
    }
}

/// Hysteria2Config 实现 HandlerConfig trait
impl HandlerConfig for Hysteria2Config {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[test]
    fn test_parse_client_hello() {
        let config = Hysteria2Config::default();
        let handler = Hysteria2Handler::new(config);

        // Build a minimal client hello
        let mut data = Vec::new();
        data.push(0x01); // ClientHello frame type
        data.push(0x02); // Version 2
        data.push(4); // Password length
        data.extend_from_slice(b"test");

        let result = handler.parse_client_hello(&data);
        assert!(result.is_ok());
        let hello = result.unwrap();
        assert_eq!(hello.version, 2);
        assert_eq!(hello.password, "test");
    }

    #[test]
    fn test_invalid_password_length() {
        let config = Hysteria2Config::default();
        let handler = Hysteria2Handler::new(config);

        // Password length claims 10 but only 3 bytes provided
        let mut data = Vec::new();
        data.push(0x01); // ClientHello frame type
        data.push(0x02); // Version 2
        data.push(10); // Password length (lie)
        data.extend_from_slice(b"test");

        let result = handler.parse_client_hello(&data);
        assert!(result.is_err());
    }
}
