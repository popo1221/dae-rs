//! Trojan 处理器实现模块
//!
//! 本模块包含 `TrojanHandler`，负责处理 Trojan 协议的客户端连接逻辑。
//!
//! # 功能说明
//! - 解析 Trojan 协议请求头（密码、命令、目标地址）
//! - 支持 TCP 代理连接（`Proxy` 命令）
//! - 支持 UDP 关联（`UdpAssociate` 命令）
//! - 支持多后端服务器和轮询负载均衡
//! - 使用常量时间比较防止时序攻击
//!
//! # 协议处理流程
//! 1. 读取 56 字节密码并验证
//! 2. 读取命令字节（Proxy/UdpAssociate）
//! 3. 读取地址类型和目标地址信息
//! 4. 根据命令类型执行相应处理
//!
//! # 安全特性
//! - 密码验证使用 `subtle::ConstantTimeEq` 进行常量时间比较
//! - 防止时序攻击（timing attack）

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info};

use super::config::{TrojanClientConfig, TrojanServerConfig};
use super::errors::TrojanError;
use super::protocol::{TrojanCommand, TrojanTargetAddress, TROJAN_CRLF};
use super::types::relay_bidirectional;
use super::udp::UdpFrameBuilder;
use dae_protocol_core::{Handler, ProtocolType};

/// Trojan 协议处理器
///
/// 负责处理 Trojan 客户端请求，实现协议解析、路由和流量转发。
///
/// # 字段说明
/// - `config`: 客户端配置信息
/// - `backends`: 远程服务器后端列表，支持多后端负载均衡
/// - `current_index`: 轮询调度当前索引
///
/// # 多后端支持
/// 处理器支持配置多个后端服务器，通过轮询（round-robin）策略选择后端。
/// 当前连接失败时，下一次会尝试下一个后端。
pub struct TrojanHandler {
    /// 客户端配置
    config: TrojanClientConfig,
    /// 远程服务器后端列表
    backends: Vec<TrojanServerConfig>,
    /// 轮询调度当前索引
    current_index: std::sync::atomic::AtomicUsize,
}

impl TrojanHandler {
    /// 创建只有一个后端的 Trojan 处理器
    ///
    /// # 参数
    /// - `config`: Trojan 客户端配置，包含服务器信息和超时设置
    ///
    /// # 返回
    /// 新的 TrojanHandler 实例
    ///
    /// # 示例
    /// ```ignore
    /// let config = TrojanClientConfig::default();
    /// let handler = TrojanHandler::new(config);
    /// ```
    pub fn new(config: TrojanClientConfig) -> Self {
        Self {
            backends: vec![config.server.clone()],
            current_index: std::sync::atomic::AtomicUsize::new(0),
            config,
        }
    }

    /// 创建支持多后端的 Trojan 处理器
    ///
    /// # 参数
    /// - `config`: Trojan 客户端配置
    /// - `backends`: 额外的服务器后端列表（会被追加到主服务器后）
    ///
    /// # 行为
    /// - 如果 `backends` 为空，则只使用 `config.server` 作为唯一后端
    /// - 轮询调度时会依次使用所有后端
    pub fn with_backends(config: TrojanClientConfig, backends: Vec<TrojanServerConfig>) -> Self {
        Self {
            backends: if backends.is_empty() {
                vec![config.server.clone()]
            } else {
                backends
            },
            current_index: std::sync::atomic::AtomicUsize::new(0),
            config,
        }
    }

    /// 使用默认配置创建 Trojan 处理器
    ///
    /// 使用 `TrojanClientConfig::default()` 初始化配置，
    /// 连接到 127.0.0.1:443。
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: TrojanClientConfig::default(),
            backends: vec![TrojanServerConfig::default()],
            current_index: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// 获取下一个后端服务器（轮询调度）
    ///
    /// # 返回
    /// 下一个后端服务器的配置引用
    ///
    /// # 线程安全
    /// 使用原子操作实现无锁轮询，多线程并发调用安全
    fn next_backend(&self) -> &TrojanServerConfig {
        let idx = self
            .current_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.backends.len();
        &self.backends[idx]
    }

    /// 获取所有已配置的后端服务器列表
    #[allow(dead_code)]
    pub fn get_backends(&self) -> &[TrojanServerConfig] {
        &self.backends
    }

    /// 获取已配置的后端服务器数量
    ///
    /// # 返回
    /// 后端服务器总数
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// 获取本地监听地址
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// 验证密码是否正确（常量时间比较）
    ///
    /// # 参数
    /// - `password`: 待验证的密码字符串
    ///
    /// # 返回
    /// - `true`: 密码匹配
    /// - `false`: 密码不匹配
    ///
    /// # 安全说明
    /// 使用 `subtle::ConstantTimeEq` 进行比较，防止时序攻击。
    /// 即使密码长度不同，比较也会执行完整的固定时间，
    /// 防止通过比较时间推断密码前缀。
    pub fn validate_password(&self, password: &str) -> bool {
        let expected = self.config.server.password.as_bytes();
        let input = password.as_bytes();
        expected.ct_eq(input).unwrap_u8() == 1
    }

    /// 处理 Trojan TCP 连接
    ///
    /// # 参数
    /// - `self`: Arc<Self>，确保处理器在多连接场景下共享
    /// - `client`: 客户端 TCP 连接
    ///
    /// # 返回
    /// - `Ok(())`: 处理成功完成
    /// - `Err(std::io::Error)`: 处理过程中发生错误
    ///
    /// # 协议处理步骤
    /// 1. 读取 56 字节密码
    /// 2. 读取并验证 CRLF
    /// 3. 读取命令字节
    /// 4. 读取地址类型和目标地址
    /// 5. 根据命令执行 TCP 代理或 UDP 关联
    ///
    /// # 错误处理
    /// - 密码错误、CRLF 不匹配、未知命令等都会关闭连接
    /// - 连接后端超时会在日志中记录并返回错误
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> Result<(), TrojanError> {
        let client_addr = client.peer_addr()?;

        // Trojan 协议格式:
        // TLS 握手后，客户端发送:
        // [password (56 bytes)][\r\n]
        // [command (1 byte)][address type (1 byte)][address][port (2 bytes)][\r\n]
        // [payload ...]

        // 读取密码（56 字节）
        let mut password_buf = vec![0u8; 56];
        client.read_exact(&mut password_buf).await?;

        // 读取 CRLF（2 字节）
        let mut crlf_buf = [0u8; 2];
        client.read_exact(&mut crlf_buf).await?;
        if crlf_buf != TROJAN_CRLF {
            error!("Invalid Trojan header: missing CRLF after password");
            return Err(TrojanError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Trojan header",
            )));
        }

        // 读取命令字节
        let mut cmd_buf = [0u8; 1];
        client.read_exact(&mut cmd_buf).await?;
        let command = cmd_buf[0];

        let cmd = match command {
            0x01 => TrojanCommand::Proxy,
            0x02 => TrojanCommand::UdpAssociate,
            _ => {
                error!("Unknown Trojan command: {}", command);
                return Err(TrojanError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown Trojan command",
                )));
            }
        };

        debug!("Trojan TCP: {} command={:?}", client_addr, cmd);

        // 读取地址头（命令和 UDP Associate 共享此格式）
        // 读取地址类型
        let mut atyp_buf = [0u8; 1];
        client.read_exact(&mut atyp_buf).await?;
        let atyp = atyp_buf[0];

        // 根据地址类型读取地址
        let address = match atyp {
            0x01 => {
                // IPv4（4 字节）
                let mut ip_buf = [0u8; 4];
                client.read_exact(&mut ip_buf).await?;
                TrojanTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(
                    ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3],
                )))
            }
            0x02 => {
                // 域名（1 字节长度 + 域名）
                let mut len_buf = [0u8; 1];
                client.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; domain_len];
                client.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8(domain_buf).map_err(|_| {
                    TrojanError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid domain in Trojan header",
                    ))
                })?;
                TrojanTargetAddress::Domain(domain, 0) // 端口后续读取
            }
            0x03 => {
                // IPv6（16 字节）
                let mut ip_buf = [0u8; 16];
                client.read_exact(&mut ip_buf).await?;
                TrojanTargetAddress::Ipv6(IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([ip_buf[0], ip_buf[1]]),
                    u16::from_be_bytes([ip_buf[2], ip_buf[3]]),
                    u16::from_be_bytes([ip_buf[4], ip_buf[5]]),
                    u16::from_be_bytes([ip_buf[6], ip_buf[7]]),
                    u16::from_be_bytes([ip_buf[8], ip_buf[9]]),
                    u16::from_be_bytes([ip_buf[10], ip_buf[11]]),
                    u16::from_be_bytes([ip_buf[12], ip_buf[13]]),
                    u16::from_be_bytes([ip_buf[14], ip_buf[15]]),
                )))
            }
            _ => {
                return Err(TrojanError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid address type in Trojan header",
                )));
            }
        };

        // 读取端口（2 字节）
        let mut port_buf = [0u8; 2];
        client.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        // 读取最后的 CRLF（2 字节）
        let mut crlf_buf = [0u8; 2];
        client.read_exact(&mut crlf_buf).await?;
        if crlf_buf != TROJAN_CRLF {
            return Err(TrojanError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Trojan header: missing CRLF after address",
            )));
        }

        match cmd {
            TrojanCommand::Proxy => {
                let address_str = match &address {
                    TrojanTargetAddress::Domain(d, _) => format!("{d}:{port}"),
                    _ => format!("{address}:{port}"),
                };

                // 使用轮询选择后端
                let backend = self.next_backend();
                let remote_addr = format!("{}:{}", backend.addr, backend.port);
                let timeout = self.config.tcp_timeout;

                info!(
                    "Trojan TCP: {} -> {} (via {}:{}, {} backends available)",
                    client_addr,
                    address_str,
                    backend.addr,
                    backend.port,
                    self.backend_count()
                );

                // 连接到选定的后端服务器
                let remote =
                    match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            error!(
                                "Failed to connect to Trojan backend {}:{}: {}",
                                backend.addr, backend.port, e
                            );
                            return Err(TrojanError::Io(e));
                        }
                        Err(_) => {
                            error!(
                                "Timeout connecting to Trojan backend {}:{}",
                                backend.addr, backend.port
                            );
                            return Err(TrojanError::Io(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "connection to Trojan server timed out",
                            )));
                        }
                    };

                debug!("Connected to Trojan server {}", remote_addr);

                // 在客户端和远程之间转发数据
                self.relay(client, remote).await
            }
            TrojanCommand::UdpAssociate => {
                // Trojan UDP 关联 - UDP 数据包封装在 Trojan UDP 帧中
                // 帧格式: [cmd(1)][uuid(16)][ver(1)][port(2)][atyp(1)][addr][payload]
                // 初始头部解析后，UDP 帧通过 TCP 交换

                let address_str = match &address {
                    TrojanTargetAddress::Domain(d, _) => format!("{d}:{port}"),
                    _ => format!("{address}:{port}"),
                };

                info!(
                    "Trojan UDP Associate: {} -> {} ({} backends available)",
                    client_addr,
                    address_str,
                    self.backend_count()
                );

                // 使用轮询选择后端
                let backend = self.next_backend();
                let backend_addr = format!("{}:{}", backend.addr, backend.port);

                // 连接 UDP socket 到 Trojan 后端服务器
                let remote_udp = match tokio::time::timeout(
                    self.config.udp_timeout,
                    UdpSocket::bind("0.0.0.0:0"),
                )
                .await
                {
                    Ok(Ok(socket)) => socket,
                    Ok(Err(e)) => {
                        error!("Failed to bind UDP socket: {}", e);
                        return Err(TrojanError::Io(e));
                    }
                    Err(_) => {
                        error!("Timeout binding UDP socket");
                        return Err(TrojanError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP socket bind timed out",
                        )));
                    }
                };

                if let Err(e) = remote_udp.connect(&backend_addr).await {
                    error!("Failed to connect UDP to backend {}: {}", backend_addr, e);
                    return Err(TrojanError::Io(e));
                }

                debug!("Connected UDP socket to backend {}", backend_addr);

                // 在客户端（TCP）和远程（UDP）之间转发 UDP 数据包
                self.relay_udp_over_tcp(client, remote_udp, &address_str)
                    .await?;

                Ok(())
            }
        }
    }

    /// 在客户端和远程 TCP 连接之间转发数据
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 流
    /// - `remote`: 远程服务器 TCP 流
    async fn relay(&self, client: TcpStream, remote: TcpStream) -> Result<(), TrojanError> {
        Ok(relay_bidirectional(client, remote).await?)
    }

    /// 通过 TCP 传输的 Trojan UDP 帧协议，在客户端（TCP）和远程（UDP socket）之间转发 UDP 数据包
    ///
    /// # Trojan UDP 帧格式（通过 TCP 传输）
    /// ```text
    /// [cmd (1 byte)][uuid (16 bytes)][ver (1 byte)][target port (2 bytes)][addr type (1 byte)][target addr (variable)][payload (variable)]
    /// ```
    ///
    /// # 命令类型
    /// - `0x01`: UDP 数据包
    /// - `0x02`: 断开连接（DISCONNECT）
    /// - `0x03`: 心跳检测（PING/PONG）
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 流
    /// - `remote_udp`: 到 Trojan 服务器的 UDP socket
    /// - `target_info`: 目标地址信息字符串（用于日志）
    async fn relay_udp_over_tcp(
        &self,
        mut client: TcpStream,
        remote_udp: UdpSocket,
        target_info: &str,
    ) -> Result<(), TrojanError> {
        use super::udp::{MAX_UDP_FRAME_SIZE, UDP_HEADER_SIZE};
        let remote_addr = target_info.to_string();

        info!("Starting Trojan UDP relay: {} via UDP socket", remote_addr);

        loop {
            // 从 TCP 读取 UDP 帧头
            let mut header_buf = [0u8; UDP_HEADER_SIZE];
            match tokio::time::timeout(self.config.udp_timeout, client.read_exact(&mut header_buf))
                .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!("TCP read finished: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("TCP read timeout");
                    break;
                }
            };

            let (cmd, uuid, port, atyp) = match UdpFrameBuilder::parse_header(&header_buf) {
                Some(v) => v,
                None => continue,
            };

            let ver = header_buf[17];
            let target_port = u16::from_be_bytes(port);

            // 验证版本号
            if ver != 0x01 {
                debug!("Unknown Trojan UDP version: {}", ver);
                continue;
            }

            match cmd {
                0x01 => {
                    // UDP 数据 - 读取目标地址和载荷
                    let target_addr = match atyp {
                        0x01 => {
                            // IPv4 - 4 字节
                            let mut ip_buf = [0u8; 4];
                            client.read_exact(&mut ip_buf).await?;
                            IpAddr::V4(Ipv4Addr::new(ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]))
                                .to_string()
                        }
                        0x02 => {
                            // 域名 - 1 字节长度 + 域名
                            let mut len_buf = [0u8; 1];
                            client.read_exact(&mut len_buf).await?;
                            let domain_len = len_buf[0] as usize;
                            let mut domain_buf = vec![0u8; domain_len];
                            client.read_exact(&mut domain_buf).await?;
                            String::from_utf8(domain_buf).map_err(|_| {
                                TrojanError::Io(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "invalid domain in Trojan UDP header",
                                ))
                            })?
                        }
                        0x03 => {
                            // IPv6 - 16 字节
                            let mut ip_buf = [0u8; 16];
                            client.read_exact(&mut ip_buf).await?;
                            IpAddr::V6(Ipv6Addr::new(
                                u16::from_be_bytes([ip_buf[0], ip_buf[1]]),
                                u16::from_be_bytes([ip_buf[2], ip_buf[3]]),
                                u16::from_be_bytes([ip_buf[4], ip_buf[5]]),
                                u16::from_be_bytes([ip_buf[6], ip_buf[7]]),
                                u16::from_be_bytes([ip_buf[8], ip_buf[9]]),
                                u16::from_be_bytes([ip_buf[10], ip_buf[11]]),
                                u16::from_be_bytes([ip_buf[12], ip_buf[13]]),
                                u16::from_be_bytes([ip_buf[14], ip_buf[15]]),
                            ))
                            .to_string()
                        }
                        _ => {
                            debug!("Unknown address type in Trojan UDP: {}", atyp);
                            continue;
                        }
                    };

                    let target = format!("{}:{}", target_addr, target_port);

                    // 读取剩余的 UDP 数据（载荷）
                    let mut payload_buf = vec![0u8; MAX_UDP_FRAME_SIZE];
                    let mut total_read = 0;

                    // 尝试读取尽可能多的数据
                    loop {
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(100),
                            client.read(&mut payload_buf[total_read..]),
                        )
                        .await
                        {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => {
                                total_read += n;
                                if total_read >= MAX_UDP_FRAME_SIZE {
                                    break;
                                }
                            }
                            Ok(Err(e)) => {
                                debug!("Error reading UDP payload: {}", e);
                                break;
                            }
                            Err(_) => break,
                        }
                    }

                    if total_read == 0 {
                        continue;
                    }

                    debug!(
                        "Trojan UDP: forwarding {} bytes to {} (target: {})",
                        total_read, remote_addr, target
                    );

                    // 通过 UDP 转发载荷到远程 Trojan 服务器
                    match remote_udp.send(&payload_buf[..total_read]).await {
                        Ok(n) => debug!("Sent {} bytes to UDP server", n),
                        Err(e) => {
                            debug!("Failed to send to UDP server: {}", e);
                        }
                    }

                    // 从 UDP 服务器读取响应
                    let mut response_buf = vec![0u8; MAX_UDP_FRAME_SIZE];
                    match tokio::time::timeout(
                        self.config.udp_timeout,
                        remote_udp.recv(&mut response_buf),
                    )
                    .await
                    {
                        Ok(Ok(m)) if m > 0 => {
                            // 构建响应帧并通过 TCP 发送回客户端
                            let builder = UdpFrameBuilder::new(0x01, uuid, port, atyp);
                            let response_frame =
                                builder.build_response(&target_addr, &response_buf[..m]);

                            if let Err(e) = client.write_all(&response_frame).await {
                                debug!("Failed to send UDP response to client: {}", e);
                            }
                        }
                        _ => {
                            // 超时或错误 - 发送 PING 保持连接
                            debug!("No UDP response, sending PING");
                            let builder = UdpFrameBuilder::new(0x03, uuid, port, atyp);
                            let ping_frame = builder.build_pong();

                            if let Err(e) = client.write_all(&ping_frame).await {
                                debug!("Failed to send PING: {}", e);
                                break;
                            }
                        }
                    }
                }
                0x02 => {
                    // DISCONNECT - 客户端请求断开连接
                    debug!("Trojan UDP: DISCONNECT received");
                    break;
                }
                0x03 => {
                    // PING - 客户端检查连接是否存活
                    debug!("Trojan UDP: PING received");
                    // 发送 PONG 响应
                    let builder = UdpFrameBuilder::new(0x03, uuid, port, atyp);
                    let pong_frame = builder.build_pong();

                    if let Err(e) = client.write_all(&pong_frame).await {
                        debug!("Failed to send PONG: {}", e);
                        break;
                    }
                }
                _ => {
                    debug!("Unknown Trojan UDP command: {}", cmd);
                }
            }
        }

        info!("Trojan UDP relay finished for {}", remote_addr);
        Ok(())
    }

    /// 处理 UDP 流量
    ///
    /// # 参数
    /// - `self`: Arc<Self>
    /// - `client`: 本地 UDP socket
    ///
    /// # 注意
    /// 这是一个较老的 UDP 处理方式，直接在 UDP 层面操作。
    /// 建议使用 `handle` 方法中的 UDP Associate 机制。
    #[allow(dead_code)]
    pub async fn handle_udp(self: Arc<Self>, client: UdpSocket) -> std::io::Result<()> {
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        loop {
            let (n, client_addr) = client.recv_from(&mut buf).await?;

            if n < 5 {
                continue;
            }

            // 解析 Trojan UDP 头
            let (target_addr, target_port, payload_offset) =
                match TrojanTargetAddress::parse_from_bytes(&buf) {
                    Some((addr, port)) => (addr, port, 0),
                    None => continue,
                };

            let payload = &buf[payload_offset..n];

            debug!(
                "Trojan UDP: {} -> {}:{} ({} bytes)",
                client_addr,
                target_addr,
                target_port,
                payload.len()
            );

            // 转发到 Trojan 服务器并返回响应
            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
            let server_socket = UdpSocket::bind("0.0.0.0:0").await?;
            server_socket.send_to(payload, &server_addr).await?;

            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            if let Ok(Ok((m, _))) = tokio::time::timeout(
                self.config.udp_timeout,
                server_socket.recv_from(&mut response_buf),
            )
            .await
            {
                client.send_to(&response_buf[..m], &client_addr).await?;
            }
        }
    }
}

/// 实现 Handler trait for TrojanHandler
#[async_trait]
impl Handler for TrojanHandler {
    type Config = TrojanClientConfig;

    fn name(&self) -> &'static str {
        "trojan"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Trojan
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        self.handle(stream).await.map_err(std::io::Error::from)
    }
}

impl TrojanHandler {
    /// Handle Trojan connection with protocol tracking
    ///
    /// This method extends `handle` by capturing protocol-specific
    /// tracking information including password hint, command type, and target address.
    ///
    /// # Returns
    ///
    /// - `Ok(((), TrojanTrackingInfo))`: Success with tracking info
    /// - `Err(TrojanError)`: Connection error
    #[allow(dead_code)]
    pub async fn handle_with_tracking(
        self: Arc<Self>,
        mut client: TcpStream,
    ) -> Result<((), TrojanTrackingInfo), TrojanError> {
        use tokio::io::AsyncReadExt;

        let client_addr = client.peer_addr().map_err(TrojanError::Io)?;

        // Read password (56 bytes)
        let mut password_buf = vec![0u8; 56];
        client.read_exact(&mut password_buf).await.map_err(TrojanError::Io)?;

        // Validate password
        let expected_password = self.config.server.password.as_bytes();
        if expected_password.len() == 56 && password_buf[..] != expected_password[..] {
            error!("Trojan password mismatch from {}", client_addr);
            return Err(TrojanError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid Trojan password",
            )));
        }

        // Read command byte
        let mut cmd_buf = [0u8; 1];
        client.read_exact(&mut cmd_buf).await.map_err(TrojanError::Io)?;
        let command = cmd_buf[0];
        let cmd = match command {
            0x01 => TrojanCommand::Proxy,
            0x02 => TrojanCommand::UdpAssociate,
            _ => {
                error!("Unknown Trojan command: {}", command);
                return Err(TrojanError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown Trojan command",
                )));
            }
        };

        // Build tracking info
        let password_hint = if self.config.server.password.len() > 8 {
            format!("{}...", &self.config.server.password[..8])
        } else {
            self.config.server.password.clone()
        };
        let mut tracking_info = TrojanTrackingInfo::with_password(&password_hint)
            .with_command(cmd);

        // Parse address based on type
        let mut atyp_buf = [0u8; 1];
        client.read_exact(&mut atyp_buf).await.map_err(TrojanError::Io)?;
        let atyp = atyp_buf[0];

        let address = match atyp {
            0x01 => {
                // IPv4（4 字节）
                let mut ip_buf = [0u8; 4];
                client.read_exact(&mut ip_buf).await.map_err(TrojanError::Io)?;
                TrojanTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(
                    ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3],
                )))
            }
            0x02 => {
                // Domain（1 字节长度 + 域名）
                let mut len_buf = [0u8; 1];
                client.read_exact(&mut len_buf).await.map_err(TrojanError::Io)?;
                let domain_len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; domain_len];
                client.read_exact(&mut domain_buf).await.map_err(TrojanError::Io)?;
                let domain = String::from_utf8(domain_buf).map_err(|_| {
                    TrojanError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid domain in Trojan header",
                    ))
                })?;
                TrojanTargetAddress::Domain(domain, 0)
            }
            0x03 => {
                // IPv6（16 字节）
                let mut ip_buf = [0u8; 16];
                client.read_exact(&mut ip_buf).await.map_err(TrojanError::Io)?;
                TrojanTargetAddress::Ipv6(IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([ip_buf[0], ip_buf[1]]),
                    u16::from_be_bytes([ip_buf[2], ip_buf[3]]),
                    u16::from_be_bytes([ip_buf[4], ip_buf[5]]),
                    u16::from_be_bytes([ip_buf[6], ip_buf[7]]),
                    u16::from_be_bytes([ip_buf[8], ip_buf[9]]),
                    u16::from_be_bytes([ip_buf[10], ip_buf[11]]),
                    u16::from_be_bytes([ip_buf[12], ip_buf[13]]),
                    u16::from_be_bytes([ip_buf[14], ip_buf[15]]),
                )))
            }
            _ => {
                return Err(TrojanError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid address type in Trojan header",
                )));
            }
        };

        // Read port (2 bytes)
        let mut port_buf = [0u8; 2];
        client.read_exact(&mut port_buf).await.map_err(TrojanError::Io)?;
        let port = u16::from_be_bytes(port_buf);

        // Read final CRLF (2 bytes)
        let mut crlf_buf = [0u8; 2];
        client.read_exact(&mut crlf_buf).await.map_err(TrojanError::Io)?;
        if crlf_buf != TROJAN_CRLF {
            return Err(TrojanError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Trojan header: missing CRLF",
            )));
        }

        // Build target address string
        let address_str = match &address {
            TrojanTargetAddress::Domain(d, _) => format!("{}:{}", d, port),
            _ => format!("{}:{}", address, port),
        };
        tracking_info = tracking_info.with_target_addr(&address_str);

        match cmd {
            TrojanCommand::Proxy => {
                // Use round-robin backend selection
                let backend = self.next_backend();
                let remote_addr = format!("{}:{}", backend.addr, backend.port);
                let timeout = self.config.tcp_timeout;

                info!(
                    "Trojan TCP: {} -> {} (via {}:{}, {} backends available)",
                    client_addr,
                    address_str,
                    backend.addr,
                    backend.port,
                    self.backend_count()
                );

                // Connect to backend server
                let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        error!("Failed to connect to Trojan backend: {}", e);
                        return Err(TrojanError::Io(e));
                    }
                    Err(_) => {
                        return Err(TrojanError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "connection to Trojan server timed out",
                        )));
                    }
                };

                debug!("Connected to Trojan server {}", remote_addr);

                // Relay with stats
                let stats = match dae_relay::relay_bidirectional_with_stats(client, remote).await {
                    Ok(s) => s,
                    Err(e) => return Err(TrojanError::Io(e)),
                };

                tracking_info = tracking_info.with_bytes(
                    stats.bytes_remote_to_client,
                    stats.bytes_client_to_remote,
                );

                Ok(((), tracking_info))
            }
            TrojanCommand::UdpAssociate => {
                info!(
                    "Trojan UDP Associate: {} -> {} ({} backends available)",
                    client_addr,
                    address_str,
                    self.backend_count()
                );
                // For now, return unsupported error for UDP
                // Full UDP support would need similar relay logic
                Err(TrojanError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP associate not fully implemented with tracking",
                )))
            }
        }
    }
}

/// Trojan tracking information for protocol-specific tracking
#[derive(Debug, Default, Clone)]
pub struct TrojanTrackingInfo {
    /// Password hint (first 8 chars of password)
    pub password_hint: String,
    /// Command type (Proxy/UdpAssociate)
    pub command: String,
    /// Target address
    pub target_addr: String,
    /// Inbound bytes
    pub bytes_in: u64,
    /// Outbound bytes
    pub bytes_out: u64,
}

impl TrojanTrackingInfo {
    /// Create a new Trojan tracking info
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from password
    pub fn with_password(password: &str) -> Self {
        // Use first 8 chars as hint for privacy
        let hint = if password.len() > 8 {
            format!("{}...", &password[..8])
        } else {
            password.to_string()
        };
        Self {
            password_hint: hint,
            ..Default::default()
        }
    }

    /// Set command type
    pub fn with_command(mut self, cmd: TrojanCommand) -> Self {
        self.command = format!("{:?}", cmd);
        self
    }

    /// Set target address
    pub fn with_target_addr(mut self, addr: &str) -> Self {
        self.target_addr = addr.to_string();
        self
    }

    /// Set bytes transferred
    pub fn with_bytes(mut self, bytes_in: u64, bytes_out: u64) -> Self {
        self.bytes_in = bytes_in;
        self.bytes_out = bytes_out;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::TrojanTlsConfig;
    use super::*;

    /// 测试处理器创建（单个后端）
    #[test]
    fn test_handler_creation() {
        let config = TrojanClientConfig::default();
        let handler = TrojanHandler::new(config);
        assert_eq!(handler.backend_count(), 1);
    }

    /// 测试多后端处理器创建
    #[test]
    fn test_handler_with_multiple_backends() {
        let config = TrojanClientConfig::default();
        let backends = vec![
            TrojanServerConfig::default(),
            TrojanServerConfig {
                addr: "2.2.2.2".to_string(),
                ..Default::default()
            },
        ];
        let handler = TrojanHandler::with_backends(config, backends);
        assert_eq!(handler.backend_count(), 2);
    }

    /// 测试轮询调度
    #[test]
    fn test_next_backend_round_robin() {
        let config = TrojanClientConfig::default();
        let backends = vec![
            TrojanServerConfig {
                addr: "1.1.1.1".to_string(),
                ..Default::default()
            },
            TrojanServerConfig {
                addr: "2.2.2.2".to_string(),
                ..Default::default()
            },
        ];
        let handler = TrojanHandler::with_backends(config, backends);

        // 由于 fetch_add，索引会先递增
        let backend1 = handler.next_backend();
        let backend2 = handler.next_backend();

        // 两次调用应返回不同的后端
        assert_ne!(backend1.addr, backend2.addr);
    }

    /// 测试客户端配置默认值
    #[test]
    fn test_trojan_client_config_default() {
        let config = TrojanClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
    }

    /// 测试服务器配置默认值
    #[test]
    fn test_trojan_server_config_default() {
        let config = TrojanServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 443);
    }

    /// 测试自定义服务器配置
    #[test]
    fn test_trojan_server_config_custom() {
        let config = TrojanServerConfig {
            addr: "192.168.1.1".to_string(),
            port: 8443,
            password: "my_secret".to_string(),
            tls: TrojanTlsConfig::default(),
        };
        assert_eq!(config.addr, "192.168.1.1");
        assert_eq!(config.port, 8443);
        assert_eq!(config.password, "my_secret");
        assert!(config.tls.enabled);
    }
}
