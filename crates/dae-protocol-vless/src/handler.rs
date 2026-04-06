//! VLESS 处理器实现模块
//!
//! 本模块实现 VLESS 协议处理器，支持：
//! - TCP 代理连接
//! - UDP 数据包处理
//! - XTLS Reality Vision 混淆
//!
//! # 协议处理流程
//! 1. 读取 VLESS 头部（38 字节）
//! 2. 验证版本号和 UUID
//! 3. 解析命令类型
//! 4. 根据命令执行相应的处理逻辑

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info};

use crate::config::VlessClientConfig;
use crate::crypto::hmac_sha256;
use crate::errors::VlessError;
use crate::protocol::VlessTargetAddress;
use crate::protocol::{VlessAddressType, VlessCommand, VLESS_HEADER_MIN_SIZE, VLESS_VERSION};
use crate::relay_data;
use crate::tls::build_reality_client_hello;
use dae_protocol_core::{Handler, ProtocolType};

/// VLESS 协议处理器
///
/// 负责处理 VLESS 协议的客户端连接。
///
/// # 字段说明
/// - `config`: VLESS 客户端配置
pub struct VlessHandler {
    /// VLESS 客户端配置
    config: VlessClientConfig,
}

impl VlessHandler {
    /// 创建新的 VLESS 处理器
    ///
    /// # 参数
    /// - `config`: VLESS 客户端配置
    pub fn new(config: VlessClientConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建处理器
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: VlessClientConfig::default(),
        }
    }

    /// 获取监听地址
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// 验证 UUID 格式
    ///
    /// # 参数
    /// - `uuid`: UUID 字节数组
    ///
    /// # 返回
    /// - `true`: UUID 长度为 16 字节（有效）
    /// - `false`: UUID 长度不是 16 字节
    ///
    /// # 说明
    /// VLESS 协议要求 UUID 为 128 位（16 字节）。
    pub fn validate_uuid(uuid: &[u8]) -> bool {
        uuid.len() == 16
    }

    /// 处理 VLESS 连接（实现 Handler trait）
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 连接
    ///
    /// # 协议处理
    /// 1. 读取 38 字节请求头
    /// 2. 验证版本号（必须为 0x01）
    /// 3. 验证 UUID（16 字节）
    /// 4. 解析命令并分发处理
    pub async fn handle_vless(self: Arc<Self>, mut client: TcpStream) -> Result<(), VlessError> {
        let client_addr = client.peer_addr()?;

        // 读取 VLESS 头部
        let mut header_buf = vec![0u8; VLESS_HEADER_MIN_SIZE];
        client.read_exact(&mut header_buf).await?;

        // 验证版本号
        if header_buf[0] != VLESS_VERSION {
            error!("Invalid VLESS version: {}", header_buf[0]);
            return Err(VlessError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VLESS version",
            )));
        }

        // 提取 UUID（字节 1-16）
        let uuid = &header_buf[1..17];
        if !Self::validate_uuid(uuid) {
            error!("Invalid UUID length");
            return Err(VlessError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid UUID",
            )));
        }

        // 验证 UUID 是否匹配配置
        let expected_uuid = self.config.server.uuid.as_bytes();
        if expected_uuid.len() == 16 && uuid != expected_uuid {
            error!("UUID mismatch");
            return Err(VlessError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid UUID",
            )));
        }

        // 提取命令（字节 18）
        let command = header_buf[18];
        let cmd = VlessCommand::from_u8(command).ok_or_else(|| {
            error!("Unknown VLESS command: {}", command);
            std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown VLESS command")
        })?;

        debug!("VLESS TCP: {} command={:?}", client_addr, cmd);

        match cmd {
            VlessCommand::Tcp => self.handle_tcp(client, &header_buf).await,
            VlessCommand::Udp => {
                error!("VLESS UDP: UDP traffic should go through the UDP port, not TCP");
                Err(VlessError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP traffic should use the UDP port",
                )))
            }
            VlessCommand::XtlsVision => self.handle_reality_vision(client, &header_buf).await,
        }
    }

    /// 处理 VLESS TCP 连接
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 连接
    /// - `_header_buf`: 已读取的头部数据（未使用）
    ///
    /// # 处理流程
    /// 1. 读取扩展头部（port + atyp + addr + iv）
    /// 2. 解析目标地址
    /// 3. 连接到 VLESS 服务器
    /// 4. 在客户端和服务器之间转发数据
    async fn handle_tcp(
        self: &Arc<Self>,
        mut client: TcpStream,
        _header_buf: &[u8],
    ) -> Result<(), VlessError> {
        // 读取扩展头部: port(4) + atyp(1) + addr + iv(16)
        let mut addl_buf = vec![0u8; 64];
        client.read_exact(&mut addl_buf).await?;

        // 解析目标地址
        let address = self.parse_target_address(&addl_buf)?;
        let _port = match &address {
            VlessTargetAddress::Domain(_, p) => *p,
            _ => u16::from_be_bytes([addl_buf[5], addl_buf[6]]),
        };

        info!(
            "VLESS TCP: -> {} (via {}:{})",
            address, self.config.server.addr, self.config.server.port
        );

        // 连接到 VLESS 服务器
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(VlessError::Io(e)),
            Err(_) => {
                return Err(VlessError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection to VLESS server timed out",
                )));
            }
        };

        debug!("Connected to VLESS server {}", remote_addr);

        // 在客户端和远程之间转发数据
        Ok(relay_data(client, remote).await?)
    }

    /// 处理 VLESS UDP 数据包
    ///
    /// # 参数
    /// - `client`: 本地 UDP socket（Arc 包装以共享）
    ///
    /// # VLESS UDP 头部格式
    /// ```text
    /// [v1(1)][uuid(16)][ver(1)][cmd(1)][port(2)][atyp(1)][addr][iv(16)][payload]
    /// ```
    ///
    /// # 处理流程
    /// 1. 接收 UDP 数据包
    /// 2. 解析 VLESS 头部（验证 UUID、版本、命令）
    /// 3. 提取目标地址和载荷
    /// 4. 发送到上游 VLESS 服务器
    /// 5. 接收响应并返回给客户端
    pub async fn handle_udp(self: Arc<Self>, client: Arc<UdpSocket>) -> Result<(), VlessError> {
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        let local_addr = client.local_addr().unwrap_or_else(|e| {
            debug!("VLESS UDP: failed to get local addr: {}", e);
            SocketAddr::from(([0, 0, 0, 0], 0))
        });
        info!(
            "VLESS UDP: listening on {} (via {}:{})",
            local_addr, self.config.server.addr, self.config.server.port
        );

        loop {
            let (n, client_addr) = client.recv_from(&mut buf).await?;

            const MIN_HEADER_SIZE: usize = 40;

            if n < MIN_HEADER_SIZE {
                debug!(
                    "VLESS UDP: packet too small from {}: {} bytes",
                    client_addr, n
                );
                continue;
            }

            let v1 = buf[0];
            if v1 != VLESS_VERSION {
                debug!("VLESS UDP: invalid version {} from {}", v1, client_addr);
                continue;
            }

            let uuid = &buf[1..17];
            if !Self::validate_uuid(uuid) {
                debug!("VLESS UDP: invalid UUID from {}", client_addr);
                continue;
            }

            let expected_uuid = self.config.server.uuid.as_bytes();
            if expected_uuid.len() == 16 && uuid != expected_uuid {
                debug!("VLESS UDP: UUID mismatch from {}", client_addr);
                continue;
            }

            let ver = buf[17];
            if ver != VLESS_VERSION {
                debug!(
                    "VLESS UDP: invalid protocol version {} from {}",
                    ver, client_addr
                );
                continue;
            }

            let cmd = buf[18];
            if cmd != VlessCommand::Udp as u8 {
                debug!("VLESS UDP: invalid command {} from {}", cmd, client_addr);
                continue;
            }

            let port = u16::from_be_bytes([buf[19], buf[20]]);
            let atyp = buf[21];

            let addr_start = 22;
            let (target_addr, addr_len) = match VlessAddressType::from_u8(atyp) {
                Some(VlessAddressType::Ipv4) => {
                    if n < addr_start + 4 + 2 {
                        debug!("VLESS UDP: buffer too small for IPv4 from {}", client_addr);
                        continue;
                    }
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        buf[addr_start],
                        buf[addr_start + 1],
                        buf[addr_start + 2],
                        buf[addr_start + 3],
                    ));
                    (ip, 4)
                }
                Some(VlessAddressType::Domain) => {
                    if n < addr_start + 1 + 2 {
                        debug!(
                            "VLESS UDP: buffer too small for domain length from {}",
                            client_addr
                        );
                        continue;
                    }
                    let domain_len = buf[addr_start] as usize;
                    if n < addr_start + 1 + domain_len + 2 {
                        debug!(
                            "VLESS UDP: buffer too small for domain from {}",
                            client_addr
                        );
                        continue;
                    }
                    let _domain = String::from_utf8(
                        buf[addr_start + 1..addr_start + 1 + domain_len].to_vec(),
                    )
                    .unwrap_or_else(|_| "invalid".to_string());
                    (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1 + domain_len)
                }
                Some(VlessAddressType::Ipv6) => {
                    if n < addr_start + 16 + 2 {
                        debug!("VLESS UDP: buffer too small for IPv6 from {}", client_addr);
                        continue;
                    }
                    let ip = IpAddr::V6(Ipv6Addr::new(
                        u16::from_be_bytes([buf[addr_start], buf[addr_start + 1]]),
                        u16::from_be_bytes([buf[addr_start + 2], buf[addr_start + 3]]),
                        u16::from_be_bytes([buf[addr_start + 4], buf[addr_start + 5]]),
                        u16::from_be_bytes([buf[addr_start + 6], buf[addr_start + 7]]),
                        u16::from_be_bytes([buf[addr_start + 8], buf[addr_start + 9]]),
                        u16::from_be_bytes([buf[addr_start + 10], buf[addr_start + 11]]),
                        u16::from_be_bytes([buf[addr_start + 12], buf[addr_start + 13]]),
                        u16::from_be_bytes([buf[addr_start + 14], buf[addr_start + 15]]),
                    ));
                    (ip, 16)
                }
                None => {
                    debug!(
                        "VLESS UDP: invalid address type {} from {}",
                        atyp, client_addr
                    );
                    continue;
                }
            };

            let iv_start = addr_start + addr_len;
            if n < iv_start + 16 {
                debug!("VLESS UDP: buffer too small for IV from {}", client_addr);
                continue;
            }
            let iv = &buf[iv_start..iv_start + 16];

            let payload_start = iv_start + 16;
            if n <= payload_start {
                debug!("VLESS UDP: no payload from {}", client_addr);
                continue;
            }
            let payload = &buf[payload_start..n];

            debug!(
                "VLESS UDP: {} -> {}:{} ({} bytes, iv: {:?})",
                client_addr,
                target_addr,
                port,
                payload.len(),
                &iv[..8]
            );

            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);

            let server_socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    debug!("VLESS UDP: failed to bind server socket: {}", e);
                    continue;
                }
            };

            // 构造服务器数据包
            let mut server_packet = Vec::with_capacity(n);
            server_packet.push(VLESS_VERSION);
            server_packet.extend_from_slice(uuid);
            server_packet.push(VLESS_VERSION);
            server_packet.push(VlessCommand::Udp as u8);
            server_packet.extend_from_slice(&port.to_be_bytes());

            match VlessAddressType::from_u8(atyp) {
                Some(VlessAddressType::Ipv4) => {
                    server_packet.push(atyp);
                    if let IpAddr::V4(ipv4) = target_addr {
                        server_packet.extend_from_slice(&ipv4.octets());
                    }
                }
                Some(VlessAddressType::Ipv6) => {
                    server_packet.push(atyp);
                    if let IpAddr::V6(ipv6) = target_addr {
                        for segment in ipv6.segments() {
                            server_packet.extend_from_slice(&segment.to_be_bytes());
                        }
                    }
                }
                Some(VlessAddressType::Domain) => {
                    let domain_len = buf[addr_start] as usize;
                    server_packet.push(atyp);
                    server_packet.extend_from_slice(&buf[addr_start..addr_start + 1 + domain_len]);
                }
                None => continue,
            }

            server_packet.extend_from_slice(iv);
            server_packet.extend_from_slice(payload);

            if let Err(e) = server_socket.send_to(&server_packet, &server_addr).await {
                debug!("VLESS UDP: failed to send to server: {}", e);
                continue;
            }

            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            match tokio::time::timeout(
                self.config.udp_timeout,
                server_socket.recv_from(&mut response_buf),
            )
            .await
            {
                Ok(Ok((m, _))) => {
                    if let Err(e) = client.send_to(&response_buf[..m], &client_addr).await {
                        debug!("VLESS UDP: failed to send response to client: {}", e);
                    }
                }
                Ok(Err(e)) => {
                    debug!("VLESS UDP: server recv error: {}", e);
                }
                Err(_) => {
                    debug!("VLESS UDP: server response timed out");
                }
            }
        }
    }

    /// 处理 VLESS Reality Vision 连接
    ///
    /// XTLS Reality Vision 是一种流量伪装技术：
    /// 1. 使用 X25519 密钥交换
    /// 2. 构造特殊的 TLS ClientHello 伪装成访问某个真实网站
    /// 3. 服务器验证后直接在 TLS 层转发流量
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 连接
    /// - `_header_buf`: 已读取的头部数据
    async fn handle_reality_vision(
        self: &Arc<Self>,
        client: TcpStream,
        _header_buf: &[u8],
    ) -> Result<(), VlessError> {
        let reality_config = self.config.server.reality.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Reality config required for XTLS Vision",
            )
        })?;

        // 生成临时 X25519 密钥对
        let mut rng = rand::rngs::OsRng;
        let scalar = curve25519_dalek::Scalar::random(&mut rng);
        let point = curve25519_dalek::MontgomeryPoint::mul_base(&scalar);
        let client_public: [u8; 32] = point.to_bytes();

        // 验证服务器公钥长度
        let server_public_key = &reality_config.public_key;
        if server_public_key.len() != 32 {
            return Err(VlessError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid server public key length",
            )));
        }

        // 计算共享密钥
        let server_point_array: [u8; 32] =
            server_public_key.as_slice().try_into().map_err(|_| {
                VlessError::Io(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid public key",
                ))
            })?;
        let server_point = curve25519_dalek::MontgomeryPoint(server_point_array);
        let shared_point = server_point * scalar;
        let shared_secret: [u8; 32] = shared_point.to_bytes();

        // 构造 Reality 请求
        let mut request = [0u8; 48];
        let hmac_key = hmac_sha256(&shared_secret, b"Reality Souls");
        request[..32].copy_from_slice(&hmac_key);

        if reality_config.short_id.len() >= 8 {
            request[32..40].copy_from_slice(&reality_config.short_id[..8]);
        }
        let random_bytes: [u8; 8] = rand::random();
        request[40..].copy_from_slice(&random_bytes);

        // 构建伪装 TLS ClientHello
        let destination = &reality_config.destination;
        let client_hello = build_reality_client_hello(&client_public, &request, destination)?;

        // 连接到 VLESS 服务器
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let mut remote =
            tokio::time::timeout(self.config.tcp_timeout, TcpStream::connect(&remote_addr))
                .await
                .map_err(|_| {
                    VlessError::Io(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "connection timed out",
                    ))
                })?
                .map_err(|_| {
                    VlessError::Io(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "connection timed out",
                    ))
                })?;

        remote.write_all(&client_hello).await?;
        remote.flush().await?;

        debug!("Sent Reality ClientHello to {}", remote_addr);

        // 读取服务器响应
        let mut server_response = vec![0u8; 8192];
        let n = tokio::time::timeout(self.config.tcp_timeout, remote.read(&mut server_response))
            .await
            .map_err(|_| {
                VlessError::Io(std::io::Error::new(ErrorKind::TimedOut, "read timed out"))
            })?
            .map_err(|_| {
                VlessError::Io(std::io::Error::new(ErrorKind::TimedOut, "read timed out"))
            })?;

        if n == 0 {
            return Err(VlessError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "server closed connection",
            )));
        }

        debug!("Received {} bytes from server", n);

        // 转发数据
        Ok(relay_data(client, remote).await?)
    }

    /// 解析目标地址
    ///
    /// # 参数
    /// - `buf`: 包含地址数据的缓冲区
    ///
    /// # 返回
    /// - `Ok(VlessTargetAddress)`: 解析成功
    /// - `Err(std::io::Error)`: 缓冲区太小或格式错误
    fn parse_target_address(&self, buf: &[u8]) -> Result<VlessTargetAddress, VlessError> {
        if buf.len() < 5 {
            return Err(VlessError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "buffer too small for VLESS address parsing (need at least 5 bytes)",
            )));
        }
        let atyp = buf[4];
        match VlessAddressType::from_u8(atyp) {
            Some(VlessAddressType::Ipv4) => {
                if buf.len() < 10 {
                    return Err(VlessError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for IPv4",
                    )));
                }
                let ip = IpAddr::V4(Ipv4Addr::new(buf[5], buf[6], buf[7], buf[8]));
                let _port = u16::from_be_bytes([buf[9], buf[10]]);
                Ok(VlessTargetAddress::Ipv4(ip))
            }
            Some(VlessAddressType::Domain) => {
                if buf.len() < 6 {
                    return Err(VlessError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for domain",
                    )));
                }
                let domain_len = buf[5] as usize;
                if domain_len == 0 {
                    return Err(VlessError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "empty domain not allowed",
                    )));
                }
                if buf.len() < 6 + domain_len + 2 {
                    return Err(VlessError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for domain content",
                    )));
                }
                let domain = String::from_utf8(buf[6..6 + domain_len].to_vec()).map_err(|_| {
                    VlessError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid domain",
                    ))
                })?;
                let port = u16::from_be_bytes([buf[6 + domain_len], buf[6 + domain_len + 1]]);
                Ok(VlessTargetAddress::Domain(domain, port))
            }
            Some(VlessAddressType::Ipv6) => {
                if buf.len() < 22 {
                    return Err(VlessError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for IPv6",
                    )));
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([buf[5], buf[6]]),
                    u16::from_be_bytes([buf[7], buf[8]]),
                    u16::from_be_bytes([buf[9], buf[10]]),
                    u16::from_be_bytes([buf[11], buf[12]]),
                    u16::from_be_bytes([buf[13], buf[14]]),
                    u16::from_be_bytes([buf[15], buf[16]]),
                    u16::from_be_bytes([buf[17], buf[18]]),
                    u16::from_be_bytes([buf[19], buf[20]]),
                ));
                let _port = u16::from_be_bytes([buf[21], buf[22]]);
                Ok(VlessTargetAddress::Ipv6(ip))
            }
            None => Err(VlessError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid address type",
            ))),
        }
    }
}

/// 为 VlessHandler 实现 Handler trait
#[async_trait]
impl Handler for VlessHandler {
    type Config = VlessClientConfig;

    fn name(&self) -> &'static str {
        "vless"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Vless
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        self.handle_vless(stream)
            .await
            .map_err(std::io::Error::from)
    }
}
