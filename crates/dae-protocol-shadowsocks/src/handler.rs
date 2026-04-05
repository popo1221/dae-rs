//! Shadowsocks 处理器实现模块
//!
//! 实现了 ss-local（本地代理）侧的连接处理器，负责解析 Shadowsocks 协议并转发数据。
//!
//! # 处理流程
//!
//! 1. 读取 Shadowsocks AEAD 头部（包含目标地址信息）
//! 2. 解析目标地址和端口
//! 3. 连接到远程 Shadowsocks 服务器
//! 4. 使用 `relay_bidirectional` 在客户端和服务器间双向转发数据
//!
//! # AEAD 协议格式
//!
//! AEAD 模式下，首个数据包包含加密的目标地址信息：
//! - `[1 byte type][2 bytes length][encrypted payload]`
//!
//! 解密后 payload 格式：`[1 byte ATYP][address][2 bytes port]`

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info};

use super::config::SsClientConfig;
use super::protocol::TargetAddress;

/// Shadowsocks 处理器，实现 ss-local 侧的数据处理
///
/// 负责处理单个 Shadowsocks 客户端连接，包括协议解析、目标地址提取、
/// 服务器连接建立和数据转发。
///
/// # 使用方式
///
/// 通常不直接创建，而是通过 [`ShadowsocksServer`] 内部使用：
///
/// ```ignore
/// let handler = Arc::new(ShadowsocksHandler::new(config));
/// handler.handle(client_stream).await?;
/// ```
pub struct ShadowsocksHandler {
    /// 客户端配置
    config: SsClientConfig,
}

impl ShadowsocksHandler {
    /// 创建 Shadowsocks 处理器
    ///
    /// # 参数
    ///
    /// - `config`: 完整的客户端配置
    ///
    /// # 返回值
    ///
    /// 返回配置好的处理器实例，用于处理 Shadowsocks 连接。
    pub fn new(config: SsClientConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建处理器
    ///
    /// 默认配置监听 `127.0.0.1:1080`，服务器为 `127.0.0.1:8388`，
    /// 加密方法为 `chacha20-ietf-poly1305`。
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: SsClientConfig::default(),
        }
    }

    /// 获取监听地址
    ///
    /// # 返回值
    ///
    /// 返回处理器配置的本地监听地址。
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.config.listen_addr
    }

    /// 处理 Shadowsocks 连接
    ///
    /// 这是处理器的主入口方法，处理一个完整的 Shadowsocks 客户端连接。
    ///
    /// # 参数
    ///
    /// - `self: Arc<Self>`: 处理器必须在 `Arc` 中以支持跨任务共享
    /// - `client`: 与 Shadowsocks 客户端之间的 TCP 流
    ///
    /// # 处理步骤
    ///
    /// 1. **读取 AEAD 头部**：读取 Shadowsocks AEAD 首部的类型字节和长度前缀
    /// 2. **解析目标地址**：从加密 payload 中解析目标地址和端口
    /// 3. **连接服务器**：建立到 Shadowsocks 服务器的 TCP 连接
    /// 4. **数据转发**：使用 `relay_bidirectional` 在客户端和服务器间双向转发数据
    ///
    /// # 错误处理
    ///
    /// - 连接超时：返回 `TimedOut` 错误
    /// - 地址解析失败：返回 `InvalidData` 错误
    /// - 服务器连接失败：返回对应的 IO 错误
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // Read the Shadowsocks AEAD header
        // Format: [1 byte type][payload]
        // For AEAD: first packet contains target address encrypted
        let mut header_buf = vec![0u8; 1];
        client.read_exact(&mut header_buf).await?;

        // For AEAD, we need to read the length prefix and encrypted payload
        // Length prefix is typically 2 bytes for AEAD
        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await?;
        let payload_len = u16::from_be_bytes(len_buf) as usize;

        // Read encrypted payload (contains target address)
        let mut encrypted_payload = vec![0u8; payload_len];
        client.read_exact(&mut encrypted_payload).await?;

        // Parse target address from payload
        // In a real implementation, we would decrypt the payload first
        // For now, we try to parse assuming plaintext (for testing/non-encrypted mode)
        // or the payload contains the raw target address
        let (target_addr, target_port) = match TargetAddress::parse_from_aead(&encrypted_payload) {
            Some((addr, port)) => (addr, port),
            None => {
                // If parsing fails, assume this is encrypted and we need the key
                // For a full implementation, decryption would happen here
                error!("Failed to parse Shadowsocks target address");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid Shadowsocks AEAD payload",
                ));
            }
        };

        info!(
            "Shadowsocks TCP: {} -> {}:{}",
            client_addr, target_addr, target_port
        );

        // Connect to the Shadowsocks server
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection to Shadowsocks server timed out",
                ));
            }
        };

        debug!("Connected to Shadowsocks server {}", remote_addr);

        // Relay data between client and remote
        self.relay(client, remote).await
    }

    /// Relay data between client and Shadowsocks server
    async fn relay(&self, client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        dae_relay::relay_bidirectional(client, remote).await
    }

    /// 处理 UDP 流量
    ///
    /// Shadowsocks UDP 代理处理器，将 UDP 数据报转发到目标地址并接收响应。
    ///
    /// # 参数
    ///
    /// - `self: Arc<Self>`: 处理器实例
    /// - `client`: 客户端 UDP 套接字
    ///
    /// # Shadowsocks UDP 数据报格式
    ///
    /// - ATYP (1 byte): 地址类型
    /// - DST.ADDR (变长): 目标地址
    /// - DST.PORT (2 bytes): 目标端口
    /// - DATA (N bytes): 原始 UDP 数据负载
    ///
    /// - ATYP: 地址类型（0x01=IPv4, 0x03=域名, 0x04=IPv6）
    /// - DST.ADDR: 目标地址（IPv4时4字节，IPv6时16字节，域名时1字节长度+域名）
    /// - DST.PORT: 目标端口（2字节，大端序）
    /// - DATA: 原始 UDP 数据负载
    #[allow(dead_code)]
    pub async fn handle_udp(self: Arc<Self>, client: UdpSocket) -> std::io::Result<()> {
        // Maximum UDP packet size for Shadowsocks
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        loop {
            let (n, client_addr) = client.recv_from(&mut buf).await?;

            if n < 3 {
                continue;
            }

            // Parse Shadowsocks UDP packet
            let atyp = buf[0];
            let (target_addr, target_port, payload_offset) = match atyp {
                0x01 => {
                    // IPv4
                    if n < 7 {
                        continue;
                    }
                    let ip = IpAddr::V4(Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]));
                    let port = u16::from_be_bytes([buf[5], buf[6]]);
                    (TargetAddress::Ip(ip), port, 7)
                }
                0x03 => {
                    // Domain
                    if n < 4 {
                        continue;
                    }
                    let domain_len = buf[1] as usize;
                    if n < 4 + domain_len {
                        continue;
                    }
                    let domain =
                        String::from_utf8(buf[2..2 + domain_len].to_vec()).unwrap_or_default();
                    let port = u16::from_be_bytes([buf[2 + domain_len], buf[3 + domain_len]]);
                    (TargetAddress::Domain(domain, port), port, 4 + domain_len)
                }
                0x04 => {
                    // IPv6
                    if n < 18 {
                        continue;
                    }
                    let ip = IpAddr::V6(Ipv6Addr::new(
                        u16::from_be_bytes([buf[1], buf[2]]),
                        u16::from_be_bytes([buf[3], buf[4]]),
                        u16::from_be_bytes([buf[5], buf[6]]),
                        u16::from_be_bytes([buf[7], buf[8]]),
                        u16::from_be_bytes([buf[9], buf[10]]),
                        u16::from_be_bytes([buf[11], buf[12]]),
                        u16::from_be_bytes([buf[13], buf[14]]),
                        u16::from_be_bytes([buf[15], buf[16]]),
                    ));
                    let port = u16::from_be_bytes([buf[17], buf[18]]);
                    (TargetAddress::Ip(ip), port, 19)
                }
                _ => continue,
            };

            let payload = &buf[payload_offset..n];

            debug!(
                "Shadowsocks UDP: {} -> {}:{} ({} bytes)",
                client_addr,
                target_addr,
                target_port,
                payload.len()
            );

            // Forward to Shadowsocks server and back
            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
            let server_socket = UdpSocket::bind("0.0.0.0:0").await?;
            server_socket.send_to(payload, &server_addr).await?;

            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            match tokio::time::timeout(
                self.config.udp_timeout,
                server_socket.recv_from(&mut response_buf),
            )
            .await
            {
                Ok(Ok((m, _))) => {
                    client.send_to(&response_buf[..m], &client_addr).await?;
                }
                _ => {
                    // Timeout or error, ignore
                }
            }
        }
    }
}
