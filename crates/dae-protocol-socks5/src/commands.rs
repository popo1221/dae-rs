//! SOCKS5 命令处理模块（RFC 1928）
//!
//! 处理 CONNECT（0x01）、BIND（0x02）和 UDP ASSOCIATE（0x03）命令。

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::info;

use super::address::Socks5Address;
use super::consts;
use super::reply::Socks5Reply;

/// SOCKS5 命令类型
///
/// 定义 SOCKS5 协议支持的命令。
#[derive(Debug, Clone, Copy)]
pub enum Socks5Command {
    /// CONNECT 命令：请求连接到目标服务器
    Connect,
    /// BIND 命令：请求服务器绑定地址并等待连接
    Bind,
    /// UDP ASSOCIATE 命令：请求建立 UDP 代理
    UdpAssociate,
}

impl Socks5Command {
    /// 从字节值解析命令
    ///
    /// # 参数
    /// - `v`: 原始字节值
    ///
    /// # 返回值
    /// - `Some(Socks5Command)`: 有效的命令
    /// - `None`: 无效的命令码
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            consts::CMD_CONNECT => Some(Socks5Command::Connect),
            consts::CMD_BIND => Some(Socks5Command::Bind),
            consts::CMD_UDP_ASSOCIATE => Some(Socks5Command::UdpAssociate),
            _ => None,
        }
    }
}

/// SOCKS5 命令处理器
///
/// 负责处理 SOCKS5 协议的请求阶段。
pub struct CommandHandler {
    /// TCP 超时时间（秒）
    tcp_timeout_secs: u64,
    /// UDP 接收缓冲区大小（可选）
    udp_rcvbuf: Option<usize>,
    /// UDP 超时时间（秒）
    udp_timeout_secs: u64,
}

impl CommandHandler {
    /// 创建新的命令处理器
    ///
    /// # 参数
    /// - `tcp_timeout_secs`: TCP 连接超时时间
    pub fn new(tcp_timeout_secs: u64) -> Self {
        Self {
            tcp_timeout_secs,
            udp_rcvbuf: None,
            udp_timeout_secs: 30,
        }
    }

    /// 设置 UDP 接收缓冲区大小
    ///
    /// # 参数
    /// - `size`: 缓冲区大小（字节）
    pub fn with_udp_rcvbuf(mut self, size: usize) -> Self {
        self.udp_rcvbuf = Some(size);
        self
    }

    /// 设置 UDP 超时时间
    ///
    /// # 参数
    /// - `secs`: 超时时间（秒）
    pub fn with_udp_timeout(mut self, secs: u64) -> Self {
        self.udp_timeout_secs = secs;
        self
    }

    /// 处理 SOCKS5 请求（阶段3）
    ///
    /// 解析客户端请求并执行对应的命令。
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 流
    ///
    /// # SOCKS5 请求格式
    ///
    /// ```text
    /// |VER |CMD |RSV |ATYP|  DST.ADDR   |  DST.PORT   |
    /// | 1  | 1  |  1 |  1  | Variable   |      2      |
    /// ```
    pub async fn handle_request(&self, mut client: TcpStream) -> std::io::Result<()> {
        // Read request: VER (1) + CMD (1) + RSV (1) + ATYP (1) + DST.ADDR + DST.PORT (2)
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await?;

        let ver = header[0];
        let cmd = header[1];

        if ver != consts::VER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid SOCKS version: {ver}"),
            ));
        }

        let command = match Socks5Command::from_u8(cmd) {
            Some(c) => c,
            None => {
                self.send_reply(
                    &mut client,
                    Socks5Reply::CommandNotSupported,
                    &Socks5Address::IPv4(Ipv4Addr::new(0, 0, 0, 0), 0),
                )
                .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown command: {cmd}"),
                ));
            }
        };

        // Parse destination address
        let dst_addr = Socks5Address::parse_from(&mut client).await?;
        tracing::debug!("SOCKS5 request: {:?} to {:?}", command, dst_addr);

        match command {
            Socks5Command::Connect => self.handle_connect(client, &dst_addr).await,
            Socks5Command::Bind => {
                self.send_reply(
                    &mut client,
                    Socks5Reply::CommandNotSupported,
                    &Socks5Address::IPv4(Ipv4Addr::new(0, 0, 0, 0), 0),
                )
                .await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "BIND command not supported",
                ))
            }
            Socks5Command::UdpAssociate => self.handle_udp_associate(client, &dst_addr).await,
        }
    }

    /// 处理 CONNECT 命令
    ///
    /// CONNECT 命令请求代理服务器连接到指定的目标地址。
    ///
    /// # 处理流程
    /// 1. 解析目标地址（IPv4/IPv6/域名）
    /// 2. 如果是域名，进行 DNS 解析
    /// 3. 建立到目标服务器的 TCP 连接
    /// 4. 发送成功响应
    /// 5. 桥接客户端和目标服务器的连接
    #[allow(clippy::incompatible_msrv)]
    pub async fn handle_connect(
        &self,
        mut client: TcpStream,
        dst_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        use dae_relay::relay_bidirectional as relay;

        // Resolve address
        let socket_addr = match dst_addr.to_socket_addr() {
            Some(addr) => addr,
            None => {
                // Need DNS resolution for domain names
                if let Socks5Address::Domain(domain, port) = dst_addr {
                    match tokio::net::lookup_host(format!("{domain}:{port}")).await {
                        Ok(mut addrs) => match addrs.next() {
                            Some(addr) => addr,
                            None => {
                                self.send_reply(
                                    &mut client,
                                    Socks5Reply::HostUnreachable,
                                    dst_addr,
                                )
                                .await?;
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::HostUnreachable,
                                    "no addresses found",
                                ));
                            }
                        },
                        Err(e) => {
                            self.send_reply(&mut client, Socks5Reply::HostUnreachable, dst_addr)
                                .await?;
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::HostUnreachable,
                                format!("DNS resolution failed: {e}"),
                            ));
                        }
                    }
                } else {
                    unreachable!()
                }
            }
        };

        // Connect to remote
        let timeout = std::time::Duration::from_secs(self.tcp_timeout_secs);
        let remote = match tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(socket_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let reply = Socks5Reply::from_io_error(&e);
                self.send_reply(&mut client, reply, dst_addr).await?;
                return Err(e);
            }
            Err(_) => {
                self.send_reply(&mut client, Socks5Reply::HostUnreachable, dst_addr)
                    .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timeout",
                ));
            }
        };

        let _local_addr = client.local_addr()?;

        // Send success reply with bound address (use local address)
        let bound_addr = Socks5Address::IPv4(
            if let std::net::SocketAddr::V4(v4) = client
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
            {
                *v4.ip()
            } else {
                Ipv4Addr::new(0, 0, 0, 0)
            },
            0,
        );
        self.send_reply(&mut client, Socks5Reply::Success, &bound_addr)
            .await?;

        info!("SOCKS5 CONNECT: -> {}", socket_addr);

        // Relay data between client and remote
        relay(client, remote).await
    }

    /// 处理 UDP ASSOCIATE 命令
    ///
    /// UDP ASSOCIATE 命令请求服务器设置 UDP 转发以处理 UDP 数据报。
    ///
    /// # RFC 1928 说明
    ///
    /// UDP ASSOCIATE 命令请求服务器设置 UDP 转发来处理 UDP 数据报。
    /// 客户端发送初始请求，服务器返回 UDP 转发地址。
    /// TCP 连接保持打开状态以管理 UDP 转发生命周期。
    ///
    /// # 参数
    /// - `client`: 客户端 TCP 连接
    /// - `dst_addr`: 客户端期望的 UDP 转发地址（通常被忽略）
    pub async fn handle_udp_associate(
        &self,
        mut client: TcpStream,
        _dst_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        // Get client address for UDP relay
        let client_addr = client.peer_addr()?;

        // Create a UDP socket for the association
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let udp_bind_addr = udp_socket.local_addr()?;

        // Note: UDP buffer size configuration is handled via system defaults
        // tokio::net::UdpSocket doesn't expose set_recv_buffer_size, but the
        // udp_rcvbuf field is kept for future use with standard library sockets if needed

        // Convert to IPv4 if possible for the reply
        let bind_addr = match udp_bind_addr {
            SocketAddr::V4(v4) => Socks5Address::IPv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Socks5Address::IPv6(*v6.ip(), v6.port()),
        };

        // Send success reply with UDP relay address
        self.send_reply(&mut client, Socks5Reply::Success, &bind_addr)
            .await?;

        info!(
            "SOCKS5 UDP ASSOCIATE: client={} relay={}",
            client_addr, udp_bind_addr
        );

        // Spawn UDP relay task and wait for TCP connection to close
        let udp_socket = Arc::new(udp_socket);

        // Keep TCP connection alive to manage UDP relay lifecycle
        // The UDP relay runs until the TCP connection closes
        let udp_timeout_secs = self.udp_timeout_secs;
        let udp_rcvbuf = self.udp_rcvbuf;
        tokio::spawn(async move {
            Self::udp_relay_loop(udp_socket, udp_timeout_secs, udp_rcvbuf).await;
        });

        // Wait for TCP connection to close
        let mut tcp_buf = [0u8; 1];
        let _ = client.read_exact(&mut tcp_buf).await;

        info!("SOCKS5 UDP ASSOCIATE: connection closed");
        Ok(())
    }

    /// UDP relay loop
    ///
    /// Receives UDP datagrams from clients, forwards to destinations,
    /// and returns responses back to clients.
    ///
    /// # SOCKS5 UDP Datagram Format (RFC 1928)
    ///
    /// ```text
    /// |RSV (2)|FRAG (1)|ATYP (1)|DST.ADDR     |DST.PORT (2)|DATA        |
    /// |  0x0000  |   n   |  1    | Variable   |     2      | Variable   |
    /// ```
    async fn udp_relay_loop(udp_socket: Arc<UdpSocket>, udp_timeout_secs: u64, _udp_rcvbuf: Option<usize>) {
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let timeout = std::time::Duration::from_secs(udp_timeout_secs);

        loop {
            // Receive datagram from client
            let (n, src_addr) = match tokio::time::timeout(timeout, udp_socket.recv_from(&mut buf)).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) | Err(_) => {
                    // Timeout or error, continue to next iteration
                    continue;
                }
            };

            if n < 10 {
                // Minimum: RSV(2) + FRAG(1) + ATYP(1) + ADDR(1) + PORT(2) + DATA(1) = 7
                // But typically at least 10 bytes for IPv4
                tracing::debug!("UDP packet too short: {} bytes from {}", n, src_addr);
                continue;
            }

            // Parse SOCKS5 UDP header
            let rsv = u16::from_be_bytes([buf[0], buf[1]]);
            let frag = buf[2];
            let _atyp = buf[3]; // Address type, needed for parsing

            // Check reserved bytes and fragment number
            if rsv != 0 {
                tracing::debug!("Invalid RSV in UDP packet: 0x{:04x}", rsv);
                continue;
            }

            // Fragmentation not supported
            if frag != 0 {
                tracing::debug!("Fragmented UDP packets not supported: frag={}", frag);
                // RFC 1928: if frag is non-zero and not supported, drop
                continue;
            }

            // Parse destination address
            let (dst_addr, dst_port, payload_offset) = match Self::parse_udp_dst_addr(&buf[3..]) {
                Some(result) => result,
                None => {
                    tracing::debug!("Failed to parse UDP destination address");
                    continue;
                }
            };

            let payload = &buf[payload_offset..n];
            let dst_str = format!("{}:{}", dst_addr, dst_port);

            tracing::debug!(
                "SOCKS5 UDP: {} -> {} ({} bytes)",
                src_addr,
                dst_str,
                payload.len()
            );

            // Forward to destination
            let dst_socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("Failed to create UDP socket for {}: {}", dst_str, e);
                    continue;
                }
            };

            if let Err(e) = dst_socket.send_to(payload, &dst_str).await {
                tracing::debug!("Failed to send UDP to {}: {}", dst_str, e);
                continue;
            }

            // Receive response from destination
            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            match tokio::time::timeout(timeout, dst_socket.recv_from(&mut response_buf)).await {
                Ok(Ok((m, _))) => {
                    // Build response SOCKS5 UDP header
                    let response_header = Self::build_udp_response_header(&buf[3..]);
                    let mut response = response_header;
                    response.extend_from_slice(&response_buf[..m]);

                    // Send back to client
                    if let Err(e) = udp_socket.send_to(&response, &src_addr).await {
                        tracing::debug!("Failed to send UDP response to {}: {}", src_addr, e);
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    // Timeout or error receiving response
                    tracing::debug!("Timeout receiving UDP response from {}", dst_str);
                }
            }
        }
    }

    /// Parse destination address from SOCKS5 UDP header
    ///
    /// # Arguments
    /// - `data`: slice starting from ATYP byte
    ///
    /// # Returns
    /// - `Some((address_string, port, total_header_len))` on success
    /// - `None` on failure
    fn parse_udp_dst_addr(data: &[u8]) -> Option<(String, u16, usize)> {
        if data.is_empty() {
            return None;
        }

        let atyp = data[0];
        match atyp {
            consts::ATYP_IPV4 => {
                // IPv4: ATYP(1) + IP(4) + PORT(2) = 7 bytes header
                if data.len() < 7 {
                    return None;
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Some((ip.to_string(), port, 7))
            }
            consts::ATYP_IPV6 => {
                // IPv6: ATYP(1) + IP(16) + PORT(2) = 19 bytes header
                if data.len() < 19 {
                    return None;
                }
                let ip = Ipv6Addr::new(
                    u16::from_be_bytes([data[1], data[2]]),
                    u16::from_be_bytes([data[3], data[4]]),
                    u16::from_be_bytes([data[5], data[6]]),
                    u16::from_be_bytes([data[7], data[8]]),
                    u16::from_be_bytes([data[9], data[10]]),
                    u16::from_be_bytes([data[11], data[12]]),
                    u16::from_be_bytes([data[13], data[14]]),
                    u16::from_be_bytes([data[15], data[16]]),
                );
                let port = u16::from_be_bytes([data[17], data[18]]);
                Some((ip.to_string(), port, 19))
            }
            consts::ATYP_DOMAIN => {
                // Domain: ATYP(1) + LEN(1) + DOMAIN + PORT(2)
                if data.len() < 4 {
                    return None;
                }
                let domain_len = data[1] as usize;
                if data.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(data[2..2 + domain_len].to_vec())
                    .map_err(|_| ())
                    .ok()?;
                let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
                Some((domain, port, 4 + domain_len))
            }
            _ => None,
        }
    }

    /// Build SOCKS5 UDP response header
    ///
    /// Returns a response header with the same destination address but with RSV=0 and FRAG=0.
    /// The header format: RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT
    fn build_udp_response_header(src_header: &[u8]) -> Vec<u8> {
        let mut header = Vec::with_capacity(src_header.len() + 3);
        // RSV = 0
        header.push(0x00);
        header.push(0x00);
        // FRAG = 0 (no fragmentation)
        header.push(0x00);
        // Copy ATYP + DST.ADDR + DST.PORT from source
        header.extend_from_slice(src_header);
        header
    }

    /// 发送 SOCKS5 回复
    ///
    /// # 参数
    /// - `client`: 客户端连接
    /// - `reply`: 回复状态
    /// - `bind_addr`: 绑定地址（服务器分配的地址）
    ///
    /// # 回复格式
    ///
    /// ```text
    /// |VER |REP |RSV |ATYP|  BND.ADDR   |  BND.PORT   |
    /// | 1  |  1 |  1 |  1  | Variable   |      2      |
    /// ```
    pub async fn send_reply(
        &self,
        client: &mut TcpStream,
        reply: Socks5Reply,
        bind_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        // Reply format: VER (1) + REP (1) + RSV (1) + ATYP (1) + BND.ADDR + BND.PORT (2)
        client
            .write_all(&[consts::VER, reply.to_u8(), 0x00])
            .await?;
        bind_addr.write_to(client).await
    }
}
