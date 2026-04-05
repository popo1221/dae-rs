//! SOCKS5 命令处理模块（RFC 1928）
//!
//! 处理 CONNECT（0x01）、BIND（0x02）和 UDP ASSOCIATE（0x03）命令。

use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
    /// ```
    /// |VER |CMD |RSV |ATYP|  DST.ADDR   |  DST.PORT   |
    /// | 1  | 1  | 1  | 1  | Variable   |      2      |
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
    ///
    /// # 注意
    ///
    /// 这是简化实现，实际的 UDP 转发需要：
    /// - UDP 套接字接收来自客户端的数据报
    /// - 解析 SOCKS5 UDP 头（RSV, FRAG, ATYP, DST.ADDR, DST.PORT）
    /// - 转发到目标地址
    /// - 返回响应到客户端
    pub async fn handle_udp_associate(
        &self,
        mut client: TcpStream,
        _dst_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        // Get client address for UDP relay
        let client_addr = client.peer_addr()?;

        // Create a UDP socket for the association
        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let udp_bind_addr = udp_socket.local_addr()?;

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

        // Note: Full UDP relay implementation requires:
        // - UDP socket receiving datagrams from clients
        // - Parsing SOCKS5 UDP header (RSV, FRAG, ATYP, DST.ADDR, DST.PORT)
        // - Forwarding to target destinations
        // - Returning responses back to client
        // This is a stub that keeps the TCP connection open to maintain the association
        // The actual UDP datagram forwarding should be handled by a separate relay service
        let mut tcp_buf = [0u8; 1];
        let _ = client.read_exact(&mut tcp_buf).await;

        info!("SOCKS5 UDP ASSOCIATE: connection closed");
        Ok(())
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
    /// ```
    /// |VER |REP |RSV |ATYP|  BND.ADDR   |  BND.PORT   |
    /// | 1  | 1  | 1  | 1  | Variable   |      2      |
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
