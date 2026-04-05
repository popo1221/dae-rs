//! SOCKS4 服务器处理器实现模块
//!
//! 包含 SOCKS4 服务器配置和连接处理逻辑。

use std::net::SocketAddrV4;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use super::protocol::{Socks4Command, Socks4Reply, REP_REQUEST_GRANTED, REP_REQUEST_REJECTED};
use super::request::Socks4Request;

/// SOCKS4 处理器配置
///
/// 包含 SOCKS4 代理服务器的配置参数。
#[derive(Debug, Clone)]
pub struct Socks4Config {
    /// SOCKS4 服务器绑定地址
    ///
    /// 用于 BIND 命令，当服务器需要主动连接客户端时使用。
    pub bind_addr: String,

    /// SOCKS4 服务器监听端口
    pub port: u16,

    /// 是否启用 SOCKS4a 扩展（支持域名）
    ///
    /// SOCKS4a 是 SOCKS4 的扩展，通过特殊标记支持域名解析。
    /// 默认启用。
    pub enable_socks4a: bool,
}

impl Default for Socks4Config {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_string(),
            port: 1080,
            enable_socks4a: true,
        }
    }
}

/// SOCKS4 服务器
///
/// 负责监听并处理 SOCKS4 客户端连接请求。
pub struct Socks4Server {
    config: Socks4Config,
}

impl Socks4Server {
    /// 创建新的 SOCKS4 服务器
    ///
    /// # 参数
    /// - `config`: 服务器配置
    pub fn new(config: Socks4Config) -> Self {
        Self { config }
    }

    /// 使用默认配置创建服务器
    ///
    /// 默认配置：绑定地址 127.0.0.1，端口 1080，启用 SOCKS4a。
    pub fn with_default_config() -> Self {
        Self::new(Socks4Config::default())
    }

    /// 处理 SOCKS4 连接
    ///
    /// 处理一个完整的 SOCKS4 客户端连接请求。
    ///
    /// # 参数
    /// - `stream`: 客户端 TCP 连接流
    ///
    /// # 处理流程
    /// 1. 解析 SOCKS4 请求
    /// 2. 根据命令类型处理（CONNECT 或 BIND）
    /// 3. 返回响应并建立连接桥接
    pub async fn handle_connection(&self, mut stream: TcpStream) -> std::io::Result<()> {
        // Parse request
        let request = match Socks4Request::parse(&mut stream).await {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse SOCKS4 request: {}", e);
                // Send rejection
                let response = [
                    0x00,
                    REP_REQUEST_REJECTED,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ];
                let _ = stream.write_all(&response).await;
                return Err(e);
            }
        };

        debug!(
            "SOCKS4 request: {:?}, user: {}",
            request.command, request.user_id
        );

        match request.command {
            Socks4Command::Connect => self.handle_connect(stream, request).await,
            Socks4Command::Bind => self.handle_bind(stream, request).await,
        }
    }

    /// 处理 CONNECT 命令
    ///
    /// CONNECT 命令请求代理服务器连接到指定的目标地址。
    ///
    /// # 处理流程
    /// 1. 如果是 SOCKS4a 请求，解析域名并 DNS 解析
    /// 2. 建立到目标服务器的 TCP 连接
    /// 3. 发送成功响应
    /// 4. 桥接客户端和目标服务器的连接
    async fn handle_connect(
        &self,
        mut stream: TcpStream,
        request: Socks4Request,
    ) -> std::io::Result<()> {
        use std::net::ToSocketAddrs;

        // Resolve domain if SOCKS4a
        let target_addr = if request.is_socks4a {
            if let Some(ref domain) = request.domain {
                let addr_str = format!("{}:{}", domain, request.address.port);
                info!("SOCKS4a resolving domain: {}", addr_str);

                // Try to resolve the domain
                let addr = addr_str.to_socket_addrs();
                match addr {
                    Ok(mut addrs) => {
                        if let Some(socket_addr) = addrs.next() {
                            socket_addr
                        } else {
                            return self
                                .send_rejection(&mut stream, Socks4Reply::RequestRejected)
                                .await;
                        }
                    }
                    Err(_) => {
                        return self
                            .send_rejection(&mut stream, Socks4Reply::RequestRejected)
                            .await;
                    }
                }
            } else {
                return self
                    .send_rejection(&mut stream, Socks4Reply::RequestRejected)
                    .await;
            }
        } else {
            std::net::SocketAddr::V4(SocketAddrV4::new(request.address.ip, request.address.port))
        };

        debug!("SOCKS4a connecting to: {}", target_addr);

        // Connect to target
        let target_stream = match tokio::net::TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to {}: {}", target_addr, e);
                return self
                    .send_rejection(&mut stream, Socks4Reply::RequestRejected)
                    .await;
            }
        };

        // Send success response
        let response = [
            0x00,
            REP_REQUEST_GRANTED,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        stream.write_all(&response).await?;

        // Bridge connections
        self.bridge_connections(stream, target_stream).await
    }

    /// 处理 BIND 命令
    ///
    /// BIND 命令用于支持需要服务器主动连接客户端的协议（如 FTP）。
    ///
    /// # 处理流程
    /// 1. 在服务器上创建监听套接字
    /// 2. 发送第一次响应（包含绑定地址）
    /// 3. 等待远程服务器连接
    /// 4. 发送第二次响应（连接建立）
    /// 5. 桥接连接
    async fn handle_bind(
        &self,
        mut stream: TcpStream,
        _request: Socks4Request,
    ) -> std::io::Result<()> {
        // For BIND, we need to:
        // 1. Create a listening socket
        // 2. Send its address to client
        // 3. Wait for incoming connection
        // 4. Send success when connection arrives

        let bind_addr = format!("{}:{}", self.config.bind_addr, self.config.port);
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        let local_addr = listener.local_addr()?;

        debug!("SOCKS4 BIND listening on {}", local_addr);

        // Send first response (binding)
        // VN(1) + CD(1) + DSTPORT(2) + DSTIP(4) = 8 bytes
        let ip_octets = if let std::net::IpAddr::V4(ipv4) = local_addr.ip() {
            ipv4.octets()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS4 only supports IPv4",
            ));
        };
        let response = [
            0x00,
            REP_REQUEST_GRANTED,
            local_addr.port().to_be_bytes()[0],
            local_addr.port().to_be_bytes()[1],
            ip_octets[0],
            ip_octets[1],
            ip_octets[2],
            ip_octets[3],
        ];
        stream.write_all(&response).await?;

        // Wait for incoming connection
        match listener.accept().await {
            Ok((incoming, remote_addr)) => {
                debug!("SOCKS4 BIND received connection from {}", remote_addr);

                // Send second response (established)
                // For SOCKS4 BIND, the remote address must be IPv4
                let remote_ip = if let std::net::IpAddr::V4(ipv4) = remote_addr.ip() {
                    ipv4.octets()
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SOCKS4 only supports IPv4",
                    ));
                };
                let response2 = [
                    0x00,
                    REP_REQUEST_GRANTED,
                    remote_addr.port().to_be_bytes()[0],
                    remote_addr.port().to_be_bytes()[1],
                    remote_ip[0],
                    remote_ip[1],
                    remote_ip[2],
                    remote_ip[3],
                ];
                stream.write_all(&response2).await?;

                // Bridge connections
                self.bridge_connections(stream, incoming).await
            }
            Err(e) => {
                error!("SOCKS4 BIND accept failed: {}", e);
                self.send_rejection(&mut stream, Socks4Reply::RequestRejected)
                    .await
            }
        }
    }

    /// 桥接两个连接（双向数据转发）
    ///
    /// 同时在两个 TCP 连接之间双向转发数据。
    ///
    /// # 参数
    /// - `client`: 客户端连接
    /// - `target`: 目标服务器连接
    async fn bridge_connections(
        &self,
        client: TcpStream,
        target: TcpStream,
    ) -> std::io::Result<()> {
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut rr, mut rw) = tokio::io::split(target);

        let client_to_target = tokio::io::copy(&mut cr, &mut rw);
        let target_to_client = tokio::io::copy(&mut rr, &mut cw);

        tokio::try_join!(client_to_target, target_to_client)?;
        Ok(())
    }

    /// 发送拒绝响应
    ///
    /// # 参数
    /// - `stream`: 客户端连接
    /// - `reply`: 拒绝原因
    async fn send_rejection(
        &self,
        stream: &mut TcpStream,
        reply: Socks4Reply,
    ) -> std::io::Result<()> {
        let response = [0x00, reply.to_u8(), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        stream.write_all(&response).await
    }
}
