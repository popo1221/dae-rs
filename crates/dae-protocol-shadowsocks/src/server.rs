//! Shadowsocks 服务器实现模块
//!
//! 实现了服务器端功能，监听并处理来自 Shadowsocks 客户端的连接请求。
//!
//! # 工作流程
//!
//! 1. 服务器绑定并监听指定地址
//! 2. 接收客户端连接
//! 3. 为每个连接启动独立的处理任务
//! 4. 使用 [`ShadowsocksHandler`] 处理实际的数据转发
//!
//! # 线程安全
//!
//! [`ShadowsocksServer`] 使用 `Arc` 共享处理器，可以在多个连接间复用

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, error, info};

use super::config::SsClientConfig;
use super::handler::ShadowsocksHandler;

/// Shadowsocks 服务器，负责监听并接受客户端连接
///
/// 服务器创建 TCP 监听器，接收连接后使用 `ShadowsocksHandler` 处理每个连接。
/// 使用 `Arc<Self>` 可以在多个异步任务间安全共享服务器实例。
///
/// # 创建方式
///
/// - [`Self::new`]: 使用默认配置创建服务器
/// - [`Self::with_config`]: 使用自定义配置创建服务器
///
/// # 启动服务器
///
/// ```ignore
/// let server = Arc::new(ShadowsocksServer::with_config(config).await?);
/// server.start().await?;
/// ```
pub struct ShadowsocksServer {
    /// 处理器实例，用于处理每个连接
    handler: Arc<ShadowsocksHandler>,
    /// TCP 监听器，用于接受新连接
    listener: TcpListener,
    /// 服务器监听的地址
    listen_addr: SocketAddr,
}

impl ShadowsocksServer {
    /// 创建 Shadowsocks 服务器（使用默认配置）
    ///
    /// # 参数
    ///
    /// - `addr`: 服务器监听的 Socket 地址
    ///
    /// # 返回值
    ///
    /// - 成功：返回 `ShadowsocksServer` 实例
    /// - 失败：返回 `std::io::Error` 错误
    ///
    /// # 注意
    ///
    /// 此方法使用 [`SsClientConfig::default`] 创建默认配置，
    /// 服务器地址为 `127.0.0.1:8388`，加密方法为 `chacha20-ietf-poly1305`。
    /// 如需自定义配置，请使用 [`with_config`](Self::with_config)。
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(ShadowsocksHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// 使用自定义配置创建 Shadowsocks 服务器
    ///
    /// # 参数
    ///
    /// - `config`: 完整的客户端配置，包括监听地址、服务器信息和超时设置
    ///
    /// # 返回值
    ///
    /// - 成功：返回配置好的 `ShadowsocksServer` 实例
    /// - 失败：返回 `std::io::Error`（如地址已被占用或权限不足）
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let config = SsClientConfig {
    ///     listen_addr: "127.0.0.1:1080".parse().unwrap(),
    ///     server: SsServerConfig {
    ///         addr: "example.com".to_string(),
    ///         port: 8388,
    ///         method: SsCipherType::Chacha20IetfPoly1305,
    ///         password: "password".to_string(),
    ///         ota: false,
    ///     },
    ///     tcp_timeout: Duration::from_secs(60),
    ///     udp_timeout: Duration::from_secs(30),
    /// };
    /// let server = ShadowsocksServer::with_config(config).await?;
    /// ```
    pub async fn with_config(config: SsClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(ShadowsocksHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// 启动 Shadowsocks 服务器
    ///
    /// 开始接受并处理客户端连接。此方法是阻塞的，会一直运行直到发生错误。
    ///
    /// # 参数
    ///
    /// - `self: Arc<Self>`: 服务器必须包装在 `Arc` 中，以便安全地在多个任务间共享
    ///
    /// # 工作方式
    ///
    /// 1. 进入无限循环，持续接受新连接
    /// 2. 每当有新连接时，克隆处理器并启动新的异步任务处理该连接
    /// 3. 如果接受连接失败，记录错误并继续接受下一个连接
    ///
    /// # 错误处理
    ///
    /// - 接受连接错误会被记录但不会导致服务器停止
    /// - 处理连接时的错误会被记录为调试信息
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("Shadowsocks server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("Shadowsocks connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Shadowsocks accept error: {}", e);
                }
            }
        }
    }
}
