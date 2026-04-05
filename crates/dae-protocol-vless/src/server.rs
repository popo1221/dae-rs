//! VLESS 服务器实现模块
//!
//! 本模块实现 VLESS 服务器，负责监听连接并分发给处理器。

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::config::VlessClientConfig;
use crate::handler::VlessHandler;

/// VLESS 服务器
///
/// 负责监听 VLESS 客户端连接，并分发给处理器。
///
/// # 字段说明
/// - `handler`: VLESS 处理器实例
/// - `listener`: TCP 监听器
/// - `udp_socket`: UDP 监听 socket（可选）
/// - `listen_addr`: 监听地址
pub struct VlessServer {
    /// VLESS 处理器实例
    handler: Arc<VlessHandler>,
    /// TCP 监听器
    listener: TcpListener,
    /// UDP socket（用于 UDP 转发）
    udp_socket: Arc<Mutex<Option<UdpSocket>>>,
    /// 监听地址
    listen_addr: SocketAddr,
}

impl VlessServer {
    /// 创建新的 VLESS 服务器
    ///
    /// # 参数
    /// - `addr`: 监听地址
    ///
    /// # 返回
    /// - `Ok(Self)`: 创建成功
    /// - `Err(std::io::Error)`: 绑定失败
    ///
    /// # 注意
    /// 使用默认处理器配置。
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let udp_socket = Arc::new(Mutex::new(UdpSocket::bind(addr).await.ok()));
        Ok(Self {
            handler: Arc::new(VlessHandler::new_default()),
            listener,
            udp_socket,
            listen_addr: addr,
        })
    }

    /// 使用自定义配置创建服务器
    ///
    /// # 参数
    /// - `config`: VLESS 客户端配置
    ///
    /// # 返回
    /// - `Ok(Self)`: 创建成功
    /// - `Err(std::io::Error)`: 绑定失败
    ///
    /// # 说明
    /// 配置中的 `listen_addr` 用于绑定监听地址。
    pub async fn with_config(config: VlessClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(VlessHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        let udp_socket = Arc::new(Mutex::new(UdpSocket::bind(listen_addr).await.ok()));
        Ok(Self {
            handler,
            listener,
            udp_socket,
            listen_addr,
        })
    }

    /// 启动 VLESS 服务器
    ///
    /// # 返回
    /// - `Ok(())`: 永不返回（服务器持续运行）
    /// - `Err(std::io::Error)`: 接受连接时发生错误
    ///
    /// # 行为
    /// 1. 启动 UDP 监听（如果可用）
    /// 2. 无限循环接受 TCP 连接
    /// 3. 为每个连接启动异步处理任务
    #[allow(dead_code)]
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("VLESS server listening on {}", self.listen_addr);

        // 启动 UDP 监听
        let maybe_socket = {
            let mut guard = self.udp_socket.lock().await;
            guard.take()
        };

        if let Some(socket) = maybe_socket {
            let handler = self.handler.clone();
            tokio::spawn(async move {
                let _ = handler.handle_udp(Arc::new(socket)).await;
            });
            info!("VLESS UDP server listening on {}", self.listen_addr);
        }

        // 接受 TCP 连接
        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_vless(client).await {
                            debug!("VLESS connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("VLESS accept error: {}", e);
                }
            }
        }
    }
}
