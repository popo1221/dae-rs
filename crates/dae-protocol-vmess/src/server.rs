//! VMess 服务器实现模块
//!
//! 本模块实现 VMess 服务器，负责监听连接并分发给处理器。

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, error, info};

use super::config::VmessClientConfig;
use super::handler::VmessHandler;

/// VMess 服务器
///
/// 负责监听 VMess 客户端连接，并分发给处理器。
///
/// # 字段说明
/// - `handler`: VMess 处理器实例
/// - `listener`: TCP 监听器
/// - `listen_addr`: 监听地址
pub struct VmessServer {
    /// VMess 处理器实例
    handler: Arc<VmessHandler>,
    /// TCP 监听器
    listener: TcpListener,
    /// 监听地址
    listen_addr: SocketAddr,
}

impl VmessServer {
    /// 创建新的 VMess 服务器
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
        Ok(Self {
            handler: Arc::new(VmessHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// 使用自定义配置创建服务器
    ///
    /// # 参数
    /// - `config`: VMess 客户端配置
    ///
    /// # 返回
    /// - `Ok(Self)`: 创建成功
    /// - `Err(std::io::Error)`: 绑定失败
    pub async fn with_config(config: VmessClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(VmessHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// 启动 VMess 服务器
    ///
    /// # 返回
    /// - `Ok(())`: 永不返回（服务器持续运行）
    /// - `Err(std::io::Error)`: 接受连接时发生错误
    ///
    /// # 行为
    /// 1. 在日志中记录监听地址
    /// 2. 无限循环接受新连接
    /// 3. 为每个连接克隆处理器并生成异步任务
    /// 4. 处理错误只记录不断开（容错设计）
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("VMess server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("VMess connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("VMess accept error: {}", e);
                }
            }
        }
    }
}
