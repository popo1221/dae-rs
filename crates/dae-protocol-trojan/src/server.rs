//! Trojan 服务器实现模块
//!
//! 本模块包含 `TrojanServer`，负责监听 Trojan 连接并分发给处理器。
//!
//! # 功能说明
//! - 在指定地址监听 TCP 连接
//! - 为每个连接创建异步任务处理
//! - 支持多后端配置和负载均衡
//!
//! # 使用方式
//! 服务器创建后调用 `start()` 方法开始监听。
//! `start()` 方法会阻塞当前任务直到服务器关闭。

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, error, info};

use super::config::{TrojanClientConfig, TrojanServerConfig};
use super::handler::TrojanHandler;

/// Trojan 服务器
///
/// 负责监听 Trojan 客户端连接，并将每个连接分发给 TrojanHandler 处理。
///
/// # 字段说明
/// - `handler`: Trojan 处理器实例，用于处理每个连接
/// - `listener`: TCP 监听器，用于接受新连接
/// - `listen_addr`: 服务器监听地址
///
/// # 使用示例
/// ```ignore
/// let config = TrojanClientConfig::default();
/// let server = TrojanServer::with_config(config).await.unwrap();
/// server.start().await;
/// ```
pub struct TrojanServer {
    /// Trojan 处理器实例
    handler: Arc<TrojanHandler>,
    /// TCP 监听器
    listener: TcpListener,
    /// 服务器监听地址
    listen_addr: SocketAddr,
}

impl TrojanServer {
    /// 创建新的 Trojan 服务器
    ///
    /// 使用默认配置创建一个 Trojan 服务器，监听在指定地址。
    ///
    /// # 参数
    /// - `addr`: 监听地址，如 `127.0.0.1:1080`
    ///
    /// # 返回
    /// - `Ok(Self)`: 服务器创建成功
    /// - `Err(std::io::Error)`: 地址绑定失败
    ///
    /// # 注意
    /// 此方法使用默认处理器配置，连接到 127.0.0.1:443。
    /// 如需自定义配置，请使用 `with_config` 或 `with_backends`。
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(TrojanHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// 使用自定义配置创建 Trojan 服务器
    ///
    /// # 参数
    /// - `config`: Trojan 客户端配置
    ///
    /// # 返回
    /// - `Ok(Self)`: 服务器创建成功
    /// - `Err(std::io::Error)`: 地址绑定失败
    ///
    /// # 配置说明
    /// 配置中的 `listen_addr` 用于绑定监听地址，
    /// `server` 配置用于连接上游 Trojan 服务器。
    pub async fn with_config(config: TrojanClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(TrojanHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// 创建支持多后端的 Trojan 服务器
    ///
    /// # 参数
    /// - `config`: Trojan 客户端配置
    /// - `backends`: 额外的服务器后端列表
    ///
    /// # 返回
    /// - `Ok(Self)`: 服务器创建成功
    /// - `Err(std::io::Error)`: 地址绑定失败
    ///
    /// # 行为
    /// 服务器会使用轮询策略在多个后端之间分配连接。
    #[allow(dead_code)]
    pub async fn with_backends(
        config: TrojanClientConfig,
        backends: Vec<TrojanServerConfig>,
    ) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(TrojanHandler::with_backends(config, backends));
        let listener = TcpListener::bind(listen_addr).await?;
        info!(
            "Trojan server created with {} backends",
            handler.backend_count()
        );
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// 启动 Trojan 服务器
    ///
    /// 开始监听并接受连接，为每个连接启动一个异步任务处理。
    ///
    /// # 返回
    /// - `Ok(())`: 永不返回（服务器持续运行）
    /// - `Err(std::io::Error)`: 接受连接时发生错误
    ///
    /// # 行为
    /// - 在日志中记录监听地址
    /// - 无限循环接受新连接
    /// - 为每个连接克隆处理器并生成异步任务
    /// - 处理错误只记录不断开（容错设计）
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("Trojan server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("Trojan connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Trojan accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// 测试服务器创建（绑定到端口 0）
    #[tokio::test]
    async fn test_server_creation() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // 绑定到端口 0 会分配一个可用端口
        let result = TrojanServer::new(addr).await;
        // 由于是默认配置且没有真实后端，连接处理会失败，但创建应该成功
        assert!(result.is_ok());
    }
}
