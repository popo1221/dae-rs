//! SOCKS5 处理器和服务器类型定义模块
//!
//! 包含 SOCKS5 连接处理器和服务器的配置和处理逻辑。

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use super::auth::CombinedAuthHandler;
use super::commands::CommandHandler;
use super::handshake::Handshake;
use dae_relay::RelayStats;

/// SOCKS5 连接处理器配置
///
/// 包含 SOCKS5 处理器运行所需的配置参数。
#[derive(Clone)]
pub struct Socks5HandlerConfig {
    /// 认证处理器
    ///
    /// 负责处理客户端认证，支持 NO_AUTH 或用户名/密码认证。
    pub auth_handler: Arc<dyn super::auth::AuthHandler>,

    /// TCP 连接超时时间（秒）
    ///
    /// TCP 连接建立和数据传输的超时时间。
    pub tcp_timeout_secs: u64,
}

impl std::fmt::Debug for Socks5HandlerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5HandlerConfig")
            .field("auth_handler", &"dyn AuthHandler")
            .field("tcp_timeout_secs", &self.tcp_timeout_secs)
            .finish()
    }
}

impl Default for Socks5HandlerConfig {
    fn default() -> Self {
        Self {
            auth_handler: Arc::new(CombinedAuthHandler::new()),
            tcp_timeout_secs: 60,
        }
    }
}

/// SOCKS5 连接处理器
///
/// 负责处理单个 SOCKS5 客户端连接请求。
///
/// # SOCKS5 处理流程
///
/// 1. **问候阶段**：接收客户端问候，选择认证方法
/// 2. **认证阶段**（可选）：如果选择了需要认证的方法，进行认证
/// 3. **请求阶段**：接收并处理客户端请求（CONNECT/BIND/UDP_ASSOCIATE）
pub struct Socks5Handler {
    config: Socks5HandlerConfig,
}

impl Socks5Handler {
    /// 创建新的 SOCKS5 处理器
    ///
    /// # 参数
    /// - `config`: 处理器配置
    pub fn new(config: Socks5HandlerConfig) -> Self {
        Self { config }
    }

    /// 使用无认证配置创建处理器
    ///
    /// 适用于允许任何人连接的 SOCKS5 服务器。
    pub fn new_no_auth() -> Self {
        Self {
            config: Socks5HandlerConfig::default(),
        }
    }

    /// 使用用户名/密码认证创建处理器
    ///
    /// # 参数
    /// - `users`: 用户名和密码对列表
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let handler = Socks5Handler::new_with_auth(vec![
    ///     ("user1".to_string(), "pass1".to_string()),
    ///     ("user2".to_string(), "pass2".to_string()),
    /// ]);
    /// ```
    pub fn new_with_auth(users: Vec<(String, String)>) -> Self {
        Self {
            config: Socks5HandlerConfig {
                auth_handler: Arc::new(CombinedAuthHandler::with_username_password(users)),
                tcp_timeout_secs: 60,
            },
        }
    }

    /// 处理 SOCKS5 连接
    ///
    /// 处理一个完整的 SOCKS5 客户端连接。
    ///
    /// # 参数
    /// - `self: Arc<Self>`: 处理器实例（需要在 Arc 中以支持跨任务共享）
    /// - `client`: 客户端 TCP 流
    ///
    /// # 处理流程
    ///
    /// 1. **问候阶段**：调用 Handshake 处理客户端问候和认证方法协商
    /// 2. **认证阶段**（可选）：如果选择了 USERNAME_PASSWORD 认证，执行认证流程
    /// 3. **请求阶段**：调用 CommandHandler 处理请求
    ///
    /// # 返回值
    /// 返回 `Ok(Some(RelayStats))` 如果有字节统计，`Ok(None)` 对于不支持统计的命令。
    pub async fn handle(
        self: Arc<Self>,
        mut client: TcpStream,
    ) -> std::io::Result<Option<RelayStats>> {
        // Phase 1: Greeting and authentication method selection
        let handshake = Handshake::new(self.config.auth_handler.clone());
        let auth_method = handshake.handle_greeting(&mut client).await?;
        debug!("Selected auth method: {}", auth_method);

        // Phase 2: Authentication (if required)
        if auth_method == super::consts::USERNAME_PASSWORD {
            handshake.handle_authentication(&mut client).await?;
        } else if auth_method == super::consts::NO_AUTH {
            // No authentication needed
        } else if auth_method == super::consts::NO_ACCEPTABLE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "no acceptable authentication method",
            ));
        }

        // Phase 3: Request processing
        let cmd_handler = CommandHandler::new(self.config.tcp_timeout_secs);
        cmd_handler.handle_request(client).await
    }
}

/// SOCKS5 服务器
///
/// 监听并接受 SOCKS5 客户端连接请求。
pub struct Socks5Server {
    /// 处理器实例
    handler: Arc<Socks5Handler>,
    /// TCP 监听器
    listener: TcpListener,
    /// 服务器监听地址
    listen_addr: SocketAddr,
}

impl Socks5Server {
    /// 创建新的 SOCKS5 服务器
    ///
    /// # 参数
    /// - `addr`: 服务器监听地址
    ///
    /// # 返回值
    /// - `Ok(Socks5Server)`: 服务器实例
    /// - `Err`: 监听失败（如端口被占用）
    ///
    /// # 注意
    ///
    /// 此方法使用无认证配置。如需认证配置，使用 `with_handler`。
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(Socks5Handler::new_no_auth()),
            listener,
            listen_addr: addr,
        })
    }

    /// 使用自定义处理器创建服务器
    ///
    /// # 参数
    /// - `addr`: 服务器监听地址
    /// - `handler`: 自定义 SOCKS5 处理器
    pub async fn with_handler(addr: SocketAddr, handler: Socks5Handler) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(handler),
            listener,
            listen_addr: addr,
        })
    }

    /// 启动 SOCKS5 服务器
    ///
    /// 开始接受并处理客户端连接。此方法是阻塞的，会一直运行直到发生错误。
    ///
    /// # 参数
    /// - `self: Arc<Self>`: 服务器实例（需要在 Arc 中以支持跨任务共享）
    ///
    /// # 工作方式
    ///
    /// 1. 进入无限循环，持续接受新连接
    /// 2. 每当有新连接时，克隆处理器并启动新的异步任务处理该连接
    /// 3. 如果接受连接失败，记录错误并继续接受下一个连接
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("SOCKS5 server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("SOCKS5 connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("SOCKS5 accept error: {}", e);
                }
            }
        }
    }
}
