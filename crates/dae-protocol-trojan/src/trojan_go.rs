//! Trojan-Go 协议扩展模块
//!
//! 本模块实现了 Trojan-Go 协议的扩展功能，包括 WebSocket 传输支持。
//!
//! # Trojan-Go 简介
//! Trojan-Go 是 Trojan 协议的扩展实现，增加了以下功能：
//! - **WebSocket 传输**: 通过 WebSocket 封装 Trojan 流量，可用于绕过网络审查
//! - **TLS 混淆**: TLS 伪装，使流量看起来像正常的 HTTPS WebSocket 流量
//! - **多路复用**: 在单一连接上复用多个 TCP 流
//!
//! # 协议规范
//! 详细协议规范请参考: <https://github.com/p4gefau1t/trojan-go>
//!
//! # 支持的传输模式
//! - `WebSocket`: 明文 WebSocket（ws://）
//! - `WebSocketTLS`: TLS 加密的 WebSocket（wss://）

use std::time::Duration;

use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tracing::{debug, error, info, warn};

use futures_util::{SinkExt, StreamExt};

/// Trojan-Go WebSocket 传输模式
///
/// 定义 Trojan-Go 使用的 WebSocket 传输类型。
///
/// # 变体说明
/// - `WebSocket`: 明文 WebSocket，使用 `ws://` 协议
/// - `WebSocketTLS`: TLS 加密的 WebSocket，使用 `wss://` 协议
///
/// # 选择建议
/// - 在严格网络环境下使用 `WebSocketTLS`（如被审查的网络）
/// - 在普通网络环境下可使用 `WebSocket` 以减少开销
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanGoMode {
    /// 明文 WebSocket（ws://）
    /// 适用于网络条件较好的环境
    WebSocket,
    /// TLS 加密 WebSocket（wss://）
    /// 适用于需要 TLS 混淆的场景
    WebSocketTLS,
}

#[allow(clippy::should_implement_trait)]
impl TrojanGoMode {
    /// 从字符串解析 Trojan-Go 模式
    ///
    /// # 参数
    /// - `s`: 模式字符串，不区分大小写
    ///
    /// # 支持的字符串
    /// - `"websocket"` 或 `"ws"` -> `WebSocket`
    /// - `"wss"` 或 `"websocket+tls"` -> `WebSocketTLS`
    ///
    /// # 返回
    /// - `Some(TrojanGoMode)`: 解析成功
    /// - `None`: 不支持的模式字符串
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "websocket" | "ws" => Some(TrojanGoMode::WebSocket),
            "wss" | "websocket+tls" => Some(TrojanGoMode::WebSocketTLS),
            _ => None,
        }
    }
}

/// Trojan-Go WebSocket 配置
///
/// 配置 Trojan-Go WebSocket 连接的参数。
///
/// # 字段说明
/// - `mode`: WebSocket 传输模式（明文或 TLS）
/// - `path`: WebSocket 路径，如 `/trojan` 或 `/`（默认: `/`）
/// - `host`: HTTP Host 请求头，用于伪装（默认: 空字符串）
/// - `tls_sni`: TLS SNI 服务器名称，用于 TLS 握手（默认: None）
/// - `insecure`: 是否跳过 TLS 证书验证（默认: false）
/// - `timeout`: 连接超时时间（默认: 30 秒）
///
/// # 配置示例
/// ```ignore
/// let config = TrojanGoWsConfig::websocket_tls()
///     .with_path("/trojan")
///     .with_host("example.com")
///     .with_tls_sni("real-server.com");
/// ```
#[derive(Debug, Clone)]
pub struct TrojanGoWsConfig {
    /// WebSocket 传输模式（默认: WebSocket）
    pub mode: TrojanGoMode,
    /// WebSocket 路径（默认: "/"）
    pub path: String,
    /// HTTP Host 请求头（默认: 空字符串）
    pub host: String,
    /// TLS SNI 服务器名称（默认: None）
    pub tls_sni: Option<String>,
    /// 是否跳过 TLS 证书验证（默认: false）
    pub insecure: bool,
    /// 连接超时时间（默认: 30 秒）
    pub timeout: Duration,
}

impl Default for TrojanGoWsConfig {
    /// 创建默认配置
    ///
    /// 默认使用明文 WebSocket，路径为 `/`。
    fn default() -> Self {
        Self {
            mode: TrojanGoMode::WebSocket,
            path: "/".to_string(),
            host: String::new(),
            tls_sni: None,
            insecure: false,
            timeout: Duration::from_secs(30),
        }
    }
}

impl TrojanGoWsConfig {
    /// 使用指定模式创建配置
    ///
    /// # 参数
    /// - `mode`: WebSocket 传输模式
    fn new(mode: TrojanGoMode) -> Self {
        Self {
            mode,
            ..Default::default()
        }
    }

    /// 创建明文 WebSocket 配置
    ///
    /// # 示例
    /// ```ignore
    /// let config = TrojanGoWsConfig::websocket();
    /// ```
    pub fn websocket() -> Self {
        Self::new(TrojanGoMode::WebSocket)
    }

    /// 创建 TLS WebSocket 配置
    ///
    /// # 示例
    /// ```ignore
    /// let config = TrojanGoWsConfig::websocket_tls();
    /// ```
    pub fn websocket_tls() -> Self {
        Self::new(TrojanGoMode::WebSocketTLS)
    }

    /// 设置 WebSocket 路径
    ///
    /// # 参数
    /// - `path`: WebSocket 路径，如 `/trojan`
    ///
    /// # 返回
    /// 修改后的配置副本（链式调用支持）
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    /// 设置 HTTP Host 请求头
    ///
    /// # 参数
    /// - `host`: Host 头值，如 `example.com`
    ///
    /// # 返回
    /// 修改后的配置副本
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    /// 设置 TLS SNI 服务器名称
    ///
    /// # 参数
    /// - `sni`: TLS SNI 值，如 `real-server.com`
    ///
    /// # 返回
    /// 修改后的配置副本
    ///
    /// # 说明
    /// SNI 用于 TLS 握手时的服务器名称指示，
    /// 可以设置为与 WebSocket 域名不同的真实服务器地址。
    pub fn with_tls_sni(mut self, sni: &str) -> Self {
        self.tls_sni = Some(sni.to_string());
        self
    }
}

/// Trojan-Go WebSocket 处理器
///
/// 负责建立和管理 Trojan-Go WebSocket 连接。
///
/// # 功能
/// - 构建 WebSocket 连接 URL
/// - 建立 WebSocket 连接
/// - 提供数据收发接口
pub struct TrojanGoWsHandler {
    /// WebSocket 配置
    config: TrojanGoWsConfig,
}

impl TrojanGoWsHandler {
    /// 使用配置创建新的 WebSocket 处理器
    ///
    /// # 参数
    /// - `config`: WebSocket 配置
    pub fn new(config: TrojanGoWsConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建处理器
    pub fn new_default() -> Self {
        Self {
            config: TrojanGoWsConfig::default(),
        }
    }

    /// 连接到 Trojan-Go 服务器
    ///
    /// # 参数
    /// - `server_addr`: 服务器地址，格式为 `host:port`
    ///
    /// # 返回
    /// - `Ok(TrojanGoWsStream)`: 连接成功
    /// - `Err(std::io::Error)`: 连接失败
    ///
    /// # 行为
    /// 1. 根据配置构建 WebSocket URL
    /// 2. 建立 WebSocket 连接
    /// 3. 返回 WebSocket 流用于数据传输
    pub async fn connect(&self, server_addr: &str) -> std::io::Result<TrojanGoWsStream> {
        let url = self.build_url(server_addr)?;
        debug!("Connecting to {} with Trojan-go WebSocket", url);

        // 建立 WebSocket 连接
        let (ws_stream, response) = connect_async(&url).await.map_err(|e| {
            std::io::Error::other(format!("Trojan-go WebSocket connect error: {e}"))
        })?;

        // 记录响应状态
        let status = response.status().as_u16();
        debug!("Trojan-go WebSocket connected with status: {}", status);

        info!("Trojan-go WebSocket connected to {}", server_addr);

        Ok(TrojanGoWsStream::new(ws_stream))
    }

    /// 构建 WebSocket 连接 URL
    ///
    /// # 参数
    /// - `server_addr`: 服务器地址，格式为 `host:port`
    ///
    /// # 返回
    /// - `Ok(String)`: 完整的 WebSocket URL
    /// - `Err(std::io::Error)`: 地址格式错误
    ///
    /// # URL 格式
    /// - WebSocket: `ws://{host}:{port}{path}`
    /// - WebSocketTLS: `wss://{sni}:{port}{path}`
    ///
    /// # 字段优先级
    /// - host: 优先使用配置的 host，否则使用 server_addr 中的主机名
    /// - port: 优先使用 server_addr 中的端口，否则根据模式使用默认端口
    /// - path: 使用配置的 path
    fn build_url(&self, server_addr: &str) -> std::io::Result<String> {
        let host = if self.config.host.is_empty() {
            server_addr.split(':').next().unwrap_or(server_addr)
        } else {
            &self.config.host
        };

        let port = server_addr
            .split(':')
            .nth(1)
            .unwrap_or(match self.config.mode {
                TrojanGoMode::WebSocket => "80",
                TrojanGoMode::WebSocketTLS => "443",
            });

        let path = if self.config.path.is_empty() {
            "/"
        } else {
            &self.config.path
        };

        match self.config.mode {
            TrojanGoMode::WebSocket => Ok(format!("ws://{host}:{port}{path}")),
            TrojanGoMode::WebSocketTLS => {
                let sni = self.config.tls_sni.as_deref().unwrap_or(host);
                Ok(format!("wss://{sni}:{port}{path}"))
            }
        }
    }
}

/// Trojan-Go WebSocket 流
///
/// 封装 `tokio_tungstenite` 的 WebSocket 流，
/// 提供 Trojan-Go 协议的数据收发接口。
///
/// # 类型参数
/// - 内部使用 `MaybeTlsStream<TcpStream>`，支持 TCP 和 TLS TCP 流
pub struct TrojanGoWsStream {
    /// WebSocket 流，支持加密和非加密
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

impl TrojanGoWsStream {
    /// 创建新的 WebSocket 流
    ///
    /// # 参数
    /// - `ws`: 底层的 WebSocket 流
    pub fn new(
        ws: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Self {
        Self { ws }
    }

    /// 发送数据
    ///
    /// # 参数
    /// - `data`: 待发送的字节数据
    ///
    /// # 返回
    /// - `Ok(())`: 发送成功
    /// - `Err(std::io::Error)`: 发送失败
    ///
    /// # 协议说明
    /// Trojan-Go 使用二进制 WebSocket 消息（`Message::Binary`）传输数据。
    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        // Trojan-Go 使用二进制 WebSocket 消息
        self.ws
            .send(Message::Binary(data.to_vec()))
            .await
            .map_err(|e| std::io::Error::other(format!("send error: {e}")))?;
        Ok(())
    }

    /// 接收数据
    ///
    /// # 参数
    /// - `buffer`: 接收缓冲区
    ///
    /// # 返回
    /// - `Ok(usize)`: 接收到的字节数
    /// - `Err(std::io::Error)`: 接收失败
    ///
    /// # 行为
    /// - 循环等待直到收到有效的二进制或文本消息
    /// - 收到 Close 消息时返回 0（表示连接关闭）
    /// - 自动响应 Ping 消息（发送 Pong）
    /// - 忽略收到的 Pong 消息
    ///
    /// # 消息类型处理
    /// - `Binary`: 直接返回数据
    /// - `Text`: 转换为字节后返回
    /// - `Ping`: 自动响应 Pong
    /// - `Close`: 返回 0
    pub async fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(msg) = self.ws.next().await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        let len = std::cmp::min(data.len(), buffer.len());
                        buffer[..len].copy_from_slice(&data[..len]);
                        return Ok(len);
                    }
                    Ok(Message::Text(text)) => {
                        // Trojan-Go 可能发送文本（用于 WebSocket ping/pong）
                        let bytes = text.into_bytes();
                        let len = std::cmp::min(bytes.len(), buffer.len());
                        buffer[..len].copy_from_slice(&bytes[..len]);
                        return Ok(len);
                    }
                    Ok(Message::Close(_)) => {
                        return Ok(0);
                    }
                    Ok(Message::Ping(data)) => {
                        // 响应 Ping
                        if self.ws.send(Message::Pong(data)).await.is_err() {
                            warn!("Failed to send pong");
                        }
                    }
                    Ok(Message::Pong(_)) => {
                        // 忽略 Pong
                    }
                    Ok(Message::Frame(_)) => {
                        // 忽略 Frame
                    }
                    Err(e) => {
                        error!("Trojan-go WebSocket error: {}", e);
                        return Err(std::io::Error::other(format!("recv error: {e}")));
                    }
                }
            } else {
                return Err(std::io::Error::other("stream ended"));
            }
        }
    }

    /// 优雅关闭 WebSocket 连接
    ///
    /// # 返回
    /// - `Ok(())`: 关闭成功
    /// - `Err(std::io::Error)`: 关闭失败
    ///
    /// # 说明
    /// 此方法发送 Close 握手信号，而非直接断开连接。
    /// 等待远程端响应 Close 后，连接才会完全关闭。
    pub async fn close(&mut self) -> std::io::Result<()> {
        self.ws
            .close(None)
            .await
            .map_err(|e| std::io::Error::other(format!("close error: {e}")))?;
        Ok(())
    }

    /// 获取底层的 WebSocket 流
    ///
    /// # 返回
    /// 底层的 WebSocket 流所有权
    ///
    /// # 用途
    /// 允许调用者直接访问底层流进行高级操作。
    #[allow(dead_code)]
    pub fn into_inner(
        self,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        self.ws
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试模式字符串解析
    #[test]
    fn test_trojan_go_mode_from_str() {
        assert_eq!(
            TrojanGoMode::from_str("websocket"),
            Some(TrojanGoMode::WebSocket)
        );
        assert_eq!(
            TrojanGoMode::from_str("wss"),
            Some(TrojanGoMode::WebSocketTLS)
        );
        assert_eq!(TrojanGoMode::from_str("unknown"), None);
    }

    /// 测试 WebSocket 配置构建器
    #[test]
    fn test_trojan_go_ws_config_builder() {
        let config = TrojanGoWsConfig::websocket()
            .with_path("/trojan")
            .with_host("example.com")
            .with_tls_sni("sni.example.com");

        assert_eq!(config.mode, TrojanGoMode::WebSocket);
        assert_eq!(config.path, "/trojan");
        assert_eq!(config.host, "example.com");
        assert_eq!(config.tls_sni, Some("sni.example.com".to_string()));
    }

    /// 测试 TLS WebSocket 配置
    #[test]
    fn test_trojan_go_ws_config_tls() {
        let config = TrojanGoWsConfig::websocket_tls();
        assert_eq!(config.mode, TrojanGoMode::WebSocketTLS);
    }

    /// 测试默认配置
    #[test]
    fn test_default_config() {
        let config = TrojanGoWsConfig::default();
        assert_eq!(config.mode, TrojanGoMode::WebSocket);
        assert_eq!(config.path, "/");
    }
}
