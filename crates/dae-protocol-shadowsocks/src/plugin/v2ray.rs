//! Shadowsocks v2ray-plugin WebSocket 混淆插件
//!
//! 实现 v2ray-plugin 协议，用于 Shadowsocks 流量的 WebSocket 混淆传输。
//! v2ray-plugin 提供基于 WebSocket 的传输方式，支持可选的 TLS 加密。
//!
//! # 工作模式
//!
//! - WebSocket：纯 WebSocket 传输，无 TLS
//! - WebSocket+TLS (wss)：WebSocket over TLS，提供 TLS 加密
//!
//! # v2ray-plugin vs simple-obfs
//!
//! | 特性 | v2ray-plugin | simple-obfs |
//! |------|-------------|--------------|
//! | 传输协议 | WebSocket | TCP |
//! | TLS 支持 | 可选 | 可选 |
//! | 伪装程度 | 高（完整 WebSocket） | 中（仅 HTTP/TLS 头）|
//! | 性能开销 | 较高 | 较低 |
//!
//! 注意：这是一个简化实现，完整的 v2ray-plugin 支持需要处理 WebSocket 消息和 TLS 终止。

use std::time::Duration;

use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tracing::{debug, info};

use futures_util::{SinkExt, StreamExt};

/// v2ray-plugin WebSocket 模式
///
/// 定义 v2ray-plugin 支持的两种传输模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2rayMode {
    /// WebSocket 模式（无 TLS）
    WebSocket,
    /// WebSocket over TLS 模式
    WebSocketTLS,
}

#[allow(clippy::should_implement_trait)]
impl V2rayMode {
    /// 从字符串解析模式
    ///
    /// 支持的格式：
    /// - "websocket", "ws" -> WebSocket
    /// - "websocket+tls", "wss", "tls" -> WebSocketTLS
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "websocket" | "ws" => Some(V2rayMode::WebSocket),
            "websocket+tls" | "wss" | "tls" => Some(V2rayMode::WebSocketTLS),
            _ => None,
        }
    }
}

/// v2ray-plugin 配置
///
/// 包含 v2ray-plugin 的所有配置参数。
#[derive(Debug, Clone)]
pub struct V2rayConfig {
    /// 插件模式
    pub mode: V2rayMode,
    /// WebSocket 路径
    pub path: String,
    /// HTTP Host 头
    pub host: String,
    /// TLS 服务器名称（SNI）
    pub tls_server_name: Option<String>,
    /// 是否跳过 TLS 证书验证
    pub insecure: bool,
    /// 连接超时
    pub timeout: Duration,
}

impl V2rayConfig {
    /// 使用指定模式创建配置
    pub fn new(mode: V2rayMode) -> Self {
        Self {
            mode,
            path: "/".to_string(),
            host: String::new(),
            tls_server_name: None,
            insecure: false,
            timeout: Duration::from_secs(30),
        }
    }

    /// 创建 WebSocket 模式配置
    pub fn websocket() -> Self {
        Self::new(V2rayMode::WebSocket)
    }

    /// 创建 WebSocket+TLS 模式配置
    pub fn websocket_tls() -> Self {
        Self::new(V2rayMode::WebSocketTLS)
    }

    /// 设置 WebSocket 路径
    ///
    /// # 参数
    /// - `path`: WebSocket 路径，如 "/custom/path"
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    /// 设置 Host 头
    ///
    /// # 参数
    /// - `host`: HTTP Host 头值
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    /// 设置 TLS 服务器名称（SNI）
    ///
    /// # 参数
    /// - `sni`: TLS SNI 值
    pub fn with_tls_server_name(mut self, sni: &str) -> Self {
        self.tls_server_name = Some(sni.to_string());
        self
    }

    /// 设置跳过 TLS 证书验证
    ///
    /// ⚠️ 警告：这会降低安全性，仅在测试环境中使用。
    pub fn with_insecure(mut self) -> Self {
        self.insecure = true;
        self
    }
}

/// v2ray-plugin WebSocket 处理器
///
/// 负责使用 v2ray-plugin WebSocket 混淆连接到服务器。
pub struct V2rayPlugin {
    config: V2rayConfig,
}

impl V2rayPlugin {
    /// 创建 v2ray-plugin 处理器
    pub fn new(config: V2rayConfig) -> Self {
        Self { config }
    }

    /// 使用 v2ray-plugin WebSocket 混淆连接到服务器
    ///
    /// # 参数
    /// - `server_addr`: 服务器地址
    ///
    /// # 返回值
    /// - `Ok((WebSocketStream,))`: WebSocket 流
    /// - `Err`: 连接失败
    ///
    /// # 连接流程
    /// 1. 根据配置构建 WebSocket URL
    /// 2. 建立 WebSocket 连接
    /// 3. 返回 WebSocket 流供数据转发使用
    #[allow(dead_code)]
    pub async fn connect(
        &self,
        server_addr: &str,
    ) -> std::io::Result<(
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    )> {
        let url = self.build_url(server_addr);
        debug!("Connecting to {} with v2ray-plugin", url);

        // Connect WebSocket
        let (ws_stream, _response) = connect_async(&url)
            .await
            .map_err(|e| std::io::Error::other(format!("WebSocket connect error: {}", e)))?;

        info!("v2ray-plugin WebSocket connected to {}", server_addr);

        Ok((ws_stream,))
    }

    /// 构建 WebSocket URL
    ///
    /// 根据配置的模式（WebSocket 或 WebSocket+TLS）构建完整的 URL。
    fn build_url(&self, server_addr: &str) -> String {
        let host = if self.config.host.is_empty() {
            server_addr.split(':').next().unwrap_or(server_addr)
        } else {
            &self.config.host
        };

        match self.config.mode {
            V2rayMode::WebSocket => {
                format!(
                    "ws://{}:{}{}",
                    host,
                    server_addr.split(':').nth(1).unwrap_or("80"),
                    self.config.path
                )
            }
            V2rayMode::WebSocketTLS => {
                let sni = self.config.tls_server_name.as_deref().unwrap_or(host);
                let port = server_addr.split(':').nth(1).unwrap_or("443");
                format!("wss://{}:{}{}", sni, port, self.config.path)
            }
        }
    }
}

/// v2ray-plugin WebSocket 流处理器
///
/// 提供 WebSocket 消息的发送和接收接口。
pub struct V2rayStream {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

impl V2rayStream {
    /// 创建 WebSocket 流处理器
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
    /// - `data`: 要发送的字节数据
    ///
    /// # 返回值
    /// - `Ok(())`: 发送成功
    /// - `Err`: 发送失败
    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.ws
            .send(Message::Binary(data.to_vec()))
            .await
            .map_err(|e| std::io::Error::other(format!("send error: {}", e)))?;
        Ok(())
    }

    /// 接收数据
    ///
    /// 从 WebSocket 流中接收下一条消息。
    ///
    /// # 参数
    /// - `buffer`: 接收缓冲区
    ///
    /// # 返回值
    /// - `Ok(usize)`: 接收到的字节数
    /// - `Err`: 接收失败或流已关闭
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
                        let bytes = text.into_bytes();
                        let len = std::cmp::min(bytes.len(), buffer.len());
                        buffer[..len].copy_from_slice(&bytes[..len]);
                        return Ok(len);
                    }
                    Ok(Message::Close(_)) => return Ok(0),
                    Ok(Message::Ping(data)) => {
                        if self.ws.send(Message::Pong(data)).await.is_err() {
                            return Err(std::io::Error::other("pong failed"));
                        }
                    }
                    Ok(Message::Pong(_)) => {}
                    Ok(Message::Frame(_)) => {}
                    Err(e) => {
                        return Err(std::io::Error::other(format!("recv error: {}", e)));
                    }
                }
            } else {
                return Err(std::io::Error::other("stream ended"));
            }
        }
    }

    /// 关闭 WebSocket 连接
    #[allow(dead_code)]
    pub async fn close(&mut self) -> std::io::Result<()> {
        self.ws
            .close(None)
            .await
            .map_err(|e| std::io::Error::other(format!("close error: {}", e)))?;
        Ok(())
    }

    /// 获取内部的 WebSocket 流
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

    #[test]
    fn test_v2ray_mode_from_str() {
        assert_eq!(V2rayMode::from_str("websocket"), Some(V2rayMode::WebSocket));
        assert_eq!(V2rayMode::from_str("wss"), Some(V2rayMode::WebSocketTLS));
        assert_eq!(V2rayMode::from_str("tls"), Some(V2rayMode::WebSocketTLS));
        assert_eq!(V2rayMode::from_str("unknown"), None);
    }

    #[test]
    fn test_v2ray_config_builder() {
        let config = V2rayConfig::websocket()
            .with_path("/custom/path")
            .with_host("example.com")
            .with_tls_server_name("sni.example.com")
            .with_insecure();

        assert_eq!(config.mode, V2rayMode::WebSocket);
        assert_eq!(config.path, "/custom/path");
        assert_eq!(config.host, "example.com");
        assert_eq!(config.tls_server_name, Some("sni.example.com".to_string()));
        assert!(config.insecure);
    }

    #[test]
    fn test_v2ray_config_tls() {
        let config = V2rayConfig::websocket_tls();
        assert_eq!(config.mode, V2rayMode::WebSocketTLS);
    }
}
