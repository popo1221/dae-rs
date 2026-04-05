//! Shadowsocks 配置类型模块
//!
//! 包含服务器和客户端配置结构，用于配置 Shadowsocks 代理的各种参数。
//!
//! # 配置结构
//!
//! - [`SsServerConfig`]: Shadowsocks 服务器端配置，包含服务器地址、端口、加密方法和密码
//! - [`SsClientConfig`]: Shadowsocks 客户端配置，包含监听地址、服务器配置和超时设置

use std::net::SocketAddr;
use std::time::Duration;

use super::protocol::SsCipherType;

/// Shadowsocks 服务器端配置
///
/// 包含连接到 Shadowsocks 服务器所需的所有配置信息。
/// 服务器地址可以是 IP 地址或域名，端口为服务器监听端口。
///
/// # 示例
///
/// ```ignore
/// let config = SsServerConfig {
///     addr: "example.com".to_string(),
///     port: 8388,
///     method: SsCipherType::Chacha20IetfPoly1305,
///     password: "your-password".to_string(),
///     ota: false,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SsServerConfig {
    /// 服务器地址，支持 IP 地址或域名
    ///
    /// 例如：`"127.0.0.1"` 或 `"example.com"`
    pub addr: String,

    /// 服务器监听端口
    ///
    /// 标准 Shadowsocks 端口范围通常是 1024-65535
    pub port: u16,

    /// 加密方法（**仅支持 AEAD 加密算法**）
    ///
    /// 支持的 AEAD 加密算法：
    /// - `SsCipherType::Chacha20IetfPoly1305` (推荐，安全系数最高)
    /// - `SsCipherType::Aes256Gcm` (AES-256-GCM)
    /// - `SsCipherType::Aes128Gcm` (AES-128-GCM)
    ///
    /// ⚠️ **不支持流式加密算法**：rc4-md5、aes-ctr、aes-cfb 等流加密暂不支持。
    /// 相关讨论见 GitHub Issue #78。
    pub method: SsCipherType,

    /// 密码/密钥
    ///
    /// Shadowsocks 服务器配置的密码，用于派生加密密钥
    pub password: String,

    /// 是否启用一次一密（One-Time Auth, OTA）
    ///
    /// OTA 是一种额外的安全增强机制，但 AEAD 模式默认已具备足够的安全性。
    /// 目前 AEAD 模式下此选项通常设为 `false`。
    #[allow(dead_code)]
    pub ota: bool,
}

impl Default for SsServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 8388,
            method: SsCipherType::Chacha20IetfPoly1305,
            password: String::new(),
            ota: false,
        }
    }
}

/// Shadowsocks 客户端配置
///
/// 包含 ss-local（本地代理）所需的完整配置，包括监听地址、远程服务器信息和超时设置。
///
/// # 使用场景
///
/// 此配置用于在本地启动一个 Shadowsocks 客户端代理，监听本地端口，
/// 接收需要代理的连接并转发到远程 Shadowsocks 服务器。
///
/// # 超时设置
///
/// - `tcp_timeout`: TCP 连接建立和数据传输的超时时间
/// - `udp_timeout`: UDP 会话保持时间，超过后 UDP 关联会被清除
#[derive(Debug, Clone)]
pub struct SsClientConfig {
    /// 本地监听地址，指定代理服务监听的 IP 和端口
    ///
    /// 例如：`SocketAddr::from(([127, 0, 0, 1], 1080))` 表示只监听本地回环地址的 1080 端口
    pub listen_addr: SocketAddr,

    /// 远程服务器配置
    ///
    /// 包含要连接的 Shadowsocks 服务器地址、端口和加密参数
    pub server: SsServerConfig,

    /// TCP 连接超时时间
    ///
    /// 从客户端到 Shadowsocks 服务器的 TCP 连接建立和数据传输超时。
    /// 超过此时间未完成连接或数据传输，将返回超时错误。
    pub tcp_timeout: Duration,

    /// UDP 会话超时时间
    ///
    /// UDP 代理会话在无活动情况下保持的时间。
    /// 超过此时间后，UDP 关联会被服务器清除。
    pub udp_timeout: Duration,
}

impl Default for SsClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: SsServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SsClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 8388);
        assert_eq!(config.server.method, SsCipherType::Chacha20IetfPoly1305);
    }

    #[test]
    fn test_ss_client_config_default() {
        let config = SsClientConfig::default();
        assert_eq!(config.server.port, 8388);
    }

    #[test]
    fn test_ss_client_config_clone() {
        let config = SsClientConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.server.method, config.server.method);
    }
}
