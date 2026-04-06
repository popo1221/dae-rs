//! Trojan 配置类型模块
//!
//! 本模块包含 Trojan 协议所需的所有配置类型，包括：
//! - `TrojanTlsConfig`: TLS 传输层配置
//! - `TrojanServerConfig`: 远程 Trojan 服务器配置
//! - `TrojanClientConfig`: 本地客户端配置（包含服务器配置）
//!
//! # 配置层次
//! `TrojanClientConfig` 包含 `TrojanServerConfig`，后者又包含 `TrojanTlsConfig`。
//! 这种嵌套结构使得配置既可以在客户端级别统一设置，也可以在服务器级别单独覆盖。

use dae_protocol_core::HandlerConfig;
use std::net::SocketAddr;
use std::time::Duration;

/// Trojan TLS 传输层配置
///
/// 控制 Trojan 协议的 TLS 加密行为。对于传出连接（连接远程服务器），
/// 设置 `insecure: true` 可跳过 TLS 证书验证（仅用于测试）；
/// 对于传入连接（作为服务器），需要提供 `cert_file` 和 `key_file`。
///
/// # 字段说明
/// - `enabled`: 是否启用 TLS，默认为 `true`。设为 `false` 会使用明文传输（不推荐）
/// - `version`: TLS 版本，可选 "1.2" 或 "1.3"，默认为 "1.3"
/// - `alpn`: 应用层协议协商列表，默认为 ["h2", "http/1.1"]
/// - `server_name`: SNI（Server Name Indication）字段，用于 TLS 握手时标识目标服务器
/// - `cert_file`: TLS 证书文件路径（用于接收传入连接时）
/// - `key_file`: TLS 私钥文件路径（用于接收传入连接时）
/// - `insecure`: 是否跳过 TLS 证书验证，默认为 `false`（生产环境应保持为 `false`）
///
/// # 示例
/// ```ignore
/// let tls_config = TrojanTlsConfig {
///     enabled: true,
///     version: "1.3".to_string(),
///     alpn: vec!["h2".to_string()],
///     server_name: Some("example.com".to_string()),
///     insecure: false,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct TrojanTlsConfig {
    /// 是否启用 TLS（默认: true）
    pub enabled: bool,
    /// TLS 版本，可选 "1.2" 或 "1.3"（默认: "1.3"）
    pub version: String,
    /// ALPN 协议列表，如 ["h2", "http/1.1"]（默认: ["h2", "http/1.1"]）
    pub alpn: Vec<String>,
    /// SNI 服务器名称，用于 TLS 握手（默认: None）
    pub server_name: Option<String>,
    /// TLS 证书文件路径，用于接收传入连接（默认: None）
    pub cert_file: Option<String>,
    /// TLS 私钥文件路径，用于接收传入连接（默认: None）
    pub key_file: Option<String>,
    /// 是否跳过 TLS 证书验证（默认: false，生产环境勿设为 true）
    pub insecure: bool,
}

impl Default for TrojanTlsConfig {
    /// 创建默认的 TLS 配置
    ///
    /// 默认配置：启用 TLS 1.3，使用 h2 和 http/1.1 ALPN，
    /// 不跳过证书验证，不设置服务器名称。
    fn default() -> Self {
        Self {
            enabled: true,
            version: "1.3".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            server_name: None,
            cert_file: None,
            key_file: None,
            insecure: false,
        }
    }
}

/// Trojan 远程服务器配置
///
/// 定义连接到的远程 Trojan 服务器的地址和认证信息。
///
/// # 字段说明
/// - `addr`: 服务器地址，可以是 IP 地址或域名（默认: "127.0.0.1"）
/// - `port`: 服务器端口（默认: 443）
/// - `password`: 认证密码，Trojan 协议中使用 56 字节的密码字符串（默认: 空字符串）
/// - `tls`: TLS 传输层配置
///
/// # 注意事项
/// - password 字段应为完整的密码字符串，协议会将其编码为 56 字节
/// - 建议使用强密码以防止暴力破解
/// - 服务器端口通常为 443（HTTPS 标准端口）
#[derive(Debug, Clone)]
pub struct TrojanServerConfig {
    /// 服务器地址，IP 或域名（默认: "127.0.0.1"）
    pub addr: String,
    /// 服务器端口号（默认: 443）
    pub port: u16,
    /// 认证密码，协议要求 56 字节（默认: 空字符串）
    pub password: String,
    /// TLS 传输层配置
    pub tls: TrojanTlsConfig,
}

impl Default for TrojanServerConfig {
    /// 创建默认的服务器配置
    ///
    /// 默认连接到本地 443 端口，密码为空，启用默认 TLS 配置。
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 443,
            password: String::new(),
            tls: TrojanTlsConfig::default(),
        }
    }
}

/// Trojan 客户端配置
///
/// 定义本地 Trojan 客户端的监听地址和上游服务器配置。
///
/// # 字段说明
/// - `listen_addr`: 本地监听地址，客户端在此地址接收代理请求（默认: 127.0.0.1:1080）
/// - `server`: 上游 Trojan 服务器配置
/// - `tcp_timeout`: TCP 连接超时时间（默认: 60 秒）
/// - `udp_timeout`: UDP 会话超时时间（默认: 30 秒）
///
/// # 使用场景
/// - 作为透明代理时，`listen_addr` 应设置为局域网 IP 以便其他设备连接
/// - 作为本地代理时，可使用 127.0.0.1:1080 或 127.0.0.1:7890 等常用端口
#[derive(Debug, Clone)]
pub struct TrojanClientConfig {
    /// 本地监听地址（默认: 127.0.0.1:1080）
    pub listen_addr: SocketAddr,
    /// 上游 Trojan 服务器配置
    pub server: TrojanServerConfig,
    /// TCP 连接超时时间（默认: 60 秒）
    pub tcp_timeout: Duration,
    /// UDP 会话超时时间（默认: 30 秒）
    pub udp_timeout: Duration,
}

impl Default for TrojanClientConfig {
    /// 创建默认的客户端配置
    ///
    /// 默认监听 127.0.0.1:1080，连接本地 Trojan 服务器 443 端口，
    /// TCP 超时 60 秒，UDP 超时 30 秒。
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: TrojanServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

/// 为 TrojanClientConfig 实现 HandlerConfig trait
///
/// 使得 TrojanClientConfig 可以作为协议处理器的配置类型使用，
/// 实现跨协议的统一接口。
impl HandlerConfig for TrojanClientConfig {}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试默认 TLS 配置的值
    #[test]
    fn test_default_tls_config() {
        let config = TrojanTlsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.version, "1.3");
        assert_eq!(config.alpn.len(), 2);
        assert!(!config.insecure);
    }

    /// 测试默认服务器配置的初始值
    #[test]
    fn test_default_server_config() {
        let config = TrojanServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 443);
        assert!(config.password.is_empty());
    }

    /// 测试默认客户端配置的初始值
    #[test]
    fn test_default_client_config() {
        let config = TrojanClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
        assert_eq!(config.server.port, 443);
        assert_eq!(config.tcp_timeout, Duration::from_secs(60));
        assert_eq!(config.udp_timeout, Duration::from_secs(30));
    }
}
