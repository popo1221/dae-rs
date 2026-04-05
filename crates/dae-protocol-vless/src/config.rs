//! VLESS 配置类型模块
//!
//! 本模块包含 VLESS 协议所需的所有配置类型：
//! - `VlessServerConfig`: 远程服务器配置
//! - `VlessClientConfig`: 客户端配置
//! - `VlessTlsConfig`: TLS 传输层配置
//! - `VlessRealityConfig`: XTLS Reality 配置

use std::net::SocketAddr;
use std::time::Duration;

/// VLESS 服务器配置
///
/// 定义连接到的远程 VLESS 服务器的地址、认证和传输配置。
///
/// # 字段说明
/// - `addr`: 服务器地址，IP 或域名（默认: "127.0.0.1"）
/// - `port`: 服务器端口（默认: 443）
/// - `uuid`: 用户认证 UUID，128 位（16 字节）
/// - `tls`: TLS 传输层配置
/// - `reality`: XTLS Reality 配置（可选，用于 Reality Vision 模式）
///
/// # UUID 格式
/// UUID 必须是标准的 16 字节（128 位）标识符，
/// 通常表示为 36 个字符的字符串（包含连字符）。
/// 例如: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
///
/// # Reality 配置
/// 如果需要使用 XTLS Reality Vision 混淆流量，
/// 需要提供 `reality` 字段配置。
#[derive(Debug, Clone)]
pub struct VlessServerConfig {
    /// 服务器地址，IP 或域名（默认: "127.0.0.1"）
    pub addr: String,
    /// 服务器端口（默认: 443）
    pub port: u16,
    /// 用户认证 UUID（16 字节/128 位）
    pub uuid: String,
    /// TLS 传输层配置
    pub tls: VlessTlsConfig,
    /// XTLS Reality 配置（可选，用于 Reality Vision）
    pub reality: Option<VlessRealityConfig>,
}

impl Default for VlessServerConfig {
    /// 创建默认配置
    ///
    /// 默认连接到 127.0.0.1:443，UUID 为空字符串，
    /// 启用 TLS，不配置 Reality。
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 443,
            uuid: String::new(),
            tls: VlessTlsConfig::default(),
            reality: None,
        }
    }
}

/// VLESS Reality 配置（VLESS XTLS Vision）
///
/// XTLS Reality 是一种流量伪装技术，通过伪造 TLS 指纹，
/// 使流量看起来像访问真实存在的网站，从而对抗深度包检测（DPI）。
///
/// # 字段说明
/// - `private_key`: X25519 私钥（32 字节），用于生成共享密钥
/// - `public_key`: X25519 公钥（32 字节），服务器公钥
/// - `short_id`: 短 ID（8 字节），用于标识 Reality 节点，可为空
/// - `destination`: 目标服务器名（SNI），Reality 流量伪装成的目标
/// - `flow`: 流类型，通常为 "vision"（Reality Vision 模式）
///
/// # 工作原理
/// 1. 客户端使用私钥和服务器公钥计算共享密钥
/// 2. 构造特殊的 TLS ClientHello，伪装成访问 destination
/// 3. 服务器验证请求后，直接在 TLS 层转发（XTLS）
///
/// # 注意事项
/// - private_key 和 public_key 必须是有效的 X25519 密钥对
/// - destination 通常设置为热门网站的域名（如 Google、Cloudflare）
#[derive(Debug, Clone)]
pub struct VlessRealityConfig {
    /// X25519 私钥（32 字节）
    pub private_key: Vec<u8>,
    /// X25519 公钥（32 字节）
    pub public_key: Vec<u8>,
    /// 短 ID（最多 8 字节，可为空）
    pub short_id: Vec<u8>,
    /// 目标服务器名（SNI），用于伪装（必需）
    pub destination: String,
    /// 流类型（通常为 "vision"）
    pub flow: String,
}

impl VlessRealityConfig {
    /// 创建新的 Reality 配置
    ///
    /// # 参数
    /// - `private_key`: X25519 私钥（32 字节）
    /// - `public_key`: X25519 公钥（32 字节）
    /// - `short_id`: 短 ID（最多 8 字节）
    /// - `destination`: SNI 伪装目标
    ///
    /// # 返回
    /// 配置好的 VlessRealityConfig，flow 默认为 "vision"
    pub fn new(private_key: &[u8], public_key: &[u8], short_id: &[u8], destination: &str) -> Self {
        Self {
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            short_id: short_id.to_vec(),
            destination: destination.to_string(),
            flow: "vision".to_string(),
        }
    }
}

/// VLESS TLS 配置
///
/// 控制 VLESS 协议的 TLS 加密行为。
///
/// # 字段说明
/// - `enabled`: 是否启用 TLS（默认: true）
/// - `version`: TLS 版本（默认: "1.3"）
/// - `alpn`: ALPN 协议列表（默认: ["h2", "http/1.1"]）
/// - `server_name`: SNI 服务器名称（可选）
/// - `cert_file`: TLS 证书文件（用于服务器模式）
/// - `key_file`: TLS 私钥文件（用于服务器模式）
/// - `insecure`: 是否跳过证书验证（默认: false）
#[derive(Debug, Clone)]
pub struct VlessTlsConfig {
    /// 是否启用 TLS（默认: true）
    pub enabled: bool,
    /// TLS 版本（默认: "1.3"）
    pub version: String,
    /// ALPN 协议列表（默认: ["h2", "http/1.1"]）
    pub alpn: Vec<String>,
    /// SNI 服务器名称（默认: None）
    pub server_name: Option<String>,
    /// TLS 证书文件路径（默认: None）
    pub cert_file: Option<String>,
    /// TLS 私钥文件路径（默认: None）
    pub key_file: Option<String>,
    /// 是否跳过 TLS 证书验证（默认: false）
    pub insecure: bool,
}

impl Default for VlessTlsConfig {
    /// 创建默认 TLS 配置
    ///
    /// 默认启用 TLS 1.3，使用 h2 和 http/1.1 ALPN。
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

/// VLESS 客户端配置
///
/// 定义本地 VLESS 客户端的配置信息。
///
/// # 字段说明
/// - `listen_addr`: 本地监听地址（默认: 127.0.0.1:1080）
/// - `server`: 远程服务器配置
/// - `tcp_timeout`: TCP 连接超时（默认: 60 秒）
/// - `udp_timeout`: UDP 会话超时（默认: 30 秒）
#[derive(Debug, Clone)]
pub struct VlessClientConfig {
    /// 本地监听地址（默认: 127.0.0.1:1080）
    pub listen_addr: SocketAddr,
    /// 远程服务器配置
    pub server: VlessServerConfig,
    /// TCP 连接超时（默认: 60 秒）
    pub tcp_timeout: Duration,
    /// UDP 会话超时（默认: 30 秒）
    pub udp_timeout: Duration,
}

impl Default for VlessClientConfig {
    /// 创建默认客户端配置
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: VlessServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}
