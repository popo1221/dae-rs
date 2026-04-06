//! VMess 协议类型模块
//!
//! 本模块包含 VMess 协议的常量和枚举类型。

/// VMess 协议版本号（旧版本）
///
/// 旧版 VMess 协议使用版本号 0x01。
#[allow(dead_code)]
pub const VMESS_VERSION: u8 = 0x01;

/// VMess AEAD 协议版本标识符（VMess-AEAD-2022）
///
/// 用于 VMess-AEAD-2022 协议的密钥派生。
/// 在 HMAC-SHA256 中作为盐值使用。
#[allow(dead_code)]
pub const VMESS_AEAD_VERSION: &[u8] = b"VMessAEAD";

/// VMess 地址类型
///
/// 标识目标地址的编码格式。
///
/// # 变体说明
/// - `Ipv4`: IPv4 地址（atyp = 0x01）
/// - `Domain`: 域名（atyp = 0x02）
/// - `Ipv6`: IPv6 地址（atyp = 0x03）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessAddressType {
    /// IPv4 地址（atyp = 0x01）
    Ipv4 = 0x01,
    /// 域名地址（atyp = 0x02）
    Domain = 0x02,
    /// IPv6 地址（atyp = 0x03）
    Ipv6 = 0x03,
}

/// VMess 安全类型
///
/// 定义 VMess 协议的加密方式。
///
/// # 变体说明（按安全性排序）
/// - `None`: 不加密（已废弃）
/// - `Aes128Cfb`: AES-128-CFB（已废弃，不推荐）
/// - `Aes128Gcm`: AES-128-GCM（推荐）
/// - `ChaCha20Poly1305`: ChaCha20-Poly1305（推荐）
/// - `Aes128GcmAead`: AES-128-GCM with AEAD（VMess-AEAD-2022，推荐）
/// - `ChaCha20Poly1305Aead`: ChaCha20-Poly1305 with AEAD（VMess-AEAD-2022，推荐）
///
/// # 默认值
/// 默认使用 `Aes128GcmAead`（VMess-AEAD-2022）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmessSecurity {
    /// AES-128-CFB（已废弃）
    #[deprecated(note = "CFB mode has known weaknesses, use AEAD modes instead")]
    Aes128Cfb = 0x01,
    /// AES-128-GCM（推荐用于兼容）
    Aes128Gcm = 0x02,
    /// ChaCha20-Poly1305（推荐用于移动设备）
    ChaCha20Poly1305 = 0x03,
    /// 不加密（已废弃）
    None = 0x04,
    /// AES-128-GCM with AEAD（VMess-AEAD-2022，推荐）
    #[default]
    Aes128GcmAead = 0x11,
    /// ChaCha20-Poly1305 with AEAD（VMess-AEAD-2022，推荐）
    ChaCha20Poly1305Aead = 0x12,
}

impl std::fmt::Display for VmessSecurity {
    /// 格式化安全类型为字符串
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(deprecated)]
        match self {
            VmessSecurity::Aes128Cfb => write!(f, "aes-128-cfb"),
            VmessSecurity::Aes128Gcm => write!(f, "aes-128-gcm"),
            VmessSecurity::ChaCha20Poly1305 => write!(f, "chacha20-poly1305"),
            VmessSecurity::None => write!(f, "none"),
            VmessSecurity::Aes128GcmAead => write!(f, "aes-128-gcm-aead"),
            VmessSecurity::ChaCha20Poly1305Aead => write!(f, "chacha20-poly1305-aead"),
        }
    }
}

#[allow(clippy::should_implement_trait)]
impl VmessSecurity {
    /// 从字符串解析安全类型
    ///
    /// # 参数
    /// - `s`: 安全类型字符串（不区分大小写）
    ///
    /// # 支持的字符串
    /// - `"aes-128-cfb"`, `"aes128cfb"`
    /// - `"aes-128-gcm"`, `"aes128gcm"`
    /// - `"chacha20-poly1305"`, `"chacha20poly1305"`
    /// - `"none"`, `"auto"`
    /// - `"aes-128-gcm-aead"`, `"aes128gcmaead"`
    /// - `"chacha20-poly1305-aead"`, `"chacha20poly1305aead"`
    ///
    /// # 返回
    /// - `Some(VmessSecurity)`: 解析成功
    /// - `None`: 不支持的安全类型
    pub fn from_str(s: &str) -> Option<Self> {
        #[allow(deprecated)]
        match s.to_lowercase().as_str() {
            "aes-128-cfb" | "aes128cfb" => Some(VmessSecurity::Aes128Cfb),
            "aes-128-gcm" | "aes128gcm" => Some(VmessSecurity::Aes128Gcm),
            "chacha20-poly1305" | "chacha20poly1305" => Some(VmessSecurity::ChaCha20Poly1305),
            "none" | "auto" => Some(VmessSecurity::None),
            "aes-128-gcm-aead" | "aes128gcmaead" => Some(VmessSecurity::Aes128GcmAead),
            "chacha20-poly1305-aead" | "chacha20poly1305aead" => {
                Some(VmessSecurity::ChaCha20Poly1305Aead)
            }
            _ => None,
        }
    }
}

/// VMess 命令类型
///
/// 定义客户端请求的操作类型。
///
/// # 变体说明
/// - `Tcp`: TCP 代理连接
/// - `Udp`: UDP 数据包（多路复用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCommand {
    /// TCP 连接（command = 0x01）
    Tcp = 0x01,
    /// UDP 数据包（command = 0x02）
    Udp = 0x02,
}

/// VMess 服务器配置
///
/// 定义连接到的远程 VMess 服务器的配置信息。
///
/// # 字段说明
/// - `addr`: 服务器地址，IP 或域名（默认: "127.0.0.1"）
/// - `port`: 服务器端口（默认: 10086）
/// - `user_id`: 用户 ID（UUID），用于身份认证
/// - `security`: 加密类型（默认: Aes128GcmAead）
/// - `enable_aead`: 是否启用 AEAD（VMess-AEAD-2022，默认: true）
///
/// # user_id 说明
/// user_id 是 VMess 的用户标识符，通常为标准 UUID 格式。
/// 例如: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
///
/// # AEAD 说明
/// VMess-AEAD-2022 使用 AES-256-GCM 进行头部加密，
/// 提供更好的安全性。`enable_aead: true` 时使用新版协议。
#[derive(Debug, Clone)]
pub struct VmessServerConfig {
    /// 服务器地址（默认: "127.0.0.1"）
    pub addr: String,
    /// 服务器端口（默认: 10086）
    pub port: u16,
    /// 用户 ID（UUID）
    pub user_id: String,
    /// 加密类型（默认: Aes128GcmAead）
    pub security: VmessSecurity,
    /// 是否启用 AEAD（VMess-AEAD-2022）（默认: true）
    pub enable_aead: bool,
}

impl Default for VmessServerConfig {
    /// 创建默认配置
    ///
    /// 默认连接到 127.0.0.1:10086，启用 AEAD 加密。
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 10086,
            user_id: String::new(),
            security: VmessSecurity::Aes128GcmAead,
            enable_aead: true,
        }
    }
}
