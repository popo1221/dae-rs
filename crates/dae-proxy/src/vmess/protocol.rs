//! VMess protocol types
//!
//! Constants and enums for VMess protocol implementation.

/// VMess protocol version
#[allow(dead_code)]
pub const VMESS_VERSION: u8 = 0x01;

/// VMess AEAD protocol version (2022)
#[allow(dead_code)]
pub const VMESS_AEAD_VERSION: &[u8] = b"VMessAEAD";

/// VMess address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessAddressType {
    /// IPv4
    Ipv4 = 0x01,
    /// Domain
    Domain = 0x02,
    /// IPv6
    Ipv6 = 0x03,
}

/// VMess security type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmessSecurity {
    /// AES-128-CFB
    Aes128Cfb = 0x01,
    /// AES-128-GCM (recommended)
    Aes128Gcm = 0x02,
    /// ChaCha20-Poly1305 (recommended)
    ChaCha20Poly1305 = 0x03,
    /// None
    None = 0x04,
    /// AES-128-GCM with AEAD (VMess-AEAD-2022)
    #[default]
    Aes128GcmAead = 0x11,
    /// ChaCha20-Poly1305 with AEAD (VMess-AEAD-2022)
    ChaCha20Poly1305Aead = 0x12,
}

impl std::fmt::Display for VmessSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    /// Parse security type from string
    pub fn from_str(s: &str) -> Option<Self> {
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

/// VMess command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCommand {
    /// TCP connection
    Tcp = 0x01,
    /// UDP (mux)
    Udp = 0x02,
}

/// VMess server configuration
#[derive(Debug, Clone)]
pub struct VmessServerConfig {
    /// Server address (IP or domain)
    pub addr: String,
    /// Server port
    pub port: u16,
    /// User ID (UUID)
    pub user_id: String,
    /// Security type
    pub security: VmessSecurity,
    /// Enable AEAD (VMess-AEAD-2022)
    pub enable_aead: bool,
}

impl Default for VmessServerConfig {
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
