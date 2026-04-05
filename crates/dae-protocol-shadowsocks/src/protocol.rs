//! Shadowsocks 协议类型模块
//!
//! 包含 AEAD 加密算法类型和目标地址解析功能。
//!
//! # 地址类型（ATYP）
//!
//! Shadowsocks 协议使用 ATYP（Address Type）字段标识目标地址类型：
//! - `0x01`: IPv4 地址（4字节）
//! - `0x03`: 域名（1字节长度 + 域名字节序列）
//! - `0x04`: IPv6 地址（16字节）
//!
//! # AEAD 加密
//!
//! AEAD（Authenticated Encryption with Associated Data）模式提供加密和认证：
//! - 加密 payload
//! - 生成认证标签防止篡改
//! 支持的算法：chacha20-ietf-poly1305, aes-256-gcm, aes-128-gcm

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Shadowsocks AEAD 加密算法类型
///
/// AEAD（带关联数据的认证加密）模式是当前推荐的加密方式，
/// 同时提供数据机密性和完整性保护。
///
/// # 支持的算法
///
/// | 算法 | 密钥长度 | 推荐程度 |
/// |------|----------|----------|
/// | `Chacha20IetfPoly1305` | 256 bits | ⭐⭐⭐ 推荐 |
/// | `Aes256Gcm` | 256 bits | ⭐⭐ |
/// | `Aes128Gcm` | 128 bits | ⭐ |
///
/// # 不支持的算法
///
/// 流式加密算法（如 rc4-md5、aes-ctr、aes-cfb）暂不支持，
/// 因为存在已知的安全问题。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SsCipherType {
    /// chacha20-ietf-poly1305
    #[default]
    Chacha20IetfPoly1305,
    /// aes-256-gcm
    Aes256Gcm,
    /// aes-128-gcm
    Aes128Gcm,
}

impl std::fmt::Display for SsCipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsCipherType::Chacha20IetfPoly1305 => write!(f, "chacha20-ietf-poly1305"),
            SsCipherType::Aes256Gcm => write!(f, "aes-256-gcm"),
            SsCipherType::Aes128Gcm => write!(f, "aes-128-gcm"),
        }
    }
}

#[allow(clippy::should_implement_trait)]
impl SsCipherType {
    /// Parse cipher type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chacha20-ietf-poly1305" | "chacha20poly1305" => {
                Some(SsCipherType::Chacha20IetfPoly1305)
            }
            "aes-256-gcm" | "aes256gcm" => Some(SsCipherType::Aes256Gcm),
            "aes-128-gcm" | "aes128gcm" => Some(SsCipherType::Aes128Gcm),
            _ => None,
        }
    }
}

/// Shadowsocks 目标地址
///
/// 表示 Shadowsocks 协议中的目标地址，可以是 IPv4、IPv6 或域名。
///
/// # ATYP 映射
///
/// - `Ip(IpAddr::V4(...))` → ATYP = 0x01
/// - `Ip(IpAddr::V6(...))` → ATYP = 0x04
/// - `Domain(name, port)` → ATYP = 0x03
///
/// # 使用场景
///
/// - 解析 AEAD payload 中的目标地址
/// - 序列化地址用于协议传输
/// - 构建调试和日志信息
#[derive(Debug, Clone)]
pub enum TargetAddress {
    /// IPv4 或 IPv6 地址
    ///
    /// 使用 `std::net::IpAddr` 类型，可同时表示 IPv4 和 IPv6。
    Ip(IpAddr),

    /// 域名和端口
    ///
    /// 用于 SOCKS 风格的目标指定，域名需要 DNS 解析。
    /// 元组包含：(域名, 端口)
    Domain(String, u16),
}

impl std::fmt::Display for TargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddress::Ip(ip) => write!(f, "{ip}"),
            TargetAddress::Domain(domain, _) => write!(f, "{domain}"),
        }
    }
}

impl TargetAddress {
    /// 从 Shadowsocks AEAD payload 中解析目标地址
    ///
    /// # 参数
    ///
    /// - `payload`: AEAD 解密后的 payload 字节数组
    ///
    /// # 返回值
    ///
    /// - `Some((TargetAddress, port))`: 成功解析返回地址和端口
    /// - `None`: payload 格式无效或长度不足
    ///
    /// # Payload 格式
    ///
    /// AEAD 解密后的 payload 格式：
    /// - ATYP (1 byte): 地址类型
    /// - ADDRESS (变长): 目标地址
    /// - PORT (2 bytes): 目标端口
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let payload = [0x01, 192, 168, 1, 1, 0x1F, 0x90]; // 192.168.1.1:8080
    /// if let Some((addr, port)) = TargetAddress::parse_from_aead(&payload) {
    ///     println!("Target: {}:{}", addr, port);
    /// }
    /// ```
    pub fn parse_from_aead(payload: &[u8]) -> Option<(Self, u16)> {
        if payload.is_empty() {
            return None;
        }

        let atyp = payload[0];
        match atyp {
            0x01 => {
                // IPv4: 1 byte type + 4 bytes IP + 2 bytes port
                if payload.len() < 7 {
                    return None;
                }
                let ip = IpAddr::V4(Ipv4Addr::new(
                    payload[1], payload[2], payload[3], payload[4],
                ));
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                Some((TargetAddress::Ip(ip), port))
            }
            0x03 => {
                // Domain: 1 byte type + 1 byte length + domain + 2 bytes port
                if payload.len() < 4 {
                    return None;
                }
                let domain_len = payload[1] as usize;
                if payload.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[2..2 + domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([payload[2 + domain_len], payload[3 + domain_len]]);
                Some((TargetAddress::Domain(domain, port), port))
            }
            0x04 => {
                // IPv6: 1 byte type + 16 bytes IP + 2 bytes port
                if payload.len() < 18 {
                    return None;
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([payload[1], payload[2]]),
                    u16::from_be_bytes([payload[3], payload[4]]),
                    u16::from_be_bytes([payload[5], payload[6]]),
                    u16::from_be_bytes([payload[7], payload[8]]),
                    u16::from_be_bytes([payload[9], payload[10]]),
                    u16::from_be_bytes([payload[11], payload[12]]),
                    u16::from_be_bytes([payload[13], payload[14]]),
                    u16::from_be_bytes([payload[15], payload[16]]),
                ));
                let port = u16::from_be_bytes([payload[17], payload[18]]);
                Some((TargetAddress::Ip(ip), port))
            }
            _ => None,
        }
    }

    /// 将地址序列化为 Shadowsocks 协议格式的字节
    ///
    /// # 返回值
    ///
    /// 返回包含 ATYP 和地址字节的向量，不包含端口。
    ///
    /// # 序列化格式
    ///
    /// - IPv4: `[0x01][4字节IP]`
    /// - IPv6: `[0x04][16字节IP]`
    /// - Domain: `[0x03][长度:u8][域名字节]`
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TargetAddress::Ip(IpAddr::V4(ip)) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                bytes.extend_from_slice(&ip.octets());
                bytes
            }
            TargetAddress::Ip(IpAddr::V6(ip)) => {
                let mut bytes = vec![0x04]; // ATYP IPv6
                for &segment in &ip.segments() {
                    bytes.extend_from_slice(&segment.to_be_bytes());
                }
                bytes
            }
            TargetAddress::Domain(domain, _) => {
                let mut bytes = vec![0x03, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }

    /// 获取地址的可读字符串表示
    ///
    /// # 返回值
    ///
    /// - IPv4/IPv6: 返回 IP 地址字符串
    /// - Domain: 返回域名（不包含端口）
    pub fn address_string(&self) -> String {
        match self {
            TargetAddress::Ip(ip) => ip.to_string(),
            TargetAddress::Domain(domain, _) => domain.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_type_from_str() {
        assert_eq!(
            SsCipherType::from_str("chacha20-ietf-poly1305"),
            Some(SsCipherType::Chacha20IetfPoly1305)
        );
        assert_eq!(
            SsCipherType::from_str("aes-256-gcm"),
            Some(SsCipherType::Aes256Gcm)
        );
        assert_eq!(
            SsCipherType::from_str("aes-128-gcm"),
            Some(SsCipherType::Aes128Gcm)
        );
        assert_eq!(SsCipherType::from_str("invalid"), None);
    }

    #[test]
    fn test_cipher_type_display() {
        assert_eq!(
            SsCipherType::Chacha20IetfPoly1305.to_string(),
            "chacha20-ietf-poly1305"
        );
        assert_eq!(SsCipherType::Aes256Gcm.to_string(), "aes-256-gcm");
        assert_eq!(SsCipherType::Aes128Gcm.to_string(), "aes-128-gcm");
    }

    #[test]
    fn test_cipher_type_all_variants() {
        // Only these ciphers are supported
        assert!(SsCipherType::from_str("aes-128-gcm").is_some());
        assert!(SsCipherType::from_str("aes-256-gcm").is_some());
        assert!(SsCipherType::from_str("chacha20-ietf-poly1305").is_some());
        // These are NOT supported
        assert!(SsCipherType::from_str("aes-128-cfb").is_none());
        assert!(SsCipherType::from_str("aes-256-cfb").is_none());
        assert!(SsCipherType::from_str("invalid").is_none());
    }

    #[test]
    fn test_cipher_type_to_string() {
        assert_eq!(SsCipherType::Aes128Gcm.to_string(), "aes-128-gcm");
        assert_eq!(SsCipherType::Aes256Gcm.to_string(), "aes-256-gcm");
        assert_eq!(
            SsCipherType::Chacha20IetfPoly1305.to_string(),
            "chacha20-ietf-poly1305"
        );
    }

    #[test]
    fn test_target_address_parse_ipv4() {
        let payload = [
            0x01, 192, 168, 1, 1, 0x1F, 0x90, // 192.168.1.1:8080
        ];
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TargetAddress::Ip(IpAddr::V4(ip)) => {
                assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
            }
            _ => panic!("Expected IPv4"),
        }
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_target_address_parse_domain() {
        // Domain format: ATYP(1) + LEN(1) + DOMAIN(LEN) + PORT(2)
        // example.com = 11 bytes
        let payload = [
            0x03, // ATYP_DOMAIN
            0x0b, // domain length = 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // "example.com"
            0x00, 0x50, // port = 80
        ];
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TargetAddress::Domain(domain, _) => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected Domain"),
        }
        assert_eq!(port, 80);
    }

    #[test]
    fn test_target_address_to_bytes_ipv4() {
        let addr = TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 192, 168, 1, 1]);
    }

    #[test]
    fn test_target_address_ipv6() {
        let payload = [
            0x04, // ATYP_IPV6
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x50, // [2001:db8::1]:80
        ];
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_some());
    }

    #[test]
    fn test_target_address_invalid() {
        let payload = [0xFF, 0x00]; // Invalid type
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_target_address_truncated() {
        let payload = [0x01, 192]; // Too short for IPv4
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_target_address_domain_length_mismatch() {
        // Domain length says 11 but only 3 bytes follow
        let payload = [0x03, 0x0b, 0x65, 0x78, 0x61]; // "exa" only
        let result = TargetAddress::parse_from_aead(&payload);
        assert!(result.is_none());
    }

    #[test]
    fn test_target_address_debug() {
        let addr = TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("Ip"));
    }
}
