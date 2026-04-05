//! Trojan 协议数据类型和解析模块
//!
//! 本模块包含 Trojan 协议层面的所有数据类型，包括：
//! - 命令类型（TCP 代理 / UDP 关联）
//! - 地址类型（IPv4 / 域名 / IPv6）
//! - 目标地址的序列化和反序列化
//!
//! # Trojan 协议格式
//! Trojan 协议在 TLS 握手后发送请求头：
//! ```
//! [password (56 bytes)][\r\n]
//! [command (1 byte)][address type (1 byte)][address][port (2 bytes)][\r\n]
//! [payload ...]
//! ```
//! UDP 关联请求的 payload 字段为空。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Trojan 协议命令类型
///
/// 定义客户端请求的操作类型。
///
/// # 变体说明
/// - `Proxy`: TCP 代理连接，请求与目标服务器建立 TCP 连接并转发数据
/// - `UdpAssociate`: UDP 关联请求，用于 UDP 数据包的转发
///
/// # 协议值
/// - `Proxy` = 0x01
/// - `UdpAssociate` = 0x02
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    /// TCP 连接请求（command = 0x01）
    /// 客户端请求代理服务器与目标地址建立 TCP 连接
    Proxy = 0x01,
    /// UDP 关联请求（command = 0x02）
    /// 用于在 Trojan 协议中封装 UDP 数据包
    UdpAssociate = 0x02,
}

/// Trojan 地址类型
///
/// 标识目标地址的编码格式。
///
/// # 变体说明
/// - `Ipv4`: IPv4 地址，4 字节（atyp = 0x01）
/// - `Domain`: 域名，1 字节长度 + 可变长度域名（atyp = 0x02）
/// - `Ipv6`: IPv6 地址，16 字节（atyp = 0x03）
///
/// # 注意事项
/// - 域名长度字段为 1 字节，最大 255 字节
/// - IPv4 和 IPv6 地址均使用网络字节序（大端序）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanAddressType {
    /// IPv4 地址（atyp = 0x01）
    /// 格式：[0x01][4 字节 IP][2 字节端口]
    Ipv4 = 0x01,
    /// 域名地址（atyp = 0x02）
    /// 格式：[0x02][1 字节长度][域名][2 字节端口]
    Domain = 0x02,
    /// IPv6 地址（atyp = 0x03）
    /// 格式：[0x03][16 字节 IP][2 字节端口]
    Ipv6 = 0x03,
}

/// Trojan 目标地址
///
/// 表示代理请求的目标地址，可以是 IPv4、域名或 IPv6。
///
/// # 变体说明
/// - `Ipv4(IpAddr)`: IPv4 地址
/// - `Domain(String, u16)`: 域名和端口（元组形式存储）
/// - `Ipv6(IpAddr)`: IPv6 地址
///
/// # Display 实现
/// 实现了 `std::fmt::Display`，格式如下：
/// - IPv4/IPv6: 直接输出 IP 地址
/// - Domain: 输出域名（不含端口）
#[derive(Debug, Clone)]
pub enum TrojanTargetAddress {
    /// IPv4 目标地址
    /// - 参数: `IpAddr` - IPv4 地址
    Ipv4(IpAddr),
    /// 域名目标地址
    /// - 参数: `String` - 域名
    /// - 参数: `u16` - 端口号（此处端口会被忽略，以解析后的端口为准）
    Domain(String, u16),
    /// IPv6 目标地址
    Ipv6(IpAddr),
}

impl std::fmt::Display for TrojanTargetAddress {
    /// 格式化目标地址为字符串
    ///
    /// # 格式
    /// - IPv4: `192.168.1.1`
    /// - Domain: `example.com`（不含端口）
    /// - IPv6: `::1` 或完整的 IPv6 格式
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrojanTargetAddress::Ipv4(ip) => write!(f, "{ip}"),
            TrojanTargetAddress::Domain(domain, _) => write!(f, "{domain}"),
            TrojanTargetAddress::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

impl TrojanTargetAddress {
    /// 从 Trojan 协议字节流解析目标地址
    ///
    /// # 参数
    /// - `payload`: 包含地址类型和地址数据的字节数组
    ///
    /// # 返回值
    /// - `Some((Self, u16))`: 解析成功，返回地址和端口
    /// - `None`: 解析失败（数据不完整或格式错误）
    ///
    /// # 支持的地址格式
    /// - **IPv4** (atyp=0x01): 1 字节类型 + 4 字节 IP + 2 字节端口 = 7 字节
    /// - **域名** (atyp=0x02): 1 字节类型 + 1 字节长度 + 域名 + 2 字节端口
    /// - **IPv6** (atyp=0x03): 1 字节类型 + 16 字节 IP + 2 字节端口 = 19 字节
    ///
    /// # 错误处理
    /// - 字节数不足时返回 `None`
    /// - 域名解析失败（非 UTF-8 编码）时返回 `None`
    pub fn parse_from_bytes(payload: &[u8]) -> Option<(Self, u16)> {
        if payload.is_empty() {
            return None;
        }

        let atyp = payload[0];
        match atyp {
            0x01 => {
                // IPv4: 1 byte type + 4 bytes IP + 2 bytes port
                // 总共需要 7 字节
                if payload.len() < 7 {
                    return None;
                }
                let ip = IpAddr::V4(Ipv4Addr::new(
                    payload[1], payload[2], payload[3], payload[4],
                ));
                let port = u16::from_be_bytes([payload[5], payload[6]]);
                Some((TrojanTargetAddress::Ipv4(ip), port))
            }
            0x02 => {
                // Domain: 1 byte type + 1 byte length + domain + 2 bytes port
                // 最小 4 字节（空域名不可能存在，但协议层面可以解析）
                if payload.len() < 4 {
                    return None;
                }
                let domain_len = payload[1] as usize;
                if payload.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[2..2 + domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([payload[2 + domain_len], payload[3 + domain_len]]);
                Some((TrojanTargetAddress::Domain(domain, port), port))
            }
            0x03 => {
                // IPv6: 1 byte type + 16 bytes IP + 2 bytes port
                // 总共需要 19 字节
                if payload.len() < 19 {
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
                Some((TrojanTargetAddress::Ipv6(ip), port))
            }
            _ => None,
        }
    }

    /// 将目标地址序列化为 Trojan 协议字节格式
    ///
    /// # 返回值
    /// - 包含地址类型前缀和地址数据的字节向量
    /// - 不包含端口（端口应单独编码）
    ///
    /// # 格式
    /// - IPv4: `[0x01][4 字节 IP]`
    /// - Domain: `[0x02][1 字节长度][域名字节]`
    /// - IPv6: `[0x03][16 字节 IP]`
    ///
    /// # 注意
    /// - 此方法不包含端口信息，调用者需要自行追加端口字节
    /// - IPv6 的 to_string() 格式与协议格式不同，需使用 segments() 方法
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TrojanTargetAddress::Ipv4(ip) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes
            }
            TrojanTargetAddress::Ipv6(ip) => {
                let mut bytes = vec![0x03]; // ATYP IPv6
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes
            }
            TrojanTargetAddress::Domain(domain, _) => {
                let mut bytes = vec![0x02, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }
}

/// Trojan 协议 CRLF 换行符常量
///
/// Trojan 协议使用 `\r\n` (0x0D 0x0A) 作为请求头各部分之间的分隔符。
/// 出现在：
/// - 密码和命令之间
/// - 地址信息和 payload 之间
///
/// # 协议位置
/// ```
/// [password (56 bytes)][\r\n]
/// [command (1 byte)][address type (1 byte)][address][port (2 bytes)][\r\n]
/// ```
pub const TROJAN_CRLF: &[u8] = b"\r\n";

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证命令类型的协议值正确
    #[test]
    fn test_command_values() {
        assert_eq!(TrojanCommand::Proxy as u8, 0x01);
        assert_eq!(TrojanCommand::UdpAssociate as u8, 0x02);
    }

    /// 验证地址类型的协议值正确
    #[test]
    fn test_address_type_values() {
        assert_eq!(TrojanAddressType::Ipv4 as u8, 0x01);
        assert_eq!(TrojanAddressType::Domain as u8, 0x02);
        assert_eq!(TrojanAddressType::Ipv6 as u8, 0x03);
    }

    /// 测试 IPv4 地址解析
    #[test]
    fn test_target_address_parse_ipv4() {
        let payload = [
            0x01, 192, 168, 1, 1, 0x1F, 0x90, // 192.168.1.1:8080 (0x1F90 = 8080)
        ];
        let result = TrojanTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TrojanTargetAddress::Ipv4(ip) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            }
            _ => panic!("Expected IPv4"),
        }
        assert_eq!(port, 8080);
    }

    /// 测试域名地址解析
    #[test]
    fn test_target_address_parse_domain() {
        // Domain format: ATYP(1) + LEN(1) + DOMAIN(LEN) + PORT(2)
        let payload = [
            0x02, // ATYP_DOMAIN
            0x0b, // domain length = 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // "example.com"
            0x00, 0x50, // port = 80
        ];
        let result = TrojanTargetAddress::parse_from_bytes(&payload);
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        match addr {
            TrojanTargetAddress::Domain(domain, _) => {
                assert_eq!(domain, "example.com");
            }
            _ => panic!("Expected Domain"),
        }
        assert_eq!(port, 80);
    }

    /// 测试 IPv4 地址序列化
    #[test]
    fn test_target_address_to_bytes_ipv4() {
        let addr = TrojanTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 192, 168, 1, 1]);
    }
}
