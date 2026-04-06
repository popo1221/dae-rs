//! VLESS 协议类型模块
//!
//! 本模块包含 VLESS 协议的核心类型定义和解析逻辑：
//! - 协议版本常量
//! - 命令类型枚举
//! - 地址类型枚举
//! - 目标地址类型及其序列化/反序列化
//!
//! # VLESS 协议格式
//! ```text
//! [v1 (1)][uuid (16)][ver (1)][cmd (1)][port (4)][atyp (1)][addr][iv (16)]
//! [payload ...]
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// VLESS 协议版本号
///
/// VLESS 协议的版本标识，固定为 0x01。
pub const VLESS_VERSION: u8 = 0x01;

/// VLESS 头部最小大小（字节）
///
/// 完整请求头: v1(1) + uuid(16) + ver(1) + cmd(1) + port(4) + atyp(1) + iv(16) = 38 字节
pub const VLESS_HEADER_MIN_SIZE: usize = 38;

/// VLESS 请求头部大小（不含 uuid）
///
/// port(4) + atyp(1) + addr + iv(16) = 22 字节 + 变长地址
#[allow(dead_code)]
pub const VLESS_REQUEST_HEADER_SIZE: usize = 22;

/// 最大域名长度（VLESS 协议限制）
///
/// VLESS 协议使用 1 字节存储域名长度，最大 255 字节。
const MAX_DOMAIN_LEN: usize = 255;

/// VLESS 命令类型
///
/// 定义客户端请求的操作类型。
///
/// # 变体说明
/// - `Tcp`: TCP 代理连接
/// - `Udp`: UDP 数据包（多路复用模式）
/// - `XtlsVision`: XTLS Vision 模式（Reality）
///
/// # 协议值
/// - `Tcp` = 0x01
/// - `Udp` = 0x02
/// - `XtlsVision` = 0x03
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    /// TCP 连接（command = 0x01）
    Tcp = 0x01,
    /// UDP 数据包（command = 0x02）
    Udp = 0x02,
    /// XTLS Vision 模式（command = 0x03）
    /// 用于 Reality Vision 混淆
    XtlsVision = 0x03,
}

impl VlessCommand {
    /// 从字节值转换为 VlessCommand
    ///
    /// # 参数
    /// - `v`: 命令字节值
    ///
    /// # 返回
    /// - `Some(VlessCommand)`: 有效命令
    /// - `None`: 无效命令值
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(VlessCommand::Tcp),
            0x02 => Some(VlessCommand::Udp),
            0x03 => Some(VlessCommand::XtlsVision),
            _ => None,
        }
    }
}

/// VLESS 地址类型
///
/// 标识目标地址的编码格式。
///
/// # 变体说明
/// - `Ipv4`: IPv4 地址（atyp = 0x01）
/// - `Domain`: 域名（atyp = 0x02）
/// - `Ipv6`: IPv6 地址（atyp = 0x03）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessAddressType {
    /// IPv4 地址（atyp = 0x01）
    Ipv4 = 0x01,
    /// 域名地址（atyp = 0x02）
    Domain = 0x02,
    /// IPv6 地址（atyp = 0x03）
    Ipv6 = 0x03,
}

impl VlessAddressType {
    /// 从字节值转换为 VlessAddressType
    ///
    /// # 参数
    /// - `v`: 地址类型字节值
    ///
    /// # 返回
    /// - `Some(VlessAddressType)`: 有效地址类型
    /// - `None`: 无效地址类型值
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(VlessAddressType::Ipv4),
            0x02 => Some(VlessAddressType::Domain),
            0x03 => Some(VlessAddressType::Ipv6),
            _ => None,
        }
    }
}

/// VLESS 目标地址
///
/// 表示 VLESS 请求的目标地址。
///
/// # 变体说明
/// - `Ipv4(IpAddr)`: IPv4 地址
/// - `Domain(String, u16)`: 域名和端口
/// - `Ipv6(IpAddr)`: IPv6 地址
#[derive(Debug, Clone)]
pub enum VlessTargetAddress {
    /// IPv4 目标地址
    Ipv4(IpAddr),
    /// 域名目标地址
    /// 元组: (域名, 端口)
    Domain(String, u16),
    /// IPv6 目标地址
    Ipv6(IpAddr),
}

impl std::fmt::Display for VlessTargetAddress {
    /// 格式化地址为字符串
    ///
    /// # 格式
    /// - IPv4: `192.168.1.1`
    /// - Domain: `example.com`（不含端口）
    /// - IPv6: 完整 IPv6 格式
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VlessTargetAddress::Ipv4(ip) => write!(f, "{ip}"),
            VlessTargetAddress::Domain(domain, _) => write!(f, "{domain}"),
            VlessTargetAddress::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

impl VlessTargetAddress {
    /// 从字节流解析目标地址
    ///
    /// # 参数
    /// - `payload`: 包含地址类型和数据的字节数组
    ///
    /// # 返回
    /// - `Some((Self, u16))`: 解析成功，返回 (地址, 端口)
    /// - `None`: 解析失败
    ///
    /// # 支持的格式
    /// - **IPv4** (atyp=0x01): [类型(1)][IP(4)][端口(2)] = 7 字节
    /// - **域名** (atyp=0x02): [类型(1)][长度(1)][域名(N)][端口(2)]
    /// - **IPv6** (atyp=0x03): [类型(1)][IP(16)][端口(2)] = 19 字节
    ///
    /// # 安全说明
    /// - 域名长度为 0 时返回 `None`（拒绝空域名）
    /// - 使用 `from_utf8` 验证域名编码合法性
    pub fn parse_from_bytes(payload: &[u8]) -> Option<(Self, u16)> {
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
                Some((VlessTargetAddress::Ipv4(ip), port))
            }
            0x02 => {
                // Domain: 1 byte type + 1 byte length + domain + 2 bytes port
                if payload.len() < 4 {
                    return None;
                }
                let domain_len = payload[1] as usize;
                // 拒绝空域名（安全考量）
                if domain_len == 0 {
                    return None;
                }
                if payload.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(payload[2..2 + domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([payload[2 + domain_len], payload[3 + domain_len]]);
                Some((VlessTargetAddress::Domain(domain, port), port))
            }
            0x03 => {
                // IPv6: 1 byte type + 16 bytes IP + 2 bytes port
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
                Some((VlessTargetAddress::Ipv6(ip), port))
            }
            _ => None,
        }
    }

    /// 将目标地址序列化为字节
    ///
    /// # 返回
    /// - 包含地址类型前缀和地址的字节向量
    /// - 不包含端口（端口需单独编码）
    ///
    /// # 域名长度保护
    /// - 如果域名超过 255 字节（MAX_DOMAIN_LEN），返回无效编码（防止截断）
    /// - 这会导致下游解析失败，而不是静默截断数据
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VlessTargetAddress::Ipv4(ip) => {
                let mut bytes = vec![0x01]; // ATYP IPv4
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes
            }
            VlessTargetAddress::Ipv6(ip) => {
                let mut bytes = vec![0x03]; // ATYP IPv6
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes
            }
            VlessTargetAddress::Domain(domain, _) => {
                // 域名长度保护：超过 255 字节时返回无效编码
                // 防止静默截断导致数据损坏
                if domain.len() > MAX_DOMAIN_LEN {
                    return vec![0x02, 0x00]; // 无效编码
                }
                let mut bytes = vec![0x02, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }
}
