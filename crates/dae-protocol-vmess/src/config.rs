//! VMess 配置类型模块
//!
//! 本模块包含 VMess 协议所需的配置类型。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use super::protocol::VmessServerConfig;

/// VMess 客户端配置
///
/// 定义本地 VMess 客户端的配置信息。
///
/// # 字段说明
/// - `listen_addr`: 本地监听地址（默认: 127.0.0.1:1080）
/// - `server`: 远程服务器配置
/// - `tcp_timeout`: TCP 连接超时（默认: 60 秒）
/// - `udp_timeout`: UDP 会话超时（默认: 30 秒）
#[derive(Debug, Clone)]
pub struct VmessClientConfig {
    /// 本地监听地址（默认: 127.0.0.1:1080）
    pub listen_addr: SocketAddr,
    /// 远程服务器配置
    pub server: VmessServerConfig,
    /// TCP 连接超时（默认: 60 秒）
    pub tcp_timeout: Duration,
    /// UDP 会话超时（默认: 30 秒）
    pub udp_timeout: Duration,
}

impl Default for VmessClientConfig {
    /// 创建默认配置
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            server: VmessServerConfig::default(),
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

/// VMess 目标地址
///
/// 表示 VMess 请求的目标地址。
///
/// # 变体说明
/// - `Ipv4(IpAddr)`: IPv4 地址
/// - `Domain(String, u16)`: 域名和端口
/// - `Ipv6(IpAddr)`: IPv6 地址
#[derive(Debug, Clone)]
pub enum VmessTargetAddress {
    /// IPv4 目标地址
    Ipv4(IpAddr),
    /// 域名目标地址
    /// 元组: (域名, 端口)
    Domain(String, u16),
    /// IPv6 目标地址
    Ipv6(IpAddr),
}

impl std::fmt::Display for VmessTargetAddress {
    /// 格式化地址为字符串
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmessTargetAddress::Ipv4(ip) => write!(f, "{ip}"),
            VmessTargetAddress::Domain(domain, _) => write!(f, "{domain}"),
            VmessTargetAddress::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

impl VmessTargetAddress {
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
    /// - **IPv4** (atyp=0x01): [类型(1)][IP(4)][端口(2)]
    /// - **域名** (atyp=0x02): [类型(1)][长度(1)][域名(N)][端口(2)]
    /// - **IPv6** (atyp=0x03): [类型(1)][IP(16)][端口(2)]
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
                Some((VmessTargetAddress::Ipv4(ip), port))
            }
            0x02 => {
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
                Some((VmessTargetAddress::Domain(domain, port), port))
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
                Some((VmessTargetAddress::Ipv6(ip), port))
            }
            _ => None,
        }
    }

    /// 将目标地址序列化为字节
    ///
    /// # 返回
    /// 包含地址类型前缀和地址的字节向量（不含端口）
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VmessTargetAddress::Ipv4(ip) => {
                let mut bytes = vec![0x01];
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes
            }
            VmessTargetAddress::Ipv6(ip) => {
                let mut bytes = vec![0x03];
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes
            }
            VmessTargetAddress::Domain(domain, _) => {
                let mut bytes = vec![0x02, domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
        }
    }
}
