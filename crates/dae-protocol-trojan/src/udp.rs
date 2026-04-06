//! Trojan UDP 处理模块
//!
//! 本模块包含 Trojan UDP 协议的常量和工具函数，包括：
//! - UDP 帧格式常量
//! - UDP 命令类型定义
//! - UDP 帧构建和解析工具

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Trojan UDP 帧最大大小
pub const MAX_UDP_FRAME_SIZE: usize = 65535;

/// Trojan UDP 帧头部大小（字节）
/// cmd(1) + uuid(16) + ver(1) + port(2) + atyp(1) = 21 字节
pub const UDP_HEADER_SIZE: usize = 21;

/// Trojan UDP 命令类型
///
/// # 命令值
/// - `0x01`: UDP 数据包
/// - `0x02`: 断开连接（DISCONNECT）
/// - `0x03`: 心跳检测（PING/PONG）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCommand {
    /// UDP 数据包（command = 0x01）
    Data = 0x01,
    /// 断开连接（command = 0x02）
    Disconnect = 0x02,
    /// 心跳检测（command = 0x03）
    Ping = 0x03,
}

impl UdpCommand {
    /// 从字节值创建 UdpCommand
    ///
    /// # 参数
    /// - `value`: 命令字节值
    ///
    /// # 返回
    /// - `Some(UdpCommand)`: 有效的命令
    /// - `None`: 无效的命令值
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(UdpCommand::Data),
            0x02 => Some(UdpCommand::Disconnect),
            0x03 => Some(UdpCommand::Ping),
            _ => None,
        }
    }
}

/// Trojan UDP 协议版本
pub const UDP_PROTOCOL_VERSION: u8 = 0x01;

/// Trojan UDP 帧构建器
///
/// 用于构建 Trojan UDP 响应帧。
pub struct UdpFrameBuilder {
    cmd: u8,
    uuid: [u8; 16],
    port: [u8; 2],
    atyp: u8,
}

impl UdpFrameBuilder {
    /// 创建新的帧构建器
    ///
    /// # 参数
    /// - `cmd`: 命令字节
    /// - `uuid`: 16 字节会话 UUID
    /// - `port`: 2 字节端口号
    /// - `atyp`: 地址类型
    pub fn new(cmd: u8, uuid: [u8; 16], port: [u8; 2], atyp: u8) -> Self {
        Self {
            cmd,
            uuid,
            port,
            atyp,
        }
    }

    /// 从 UDP 帧头部提取关键信息
    ///
    /// # 参数
    /// - `header`: 21 字节的 UDP 帧头部
    ///
    /// # 返回
    /// - `Some((cmd, uuid, port, atyp))`: 解析成功
    /// - `None`: 头部数据不完整
    pub fn parse_header(header: &[u8; UDP_HEADER_SIZE]) -> Option<(u8, [u8; 16], [u8; 2], u8)> {
        if header.len() < UDP_HEADER_SIZE {
            return None;
        }
        let cmd = header[0];
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&header[1..17]);
        let port = [header[18], header[19]];
        let atyp = header[20];
        Some((cmd, uuid, port, atyp))
    }

    /// 构建带目标地址的 UDP 响应帧
    ///
    /// # 参数
    /// - `target_addr`: 目标地址字符串
    /// - `payload`: UDP 数据载荷
    ///
    /// # 返回
    /// 完整的 UDP 响应帧字节向量
    pub fn build_response(&self, target_addr: &str, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(UDP_HEADER_SIZE + payload.len() + 256);
        frame.push(self.cmd);
        frame.extend_from_slice(&self.uuid);
        frame.push(UDP_PROTOCOL_VERSION);
        frame.extend_from_slice(&self.port);
        frame.push(self.atyp);

        // 添加目标地址
        if let Ok(ip) = target_addr.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => frame.extend_from_slice(&v4.octets()),
                IpAddr::V6(v6) => frame.extend_from_slice(&v6.octets()),
            }
        } else {
            // 可能是域名
            frame.push(target_addr.len() as u8);
            frame.extend_from_slice(target_addr.as_bytes());
        }

        frame.extend_from_slice(payload);
        frame
    }

    /// 构建 PING/PONG 帧（无载荷）
    ///
    /// # 返回
    /// PING 响应帧字节向量
    pub fn build_pong(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(UDP_HEADER_SIZE);
        frame.push(self.cmd);
        frame.extend_from_slice(&self.uuid);
        frame.push(UDP_PROTOCOL_VERSION);
        frame.extend_from_slice(&self.port);
        frame.push(self.atyp);
        frame
    }
}

/// 从 IP 地址字节构建目标地址字符串
///
/// # 参数
/// - `atyp`: 地址类型
/// - `ip_bytes`: IP 地址字节
/// - `domain`: 可选的域名（当 atyp 为 0x02 时使用）
///
/// # 返回
/// 格式化的目标地址字符串
pub fn build_target_addr(atyp: u8, ip_bytes: &[u8], domain: Option<&str>) -> String {
    match atyp {
        0x01 => {
            // IPv4
            if ip_bytes.len() >= 4 {
                IpAddr::V4(Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
                    .to_string()
            } else {
                String::new()
            }
        }
        0x02 => {
            // Domain
            domain.unwrap_or("").to_string()
        }
        0x03 => {
            // IPv6
            if ip_bytes.len() >= 16 {
                let segments: [u16; 8] = [
                    u16::from_be_bytes([ip_bytes[0], ip_bytes[1]]),
                    u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]),
                    u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]),
                    u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]),
                    u16::from_be_bytes([ip_bytes[8], ip_bytes[9]]),
                    u16::from_be_bytes([ip_bytes[10], ip_bytes[11]]),
                    u16::from_be_bytes([ip_bytes[12], ip_bytes[13]]),
                    u16::from_be_bytes([ip_bytes[14], ip_bytes[15]]),
                ];
                IpAddr::V6(Ipv6Addr::new(
                    segments[0], segments[1], segments[2], segments[3],
                    segments[4], segments[5], segments[6], segments[7],
                ))
                .to_string()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_command_from_u8() {
        assert_eq!(UdpCommand::from_u8(0x01), Some(UdpCommand::Data));
        assert_eq!(UdpCommand::from_u8(0x02), Some(UdpCommand::Disconnect));
        assert_eq!(UdpCommand::from_u8(0x03), Some(UdpCommand::Ping));
        assert_eq!(UdpCommand::from_u8(0x04), None);
    }

    #[test]
    fn test_header_size() {
        assert_eq!(UDP_HEADER_SIZE, 21);
    }

    #[test]
    fn test_parse_header() {
        let header = [
            0x01, // cmd
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // uuid (16 bytes)
            0x01, // ver
            0x1F, 0x90, // port (8080)
            0x01, // atyp
        ];
        let (cmd, uuid, port, atyp) = UdpFrameBuilder::parse_header(&header).unwrap();
        assert_eq!(cmd, 0x01);
        assert_eq!(uuid, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(port, [0x1F, 0x90]);
        assert_eq!(atyp, 0x01);
    }

    #[test]
    fn test_build_target_addr_ipv4() {
        let addr = build_target_addr(0x01, &[192, 168, 1, 1], None);
        assert_eq!(addr, "192.168.1.1");
    }

    #[test]
    fn test_build_target_addr_domain() {
        let addr = build_target_addr(0x02, &[], Some("example.com"));
        assert_eq!(addr, "example.com");
    }
}
