//! Juicity 协议编解码器模块
//!
//! 实现了 Juicity 协议的二进制格式编码/解码功能。
//!
//! # 协议格式
//!
//! [1 字节命令][4 字节连接 ID][4 字节会话 ID]
//! [4 字节序列号][2 字节端口][1 字节地址类型][地址][载荷...]
//!
//! # 地址格式
//!
//! - IPv4: 1 字节类型(0x01) + 4 字节 IP + 2 字节端口
//! - 域名: 1 字节类型(0x02) + 1 字节长度 + 域名 + 2 字节端口
//! - IPv6: 1 字节类型(0x03) + 16 字节 IP + 2 字节端口

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Juicity 协议命令
///
/// 定义了 Juicity 协议中的各种命令类型。
///
/// # 命令说明
///
/// - `Open`: 打开新连接（0x01）
/// - `Send`: 发送数据（0x02）
/// - `Close`: 关闭连接（0x03）
/// - `Ping`: 心跳请求（0x04）
/// - `Pong`: 心跳响应（0x05）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JuicityCommand {
    /// 打开新连接
    Open = 0x01,
    /// 发送数据
    Send = 0x02,
    /// 关闭连接
    Close = 0x03,
    /// 心跳请求
    Ping = 0x04,
    /// 心跳响应
    Pong = 0x05,
}

impl JuicityCommand {
    /// Parse command from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(JuicityCommand::Open),
            0x02 => Some(JuicityCommand::Send),
            0x03 => Some(JuicityCommand::Close),
            0x04 => Some(JuicityCommand::Ping),
            0x05 => Some(JuicityCommand::Pong),
            _ => None,
        }
    }

    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Juicity 地址类型
///
/// 定义了 Juicity 协议中支持的地址类型。
///
/// # 类型说明
///
/// - `Ipv4`: IPv4 地址（0x01）
/// - `Domain`: 域名地址（0x02）
/// - `Ipv6`: IPv6 地址（0x03）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JuicityAddressType {
    /// IPv4 地址
    Ipv4 = 0x01,
    /// 域名地址
    Domain = 0x02,
    /// IPv6 地址
    Ipv6 = 0x03,
}

impl JuicityAddressType {
    /// Parse from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(JuicityAddressType::Ipv4),
            0x02 => Some(JuicityAddressType::Domain),
            0x03 => Some(JuicityAddressType::Ipv6),
            _ => None,
        }
    }

    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Juicity 帧
///
/// 表示 Juicity 协议中的一个完整消息。
///
/// # 字段说明
///
/// - `command`: 命令类型
/// - `connection_id`: 连接 ID
/// - `session_id`: 会话 ID
/// - `sequence`: 序列号
/// - `address`: 目标地址（仅 Open 命令）
/// - `payload`: 载荷数据
///
/// # 创建方法
///
/// - `new_open`: 创建 Open 帧
/// - `new_send`: 创建 Send 帧
/// - `new_close`: 创建 Close 帧
/// - `new_ping`: 创建 Ping 帧
/// - `new_pong`: 创建 Pong 帧
#[derive(Debug, Clone)]
pub struct JuicityFrame {
    /// Command type
    pub command: JuicityCommand,
    /// Connection ID
    pub connection_id: u32,
    /// Session ID
    pub session_id: u32,
    /// Sequence number
    pub sequence: u32,
    /// Target address (optional, for Open command)
    pub address: Option<JuicityAddress>,
    /// Payload data
    pub payload: Vec<u8>,
}

impl JuicityFrame {
    /// Create a new Open frame
    pub fn new_open(connection_id: u32, session_id: u32, address: JuicityAddress) -> Self {
        Self {
            command: JuicityCommand::Open,
            connection_id,
            session_id,
            sequence: 0,
            address: Some(address),
            payload: Vec::new(),
        }
    }

    /// Create a new Send frame
    pub fn new_send(connection_id: u32, session_id: u32, sequence: u32, payload: Vec<u8>) -> Self {
        Self {
            command: JuicityCommand::Send,
            connection_id,
            session_id,
            sequence,
            address: None,
            payload,
        }
    }

    /// Create a new Close frame
    pub fn new_close(connection_id: u32, session_id: u32) -> Self {
        Self {
            command: JuicityCommand::Close,
            connection_id,
            session_id,
            sequence: 0,
            address: None,
            payload: Vec::new(),
        }
    }

    /// Create a new Ping frame
    pub fn new_ping(connection_id: u32, session_id: u32) -> Self {
        Self {
            command: JuicityCommand::Ping,
            connection_id,
            session_id,
            sequence: 0,
            address: None,
            payload: Vec::new(),
        }
    }

    /// Create a new Pong frame
    pub fn new_pong(connection_id: u32, session_id: u32) -> Self {
        Self {
            command: JuicityCommand::Pong,
            connection_id,
            session_id,
            sequence: 0,
            address: None,
            payload: Vec::new(),
        }
    }
}

/// Juicity 地址
///
/// 表示 Juicity 协议中的目标地址，可以是 IPv4、域名或 IPv6。
///
/// # 地址类型
///
/// - `Ipv4(IpAddr, u16)`: IPv4 地址和端口
/// - `Domain(String, u16)`: 域名和端口
/// - `Ipv6(IpAddr, u16)`: IPv6 地址和端口
#[derive(Debug, Clone)]
pub enum JuicityAddress {
    /// IPv4 地址和端口
    Ipv4(IpAddr, u16),
    /// 域名和端口
    Domain(String, u16),
    /// IPv6 地址和端口
    Ipv6(IpAddr, u16),
}

impl JuicityAddress {
    /// Parse from bytes (address_type + address + port)
    pub fn parse_from_bytes(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.is_empty() {
            return None;
        }

        let atyp = match JuicityAddressType::from_byte(buf[0])? {
            JuicityAddressType::Ipv4 => {
                // IPv4: 1 byte type + 4 bytes IP + 2 bytes port = 7 bytes
                if buf.len() < 7 {
                    return None;
                }
                let ip = IpAddr::V4(Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]));
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                (JuicityAddress::Ipv4(ip, port), 7)
            }
            JuicityAddressType::Domain => {
                // Domain: 1 byte type + 1 byte length + domain + 2 bytes port
                if buf.len() < 4 {
                    return None;
                }
                let domain_len = buf[1] as usize;
                if buf.len() < 4 + domain_len {
                    return None;
                }
                let domain = String::from_utf8(buf[2..2 + domain_len].to_vec()).ok()?;
                let port = u16::from_be_bytes([buf[2 + domain_len], buf[3 + domain_len]]);
                (JuicityAddress::Domain(domain, port), 4 + domain_len)
            }
            JuicityAddressType::Ipv6 => {
                // IPv6: 1 byte type + 16 bytes IP + 2 bytes port = 19 bytes
                if buf.len() < 19 {
                    return None;
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([buf[1], buf[2]]),
                    u16::from_be_bytes([buf[3], buf[4]]),
                    u16::from_be_bytes([buf[5], buf[6]]),
                    u16::from_be_bytes([buf[7], buf[8]]),
                    u16::from_be_bytes([buf[9], buf[10]]),
                    u16::from_be_bytes([buf[11], buf[12]]),
                    u16::from_be_bytes([buf[13], buf[14]]),
                    u16::from_be_bytes([buf[15], buf[16]]),
                ));
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                (JuicityAddress::Ipv6(ip, port), 19)
            }
        };

        Some(atyp)
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            JuicityAddress::Ipv4(ip, port) => {
                let mut bytes = vec![JuicityAddressType::Ipv4.to_byte()];
                if let IpAddr::V4(ipv4) = ip {
                    bytes.extend_from_slice(&ipv4.octets());
                }
                bytes.extend_from_slice(&port.to_be_bytes());
                bytes
            }
            JuicityAddress::Ipv6(ip, port) => {
                let mut bytes = vec![JuicityAddressType::Ipv6.to_byte()];
                if let IpAddr::V6(ipv6) = ip {
                    for &segment in &ipv6.segments() {
                        bytes.extend_from_slice(&segment.to_be_bytes());
                    }
                }
                bytes.extend_from_slice(&port.to_be_bytes());
                bytes
            }
            JuicityAddress::Domain(domain, port) => {
                let mut bytes = vec![JuicityAddressType::Domain.to_byte(), domain.len() as u8];
                bytes.extend_from_slice(domain.as_bytes());
                bytes.extend_from_slice(&port.to_be_bytes());
                bytes
            }
        }
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        match self {
            JuicityAddress::Ipv4(_, port) => *port,
            JuicityAddress::Domain(_, port) => *port,
            JuicityAddress::Ipv6(_, port) => *port,
        }
    }
}

impl std::fmt::Display for JuicityAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JuicityAddress::Ipv4(ip, port) => write!(f, "{ip}:{port}"),
            JuicityAddress::Domain(domain, port) => write!(f, "{domain}:{port}"),
            JuicityAddress::Ipv6(ip, port) => write!(f, "[{ip}]:{port}"),
        }
    }
}

/// Juicity codec for encoding/decoding frames
pub struct JuicityCodec;

impl JuicityCodec {
    /// Encode a frame to bytes
    pub fn encode(frame: &JuicityFrame) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);

        // Command (1 byte)
        buf.push(frame.command.to_byte());

        // Connection ID (4 bytes, little-endian)
        buf.extend_from_slice(&frame.connection_id.to_le_bytes());

        // Session ID (4 bytes, little-endian)
        buf.extend_from_slice(&frame.session_id.to_le_bytes());

        // Sequence (4 bytes, little-endian)
        buf.extend_from_slice(&frame.sequence.to_le_bytes());

        // Address (if present)
        if let Some(ref addr) = frame.address {
            buf.extend_from_slice(&addr.to_bytes());
        }

        // Payload
        if !frame.payload.is_empty() {
            buf.extend_from_slice(&frame.payload);
        }

        buf
    }

    /// Decode a frame from bytes
    pub fn decode(buf: &[u8]) -> Option<JuicityFrame> {
        if buf.len() < 13 {
            // Minimum: 1 cmd + 4 conn_id + 4 sess_id + 4 seq = 13 bytes
            // For Open with address, we need at least 14 bytes (add 1 for address type)
            return None;
        }

        let mut pos = 0;

        // Command (1 byte)
        let command = JuicityCommand::from_byte(buf[pos])?;
        pos += 1;

        // Connection ID (4 bytes)
        let connection_id =
            u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        // Session ID (4 bytes)
        let session_id = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        // Sequence (4 bytes)
        let sequence = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        // Address (if present, for Open command)
        let address = if command == JuicityCommand::Open && pos < buf.len() {
            let slice = &buf[pos..];
            let (addr, addr_len) = JuicityAddress::parse_from_bytes(slice)?;
            pos += addr_len;
            Some(addr)
        } else {
            None
        };

        // Payload (remaining bytes)
        let payload = if pos < buf.len() {
            buf[pos..].to_vec()
        } else {
            Vec::new()
        };

        Some(JuicityFrame {
            command,
            connection_id,
            session_id,
            sequence,
            address,
            payload,
        })
    }

    /// Encode frame header only (for Open command with large payload)
    pub fn encode_header(frame: &JuicityFrame) -> Vec<u8> {
        let mut buf = Vec::with_capacity(14);

        buf.push(frame.command.to_byte());
        buf.extend_from_slice(&frame.connection_id.to_le_bytes());
        buf.extend_from_slice(&frame.session_id.to_le_bytes());
        buf.extend_from_slice(&frame.sequence.to_le_bytes());

        if let Some(ref addr) = frame.address {
            buf.extend_from_slice(&addr.to_bytes());
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_conversion() {
        assert_eq!(JuicityCommand::from_byte(0x01), Some(JuicityCommand::Open));
        assert_eq!(JuicityCommand::from_byte(0x02), Some(JuicityCommand::Send));
        assert_eq!(JuicityCommand::from_byte(0x03), Some(JuicityCommand::Close));
        assert_eq!(JuicityCommand::from_byte(0x04), Some(JuicityCommand::Ping));
        assert_eq!(JuicityCommand::from_byte(0x05), Some(JuicityCommand::Pong));
        assert_eq!(JuicityCommand::from_byte(0xFF), None);

        assert_eq!(JuicityCommand::Open.to_byte(), 0x01);
    }

    #[test]
    fn test_address_type_conversion() {
        assert_eq!(
            JuicityAddressType::from_byte(0x01),
            Some(JuicityAddressType::Ipv4)
        );
        assert_eq!(
            JuicityAddressType::from_byte(0x02),
            Some(JuicityAddressType::Domain)
        );
        assert_eq!(
            JuicityAddressType::from_byte(0x03),
            Some(JuicityAddressType::Ipv6)
        );
        assert_eq!(JuicityAddressType::from_byte(0xFF), None);
    }

    #[test]
    fn test_address_ipv4_parse() {
        let bytes = [0x01, 192, 168, 1, 1, 0x1F, 0x90]; // 192.168.1.1:8080
        let (addr, len) = JuicityAddress::parse_from_bytes(&bytes).unwrap();
        match addr {
            JuicityAddress::Ipv4(ip, port) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected Ipv4"),
        }
        assert_eq!(len, 7);
    }

    #[test]
    fn test_address_domain_parse() {
        let bytes = [
            0x02, // ATYP_DOMAIN
            0x0b, // domain length = 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', // "example.com" (11 chars)
            0x00, 0x50, // port = 80
        ];
        let (addr, len) = JuicityAddress::parse_from_bytes(&bytes).unwrap();
        match addr {
            JuicityAddress::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 80);
            }
            _ => panic!("Expected Domain"),
        }
        assert_eq!(len, 15); // 1 + 1 + 11 + 2
    }

    #[test]
    fn test_address_ipv6_parse() {
        let bytes = [
            0x03, // ATYP_IPV6
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x50, // [2001:db8::1]:80
        ];
        let (addr, len) = JuicityAddress::parse_from_bytes(&bytes).unwrap();
        match addr {
            JuicityAddress::Ipv6(ip, port) => {
                assert_eq!(
                    ip,
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001))
                );
                assert_eq!(port, 80);
            }
            _ => panic!("Expected Ipv6"),
        }
        assert_eq!(len, 19);
    }

    #[test]
    fn test_address_to_bytes_ipv4() {
        let addr = JuicityAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 192, 168, 1, 1, 0x1F, 0x90]);
    }

    #[test]
    fn test_address_to_bytes_domain() {
        let addr = JuicityAddress::Domain("example.com".to_string(), 80);
        let bytes = addr.to_bytes();
        // 1 byte type + 1 byte length + 11 bytes domain + 2 bytes port = 15 bytes
        assert_eq!(
            bytes,
            vec![
                0x02, // ATYP_DOMAIN
                0x0b, // length (11 chars for "example.com")
                b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                b'm', // "example.com"
                0x00, 0x50 // port = 80
            ]
        );
    }

    #[test]
    fn test_frame_open_encode_decode() {
        let addr = JuicityAddress::Domain("example.com".to_string(), 443);
        let frame = JuicityFrame::new_open(0x12345678, 0xABCDEF00, addr);

        let encoded = JuicityCodec::encode(&frame);
        let decoded = JuicityCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.command, JuicityCommand::Open);
        assert_eq!(decoded.connection_id, 0x12345678);
        assert_eq!(decoded.session_id, 0xABCDEF00);
        assert!(decoded.address.is_some());
        match decoded.address.unwrap() {
            JuicityAddress::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected Domain"),
        }
    }

    #[test]
    fn test_frame_send_encode_decode() {
        let payload = b"Hello, Juicity!";
        let frame = JuicityFrame::new_send(0x12345678, 0xABCDEF00, 42, payload.to_vec());

        let encoded = JuicityCodec::encode(&frame);
        let decoded = JuicityCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.command, JuicityCommand::Send);
        assert_eq!(decoded.connection_id, 0x12345678);
        assert_eq!(decoded.session_id, 0xABCDEF00);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload, payload.to_vec());
    }

    #[test]
    fn test_frame_close_encode_decode() {
        let frame = JuicityFrame::new_close(0x12345678, 0xABCDEF00);

        let encoded = JuicityCodec::encode(&frame);
        let decoded = JuicityCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.command, JuicityCommand::Close);
        assert_eq!(decoded.connection_id, 0x12345678);
        assert_eq!(decoded.session_id, 0xABCDEF00);
    }

    #[test]
    fn test_frame_ping_pong() {
        let ping = JuicityFrame::new_ping(0x12345678, 0xABCDEF00);
        let encoded = JuicityCodec::encode(&ping);
        let decoded = JuicityCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.command, JuicityCommand::Ping);

        let pong = JuicityFrame::new_pong(0x12345678, 0xABCDEF00);
        let encoded = JuicityCodec::encode(&pong);
        let decoded = JuicityCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.command, JuicityCommand::Pong);
    }
}
