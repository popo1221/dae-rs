//! SOCKS4 协议类型和常量定义模块
//!
//! 包含 SOCKS4 和 SOCKS4a 协议的核心类型定义。

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::io::AsyncReadExt;
use tracing::debug;

/// SOCKS4 协议常量
mod consts {
    /// 协议版本号
    pub const VER: u8 = 0x04;

    /// SOCKS4a 魔术地址前三个字节
    ///
    /// 当 DST.IP 前三个字节为 0.0.0 且第四个字节非零时，
    /// 表示这是一个 SOCKS4a 请求，后续会有域名。
    #[allow(dead_code)]
    pub const SOCKS4A_MAGIC_IP: [u8; 3] = [0x00, 0x00, 0x00];

    /// 命令码
    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;

    /// 响应码
    pub const REP_REQUEST_GRANTED: u8 = 0x5A;
    pub const REP_REQUEST_REJECTED: u8 = 0x5B;
    pub const REP_REQUEST_FAILED: u8 = 0x5C; // Identd 未运行
    pub const REP_REQUEST_FAILED_USER: u8 = 0x5D; // 用户 ID 不匹配
}

// Re-export constants for use in other modules
#[allow(unused_imports)]
pub use consts::{
    CMD_BIND, CMD_CONNECT, REP_REQUEST_FAILED, REP_REQUEST_FAILED_USER, REP_REQUEST_GRANTED,
    REP_REQUEST_REJECTED, SOCKS4A_MAGIC_IP, VER,
};

/// SOCKS4 命令类型
///
/// 定义 SOCKS4 协议支持的命令。
#[derive(Debug, Clone, Copy)]
pub enum Socks4Command {
    /// CONNECT 命令：请求连接到目标服务器
    Connect,
    /// BIND 命令：请求服务器绑定地址并等待连接
    Bind,
}

impl Socks4Command {
    /// 从字节值解析命令
    ///
    /// # 参数
    /// - `v`: 原始字节值
    ///
    /// # 返回值
    /// - `Some(Socks4Command)`: 有效的命令
    /// - `None`: 无效的命令码
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            consts::CMD_CONNECT => Some(Socks4Command::Connect),
            consts::CMD_BIND => Some(Socks4Command::Bind),
            _ => None,
        }
    }
}

/// SOCKS4 响应码
///
/// 定义 SOCKS4 服务器返回给客户端的响应状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks4Reply {
    /// 请求成功，连接已建立
    RequestGranted,
    /// 请求被拒绝
    RequestRejected,
    /// 请求失败，identd 未运行
    RequestFailedIdentd,
    /// 请求失败，用户 ID 不匹配
    RequestFailedUserId,
}

impl Socks4Reply {
    /// 转换为字节值
    ///
    /// # 返回值
    /// - 0x5A: RequestGranted
    /// - 0x5B: RequestRejected
    /// - 0x5C: RequestFailedIdentd
    /// - 0x5D: RequestFailedUserId
    pub fn to_u8(self) -> u8 {
        match self {
            Socks4Reply::RequestGranted => consts::REP_REQUEST_GRANTED,
            Socks4Reply::RequestRejected => consts::REP_REQUEST_REJECTED,
            Socks4Reply::RequestFailedIdentd => consts::REP_REQUEST_FAILED,
            Socks4Reply::RequestFailedUserId => consts::REP_REQUEST_FAILED_USER,
        }
    }
}

impl std::fmt::Display for Socks4Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks4Reply::RequestGranted => write!(f, "request granted"),
            Socks4Reply::RequestRejected => write!(f, "request rejected"),
            Socks4Reply::RequestFailedIdentd => write!(f, "request rejected: identd not running"),
            Socks4Reply::RequestFailedUserId => write!(f, "request rejected: user id mismatch"),
        }
    }
}

/// SOCKS4 地址类型
///
/// SOCKS4 仅支持 IPv4 地址。
///
/// # SOCKS4 vs SOCKS4a 地址区别
///
/// SOCKS4:
/// - DST.IP: 4 字节 IPv4 地址
/// - DST.PORT: 2 字节端口号
///
/// SOCKS4a:
/// - DST.IP: 0.0.0.X（X 非零，表示后续有域名）
/// - DST.PORT: 2 字节端口号
/// - 域名: null 结尾的字符串
#[derive(Debug, Clone)]
pub struct Socks4Address {
    /// IPv4 地址
    pub ip: Ipv4Addr,
    /// 端口号
    pub port: u16,
}

impl Socks4Address {
    /// 从 SOCKS4 请求中解析地址
    ///
    /// # 参数
    /// - `reader`: 字节读取器
    /// - `use_socks4a`: 是否启用 SOCKS4a 支持
    ///
    /// # 返回值
    /// - `Ok(Socks4Address)`: 解析成功
    /// - `Err`: 解析失败
    ///
    /// # SOCKS4a 检测
    ///
    /// 当 `use_socks4a` 为 true 且 DST.IP 前三个字节为 0.0.0 时，
    /// 会将第四个字节作为域名长度，读取并解析域名。
    pub async fn parse_from<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        use_socks4a: bool,
    ) -> std::io::Result<Self> {
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        let mut ip_buf = [0u8; 4];
        reader.read_exact(&mut ip_buf).await?;

        // Check for SOCKS4a domain name indication
        if use_socks4a && ip_buf[0] == 0x00 && ip_buf[1] == 0x00 && ip_buf[2] == 0x00 {
            // SOCKS4a: need to read domain name
            let mut domain_buf = Vec::new();
            let mut b = [0u8; 1];
            loop {
                reader.read_exact(&mut b).await?;
                if b[0] == 0x00 {
                    break;
                }
                domain_buf.push(b[0]);
            }

            let domain = String::from_utf8(domain_buf).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain")
            })?;

            // For SOCKS4a, we need DNS resolution - return a special marker
            // The actual connection will resolve the domain
            debug!("SOCKS4a domain resolution: {}", domain);

            // We use 0.0.0.0 as placeholder since actual IP is unknown
            // Caller must handle domain resolution
            return Ok(Socks4Address {
                ip: Ipv4Addr::new(0, 0, 0, 0),
                port,
            });
        }

        let ip = Ipv4Addr::new(ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]);
        Ok(Socks4Address { ip, port })
    }

    /// 转换为 SocketAddr
    ///
    /// # 返回值
    /// - `SocketAddr`: IPv4 Socket 地址
    pub fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(self.ip, self.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks4_command_from_u8() {
        assert!(matches!(
            Socks4Command::from_u8(consts::CMD_CONNECT),
            Some(Socks4Command::Connect)
        ));
        assert!(matches!(
            Socks4Command::from_u8(consts::CMD_BIND),
            Some(Socks4Command::Bind)
        ));
        assert!(Socks4Command::from_u8(0xFF).is_none());
    }

    #[test]
    fn test_socks4_reply_to_u8() {
        assert_eq!(Socks4Reply::RequestGranted.to_u8(), 0x5A);
        assert_eq!(Socks4Reply::RequestRejected.to_u8(), 0x5B);
        assert_eq!(Socks4Reply::RequestFailedIdentd.to_u8(), 0x5C);
        assert_eq!(Socks4Reply::RequestFailedUserId.to_u8(), 0x5D);
    }

    #[test]
    fn test_socks4_address_to_socket_addr() {
        let addr = Socks4Address {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            port: 8080,
        };
        let socket: SocketAddr = addr.to_socket_addr();
        assert_eq!(socket.port(), 8080);
    }

    #[test]
    fn test_socks4_command_from_u8_exhaustive() {
        // Test all valid command codes
        assert!(Socks4Command::from_u8(0x01).is_some());
        assert!(Socks4Command::from_u8(0x02).is_some());
        // Test invalid command codes
        assert!(Socks4Command::from_u8(0x00).is_none());
        assert!(Socks4Command::from_u8(0x03).is_none());
        assert!(Socks4Command::from_u8(0xFF).is_none());
    }

    #[tokio::test]
    async fn test_socks4_reply_display() {
        assert_eq!(
            format!("{}", Socks4Reply::RequestGranted),
            "request granted"
        );
        assert_eq!(
            format!("{}", Socks4Reply::RequestRejected),
            "request rejected"
        );
    }
}
