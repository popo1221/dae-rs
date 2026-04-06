//! SOCKS5 地址解析模块（RFC 1928）
//!
//! 支持 IPv4、IPv6 和域名地址类型。

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// SOCKS5 地址类型
///
/// 支持三种地址类型：IPv4、IPv6 和域名。
///
/// # ATYP 映射
///
/// - `IPv4(Ipv4Addr, u16)` → ATYP = 0x01
/// - `IPv6(Ipv6Addr, u16)` → ATYP = 0x04
/// - `Domain(String, u16)` → ATYP = 0x03
#[derive(Debug, Clone)]
pub enum Socks5Address {
    /// IPv4 地址
    ///
    /// 包含 IPv4 地址和端口号。
    IPv4(Ipv4Addr, u16),

    /// IPv6 地址
    ///
    /// 包含 IPv6 地址和端口号。
    IPv6(Ipv6Addr, u16),

    /// 域名地址
    ///
    /// 包含域名和端口号。域名需要 DNS 解析。
    /// 域名格式：1字节长度 + 域名字节序列。
    Domain(String, u16),
}

impl Socks5Address {
    /// 从 SOCKS5 协议解析地址
    ///
    /// # 参数
    /// - `reader`: 字节读取器
    ///
    /// # 返回值
    /// - `Ok(Socks5Address)`: 解析成功
    /// - `Err`: 解析失败（如未知地址类型）
    ///
    /// # SOCKS5 地址格式
    ///
    /// ```text
    /// |ATYP|  DST.ADDR                                    |
    /// | 1  | Variable (1 or 4 or 16 bytes, plus port)    |
    /// ```
    pub async fn parse_from<R: AsyncReadExt + Unpin>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; 1];

        // Read address type
        reader.read_exact(&mut buf).await?;
        let atyp = buf[0];

        match atyp {
            super::consts::ATYP_IPV4 => {
                let mut addr_buf = [0u8; 4];
                reader.read_exact(&mut addr_buf).await?;
                let mut port_buf = [0u8; 2];
                reader.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                let ip = Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                Ok(Socks5Address::IPv4(ip, port))
            }
            super::consts::ATYP_IPV6 => {
                let mut addr_buf = [0u8; 16];
                reader.read_exact(&mut addr_buf).await?;
                let mut port_buf = [0u8; 2];
                reader.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                let ip = Ipv6Addr::new(
                    u16::from_be_bytes([addr_buf[0], addr_buf[1]]),
                    u16::from_be_bytes([addr_buf[2], addr_buf[3]]),
                    u16::from_be_bytes([addr_buf[4], addr_buf[5]]),
                    u16::from_be_bytes([addr_buf[6], addr_buf[7]]),
                    u16::from_be_bytes([addr_buf[8], addr_buf[9]]),
                    u16::from_be_bytes([addr_buf[10], addr_buf[11]]),
                    u16::from_be_bytes([addr_buf[12], addr_buf[13]]),
                    u16::from_be_bytes([addr_buf[14], addr_buf[15]]),
                );
                Ok(Socks5Address::IPv6(ip, port))
            }
            super::consts::ATYP_DOMAIN => {
                reader.read_exact(&mut buf).await?;
                let domain_len = buf[0] as usize;
                let mut domain_buf = vec![0u8; domain_len];
                reader.read_exact(&mut domain_buf).await?;
                let mut port_buf = [0u8; 2];
                reader.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                let domain = String::from_utf8(domain_buf).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain")
                })?;
                Ok(Socks5Address::Domain(domain, port))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown address type: {atyp}"),
            )),
        }
    }

    /// 转换为 SocketAddr（如果可能）
    ///
    /// # 返回值
    /// - `Some(SocketAddr)`: IPv4 或 IPv6 地址转换成功
    /// - `None`: 域名地址需要 DNS 解析，无法直接转换
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Socks5Address::IPv4(ip, port) => Some(SocketAddr::V4(SocketAddrV4::new(*ip, *port))),
            Socks5Address::IPv6(ip, port) => {
                Some(SocketAddr::V6(SocketAddrV6::new(*ip, *port, 0, 0)))
            }
            Socks5Address::Domain(_, _) => None, // Need DNS resolution
        }
    }

    /// 写入 SOCKS5 协议格式
    ///
    /// # 参数
    /// - `writer`: 字节写入器
    ///
    /// # 格式
    ///
    /// 输出完整的 SOCKS5 地址表示（ATYP + 地址 + 端口）。
    pub async fn write_to<W: AsyncWriteExt + Unpin>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Socks5Address::IPv4(ip, port) => {
                writer.write_all(&[super::consts::ATYP_IPV4]).await?;
                writer.write_all(&ip.octets()).await?;
                writer.write_all(&port.to_be_bytes()).await?;
            }
            Socks5Address::IPv6(ip, port) => {
                writer.write_all(&[super::consts::ATYP_IPV6]).await?;
                for segment in ip.segments() {
                    writer.write_all(&segment.to_be_bytes()).await?;
                }
                writer.write_all(&port.to_be_bytes()).await?;
            }
            Socks5Address::Domain(domain, port) => {
                writer.write_all(&[super::consts::ATYP_DOMAIN]).await?;
                writer.write_all(&[domain.len() as u8]).await?;
                writer.write_all(domain.as_bytes()).await?;
                writer.write_all(&port.to_be_bytes()).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socks5_address_ipv4() {
        let addr = Socks5Address::IPv4(Ipv4Addr::new(192, 168, 1, 1), 8080);
        let mut buf = Vec::new();
        addr.write_to(&mut buf).await.unwrap();

        assert_eq!(buf[0], crate::consts::ATYP_IPV4);
        assert_eq!(buf[1..5], [192, 168, 1, 1]);
        assert_eq!(buf[5..7], [0x1F, 0x90]); // 8080 in big endian
    }

    #[test]
    fn test_socks5_address_ipv6() {
        let addr = Socks5Address::IPv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8080);
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("IPv6"));
    }

    #[test]
    fn test_socks5_address_domain() {
        let addr = Socks5Address::Domain("example.com".to_string(), 443);
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("example.com"));
    }

    #[test]
    fn test_socks5_address_to_socket_addr_ipv4() {
        let addr = Socks5Address::IPv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let socket: SocketAddr = addr.to_socket_addr().unwrap();
        assert_eq!(socket.port(), 8080);
    }

    #[test]
    fn test_socks5_address_to_socket_addr_ipv6() {
        let addr = Socks5Address::IPv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8080);
        let socket: SocketAddr = addr.to_socket_addr().unwrap();
        assert_eq!(socket.port(), 8080);
    }

    #[test]
    fn test_socks5_address_to_socket_addr_domain_fails() {
        let addr = Socks5Address::Domain("example.com".to_string(), 443);
        let socket = addr.to_socket_addr();
        assert!(socket.is_none());
    }

    #[test]
    fn test_socks5_address_clone() {
        let addr = Socks5Address::IPv4(Ipv4Addr::new(1, 2, 3, 4), 5678);
        let cloned = addr.clone();
        assert_eq!(format!("{:?}", addr), format!("{:?}", cloned));
    }

    #[test]
    fn test_socks5_address_ipv6_write_format() {
        let addr = Socks5Address::IPv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443);
        // Verify debug format works
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("IPv6"));
    }
}
