//! SOCKS4 请求处理模块
//!
//! 包含 SOCKS4 请求解析和响应写入逻辑。

use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::protocol::{Socks4Address, Socks4Command, Socks4Reply, VER};

/// SOCKS4 连接请求
///
/// 包含解析后的 SOCKS4 请求的所有信息。
#[derive(Debug)]
pub struct Socks4Request {
    /// 命令类型（CONNECT 或 BIND）
    pub command: Socks4Command,
    /// 目标地址
    pub address: Socks4Address,
    /// 用户 ID（用于认证）
    pub user_id: String,
    /// 是否为 SOCKS4a 请求（包含域名）
    pub is_socks4a: bool,
    /// 域名（仅 SOCKS4a 请求有值）
    pub domain: Option<String>,
}

impl Socks4Request {
    /// 解析 SOCKS4 请求
    ///
    /// 从字节流中解析完整的 SOCKS4 请求。
    ///
    /// # 参数
    /// - `reader`: 字节读取器
    ///
    /// # 返回值
    /// - `Ok(Socks4Request)`: 解析成功
    /// - `Err`: 解析失败（版本错误、命令无效等）
    ///
    /// # SOCKS4 请求格式
    ///
    /// - VN: 版本号（必须为 0x04）
    /// - CD: 命令码（0x01=CONNECT, 0x02=BIND）
    /// - DSTPORT: 目标端口（2字节，大端序）
    /// - DSTIP: 目标 IP（4字节）
    /// - USERID: 用户 ID（变长，null 结尾）
    ///
    /// # SOCKS4a 请求格式（扩展）
    ///
    /// 当 DSTIP 前三个字节为 0.0.0 且第四个字节非零时，需要额外解析域名。
    pub async fn parse<R: AsyncReadExt + Unpin>(reader: &mut R) -> std::io::Result<Self> {
        let mut ver_buf = [0u8; 1];
        reader.read_exact(&mut ver_buf).await?;

        if ver_buf[0] != VER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid SOCKS4 version: {}", ver_buf[0]),
            ));
        }

        let mut cmd_buf = [0u8; 1];
        reader.read_exact(&mut cmd_buf).await?;
        let command = Socks4Command::from_u8(cmd_buf[0]).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid command")
        })?;

        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        let mut ip_head = [0u8; 3];
        reader.read_exact(&mut ip_head).await?;
        let is_socks4a = ip_head[0] == 0x00 && ip_head[1] == 0x00 && ip_head[2] == 0x00;

        let mut ip_tail = [0u8; 1];
        reader.read_exact(&mut ip_tail).await?;

        let ip_buf: [u8; 4];
        let domain_len: Option<usize>;

        if is_socks4a {
            if ip_tail[0] == 0x00 {
                ip_buf = [0x00, 0x00, 0x00, 0x00];
                domain_len = None;
            } else {
                domain_len = Some(ip_tail[0] as usize);
                ip_buf = [0x00, 0x00, 0x00, ip_tail[0]];
            }
        } else {
            ip_buf = [ip_head[0], ip_head[1], ip_head[2], ip_tail[0]];
            domain_len = None;
        }

        let mut user_buf = Vec::new();
        let mut b = [0u8; 1];
        loop {
            reader.read_exact(&mut b).await?;
            if b[0] == 0x00 {
                break;
            }
            user_buf.push(b[0]);
        }
        let user_id = String::from_utf8(user_buf)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid user_id"))?;

        let mut domain = None;
        if is_socks4a {
            if let Some(len) = domain_len {
                let mut domain_buf = vec![0u8; len];
                reader.read_exact(&mut domain_buf).await?;
                let mut null_byte = [0u8; 1];
                reader.read_exact(&mut null_byte).await?;
                domain = Some(String::from_utf8(domain_buf).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain")
                })?);
            }
        }

        let ip = Ipv4Addr::new(ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]);
        let address = Socks4Address { ip, port };

        Ok(Socks4Request {
            command,
            address,
            user_id,
            is_socks4a,
            domain,
        })
    }

    /// 写入响应
    ///
    /// 将 SOCKS4 响应写入字节流。
    ///
    /// # 参数
    /// - `writer`: 字节写入器
    /// - `reply`: 响应状态
    /// - `bind_addr`: 绑定地址（仅 BIND 命令需要）
    ///
    /// # SOCKS4 响应格式
    ///
    /// - VN: 版本号（固定为 0x00）
    /// - CD: 响应码
    /// - DSTPORT: 端口（如果 BIND，则为绑定端口）
    /// - DSTIP: IP 地址（如果 BIND，则为绑定 IP）
    pub async fn write_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        reply: Socks4Reply,
        bind_addr: Option<(Ipv4Addr, u16)>,
    ) -> std::io::Result<()> {
        writer.write_all(&[0x00]).await?;
        writer.write_all(&[reply.to_u8()]).await?;

        if let Some((ip, port)) = bind_addr {
            writer.write_all(&port.to_be_bytes()).await?;
            writer.write_all(&ip.octets()).await?;
        } else {
            writer.write_all(&[0x00, 0x00]).await?;
            writer.write_all(&[0x00, 0x00, 0x00, 0x00]).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_socks4_request_parse_connect() {
        let request = vec![
            0x04, 0x01, 0x00, 0x50, 0xC0, 0xA8, 0x01, 0x01, 0x75, 0x73, 0x65, 0x72, 0x00,
        ];

        let mut cursor = Cursor::new(request);
        let parsed = Socks4Request::parse(&mut cursor).await.unwrap();

        assert!(matches!(parsed.command, Socks4Command::Connect));
        assert_eq!(parsed.address.port, 80);
        assert_eq!(parsed.address.ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.user_id, "user");
        assert!(!parsed.is_socks4a);
    }

    #[tokio::test]
    async fn test_socks4_request_parse_bind() {
        let request = vec![
            0x04, 0x02, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00,
        ];

        let mut cursor = Cursor::new(request);
        let parsed = Socks4Request::parse(&mut cursor).await.unwrap();
        assert!(matches!(parsed.command, Socks4Command::Bind));
    }

    #[tokio::test]
    async fn test_socks4_request_parse_empty_user_id() {
        let request = vec![0x04, 0x01, 0x00, 0x50, 0xC0, 0xA8, 0x01, 0x01, 0x00];

        let mut cursor = Cursor::new(request);
        let parsed = Socks4Request::parse(&mut cursor).await.unwrap();
        assert_eq!(parsed.user_id, "");
    }

    #[test]
    fn test_socks4_request_debug_repr() {
        let request = Socks4Request {
            command: Socks4Command::Connect,
            address: Socks4Address {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                port: 443,
            },
            user_id: "admin".to_string(),
            is_socks4a: false,
            domain: None,
        };
        let repr = format!("{:?}", request);
        assert!(repr.contains("Connect"));
        assert!(repr.contains("10.0.0.1"));
    }
}
