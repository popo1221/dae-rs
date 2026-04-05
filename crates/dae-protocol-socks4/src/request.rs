//! SOCKS4 request handling
//!
//! Contains the SOCKS4 request parsing and response writing logic.

use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::protocol::{Socks4Address, Socks4Command, Socks4Reply, VER};

/// SOCKS4 connection request
#[derive(Debug)]
pub struct Socks4Request {
    /// Command (CONNECT or BIND)
    pub command: Socks4Command,
    /// Target address
    pub address: Socks4Address,
    /// User ID
    pub user_id: String,
    /// Whether this is SOCKS4a (domain name included)
    pub is_socks4a: bool,
    /// Domain name (if SOCKS4a)
    pub domain: Option<String>,
}

impl Socks4Request {
    /// Parse a SOCKS4 CONNECT request
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

        // Read DSTPORT (2 bytes)
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        // Read first 3 bytes of DSTIP to check for SOCKS4a
        let mut ip_head = [0u8; 3];
        reader.read_exact(&mut ip_head).await?;
        let is_socks4a = ip_head[0] == 0x00 && ip_head[1] == 0x00 && ip_head[2] == 0x00;

        // Read the 4th byte of DSTIP
        let mut ip_tail = [0u8; 1];
        reader.read_exact(&mut ip_tail).await?;

        // For SOCKS4a, the 4th byte (ip_tail) is non-zero and contains the first byte of domain length
        // For SOCKS4, it contains the last octet of the IPv4 address
        let ip_buf: [u8; 4];
        let domain_len: Option<usize>;

        if is_socks4a {
            // SOCKS4a: IP is 0.0.0.X where X != 0
            // After this comes the domain as a null-terminated string
            if ip_tail[0] == 0x00 {
                // This is actually a pure SOCKS4 request with IP 0.0.0.0
                // Should not happen normally
                ip_buf = [0x00, 0x00, 0x00, 0x00];
                domain_len = None;
            } else {
                // ip_tail[0] is the domain length
                domain_len = Some(ip_tail[0] as usize);
                ip_buf = [0x00, 0x00, 0x00, ip_tail[0]]; // Store as marker
            }
        } else {
            ip_buf = [ip_head[0], ip_head[1], ip_head[2], ip_tail[0]];
            domain_len = None;
        }

        // Parse user ID (null-terminated string)
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

        // For SOCKS4a, parse domain after user ID
        let mut domain = None;
        if is_socks4a {
            if let Some(len) = domain_len {
                // Read the domain bytes
                let mut domain_buf = vec![0u8; len];
                reader.read_exact(&mut domain_buf).await?;
                // Read the null terminator
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

    /// Write response
    pub async fn write_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        reply: Socks4Reply,
        bind_addr: Option<(Ipv4Addr, u16)>,
    ) -> std::io::Result<()> {
        // Response format:
        // VN (1 byte): 0
        // CD (1 byte): reply code
        // DSTPORT (2 bytes): port (if bind) or ignored
        // DSTIP (4 bytes): IP (if bind) or ignored
        writer.write_all(&[0x00]).await?; // VN - null byte
        writer.write_all(&[reply.to_u8()]).await?; // CD

        if let Some((ip, port)) = bind_addr {
            writer.write_all(&port.to_be_bytes()).await?;
            writer.write_all(&ip.octets()).await?;
        } else {
            writer.write_all(&[0x00, 0x00]).await?; // DSTPORT
            writer.write_all(&[0x00, 0x00, 0x00, 0x00]).await?; // DSTIP
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
        // Build a minimal SOCKS4 CONNECT request
        let request = vec![
            0x04, // VER
            0x01, // CMD CONNECT
            0x00, 0x50, // DSTPORT: 80
            0xC0, 0xA8, 0x01, 0x01, // DSTIP: 192.168.1.1
            0x75, 0x73, 0x65, 0x72, 0x00, // USERID: "user" + null
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
            0x04, 0x02, // CMD BIND
            0x00, 0x50, // DSTPORT: 80
            0x00, 0x00, 0x00, 0x00, // DSTIP: 0.0.0.0 (will be determined later)
            0x75, 0x73, 0x65, 0x72, 0x00, // USERID
        ];

        let mut cursor = Cursor::new(request);
        let parsed = Socks4Request::parse(&mut cursor).await.unwrap();
        assert!(matches!(parsed.command, Socks4Command::Bind));
    }

    #[tokio::test]
    async fn test_socks4_request_parse_empty_user_id() {
        let request = vec![
            0x04, 0x01, 0x00, 0x50, 0xC0, 0xA8, 0x01, 0x01,
            0x00, // Empty user ID (just null terminator)
        ];

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
