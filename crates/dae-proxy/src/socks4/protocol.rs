//! SOCKS4 protocol types and constants
//!
//! Contains the core protocol definitions for SOCKS4 and SOCKS4a.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::io::AsyncReadExt;
use tracing::debug;

/// SOCKS4 protocol constants
mod consts {
    /// Protocol version
    pub const VER: u8 = 0x04;

    /// SOCKS4a magic address when domain is used
    #[allow(dead_code)]
    pub const SOCKS4A_MAGIC_IP: [u8; 3] = [0x00, 0x00, 0x00];

    /// Commands
    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;

    /// Response codes
    pub const REP_REQUEST_GRANTED: u8 = 0x5A;
    pub const REP_REQUEST_REJECTED: u8 = 0x5B;
    pub const REP_REQUEST_FAILED: u8 = 0x5C; // Identd not running
    pub const REP_REQUEST_FAILED_USER: u8 = 0x5D; // User id mismatch
}

// Re-export constants for use in other modules
#[allow(unused_imports)]
pub use consts::{
    CMD_BIND, CMD_CONNECT, REP_REQUEST_FAILED, REP_REQUEST_FAILED_USER, REP_REQUEST_GRANTED,
    REP_REQUEST_REJECTED, SOCKS4A_MAGIC_IP, VER,
};

/// SOCKS4 command
#[derive(Debug, Clone, Copy)]
pub enum Socks4Command {
    Connect,
    Bind,
}

impl Socks4Command {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            consts::CMD_CONNECT => Some(Socks4Command::Connect),
            consts::CMD_BIND => Some(Socks4Command::Bind),
            _ => None,
        }
    }
}

/// SOCKS4 response code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks4Reply {
    RequestGranted,
    RequestRejected,
    RequestFailedIdentd,
    RequestFailedUserId,
}

impl Socks4Reply {
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

/// SOCKS4 address type (IPv4 only)
#[derive(Debug, Clone)]
pub struct Socks4Address {
    /// IPv4 address
    pub ip: Ipv4Addr,
    /// Port
    pub port: u16,
}

impl Socks4Address {
    /// Parse from SOCKS4 request format
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

    /// Convert to SocketAddr
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
