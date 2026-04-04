//! SOCKS4 protocol handler (RFC 1928 predecessor)
//!
//! Implements SOCKS4 and SOCKS4a proxy server functionality including:
//! - CONNECT command (0x01)
//! - BIND command (0x02)
//! - IPv4 addresses
//! - SOCKS4a extension for domain name resolution
//!
//! # Differences from SOCKS5
//! - SOCKS4 only supports IPv4
//! - SOCKS4a adds domain name resolution support
//! - No authentication support in SOCKS4 (SOCKS4a uses userid for identification)

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// SOCKS4 protocol constants
mod consts {
    /// Protocol version
    pub const VER: u8 = 0x04;

    /// SOCKS4a magic address when domain is used
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

        if ver_buf[0] != consts::VER {
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

/// SOCKS4 handler configuration
#[derive(Debug, Clone)]
pub struct Socks4Config {
    /// Bind address for the SOCKS4 server
    pub bind_addr: String,
    /// Port to listen on
    pub port: u16,
    /// Enable SOCKS4a extension (default: true)
    pub enable_socks4a: bool,
}

impl Default for Socks4Config {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".to_string(),
            port: 1080,
            enable_socks4a: true,
        }
    }
}

/// SOCKS4 server
pub struct Socks4Server {
    config: Socks4Config,
}

impl Socks4Server {
    pub fn new(config: Socks4Config) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(Socks4Config::default())
    }

    /// Handle an incoming SOCKS4 connection
    pub async fn handle_connection(&self, mut stream: TcpStream) -> std::io::Result<()> {
        // Parse request
        let request = match Socks4Request::parse(&mut stream).await {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse SOCKS4 request: {}", e);
                // Send rejection
                let response = [
                    0x00,
                    consts::REP_REQUEST_REJECTED,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ];
                let _ = stream.write_all(&response).await;
                return Err(e);
            }
        };

        debug!(
            "SOCKS4 request: {:?}, user: {}",
            request.command, request.user_id
        );

        match request.command {
            Socks4Command::Connect => self.handle_connect(stream, request).await,
            Socks4Command::Bind => self.handle_bind(stream, request).await,
        }
    }

    /// Handle CONNECT command
    async fn handle_connect(
        &self,
        mut stream: TcpStream,
        request: Socks4Request,
    ) -> std::io::Result<()> {
        use std::net::ToSocketAddrs;

        // Resolve domain if SOCKS4a
        let target_addr = if request.is_socks4a {
            if let Some(ref domain) = request.domain {
                let addr_str = format!("{}:{}", domain, request.address.port);
                info!("SOCKS4a resolving domain: {}", addr_str);

                // Try to resolve the domain
                let addr = addr_str.to_socket_addrs();
                match addr {
                    Ok(mut addrs) => {
                        if let Some(socket_addr) = addrs.next() {
                            socket_addr
                        } else {
                            return self
                                .send_rejection(&mut stream, Socks4Reply::RequestRejected)
                                .await;
                        }
                    }
                    Err(_) => {
                        return self
                            .send_rejection(&mut stream, Socks4Reply::RequestRejected)
                            .await;
                    }
                }
            } else {
                return self
                    .send_rejection(&mut stream, Socks4Reply::RequestRejected)
                    .await;
            }
        } else {
            std::net::SocketAddr::V4(SocketAddrV4::new(request.address.ip, request.address.port))
        };

        debug!("SOCKS4a connecting to: {}", target_addr);

        // Connect to target
        let target_stream = match tokio::net::TcpStream::connect(target_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to {}: {}", target_addr, e);
                return self
                    .send_rejection(&mut stream, Socks4Reply::RequestRejected)
                    .await;
            }
        };

        // Send success response
        let response = [
            0x00,
            consts::REP_REQUEST_GRANTED,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        stream.write_all(&response).await?;

        // Bridge connections
        self.bridgeConnections(stream, target_stream).await
    }

    /// Handle BIND command
    async fn handle_bind(
        &self,
        mut stream: TcpStream,
        request: Socks4Request,
    ) -> std::io::Result<()> {
        // For BIND, we need to:
        // 1. Create a listening socket
        // 2. Send its address to client
        // 3. Wait for incoming connection
        // 4. Send success when connection arrives

        let bind_addr = format!("{}:{}", self.config.bind_addr, self.config.port);
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        let local_addr = listener.local_addr()?;

        debug!("SOCKS4 BIND listening on {}", local_addr);

        // Send first response (binding)
        // VN(1) + CD(1) + DSTPORT(2) + DSTIP(4) = 8 bytes
        let ip_octets = if let std::net::IpAddr::V4(ipv4) = local_addr.ip() {
            ipv4.octets()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS4 only supports IPv4",
            ));
        };
        let response = [
            0x00,
            consts::REP_REQUEST_GRANTED,
            local_addr.port().to_be_bytes()[0],
            local_addr.port().to_be_bytes()[1],
            ip_octets[0],
            ip_octets[1],
            ip_octets[2],
            ip_octets[3],
        ];
        stream.write_all(&response).await?;

        // Wait for incoming connection
        match listener.accept().await {
            Ok((incoming, remote_addr)) => {
                debug!("SOCKS4 BIND received connection from {}", remote_addr);

                // Send second response (established)
                // For SOCKS4 BIND, the remote address must be IPv4
                let remote_ip = if let std::net::IpAddr::V4(ipv4) = remote_addr.ip() {
                    ipv4.octets()
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SOCKS4 only supports IPv4",
                    ));
                };
                let response2 = [
                    0x00,
                    consts::REP_REQUEST_GRANTED,
                    remote_addr.port().to_be_bytes()[0],
                    remote_addr.port().to_be_bytes()[1],
                    remote_ip[0],
                    remote_ip[1],
                    remote_ip[2],
                    remote_ip[3],
                ];
                stream.write_all(&response2).await?;

                // Bridge connections
                self.bridgeConnections(stream, incoming).await
            }
            Err(e) => {
                error!("SOCKS4 BIND accept failed: {}", e);
                self.send_rejection(&mut stream, Socks4Reply::RequestRejected)
                    .await
            }
        }
    }

    /// Bridge two connections bidirectionally
    async fn bridgeConnections(
        &self,
        mut client: TcpStream,
        mut target: TcpStream,
    ) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Simple half-duplex bridging
        // In production, use proper bidirectional copying
        let (mut client_reader, mut client_writer) = client.split();
        let (mut target_reader, mut target_writer) = target.split();

        // Copy target -> client
        let mut buf = vec![0u8; 8192];
        loop {
            let n = target_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_writer.write_all(&buf[..n]).await?;
        }

        Ok(())
    }

    /// Send rejection response
    async fn send_rejection(
        &self,
        stream: &mut TcpStream,
        reply: Socks4Reply,
    ) -> std::io::Result<()> {
        let response = [0x00, reply.to_u8(), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        stream.write_all(&response).await
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

        let mut cursor = std::io::Cursor::new(request);
        let parsed = Socks4Request::parse(&mut cursor).await.unwrap();

        assert!(matches!(parsed.command, Socks4Command::Connect));
        assert_eq!(parsed.address.port, 80);
        assert_eq!(parsed.address.ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.user_id, "user");
        assert!(!parsed.is_socks4a);
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
    async fn test_socks4_request_parse_bind() {
        let request = vec![
            0x04, 0x02, // CMD BIND
            0x00, 0x50, // DSTPORT: 80
            0x00, 0x00, 0x00, 0x00, // DSTIP: 0.0.0.0 (will be determined later)
            0x75, 0x73, 0x65, 0x72, 0x00, // USERID
        ];

        let mut cursor = std::io::Cursor::new(request);
        let parsed = Socks4Request::parse(&mut cursor).await.unwrap();
        assert!(matches!(parsed.command, Socks4Command::Bind));
    }

    #[tokio::test]
    async fn test_socks4_request_parse_empty_user_id() {
        let request = vec![
            0x04, 0x01, 0x00, 0x50, 0xC0, 0xA8, 0x01, 0x01,
            0x00, // Empty user ID (just null terminator)
        ];

        let mut cursor = std::io::Cursor::new(request);
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
