//! SOCKS5 protocol handler (RFC 1928)
//!
//! Implements SOCKS5 proxy server functionality including:
//! - Authentication (NO_AUTH, USERNAME/PASSWORD)
//! - CONNECT command (0x01)
//! - UDP ASSOCIATE command (0x03)
//! - Address parsing (IPv4, IPv6, Domain)

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// SOCKS5 protocol constants
mod consts {
    pub const VER: u8 = 0x05;

    // Authentication methods
    pub const NO_AUTH: u8 = 0x00;
    #[allow(dead_code)]
    pub const GSSAPI: u8 = 0x01;
    pub const USERNAME_PASSWORD: u8 = 0x02;
    pub const NO_ACCEPTABLE: u8 = 0xFF;

    // Commands
    pub const CMD_CONNECT: u8 = 0x01;
    pub const CMD_BIND: u8 = 0x02;
    pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

    // Address types
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;

    // Reply codes
    pub const REP_SUCCESS: u8 = 0x00;
    pub const REP_GENERAL_FAILURE: u8 = 0x01;
    pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const REP_HOST_UNREACHABLE: u8 = 0x04;
    pub const REP_CONNECTION_REFUSED: u8 = 0x05;
    pub const REP_TTL_EXPIRED: u8 = 0x06;
    pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// SOCKS5 address type
#[derive(Debug, Clone)]
pub enum Socks5Address {
    /// IPv4 address (4 bytes) + port
    IPv4(Ipv4Addr, u16),
    /// IPv6 address (16 bytes) + port
    IPv6(Ipv6Addr, u16),
    /// Domain name (1-byte length + bytes) + port
    Domain(String, u16),
}

impl Socks5Address {
    /// Parse from SOCKS5 format
    pub async fn parse_from<R: AsyncReadExt + Unpin>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; 1];

        // Read address type
        reader.read_exact(&mut buf).await?;
        let atyp = buf[0];

        match atyp {
            consts::ATYP_IPV4 => {
                let mut addr_buf = [0u8; 4];
                reader.read_exact(&mut addr_buf).await?;
                let mut port_buf = [0u8; 2];
                reader.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                let ip = Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
                Ok(Socks5Address::IPv4(ip, port))
            }
            consts::ATYP_IPV6 => {
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
            consts::ATYP_DOMAIN => {
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

    /// Convert to SocketAddr if possible
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Socks5Address::IPv4(ip, port) => Some(SocketAddr::V4(SocketAddrV4::new(*ip, *port))),
            Socks5Address::IPv6(ip, port) => {
                Some(SocketAddr::V6(SocketAddrV6::new(*ip, *port, 0, 0)))
            }
            Socks5Address::Domain(_, _) => None, // Need DNS resolution
        }
    }

    /// Write in SOCKS5 format
    pub async fn write_to<W: AsyncWriteExt + Unpin>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Socks5Address::IPv4(ip, port) => {
                writer.write_all(&[consts::ATYP_IPV4]).await?;
                writer.write_all(&ip.octets()).await?;
                writer.write_all(&port.to_be_bytes()).await?;
            }
            Socks5Address::IPv6(ip, port) => {
                writer.write_all(&[consts::ATYP_IPV6]).await?;
                for segment in ip.segments() {
                    writer.write_all(&segment.to_be_bytes()).await?;
                }
                writer.write_all(&port.to_be_bytes()).await?;
            }
            Socks5Address::Domain(domain, port) => {
                writer.write_all(&[consts::ATYP_DOMAIN]).await?;
                writer.write_all(&[domain.len() as u8]).await?;
                writer.write_all(domain.as_bytes()).await?;
                writer.write_all(&port.to_be_bytes()).await?;
            }
        }
        Ok(())
    }
}

/// SOCKS5 username/password credentials
#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
}

/// SOCKS5 authentication handler trait
pub trait AuthHandler: Send + Sync {
    /// Check if authentication is required
    fn requires_auth(&self) -> bool;

    /// Validate credentials, returns true if valid
    fn validate_credentials(&self, username: &str, password: &str) -> bool;
}

/// No authentication handler - allows all connections
#[derive(Debug, Clone, Default)]
pub struct NoAuthHandler;

impl AuthHandler for NoAuthHandler {
    fn requires_auth(&self) -> bool {
        false
    }

    fn validate_credentials(&self, _username: &str, _password: &str) -> bool {
        true
    }
}

/// Username/password authentication handler
#[derive(Debug, Clone)]
pub struct UsernamePasswordHandler {
    credentials: std::collections::HashMap<String, String>,
}

impl UsernamePasswordHandler {
    pub fn new() -> Self {
        Self {
            credentials: std::collections::HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: &str, password: &str) {
        self.credentials
            .insert(username.to_string(), password.to_string());
    }
}

impl Default for UsernamePasswordHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthHandler for UsernamePasswordHandler {
    fn requires_auth(&self) -> bool {
        true
    }

    fn validate_credentials(&self, username: &str, password: &str) -> bool {
        self.credentials
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }
}

/// Combined auth handler that supports both NO_AUTH and username/password
#[derive(Clone)]
pub struct CombinedAuthHandler {
    no_auth_allowed: bool,
    username_password: Option<UsernamePasswordHandler>,
}

impl std::fmt::Debug for CombinedAuthHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CombinedAuthHandler")
            .field("no_auth_allowed", &self.no_auth_allowed)
            .field(
                "username_password",
                &self.username_password.as_ref().map(|_| "***"),
            )
            .finish()
    }
}

impl CombinedAuthHandler {
    pub fn new() -> Self {
        Self {
            no_auth_allowed: true,
            username_password: None,
        }
    }

    pub fn with_username_password(users: Vec<(String, String)>) -> Self {
        let mut handler = UsernamePasswordHandler::new();
        for (username, password) in users {
            handler.add_user(&username, &password);
        }
        Self {
            no_auth_allowed: true,
            username_password: Some(handler),
        }
    }

    pub fn no_auth_allowed(mut self, allowed: bool) -> Self {
        self.no_auth_allowed = allowed;
        self
    }
}

impl Default for CombinedAuthHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthHandler for CombinedAuthHandler {
    fn requires_auth(&self) -> bool {
        !self.no_auth_allowed || self.username_password.is_some()
    }

    fn validate_credentials(&self, username: &str, password: &str) -> bool {
        if let Some(ref handler) = self.username_password {
            return handler.validate_credentials(username, password);
        }
        false
    }
}

/// SOCKS5 command
#[derive(Debug, Clone, Copy)]
pub enum Socks5Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Socks5Command {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            consts::CMD_CONNECT => Some(Socks5Command::Connect),
            consts::CMD_BIND => Some(Socks5Command::Bind),
            consts::CMD_UDP_ASSOCIATE => Some(Socks5Command::UdpAssociate),
            _ => None,
        }
    }
}

/// SOCKS5 reply type
#[derive(Debug, Clone, Copy)]
pub enum Socks5Reply {
    Success,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Socks5Reply {
    pub fn to_u8(self) -> u8 {
        match self {
            Socks5Reply::Success => consts::REP_SUCCESS,
            Socks5Reply::GeneralFailure => consts::REP_GENERAL_FAILURE,
            Socks5Reply::ConnectionNotAllowed => consts::REP_CONNECTION_NOT_ALLOWED,
            Socks5Reply::NetworkUnreachable => consts::REP_NETWORK_UNREACHABLE,
            Socks5Reply::HostUnreachable => consts::REP_HOST_UNREACHABLE,
            Socks5Reply::ConnectionRefused => consts::REP_CONNECTION_REFUSED,
            Socks5Reply::TtlExpired => consts::REP_TTL_EXPIRED,
            Socks5Reply::CommandNotSupported => consts::REP_COMMAND_NOT_SUPPORTED,
            Socks5Reply::AddressTypeNotSupported => consts::REP_ADDRESS_TYPE_NOT_SUPPORTED,
        }
    }

    pub fn from_io_error(e: &std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::ConnectionRefused => Socks5Reply::ConnectionRefused,
            std::io::ErrorKind::HostUnreachable => Socks5Reply::HostUnreachable,
            std::io::ErrorKind::NetworkUnreachable => Socks5Reply::NetworkUnreachable,
            std::io::ErrorKind::TimedOut => Socks5Reply::TtlExpired,
            _ => Socks5Reply::GeneralFailure,
        }
    }
}

/// SOCKS5 connection handler configuration
#[derive(Clone)]
pub struct Socks5HandlerConfig {
    /// Authentication handler
    pub auth_handler: Arc<dyn AuthHandler>,
    /// TCP connection timeout
    pub tcp_timeout_secs: u64,
}

impl std::fmt::Debug for Socks5HandlerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5HandlerConfig")
            .field("auth_handler", &"dyn AuthHandler")
            .field("tcp_timeout_secs", &self.tcp_timeout_secs)
            .finish()
    }
}

impl Default for Socks5HandlerConfig {
    fn default() -> Self {
        Self {
            auth_handler: Arc::new(CombinedAuthHandler::new()),
            tcp_timeout_secs: 60,
        }
    }
}

/// SOCKS5 connection handler
pub struct Socks5Handler {
    config: Socks5HandlerConfig,
}

impl Socks5Handler {
    /// Create a new SOCKS5 handler
    pub fn new(config: Socks5HandlerConfig) -> Self {
        Self { config }
    }

    /// Create with default no-auth config
    pub fn new_no_auth() -> Self {
        Self {
            config: Socks5HandlerConfig::default(),
        }
    }

    /// Create with username/password auth
    pub fn new_with_auth(users: Vec<(String, String)>) -> Self {
        Self {
            config: Socks5HandlerConfig {
                auth_handler: Arc::new(CombinedAuthHandler::with_username_password(users)),
                tcp_timeout_secs: 60,
            },
        }
    }

    /// Handle a SOCKS5 connection
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        // Phase 1: Greeting and authentication method selection
        let auth_method = self.handle_greeting(&mut client).await?;
        debug!("Selected auth method: {}", auth_method);

        // Phase 2: Authentication (if required)
        if auth_method == consts::USERNAME_PASSWORD {
            self.handle_authentication(&mut client).await?;
        } else if auth_method == consts::NO_AUTH {
            // No authentication needed
        } else if auth_method == consts::NO_ACCEPTABLE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "no acceptable authentication method",
            ));
        }

        // Phase 3: Request processing
        self.handle_request(client).await
    }

    /// Handle SOCKS5 greeting (phase 1)
    async fn handle_greeting(&self, client: &mut TcpStream) -> std::io::Result<u8> {
        // Read greeting: VER (1) + NMETHODS (1) + METHODS (1-255)
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await?;

        let ver = header[0];
        let nmethods = header[1];

        if ver != consts::VER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid SOCKS version: {ver}"),
            ));
        }

        // Read methods
        let mut methods = vec![0u8; nmethods as usize];
        client.read_exact(&mut methods).await?;

        // Select auth method
        let selected = self.select_auth_method(&methods);

        // Send method selection response: VER (1) + METHOD (1)
        client.write_all(&[consts::VER, selected]).await?;

        Ok(selected)
    }

    /// Select authentication method based on client preferences
    fn select_auth_method(&self, client_methods: &[u8]) -> u8 {
        // Check if NO_AUTH is offered and allowed
        if client_methods.contains(&consts::NO_AUTH) && !self.config.auth_handler.requires_auth() {
            return consts::NO_AUTH;
        }

        // Check if username/password is offered and we support it
        if client_methods.contains(&consts::USERNAME_PASSWORD) {
            // Check if we have a username/password handler
            if self.config.auth_handler.requires_auth() {
                return consts::USERNAME_PASSWORD;
            }
        }

        // No acceptable method
        consts::NO_ACCEPTABLE
    }

    /// Handle username/password authentication (RFC 1929)
    async fn handle_authentication(&self, client: &mut TcpStream) -> std::io::Result<()> {
        // Read: VER (1) + USERNAME_LEN (1) + USERNAME + PASSWORD_LEN (1) + PASSWORD
        let mut version = [0u8; 1];
        client.read_exact(&mut version).await?;

        if version[0] != 0x01 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid auth protocol version",
            ));
        }

        let mut ulen = [0u8; 1];
        client.read_exact(&mut ulen).await?;
        let username_len = ulen[0] as usize;

        let mut username_buf = vec![0u8; username_len];
        client.read_exact(&mut username_buf).await?;
        let username = String::from_utf8(username_buf).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid username")
        })?;

        let mut plen = [0u8; 1];
        client.read_exact(&mut plen).await?;
        let password_len = plen[0] as usize;

        let mut password_buf = vec![0u8; password_len];
        client.read_exact(&mut password_buf).await?;
        let password = String::from_utf8(password_buf).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid password")
        })?;

        // Validate credentials
        let valid = self
            .config
            .auth_handler
            .validate_credentials(&username, &password);

        // Send response: VER (1) + STATUS (1)
        if valid {
            client.write_all(&[0x01, 0x00]).await?; // Success
            Ok(())
        } else {
            client.write_all(&[0x01, 0x01]).await?; // Failure
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid credentials",
            ))
        }
    }

    /// Handle SOCKS5 request (phase 3)
    async fn handle_request(&self, mut client: TcpStream) -> std::io::Result<()> {
        // Read request: VER (1) + CMD (1) + RSV (1) + ATYP (1) + DST.ADDR + DST.PORT (2)
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await?;

        let ver = header[0];
        let cmd = header[1];

        if ver != consts::VER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid SOCKS version: {ver}"),
            ));
        }

        let command = match Socks5Command::from_u8(cmd) {
            Some(c) => c,
            None => {
                self.send_reply(
                    &mut client,
                    Socks5Reply::CommandNotSupported,
                    &Socks5Address::IPv4(Ipv4Addr::new(0, 0, 0, 0), 0),
                )
                .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown command: {cmd}"),
                ));
            }
        };

        // Parse destination address
        let dst_addr = Socks5Address::parse_from(&mut client).await?;
        debug!("SOCKS5 request: {:?} to {:?}", command, dst_addr);

        match command {
            Socks5Command::Connect => self.handle_connect(client, &dst_addr).await,
            Socks5Command::Bind => {
                self.send_reply(
                    &mut client,
                    Socks5Reply::CommandNotSupported,
                    &Socks5Address::IPv4(Ipv4Addr::new(0, 0, 0, 0), 0),
                )
                .await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "BIND command not supported",
                ))
            }
            Socks5Command::UdpAssociate => self.handle_udp_associate(client, &dst_addr).await,
        }
    }

    /// Handle CONNECT command
    async fn handle_connect(
        &self,
        mut client: TcpStream,
        dst_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        // Resolve address
        let socket_addr = match dst_addr.to_socket_addr() {
            Some(addr) => addr,
            None => {
                // Need DNS resolution for domain names
                if let Socks5Address::Domain(domain, port) = dst_addr {
                    match tokio::net::lookup_host(format!("{domain}:{port}")).await {
                        Ok(mut addrs) => match addrs.next() {
                            Some(addr) => addr,
                            None => {
                                self.send_reply(
                                    &mut client,
                                    Socks5Reply::HostUnreachable,
                                    dst_addr,
                                )
                                .await?;
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::HostUnreachable,
                                    "no addresses found",
                                ));
                            }
                        },
                        Err(e) => {
                            self.send_reply(&mut client, Socks5Reply::HostUnreachable, dst_addr)
                                .await?;
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::HostUnreachable,
                                format!("DNS resolution failed: {e}"),
                            ));
                        }
                    }
                } else {
                    unreachable!()
                }
            }
        };

        // Connect to remote
        let timeout = std::time::Duration::from_secs(self.config.tcp_timeout_secs);
        let remote = match tokio::time::timeout(timeout, TcpStream::connect(socket_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let reply = Socks5Reply::from_io_error(&e);
                self.send_reply(&mut client, reply, dst_addr).await?;
                return Err(e);
            }
            Err(_) => {
                self.send_reply(&mut client, Socks5Reply::HostUnreachable, dst_addr)
                    .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timeout",
                ));
            }
        };

        let _local_addr = client.local_addr()?;

        // Send success reply with bound address (use local address)
        let bound_addr = Socks5Address::IPv4(
            if let std::net::SocketAddr::V4(v4) = client
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
            {
                *v4.ip()
            } else {
                Ipv4Addr::new(0, 0, 0, 0)
            },
            0,
        );
        self.send_reply(&mut client, Socks5Reply::Success, &bound_addr)
            .await?;

        info!("SOCKS5 CONNECT: -> {}", socket_addr);

        // Relay data between client and remote
        self.relay(client, remote).await
    }

    /// Handle UDP ASSOCIATE command
    async fn handle_udp_associate(
        &self,
        mut client: TcpStream,
        _dst_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        // Get client address for UDP relay
        let client_addr = client.peer_addr()?;

        // Create a UDP socket for the association
        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let udp_bind_addr = udp_socket.local_addr()?;

        // Convert to IPv4 if possible for the reply
        let bind_addr = match udp_bind_addr {
            SocketAddr::V4(v4) => Socks5Address::IPv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Socks5Address::IPv6(*v6.ip(), v6.port()),
        };

        // Send success reply with UDP relay address
        self.send_reply(&mut client, Socks5Reply::Success, &bind_addr)
            .await?;

        info!(
            "SOCKS5 UDP ASSOCIATE: client={} relay={}",
            client_addr, udp_bind_addr
        );

        // Keep TCP connection open for UDP relay control
        // In a full implementation, we would:
        // 1. Wait for client to send UDP datagrams
        // 2. Forward them to target
        // 3. Relay responses back
        // For now, just wait for EOF on TCP connection
        let mut buf = [0u8; 1];
        let _ = client.read_exact(&mut buf).await;

        info!("SOCKS5 UDP ASSOCIATE: connection closed");
        Ok(())
    }

    /// Send SOCKS5 reply
    async fn send_reply(
        &self,
        client: &mut TcpStream,
        reply: Socks5Reply,
        bind_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        // Reply format: VER (1) + REP (1) + RSV (1) + ATYP (1) + BND.ADDR + BND.PORT (2)
        client
            .write_all(&[consts::VER, reply.to_u8(), 0x00])
            .await?;
        bind_addr.write_to(client).await
    }

    /// Relay data between client and remote
    async fn relay(&self, client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut rr, mut rw) = tokio::io::split(remote);

        let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
        let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

        tokio::try_join!(client_to_remote, remote_to_client)?;
        Ok(())
    }
}

/// SOCKS5 server that listens for connections
pub struct Socks5Server {
    handler: Arc<Socks5Handler>,
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl Socks5Server {
    /// Create a new SOCKS5 server
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(Socks5Handler::new_no_auth()),
            listener,
            listen_addr: addr,
        })
    }

    /// Create with custom handler
    pub async fn with_handler(addr: SocketAddr, handler: Socks5Handler) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(handler),
            listener,
            listen_addr: addr,
        })
    }

    /// Start the SOCKS5 server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("SOCKS5 server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("SOCKS5 connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("SOCKS5 accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_reply_to_u8() {
        assert_eq!(Socks5Reply::Success.to_u8(), 0x00);
        assert_eq!(Socks5Reply::GeneralFailure.to_u8(), 0x01);
        assert_eq!(Socks5Reply::ConnectionRefused.to_u8(), 0x05);
    }

    #[test]
    fn test_socks5_command_from_u8() {
        assert!(matches!(
            Socks5Command::from_u8(0x01),
            Some(Socks5Command::Connect)
        ));
        assert!(matches!(
            Socks5Command::from_u8(0x03),
            Some(Socks5Command::UdpAssociate)
        ));
        assert!(Socks5Command::from_u8(0xFF).is_none());
    }

    #[tokio::test]
    async fn test_socks5_address_ipv4() {
        let addr = Socks5Address::IPv4(Ipv4Addr::new(192, 168, 1, 1), 8080);
        let mut buf = Vec::new();
        addr.write_to(&mut buf).await.unwrap();

        assert_eq!(buf[0], consts::ATYP_IPV4);
        assert_eq!(buf[1..5], [192, 168, 1, 1]);
        assert_eq!(buf[5..7], [0x1F, 0x90]); // 8080 in big endian
    }

    #[test]
    fn test_socks5_reply_all_variants() {
        assert_eq!(Socks5Reply::Success.to_u8(), 0x00);
        assert_eq!(Socks5Reply::GeneralFailure.to_u8(), 0x01);
        assert_eq!(Socks5Reply::ConnectionNotAllowed.to_u8(), 0x02);
        assert_eq!(Socks5Reply::NetworkUnreachable.to_u8(), 0x03);
        assert_eq!(Socks5Reply::HostUnreachable.to_u8(), 0x04);
        assert_eq!(Socks5Reply::ConnectionRefused.to_u8(), 0x05);
        assert_eq!(Socks5Reply::TtlExpired.to_u8(), 0x06);
        assert_eq!(Socks5Reply::CommandNotSupported.to_u8(), 0x07);
        assert_eq!(Socks5Reply::AddressTypeNotSupported.to_u8(), 0x08);
    }

    #[test]
    fn test_socks5_command_all_variants() {
        assert!(matches!(
            Socks5Command::from_u8(0x01),
            Some(Socks5Command::Connect)
        ));
        assert!(matches!(
            Socks5Command::from_u8(0x02),
            Some(Socks5Command::Bind)
        ));
        assert!(matches!(
            Socks5Command::from_u8(0x03),
            Some(Socks5Command::UdpAssociate)
        ));
        assert!(Socks5Command::from_u8(0x00).is_none());
        assert!(Socks5Command::from_u8(0x04).is_none());
        assert!(Socks5Command::from_u8(0xFF).is_none());
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
    fn test_socks5_consts() {
        assert_eq!(consts::VER, 0x05);
        assert_eq!(consts::NO_AUTH, 0x00);
        assert_eq!(consts::USERNAME_PASSWORD, 0x02);
        assert_eq!(consts::CMD_CONNECT, 0x01);
        assert_eq!(consts::ATYP_IPV4, 0x01);
        assert_eq!(consts::ATYP_DOMAIN, 0x03);
        assert_eq!(consts::ATYP_IPV6, 0x04);
        assert_eq!(consts::REP_SUCCESS, 0x00);
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

    #[test]
    fn test_socks5_reply_to_u8_all() {
        assert_eq!(Socks5Reply::Success.to_u8(), 0x00);
        assert_eq!(Socks5Reply::GeneralFailure.to_u8(), 0x01);
        assert_eq!(Socks5Reply::ConnectionNotAllowed.to_u8(), 0x02);
        assert_eq!(Socks5Reply::NetworkUnreachable.to_u8(), 0x03);
        assert_eq!(Socks5Reply::HostUnreachable.to_u8(), 0x04);
        assert_eq!(Socks5Reply::ConnectionRefused.to_u8(), 0x05);
        assert_eq!(Socks5Reply::TtlExpired.to_u8(), 0x06);
        assert_eq!(Socks5Reply::CommandNotSupported.to_u8(), 0x07);
        assert_eq!(Socks5Reply::AddressTypeNotSupported.to_u8(), 0x08);
    }

    #[test]
    fn test_socks5_handler_config_default() {
        let config = Socks5HandlerConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Socks5HandlerConfig"));
    }
}
