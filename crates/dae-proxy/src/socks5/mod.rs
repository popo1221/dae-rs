//! SOCKS5 protocol handler (RFC 1928)
//!
//! Implements SOCKS5 proxy server functionality including:
//! - Authentication (NO_AUTH, USERNAME/PASSWORD)
//! - CONNECT command (0x01)
//! - UDP ASSOCIATE command (0x03)
//! - Address parsing (IPv4, IPv6, Domain)

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

pub mod address;
pub mod auth;
pub mod commands;
pub mod handshake;
pub mod relay;
pub mod reply;

// Re-export types for convenience
pub use address::Socks5Address;
pub use auth::{
    AuthHandler, CombinedAuthHandler, NoAuthHandler, UserCredentials, UsernamePasswordHandler,
};
pub use commands::{CommandHandler, Socks5Command};
pub use reply::Socks5Reply;

// Protocol constants
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

pub use consts::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE, GSSAPI,
    NO_ACCEPTABLE, NO_AUTH, REP_ADDRESS_TYPE_NOT_SUPPORTED, REP_COMMAND_NOT_SUPPORTED,
    REP_CONNECTION_NOT_ALLOWED, REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE,
    REP_NETWORK_UNREACHABLE, REP_SUCCESS, REP_TTL_EXPIRED, USERNAME_PASSWORD, VER,
};

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
        let handshake = handshake::Handshake::new(self.config.auth_handler.clone());
        let auth_method = handshake.handle_greeting(&mut client).await?;
        debug!("Selected auth method: {}", auth_method);

        // Phase 2: Authentication (if required)
        if auth_method == consts::USERNAME_PASSWORD {
            handshake.handle_authentication(&mut client).await?;
        } else if auth_method == consts::NO_AUTH {
            // No authentication needed
        } else if auth_method == consts::NO_ACCEPTABLE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "no acceptable authentication method",
            ));
        }

        // Phase 3: Request processing
        let cmd_handler = commands::CommandHandler::new(self.config.tcp_timeout_secs);
        cmd_handler.handle_request(client).await
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
    fn test_socks5_handler_config_default() {
        let config = Socks5HandlerConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Socks5HandlerConfig"));
    }
}
