//! SOCKS5 handler and server types

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use super::auth::CombinedAuthHandler;
use super::commands::CommandHandler;
use super::handshake::Handshake;

/// SOCKS5 connection handler configuration
#[derive(Clone)]
pub struct Socks5HandlerConfig {
    /// Authentication handler
    pub auth_handler: Arc<dyn super::auth::AuthHandler>,
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
        use tracing::debug;

        // Phase 1: Greeting and authentication method selection
        let handshake = Handshake::new(self.config.auth_handler.clone());
        let auth_method = handshake.handle_greeting(&mut client).await?;
        debug!("Selected auth method: {}", auth_method);

        // Phase 2: Authentication (if required)
        if auth_method == super::consts::USERNAME_PASSWORD {
            handshake.handle_authentication(&mut client).await?;
        } else if auth_method == super::consts::NO_AUTH {
            // No authentication needed
        } else if auth_method == super::consts::NO_ACCEPTABLE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "no acceptable authentication method",
            ));
        }

        // Phase 3: Request processing
        let cmd_handler = CommandHandler::new(self.config.tcp_timeout_secs);
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
