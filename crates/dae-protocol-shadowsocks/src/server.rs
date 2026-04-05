//! Shadowsocks server implementation
//!
//! Implements the server side that listens for Shadowsocks connections.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, error, info};

use super::config::SsClientConfig;
use super::handler::ShadowsocksHandler;

/// Shadowsocks server that listens for connections
pub struct ShadowsocksServer {
    handler: Arc<ShadowsocksHandler>,
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl ShadowsocksServer {
    /// Create a new Shadowsocks server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(ShadowsocksHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    pub async fn with_config(config: SsClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(ShadowsocksHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// Start the Shadowsocks server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("Shadowsocks server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("Shadowsocks connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Shadowsocks accept error: {}", e);
                }
            }
        }
    }
}
