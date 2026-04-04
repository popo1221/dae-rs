//! Trojan server implementation

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::config::TrojanClientConfig;
use crate::handler::{TrojanHandler, TrojanHandlerConfig};

/// Trojan server that listens for connections
pub struct TrojanServer {
    handler: Arc<TrojanHandler>,
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl TrojanServer {
    /// Create a new Trojan server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let config = TrojanHandlerConfig {
            listen_addr: addr,
            ..Default::default()
        };
        Ok(Self {
            handler: Arc::new(TrojanHandler::new(config)),
            listener,
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    pub async fn with_config(config: TrojanClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler_config = TrojanHandlerConfig {
            listen_addr,
            server: config.server,
            tcp_timeout_ms: config.tcp_timeout.as_millis() as u64,
            udp_timeout_ms: config.udp_timeout.as_millis() as u64,
        };
        let handler = Arc::new(TrojanHandler::new(handler_config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// Start the Trojan server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("Trojan server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_connection(client).await {
                            debug!("Trojan connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Trojan accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_server_creation() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // This will fail because we don't have a running Trojan handler setup
        // but it tests the basic structure
        let result = TrojanServer::new(addr).await;
        // We expect this to work since we're binding to port 0
        assert!(result.is_ok());
    }
}
