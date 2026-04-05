//! VMess server implementation
//!
//! Server that listens for VMess connections and handles them using the VMess handler.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{debug, error, info};

use super::config::VmessClientConfig;
use super::handler::VmessHandler;

/// VMess server that listens for connections
///
/// Fully implements VMess AEAD-2022 protocol:
/// - Reads and decrypts VMess AEAD headers using AES-256-GCM
/// - Supports IPv4, IPv6, and domain target addresses
/// - Relays traffic to the configured upstream VMess server
pub struct VmessServer {
    handler: Arc<VmessHandler>,
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl VmessServer {
    /// Create a new VMess server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            handler: Arc::new(VmessHandler::new_default()),
            listener,
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    pub async fn with_config(config: VmessClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(VmessHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        Ok(Self {
            handler,
            listener,
            listen_addr,
        })
    }

    /// Start the VMess server
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("VMess server listening on {}", self.listen_addr);

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(client).await {
                            debug!("VMess connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("VMess accept error: {}", e);
                }
            }
        }
    }
}
