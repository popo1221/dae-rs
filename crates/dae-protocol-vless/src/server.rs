//! VLESS server implementation
//!
//! Server that listens for VLESS connections.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::config::VlessClientConfig;
use crate::handler::VlessHandler;

/// VLESS server that listens for connections
pub struct VlessServer {
    handler: Arc<VlessHandler>,
    listener: TcpListener,
    udp_socket: Arc<Mutex<Option<UdpSocket>>>,
    listen_addr: SocketAddr,
}

impl VlessServer {
    /// Create a new VLESS server
    #[allow(dead_code)]
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let udp_socket = Arc::new(Mutex::new(UdpSocket::bind(addr).await.ok()));
        Ok(Self {
            handler: Arc::new(VlessHandler::new_default()),
            listener,
            udp_socket,
            listen_addr: addr,
        })
    }

    /// Create with custom configuration
    pub async fn with_config(config: VlessClientConfig) -> std::io::Result<Self> {
        let listen_addr = config.listen_addr;
        let handler = Arc::new(VlessHandler::new(config));
        let listener = TcpListener::bind(listen_addr).await?;
        let udp_socket = Arc::new(Mutex::new(UdpSocket::bind(listen_addr).await.ok()));
        Ok(Self {
            handler,
            listener,
            udp_socket,
            listen_addr,
        })
    }

    /// Start the VLESS server
    #[allow(dead_code)]
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        info!("VLESS server listening on {}", self.listen_addr);

        let maybe_socket = {
            let mut guard = self.udp_socket.lock().await;
            guard.take()
        };

        if let Some(socket) = maybe_socket {
            let handler = self.handler.clone();
            tokio::spawn(async move {
                let _ = handler.handle_udp(Arc::new(socket)).await;
            });
            info!("VLESS UDP server listening on {}", self.listen_addr);
        }

        loop {
            match self.listener.accept().await {
                Ok((client, addr)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_vless(client).await {
                            debug!("VLESS connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("VLESS accept error: {}", e);
                }
            }
        }
    }
}
