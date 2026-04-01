//! Proxy core implementation
//!
//! Main entry point for the proxy subsystem that coordinates TCP/UDP relays
//! and integrates with eBPF maps.

use crate::connection_pool::{new_connection_pool, SharedConnectionPool};
use crate::ebpf_integration::{EbpfMaps, EbpfRoutingHandle, EbpfSessionHandle, EbpfStatsHandle};
use crate::protocol_dispatcher::{CombinedProxyServer, ProtocolDispatcherConfig};
use crate::shadowsocks::{ShadowsocksHandler, ShadowsocksServer};
use crate::tcp::{TcpProxy, TcpProxyConfig};
use crate::udp::{UdpProxy, UdpProxyConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info, warn};

/// Proxy error types
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("TCP proxy error: {0}")]
    TcpError(String),
    #[error("UDP proxy error: {0}")]
    UdpError(String),
    #[error("eBPF error: {0}")]
    EbpfError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Shutdown error: {0}")]
    ShutdownError(String),
    #[error("Shadowsocks error: {0}")]
    ShadowsocksError(String),
}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        ProxyError::ConfigError(e.to_string())
    }
}

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// TCP proxy configuration
    pub tcp: TcpProxyConfig,
    /// UDP proxy configuration
    pub udp: UdpProxyConfig,
    /// eBPF configuration
    pub ebpf: EbpfConfig,
    /// Connection pool settings
    pub pool: ConnectionPoolConfig,
    /// XDP object path
    pub xdp_object: PathBuf,
    /// XDP interface
    pub xdp_interface: String,
    /// SOCKS5 listen address (None to disable)
    pub socks5_listen: Option<SocketAddr>,
    /// HTTP proxy listen address (None to disable)
    pub http_listen: Option<SocketAddr>,
    /// HTTP proxy authentication (username, password) - None to disable auth
    pub http_auth: Option<(String, String)>,
    /// Shadowsocks listen address (None to disable)
    pub ss_listen: Option<SocketAddr>,
    /// Shadowsocks server configuration (None to disable)
    pub ss_server: Option<super::shadowsocks::SsServerConfig>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            tcp: TcpProxyConfig::default(),
            udp: UdpProxyConfig::default(),
            ebpf: EbpfConfig::default(),
            pool: ConnectionPoolConfig::default(),
            xdp_object: PathBuf::from("bpf/dae-xdp.o"),
            xdp_interface: String::from("eth0"),
            socks5_listen: Some(SocketAddr::from(([127, 0, 0, 1], 1080))),
            http_listen: Some(SocketAddr::from(([127, 0, 0, 1], 8080))),
            http_auth: None,
            ss_listen: None,
            ss_server: None,
        }
    }
}

/// eBPF configuration
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    /// Enable eBPF integration
    pub enabled: bool,
    /// Session map size
    pub session_map_size: u32,
    /// Routing map size
    pub routing_map_size: u32,
    /// Stats map size
    pub stats_map_size: u32,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_map_size: 65536,
            routing_map_size: 16384,
            stats_map_size: 256,
        }
    }
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// TCP connection timeout
    pub tcp_timeout: Duration,
    /// UDP session timeout
    pub udp_timeout: Duration,
    /// TCP keepalive interval
    pub tcp_keepalive: Duration,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
            tcp_keepalive: Duration::from_secs(10),
        }
    }
}

/// The main Proxy struct that coordinates all proxy components
pub struct Proxy {
    config: ProxyConfig,
    tcp_proxy: Arc<TcpProxy>,
    udp_proxy: Arc<UdpProxy>,
    connection_pool: SharedConnectionPool,
    session_handle: Arc<RwLock<EbpfSessionHandle>>,
    routing_handle: Arc<EbpfRoutingHandle>,
    stats_handle: Arc<RwLock<EbpfStatsHandle>>,
    shutdown_tx: broadcast::Sender<()>,
    running: RwLock<bool>,
    combined_server: Option<Arc<CombinedProxyServer>>,
    shadowsocks_server: Option<Arc<ShadowsocksServer>>,
}

impl Proxy {
    /// Create a new proxy instance
    pub async fn new(config: ProxyConfig) -> std::io::Result<Self> {
        info!("Initializing proxy with config: {:?}", config);

        // Initialize eBPF maps
        let maps = EbpfMaps::new();
        let session_handle = Arc::new(RwLock::new(EbpfSessionHandle::new(maps.clone())));
        let routing_handle = Arc::new(EbpfRoutingHandle::new(maps.clone()));
        let stats_handle = Arc::new(RwLock::new(EbpfStatsHandle::new(maps)));

        // Initialize connection pool
        let connection_pool = new_connection_pool(
            config.pool.tcp_timeout,
            config.pool.udp_timeout,
            config.pool.tcp_keepalive,
        );

        // Create TCP proxy
        let tcp_proxy = Arc::new(TcpProxy::new(
            config.tcp.clone(),
            connection_pool.clone(),
        ));

        // Create UDP proxy
        let udp_proxy = Arc::new(UdpProxy::new(
            config.udp.clone(),
            connection_pool.clone(),
        ));

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);

        // Create combined proxy server if any protocol is enabled
        let combined_server = Self::create_combined_server(&config).await?;

        // Create Shadowsocks server if configured
        let shadowsocks_server = Self::create_shadowsocks_server(&config).await?;

        Ok(Self {
            config,
            tcp_proxy,
            udp_proxy,
            connection_pool,
            session_handle,
            routing_handle,
            stats_handle,
            shutdown_tx,
            running: RwLock::new(false),
            combined_server,
            shadowsocks_server,
        })
    }

    /// Create combined SOCKS5/HTTP proxy server
    async fn create_combined_server(config: &ProxyConfig) -> std::io::Result<Option<Arc<CombinedProxyServer>>> {
        let dispatcher_config = ProtocolDispatcherConfig {
            socks5_addr: config.socks5_listen,
            http_addr: config.http_listen,
        };

        // Check if any protocol is configured
        if dispatcher_config.socks5_addr.is_none() && dispatcher_config.http_addr.is_none() {
            return Ok(None);
        }

        let server = CombinedProxyServer::new(dispatcher_config).await?;
        Ok(Some(Arc::new(server)))
    }

    /// Create Shadowsocks server if configured
    async fn create_shadowsocks_server(config: &ProxyConfig) -> std::io::Result<Option<Arc<ShadowsocksServer>>> {
        if config.ss_listen.is_none() || config.ss_server.is_none() {
            return Ok(None);
        }

        let ss_config = config.ss_server.as_ref().unwrap();
        let ss_listen = config.ss_listen.unwrap();

        let ss_client_config = super::shadowsocks::SsClientConfig {
            listen_addr: ss_listen,
            server: ss_config.clone(),
            tcp_timeout: config.pool.tcp_timeout,
            udp_timeout: config.pool.udp_timeout,
        };

        let server = ShadowsocksServer::with_config(ss_client_config).await?;
        Ok(Some(Arc::new(server)))
    }

    /// Start the proxy
    pub async fn start(self: Arc<Self>) -> std::io::Result<()> {
        {
            let mut running = self.running.write().await;
            if *running {
                warn!("Proxy is already running");
                return Ok(());
            }
            *running = true;
        }

        info!("Starting proxy services...");

        // Start TCP proxy
        let tcp = self.tcp_proxy.clone();
        let tcp_handle = tokio::spawn(async move {
            if let Err(e) = tcp.start().await {
                error!("TCP proxy error: {}", e);
            }
        });

        // Start UDP proxy
        let udp = self.udp_proxy.clone();
        let udp_handle = tokio::spawn(async move {
            if let Err(e) = udp.start().await {
                error!("UDP proxy error: {}", e);
            }
        });

        // Start connection pool cleanup task
        let pool = self.connection_pool.clone();
        let pool_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                pool.cleanup_expired().await;
            }
        });

        // Start combined SOCKS5/HTTP proxy server
        let mut handles = vec![tcp_handle, udp_handle, pool_handle];
        if let Some(ref server) = self.combined_server {
            if let Some(socks5) = self.config.socks5_listen {
                info!("Starting SOCKS5 server on {}", socks5);
            }
            if let Some(http) = self.config.http_listen {
                info!("Starting HTTP proxy server on {}", http);
            }
            let srv = server.clone();
            let combined_handle = tokio::spawn(async move {
                let _ = srv.start().await;
            });
            handles.push(combined_handle);
        }

        // Start Shadowsocks server if configured
        if let Some(ref ss_server) = self.shadowsocks_server {
            if let Some(ss_listen) = self.config.ss_listen {
                info!("Starting Shadowsocks server on {}", ss_listen);
                if let Some(ref ss_config) = self.config.ss_server {
                    info!("  -> {}:{} (method: {}, ota: {})",
                        ss_config.addr, ss_config.port, ss_config.method, ss_config.ota);
                }
            }
            let srv = ss_server.clone();
            let ss_handle = tokio::spawn(async move {
                let _ = srv.start().await;
            });
            handles.push(ss_handle);
        }

        info!("Proxy services started");

        // Wait for shutdown signal
        let _ = self.shutdown_tx.subscribe().recv().await;

        info!("Proxy shutdown initiated");
        
        // Signal tasks to stop
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        // Close all connections
        self.connection_pool.close_all().await;

        // Abort running tasks
        for handle in handles {
            handle.abort();
        }

        info!("Proxy shutdown complete");
        Ok(())
    }

    /// Stop the proxy gracefully
    pub async fn stop(&self) {
        info!("Stopping proxy...");
        let _ = self.shutdown_tx.send(());
    }

    /// Check if proxy is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get session handle for external access
    pub fn session_handle(&self) -> &Arc<RwLock<EbpfSessionHandle>> {
        &self.session_handle
    }

    /// Get routing handle for external access
    pub fn routing_handle(&self) -> &Arc<EbpfRoutingHandle> {
        &self.routing_handle
    }

    /// Get stats handle for external access
    pub fn stats_handle(&self) -> &Arc<RwLock<EbpfStatsHandle>> {
        &self.stats_handle
    }
}

/// Create a proxy with default configuration
pub async fn create_proxy() -> std::io::Result<Arc<Proxy>> {
    let config = ProxyConfig::default();
    Ok(Arc::new(Proxy::new(config).await?))
}

/// Run proxy with signal handling
pub async fn run_with_signals(proxy: Arc<Proxy>) -> std::io::Result<()> {
    // Spawn proxy task
    let proxy_clone = proxy.clone();
    let proxy_handle = tokio::spawn(async move {
        proxy_clone.start().await
    });

    // Wait for shutdown signal
    tokio::select! {
        result = proxy_handle => {
            if let Err(e) = result {
                error!("Proxy task panicked: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
            proxy.stop().await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert_eq!(config.tcp.listen_addr.port(), 1080);
        assert_eq!(config.udp.listen_addr.port(), 1080);
        assert!(config.ss_listen.is_none());
        assert!(config.ss_server.is_none());
    }

    #[tokio::test]
    async fn test_connection_pool_config_default() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.tcp_timeout, Duration::from_secs(60));
        assert_eq!(config.udp_timeout, Duration::from_secs(30));
    }
}
