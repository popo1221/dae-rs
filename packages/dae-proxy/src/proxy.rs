//! Proxy core implementation
//!
//! Main entry point for the proxy subsystem that coordinates TCP/UDP relays
//! and integrates with eBPF maps.

use crate::connection_pool::{new_connection_pool, SharedConnectionPool};
use crate::ebpf_integration::{EbpfMaps, EbpfRoutingHandle, EbpfSessionHandle, EbpfStatsHandle};
use crate::tcp::{TcpProxy, TcpProxyConfig};
use crate::udp::{UdpProxy, UdpProxyConfig};
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
        })
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
        tcp_handle.abort();
        udp_handle.abort();
        pool_handle.abort();

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
    }

    #[tokio::test]
    async fn test_connection_pool_config_default() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.tcp_timeout, Duration::from_secs(60));
        assert_eq!(config.udp_timeout, Duration::from_secs(30));
    }
}
