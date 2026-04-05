//! Proxy core implementation
//!
//! Main entry point for the proxy subsystem that coordinates TCP/UDP relays
//! and integrates with eBPF maps.

pub mod coordinator;
pub mod dispatcher;
pub mod lifecycle;

use crate::connection_pool::{new_connection_pool, SharedConnectionPool};
use crate::ebpf_integration::{EbpfMaps, EbpfRoutingHandle, EbpfSessionHandle, EbpfStatsHandle};
use crate::shadowsocks::ShadowsocksServer;
use crate::tcp::{TcpProxy, TcpProxyConfig};
use crate::tracking::store::TrackingStore;
use crate::trojan_protocol::{TrojanServer, TrojanServerConfig};
use crate::udp::{UdpProxy, UdpProxyConfig};
use crate::vless::{VlessServer, VlessServerConfig};
use crate::vmess::{VmessServer, VmessServerConfig};
use dae_config::TrackingConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use coordinator::Coordinator;
use dispatcher::Dispatcher;
use lifecycle::Lifecycle;

// Re-export ProxyError from the centralized error module
pub use crate::core::error::ProxyError;

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
    /// Tracking/monitoring configuration
    pub tracking: TrackingConfig,
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
    /// VLESS listen address (None to disable)
    pub vless_listen: Option<SocketAddr>,
    /// VLESS server configuration (None to disable)
    pub vless_server: Option<VlessServerConfig>,
    /// VMess listen address (None to disable)
    pub vmess_listen: Option<SocketAddr>,
    /// VMess server configuration (None to disable)
    pub vmess_server: Option<VmessServerConfig>,
    /// Trojan listen address (None to disable)
    pub trojan_listen: Option<SocketAddr>,
    /// Trojan server configuration (None to disable)
    pub trojan_server: Option<TrojanServerConfig>,
    /// Trojan backend servers from config file (fallback if trojan_server not set)
    pub trojan_backends: Vec<TrojanServerConfig>,
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
            vless_listen: None,
            vless_server: None,
            vmess_listen: None,
            vmess_server: None,
            trojan_listen: None,
            trojan_server: None,
            trojan_backends: Vec::new(),
            tracking: TrackingConfig::default(),
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
    running: RwLock<bool>,
    combined_server: Option<Arc<crate::protocol_dispatcher::CombinedProxyServer>>,
    shadowsocks_server: Option<Arc<ShadowsocksServer>>,
    vless_server: Option<Arc<VlessServer>>,
    vmess_server: Option<Arc<VmessServer>>,
    trojan_server: Option<Arc<TrojanServer>>,
    tracking_store: Option<Arc<TrackingStore>>,
    coordinator: Coordinator,
    lifecycle: Arc<Lifecycle>,
}

impl Proxy {
    /// Create a new proxy instance
    pub async fn new(config: ProxyConfig) -> std::io::Result<Self> {
        info!("Initializing proxy with config: {:?}", config);

        // Initialize eBPF maps (in-memory implementation)
        let maps = EbpfMaps::new_in_memory();
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
        let tcp_proxy = Arc::new(TcpProxy::new(config.tcp.clone(), connection_pool.clone()));

        // Create UDP proxy
        let udp_proxy = Arc::new(UdpProxy::new(config.udp.clone(), connection_pool.clone()));

        // Create coordinator for shutdown signals
        let coordinator = Coordinator::new().0;

        // Create lifecycle manager
        let lifecycle = Arc::new(Lifecycle);

        // Create combined proxy server if any protocol is enabled
        let combined_server = Dispatcher::create_combined_server(&config).await?;

        // Create Shadowsocks server if configured
        let shadowsocks_server = Dispatcher::create_shadowsocks_server(&config).await?;

        // Create VLESS server if configured
        let vless_server = Dispatcher::create_vless_server(&config).await?;

        // Create VMess server if configured
        let vmess_server = Dispatcher::create_vmess_server(&config).await?;

        // Create Trojan server if configured
        let trojan_server = Dispatcher::create_trojan_server(&config).await?;

        // Initialize tracking store if enabled
        let tracking_store = if config.tracking.enabled {
            info!("Tracking enabled, initializing tracking store");
            Some(TrackingStore::shared())
        } else {
            None
        };

        Ok(Self {
            config,
            tcp_proxy,
            udp_proxy,
            connection_pool,
            session_handle,
            routing_handle,
            stats_handle,
            running: RwLock::new(false),
            combined_server,
            shadowsocks_server,
            vless_server,
            vmess_server,
            trojan_server,
            tracking_store,
            coordinator,
            lifecycle,
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

        // Start all services and get handles
        let handles = self.lifecycle.start(&self).await?;

        // Wait for shutdown signal
        let mut shutdown_rx = self.coordinator.shutdown_tx.subscribe();
        let _ = shutdown_rx.recv().await;

        // Perform shutdown
        self.lifecycle
            .shutdown(&self, &self.coordinator, handles)
            .await;

        // Mark as not running
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        Ok(())
    }

    /// Stop the proxy gracefully
    pub async fn stop(&self) {
        info!("Stopping proxy...");
        self.coordinator.send_shutdown();
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

    /// Get tracking store for external access
    #[allow(dead_code)]
    pub fn tracking_store(&self) -> Option<&Arc<TrackingStore>> {
        self.tracking_store.as_ref()
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
    let proxy_handle = tokio::spawn(async move { proxy_clone.start().await });

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
        assert!(config.vless_listen.is_none());
        assert!(config.vmess_listen.is_none());
        assert!(config.trojan_listen.is_none());
    }

    #[tokio::test]
    async fn test_connection_pool_config_default() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.tcp_timeout, Duration::from_secs(60));
        assert_eq!(config.udp_timeout, Duration::from_secs(30));
        assert_eq!(config.tcp_keepalive, Duration::from_secs(10));
    }

    #[test]
    fn test_ebpf_config_default() {
        let config = EbpfConfig::default();
        assert!(config.enabled);
        assert_eq!(config.session_map_size, 65536);
        assert_eq!(config.routing_map_size, 16384);
        assert_eq!(config.stats_map_size, 256);
    }

    #[test]
    fn test_ebpf_config_custom() {
        let config = EbpfConfig {
            enabled: false,
            session_map_size: 131072,
            routing_map_size: 32768,
            stats_map_size: 512,
        };
        assert!(!config.enabled);
        assert_eq!(config.session_map_size, 131072);
        assert_eq!(config.routing_map_size, 32768);
        assert_eq!(config.stats_map_size, 512);
    }

    #[test]
    fn test_proxy_error_display() {
        let err = ProxyError::Connect(std::io::Error::new(std::io::ErrorKind::Other, "test error"));
        assert!(format!("{}", err).contains("connect failed"));

        let err = ProxyError::Auth("test error".to_string());
        assert!(format!("{}", err).contains("authentication failed"));

        let err = ProxyError::Protocol("test error".to_string());
        assert!(format!("{}", err).contains("protocol error"));

        let err = ProxyError::Dispatch("test error".to_string());
        assert!(format!("{}", err).contains("dispatch error"));

        let err = ProxyError::Config("test error".to_string());
        assert!(format!("{}", err).contains("configuration error"));
    }

    #[test]
    fn test_proxy_error_debug() {
        let err = ProxyError::Protocol("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Protocol"));
    }

    #[test]
    fn test_proxy_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err: ProxyError = io_err.into();
        match err {
            ProxyError::Connect(_) => {}
            _ => panic!("Expected Connect variant"),
        }
    }

    #[test]
    fn test_proxy_config_debug() {
        let config = ProxyConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("ProxyConfig"));
    }

    #[test]
    fn test_connection_pool_config_debug() {
        let config = ConnectionPoolConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("ConnectionPoolConfig"));
    }

    #[test]
    fn test_ebpf_config_debug() {
        let config = EbpfConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("EbpfConfig"));
    }
}
