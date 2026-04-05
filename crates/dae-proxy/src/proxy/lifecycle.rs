//! Lifecycle module - manages proxy startup and shutdown
//!
//! This module handles the lifecycle aspects of the proxy including:
//! - Starting all proxy services
//! - Graceful shutdown handling
//! - Task management

use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::tracking::store::TrackingStore;

use super::coordinator::Coordinator;
use crate::proxy::Proxy;

/// Lifecycle manager for starting and stopping the proxy
pub(crate) struct Lifecycle;

impl Lifecycle {
    /// Start all proxy services and return task handles
    pub(crate) async fn start(
        self: &Arc<Self>,
        proxy: &Arc<Proxy>,
    ) -> std::io::Result<Vec<JoinHandle<()>>> {
        info!("Starting proxy services...");

        // Start TCP proxy
        let tcp = proxy.tcp_proxy.clone();
        let tcp_handle = tokio::spawn(async move {
            if let Err(e) = tcp.start().await {
                error!("TCP proxy error: {}", e);
            }
        });

        // Start UDP proxy
        let udp = proxy.udp_proxy.clone();
        let udp_handle = tokio::spawn(async move {
            if let Err(e) = udp.start().await {
                error!("UDP proxy error: {}", e);
            }
        });

        // Start connection pool cleanup task
        let pool = proxy.connection_pool.clone();
        let pool_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                pool.cleanup_expired().await;
            }
        });

        // Start combined SOCKS5/HTTP proxy server
        let mut handles = vec![tcp_handle, udp_handle, pool_handle];
        if let Some(ref server) = proxy.combined_server {
            if let Some(socks5) = proxy.config.socks5_listen {
                info!("Starting SOCKS5 server on {}", socks5);
            }
            if let Some(http) = proxy.config.http_listen {
                info!("Starting HTTP proxy server on {}", http);
            }
            let srv = server.clone();
            let combined_handle = tokio::spawn(async move {
                let _ = srv.start().await;
            });
            handles.push(combined_handle);
        }

        // Start Shadowsocks server if configured
        if let Some(ref ss_server) = proxy.shadowsocks_server {
            if let Some(ss_listen) = proxy.config.ss_listen {
                info!("Starting Shadowsocks server on {}", ss_listen);
                if let Some(ref ss_config) = proxy.config.ss_server {
                    info!(
                        "  -> {}:{} (method: {}, ota: {})",
                        ss_config.addr, ss_config.port, ss_config.method, ss_config.ota
                    );
                }
            }
            let srv = ss_server.clone();
            let ss_handle = tokio::spawn(async move {
                let _ = srv.start().await;
            });
            handles.push(ss_handle);
        }

        // Start VLESS server if configured
        if let Some(ref vless_server) = proxy.vless_server {
            if let Some(vless_listen) = proxy.config.vless_listen {
                info!("Starting VLESS server on {}", vless_listen);
                if let Some(ref vless_config) = proxy.config.vless_server {
                    info!(
                        "  -> {}:{} (uuid: {})",
                        vless_config.addr, vless_config.port, vless_config.uuid
                    );
                }
            }
            let srv = vless_server.clone();
            let vless_handle = tokio::spawn(async move {
                let _ = srv.start().await;
            });
            handles.push(vless_handle);
        }

        // Start VMess server if configured
        if let Some(ref vmess_server) = proxy.vmess_server {
            if let Some(vmess_listen) = proxy.config.vmess_listen {
                info!("Starting VMess server on {}", vmess_listen);
                if let Some(ref vmess_config) = proxy.config.vmess_server {
                    info!(
                        "  -> {}:{} (user_id: {}, security: {})",
                        vmess_config.addr,
                        vmess_config.port,
                        vmess_config.user_id,
                        vmess_config.security
                    );
                }
            }
            let srv = vmess_server.clone();
            let vmess_handle = tokio::spawn(async move {
                let _ = srv.start().await;
            });
            handles.push(vmess_handle);
        }

        // Start Trojan server if configured
        if let Some(ref trojan_server) = proxy.trojan_server {
            if let Some(trojan_listen) = proxy.config.trojan_listen {
                info!("Starting Trojan server on {}", trojan_listen);
                if let Some(ref trojan_config) = proxy.config.trojan_server {
                    info!(
                        "  -> {}:{} (password: [hidden])",
                        trojan_config.addr, trojan_config.port
                    );
                }
            }
            let srv = trojan_server.clone();
            let trojan_handle = tokio::spawn(async move {
                let _ = srv.start().await;
            });
            handles.push(trojan_handle);
        }

        // Start tracking HTTP server if enabled
        if let Some(ref store) = proxy.tracking_store {
            Self::start_tracking_servers(store, &proxy.config).await;
        }

        info!("Proxy services started");
        Ok(handles)
    }

    /// Start tracking HTTP servers (Prometheus, JSON API)
    async fn start_tracking_servers(
        store: &Arc<TrackingStore>,
        config: &crate::proxy::ProxyConfig,
    ) {
        let export_cfg = &config.tracking.export;
        if export_cfg.prometheus || export_cfg.json_api || export_cfg.websocket {
            let prom_port = export_cfg.prometheus_port;
            let json_port = export_cfg.json_api_port;
            let prom_path = export_cfg.prometheus_path.clone();
            let json_path = export_cfg.json_api_path.clone();
            let store_clone = store.clone();
            let enable_ws = export_cfg.websocket;
            let track_store = store_clone.clone();

            if export_cfg.prometheus {
                info!(
                    "Starting tracking Prometheus metrics server on :{}/{}",
                    prom_port, prom_path
                );
                let prom_store = store_clone.clone();
                tokio::spawn(async move {
                    if let Err(e) = TrackingStore::start_http_server(
                        prom_port, &prom_path, true, false, prom_store,
                    )
                    .await
                    {
                        error!("Tracking Prometheus server error: {}", e);
                    }
                });
            }

            if export_cfg.json_api {
                info!(
                    "Starting tracking JSON API server on :{}/{}",
                    json_port, json_path
                );
                let json_store = store_clone.clone();
                tokio::spawn(async move {
                    if let Err(e) = TrackingStore::start_http_server(
                        json_port, &json_path, false, enable_ws, json_store,
                    )
                    .await
                    {
                        error!("Tracking JSON API server error: {}", e);
                    }
                });
            }

            // Record initial stats if we have the store
            track_store.record_routed(0);
        } else if config.tracking.enabled {
            // Tracking is enabled but no export configured - just log it
            info!("Tracking enabled (no HTTP export configured), metrics available via store");
        }
    }

    /// Stop the proxy and cleanup all resources
    pub(crate) async fn shutdown(
        self: &Arc<Self>,
        proxy: &Arc<Proxy>,
        coordinator: &Coordinator,
        handles: Vec<JoinHandle<()>>,
    ) {
        info!("Proxy shutdown initiated");

        // Signal tasks to stop
        coordinator.send_shutdown();

        // Close all connections
        proxy.connection_pool.close_all().await;

        // Abort running tasks
        for handle in handles {
            handle.abort();
        }

        info!("Proxy shutdown complete");
    }
}
