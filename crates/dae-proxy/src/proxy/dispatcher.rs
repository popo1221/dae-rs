//! Dispatcher module - handles protocol server creation and task spawning
//!
//! This module contains factory methods for creating various proxy servers:
//! - Combined SOCKS5/HTTP proxy server
//! - Shadowsocks server
//! - VLESS server
//! - VMess server
//! - Trojan server

use crate::protocol_dispatcher::{CombinedProxyServer, ProtocolDispatcherConfig};
use crate::shadowsocks::ShadowsocksServer;
use crate::trojan_protocol::{TrojanClientConfig, TrojanServer};
use crate::vless::{VlessClientConfig, VlessServer};
use crate::vmess::VmessServer;

use tracing::info;

/// Dispatcher for creating and managing protocol servers
pub(crate) struct Dispatcher;

impl Dispatcher {
    /// Create combined SOCKS5/HTTP proxy server if configured
    pub(crate) async fn create_combined_server(
        config: &crate::proxy::ProxyConfig,
    ) -> std::io::Result<Option<std::sync::Arc<CombinedProxyServer>>> {
        let dispatcher_config = ProtocolDispatcherConfig {
            socks5_addr: config.socks5_listen,
            http_addr: config.http_listen,
        };

        // Check if any protocol is configured
        if dispatcher_config.socks5_addr.is_none() && dispatcher_config.http_addr.is_none() {
            return Ok(None);
        }

        let server = CombinedProxyServer::new(dispatcher_config).await?;
        Ok(Some(std::sync::Arc::new(server)))
    }

    /// Create Shadowsocks server if configured
    pub(crate) async fn create_shadowsocks_server(
        config: &crate::proxy::ProxyConfig,
    ) -> std::io::Result<Option<std::sync::Arc<ShadowsocksServer>>> {
        if config.ss_listen.is_none() || config.ss_server.is_none() {
            return Ok(None);
        }

        let ss_config = config.ss_server.as_ref().unwrap();
        let ss_listen = config.ss_listen.unwrap();

        let ss_client_config = crate::shadowsocks::SsClientConfig {
            listen_addr: ss_listen,
            server: ss_config.clone(),
            tcp_timeout: config.pool.tcp_timeout,
            udp_timeout: config.pool.udp_timeout,
        };

        let server = ShadowsocksServer::with_config(ss_client_config).await?;
        Ok(Some(std::sync::Arc::new(server)))
    }

    /// Create VLESS server if configured
    pub(crate) async fn create_vless_server(
        config: &crate::proxy::ProxyConfig,
    ) -> std::io::Result<Option<std::sync::Arc<VlessServer>>> {
        if config.vless_listen.is_none() || config.vless_server.is_none() {
            return Ok(None);
        }

        let vless_config = config.vless_server.as_ref().unwrap();
        let vless_listen = config.vless_listen.unwrap();

        let vless_client_config = VlessClientConfig {
            listen_addr: vless_listen,
            server: vless_config.clone(),
            tcp_timeout: config.pool.tcp_timeout,
            udp_timeout: config.pool.udp_timeout,
        };

        let server = VlessServer::with_config(vless_client_config).await?;
        Ok(Some(std::sync::Arc::new(server)))
    }

    /// Create VMess server if configured
    pub(crate) async fn create_vmess_server(
        config: &crate::proxy::ProxyConfig,
    ) -> std::io::Result<Option<std::sync::Arc<VmessServer>>> {
        if config.vmess_listen.is_none() || config.vmess_server.is_none() {
            return Ok(None);
        }

        let vmess_config = config.vmess_server.as_ref().unwrap();
        let vmess_listen = config.vmess_listen.unwrap();

        let vmess_client_config = crate::vmess::VmessClientConfig {
            listen_addr: vmess_listen,
            server: vmess_config.clone(),
            tcp_timeout: config.pool.tcp_timeout,
            udp_timeout: config.pool.udp_timeout,
        };

        let server = VmessServer::with_config(vmess_client_config).await?;
        Ok(Some(std::sync::Arc::new(server)))
    }

    /// Create Trojan server if configured
    pub(crate) async fn create_trojan_server(
        config: &crate::proxy::ProxyConfig,
    ) -> std::io::Result<Option<std::sync::Arc<TrojanServer>>> {
        if config.trojan_listen.is_none() || config.trojan_server.is_none() {
            return Ok(None);
        }

        let trojan_config = config.trojan_server.as_ref().unwrap();
        let trojan_listen = config.trojan_listen.unwrap();

        let trojan_client_config = TrojanClientConfig {
            listen_addr: trojan_listen,
            server: trojan_config.clone(),
            tcp_timeout: config.pool.tcp_timeout,
            udp_timeout: config.pool.udp_timeout,
        };

        // Use multiple backends if available
        let server = if !config.trojan_backends.is_empty() {
            info!(
                "Creating Trojan server with {} backends",
                config.trojan_backends.len()
            );
            TrojanServer::with_backends(trojan_client_config, config.trojan_backends.clone())
                .await?
        } else {
            TrojanServer::with_config(trojan_client_config).await?
        };
        Ok(Some(std::sync::Arc::new(server)))
    }
}
