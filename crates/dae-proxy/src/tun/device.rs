//! TUN 设备管理和主代理处理器

use crate::connection_pool::{ConnectionKey, SharedConnectionPool};
use crate::rule_engine::{RuleAction, SharedRuleEngine};
use crate::tun::dns::SharedDnsHijacker;
use crate::tun::packet::{PacketDirection, TunPacket};
use crate::tun::routing::RouteResult;
use crate::tun::tcp::TcpTunSession;
use crate::tun::udp::UdpSessionData;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio_tun::TunBuilder;
use tracing::{debug, error, info};

/// TUN 设备配置
///
/// 配置 TUN 透明代理的各项参数。
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Enable TUN transparent proxy
    pub enabled: bool,
    /// TUN interface name
    pub interface: String,
    /// TUN device IP address
    pub tun_ip: String,
    /// TUN netmask
    pub tun_netmask: String,
    /// DNS hijack server addresses (IPs to intercept DNS queries to)
    pub dns_hijack: Vec<IpAddr>,
    /// MTU for TUN device
    pub mtu: u32,
    /// TCP connection timeout
    pub tcp_timeout: Duration,
    /// UDP session timeout
    pub udp_timeout: Duration,
    /// Maximum packet size
    pub max_packet_size: usize,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "dae0".to_string(),
            tun_ip: "10.0.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            dns_hijack: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
            mtu: 1500,
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
            max_packet_size: 64 * 1024,
        }
    }
}

/// TUN 代理主处理器
///
/// TUN 透明代理的核心处理单元，负责数据包的路由和转发。
#[allow(dead_code)]
pub struct TunProxy {
    /// Configuration
    config: TunConfig,
    /// Rule engine
    rule_engine: SharedRuleEngine,
    /// Connection pool
    connection_pool: SharedConnectionPool,
    /// DNS hijacker
    dns_hijacker: SharedDnsHijacker,
    /// TCP sessions
    tcp_sessions: RwLock<HashMap<ConnectionKey, Arc<TcpTunSession>>>,
    /// UDP sessions
    udp_sessions: RwLock<HashMap<ConnectionKey, Arc<UdpSessionData>>>,
    /// Local TUN IP
    local_ip: Ipv4Addr,
}

impl TunProxy {
    /// Create a new TUN proxy
    pub fn new(
        config: TunConfig,
        rule_engine: SharedRuleEngine,
        connection_pool: SharedConnectionPool,
        dns_hijacker: SharedDnsHijacker,
    ) -> Self {
        let local_ip: Ipv4Addr = config.tun_ip.parse().unwrap_or(Ipv4Addr::new(10, 0, 0, 1));

        Self {
            config,
            rule_engine,
            connection_pool,
            dns_hijacker,
            tcp_sessions: RwLock::new(HashMap::new()),
            udp_sessions: RwLock::new(HashMap::new()),
            local_ip,
        }
    }

    /// Check if this packet should be handled by TUN proxy
    pub fn should_handle(&self, packet: &TunPacket) -> bool {
        // Handle outbound packets (from local to network)
        // and inbound packets (from network to local)

        // Check if destination is our TUN IP
        if let IpAddr::V4(dst) = packet.ip_header.dst_ip {
            if dst == self.local_ip {
                return true;
            }
        }

        // Check if this is DNS hijack
        if packet.is_dns() && self.dns_hijacker.is_hijacked_ip(packet.ip_header.dst_ip) {
            return true;
        }

        // Handle all outbound packets from TUN
        if packet.direction == PacketDirection::Outbound {
            return true;
        }

        false
    }

    /// Start the TUN proxy - opens TUN device and processes packets
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Starting TUN proxy on interface {} with IP {}/{}",
            self.config.interface, self.config.tun_ip, self.config.tun_netmask
        );

        // Build TUN device using tokio-tun
        let tun = TunBuilder::new()
            .name(&self.config.interface)
            .tap(false) // Use TUN mode (layer 3)
            .packet_info(true) // Include packet metadata
            .mtu(self.config.mtu as i32)
            .address(self.config.tun_ip.parse()?)
            .netmask(self.config.tun_netmask.parse()?)
            .up()
            .try_build()?;

        info!("TUN device {} created successfully", tun.name());

        let mut buf = vec![0u8; self.config.max_packet_size];
        let mut tun = tun;

        loop {
            // Read packet from TUN device
            let n = tun.read(&mut buf).await?;
            if n == 0 {
                continue;
            }

            let packet_data = &buf[..n];

            // Parse the packet
            match TunPacket::parse(packet_data.to_vec(), PacketDirection::Outbound) {
                Some(packet) => {
                    if self.should_handle(&packet) {
                        // Route the packet based on rules
                        let result = self.route_packet(packet).await;

                        match result {
                            RouteResult::Forwarded => {
                                debug!("Packet forwarded successfully");
                            }
                            RouteResult::Dropped => {
                                debug!("Packet dropped by rules");
                            }
                            RouteResult::Response(dns_response) => {
                                // Send response back (e.g., DNS hijack response)
                                if let Err(e) = tun.write(&dns_response).await {
                                    error!("Failed to write response: {}", e);
                                }
                            }
                        }
                    }
                }
                None => {
                    debug!("Failed to parse packet, ignoring");
                }
            }
        }
    }

    /// Route a packet based on rule engine decision
    pub async fn route_packet(&self, packet: TunPacket) -> RouteResult {
        let info = packet.to_packet_info();
        let action = self.rule_engine.match_packet(&info).await;

        debug!(
            "Routing packet: {} -> {} (proto: {:?}, port: {}), action: {:?}",
            packet.ip_header.src_ip,
            packet.ip_header.dst_ip,
            packet.ip_header.protocol,
            packet.dst_port(),
            action
        );

        match action {
            RuleAction::Proxy | RuleAction::Default => {
                // Route through proxy
                self.proxy_packet(packet).await
            }
            RuleAction::Pass | RuleAction::Direct | RuleAction::MustDirect => {
                // Direct forwarding
                self.direct_packet(packet).await
            }
            RuleAction::Drop => {
                // Drop the packet
                RouteResult::Dropped
            }
        }
    }

    /// Proxy a packet through the proxy chain
    async fn proxy_packet(&self, packet: TunPacket) -> RouteResult {
        if packet.is_dns() {
            // Handle DNS specially
            if let Some(ref dns) = packet.dns_query {
                let src_port = packet.src_port();
                if let Some(response) = self
                    .dns_hijacker
                    .handle_query(dns, packet.ip_header.src_ip, src_port)
                    .await
                {
                    // Inject DNS response back to TUN
                    return RouteResult::Response(response);
                }
            }
            return RouteResult::Forwarded;
        }

        if packet.is_tcp() {
            // TCP proxy via connection pool
            if let Some(_key) = &packet.connection_key {
                return RouteResult::Forwarded; // Would need actual proxy connection
            }
        }

        if packet.is_udp() {
            // UDP proxy
            return RouteResult::Forwarded; // Would need actual UDP relay
        }

        RouteResult::Dropped
    }

    /// Directly forward a packet (no proxy)
    async fn direct_packet(&self, _packet: TunPacket) -> RouteResult {
        // Direct forwarding would send packet back to TUN device
        // The actual network send would be handled by the TUN device write
        RouteResult::Forwarded
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let tcp_timeout = self.config.tcp_timeout;
        let udp_timeout = self.config.udp_timeout;

        // Cleanup TCP sessions
        {
            let mut sessions = self.tcp_sessions.write().await;
            sessions.retain(|_, session| !session.is_expired(tcp_timeout));
        }

        // Cleanup UDP sessions
        {
            let mut sessions = self.udp_sessions.write().await;
            sessions.retain(|_, session| !session.is_expired(udp_timeout));
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> TunStats {
        let tcp_count = self.tcp_sessions.read().await.len();
        let udp_count = self.udp_sessions.read().await.len();
        let dns_cache_size = self.dns_hijacker.cache_size().await;

        TunStats {
            active_tcp_sessions: tcp_count,
            active_udp_sessions: udp_count,
            dns_cache_size,
        }
    }
}

/// TUN 代理统计数据
///
/// 记录 TUN 代理的运行统计信息。
#[derive(Debug, Clone)]
pub struct TunStats {
    /// Number of active TCP sessions
    pub active_tcp_sessions: usize,
    /// Number of active UDP sessions
    pub active_udp_sessions: usize,
    /// DNS cache size
    pub dns_cache_size: usize,
}
