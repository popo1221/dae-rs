//! dae-proxy library
//!
//! High-performance user-space proxy core for dae-rs transparent proxy.
//! This module provides the core TCP/UDP forwarding infrastructure
//! that integrates with the eBPF subsystem.
//!
//! # Architecture
//!
//! - `connection`: Connection tracking with state management
//! - `connection_pool`: Connection reuse by 4-tuple with expiration
//! - `tcp`: TCP relay using tokio with bidirectional copy
//! - `udp`: UDP relay with NAT semantics
//! - `ebpf_integration`: eBPF map wrappers for session/routing/stats
//! - `proxy`: Main proxy coordinator

// Re-export public types for easy access
pub use crate::connection::{Connection, ConnectionState, Protocol, SharedConnection};
pub use crate::connection_pool::{ConnectionKey, ConnectionPool, SharedConnectionPool};
pub use crate::tcp::{TcpProxy, TcpProxyConfig};
pub use crate::udp::{UdpProxy, UdpProxyConfig};
pub use crate::ebpf_integration::{
    EbpfError, EbpfMaps, EbpfRoutingHandle, EbpfSessionHandle, EbpfStatsHandle, Result as EbpfResult,
};
pub use crate::proxy::{Proxy, ProxyConfig, ProxyError};
pub use crate::socks5::{Socks5Handler, Socks5Server};
pub use crate::http_proxy::{HttpProxyHandler, HttpProxyServer};
pub use crate::protocol_dispatcher::{ProtocolDispatcher, ProtocolDispatcherConfig};
pub use crate::shadowsocks::{
    ShadowsocksHandler, ShadowsocksServer,
    SsCipherType, SsClientConfig, SsServerConfig,
};
pub use crate::vless::{
    VlessHandler, VlessServer,
    VlessServerConfig, VlessClientConfig, VlessTlsConfig,
    VlessCommand, VlessAddressType, VlessTargetAddress,
};
pub use crate::vmess::{
    VmessHandler, VmessServer,
    VmessServerConfig, VmessClientConfig,
    VmessSecurity, VmessCommand, VmessAddressType, VmessTargetAddress,
};
pub use crate::trojan::{
    TrojanHandler, TrojanServer,
    TrojanServerConfig, TrojanClientConfig, TrojanTlsConfig,
    TrojanCommand, TrojanAddressType, TrojanTargetAddress,
};
pub use crate::rules::{Rule, RuleGroup, RuleMatchAction, RuleType, DomainRule, IpCidrRule, GeoIpRule, ProcessRule, DnsTypeRule};
pub use crate::rule_engine::{RuleEngine, RuleEngineConfig, RuleEngineStats, RuleAction, PacketInfo, SharedRuleEngine, new_rule_engine};

pub mod connection;
pub mod connection_pool;
pub mod ebpf_integration;
pub mod proxy;
pub mod tcp;
pub mod udp;
pub mod socks5;
pub mod http_proxy;
pub mod protocol_dispatcher;
pub mod shadowsocks;
pub mod vless;
pub mod vmess;
pub mod trojan;
pub mod rules;
pub mod rule_engine;

/// Proxy protocol implementations (Phase 4 placeholder)
///
/// This module contains proxy protocol enums that will be
/// implemented in Phase 4 (Shadowsocks, VLESS, etc.)
#[allow(unused_imports)]
pub mod protocol {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[derive(Debug, Clone)]
    pub enum ProxyProtocol {
        Http,
        Socks5,
        Shadowsocks,
        VLess,
        Trojan,
    }

    impl ProxyProtocol {
        pub fn name(&self) -> &'static str {
            match self {
                ProxyProtocol::Http => "HTTP",
                ProxyProtocol::Socks5 => "SOCKS5",
                ProxyProtocol::Shadowsocks => "Shadowsocks",
                ProxyProtocol::VLess => "VLESS",
                ProxyProtocol::Trojan => "Trojan",
            }
        }
    }

    /// A proxy connection handler
    pub struct ProxyHandler {
        protocol: ProxyProtocol,
    }

    impl ProxyHandler {
        pub fn new(protocol: ProxyProtocol) -> Self {
            Self { protocol }
        }

        pub fn protocol_name(&self) -> &'static str {
            self.protocol.name()
        }

        /// Forward traffic between client and remote
        pub async fn forward(&self, mut client: TcpStream, remote_addr: &str) -> std::io::Result<()> {
            let mut remote = TcpStream::connect(remote_addr).await?;

            // Simple byte forwarding (placeholder for actual protocol implementation)
            let mut buf = vec![0u8; 8192];
            loop {
                let n = client.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                remote.write_all(&buf[..n]).await?;
            }

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_protocol_names() {
            assert_eq!(ProxyProtocol::Http.name(), "HTTP");
            assert_eq!(ProxyProtocol::Socks5.name(), "SOCKS5");
            assert_eq!(ProxyProtocol::Shadowsocks.name(), "Shadowsocks");
        }
    }
}
