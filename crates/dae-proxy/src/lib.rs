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
pub use crate::ebpf_integration::{
    EbpfError, EbpfMaps, EbpfRoutingHandle, EbpfSessionHandle, EbpfStatsHandle,
    Result as EbpfResult,
};
pub use crate::http_proxy::{HttpProxyHandler, HttpProxyServer};
pub use crate::protocol_dispatcher::{ProtocolDispatcher, ProtocolDispatcherConfig};
pub use crate::proxy::{Proxy, ProxyConfig, ProxyError};
pub use crate::shadowsocks::{
    plugin::{
        ObfsConfig, ObfsHttp, ObfsMode, ObfsStream, ObfsTls, V2rayConfig, V2rayMode, V2rayPlugin,
        V2rayStream,
    },
    ssr::{SsrClientConfig, SsrHandler, SsrObfs, SsrObfsHandler, SsrProtocol, SsrServerConfig},
    ShadowsocksHandler, ShadowsocksServer, SsCipherType, SsClientConfig, SsServerConfig,
};
pub use crate::socks5::{Socks5Handler, Socks5Server};
pub use crate::tcp::{TcpProxy, TcpProxyConfig};
pub use crate::udp::{UdpProxy, UdpProxyConfig};
pub use crate::vless::{
    VlessAddressType, VlessClientConfig, VlessCommand, VlessHandler, VlessRealityConfig,
    VlessServer, VlessServerConfig, VlessTargetAddress, VlessTlsConfig,
};
pub use crate::vmess::{
    VmessAddressType, VmessClientConfig, VmessCommand, VmessHandler, VmessSecurity, VmessServer,
    VmessServerConfig, VmessTargetAddress,
};
// Trojan protocol - re-exported from trojan_protocol for backward compatibility
pub use crate::control::{
    connect_and_get_status, connect_and_send, ControlCommand, ControlResponse, ControlServer,
    ControlState, NodeTestResult, ProxyStats, ProxyStatus,
};

// Logging module exports
pub use crate::core::{Context, Error, Result};
// Juicity exports (QUIC-based, optional)
#[cfg(feature = "protocol-juicity")]
pub use crate::juicity::codec::{JuicityAddress, JuicityCodec, JuicityCommand, JuicityFrame};
#[cfg(feature = "protocol-juicity")]
pub use crate::juicity::{
    CongestionControl, JuicityClient, JuicityConfig, JuicityConnection, JuicityError,
    JuicityHandler, JuicityServer,
};
pub use crate::logging::{
    connect_to_log_stream, handle_control_log_command, parse_level_response, process_log_command,
    LogCommand, LogLevel, LogMessage, LogService, LogState,
};
pub use crate::node::{
    Node,
    NodeError,
    NodeHandle,
    NodeId,
    NodeManager,
    NodeManagerConfig,
    NodeSelector,
    NodeState,
    // Node Store - Zed-inspired naming
    NodeStoreTrait,
    SelectionPolicy,
};
pub use crate::rule_engine::{
    new_rule_engine, PacketInfo, RuleAction, RuleEngine, RuleEngineConfig, RuleEngineStats,
    SharedRuleEngine,
};
pub use crate::rules::{
    DnsTypeRule, DomainRule, GeoIpRule, IpCidrRule, ProcessRule, Rule, RuleGroup, RuleMatchAction,
    RuleType,
};
pub use crate::trojan_protocol::{
    TrojanAddressType, TrojanClientConfig, TrojanCommand, TrojanHandler, TrojanServer,
    TrojanServerConfig, TrojanTargetAddress, TrojanTlsConfig,
};

// TUN transparent proxy exports
pub use crate::tun::new_dns_hijacker;
pub use crate::tun::{
    DnsHijackEntry, DnsHijacker, RouteResult, SharedDnsHijacker, TcpFlags, TcpHeader,
    TcpTunSession, TunConfig, TunPacket, TunProxy, TunStats, UdpHeader,
};

// Protocol layer abstractions
//
// # Unified Handler Architecture (Zed-inspired)
//
// The protocol module provides a unified Handler trait that all protocol
// Protocol layer abstractions
//
// # Handler Trait System (Zed-inspired)
//
// The protocol module provides a unified Handler trait system:
// - [`UnifiedHandler`]: Canonical Handler trait from unified_handler (recommended)
// - [`ProtocolHandler`]: Deprecated, use UnifiedHandler instead
// - [`ProtocolHandlerAdapter`]: Bridge ProtocolHandler -> UnifiedHandler
//
// Note: simple_handler is also deprecated; use unified_handler instead.
pub use crate::protocol::{ProtocolRegistry, ProtocolType};

// Unified Handler trait (primary interface)
pub use crate::protocol::unified_handler::{
    Handler as UnifiedHandler, HandlerConfig as UnifiedHandlerConfig, HandlerStats, HandlerStatsExt,
};

// Deprecated: Use UnifiedHandler instead
#[deprecated(since = "0.1.0", note = "Use UnifiedHandler instead")]
pub use crate::protocol::ProtocolHandler;

pub mod connection;
pub mod connection_pool;
pub mod control;
pub mod core;
pub mod dns;
pub mod ebpf_check;
pub mod ebpf_integration;
pub mod http_proxy;
// QUIC-based protocols (optional - depend on quinn crate)
#[cfg(feature = "protocol-hysteria2")]
pub mod hysteria2;
#[cfg(feature = "protocol-juicity")]
pub mod juicity;
pub mod logging;
pub mod mac;
pub mod nat;
pub mod node;
pub mod process;
pub mod protocol;
pub mod protocol_dispatcher;
pub mod proxy;
pub mod proxy_chain;
pub mod rule_engine;
pub mod rules;
pub mod shadowsocks;
pub mod socks4;
pub mod socks5;
pub mod tcp;
pub mod tracking;
pub mod transport;
pub mod trojan_protocol; // Module structure following Zed's architecture
#[cfg(feature = "protocol-tuic")]
pub mod tuic;
pub mod tun;
pub mod udp;
pub mod vless;
pub mod vmess;

// Process rule engine exports
pub use crate::process::{
    match_process_name, ProcessInfo, ProcessMatchRule, ProcessResolver, ProcessRuleSet,
    ProcessRuleSetBuilder, TASK_COMM_LEN,
};

// MAC address rule engine exports
pub use crate::mac::{MacAddr, MacRule, MacRuleSet, OuiDatabase};

// Hysteria2 protocol exports (QUIC-based, optional)
#[cfg(feature = "protocol-hysteria2")]
pub use crate::hysteria2::{Hysteria2Config, Hysteria2Error, Hysteria2Handler, Hysteria2Server};

// DNS module exports
pub use crate::dns::{
    DnsCacheEntry, DnsError, DnsResolution, MacDnsConfig, MacDnsResolver, MacDnsRule,
};

// Re-export transport types
pub use transport::{
    GrpcConfig, GrpcTransport, RealityConfig, TcpTransport, TlsConfig, TlsTransport, Transport,
    WsConfig, WsConnector, WsTransport,
};

// Configuration module with hot reload support
pub mod config;
pub use config::{
    ConfigEvent, HotReload, HotReloadError, HotReloadable, WatchEvent, WatchEventKind,
};

// Metrics module with Prometheus export
pub mod metrics;
pub use metrics::{
    dec_active_connections,
    dec_active_tcp_connections,
    dec_active_udp_connections,
    // Gauge functions
    inc_active_connections,
    inc_active_tcp_connections,
    inc_active_udp_connections,
    inc_bytes_received,
    inc_bytes_sent,
    // Counter functions
    inc_connection,
    inc_dns_resolution,
    inc_error,
    inc_node_latency_test,
    inc_rule_match,
    // Histogram functions
    observe_connection_duration,
    observe_dns_latency,
    observe_ebpf_latency,
    observe_node_latency,
    observe_request_size,
    observe_response_time,
    observe_rule_match_latency,
    set_connection_pool_size,
    set_ebpf_map_entries,
    set_memory_usage,
    set_node_count,
    set_node_latency,
    // Server
    start_metrics_server,
    stop_metrics_server,
    MetricsServer,
};
