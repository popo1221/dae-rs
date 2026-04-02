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
// Trojan protocol - re-exported from trojan_protocol for backward compatibility
pub use crate::trojan_protocol::{
    TrojanHandler, TrojanServer,
    TrojanServerConfig, TrojanClientConfig, TrojanTlsConfig,
    TrojanCommand, TrojanAddressType, TrojanTargetAddress,
};
pub use crate::juicity::{
    JuicityHandler, JuicityServer, JuicityClient, JuicityConfig,
    JuicityError, CongestionControl, JuicityConnection,
};
pub use crate::juicity::codec::{
    JuicityCodec, JuicityFrame, JuicityCommand, JuicityAddress,
};
pub use crate::rules::{Rule, RuleGroup, RuleMatchAction, RuleType, DomainRule, IpCidrRule, GeoIpRule, ProcessRule, DnsTypeRule};
pub use crate::rule_engine::{RuleEngine, RuleEngineConfig, RuleEngineStats, RuleAction, PacketInfo, SharedRuleEngine, new_rule_engine};
pub use crate::core::{Error, Result, Context};
pub use crate::node::{Node, NodeId, NodeManager, NodeError, SelectionPolicy, NodeSelector};
pub use crate::control::{
    ControlServer, ControlState, ControlCommand, ControlResponse,
    ProxyStatus, ProxyStats, NodeTestResult,
    connect_and_send, connect_and_get_status,
};

// Protocol layer abstractions
//
// # Unified Handler Architecture (Zed-inspired)
//
// The protocol module provides a unified Handler trait that all protocol
// handlers should implement. For backward compatibility, ProtocolHandler is
// still available but deprecated in favor of the simpler Handler trait.
//
// See [`protocol::unified_handler`] for the unified Handler trait.
pub use crate::protocol::{
    ProtocolType,
    ProtocolRegistry,
};

// Unified Handler trait (primary interface)
pub use crate::protocol::unified_handler::{
    Handler as UnifiedHandler,
    HandlerConfig as UnifiedHandlerConfig,
    HandlerStats,
    HandlerStatsExt,
    ProtocolHandlerAdapter,
};

// Deprecated: Use UnifiedHandler instead
#[deprecated(since = "0.1.0", note = "Use UnifiedHandler instead")]
pub use crate::protocol::ProtocolHandler;

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
pub mod trojan_protocol; // Module structure following Zed's architecture
pub mod juicity;
pub mod rules;
pub mod rule_engine;
pub mod control;
pub mod transport;
pub mod core;
pub mod mac;
pub mod node;
pub mod protocol;
pub mod protocol_legacy;
pub mod dns;
pub mod process;
pub mod hysteria2;

// Process rule engine exports
pub use crate::process::{
    ProcessMatchRule, ProcessRuleSet, ProcessInfo, ProcessResolver,
    match_process_name, ProcessRuleSetBuilder, TASK_COMM_LEN,
};

// MAC address rule engine exports
pub use crate::mac::{
    MacRule, MacRuleSet, MacAddr, OuiDatabase,
};

// Hysteria2 protocol exports
pub use crate::hysteria2::{
    Hysteria2Handler, Hysteria2Server, Hysteria2Config, Hysteria2Error,
};

// DNS module exports
pub use crate::dns::{
    MacDnsResolver, MacDnsConfig, MacDnsRule, DnsCacheEntry, DnsResolution, DnsError,
};

// Re-export transport types
pub use transport::{
    Transport, TcpTransport, WsTransport, WsConnector, WsConfig,
    TlsTransport, TlsConfig, RealityConfig,
    GrpcTransport, GrpcConfig,
};

// Configuration module with hot reload support
pub mod config;
pub use config::{
    HotReload, HotReloadError, HotReloadable,
    ConfigEvent, WatchEvent, WatchEventKind,
};

// Metrics module with Prometheus export
pub mod metrics;
pub use metrics::{
    MetricsServer,
    // Counter functions
    inc_connection, inc_bytes_sent, inc_bytes_received,
    inc_rule_match, inc_dns_resolution, inc_error, inc_node_latency_test,
    // Gauge functions
    inc_active_connections, dec_active_connections,
    inc_active_tcp_connections, dec_active_tcp_connections,
    inc_active_udp_connections, dec_active_udp_connections,
    set_connection_pool_size, set_node_count, set_node_latency,
    set_memory_usage, set_ebpf_map_entries,
    // Histogram functions
    observe_connection_duration, observe_request_size,
    observe_response_time, observe_dns_latency,
    observe_ebpf_latency, observe_rule_match_latency, observe_node_latency,
    // Server
    start_metrics_server, stop_metrics_server,
};
