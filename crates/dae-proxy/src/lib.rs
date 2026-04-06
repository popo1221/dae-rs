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
// HTTP proxy protocol from external crate (module alias for internal path compatibility)
pub use crate::protocol_dispatcher::{ProtocolDispatcher, ProtocolDispatcherConfig};
pub use crate::proxy::{Proxy, ProxyConfig, ProxyError};
pub use dae_protocol_http_proxy as http_proxy;
// Shadowsocks protocol from external crate (module alias for internal path compatibility)
pub use crate::tcp::{TcpProxy, TcpProxyConfig};
pub use crate::udp::{UdpProxy, UdpProxyConfig};
pub use dae_protocol_shadowsocks as shadowsocks;
// VLESS protocol from external crate (module alias for internal path compatibility)
pub use dae_protocol_vless as vless;
// VMess protocol from external crate (module alias for internal path compatibility)
pub use dae_protocol_vmess as vmess;

// Control plane types (local module)
pub use crate::control::{
    connect_and_get_status, connect_and_send, ControlCommand, ControlResponse, ControlServer,
    ControlState, NodeTestResult, ProxyStats, ProxyStatus,
};

// Logging module exports
pub use crate::core::{Context, Error, Result};
// Juicity protocol from external crate (QUIC-based, optional)
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
#[cfg(feature = "protocol-juicity")]
pub use dae_protocol_juicity as juicity;
// Trojan protocol from external crate (module alias for internal path compatibility)
pub use dae_protocol_trojan as trojan_protocol;

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
// HTTP proxy, QUIC-based protocols from external crates
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
// SOCKS4/5 protocols (extracted from dae-proxy)
pub use dae_protocol_socks4::{
    Socks4Address, Socks4Command, Socks4Config, Socks4Reply, Socks4Request, Socks4Server,
};
pub use dae_protocol_socks5::{
    auth::{
        AuthHandler, CombinedAuthHandler, NoAuthHandler, UserCredentials, UsernamePasswordHandler,
    },
    commands::Socks5Command,
    handshake::Handshake,
    reply::Socks5Reply,
    Socks5Address, Socks5Handler, Socks5HandlerConfig, Socks5Server,
};

// Re-export commonly used protocol types at crate root for convenience
pub use dae_protocol_http_proxy::{HttpProxyHandler, HttpProxyServer};
#[cfg(feature = "protocol-hysteria2")]
pub use dae_protocol_hysteria2::{
    Hysteria2Config, Hysteria2Error, Hysteria2Handler, Hysteria2Server,
};
#[cfg(feature = "protocol-juicity")]
pub use dae_protocol_juicity::{
    CongestionControl, JuicityAddress, JuicityClient, JuicityCodec, JuicityCommand, JuicityConfig,
    JuicityConnection, JuicityError, JuicityFrame, JuicityHandler, JuicityServer,
};
pub use dae_protocol_shadowsocks::{
    ObfsConfig, ObfsHttp, ObfsMode, ObfsStream, ObfsTls, ShadowsocksHandler, ShadowsocksServer,
    SsCipherType, SsClientConfig, SsServerConfig, SsrClientConfig, SsrHandler, SsrObfs,
    SsrObfsHandler, SsrProtocol, SsrServerConfig, V2rayConfig, V2rayMode, V2rayPlugin, V2rayStream,
};
pub use dae_protocol_trojan::{
    TrojanAddressType, TrojanClientConfig, TrojanCommand, TrojanHandler, TrojanServer,
    TrojanServerConfig, TrojanTargetAddress, TrojanTlsConfig,
};
#[cfg(feature = "protocol-tuic")]
pub use dae_protocol_tuic::{
    TuicClient, TuicCodec, TuicCommand, TuicCommandType, TuicConfig, TuicError, TuicHandler,
    TuicServer,
};
pub use dae_protocol_vless::{
    VlessAddressType, VlessClientConfig, VlessCommand, VlessHandler, VlessRealityConfig,
    VlessServer, VlessServerConfig, VlessTargetAddress, VlessTlsConfig,
};
pub use dae_protocol_vmess::{
    VmessAddressType, VmessClientConfig, VmessCommand, VmessHandler, VmessSecurity, VmessServer,
    VmessServerConfig, VmessTargetAddress,
};

pub mod tcp;
pub mod tracking;
pub mod transport;
// TUIC protocol from external crate (QUIC-based, optional)
#[cfg(feature = "protocol-tuic")]
pub use dae_protocol_tuic as tuic;

pub mod tun;
pub mod udp;

// Process rule engine exports
pub use crate::process::{
    match_process_name, ProcessInfo, ProcessMatchRule, ProcessResolver, ProcessRuleSet,
    ProcessRuleSetBuilder, TASK_COMM_LEN,
};

// MAC address rule engine exports
pub use crate::mac::{MacAddr, MacRule, MacRuleSet, OuiDatabase};

// Hysteria2 protocol from external crate (QUIC-based, optional)
#[cfg(feature = "protocol-hysteria2")]
pub use dae_protocol_hysteria2 as hysteria2;

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
