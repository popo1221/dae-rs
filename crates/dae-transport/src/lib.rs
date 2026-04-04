//! dae-transport - Transport layer implementations for dae-rs
//!
//! Provides various transport protocols:
//! - TCP: Plain TCP connections
//! - TLS: TLS/Reality transport
//! - WebSocket: WebSocket transport
//! - gRPC: gRPC transport

pub mod traits;
pub mod tcp;
pub mod tls;
pub mod ws;
pub mod grpc;
pub mod httpupgrade;
pub mod meek;

pub use traits::{Transport, MAX_UDP_PACKET_SIZE};
pub use tcp::TcpTransport;
pub use tls::{TlsConfig, TlsTransport, RealityConfig};
pub use ws::{WsConfig, WsTransport};
pub use grpc::{GrpcConfig, GrpcTransport};
pub use httpupgrade::HttpUpgradeTransport;
pub use meek::{MeekConfig, MeekTactic, MeekTransport};
