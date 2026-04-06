//! TUN 代理的 UDP 会话处理

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// TUN 代理的 UDP 会话数据
///
/// 存储 UDP 会话的状态和 socket 信息。
#[derive(Debug)]
pub struct UdpSessionData {
    /// Client address (TUN side)
    pub client_addr: SocketAddr,
    /// Server address (network side)
    pub server_addr: SocketAddr,
    /// Client socket
    pub client_socket: Arc<UdpSocket>,
    /// Server socket
    pub server_socket: Arc<UdpSocket>,
    /// Last activity time
    pub last_activity: Instant,
}

impl UdpSessionData {
    /// Create a new UDP session
    pub fn new(
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        client_socket: Arc<UdpSocket>,
        server_socket: Arc<UdpSocket>,
    ) -> Self {
        Self {
            client_addr,
            server_addr,
            client_socket,
            server_socket,
            last_activity: Instant::now(),
        }
    }

    /// Check if session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}
