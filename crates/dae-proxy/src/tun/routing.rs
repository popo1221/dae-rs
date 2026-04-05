//! Routing types for TUN proxy

/// Result of routing a packet
#[derive(Debug, Clone)]
pub enum RouteResult {
    /// Packet was dropped
    Dropped,
    /// Packet was forwarded (direct or proxy)
    Forwarded,
    /// Packet should be responded to (e.g., DNS response)
    Response(Vec<u8>),
}
