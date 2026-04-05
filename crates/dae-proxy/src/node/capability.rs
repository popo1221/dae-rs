//! Node Capabilities Module
//!
//! Provides capability detection and representation for proxy nodes.
//! This enables protocol-oriented node features detecting/filtering.

/// Node capability attributes
#[derive(Debug, Clone, Default)]
pub struct NodeCapabilities {
    /// Full-Cone NAT support
    pub fullcone: bool,
    /// UDP protocol support
    pub udp: bool,
    /// V2Ray compatibility
    pub v2ray: bool,
}

impl NodeCapabilities {
    /// Create new empty capabilities
    pub fn new() -> Self {
        Self::default()
    }

    /// Create capabilities with all features disabled
    pub fn none() -> Self {
        Self {
            fullcone: false,
            udp: false,
            v2ray: false,
        }
    }

    /// Create capabilities with all features enabled (assumed)
    pub fn all() -> Self {
        Self {
            fullcone: true,
            udp: true,
            v2ray: true,
        }
    }

    /// Set full-cone NAT support
    pub fn with_fullcone(mut self, enabled: bool) -> Self {
        self.fullcone = enabled;
        self
    }

    /// Set UDP support
    pub fn with_udp(mut self, enabled: bool) -> Self {
        self.udp = enabled;
        self
    }

    /// Set V2Ray compatibility
    pub fn with_v2ray(mut self, enabled: bool) -> Self {
        self.v2ray = enabled;
        self
    }

    /// Check if this node supports UDP
    pub fn supports_udp(&self) -> bool {
        self.udp
    }

    /// Check if this node supports full-cone NAT
    pub fn supports_fullcone(&self) -> bool {
        self.fullcone
    }

    /// Check if this node is V2Ray compatible
    pub fn is_v2ray_compatible(&self) -> bool {
        self.v2ray
    }
}

/// Capability detection result
#[derive(Debug, Clone)]
pub struct CapabilityDetectionResult {
    /// Detected capabilities
    pub capabilities: NodeCapabilities,
    /// Detection method used
    pub method: DetectionMethod,
    /// Timestamp of detection
    pub timestamp: std::time::Instant,
}

impl CapabilityDetectionResult {
    /// Create a new detection result
    pub fn new(capabilities: NodeCapabilities, method: DetectionMethod) -> Self {
        Self {
            capabilities,
            method,
            timestamp: std::time::Instant::now(),
        }
    }
}

/// Detection method used to determine capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod {
    /// Capabilities were explicitly configured
    Configured,
    /// Capabilities were auto-detected via STUN
    Stun,
    /// Capabilities were inferred from protocol behavior
    Inferred,
    /// Capabilities are unknown (default)
    Unknown,
}

/// Capability filter for routing rules
#[derive(Debug, Clone, Default)]
pub struct CapabilityFilter {
    /// Required full-cone support (None = don't care)
    pub fullcone: Option<bool>,
    /// Required UDP support (None = don't care)
    pub udp: Option<bool>,
    /// Required V2Ray compatibility (None = don't care)
    pub v2ray: Option<bool>,
}

impl CapabilityFilter {
    /// Create a new filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Create filter requiring full-cone NAT
    pub fn require_fullcone(mut self) -> Self {
        self.fullcone = Some(true);
        self
    }

    /// Create filter requiring UDP support
    pub fn require_udp(mut self) -> Self {
        self.udp = Some(true);
        self
    }

    /// Create filter requiring V2Ray compatibility
    pub fn require_v2ray(mut self) -> Self {
        self.v2ray = Some(true);
        self
    }

    /// Check if a node matches this filter
    pub fn matches(&self, capabilities: &NodeCapabilities) -> bool {
        if let Some(required_fullcone) = self.fullcone {
            if capabilities.fullcone != required_fullcone {
                return false;
            }
        }
        if let Some(required_udp) = self.udp {
            if capabilities.udp != required_udp {
                return false;
            }
        }
        if let Some(required_v2ray) = self.v2ray {
            if capabilities.v2ray != required_v2ray {
                return false;
            }
        }
        true
    }
}

/// Inference capabilities based on node type and protocol
pub fn infer_capabilities(node_type: &str) -> NodeCapabilities {
    match node_type {
        "vless" | "vmess" => {
            // VLESS/VMess typically support UDP and can be full-cone
            NodeCapabilities::all()
        }
        "shadowsocks" | "trojan" => {
            // Shadowsocks and Trojan support UDP
            NodeCapabilities::new().with_udp(true)
        }
        "socks5" => {
            // SOCKS5 supports UDP associate
            NodeCapabilities::new().with_udp(true)
        }
        "http" | "http_proxy" => {
            // HTTP proxy doesn't support UDP
            NodeCapabilities::none()
        }
        _ => NodeCapabilities::none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_defaults() {
        let caps = NodeCapabilities::new();
        assert!(!caps.fullcone);
        assert!(!caps.udp);
        assert!(!caps.v2ray);
    }

    #[test]
    fn test_capability_builder() {
        let caps = NodeCapabilities::none()
            .with_fullcone(true)
            .with_udp(true)
            .with_v2ray(false);

        assert!(caps.fullcone);
        assert!(caps.udp);
        assert!(!caps.v2ray);
    }

    #[test]
    fn test_capability_filter_fullcone() {
        let filter = CapabilityFilter::new().require_fullcone();
        let caps = NodeCapabilities::none().with_fullcone(true);
        assert!(filter.matches(&caps));

        let caps = NodeCapabilities::none().with_fullcone(false);
        assert!(!filter.matches(&caps));
    }

    #[test]
    fn test_capability_filter_udp() {
        let filter = CapabilityFilter::new().require_udp();
        let caps = NodeCapabilities::none().with_udp(true);
        assert!(filter.matches(&caps));

        let caps = NodeCapabilities::none().with_udp(false);
        assert!(!filter.matches(&caps));
    }

    #[test]
    fn test_infer_capabilities_vless() {
        let caps = infer_capabilities("vless");
        assert!(caps.fullcone);
        assert!(caps.udp);
        assert!(caps.v2ray);
    }

    #[test]
    fn test_infer_capabilities_shadowsocks() {
        let caps = infer_capabilities("shadowsocks");
        assert!(!caps.fullcone);
        assert!(caps.udp);
        assert!(!caps.v2ray);
    }

    #[test]
    fn test_infer_capabilities_http() {
        let caps = infer_capabilities("http");
        assert!(!caps.fullcone);
        assert!(!caps.udp);
        assert!(!caps.v2ray);
    }
}
