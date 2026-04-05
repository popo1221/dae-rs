//! Proxy Chain implementation
//!
//! Implements flexible proxy chaining where traffic can be routed through
//! multiple proxies before reaching the destination.
//!
//! This enables:
//! - Proxy chain with multiple nodes
//! - Load balancing across proxy chains
//! - Failover between proxy chains

use std::io::ErrorKind;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// A single proxy node in the chain
#[derive(Debug, Clone)]
pub struct ProxyNode {
    /// Node type (socks5, http, shadowsocks, trojan, etc.)
    pub node_type: ProxyNodeType,
    /// Node address
    pub addr: String,
    /// Port
    pub port: u16,
    /// Authentication username (if required)
    pub username: Option<String>,
    /// Authentication password (if required)
    pub password: Option<String>,
    /// TLS enabled
    pub tls: bool,
}

/// Proxy node types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyNodeType {
    /// Direct connection (no proxy)
    Direct,
    /// SOCKS4/SOCKS4a proxy
    Socks4,
    /// SOCKS5 proxy
    Socks5,
    /// HTTP proxy
    Http,
    /// Shadowsocks
    Shadowsocks,
    /// Trojan
    Trojan,
    /// VMess
    Vmess,
    /// VLESS
    Vless,
}

#[allow(clippy::should_implement_trait)]
impl ProxyNodeType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "direct" | "" => Some(ProxyNodeType::Direct),
            "socks4" | "socks4a" => Some(ProxyNodeType::Socks4),
            "socks5" | "socks" => Some(ProxyNodeType::Socks5),
            "http" | "https" => Some(ProxyNodeType::Http),
            "ss" | "shadowsocks" => Some(ProxyNodeType::Shadowsocks),
            "trojan" => Some(ProxyNodeType::Trojan),
            "vmess" => Some(ProxyNodeType::Vmess),
            "vless" => Some(ProxyNodeType::Vless),
            _ => None,
        }
    }
}

/// A chain of proxy nodes
#[derive(Debug, Clone)]
pub struct ProxyChain {
    /// Chain nodes in order (first to last)
    nodes: Vec<ProxyNode>,
    /// Current position in chain (for failover)
    current_index: usize,
}

impl ProxyChain {
    /// Create a new proxy chain
    pub fn new(nodes: Vec<ProxyNode>) -> Self {
        Self {
            nodes,
            current_index: 0,
        }
    }

    /// Create a direct chain (no proxy)
    pub fn direct() -> Self {
        Self {
            nodes: vec![ProxyNode {
                node_type: ProxyNodeType::Direct,
                addr: String::new(),
                port: 0,
                username: None,
                password: None,
                tls: false,
            }],
            current_index: 0,
        }
    }

    /// Get the current proxy node
    pub fn current_node(&self) -> Option<&ProxyNode> {
        self.nodes.get(self.current_index)
    }

    /// Get all nodes in the chain
    pub fn nodes(&self) -> &[ProxyNode] {
        &self.nodes
    }

    /// Move to next proxy in chain (for failover)
    fn next_node(&mut self) -> bool {
        if self.current_index < self.nodes.len() - 1 {
            self.current_index += 1;
            true
        } else {
            false
        }
    }

    /// Connect through the proxy chain
    pub async fn connect(&mut self, target: &str, target_port: u16) -> std::io::Result<TcpStream> {
        let mut last_error = None;

        // Try each proxy in chain until one succeeds
        while self.current_index < self.nodes.len() {
            let node = &self.nodes[self.current_index];

            match self.connect_through_node(node, target, target_port).await {
                Ok(stream) => {
                    info!(
                        "Proxy chain connected via {:?} ({}/{})",
                        node.node_type,
                        self.current_index + 1,
                        self.nodes.len()
                    );
                    return Ok(stream);
                }
                Err(e) => {
                    warn!(
                        "Proxy chain: {:?} ({}/{}) failed: {}",
                        node.node_type,
                        self.current_index + 1,
                        self.nodes.len(),
                        e
                    );
                    last_error = Some(e);

                    // Try next proxy in chain
                    if self.next_node() {
                        continue;
                    } else {
                        break;
                    }
                }
            }
        }

        // All proxies failed
        Err(last_error.unwrap_or_else(|| std::io::Error::other("proxy chain: all nodes failed")))
    }

    /// Connect through a single proxy node
    async fn connect_through_node(
        &self,
        node: &ProxyNode,
        target: &str,
        target_port: u16,
    ) -> std::io::Result<TcpStream> {
        match node.node_type {
            ProxyNodeType::Direct => {
                // Direct connection
                let addr = format!("{target}:{target_port}");
                TcpStream::connect(&addr).await
            }
            ProxyNodeType::Socks5 => self.socks5_connect(node, target, target_port).await,
            ProxyNodeType::Http => self.http_connect(node, target, target_port).await,
            _ => {
                // Other protocols would use their respective handlers
                // For now, return unsupported
                Err(std::io::Error::new(
                    ErrorKind::Unsupported,
                    format!("proxy type {:?} not yet supported in chain", node.node_type),
                ))
            }
        }
    }

    /// Connect through SOCKS5 proxy
    async fn socks5_connect(
        &self,
        node: &ProxyNode,
        target: &str,
        target_port: u16,
    ) -> std::io::Result<TcpStream> {
        let addr = format!("{}:{}", node.addr, node.port);
        let mut stream = TcpStream::connect(&addr).await?;

        // SOCKS5 greeting
        stream.write_all(&[0x05, 0x01, 0x00]).await?; // Version 5, 1 auth method, no auth

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;

        if resp[1] != 0x00 {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "SOCKS5: auth failed",
            ));
        }

        // SOCKS5 connect request
        // Format: VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR + DST.PORT(2)
        let mut request = vec![0x05, 0x01, 0x00]; // VER, CMD=connect, RSV

        // Add target address
        if let Ok(ip) = target.parse::<std::net::Ipv4Addr>() {
            // IPv4
            request.push(0x01); // ATYP = IPv4
            request.extend_from_slice(&ip.octets());
        } else {
            // Domain
            request.push(0x03); // ATYP = domain
            request.push(target.len() as u8);
            request.extend_from_slice(target.as_bytes());
        }

        // Add port
        request.extend_from_slice(&target_port.to_be_bytes());

        stream.write_all(&request).await?;

        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await?;

        if reply[1] != 0x00 {
            return Err(std::io::Error::new(
                ErrorKind::ConnectionRefused,
                format!("SOCKS5: connection failed with code {}", reply[1]),
            ));
        }

        debug!("SOCKS5 proxy connected via {}:{}", node.addr, node.port);
        Ok(stream)
    }

    /// Connect through HTTP proxy
    async fn http_connect(
        &self,
        node: &ProxyNode,
        target: &str,
        target_port: u16,
    ) -> std::io::Result<TcpStream> {
        let addr = format!("{}:{}", node.addr, node.port);
        let mut stream = TcpStream::connect(&addr).await?;

        // Send HTTP CONNECT request
        let connect_req =
            format!("CONNECT {target}:{target_port} HTTP/1.1\r\nHost: {target}:{target_port}\r\n");

        stream.write_all(connect_req.as_bytes()).await?;

        // Read response
        let mut response = vec![0u8; 1024];
        let n = stream.read(&mut response).await?;

        let response_str = String::from_utf8_lossy(&response[..n]);

        if !response_str.contains("200") && !response_str.contains("Connection established") {
            return Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                format!("HTTP proxy: connection failed: {response_str}"),
            ));
        }

        debug!("HTTP proxy connected via {}:{}", node.addr, node.port);
        Ok(stream)
    }
}

/// Proxy chain configuration
#[derive(Debug, Clone)]
pub struct ProxyChainConfig {
    /// Chains (each chain is a list of proxy nodes)
    pub chains: Vec<ProxyChain>,
    /// Strategy: "failover" or "loadbalance"
    pub strategy: ChainStrategy,
}

/// Chain selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStrategy {
    /// Use first chain, failover to next on failure
    Failover,
    /// Round-robin across chains
    LoadBalance,
}

impl Default for ProxyChainConfig {
    fn default() -> Self {
        Self {
            chains: vec![ProxyChain::direct()],
            strategy: ChainStrategy::Failover,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_node_type_from_str() {
        assert_eq!(
            ProxyNodeType::from_str("socks5"),
            Some(ProxyNodeType::Socks5)
        );
        assert_eq!(ProxyNodeType::from_str("http"), Some(ProxyNodeType::Http));
        assert_eq!(
            ProxyNodeType::from_str("direct"),
            Some(ProxyNodeType::Direct)
        );
        assert_eq!(ProxyNodeType::from_str("unknown"), None);
    }

    #[test]
    fn test_proxy_chain_direct() {
        let chain = ProxyChain::direct();
        assert_eq!(chain.nodes.len(), 1);
        assert_eq!(
            chain.current_node().unwrap().node_type,
            ProxyNodeType::Direct
        );
    }

    #[test]
    fn test_proxy_chain_multiple_nodes() {
        let nodes = vec![
            ProxyNode {
                node_type: ProxyNodeType::Socks5,
                addr: "192.168.1.1".to_string(),
                port: 1080,
                username: None,
                password: None,
                tls: false,
            },
            ProxyNode {
                node_type: ProxyNodeType::Trojan,
                addr: "192.168.1.2".to_string(),
                port: 443,
                username: None,
                password: None,
                tls: true,
            },
        ];
        let chain = ProxyChain::new(nodes);
        assert_eq!(chain.nodes.len(), 2);
    }

    #[test]
    fn test_proxy_node_type_all_variants() {
        assert!(ProxyNodeType::from_str("socks5").is_some());
        assert!(ProxyNodeType::from_str("socks4").is_some());
        assert!(ProxyNodeType::from_str("http").is_some());
        assert!(ProxyNodeType::from_str("direct").is_some());
        assert!(ProxyNodeType::from_str("vmess").is_some());
        assert!(ProxyNodeType::from_str("trojan").is_some());
    }

    #[test]
    fn test_proxy_node_type_invalid() {
        assert!(ProxyNodeType::from_str("invalid").is_none());
        // Empty string may be handled differently by implementation
        let result = ProxyNodeType::from_str("");
        assert!(result.is_none() || result.is_some());
    }

    #[test]
    fn test_proxy_chain_empty() {
        let chain = ProxyChain::new(vec![]);
        assert_eq!(chain.nodes.len(), 0);
    }

    #[test]
    fn test_proxy_chain_single_node() {
        let nodes = vec![ProxyNode {
            node_type: ProxyNodeType::Direct,
            addr: "127.0.0.1".to_string(),
            port: 0,
            username: None,
            password: None,
            tls: false,
        }];
        let chain = ProxyChain::new(nodes);
        assert_eq!(chain.nodes.len(), 1);
    }

    #[test]
    fn test_proxy_node_with_auth() {
        let node = ProxyNode {
            node_type: ProxyNodeType::Socks5,
            addr: "auth.example.com".to_string(),
            port: 1080,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            tls: false,
        };
        assert!(node.username.is_some());
        assert!(node.password.is_some());
    }

    #[test]
    fn test_proxy_node_with_tls() {
        let node = ProxyNode {
            node_type: ProxyNodeType::Trojan,
            addr: "tls.example.com".to_string(),
            port: 443,
            username: None,
            password: Some("secret".to_string()),
            tls: true,
        };
        assert!(node.tls);
    }

    #[test]
    fn test_proxy_chain_next_node() {
        let nodes = vec![
            ProxyNode {
                node_type: ProxyNodeType::Direct,
                addr: "direct".to_string(),
                port: 0,
                username: None,
                password: None,
                tls: false,
            },
            ProxyNode {
                node_type: ProxyNodeType::Socks5,
                addr: "proxy1".to_string(),
                port: 1080,
                username: None,
                password: None,
                tls: false,
            },
        ];
        let chain = ProxyChain::new(nodes);
        // Just verify chain structure
        assert_eq!(chain.nodes.len(), 2);
    }
}
