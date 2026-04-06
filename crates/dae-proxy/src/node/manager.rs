//! NodeManager trait - 节点生命周期管理
//!
//! 本模块定义 NodeManager trait，用于管理节点注册、选择和延迟追踪。

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

pub use super::hash::{fnv1a_hash, sip_hash, Fnv1aHasher, SipHasher};
pub use super::node::{Node, NodeError, NodeId};

/// 连接指纹 - 用于基于哈希的负载均衡策略
///
/// 记录连接的 5 元组信息，用于一致性哈希等策略。
#[derive(Debug, Clone, Default)]
pub struct ConnectionFingerprint {
    /// 源 IP（网络字节序，IPv4 为 u32）
    pub src_ip: u32,
    /// 目标 IP（网络字节序，IPv4 为 u32）
    pub dst_ip: u32,
    /// 源端口
    pub src_port: u16,
    /// 目标端口
    pub dst_port: u16,
    /// 协议（6=TCP, 17=UDP）
    pub proto: u8,
    /// URL 或主机名（用于基于 URL 的哈希，可选）
    pub url: Option<String>,
}

impl ConnectionFingerprint {
    /// Create from 5-tuple
    pub fn from_5tuple(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
            url: None,
        }
    }

    /// Create from source IP only (for sticky session)
    pub fn from_src_ip(src_ip: u32) -> Self {
        Self {
            src_ip,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            proto: 0,
            url: None,
        }
    }

    /// Calculate hash for consistent hashing
    ///
    /// Uses FNV-1a (Fowler–Noll–Vo) hash algorithm for non-cryptographic
    /// hashing with good distribution properties. This is NOT SipHash
    /// (which was incorrectly documented in the original implementation).
    ///
    /// FNV-1a is used here instead of SipHash because:
    /// - Consistent hashing doesn't need anti-hash-flood protection
    /// - FNV-1a is faster for non-keyed hashing
    /// - Matches the documented behavior
    pub fn hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut s = Fnv1aHasher::new();
        self.src_ip.hash(&mut s);
        self.dst_ip.hash(&mut s);
        self.src_port.hash(&mut s);
        self.dst_port.hash(&mut s);
        self.proto.hash(&mut s);
        if let Some(ref url) = self.url {
            url.hash(&mut s);
        }
        s.finish()
    }
}

/// 节点选择策略
///
/// 定义了多种节点选择策略，用于决定如何从可用节点池中选择一个节点处理连接。
#[derive(Debug, Clone)]
pub enum SelectionPolicy {
    /// 选择延迟最低的节点
    LowestLatency,
    /// 根据 ID 选择特定节点
    Specific(NodeId),
    /// 随机选择一个可用节点
    Random,
    /// 轮询选择节点（需要在选择器中使用原子计数器）
    RoundRobin,
    /// 优先直连（不经过代理）
    PreferDirect,
    /// 一致性哈希 - 相同指纹始终路由到相同节点
    ConsistentHashing(ConnectionFingerprint),
    /// 粘性会话 - 基于源 IP 哈希
    StickySession(ConnectionFingerprint),
    /// URL 哈希 - 基于 HTTP host/URL 哈希
    UrlHash(ConnectionFingerprint),
}

/// NodeManager trait - manages node lifecycle and selection
///
/// This trait provides the core functionality for:
/// - Node registration and lookup
/// - Node selection based on policies
/// - Latency tracking and updates
/// - Health state management
#[async_trait]
pub trait NodeManager: Send + Sync {
    /// Select a node based on the given policy
    async fn select(&self, policy: &SelectionPolicy) -> Option<Arc<dyn Node>>;

    /// Get a specific node by ID
    fn get(&self, id: &NodeId) -> Option<Arc<dyn Node>>;

    /// Get all registered nodes
    async fn all_nodes(&self) -> Vec<Arc<dyn Node>>;

    /// Get all available (online) nodes
    async fn available_nodes(&self) -> Vec<Arc<dyn Node>>;

    /// Update the latency for a specific node
    async fn update_latency(&self, node_id: &NodeId, latency: u32);

    /// Mark a node as offline
    async fn set_offline(&self, node_id: &NodeId);

    /// Get the latency for a specific node (if known)
    fn get_latency(&self, node_id: &NodeId) -> Option<u32>;

    /// Run latency tests for all nodes and return results
    async fn run_latency_test(&self) -> HashMap<NodeId, u32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selection_policy_lowest_latency() {
        let policy = SelectionPolicy::LowestLatency;
        assert!(matches!(policy, SelectionPolicy::LowestLatency));
    }

    #[test]
    fn test_selection_policy_specific() {
        let policy = SelectionPolicy::Specific("node1".to_string());
        assert!(matches!(policy, SelectionPolicy::Specific(_)));
        if let SelectionPolicy::Specific(id) = policy {
            assert_eq!(id, "node1");
        }
    }

    #[test]
    fn test_selection_policy_random() {
        let policy = SelectionPolicy::Random;
        assert!(matches!(policy, SelectionPolicy::Random));
    }

    #[test]
    fn test_selection_policy_round_robin() {
        let policy = SelectionPolicy::RoundRobin;
        assert!(matches!(policy, SelectionPolicy::RoundRobin));
    }

    #[test]
    fn test_selection_policy_prefer_direct() {
        let policy = SelectionPolicy::PreferDirect;
        assert!(matches!(policy, SelectionPolicy::PreferDirect));
    }

    #[test]
    fn test_selection_policy_clone() {
        let policy1 = SelectionPolicy::Specific("node1".to_string());
        let policy2 = policy1.clone();

        if let SelectionPolicy::Specific(id1) = policy1 {
            if let SelectionPolicy::Specific(id2) = policy2 {
                assert_eq!(id1, id2);
            } else {
                // This should never happen - policy2 was cloned from policy1 which is Specific
                unreachable!("clone() produced wrong variant");
            }
        } else {
            // This should never happen - policy1 was directly set to Specific
            unreachable!("initial policy was not Specific");
        }
    }
}
