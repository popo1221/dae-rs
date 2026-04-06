//! 节点能力规则模块
//!
//! 包含节点能力和节点标签规则类型及匹配逻辑。

use crate::rule_engine::PacketInfo;

/// 节点能力类型
///
/// 定义节点支持的不同能力。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityType {
    /// 全锥型 NAT（Full-Cone NAT）能力
    FullCone,
    /// UDP 协议支持
    Udp,
    /// V2Ray 兼容性
    V2Ray,
}

/// 节点能力规则
///
/// 根据节点能力匹配数据包的规则。
#[derive(Debug, Clone)]
pub struct CapabilityRule {
    /// Capability type to match
    pub capability: CapabilityType,
    /// Expected value (true/false)
    pub expected_value: bool,
}

impl CapabilityRule {
    /// Create a new capability rule from type string and value
    ///
    /// Supported formats:
    /// - "fullcone" or "fullcone(true)" or "fullcone(enabled)" -> FullCone with true
    /// - "fullcone(false)" or "fullcone(disabled)" -> FullCone with false
    /// - "udp" or "udp(true)" -> Udp with true
    /// - "v2ray" or "v2ray(compatible)" -> V2Ray with true
    pub fn new(capability_str: &str, value_str: &str) -> Result<Self, String> {
        let capability = match capability_str.to_lowercase().as_str() {
            "fullcone" | "full-cone" => CapabilityType::FullCone,
            "udp" => CapabilityType::Udp,
            "v2ray" | "v2ray(compatible)" => CapabilityType::V2Ray,
            _ => return Err(format!("Unknown capability type: {capability_str}")),
        };

        let expected_value = match value_str.to_lowercase().as_str() {
            "true" | "1" | "enabled" | "compatible" => true,
            "false" | "0" | "disabled" => false,
            _ => return Err(format!("Invalid capability value: {value_str}")),
        };

        Ok(Self {
            capability,
            expected_value,
        })
    }

    /// Check if this rule matches the given packet info
    pub fn matches_packet(&self, info: &PacketInfo) -> bool {
        // Get the actual capability value from packet info
        let actual_value = match self.capability {
            CapabilityType::FullCone => info.node_fullcone.unwrap_or(false),
            CapabilityType::Udp => info.node_udp.unwrap_or(true),
            CapabilityType::V2Ray => info.node_v2ray.unwrap_or(true),
        };
        actual_value == self.expected_value
    }
}

/// Node tag rule - matches packets based on the selected node's tag
///
/// This rule type is used to route traffic to nodes with specific tags.
/// For example, a rule with tag "hk" would match if the selected node
/// has the "hk" tag.
///
/// Note: Node-tag rules require node tag support in the proxy chain.
/// The `PacketInfo.node_tag` field must be set before rule matching for
/// this rule type to work correctly.
#[derive(Debug, Clone)]
pub struct NodeTagRule {
    /// Tag to match against
    pub tag: String,
}

impl NodeTagRule {
    /// Create a new node tag rule
    pub fn new(tag: &str) -> Self {
        Self {
            tag: tag.to_lowercase(),
        }
    }

    /// Check if this rule matches the given packet info
    ///
    /// Returns true if the packet info's `node_tag` matches this rule's tag.
    /// If `node_tag` is not set (None), returns false.
    pub fn matches_packet(&self, info: &PacketInfo) -> bool {
        // node_tag must be set by the node selector before rule matching
        // For now, we check if info.node_tag matches our tag
        // This will be implemented fully when node group support is added
        if let Some(ref node_tag) = info.node_tag {
            node_tag.to_lowercase() == self.tag
        } else {
            // If no node tag is set, we can't match
            // This is expected behavior when node-tag rules are used but
            // node selection hasn't populated the tag yet
            false
        }
    }
}
