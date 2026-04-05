//! dae-proxy 节点管理 - 核心 trait 和类型定义
//!
//! 本模块定义了所有代理节点类型必须实现的 Node trait。

use async_trait::async_trait;

// Re-export NodeError from the centralized error module
pub use crate::core::error::NodeError;

/// 节点 ID 类型 - 在配置中唯一标识一个节点
pub type NodeId = String;

/// 节点 trait - 所有节点类型都必须实现此 trait
///
/// 此 trait 定义了所有代理节点的通用接口，包括直接路由节点和上游代理节点。
#[async_trait]
pub trait Node: Send + Sync {
    /// 获取节点的唯一标识符
    fn id(&self) -> &NodeId;

    /// 获取节点的显示名称
    fn name(&self) -> &str;

    /// 获取节点使用的协议名称
    fn protocol(&self) -> &'static str;

    /// Ping 节点并返回延迟（毫秒）
    async fn ping(&self) -> Result<u32, NodeError>;

    /// 检查节点当前是否可用
    async fn is_available(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_error_timeout_is_retryable() {
        let err = NodeError::Timeout;
        assert!(err.is_retryable());
    }

    #[test]
    fn test_node_error_connection_failed_not_retryable() {
        let err = NodeError::ConnectionFailed("connection refused".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_node_error_unavailable_not_retryable() {
        let err = NodeError::Unavailable("node-1".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_node_error_display_timeout() {
        let err = NodeError::Timeout;
        assert_eq!(format!("{}", err), "timeout");
    }

    #[test]
    fn test_node_error_display_connection_failed() {
        let err = NodeError::ConnectionFailed("refused".to_string());
        assert!(format!("{}", err).contains("refused"));
    }

    #[test]
    fn test_node_error_display_unavailable() {
        let err = NodeError::Unavailable("node-1".to_string());
        assert!(format!("{}", err).contains("node unavailable"));
    }
}
