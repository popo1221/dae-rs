//! 代理节点健康检查模块
//!
//! 本模块提供健康检查功能，用于监控节点的可用性和性能。

use std::sync::Arc;
use std::time::Duration;

use super::node::{Node, NodeError, NodeId};

/// 健康检查结果
///
/// 包含节点健康检查的详细结果。
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub node_id: NodeId,
    pub is_healthy: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<NodeError>,
}

/// 健康检查器配置
///
/// 配置健康检查的各项参数。
#[derive(Debug, Clone)]
pub struct HealthCheckerConfig {
    /// Interval between health checks
    pub check_interval: Duration,
    /// Timeout for each health check
    pub check_timeout: Duration,
    /// Number of consecutive failures before marking node offline
    pub failure_threshold: u32,
    /// Number of consecutive successes before marking node online
    pub recovery_threshold: u32,
}

impl Default for HealthCheckerConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            check_timeout: Duration::from_secs(10),
            failure_threshold: 3,
            recovery_threshold: 2,
        }
    }
}

/// 健康检查器 - 监控节点健康状态
///
/// 对节点执行定期健康检查并追踪可用性指标。
pub struct HealthChecker {
    config: HealthCheckerConfig,
}

impl HealthChecker {
    /// 使用指定配置创建新的健康检查器
    pub fn new(config: HealthCheckerConfig) -> Self {
        Self { config }
    }

    /// Create a HealthChecker with default configuration
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self::new(HealthCheckerConfig::default())
    }

    /// Check the health of a single node
    pub async fn check_node(node: &Arc<dyn Node>) -> HealthCheckResult {
        let node_id = node.id().clone();

        match node.ping().await {
            Ok(latency) => HealthCheckResult {
                node_id,
                is_healthy: true,
                latency_ms: Some(latency),
                error: None,
            },
            Err(e) => HealthCheckResult {
                node_id,
                is_healthy: false,
                latency_ms: None,
                error: Some(e),
            },
        }
    }

    /// Check health of multiple nodes concurrently
    pub async fn check_nodes(nodes: &[Arc<dyn Node>]) -> Vec<HealthCheckResult> {
        let futures: Vec<_> = nodes.iter().map(Self::check_node).collect();

        futures::future::join_all(futures).await
    }

    /// Get the configuration
    pub fn config(&self) -> &HealthCheckerConfig {
        &self.config
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct TestNode {
        id: NodeId,
        should_fail: bool,
    }

    #[async_trait]
    impl Node for TestNode {
        fn id(&self) -> &NodeId {
            &self.id
        }
        fn name(&self) -> &str {
            "Test"
        }
        fn protocol(&self) -> &'static str {
            "test"
        }
        async fn ping(&self) -> Result<u32, NodeError> {
            if self.should_fail {
                Err(NodeError::Timeout)
            } else {
                Ok(50)
            }
        }
        async fn is_available(&self) -> bool {
            !self.should_fail
        }
    }

    #[tokio::test]
    async fn test_health_check_success() {
        let node: Arc<dyn Node> = Arc::new(TestNode {
            id: "test1".into(),
            should_fail: false,
        });

        let result = HealthChecker::check_node(&node).await;
        assert!(result.is_healthy);
        assert_eq!(result.latency_ms, Some(50));
    }

    #[tokio::test]
    async fn test_health_check_failure() {
        let node: Arc<dyn Node> = Arc::new(TestNode {
            id: "test2".into(),
            should_fail: true,
        });

        let result = HealthChecker::check_node(&node).await;
        assert!(!result.is_healthy);
        assert!(result.error.is_some());
    }
}
