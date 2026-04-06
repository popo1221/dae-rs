//! DNS 上游和源循环检测
//!
//! 自动检测 DNS 上游或源是否也是我们的客户端，提醒用户添加 SIP（源 IP）规则。
//!
//! 防止 DNS 循环：
//! - 上游 DNS 服务器位于同一个 dae-rs 实例之后
//! - DNS 查询在 dae-rs 和上游之间无限循环
//!
//! # 检测策略
//!
//! 1. **上游循环检测**: 检查上游 DNS 服务器 IP 是否也可通过 dae-rs 到达（即上游是客户端）
//! 2. **源循环检测**: 检查 DNS 查询源是否也可通过 dae-rs 到达

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// DNS 循环检测结果
///
/// 表示 DNS 循环检测的结果状态。
#[derive(Debug, Clone)]
pub enum LoopDetectionResult {
    /// No loop detected
    NoLoop,
    /// Upstream is also a client (potential loop)
    UpstreamIsClient {
        upstream: IpAddr,
        suggestion: String,
    },
    /// Source IP is also reachable through dae-rs
    SourceIsReachable { source: IpAddr, suggestion: String },
}

impl std::fmt::Display for LoopDetectionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoopDetectionResult::NoLoop => write!(f, "No loop detected"),
            LoopDetectionResult::UpstreamIsClient {
                upstream,
                suggestion,
            } => {
                write!(f, "Upstream {upstream} is a client - {suggestion}")
            }
            LoopDetectionResult::SourceIsReachable { source, suggestion } => {
                write!(f, "Source {source} is reachable - {suggestion}")
            }
        }
    }
}

/// DNS 循环检测配置
///
/// 配置 DNS 循环检测的各项参数。
#[derive(Debug, Clone)]
pub struct LoopDetectionConfig {
    /// Enable upstream loop detection
    pub check_upstream: bool,
    /// Enable source loop detection
    pub check_source: bool,
    /// Known client IP ranges (CIDR notation)
    pub known_client_ranges: Vec<String>,
    /// Notification callback URL (optional)
    pub notification_url: Option<String>,
}

impl Default for LoopDetectionConfig {
    fn default() -> Self {
        Self {
            check_upstream: true,
            check_source: true,
            known_client_ranges: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            notification_url: None,
        }
    }
}

/// DNS 循环检测器
///
/// 检测并报告潜在的 DNS 循环问题。
pub struct DnsLoopDetector {
    config: LoopDetectionConfig,
    /// Track detected loops to avoid repeated warnings
    detected_loops: Arc<RwLock<HashSet<String>>>,
}

impl DnsLoopDetector {
    pub fn new(config: LoopDetectionConfig) -> Self {
        Self {
            config,
            detected_loops: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(LoopDetectionConfig::default())
    }

    /// Check if upstream DNS server is also a client
    pub async fn check_upstream_loop(&self, upstream_ip: IpAddr) -> LoopDetectionResult {
        if !self.config.check_upstream {
            return LoopDetectionResult::NoLoop;
        }

        // Check if upstream IP is in known client ranges
        if self.is_in_client_range(upstream_ip) {
            let suggestion = format!(
                "Add SIP rule to route {} directly: sip({}, {})",
                upstream_ip, upstream_ip, "direct"
            );

            // Record detected loop
            let key = format!("upstream:{upstream_ip}");
            let mut loops = self.detected_loops.write().await;
            if !loops.contains(&key) {
                loops.insert(key.clone());
                warn!(
                    "DNS loop detected: upstream {} is also a client. {}",
                    upstream_ip, suggestion
                );
            }

            return LoopDetectionResult::UpstreamIsClient {
                upstream: upstream_ip,
                suggestion,
            };
        }

        LoopDetectionResult::NoLoop
    }

    /// Check if source IP is also reachable through dae-rs
    pub async fn check_source_loop(&self, source_ip: IpAddr) -> LoopDetectionResult {
        if !self.config.check_source {
            return LoopDetectionResult::NoLoop;
        }

        // Check if source IP is in known client ranges
        if self.is_in_client_range(source_ip) {
            let suggestion = format!(
                "Add SIP rule to route {} directly: sip({}, {})",
                source_ip, source_ip, "direct"
            );

            // Record detected loop
            let key = format!("source:{source_ip}");
            let mut loops = self.detected_loops.write().await;
            if !loops.contains(&key) {
                loops.insert(key.clone());
                warn!(
                    "DNS loop detected: source {} is reachable. {}",
                    source_ip, suggestion
                );
            }

            return LoopDetectionResult::SourceIsReachable {
                source: source_ip,
                suggestion,
            };
        }

        LoopDetectionResult::NoLoop
    }

    /// Check both upstream and source
    pub async fn check(&self, upstream_ip: IpAddr, source_ip: IpAddr) -> Vec<LoopDetectionResult> {
        let mut results = Vec::new();

        let upstream_result = self.check_upstream_loop(upstream_ip).await;
        if !matches!(upstream_result, LoopDetectionResult::NoLoop) {
            results.push(upstream_result);
        }

        let source_result = self.check_source_loop(source_ip).await;
        if !matches!(source_result, LoopDetectionResult::NoLoop) {
            results.push(source_result);
        }

        results
    }

    /// Check if IP is in known client ranges
    fn is_in_client_range(&self, ip: IpAddr) -> bool {
        if let IpAddr::V4(ipv4) = ip {
            let ip_u32 = u32::from(ipv4);
            for range in &self.config.known_client_ranges {
                if let Some((net_addr, netmask)) = parse_cidr_impl(range) {
                    let net_u32 = u32::from(net_addr);
                    if (ip_u32 & netmask) == (net_u32 & netmask) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Clear detected loops (e.g., after config change)
    pub async fn clear_detected_loops(&self) {
        let mut loops = self.detected_loops.write().await;
        loops.clear();
        info!("DNS loop detection: cleared detected loops");
    }

    /// Get count of currently detected loops
    pub async fn detected_loop_count(&self) -> usize {
        let loops = self.detected_loops.read().await;
        loops.len()
    }

    /// Get all detected loops
    pub async fn get_detected_loops(&self) -> Vec<String> {
        let loops = self.detected_loops.read().await;
        loops.iter().cloned().collect()
    }
}

/// Parse CIDR notation to (network address, mask)
fn parse_cidr_impl(cidr: &str) -> Option<(Ipv4Addr, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let addr: Ipv4Addr = parts[0].parse().ok()?;
    let mask_bits: u32 = parts[1].parse().ok()?;
    if mask_bits > 32 {
        return None;
    }
    let mask = if mask_bits == 0 {
        0
    } else {
        !((1u32 << (32 - mask_bits)) - 1)
    };
    Some((addr, mask))
}

/// DNS loop detection with user notification
pub struct NotifyingDnsLoopDetector {
    detector: DnsLoopDetector,
    config: LoopDetectionConfig,
}

impl NotifyingDnsLoopDetector {
    pub fn new(config: LoopDetectionConfig) -> Self {
        Self {
            detector: DnsLoopDetector::new(config.clone()),
            config,
        }
    }

    /// Check and notify if loops detected
    pub async fn check_and_notify(
        &self,
        upstream_ip: IpAddr,
        source_ip: IpAddr,
    ) -> Vec<LoopDetectionResult> {
        let results = self.detector.check(upstream_ip, source_ip).await;

        // Send notification if loops detected
        if !results.is_empty() && self.config.notification_url.is_some() {
            let message = results
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join("; ");

            // In a real implementation, this would send an HTTP request
            // to the notification_url
            debug!("Would notify: {}", message);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_no_loop_when_disabled() {
        let config = LoopDetectionConfig {
            check_upstream: false,
            check_source: false,
            ..Default::default()
        };
        let detector = DnsLoopDetector::new(config);

        let result = detector
            .check_upstream_loop("10.0.0.1".parse().unwrap())
            .await;
        assert!(matches!(result, LoopDetectionResult::NoLoop));
    }

    #[tokio::test]
    async fn test_clear_loops() {
        let detector = DnsLoopDetector::with_default_config();

        // Trigger a loop detection
        detector
            .check_upstream_loop("10.0.0.1".parse().unwrap())
            .await;

        assert_eq!(detector.detected_loop_count().await, 1);

        detector.clear_detected_loops().await;
        assert_eq!(detector.detected_loop_count().await, 0);
    }

    #[test]
    fn test_parse_cidr() {
        // Test 10.0.0.0/8
        let (addr, mask) = parse_cidr_impl("10.0.0.0/8").unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(mask, 0xFF000000);

        // Test 192.168.1.0/24
        let (addr, mask) = parse_cidr_impl("192.168.1.0/24").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(mask, 0xFFFFFF00);
    }
}
