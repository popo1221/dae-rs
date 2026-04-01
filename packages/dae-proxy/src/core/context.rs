//! Request context for dae-proxy
//!
//! This module provides the Context struct that flows through the entire
//! request processing pipeline.

use crate::node::NodeId;
use crate::rule_engine::RuleAction;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for generating unique request IDs
static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a unique request ID
fn generate_request_id() -> u64 {
    REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Request context - flows through the entire request processing pipeline
///
/// This struct carries all information about a request as it moves through
/// the proxy system, from initial packet reception to final forwarding.
#[derive(Debug, Clone)]
pub struct Context {
    /// Request ID (for tracing)
    pub request_id: u64,
    /// Source address
    pub source: SocketAddr,
    /// Destination address
    pub destination: SocketAddr,
    /// Rule match result
    pub rule_action: RuleAction,
    /// Specified node ID (optional, for proxy selection)
    pub node_id: Option<NodeId>,
    /// Whether to use direct connection
    pub direct: bool,
    /// Process name (if available)
    pub process_name: Option<String>,
    /// Process PID (if available)
    pub process_pid: Option<u32>,
}

impl Context {
    /// Create a new Context with the given source and destination
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            request_id: generate_request_id(),
            source,
            destination,
            rule_action: RuleAction::Proxy,
            node_id: None,
            direct: false,
            process_name: None,
            process_pid: None,
        }
    }
    
    /// Mark this context for direct connection
    pub fn set_direct(&mut self) {
        self.direct = true;
        self.rule_action = RuleAction::Direct;
    }
    
    /// Mark this context for forced direct connection (Real Direct)
    pub fn set_must_direct(&mut self) {
        self.direct = true;
        self.rule_action = RuleAction::MustDirect;
    }
    
    /// Check if this context should be proxied
    pub fn should_proxy(&self) -> bool {
        !self.direct && self.rule_action == RuleAction::Proxy
    }
    
    /// Check if this context should be dropped
    pub fn should_drop(&self) -> bool {
        self.rule_action == RuleAction::Drop
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_context_creation() {
        let source = SocketAddr::from((IpAddr::from_str("127.0.0.1").unwrap(), 8080));
        let dest = SocketAddr::from((IpAddr::from_str("192.168.1.1").unwrap(), 80));
        
        let ctx = Context::new(source, dest);
        
        assert_eq!(ctx.source, source);
        assert_eq!(ctx.destination, dest);
        assert_eq!(ctx.rule_action, RuleAction::Proxy);
        assert!(!ctx.direct);
        assert!(ctx.node_id.is_none());
    }
    
    #[test]
    fn test_set_direct() {
        let source = SocketAddr::from((IpAddr::from_str("127.0.0.1").unwrap(), 8080));
        let dest = SocketAddr::from((IpAddr::from_str("192.168.1.1").unwrap(), 80));
        
        let mut ctx = Context::new(source, dest);
        ctx.set_direct();
        
        assert!(ctx.direct);
        assert_eq!(ctx.rule_action, RuleAction::Direct);
    }
    
    #[test]
    fn test_set_must_direct() {
        let source = SocketAddr::from((IpAddr::from_str("127.0.0.1").unwrap(), 8080));
        let dest = SocketAddr::from((IpAddr::from_str("192.168.1.1").unwrap(), 80));
        
        let mut ctx = Context::new(source, dest);
        ctx.set_must_direct();
        
        assert!(ctx.direct);
        assert_eq!(ctx.rule_action, RuleAction::MustDirect);
    }
    
    #[test]
    fn test_request_id_uniqueness() {
        let source = SocketAddr::from((IpAddr::from_str("127.0.0.1").unwrap(), 8080));
        let dest = SocketAddr::from((IpAddr::from_str("192.168.1.1").unwrap(), 80));
        
        let ctx1 = Context::new(source, dest);
        let ctx2 = Context::new(source, dest);
        
        // Request IDs should be unique (though they might not be in fast succession due to atomic)
        // This is a basic check
        assert_ne!(ctx1.request_id, ctx2.request_id);
    }
}
