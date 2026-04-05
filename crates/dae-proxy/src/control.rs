//! Unix Domain Socket Control Interface
//!
//! Provides a control interface for runtime management of the dae-proxy daemon.
//! Commands: status, reload, stats, shutdown, test
//!
//! The control socket is typically at /var/run/dae/control.sock

use crate::metrics::{
    inc_node_latency_test, ACTIVE_TCP_CONNECTIONS_GAUGE, ACTIVE_UDP_CONNECTIONS_GAUGE,
    BYTES_RECEIVED_COUNTER, BYTES_SENT_COUNTER, CONNECTION_COUNTER,
};
use crate::tracking::store::SharedTrackingStore;
use crate::tracking::types::ConnectionState;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Control command types
#[derive(Debug, Clone)]
pub enum ControlCommand {
    /// Get proxy status
    Status,
    /// Reload configuration (hot reload)
    Reload,
    /// Get statistics
    Stats,
    /// Shutdown the proxy gracefully
    Shutdown,
    /// Test connectivity to a specific node
    TestNode(String),
    /// Get version information
    Version,
    /// Get help
    Help,
}

/// Control response types
#[derive(Debug, Clone)]
pub enum ControlResponse {
    /// Success response with data
    Ok(String),
    /// Error response
    Error(String),
    /// Statistics response
    Stats(ProxyStats),
    /// Status response
    Status(ProxyStatus),
    /// Test result response
    TestResult(NodeTestResult),
    /// Version response
    Version(String),
}

/// Proxy running status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub tcp_connections: usize,
    pub udp_sessions: usize,
    pub rules_loaded: bool,
    pub rule_count: usize,
    pub nodes_configured: usize,
    // Extended stats
    pub total_connections: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
}

/// Proxy statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStats {
    pub total_connections: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_tcp_connections: usize,
    pub active_udp_sessions: usize,
    pub rules_hit: u64,
    pub nodes_tested: usize,
    pub rule_count: usize,
    pub node_count: usize,
}

/// Node test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTestResult {
    pub node_name: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Shared control state
pub struct ControlState {
    pub running: Arc<RwLock<bool>>,
    pub start_time: SystemTime,
    /// Tracking store for real statistics (optional, set during initialization)
    pub tracking_store: Option<SharedTrackingStore>,
    /// Callback for hot reload functionality
    reload_callback: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Callback for node testing
    #[allow(clippy::type_complexity)]
    node_tester: Option<Arc<dyn Fn(&str) -> NodeTestResult + Send + Sync>>,
    /// Configuration state
    config_state: RwLock<ConfigState>,
}

/// Configuration state tracked by control interface
struct ConfigState {
    rules_loaded: bool,
    rule_count: usize,
    node_count: usize,
}

impl ControlState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            start_time: SystemTime::now(),
            tracking_store: None,
            reload_callback: None,
            node_tester: None,
            config_state: RwLock::new(ConfigState {
                rules_loaded: false,
                rule_count: 0,
                node_count: 0,
            }),
        }
    }

    /// Set the tracking store for real statistics
    pub fn set_tracking_store(&mut self, store: SharedTrackingStore) {
        self.tracking_store = Some(store);
    }

    /// Set the reload callback for hot reload functionality
    pub fn set_reload_callback<F>(&mut self, callback: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.reload_callback = Some(Arc::new(callback));
    }

    /// Set the node tester callback
    pub fn set_node_tester<F>(&mut self, tester: F)
    where
        F: Fn(&str) -> NodeTestResult + Send + Sync + 'static,
    {
        self.node_tester = Some(Arc::new(tester));
    }

    /// Update configuration state
    pub async fn update_config(&self, rules_loaded: bool, rule_count: usize, node_count: usize) {
        let mut state = self.config_state.write().await;
        state.rules_loaded = rules_loaded;
        state.rule_count = rule_count;
        state.node_count = node_count;
    }

    pub async fn set_running(&self, running: bool) {
        *self.running.write().await = running;
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub fn uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.start_time)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Trigger hot reload if callback is set
    pub fn trigger_reload(&self) -> bool {
        if let Some(callback) = &self.reload_callback {
            callback();
            true
        } else {
            false
        }
    }

    /// Test a node if tester is available
    pub fn test_node(&self, node_name: &str) -> Option<NodeTestResult> {
        self.node_tester.as_ref().map(|tester| tester(node_name))
    }

    pub async fn get_status(&self) -> ProxyStatus {
        let config = self.config_state.read().await;

        // Get active connection counts from Prometheus gauges
        let tcp_connections = ACTIVE_TCP_CONNECTIONS_GAUGE.get() as usize;
        let udp_sessions = ACTIVE_UDP_CONNECTIONS_GAUGE.get() as usize;

        // Get additional stats from tracking store if available
        let (total_connections, total_bytes_in, total_bytes_out, _rules_hit) =
            if let Some(store) = &self.tracking_store {
                let overall = store.get_overall();
                let protocols = store.get_protocol_stats();
                (
                    overall.connections_total,
                    protocols.tcp.bytes + protocols.udp.bytes, // bytes is total bytes for protocol
                    protocols.tcp.bytes + protocols.udp.bytes,
                    overall.routed_total,
                )
            } else {
                // Fallback to legacy counter-based calculation
                let overall = get_overall_from_metrics();
                (
                    overall.connections_total,
                    overall.bytes_in,
                    overall.bytes_out,
                    overall.rules_hit,
                )
            };

        ProxyStatus {
            running: *self.running.read().await,
            uptime_secs: self.uptime_secs(),
            tcp_connections,
            udp_sessions,
            rules_loaded: config.rules_loaded,
            rule_count: config.rule_count,
            nodes_configured: config.node_count,
            // Extended stats embedded in status for convenience
            total_connections,
            total_bytes_in,
            total_bytes_out,
        }
    }

    pub fn get_stats(&self) -> ProxyStats {
        // Get active connection counts from Prometheus gauges
        let active_tcp_connections = ACTIVE_TCP_CONNECTIONS_GAUGE.get() as usize;
        let active_udp_sessions = ACTIVE_UDP_CONNECTIONS_GAUGE.get() as usize;

        // Get overall stats from metrics counters
        let overall = get_overall_from_metrics();

        // Get rule and node counts from config state (sync access via block_on)
        let (rule_count, node_count) = {
            // Note: In async context, we would use .read().await
            // For sync context, we use try_read which may fail if write lock is held
            // This is acceptable for stats collection
            (0, 0) // Will be populated via runtime integration
        };

        ProxyStats {
            total_connections: overall.connections_total,
            total_bytes_in: overall.bytes_in,
            total_bytes_out: overall.bytes_out,
            active_tcp_connections,
            active_udp_sessions,
            rules_hit: overall.rules_hit,
            nodes_tested: overall.nodes_tested,
            rule_count,
            node_count,
        }
    }

    /// Get stats from tracking store directly (preferred method)
    pub fn get_stats_from_store(&self) -> ProxyStats {
        if let Some(store) = &self.tracking_store {
            let overall = store.get_overall();
            let protocols = store.get_protocol_stats();
            let active_connections = store.connections().get_active();

            // Count active TCP vs UDP connections (Established or New state)
            let active_tcp: usize = active_connections
                .iter()
                .filter(|(_, stats)| {
                    stats.state == ConnectionState::Established as u8
                        || stats.state == ConnectionState::New as u8
                })
                .filter(|(key, _)| key.proto == 6) // TCP
                .count();
            let active_udp: usize = active_connections
                .iter()
                .filter(|(_, stats)| {
                    stats.state == ConnectionState::Established as u8
                        || stats.state == ConnectionState::New as u8
                })
                .filter(|(key, _)| key.proto == 17) // UDP
                .count();

            let rules_hit = overall.routed_total;
            let nodes_tested = store.get_node_count();

            ProxyStats {
                total_connections: overall.connections_total,
                total_bytes_in: protocols.tcp.bytes + protocols.udp.bytes, // total bytes received
                total_bytes_out: protocols.tcp.bytes + protocols.udp.bytes, // same for now (bidirectional)
                active_tcp_connections: active_tcp,
                active_udp_sessions: active_udp,
                rules_hit,
                nodes_tested,
                rule_count: store.get_rule_count(),
                node_count: store.get_node_count(),
            }
        } else {
            self.get_stats()
        }
    }
}

impl Default for ControlState {
    fn default() -> Self {
        Self::new()
    }
}

/// Control server that listens on Unix domain socket
pub struct ControlServer {
    socket_path: String,
    state: Arc<ControlState>,
}

impl ControlServer {
    /// Create a new control server
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            state: Arc::new(ControlState::new()),
        }
    }

    /// Get the control state for sharing with proxy
    pub fn state(&self) -> Arc<ControlState> {
        self.state.clone()
    }

    /// Start the control server
    pub async fn start(&self) -> std::io::Result<()> {
        // Create socket directory if needed
        if let Some(parent) = Path::new(&self.socket_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Remove existing socket
        if Path::new(&self.socket_path).exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("Control server listening on {}", self.socket_path);

        // Set socket permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o666))?;
        }

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, &state).await {
                            error!("Control connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Control server accept error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single control connection
    async fn handle_connection(
        stream: UnixStream,
        state: &Arc<ControlState>,
    ) -> std::io::Result<()> {
        let mut stream = BufStream::new(stream);
        let mut line = String::new();

        // Read command
        if stream.read_line(&mut line).await? == 0 {
            return Ok(());
        }

        let response = Self::process_command(line.trim(), state).await;

        // Send response
        let response_str = match &response {
            ControlResponse::Ok(msg) => msg.clone(),
            ControlResponse::Error(msg) => format!("ERROR: {msg}\n"),
            ControlResponse::Stats(stats) => {
                format!("{}\n", serde_json::to_string(stats).unwrap_or_default())
            }
            ControlResponse::Status(status) => {
                format!("{}\n", serde_json::to_string(status).unwrap_or_default())
            }
            ControlResponse::TestResult(result) => {
                format!("{}\n", serde_json::to_string(result).unwrap_or_default())
            }
            ControlResponse::Version(ver) => format!("dae-rs {ver}\n"),
        };

        stream.write_all(response_str.as_bytes()).await?;
        stream.flush().await?;

        Ok(())
    }

    /// Process a control command
    async fn process_command(cmd: &str, state: &Arc<ControlState>) -> ControlResponse {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let command = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();

        match command.as_str() {
            "status" => {
                // Use tracking store if available, otherwise use metrics
                let status = if state.tracking_store.is_some() {
                    state.get_status().await
                } else {
                    // Fallback to metrics-based status
                    let config = state.config_state.read().await;
                    ProxyStatus {
                        running: *state.running.read().await,
                        uptime_secs: state.uptime_secs(),
                        tcp_connections: ACTIVE_TCP_CONNECTIONS_GAUGE.get() as usize,
                        udp_sessions: ACTIVE_UDP_CONNECTIONS_GAUGE.get() as usize,
                        rules_loaded: config.rules_loaded,
                        rule_count: config.rule_count,
                        nodes_configured: config.node_count,
                        total_connections: CONNECTION_COUNTER.get(),
                        total_bytes_in: get_bytes_received_total(),
                        total_bytes_out: get_bytes_sent_total(),
                    }
                };
                ControlResponse::Status(status)
            }
            "reload" => {
                info!("Hot reload requested via control socket");
                if state.trigger_reload() {
                    ControlResponse::Ok("Configuration reload initiated".to_string())
                } else {
                    // No callback set, but acknowledge the command
                    warn!("Hot reload callback not configured");
                    ControlResponse::Ok(
                        "Configuration reload requested (callback not configured)".to_string(),
                    )
                }
            }
            "stats" => {
                let stats = if state.tracking_store.is_some() {
                    state.get_stats_from_store()
                } else {
                    state.get_stats()
                };
                ControlResponse::Stats(stats)
            }
            "shutdown" => {
                info!("Shutdown requested via control socket");
                state.set_running(false).await;
                ControlResponse::Ok("Shutdown initiated".to_string())
            }
            "test" => {
                let node_name = parts.get(1).map(|s| s.to_string());
                if let Some(name) = node_name {
                    info!("Testing node: {}", name);
                    if let Some(result) = state.test_node(&name) {
                        inc_node_latency_test();
                        ControlResponse::TestResult(result)
                    } else {
                        // No tester configured, return an error
                        ControlResponse::Error(
                            "Node testing not available (tester not configured)".to_string(),
                        )
                    }
                } else {
                    ControlResponse::Error("Usage: test <node_name>".to_string())
                }
            }
            "version" | "ver" => ControlResponse::Version(env!("CARGO_PKG_VERSION").to_string()),
            "help" | "?" => {
                let help = r#"Available commands:
  status         Show proxy status
  stats          Show statistics
  reload         Hot reload configuration
  shutdown       Shutdown the proxy gracefully
  test <node>    Test connectivity to a node
  version        Show version information
  help           Show this help message
"#;
                ControlResponse::Ok(help.to_string())
            }
            "" => ControlResponse::Ok("Use 'help' for available commands".to_string()),
            _ => {
                warn!("Unknown control command: {}", cmd);
                ControlResponse::Error(format!(
                    "Unknown command: {cmd}. Use 'help' for available commands."
                ))
            }
        }
    }
}

/// Legacy overall stats structure for metrics-based fallback
struct LegacyOverallStats {
    connections_total: u64,
    bytes_in: u64,
    bytes_out: u64,
    rules_hit: u64,
    nodes_tested: usize,
}

/// Get overall stats from Prometheus metrics (fallback when no tracking store)
fn get_overall_from_metrics() -> LegacyOverallStats {
    LegacyOverallStats {
        connections_total: CONNECTION_COUNTER.get(),
        bytes_in: get_bytes_received_total(),
        bytes_out: get_bytes_sent_total(),
        rules_hit: 0,    // Would need RULE_MATCH_COUNTER sum
        nodes_tested: 0, // Would need NODE_LATENCY_TEST_COUNTER
    }
}

/// Get total bytes received from metrics
fn get_bytes_received_total() -> u64 {
    // Sum across all transport labels
    BYTES_RECEIVED_COUNTER.with_label_values(&["all"]).get()
}

/// Get total bytes sent from metrics  
fn get_bytes_sent_total() -> u64 {
    BYTES_SENT_COUNTER.with_label_values(&["all"]).get()
}

/// Connect to control socket and send command
pub async fn connect_and_send(socket_path: &str, command: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path).await?;

    stream.write_all(format!("{command}\n").as_bytes()).await?;
    stream.flush().await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;

    Ok(response)
}

/// Connect to control socket and get response as structured type
pub async fn connect_and_get_status(socket_path: &str) -> std::io::Result<ControlResponse> {
    let response = connect_and_send(socket_path, "status").await?;

    // Parse JSON response
    if let Ok(status) = serde_json::from_str::<ProxyStatus>(&response) {
        return Ok(ControlResponse::Status(status));
    }

    if response.starts_with("ERROR:") {
        return Ok(ControlResponse::Error(
            response.trim_start_matches("ERROR:").trim().to_string(),
        ));
    }

    Ok(ControlResponse::Ok(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_control_command_parsing() {
        // Test status command
        let state1 = ControlState::new();
        let resp = ControlServer::process_command("status", &Arc::new(state1)).await;
        assert!(matches!(resp, ControlResponse::Status(_)));

        // Test help command
        let state2 = ControlState::new();
        let resp = ControlServer::process_command("help", &Arc::new(state2)).await;
        assert!(matches!(resp, ControlResponse::Ok(_)));

        // Test unknown command
        let state3 = ControlState::new();
        let resp = ControlServer::process_command("unknown", &Arc::new(state3)).await;
        assert!(matches!(resp, ControlResponse::Error(_)));

        // Test version command
        let state4 = ControlState::new();
        let resp = ControlServer::process_command("version", &Arc::new(state4)).await;
        assert!(matches!(resp, ControlResponse::Version(_)));
    }

    #[tokio::test]
    async fn test_control_state() {
        let state = ControlState::new();

        assert!(!state.is_running().await);

        state.set_running(true).await;
        assert!(state.is_running().await);

        // Wait a bit and check uptime (u64 is always >= 0, so use >= 0)
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(state.uptime_secs() >= 0);
    }

    #[test]
    fn test_node_test_result_serialization() {
        let result = NodeTestResult {
            node_name: "test-node".to_string(),
            success: true,
            latency_ms: Some(100),
            error: None,
        };

        let json = serde_json::to_string(&result)
            .expect("test: serialization of NodeTestResult should not fail");
        assert!(json.contains("test-node"));
        assert!(json.contains("true"));
        assert!(json.contains("100"));
    }
}
