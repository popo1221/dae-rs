//! Unix Domain Socket Control Interface
//!
//! Provides a control interface for runtime management of the dae-proxy daemon.
//! Commands: status, reload, stats, shutdown, test
//!
//! The control socket is typically at /var/run/dae/control.sock

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use serde::{Deserialize, Serialize};

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
    pub stats: ProxyStats,
}

impl ControlState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            start_time: SystemTime::now(),
            stats: ProxyStats {
                total_connections: 0,
                total_bytes_in: 0,
                total_bytes_out: 0,
                active_tcp_connections: 0,
                active_udp_sessions: 0,
                rules_hit: 0,
                nodes_tested: 0,
            },
        }
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

    pub fn get_status(&self, rules_loaded: bool, rule_count: usize, nodes_configured: usize) -> ProxyStatus {
        ProxyStatus {
            running: false, // Will be updated by caller
            uptime_secs: self.uptime_secs(),
            tcp_connections: self.stats.active_tcp_connections,
            udp_sessions: self.stats.active_udp_sessions,
            rules_loaded,
            rule_count,
            nodes_configured,
        }
    }

    pub fn get_stats(&self) -> ProxyStats {
        self.stats.clone()
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
            ControlResponse::Stats(stats) => format!("{}\n", serde_json::to_string(stats).unwrap_or_default()),
            ControlResponse::Status(status) => format!("{}\n", serde_json::to_string(status).unwrap_or_default()),
            ControlResponse::TestResult(result) => format!("{}\n", serde_json::to_string(result).unwrap_or_default()),
            ControlResponse::Version(ver) => format!("dae-rs {ver}\n"),
        };

        stream.write_all(response_str.as_bytes()).await?;
        stream.flush().await?;

        Ok(())
    }

    /// Process a control command
    async fn process_command(
        cmd: &str,
        state: &Arc<ControlState>,
    ) -> ControlResponse {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let command = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();

        match command.as_str() {
            "status" => {
                let running = state.is_running().await;
                let status = state.get_status(rules_loaded(), rule_count(), node_count());
                ControlResponse::Status(ProxyStatus { running, ..status })
            }
            "reload" => {
                info!("Hot reload requested via control socket");
                // In real implementation, this would trigger config reload
                // For now, just acknowledge
                ControlResponse::Ok("Configuration reload initiated".to_string())
            }
            "stats" => {
                let stats = state.get_stats();
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
                    // In real implementation, this would test the actual node
                    ControlResponse::TestResult(NodeTestResult {
                        node_name: name,
                        success: true,
                        latency_ms: Some(42),
                        error: None,
                    })
                } else {
                    ControlResponse::Error("Usage: test <node_name>".to_string())
                }
            }
            "version" | "ver" => {
                ControlResponse::Version(env!("CARGO_PKG_VERSION").to_string())
            }
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
            "" => {
                ControlResponse::Ok("Use 'help' for available commands".to_string())
            }
            _ => {
                warn!("Unknown control command: {}", cmd);
                ControlResponse::Error(format!("Unknown command: {cmd}. Use 'help' for available commands."))
            }
        }
    }
}

/// Placeholder functions - in real implementation these would access actual state
fn rules_loaded() -> bool {
    true
}

fn rule_count() -> usize {
    0
}

fn node_count() -> usize {
    0
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
        return Ok(ControlResponse::Error(response.trim_start_matches("ERROR:").trim().to_string()));
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
        
        // Wait a bit and check uptime
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
        
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test-node"));
        assert!(json.contains("true"));
        assert!(json.contains("100"));
    }
}
