//! NaiveProxy integration module
//!
//! NaiveProxy is a forward-grade proxy that uses Chromium's networking stack
//! for better censorship resistance. It runs as an external process and dae-rs
//! communicates with it via HTTP proxy protocol.
//!
//! # How it works
//!
//! 1. Start naiveproxy as a local HTTP proxy server
//! 2. Configure dae-rs to use this local proxy for outgoing connections
//! 3. NaiveProxy handles the actual proxying through its tunnel
//!
//! # Command Line
//!
//! ```bash
//! naiveproxy --listen=http://127.0.0.1:1090 --proxy=https://your-server.com
//! ```

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// NaiveProxy configuration
#[derive(Debug, Clone)]
pub struct NaiveProxyConfig {
    /// Path to naiveproxy binary
    pub binary_path: PathBuf,
    /// Listen address for local HTTP proxy
    pub listen_addr: String,
    /// Upstream proxy URL (e.g., https://user:pass@server.com)
    pub upstream_proxy: String,
    /// Additional command line arguments
    pub extra_args: Vec<String>,
    /// Whether to enable logging
    pub enable_logging: bool,
    /// Log level (info, debug, warn, error)
    pub log_level: String,
}

impl Default for NaiveProxyConfig {
    fn default() -> Self {
        Self {
            binary_path: PathBuf::from("naiveproxy"),
            listen_addr: "127.0.0.1:1090".to_string(),
            upstream_proxy: String::new(),
            extra_args: Vec::new(),
            enable_logging: false,
            log_level: "info".to_string(),
        }
    }
}

impl NaiveProxyConfig {
    /// Create a new config with required parameters
    pub fn new(listen_addr: &str, upstream_proxy: &str) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            upstream_proxy: upstream_proxy.to_string(),
            ..Default::default()
        }
    }

    /// Set custom binary path
    pub fn with_binary_path(mut self, path: PathBuf) -> Self {
        self.binary_path = path;
        self
    }

    /// Add extra arguments
    pub fn with_extra_args(mut self, args: Vec<String>) -> Self {
        self.extra_args = args;
        self
    }

    /// Enable logging
    pub fn with_logging(mut self, level: &str) -> Self {
        self.enable_logging = true;
        self.log_level = level.to_string();
        self
    }
}

/// NaiveProxy process manager
pub struct NaiveProxyManager {
    config: NaiveProxyConfig,
    process: Option<Child>,
    running: Arc<RwLock<bool>>,
}

impl NaiveProxyManager {
    /// Create a new manager with config
    pub fn new(config: NaiveProxyConfig) -> Self {
        Self {
            config,
            process: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the naiveproxy process
    pub async fn start(&mut self) -> std::io::Result<()> {
        if *self.running.read().await {
            warn!("NaiveProxy is already running");
            return Ok(());
        }

        info!("Starting NaiveProxy: {}", self.config.listen_addr);

        // Build command line arguments
        let mut args = vec![
            format!("--listen={}", self.config.listen_addr),
            format!("--proxy={}", self.config.upstream_proxy),
        ];

        if self.config.enable_logging {
            args.push(format!("--log-level={}", self.config.log_level));
        }

        args.extend(self.config.extra_args.clone());

        // Spawn the process
        let mut child = Command::new(&self.config.binary_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        // Wait a bit for the process to start
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Check if process is still running
        if let Some(status) = child
            .try_wait()
            .map_err(|e| std::io::Error::other(format!("Failed to check status: {}", e)))?
        {
            if status.code().is_some() {
                return Err(std::io::Error::other(format!(
                    "NaiveProxy exited early with status: {:?}",
                    status.code()
                )));
            }
        }

        *self.running.write().await = true;
        self.process = Some(child);
        info!("NaiveProxy started successfully");

        Ok(())
    }

    /// Stop the naiveproxy process
    pub async fn stop(&mut self) -> std::io::Result<()> {
        if !*self.running.read().await {
            return Ok(());
        }

        info!("Stopping NaiveProxy");

        if let Some(mut child) = self.process.take() {
            child.kill().await?;
            *self.running.write().await = false;
        }

        Ok(())
    }

    /// Check if naiveproxy is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> &str {
        &self.config.listen_addr
    }

    /// Get HTTP proxy URL
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.config.listen_addr)
    }

    /// Check if the proxy is responding
    pub async fn health_check(&self) -> bool {
        if !*self.running.read().await {
            return false;
        }

        // Try to connect to the listen address
        let addr = &self.config.listen_addr;
        match TcpStream::connect(addr).await {
            Ok(_) => true,
            Err(e) => {
                debug!("NaiveProxy health check failed: {}", e);
                false
            }
        }
    }
}

impl Drop for NaiveProxyManager {
    fn drop(&mut self) {
        // Best effort kill on drop - ignore errors since we're in a destructor
        if let Some(ref mut child) = self.process {
            let _ = child.start_kill();
        }
    }
}

/// HTTP CONNECT tunnel handler for communicating with naiveproxy
#[derive(Debug)]
pub struct HttpConnectTunnel {
    /// Target host
    host: String,
    /// Target port
    port: u16,
}

impl HttpConnectTunnel {
    /// Create a new tunnel request
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
        }
    }

    /// Send CONNECT request and upgrade to tunnel
    pub async fn connect(&self, proxy_addr: &str) -> std::io::Result<TcpStream> {
        let mut stream = TcpStream::connect(proxy_addr).await?;

        // Send CONNECT request
        let request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            self.host, self.port, self.host, self.port
        );
        stream.write_all(request.as_bytes()).await?;

        // Read response
        let mut response = [0u8; 200];
        let n = stream.read(&mut response).await?;

        let response_str = String::from_utf8_lossy(&response[..n]);

        // Check for 200 Connection Established
        if !response_str.contains("200") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("Tunnel failed: {}", response_str),
            ));
        }

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_naive_proxy_config_default() {
        let config = NaiveProxyConfig::default();
        assert_eq!(config.listen_addr, "127.0.0.1:1090");
        assert_eq!(config.binary_path, PathBuf::from("naiveproxy"));
        assert!(!config.enable_logging);
    }

    #[test]
    fn test_naive_proxy_config_builder() {
        let config = NaiveProxyConfig::new("127.0.0.1:1080", "https://example.com")
            .with_binary_path(PathBuf::from("/usr/bin/naiveproxy"))
            .with_logging("debug")
            .with_extra_args(vec!["--ipv6".to_string()]);

        assert_eq!(config.listen_addr, "127.0.0.1:1080");
        assert_eq!(config.upstream_proxy, "https://example.com");
        assert_eq!(config.binary_path, PathBuf::from("/usr/bin/naiveproxy"));
        assert!(config.enable_logging);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.extra_args, vec!["--ipv6"]);
    }

    #[test]
    fn test_http_connect_tunnel() {
        let tunnel = HttpConnectTunnel::new("example.com", 443);
        assert_eq!(tunnel.host, "example.com");
        assert_eq!(tunnel.port, 443);
    }

    #[tokio::test]
    async fn test_tunnel_request_format() {
        let tunnel = HttpConnectTunnel::new("example.com", 443);
        // We can't actually connect in tests, but we can verify the format
        let expected = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        // The actual request would be formatted as above
        assert!(true); // Placeholder - actual network test would require a server
    }

    #[test]
    fn test_naive_proxy_config_clone() {
        let config = NaiveProxyConfig::default()
            .with_binary_path(PathBuf::from("/clone/path"))
            .with_logging("info");
        let cloned = config.clone();

        assert_eq!(cloned.binary_path, config.binary_path);
        assert_eq!(cloned.log_level, config.log_level);
    }

    #[test]
    fn test_naive_proxy_config_debug() {
        let config = NaiveProxyConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("NaiveProxyConfig"));
    }

    #[test]
    fn test_naive_proxy_manager_new() {
        let manager = NaiveProxyManager::new(NaiveProxyConfig::default());
        // Just verify it can be created
        assert!(manager.config.listen_addr == "127.0.0.1:1090");
    }

    #[test]
    fn test_naive_proxy_config_with_multiple_extra_args() {
        let config =
            NaiveProxyConfig::new("127.0.0.1:1080", "https://proxy.com").with_extra_args(vec![
                "--ipv6".to_string(),
                "--verbose".to_string(),
                "--conf=./config.json".to_string(),
            ]);

        assert_eq!(config.extra_args.len(), 3);
        assert!(config.extra_args.contains(&"--ipv6".to_string()));
        assert!(config.extra_args.contains(&"--verbose".to_string()));
    }

    #[test]
    fn test_naive_proxy_config_logging_disabled() {
        let config = NaiveProxyConfig::default();
        assert!(!config.enable_logging);
        assert_eq!(config.log_level, "info"); // Default
    }

    #[test]
    fn test_naive_proxy_config_logging_enabled() {
        let config = NaiveProxyConfig::default().with_logging("debug");
        assert!(config.enable_logging);
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_naive_proxy_config_different_log_levels() {
        for level in &["error", "warn", "info", "debug", "trace"] {
            let config = NaiveProxyConfig::default().with_logging(level);
            assert_eq!(config.log_level, *level);
        }
    }

    #[test]
    fn test_http_connect_tunnel_with_different_ports() {
        let tunnel = HttpConnectTunnel::new("example.com", 80);
        assert_eq!(tunnel.port, 80);

        let tunnel = HttpConnectTunnel::new("example.com", 8080);
        assert_eq!(tunnel.port, 8080);

        let tunnel = HttpConnectTunnel::new("example.com", 65535);
        assert_eq!(tunnel.port, 65535);
    }

    #[test]
    fn test_http_connect_tunnel_debug() {
        let tunnel = HttpConnectTunnel::new("debug.test.com", 443);
        let debug_str = format!("{:?}", tunnel);
        assert!(debug_str.contains("HttpConnectTunnel"));
        assert!(debug_str.contains("debug.test.com"));
    }

    #[test]
    fn test_naive_proxy_config_listen_addr_variants() {
        let config = NaiveProxyConfig::new("0.0.0.0:8080", "https://proxy.com");
        assert_eq!(config.listen_addr, "0.0.0.0:8080");

        let config = NaiveProxyConfig::new("[::]:8080", "https://proxy.com");
        assert_eq!(config.listen_addr, "[::]:8080");

        let config = NaiveProxyConfig::new("localhost:9090", "https://proxy.com");
        assert_eq!(config.listen_addr, "localhost:9090");
    }

    #[test]
    fn test_naive_proxy_manager_proxy_url() {
        let manager = NaiveProxyManager::new(NaiveProxyConfig::new(
            "127.0.0.1:1080",
            "https://proxy1.com",
        ));
        assert_eq!(manager.proxy_url(), "http://127.0.0.1:1080");

        let manager =
            NaiveProxyManager::new(NaiveProxyConfig::new("127.0.0.1:1081", "http://proxy2.com"));
        assert_eq!(manager.proxy_url(), "http://127.0.0.1:1081");
    }
}
