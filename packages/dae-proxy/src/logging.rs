//! Userspace Logging Service
//!
//! Provides a logging subsystem that runs in userspace for easier debugging and monitoring.
//! Supports Unix Domain Socket for log streaming and configurable log levels.
//!
//! # Features
//!
//! - Dynamic log level adjustment without restart
//! - Integration with external logging systems
//! - Real-time log streaming to management interfaces
//! - Better debugging experience
//!
//! # Architecture
//!
//! The logging service consists of:
//! - `LogLevel`: Enum for log levels (trace, debug, info, warn, error)
//! - `LogMessage`: Structured log format with level, timestamp, message
//! - `LogService`: Service that accepts log messages via UDS
//! - `LogSink`: Trait for custom log sinks

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Log level enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Convert from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" | "warning" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    /// Check if this level should be logged given the current level
    pub fn should_log(&self, min_level: LogLevel) -> bool {
        *self >= min_level
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Structured log message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessage {
    /// Timestamp as RFC3339 string
    pub timestamp: String,
    /// Log level
    pub level: LogLevel,
    /// Target/module that generated the log
    pub target: Option<String>,
    /// Log message
    pub message: String,
    /// Optional structured fields (JSON)
    pub fields: Option<serde_json::Value>,
}

impl LogMessage {
    /// Create a new log message
    pub fn new(level: LogLevel, message: String) -> Self {
        Self {
            timestamp: chrono_lite_timestamp(),
            level,
            target: None,
            message,
            fields: None,
        }
    }

    /// Create with target
    pub fn with_target(level: LogLevel, target: String, message: String) -> Self {
        Self {
            timestamp: chrono_lite_timestamp(),
            level,
            target: Some(target),
            message,
            fields: None,
        }
    }

    /// Create with fields
    pub fn with_fields(level: LogLevel, message: String, fields: serde_json::Value) -> Self {
        Self {
            timestamp: chrono_lite_timestamp(),
            level,
            target: None,
            message,
            fields: Some(fields),
        }
    }

    /// Format for display
    pub fn format_display(&self) -> String {
        let target = self.target.as_deref().unwrap_or("app");
        match &self.fields {
            Some(fields) => {
                format!(
                    "{} {} [{}] {} {}",
                    self.timestamp,
                    self.level,
                    target,
                    self.message,
                    fields
                )
            }
            None => {
                format!("{} {} [{}] {}", self.timestamp, self.level, target, self.message)
            }
        }
    }

    /// Format as JSON line
    pub fn format_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| self.format_display())
    }
}

/// Get current timestamp in RFC3339-like format (without full chrono dependency)
fn chrono_lite_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;
    let millis = now.subsec_millis();
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        hours, minutes, seconds, millis
    )
}

/// Shared log state
pub struct LogState {
    /// Current minimum log level
    min_level: RwLock<LogLevel>,
    /// Broadcast channel for log messages
    sender: broadcast::Sender<LogMessage>,
}

impl LogState {
    /// Create new log state
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1000);
        Self {
            min_level: RwLock::new(LogLevel::Info),
            sender,
        }
    }

    /// Get current minimum log level
    pub async fn get_min_level(&self) -> LogLevel {
        *self.min_level.read().await
    }

    /// Set minimum log level
    pub async fn set_min_level(&self, level: LogLevel) {
        *self.min_level.write().await = level;
    }

    /// Log a message if it passes the level filter
    pub async fn log(&self, msg: LogMessage) {
        let min_level = self.get_min_level().await;
        if msg.level.should_log(min_level) {
            let _ = self.sender.send(msg);
        }
    }

    /// Subscribe to log messages
    pub fn subscribe(&self) -> broadcast::Receiver<LogMessage> {
        self.sender.subscribe()
    }
}

impl Default for LogState {
    fn default() -> Self {
        Self::new()
    }
}

/// Log service that provides UDS-based log streaming
pub struct LogService {
    socket_path: String,
    state: Arc<LogState>,
}

impl LogService {
    /// Create a new log service
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            state: Arc::new(LogState::new()),
        }
    }

    /// Get the log state for sharing with proxy
    pub fn state(&self) -> Arc<LogState> {
        self.state.clone()
    }

    /// Get current log level
    pub async fn get_log_level(&self) -> LogLevel {
        self.state.get_min_level().await
    }

    /// Set log level
    pub async fn set_log_level(&self, level: LogLevel) {
        self.state.set_min_level(level).await;
        info!("Log level changed to {}", level);
    }

    /// Start the log service
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
        info!("Log service listening on {}", self.socket_path);

        // Set socket permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o666))?;
        }

        let state = self.state.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_log_connection(stream, state).await {
                                error!("Log connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Log service accept error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle a log subscription connection
    async fn handle_log_connection(
        stream: UnixStream,
        state: Arc<LogState>,
    ) -> std::io::Result<()> {
        let mut stream = BufStream::new(stream);
        let mut receiver = state.subscribe();

        // Send current log level first
        let level = state.get_min_level().await;
        stream
            .write_all(format!("LEVEL:{}\n", level.as_str()).as_bytes())
            .await?;
        stream.flush().await?;

        // Stream logs until connection closes
        loop {
            let mut line_buf = String::new();
            tokio::select! {
                msg = receiver.recv() => {
                    match msg {
                        Ok(log_msg) => {
                            let line = log_msg.format_json() + "\n";
                            if stream.write_all(line.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // Skip lagged messages
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                result = stream.read_line(&mut line_buf) => {
                    // Client sends commands
                    if result? == 0 {
                        break; // Connection closed
                    }
                }
            }
        }

        stream.flush().await?;
        Ok(())
    }
}

/// Connect to log socket and receive logs
pub async fn connect_to_log_stream(
    socket_path: &str,
) -> std::io::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    let stream = UnixStream::connect(socket_path).await?;
    Ok(stream)
}

/// Parse log level from response
pub fn parse_level_response(response: &str) -> Option<LogLevel> {
    let line = response.trim();
    if line.starts_with("LEVEL:") {
        LogLevel::from_str(line.trim_start_matches("LEVEL:"))
    } else {
        None
    }
}

/// Log command types for control integration
#[derive(Debug, Clone)]
pub enum LogCommand {
    /// Get current log level
    GetLevel,
    /// Set log level
    SetLevel(LogLevel),
    /// Get help
    Help,
}

/// Process a log command and return response
pub async fn process_log_command(
    state: &Arc<LogState>,
    command: LogCommand,
) -> String {
    match command {
        LogCommand::GetLevel => {
            let level = state.get_min_level().await;
            format!("{}\n", level.as_str())
        }
        LogCommand::SetLevel(level) => {
            state.set_min_level(level).await;
            format!("Log level set to {}\n", level)
        }
        LogCommand::Help => {
            r#"Available log commands:
  level          Get current log level
  level <level>  Set log level (trace, debug, info, warn, error)
  help           Show this help message
"#.to_string()
        }
    }
}

/// Add log level commands to control API
pub async fn handle_control_log_command(
    state: &Arc<LogState>,
    cmd: &str,
) -> Option<String> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let command = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();

    match command.as_str() {
        "level" => {
            if parts.len() > 1 {
                if let Some(level) = LogLevel::from_str(parts[1]) {
                    let _ = process_log_command(state, LogCommand::SetLevel(level)).await;
                    Some(format!("Log level set to {}", level))
                } else {
                    Some(format!("Invalid log level: {}", parts[1]))
                }
            } else {
                Some(process_log_command(state, LogCommand::GetLevel).await)
            }
        }
        "log" => {
            Some(process_log_command(state, LogCommand::Help).await)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::from_str("trace"), Some(LogLevel::Trace));
        assert_eq!(LogLevel::from_str("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("warn"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("invalid"), None);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_level_should_log() {
        assert!(LogLevel::Error.should_log(LogLevel::Info));
        assert!(LogLevel::Warn.should_log(LogLevel::Info));
        assert!(!LogLevel::Debug.should_log(LogLevel::Info));
        assert!(!LogLevel::Trace.should_log(LogLevel::Info));
    }

    #[test]
    fn test_log_message_creation() {
        let msg = LogMessage::new(LogLevel::Info, "test message".to_string());
        assert_eq!(msg.level, LogLevel::Info);
        assert_eq!(msg.message, "test message");
        assert!(msg.target.is_none());
        assert!(msg.fields.is_none());
    }

    #[test]
    fn test_log_message_with_target() {
        let msg = LogMessage::with_target(LogLevel::Debug, "proxy".to_string(), "test".to_string());
        assert_eq!(msg.target, Some("proxy".to_string()));
    }

    #[test]
    fn test_log_message_format_display() {
        let msg = LogMessage::new(LogLevel::Info, "test message".to_string());
        let display = msg.format_display();
        assert!(display.contains("info"));
        assert!(display.contains("test message"));
    }

    #[test]
    fn test_log_message_format_json() {
        let msg = LogMessage::new(LogLevel::Info, "test message".to_string());
        let json = msg.format_json();
        assert!(json.contains("\"level\":\"info\""));
        assert!(json.contains("\"message\":\"test message\""));
    }

    #[tokio::test]
    async fn test_log_state_level_filter() {
        let state = LogState::new();

        state.set_min_level(LogLevel::Info).await;
        assert_eq!(state.get_min_level().await, LogLevel::Info);

        // Trace and Debug should not pass when level is Info
        let trace_msg = LogMessage::new(LogLevel::Trace, "trace".to_string());
        let debug_msg = LogMessage::new(LogLevel::Debug, "debug".to_string());
        let info_msg = LogMessage::new(LogLevel::Info, "info".to_string());
        let warn_msg = LogMessage::new(LogLevel::Warn, "warn".to_string());

        let mut receiver = state.subscribe();
        state.log(trace_msg).await;
        state.log(debug_msg).await;
        state.log(info_msg).await;
        state.log(warn_msg).await;

        // Should only receive info and warn
        let received: Vec<_> = {
            let mut msgs = Vec::new();
            for _ in 0..2 {
                if let Ok(msg) = receiver.recv().await {
                    msgs.push(msg.message);
                }
            }
            msgs
        };

        assert!(received.contains(&"info".to_string()));
        assert!(received.contains(&"warn".to_string()));
        assert!(!received.contains(&"trace".to_string()));
        assert!(!received.contains(&"debug".to_string()));
    }

    #[test]
    fn test_parse_level_response() {
        assert_eq!(parse_level_response("LEVEL:info\n"), Some(LogLevel::Info));
        assert_eq!(parse_level_response("LEVEL:debug\n"), Some(LogLevel::Debug));
        assert_eq!(parse_level_response("invalid"), None);
    }
}
