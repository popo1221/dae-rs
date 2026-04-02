//! TUIC protocol implementation
//!
//! Provides TUIC protocol handler, server, and client support.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::core::{Context, Error, Result as ProxyResult};

/// TUIC protocol version
pub const TUIC_VERSION: u8 = 0x05;

/// TUIC command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TuicCommandType {
    /// Authentication command
    Auth = 0x01,
    /// Connect command (TCP)
    Connect = 0x02,
    /// Disconnect command
    Disconnect = 0x03,
    /// Heartbeat command
    Heartbeat = 0x04,
    /// UDP packet command
    UdpPacket = 0x05,
}

impl TuicCommandType {
    /// Parse command type from u8
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(TuicCommandType::Auth),
            0x02 => Some(TuicCommandType::Connect),
            0x03 => Some(TuicCommandType::Disconnect),
            0x04 => Some(TuicCommandType::Heartbeat),
            0x05 => Some(TuicCommandType::UdpPacket),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// TUIC authentication request
#[derive(Debug, Clone)]
pub struct TuicAuthRequest {
    /// Protocol version
    pub version: u8,
    /// UUID (as string)
    pub uuid: String,
    /// Authentication token
    pub token: String,
}

/// TUIC connect request
#[derive(Debug, Clone)]
pub struct TuicConnectRequest {
    /// Target address type
    pub addr_type: u8,
    /// Target host
    pub host: String,
    /// Target port
    pub port: u16,
    /// Session ID
    pub session_id: u64,
}

/// TUIC heartbeat request
#[derive(Debug, Clone)]
pub struct TuicHeartbeatRequest {
    /// Timestamp
    pub timestamp: i64,
}

/// TUIC protocol commands
#[derive(Debug, Clone)]
pub enum TuicCommand {
    /// Authentication
    Auth(super::codec::TuicAuthRequest),
    /// Connect request
    Connect(TuicConnectRequest),
    /// Connect response (session_id, success)
    ConnectResponse(u64, bool),
    /// Disconnect (session_id)
    Disconnect(u64),
    /// Heartbeat
    Heartbeat(TuicHeartbeatRequest),
    /// Heartbeat response (timestamp)
    HeartbeatResponse(i64),
    /// UDP packet (session_id, data)
    UdpPacket(u64, Vec<u8>),
}

/// TUIC configuration
#[derive(Debug, Clone)]
pub struct TuicConfig {
    /// Authentication token
    pub token: String,
    /// UUID for authentication
    pub uuid: String,
    /// Server name for TLS SNI
    pub server_name: String,
    /// Congestion control algorithm
    pub congestion_control: String,
    /// Max idle timeout in seconds
    pub max_idle_timeout: u32,
    /// Max UDP packet size
    pub max_udp_packet_size: u32,
    /// Flow control window
    pub flow_control_window: u32,
}

impl Default for TuicConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            uuid: String::new(),
            server_name: "tuic.cloud".to_string(),
            congestion_control: "bbr".to_string(),
            max_idle_timeout: 15,
            max_udp_packet_size: 1400,
            flow_control_window: 8388608,
        }
    }
}

impl TuicConfig {
    /// Create a new TUIC config from token and UUID
    pub fn new(token: String, uuid: String) -> Self {
        Self {
            token,
            uuid,
            ..Default::default()
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), TuicError> {
        if self.token.is_empty() {
            return Err(TuicError::InvalidConfig(
                "token cannot be empty".to_string(),
            ));
        }
        if self.uuid.is_empty() {
            return Err(TuicError::InvalidConfig("uuid cannot be empty".to_string()));
        }
        Ok(())
    }
}

/// TUIC protocol error
#[derive(Debug, thiserror::Error)]
pub enum TuicError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid protocol: {0}")]
    InvalidProtocol(String),

    #[error("Invalid command: {0}")]
    InvalidCommand(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("Timeout")]
    Timeout,

    #[error("Not connected")]
    NotConnected,
}

/// TUIC session state
#[derive(Debug, Clone)]
pub struct TuicSession {
    /// Session ID
    pub session_id: u64,
    /// Remote address
    pub remote: SocketAddr,
    /// Target address
    pub target_addr: Option<(String, u16)>,
    /// Connected flag
    pub connected: bool,
    /// Last heartbeat time
    pub last_heartbeat: i64,
}

impl TuicSession {
    /// Create a new session
    pub fn new(session_id: u64, remote: SocketAddr) -> Self {
        Self {
            session_id,
            remote,
            target_addr: None,
            connected: false,
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }
}

/// TUIC server for handling incoming connections
#[derive(Debug, Clone)]
pub struct TuicServer {
    config: TuicConfig,
    sessions: Arc<RwLock<HashMap<u64, TuicSession>>>,
}

use std::collections::HashMap;

impl TuicServer {
    /// Create a new TUIC server
    pub fn new(config: TuicConfig) -> Result<Self, TuicError> {
        config.validate()?;
        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get the server configuration
    pub fn config(&self) -> &TuicConfig {
        &self.config
    }

    /// Start listening on the given address
    pub async fn listen(&self, addr: SocketAddr) -> Result<(), TuicError> {
        info!("TUIC server listening on {}", addr);
        let listener = TcpListener::bind(addr).await?;

        loop {
            match listener.accept().await {
                Ok((stream, remote)) => {
                    let config = self.config.clone();
                    let sessions = self.sessions.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, remote, config, sessions).await {
                            error!("TUIC client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("TUIC accept error: {}", e);
                }
            }
        }
    }
}

/// Handle a TUIC client connection
async fn handle_client(
    mut stream: TcpStream,
    remote: SocketAddr,
    config: TuicConfig,
    sessions: Arc<RwLock<HashMap<u64, TuicSession>>>,
) -> Result<(), TuicError> {
    debug!("New TUIC connection from {}", remote);

    // Read auth request
    let auth_request = match TuicCodec::read_auth_request(&mut stream).await {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to read auth request: {}", e);
            return Err(e);
        }
    };

    // Verify authentication
    if auth_request.token != config.token || auth_request.uuid != config.uuid {
        error!("Authentication failed for UUID: {}", auth_request.uuid);
        TuicCodec::write_auth_response(&mut stream, false).await?;
        return Err(TuicError::AuthFailed("Invalid credentials".to_string()));
    }

    // Send auth success
    TuicCodec::write_auth_response(&mut stream, true).await?;
    info!("TUIC client authenticated: {}", auth_request.uuid);

    // Main command loop
    loop {
        match TuicCodec::read_command(&mut stream).await {
            Ok(command) => {
                match command {
                    TuicCommand::Connect(connect) => {
                        debug!(
                            "Connect request: {}:{} session={}",
                            connect.host, connect.port, connect.session_id
                        );

                        let session = TuicSession::new(connect.session_id, remote);
                        session.target_addr = Some((connect.host.clone(), connect.port));
                        session.connected = true;

                        sessions
                            .write()
                            .await
                            .insert(connect.session_id, session.clone());

                        // Respond to connect
                        TuicCodec::write_connect_response(&mut stream, connect.session_id, true)
                            .await?;

                        // Handle the connection...
                        handle_tcp_relay(stream, session).await?;
                        break;
                    }
                    TuicCommand::Heartbeat(heartbeat) => {
                        debug!("Heartbeat: timestamp={}", heartbeat.timestamp);
                        TuicCodec::write_heartbeat_response(&mut stream, heartbeat.timestamp)
                            .await?;
                    }
                    TuicCommand::Disconnect(session_id) => {
                        debug!("Disconnect: session_id={}", session_id);
                        sessions.write().await.remove(&session_id);
                        break;
                    }
                    _ => {
                        warn!("Unexpected command type");
                    }
                }
            }
            Err(e) => {
                error!("Command read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Handle TCP relay for a TUIC session
async fn handle_tcp_relay(
    mut client_stream: TcpStream,
    session: TuicSession,
) -> Result<(), TuicError> {
    if let Some((host, port)) = session.target_addr {
        let target: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|e| TuicError::InvalidProtocol(format!("Invalid target address: {}", e)))?;

        let mut target_stream = TcpStream::connect(target).await?;

        // Bidirectional copy
        let (mut client_read, mut client_write) = client_stream.split();
        let (mut target_read, mut target_write) = target_stream.split();

        tokio::io::copy(&mut client_read, &mut target_write).await?;
        tokio::io::copy(&mut target_read, &mut client_write).await?;
    }

    Ok(())
}

/// TUIC client for connecting to TUIC servers
#[derive(Debug, Clone)]
pub struct TuicClient {
    config: TuicConfig,
    server_addr: SocketAddr,
}

impl TuicClient {
    /// Create a new TUIC client
    pub fn new(config: TuicConfig, server_addr: SocketAddr) -> Self {
        Self {
            config,
            server_addr,
        }
    }

    /// Connect to the TUIC server and create a session
    pub async fn connect(&self) -> Result<TuicClientSession, TuicError> {
        let mut stream = TcpStream::connect(self.server_addr).await?;

        // Send auth request
        let auth_request = crate::tuic::codec::TuicAuthRequest {
            version: TUIC_VERSION,
            uuid: self.config.uuid.clone(),
            token: self.config.token.clone(),
        };

        TuicCodec::write_auth_request(&mut stream, &auth_request).await?;

        // Read auth response
        let auth_success = TuicCodec::read_auth_response(&mut stream).await?;
        if !auth_success {
            return Err(TuicError::AuthFailed(
                "Server rejected authentication".to_string(),
            ));
        }

        info!("TUIC client connected to server");

        Ok(TuicClientSession {
            stream,
            server_addr: self.server_addr,
            session_id: 0,
        })
    }

    /// Connect to a target address through the TUIC session
    pub async fn connect_target(
        &self,
        session: &mut TuicClientSession,
        host: String,
        port: u16,
    ) -> Result<(), TuicError> {
        let session_id = rand::random::<u64>();
        session.session_id = session_id;

        let connect_request = TuicConnectRequest {
            addr_type: if host.parse::<std::net::IpAddr>().is_ok() {
                0x01
            } else {
                0x02
            },
            host,
            port,
            session_id,
        };

        TuicCodec::write_connect_request(&mut session.stream, &connect_request).await?;

        let success = TuicCodec::read_connect_response(&mut session.stream).await?;
        if !success {
            return Err(TuicError::InvalidProtocol("Connect rejected".to_string()));
        }

        Ok(())
    }
}

/// TUIC client session handle
#[derive(Debug)]
pub struct TuicClientSession {
    /// The TCP stream
    pub stream: TcpStream,
    /// Server address
    pub server_addr: SocketAddr,
    /// Current session ID
    pub session_id: u64,
}

/// TUIC handler for protocol dispatcher integration
#[derive(Debug, Clone)]
pub struct TuicHandler {
    config: TuicConfig,
}

impl TuicHandler {
    /// Create a new TUIC handler
    pub fn new(config: TuicConfig) -> Self {
        Self { config }
    }

    /// Handle inbound TUIC connection
    pub async fn handle_inbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        // For inbound handling, we expect the connection to already be established
        // This is called by the protocol dispatcher after initial setup
        debug!("TUIC handler processing inbound connection");
        Ok(())
    }

    /// Handle outbound TUIC connection
    pub async fn handle_outbound(&self, ctx: &mut Context) -> ProxyResult<()> {
        debug!("TUIC handler processing outbound connection");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_command_type_conversion() {
        assert_eq!(TuicCommandType::from_u8(0x01), Some(TuicCommandType::Auth));
        assert_eq!(
            TuicCommandType::from_u8(0x02),
            Some(TuicCommandType::Connect)
        );
        assert_eq!(
            TuicCommandType::from_u8(0x03),
            Some(TuicCommandType::Disconnect)
        );
        assert_eq!(
            TuicCommandType::from_u8(0x04),
            Some(TuicCommandType::Heartbeat)
        );
        assert_eq!(TuicCommandType::from_u8(0xFF), None);

        assert_eq!(TuicCommandType::Auth.as_u8(), 0x01);
        assert_eq!(TuicCommandType::Connect.as_u8(), 0x02);
    }

    #[test]
    fn test_tuic_config_validation() {
        let valid_config = TuicConfig::new("token123".to_string(), "uuid456".to_string());
        assert!(valid_config.validate().is_ok());

        let empty_token = TuicConfig::new("".to_string(), "uuid456".to_string());
        assert!(empty_token.validate().is_err());

        let empty_uuid = TuicConfig::new("token123".to_string(), "".to_string());
        assert!(empty_uuid.validate().is_err());
    }

    #[test]
    fn test_tuic_session() {
        let session = TuicSession::new(12345, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(session.session_id, 12345);
        assert!(!session.connected);
        assert!(session.target_addr.is_none());
    }

    #[test]
    fn test_tuic_session_with_target() {
        let mut session = TuicSession::new(12345, "127.0.0.1:8080".parse().unwrap());
        session.target_addr = Some(("example.com".to_string(), 443));
        session.connected = true;

        assert!(session.target_addr.is_some());
        let (host, port) = session.target_addr.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert!(session.connected);
    }

    #[test]
    fn test_tuic_config_default() {
        let config = TuicConfig::default();
        assert_eq!(config.server_name, "tuic.cloud");
        assert_eq!(config.congestion_control, "bbr");
        assert_eq!(config.max_idle_timeout, 15);
        assert_eq!(config.max_udp_packet_size, 1400);
        assert_eq!(config.flow_control_window, 8388608);
    }

    #[test]
    fn test_tuic_config_with_values() {
        let config = TuicConfig::new("my_token".to_string(), "my_uuid".to_string());
        assert_eq!(config.token, "my_token");
        assert_eq!(config.uuid, "my_uuid");
    }

    #[test]
    fn test_tuic_error_display() {
        let err = TuicError::InvalidProtocol("bad proto".to_string());
        assert!(format!("{}", err).contains("bad proto"));

        let err = TuicError::InvalidCommand("bad cmd".to_string());
        assert!(format!("{}", err).contains("bad cmd"));

        let err = TuicError::AuthFailed("bad auth".to_string());
        assert!(format!("{}", err).contains("bad auth"));

        let err = TuicError::InvalidConfig("bad config".to_string());
        assert!(format!("{}", err).contains("bad config"));
    }

    #[test]
    fn test_tuic_command_type_all_variants() {
        // Test all command type conversions
        for v in 0x00..=0xFF {
            let result = TuicCommandType::from_u8(v);
            match v {
                0x01 => assert_eq!(result, Some(TuicCommandType::Auth)),
                0x02 => assert_eq!(result, Some(TuicCommandType::Connect)),
                0x03 => assert_eq!(result, Some(TuicCommandType::Disconnect)),
                0x04 => assert_eq!(result, Some(TuicCommandType::Heartbeat)),
                0x05 => assert_eq!(result, Some(TuicCommandType::UdpPacket)),
                _ => assert_eq!(result, None),
            }
        }
    }
}
