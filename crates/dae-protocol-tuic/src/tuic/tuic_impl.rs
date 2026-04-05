//! TUIC protocol types
//!
//! All TUIC protocol types are defined here to avoid circular dependencies.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Context type (stub - not used in actual implementation)
#[derive(Debug, Clone)]
pub struct Context {
    _private: (),
}

/// Proxy result type
pub type ProxyResult = std::result::Result<(), TuicError>;

/// TUIC protocol version
pub const TUIC_VERSION: u8 = 0x05;

/// TUIC command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TuicCommandType {
    Auth = 0x01,
    Connect = 0x02,
    Disconnect = 0x03,
    Heartbeat = 0x04,
    UdpPacket = 0x05,
}

impl TuicCommandType {
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

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// TUIC authentication request
#[derive(Debug, Clone)]
pub struct TuicAuthRequest {
    pub version: u8,
    pub uuid: String,
    pub token: String,
}

/// TUIC connect request
#[derive(Debug, Clone)]
pub struct TuicConnectRequest {
    pub addr_type: u8,
    pub host: String,
    pub port: u16,
    pub session_id: u64,
}

/// TUIC heartbeat request
#[derive(Debug, Clone)]
pub struct TuicHeartbeatRequest {
    pub timestamp: i64,
}

/// TUIC protocol commands
#[derive(Debug, Clone)]
pub enum TuicCommand {
    Auth(TuicAuthRequest),
    Connect(TuicConnectRequest),
    ConnectResponse(u64, bool),
    Disconnect(u64),
    Heartbeat(TuicHeartbeatRequest),
    HeartbeatResponse(i64),
    UdpPacket(u64, Vec<u8>),
}

/// TUIC configuration
#[derive(Debug, Clone)]
pub struct TuicConfig {
    pub token: String,
    pub uuid: String,
    pub server_name: String,
    pub congestion_control: String,
    pub max_idle_timeout: u32,
    pub max_udp_packet_size: u32,
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
    pub fn new(token: String, uuid: String) -> Self {
        Self { token, uuid, ..Default::default() }
    }

    pub fn validate(&self) -> Result<(), TuicError> {
        if self.token.is_empty() {
            return Err(TuicError::InvalidConfig("token cannot be empty".to_string()));
        }
        if self.uuid.is_empty() {
            return Err(TuicError::InvalidConfig("uuid cannot be empty".to_string()));
        }
        Ok(())
    }
}

/// TUIC error
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
    #[error("Timeout")]
    Timeout,
    #[error("Not connected")]
    NotConnected,
}

/// TUIC session
#[derive(Debug, Clone)]
pub struct TuicSession {
    pub session_id: u64,
    pub remote: SocketAddr,
    pub target_addr: Option<(String, u16)>,
    pub connected: bool,
    pub last_heartbeat: i64,
}

impl TuicSession {
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

/// TUIC server
#[derive(Debug, Clone)]
pub struct TuicServer {
    config: TuicConfig,
    sessions: Arc<RwLock<HashMap<u64, TuicSession>>>,
}

impl TuicServer {
    pub fn new(config: TuicConfig) -> Result<Self, TuicError> {
        config.validate()?;
        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn config(&self) -> &TuicConfig {
        &self.config
    }

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

async fn handle_client(
    mut stream: TcpStream,
    remote: SocketAddr,
    config: TuicConfig,
    sessions: Arc<RwLock<HashMap<u64, TuicSession>>>,
) -> Result<(), TuicError> {
    use super::codec::TuicCodec;
    use super::tuic_impl::TuicCommand;

    debug!("New TUIC connection from {}", remote);

    let auth_request = match TuicCodec::read_auth_request(&mut stream).await {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to read auth request: {}", e);
            return Err(e);
        }
    };

    if auth_request.token != config.token || auth_request.uuid != config.uuid {
        error!("Authentication failed for UUID: {}", auth_request.uuid);
        TuicCodec::write_auth_response(&mut stream, false).await?;
        return Err(TuicError::AuthFailed("Invalid credentials".to_string()));
    }

    TuicCodec::write_auth_response(&mut stream, true).await?;
    info!("TUIC client authenticated: {}", auth_request.uuid);

    loop {
        match TuicCodec::read_command(&mut stream).await {
            Ok(command) => {
                match command {
                    TuicCommand::Connect(connect) => {
                        debug!("Connect request: {}:{} session={}", connect.host, connect.port, connect.session_id);
                        let mut session = TuicSession::new(connect.session_id, remote);
                        session.target_addr = Some((connect.host.clone(), connect.port));
                        session.connected = true;
                        sessions.write().await.insert(connect.session_id, session.clone());
                        TuicCodec::write_connect_response(&mut stream, connect.session_id, true).await?;
                        handle_tcp_relay(stream, session).await?;
                        break;
                    }
                    TuicCommand::Heartbeat(heartbeat) => {
                        debug!("Heartbeat: timestamp={}", heartbeat.timestamp);
                        TuicCodec::write_heartbeat_response(&mut stream, heartbeat.timestamp).await?;
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

async fn handle_tcp_relay(mut client_stream: TcpStream, session: TuicSession) -> Result<(), TuicError> {
    if let Some((host, port)) = session.target_addr {
        let target: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|e| TuicError::InvalidProtocol(format!("Invalid target address: {}", e)))?;
        let mut target_stream = TcpStream::connect(target).await?;
        let (mut cr, mut cw) = client_stream.split();
        let (mut tr, mut tw) = target_stream.split();
        tokio::io::copy(&mut cr, &mut tw).await?;
        tokio::io::copy(&mut tr, &mut cw).await?;
    }
    Ok(())
}

/// TUIC client
#[derive(Debug, Clone)]
pub struct TuicClient {
    config: TuicConfig,
    server_addr: SocketAddr,
}

impl TuicClient {
    pub fn new(config: TuicConfig, server_addr: SocketAddr) -> Self {
        Self { config, server_addr }
    }

    pub async fn connect(&self) -> Result<TuicClientSession, TuicError> {
        use super::codec::TuicCodec;
        use super::tuic_impl::TuicAuthRequest;
        let mut stream = TcpStream::connect(self.server_addr).await?;
        let auth_request = TuicAuthRequest {
            version: TUIC_VERSION,
            uuid: self.config.uuid.clone(),
            token: self.config.token.clone(),
        };
        TuicCodec::write_auth_request(&mut stream, &auth_request).await?;
        let auth_success = TuicCodec::read_auth_response(&mut stream).await?;
        if !auth_success {
            return Err(TuicError::AuthFailed("Server rejected authentication".to_string()));
        }
        info!("TUIC client connected to server");
        Ok(TuicClientSession { stream, server_addr: self.server_addr, session_id: 0 })
    }

    pub async fn connect_target(&self, session: &mut TuicClientSession, host: String, port: u16) -> Result<(), TuicError> {
        use super::codec::TuicCodec;
        use super::tuic_impl::TuicConnectRequest;
        let session_id = rand::random::<u64>();
        session.session_id = session_id;
        let connect_request = TuicConnectRequest {
            addr_type: if host.parse::<std::net::IpAddr>().is_ok() { 0x01 } else { 0x02 },
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

/// TUIC client session
#[derive(Debug)]
pub struct TuicClientSession {
    pub stream: TcpStream,
    pub server_addr: SocketAddr,
    pub session_id: u64,
}

/// TUIC handler
#[derive(Debug, Clone)]
pub struct TuicHandler {
    config: TuicConfig,
}

impl TuicHandler {
    pub fn new(config: TuicConfig) -> Self {
        Self { config }
    }

    pub async fn handle_inbound(&self, _ctx: &mut Context) -> ProxyResult {
        debug!("TUIC handler processing inbound connection");
        Ok(())
    }

    pub async fn handle_outbound(&self, _ctx: &mut Context) -> ProxyResult {
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
        assert_eq!(TuicCommandType::from_u8(0x02), Some(TuicCommandType::Connect));
        assert_eq!(TuicCommandType::from_u8(0x03), Some(TuicCommandType::Disconnect));
        assert_eq!(TuicCommandType::from_u8(0x04), Some(TuicCommandType::Heartbeat));
        assert_eq!(TuicCommandType::from_u8(0xFF), None);
        assert_eq!(TuicCommandType::Auth.as_u8(), 0x01);
        assert_eq!(TuicCommandType::Connect.as_u8(), 0x02);
    }

    #[test]
    fn test_tuic_config_validation() {
        let valid = TuicConfig::new("token123".to_string(), "uuid456".to_string());
        assert!(valid.validate().is_ok());
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
    }

    #[test]
    fn test_tuic_error_display() {
        let err = TuicError::InvalidProtocol("bad proto".to_string());
        assert!(format!("{}", err).contains("bad proto"));
    }
}
