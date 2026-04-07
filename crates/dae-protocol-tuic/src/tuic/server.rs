//! TUIC 服务器实现
//!
//! 提供 TUIC 服务器端的完整实现，包括会话管理和请求处理。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use dae_relay::{relay_bidirectional_with_stats, RelayStats};

use super::codec::TuicCodec;
use super::consts::{TuicCommand, TuicError};
use super::TuicConfig;

/// TUIC 会话
///
/// 表示一个活跃的 TUIC 连接会话。
#[derive(Debug, Clone)]
pub struct TuicSession {
    pub session_id: u64,
    pub remote: SocketAddr,
    pub target_addr: Option<(String, u16)>,
    pub connected: bool,
    pub last_heartbeat: i64,
}

impl TuicSession {
    /// 创建新的 TUIC 会话
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

/// TUIC 服务器
///
/// 用于接收和管理 TUIC 客户端连接的服务器。
#[derive(Debug, Clone)]
pub struct TuicServer {
    config: TuicConfig,
    sessions: Arc<RwLock<HashMap<u64, TuicSession>>>,
}

impl TuicServer {
    /// 创建新的 TUIC 服务器
    pub fn new(config: TuicConfig) -> Result<Self, TuicError> {
        config.validate()?;
        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 获取服务器配置
    pub fn config(&self) -> &TuicConfig {
        &self.config
    }

    /// 启动服务器监听
    pub async fn listen(&self, addr: SocketAddr) -> Result<(), TuicError> {
        use tokio::net::TcpListener;
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
            Ok(command) => match command {
                TuicCommand::Connect(connect) => {
                    debug!(
                        "Connect request: {}:{} session={}",
                        connect.host, connect.port, connect.session_id
                    );
                    let mut session = TuicSession::new(connect.session_id, remote);
                    session.target_addr = Some((connect.host.clone(), connect.port));
                    session.connected = true;
                    sessions
                        .write()
                        .await
                        .insert(connect.session_id, session.clone());
                    TuicCodec::write_connect_response(&mut stream, connect.session_id, true)
                        .await?;
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
            },
            Err(e) => {
                error!("Command read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_tcp_relay(
    client_stream: TcpStream,
    session: TuicSession,
) -> Result<RelayStats, TuicError> {
    if let Some((host, port)) = session.target_addr {
        let target: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|e| TuicError::InvalidProtocol(format!("Invalid target address: {}", e)))?;
        let target_stream = TcpStream::connect(target).await?;
        let stats = relay_bidirectional_with_stats(client_stream, target_stream).await?;
        Ok(stats)
    } else {
        Ok(RelayStats::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_session() {
        let session = TuicSession::new(12345, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(session.session_id, 12345);
        assert!(!session.connected);
    }
}
