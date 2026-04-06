//! TUIC 客户端实现
//!
//! 提供 TUIC 客户端的完整实现。

use std::net::SocketAddr;

use tokio::net::TcpStream;
use tracing::info;

use super::codec::TuicCodec;
use super::consts::{TuicError, TUIC_VERSION};
use super::TuicConfig;

/// TUIC 客户端
///
/// 用于连接到远程 TUIC 服务器的客户端。
pub struct TuicClient {
    config: TuicConfig,
    server_addr: SocketAddr,
}

/// TUIC 客户端会话
///
/// 表示客户端到服务器的活动连接。
#[derive(Debug)]
pub struct TuicClientSession {
    pub stream: TcpStream,
    pub server_addr: SocketAddr,
    pub session_id: u64,
}

impl TuicClient {
    /// 创建新的 TUIC 客户端
    pub fn new(config: TuicConfig, server_addr: SocketAddr) -> Self {
        Self {
            config,
            server_addr,
        }
    }

    /// 连接到 TUIC 服务器
    pub async fn connect(&self) -> Result<TuicClientSession, TuicError> {
        use super::consts::TuicAuthRequest;
        let mut stream = TcpStream::connect(self.server_addr).await?;
        let auth_request = TuicAuthRequest {
            version: TUIC_VERSION,
            uuid: self.config.uuid.clone(),
            token: self.config.token.clone(),
        };
        TuicCodec::write_auth_request(&mut stream, &auth_request).await?;
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

    /// 连接到目标地址
    pub async fn connect_target(
        &self,
        session: &mut TuicClientSession,
        host: String,
        port: u16,
    ) -> Result<(), TuicError> {
        use super::consts::TuicConnectRequest;
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
