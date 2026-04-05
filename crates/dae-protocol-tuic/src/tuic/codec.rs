//! TUIC protocol codec implementation
//!
//! Provides serialization and deserialization for TUIC protocol messages.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use super::tuic_impl::{
    TuicCommand, TuicCommandType, TuicConnectRequest, TuicError, TuicHeartbeatRequest,
    TuicAuthRequest, TUIC_VERSION,
};

/// TUIC protocol codec
pub struct TuicCodec;

impl TuicCodec {
    /// Read authentication request from stream
    pub async fn read_auth_request<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<TuicAuthRequest, TuicError> {
        let mut version_buf = [0u8; 1];
        reader.read_exact(&mut version_buf).await?;
        let version = version_buf[0];

        if version != TUIC_VERSION {
            return Err(TuicError::InvalidProtocol(format!(
                "Unsupported TUIC version: expected 0x{:02x}, got 0x{:02x}",
                TUIC_VERSION, version
            )));
        }

        let mut uuid_buf = vec![0u8; 36];
        reader.read_exact(&mut uuid_buf).await?;
        let uuid = String::from_utf8(uuid_buf)
            .map_err(|e| TuicError::InvalidProtocol(format!("Invalid UUID: {}", e)))?
            .trim_end_matches('\0')
            .to_string();

        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let token_len = u16::from_be_bytes(len_buf) as usize;

        let mut token_buf = vec![0u8; token_len];
        reader.read_exact(&mut token_buf).await?;
        let token = String::from_utf8(token_buf)
            .map_err(|e| TuicError::InvalidProtocol(format!("Invalid token: {}", e)))?
            .trim_end_matches('\0')
            .to_string();

        debug!("Read auth request: version=0x{:02x}, uuid={}", version, uuid);

        Ok(TuicAuthRequest { version, uuid, token })
    }

    /// Write authentication request to stream
    pub async fn write_auth_request<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        req: &TuicAuthRequest,
    ) -> Result<(), TuicError> {
        writer.write_all(&[req.version]).await?;
        let mut uuid_buf = vec![0u8; 36];
        let uuid_bytes = req.uuid.as_bytes();
        let copy_len = uuid_bytes.len().min(36);
        uuid_buf[..copy_len].copy_from_slice(&uuid_bytes[..copy_len]);
        writer.write_all(&uuid_buf).await?;
        let token_bytes = req.token.as_bytes();
        writer.write_all(&(token_bytes.len() as u16).to_be_bytes()).await?;
        writer.write_all(token_bytes).await?;
        debug!("Wrote auth request: version=0x{:02x}, uuid={}", req.version, req.uuid);
        Ok(())
    }

    /// Read authentication response
    pub async fn read_auth_response<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<bool, TuicError> {
        let mut status_buf = [0u8; 1];
        reader.read_exact(&mut status_buf).await?;
        Ok(status_buf[0] == 0x00)
    }

    /// Write authentication response
    pub async fn write_auth_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        success: bool,
    ) -> Result<(), TuicError> {
        writer.write_all(&[if success { 0x00 } else { 0x01 }]).await?;
        Ok(())
    }

    /// Read a TUIC command from stream
    pub async fn read_command<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<TuicCommand, TuicError> {
        let mut cmd_buf = [0u8; 1];
        reader.read_exact(&mut cmd_buf).await?;
        let cmd_type = TuicCommandType::from_u8(cmd_buf[0])
            .ok_or_else(|| TuicError::InvalidCommand(format!("Unknown command: 0x{:02x}", cmd_buf[0])))?;

        match cmd_type {
            TuicCommandType::Connect => {
                let request = Self::read_connect_request(reader).await?;
                Ok(TuicCommand::Connect(request))
            }
            TuicCommandType::Heartbeat => {
                let mut ts_buf = [0u8; 8];
                reader.read_exact(&mut ts_buf).await?;
                Ok(TuicCommand::Heartbeat(TuicHeartbeatRequest { timestamp: i64::from_be_bytes(ts_buf) }))
            }
            TuicCommandType::Disconnect => {
                let mut sid_buf = [0u8; 8];
                reader.read_exact(&mut sid_buf).await?;
                Ok(TuicCommand::Disconnect(u64::from_be_bytes(sid_buf)))
            }
            TuicCommandType::Auth => {
                Err(TuicError::InvalidCommand("Auth not expected here".to_string()))
            }
            TuicCommandType::UdpPacket => {
                let session_id = Self::read_session_id(reader).await?;
                let mut len_buf = [0u8; 2];
                reader.read_exact(&mut len_buf).await?;
                let data_len = u16::from_be_bytes(len_buf) as usize;
                let mut data = vec![0u8; data_len];
                reader.read_exact(&mut data).await?;
                Ok(TuicCommand::UdpPacket(session_id, data))
            }
        }
    }

    /// Write a TUIC command to stream
    pub async fn write_command<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        cmd: &TuicCommand,
    ) -> Result<(), TuicError> {
        match cmd {
            TuicCommand::Connect(request) => {
                writer.write_all(&[TuicCommandType::Connect.as_u8()]).await?;
                Self::write_connect_request(writer, request).await?;
            }
            TuicCommand::ConnectResponse(session_id, success) => {
                writer.write_all(&[TuicCommandType::Connect.as_u8()]).await?;
                writer.write_all(&session_id.to_be_bytes()).await?;
                writer.write_all(&[if *success { 0x00 } else { 0x01 }]).await?;
            }
            TuicCommand::Heartbeat(request) => {
                writer.write_all(&[TuicCommandType::Heartbeat.as_u8()]).await?;
                writer.write_all(&request.timestamp.to_be_bytes()).await?;
            }
            TuicCommand::HeartbeatResponse(timestamp) => {
                writer.write_all(&[TuicCommandType::Heartbeat.as_u8()]).await?;
                writer.write_all(&timestamp.to_be_bytes()).await?;
            }
            TuicCommand::Disconnect(session_id) => {
                writer.write_all(&[TuicCommandType::Disconnect.as_u8()]).await?;
                writer.write_all(&session_id.to_be_bytes()).await?;
            }
            TuicCommand::UdpPacket(session_id, data) => {
                writer.write_all(&[TuicCommandType::UdpPacket.as_u8()]).await?;
                writer.write_all(&session_id.to_be_bytes()).await?;
                writer.write_all(&(data.len() as u16).to_be_bytes()).await?;
                writer.write_all(data).await?;
            }
            TuicCommand::Auth(_) => {
                return Err(TuicError::InvalidCommand("Auth should use write_auth_request".to_string()));
            }
        }
        Ok(())
    }

    async fn read_connect_request<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<TuicConnectRequest, TuicError> {
        let mut addr_buf = [0u8; 1];
        reader.read_exact(&mut addr_buf).await?;
        let addr_type = addr_buf[0];

        let host_len = match addr_type {
            0x01 => 4,
            0x02 => {
                let mut len_buf = [0u8; 1];
                reader.read_exact(&mut len_buf).await?;
                len_buf[0] as usize
            }
            0x03 => 16,
            _ => return Err(TuicError::InvalidProtocol(format!("Invalid address type: 0x{:02x}", addr_type))),
        };

        let mut host_buf = vec![0u8; host_len];
        reader.read_exact(&mut host_buf).await?;
        let host = match addr_type {
            0x01 => format!("{}.{}.{}.{}", host_buf[0], host_buf[1], host_buf[2], host_buf[3]),
            0x02 => String::from_utf8(host_buf).map_err(|e| TuicError::InvalidProtocol(format!("Invalid host: {}", e)))?.trim_end_matches('\0').to_string(),
            0x03 => format!("{:x?}", &host_buf),
            _ => unreachable!(),
        };

        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        let mut session_buf = [0u8; 8];
        reader.read_exact(&mut session_buf).await?;
        let session_id = u64::from_be_bytes(session_buf);

        debug!("Read connect request: {}:{} session_id={}", host, port, session_id);
        Ok(TuicConnectRequest { addr_type, host, port, session_id })
    }

    /// Write connect request
    pub async fn write_connect_request<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        request: &TuicConnectRequest,
    ) -> Result<(), TuicError> {
        writer.write_all(&[request.addr_type]).await?;
        match request.addr_type {
            0x01 => {
                let parts: Vec<u8> = request.host.split('.').filter_map(|s| s.parse().ok()).collect();
                if parts.len() != 4 {
                    return Err(TuicError::InvalidProtocol("Invalid IPv4".to_string()));
                }
                writer.write_all(&parts).await?;
            }
            0x02 => {
                let host_bytes = request.host.as_bytes();
                writer.write_all(&[host_bytes.len() as u8]).await?;
                writer.write_all(host_bytes).await?;
            }
            0x03 => {
                return Err(TuicError::InvalidProtocol("IPv6 not implemented".to_string()));
            }
            _ => return Err(TuicError::InvalidProtocol(format!("Invalid addr type: 0x{:02x}", request.addr_type))),
        }
        writer.write_all(&request.port.to_be_bytes()).await?;
        writer.write_all(&request.session_id.to_be_bytes()).await?;
        debug!("Wrote connect request: {}:{} session_id={}", request.host, request.port, request.session_id);
        Ok(())
    }

    /// Read connect response
    pub async fn read_connect_response<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<bool, TuicError> {
        let _session_id = Self::read_session_id(reader).await?;
        let mut status_buf = [0u8; 1];
        reader.read_exact(&mut status_buf).await?;
        Ok(status_buf[0] == 0x00)
    }

    /// Write connect response
    pub async fn write_connect_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        session_id: u64,
        success: bool,
    ) -> Result<(), TuicError> {
        writer.write_all(&session_id.to_be_bytes()).await?;
        writer.write_all(&[if success { 0x00 } else { 0x01 }]).await?;
        Ok(())
    }

    /// Write heartbeat response
    pub async fn write_heartbeat_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        timestamp: i64,
    ) -> Result<(), TuicError> {
        writer.write_all(&timestamp.to_be_bytes()).await?;
        Ok(())
    }

    async fn read_session_id<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<u64, TuicError> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).await?;
        Ok(u64::from_be_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_auth_request_roundtrip() {
        let request = TuicAuthRequest {
            version: 0x05,
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            token: "test_token".to_string(),
        };
        let mut buf = Vec::new();
        let mut writer = Cursor::new(&mut buf);
        TuicCodec::write_auth_request(&mut writer, &request).await.unwrap();
        let mut reader = Cursor::new(&buf);
        let decoded = TuicCodec::read_auth_request(&mut reader).await.unwrap();
        assert_eq!(decoded.version, request.version);
        assert_eq!(decoded.uuid, request.uuid);
        assert_eq!(decoded.token, request.token);
    }

    #[tokio::test]
    async fn test_auth_response_roundtrip() {
        let mut buf = Vec::new();
        let mut writer = Cursor::new(&mut buf);
        TuicCodec::write_auth_response(&mut writer, true).await.unwrap();
        let mut reader = Cursor::new(&buf);
        assert!(TuicCodec::read_auth_response(&mut reader).await.unwrap());

        buf.clear();
        let mut writer = Cursor::new(&mut buf);
        TuicCodec::write_auth_response(&mut writer, false).await.unwrap();
        let mut reader = Cursor::new(&buf);
        assert!(!TuicCodec::read_auth_response(&mut reader).await.unwrap());
    }

    #[test]
    fn test_command_type_conversion() {
        assert_eq!(TuicCommandType::from_u8(0x01), Some(TuicCommandType::Auth));
        assert_eq!(TuicCommandType::from_u8(0x02), Some(TuicCommandType::Connect));
        assert_eq!(TuicCommandType::from_u8(0xff), None);
    }
}
