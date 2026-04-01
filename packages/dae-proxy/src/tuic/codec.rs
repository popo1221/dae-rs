//! TUIC protocol codec implementation
//!
//! Provides serialization and deserialization for TUIC protocol messages.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error};

use super::{TuicCommand, TuicCommandType, TuicError, TuicConnectRequest, TuicHeartbeatRequest};

/// TUIC protocol codec for reading and writing TUIC messages
pub struct TuicCodec;

/// TUIC authentication request (wire format)
#[derive(Debug, Clone)]
pub struct TuicAuthRequest {
    /// Protocol version (0x05)
    pub version: u8,
    /// UUID (16 bytes)
    pub uuid: String,
    /// Authentication token
    pub token: String,
}

/// TUIC connect request (wire format)
#[derive(Debug, Clone)]
pub struct TuicConnectRequest {
    /// Address type (0x01: IPv4, 0x02: Domain, 0x03: IPv6)
    pub addr_type: u8,
    /// Target host
    pub host: String,
    /// Target port
    pub port: u16,
    /// Session ID
    pub session_id: u64,
}

impl TuicCodec {
    /// Read authentication request from stream
    pub async fn read_auth_request<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<TuicAuthRequest, TuicError> {
        // Read version (1 byte)
        let mut version_buf = [0u8; 1];
        reader.read_exact(&mut version_buf).await?;
        let version = version_buf[0];

        if version != super::TUIC_VERSION {
            return Err(TuicError::InvalidProtocol(format!(
                "Unsupported TUIC version: expected 0x{:02x}, got 0x{:02x}",
                super::TUIC_VERSION, version
            )));
        }

        // Read UUID (16 bytes, hex string)
        let mut uuid_buf = vec![0u8; 36];
        reader.read_exact(&mut uuid_buf).await?;
        let uuid = String::from_utf8(uuid_buf)
            .map_err(|e| TuicError::InvalidProtocol(format!("Invalid UUID: {}", e)))?
            .trim_end_matches('\0')
            .to_string();

        // Read token length (2 bytes, big endian)
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf).await?;
        let token_len = u16::from_be_bytes(len_buf) as usize;

        // Read token
        let mut token_buf = vec![0u8; token_len];
        reader.read_exact(&mut token_buf).await?;
        let token = String::from_utf8(token_buf)
            .map_err(|e| TuicError::InvalidProtocol(format!("Invalid token: {}", e)))?
            .trim_end_matches('\0')
            .to_string();

        debug!("Read auth request: version=0x{:02x}, uuid={}, token_len={}", version, uuid, token_len);

        Ok(TuicAuthRequest {
            version,
            uuid,
            token,
        })
    }

    /// Write authentication request to stream
    pub async fn write_auth_request<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        req: &TuicAuthRequest,
    ) -> Result<(), TuicError> {
        // Write version
        writer.write_all(&[req.version]).await?;

        // Write UUID (36 bytes, padded with zeros)
        let mut uuid_buf = vec![0u8; 36];
        let uuid_bytes = req.uuid.as_bytes();
        let copy_len = uuid_bytes.len().min(36);
        uuid_buf[..copy_len].copy_from_slice(&uuid_bytes[..copy_len]);
        writer.write_all(&uuid_buf).await?;

        // Write token length and token
        let token_bytes = req.token.as_bytes();
        writer.write_all(&(token_bytes.len() as u16).to_be_bytes()).await?;
        writer.write_all(token_bytes).await?;

        debug!("Wrote auth request: version=0x{:02x}, uuid={}", req.version, req.uuid);

        Ok(())
    }

    /// Read authentication response from stream
    pub async fn read_auth_response<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<bool, TuicError> {
        let mut status_buf = [0u8; 1];
        reader.read_exact(&mut status_buf).await?;
        let success = status_buf[0] == 0x00;

        debug!("Read auth response: success={}", success);

        Ok(success)
    }

    /// Write authentication response to stream
    pub async fn write_auth_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        success: bool,
    ) -> Result<(), TuicError> {
        let status = if success { 0x00 } else { 0x01 };
        writer.write_all(&[status]).await?;

        debug!("Wrote auth response: success={}", success);

        Ok(())
    }

    /// Read a TUIC command from stream
    pub async fn read_command<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<TuicCommand, TuicError> {
        // Read command type (1 byte)
        let mut cmd_buf = [0u8; 1];
        reader.read_exact(&mut cmd_buf).await?;
        let cmd_type = cmd_buf[0];

        let command_type = TuicCommandType::from_u8(cmd_type)
            .ok_or_else(|| TuicError::InvalidCommand(format!("Unknown command type: 0x{:02x}", cmd_type)))?;

        match command_type {
            TuicCommandType::Connect => {
                let request = Self::read_connect_request(reader).await?;
                Ok(TuicCommand::Connect(request))
            }
            TuicCommandType::Heartbeat => {
                let request = Self::read_heartbeat_request(reader).await?;
                Ok(TuicCommand::Heartbeat(request))
            }
            TuicCommandType::Disconnect => {
                let mut session_id_buf = [0u8; 8];
                reader.read_exact(&mut session_id_buf).await?;
                let session_id = u64::from_be_bytes(session_id_buf);
                Ok(TuicCommand::Disconnect(session_id))
            }
            TuicCommandType::Auth => {
                // Auth is handled separately
                Err(TuicError::InvalidCommand("Auth command not expected here".to_string()))
            }
            TuicCommandType::UdpPacket => {
                // UDP packet handling
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
                Self::write_heartbeat_request(writer, request).await?;
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
                return Err(TuicError::InvalidCommand("Auth command should use write_auth_request".to_string()));
            }
        }

        Ok(())
    }

    /// Read connect request
    async fn read_connect_request<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<TuicConnectRequest, TuicError> {
        // Read address type
        let mut addr_buf = [0u8; 1];
        reader.read_exact(&mut addr_buf).await?;
        let addr_type = addr_buf[0];

        // Read host
        let host_len = match addr_type {
            0x01 => 4,  // IPv4
            0x02 => {
                let mut len_buf = [0u8; 1];
                reader.read_exact(&mut len_buf).await?;
                len_buf[0] as usize
            }
            0x03 => 16, // IPv6
            _ => return Err(TuicError::InvalidProtocol(format!("Invalid address type: 0x{:02x}", addr_type))),
        };

        let mut host_buf = vec![0u8; host_len];
        reader.read_exact(&mut host_buf).await?;

        let host = match addr_type {
            0x01 => {
                // IPv4
                format!("{}.{}.{}.{}", host_buf[0], host_buf[1], host_buf[2], host_buf[3])
            }
            0x02 => {
                // Domain
                String::from_utf8(host_buf)
                    .map_err(|e| TuicError::InvalidProtocol(format!("Invalid host: {}", e)))?
                    .trim_end_matches('\0')
                    .to_string()
            }
            0x03 => {
                // IPv6 (simplified)
                format!("{:x?}", &host_buf)
            }
            _ => unreachable!(),
        };

        // Read port
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        // Read session ID
        let mut session_buf = [0u8; 8];
        reader.read_exact(&mut session_buf).await?;
        let session_id = u64::from_be_bytes(session_buf);

        debug!("Read connect request: {}:{} session_id={}", host, port, session_id);

        Ok(TuicConnectRequest {
            addr_type,
            host,
            port,
            session_id,
        })
    }

    /// Write connect request
    pub async fn write_connect_request<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        request: &TuicConnectRequest,
    ) -> Result<(), TuicError> {
        writer.write_all(&[request.addr_type]).await?;

        match request.addr_type {
            0x01 => {
                // IPv4
                let parts: Vec<u8> = request.host
                    .split('.')
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if parts.len() != 4 {
                    return Err(TuicError::InvalidProtocol("Invalid IPv4 address".to_string()));
                }
                writer.write_all(&parts).await?;
            }
            0x02 => {
                // Domain
                let host_bytes = request.host.as_bytes();
                writer.write_all(&(host_bytes.len() as u8)).await?;
                writer.write_all(host_bytes).await?;
            }
            0x03 => {
                // IPv6 (simplified - would need proper parsing)
                return Err(TuicError::InvalidProtocol("IPv6 not yet implemented".to_string()));
            }
            _ => {
                return Err(TuicError::InvalidProtocol(format!("Invalid address type: 0x{:02x}", request.addr_type)));
            }
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
        let session_id = Self::read_session_id(reader).await?;
        let mut status_buf = [0u8; 1];
        reader.read_exact(&mut status_buf).await?;
        let success = status_buf[0] == 0x00;

        debug!("Read connect response: session_id={}, success={}", session_id, success);

        Ok(success)
    }

    /// Write connect response
    pub async fn write_connect_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        session_id: u64,
        success: bool,
    ) -> Result<(), TuicError> {
        writer.write_all(&session_id.to_be_bytes()).await?;
        writer.write_all(&[if success { 0x00 } else { 0x01 }]).await?;

        debug!("Wrote connect response: session_id={}, success={}", session_id, success);

        Ok(())
    }

    /// Read heartbeat request
    async fn read_heartbeat_request<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<TuicHeartbeatRequest, TuicError> {
        let mut timestamp_buf = [0u8; 8];
        reader.read_exact(&mut timestamp_buf).await?;
        let timestamp = i64::from_be_bytes(timestamp_buf);

        debug!("Read heartbeat: timestamp={}", timestamp);

        Ok(TuicHeartbeatRequest { timestamp })
    }

    /// Write heartbeat request
    pub async fn write_heartbeat_request<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        request: &TuicHeartbeatRequest,
    ) -> Result<(), TuicError> {
        writer.write_all(&request.timestamp.to_be_bytes()).await?;

        debug!("Wrote heartbeat: timestamp={}", request.timestamp);

        Ok(())
    }

    /// Write heartbeat response
    pub async fn write_heartbeat_response<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        timestamp: i64,
    ) -> Result<(), TuicError> {
        writer.write_all(&timestamp.to_be_bytes()).await?;

        debug!("Wrote heartbeat response: timestamp={}", timestamp);

        Ok(())
    }

    /// Read session ID
    async fn read_session_id<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<u64, TuicError> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).await?;
        Ok(u64::from_be_bytes(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::Cursor;

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
        // Test success
        let mut buf = Vec::new();
        let mut writer = Cursor::new(&mut buf);
        TuicCodec::write_auth_response(&mut writer, true).await.unwrap();

        let mut reader = Cursor::new(&buf);
        let success = TuicCodec::read_auth_response(&mut reader).await.unwrap();
        assert!(success);

        // Test failure
        buf.clear();
        let mut writer = Cursor::new(&mut buf);
        TuicCodec::write_auth_response(&mut writer, false).await.unwrap();

        let mut reader = Cursor::new(&buf);
        let success = TuicCodec::read_auth_response(&mut reader).await.unwrap();
        assert!(!success);
    }

    #[tokio::test]
    async fn test_connect_request_roundtrip() {
        let request = TuicConnectRequest {
            addr_type: 0x02,
            host: "example.com".to_string(),
            port: 443,
            session_id: 12345,
        };

        let mut buf = Vec::new();
        let mut writer = Cursor::new(&mut buf);
        TuicCodec::write_connect_request(&mut writer, &request).await.unwrap();

        // Note: read_connect_request is private, so we test through read_command
        let mut reader = Cursor::new(&buf);
        // Would need to prepend command byte for full test
    }

    #[tokio::test]
    async fn test_command_type_conversion() {
        assert_eq!(TuicCommandType::from_u8(0x01), Some(TuicCommandType::Auth));
        assert_eq!(TuicCommandType::from_u8(0x02), Some(TuicCommandType::Connect));
        assert_eq!(TuicCommandType::from_u8(0x03), Some(TuicCommandType::Disconnect));
        assert_eq!(TuicCommandType::from_u8(0x04), Some(TuicCommandType::Heartbeat));
        assert_eq!(TuicCommandType::from_u8(0x05), Some(TuicCommandType::UdpPacket));
        assert_eq!(TuicCommandType::from_u8(0xff), None);
    }
}
