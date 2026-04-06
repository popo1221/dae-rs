//! Juicity 协议编解码器模块
//!
//! 实现了 Juicity 协议的二进制格式编码/解码功能。

use crate::types::{JuicityAddress, JuicityCommand, JuicityFrame};

/// Juicity codec for encoding/decoding frames
pub struct JuicityCodec;

impl JuicityCodec {
    /// Encode a frame to bytes
    pub fn encode(frame: &JuicityFrame) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);

        // Command (1 byte)
        buf.push(frame.command.to_byte());

        // Connection ID (4 bytes, little-endian)
        buf.extend_from_slice(&frame.connection_id.to_le_bytes());

        // Session ID (4 bytes, little-endian)
        buf.extend_from_slice(&frame.session_id.to_le_bytes());

        // Sequence (4 bytes, little-endian)
        buf.extend_from_slice(&frame.sequence.to_le_bytes());

        // Address (if present)
        if let Some(ref addr) = frame.address {
            buf.extend_from_slice(&addr.to_bytes());
        }

        // Payload
        if !frame.payload.is_empty() {
            buf.extend_from_slice(&frame.payload);
        }

        buf
    }

    /// Decode a frame from bytes
    pub fn decode(buf: &[u8]) -> Option<JuicityFrame> {
        if buf.len() < 13 {
            // Minimum: 1 cmd + 4 conn_id + 4 sess_id + 4 seq = 13 bytes
            // For Open with address, we need at least 14 bytes (add 1 for address type)
            return None;
        }

        let mut pos = 0;

        // Command (1 byte)
        let command = JuicityCommand::from_byte(buf[pos])?;
        pos += 1;

        // Connection ID (4 bytes)
        let connection_id =
            u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        // Session ID (4 bytes)
        let session_id = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        // Sequence (4 bytes)
        let sequence = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;

        // Address (if present, for Open command)
        let address = if command == JuicityCommand::Open && pos < buf.len() {
            let slice = &buf[pos..];
            let (addr, addr_len) = JuicityAddress::parse_from_bytes(slice)?;
            pos += addr_len;
            Some(addr)
        } else {
            None
        };

        // Payload (remaining bytes)
        let payload = if pos < buf.len() {
            buf[pos..].to_vec()
        } else {
            Vec::new()
        };

        Some(JuicityFrame {
            command,
            connection_id,
            session_id,
            sequence,
            address,
            payload,
        })
    }

    /// Encode frame header only (for Open command with large payload)
    pub fn encode_header(frame: &JuicityFrame) -> Vec<u8> {
        let mut buf = Vec::with_capacity(14);

        buf.push(frame.command.to_byte());
        buf.extend_from_slice(&frame.connection_id.to_le_bytes());
        buf.extend_from_slice(&frame.session_id.to_le_bytes());
        buf.extend_from_slice(&frame.sequence.to_le_bytes());

        if let Some(ref addr) = frame.address {
            buf.extend_from_slice(&addr.to_bytes());
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{JuicityAddress, JuicityCommand, JuicityFrame};
    use crate::JuicityCodec;

    #[test]
    fn test_frame_open_encode_decode() {
        let addr = JuicityAddress::Domain("example.com".to_string(), 443);
        let frame = JuicityFrame::new_open(0x12345678, 0xABCDEF00, addr);

        let encoded = JuicityCodec::encode(&frame);
        let decoded = JuicityCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.command, JuicityCommand::Open);
        assert_eq!(decoded.connection_id, 0x12345678);
        assert_eq!(decoded.session_id, 0xABCDEF00);
        assert!(decoded.address.is_some());
        match decoded.address.unwrap() {
            JuicityAddress::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected Domain"),
        }
    }

    #[test]
    fn test_frame_send_encode_decode() {
        let payload = b"Hello, Juicity!";
        let frame = JuicityFrame::new_send(0x12345678, 0xABCDEF00, 42, payload.to_vec());

        let encoded = JuicityCodec::encode(&frame);
        let decoded = JuicityCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.command, JuicityCommand::Send);
        assert_eq!(decoded.connection_id, 0x12345678);
        assert_eq!(decoded.session_id, 0xABCDEF00);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload, payload.to_vec());
    }

    #[test]
    fn test_frame_close_encode_decode() {
        let frame = JuicityFrame::new_close(0x12345678, 0xABCDEF00);

        let encoded = JuicityCodec::encode(&frame);
        let decoded = JuicityCodec::decode(&encoded).unwrap();

        assert_eq!(decoded.command, JuicityCommand::Close);
        assert_eq!(decoded.connection_id, 0x12345678);
        assert_eq!(decoded.session_id, 0xABCDEF00);
    }

    #[test]
    fn test_frame_ping_pong() {
        let ping = JuicityFrame::new_ping(0x12345678, 0xABCDEF00);
        let encoded = JuicityCodec::encode(&ping);
        let decoded = JuicityCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.command, JuicityCommand::Ping);

        let pong = JuicityFrame::new_pong(0x12345678, 0xABCDEF00);
        let encoded = JuicityCodec::encode(&pong);
        let decoded = JuicityCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.command, JuicityCommand::Pong);
    }
}
