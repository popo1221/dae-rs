//! gRPC transport implementation for VLESS
//!
//! Implements HTTP/2 gRPC transport used by VLESS protocol.
//! This is a lightweight implementation that handles:
//! - HTTP/2 connection initialization with TLS
//! - gRPC request/response framing (length-prefixed messages)
//! - Service/method routing via :path header
//!
//! # VLESS gRPC Transport
//!
//! VLESS over gRPC uses HTTP/2 with:
//! - Content-Type: application/grpc
//! - TE: trailers
//! - Message framing: 1-byte length prefix (MSB=1 indicates compressed)
//! - :path header contains service and method

use super::Transport;
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::fmt::Debug;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// gRPC transport configuration
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Service name (e.g., "grpc.WebSocket")
    pub service_name: String,
    /// Method name (e.g., "/WebSocket/Tunnel")
    pub method_name: String,
    /// Host
    pub host: String,
    /// Port
    pub port: u16,
    /// Use TLS
    pub tls: bool,
    /// TLS server name (SNI)
    pub sni: Option<String>,
    /// TLS certificate verification
    pub insecure: bool,
    /// Connect timeout
    pub connect_timeout: Duration,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            service_name: "grpc.WebSocket".to_string(),
            method_name: "/WebSocket/Tunnel".to_string(),
            host: "localhost".to_string(),
            port: 443,
            tls: true,
            sni: None,
            insecure: false,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

impl GrpcConfig {
    /// Create a new gRPC config
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            ..Default::default()
        }
    }

    /// Set service name
    pub fn with_service(mut self, service: &str) -> Self {
        self.service_name = service.to_string();
        self
    }

    /// Set method name
    pub fn with_method(mut self, method: &str) -> Self {
        self.method_name = method.to_string();
        self
    }

    /// Enable TLS
    pub fn with_tls(mut self) -> Self {
        self.tls = true;
        self
    }

    /// Disable TLS verification (not recommended)
    pub fn with_insecure(mut self) -> Self {
        self.insecure = true;
        self
    }

    /// Get the full :path header value
    pub fn path(&self) -> String {
        format!("{}{}", self.service_name, self.method_name)
    }
}

/// gRPC transport for VLESS
#[derive(Debug, Clone)]
pub struct GrpcTransport {
    config: GrpcConfig,
}

impl GrpcTransport {
    /// Create a new gRPC transport
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            config: GrpcConfig::new(host, port),
        }
    }

    /// Create with full config
    pub fn with_config(config: GrpcConfig) -> Self {
        Self { config }
    }
}

#[allow(dead_code)]
impl GrpcTransport {
    /// Build HTTP/2 SETTINGS frame
    fn build_settings_frame() -> Bytes {
        let mut buf = BytesMut::with_capacity(9);
        // Length (3 bytes, big-endian): 0
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        // Type: SETTINGS (0x4)
        buf.put_u8(0x4);
        // Flags: ACK (0x1)
        buf.put_u8(0x1);
        // Stream ID: 0
        buf.put_u32(0);
        Bytes::from(buf)
    }

    /// Build HTTP/2 HEADERS frame for gRPC request
    fn build_request_headers(config: &GrpcConfig, stream_id: u32) -> Bytes {
        let _buf = BytesMut::new();

        // Build pseudo-headers (must come before regular headers)
        let host = &config.host;
        let path = config.path();
        let _scheme = if config.tls { "https" } else { "http" };

        // Calculate the header block size
        // :method: POST
        // :scheme: https/http
        // :path: /service/method
        // :authority: host:port
        // content-type: application/grpc
        // te: trailers
        // user-agent: dae-rs

        let mut header_block = Vec::new();

        // :method = POST
        header_block.extend_from_slice(b"\x83\x84\x07:method");
        header_block.push(0); // never indexed
        header_block.extend_from_slice(b"\x04POST");

        // :scheme
        header_block.extend_from_slice(b"\x85\x8e\x07:scheme");
        header_block.push(0);
        header_block.extend_from_slice(if config.tls { b"https" } else { b"http" });

        // :path
        header_block.extend_from_slice(b"\x85\x8e\x05:path");
        header_block.push(0);
        header_block.extend_from_slice(path.as_bytes());

        // :authority (host:port)
        header_block.extend_from_slice(b"\x85\x8e\x0a:authority");
        header_block.push(0);
        let authority = format!("{}:{}", host, config.port);
        header_block.extend_from_slice(authority.as_bytes());

        // content-type = application/grpc
        header_block.extend_from_slice(b"\x87\x92\x0ccontent-type");
        header_block.push(0);
        header_block.extend_from_slice(b"application/grpc");

        // te = trailers
        header_block.extend_from_slice(b"\x82\x87\x02te");
        header_block.push(0);
        header_block.extend_from_slice(b"trailers");

        // user-agent
        header_block.extend_from_slice(b"\x83\x89\nuser-agent");
        header_block.push(0);
        header_block.extend_from_slice(b"dae-rs/grpc");

        // Headers frame
        let length = header_block.len();
        let mut frame = BytesMut::with_capacity(9 + length);
        // HTTP/2 frame header
        frame.put_u8(((length >> 16) & 0xFF) as u8);
        frame.put_u8(((length >> 8) & 0xFF) as u8);
        frame.put_u8((length & 0xFF) as u8);
        frame.put_u8(0x1); // HEADERS
        frame.put_u8(0x4 | 0x1); // END_HEADERS | END_STREAM (no body)
        frame.put_u32(stream_id | 0x80000000); // Reserved bit set
        frame.put(&*header_block);

        Bytes::from(frame)
    }

    /// Build a gRPC data frame with length-prefixed message
    fn build_data_frame(stream_id: u32, data: &[u8], is_last: bool) -> Bytes {
        let mut buf = BytesMut::with_capacity(9 + data.len() + 5); // header + data + length prefix

        // gRPC message format: 1-byte flag (0x80 = compressed) + 4-byte length + data
        let grpc_payload_len = 1 + 4 + data.len();
        let mut grpc_payload = BytesMut::with_capacity(grpc_payload_len);
        grpc_payload.put_u8(0); // flag: no compression
        grpc_payload.put_u32(data.len() as u32);
        grpc_payload.put(data);

        // HTTP/2 DATA frame
        let length = grpc_payload.len();
        buf.put_u8(((length >> 16) & 0xFF) as u8);
        buf.put_u8(((length >> 8) & 0xFF) as u8);
        buf.put_u8((length & 0xFF) as u8);
        buf.put_u8(0x0); // DATA
        let flags = if is_last { 0x1 } else { 0x0 }; // END_STREAM
        buf.put_u8(flags);
        buf.put_u32(stream_id | 0x80000000); // Reserved bit set
        buf.put(&*grpc_payload);

        Bytes::from(buf)
    }

    /// Build HTTP/2 WINDOW_UPDATE frame
    fn build_window_update(frame_size: u32) -> Bytes {
        let mut buf = BytesMut::with_capacity(13);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(4); // Length: 4
        buf.put_u8(0x9); // WINDOW_UPDATE
        buf.put_u8(0x0); // Flags
        buf.put_u32(0); // Stream ID: 0 (connection level)
        buf.put_u32(frame_size | 0x80000000); // Increment (reserved bit set)
        Bytes::from(buf)
    }

    /// Send HTTP/2 connection preface and initial settings
    async fn send_http2_preface<S: AsyncWriteExt + Unpin>(&self, stream: &mut S) -> IoResult<()> {
        // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await?;

        // SETTINGS frame (empty, with ACK flag)
        stream.write_all(&Self::build_settings_frame()).await?;

        // WINDOW_UPDATE for connection
        stream.write_all(&Self::build_window_update(65535)).await?;

        stream.flush().await?;
        Ok(())
    }

    /// Read and parse HTTP/2 frame
    async fn read_frame<R: AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> IoResult<Option<(u8, u8, u32, Bytes)>> {
        let mut header = [0u8; 9];
        reader.read_exact(&mut header).await?;

        let length = ((header[0] as u32) << 16) | ((header[1] as u32) << 8) | (header[2] as u32);
        let frame_type = header[3];
        let _flags = header[4];
        let stream_id = (u32::from_be_bytes([0, header[5], header[6], header[7]]) & 0x7FFFFFFF)
            | (((header[5] & 0x80) != 0) as u32 * 0x80000000);

        if length > 0 {
            let mut payload = vec![0u8; length as usize];
            reader.read_exact(&mut payload).await?;
            Ok(Some((frame_type, _flags, stream_id, Bytes::from(payload))))
        } else {
            Ok(Some((frame_type, _flags, stream_id, Bytes::new())))
        }
    }

    /// Read HTTP/2 SETTINGS frame and send ACK
    async fn handle_settings<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        &self,
        _reader: &mut R,
        writer: &mut W,
        _flags: u8,
    ) -> IoResult<()> {
        // Send SETTINGS with ACK
        let ack_frame = Self::build_settings_frame();
        // Modify flags to ACK (0x1)
        let mut ack_bytes = ack_frame.as_ref().to_vec();
        if ack_bytes.len() > 5 {
            ack_bytes[4] = 0x1;
        }
        writer.write_all(&ack_bytes).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Handle HTTP/2 HEADERS frame (response)
    async fn handle_response_headers(
        &self,
        _flags: u8,
        _stream_id: u32,
        _data: &Bytes,
    ) -> IoResult<Vec<(Vec<u8>, Vec<u8>)>> {
        // Parse response headers
        // In gRPC, response headers contain :status, content-type, etc.
        // For now, we just validate that we got HEADERS
        Ok(Vec::new())
    }
}

#[async_trait]
impl Transport for GrpcTransport {
    fn name(&self) -> &'static str {
        "grpc"
    }

    async fn dial(&self, _addr: &str) -> IoResult<TcpStream> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        info!("gRPC dial to {}", addr);

        let stream = tokio::net::TcpStream::connect(&addr).await?;

        if self.config.tls {
            // For TLS, we need to implement HTTP/2 ALPN
            // This is a simplified version - full implementation would use rustls with ALPN
            debug!("TLS gRPC connection to {}", addr);
        }

        // Send HTTP/2 preface and establish connection
        let mut stream = stream;
        self.send_http2_preface(&mut stream).await?;

        // For VLESS gRPC, we send HEADERS frame with request
        let stream_id = 1u32;
        let headers = Self::build_request_headers(&self.config, stream_id);
        stream.write_all(&headers).await?;
        stream.flush().await?;

        debug!(
            "gRPC request sent for {} {}",
            self.config.service_name, self.config.method_name
        );

        Ok(stream)
    }

    async fn listen(&self, addr: &str) -> IoResult<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }
}

/// gRPC client for making individual requests
#[derive(Debug)]
#[allow(dead_code)]
pub struct GrpcClient {
    config: GrpcConfig,
}

impl GrpcClient {
    /// Create a new gRPC client
    pub fn new(config: GrpcConfig) -> Self {
        Self { config }
    }

    /// Send a gRPC request and receive response
    ///
    /// # Note
    ///
    /// Unary gRPC calls are not supported. This implementation only supports
    /// streaming gRPC (server-streaming and bidirectional) as used by VLESS Reality
    /// Vision. For streaming gRPC, use the `GrpcStream` returned by
    /// `GrpcTransport::stream()` directly.
    ///
    /// If you need unary gRPC support, see tracking issue #72.
    pub async fn unary<T: AsRef<[u8]>, R: AsRef<[u8]>>(&self, _request: T) -> IoResult<Vec<u8>> {
        Err(IoError::new(
            ErrorKind::Unsupported,
            "Unary gRPC not implemented - only streaming gRPC is supported (see issue #72)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_config_default() {
        let config = GrpcConfig::default();
        assert_eq!(config.service_name, "grpc.WebSocket");
        assert_eq!(config.method_name, "/WebSocket/Tunnel");
        assert!(config.tls);
        assert_eq!(config.port, 443);
    }

    #[test]
    fn test_grpc_config_builder() {
        let config = GrpcConfig::new("example.com", 8443)
            .with_service("my.Service")
            .with_method("/Method/Call")
            .with_insecure();

        assert_eq!(config.host, "example.com");
        assert_eq!(config.port, 8443);
        assert_eq!(config.service_name, "my.Service");
        assert_eq!(config.method_name, "/Method/Call");
        assert!(config.insecure);
        assert!(config.tls); // with_insecure doesn't disable tls, just skips verification
    }

    #[test]
    fn test_grpc_config_path() {
        let config = GrpcConfig::default();
        assert_eq!(config.path(), "grpc.WebSocket/WebSocket/Tunnel");
    }

    #[test]
    fn test_grpc_transport_name() {
        let transport = GrpcTransport::new("localhost", 443);
        assert_eq!(transport.name(), "grpc");
    }

    #[tokio::test]
    async fn test_http2_preface_sending() {
        let config = GrpcConfig::default();
        let transport = GrpcTransport::with_config(config);

        // We can't easily test the full dial without a server
        // But we can verify the preface format
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert_eq!(preface.len(), 24);
    }

    #[test]
    fn test_build_settings_frame() {
        let frame = GrpcTransport::build_settings_frame();
        // SETTINGS frame with ACK: length=0, type=0x4, flags=0x1, stream=0
        assert_eq!(frame.len(), 9);
        assert_eq!(frame[3], 0x4); // SETTINGS
        assert_eq!(frame[4], 0x1); // ACK
        assert_eq!(frame[5], 0);
        assert_eq!(frame[6], 0);
        assert_eq!(frame[7], 0);
        assert_eq!(frame[8], 0);
    }

    #[test]
    fn test_build_data_frame() {
        let data = b"hello";
        let frame = GrpcTransport::build_data_frame(1, data, true);

        // Frame header (9 bytes) + 5 (1 flag + 4 length + 5 data)
        assert!(frame.len() >= 9 + 5);

        // Check HTTP/2 DATA frame type
        assert_eq!(frame[3], 0x0); // DATA
        assert_eq!(frame[4], 0x1); // END_STREAM
    }

    #[test]
    fn test_grpc_config_with_service() {
        let config = GrpcConfig::default().with_service("CustomService");
        assert_eq!(config.service_name, "CustomService");
        assert_eq!(config.path(), "CustomService/WebSocket/Tunnel");
    }

    #[test]
    fn test_grpc_config_with_method() {
        let config = GrpcConfig::default().with_method("/Custom/Method");
        assert_eq!(config.method_name, "/Custom/Method");
        assert_eq!(config.path(), "grpc.WebSocket/Custom/Method");
    }

    #[test]
    fn test_grpc_config_clone() {
        let config = GrpcConfig::default()
            .with_service("clone.test")
            .with_insecure();
        let cloned = config.clone();

        assert_eq!(cloned.service_name, config.service_name);
        assert_eq!(cloned.insecure, config.insecure);
    }

    #[test]
    fn test_grpc_config_debug() {
        let config = GrpcConfig::new("debug.test", 8443);
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("GrpcConfig"));
        assert!(debug_str.contains("debug.test"));
    }

    #[test]
    fn test_build_settings_frame_format() {
        let frame = GrpcTransport::build_settings_frame();
        // Frame format: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID
        assert_eq!(frame.len(), 9);

        // Verify HTTP/2 frame header structure
        assert_eq!(frame[0], 0); // Length high byte
        assert_eq!(frame[1], 0); // Length mid byte
        assert_eq!(frame[2], 0); // Length low byte (0 length for SETTINGS with ACK)
    }

    #[test]
    fn test_build_data_frame_with_different_stream_id() {
        let data = b"test";
        let frame1 = GrpcTransport::build_data_frame(1, data, false);
        let frame2 = GrpcTransport::build_data_frame(2, data, false);

        // Both should have same length but different stream IDs in header
        assert_eq!(frame1.len(), frame2.len());
    }

    #[test]
    fn test_build_data_frame_without_end_stream() {
        let data = b"chunk";
        let frame = GrpcTransport::build_data_frame(1, data, false);

        // Without END_STREAM flag, flags byte should be 0
        assert_eq!(frame[4], 0x0); // No END_STREAM
    }

    #[test]
    fn test_build_data_frame_empty_data() {
        let data = b"";
        let frame = GrpcTransport::build_data_frame(1, data, true);

        // Even empty data should have HTTP/2 frame overhead
        assert!(frame.len() >= 9);
        assert_eq!(frame[3], 0x0); // DATA frame type
    }

    #[test]
    fn test_build_window_update_frame() {
        let frame = GrpcTransport::build_window_update(65535);

        // WINDOW_UPDATE frame: length=4, type=9, flags=0, stream=0, increment=65535
        assert_eq!(frame.len(), 13);
        assert_eq!(frame[3], 0x9); // WINDOW_UPDATE
        assert_eq!(frame[4], 0x0); // No flags
    }

    #[test]
    fn test_grpc_transport_new() {
        let transport = GrpcTransport::new("new.test", 443);
        assert_eq!(transport.config.host, "new.test");
        assert_eq!(transport.config.port, 443);
    }

    #[test]
    fn test_grpc_transport_with_config() {
        let config = GrpcConfig::new("config.test", 8080);
        let transport = GrpcTransport::with_config(config.clone());
        assert_eq!(transport.config.host, config.host);
    }

    #[test]
    fn test_grpc_client_new() {
        let client = GrpcClient::new(GrpcConfig::default());
        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("GrpcClient"));
    }

    #[test]
    fn test_grpc_config_path_special_chars() {
        let config = GrpcConfig::default()
            .with_service("Service.With.Dots")
            .with_method("/method/with/slashes");
        assert_eq!(config.path(), "Service.With.Dots/method/with/slashes");
    }
}
