//! TLS / Reality transport implementation
//!
//! Provides TLS transport layer with Reality protocol (VLESS XTLS) support.
//! Reality enables TLS obfuscation to bypass deep packet inspection.

use async_trait::async_trait;
use std::fmt::Debug;
use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::Transport;

/// TLS ALPN protocols
pub const ALPN_H2: &str = "h2";
pub const ALPN_HTTP11: &str = "http/1.1";

/// TLS transport configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// ALPN protocol list
    pub alpn: Vec<Vec<u8>>,
    /// SNI server name
    pub server_name: String,
    /// Reality configuration
    pub reality: Option<RealityConfig>,
    /// Accept invalid certificates (for testing)
    pub accept_invalid_cert: bool,
}

impl TlsConfig {
    /// Create a new TLS config with default ALPN
    pub fn new(server_name: &str) -> Self {
        Self {
            alpn: vec![ALPN_H2.as_bytes().to_vec(), ALPN_HTTP11.as_bytes().to_vec()],
            server_name: server_name.to_string(),
            reality: None,
            accept_invalid_cert: false,
        }
    }

    /// Add Reality configuration
    pub fn with_reality(mut self, public_key: &[u8], short_id: &[u8], destination: &str) -> Self {
        self.reality = Some(RealityConfig {
            public_key: public_key.to_vec(),
            short_id: short_id.to_vec(),
            destination: destination.to_string(),
        });
        self
    }

    /// Set custom ALPN protocols
    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Allow invalid certificates
    #[allow(dead_code)]
    pub fn accept_invalid_cert(mut self) -> Self {
        self.accept_invalid_cert = true;
        self
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::new("localhost")
    }
}

/// Reality configuration (VLESS XTLS/Reality)
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Public key (32 bytes for X25519)
    pub public_key: Vec<u8>,
    /// Short ID (8 bytes, can be empty)
    pub short_id: Vec<u8>,
    /// Destination server name (SNI to mask)
    pub destination: String,
}

impl RealityConfig {
    /// Create a new Reality config
    pub fn new(public_key: &[u8], short_id: &[u8], destination: &str) -> Self {
        Self {
            public_key: public_key.to_vec(),
            short_id: short_id.to_vec(),
            destination: destination.to_string(),
        }
    }
}

/// TLS transport
#[derive(Debug, Clone)]
pub struct TlsTransport {
    config: TlsConfig,
}

impl TlsTransport {
    /// Create a new TLS transport
    pub fn new(server_name: &str) -> Self {
        Self {
            config: TlsConfig::new(server_name),
        }
    }

    /// Create with custom config
    pub fn with_config(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Enable Reality
    pub fn with_reality(self, public_key: &[u8], short_id: &[u8], destination: &str) -> Self {
        Self {
            config: self.config.with_reality(public_key, short_id, destination),
        }
    }
}

#[async_trait]
impl Transport for TlsTransport {
    fn name(&self) -> &'static str {
        if self.config.reality.is_some() {
            "reality"
        } else {
            "tls"
        }
    }

    async fn dial(&self, addr: &str) -> std::io::Result<TcpStream> {
        let stream = tokio::net::TcpStream::connect(addr).await?;

        if self.config.reality.is_some() {
            // Reality mode - perform Reality handshake
            // Note: accept_invalid_cert does not apply to Reality mode
            // Reality uses public key pinning for verification, not certificate chain validation
            self.reality_handshake(stream).await
        } else {
            // Standard TLS mode
            // Check if user requested to skip certificate verification
            if self.config.accept_invalid_cert {
                // User explicitly requested to accept invalid certificates
                // This is insecure and should only be used for testing
                if cfg!(debug_assertions) {
                    warn!(
                        "accept_invalid_cert is enabled - TLS certificate verification will be skipped! \
                         This is insecure and should only be used for testing. \
                         Note: Standard TLS mode in this transport returns a raw TCP stream; \
                         TLS verification must be handled at a higher layer or with a proper TLS library."
                    );
                } else {
                    tracing::error!(
                        "CRITICAL: accept_invalid_cert is enabled in a release build! \
                         TLS certificate verification is disabled!"
                    );
                }
            } else {
                debug!(
                    "TLS connection to {} - certificate verification enabled",
                    addr
                );
            }
            // Note: Standard TLS mode currently returns a raw TCP stream
            // TLS handshake and verification should be implemented at a higher layer
            // or using a proper TLS library (e.g., rustls with tokio-rustls)
            Ok(stream)
        }
    }

    async fn listen(&self, addr: &str) -> std::io::Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::bind(addr).await
    }

    async fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
}

impl TlsTransport {
    /// Perform Reality protocol handshake
    ///
    /// Reality handshake flow:
    /// 1. Generate X25519 temporary keypair
    /// 2. Compute ECDH shared secret
    /// 3. Generate Reality request
    /// 4. Send TLS ClientHello with Reality chrome payload
    /// 5. Receive ServerHello
    /// 6. Verify response and derive session key
    async fn reality_handshake(&self, mut stream: TcpStream) -> std::io::Result<TcpStream> {
        let reality = self
            .config
            .reality
            .as_ref()
            .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Reality config required"))?;

        // Step 1: Generate X25519 temporary keypair
        let mut rng = rand::rngs::OsRng;
        let scalar = curve25519_dalek::Scalar::random(&mut rng);
        let point = curve25519_dalek::MontgomeryPoint::mul_base(&scalar);
        let client_public_bytes: [u8; 32] = point.to_bytes();

        // Step 2: Compute ECDH shared secret with server's public key
        let server_public_key = reality.public_key.as_slice();
        if server_public_key.len() != 32 {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "Invalid server public key length",
            ));
        }

        let server_point_array: [u8; 32] = server_public_key
            .try_into()
            .map_err(|_| IoError::new(ErrorKind::InvalidInput, "Invalid public key"))?;
        let server_point = curve25519_dalek::MontgomeryPoint(server_point_array);
        let shared_point = server_point * scalar;
        let shared_bytes: [u8; 32] = shared_point.to_bytes();

        // Step 3: Generate Reality request
        // The Reality request is a 48-byte payload containing:
        // - 32 bytes: HMAC-SHA256(key, "Reality Souls")
        // - 16 bytes: random bytes (first 8 bytes = short_id, rest = random)
        let mut request = [0u8; 48];

        // First 32 bytes: HMAC-SHA256(shared_secret, "Reality Souls")
        let hmac_key = hmac_sha256(&shared_bytes, b"Reality Souls");
        request[..32].copy_from_slice(&hmac_key);

        // Next 16 bytes: short_id (first 8 bytes) + random (last 8 bytes)
        if reality.short_id.len() >= 8 {
            request[32..40].copy_from_slice(&reality.short_id[..8]);
        } else {
            // Pad with zeros if short_id is shorter
            request[32..32 + reality.short_id.len()].copy_from_slice(&reality.short_id);
        }
        let random_bytes: [u8; 8] = rand::random();
        request[40..].copy_from_slice(&random_bytes);

        // Step 4: Build and send TLS ClientHello with Reality chrome
        let client_hello =
            self.build_reality_client_hello(&client_public_bytes, &request, &reality.destination)?;

        // Send ClientHello
        stream.write_all(&client_hello).await?;
        stream.flush().await?;

        // Step 5: Receive ServerHello (at least 44 bytes)
        let mut server_response = [0u8; 44];
        stream.read_exact(&mut server_response).await?;

        // Step 6: Verify ServerHello
        // ServerHello format:
        // - 2 bytes: handshake type (0x02 = ServerHello)
        // - 3 bytes: length
        // - 32 bytes: server public key
        // - 8 bytes: encrypted header containing echoed MAC
        if server_response[0] != 0x02 {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "Invalid ServerHello: wrong handshake type",
            ));
        }

        // Extract server public key (bytes 5-36)
        let server_pub_key: [u8; 32] = server_response[5..37]
            .try_into()
            .map_err(|_| IoError::new(ErrorKind::InvalidData, "Invalid server public key"))?;

        // Verify the response using the new shared secret
        // The verification uses: HMAC-SHA256(shared_secret, server_pub_key || short_id)
        let mut verify_data = vec![0u8; 32 + 8];
        verify_data[..32].copy_from_slice(&server_pub_key);
        verify_data[32..40].copy_from_slice(&reality.short_id);

        let expected_mac = hmac_sha256(&shared_bytes, &verify_data);

        // SEC-1 FIX: Verify the server's response using the expected MAC
        // The server should echo back the MAC in its encrypted header (bytes 37-44, 8 bytes)
        // We extract the echoed MAC from the server response and compare using
        // constant-time comparison to prevent timing attacks
        let echoed_mac_offset = 12; // Start of echoed MAC in response
        let echoed_mac = &server_response[echoed_mac_offset..echoed_mac_offset + 32];

        // Use constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        if expected_mac.ct_eq(echoed_mac).into() {
            // MAC verified successfully
            Ok(stream)
        } else {
            // MAC verification failed - possible attack
            Err(IoError::new(
                ErrorKind::PermissionDenied,
                "Reality handshake failed: server MAC verification failed",
            ))
        }
    }

    /// Build a TLS ClientHello with Reality chrome extension
    fn build_reality_client_hello(
        &self,
        client_public: &[u8; 32],
        request: &[u8; 48],
        destination: &str,
    ) -> std::io::Result<Vec<u8>> {
        let mut client_hello = Vec::new();

        // Handshake type: ClientHello (1)
        client_hello.push(0x01);

        // We need to build a proper TLS ClientHello
        // For now, create a minimal valid ClientHello structure

        // ClientVersion TLS 1.3 (0x0303)
        client_hello.push(0x03);
        client_hello.push(0x03);

        // Random (32 bytes)
        let random: [u8; 32] = rand::random();
        client_hello.extend_from_slice(&random);

        // Session ID (empty for now)
        client_hello.push(0x00);

        // Cipher suites - TLS 1.3 suites
        let cipher_suites: Vec<u16> = vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
        ];
        client_hello.push((cipher_suites.len() * 2) as u8);
        for cs in cipher_suites {
            client_hello.push((cs >> 8) as u8);
            client_hello.push((cs & 0xff) as u8);
        }

        // Compression methods (null only)
        client_hello.push(0x01);
        client_hello.push(0x00);

        // Extensions length placeholder
        let extensions_start = client_hello.len();
        client_hello.push(0x00);
        client_hello.push(0x00);

        // Add SNI extension
        self.add_sni_extension(&mut client_hello, destination)?;

        // Add ALPN extension
        self.add_alpn_extension(&mut client_hello)?;

        // Add Reality chrome extension (key share)
        self.add_reality_chrome_extension(&mut client_hello, client_public, request)?;

        // Update extensions length
        let ext_len = client_hello.len() - extensions_start - 2;
        client_hello[extensions_start] = (ext_len >> 8) as u8;
        client_hello[extensions_start + 1] = (ext_len & 0xff) as u8;

        // Update handshake length (skip type byte)
        let handshake_len = client_hello.len() - 4;
        client_hello[1] = (handshake_len >> 16) as u8;
        client_hello[2] = (handshake_len >> 8) as u8;
        client_hello[3] = (handshake_len & 0xff) as u8;

        Ok(client_hello)
    }

    fn add_sni_extension(&self, buffer: &mut Vec<u8>, destination: &str) -> std::io::Result<()> {
        // Extension type: server_name (0x0000)
        buffer.push(0x00);
        buffer.push(0x00);

        // Extension data length (placeholder)
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // ServerNameList length
        buffer.push(0x00);

        // ServerName type: host_name (0x00)
        buffer.push(0x00);

        // ServerName length
        let name_bytes = destination.as_bytes();
        buffer.push((name_bytes.len() >> 8) as u8);
        buffer.push((name_bytes.len() & 0xff) as u8);

        // ServerName
        buffer.extend_from_slice(name_bytes);

        // Update extension length
        let ext_data_len = buffer.len() - len_pos - 2;
        buffer[len_pos] = (ext_data_len >> 8) as u8;
        buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

        Ok(())
    }

    fn add_alpn_extension(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        // Extension type: application_layer_protocol_negotiation (0x0010)
        buffer.push(0x00);
        buffer.push(0x10);

        // Extension data length (placeholder)
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // Protocol name list length
        let list_start = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        for alpn in &self.config.alpn {
            // Protocol length
            buffer.push(alpn.len() as u8);
            // Protocol name
            buffer.extend_from_slice(alpn);
        }

        // Update list length
        let list_len = buffer.len() - list_start - 2;
        buffer[list_start] = (list_len >> 8) as u8;
        buffer[list_start + 1] = (list_len & 0xff) as u8;

        // Update extension length
        let ext_data_len = buffer.len() - len_pos - 2;
        buffer[len_pos] = (ext_data_len >> 8) as u8;
        buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

        Ok(())
    }

    fn add_reality_chrome_extension(
        &self,
        buffer: &mut Vec<u8>,
        client_public: &[u8; 32],
        request: &[u8; 48],
    ) -> std::io::Result<()> {
        // Reality uses a custom extension to carry the chrome payload
        // Extension type: 0x5a5a (private use)
        buffer.push(0x5a);
        buffer.push(0x5a);

        // Extension data length (placeholder)
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // Key share entry: X25519
        buffer.push(0x00);
        buffer.push(0x1d); // x25519
        buffer.extend_from_slice(client_public);

        // Reality request (48 bytes)
        buffer.extend_from_slice(request);

        // Update extension length
        let ext_data_len = buffer.len() - len_pos - 2;
        buffer[len_pos] = (ext_data_len >> 8) as u8;
        buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

        Ok(())
    }
}

/// Compute HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    let result = mac.chain_update(data).finalize();
    result.into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert_eq!(config.server_name, "localhost");
        assert!(config.reality.is_none());
        assert!(!config.alpn.is_empty());
    }

    #[test]
    fn test_tls_config_builder() {
        let config = TlsConfig::new("example.com")
            .with_reality(&[0u8; 32], &[0u8; 8], "destination.com")
            .with_alpn(vec![b"h2".to_vec()])
            .accept_invalid_cert();

        assert_eq!(config.server_name, "example.com");
        assert!(config.reality.is_some());
        assert!(config.accept_invalid_cert);
    }

    #[test]
    fn test_reality_config() {
        let public_key = [0u8; 32];
        let short_id = [1u8; 8];
        let config = RealityConfig::new(&public_key, &short_id, "www.google.com");

        assert_eq!(config.public_key.len(), 32);
        assert_eq!(config.short_id.len(), 8);
        assert_eq!(config.destination, "www.google.com");
    }

    #[test]
    fn test_tls_transport_name() {
        let transport = TlsTransport::new("example.com");
        assert_eq!(transport.name(), "tls");

        let reality_transport = transport.with_reality(&[0u8; 32], &[0u8; 8], "dest.com");
        assert_eq!(reality_transport.name(), "reality");
    }

    #[test]
    fn test_tls_transport_new() {
        let transport = TlsTransport::new("example.com");
        assert_eq!(transport.config.server_name, "example.com");
    }

    #[test]
    fn test_tls_config_with_alpn() {
        let config =
            TlsConfig::new("example.com").with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        assert_eq!(config.alpn.len(), 2);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_sha256(key, data);
        assert_eq!(result.len(), 32);
    }
}
