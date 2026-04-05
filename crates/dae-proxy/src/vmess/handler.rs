//! VMess handler implementation
//!
//! Implements the client-side VMess handler with AEAD-2022 cryptographic operations.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use super::config::{VmessClientConfig, VmessTargetAddress};
use crate::protocol::unified_handler::Handler;
use crate::protocol::ProtocolType;

/// VMess handler that implements the client-side protocol
pub struct VmessHandler {
    config: VmessClientConfig,
}

impl VmessHandler {
    /// Create a new VMess handler
    pub fn new(config: VmessClientConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: VmessClientConfig::default(),
        }
    }

    /// Get the listen address
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Get current timestamp (seconds since epoch)
    #[allow(dead_code)]
    pub fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Compute HMAC-SHA256
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mac = HmacSha256::new_from_slice(key).expect("HMAC can take any key size");
        let result = mac.chain_update(data).finalize();
        result.into_bytes().into()
    }

    /// Derive VMess AEAD-2022 session key from user ID
    ///
    /// user_key = HMAC-SHA256(user_id, "VMess AEAD")
    pub fn derive_user_key(user_id: &str) -> [u8; 32] {
        let key = Self::hmac_sha256(user_id.as_bytes(), b"VMess AEAD");
        key
    }

    /// Derive request encryption key and IV for VMess AEAD-2022
    ///
    /// request_auth_key = HMAC-SHA256(user_key, nonce)
    /// request_key = HKDF-Expand(request_auth_key, "VMess header", 32)
    /// request_iv = HMAC-SHA256(request_auth_key, nonce) [first 12 bytes]
    pub fn derive_request_key_iv(user_key: &[u8; 32], nonce: &[u8]) -> ([u8; 32], [u8; 12]) {
        // request_auth_key = HMAC-SHA256(user_key, nonce)
        let auth_result = Self::hmac_sha256(user_key, nonce);

        // request_key = HKDF-Expand-SHA256(auth_key, "VMess header", 32 bytes)
        // Per HKDF spec: HKDF-Expand(key, info, L) = HMAC-Hash(key, info || 0x01) || ...
        // We do one iteration which gives 32 bytes (HmacSha256 output size)
        let mut request_key = [0u8; 32];
        {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mac = HmacSha256::new_from_slice(&auth_result).expect("HMAC can take any key size");
            // info || 0x01
            let mut info_with_tweak = [0u8; 13];
            info_with_tweak[..12].copy_from_slice(b"VMess header");
            info_with_tweak[12] = 0x01;
            let result = mac.chain_update(info_with_tweak).finalize();
            request_key.copy_from_slice(&result.into_bytes()[..32]);
        }

        // request_iv = HMAC-SHA256(auth_key, nonce) [first 12 bytes]
        let iv_result = Self::hmac_sha256(&auth_result, nonce);
        let mut request_iv = [0u8; 12];
        request_iv.copy_from_slice(&iv_result[..12]);

        (request_key, request_iv)
    }

    /// Decrypt VMess AEAD-2022 header
    ///
    /// Format: [16-byte nonce][encrypted data][16-byte auth tag]
    /// Returns the decrypted header data on success.
    pub fn decrypt_header(user_key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, &'static str> {
        use aes_gcm::aead::KeyInit;

        if encrypted.len() < 32 {
            return Err("encrypted header too short (< 32 bytes)");
        }

        let nonce = &encrypted[..16];
        let ciphertext_with_tag = &encrypted[16..];

        let (request_key, _) = Self::derive_request_key_iv(user_key, nonce);

        let cipher = Aes256Gcm::new_from_slice(&request_key)
            .map_err(|_| "failed to create AES-GCM cipher")?;

        // Use first 12 bytes of the 16-byte nonce for AES-GCM
        let nonce_bytes: [u8; 12] = match nonce[..12].try_into() {
            Ok(n) => n,
            Err(_) => return Err("nonce is not 16 bytes"),
        };
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|_| "AES-GCM decryption failed (auth tag mismatch or corrupt data)")
    }

    /// Handle a VMess TCP connection
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // VMess AEAD-2022 header format:
        // [4 bytes length (big-endian)][16-byte nonce][encrypted data][16-byte auth tag]

        // Read length prefix (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await?;
        let header_len = u32::from_be_bytes(len_buf) as usize;

        if header_len > 65535 {
            warn!(
                "VMess TCP: {} header_len {} too large",
                client_addr, header_len
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VMess header too large",
            ));
        }

        // Read encrypted header
        let mut encrypted_header = vec![0u8; header_len];
        client.read_exact(&mut encrypted_header).await?;

        debug!("VMess TCP: {} header_len={}", client_addr, header_len);

        // Derive user key from user_id
        let user_key = Self::derive_user_key(&self.config.server.user_id);

        // Decrypt the VMess AEAD header
        let decrypted_header = match Self::decrypt_header(&user_key, &encrypted_header) {
            Ok(header) => header,
            Err(e) => {
                warn!(
                    "VMess TCP: {} header decryption failed: {} — dropping connection",
                    client_addr, e
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("VMess header decryption failed: {}", e),
                ));
            }
        };

        // Parse the decrypted VMess header:
        // [version(1)][option(1)][port(2)][addr_type(1)][addr(var)][timestamp(4)][random(4)][checksum(4)]
        let (target_addr, target_port) =
            match VmessTargetAddress::parse_from_bytes(&decrypted_header) {
                Some((addr, port)) => (addr, port),
                None => {
                    // ⚠️ Fallback heuristic: some VMess implementations may have non-standard
                    // header formatting. We search for an address type marker
                    // (0x01=IPv4, 0x02=domain, 0x03=IPv6) in the decrypted data.
                    //
                    // WARNING: This heuristic is FRAGILE because random bytes in the header
                    // could accidentally match address type markers, masking real bugs:
                    // - Wrong decryption key would produce garbage that might coincidentally
                    //   contain valid-looking address type bytes
                    // - Protocol version mismatches might produce false positives
                    //
                    // The warn! log below indicates potential issues that should be investigated.
                    // Operators should monitor for this warning - if it appears frequently
                    // with different clients, it may indicate a configuration problem.
                    warn!(
                        "VMess TCP: {} standard header parsing failed, using fallback heuristic. \
                    First 16 bytes (hex): {:?}",
                        client_addr,
                        decrypted_header
                            .iter()
                            .take(16)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                    );

                    // Find first occurrence of address type marker in the entire decrypted header
                    if let Some(pos) = decrypted_header
                        .iter()
                        .position(|&b| matches!(b, 0x01..=0x03))
                    {
                        debug!(
                            "VMess TCP: {} found address type marker 0x{:02x} at pos {}, \
                        trying fallback parse",
                            client_addr, decrypted_header[pos], pos
                        );

                        if let Some(result) =
                            VmessTargetAddress::parse_from_bytes(&decrypted_header[pos..])
                        {
                            debug!(
                                "VMess TCP: {} fallback parsing succeeded at pos {}",
                                client_addr, pos
                            );
                            (result.0, result.1)
                        } else {
                            error!(
                                "VMess TCP: {} fallback parsing at pos {} also failed. \
                            Header may be corrupted or encryption key mismatch.",
                                client_addr, pos
                            );
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid VMess decrypted header",
                            ));
                        }
                    } else {
                        error!(
                            "VMess TCP: {} no valid address type (0x01/0x02/0x03) found in \
                        decrypted header ({} bytes). Check encryption key configuration.",
                            client_addr,
                            decrypted_header.len()
                        );
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "no address in VMess header",
                        ));
                    }
                }
            };

        info!(
            "VMess TCP: {} -> {}:{} (via {}:{})",
            client_addr, target_addr, target_port, self.config.server.addr, self.config.server.port
        );

        // Connect to upstream VMess server
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection to VMess server timed out",
                ));
            }
        };

        debug!("Connected to VMess server {}", remote_addr);

        // Relay data between client and remote
        self.relay(client, remote).await
    }

    /// Relay data between client and remote
    async fn relay(&self, client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut rr, mut rw) = tokio::io::split(remote);

        let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
        let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

        tokio::try_join!(client_to_remote, remote_to_client)?;
        Ok(())
    }

    /// Handle UDP traffic
    #[allow(dead_code)]
    pub async fn handle_udp(self: Arc<Self>, client: UdpSocket) -> std::io::Result<()> {
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        loop {
            let (n, client_addr) = client.recv_from(&mut buf).await?;

            if n < 5 {
                continue;
            }

            // Parse VMess UDP header
            let (target_addr, target_port, payload_offset) =
                match VmessTargetAddress::parse_from_bytes(&buf) {
                    Some((addr, port)) => (addr, port, 0),
                    None => continue,
                };

            let payload = &buf[payload_offset..n];

            debug!(
                "VMess UDP: {} -> {}:{} ({} bytes)",
                client_addr,
                target_addr,
                target_port,
                payload.len()
            );

            // Forward to VMess server and back
            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
            let server_socket = UdpSocket::bind("0.0.0.0:0").await?;
            server_socket.send_to(payload, &server_addr).await?;

            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            if let Ok(Ok((m, _))) = tokio::time::timeout(
                self.config.udp_timeout,
                server_socket.recv_from(&mut response_buf),
            )
            .await
            {
                client.send_to(&response_buf[..m], &client_addr).await?;
            }
        }
    }
}

/// Implement Handler trait for VmessHandler
///
/// This allows VmessHandler to be used through the unified Handler interface.
#[async_trait]
impl Handler for VmessHandler {
    type Config = VmessClientConfig;

    fn name(&self) -> &'static str {
        "vmess"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Vmess
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        self.handle(stream).await
    }
}
