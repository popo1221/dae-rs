//! VLESS handler implementation
//!
//! Implements the VLESS protocol handler.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info};

use crate::protocol::unified_handler::Handler;
use crate::protocol::ProtocolType;
use crate::vless::config::VlessClientConfig;
use crate::vless::crypto::hmac_sha256;
use crate::vless::protocol::VlessTargetAddress;
use crate::vless::protocol::{
    VlessAddressType, VlessCommand, VLESS_HEADER_MIN_SIZE, VLESS_VERSION,
};
use crate::vless::relay::relay_data;

/// VLESS handler that implements the Handler trait
pub struct VlessHandler {
    config: VlessClientConfig,
}

impl VlessHandler {
    /// Create a new VLESS handler
    pub fn new(config: VlessClientConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        Self {
            config: VlessClientConfig::default(),
        }
    }

    /// Get the listen address
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Validate UUID
    pub fn validate_uuid(uuid: &[u8]) -> bool {
        // UUID must be 16 bytes (128 bits)
        uuid.len() == 16
    }

    /// Handle a VLESS connection (implements Handler trait)
    pub async fn handle_vless(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // Read VLESS header
        let mut header_buf = vec![0u8; VLESS_HEADER_MIN_SIZE];
        client.read_exact(&mut header_buf).await?;

        // Validate version
        if header_buf[0] != VLESS_VERSION {
            error!("Invalid VLESS version: {}", header_buf[0]);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VLESS version",
            ));
        }

        // Extract UUID (bytes 1-16)
        let uuid = &header_buf[1..17];
        if !Self::validate_uuid(uuid) {
            error!("Invalid UUID length");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid UUID",
            ));
        }

        // Verify UUID matches config
        let expected_uuid = self.config.server.uuid.as_bytes();
        if expected_uuid.len() == 16 && uuid != expected_uuid {
            error!("UUID mismatch");
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid UUID",
            ));
        }

        // Extract command (byte 18)
        let command = header_buf[18];
        let cmd = VlessCommand::from_u8(command).ok_or_else(|| {
            error!("Unknown VLESS command: {}", command);
            std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown VLESS command")
        })?;

        debug!("VLESS TCP: {} command={:?}", client_addr, cmd);

        match cmd {
            VlessCommand::Tcp => self.handle_tcp(client, &header_buf).await,
            VlessCommand::Udp => {
                // VLESS UDP should use the dedicated UDP port, not TCP channel.
                // The client should send UDP packets directly to the UDP listener.
                error!("VLESS UDP: UDP traffic should go through the UDP port, not TCP");
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP traffic should use the UDP port",
                ))
            }
            VlessCommand::XtlsVision => {
                // Reality Vision mode
                self.handle_reality_vision(client, &header_buf).await
            }
        }
    }

    /// Handle VLESS TCP connection
    async fn handle_tcp(
        self: &Arc<Self>,
        mut client: TcpStream,
        _header_buf: &[u8],
    ) -> std::io::Result<()> {
        // Read additional header: port(4) + atyp(1) + addr + iv(16)
        let mut addl_buf = vec![0u8; 64];
        client.read_exact(&mut addl_buf).await?;

        // Parse address
        let address = self.parse_target_address(&addl_buf)?;
        let _port = match &address {
            VlessTargetAddress::Domain(_, p) => *p,
            _ => u16::from_be_bytes([addl_buf[5], addl_buf[6]]),
        };

        info!(
            "VLESS TCP: -> {} (via {}:{})",
            address, self.config.server.addr, self.config.server.port
        );

        // Connect to VLESS server
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let timeout = self.config.tcp_timeout;

        let remote = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection to VLESS server timed out",
                ));
            }
        };

        debug!("Connected to VLESS server {}", remote_addr);

        // Relay data between client and remote
        relay_data(client, remote).await
    }

    /// Handle VLESS UDP packets directly
    ///
    /// This method handles UDP packets that contain VLESS headers.
    /// Each UDP packet has the following format:
    /// - v1 (1 byte): version, 0x01
    /// - uuid (16 bytes): user UUID
    /// - ver (1 byte): protocol version, 0x01
    /// - cmd (1 byte): command, 0x02 for UDP
    /// - port (4 bytes): target port (big-endian)
    /// - atyp (1 byte): address type (0x01=IPv4, 0x02=domain, 0x03=IPv6)
    /// - addr (variable): target address
    /// - iv (16 bytes): initial vector for encryption
    /// - payload: encrypted data
    ///
    /// This is the entry point when VLESS server listens on a UDP port
    /// and receives VLESS UDP packets directly from clients.
    pub async fn handle_udp(self: Arc<Self>, client: Arc<UdpSocket>) -> std::io::Result<()> {
        const MAX_UDP_SIZE: usize = 65535;
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        let local_addr = client.local_addr().unwrap_or_else(|e| {
            debug!("VLESS UDP: failed to get local addr: {}", e);
            SocketAddr::from(([0, 0, 0, 0], 0))
        });
        info!(
            "VLESS UDP: listening on {} (via {}:{})",
            local_addr, self.config.server.addr, self.config.server.port
        );

        loop {
            let (n, client_addr) = client.recv_from(&mut buf).await?;

            // Minimum header size: v1(1) + uuid(16) + ver(1) + cmd(1) + port(4) + atyp(1) + iv(16) = 40
            const MIN_HEADER_SIZE: usize = 40;

            if n < MIN_HEADER_SIZE {
                debug!(
                    "VLESS UDP: packet too small from {}: {} bytes",
                    client_addr, n
                );
                continue;
            }

            // Parse VLESS UDP header
            let v1 = buf[0];
            if v1 != VLESS_VERSION {
                debug!("VLESS UDP: invalid version {} from {}", v1, client_addr);
                continue;
            }

            // Extract UUID (bytes 1-16)
            let uuid = &buf[1..17];
            if !Self::validate_uuid(uuid) {
                debug!("VLESS UDP: invalid UUID from {}", client_addr);
                continue;
            }

            // Verify UUID matches config
            let expected_uuid = self.config.server.uuid.as_bytes();
            if expected_uuid.len() == 16 && uuid != expected_uuid {
                debug!("VLESS UDP: UUID mismatch from {}", client_addr);
                continue;
            }

            // Verify protocol version (byte 17)
            let ver = buf[17];
            if ver != VLESS_VERSION {
                debug!(
                    "VLESS UDP: invalid protocol version {} from {}",
                    ver, client_addr
                );
                continue;
            }

            // Verify command (byte 18) is UDP
            let cmd = buf[18];
            if cmd != VlessCommand::Udp as u8 {
                debug!("VLESS UDP: invalid command {} from {}", cmd, client_addr);
                continue;
            }

            // Extract port (bytes 19-22, big-endian)
            let port = u16::from_be_bytes([buf[19], buf[20]]);

            // Extract address type (byte 21)
            let atyp = buf[21];

            // Parse target address based on address type
            // Address starts at byte 22
            let addr_start = 22;
            let (target_addr, addr_len) = match VlessAddressType::from_u8(atyp) {
                Some(VlessAddressType::Ipv4) => {
                    // IPv4: 4 bytes
                    if n < addr_start + 4 + 2 {
                        debug!("VLESS UDP: buffer too small for IPv4 from {}", client_addr);
                        continue;
                    }
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        buf[addr_start],
                        buf[addr_start + 1],
                        buf[addr_start + 2],
                        buf[addr_start + 3],
                    ));
                    (ip, 4)
                }
                Some(VlessAddressType::Domain) => {
                    // Domain: 1 byte length + domain name
                    if n < addr_start + 1 + 2 {
                        debug!(
                            "VLESS UDP: buffer too small for domain length from {}",
                            client_addr
                        );
                        continue;
                    }
                    let domain_len = buf[addr_start] as usize;
                    if n < addr_start + 1 + domain_len + 2 {
                        debug!(
                            "VLESS UDP: buffer too small for domain from {}",
                            client_addr
                        );
                        continue;
                    }
                    let _domain = String::from_utf8(
                        buf[addr_start + 1..addr_start + 1 + domain_len].to_vec(),
                    )
                    .unwrap_or_else(|_| "invalid".to_string());
                    (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1 + domain_len) // Placeholder, will resolve later
                }
                Some(VlessAddressType::Ipv6) => {
                    // IPv6: 16 bytes
                    if n < addr_start + 16 + 2 {
                        debug!("VLESS UDP: buffer too small for IPv6 from {}", client_addr);
                        continue;
                    }
                    let ip = IpAddr::V6(Ipv6Addr::new(
                        u16::from_be_bytes([buf[addr_start], buf[addr_start + 1]]),
                        u16::from_be_bytes([buf[addr_start + 2], buf[addr_start + 3]]),
                        u16::from_be_bytes([buf[addr_start + 4], buf[addr_start + 5]]),
                        u16::from_be_bytes([buf[addr_start + 6], buf[addr_start + 7]]),
                        u16::from_be_bytes([buf[addr_start + 8], buf[addr_start + 9]]),
                        u16::from_be_bytes([buf[addr_start + 10], buf[addr_start + 11]]),
                        u16::from_be_bytes([buf[addr_start + 12], buf[addr_start + 13]]),
                        u16::from_be_bytes([buf[addr_start + 14], buf[addr_start + 15]]),
                    ));
                    (ip, 16)
                }
                None => {
                    debug!(
                        "VLESS UDP: invalid address type {} from {}",
                        atyp, client_addr
                    );
                    continue;
                }
            };

            // IV is after address (16 bytes)
            let iv_start = addr_start + addr_len;
            if n < iv_start + 16 {
                debug!("VLESS UDP: buffer too small for IV from {}", client_addr);
                continue;
            }
            let iv = &buf[iv_start..iv_start + 16];

            // Payload starts after IV
            let payload_start = iv_start + 16;
            if n <= payload_start {
                debug!("VLESS UDP: no payload from {}", client_addr);
                continue;
            }
            let payload = &buf[payload_start..n];

            debug!(
                "VLESS UDP: {} -> {}:{} ({} bytes, iv: {:?})",
                client_addr,
                target_addr,
                port,
                payload.len(),
                &iv[..8]
            );

            // Create a UDP session to forward the packet
            // We need to:
            // 1. Connect to the VLESS server
            // 2. Send the packet with proper VLESS header
            // 3. Receive response and send back to client

            let server_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);

            // Create server UDP socket
            let server_socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    debug!("VLESS UDP: failed to bind server socket: {}", e);
                    continue;
                }
            };

            // Build the VLESS header for server communication
            // The header format for server->server communication:
            // v1(1) + uuid(16) + ver(1) + cmd(1) + port(4) + atyp(1) + addr + iv(16) + payload
            let mut server_packet = Vec::with_capacity(n);
            server_packet.push(VLESS_VERSION); // v1
            server_packet.extend_from_slice(uuid); // uuid
            server_packet.push(VLESS_VERSION); // ver
            server_packet.push(VlessCommand::Udp as u8); // cmd
            server_packet.extend_from_slice(&port.to_be_bytes()); // port

            // For domain, we need to resolve it or use it as-is
            match VlessAddressType::from_u8(atyp) {
                Some(VlessAddressType::Ipv4) => {
                    server_packet.push(atyp);
                    if let IpAddr::V4(ipv4) = target_addr {
                        server_packet.extend_from_slice(&ipv4.octets());
                    }
                }
                Some(VlessAddressType::Ipv6) => {
                    server_packet.push(atyp);
                    if let IpAddr::V6(ipv6) = target_addr {
                        for segment in ipv6.segments() {
                            server_packet.extend_from_slice(&segment.to_be_bytes());
                        }
                    }
                }
                Some(VlessAddressType::Domain) => {
                    // For domain, we include the raw domain in the packet
                    let domain_len = buf[addr_start] as usize;
                    server_packet.push(atyp);
                    server_packet.extend_from_slice(&buf[addr_start..addr_start + 1 + domain_len]);
                }
                None => continue,
            }

            server_packet.extend_from_slice(iv); // iv
            server_packet.extend_from_slice(payload); // payload

            // Send to server
            if let Err(e) = server_socket.send_to(&server_packet, &server_addr).await {
                debug!("VLESS UDP: failed to send to server: {}", e);
                continue;
            }

            // Receive response from server
            let mut response_buf = vec![0u8; MAX_UDP_SIZE];
            match tokio::time::timeout(
                self.config.udp_timeout,
                server_socket.recv_from(&mut response_buf),
            )
            .await
            {
                Ok(Ok((m, _))) => {
                    // Forward response back to client
                    if let Err(e) = client.send_to(&response_buf[..m], &client_addr).await {
                        debug!("VLESS UDP: failed to send response to client: {}", e);
                    }
                }
                Ok(Err(e)) => {
                    debug!("VLESS UDP: server recv error: {}", e);
                }
                Err(_) => {
                    debug!("VLESS UDP: server response timed out");
                }
            }
        }
    }

    /// Handle VLESS Reality Vision connection
    ///
    /// Reality Vision uses XTLS which is a special TLS obfuscation protocol.
    /// The client:
    /// 1. Generates X25519 keypair
    /// 2. Computes shared secret with server's public key
    /// 3. Builds a special TLS ClientHello with Reality chrome
    /// 4. Server responds with encrypted header containing the real destination
    async fn handle_reality_vision(
        self: &Arc<Self>,
        client: TcpStream,
        _header_buf: &[u8],
    ) -> std::io::Result<()> {
        let reality_config = self.config.server.reality.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Reality config required for XTLS Vision",
            )
        })?;

        // Step 1: Generate X25519 temporary keypair
        let mut rng = rand::rngs::OsRng;
        let scalar = curve25519_dalek::Scalar::random(&mut rng);
        let point = curve25519_dalek::MontgomeryPoint::mul_base(&scalar);
        let client_public: [u8; 32] = point.to_bytes();

        // Step 2: Compute ECDH shared secret with server's public key
        let server_public_key = &reality_config.public_key;
        if server_public_key.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid server public key length",
            ));
        }

        let server_point_array: [u8; 32] = server_public_key
            .as_slice()
            .try_into()
            .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "Invalid public key"))?;
        let server_point = curve25519_dalek::MontgomeryPoint(server_point_array);
        let shared_point = server_point * scalar;
        let shared_secret: [u8; 32] = shared_point.to_bytes();

        // Step 3: Generate Reality request
        // The Reality request is a 48-byte payload containing:
        // - 32 bytes: HMAC-SHA256(key, "Reality Souls")
        // - 16 bytes: short_id (first 8 bytes) + random (last 8 bytes)
        let mut request = [0u8; 48];

        // First 32 bytes: HMAC-SHA256(shared_secret, "Reality Souls")
        let hmac_key = hmac_sha256(&shared_secret, b"Reality Souls");
        request[..32].copy_from_slice(&hmac_key);

        // Next 16 bytes: short_id (first 8 bytes) + random (last 8 bytes)
        if reality_config.short_id.len() >= 8 {
            request[32..40].copy_from_slice(&reality_config.short_id[..8]);
        }
        let random_bytes: [u8; 8] = rand::random();
        request[40..].copy_from_slice(&random_bytes);

        // Step 4: Build TLS ClientHello with Reality chrome
        let destination = &reality_config.destination;
        let client_hello =
            self.build_reality_client_hello(&client_public, &request, destination)?;

        // Step 5: Connect to server and send ClientHello
        let remote_addr = format!("{}:{}", self.config.server.addr, self.config.server.port);
        let mut remote =
            tokio::time::timeout(self.config.tcp_timeout, TcpStream::connect(&remote_addr))
                .await??;

        // Send ClientHello
        remote.write_all(&client_hello).await?;
        remote.flush().await?;

        debug!("Sent Reality ClientHello to {}", remote_addr);

        // Step 6: Receive ServerHello
        let mut server_response = vec![0u8; 8192];
        let n = tokio::time::timeout(self.config.tcp_timeout, remote.read(&mut server_response))
            .await??;

        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "server closed connection",
            ));
        }

        debug!("Received {} bytes from server", n);

        // For Reality Vision, after the TLS handshake, we need to:
        // 1. Parse the server's response to get the real destination
        // 2. Forward traffic bidirectionally

        // For now, just relay between client and server
        // A full implementation would parse the server's response to get
        // the real destination address from the server's ServerHello
        relay_data(client, remote).await
    }

    /// Build a TLS ClientHello with Reality chrome extension
    fn build_reality_client_hello(
        &self,
        client_public: &[u8; 32],
        request: &[u8; 48],
        destination: &str,
    ) -> std::io::Result<Vec<u8>> {
        let mut client_hello = Vec::new();

        // TLS Record Layer: Handshake (0x16)
        client_hello.push(0x16);

        // TLS Version TLS 1.3 (0x0303)
        client_hello.push(0x03);
        client_hello.push(0x03);

        // Handshake payload placeholder
        let payload_start = client_hello.len();
        client_hello.push(0x00); // length placeholder
        client_hello.push(0x00);
        client_hello.push(0x00);

        // Handshake type: ClientHello (0x01)
        client_hello.push(0x01);

        // Handshake length (placeholder, will update later)
        let handshake_len_pos = client_hello.len();
        client_hello.push(0x00);
        client_hello.push(0x00);
        client_hello.push(0x00);

        // ClientVersion TLS 1.3 (0x0303)
        client_hello.push(0x03);
        client_hello.push(0x03);

        // Random (32 bytes)
        let random: [u8; 32] = rand::random();
        client_hello.extend_from_slice(&random);

        // Session ID (empty)
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

        // Add SNI extension (server_name)
        self.add_sni_extension(&mut client_hello, destination)?;

        // Add ALPN extension
        self.add_alpn_extension(&mut client_hello)?;

        // Add supported_versions extension (TLS 1.3)
        self.add_supported_versions_extension(&mut client_hello)?;

        // Add psk_key_exchange_modes extension
        self.add_psk_modes_extension(&mut client_hello)?;

        // Add key_share extension with Reality chrome
        self.add_reality_key_share(&mut client_hello, client_public, request)?;

        // Update extensions length
        let ext_len = client_hello.len() - extensions_start - 2;
        client_hello[extensions_start] = (ext_len >> 8) as u8;
        client_hello[extensions_start + 1] = (ext_len & 0xff) as u8;

        // Update handshake length
        let handshake_len = client_hello.len() - handshake_len_pos - 3;
        client_hello[handshake_len_pos] = (handshake_len >> 16) as u8;
        client_hello[handshake_len_pos + 1] = (handshake_len >> 8) as u8;
        client_hello[handshake_len_pos + 2] = (handshake_len & 0xff) as u8;

        // Update record layer length
        let record_len = client_hello.len() - payload_start - 3 + 4; // +4 for record header
        client_hello[payload_start] = (record_len >> 8) as u8;
        client_hello[payload_start + 1] = (record_len & 0xff) as u8;
        client_hello[payload_start + 2] = (record_len & 0xff) as u8;

        Ok(client_hello)
    }

    fn add_sni_extension(&self, buffer: &mut Vec<u8>, destination: &str) -> std::io::Result<()> {
        // Extension type: server_name (0x0000)
        buffer.push(0x00);
        buffer.push(0x00);

        // Extension data length
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

        // Extension data length
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // Protocol name list length
        let list_start = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        let alpn_list = ["h2", "http/1.1"];
        for alpn in &alpn_list {
            buffer.push(alpn.len() as u8);
            buffer.extend_from_slice(alpn.as_bytes());
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

    fn add_supported_versions_extension(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        // Extension type: supported_versions (0x002b)
        buffer.push(0x00);
        buffer.push(0x2b);

        // Extension data length
        buffer.push(0x02);

        // Client: supported version TLS 1.3
        buffer.push(0x03);
        buffer.push(0x03);

        Ok(())
    }

    fn add_psk_modes_extension(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        // Extension type: psk_key_exchange_modes (0x002d)
        buffer.push(0x00);
        buffer.push(0x2d);

        // Extension data length
        buffer.push(0x02);

        // PSK modes: psk_dhe_ke (0x01)
        buffer.push(0x01);
        buffer.push(0x01);

        Ok(())
    }

    fn add_reality_key_share(
        &self,
        buffer: &mut Vec<u8>,
        client_public: &[u8; 32],
        _request: &[u8; 48],
    ) -> std::io::Result<()> {
        // Extension type: key_share (0x0033)
        buffer.push(0x00);
        buffer.push(0x33);

        // Extension data length (placeholder)
        let len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // Key share entry length
        let entry_len_pos = buffer.len();
        buffer.push(0x00);
        buffer.push(0x00);

        // Key share entry:
        // - 2 bytes: named group (x25519 = 0x001d)
        buffer.push(0x00);
        buffer.push(0x1d);

        // - 1 byte: key exchange length (32 bytes)
        buffer.push(0x20);

        // - 32 bytes: key exchange value (client public)
        buffer.extend_from_slice(client_public);

        // Update key share entry length
        let entry_len = buffer.len() - entry_len_pos - 2;
        buffer[entry_len_pos] = (entry_len >> 8) as u8;
        buffer[entry_len_pos + 1] = (entry_len & 0xff) as u8;

        // Update extension length
        let ext_data_len = buffer.len() - len_pos - 2;
        buffer[len_pos] = (ext_data_len >> 8) as u8;
        buffer[len_pos + 1] = (ext_data_len & 0xff) as u8;

        // Add secondary key share for Reality request
        // This is the "chrome" payload that contains the VLESS request
        //
        // Reality uses a special format:
        // - First extension: key_share with X25519 public key
        // - The "chrome" is encoded in a subsequent handshake message or
        //   as part of the key derivation
        //
        // For VLESS Reality Vision, the request (48 bytes) is sent
        // as the first bytes after the key exchange
        //
        // Note: The actual Reality implementation may encode the request
        // differently. This is a simplified implementation.

        Ok(())
    }

    /// Parse target address from VLESS header
    fn parse_target_address(&self, buf: &[u8]) -> std::io::Result<VlessTargetAddress> {
        // Validate minimum buffer size before accessing any indices
        if buf.len() < 5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "buffer too small for VLESS address parsing (need at least 5 bytes)",
            ));
        }
        let atyp = buf[4];
        match VlessAddressType::from_u8(atyp) {
            Some(VlessAddressType::Ipv4) => {
                if buf.len() < 10 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for IPv4",
                    ));
                }
                let ip = IpAddr::V4(Ipv4Addr::new(buf[5], buf[6], buf[7], buf[8]));
                let _port = u16::from_be_bytes([buf[9], buf[10]]);
                Ok(VlessTargetAddress::Ipv4(ip))
            }
            Some(VlessAddressType::Domain) => {
                if buf.len() < 6 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for domain",
                    ));
                }
                let domain_len = buf[5] as usize;
                // Reject empty domains (domain_len == 0) for security
                // Empty domains could indicate malformed packets or injection attempts
                if domain_len == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "empty domain not allowed",
                    ));
                }
                if buf.len() < 6 + domain_len + 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for domain content",
                    ));
                }
                let domain = String::from_utf8(buf[6..6 + domain_len].to_vec()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain")
                })?;
                let port = u16::from_be_bytes([buf[6 + domain_len], buf[6 + domain_len + 1]]);
                Ok(VlessTargetAddress::Domain(domain, port))
            }
            Some(VlessAddressType::Ipv6) => {
                if buf.len() < 22 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer too small for IPv6",
                    ));
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([buf[5], buf[6]]),
                    u16::from_be_bytes([buf[7], buf[8]]),
                    u16::from_be_bytes([buf[9], buf[10]]),
                    u16::from_be_bytes([buf[11], buf[12]]),
                    u16::from_be_bytes([buf[13], buf[14]]),
                    u16::from_be_bytes([buf[15], buf[16]]),
                    u16::from_be_bytes([buf[17], buf[18]]),
                    u16::from_be_bytes([buf[19], buf[20]]),
                ));
                let _port = u16::from_be_bytes([buf[21], buf[22]]);
                Ok(VlessTargetAddress::Ipv6(ip))
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid address type",
            )),
        }
    }
}

/// Implement Handler trait for VlessHandler
///
/// This allows VlessHandler to be used through the unified Handler interface.
#[async_trait]
impl Handler for VlessHandler {
    type Config = VlessClientConfig;

    fn name(&self) -> &'static str {
        "vless"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Vless
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        self.handle_vless(stream).await
    }
}
