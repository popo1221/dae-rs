//! Trojan handler implementation
//!
//! This module contains the TrojanHandler which implements the client-side
//! Trojan protocol, including multi-backend support for failover.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info};

use super::config::{TrojanClientConfig, TrojanServerConfig};
use super::consts::*;
use super::protocol::{TrojanCommand, TrojanTargetAddress, TROJAN_CRLF};
use crate::protocol::relay::relay_bidirectional;
use crate::protocol::unified_handler::Handler;
use crate::protocol::ProtocolType;

/// Trojan handler that implements the client-side protocol
pub struct TrojanHandler {
    config: TrojanClientConfig,
    /// Multiple backends for failover
    backends: Vec<TrojanServerConfig>,
    /// Current backend index for round-robin
    current_index: std::sync::atomic::AtomicUsize,
}

impl TrojanHandler {
    /// Create a new Trojan handler with single backend
    pub fn new(config: TrojanClientConfig) -> Self {
        Self {
            backends: vec![config.server.clone()],
            current_index: std::sync::atomic::AtomicUsize::new(0),
            config,
        }
    }

    /// Create a new Trojan handler with multiple backends
    pub fn with_backends(config: TrojanClientConfig, backends: Vec<TrojanServerConfig>) -> Self {
        Self {
            backends: if backends.is_empty() {
                vec![config.server.clone()]
            } else {
                backends
            },
            current_index: std::sync::atomic::AtomicUsize::new(0),
            config,
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self {
            config: TrojanClientConfig::default(),
            backends: vec![TrojanServerConfig::default()],
            current_index: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Get the next backend using round-robin
    fn next_backend(&self) -> &TrojanServerConfig {
        let idx = self
            .current_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.backends.len();
        &self.backends[idx]
    }

    /// Get all backends
    pub fn get_backends(&self) -> &[TrojanServerConfig] {
        &self.backends
    }

    /// Get the number of configured backends
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Get the listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Validate password using constant-time comparison to prevent timing attacks
    pub fn validate_password(&self, password: &str) -> bool {
        // Use constant-time comparison to prevent timing attacks
        let expected = self.config.server.password.as_bytes();
        let input = password.as_bytes();
        expected.ct_eq(input).unwrap_u8() == 1
    }

    /// Handle a Trojan TCP connection
    pub async fn handle(self: Arc<Self>, mut client: TcpStream) -> std::io::Result<()> {
        let client_addr = client.peer_addr()?;

        // Trojan protocol:
        // After TLS handshake, client sends:
        // [password (56 bytes)][0x0D, 0x0A]  <- CRLF
        // [command (1 byte)][address type (1 byte)][address][port (2 bytes)][0x0D, 0x0A]

        // Read password (56 bytes)
        let mut password_buf = vec![0u8; 56];
        client.read_exact(&mut password_buf).await?;

        // Read CRLF (2 bytes)
        let mut crlf_buf = [0u8; 2];
        client.read_exact(&mut crlf_buf).await?;
        if crlf_buf != TROJAN_CRLF {
            error!("Invalid Trojan header: missing CRLF after password");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Trojan header",
            ));
        }

        // Read command and address
        let mut cmd_buf = [0u8; 1];
        client.read_exact(&mut cmd_buf).await?;
        let command = cmd_buf[0];

        let cmd = match command {
            0x01 => TrojanCommand::Proxy,
            0x02 => TrojanCommand::UdpAssociate,
            _ => {
                error!("Unknown Trojan command: {}", command);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown Trojan command",
                ));
            }
        };

        debug!("Trojan TCP: {} command={:?}", client_addr, cmd);

        // Read address header (common for both Proxy and UdpAssociate)
        // Read address type
        let mut atyp_buf = [0u8; 1];
        client.read_exact(&mut atyp_buf).await?;
        let atyp = atyp_buf[0];

        // Read address based on type
        let address = match atyp {
            0x01 => {
                // IPv4 (4 bytes)
                let mut ip_buf = [0u8; 4];
                client.read_exact(&mut ip_buf).await?;
                TrojanTargetAddress::Ipv4(IpAddr::V4(Ipv4Addr::new(
                    ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3],
                )))
            }
            0x02 => {
                // Domain (1 byte length + domain)
                let mut len_buf = [0u8; 1];
                client.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; domain_len];
                client.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8(domain_buf).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid domain in Trojan header",
                    )
                })?;
                TrojanTargetAddress::Domain(domain, 0) // Port will be read next
            }
            0x03 => {
                // IPv6 (16 bytes)
                let mut ip_buf = [0u8; 16];
                client.read_exact(&mut ip_buf).await?;
                TrojanTargetAddress::Ipv6(IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([ip_buf[0], ip_buf[1]]),
                    u16::from_be_bytes([ip_buf[2], ip_buf[3]]),
                    u16::from_be_bytes([ip_buf[4], ip_buf[5]]),
                    u16::from_be_bytes([ip_buf[6], ip_buf[7]]),
                    u16::from_be_bytes([ip_buf[8], ip_buf[9]]),
                    u16::from_be_bytes([ip_buf[10], ip_buf[11]]),
                    u16::from_be_bytes([ip_buf[12], ip_buf[13]]),
                    u16::from_be_bytes([ip_buf[14], ip_buf[15]]),
                )))
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid address type in Trojan header",
                ));
            }
        };

        // Read port (2 bytes)
        let mut port_buf = [0u8; 2];
        client.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        // Read final CRLF (2 bytes)
        let mut crlf_buf = [0u8; 2];
        client.read_exact(&mut crlf_buf).await?;
        if crlf_buf != TROJAN_CRLF {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Trojan header: missing CRLF after address",
            ));
        }

        match cmd {
            TrojanCommand::Proxy => {
                let address_str = match &address {
                    TrojanTargetAddress::Domain(d, _) => format!("{d}:{port}"),
                    _ => format!("{address}:{port}"),
                };

                // Select backend using round-robin
                let backend = self.next_backend();
                let remote_addr = format!("{}:{}", backend.addr, backend.port);
                let timeout = self.config.tcp_timeout;

                info!(
                    "Trojan TCP: {} -> {} (via {}:{}, {} backends available)",
                    client_addr,
                    address_str,
                    backend.addr,
                    backend.port,
                    self.backend_count()
                );

                // Connect to the selected backend
                let remote =
                    match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            error!(
                                "Failed to connect to Trojan backend {}:{}: {}",
                                backend.addr, backend.port, e
                            );
                            return Err(e);
                        }
                        Err(_) => {
                            error!(
                                "Timeout connecting to Trojan backend {}:{}",
                                backend.addr, backend.port
                            );
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "connection to Trojan server timed out",
                            ));
                        }
                    };

                debug!("Connected to Trojan server {}", remote_addr);

                // Relay data between client and remote
                self.relay(client, remote).await
            }
            TrojanCommand::UdpAssociate => {
                // Trojan UDP Associate - UDP packets are encapsulated in Trojan UDP frames
                // Frame format: [cmd(1)][uuid(16)][ver(1)][port(2)][atyp(1)][addr][payload]
                // After initial header is parsed (above), UDP frames are exchanged over TCP

                let address_str = match &address {
                    TrojanTargetAddress::Domain(d, _) => format!("{d}:{port}"),
                    _ => format!("{address}:{port}"),
                };

                info!(
                    "Trojan UDP Associate: {} -> {} ({} backends available)",
                    client_addr,
                    address_str,
                    self.backend_count()
                );

                // Select backend using round-robin
                let backend = self.next_backend();
                let backend_addr = format!("{}:{}", backend.addr, backend.port);

                // Connect UDP socket to the Trojan backend server
                let remote_udp = match tokio::time::timeout(
                    self.config.udp_timeout,
                    UdpSocket::bind("0.0.0.0:0"),
                )
                .await
                {
                    Ok(Ok(socket)) => socket,
                    Ok(Err(e)) => {
                        error!("Failed to bind UDP socket: {}", e);
                        return Err(e);
                    }
                    Err(_) => {
                        error!("Timeout binding UDP socket");
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP socket bind timed out",
                        ));
                    }
                };

                if let Err(e) = remote_udp.connect(&backend_addr).await {
                    error!("Failed to connect UDP to backend {}: {}", backend_addr, e);
                    return Err(e);
                }

                debug!("Connected UDP socket to backend {}", backend_addr);

                // Relay UDP packets between client (TCP) and remote (UDP)
                self.relay_udp_over_tcp(client, remote_udp, &address_str)
                    .await?;

                Ok(())
            }
        }
    }

    /// Relay data between client and remote
    async fn relay(&self, client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
        relay_bidirectional(client, remote).await
    }

    /// Relay UDP packets between client (TCP stream) and remote (UDP socket)
    ///
    /// Trojan UDP frame format over TCP:
    /// [cmd (1)][uuid (16)][ver (1)][target port (2)][addr type (1)][target addr (variable)][payload (variable)]
    ///
    /// Commands: 0x01 = UDP data, 0x02 = DISCONNECT, 0x03 = PING
    async fn relay_udp_over_tcp(
        &self,
        mut client: TcpStream,
        remote_udp: UdpSocket,
        target_info: &str,
    ) -> std::io::Result<()> {
        let max_frame_size = MAX_UDP_FRAME_SIZE;
        let remote_addr = target_info.to_string();

        info!("Starting Trojan UDP relay: {} via UDP socket", remote_addr);

        // For Trojan UDP over TCP, we need to:
        // 1. Read UDP frames from client TCP stream
        // 2. Extract payload and forward to remote UDP socket
        // 3. Read responses from UDP socket and send back via TCP

        loop {
            // Read UDP frame header from TCP
            // Minimum header: cmd(1) + uuid(16) + ver(1) + port(2) + atyp(1) = 21 bytes
            let mut header_buf = [0u8; TROJAN_UDP_HEADER_SIZE];
            match tokio::time::timeout(self.config.udp_timeout, client.read_exact(&mut header_buf))
                .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!("TCP read finished: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("TCP read timeout");
                    break;
                }
            };

            let cmd = header_buf[0];
            // uuid is at header_buf[1..17] (16 bytes)
            let ver = header_buf[17];
            let target_port = u16::from_be_bytes([header_buf[18], header_buf[19]]);
            let atyp = header_buf[20];

            // Validate version
            if ver != TROJAN_UDP_VERSION {
                debug!("Unknown Trojan UDP version: {}", ver);
                continue;
            }

            match cmd {
                TROJAN_UDP_CMD_DATA => {
                    // UDP data - read target address and payload
                    let target_addr = match atyp {
                        0x01 => {
                            // IPv4 - 4 bytes
                            let mut ip_buf = [0u8; 4];
                            client.read_exact(&mut ip_buf).await?;
                            IpAddr::V4(Ipv4Addr::new(ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]))
                                .to_string()
                        }
                        0x02 => {
                            // Domain - 1 byte length + domain
                            let mut len_buf = [0u8; 1];
                            client.read_exact(&mut len_buf).await?;
                            let domain_len = len_buf[0] as usize;
                            let mut domain_buf = vec![0u8; domain_len];
                            client.read_exact(&mut domain_buf).await?;
                            String::from_utf8(domain_buf).map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "invalid domain in Trojan UDP header",
                                )
                            })?
                        }
                        0x03 => {
                            // IPv6 - 16 bytes
                            let mut ip_buf = [0u8; 16];
                            client.read_exact(&mut ip_buf).await?;
                            IpAddr::V6(Ipv6Addr::new(
                                u16::from_be_bytes([ip_buf[0], ip_buf[1]]),
                                u16::from_be_bytes([ip_buf[2], ip_buf[3]]),
                                u16::from_be_bytes([ip_buf[4], ip_buf[5]]),
                                u16::from_be_bytes([ip_buf[6], ip_buf[7]]),
                                u16::from_be_bytes([ip_buf[8], ip_buf[9]]),
                                u16::from_be_bytes([ip_buf[10], ip_buf[11]]),
                                u16::from_be_bytes([ip_buf[12], ip_buf[13]]),
                                u16::from_be_bytes([ip_buf[14], ip_buf[15]]),
                            ))
                            .to_string()
                        }
                        _ => {
                            debug!("Unknown address type in Trojan UDP: {}", atyp);
                            continue;
                        }
                    };

                    let target = format!("{}:{}", target_addr, target_port);

                    // Read remaining UDP data (payload)
                    // We need to read until EOF or timeout
                    let mut payload_buf = vec![0u8; MAX_UDP_FRAME_SIZE];
                    let mut total_read = 0;

                    // Try to read as much as available (non-blocking-ish)
                    loop {
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(100),
                            client.read(&mut payload_buf[total_read..]),
                        )
                        .await
                        {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => {
                                total_read += n;
                                if total_read >= max_frame_size {
                                    break;
                                }
                            }
                            Ok(Err(e)) => {
                                debug!("Error reading UDP payload: {}", e);
                                break;
                            }
                            Err(_) => break,
                        }
                    }

                    if total_read == 0 {
                        continue;
                    }

                    debug!(
                        "Trojan UDP: forwarding {} bytes to {} (target: {})",
                        total_read, remote_addr, target
                    );

                    // Forward payload to remote Trojan server via UDP
                    match remote_udp.send(&payload_buf[..total_read]).await {
                        Ok(n) => debug!("Sent {} bytes to UDP server", n),
                        Err(e) => {
                            debug!("Failed to send to UDP server: {}", e);
                        }
                    }

                    // Read response from UDP server
                    let mut response_buf = vec![0u8; MAX_UDP_FRAME_SIZE];
                    match tokio::time::timeout(
                        self.config.udp_timeout,
                        remote_udp.recv(&mut response_buf),
                    )
                    .await
                    {
                        Ok(Ok(m)) if m > 0 => {
                            // Build response frame and send back to client via TCP
                            // Response frame: [cmd][uuid(16)][ver][port(2)][atyp(1)][addr][payload]
                            let mut response_frame = Vec::with_capacity(TROJAN_UDP_HEADER_SIZE + m);
                            response_frame.push(TROJAN_UDP_CMD_DATA); // cmd = UDP
                            response_frame.extend_from_slice(&header_buf[1..17]); // uuid
                            response_frame.push(TROJAN_UDP_VERSION); // ver
                            response_frame.extend_from_slice(&header_buf[18..20]); // port
                            response_frame.push(atyp); // address type

                            // Add target address back
                            match atyp {
                                0x01 => {
                                    // IPv4 - read the 4 bytes we stored earlier
                                    let ip = target_addr.parse::<IpAddr>().unwrap();
                                    if let IpAddr::V4(v4) = ip {
                                        response_frame.extend_from_slice(&v4.octets());
                                    }
                                }
                                0x02 => {
                                    // Domain
                                    let domain = &target_addr;
                                    response_frame.push(domain.len() as u8);
                                    response_frame.extend_from_slice(domain.as_bytes());
                                }
                                0x03 => {
                                    // IPv6
                                    let ip = target_addr.parse::<IpAddr>().unwrap();
                                    if let IpAddr::V6(v6) = ip {
                                        let octets = v6.octets();
                                        response_frame.extend_from_slice(&octets);
                                    }
                                }
                                _ => {}
                            }

                            response_frame.extend_from_slice(&response_buf[..m]);

                            if let Err(e) = client.write_all(&response_frame).await {
                                debug!("Failed to send UDP response to client: {}", e);
                            }
                        }
                        _ => {
                            // Timeout or error - send PING to keepalive
                            debug!("No UDP response, sending PING");
                            let mut ping_frame = Vec::new();
                            ping_frame.push(TROJAN_UDP_CMD_PING); // cmd = PING
                            ping_frame.extend_from_slice(&header_buf[1..17]); // uuid
                            ping_frame.push(TROJAN_UDP_VERSION); // ver
                            ping_frame.extend_from_slice(&header_buf[18..20]); // port
                            ping_frame.push(atyp);

                            if let Err(e) = client.write_all(&ping_frame).await {
                                debug!("Failed to send PING: {}", e);
                                break;
                            }
                        }
                    }
                }
                TROJAN_UDP_CMD_DISCONNECT => {
                    // DISCONNECT
                    debug!("Trojan UDP: DISCONNECT received");
                    break;
                }
                TROJAN_UDP_CMD_PING => {
                    // PING - client is checking if we're alive
                    debug!("Trojan UDP: PING received");
                    // Send back PONG
                    let mut pong_frame = Vec::new();
                    pong_frame.push(TROJAN_UDP_CMD_PING); // cmd = PING (PONG is same as PING in Trojan)
                    pong_frame.extend_from_slice(&header_buf[1..17]); // uuid
                    pong_frame.push(TROJAN_UDP_VERSION); // ver
                    pong_frame.extend_from_slice(&header_buf[18..20]); // port
                    pong_frame.push(atyp);

                    if let Err(e) = client.write_all(&pong_frame).await {
                        debug!("Failed to send PONG: {}", e);
                        break;
                    }
                }
                _ => {
                    debug!("Unknown Trojan UDP command: {}", cmd);
                }
            }
        }

        info!("Trojan UDP relay finished for {}", remote_addr);
        Ok(())
    }


}

/// Implement Handler trait for TrojanHandler
///
/// This allows TrojanHandler to be used through the unified Handler interface.
#[async_trait]
impl Handler for TrojanHandler {
    type Config = TrojanClientConfig;

    fn name(&self) -> &'static str {
        "trojan"
    }

    fn protocol(&self) -> ProtocolType {
        ProtocolType::Trojan
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    async fn handle(self: Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        self.handle(stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::TrojanTlsConfig;
    use super::*;

    #[test]
    fn test_handler_creation() {
        let config = TrojanClientConfig::default();
        let handler = TrojanHandler::new(config);
        assert_eq!(handler.backend_count(), 1);
    }

    #[test]
    fn test_handler_with_multiple_backends() {
        let config = TrojanClientConfig::default();
        let backends = vec![
            TrojanServerConfig::default(),
            TrojanServerConfig {
                addr: "2.2.2.2".to_string(),
                ..Default::default()
            },
        ];
        let handler = TrojanHandler::with_backends(config, backends);
        assert_eq!(handler.backend_count(), 2);
    }

    #[test]
    fn test_next_backend_round_robin() {
        let config = TrojanClientConfig::default();
        let backends = vec![
            TrojanServerConfig {
                addr: "1.1.1.1".to_string(),
                ..Default::default()
            },
            TrojanServerConfig {
                addr: "2.2.2.2".to_string(),
                ..Default::default()
            },
        ];
        let handler = TrojanHandler::with_backends(config, backends);

        // First call should return first backend
        // (due to fetch_add, the index is incremented first)
        let backend1 = handler.next_backend();
        let backend2 = handler.next_backend();

        // Both should be different
        assert_ne!(backend1.addr, backend2.addr);
    }

    #[test]
    fn test_trojan_client_config_default() {
        let config = TrojanClientConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 1080)));
    }

    #[test]
    fn test_trojan_server_config_default() {
        let config = TrojanServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 443);
    }

    #[test]
    fn test_trojan_server_config_custom() {
        let config = TrojanServerConfig {
            addr: "192.168.1.1".to_string(),
            port: 8443,
            password: "my_secret".to_string(),
            tls: TrojanTlsConfig::default(),
        };
        assert_eq!(config.addr, "192.168.1.1");
        assert_eq!(config.port, 8443);
        assert_eq!(config.password, "my_secret");
        assert!(config.tls.enabled);
    }
}
