//! Trojan handler implementation
//!
//! This module contains the TrojanHandler which implements the client-side
//! Trojan protocol, including multi-backend support for failover.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info};

use super::config::{TrojanClientConfig, TrojanServerConfig};
use super::protocol::{TrojanCommand, TrojanTargetAddress, TROJAN_CRLF};

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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn get_backends(&self) -> &[TrojanServerConfig] {
        &self.backends
    }

    /// Get the number of configured backends
    #[allow(dead_code)]
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Get the listen address
    #[allow(dead_code)]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Validate password
    pub fn validate_password(&self, password: &str) -> bool {
        // Simple constant-time comparison would be better in production
        self.config.server.password == password
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

        match cmd {
            TrojanCommand::Proxy => {
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
                // UDP associate handling
                error!("Trojan UDP Associate not fully implemented");
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Trojan UDP Associate not implemented",
                ))
            }
        }
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

            // Parse Trojan UDP header
            let (target_addr, target_port, payload_offset) =
                match TrojanTargetAddress::parse_from_bytes(&buf) {
                    Some((addr, port)) => (addr, port, 0),
                    None => continue,
                };

            let payload = &buf[payload_offset..n];

            debug!(
                "Trojan UDP: {} -> {}:{} ({} bytes)",
                client_addr,
                target_addr,
                target_port,
                payload.len()
            );

            // Forward to Trojan server and back
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
