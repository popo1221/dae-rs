//!
//! Hysteria2 protocol handler
//!
//! This module implements the Hysteria2 proxy protocol.
//!
//! Hysteria2 Protocol Documentation:
//! - Uses QUIC (RFC 9000) as the underlying transport
//! - Authentication via password (simple shared secret)
//! - Supports obfuscation to bypass deep packet inspection
//! - Bandwidth-aware congestion control
//!
//! Protocol flow:
//! 1. Client sends Hello message with auth frame
//! 2. Server validates password
//! 3. Client and server exchange UDP datagrams
//! 4. Each datagram contains multiplexed stream data

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};


/// Hysteria2 configuration for server mode
#[derive(Debug, Clone)]
pub struct Hysteria2Config {
    /// Authentication password
    pub password: String,
    /// Server name for TLS (SNI)
    pub server_name: String,
    /// Obfuscation password (optional, for bypassing DPI)
    pub obfuscate_password: Option<String>,
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Bandwidth limit (bps), 0 = unlimited
    pub bandwidth_limit: u64,
    /// QUIC max idle timeout
    pub idle_timeout: Duration,
    /// Enable UDP
    pub udp_enabled: bool,
}

impl Default for Hysteria2Config {
    fn default() -> Self {
        Self {
            password: String::new(),
            server_name: String::new(),
            obfuscate_password: None,
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8123),
            bandwidth_limit: 0,
            idle_timeout: Duration::from_secs(30),
            udp_enabled: true,
        }
    }
}

/// Hysteria2 error types
#[derive(Debug, thiserror::Error)]
pub enum Hysteria2Error {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("QUIC error: {0}")]
    Quic(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}

/// Hysteria2 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Hysteria2FrameType {
    /// Client Hello
    ClientHello = 0x01,
    /// Server Hello
    ServerHello = 0x02,
    /// UDP packet
    UdpPacket = 0x03,
    /// Heartbeat
    Heartbeat = 0x04,
    /// Disconnect
    Disconnect = 0x05,
}

/// Hysteria2 address types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hysteria2Address {
    /// IPv4 address
    Ip(IpAddr),
    /// Domain name with port
    Domain(String, u16),
}

impl Hysteria2Address {
    /// Parse address from bytes
    pub fn parse(data: &[u8]) -> Result<(Self, usize), Hysteria2Error> {
        if data.is_empty() {
            return Err(Hysteria2Error::InvalidAddress("Empty data".to_string()));
        }
        
        let addr_type = data[0];
        match addr_type {
            0x01 => {
                // IPv4
                if data.len() < 7 {
                    return Err(Hysteria2Error::InvalidAddress("IPv4 requires 7 bytes".to_string()));
                }
                let ip = IpAddr::V4(Ipv4Addr::new(data[1], data[2], data[3], data[4]));
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((Hysteria2Address::Ip(ip), 7))
            }
            0x02 => {
                // Domain
                if data.len() < 2 {
                    return Err(Hysteria2Error::InvalidAddress("Domain requires length byte".to_string()));
                }
                let domain_len = data[1] as usize;
                if data.len() < 2 + domain_len + 2 {
                    return Err(Hysteria2Error::InvalidAddress("Domain data too short".to_string()));
                }
                let domain = String::from_utf8_lossy(&data[2..2 + domain_len]).to_string();
                let port = u16::from_be_bytes([data[2 + domain_len], data[2 + domain_len + 1]]);
                Ok((Hysteria2Address::Domain(domain, port), 2 + domain_len + 2))
            }
            0x03 => {
                // IPv6
                if data.len() < 19 {
                    return Err(Hysteria2Error::InvalidAddress("IPv6 requires 19 bytes".to_string()));
                }
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([data[1], data[2]]),
                    u16::from_be_bytes([data[3], data[4]]),
                    u16::from_be_bytes([data[5], data[6]]),
                    u16::from_be_bytes([data[7], data[8]]),
                    u16::from_be_bytes([data[9], data[10]]),
                    u16::from_be_bytes([data[11], data[12]]),
                    u16::from_be_bytes([data[13], data[14]]),
                    u16::from_be_bytes([data[15], data[16]]),
                ));
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((Hysteria2Address::Ip(ip), 19))
            }
            _ => Err(Hysteria2Error::InvalidAddress(format!("Unknown address type: {}", addr_type))),
        }
    }
    
    /// Encode address to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Hysteria2Address::Ip(IpAddr::V4(ip)) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
                // Port will be appended by caller
            }
            Hysteria2Address::Ip(IpAddr::V6(ip)) => {
                buf.push(0x03);
                for segment in ip.segments() {
                    buf.extend_from_slice(&segment.to_be_bytes());
                }
                // Port will be appended by caller
            }
            Hysteria2Address::Domain(domain, _) => {
                buf.push(0x02);
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                // Port will be appended by caller
            }
        }
        buf
    }
}

/// Hysteria2 client hello message
#[derive(Debug, Clone)]
pub struct Hysteria2ClientHello {
    /// Protocol version (2 for Hysteria2)
    pub version: u8,
    /// Auth password (UTF-8)
    pub password: String,
    /// Requested local address (optional)
    pub local_addr: Option<Hysteria2Address>,
}

/// Hysteria2 server hello message
#[derive(Debug, Clone)]
pub struct Hysteria2ServerHello {
    /// Protocol version (2 for Hysteria2)
    pub version: u8,
    /// Whether auth was successful
    pub auth_ok: bool,
    /// Server assigned session ID
    pub session_id: u64,
}

/// Hysteria2 handler for managing client connections
pub struct Hysteria2Handler {
    config: Hysteria2Config,
}

impl Hysteria2Handler {
    /// Create a new Hysteria2 handler
    pub fn new(config: Hysteria2Config) -> Self {
        Self { config }
    }
    
    /// Handle an incoming Hysteria2 client connection
    pub async fn handle(&self, mut stream: TcpStream) -> Result<(), Hysteria2Error> {
        // Read client hello
        let mut hello_buf = [0u8; 1024];
        let n = stream.read(&mut hello_buf).await?;
        if n == 0 {
            return Err(Hysteria2Error::Protocol("Connection closed during hello".to_string()));
        }
        
        // Parse client hello
        let client_hello = self.parse_client_hello(&hello_buf[..n])?;
        
        // Validate password
        if client_hello.password != self.config.password {
            return Err(Hysteria2Error::AuthFailed("Invalid password".to_string()));
        }
        
        // Send server hello
        let server_hello = Hysteria2ServerHello {
            version: 2,
            auth_ok: true,
            session_id: rand::random(),
        };
        self.send_server_hello(&mut stream, &server_hello).await?;
        
        // Handle the UDP relay
        if self.config.udp_enabled {
            self.handle_udp_relay(stream, client_hello.local_addr).await?;
        }
        
        Ok(())
    }
    
    fn parse_client_hello(&self, data: &[u8]) -> Result<Hysteria2ClientHello, Hysteria2Error> {
        if data.is_empty() {
            return Err(Hysteria2Error::Protocol("Empty hello data".to_string()));
        }
        
        let frame_type = data[0];
        if frame_type != Hysteria2FrameType::ClientHello as u8 {
            return Err(Hysteria2Error::Protocol(format!("Expected ClientHello (0x01), got 0x{:02x}", frame_type)));
        }
        
        if data.len() < 3 {
            return Err(Hysteria2Error::Protocol("ClientHello too short".to_string()));
        }
        
        let version = data[1];
        if version != 2 {
            return Err(Hysteria2Error::Protocol(format!("Unsupported Hysteria2 version: {}", version)));
        }
        
        let password_len = data[2] as usize;
        if data.len() < 3 + password_len {
            return Err(Hysteria2Error::Protocol("Password data too short".to_string()));
        }
        
        let password = String::from_utf8_lossy(&data[3..3 + password_len]).to_string();
        
        let local_addr = if data.len() > 3 + password_len {
            let (_, size) = Hysteria2Address::parse(&data[3 + password_len..])?;
            // For now, skip local_addr parsing - it requires more complex handling
            None
        } else {
            None
        };
        
        Ok(Hysteria2ClientHello {
            version,
            password,
            local_addr,
        })
    }
    
    async fn send_server_hello(&self, stream: &mut TcpStream, hello: &Hysteria2ServerHello) -> Result<(), Hysteria2Error> {
        let mut buf = Vec::new();
        buf.push(Hysteria2FrameType::ServerHello as u8);
        buf.push(hello.version);
        buf.push(if hello.auth_ok { 0x01 } else { 0x00 });
        buf.extend_from_slice(&hello.session_id.to_be_bytes());
        
        stream.write_all(&buf).await?;
        Ok(())
    }
    
    async fn handle_udp_relay(&self, _stream: TcpStream, _local_addr: Option<Hysteria2Address>) -> Result<(), Hysteria2Error> {
        // UDP relay implementation would go here
        // This involves setting up UDP hole punching and relay
        warn!("UDP relay not yet fully implemented - requires QUIC integration");
        Ok(())
    }
}

/// Hysteria2 server for accepting client connections
pub struct Hysteria2Server {
    config: Hysteria2Config,
    listener: Option<TcpListener>,
}

impl Hysteria2Server {
    /// Create a new Hysteria2 server
    pub async fn new(config: Hysteria2Config) -> Result<Self, Hysteria2Error> {
        let listener = TcpListener::bind(config.listen_addr).await?;
        info!("Hysteria2 server listening on {}", config.listen_addr);
        
        Ok(Self {
            config,
            listener: Some(listener),
        })
    }
    
    /// Start the server
    pub async fn serve(self) -> Result<(), Hysteria2Error> {
        let listener = self.listener.ok_or_else(|| {
            Hysteria2Error::Protocol("Server already started".to_string())
        })?;
        
        let handler = Arc::new(Hysteria2Handler::new(self.config));
        
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle(stream).await {
                            error!("Hysteria2 connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hysteria2_address_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let addr = Hysteria2Address::Ip(ip);
        let encoded = addr.encode();
        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..5], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_hysteria2_address_domain() {
        let addr = Hysteria2Address::Domain("example.com".to_string(), 443);
        let encoded = addr.encode();
        assert_eq!(encoded[0], 0x02);
        assert_eq!(encoded[1], 11); // "example.com" length
        assert_eq!(&encoded[2..13], b"example.com");
    }

    #[test]
    fn test_parse_client_hello() {
        let config = Hysteria2Config::default();
        let handler = Hysteria2Handler::new(config);
        
        // Build a minimal client hello
        let mut data = Vec::new();
        data.push(0x01); // ClientHello frame type
        data.push(0x02); // Version 2
        data.push(4);    // Password length
        data.extend_from_slice(b"test");
        
        let result = handler.parse_client_hello(&data);
        assert!(result.is_ok());
        let hello = result.unwrap();
        assert_eq!(hello.version, 2);
        assert_eq!(hello.password, "test");
    }

    #[test]
    fn test_invalid_password_length() {
        let config = Hysteria2Config::default();
        let handler = Hysteria2Handler::new(config);
        
        // Password length claims 10 but only 3 bytes provided
        let mut data = Vec::new();
        data.push(0x01); // ClientHello frame type
        data.push(0x02); // Version 2
        data.push(10);   // Password length (lie)
        data.extend_from_slice(b"test");
        
        let result = handler.parse_client_hello(&data);
        assert!(result.is_err());
    }
}
