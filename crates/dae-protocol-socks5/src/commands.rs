//! SOCKS5 command processing (RFC 1928)
//!
//! Handles CONNECT (0x01), BIND (0x02), and UDP ASSOCIATE (0x03) commands.

use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

use super::address::Socks5Address;
use super::consts;
use super::reply::Socks5Reply;

/// SOCKS5 command
#[derive(Debug, Clone, Copy)]
pub enum Socks5Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Socks5Command {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            consts::CMD_CONNECT => Some(Socks5Command::Connect),
            consts::CMD_BIND => Some(Socks5Command::Bind),
            consts::CMD_UDP_ASSOCIATE => Some(Socks5Command::UdpAssociate),
            _ => None,
        }
    }
}

/// Command handler for SOCKS5 commands
pub struct CommandHandler {
    tcp_timeout_secs: u64,
}

impl CommandHandler {
    pub fn new(tcp_timeout_secs: u64) -> Self {
        Self { tcp_timeout_secs }
    }

    /// Handle SOCKS5 request (phase 3)
    pub async fn handle_request(&self, mut client: TcpStream) -> std::io::Result<()> {
        // Read request: VER (1) + CMD (1) + RSV (1) + ATYP (1) + DST.ADDR + DST.PORT (2)
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await?;

        let ver = header[0];
        let cmd = header[1];

        if ver != consts::VER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid SOCKS version: {ver}"),
            ));
        }

        let command = match Socks5Command::from_u8(cmd) {
            Some(c) => c,
            None => {
                self.send_reply(
                    &mut client,
                    Socks5Reply::CommandNotSupported,
                    &Socks5Address::IPv4(Ipv4Addr::new(0, 0, 0, 0), 0),
                )
                .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown command: {cmd}"),
                ));
            }
        };

        // Parse destination address
        let dst_addr = Socks5Address::parse_from(&mut client).await?;
        tracing::debug!("SOCKS5 request: {:?} to {:?}", command, dst_addr);

        match command {
            Socks5Command::Connect => self.handle_connect(client, &dst_addr).await,
            Socks5Command::Bind => {
                self.send_reply(
                    &mut client,
                    Socks5Reply::CommandNotSupported,
                    &Socks5Address::IPv4(Ipv4Addr::new(0, 0, 0, 0), 0),
                )
                .await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "BIND command not supported",
                ))
            }
            Socks5Command::UdpAssociate => self.handle_udp_associate(client, &dst_addr).await,
        }
    }

    /// Handle CONNECT command
    #[allow(clippy::incompatible_msrv)]
    pub async fn handle_connect(
        &self,
        mut client: TcpStream,
        dst_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        use super::relay::relay;

        // Resolve address
        let socket_addr = match dst_addr.to_socket_addr() {
            Some(addr) => addr,
            None => {
                // Need DNS resolution for domain names
                if let Socks5Address::Domain(domain, port) = dst_addr {
                    match tokio::net::lookup_host(format!("{domain}:{port}")).await {
                        Ok(mut addrs) => match addrs.next() {
                            Some(addr) => addr,
                            None => {
                                self.send_reply(
                                    &mut client,
                                    Socks5Reply::HostUnreachable,
                                    dst_addr,
                                )
                                .await?;
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::HostUnreachable,
                                    "no addresses found",
                                ));
                            }
                        },
                        Err(e) => {
                            self.send_reply(&mut client, Socks5Reply::HostUnreachable, dst_addr)
                                .await?;
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::HostUnreachable,
                                format!("DNS resolution failed: {e}"),
                            ));
                        }
                    }
                } else {
                    unreachable!()
                }
            }
        };

        // Connect to remote
        let timeout = std::time::Duration::from_secs(self.tcp_timeout_secs);
        let remote = match tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(socket_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let reply = Socks5Reply::from_io_error(&e);
                self.send_reply(&mut client, reply, dst_addr).await?;
                return Err(e);
            }
            Err(_) => {
                self.send_reply(&mut client, Socks5Reply::HostUnreachable, dst_addr)
                    .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timeout",
                ));
            }
        };

        let _local_addr = client.local_addr()?;

        // Send success reply with bound address (use local address)
        let bound_addr = Socks5Address::IPv4(
            if let std::net::SocketAddr::V4(v4) = client
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
            {
                *v4.ip()
            } else {
                Ipv4Addr::new(0, 0, 0, 0)
            },
            0,
        );
        self.send_reply(&mut client, Socks5Reply::Success, &bound_addr)
            .await?;

        info!("SOCKS5 CONNECT: -> {}", socket_addr);

        // Relay data between client and remote
        relay(client, remote).await
    }

    /// Handle UDP ASSOCIATE command
    pub async fn handle_udp_associate(
        &self,
        mut client: TcpStream,
        _dst_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        // Get client address for UDP relay
        let client_addr = client.peer_addr()?;

        // Create a UDP socket for the association
        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let udp_bind_addr = udp_socket.local_addr()?;

        // Convert to IPv4 if possible for the reply
        let bind_addr = match udp_bind_addr {
            SocketAddr::V4(v4) => Socks5Address::IPv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Socks5Address::IPv6(*v6.ip(), v6.port()),
        };

        // Send success reply with UDP relay address
        self.send_reply(&mut client, Socks5Reply::Success, &bind_addr)
            .await?;

        info!(
            "SOCKS5 UDP ASSOCIATE: client={} relay={}",
            client_addr, udp_bind_addr
        );

        // Keep TCP connection open for UDP relay control
        // In a full implementation, we would:
        // 1. Wait for client to send UDP datagrams
        // 2. Forward them to target
        // 3. Relay responses back
        // For now, just wait for EOF on TCP connection
        let mut buf = [0u8; 1];
        let _ = client.read_exact(&mut buf).await;

        info!("SOCKS5 UDP ASSOCIATE: connection closed");
        Ok(())
    }

    /// Send SOCKS5 reply
    pub async fn send_reply(
        &self,
        client: &mut TcpStream,
        reply: Socks5Reply,
        bind_addr: &Socks5Address,
    ) -> std::io::Result<()> {
        // Reply format: VER (1) + REP (1) + RSV (1) + ATYP (1) + BND.ADDR + BND.PORT (2)
        client
            .write_all(&[consts::VER, reply.to_u8(), 0x00])
            .await?;
        bind_addr.write_to(client).await
    }
}
