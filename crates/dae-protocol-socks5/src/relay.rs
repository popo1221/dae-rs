//! SOCKS5 data relay
//!
//! Bidirectional relay between SOCKS5 client and remote server.

use tokio::net::TcpStream;

/// Relay data bidirectionally between client and remote TCP streams.
pub async fn relay_bidirectional(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let client_to_remote = tokio::io::copy(&mut client_read, &mut remote_write);
    let remote_to_client = tokio::io::copy(&mut remote_read, &mut client_write);

    tokio::try_join!(client_to_remote, remote_to_client)?;
    Ok(())
}

/// Relay data between SOCKS5 client and remote server.
pub async fn relay(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    relay_bidirectional(client, remote).await
}
