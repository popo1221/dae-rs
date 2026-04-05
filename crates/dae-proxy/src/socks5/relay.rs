//! SOCKS5 data relay
//!
//! Relays data between client and remote server.

use tokio::net::TcpStream;

/// Relay data between client and remote
pub async fn relay(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut rr, mut rw) = tokio::io::split(remote);

    let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
    let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

    tokio::try_join!(client_to_remote, remote_to_client)?;
    Ok(())
}
