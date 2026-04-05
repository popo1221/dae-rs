//! Network interface handling
//!
//! Utilities for working with network interfaces.

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use tracing::{debug, info};

/// Network interface information
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface name
    pub name: String,
    /// Interface index
    pub ifindex: u32,
    /// Interface flags
    pub flags: u32,
    /// IPv4 address (if available)
    pub ipv4: Option<Ipv4Addr>,
}

/// Get interface information by name
#[allow(dead_code)]
pub fn get_interface(name: &str) -> Result<InterfaceInfo> {
    // Use netlink or /sys filesystem to get interface info
    // For now, we'll use a simplified approach
    
    let ifindex_path = format!("/sys/class/net/{}/ifindex", name);
    let ifindex = std::fs::read_to_string(&ifindex_path)
        .context(format!("Failed to read interface index for {}", name))?
        .trim()
        .parse::<u32>()
        .context("Invalid interface index")?;

    let flags_path = format!("/sys/class/net/{}/flags", name);
    let flags = std::fs::read_to_string(&flags_path)
        .context(format!("Failed to read interface flags for {}", name))?
        .trim()
        .parse::<u32>()
        .context("Invalid interface flags")?;

    // Try to read IPv4 address
    let ipv4 = get_interface_ipv4(name).ok();

    debug!(
        "Interface {}: ifindex={}, flags={:#x}, ipv4={:?}",
        name, ifindex, flags, ipv4
    );

    Ok(InterfaceInfo {
        name: name.to_string(),
        ifindex,
        flags,
        ipv4,
    })
}

/// Get the IPv4 address of a network interface by parsing `ip addr show` output.
///
/// This is a fallback implementation that parses the output of the `ip` command.
/// For production use, consider using the netlink crate for proper address resolution.
///
/// See GitHub Issue #76.
#[allow(dead_code)]
fn get_interface_ipv4(name: &str) -> Result<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .args(["-4", "addr", "show", name])
        .output()
        .context("Failed to execute 'ip -4 addr show'")?;

    if !output.status.success() {
        anyhow::bail!("'ip -4 addr show' failed for interface {}", name);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output like: "inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(inet_pos) = trimmed.find("inet ") {
            let after_inet = &trimmed[inet_pos + 5..];
            if let Some(space_pos) = after_inet.find(' ') {
                let addr = &after_inet[..space_pos];
                if let Some(slash_pos) = addr.find('/') {
                    let ip_str = &addr[..slash_pos];
                    return ip_str
                        .parse::<Ipv4Addr>()
                        .with_context(|| format!("Failed to parse IPv4 address: {}", ip_str));
                }
            }
        }
    }

    anyhow::bail!("No IPv4 address found for interface {}", name)
}

/// List all network interfaces
#[allow(dead_code)]
pub fn list_interfaces() -> Result<Vec<String>> {
    let net_path = "/sys/class/net";
    let entries = std::fs::read_dir(net_path)
        .context("Failed to read /sys/class/net")?;

    let mut interfaces = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(name_str) = name.to_str() {
            // Skip loopback
            if name_str != "lo" {
                interfaces.push(name_str.to_string());
            }
        }
    }

    Ok(interfaces)
}

/// Check if an interface is up
#[allow(dead_code)]
pub fn is_interface_up(name: &str) -> Result<bool> {
    let flags_path = format!("/sys/class/net/{}/flags", name);
    let flags = std::fs::read_to_string(&flags_path)
        .context(format!("Failed to read flags for {}", name))?
        .trim()
        .parse::<u32>()?;

    // IFF_UP flag is 0x1
    Ok((flags & 0x1) != 0)
}

/// Get interface MTU
#[allow(dead_code)]
pub fn get_interface_mtu(name: &str) -> Result<u32> {
    let mtu_path = format!("/sys/class/net/{}/mtu", name);
    let mtu = std::fs::read_to_string(&mtu_path)
        .context(format!("Failed to read MTU for {}", name))?
        .trim()
        .parse::<u32>()
        .context("Invalid MTU value")?;

    info!("Interface {} MTU: {}", name, mtu);
    Ok(mtu)
}
