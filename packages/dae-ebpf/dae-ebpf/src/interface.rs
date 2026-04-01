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

/// Get the IPv4 address of an interface
#[allow(dead_code)]
fn get_interface_ipv4(name: &str) -> Result<Ipv4Addr> {
    let _ = name;
    // For now, return an error as getting IPv4 requires more complex parsing
    anyhow::bail!("IPv4 address parsing not implemented")
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
