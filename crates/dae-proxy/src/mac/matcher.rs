//! MAC address matching logic
//!
//! Provides MAC address matching with mask support and IP-to-MAC lookup.

use std::net::IpAddr;

use super::MacAddr;

/// Match a MAC address against a pattern with optional mask
///
/// # Arguments
/// * `mac` - The MAC address to check
/// * `pattern` - The MAC address pattern to match against
/// * `mask` - Optional mask. When provided, only bytes where mask is non-zero are compared.
///   For example, mask "FF:FF:FF:00:00:00" only compares the OUI (first 3 bytes).
///
/// # Returns
/// `true` if the MAC address matches the pattern (applying mask if specified)
pub fn match_mac_with_mask(mac: &MacAddr, pattern: &MacAddr, mask: &Option<MacAddr>) -> bool {
    match mask {
        Some(m) => {
            // Apply mask to both addresses and compare
            let masked_mac = [
                mac.byte(0).unwrap_or(0) & m.byte(0).unwrap_or(0),
                mac.byte(1).unwrap_or(0) & m.byte(1).unwrap_or(0),
                mac.byte(2).unwrap_or(0) & m.byte(2).unwrap_or(0),
                mac.byte(3).unwrap_or(0) & m.byte(3).unwrap_or(0),
                mac.byte(4).unwrap_or(0) & m.byte(4).unwrap_or(0),
                mac.byte(5).unwrap_or(0) & m.byte(5).unwrap_or(0),
            ];
            let masked_pattern = [
                pattern.byte(0).unwrap_or(0) & m.byte(0).unwrap_or(0),
                pattern.byte(1).unwrap_or(0) & m.byte(1).unwrap_or(0),
                pattern.byte(2).unwrap_or(0) & m.byte(2).unwrap_or(0),
                pattern.byte(3).unwrap_or(0) & m.byte(3).unwrap_or(0),
                pattern.byte(4).unwrap_or(0) & m.byte(4).unwrap_or(0),
                pattern.byte(5).unwrap_or(0) & m.byte(5).unwrap_or(0),
            ];
            masked_mac == masked_pattern
        }
        None => {
            // Exact match
            mac.bytes() == pattern.bytes()
        }
    }
}

/// Match with mask - returns Option<bool> for cleaner usage
pub fn match_mac_with_mask_opt(
    mac: &MacAddr,
    pattern: &MacAddr,
    mask: &Option<MacAddr>,
) -> Option<bool> {
    Some(match_mac_with_mask(mac, pattern, mask))
}

/// Get MAC address for an IP address by querying the ARP cache
///
/// This function reads from the system's ARP cache to find the MAC address
/// associated with the given IP address.
///
/// # Arguments
/// * `ip` - The IP address to look up
///
/// # Returns
/// `Some(MacAddr)` if found in ARP cache, `None` otherwise
pub fn get_mac_by_ip(ip: IpAddr) -> Option<MacAddr> {
    // On Linux, we can read /proc/net/arp to get the ARP cache
    #[cfg(target_os = "linux")]
    {
        get_mac_from_arp_cache(&ip)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ip;
        None
    }
}

#[cfg(target_os = "linux")]
fn get_mac_from_arp_cache(ip: &IpAddr) -> Option<MacAddr> {
    use std::fs;
    use std::io::{BufRead, BufReader};

    let arp_file = fs::File::open("/proc/net/arp").ok()?;
    let reader = BufReader::new(arp_file);

    let ip_str = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(_) => return None, // /proc/net/arp only shows IPv4
    };

    for line in reader.lines().skip(1) {
        let line = line.ok()?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        // parts[0] = IP address, parts[3] = HW type, parts[4] = MAC address
        if parts[0] != ip_str {
            continue;
        }

        // Check HW type (0x1 = Ethernet)
        if parts[3] != "0x1" {
            continue;
        }

        let mac_str = parts[4];
        if mac_str == "00:00:00:00:00:00" {
            continue;
        }

        return MacAddr::parse(mac_str);
    }

    None
}

/// Send an ARP request to populate the cache (on Linux)
/// This is a no-op wrapper - actual ARP resolution happens naturally when
/// the system tries to communicate with an IP.
#[cfg(target_os = "linux")]
pub fn probe_arp(ip: &IpAddr) -> Option<MacAddr> {
    use std::process::Command;

    if let IpAddr::V4(v4) = ip {
        // Try to ping the IP to populate ARP cache
        let _ = Command::new("ping")
            .args(["-c", "1", "-W", "1", &v4.to_string()])
            .output();

        // Small delay to let ARP cache update
        std::thread::sleep(std::time::Duration::from_millis(100));

        get_mac_from_arp_cache(ip)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe_arp(_ip: &IpAddr) -> Option<MacAddr> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mac1 = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        let mac2 = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        let mac3 = MacAddr::parse("11:22:33:44:55:66").unwrap();

        assert!(match_mac_with_mask(&mac1, &mac2, &None));
        assert!(!match_mac_with_mask(&mac1, &mac3, &None));
    }

    #[test]
    fn test_mask_match() {
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        let oui = MacAddr::parse("AA:BB:CC:00:00:00").unwrap();
        let mask = MacAddr::parse("FF:FF:FF:00:00:00").unwrap();

        assert!(match_mac_with_mask(&mac, &oui, &Some(mask)));

        let mac2 = MacAddr::parse("AA:BB:CD:DD:EE:FF").unwrap();
        assert!(!match_mac_with_mask(&mac2, &oui, &Some(mask)));
    }

    #[test]
    fn test_mac_addr_parsing() {
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac.bytes(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let mac2 = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac2.bytes(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_addr_display() {
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(format!("{mac}"), "AA:BB:CC:DD:EE:FF");
    }
}
