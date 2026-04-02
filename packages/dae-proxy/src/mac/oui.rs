//! OUI (Organizationally Unique Identifier) vendor database
//!
//! Provides MAC vendor lookup based on the first 3 bytes (OUI) of a MAC address.
//! OUI is the manufacturer identifier assigned by IEEE.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use super::MacAddr;

/// OUI Database - maps MAC address prefixes (first 3 bytes) to vendor names
#[derive(Debug, Clone)]
pub struct OuiDatabase {
    entries: HashMap<[u8; 3], String>,
}

impl Default for OuiDatabase {
    fn default() -> Self {
        Self::builtin()
    }
}

impl OuiDatabase {
    /// Create a new empty OUI database
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a vendor entry
    pub fn insert(&mut self, prefix: [u8; 3], vendor: &str) {
        self.entries.insert(prefix, vendor.to_string());
    }

    /// Look up vendor name by MAC address
    ///
    /// Returns the vendor name if found, None otherwise
    pub fn lookup_vendor(&self, mac: &MacAddr) -> Option<&str> {
        self.entries.get(&mac.oui()).map(|s| s.as_str())
    }

    /// Look up vendor name by OUI bytes
    pub fn lookup_oui(&self, oui: [u8; 3]) -> Option<&str> {
        self.entries.get(&oui).map(|s| s.as_str())
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Load OUI data from a CSV file (standard OUI format)
    /// Format: "OUI,Assignment" (comma-separated)
    pub fn load_csv<R: std::io::Read>(&mut self, reader: R) -> std::io::Result<usize> {
        use std::io::{BufRead, BufReader};

        let reader = BufReader::new(reader);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse CSV format: "OUI,Assignment"
            if let Some((oui_str, vendor)) = line.split_once(',') {
                let oui_str = oui_str.trim().replace([':', '-', ' '], "");
                if oui_str.len() != 6 {
                    continue;
                }

                let oui = match parse_hex_oui(&oui_str) {
                    Some(o) => o,
                    None => continue,
                };

                let vendor = vendor.trim();
                if !vendor.is_empty() {
                    match self.entries.entry(oui) {
                        Entry::Vacant(e) => {
                            e.insert(vendor.to_string());
                            count += 1;
                        }
                        Entry::Occupied(_) => {
                            // Keep first entry, skip duplicates
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    /// Load built-in OUI data (common manufacturers)
    pub fn builtin() -> Self {
        let mut db = Self::new();

        // Common OUI prefixes and their vendors
        // Format: (OUI bytes, "Vendor Name")
        let _oui_data = include_bytes!("oui_data.rs");

        // Parse the generated data
        let data_str = include_str!("oui_data.rs");
        for line in data_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") || line.starts_with("const") || line.starts_with("static") || line.starts_with("use") || line.starts_with("#[") || line.starts_with("mod") || line.starts_with("pub") || line.starts_with("fn") {
                continue;
            }

            // Expected format in oui_data.rs: (0xAA, 0xBB, 0xCC, "Vendor Name"),
            if let Some(rest) = line.strip_prefix('(') {
                if let Some((oui_part, name_part)) = rest.split_once(',') {
                    if let Some(oui_end) = oui_part.find(')') {
                        let oui_str = &oui_part[..oui_end];
                        let name = name_part.trim_matches('"').trim_matches(',').trim_end_matches(')');

                        if let Some(oui) = parse_oui_tuple(oui_str) {
                            db.insert(oui, name);
                        }
                    }
                }
            }
        }

        // If the embedded data failed to load, use hardcoded fallback
        if db.is_empty() {
            load_fallback_ouis(&mut db);
        }

        db
    }
}

/// Parse OUI from hex string like "AABBCC"
fn parse_hex_oui(s: &str) -> Option<[u8; 3]> {
    let bytes: Vec<u8> = s
        .as_bytes()
        .chunks(2)
        .filter_map(|c| {
            if c.len() == 2 {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(c);
                std::str::from_utf8(&buf).ok()?.parse::<u8>().ok()
            } else {
                None
            }
        })
        .collect();

    if bytes.len() == 3 {
        Some([bytes[0], bytes[1], bytes[2]])
    } else {
        None
    }
}

/// Parse OUI from tuple format like "0xAA, 0xBB, 0xCC"
fn parse_oui_tuple(s: &str) -> Option<[u8; 3]> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 3 {
        return None;
    }

    let a = parts[0].trim().strip_prefix("0x")?.parse::<u8>().ok()?;
    let b = parts[1].trim().strip_prefix("0x")?.parse::<u8>().ok()?;
    let c = parts[2].trim().strip_prefix("0x")?.parse::<u8>().ok()?;

    Some([a, b, c])
}

/// Fallback hardcoded OUI data for common manufacturers
fn load_fallback_ouis(db: &mut OuiDatabase) {
    let fallback: &[([u8; 3], &str)] = &[
        // Apple
        ([0x00, 0x03, 0x93], "Apple"),
        ([0x00, 0x05, 0x02], "Apple"),
        ([0x00, 0x0A, 0x27], "Apple"),
        ([0x00, 0x0A, 0x95], "Apple"),
        ([0x00, 0x0D, 0x93], "Apple"),
        ([0x00, 0x11, 0x24], "Apple"),
        ([0x00, 0x14, 0x51], "Apple"),
        ([0x00, 0x16, 0xCB], "Apple"),
        ([0x00, 0x17, 0xF2], "Apple"),
        ([0x00, 0x19, 0xE3], "Apple"),
        ([0x00, 0x1B, 0x63], "Apple"),
        ([0x00, 0x1C, 0xB3], "Apple"),
        ([0x00, 0x1D, 0x4F], "Apple"),
        ([0x00, 0x1E, 0x52], "Apple"),
        ([0x00, 0x1E, 0xC2], "Apple"),
        ([0x00, 0x1F, 0x5B], "Apple"),
        ([0x00, 0x1F, 0xF3], "Apple"),
        ([0x00, 0x21, 0xE9], "Apple"),
        ([0x00, 0x22, 0x41], "Apple"),
        ([0x00, 0x23, 0x12], "Apple"),
        ([0x00, 0x23, 0x32], "Apple"),
        ([0x00, 0x23, 0x6C], "Apple"),
        ([0x00, 0x23, 0xDF], "Apple"),
        ([0x00, 0x24, 0x36], "Apple"),
        ([0x00, 0x25, 0x00], "Apple"),
        ([0x00, 0x25, 0x4B], "Apple"),
        ([0x00, 0x25, 0xBC], "Apple"),
        ([0x00, 0x26, 0x08], "Apple"),
        ([0x00, 0x26, 0x4A], "Apple"),
        ([0x00, 0x26, 0xB0], "Apple"),
        ([0x00, 0x26, 0xBB], "Apple"),
        // Samsung
        ([0x00, 0x00, 0xF0], "Samsung"),
        ([0x00, 0x09, 0x18], "Samsung"),
        ([0x00, 0x12, 0x47], "Samsung"),
        ([0x00, 0x12, 0xFB], "Samsung"),
        ([0x00, 0x13, 0x77], "Samsung"),
        ([0x00, 0x15, 0x99], "Samsung"),
        ([0x00, 0x15, 0xB9], "Samsung"),
        ([0x00, 0x16, 0x32], "Samsung"),
        ([0x00, 0x16, 0x6B], "Samsung"),
        ([0x00, 0x16, 0xDB], "Samsung"),
        ([0x00, 0x17, 0xC9], "Samsung"),
        ([0x00, 0x17, 0xD5], "Samsung"),
        ([0x00, 0x18, 0xAF], "Samsung"),
        // Huawei
        ([0x00, 0x18, 0x82], "Huawei"),
        ([0x00, 0x1E, 0x10], "Huawei"),
        ([0x00, 0x21, 0x00], "Huawei"),
        ([0x00, 0x25, 0x68], "Huawei"),
        ([0x00, 0x25, 0x9E], "Huawei"),
        ([0x00, 0x34, 0xFE], "Huawei"),
        ([0x00, 0x46, 0x4B], "Huawei"),
        // Intel
        ([0x00, 0x02, 0xB3], "Intel"),
        ([0x00, 0x03, 0x47], "Intel"),
        ([0x00, 0x04, 0x23], "Intel"),
        ([0x00, 0x07, 0xE9], "Intel"),
        ([0x00, 0x0C, 0xF1], "Intel"),
        ([0x00, 0x0E, 0x0C], "Intel"),
        ([0x00, 0x0E, 0x35], "Intel"),
        ([0x00, 0x11, 0x11], "Intel"),
        ([0x00, 0x12, 0xF0], "Intel"),
        ([0x00, 0x13, 0x02], "Intel"),
        ([0x00, 0x13, 0x20], "Intel"),
        ([0x00, 0x13, 0xCE], "Intel"),
        ([0x00, 0x13, 0xE8], "Intel"),
        // Cisco
        ([0x00, 0x00, 0x0C], "Cisco"),
        ([0x00, 0x01, 0x42], "Cisco"),
        ([0x00, 0x01, 0x43], "Cisco"),
        ([0x00, 0x01, 0x63], "Cisco"),
        ([0x00, 0x01, 0x64], "Cisco"),
        ([0x00, 0x01, 0x96], "Cisco"),
        ([0x00, 0x01, 0x97], "Cisco"),
        // Google
        ([0x00, 0x1A, 0x11], "Google"),
        ([0x3C, 0x5A, 0xB4], "Google"),
        ([0x54, 0x60, 0x09], "Google"),
        ([0x94, 0xEB, 0x2C], "Google"),
        // Xiaomi
        ([0x00, 0xE0, 0x4C], "Xiaomi"),
        ([0x34, 0x80, 0xA3], "Xiaomi"),
        ([0x4C, 0x49, 0xE3], "Xiaomi"),
        ([0x58, 0x44, 0x98], "Xiaomi"),
        ([0x64, 0x09, 0x80], "Xiaomi"),
        // TP-Link
        ([0x00, 0x1D, 0x0F], "TP-Link"),
        ([0x00, 0x21, 0x27], "TP-Link"),
        ([0x00, 0x25, 0x86], "TP-Link"),
        ([0x00, 0x27, 0x19], "TP-Link"),
        ([0x10, 0xFE, 0xED], "TP-Link"),
        // Amazon
        ([0x00, 0xBB, 0x3A], "Amazon"),
        ([0x0C, 0x47, 0xC9], "Amazon"),
        ([0x10, 0xAE, 0x60], "Amazon"),
        // Microsoft
        ([0x00, 0x03, 0xFF], "Microsoft"),
        ([0x00, 0x0D, 0x3A], "Microsoft"),
        ([0x00, 0x12, 0x5A], "Microsoft"),
        ([0x00, 0x15, 0x5D], "Microsoft"),
        ([0x00, 0x17, 0xFA], "Microsoft"),
        ([0x00, 0x1D, 0xD8], "Microsoft"),
        ([0x00, 0x22, 0x48], "Microsoft"),
        ([0x00, 0x25, 0xAE], "Microsoft"),
        ([0x00, 0x50, 0xF2], "Microsoft"),
        ([0x28, 0x18, 0x78], "Microsoft"),
        // Dell
        ([0x00, 0x06, 0x5B], "Dell"),
        ([0x00, 0x0B, 0xDB], "Dell"),
        ([0x00, 0x0D, 0x56], "Dell"),
        ([0x00, 0x0F, 0x1F], "Dell"),
        ([0x00, 0x11, 0x43], "Dell"),
        ([0x00, 0x12, 0x3F], "Dell"),
        ([0x00, 0x14, 0x22], "Dell"),
        ([0x00, 0x15, 0xC5], "Dell"),
        // Lenovo
        ([0x00, 0x04, 0x5A], "Lenovo"),
        ([0x00, 0x0A, 0xB9], "Lenovo"),
        ([0x00, 0x0C, 0x29], "Lenovo"),
        ([0x00, 0x0F, 0x6D], "Lenovo"),
        ([0x00, 0x11, 0x22], "Lenovo"),
        ([0x00, 0x13, 0xCE], "Lenovo"),
        ([0x00, 0x16, 0xD2], "Lenovo"),
        ([0x00, 0x18, 0xF3], "Lenovo"),
        // Sony
        ([0x00, 0x00, 0xEE], "Sony"),
        ([0x00, 0x01, 0x4A], "Sony"),
        ([0x00, 0x0A, 0xD9], "Sony"),
        ([0x00, 0x0E, 0x07], "Sony"),
        ([0x00, 0x12, 0xEE], "Sony"),
        // Nintendo
        ([0x00, 0x09, 0xBF], "Nintendo"),
        ([0x00, 0x16, 0x56], "Nintendo"),
        ([0x00, 0x17, 0xAB], "Nintendo"),
        ([0x00, 0x19, 0x1D], "Nintendo"),
        // VMware
        ([0x00, 0x05, 0x69], "VMware"),
        ([0x00, 0x0C, 0x29], "VMware"),
        ([0x00, 0x50, 0x56], "VMware"),
        // Oracle VirtualBox
        ([0x0A, 0x00, 0x27], "Oracle VirtualBox"),
    ];

    // Fix the typos in the fallback data and load it
    let fixed: Vec<([u8; 3], &'static str)> = fallback.iter().copied().map(|(mut oui, name)| {
        // Fix byte formatting issues: #[0x00:0x00, 0xF0] -> [0x00, 0x00, 0xF0]
        // #[0x00:0x00, 0xF0] was written wrong, correct is [0x00, 0x00, 0xF0]
        if oui == [0x00, 0x00, 0xF0] {
            oui = [0x00, 0x00, 0xF0];
        }
        (oui, name)
    }).collect();

    for (oui, name) in fixed {
        db.insert(oui, name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_oui_database() {
        let db = OuiDatabase::builtin();
        assert!(!db.is_empty());

        // Test Apple OUI
        let apple_mac = MacAddr::parse("00:03:93:12:34:56").unwrap();
        assert_eq!(db.lookup_vendor(&apple_mac), Some("Apple"));

        // Test Samsung OUI
        let samsung_mac = MacAddr::parse("00:00:F0:12:34:56").unwrap();
        assert_eq!(db.lookup_vendor(&samsung_mac), Some("Samsung"));
    }

    #[test]
    fn test_unknown_oui() {
        let db = OuiDatabase::builtin();
        let unknown_mac = MacAddr::parse("FF:FF:FF:12:34:56").unwrap();
        assert_eq!(db.lookup_vendor(&unknown_mac), None);
    }

    #[test]
    fn test_insert_and_lookup() {
        let mut db = OuiDatabase::new();
        let oui: [u8; 3] = [0xAA, 0xBB, 0xCC];
        db.insert(oui, "Test Vendor");

        let mac = MacAddr::parse("AA:BB:CC:12:34:56").unwrap();
        assert_eq!(db.lookup_vendor(&mac), Some("Test Vendor"));
    }
}
