# eBPF Map Design for dae-rs

> **Document Type:** Technical Design
> **Created:** 2026-04-05
> **Status:** Draft
> **Target:** Production eBPF integration with aya framework

---

## 1. Overview

This document describes the eBPF Map design for dae-rs transparent proxy, following the architecture defined in `EBPF_REFACTOR_ARCH.md`. The design is based on go-dae's eBPF implementation using aya Rust framework.

## 2. Map Types Overview

| Map Name | Type | Purpose | Key | Value |
|----------|------|---------|-----|-------|
| `SESSIONS` | HashMap | Connection tracking | `SessionKey` (5-tuple) | `SessionEntry` |
| `ROUTING` | LpmTrie | IP CIDR routing | `Key<u32>` (IP + prefix) | `RoutingEntry` |
| `DNS_MAP` | HashMap | Domain name resolution | `u64` (domain hash) | `DnsMapEntry` |
| `CONFIG` | Array | Global configuration | `u32` (key index) | `ConfigEntry` |
| `STATS` | PerCpuArray | Statistics counters | `u32` (stat index) | `StatsEntry` |
| `EVENTS` | ringbuf | Event notification | N/A | `EbpfEvent` |

## 3. Kernel-space vs User-space Types

### 3.1 Shared Types (via dae-ebpf-common)

These types are defined in `packages/dae-ebpf/dae-ebpf-common/src/` and shared between kernel and user space:

```rust
// Session key - 5-tuple connection identifier
#[repr(C)]
pub struct SessionKey {
    pub src_ip: u32,      // Network byte order
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,        // 6=TCP, 17=UDP
    reserved: [u8; 3],
}

// Session entry - connection state
#[repr(C)]
pub struct SessionEntry {
    pub state: u8,        // 0=NEW, 1=ESTABLISHED, 2=CLOSED
    pub src_mac_len: u8,
    pub packets: u64,
    pub bytes: u64,
    pub start_time: u64,
    pub last_time: u64,
    pub route_id: u32,
    pub src_mac: [u8; 6],
}

// Routing entry - routing decision
#[repr(C)]
pub struct RoutingEntry {
    pub route_id: u32,
    pub action: u8,       // 0=PASS, 1=REDIRECT, 2=DROP
    pub ifindex: u32,
    reserved: [u8; 4],
}

// Routing actions
pub mod action {
    pub const PASS: u8 = 0;
    pub const REDIRECT: u8 = 1;
    pub const DROP: u8 = 2;
}
```

### 3.2 Kernel-only Types (in dae-tc or dae-xdp packages)

```rust
// DNS map entry (kernel only)
#[repr(C)]
pub struct DnsMapEntry {
    pub ip: u32,          // Resolved IPv4
    pub ttl: u32,         // DNS TTL
    pub timestamp: u64,    // Resolution time
}

// Event structure for ring buffer (kernel → userspace)
#[repr(C)]
pub struct EbpfEvent {
    pub event_type: u8,   // 0=packet, 1=session_created, 2=session_closed, 3=dns_query
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub timestamp: u64,
    pub data: [u8; 40],   // Additional event data
}

// Control message (user space → kernel via ring buffer)
#[repr(C)]
pub struct SessionControlMsg {
    pub action: u32,       // 0=create, 1=update, 2=destroy
    pub key: SessionKey,
    pub entry: SessionEntry,
}
```

## 4. Map Specifications

### 4.1 SESSIONS Map (Connection Tracking)

**Map Definition:**
```rust
aya::maps::HashMap<SessionKey, SessionEntry>
```

**Purpose:** Track active connections for stateful transparent proxying.

**Key:** `SessionKey` (5-tuple: src_ip, dst_ip, src_port, dst_port, proto)

**Value:** `SessionEntry` (connection state, bytes, packets, timestamps)

**Operations:**
- **INSERT:** Create new session on first packet (TCP SYN for TCP, first packet for UDP)
- **UPDATE:** Update bytes/packets counters and timestamps
- **LOOKUP:** Fast 5-tuple lookup for existing sessions
- **DELETE:** Remove on connection close (TCP FIN/RST, UDP timeout)

**Lifetime:** Session timeout (configurable, default 5 minutes)

### 4.2 ROUTING Map (CIDR-based Routing)

**Map Definition:**
```rust
aya::maps::LpmTrie<u32, RoutingEntry>
```

**Purpose:** Longest Prefix Match (LPM) routing for IP-based rules.

**Key:** `Key<u32>` - struct with `{ prefix_len: u32, data: u32 }` where:
- `prefix_len`: CIDR prefix (0-32)
- `data`: IP address in network byte order

**Value:** `RoutingEntry` (route_id, action, ifindex)

**Operations:**
- **INSERT:** Add CIDR rule (e.g., `10.0.0.0/8` → route to VPN)
- **LOOKUP:** LPM lookup for destination IP, returns longest matching rule
- **DELETE:** Remove routing rule

**Example:**
```rust
// Insert 10.0.0.0/8 → route_id=1
let key = Key::new(8, 0x0A000000);
routing.insert(&key, &RoutingEntry::new(1, PASS, 0));

// Insert 10.1.0.0/16 → route_id=2 (more specific)
let key = Key::new(16, 0x0A010000);
routing.insert(&key, &RoutingEntry::new(2, REDIRECT, 5));

// Lookup 10.1.2.3 → returns route_id=2 (longest match)
let key = Key::new(32, 0x0A010203);
let entry = routing.get(&key);
```

### 4.3 DNS_MAP (Domain-based Routing)

**Map Definition:**
```rust
aya::maps::HashMap<u64, DnsMapEntry>
```

**Purpose:** Domain name to IP resolution for domain-based routing rules.

**Key:** `u64` - hashed domain name (FNV-1a or similar)

**Value:** `DnsMapEntry` (resolved IP, TTL, timestamp)

**Domain Hashing:**
```rust
fn domain_key(domain: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce84222229;
    for byte in domain {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
```

**Operations:**
- **INSERT:** Add domain → IP mapping (on DNS response)
- **LOOKUP:** Get resolved IP for domain hash
- **DELETE:** Remove on TTL expiry or DNS cache invalidation

### 4.4 CONFIG Map (Global Configuration)

**Map Definition:**
```rust
aya::maps::Array<ConfigEntry>
```

**Purpose:** Global configuration shared with eBPF programs.

**Key:** `u32` index (0 = global config, 1-N = reserved)

**Value:** `ConfigEntry`

```rust
#[repr(C)]
pub struct ConfigEntry {
    pub enabled: u32,        // 0=disabled, 1=enabled
    pub log_level: u32,      // 0=error, 1=warn, 2=info, 3=debug
    pub session_timeout: u64,
    pub max_sessions: u32,
    pub reserved: [u8; 40],
}
```

### 4.5 STATS Map (Statistics)

**Map Definition:**
```rust
aya::maps::PerCpuArray<StatsEntry>
```

**Purpose:** Per-CPU statistics counters (lock-free, high performance).

**Key:** `u32` stat index

**Value:** `StatsEntry`

```rust
#[repr(C)]
pub struct StatsEntry {
    pub packets: u64,
    pub bytes: u64,
    pub redirected: u64,
    pub passed: u64,
    pub dropped: u64,
    pub routed: u64,
    pub unmatched: u64,
}
```

**Stat Indices:**
```rust
pub mod idx {
    pub const OVERALL: u32 = 0;
    pub const TCP: u32 = 1;
    pub const UDP: u32 = 2;
    pub const ICMP: u32 = 3;
    pub const DNS: u32 = 4;
    // ... up to 255
}
```

**Note:** `PerCpuArray` automatically aggregates values across CPUs when read from user space.

### 4.6 EVENTS Map (Ring Buffer)

**Map Definition:**
```rust
aya::maps::RingBuf<EbpfEvent>
```

**Purpose:** Asynchronous event notification from kernel to user space.

**Data Direction:** Kernel → User space (read-only from userspace perspective)

**Event Types:**
- `0`: Packet event (for debugging/logging)
- `1`: Session created
- `2`: Session closed
- `3`: DNS query
- `4`: Stats snapshot

## 5. Kernel Version Compatibility

### 5.1 Feature Matrix

| Feature | Map Type | Min Kernel | Notes |
|---------|----------|------------|-------|
| HashMap | HashMap | 4.14 | Basic key-value store |
| LpmTrie | LpmTrie | 4.18 | Full CIDR support |
| PerCpuArray | PerCpuArray | 4.14 | Lock-free counters |
| ringbuf | RingBuf | 5.8 | Zero-copy events |
| perf buffer | PerfBuffer | 4.14 | Legacy event channel |
| TC clsact | tc program | 5.6 | Stable in 5.10+ |
| XDP | xdp program | 4.8 | Stable in 4.14+ |

### 5.2 Fallback Strategy

```
Kernel 5.8+  ──────────────────────────────────→ Full Features
                (ringbuf + LpmTrie + TC clsact)

Kernel 5.4-5.7 ──────────────────────────────→ Partial
                (LpmTrie + TC clsact, no ringbuf)
                Use perf buffer instead of ringbuf

Kernel 4.14-5.3 ────────────────────────────→ Basic
                (HashMap only, no LpmTrie)
                Fallback to userspace LPM scan

Kernel < 4.14 ──────────────────────────────→ None
                Pure userspace implementation
```

## 6. TC vs XDP Program Selection

### 6.1 Recommendation: TC clsact

For transparent proxying, **TC clsact is recommended** because:

1. **Full TCP/IP stack integration** - Can inspect L7 data
2. **iptables/nftables compatible** - Works with existing firewall rules
3. **Transparent proxy support** - Can redirect connections transparently
4. **Complete packet processing** - Sees packets after routing decisions

### 6.2 XDP as Alternative

XDP is suitable when:

1. **Maximum performance** needed (early DROP, early redirect)
2. **No L7 inspection** required
3. **Simple packet filtering** only

### 6.3 Program Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    TC clsact Ingress                        │
│  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────┐ │
│  │  Parse    │──▶│  Session  │──▶│  Routing  │──▶│ Action│ │
│  │  Packet   │   │  Lookup   │   │  LPM      │   │       │ │
│  └───────────┘   └───────────┘   └───────────┘   └───────┘ │
│       │              │               │                    │
│       │         ┌────┴────┐          │                    │
│       │         │ SESSIONS│          │                    │
│       │         │  Map    │          │                    │
│       │         └─────────┘          │                    │
│       │                              │                    │
│       │         ┌────────────────────┴────┐                │
│       │         │      ROUTING Map        │                │
│       │         │      (LpmTrie)          │                │
│       │         └─────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
              ┌────────────────────────────┐
              │        Actions             │
              │  PASS → Continue stack     │
              │  REDIRECT → Mark + Return  │
              │  DROP → TC_ACT_SHOT        │
              └────────────────────────────┘
```

## 7. Data Flow

### 7.1 Packet Processing (Kernel)

```
1. Packet arrives at network interface
2. TC clsact intercepts at ingress
3. Parse Ethernet, IPv4/IPv6, TCP/UDP headers
4. Create SessionKey from 5-tuple
5. Lookup SESSIONS map:
   - Found: Update counters, continue
   - Not found: Create new session
6. Lookup ROUTING map (LPM):
   - Find longest matching CIDR rule
   - If no match: lookup DNS_MAP (domain rules)
7. Apply action (PASS/REDIRECT/DROP)
8. If session event: write to EVENTS ringbuf
9. Return TC_ACT_OK or TC_ACT_SHOT
```

### 7.2 Control Plane (User Space)

```
1. Load eBPF object file
2. Create maps (SESSIONS, ROUTING, DNS_MAP, STATS, CONFIG)
3. Attach TC clsact program
4. Initialize ring buffer reader for EVENTS
5. Sync routing rules to ROUTING map
6. Process events from ring buffer asynchronously
7. Update session state based on events
8. Periodically sync stats from STATS map
```

## 8. Implementation Notes

### 8.1 Map Pinning

eBPF maps persist after program unload. For persistent storage:

```bash
# Pin map to filesystem
bpftool map pin id <map_id> /sys/fs/bpf/dae_sessions

# Reference pinned map
bpftool map show pinned /sys/fs/bpf/dae_sessions
```

### 8.2 Memory Limits

Default BPF memory limit is 64MB (RLIMIT_MEMLOCK). For high-connection scenarios:

```bash
# Check current limit
ulimit -l

# Increase limit (root)
ulimit -l 262144  # 256MB
```

### 8.3 Permissions

Required capabilities:
- `CAP_SYS_ADMIN` - Load eBPF programs
- `CAP_NET_ADMIN` - Attach TC/XDP programs
- Or: `CAP_BPF` (kernel 5.6+)

## 9. File Locations

| Component | File | Description |
|-----------|------|-------------|
| Kernel types | `packages/dae-ebpf/dae-ebpf-common/src/` | Shared type definitions |
| TC program | `packages/dae-ebpf/dae-tc/src/` | TC eBPF program |
| XDP program | `packages/dae-ebpf/dae-xdp/src/` | XDP eBPF program |
| User loader | `packages/dae-ebpf/dae-ebpf/src/` | aya-based loader |
| Integration | `packages/dae-proxy/src/ebpf_integration.rs` | Proxy integration |
| Kernel check | `packages/dae-proxy/src/ebpf_check.rs` | Kernel capability detection |

## 10. References

- go-dae eBPF implementation (upstream reference)
- aya documentation: <https://aya-rs.dev/book/>
- BPF kernel documentation: <https://www.kernel.org/doc/html/latest/bpf/>
- TC clsact: <https://www.kernel.org/doc/html/latest/networking/tc-clsact.html>
