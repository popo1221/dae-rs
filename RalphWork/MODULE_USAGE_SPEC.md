# Ralph Mode Spec: dae-rs Module Usage Analysis

## Context
dae-rs is an eBPF accelerated multi-protocol transparent proxy written in Rust. It has a modular crate structure that was refactored in Phase 3.

## Goal
Analyze how each dae-protocol-* crate is used by other crates in the workspace.

## Module Structure

### Protocol Crates
```
dae-protocol-core      - Shared traits (Handler, HandlerConfig, ProtocolType)
dae-protocol-socks4    - SOCKS4 protocol
dae-protocol-socks5    - SOCKS5 protocol
dae-protocol-http_proxy - HTTP proxy protocol
dae-protocol-shadowsocks - Shadowsocks protocol
dae-protocol-trojan   - Trojan protocol
dae-protocol-vless    - VLESS protocol
dae-protocol-vmess    - VMess protocol
dae-protocol-tuic     - TUIC protocol
dae-protocol-juicity  - Juicity protocol
dae-protocol-hysteria2 - Hysteria2 protocol
```

### Core Crates
```
dae-core              - Core eBPF functionality
dae-proxy            - Proxy server implementation
dae-api              - API server
dae-config           - Configuration
dae-relay           - Connection relay utilities
dae-tc               - Traffic control
dae-xdp              - XDP implementation
dae-ebpf             - eBPF programs
dae-ebpf-common      - eBPF common
dae-ebpf-direct      - eBPF direct
```

## Tasks

### 1. Analyze Cargo.toml dependencies
For each crate, find:
- Which crates depend on it
- What features are used
- Is it optional or required

### 2. Check actual usage in code
Find actual `use` statements importing from each protocol crate

### 3. Cross-reference with Cargo features
Check if features properly control optional dependencies

### 4. Generate usage matrix
Create a matrix showing:
- Which crates depend on which protocols
- Feature gates in use
- Any unused dependencies

## Output Format

Create `RalphWork/MODULE_USAGE_REPORT.md` with:

```markdown
# Module Usage Report

## Dependency Matrix
[Table showing which crates use which protocol crates]

## Unused Dependencies
[Any crates that are depended on but not used]

## Feature Usage
[Which features are actually used]

## Recommendations
[Any issues found]
```

## Validation
```bash
cargo metadata --format-version 1  # Check dependency tree
```
