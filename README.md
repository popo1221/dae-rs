# dae-rs

> Rust implementation of dae high-performance transparent proxy

## Overview

dae-rs is a high-performance transparent proxy written in Rust, aiming to achieve better performance through Rust's zero-cost abstractions and memory safety guarantees.

## Architecture

```
┌─────────────────────────────────────────────┐
│                 dae-cli                     │
│              (CLI & Config)                 │
└──────────┬──────────────────────┬───────────┘
           │                      │
           ▼                      ▼
┌──────────────────┐    ┌──────────────────┐
│    dae-core      │    │   dae-proxy      │
│  (Core Engine)   │    │ (Proxy Protocols)│
└──────────────────┘    └──────────────────┘
           │
           ▼
┌──────────────────┐
│    eBPF/XDP     │
│  (Traffic Hook) │
└──────────────────┘
```

## Packages

- **dae-core** - Core engine and routing logic
- **dae-cli** - Command-line interface
- **dae-config** - Configuration parsing
- **dae-proxy** - Proxy protocol implementations

## Development

### Requirements

- Rust 1.75+
- clang
- llvm
- libelf-dev

### Build

```bash
cargo build --release
```

### Test

```bash
cargo test --all
```

### Format

```bash
cargo fmt
cargo clippy --all
```

## Supported Protocols (Planned)

- HTTP Proxy
- SOCKS5
- Shadowsocks
- VLESS
- Trojan

## License

MIT
