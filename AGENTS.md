# dae-rs Operations Guide

## Build Commands

```bash
cargo check --workspace      # Fast typecheck
cargo clippy --workspace     # Lint + warnings
cargo build --workspace       # Full build
cargo test --workspace       # Run tests
cargo fmt -- --check         # Check formatting
```

## Validation Gates

- **Before commit**: `cargo clippy --workspace` must pass (warnings OK, errors not)
- **Before PR**: `cargo test --workspace` must pass
- **Integration tests**: `cargo test -p integration_tests`

## Key Paths

- **Workspace root**: `/root/.openclaw/workspace/dae-rs`
- **Protocol crates**: `crates/dae-protocol-*`
- **CI config**: `.github/workflows/ci.yml`

## Protocol Crates (10 total)

```
dae-protocol-socks4
dae-protocol-socks5
dae-protocol-http_proxy
dae-protocol-hysteria2
dae-protocol-juicity
dae-protocol-shadowsocks
dae-protocol-trojan
dae-protocol-tuic
dae-protocol-vless
dae-protocol-vmess
```

## Common Issues

1. **Integration test import error**: Check `dae_proxy::socks5` vs `dae_protocol_socks5`
2. **relay_bidirectional duplicate**: Extract to shared crate
3. **tokio full features**: Use minimal features per crate

## Rust Version

- **MSRV**: 1.75
- **Current stable**: Use `rustup show` to check
