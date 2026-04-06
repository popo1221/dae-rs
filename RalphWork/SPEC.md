# Ralph Mode Spec: dae-rs Code Review Fixes

## Context
dae-rs is an eBPF accelerated multi-protocol transparent proxy written in Rust.

## Issues to Fix

### P1 - SAFETY & Critical

#### #1: SAFETY comments in dae-tc/packet.rs
- **Problem**: 5 `unsafe` blocks lack SAFETY comments explaining invariants
- **Location**: `crates/dae-tc/src/packet.rs` lines 224, 323, 463, 556, 622
- **Fix**: Add SAFETY comments explaining memory invariants, pointer validity

#### #2: Trivy exit-code
- **Problem**: `exit-code: '0'` won't fail CI on critical CVEs
- **Location**: `.github/workflows/docker.yml`
- **Fix**: Change to `exit-code: '1'`

#### #3: LazyLock MSRV
- **Problem**: `LazyLock` requires Rust 1.80+, but MSRV is 1.75
- **Location**: `crates/dae-api/src/websocket.rs`
- **Fix**: Replace with `OnceLock` or `std::sync::Once`

### P1 - Handler Trait Unification

#### #4-7: Handler trait consistency
- **Problem**: VLESS/VMess define local Handler traits, SOCKS5/HTTP don't implement Handler trait
- **Location**: 
  - `crates/dae-protocol-vless/src/handler.rs`
  - `crates/dae-protocol-vmess/src/handler.rs`
  - `crates/dae-proxy/src/socks5/mod.rs`
  - `crates/dae-proxy/src/http_proxy/mod.rs`
- **Fix**: Refactor to use `unified_handler.rs` trait

### P2 - Code Quality

#### #8: panic! → unreachable!()
- **Problem**: 15+ `panic!` in production protocol match arms
- **Locations**: juicity, shadowsocks, trojan, vmess handlers
- **Fix**: Replace with `unreachable!()` for truly unreachable code

#### #9: connection_pool DNS failure
- **Problem**: `connection_pool.rs:256` DNS failure could panic
- **Location**: `crates/dae-proxy/src/connection_pool.rs:256`
- **Fix**: Proper error propagation

#### #10: Error type consistency
- **Problem**: Some use `thiserror`, others return `std::io::Result<()>`
- **Fix**: Standardize error handling across crates

## Validation

After each fix:
```bash
cargo clippy --all 2>&1 | grep -E "^error" | wc -l  # Must be 0
cargo build --all 2>&1 | tail -3  # Must succeed
```

## Files
- `RalphWork/IMPLEMENTATION_PLAN.md` - Priority task list
- `RalphWork/PROGRESS.md` - Iteration log
