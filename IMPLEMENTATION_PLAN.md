# dae-rs Review Fixes - Implementation Plan

## Priority Order (High to Low)

### Phase 1: Critical Fixes (Must Do)

- [ ] **1.1** Fix integration test `dae_proxy::socks5` import error
  - Check integration_tests source for correct import path
  - Validate: `cargo test --workspace` passes

- [ ] **1.2** Add Rust version matrix to CI
  - Edit `.github/workflows/ci.yml`
  - Add `1.75` (MSRV) and `stable` to matrix
  - Validate: CI workflow updated

- [ ] **1.3** Replace `panic!` with `unreachable!()` in protocol handlers
  - Files: juicity, shadowsocks, trojan, vmess handlers
  - Validate: `cargo clippy --workspace` shows fewer warnings

### Phase 2: Architecture Improvements

- [ ] **2.1** Extract `relay_bidirectional` to shared crate `crates/dae-relay/`
  - Create new crate with relay function
  - Update all 7 protocol crates to use shared version
  - Validate: `cargo check --workspace` passes

- [ ] **2.2** Standardize Handler trait pattern
  - Adopt vless/vmess Handler pattern across all crates
  - Create shared Handler trait in `crates/dae-protocol-core/` (optional)

- [ ] **2.3** Unify error handling with thiserror
  - Add thiserror to: http_proxy, socks4, socks5
  - Consider shared error types

### Phase 3: CI/CD Enhancements

- [ ] **3.1** Add cargo-audit security scanning
  - Add `rustsec/audit-check` or similar to CI

- [ ] **3.2** Add test coverage with tarpaulin
  - Add tarpaulin step to CI
  - (Optional) Upload to codecov

- [ ] **3.3** Add benchmark job
  - Add `cargo bench` to CI workflow

### Phase 4: Dependency Cleanup

- [ ] **4.1** Change `tokio = "full"` to minimal features
  - Analyze each crate's tokio usage
  - Use minimal feature sets

## Validation Commands

```bash
cargo check --workspace      # Typecheck
cargo clippy --workspace     # Lint
cargo test --workspace       # Tests
cargo build --workspace      # Build
```

## Backlog (Future)

- [ ] GeoIP extraction bug fix (separate issue)
- [ ] Add tests to protocol crates (currently only socks5 has tests)
