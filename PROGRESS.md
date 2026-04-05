# Ralph Mode: dae-rs Review Fixes

## Status: IN PROGRESS 🚀

**Started:** 2026-04-05 19:08 GMT+8

## Mission
Fix all issues from review-protocols and review-cicd:
- relay_bidirectional duplication (7 crates)
- Handler trait inconsistency
- Error handling inconsistency
- tokio "full" overuse
- CI improvements (Rust matrix, tarpaulin, cargo-audit)
- Fix integration test import error

---

## Iteration Log

### 2026-04-05 19:10 GMT+8 - Rust Version Matrix
- ✅ Added Rust version matrix to CI workflow (`.github/workflows/ci.yml`)
  - Matrix: `[1.75, stable]`
  - MSRV: 1.75, Latest: stable
  - Updated `dtolnay/rust-toolchain` to use `${{ matrix.rust }}`

### 2026-04-05 19:15 GMT+8 - panic! → unreachable!() Investigation
- ✅ Investigated panic! in protocol handlers (juicity, shadowsocks, trojan, vmess)
- **Result:** All 15 panic! statements are in `#[test]` functions (test assertions)
- **Decision:** No replacement needed — test code panic! is correct behavior
- Affected files: codec.rs (juicity), protocol.rs (shadowsocks, trojan), mod.rs (vmess, proxy)

---

## Completion Criteria

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace` passes (errors, not warnings)
- [ ] Integration test import fixed
- [ ] Rust version matrix added to CI
- [ ] `panic!` → `unreachable!()` done
- [ ] relay_bidirectional extracted to shared crate
