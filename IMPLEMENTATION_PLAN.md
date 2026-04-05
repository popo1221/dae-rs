# Implementation Plan: dae-rs CI/CD Fix

## Status: COMPLETE ✅

## Issue
CI failing due to doctest failure in `ebpf_check.rs`:
```
error[E0433]: failed to resolve: use of undeclared type `EbpfSupportLevel`
  --> packages/dae-proxy/src/ebpf_check.rs:18:5
```

## Root Cause
The doc test in `ebpf_check.rs` used wrong import path and had type inference issues.

## Completed Tasks

### Done
- [x] Fix doctest import issue in ebpf_check.rs
  - Changed `use ebpf_check::` → `use dae_proxy::ebpf_check::`
  - Added `EbpfSupportLevel` to import list
  - Fixed `reason.unwrap()` → `if let Some(r) = reason`
- [x] Fix clippy warnings in dae-config
  - `manual_strip`: `&param[7..]` → `param.strip_prefix("plugin=")`
  - `manual_unwrap`: `is_some() + unwrap()` → `plugin_type.map(|pt| ...)`

### Completion Criteria
- [x] CI passes locally: `cargo test --all` ✅
- [x] Clippy passes: `cargo clippy --all` ✅
- [x] Build succeeds: `cargo build --all` ✅
- [x] Formatting: `cargo fmt --all` ✅

## Files Changed
- `packages/dae-proxy/src/ebpf_check.rs`
- `packages/dae-config/src/subscription.rs`

## Next
- Commit and push to trigger GitHub Actions
