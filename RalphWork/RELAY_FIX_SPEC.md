# Ralph Mode Spec: dae-rs Dead Code Fixes

## Context
dae-rs module usage analysis found one dead code warning.

## Issues to Fix

### 1. Dead Code: encode() in Hysteria2
- **Location:** `crates/dae-protocol-hysteria2/src/hysteria2.rs:265`
- **Problem:** `pub fn encode(&self) -> Vec<u8>` method is never used
- **Fix:** Either:
  a) Remove if truly unused
  b) Add `#[allow(dead_code)]` if might be used later

## Validation
```bash
cargo clippy --all 2>&1 | grep -E "^error" | wc -l  # Must be 0
cargo clippy --all 2>&1 | grep "never used"  # Should be empty
```

## Output
Fix the dead code warning and commit with message: "chore(hysteria2): Remove unused encode method"
