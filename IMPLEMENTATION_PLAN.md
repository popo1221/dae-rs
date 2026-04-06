# Ralph Mode: dae-rs Module Refactoring

## Task ID
task-1775460664785-129a3u

## Objective
Split oversized modules/files into smaller, focused submodules.

## Progress Overview

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Optional QUIC (quinn) compilation | ✅ Complete (PR #101) |
| Phase 2 | socks4.rs split into 4 modules | ✅ Complete (PR #102) |
| Phase 3 | Continue module splitting | 🔄 In Progress |

## Analysis Completed

### ✅ ebpf_integration/mod.rs (1530 lines)
Already split into:
- `mod.rs`, `checks.rs`, `config.rs`, `diagnostics.rs`, `maps.rs`, `metrics.rs`

### ⚠️ subscription.rs (2285 lines)
**Status:** Complex interdependencies - postponed for later phase

**Issue:** Functions like `parse_sip008_subscription` call `uri_to_node_config` which calls other functions. Splitting requires:
1. Moving shared types first
2. Then moving functions with their dependencies
3. Careful dependency tracking

### ⚠️ connection_pool.rs (853 lines)
**Status:** Mostly tests (432 lines = 50% of file)

**Structure:**
- `CompactIp` impl block: ~73 lines
- `ConnectionKey` struct + impl: ~80 lines
- `ConnectionPool` struct + impl: ~212 lines
- `new_connection_pool` fn: ~12 lines
- `tests`: ~432 lines

**Note:** Splitting this file would mostly just move tests around.

## Findings

### Clippy Status
```
cargo clippy ✅ 0 warnings
```

### TODO/FIXME Items Found
1. `full_cone.rs`: 4 ignored tests (TODO: investigate async/blocking hang)
2. `hysteria2/lib.rs`: QUIC transport TODO (larger feature)

## Next Steps

Given the analysis, recommended next actions:

1. **Quick Win:** Fix ignored tests in full_cone.rs (investigate hang)
2. **Medium Effort:** Split connection_pool.rs (CompactIp → compact.rs, keep ConnectionPool + tests)
3. **Long Term:** subscription.rs refactor (requires careful dependency mapping)

## Validation

```
cargo check ✅ (0 errors)
cargo test ✅ (all pass)
cargo clippy ✅ (0 warnings)
```

## Session Summary
- Started: 2026-04-06T07:31:00
- Completed: Analysis phase
- Progress: 20%
- Outcome: Deferred complex splits; identified simpler opportunities
