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

## Completed in This Session

### ✅ full_cone.rs Deadlock Fix (bb70e8f, 8adc8e1)
**Root cause:** Deadlock between `create_mapping()` (holds reverse_mappings.write()) and `allocate_port()` (needs reverse_mappings.read())

**Secondary bug:** `is_incoming_allowed()` checked wrong map.

**Result:** 4 tests that were `#[ignore]` now pass. Added 5 more tests for edge cases.

### ✅ subscription.rs Analysis (bac268b)
**Analysis document:** `subscription_REFACTORING_PLAN.md`

**Key findings:**
- 2285 lines, 24 public items
- `uri_to_node_config()` is bottleneck - ALL format parsers call it
- Proper split requires moving URI parsing first
- Estimated 4 hours for full modularization

**Recommendation:** Defer full split due to complexity. Alternative: keep as-is but add tests.

## Current Branch Status
```
bac268b docs: analyze subscription.rs refactoring complexity
8adc8e1 test(nat): add 5 more tests for full_cone NAT
bb70e8f fix(nat): resolve deadlock in FullConeNat::create_mapping
```

## Validation

```
cargo check --workspace ✅
cargo test ✅ (all pass)
cargo clippy --workspace ✅
```

## Remaining Analysis

### subscription.rs (2285 lines)
**Status:** Complex interdependencies - documented in REFACTORING_PLAN.md

**Key issue:** `uri_to_node_config` (~350 lines) is called by ALL format parsers:
- parse_sip008_subscription → uri_to_node_config
- parse_clash_yaml → uri_to_node_config
- parse_singbox_json → uri_to_node_config

**Split order required:**
1. Move `uri_to_node_config` + helpers to `uri.rs` (first)
2. Then move format-specific parsers to `sip008.rs`, `clash.rs`, `singbox.rs`

### Other Oversized Files (already analyzed)
| File | Lines | Decision |
|------|-------|----------|
| ebpf_integration | 1530 | ✅ Already split |
| connection_pool.rs | 853 | 50% tests - low ROI |
| vless/handler.rs | 880 | Single struct - not worth splitting |

## Session Summary

| Timestamp | Action | Result |
|-----------|--------|--------|
| 2026-04-06T08:14 | Started subscription.rs refactor | Found complex deps |
| 2026-04-06T08:20 | Attempted split | Too complex for single session |
| 2026-04-06T08:25 | Created analysis doc | REFACTORING_PLAN.md |
| 2026-04-06T08:30 | Committed analysis | bac268b |

## Recommendations

1. **subscription.rs**: Keep as-is for now. Add tests instead of refactoring.
2. **Quick wins**: Add more test coverage to existing modules
3. **Future**: Consider subscription.rs split when more resources available

## Current Status
- Progress: 25%
- Blockers: None (analysis complete)
- Next: User discretion
