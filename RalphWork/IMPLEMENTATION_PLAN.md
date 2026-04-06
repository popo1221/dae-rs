# Ralph Mode: dae-rs Code Review Fixes

## Priority Order (P1 first)

### P1 - Must Fix

- [ ] Fix #1: SAFETY comments for unsafe blocks in dae-tc/src/packet.rs (5 locations)
- [ ] Fix #2: Trivy exit-code '0' → '1' in docker.yml
- [ ] Fix #3: LazyLock MSRV fix in dae-api (use OnceLock or bump MSRV)

### P1 - Handler Trait

- [ ] Fix #4: VLESS Handler trait → use unified_handler.rs
- [ ] Fix #5: VMess Handler trait → use unified_handler.rs
- [ ] Fix #6: SOCKS5 implement Handler trait
- [ ] Fix #7: HTTP proxy implement Handler trait

### P2 - Should Fix

- [ ] Fix #8: panic! → unreachable!() in protocol handlers (15+ locations)
- [ ] Fix #9: connection_pool.rs DNS failure handling
- [ ] Fix #10: Error type consistency (thiserror vs io::Result)

### Validation Commands
```bash
cargo clippy --all 2>&1 | grep -E "^error" | wc -l  # Must be 0
cargo build --all 2>&1 | tail -5  # Must succeed
cargo test --all 2>&1 | tail -5  # Must pass
```

## Progress
| # | Issue | Status | Iteration |
|---|-------|--------|-----------|
| 1 | SAFETY comments dae-tc/packet.rs | TODO | - |
| 2 | Trivy exit-code docker.yml | TODO | - |
| 3 | LazyLock MSRV dae-api | TODO | - |
| 4 | VLESS Handler trait | TODO | - |
| 5 | VMess Handler trait | TODO | - |
| 6 | SOCKS5 Handler trait | TODO | - |
| 7 | HTTP proxy Handler trait | TODO | - |
| 8 | panic! → unreachable!() | TODO | - |
| 9 | connection_pool DNS | TODO | - |
| 10 | Error type consistency | TODO | - |
