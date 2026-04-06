# Ralph Mode: dae-rs Review Round 2

**Started:** 2026-04-06 09:23 GMT+8

## Target Issues

### P2 Issues
1. **Replace panic! with unreachable!()** in protocol handlers (15+ locations)
   - dae-proxy/src/juicity/codec.rs (4)
   - dae-proxy/src/proxy/mod.rs (1)
   - dae-proxy/src/shadowsocks/protocol.rs (2)
   - dae-proxy/src/trojan_protocol/protocol.rs (2)
   - dae-proxy/src/vmess/mod.rs (6)

2. **Handle DNS failure gracefully** in `connection_pool.rs:256`
   - Replace `expect()` with proper error handling

### P3 Issues
1. Fix doc warnings in dae-protocol-shadowsocks
2. Address deprecated Aes128Cfb usage
3. Unify error handling across protocol crates

## Workers
| Worker | Task | Status |
|--------|------|--------|
| ralph-fix-panic-r2 | Replace panic! with unreachable!() | 🔄 |
| ralph-fix-dns | DNS failure handling in connection_pool | 🔄 |
| ralph-fix-docs | Fix doc warnings | 🔄 |

## Progress
- [ ] panic! → unreachable!() (15+ locations)
- [ ] DNS failure handling
- [ ] Doc warnings
