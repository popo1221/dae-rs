# CI/CD Review Findings - dae-rs

**Review Date**: 2026-04-06  
**Reviewer**: review-cicd subagent  
**Project**: dae-rs (eBPF accelerated multi-protocol transparent proxy)

---

## Summary

| Severity | Count | Issues |
|----------|-------|--------|
| **P0** | 0 | - |
| **P1** | 2 | Trivy exit-code=0 (security scan never fails), LazyLock MSRV mismatch in dae-api |
| **P2** | 5 | Docker single-platform, deprecated Aes128Cfb, missing MSRV in Cargo.toml, no main CHANGELOG, cross-platform CI gaps |
| **P3** | 3 | Doc warnings, dead code, clippy allow-list too broad |

---

## 1. CI Pipeline Review

### ✅ Passing Checks
- **Rust Version Matrix**: CI tests both `1.75` (MSRV) and `stable` - **GOOD**
- **cargo clippy**: Running with allow-list for known issues - **PASS**
- **cargo test**: All tests pass (19 integration tests, unit tests) - **PASS**
- **cargo build**: Builds successfully - **PASS**
- **cargo tarpaulin**: Configured and available (v0.35.2) - **PASS**
- **cargo bench**: Benchmark job configured - **PASS**
- **rustsec/audit-check**: Security audit in CI workflow - **PASS**

### ⚠️ Issues

#### P1: Trivy Security Scan Never Fails Build
**File**: `.github/workflows/docker.yml:84`
```yaml
exit-code: '0'  # Report-only mode: scan results uploaded to Security tab but do not fail build
```
**Impact**: Critical vulnerabilities in Docker images will NOT fail the CI build.  
**Recommendation**: Change to `exit-code: '1'` for CRITICAL severity, or use `exit-code: '0'` only for `--ignore-unfixed` with `--severity` filter set appropriately.

---

## 2. MSRV (Minimum Supported Rust Version) Review

### ✅ Good
- MSRV declared as **1.75** in `clippy.toml`
- README.md documents Rust 1.75+ requirement
- CI matrix tests both 1.75 and stable

### ⚠️ Issues

#### P1: LazyLock MSRV Mismatch in dae-api
**Observation**: `once_cell::sync::LazyLock` is used in dae-api but requires Rust 1.80+. The MSRV is 1.75.  
**Details**: Comment in dae-api/Cargo.toml says "# Lazy initialization (MSRV 1.75 compatible)" but LazyLock needs 1.80.  
**Current Status**: Compiles on current Rust but may fail on 1.75-1.79.  
**Recommendation**: Either:
1. Update MSRV to 1.80 in clippy.toml, OR
2. Use `once_cell::sync::OnceLock` (MSRV 1.75 compatible) instead

#### P2: MSRV Not Declared in Cargo.toml
**Issue**: MSRV is only in `clippy.toml`, not in any `package.metadata.rust` section of Cargo.toml files.  
**Impact**: Dependencies won't respect MSRV constraint, `cargo update -Z minimal-versions` won't work correctly.  
**Recommendation**: Add to each crate's Cargo.toml:
```toml
[package.metadata.clippy]
msrv = "1.75"
```
Or use rustversion crate for conditional compilation.

---

## 3. Test Coverage Review

### ✅ Good
- cargo-tarpaulin is configured and available
- Coverage reports uploaded to artifacts
- 19 integration tests passing
- Unit tests in all major crates

### ⚠️ Issues

#### P2: Coverage Reports Not Actively Used
**Observation**: Coverage reports are generated and uploaded but there's no threshold enforcement.  
**Recommendation**: Add coverage gate in CI:
```yaml
- name: Check coverage threshold
  run: |
    COVERAGE=$(find coverage -name '*.json' -exec cat {} \; | jq '.result.info.lines_covered_percent')
    if (( $(echo "$COVERAGE < 50" | bc -l) )); then exit 1; fi
```

---

## 4. Documentation Review

### ✅ Good
- README.md is comprehensive with feature tables
- CHANGELOG files exist for major changes (SEC-1, EBPF refactor, etc.)
- CHANGELOG format is detailed with code examples
- Feature implementation status is clearly documented

### ⚠️ Issues

#### P2: No Main CHANGELOG.md
**Observation**: Only module-specific CHANGELOGs exist:
- CHANGELOG-CORR-2.md
- CHANGELOG-CORR-3.md
- CHANGELOG-EBPF-REFACTOR.md
- CHANGELOG-SEC-1.md
- CHANGELOG-TRACKING.md

**Impact**: No unified changelog for releases. Users must check multiple files.  
**Recommendation**: Create `CHANGELOG.md` at root with release notes linking to detailed module changelogs.

#### P3: Clippy Warnings in Documentation
```
crates/dae-protocol-shadowsocks/src/protocol.rs:17: doc_lazy_continuation
crates/dae-protocol-shadowsocks/src/server.rs:32,33: doc_nested_refdefs
```
**Recommendation**: Fix doc comment formatting.

#### P3: Dead Code Warning
```
crates/dae-protocol-hysteria2/src/hysteria2.rs:262: method `encode` is never used
```
**Recommendation**: Either use or remove.

---

## 5. Additional Findings

### P3: Broad Clippy Allow-List
**File**: `.github/workflows/ci.yml`
```yaml
-- -A clippy::should_implement_trait \
-A clippy::module_inception \
...
```
**Observation**: Many lints are suppressed. Consider addressing root causes instead.  
**Note**: Some suppressions may be valid (e.g., `should_implement_trait` for `main`).

### P2: Docker Single-Platform Build
**File**: `.github/workflows/docker.yml`
```yaml
platforms: linux/amd64
```
**Impact**: No aarch64/arm64 support for Apple Silicon or ARM servers.  
**Recommendation**: Add matrix for multiple platforms:
```yaml
platforms: linux/amd64,linux/arm64
```

### P2: Deprecated Crypto in VMess
```
warning: use of deprecated unit variant `protocol::VmessSecurity::Aes128Cfb`
```
**Impact**: CFB mode has known weaknesses. Documented but still compiled.  
**Recommendation**: Consider removing Aes128Cfb support entirely or marking as unsafe.

---

## CI/CD Pipeline Steps (Current)

1. ✅ Checkout
2. ✅ Install Rust (1.75, stable)
3. ✅ Cache cargo
4. ✅ Check formatting (`cargo fmt`)
5. ✅ Run clippy
6. ✅ Build (`cargo build`)
7. ✅ Run tests (`cargo test`)
8. ✅ Test coverage (tarpaulin)
9. ✅ Upload coverage artifacts
10. ✅ Security audit (rustsec)
11. ✅ Benchmarks (on main/master only)
12. ⚠️ Docker build (single platform)
13. ⚠️ Trivy scan (exit-code: 0, never fails)

---

## Recommendations Priority

| Priority | Action | Effort |
|----------|--------|--------|
| **P1** | Fix Trivy exit-code to fail on critical CVEs | Low |
| **P1** | Fix or document LazyLock MSRV issue | Low |
| **P2** | Add MSRV to Cargo.toml metadata | Low |
| **P2** | Multi-platform Docker builds | Medium |
| **P2** | Add coverage threshold enforcement | Medium |
| **P2** | Create main CHANGELOG.md | Low |
| **P3** | Fix doc clippy warnings | Low |
| **P3** | Address dead code | Low |

---

## Verification Commands

```bash
# Check MSRV enforcement
cargo update -Z minimal-versions 2>&1 | head -20

# Run clippy with MSRV
rustup run 1.75 cargo clippy --all

# Check test coverage
cargo tarpaulin --ignore-panics --workspace

# Verify Trivy scan
docker run --rm aquasecurity/trivy image ghcr.io/popo1221/dae-rs:latest
```
