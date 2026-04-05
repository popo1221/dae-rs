# CHANGELOG-CORR-2

## CORR-2: Fix `accept_invalid_cert` configuration field not being used

**Date:** 2026-04-05
**Issue:** CORR-2
**Severity:** Medium

### Problem

The `accept_invalid_cert` field was defined in `TlsConfig` (packages/dae-proxy/src/transport/tls.rs) but was never actually checked or used in the code. The `TlsTransport::dial()` method would return a raw TCP stream without any TLS certificate verification logic.

### Root Cause

The `TlsConfig::accept_invalid_cert` field was added to the configuration structure with a builder method `accept_invalid_cert()`, but there was no code that actually checked the value of this field and acted on it.

### Fix

Modified `TlsTransport::dial()` in `packages/dae-proxy/src/transport/tls.rs` to:

1. **Check the `accept_invalid_cert` flag** when establishing connections in standard TLS mode
2. **Log appropriate warnings** when the flag is set:
   - In debug builds: `warn!()` about insecure certificate verification being skipped
   - In release builds: `tracing::error!()` about the critical security implication
3. **Document the limitation**: Standard TLS mode in this transport returns a raw TCP stream; TLS verification must be handled at a higher layer or with a proper TLS library

### Security Notes

- **Warning for production**: When `accept_invalid_cert` is enabled in release builds, an error-level log is emitted to catch attention
- **Debug vs Release**: Debug builds use `warn!()` while release builds use `tracing::error!()` to ensure administrators notice the insecure configuration
- **Reality mode**: The `accept_invalid_cert` flag does not apply to Reality mode, which uses public key pinning instead of certificate chain validation

### Files Changed

- `packages/dae-proxy/src/transport/tls.rs`
  - Added `tracing::{debug, warn}` imports
  - Modified `dial()` method to check `accept_invalid_cert` and log appropriate messages

### Limitations

The current implementation is a partial fix. The `accept_invalid_cert` flag is now checked and logged, but:

1. Standard TLS mode still returns a raw TCP stream without actual TLS handshake
2. No actual certificate verification is performed (or skipped)
3. Full implementation would require integrating a TLS library (e.g., rustls) to perform proper TLS handshakes with configurable certificate verification

A complete fix would involve integrating rustls with tokio-rustls for proper async TLS support.

### Testing

- `cargo check` passes
- No new compilation errors introduced
- Existing tests continue to pass
