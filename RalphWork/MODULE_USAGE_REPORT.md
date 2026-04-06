# dae-rs Protocol Crate Usage Report

**Generated:** 2026-04-06  
**Workspace:** /root/.openclaw/workspace/dae-rs

---

## Executive Summary

This report analyzes the usage and dependencies of the 11 `dae-protocol-*` crates in the dae-rs workspace.

### Protocol Crate Inventory

| Crate | Status | Dependencies |
|-------|--------|--------------|
| `dae-protocol-core` | ✅ Active | Used by 7 protocol crates |
| `dae-protocol-http_proxy` | ✅ Active | Used by dae-proxy |
| `dae-protocol-hysteria2` | ✅ Optional | Used by dae-proxy (QUIC, optional) |
| `dae-protocol-juicity` | ✅ Optional | Used by dae-proxy (QUIC, optional) |
| `dae-protocol-shadowsocks` | ✅ Active | Used by dae-proxy |
| `dae-protocol-socks4` | ✅ Active | Used by dae-proxy |
| `dae-protocol-socks5` | ✅ Active | Used by dae-proxy |
| `dae-protocol-trojan` | ✅ Active | Used by dae-proxy |
| `dae-protocol-tuic` | ✅ Optional | Used by dae-proxy (QUIC, optional) |
| `dae-protocol-vless` | ✅ Active | Used by dae-proxy |
| `dae-protocol-vmess` | ✅ Active | Used by dae-proxy |

---

## Dependency Matrix

```
                          dae-proxy
                          ├─ socks4  (required)
                          ├─ socks5  (required)
                          ├─ http_proxy (required)
                          ├─ shadowsocks (required)
                          ├─ trojan  (required)
                          ├─ vless   (required)
                          ├─ vmess   (required)
                          ├─ hysteria2 (optional, QUIC)
                          ├─ juicity (optional, QUIC)
                          └─ tuic    (optional, QUIC)
```

### Detailed Dependency Table

| Protocol Crate | Used By | Type | QUIC | Core Dependency |
|----------------|---------|------|------|----------------|
| `dae-protocol-core` | hysteria2, juicity, shadowsocks, trojan, tuic, vless, vmess | Internal | No | Yes - base trait |
| `dae-protocol-http_proxy` | dae-proxy | Required | No | No |
| `dae-protocol-hysteria2` | dae-proxy | Optional | Yes | Yes |
| `dae-protocol-juicity` | dae-proxy | Optional | Yes | Yes |
| `dae-protocol-shadowsocks` | dae-proxy | Required | No | Yes |
| `dae-protocol-socks4` | dae-proxy | Required | No | No |
| `dae-protocol-socks5` | dae-proxy | Required | No | No |
| `dae-protocol-trojan` | dae-proxy | Required | No | Yes |
| `dae-protocol-tuic` | dae-proxy | Optional | Yes | Yes |
| `dae-protocol-vless` | dae-proxy | Required | No | Yes |
| `dae-protocol-vmess` | dae-proxy | Required | No | Yes |

---

## Feature Gate Configuration

### dae-proxy/Cargo.toml

```toml
[features]
# QUIC-based protocols (optional - quinn adds ~2-3MB binary size)
protocol-hysteria2 = ["quinn", "dae-protocol-hysteria2/quic"]
protocol-tuic = ["quinn"]
protocol-juicity = ["quinn", "dae-protocol-juicity"]
```

### Dependency Declarations

```toml
# Always included (required)
dae-protocol-socks4 = { path = "../dae-protocol-socks4" }
dae-protocol-socks5 = { path = "../dae-protocol-socks5" }
dae-protocol-http_proxy = { path = "../dae-protocol-http_proxy" }
dae-protocol-shadowsocks = { path = "../dae-protocol-shadowsocks" }
dae-protocol-trojan = { path = "../dae-protocol-trojan" }
dae-protocol-vless = { path = "../dae-protocol-vless" }
dae-protocol-vmess = { path = "../dae-protocol-vmess" }

# Optional (QUIC-based)
dae-protocol-hysteria2 = { path = "../dae-protocol-hysteria2", optional = true }
dae-protocol-juicity = { path = "../dae-protocol-juicity", optional = true }
dae-protocol-tuic = { path = "../dae-protocol-tuic", optional = true }
```

---

## Usage Analysis by Crate

### 1. dae-protocol-core

**Purpose:** Core protocol traits (Handler, HandlerConfig) for unified protocol interface

**Used by:**
- `dae-protocol-hysteria2` (internal dependency)
- `dae-protocol-juicity` (internal dependency)
- `dae-protocol-shadowsocks` (internal dependency)
- `dae-protocol-trojan` (internal dependency)
- `dae-protocol-tuic` (internal dependency)
- `dae-protocol-vless` (internal dependency)
- `dae-protocol-vmess` (internal dependency)

**Import path:** `dae_protocol_core::Handler`

---

### 2. dae-protocol-http_proxy

**Purpose:** HTTP CONNECT proxy protocol handler

**Used by:**
- `crates/dae-proxy/Cargo.toml` (required dependency)
- `crates/dae-proxy/src/lib.rs`: `pub use dae_protocol_http_proxy as http_proxy;`
- `crates/dae-proxy/src/lib.rs`: `pub use dae_protocol_http_proxy::{HttpProxyHandler, HttpProxyServer};`

**Feature gate:** None (always enabled)

**Exports:**
- `HttpProxyHandler`
- `HttpProxyServer`

---

### 3. dae-protocol-hysteria2

**Purpose:** Hysteria2 QUIC-based proxy protocol

**Used by:**
- `crates/dae-proxy/Cargo.toml` (optional, requires QUIC feature)
- `crates/dae-proxy/src/lib.rs`: `#[cfg(feature = "protocol-hysteria2")]`

**Feature gate:** `protocol-hysteria2` (enables quinn dependency)

**Exports:**
- `Hysteria2Config`
- `Hysteria2Error`
- `Hysteria2Handler`
- `Hysteria2Server`

---

### 4. dae-protocol-juicity

**Purpose:** Juicity QUIC-based proxy protocol

**Used by:**
- `crates/dae-proxy/Cargo.toml` (optional, requires QUIC feature)
- `crates/dae-proxy/src/lib.rs`: `#[cfg(feature = "protocol-juicity")]`

**Feature gate:** `protocol-juicity` (enables quinn dependency)

**Exports:**
- `JuicityAddress`
- `JuicityCodec`
- `JuicityCommand`
- `JuicityFrame`
- `CongestionControl`
- `JuicityClient`
- `JuicityConfig`
- `JuicityConnection`
- `JuicityError`
- `JuicityHandler`
- `JuicityServer`

---

### 5. dae-protocol-shadowsocks

**Purpose:** Shadowsocks proxy protocol (AEAD, SSR, plugins)

**Used by:**
- `crates/dae-proxy/Cargo.toml` (required dependency)
- `crates/dae-proxy/src/lib.rs`: `pub use dae_protocol_shadowsocks as shadowsocks;`

**Feature gate:** None (always enabled)

**Exports:**
- `ShadowsocksHandler`
- `ShadowsocksServer`
- `SsCipherType`
- `SsClientConfig`
- `SsServerConfig`
- `ObfsConfig`
- `ObfsHttp`
- `ObfsMode`
- `ObfsStream`
- `ObfsTls`
- `V2rayConfig`
- `V2rayMode`
- `V2rayPlugin`
- `V2rayStream`
- `SsrClientConfig`
- `SsrHandler`
- `SsrObfs`
- `SsrObfsHandler`
- `SsrProtocol`
- `SsrServerConfig`

---

### 6. dae-protocol-socks4

**Purpose:** SOCKS4/SOCKS4a proxy protocol

**Used by:**
- `crates/dae-proxy/Cargo.toml` (required dependency)
- `crates/dae-proxy/src/lib.rs`: `pub use dae_protocol_socks4::{...}`

**Feature gate:** None (always enabled)

**Exports:**
- `Socks4Address`
- `Socks4Command`
- `Socks4Config`
- `Socks4Reply`
- `Socks4Request`
- `Socks4Server`

---

### 7. dae-protocol-socks5

**Purpose:** SOCKS5 proxy protocol with authentication support

**Used by:**
- `crates/dae-proxy/Cargo.toml` (required dependency)
- `crates/dae-proxy/src/lib.rs`: `pub use dae_protocol_socks5::{...}`
- `crates/dae-proxy/src/protocol_dispatcher.rs`: Used for protocol detection

**Feature gate:** None (always enabled)

**Exports:**
- `Socks5Address`
- `Socks5Handler`
- `Socks5HandlerConfig`
- `Socks5Server`
- `auth::{...}`
- `commands::Socks5Command`
- `handshake::Handshake`
- `reply::Socks5Reply`

---

### 8. dae-protocol-trojan

**Purpose:** Trojan proxy protocol

**Used by:**
- `crates/dae-proxy/Cargo.toml` (required dependency)
- `crates/dae-proxy/src/lib.rs`: `pub use dae_protocol_trojan as trojan_protocol;`

**Feature gate:** None (always enabled)

**Exports:**
- `TrojanAddressType`
- `TrojanClientConfig`
- `TrojanCommand`
- `TrojanHandler`
- `TrojanServer`
- `TrojanServerConfig`
- `TrojanTargetAddress`
- `TrojanTlsConfig`

---

### 9. dae-protocol-tuic

**Purpose:** TUIC QUIC-based proxy protocol

**Used by:**
- `crates/dae-proxy/Cargo.toml` (optional, requires QUIC feature)
- `crates/dae-proxy/src/lib.rs`: `#[cfg(feature = "protocol-tuic")]`

**Feature gate:** `protocol-tuic` (enables quinn dependency)

**Exports:**
- `TuicCodec`
- `TuicCommand`
- `TuicCommandType`
- `TuicClient`
- `TuicConfig`
- `TuicError`
- `TuicHandler`
- `TuicServer`

---

### 10. dae-protocol-vless

**Purpose:** VLESS proxy protocol with XTLS/XHTTP support

**Used by:**
- `crates/dae-proxy/Cargo.toml` (required dependency)
- `crates/dae-proxy/src/lib.rs`: `pub use dae_protocol_vless as vless;`

**Feature gate:** None (always enabled)

**Exports:**
- `VlessAddressType`
- `VlessClientConfig`
- `VlessCommand`
- `VlessHandler`
- `VlessRealityConfig`
- `VlessServer`
- `VlessServerConfig`
- `VlessTargetAddress`
- `VlessTlsConfig`

---

### 11. dae-protocol-vmess

**Purpose:** VMess proxy protocol

**Used by:**
- `crates/dae-proxy/Cargo.toml` (required dependency)
- `crates/dae-proxy/src/lib.rs`: `pub use dae_protocol_vmess as vmess;`

**Feature gate:** None (always enabled)

**Exports:**
- `VmessAddressType`
- `VmessClientConfig`
- `VmessCommand`
- `VmessHandler`
- `VmessSecurity`
- `VmessServer`
- `VmessServerConfig`
- `VmessTargetAddress`

---

## Unused Dependencies

**Finding:** No unused dependencies detected.

All 11 protocol crates are actively used by `dae-proxy` (directly or via feature gates).

### dae-relay Crate

Note: `dae-relay` exists as a separate crate (shared relay utilities) but is **not currently used** by any dae-protocol-* crates. This is a potential refactoring opportunity to:
1. Extract duplicated `relay_bidirectional` functions from protocol crates
2. Consolidate in `dae-relay`
3. Have protocol crates depend on `dae-relay`

---

## Binary Size Impact

| Protocol Type | Feature Gate | QUIC Dependency | Binary Impact |
|---------------|--------------|-----------------|---------------|
| SOCKS4/5 | None | No | ~0MB |
| HTTP Proxy | None | No | ~0MB |
| Shadowsocks | None | No | ~0MB |
| Trojan | None | No | ~0MB |
| VLESS | None | No | ~0MB |
| VMess | None | No | ~0MB |
| Hysteria2 | `protocol-hysteria2` | Yes | ~2-3MB |
| Juicity | `protocol-juicity` | Yes | ~2-3MB |
| TUIC | `protocol-tuic` | Yes | ~2-3MB |

**Recommendation:** Keep QUIC protocols as optional features to minimize binary size for basic deployments.

---

## Recommendations

1. **Consolidate relay code:** Extract duplicated `relay_bidirectional` from http_proxy, socks5, vless, vmess, trojan, shadowsocks into `dae-relay`

2. **Standardize Handler trait:** All 10 protocol crates should implement the canonical `Handler` trait from `dae-protocol-core`

3. **Optional dependencies:** Current QUIC feature design is correct - minimizes binary size

4. **Error handling:** Consider using `thiserror` consistently across all protocol crates (currently inconsistent)
