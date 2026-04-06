# subscription.rs Refactoring Analysis

## File Overview

- **Lines**: 2285 lines
- **Public items**: 24 (15 types, 9 functions)
- **Test lines**: ~400 lines (embedded)

## Current Structure

```
subscription.rs
├── Types (~200 lines)
│   ├── Sip008Server, Sip008Subscription (SIP008)
│   ├── SubscriptionType, SubscriptionError (shared enums)
│   ├── SubscriptionConfig, SubscriptionUpdate (shared)
│   ├── ClashProxy, ClashSubscription (Clash)
│   ├── SingBoxOutbound, SingBoxSubscription (SingBox)
│   ├── ParsedProxyUri, ProxyProtocol, NodeType (URI)
│   └── NodeConfig, NodeCapabilities (Node)
│
├── Functions (~2000 lines)
│   ├── parse_base64_subscription() → parse_uri_list()
│   ├── parse_sip008_subscription() → uri_to_node_config()
│   ├── parse_clash_yaml() → parse_uri_list()
│   ├── parse_singbox_json() → parse_uri_list()
│   ├── parse_uri_list() → extracts URIs
│   ├── uri_to_node_config() → parse_ss_uri/vmess/vless/trojan_uri()
│   ├── uris_to_node_configs()
│   ├── parse_subscription() → format detection
│   └── extract_tag()
│
└── Tests (~400 lines)
```

## Dependency Analysis

```
                    ┌──────────────────┐
                    │ uri_to_node_config │
                    └────────┬─────────┘
                             │ called by ALL format parsers
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
parse_sip008 ──────► parse_clash ──────► parse_singbox
          │                  │                  │
          │                  │                  │
          ▼                  ▼                  ▼
    parse_uri_list    parse_uri_list    parse_uri_list
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   parse_uri_list  │
                    │  (extracts URIs)  │
                    └───────────────────┘
```

## Key Finding: uri_to_node_config is the Bottleneck

`uri_to_node_config` and its 4 helper functions (parse_ss_uri, parse_vmess_uri, parse_vless_uri, parse_trojan_uri) are ~350 lines and called by ALL format parsers.

**This means:**
- SIP008 parsing needs URI parsing ✅
- Clash parsing needs URI parsing ✅
- SingBox parsing needs URI parsing ✅
- URI parsing is standalone (base) ❌

## Recommended Split Strategy

### Phase 1: Establish Directory Structure
1. Create `subscription/` directory
2. Move `subscription.rs` → `subscription/mod.rs`
3. Create empty sibling files: `sip008.rs`, `clash.rs`, `singbox.rs`, `uri.rs`, `encoding.rs`
4. Verify compilation

### Phase 2: Extract URI Types (先行)
Move to `subscription/uri.rs`:
- `ParsedProxyUri`
- `ProxyProtocol`
- `NodeType` 
- `NodeConfig`
- `NodeCapabilities`
- `parse_uri_list()`
- `uri_to_node_config()` + helpers

### Phase 3: Extract Format-Specific Parsing
Move to `subscription/sip008.rs`:
- `Sip008Server`
- `Sip008Subscription`
- `parse_sip008_subscription()`

Move to `subscription/clash.rs`:
- `ClashProxy`
- `ClashSubscription`
- `parse_clash_yaml()`

Move to `subscription/singbox.rs`:
- `SingBoxOutbound`
- `SingBoxSubscription`
- `parse_singbox_json()`

### Phase 4: Extract Encoding
Move to `subscription/encoding.rs`:
- `parse_base64_subscription()`

## Challenges

1. **Circular dependency risk**: `parse_sip008_subscription` converts to URIs then calls `uri_to_node_config`. Must move `uri_to_node_config` first.

2. **Test relocation**: Tests are in a single `#[cfg(test)]` block - need to split tests alongside code.

3. **Internal helper functions**: `parse_ss_uri`, `parse_vmess_uri`, etc. are private but used only by `uri_to_node_config`. These should move together.

## Estimated Effort

- Phase 1: 30 minutes (establish structure)
- Phase 2: 2 hours (URI types - most complex)
- Phase 3: 1 hour (format parsers - straightforward)
- Phase 4: 30 minutes (encoding)
- **Total**: ~4 hours

## Alternative: Keep as-is

Given the interdependencies, another option is to **keep subscription.rs as-is** but:
1. Add comprehensive documentation
2. Add more tests
3. Extract only clearly-separable parts (types to `subscription/types.rs`)

This provides 80% of benefit at 20% of effort.
