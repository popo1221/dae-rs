# dae-rs 目录结构重构计划 - Ralph Mode + Swarm

> 基于 Zed 多 crate 单职责架构模式
> 启动时间: 2026-04-05 11:31 GMT+8

## 项目概述

参考 Zed 仓库架构模式，重构 dae-rs 目录结构，解决当前双 workspace 结构（packages/ vs crates/）混乱的问题。

## Zed 架构核心原则

1. **Single Responsibility**: 每个 crate 只有一个职责
2. **Naming Conventions**: `*Store` 抽象接口, `*Handle` 实体引用, `*Manager` 生命周期管理
3. **分层架构**: gpui → editor → project → workspace → language → collab → lsp
4. **Entity/Context/Task**: 状态管理模式

## 当前问题

| 问题 | 影响 |
|------|------|
| `packages/` 和 `crates/` 双 workspace | 结构混乱，职责不清 |
| `socks5.rs` 27KB 单文件 | 违反 single responsibility |
| Handler trait 未统一 | 各协议各自实现 |
| `dae-proxy` ~77 文件, ~50K LOC | 过于庞大 |

## 重构任务

### Phase 1: Workspace 统一

- [ ] 清理 `crates/` 目录，统一到 `packages/`
- [ ] 统一 workspace members 配置
- [ ] 更新所有 Cargo.toml 路径引用

### Phase 2: 协议模块拆分 (参考 trojan_protocol/)

- [ ] `socks5.rs` → `socks5/`: mod.rs / handshake.rs / commands.rs / auth.rs
- [ ] `http_proxy.rs` → `http_proxy/`: mod.rs / handler.rs / connect.rs
- [ ] `shadowsocks.rs` → `shadowsocks/`: mod.rs / protocol.rs / aead.rs

### Phase 3: Handler 统一 (P1)

- [ ] 统一 Handler trait 定义
- [ ] 所有协议实现统一 Handler 接口
- [ ] 移除冗余 ProtocolHandler trait

### Phase 4: 节点管理 Zed 化

- [ ] `node/` 目录完善 `*Store` 命名
- [ ] `NodeStore` trait 统一抽象
- [ ] `NodeManager` 生命周期管理

### Phase 5: 错误层次统一

- [ ] `ProxyError` - 代理错误
- [ ] `NodeError` - 节点错误
- [ ] `EbpfError` - eBPF 错误
- [ ] `ConfigError` - 配置错误

## Swarm 团队

| Worker | 任务 | 阶段 |
|--------|------|------|
| Workspace-Worker | 清理 crates/，统一 workspace | Phase 1 |
| Socks5-Worker | 拆分 socks5.rs | Phase 2 |
| Http-Worker | 拆分 http_proxy.rs | Phase 2 |
| Shadowsocks-Worker | 拆分 shadowsocks.rs | Phase 2 |
| Handler-Worker | Handler 统一 | Phase 3 |

## Backpressure Gates

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --all` (0 warnings)
- [ ] `cargo build --all`
- [ ] `cargo test --all`

## 进度

更新于: 2026-04-05 11:31 GMT+8
