# Ralph: dae-rs 模块拆分设计

## Status: IN PROGRESS 🟡

**Started:** 2026-04-05 14:15

---

## Iteration 1 - 2026-04-05 14:15

### Status: Complete ✅

### What Was Done
- 拉取 dae-rs 最新代码 (已是最新)
- 分析 dae-proxy 模块结构 (28,967 行)
- 识别超大文件:
  - ebpf_integration/mod.rs: 1530 行
  - vless/handler.rs: 872 行
  - tuic/tuic.rs: 595 行
  - tuic/codec.rs: 624 行
- 创建 Ralph 工作区: RalphWork/
- 创建文档:
  - `RalphWork/IMPLEMENTATION_PLAN.md` - 任务规划
  - `RalphWork/SPEC.md` - 详细规格文档
  - `RalphWork/PROGRESS.md` - 本进度追踪

### Key Findings

#### 当前 Feature 状态
- dae-proxy 几乎没有 features 配置
- 所有协议都编译进单一库
- 需要从头设计 feature 结构

#### 依赖层次
```
Layer 0: core (无依赖)
Layer 1: config, metrics, logging, tracking  
Layer 2: tcp, udp, connection, connection_pool
Layer 3: protocol (抽象)
Layer 4: transport (ws, tls, grpc, quic)
Layer 5: protocol implementations
Layer 6: proxy, protocol_dispatcher
Layer 7: tun, ebpf_integration
```

#### 建议的 Feature 结构
```toml
[features]
default = ["protocol-core", "tcp", "udp", "socks5"]

# Core
protocol-core = []
tcp = ["protocol-core"]
udp = ["protocol-core"]

# Protocols
vless = ["protocol-core", "transport-tls"]
vmess = ["protocol-core", "transport-tls"]
trojan = ["protocol-core", "transport-tls"]
shadowsocks = ["protocol-core"]
hysteria2 = ["protocol-core", "transport-quic"]
juicity = ["protocol-core", "transport-quic"]
tuic = ["protocol-core", "transport-quic"]

# Transport
transport-tls = ["core"]
transport-ws = ["core"]
transport-grpc = ["core"]
transport-quic = ["core", "quinn"]
```

### Module 拆分建议

#### ebpf_integration/ → 4 子模块
- maps.rs - eBPF Map 操作 (~400行)
- session.rs - Session 管理 (~350行)
- routing.rs - 路由决策 (~300行)
- diagnostics.rs - 诊断功能 (~480行保留)

#### node/ → 7 子模块
- mod.rs, simple.rs, hash.rs, store.rs
- selector.rs, manager.rs, capability.rs, health.rs

#### protocol/ → handlers/ 子目录
- unified_handler.rs - 统一接口
- handlers/socks5.rs, vless.rs, vmess.rs, trojan.rs, shadowsocks.rs

### Validation
- 代码已拉取最新: `git pull` → Already up to date

### Next Steps (优先级排序)
1. 分析 dae-proxy/Cargo.toml 当前 features
2. 设计完整的 feature 定义
3. 开始拆分: metrics 模块作为试点
4. 验证拆分后编译和测试

### Files Changed
- Created: RalphWork/IMPLEMENTATION_PLAN.md
- Created: RalphWork/SPEC.md
- Created: RalphWork/PROGRESS.md

---

## Backlog

### High Priority
- [ ] 分析 dae-proxy/Cargo.toml 当前 features
- [ ] 设计完整的 feature 定义并写入 Cargo.toml
- [ ] 拆分 metrics 模块作为试点

### Medium Priority
- [ ] 拆分 transport 模块
- [ ] 拆分 protocol 模块
- [ ] 拆分 ebpf_integration 模块

### Low Priority
- [ ] 函数粒度优化
- [ ] 建立 Trait Hierarchy

---

## Blockers

- None

---

## Metrics

- **Code Analyzed:** 28,967 lines (dae-proxy)
- **Files Identified for Splitting:** 15+
- **Modules Identified:** 30+
- **Target Feature Groups:** 8
