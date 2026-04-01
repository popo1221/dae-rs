# dae-rs 功能实现任务列表

> 按优先级排序，基于架构优化设计实现

---

## 任务列表

### Phase A: 架构重构基础设施

| # | 任务 | 状态 | 依赖 | 优先级 |
|---|------|------|------|--------|
| A1 | 创建 `core/` 模块 - 统一错误类型、Context | ⏳ | - | 🔴 |
| A2 | 创建 `transport/` 模块 - Transport trait 定义 | ⏳ | A1 | 🔴 |
| A3 | 创建 `node/` 模块 - Node/NodeManager trait | ⏳ | A1 | 🔴 |
| A4 | 创建 `protocol/` 目录结构 - 协议抽象层 | ⏳ | A1 | 🔴 |
| A5 | 创建 `routing/rules/process.rs` - 进程规则 | ⏳ | A1 | 🟡 |
| A6 | 创建 `routing/rules/mac.rs` - MAC 规则 | ⏳ | A1 | 🟡 |

### Phase B: 核心功能实现

| # | 任务 | 状态 | 依赖 | 优先级 |
|---|------|------|------|--------|
| B1 | **Real Direct (must_direct)** - eBPF 直连 bypass | ⏳ | A1-A6 | 🔴 |
| B2 | **Process Name 分流** - pname() 规则 | ⏳ | A5 | 🔴 |
| B3 | **WebSocket 传输层** - WS/WSS 支持 | ⏳ | A2 | 🟡 |
| B4 | **TLS/Reality 传输层** - XTLS/Reality 支持 | ⏳ | A2 | 🟡 |
| B5 | **节点管理器 + 延迟测试** - 自动切换 | ⏳ | A3 | 🟡 |
| B6 | **Tuic v5 协议** - QUIC 代理 | ⏳ | A2, B5 | 🟢 |
| B7 | **Juicity 协议** - 高性能 UDP | ⏳ | A2, B5 | 🟢 |
| B8 | **Hysteria2 协议** - 抗干扰 | ⏳ | A2, B5 | 🟢 |
| B9 | **MAC 地址分流** - LAN 设备识别 | ⏳ | A6 | 🟢 |
| B10 | **高级 DNS 解析** - DNS 路由/防污染 | ⏳ | - | 🟢 |

---

## 当前进度

### 已完成
- Phase 1-6b (基础功能)

### 进行中
- 架构设计 (docs/ARCHITECTURE.md)

### 待开始
- Phase A1: core/ 模块

---

## 实现指南

### 每个任务的 PR 应包含:
1. 单元测试 (覆盖率 >= 80%)
2. 集成测试 (如适用)
3. 文档更新
4. 配置示例

### 代码规范:
- 遵循现有 rustfmt 配置
- 运行 cargo clippy 无警告
- 所有 public API 有文档注释

---

*最后更新: 2026-04-02*
