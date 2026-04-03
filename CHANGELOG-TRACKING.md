# Changelog - dae-rs Tracking Design

## v0.2.0 | 2026-04-03

### ✨ 新增

#### Tracking 数据追踪方案
- **设计方案文档**: `docs/TRACKING_DESIGN.md` - 完整的追踪系统设计方案
  - 连接级追踪 (Connection Tracking)
  - 节点级追踪 (Per-Node Stats)
  - 规则级追踪 (Per-Rule Stats)
  - 协议级追踪 (Protocol Stats)

#### 数据结构实现
- **dae-proxy/src/tracking/** - 用户态追踪模块
  - `types.rs` - 追踪数据类型定义
  - `maps.rs` - eBPF Map 类型定义
  - `store.rs` - 追踪数据存储

- **dae-ebpf-common/src/tracking.rs** - 内核态追踪类型

#### 配置支持
- **dae-config/src/tracking.rs** - 追踪配置结构
  - `TrackingConfig` - 追踪主配置
  - `TrackingExportConfig` - 导出配置 (Prometheus/JSON/WebSocket)
  - `TrackingSamplingConfig` - 采样配置
  - `TrackingProtocolsConfig` - 协议追踪配置
  - `TrackingRulesConfig` - 规则追踪配置
  - `TrackingNodesConfig` - 节点追踪配置

- **config/tracking.example.toml** - 追踪配置示例

#### 关键数据结构
- `ConnectionKey` - 5-tuple 连接键
- `ConnectionStatsEntry` - 连接统计
- `NodeStatsEntry` - 节点统计
- `RuleStatsEntry` - 规则统计
- `ProtocolStatsEntry` - 协议统计
- `OverallStats` - 全局统计
- `TrackingMetrics` - Prometheus 导出格式

#### eBPF Map 设计
- `TRACKING_STATS` - PerCPUArray 全局统计
- `CONNECTION_STATS` - HashMap 连接统计
- `NODE_STATS` - HashMap 节点统计
- `RULE_STATS` - HashMap 规则统计
- `TRACKING_EVENTS` - RingBuf 事件导出

#### 数据导出
- Prometheus 格式导出
- JSON 格式导出
- WebSocket 实时推送

### 🔧 修改

- `dae-proxy/src/node/selector.rs` - 修复重复 `new()` 定义 bug
- `dae-config/src/lib.rs` - 添加 TrackingConfig 到 Config 结构
- `dae-ebpf-common/src/lib.rs` - 导出 tracking 模块

### 📝 设计要点

1. **分层采集**: eBPF 内核态采集 + 用户态聚合
2. **高性能**: PerCPUArray 避免锁竞争, RingBuf 高效事件传输
3. **可扩展**: 模块化设计, 支持多种导出格式
4. **低损耗**: 采样策略减少性能影响
