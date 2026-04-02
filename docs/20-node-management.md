# 节点管理与健康检查 - 功能描述

## 概述
节点管理模块 (Zed 风格) 提供节点的抽象、生命周期管理、选择策略和健康检查。

## 模块结构

### Zed 命名约定
```
node/       # 核心 Node trait 和 NodeId
manager/    # NodeManager trait (接口)
selector/   # NodeSelector 实现
health/     # HealthChecker 健康检查
simple/     # 简单实现 (SimpleNode, SimpleNodeManager)
store/      # NodeStore (Zed 风格别名)
```

## 核心接口

### Node trait
```rust
pub trait Node: Send + Sync {
    fn id(&self) -> NodeId;
    fn name(&self) -> &str;
    fn address(&self) -> &str;
    fn port(&self) -> u16;
    fn node_type(&self) -> NodeType;
    fn is_enabled(&self) -> bool;
    fn set_enabled(&self, enabled: bool);
}
```

### NodeId
```rust
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NodeId(pub String);
```

### NodeManager trait
```rust
pub trait NodeManager: Send + Sync {
    fn get_node(&self, id: &NodeId) -> Option<Arc<dyn Node>>;
    fn get_all_nodes(&self) -> Vec<Arc<dyn Node>>;
    fn add_node(&self, node: Arc<dyn Node>) -> Result<(), NodeError>;
    fn remove_node(&self, id: &NodeId) -> Result<(), NodeError>;
    fn update_node(&self, node: Arc<dyn Node>) -> Result<(), NodeError>;
}
```

### NodeSelector trait
```rust
pub trait NodeSelector: Send + Sync {
    fn select(&self, ctx: &SelectionContext) -> Option<Arc<dyn Node>>;
    fn get_policy(&self) -> SelectionPolicy;
}
```

### SelectionPolicy
```rust
#[derive(Debug, Clone, Copy)]
pub enum SelectionPolicy {
    Random,
    RoundRobin,
    LeastLatency,
    WeightedRoundRobin,
}
```

## 健康检查

### HealthChecker trait
```rust
pub trait HealthChecker: Send + Sync {
    fn check(&self, node: &dyn Node) -> Future<Output = HealthCheckResult>;
    fn start_periodic_check(&self, interval: Duration);
}
```

### HealthCheckResult
```rust
pub struct HealthCheckResult {
    pub node_id: NodeId,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
    pub checked_at: SystemTime,
}
```

### HealthCheckerConfig
```rust
pub struct HealthCheckerConfig {
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub failure_threshold: u32,
    pub success_threshold: u32,
}
```

## 简单实现

### SimpleNode
```rust
pub struct SimpleNode {
    id: NodeId,
    name: String,
    address: String,
    port: u16,
    node_type: NodeType,
    enabled: bool,
}
```

### SimpleNodeManager
```rust
pub struct SimpleNodeManager {
    nodes: RwLock<HashMap<NodeId, Arc<dyn Node>>>,
    selector: Arc<dyn NodeSelector>,
}
```

### LatencyMonitor
```rust
pub struct LatencyMonitor {
    history: RwLock<HashMap<NodeId, Vec<LatencyTestResult>>>,
}

pub struct LatencyTestResult {
    pub node_id: NodeId,
    pub latency_ms: u64,
    pub timestamp: SystemTime,
}
```

## 选择策略

### DefaultNodeSelector
```rust
pub struct DefaultNodeSelector {
    policy: SelectionPolicy,
    weights: HashMap<NodeId, u32>,
}
```

| 策略 | 说明 |
|------|------|
| `Random` | 随机选择 |
| `RoundRobin` | 轮询选择 |
| `LeastLatency` | 选择延迟最低的节点 |
| `WeightedRoundRobin` | 按权重轮询 |

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `health_check.interval_secs` | u64 | 30 | 健康检查间隔 |
| `health_check.timeout_secs` | u64 | 5 | 检查超时 |
| `health_check.failure_threshold` | u32 | 3 | 失败阈值 |
| `health_check.success_threshold` | u32 | 1 | 成功阈值 |
| `selection.policy` | SelectionPolicy | LeastLatency | 选择策略 |

## 接口设计

### 公开方法
```rust
// NodeManager
fn get_node(&self, id: &NodeId) -> Option<Arc<dyn Node>>
fn get_all_nodes(&self) -> Vec<Arc<dyn Node>>
fn add_node(&self, node: Arc<dyn Node>) -> Result<(), NodeError>
fn remove_node(&self, id: &NodeId) -> Result<(), NodeError>

// NodeSelector
fn select(&self, ctx: &SelectionContext) -> Option<Arc<dyn Node>>
fn get_policy(&self) -> SelectionPolicy

// HealthChecker
fn check(&self, node: &dyn Node) -> HealthCheckResult
fn start_periodic_check(&self, interval: Duration)

// LatencyMonitor
fn record_latency(&self, node_id: &NodeId, latency_ms: u64)
fn get_average_latency(&self, node_id: &NodeId) -> Option<u64>
```

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `NodeNotFound` | 节点不存在 | 添加节点 |
| `NodeDisabled` | 节点被禁用 | 启用节点 |
| `HealthCheckFailed` | 健康检查失败 | 标记节点不可用 |
| `SelectionFailed` | 无可用节点 | 使用 fallback |

## 安全性考虑

1. **故障转移**: 节点失败时自动切换到其他节点
2. **健康检查**: 定期检查节点可用性
3. **延迟追踪**: 记录历史延迟用于选择优化
4. **权重控制**: 可配置节点权重进行流量分配
