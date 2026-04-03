# dae-rs Tracking (数据追踪) 方案设计

> 版本: 0.1.0  
> 日期: 2026-04-03  
> 状态: 设计方案

---

## 一、设计目标

dae-rs tracking 系统旨在提供多层次、可扩展的性能监控和数据追踪能力：

1. **连接级追踪** - 实时跟踪每个连接的流量、延迟、存活时间
2. **节点级追踪** - 统计每个代理节点的流量、成功率、延迟
3. **规则级追踪** - 记录每条规则的匹配次数和处理结果
4. **协议级追踪** - 统计各类协议的流量占比和性能指标

## 二、整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         dae-rs Tracking                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │  eBPF Layer │    │ User Space  │    │   Export    │          │
│  │  (Kernel)   │    │   (Rust)    │    │   Layer     │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│        │                  │                   │                  │
│        ▼                  ▼                   ▼                  │
│  ┌───────────┐      ┌───────────┐      ┌───────────┐            │
│  │  Packet   │      │ Connection│      │Prometheus │            │
│  │  Stats    │      │  Tracking │      │   JSON    │            │
│  └───────────┘      └───────────┘      │  InfluxDB │            │
│        │                  │            └───────────┘            │
│        │                  │                   │                  │
│        ▼                  ▼                   ▼                  │
│  ┌─────────────────────────────────────────────────────┐        │
│  │                  Tracking Storage                     │        │
│  │  ┌─────────┐  ┌──────────┐  ┌─────────┐            │        │
│  │  │PerCPU   │  │ HashMap  │  │ LpmTrie │            │        │
│  │  │Array    │  │(Sessions)│  │(Routing)│            │        │
│  │  └─────────┘  └──────────┘  └─────────┘            │        │
│  └─────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

## 三、数据指标设计

### 3.1 连接级追踪 (Connection Tracking)

每个活跃连接需要追踪以下数据：

| 指标 | 类型 | 说明 |
|------|------|------|
| `connection_key` | 5-tuple | src_ip, dst_ip, src_port, dst_port, proto |
| `packets_in` | u64 | 入方向数据包数 |
| `packets_out` | u64 | 出方向数据包数 |
| `bytes_in` | u64 | 入方向字节数 |
| `bytes_out` | u64 | 出方向字节数 |
| `start_time` | u64 | 连接建立时间 (epoch ms) |
| `last_time` | u64 | 最后活跃时间 (epoch ms) |
| `rtt_avg` | u32 | 平均往返延迟 (ms) |
| `rtt_min` | u32 | 最小往返延迟 (ms) |
| `rtt_max` | u32 | 最大往返延迟 (ms) |
| `state` | u8 | 连接状态 (NEW/ESTABLISHED/CLOSING/CLOSED) |
| `node_id` | u32 | 代理节点 ID |
| `rule_id` | u32 | 匹配的规则 ID |

### 3.2 节点级追踪 (Per-Node Stats)

每个代理节点需要追踪：

| 指标 | 类型 | 说明 |
|------|------|------|
| `node_id` | u32 | 节点唯一标识 |
| `total_requests` | u64 | 总请求数 |
| `successful_requests` | u64 | 成功请求数 |
| `failed_requests` | u64 | 失败请求数 |
| `bytes_sent` | u64 | 发送字节数 |
| `bytes_received` | u64 | 接收字节数 |
| `latency_avg` | f64 | 平均延迟 (ms) |
| `latency_p50` | f64 | P50 延迟 |
| `latency_p90` | f64 | P90 延迟 |
| `latency_p99` | f64 | P99 延迟 |
| `last_test_time` | u64 | 最后测试时间 |
| `status` | u8 | 节点状态 (UP/DOWN/DEGRADED) |

### 3.3 规则级追踪 (Per-Rule Stats)

每条规则需要追踪：

| 指标 | 类型 | 说明 |
|------|------|------|
| `rule_id` | u32 | 规则唯一标识 |
| `rule_type` | u8 | 规则类型 (Domain/IP/GeoIP/Process) |
| `rule_value` | String | 规则值 (域名/IP段等) |
| `match_count` | u64 | 匹配次数 |
| `pass_count` | u64 | Pass 动作次数 |
| `proxy_count` | u64 | Proxy 动作次数 |
| `drop_count` | u64 | Drop 动作次数 |
| `bytes_matched` | u64 | 匹配流量 (bytes) |

### 3.4 协议级追踪

| 指标 | 类型 | 说明 |
|------|------|------|
| `protocol` | u8 | 协议类型 (TCP/UDP/SOCKS5/HTTP/VLESS/VMess/...) |
| `total_packets` | u64 | 总数据包数 |
| `total_bytes` | u64 | 总字节数 |
| `tcp_stats` | StatsEntry | TCP 协议统计 |
| `udp_stats` | StatsEntry | UDP 协议统计 |
| `dns_stats` | StatsEntry | DNS 查询统计 |

### 3.5 聚合统计

| 指标 | 类型 | 说明 |
|------|------|------|
| `total_packets` | u64 | 全局数据包数 |
| `total_bytes` | u64 | 全局字节数 |
| `total_connections` | u64 | 累计连接数 |
| `active_connections` | u32 | 当前活跃连接数 |
| `total_dropped` | u64 | 丢弃数据包数 |
| `total_routed` | u64 | 路由数据包数 |
| `total_unmatched` | u64 | 未匹配数据包数 |

## 四、数据采集架构

### 4.1 eBPF 侧采集 (内核态)

**采集内容:**

```rust
// 在 XDP/TC 程序中采集
struct EbpfPacketStats {
    // 基础包统计 (eBPF 可直接计数)
    packets: u64,        // 包计数
    bytes: u64,           // 字节计数
    
    // 协议分类 (eBPF 解析包头)
    proto: u8,            // IP protocol (6=TCP, 17=UDP)
    src_port: u16,        // 源端口
    dst_port: u16,        // 目的端口
    
    // 时间戳 (使用 bpf_ktime_get_ns())
    timestamp: u64,       // 包到达时间
    
    // 路由决策 (eBPF 路由查表)
    action: u8,           // PASS/DROP/REDIRECT
    route_id: u32,        // 匹配的路由规则 ID
}
```

**eBPF 采集限制:**
- 单个包处理时间 < 10μs
- BPF stack 限制 512 bytes
- 不允许 unbounded loops
- 只能使用 limited map types

**优化策略:**
1. 使用 `BPF_MAP_TYPE_PERCPU_ARRAY` 存储计数器，避免锁竞争
2. 使用 `bpf_ringbuf_output()` 高效传输数据到用户态
3. 采样: 非所有包都记录，仅采样 1/N

### 4.2 用户态采集 (Rust)

**采集内容:**

```rust
struct UserSpaceStats {
    // 连接级 (需要用户态跟踪)
    connection_details: HashMap<ConnectionKey, ConnectionStats>,
    
    // 节点级 (节点管理器维护)
    node_stats: HashMap<NodeId, NodeStats>,
    
    // 规则级 (规则引擎维护)
    rule_stats: HashMap<RuleId, RuleStats>,
    
    // 延迟测量 (用户态才能做 RTT 测量)
    latency_samples: Vec<LatencySample>,
    
    // DNS 解析 (用户态才能做)
    dns_stats: DnsStats,
}
```

**延迟测量:**
- TCP: 使用 TCP timestamp option 计算 RTT
- UDP: 发送 ping/pong 测量延迟
- 应用层: 在代理协议中添加 timing

### 4.3 性能优化

1. **批量聚合**
   - eBPF ringbuf 批量传输
   - 用户态批量写入 maps

2. **异步处理**
   - 使用 tokio 异步处理统计更新
   - 不阻塞包处理流程

3. **采样策略**
   - 连接级: 全量跟踪
   - 包级: 采样 1/100
   - 延迟: 采样 1/10

## 五、数据存储设计

### 5.1 eBPF Map 设计

| Map 名称 | 类型 | Key | Value | 用途 |
|----------|------|-----|-------|------|
| `STATS` | PerCPUArray | u32 (index) | StatsEntry | 全局/协议统计 |
| `CONNECTION_STATS` | HashMap | SessionKey | ConnStatsEntry | 连接级统计 |
| `NODE_STATS` | HashMap | u32 (node_id) | NodeStatsEntry | 节点级统计 |
| `RULE_STATS` | HashMap | u32 (rule_id) | RuleStatsEntry | 规则级统计 |
| `ROUTING` | LpmTrie | IP prefix | RoutingEntry | IP 路由规则 |
| `SESSIONS` | HashMap | SessionKey | SessionEntry | 连接跟踪 |
| `TRACKING_EVENTS` | RingBuf | - | TrackingEvent | 事件导出 |

### 5.2 用户态数据结构

```rust
// 内存中的追踪存储
pub struct TrackingStore {
    // 连接追踪 (使用 dashmap 支持并发)
    connections: DashMap<ConnectionKey, ConnectionStats>,
    
    // 节点统计
    nodes: RwLock<HashMap<NodeId, NodeStats>>,
    
    // 规则统计
    rules: RwLock<HashMap<RuleId, RuleStats>>,
    
    // 协议统计
    protocols: RwLock<ProtocolStats>,
    
    // 时间窗口滑动统计
    windows: SlidingWindowStore,
}

impl TrackingStore {
    pub fn new() -> Self { ... }
    
    // 更新连接统计
    pub fn update_connection(&self, key: &ConnectionKey, stats: ConnectionStats) { ... }
    
    // 更新节点统计
    pub fn update_node(&self, node_id: NodeId, stats: NodeStats) { ... }
    
    // 更新规则统计
    pub fn update_rule(&self, rule_id: RuleId, matched: bool, action: RuleAction) { ... }
    
    // 获取聚合统计
    pub fn get_overall_stats(&self) -> OverallStats { ... }
    
    // 导出 Prometheus 格式
    pub fn export_prometheus(&self) -> String { ... }
}
```

### 5.3 聚合策略

```rust
// 滑动时间窗口聚合
enum AggregationWindow {
    Second,
    Minute,
    Hour,
    Day,
}

impl TrackingStore {
    // 每秒聚合一次
    fn aggregate_second(&self) { ... }
    
    // 每分钟聚合一次
    fn aggregate_minute(&self) { ... }
    
    // 清理过期数据
    fn cleanup(&self, max_age: Duration) { ... }
}
```

### 5.4 历史数据保留策略

| 数据类型 | 实时 | 分钟级 | 小时级 | 天级 |
|----------|------|--------|--------|------|
| 全局统计 | ✅ | 7 天 | 30 天 | 1 年 |
| 连接统计 | 1 小时 | - | - | - |
| 节点统计 | 1 小时 | 7 天 | 30 天 | 1 年 |
| 规则统计 | 1 小时 | 7 天 | 30 天 | - |

## 六、数据导出

### 6.1 导出格式

#### Prometheus 格式 (推荐)

```
# dae-rs global stats
dae_packets_total{proto="tcp"} 1234567
dae_packets_total{proto="udp"} 890123
dae_bytes_total 9876543210
dae_connections_active 42
dae_connections_total 567890
dae_dropped_total 1234

# dae-rs protocol stats
dae_protocol_packets_total{protocol="socks5"} 100000
dae_protocol_packets_total{protocol="http"} 50000
dae_protocol_packets_total{protocol="vless"} 200000

# dae-rs node stats
dae_node_requests_total{node="us-west-1"} 50000
dae_node_requests_success{node="us-west-1"} 49500
dae_node_bytes_sent{node="us-west-1"} 1000000000
dae_node_latency_avg{node="us-west-1"} 45.5
dae_node_latency_p99{node="us-west-1"} 120.0

# dae-rs rule stats
dae_rule_matches_total{rule_type="domain",rule="google.com"} 5000
dae_rule_actions_total{rule_type="domain",action="pass"} 3000
dae_rule_actions_total{rule_type="domain",action="proxy"} 2000

# dae-rs connection stats
dae_connection_bytes_in{src_ip="192.168.1.100"} 1000000
dae_connection_bytes_out{src_ip="192.168.1.100"} 500000
```

#### JSON 格式 (用于 API)

```json
{
  "timestamp": 1743667200000,
  "overall": {
    "packets_total": 1234567,
    "bytes_total": 9876543210,
    "connections_active": 42,
    "connections_total": 567890
  },
  "protocols": {
    "tcp": { "packets": 1000000, "bytes": 8000000000 },
    "udp": { "packets": 234567, "bytes": 1876543210 }
  },
  "nodes": {
    "us-west-1": {
      "requests": 50000,
      "success": 49500,
      "latency_avg": 45.5
    }
  }
}
```

### 6.2 导出接口

| 接口 | 格式 | 说明 |
|------|------|------|
| `GET /metrics` | Prometheus | Prometheus 抓取 |
| `GET /api/stats` | JSON | REST API |
| `WebSocket /ws/stats` | JSON | 实时推送 |
| `GET /api/stats/export` | JSON/CSV | 文件导出 |

### 6.3 导出配置

```toml
[tracking]
enabled = true
export_interval = 10  # 秒

[tracking.export]
# Prometheus 导出
[tracking.export.prometheus]
enabled = true
port = 9090
path = "/metrics"

# JSON API 导出
[tracking.export.json]
enabled = true
port = 8080
path = "/api/stats"

# WebSocket 实时推送
[tracking.export.websocket]
enabled = true
path = "/ws/stats"
