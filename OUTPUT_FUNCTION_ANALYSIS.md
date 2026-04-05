# dae-rs 输出功能分析报告

> 分析日期: 2026-04-05

---

## 一、Metrics 指标分析

### 1.1 PRD 需求 vs 实现对照

| PRD 需求 | 类型 | 实现状态 | 实际指标名 | 说明 |
|----------|------|---------|-----------|------|
| `dae_connections_total` | Counter | ✅ | `dae_connection_total` | 命名略有差异（无 s），语义相同 |
| `dae_bytes_sent` | Counter | ✅ | `dae_bytes_sent_total` | 带 `total` 后缀，带 `transport` label |
| `dae_bytes_received` | Counter | ✅ | `dae_bytes_received_total` | 带 `total` 后缀，带 `transport` label |
| `dae_active_connections` | Gauge | ✅ | `dae_active_connections` | 精确匹配，含 TCP/UDP 细分 gauge |
| `dae_node_latency` | Histogram | ✅ | `dae_node_latency_seconds` | Histogram 已实现，另有 Gauge 版本 |
| `dae_dns_resolution` | Counter | ✅ | `dae_dns_resolutions_total` | 带 `total` 后缀，带 `result` label |
| `dae_rule_match` | Counter | ✅ | `dae_rule_matches_total` | 带 `total` 后缀，带 `rule_type` label |

**结论**: 全部 7 项核心指标均已实现，指标命名规范略有差异（PRD 描述偏简洁，实际实现更规范）。

### 1.2 已实现指标详细清单

#### Counter（计数器）
| 指标名 | 标签 | 说明 |
|--------|------|------|
| `dae_connection_total` | — | 总连接数 |
| `dae_bytes_sent_total` | `transport` | 按传输层分类的发送字节 |
| `dae_bytes_received_total` | `transport` | 按传输层分类的接收字节 |
| `dae_rule_matches_total` | `rule_type` | 按规则类型统计的规则匹配次数 |
| `dae_dns_resolutions_total` | `result` | DNS 解析次数（按结果分类） |
| `dae_errors_total` | `error_type` | 错误次数（按错误类型分类） |
| `dae_node_latency_tests_total` | — | 节点延迟测试次数 |

#### Gauge（仪表）
| 指标名 | 标签 | 说明 |
|--------|------|------|
| `dae_active_connections` | — | 当前活跃连接总数 |
| `dae_active_tcp_connections` | — | TCP 活跃连接数 |
| `dae_active_udp_connections` | — | UDP 活跃连接数 |
| `dae_connection_pool_size` | — | 连接池当前大小 |
| `dae_node_count` | `status` | 按状态分类的节点数量 |
| `dae_node_latency_ms` | `node_id` | 节点延迟（毫秒，Gauge 版） |
| `dae_memory_usage_bytes` | — | 内存使用量（字节） |
| `dae_ebpf_map_entries` | `map_name` | eBPF Map 条目数 |

#### Histogram（直方图）
| 指标名 | 标签 | 说明 |
|--------|------|------|
| `dae_connection_duration_seconds` | `protocol` | 连接持续时间分布 |
| `dae_request_size_bytes` | `direction` | 请求大小分布 |
| `dae_response_time_seconds` | `transport` | 响应时间分布 |
| `dae_dns_resolution_latency_seconds` | — | DNS 解析延迟分布 |
| `dae_ebpf_latency_seconds` | `operation` | eBPF 操作延迟分布 |
| `dae_rule_match_latency_seconds` | — | 规则匹配延迟分布 |
| `dae_node_latency_seconds` | `node_id` | 节点延迟分布（直方图版） |

### 1.3 功能缺失

**无关键缺失**。Metrics 模块实现完整，超出 PRD 需求（额外实现了 Histogram 多维度指标）。

**次要观察**:
- PRD 中 `dae_node_latency` 描述为 Histogram，实际同时提供了 Histogram 和 Gauge 两个版本，功能更丰富
- PRD 指标名不带 `total` 后缀（如 `dae_connections_total`），实际实现为 `dae_connection_total`，命名略有不同但语义等价

---

## 二、Tracking 追踪分析

### 2.1 实现状态

Tracking 模块位于 `packages/dae-proxy/src/tracking/`，包含三个核心 Store：

| Store | 状态 | 说明 |
|-------|------|------|
| `ConnectionTrackingStore` | ✅ 已实现 | 5-tuple 连接追踪，HashMap+RwLock 实现 |
| `NodeTrackingStore` | ✅ 已实现 | 节点统计（延迟、成功率、请求数等） |
| `RuleTrackingStore` | ✅ 已实现 | 规则匹配统计（pass/proxy/drop 计数） |

额外实现：
- `TrackingStore` 聚合层：整合连接/节点/规则/协议/总体统计
- `TrackingMetrics`：提供 Prometheus 格式导出
- eBPF Map 类型定义（`maps.rs`）：`EbpfConnectionKey`、`EbpfStatsEntry` 等 C 兼容结构

### 2.2 关键数据结构

- **ConnectionKey**: 5-tuple（src_ip, dst_ip, src_port, dst_port, proto）
- **ConnectionStatsEntry**: 连接级统计（packets_in/out, bytes_in/out, RTT, state, node_id, rule_id）
- **NodeStatsEntry**: 节点级统计（latency_p50/p90/p99, success_rate, bytes sent/received）
- **RuleStatsEntry**: 规则级统计（match_count, pass/proxy/drop count, bytes_matched）
- **ProtocolStats**: TCP/UDP/ICMP 分协议统计
- **OverallStats**: 全局统计（packets_total, bytes_total, connections_total, dropped/routed/unmatched）

### 2.3 功能缺失

**无关键缺失**。Tracking 模块完整实现了 PRD 要求的全部追踪数据结构。

**已知限制**（代码注释中标注）：
- `store.rs` 使用 `RwLock<HashMap>` 而非 `dashmap`，issue #66 跟踪性能优化
- 百分位数计算为简化版本，非 HDRHistogram 精确实现

---

## 三、Control 接口分析

### 3.1 PRD 需求 vs 实现对照

| PRD 命令 | 实现状态 | 实现位置 | 说明 |
|----------|---------|---------|------|
| `Status` | ✅ | `control.rs::process_command` | 返回 `ProxyStatus` |
| `Reload` | ✅ | `control.rs::process_command` | 触发配置热重载（桩函数） |
| `Stats` | ✅ | `control.rs::process_command` | 返回 `ProxyStats` |
| `Shutdown` | ✅ | `control.rs::process_command` | 优雅关闭（桩函数） |
| `TestNode` | ✅ | `control.rs::process_command` | 测试节点连通性（桩函数） |
| `Version` | ✅ | `control.rs::process_command` | 返回 `CARGO_PKG_VERSION` |
| `Help` | ✅ | `control.rs::process_command` | 返回帮助文本 |

**结论**: 全部 7 项控制命令均已实现，接口定义与 PRD 完全一致。

### 3.2 响应类型完整性

| PRD 响应 | 实现状态 |
|----------|---------|
| `Ok(String)` | ✅ |
| `Error(String)` | ✅ |
| `Stats(ProxyStats)` | ✅ |
| `Status(ProxyStatus)` | ✅ |
| `TestResult(NodeTestResult)` | ✅ |
| `Version(String)` | ✅ |

### 3.3 功能缺失

**命令层无缺失**。

**实现层桩函数**（命令已注册但功能未完全实现）：
- `Reload`: 代码中仅返回 "Configuration reload initiated"，未真正触发配置重载
- `TestNode`: 返回固定的模拟结果（`latency_ms: Some(42)`），未真正测试节点
- 辅助函数 `rules_loaded()`, `rule_count()`, `node_count()` 均为硬编码返回值（`true/0/0`）

---

## 四、REST API 分析

### 4.1 PRD 需求 vs 实现对照

| PRD 端点 | 方法 | 实现状态 | 实际路径 | 说明 |
|----------|------|---------|---------|------|
| `/api/nodes` | GET | ✅ | `/api/nodes` | 节点列表 |
| `/api/nodes/{id}` | GET | ✅ | `/api/nodes/:id` | 节点详情 |
| `/api/nodes/test` | POST | ⚠️ 部分 | `/api/nodes/:id/test` | PRD 无 `{id}`，实际实现更 RESTful |
| `/api/rules` | GET | ✅ | `/api/rules` | 规则列表 |
| `/api/config` | GET | ✅ | `/api/config` | 获取配置 |
| `/api/config` | PUT | ✅ | `/api/config` | 更新配置（部分字段） |
| `/api/stats` | GET | ✅ | `/api/stats` | 统计信息 |
| `/health` | GET | ⚠️ | `/api/health` | **路径不匹配** |
| `/ws` | WS | ⚠️ | 独立 router | **未集成到主 API Server** |

### 4.2 已实现端点详情

**节点管理** (`routes/nodes.rs`):
- `GET /api/nodes` → `list_nodes()`
- `GET /api/nodes/:id` → `get_node()`
- `POST /api/nodes/:id/test` → `test_node()`（模拟延迟测试）

**规则管理** (`routes/rules.rs`):
- `GET /api/rules` → `list_rules()`
- `GET /api/rules/summary` → `rules_summary()`（额外端点，PRD 未提及）

**配置管理** (`routes/config.rs`):
- `GET /api/config` → `get_config()`
- `PUT /api/config` → `update_config()`（部分字段支持：socks5_listen, http_listen, ebpf_enabled）

**统计与健康** (`routes/stats.rs`):
- `GET /api/stats` → `get_stats()`
- `GET /api/health` → `health_check()`（路径与 PRD 不一致）

**WebSocket** (`websocket.rs`):
- `/ws` 端点已实现，但使用独立 router，未与主 API Server (`server.rs`) 集成
- 提供 `DashboardState` + broadcast channel 实时推送
- 支持 `ConnectionNew`, `ConnectionClose`, `StatsUpdate`, `NodeUpdate` 四种推送事件

### 4.3 功能缺失

| 缺失项 | 严重程度 | 说明 |
|--------|---------|------|
| `/health` 路径 | 中 | PRD 要求 `/health`，实际在 `/api/health` |
| `/ws` 集成 | 中 | WebSocket 独立 router，未集成到 API Server |
| `PUT /api/config` 完整性 | 低 | 仅支持部分字段更新（缺少 ebpf_interface, rules_config 等） |
| 节点测试真实性 | 低 | `test_node` 返回模拟数据，非真实节点连通性测试 |

---

## 五、综合评估

### 5.1 完整性评分

| 模块 | 需求覆盖率 | 实现质量 | 评分 |
|------|----------|---------|------|
| Metrics 指标 | 100% | 超出 PRD（额外 Histogram 指标） | ⭐⭐⭐⭐⭐ |
| Tracking 追踪 | 100% | 完整实现，eBPF 类型完备 | ⭐⭐⭐⭐⭐ |
| Control 接口 | 100% | 命令完整，桩函数待实现 | ⭐⭐⭐⭐ |
| REST API | ~88% | 大部分端点实现，路径略有差异 | ⭐⭐⭐⭐ |
| **总体** | **~97%** | — | **⭐⭐⭐⭐½** |

### 5.2 关键缺失

1. **API 路径不一致**：`/health` vs `/api/health`，`POST /api/nodes/test` vs `POST /api/nodes/:id/test`
2. **WebSocket 未集成**：websocket router 独立于 server.rs 的 API router，`/ws` 未纳入统一路由
3. **Control 接口桩函数**：Reload/TestNode/Stats 的底层实现为硬编码返回值，未与真实系统连接
4. **API State 使用 Mock 数据**：`AppState::default()` 包含硬编码的示例节点/规则数据，未集成真实后端

### 5.3 建议

**高优先级**:
1. 将 `websocket.rs::create_dashboard_router()` 合并到 `server.rs` 的 `ApiServer`，统一 API 入口
2. 将 `/api/health` 路径改为 `/health` 以符合 PRD
3. 修复 `POST /api/nodes/test` 路径为 `POST /api/nodes/:id/test`（或确认当前实现更合理）

**中优先级**:
4. 将 `control.rs` 中的 `rules_loaded()`, `rule_count()`, `node_count()` 替换为真实数据源
5. 完善 `PUT /api/config` 支持所有配置字段更新
6. 完善 `TestNode` 命令实现真实节点连通性测试

**低优先级**:
7. 将 Tracking store 的 `RwLock<HashMap>` 升级为 `dashmap`（issue #66）
8. 实现精确百分位数计算（HDRHistogram）

---

## 附录：文件路径索引

| 模块 | 文件路径 |
|------|---------|
| Metrics Counter | `packages/dae-proxy/src/metrics/counter.rs` |
| Metrics Gauge | `packages/dae-proxy/src/metrics/gauge.rs` |
| Metrics Histogram | `packages/dae-proxy/src/metrics/histogram.rs` |
| Metrics Prometheus Server | `packages/dae-proxy/src/metrics/prometheus.rs` |
| Tracking Store | `packages/dae-proxy/src/tracking/store.rs` |
| Tracking Types | `packages/dae-proxy/src/tracking/types.rs` |
| Tracking eBPF Maps | `packages/dae-proxy/src/tracking/maps.rs` |
| Control Interface | `packages/dae-proxy/src/control.rs` |
| API Server | `packages/dae-api/src/server.rs` |
| API Routes | `packages/dae-api/src/routes/*.rs` |
| API Models | `packages/dae-api/src/models.rs` |
| WebSocket | `packages/dae-api/src/websocket.rs` |
