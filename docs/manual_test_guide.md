# dae-rs 手工端到端测试指南

> 本文档描述 dae-rs 流量代理跟踪系统的手工端到端测试方法。

## 测试环境

### 测试服务器

- **IP:** `10.10.10.89`
- **SSH:** `ssh root@10.10.10.89`
- **测试用户:** root

### 前置条件

1. dae-rs 已编译并部署到测试服务器
2. 测试配置文件已准备
3. 网络连通性正常

## 测试服务器连接

```bash
# 连接到测试服务器
ssh root@10.10.10.89

# 检查 dae-rs 是否已部署
which dae-rs
dae-rs --version

# 检查测试配置目录
ls -la /etc/dae-rs/
```

## dae-proxy 启动命令

### 基本启动命令

```bash
# 使用配置文件启动
dae-rs run --config /etc/dae-rs/config.toml

# 带追踪功能启动
dae-rs run --config /etc/dae-rs/tracking-config.toml

# 后台运行并记录日志
nohup dae-rs run --config /etc/dae-rs/config.toml > /var/log/dae-rs.log 2>&1 &

# 检查进程状态
ps aux | grep dae-rs
```

### 追踪配置示例

```toml
# /etc/dae-rs/tracking-config.toml

[tracking]
enabled = true
export_interval = 10
max_connections = 65536
connection_ttl = 3600

[tracking.export]
prometheus = true
prometheus_port = 9090
prometheus_path = "/metrics"

json_api = true
json_api_port = 8080
json_api_path = "/api/stats"

[tracking.protocols.tcp]
enabled = true
track_rtt = true

[tracking.protocols.udp]
enabled = true
track_nat = true

[tracking.protocols.dns]
enabled = true
track_resolution = true

[tracking.rules]
enabled = true
track_bytes = true

[tracking.nodes]
enabled = true
track_percentiles = true
```

## TrackingStore HTTP API 端点

dae-proxy 启动后，以下 HTTP API 端点可用（默认端口 8080）：

### 端点列表

| 端点 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/metrics` | GET | Prometheus 格式指标 |
| `/api/tracking/overview` | GET | 总体统计概览 |
| `/api/tracking/connections` | GET | 连接列表（支持过滤） |
| `/api/tracking/connections/*key` | GET | 单个连接详情 |
| `/api/tracking/protocols` | GET | 协议统计 |
| `/api/tracking/rules` | GET | 规则匹配统计 |
| `/api/tracking/nodes` | GET | 节点统计 |

### API 响应格式

#### GET /api/tracking/overview

```json
{
  "overall": {
    "uptime_secs": 3600,
    "packets_total": 123456,
    "bytes_total": 1024000,
    "connections_total": 100,
    "connections_active": 5,
    "dropped_total": 10,
    "routed_total": 50000,
    "unmatched_total": 5,
    "dns_queries_total": 1000,
    "dns_cache_hits": 800,
    "dns_cache_misses": 200,
    "dns_upstream_switches": 5,
    "dns_errors": 2,
    "dns_avg_latency_ms": 12.5
  },
  "transport_protocols": {
    "tcp": {"protocol": "tcp", "packets": 100000, "bytes": 800000, "connections": 50, "active_connections": 3},
    "udp": {"protocol": "udp", "packets": 23456, "bytes": 224000, "connections": 50, "active_connections": 2},
    "icmp": {"protocol": "icmp", "packets": 0, "bytes": 0, "connections": 0, "active_connections": 0}
  }
}
```

#### GET /api/tracking/connections

Query 参数:
- `state`: `active`, `closed`, `all`（默认: all）
- `limit`: 最大返回数量（默认: 100）
- `protocol`: `tcp`, `udp`, `icmp`
- `sort_by`: `bytes_in`, `bytes_out`, `last_time`

```json
{
  "total": 5,
  "active": 3,
  "connections": [
    {
      "key": "127.0.0.1:12345-8.8.8.8:00050-6",
      "src_ip": "127.0.0.1",
      "src_port": 12345,
      "dst_ip": "8.8.8.8",
      "dst_port": 80,
      "proto": "TCP",
      "packets_in": 10,
      "packets_out": 5,
      "bytes_in": 1024,
      "bytes_out": 512,
      "state": "ESTABLISHED",
      "node_id": 1,
      "rule_id": 0,
      "start_time": 1712563200000,
      "last_time": 1712563260000,
      "age_ms": 60000,
      "idle_ms": 1000
    }
  ]
}
```

#### GET /api/tracking/protocols

```json
{
  "transport": {
    "tcp": {"protocol": "tcp", "packets": 100000, "bytes": 800000, "connections": 50, "active_connections": 3},
    "udp": {"protocol": "udp", "packets": 23456, "bytes": 224000, "connections": 50, "active_connections": 2},
    "icmp": {"protocol": "icmp", "packets": 0, "bytes": 0, "connections": 0, "active_connections": 0}
  },
  "proxy": {
    "protocols": [
      {
        "protocol": "vless",
        "bytes_in": 500000,
        "bytes_out": 300000,
        "total_bytes": 800000,
        "metadata": {"uuid": "550e8400-e29b-41d4-a716-446655440000", "flow": "vision"}
      }
    ]
  }
}
```

#### GET /api/tracking/rules

```json
{
  "total_rules": 3,
  "rules": [
    {
      "rule_id": 1,
      "rule_type": "DOMAIN",
      "match_count": 100,
      "pass_count": 20,
      "proxy_count": 70,
      "drop_count": 10,
      "bytes_matched": 1024000
    }
  ]
}
```

#### GET /api/tracking/nodes

```json
{
  "total_nodes": 2,
  "nodes": [
    {
      "node_id": 1,
      "total_requests": 500,
      "successful_requests": 450,
      "failed_requests": 50,
      "bytes_sent": 1024000,
      "bytes_received": 2048000,
      "latency_avg_ms": 45.5,
      "latency_p50_ms": 40,
      "latency_p90_ms": 80,
      "latency_p99_ms": 150,
      "success_rate": 0.9,
      "status": "UP"
    }
  ]
}
```

### Prometheus Metrics 格式

```
# dae-rs overall statistics
dae_packets_total 123456
dae_bytes_total 1024000
dae_connections_total 100
dae_connections_active 5
dae_dropped_total 10
dae_routed_total 50000
dae_unmatched_total 5

# dae-rs DNS statistics
dae_dns_queries_total 1000
dae_dns_cache_hits 800
dae_dns_cache_misses 200
dae_dns_upstream_switches 5
dae_dns_errors 2
dae_dns_latency_avg_ms 12.5

# dae-rs protocol statistics
dae_protocol_packets_total{protocol="tcp"} 100000
dae_protocol_bytes_total{protocol="tcp"} 800000
dae_protocol_packets_total{protocol="udp"} 23456
dae_protocol_bytes_total{protocol="udp"} 224000
```

## 测试场景

### T1: DNS 跟踪测试

验证 DNS 查询追踪功能。

**预期结果:**
- `dns_queries_total >= 2`（两次查询）
- `dns_cache_hits >= 1`（第二次查询应命中缓存）
- `dns_avg_latency_ms > 0`

### T2: 连接生命周期测试

验证 TCP/UDP 连接状态转换。

**预期结果:**
- 连接出现在 `state=active` 列表
- 连接状态正确转换: `NEW -> ESTABLISHED -> CLOSING -> CLOSED`

### T3: 字节计数测试

验证流量统计准确性。

**预期结果:**
- `bytes_in` 增量约等于下载数据大小
- `bytes_out` 增量约等于请求数据大小

### T4: 规则匹配测试

验证规则统计功能。

**预期结果:**
- `match_count` 正确累加
- `pass_count`, `proxy_count`, `drop_count` 准确

### T5: Prometheus Metrics 测试

验证 Prometheus 指标导出。

**预期结果:**
- `/metrics` 返回 200 OK
- 包含 `dae_dns_queries_total`, `dae_connections_total` 等指标

### T6: HTTP API 端点测试

验证所有 API 端点正常工作。

**预期结果:**
- 所有端点返回 200 OK
- JSON 格式正确

### T7: TLS Handshake 跟踪测试

验证 TLS 握手统计。

**预期结果:**
- `tls_handshakes_total >= 1`
- `tls_handshake_latency_ms > 0`

### T8: Proxy Chain 多跳测试

验证多跳代理链跟踪。

**预期结果:**
- `hop_count >= 2`
- 各 hop 有独立 latency 记录

## 常用验证命令

```bash
# 检查 dae-proxy 是否运行
curl -s http://localhost:8080/health

# 获取概览统计
curl -s http://localhost:8080/api/tracking/overview | jq .

# 获取活跃连接
curl -s "http://localhost:8080/api/tracking/connections?state=active" | jq .

# 获取 Prometheus 指标
curl -s http://localhost:8080/metrics | grep "^dae_"

# 统计 DNS 查询
curl -s http://localhost:8080/api/tracking/overview | jq '.overall.dns_queries_total'

# 获取协议统计
curl -s http://localhost:8080/api/tracking/protocols | jq .
```

## 测试脚本

测试脚本位于 `tools/manual_test/` 目录：

- `test_dns_tracking.sh` - T1: DNS 跟踪测试
- `test_connection_tracking.sh` - T2: 连接生命周期测试
- `test_prometheus_metrics.sh` - T5: Prometheus metrics 测试
- `test_api_endpoints.sh` - T6: HTTP API 端点测试
- `test_tls_handshake.sh` - T7: TLS handshake 测试

## 故障排查

### API 无响应

```bash
# 检查端口监听
netstat -tlnp | grep 8080

# 检查进程状态
ps aux | grep dae-rs

# 查看日志
tail -100 /var/log/dae-rs.log
```

### 指标为 0

```bash
# 确认追踪已启用
curl -s http://localhost:8080/api/tracking/overview | jq '.overall'

# 确认配置正确
grep -i tracking /etc/dae-rs/config.toml
```
