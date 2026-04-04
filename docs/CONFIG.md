# 配置参考手册

## 完整配置示例

```toml
# dae-rs 配置文件示例

[proxy]
# SOCKS5 监听地址
socks5_listen = "127.0.0.1:1080"
# HTTP 代理监听地址
http_listen = "127.0.0.1:8080"
# TCP 连接超时 (秒)
tcp_timeout = 60
# UDP 会话超时 (秒)
udp_timeout = 30
# eBPF 接口
ebpf_interface = "eth0"
# 启用 eBPF
ebpf_enabled = true
# 控制 socket 路径
control_socket = "/var/run/dae.sock"

[transparent_proxy]
# 启用透明代理
enabled = true
# TUN 接口名
tun_interface = "dae0"
# TUN IP 地址
tun_ip = "172.16.0.1"
# TUN 子网掩码
tun_netmask = "255.255.255.0"
# MTU
mtu = 1500
# DNS 劫持地址
dns_hijack = ["8.8.8.8:53", "1.1.1.1:53"]
# DNS 上游服务器
dns_upstream = ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"]
# TCP 超时
tcp_timeout = 60
# UDP 超时
udp_timeout = 30
# 自动设置路由
auto_route = true

[logging]
# 日志级别: trace, debug, info, warn, error
level = "info"
# 日志文件路径 (空为 stdout)
file = "/var/log/dae.log"
# 结构化日志
structured = true

# 节点配置
[[nodes]]
name = "香港节点"
type = "vless"
server = "hk.example.com"
port = 443
uuid = "your-uuid-here"
tls = true
tls_server_name = "example.com"

[[nodes]]
name = "新加坡节点"
type = "vmess"
server = "sg.example.com"
port = 10086
uuid = "another-uuid"
security = "auto"
tls = true

[[nodes]]
name = "SS 节点"
type = "shadowsocks"
server = "ss.example.com"
port = 8388
method = "chacha20-ietf-poly1305"
password = "your-password"

# 订阅配置
# 定时从订阅 URL 自动拉取并更新节点
[[subscriptions]]
url = "https://sub.example.com/clash"
update_interval_secs = 3600
verify_tls = true
name = "主订阅"

[[subscriptions]]
url = "https://backup.example.com/sub"
update_interval_secs = 7200
verify_tls = true

# 规则配置
[rules]
# 外部规则文件
config_file = "/etc/dae/rules.toml"

# 或内联规则组
[[rules.rule_groups]]
name = "默认规则"
first_match = true
default_action = "proxy"

[[rules.rule_groups.rules]]
type = "domain-suffix"
value = "cn"
action = "direct"

[[rules.rule_groups.rules]]
type = "geoip"
value = "cn"
action = "direct"

[[rules.rule_groups.rules]]
type = "domain-keyword"
value = "google"
action = "proxy"

# 跟踪配置
[tracking]
enabled = true
buffer_size = 4096
flush_interval = 5
```

## 配置结构详解

### proxy 配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `socks5_listen` | String | `127.0.0.1:1080` | SOCKS5 监听地址 |
| `http_listen` | String | `127.0.0.1:8080` | HTTP 代理监听地址 |
| `tcp_timeout` | u64 | `60` | TCP 超时 (秒) |
| `udp_timeout` | u64 | `30` | UDP 超时 (秒) |
| `ebpf_interface` | String | `eth0` | eBPF 绑定的网卡 |
| `ebpf_enabled` | bool | `true` | 是否启用 eBPF |
| `control_socket` | String | `/var/run/dae.sock` | 控制 socket 路径 |

### transparent_proxy 配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 启用透明代理 |
| `tun_interface` | String | `dae0` | TUN 设备名 |
| `tun_ip` | String | `172.16.0.1` | TUN IP 地址 |
| `tun_netmask` | String | `255.255.255.0` | 子网掩码 |
| `mtu` | u32 | `1500` | MTU 值 |
| `dns_hijack` | Vec<String> | `[]` | DNS 劫持地址列表 |
| `dns_upstream` | Vec<String> | `[]` | DNS 上游服务器 |
| `auto_route` | bool | `true` | 自动设置路由 |

### logging 配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `level` | String | `info` | 日志级别 |
| `file` | Option<String> | `None` | 日志文件路径 |
| `structured` | bool | `true` | 结构化日志 |

## 节点配置

### 通用字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | String | 节点名称 |
| `type` | NodeType | 节点类型 |
| `server` | String | 服务器地址 |
| `port` | u16 | 服务器端口 |

### VLESS 节点

```toml
[[nodes]]
name = "VLESS节点"
type = "vless"
server = "example.com"
port = 443
uuid = "your-uuid"
tls = true
tls_server_name = "example.com"
# VLESS 特定选项
[ nodes.capabilities ]
fullcone = true
udp = true
```

### VMess 节点

```toml
[[nodes]]
name = "VMess节点"
type = "vmess"
server = "example.com"
port = 10086
uuid = "your-uuid"
security = "auto"  # auto, aes-128-gcm, chacha20-poly1305
tls = false
```

### Shadowsocks 节点

```toml
[[nodes]]
name = "SS节点"
type = "shadowsocks"
server = "example.com"
port = 8388
method = "chacha20-ietf-poly1305"
password = "your-password"
```

### Trojan 节点

```toml
[[nodes]]
name = "Trojan节点"
type = "trojan"
server = "example.com"
port = 443
trojan_password = "your-password"
tls = true
tls_server_name = "example.com"
```

## 订阅格式支持

dae-rs 支持从多种订阅格式导入节点配置：

### 1. SIP008 (JSON)

```json
{
  "version": 1,
  "servers": [
    {
      "id": "server-1",
      "remarks": "香港节点",
      "server": "hk.example.com",
      "server_port": 8388,
      "password": "secret",
      "method": "chacha20-ietf-poly1305"
    }
  ]
}
```

### 2. Clash YAML

```yaml
proxies:
  - name: "香港"
    type: trojan
    server: hk.example.com
    port: 443
    password: xxxxx
    sni: example.com

proxy-groups:
  - name: "代理"
    type: url-test
    proxies:
      - 香港
    url: "http://www.gstatic.com/generate_204"
    interval: 300
```

### 3. Sing-Box JSON

```json
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "香港",
      "server": "hk.example.com",
      "port": 443,
      "uuid": "xxxxx",
      "tls": {
        "enabled": true,
        "server_name": "example.com"
      }
    }
  ]
}
```

### 4. V2Ray URI

```
vmess://eyJhbGciOiJub25lIiwidHlwIjoiYXBwIn0K...
vless://uuid@example.com:443?encryption=none...
trojan://password@example.com:443
ss://method:password@example.com:8388
```

## 订阅配置

除了手动配置节点，dae-rs 还支持通过订阅链接自动获取和更新节点。

### 订阅配置字段

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `url` | String | 必填 | 订阅地址（http/https） |
| `update_interval_secs` | u64 | 3600 | 更新间隔（秒），默认1小时 |
| `verify_tls` | bool | true | 是否验证TLS证书 |
| `user_agent` | Option<String> | dae-rs默认 | 自定义 User-Agent |
| `name` | Option<String> | None | 订阅别名，用于标识 |

### 示例

```toml
# 主订阅 - Clash 格式
[[subscriptions]]
url = "https://sub.example.com/clash"
update_interval_secs = 3600
verify_tls = true
name = "主节点"

# 备用订阅 - 较长的更新间隔
[[subscriptions]]
url = "https://backup.example.com/sub"
update_interval_secs = 7200
verify_tls = true
name = "备用节点"

# 跳过 TLS 验证（不推荐，仅测试环境使用）
[[subscriptions]]
url = "http://internal-sub.local/sub"
update_interval_secs = 1800
verify_tls = false
```

### 工作机制

1. **启动时拉取**：dae-rs 启动时会自动拉取所有订阅 URL
2. **定时更新**：按 `update_interval_secs` 间隔定时更新节点列表
3. **格式自动识别**：自动识别 SIP008/Clash YAML/Sing-Box JSON/URI 等格式
4. **节点去重**：新节点与现有节点合并，自动去除重复

### 支持的订阅格式

订阅返回内容可以是以下任意格式：

- **SIP008 JSON**：JSON 格式的节点列表
- **Clash YAML**：Clash 格式的代理配置
- **Sing-Box JSON**：Sing-Box 格式的出站配置
- **Base64 编码**：以上任意格式经过 Base64 编码
- **URI 列表**：纯文本，每行一个节点链接（vmess://, vless://, trojan://, ss://）

### 注意事项

- 订阅 URL 必须是 `http://` 或 `https://` 开头
- `update_interval_secs` 必须大于 0
- 建议使用 HTTPS 订阅，并保持 `verify_tls = true`
- 节点变更后需要重启或发送 SIGHUP 重新加载规则

## 规则配置

### 规则类型

| 类型 | 示例值 | 说明 |
|------|--------|------|
| `domain` | `example.com` | 精确域名匹配 |
| `domain-suffix` | `cn` | 域名后缀匹配 |
| `domain-keyword` | `google` | 域名关键词匹配 |
| `ipcidr` | `10.0.0.0/8` | IP 段匹配 |
| `geoip` | `cn` | GeoIP 国家码匹配 |
| `process` | `chrome` | 进程名匹配 |
| `dnstype` | `AAAA` | DNS 查询类型 |
| `capability` | `fullcone` | 节点能力匹配 |

### 规则动作

| 动作 | 说明 |
|------|------|
| `proxy` | 通过代理转发 |
| `direct` | 直连 |
| `drop` | 丢弃 |

### 规则组配置

```toml
[[rules.rule_groups]]
name = "分流规则"
first_match = true
default_action = "proxy"

# 直连国内流量
[[rules.rule_groups.rules]]
type = "geoip"
value = "cn"
action = "direct"
priority = 10

# 代理海外流量
[[rules.rule_groups.rules]]
type = "domain-suffix"
value = "com"
action = "proxy"
priority = 20
```

## 跟踪配置

```toml
[tracking]
enabled = true
buffer_size = 4096      # 跟踪缓冲区大小
flush_interval = 5       # 刷新间隔 (秒)
```

## 环境变量

| 变量 | 说明 |
|------|------|
| `DAE_CONFIG` | 配置文件路径 |
| `DAE_LOG_LEVEL` | 日志级别覆盖 |
| `DAE_EBPF_ENABLED` | 启用/禁用 eBPF |
