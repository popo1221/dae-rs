# 规则引擎 - 功能描述

## 概述
规则引擎在用户空间运行，根据域名、IP、GeoIP、进程等属性做最终的路由决策。

## 流程图/数据流

### 规则匹配流程
```
PacketInfo (from eBPF or direct)
        |
        v
Enrich with GeoIP (if enabled)
        |
        v
For each RuleGroup (sorted by priority):
        |
        +---> Match against rules in group
        |         |
        |         +---> domain-suffix: 检查域名后缀
        |         +---> domain-keyword: 检查域名关键词
        |         +---> domain: 精确域名匹配
        |         +---> ip-cidr: 检查 IP CIDR
        |         +---> geoip: 检查 GeoIP 国家
        |         +---> process-name: 检查进程名 (Linux)
        |         +---> sip (Source IP): 源 IP 匹配
        |         +---> port: 端口匹配
        |         +---> protocol: 协议匹配
        |
        v
        (match found?) --> YES --> Return action
        |
        NO
        v
Continue to next RuleGroup
        |
        v
(No match in any group) --> Return default_action
```

## 规则类型

| 规则类型 | 说明 | 示例 |
|----------|------|------|
| `domain-suffix` | 域名后缀匹配 | `.example.com` |
| `domain-keyword` | 域名包含关键词 | `google` |
| `domain` | 精确域名 | `api.example.com` |
| `ip-cidr` | IP CIDR 匹配 | `192.168.0.0/16` |
| `geoip` | GeoIP 国家代码 | `CN`, `US` |
| `process-name` | 进程名匹配 | `chrome` |
| `sip` | 源 IP 匹配 | `10.0.0.1` |
| `port` | 目标端口 | `80`, `443`, `22,80,443` |
| `protocol` | IP 协议 | `tcp`, `udp` |

## 规则动作

| 动作 | 说明 |
|------|------|
| `pass` / `direct` | 直连，不走代理 |
| `proxy` / `route` | 走代理 |
| `drop` / `deny` | 丢弃数据包 |

## 配置项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `geoip_enabled` | bool | true | 启用 GeoIP 查找 |
| `geoip_db_path` | Option<String> | None | GeoIP 数据库路径 |
| `process_matching_enabled` | bool | false | 启用进程匹配 |
| `default_action` | RuleAction | Proxy | 默认动作 |
| `hot_reload_enabled` | bool | false | 启用热重载 |
| `reload_interval_secs` | u64 | 60 | 重载间隔 |

## 接口设计

### 核心 trait/struct
- `struct PacketInfo`: 数据包信息
  - `source_ip: IpAddr`
  - `destination_ip: IpAddr`
  - `src_port: u16`
  - `dst_port: u16`
  - `protocol: u8`
  - `destination_domain: Option<String>`
  - `geoip_country: Option<String>`
  - `process_name: Option<String>`
  - `dns_query_type: Option<u16>`
- `struct Rule`: 单条规则
- `struct RuleGroup`: 规则组
- `enum RuleAction`: 动作 (Pass, Proxy, Drop, Default, Direct)
- `enum RuleMatchAction`: 匹配动作

### 公开方法
- `fn RuleEngine::new(config)`: 创建规则引擎
- `fn RuleEngine::initialize() -> Result`: 初始化
- `fn RuleEngine::load_rules(path) -> Result`: 加载规则文件
- `fn RuleEngine::match_packet(info) -> RuleAction`: 匹配数据包
- `fn RuleEngine::lookup_geoip(ip) -> Option<String>`: GeoIP 查询
- `fn RuleEngine::reload(path) -> Result`: 热重载规则
- `fn RuleEngine::get_stats() -> RuleEngineStats`: 获取统计

## TOML 规则格式
```toml
[[rule_groups]]
name = "direct"
default_action = "pass"

[[rule_groups.rules]]
type = "domain-suffix"
value = ".cn"
action = "pass"

[[rule_groups.rules]]
type = "geoip"
value = "CN"
action = "pass"

[[rule_groups]]
name = "block"
default_action = "proxy"

[[rule_groups.rules]]
type = "port"
value = "25"
action = "drop"
```

## 错误处理

| 错误类型 | 原因 | 处理方式 |
|----------|------|----------|
| `ParseError` | 规则解析失败 | 使用旧规则 |
| `GeoIPNotFound` | GeoIP 数据库未加载 | 跳过 GeoIP 匹配 |
| `FileNotFound` | 规则文件不存在 | 返回错误 |

## 安全性考虑

1. **规则优先级**: 规则组按优先级排序，先匹配的生效
2. **GeoIP 数据**: 需要定期更新 GeoIP 数据库
3. **进程名欺骗**: Linux 进程名可伪造，仅作参考
4. **规则热重载**: 支持不中断服务的规则更新
