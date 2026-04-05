# 018 - rule_engine.rs | 规则引擎

## 一句话总结（10岁版本）

**像机场安检的规则手册**：每个乘客（数据包）进来，安检员对照手册逐条检查：
- 这人名字在"禁飞名单"里吗？→ 拒绝
- 这人目的地是"敏感国家"吗？→ 要查证件（GeoIP）
- 这人带的是"普通行李"吗？→ 放行（Pass）
- 手册里没写？→ 按默认规则来（默认是 Proxy）

---

## 简化法则自检（6项）

- [x] **法则1**：规则按组（RuleGroup）组织，组内按优先级排序
- [x] **法则2**：PacketInfo 是规则匹配的上下文，包含足够做决策的所有信息
- [x] **法则3**：GeoIP 查找是懒加载的，数据库不存在不报错，查找失败不 panic
- [x] **法则4**：匹配过程是只读的，不修改 PacketInfo
- [x] **法则5**：规则可以从 TOML 文件热加载，支持动态更新
- [x] **法则6**：未匹配的包走默认动作（default_action），默认是 Proxy

---

## 外婆能听懂

想象你开了一家快递公司，要决定每个包裹怎么处理：

1. **看包裹上写的地址**（destination_ip / destination_domain）
2. **查这个地址在哪个国家**（geoip_country）
3. **看寄件人是谁**（source_ip / process_name）
4. **对照公司规则手册**（rule_groups）：
   - "寄到朝鲜的 → 拒收"
   - "域名以 .cn 结尾的 → 走代理"
   - "公司内部 IP → 直连"
5. **手册没写的 → 按公司默认政策（默认 Proxy）**

规则引擎就是干这个的：把网络数据包变成"包裹信息"，然后对照规则手册决定走哪条路。

---

## 专业结构分析

### 核心数据结构

```
PacketInfo（数据包的完整画像）
├── 网络层
│   ├── source_ip: IpAddr
│   ├── destination_ip: IpAddr
│   ├── src_port: u16
│   ├── dst_port: u16
│   └── protocol: u8           # 6=TCP, 17=UDP
│
├── 应用层
│   ├── destination_domain: Option<String>   # DNS 解析后的域名
│   ├── geoip_country: Option<String>        # ISO 3166-1 alpha-2
│   ├── process_name: Option<String>          # Linux 进程名
│   ├── dns_query_type: Option<u16>           # DNS 查询类型
│   └── connection_hash: Option<u64>          # 连接唯一标识
│
├── 节点能力（用于选择出口节点）
│   ├── node_fullcone: Option<bool>          # 全锥 NAT 支持
│   ├── node_udp: Option<bool>               # UDP 支持
│   └── node_v2ray: Option<bool>             # V2Ray 兼容
│
└── 其他
    ├── is_outbound: bool                     # 出站还是入站
    └── packet_size: usize                    # 包大小

RuleEngine
├── config: RuleEngineConfig
│   ├── geoip_enabled: bool
│   ├── geoip_db_path: Option<String>
│   ├── process_matching_enabled: bool
│   ├── default_action: RuleAction
│   ├── hot_reload_enabled: bool
│   └── reload_interval_secs: u64
│
├── rule_groups: RwLock<Vec<RuleGroup>>     # 规则组列表
├── geoip_reader: RwLock<Option<Reader>>    # GeoIP 数据库
└── loaded: RwLock<bool>                     # 是否已加载规则
```

### 规则匹配流程

```
match_packet(PacketInfo)
    │
    ├─→ [如果 geoip_country 未设置且 geoip_enabled]
    │       lookup_geoip(destination_ip) → 填充 geoip_country
    │
    ├─→ [遍历 rule_groups（已按优先级排序）]
    │       │
    │       ├─→ group.match_packet(info) → Some(Action)  # 匹配上了
    │       │       │
    │       │       └─→ return action.to_action()
    │       │
    │       └─→ group.match_packet(info) → None  # 当前组没匹配
    │               │
    │               └─→ 继续遍历下一个 group
    │
    └─→ [所有组都没匹配] → return config.default_action
```

### 规则 TOML 格式

```toml
[[rule_groups]]
name = "direct"          # 组名
default_action = "pass"  # 组内无匹配时的默认动作

[[rule_groups.rules]]
type = "domain-suffix"   # 规则类型
value = ".test"          # 匹配值
action = "pass"          # 匹配后动作
priority = 1000           # 优先级（可选，默认 1000+index）

[[rule_groups]]
name = "block"
default_action = "proxy"

[[rule_groups.rules]]
type = "geoip"           # 基于国家的规则
value = "CN"             # 中国
action = "drop"
```

### RuleAction 枚举

```
RuleAction
├── Pass        # 通过（直连）
├── Proxy       # 走代理
├── Drop        # 丢弃
├── Default     # 使用默认动作
├── Direct      # 显式直连
└── MustDirect  # 强制直连（最高优先级）
```

---

## 关键调用链追溯

### 规则引擎初始化

```
RuleEngine::new(config)
    │
    ├─→ RwLock::new(Vec::new())   # 空规则列表
    ├─→ RwLock::new(None)         # GeoIP 未加载
    └─→ RwLock::new(false)        # 未标记为已加载

RuleEngine::initialize()
    │
    └─→ init_geoip()
            │
            ├─→ 检查 geoip_db_path 是否配置
            ├─→ 检查文件是否存在
            ├─→ spawn_blocking: maxminddb::Reader::open_readfile()
            └─→ geoip_reader.write() = Some(reader)
```

### 规则加载

```
RuleEngine::load_rules(path)
    │
    ├─→ tokio::fs::read_to_string(path)
    │
    └─→ parse_and_load_rules(content)
            │
            ├─→ toml::from_str::<RuleConfig>(content)
            │       │
            │       └─→ 解析 [[rule_groups]] 数组
            │
            ├─→ [遍历每个 group_config]
            │       │
            │       ├─→ RuleGroup::new(name)
            │       ├─→ [遍历每个 rule_config]
            │       │       ├─→ Rule::new(type, value, action, priority)
            │       │       └─→ group.add_rule(rule)
            │       │
            │       └─→ group.set_default_action(default_action)
            │
            ├─→ rule_groups.sort_by(min_priority)  # 按最低优先级排序
            │
            └─→ rule_groups.write() = sorted_groups
```

### 数据包匹配

```
RuleEngine::match_packet(info: &PacketInfo)
    │
    ├─→ info.geoip_country.is_none() && geoip_enabled
    │       └─→ lookup_geoip(&info.destination_ip)
    │               │
    │               └─→ reader.lookup(ip) → Option<String>
    │                       └─→ (当前实现返回 None，有 TODO 注释)
    │
    ├─→ rule_groups.read().await  # 获取所有规则组
    │
    ├─→ [for group in groups]
    │       │
    │       └─→ group.match_packet(&info) → Option<RuleMatchAction>
    │               │
    │               ├─→ [遍历组内每条规则]
    │               │       │
    │               │       └─→ rule.matches(info) → bool
    │               │               │
    │               │               ├─→ domain-suffix:  info.domain.ends_with(value)
    │               │               ├─→ geoip:         info.geoip_country == Some(value)
    │               │               ├─→ ip-cidr:        info.ip in cidr
    │               │               └─→ ... 其他类型
    │               │
    │               ├─→ 找到匹配规则 → return Some(action)
    │               └─→ 无匹配 → return None
    │
    └─→ [所有组遍历完，无匹配]
            └─→ return config.default_action
```

---

## 设计取舍说明

### 1. 为什么要用 RwLock 而不是 Mutex？

规则匹配是**读多写少**的场景：
- 每次数据包都要匹配（读）
- 规则加载/更新才需要写（写频率低）

`RwLock` 允许多个并发读锁并行执行，只有写的时候才互斥。这比 `Mutex` 的串行化在多核 CPU 上性能好很多。

### 2. 为什么 GeoIP 查找放在 match_packet 内部？

GeoIP 是**懒加载**的：规则文件可能不包含 GeoIP 规则，不应该每次初始化都加载。放在 `match_packet` 里确保：
- 只有当包真的需要 GeoIP 时才查找
- 查找失败不影响匹配流程（返回 None，降级处理）

### 3. 为什么 domain 要 lowercase 一次？

DNS 域名是不区分大小写的（`example.com` 和 `EXAMPLE.COM` 是同一个域名），但 PacketInfo 可能在不同地方多次做比较。在入口处 lowercase 一次，就避免了热路径（hot path）中的重复转换。

```rust
// Note 注释说明了这一点
pub fn with_domain(mut self, domain: &str) -> Self {
    // Normalize to lowercase once at entry point
    // — avoid repeated conversion in hot paths
    self.destination_domain = Some(domain.to_lowercase());
    self
}
```

### 4. TODO(#75) - GeoIP lookup 未完成

当前 `lookup_geoip` 返回 `None`，有 TODO 注释说明需要配合 maxminddb 0.27 API 实现 country 字段提取。这说明 GeoIP 功能是预留的，但依赖一个具体的数据库格式。

### 5. 为什么规则按组而非扁平列表管理？

`RuleGroup` 有自己的 `default_action`，意味着每组可以有独立的默认行为。这比扁平列表更灵活：不同业务线可以有不同的默认策略，只需配置多个组。

### 6. 节点能力（node_*）字段的意义

这些字段不是给规则匹配用的，而是给**出口节点选择**用的。规则匹配决定了"这包要 Proxy"，但选哪个代理节点（不同的节点有不同的能力）需要额外信息：
- `node_fullcone`：是否支持全锥 NAT（影响 P2P 场景）
- `node_udp`：是否支持 UDP（某些代理协议不支持 UDP）
- `node_v2ray`：是否兼容 V2Ray 协议

这些字段让规则引擎不仅能做"去哪里"的决策，还能间接影响"走哪条链"。

---

## 与 dae-rs 整体架构的关系

```
dae-rs 架构
    │
    ├── eBPF (kernel space)
    │       │
    │       └─→ 数据包捕获 + 初步分流
    │               │
    ├── 用户空间
    │       │
    │       ├─→ tun.rs (协议解析 + DNS 劫持)
    │       │       │
    │       │       └─→ PacketInfo 组装
    │       │               │
    │       ├─→ rule_engine.rs (规则匹配 → 决策)
    │       │       │
    │       │       └─→ RuleAction: Pass/Proxy/Drop/Direct
    │       │               │
    │       ├─→ protocol_dispatcher.rs (协议分发)
    │       │       │
    │       ├─→ proxy_chain.rs (代理链执行)
    │       │       │
    │       └─→ 各个协议实现 (socks5/vmess/vless/trojan...)
    │               │
    └─→ eBPF (kernel space)
            └─→ 根据 RuleAction 执行数据包的路由/丢弃
```

rule_engine.rs 是 dae-rs 用户空间决策的核心——它把 tun.rs 收集的上下文信息，用规则文件定义的策略做出最终路由决定。
