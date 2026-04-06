# Ralph Mode: dae-rs 模块拆分与特性设计

## 项目目标
将 dae-rs (特别是 dae-proxy) 的大型模块拆分为更小的、独立的 features 和细粒度函数，提升代码可维护性和编译缓存。

## 分析对象
- `crates/dae-proxy/` - 主要重构目标 (~29k 行)
- `crates/dae-config/` - 配置模块
- `crates/dae-core/` - 核心引擎
- `crates/dae-api/` - API 模块

## 当前问题
1. **超大文件**: ebpf_integration/mod.rs (1530行), vless/handler.rs (872行)
2. **耦合紧密**: 模块间循环依赖
3. **Features 缺失**: 大量功能编译进单一 artifact
4. **函数粒度粗**: 巨型函数难以测试和维护

## 重构策略

### 策略 1: 特性拆分 (Feature Splitting)
将协议处理器拆分为独立 features:
- `feature = ["dae-proxy/trojan"]` 
- `feature = ["dae-proxy/vless"]`
- `feature = ["dae-proxy/vmess"]`

### 策略 2: 模块拆分 (Module Splitting)
将大型模块拆分为独立子模块:
- `ebpf_integration/` → `ebpf_integration/` + `ebpf_diagnostics/`
- `node/` → `node/` + `node_store/` + `node_selector/`

### 策略 3: 函数提取 (Function Extraction)
提取巨型函数为独立小函数，建立 Trait Hierarchy

---

## Backlog (待处理任务)

### Phase 1: 分析与设计
- [ ] 分析 dae-proxy Cargo.toml 当前 features
- [ ] 识别模块间依赖关系
- [ ] 设计新的 feature 划分方案
- [ ] 设计模块拆分方案

### Phase 2: Feature 重构
- [ ] 定义 dae-proxy 新 features 结构
- [ ] 重构 transport 层为独立 features
- [ ] 重构协议处理器为可选 features

### Phase 3: 模块拆分
- [ ] 拆分 ebpf_integration 模块
- [ ] 拆分 node 模块
- [ ] 拆分 protocol 模块

### Phase 4: 函数粒度优化
- [ ] 识别超大函数 (>200行)
- [ ] 提取关键函数到独立文件
- [ ] 建立 Trait Hierarchy

---

## 依赖分析 (从 lib.rs 提取)

### 核心层 (无依赖)
- `core/` - Context, Error, Result

### 基础设施层
- `config/` - 配置管理
- `metrics/` - 指标收集
- `logging/` - 日志服务
- `tracking/` - 追踪存储

### 代理层
- `proxy/` - 代理协调器
- `connection/` - 连接管理
- `connection_pool/` - 连接池
- `tcp/` - TCP 代理
- `udp/` - UDP 代理

### 协议层
- `protocol/` - 协议抽象
- `socks5/` - SOCKS5
- `vless/` - VLESS
- `vmess/` - VMess
- `trojan_protocol/` - Trojan
- `shadowsocks/` - Shadowsocks

### 传输层
- `transport/` - 传输抽象 (ws, tls, grpc, etc.)

### 高级功能
- `hysteria2/` - Hysteria2
- `juicity/` - Juicity
- `tuic/` - TUIC
- `dns/` - DNS 处理
- `nat/` - NAT 穿透
- `mac/` - MAC 规则
- `process/` - 进程规则
- `tun/` - TUN 接口

### eBPF 层
- `ebpf_integration/` - eBPF 集成
- `ebpf_check/` - eBPF 检查

---

## 建议的 Feature 结构

```toml
[features]
default = ["core", "socks5", "tcp", "udp"]

# Core features (always enabled)
core = []
socks5 = ["core"]
tcp = ["core"]
udp = ["core"]

# Protocol features
vless = ["core", "transport"]
vmess = ["core", "transport"]
trojan = ["core", "transport"]
shadowsocks = ["core", "transport"]

# Transport features
transport-ws = ["core"]
transport-tls = ["core"]
transport-grpc = ["core"]
transport-h2 = ["core"]

# Advanced features
hysteria2 = ["core", "transport", "quinn"]
juicity = ["core", "transport", "quinn"]
tuic = ["core", "transport", "quinn"]

# Rule engines
rule-engine = ["core"]
dns = ["core", "rule-engine"]
nat = ["core"]
mac-rule = ["core"]
process-rule = ["core"]

# Observability
metrics = ["core"]
logging = ["core"]
tracking = ["core"]

# eBPF
ebpf = ["core"]
```

---

## 进行中的任务

## 已完成

## 阻塞项

