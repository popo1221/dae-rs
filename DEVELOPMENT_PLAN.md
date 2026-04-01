# dae-rs 开发计划文档

> Rust 重构 dae 高性能透明代理方案

---

## 1. 项目概述

### 1.1 项目背景

**dae（dae-agent）** 是一个基于 eBPF 的高性能透明代理项目，使用 Go 语言开发。它通过 XDP（eExpress Data Path）技术在内核层捕获流量，实现零拷贝、透明代理功能。主要应用场景包括：

- 透明代理（游戏加速、外贸电商、远程办公）
- 流量分流与规则匹配
- 网络加速与优化

**为什么要用 Rust 重写？**

| 维度 | Go 版本问题 | Rust 优势 |
|------|-------------|-----------|
| 内存安全 | 依赖 GC，延迟不稳定 | 所有权系统，零 GC 开销 |
| 性能 | 尚可，但有 GC 暂停 | 极致性能，无 GC 暂停 |
| 并发 | goroutine 调度开销 | async/await，编译期优化 |
| 安全 | 内存安全问题偶发 | 编译期安全保障 |
| 部署 | 二进制较大 | 二进制小巧， MUSL 支持 |

### 1.2 项目目标

- **短期目标**：实现与原版 dae 功能兼容，性能持平或超越
- **长期目标**：成为 Rust 生态中最好的透明代理解决方案
- **技术愿景**：探索 eBPF + Rust 异步网络的深度融合

---

## 2. 技术架构

### 2.1 总体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                         用户空间 (User Space)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │
│  │   dae-cli   │  │  dae-config │  │  dae-proxy  │  │dae-ebpf  │ │
│  │  (控制面)   │  │  (配置解析)  │  │  (流量代理)  │ │(内核通信) │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────┬─────┘ │
│         │                │                │               │      │
│         └────────────────┼────────────────┼───────────────┘      │
│                          │                │                       │
│                    ┌─────▼────────────────▼─────┐                 │
│                    │        dae-core            │                 │
│                    │   (共享基础模块/工具库)      │                 │
│                    └───────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
                           ▲
                           │ eBPF Map 共享
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                         内核空间 (Kernel Space)                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      XDP/eBPF 程序                           ││
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ││
│  │  │ 流量捕获  │→│ 规则匹配  │→│ 流量转发  │→│  连接跟踪    │  ││
│  │  │ (XDP)   │  │ (routing) │  │ (redirect)│  │ (conntrack) │  ││
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘  ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 数据流

```
流量入口 (Ingress)
      │
      ▼
┌─────────────┐
│  网卡驱动    │  ← XDP 钩子点
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│ XDP 程序     │────→│ eBPF Map    │  (共享状态)
│ (流量分类)   │     │ - routing   │
└──────┬──────┘     │ - session    │
       │           │ - config     │
       │           └─────────────┘
       │                 ▲
       │                 │ 用户态读取
       │                 │
       ▼                 │
┌─────────────┐           │
│ 流量标记     │           │
│ (bpf_redirect)         │
└──────┬──────┘           │
       │                  │
       ▼                  │
┌─────────────┐           │
│ AF_XDP/     │───────────┘
│ sockmap     │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ 用户态代理    │────→│ 协议解析    │────→│ 出口路由     │
│ (Tokio)     │     │ (SS/QUIC)  │     │ (NIC)       │
└─────────────┘     └─────────────┘     └─────────────┘
```

### 2.3 模块拆分

| 模块 | 仓库路径 | 职责 |
|------|----------|------|
| `dae-core` | `crates/dae-core` | 共享类型定义、错误处理、日志工具、常用算法 |
| `dae-ebpf` | `crates/dae-ebpf` | eBPF 程序编译、加载、Map 管理、与内核通信 |
| `dae-proxy` | `crates/dae-proxy` | TCP/UDP 代理核心、连接池、流量调度 |
| `dae-config` | `crates/dae-config` | 配置文件解析、规则引擎、DSL 解析器 |
| `dae-cli` | `crates/dae-cli` | 命令行工具、守护进程模式、控制接口 |

---

## 3. 技术选型

### 3.1 核心技术栈

| 领域 | 选型 | 理由 |
|------|------|------|
| **eBPF 框架** | `aya` + `aya-ebpf` | Rust 官方 eBPF 库，活跃维护，支持 CO-RE |
| **异步运行时** | `tokio` | 最成熟的 Rust 异步运行时，社区生态丰富 |
| **网络编程** | `tokio` + `socket2` | 高性能 socket 操作，SO_REUSEPORT 支持 |
| **代理协议** | `shadowsocks-rust`, `quinn` | SS 支持完整，QUIC 支持现代协议 |
| **CLI 框架** | `clap` | Rust 最流行的 CLI 库，支持子命令、参数解析 |
| **配置格式** | `serde` + `toml` | 成熟的序列化/反序列化方案 |
| **日志系统** | `tracing` + `tracing-subscriber` | 结构化日志，支持 OpenTelemetry |
| **错误处理** | `thiserror` + `anyhow` | 简化错误类型定义和传播 |

### 3.2 依赖版本（建议）

```toml
[workspace]
resolver = "2"

[workspace.dependencies]
tokio = { version = "1.40", features = ["full"] }
aya = "0.13"
aya-ebpf = "0.2"
clap = { version = "4.5", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"
tracing = "0.1"
thiserror = "1.0"
anyhow = "1.0"
shadowsocks-rust = "1.20"
quinn = "3.0"
```

---

## 4. 开发阶段

### Phase 0：环境准备

**目标**：搭建完整开发环境

**时间**：1-2 天

#### 任务清单

- [ ] **0.1 硬件准备**
  - [ ] 准备 Ubuntu 22.04 LTS 开发机（物理机或 VM）
  - [ ] 推荐配置：8核 CPU / 16GB RAM / 50GB SSD
  - [ ] 如使用 VM，确保开启嵌套虚拟化（Nested VT-x/AMD-V）

- [ ] **0.2 系统依赖安装**
  - [ ] 安装 Rust latest（通过 rustup）
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    rustup default stable
    ```
  - [ ] 安装构建工具链
    ```bash
    apt install -y clang llvm libelf-dev libbpf-dev libpcap-dev make
    ```
  - [ ] 验证 clang 版本（建议 >= 14）
    ```bash
    clang --version
    ```
  - [ ] 安装 bpftool（内核 BTF 生成工具）
    ```bash
    apt install -y linux-tools-$(uname -r)
    # 或从源码编译
    ```

- [ ] **0.3 内核准备**
  - [ ] 确认内核版本 >= 5.8（支持 eBPF 特性）
    ```bash
    uname -r
    ```
  - [ ] 启用必要内核配置
    ```bash
    # 检查 XDP 支持
    cat /boot/config-$(uname -r) | grep -E "CONFIG_XDP|CONFIG_BPF"
    ```

- [ ] **0.4 开发工具链验证**
  - [ ] 安装 VS Code / JetBrains RustRover
  - [ ] 安装 rust-analyzer 插件
  - [ ] 配置 .cargo/config.toml
    ```toml
    [build]
    rustflags = ["-C", "target-feature=+bpf"]
    target = "x86_64-unknown-linux-gnu"

    [target.x86_64-unknown-linux-gnu]
    linker = "clang"
    ```
  - [ ] 验证 eBPF 程序编译能力

- [ ] **0.5 测试环境准备**
  - [ ] 准备测试用 VPS（推荐 vultr/linode 东京节点）
  - [ ] 或搭建本地测试网络拓扑
  - [ ] 准备 iperf3、wrk、netperf 等基准测试工具

---

### Phase 1：项目脚手架

**目标**：建立 Rust workspace 项目结构

**时间**：1 天

#### 任务清单

- [ ] **1.1 Workspace 初始化**
  - [ ] 创建 Cargo workspace 配置
    ```bash
    mkdir -p dae-rs && cd dae-rs
    cargo init --name dae --workspace
    ```
  - [ ] 创建 `Cargo.toml`
    ```toml
    [workspace]
    resolver = "2"
    members = [
        "crates/dae-core",
        "crates/dae-cli",
        "crates/dae-config",
        "crates/dae-proxy",
        "crates/dae-ebpf",
        "crates/dae-ebpf/dae-ebpf-common",
        "crates/dae-ebpf/dae-xdp",
    ]
    ```

- [ ] **1.2 目录结构**
  - [ ] 创建目录结构
    ```
    dae-rs/
    ├── Cargo.toml              # Workspace 配置
    ├── crates/
    │   ├── dae-core/           # 核心共享库
    │   │   ├── Cargo.toml
    │   │   └── src/
    │   ├── dae-cli/            # CLI 主程序
    │   │   ├── Cargo.toml
    │   │   └── src/
    │   ├── dae-config/         # 配置解析
    │   │   ├── Cargo.toml
    │   │   └── src/
    │   ├── dae-proxy/          # 代理核心
    │   │   ├── Cargo.toml
    │   │   └── src/
    │   └── dae-ebpf/           # eBPF 相关
    │       ├── dae-ebpf-common/   # 共享头文件/类型
    │       ├── dae-xdp/            # XDP 程序
    │       └── dae-ebpf/           # 用户态加载器
    ├── scripts/                # 辅助脚本
    ├── tests/                  # 集成测试
    └── docs/                   # 文档
    ```

- [ ] **1.3 基础依赖配置**
  - [ ] 在 `dae-core` 中定义公共依赖版本
  - [ ] 配置各 crate 间内部依赖
  - [ ] 设置 `#[deny(warnings)]` 和 `#![forbid(unsafe_code)]`

- [ ] **1.4 CI/CD 搭建**
  - [ ] 创建 `.github/workflows/ci.yml`
    ```yaml
    name: CI
    on: [push, pull_request]
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: dtolnay/rust-toolchain@stable
          - run: cargo test --workspace
          - run: cargo clippy --workspace
          - run: cargo fmt --check
  ```
  - [ ] 配置 GitHub Actions 构建矩阵（多个 Rust 版本）
  - [ ] 添加 Cargo.lock 到版本控制

- [ ] **1.5 代码规范**
  - [ ] 创建 `rustfmt.toml`
    ```toml
    edition = "2021"
    max_width = 100
    hard_tabs = false
    tab_spaces = 4
    ```
  - [ ] 创建 `.clippy.toml`
  - [ ] 配置 `cargo deny` 检查依赖安全
  - [ ] 添加 pre-commit hook（可选）

- [ ] **1.6 Hello World 验证**
  - [ ] 在 `dae-cli` 中实现基础 CLI 框架
  - [ ] 实现 `--version` / `--help` 命令
  - [ ] 验证各 crate 间依赖关系正确
  - [ ] 首次成功 `cargo build --workspace`

---

### Phase 2：eBPF 基础（核心难点）

**目标**：实现 XDP 流量捕获与 eBPF Map 共享

**时间**：2-3 周

#### 任务清单

##### Phase 2a：eBPF 程序骨架

- [ ] **2a.1 eBPF 项目初始化**
  - [ ] 配置 `aya` 依赖
  - [ ] 创建 XDP 程序的 aya-ebpf 项目结构
  - [ ] 编写基础 XDP 程序框架
    ```rust
    use aya_ebpf::bindings::xdp_action;
    use aya_ebpf::programs::XdpContext;

    #[panic_handler]
    fn panic(_info: *const core::panic::PanicInfo) -> ! {
        unsafe { core::hint::unreachable_unchecked() }
    }

    #[no_mangle]
    pub extern "C" fn xdp_prog(ctx: *mut XdpContext) -> u32 {
        // TODO: 实现流量处理
        xdp_action::XDP_PASS
    }
    ```

- [ ] **2a.2 eBPF 编译目标配置**
  - [ ] 配置 `targets/x86_64-unknown-linux-bpf` 构建
  - [ ] 创建 bpf-tool 绑定脚本
  - [ ] 验证 eBPF 程序可编译为 BPF bytecode

##### Phase 2b：eBPF Map 设计与实现

- [ ] **2b.1 共享内存 Map**
  - [ ] 实现 `ConfigMap`（规则配置共享）
    ```rust
    #[map]
    static CONFIG_MAP: HashMap<u32, ConfigEntry> = HashMap::with_max_entries(1024);
    ```
  - [ ] 实现 `SessionMap`（连接跟踪）
  - [ ] 实现 `RoutingMap`（路由规则）
  - [ ] 实现 `StatsMap`（统计信息）

- [ ] **2b.2 用户态 Map 操作**
  - [ ] 使用 `aya` 库加载和操作 Map
  - [ ] 实现 Map 持久化接口
  - [ ] 实现 Map 批量更新机制

##### Phase 2c：XDP 流量处理

- [ ] **2c.1 流量捕获**
  - [ ] 实现 NIC 流量捕获（AF_XDP 或 native XDP）
  - [ ] 实现 VLAN tag 处理
  - [ ] 实现 IPv4/IPv6 双栈支持

- [ ] **2c.2 包解析**
  - [ ] 实现 Ethernet 帧解析
  - [ ] 实现 IP 头解析（IPv4/IPv6）
  - [ ] 实现 TCP/UDP 头解析
  - [ ] 实现 DNS 请求识别

- [ ] **2c.3 流量分流**
  - [ ] 实现基于 IP CIDR 的路由
  - [ ] 实现基于域名的路由（DNS Hijack 方案）
  - [ ] 实现基于连接状态的跟踪

##### Phase 2d：性能优化

- [ ] **2d.1 性能调优**
  - [ ] 使用 BPF helper 优化查表性能
  - [ ] 实现批量包处理
  - [ ] 减少锁竞争（per-CPU Map）

- [ ] **2d.2 稳定性增强**
  - [ ] 实现 eBPF 验证器友好的代码
  - [ ] 添加运行时完整性检查
  - [ ] 实现优雅降级策略

##### Phase 2e：文档与测试

- [ ] **2e.1 文档编写**
  - [ ] 编写 eBPF 程序设计文档
  - [ ] 绘制数据包处理流程图
  - [ ] 记录 Map 数据结构设计

- [ ] **2e.2 单元测试**
  - [ ] 使用 `aya-ebpf` 测试框架
  - [ ] 测试包解析逻辑
  - [ ] 测试规则匹配逻辑

---

### Phase 3：用户态代理核心

**目标**：实现 Tokio 异步运行时和流量转发

**时间**：2-3 周

#### 任务清单

##### Phase 3a：异步运行时

- [ ] **3a.1 Tokio 集成**
  - [ ] 配置 Tokio 运行时
    ```rust
    #[tokio::main(flavor = "multi_thread", worker_threads = 8)]
    async fn main() -> Result<()> {
        // ...
    }
    ```
  - [ ] 配置 runtime metrics 采集
  - [ ] 实现 graceful shutdown

##### Phase 3b：TCP/UDP 转发

- [ ] **3b.1 连接管理**
  - [ ] 实现 `Connection` 结构体
  - [ ] 实现连接池管理器
  - [ ] 实现连接超时控制
  - [ ] 实现连接复用

- [ ] **3b.2 流量转发**
  - [ ] 实现 TCP 透明转发
  - [ ] 实现 UDP 透明转发（NAT 方式）
  - [ ] 实现 TUN 设备读写（可选）

- [ ] **3b.3 Socket 操作**
  - [ ] 使用 `socket2` 配置高性能 socket
  - [ ] 实现 SO_REUSEPORT
  - [ ] 实现 TCP_NODELAY
  - [ ] 实现 socket 池化管理

##### Phase 3c：eBPF 集成

- [ ] **3c.1 用户态加载器**
  - [ ] 实现 eBPF 程序加载
  - [ ] 实现 XDP 挂载
  - [ ] 实现 Map 同步机制

- [ ] **3c.2 控制平面**
  - [ ] 实现配置热更新
  - [ ] 实现运行时统计
  - [ ] 实现状态查询接口

##### Phase 3d：基准测试

- [ ] **3d.1 基础性能测试**
  - [ ] 实现 iperf3 吞吐量测试
  - [ ] 实现并发连接测试
  - [ ] 实现延迟测试（ping/pong）

- [ ] **3d.2 对比测试**
  - [ ] 对比 Go dae 性能
  - [ ] 记录 baseline 数据
  - [ ] 识别性能瓶颈

---

### Phase 4：代理协议实现

**目标**：实现多种代理协议支持

**时间**：4-6 周

#### Phase 4a：HTTP/SOCKS5（2 周）

- [ ] **4a.1 SOCKS5 协议**
  - [ ] 实现 SOCKS5 握手
  - [ ] 实现 CONNECT / UDP ASSOCIATE 命令
  - [ ] 实现认证机制（无认证 / 用户名密码）
  - [ ] 完整支持 RFC 1928

- [ ] **4a.2 HTTP Connect**
  - [ ] 实现 HTTP CONNECT 隧道
  - [ ] 实现 HTTP 代理认证
  - [ ] 支持 HTTPS 穿透

#### Phase 4b：Shadowsocks（2 周）

- [ ] **4b.1 Shadowsocks RFC**
  - [ ] 使用 `shadowsocks-rust` 库
  - [ ] 实现 AEAD 加密（chacha20-ietf-poly1305, aes-256-gcm）
  - [ ] 实现 OTA（一次性认证）
  - [ ] 支持多种加密方式

- [ ] **4b.2 Shadowsocks Plugin**
  - [ ] 实现 v2ray-plugin 兼容（WebSocket）
  - [ ] 实现 simple-obfs 兼容
  - [ ] 支持插件扩展

#### Phase 4c：VLESS/VMess/Trojan（2 周）

- [ ] **4c.1 VLESS 协议**
  - [ ] 实现 VLESS UUID 认证
  - [ ] 实现 VLESS 流量加密（XTLS）
  - [ ] 支持 WebSocket 传输

- [ ] **4c.2 VMess 协议**
  - [ ] 实现 VMess AEAD 加密
  - [ ] 实现 VMess 协议握手
  - [ ] 支持动态端口

- [ ] **4c.3 Trojan 协议**
  - [ ] 实现 Trojan 协议
  - [ ] 支持 TLS 卸载
  - [ ] 实现Trojan-Go 扩展

#### Phase 4d：规则引擎

- [ ] **4d.1 规则匹配**
  - [ ] 实现域名规则匹配（精确/模糊/正则）
  - [ ] 实现 IP CIDR 规则匹配
  - [ ] 实现 GeoIP 匹配（使用 maxminddb）
  - [ ] 实现进程名匹配（Linux）

- [ ] **4d.2 规则 DSL**
  - [ ] 设计规则描述语言
  - [ ] 实现规则解析器
  - [ ] 支持规则组和规则链

---

### Phase 5：配置系统

**目标**：完善配置解析和用户交互

**时间**：1-2 周

#### 任务清单

##### Phase 5a：配置格式

- [ ] **5a.1 TOML 配置**
  - [ ] 设计配置结构体
    ```rust
    #[derive(Deserialize)]
    struct Config {
        nodes: Vec<Node>,
        rules: Vec<Rule>,
        dns: DnsConfig,
        tun: TunConfig,
    }
    ```
  - [ ] 实现配置验证
  - [ ] 实现配置示例文件

- [ ] **5a.2 兼容 dae 配置**
  - [ ] 分析 dae 现有配置格式
  - [ ] 实现配置兼容层
  - [ ] 编写迁移指南

##### Phase 5b：CLI 工具

- [ ] **5b.1 命令实现**
  - [ ] 实现 `dae run` 启动守护进程
  - [ ] 实现 `dae status` 查询状态
  - [ ] 实现 `dae reload` 热更新配置
  - [ ] 实现 `dae test` 测试连接

- [ ] **5b.2 控制接口**
  - [ ] 实现 Unix Domain Socket 控制接口
  - [ ] 实现 gRPC 管理接口（可选）
  - [ ] 实现信号处理（SIGTERM/SIGINT）

##### Phase 5c：Web UI（可选）

- [ ] **5c.1 Web 管理界面**
  - [ ] 设计 RESTful API
  - [ ] 实现简单 Web UI
  - [ ] 实现连接管理界面

---

### Phase 6：生产环境

**目标**：稳定性和部署准备

**时间**：2-3 周

#### 任务清单

##### Phase 6a：测试

- [ ] **6a.1 单元测试**
  - [ ] 各模块测试覆盖率 >= 80%
  - [ ] 运行 `cargo test --workspace`

- [ ] **6a.2 集成测试**
  - [ ] 编写集成测试用例
  - [ ] 端到端流量测试

- [ ] **6a.3 压力测试**
  - [ ] 持续 24 小时压力测试
  - [ ] 10K+ 并发连接测试
  - [ ] 验证内存泄漏

##### Phase 6b：稳定性

- [ ] **6b.1 内存安全**
  - [ ] 运行 `valgrind --leak-check=full`
  - [ ] 运行 `cargo miri` 测试
  - [ ] 修复所有内存问题

- [ ] **6b.2 错误处理**
  - [ ] 完善错误类型定义
  - [ ] 添加 panic recovery
  - [ ] 实现健康检查机制

##### Phase 6c：部署

- [ ] **6c.1 构建优化**
  - [ ] 启用 LTO (Link Time Optimization)
  - [ ] 启用 codegen-units = 1
  - [ ] 使用 `cargo dist` 构建发布版本

- [ ] **6c.2 Docker 容器化**
  - [ ] 创建 Dockerfile
  - [ ] 创建 docker-compose.yml
  - [ ] 多架构构建支持（amd64/arm64）

- [ ] **6c.3 部署文档**
  - [ ] 编写快速开始指南
  - [ ] 编写完整部署文档
  - [ ] 编写常见问题解答

---

## 5. 基准测试计划

### 5.1 测试环境描述

| 组件 | 配置 | 说明 |
|------|------|------|
| 测试机 A（客户端） | 4核 CPU / 8GB RAM / 1Gbps 网络 | 安装 wrk / iperf3 |
| 测试机 B（代理服务器） | 4核 CPU / 8GB RAM / 1Gbps 网络 | 运行 dae-rs / 对比软件 |
| 测试机 C（目标服务器） | 2核 CPU / 4GB RAM | 运行 nginx / echo 服务 |
| 网络 | 同一数据中心内网 | 延迟 < 1ms |

### 5.2 测试指标

| 指标 | 测试方法 | 目标值 |
|------|----------|--------|
| 吞吐量 | iperf3 单连接 | >= 800 Mbps |
| 并发吞吐量 | iperf3 10 并发 | >= 500 Mbps |
| HTTP QPS | wrk 短连接 | >= 50K QPS |
| HTTP QPS | wrk 长连接 | >= 100K QPS |
| 平均延迟 | ping 测试 | <= 1ms（同机房） |
| P99 延迟 | wrk latency | <= 5ms |
| 内存占用 | 空闲 | <= 50MB |
| 内存占用 | 10K 连接 | <= 200MB |
| CPU 占用 | 1Gbps 转发 | <= 30% 单核 |

### 5.3 对比对象

| 软件 | 版本 | 说明 |
|------|------|------|
| Go dae | latest | 原版参考 |
| sing-box | latest | 热门透明代理 |
| mihomo | latest | 高性能代理软件 |

### 5.4 测试脚本

```bash
#!/bin/bash
# benchmark.sh - dae-rs 基准测试脚本

set -e

TARGETS=("dae-rs" "dae-go" "sing-box" "mihomo")
RESULTS_DIR="./benchmark-results"
DURATION=60  # 秒

mkdir -p $RESULTS_DIR

# 吞吐量测试
for target in "${TARGETS[@]}"; do
    echo "=== Testing $target throughput ==="

    # 启动目标服务（由外部预先启动）
    iperf3 -c localhost -t $DURATION -J > "$RESULTS_DIR/${target}_iperf3.json"
done

# HTTP 测试
for target in "${TARGETS[@]}"; do
    echo "=== Testing $target HTTP ==="

    wrk -t4 -c100 -d${DURATION}s \
        --latency \
        http://localhost:8080/test \
        > "$RESULTS_DIR/${target}_wrk.txt"
done

# 报告生成
echo "=== Benchmark Complete ==="
echo "Results saved to $RESULTS_DIR"
```

---

## 6. Git 工作流

### 6.1 分支命名规范

| 类型 | 命名格式 | 示例 |
|------|----------|------|
| 功能分支 | `feature/<issue-id>-<描述>` | `feature/42-add-ebpf-map` |
| 修复分支 | `fix/<issue-id>-<描述>` | `fix/99-fix-xdp-panic` |
| 重构分支 | `refactor/<描述>` | `refactor/connection-pool` |
| 文档分支 | `docs/<描述>` | `docs/update-readme` |
| 性能分支 | `perf/<描述>` | `perf/optimize-packet-processing` |

### 6.2 提交规范

```
<type>(<scope>): <subject>

<body>

footer
```

**Type 类型：**
- `feat`: 新功能
- `fix`: 修复 bug
- `docs`: 文档更新
- `style`: 代码格式（不影响功能）
- `refactor`: 重构
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建/工具变更

**示例：**
```
feat(ebpf): add XDP packet parsing for IPv6

- Implement IPv6 header parsing
- Add TCP/UDP checksum verification
- Update eBPF map structure

Closes: #42
```

### 6.3 PR 流程

```
1. Fork 仓库（或在主仓库创建分支）
2. 创建功能分支
3. 编写代码 + 单元测试
4. 提交代码（遵循提交规范）
5. 推送分支
6. 创建 Pull Request
7. CI 检查通过
8. Code Review
9. Squash and Merge
```

### 6.4 Code Review 清单

- [ ] 代码风格符合项目规范
- [ ] 有适当的单元测试
- [ ] 没有引入新的编译警告
- [ ] 重大变更有文档更新
- [ ] 性能相关变更有基准测试
- [ ] 安全相关变更有安全审计
- [ ] API 变更有版本考虑

---

## 7. 风险评估

### 7.1 eBPF 复杂性

| 风险 | 影响 | 概率 | 应对策略 |
|------|------|------|----------|
| eBPF 验证器拒绝程序 | 高 | 中 | 遵循验证器友好模式编写代码，使用简化逻辑分支 |
| 内核版本兼容性问题 | 高 | 中 | 优雅降级，多内核版本测试，最低支持 5.8 |
| eBPF Map 大小限制 | 中 | 低 | 动态调整 Map 大小，监控使用率 |
| XDP 硬件兼容 | 中 | 中 | 提供多种模式（native/driver/generic） |

### 7.2 Rust 异步网络深度

| 风险 | 影响 | 概率 | 应对策略 |
|------|------|------|----------|
| async trait 稳定性 | 中 | 低 | 使用 stable 特性，避免 nightly |
| tokio 调度开销 | 中 | 低 | 合理配置 worker 数量，避免过度并发 |
| 内存泄漏（Rc/Arc 循环） | 高 | 中 | 使用 weakref，定期检查，使用 miri 测试 |
| Send/Sync 约束问题 | 中 | 中 | 仔细设计数据类型边界 |

### 7.3 代理协议兼容性

| 风险 | 影响 | 概率 | 应对策略 |
|------|------|------|----------|
| 协议版本迭代 | 中 | 高 | 参考 mihomo/sing-box 实现，快速跟进 |
| 协议混淆/变形 | 高 | 中 | 完整实现 RFC，测试多种客户端 |
| 抗检测需求 | 高 | 高 | 参考 v2ray 生态，模拟真实流量 |

### 7.4 应对策略总结

1. **技术风险**：保持与上游库同步，关注 RFC 更新
2. **性能风险**：持续进行基准测试，与竞品对比
3. **兼容风险**：准备配置迁移工具，降低用户迁移成本
4. **社区风险**：积极与其他开源项目交流，贡献上游

---

## 8. 团队分工建议

### 8.1 Solo 开发（推荐初期）

| 阶段 | 负责人 | 职责 |
|------|--------|------|
| Phase 0-1 | 开发者 | 环境搭建、项目初始化 |
| Phase 2 | 开发者 | eBPF 核心开发（最难点） |
| Phase 3 | 开发者 | 用户态代理 |
| Phase 4 | 开发者 | 协议实现 |
| Phase 5-6 | 开发者 | 配置、测试、部署 |

**Solo 开发优势：**
- 代码风格统一
- 减少沟通成本
- 完整掌控架构设计

**Solo 开发劣势：**
- 时间周期长
- 难以覆盖多场景测试
- 缺少 Code Review

### 8.2 团队协作模式（后期）

| 角色 | 人数 | 职责 |
|------|------|------|
| 架构师 | 1 | 技术方案设计、代码 Review |
| eBPF 工程师 | 1-2 | Phase 2 开发 |
| 代理工程师 | 2-3 | Phase 3-4 开发 |
| 测试工程师 | 1 | 基准测试、质量保障 |
| DevOps | 1 | CI/CD、部署文档 |

### 8.3 推荐开发顺序

```
Phase 0 (1-2天) → Phase 1 (1天) → Phase 2 (2-3周) → Phase 3 (2-3周)
    → Phase 4 (4-6周) → Phase 5 (1-2周) → Phase 6 (2-3周)

总工期预估：12-19 周（约 3-5 个月）
```

---

## 9. 参考资料

### 9.1 官方文档

| 资源 | 链接 |
|------|------|
| dae 官方仓库 | https://github.com/daeuniverse/dae |
| aya 文档 | https://aya-rs.dev/book/ |
| aya eBPF 文档 | https://docs.rs/aya-ebpf/latest/aya_ebpf/ |
| tokio 文档 | https://tokio.rs/tokio/tutorial |
| Rust eBPF CO-RE | https://github.com/aya-rs/aya |

### 9.2 代理协议规范

| 协议 | 规范链接 |
|------|----------|
| Shadowsocks | https://shadowsocks.org/guide/what-is-shadowsocks.html |
| SOCKS5 | RFC 1928 |
| VLESS | https://xtls.github.io/ |
| VMess | https://www.v2fly.org/ |
| Trojan | https://trojan-gfw.github.io/ |

### 9.3 开源项目参考

| 项目 | 仓库 | 学习要点 |
|------|------|----------|
| mihomo | https://github.com/MetaCubeX/mihomo | 代理协议实现、规则引擎 |
| sing-box | https://github.com/SagerNet/sing-box | 多协议支持、配置设计 |
| snail-proxy | https://github.com/snail007/snail-proxy | Go 透明代理参考 |
| lava | https://github.com/daeuniverse/lava | dae 的 Web UI |

### 9.4 eBPF 学习资源

| 资源 | 说明 |
|------|------|
| BPF Performance Tools | Brendan Gregg 著，eBPF 权威指南 |
| Linux eBPF 文档 | https://www.kernel.org/doc/html/latest/bpf/ |
| XDP 教程 | https://github.com/xdp-project/xdp-tutorial |

---

## 附录 A：Milestones 概览

| Milestone | 内容 | 目标时间 |
|-----------|------|----------|
| M1 | Phase 0-1 完成，可编译运行 | Week 1 |
| M2 | Phase 2 完成，XDP 流量捕获 | Week 4-6 |
| M3 | Phase 3 完成，基础代理功能 | Week 7-9 |
| M4 | Phase 4 完成，主流协议支持 | Week 11-15 |
| M5 | Phase 5 完成，配置系统完善 | Week 16-17 |
| M6 | Phase 6 完成，生产就绪 | Week 18-21 |

---

*文档版本：v1.0*
*创建日期：2026-04-01*
*最后更新：2026-04-01*
