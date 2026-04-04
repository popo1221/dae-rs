# dae-rs

> Rust 实现的高性能透明代理

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org)

## 项目概述

dae-rs 是 [dae](https://github.com/daeuniverse/dae) 的 Rust 语言重实现，目标是在保持功能完整性的同时提供更优秀的性能和内存安全性。

### 核心特性

- **零成本抽象**: Rust 语言特性带来接近 C 的性能
- **内存安全**: 无 GC 停顿，无数据竞争
- **异步 I/O**: Tokio 异步运行时，高并发支持
- **eBPF 集成**: 内核级流量拦截，减少用户态开销

## 功能实现状态

### 代理协议

| 协议 | 状态 | 说明 |
|------|------|------|
| VLESS + Reality | ✅ 完整 | Vision flow 支持 |
| VMess AEAD-2022 | ✅ 完整 | 最新标准 |
| Shadowsocks AEAD | ✅ 完整 | 流加密不支持 |
| Trojan | ✅ 完整 | TCP + UDP Associate |
| TUIC | ✅ 完整 | QUIC 传输 |
| Hysteria2 | ✅ 完整 | 激进拥塞控制 |
| Juicity | ✅ 完整 | 轻量 QUIC |
| NaiveProxy/AnyTLS | ✅ 完整 | 链式代理 |
| SOCKS5 | ✅ 完整 | RFC 1928 |
| SOCKS4/SOCKS4A | ✅ 完整 | 传统协议 |
| HTTP Proxy | ✅ 完整 | CONNECT 支持 |

### 传输层

| 传输方式 | 状态 | 说明 |
|----------|------|------|
| TCP | ✅ | 原始 TCP |
| TLS | ✅ | 标准 TLS + Reality |
| WebSocket | ✅ | HTTP 伪装 |
| HTTP Upgrade | ✅ | 1.1 Upgrade |
| gRPC | ⚠️ 部分 | 仅流式传输 |
| Meek | ✅ | 域前置/云函数/指向器 |

### eBPF 集成

| 模块 | 状态 |
|------|------|
| XDP 模式 | ✅ |
| TC hooks | ✅ |
| Sockmap | ✅ |

## 快速开始

### 前置要求

- Rust 1.75+
- clang, llvm, libelf-dev, linux-headers

### 构建

```bash
# 克隆项目
git clone https://github.com/popo1221/dae-rs.git
cd dae-rs

# Debug 构建
cargo build

# Release 构建 (推荐)
cargo build --release

# 构建产物
./target/release/dae
```

### 运行

```bash
# 查看帮助
./target/release/dae --help

# 运行 (需要配置文件)
./target/release/dae run --config config/config.toml

# 验证配置
./target/release/dae validate --config config/config.toml

# 查看状态
./target/release/dae status

# 热重载配置
./target/release/dae reload

# 关闭服务
./target/release/dae shutdown
```

### 配置文件示例

```toml
[proxy]
socks5_listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"
ebpf_enabled = true

[transparent_proxy]
enabled = true
tun_ip = "172.16.0.1"
dns_hijack = ["8.8.8.8:53"]
auto_route = true

[logging]
level = "info"

[[nodes]]
name = "示例节点"
type = "vless"
server = "example.com"
port = 443
uuid = "your-uuid"
tls = true
```

详细配置请参考 [配置文档](docs/CONFIG.md)。

## 文档目录

| 文档 | 内容 |
|------|------|
| [docs/README.md](docs/00-README.md) | 项目概览 |
| [docs/INSTALL.md](docs/INSTALL.md) | 安装指南 |
| [docs/CONFIG.md](docs/CONFIG.md) | 配置参考 |
| [docs/PROTOCOLS.md](docs/PROTOCOLS.md) | 协议详情 |
| [docs/TRANSPORTS.md](docs/TRANSPORTS.md) | 传输层 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 内部架构 |
| [docs/TESTING.md](docs/TESTING.md) | 测试指南 |

## 测试

```bash
# 运行所有测试
cargo test --workspace

# 运行单元测试
cargo test

# 运行集成测试
cargo test --test e2e_*

# 代码覆盖率
make coverage
```

## 项目结构

```
dae-rs/
├── packages/
│   ├── dae-cli/           # 命令行工具
│   ├── dae-config/        # 配置解析
│   ├── dae-core/          # 核心引擎
│   ├── dae-proxy/         # 代理协议实现 (~50K LOC)
│   └── dae-ebpf/          # eBPF 集成
│       ├── dae-xdp/       # XDP 模式
│       ├── dae-ebpf/      # TC hooks
│       └── dae-ebpf-direct/ # Sockmap
├── config/                # 配置示例
└── docs/                  # 文档
```

## 性能对比

| 指标 | dae (Go) | dae-rs (Rust) |
|------|----------|---------------|
| 内存占用 | ~50MB | ~20MB |
| 启动时间 | ~200ms | ~50ms |
| 连接吞吐量 | 100K/s | 150K/s |

## 开发

```bash
# 格式化代码
make format

# 运行 clippy
make clippy

# 运行所有检查
make ci
```

## License

MIT License - see LICENSE file for details.

## 相关项目

- [dae](https://github.com/daeuniverse/dae) - Go 语言原版
- [v2ray-core](https://github.com/v2fly/v2ray-core) - 参考协议实现
- [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) - Shadowsocks Rust 实现
