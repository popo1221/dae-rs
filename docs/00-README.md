# dae-rs 项目文档

> 高性能透明代理的 Rust 实现

## 项目概述

dae-rs 是一个用 Rust 编写的**高性能透明代理**，通过 Rust 的零成本抽象和内存安全保证来实现更好的性能。项目是 Go 语言 dae 的 Rust 重实现，目标是在保持功能完整性的同时提供更优秀的性能。

## 核心模块架构

```
┌─────────────────────────────────────────────────────────────┐
│                         dae-cli                              │
│                   (命令行接口 & 配置加载)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
         ┌───────────┴───────────┐
         ▼                       ▼
┌─────────────────────┐  ┌─────────────────────┐
│      dae-core       │  │     dae-proxy       │
│    (核心引擎)        │  │   (代理协议实现)     │
│  - 规则引擎          │  │  - 10+ 代理协议     │
│  - 节点管理          │  │  - 连接池管理        │
│  - DNS 解析         │  │  - TCP/UDP 转发     │
└─────────────────────┘  └─────────────────────┘
         │                       │
         └───────────┬───────────┘
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                       dae-ebpf                              │
│              (eBPF/XDP 内核级流量拦截)                        │
├─────────────────────────────────────────────────────────────┤
│  dae-xdp      │   dae-ebpf      │   dae-ebpf-direct        │
│  (XDP 模式)   │   (通用 eBPF)   │   (Sockmap 模式)         │
└─────────────────────────────────────────────────────────────┘
```

## 核心组件

### 1. dae-proxy - 代理核心 (~50K LOC)
最大且最核心的 crate，实现所有代理协议和流量转发逻辑。

| 子模块 | 功能 |
|--------|------|
| `connection_pool` | 连接池，4-tuple 键 + IPv6 CompactIp 支持 |
| `tcp` / `udp` | TCP/UDP 流量转发 |
| `vless` | VLESS + Reality 协议 |
| `vmess` | VMess AEAD-2022 协议 |
| `shadowsocks` | Shadowsocks AEAD (2022) |
| `trojan_protocol` | Trojan 协议 |
| `tuic` | TUIC 协议 (QUIC-based) |
| `hysteria2` | Hysteria2 协议 (QUIC-based) |
| `juicity` | Juicity 协议 (QUIC-based) |
| `naiveproxy` | NaiveProxy/AnyTLS 链式代理 |
| `socks4` / `socks5` | SOCKS4/SOCKS5 协议 |
| `http_proxy` | HTTP 代理协议 |
| `rule_engine` | 规则引擎 |
| `transport/*` | 传输层抽象 (TCP/TLS/WebSocket/gRPC/Meek) |

### 2. dae-config - 配置解析 (~2K LOC)
配置文件解析、订阅格式支持、规则配置。

| 功能 | 说明 |
|------|------|
| 订阅格式 | Clash YAML、Sing-Box JSON、SIP008、V2Ray URI |
| 规则配置 | Domain/IP/GeoIP/Process 规则 |
| 节点配置 | 通用节点结构，支持多种协议 |

### 3. dae-core - 核心引擎 (~500 LOC)
基础引擎接口，抽象核心功能。

### 4. dae-cli - 命令行 (~3K LOC)
命令行工具，支持 `run`、`status`、`validate`、`reload`、`shutdown`、`test` 子命令。

### 5. dae-ebpf - eBPF 集成
内核级流量拦截模块。

| 模块 | 用途 |
|------|------|
| `dae-xdp` | XDP (Express Data Path) 模式 |
| `dae-ebpf` | 通用 eBPF 模式 (TC hooks) |
| `dae-ebpf-direct` | Sockmap 加速模式 |
| `dae-ebpf-common` | 共享类型和常量 |

## 支持的代理协议

| 协议 | 状态 | 说明 |
|------|------|------|
| **VLESS + Reality** | ✅ 完整 | 最完整的协议支持，包含 Vision flow |
| **VMess AEAD-2022** | ✅ 完整 | VMess 协议最新标准 |
| **Shadowsocks AEAD** | ✅ 完整 | 2022 版本，流加密不支持 |
| **Trojan** | ✅ 完整 | TCP 全支持，UDP Associate 已实现 |
| **TUIC** | ✅ 完整 | QUIC 传输的高性能代理 |
| **Hysteria2** | ✅ 完整 | 激进拥塞控制，高带宽场景 |
| **Juicity** | ✅ 完整 | 基于 QUIC 的轻量代理 |
| **NaiveProxy/AnyTLS** | ✅ 完整 | 链式代理，支持 Camo/Phantun |
| **SOCKS5** | ✅ 完整 | RFC 1928 标准 |
| **SOCKS4/SOCKS4A** | ✅ 完整 | 传统 SOCKS 协议 |
| **HTTP Proxy** | ✅ 完整 | HTTP CONNECT 代理 |

## 支持的传输层

| 传输方式 | 状态 | 说明 |
|----------|------|------|
| **TCP** | ✅ 完整 | 原始 TCP 连接 |
| **TLS** | ✅ 完整 | 标准 TLS，包含 Reality 支持 |
| **WebSocket** | ✅ 完整 | 伪装为 WebSocket 流量 |
| **HTTP Upgrade** | ✅ 完整 | HTTP 1.1 Upgrade 机制 |
| **gRPC** | ⚠️ 部分 | 仅支持流式传输 (streaming) |
| **Meek** | ✅ 完整 | 支持所有 tactics (域前置/云函数/指向器) |

## 文档目录

| 文档 | 内容 |
|------|------|
| [README.md](README.md) | 项目概述和快速开始 |
| [INSTALL.md](INSTALL.md) | 安装指南 |
| [CONFIG.md](CONFIG.md) | 配置参考手册 |
| [PROTOCOLS.md](PROTOCOLS.md) | 协议实现详情 |
| [TRANSPORTS.md](TRANSPORTS.md) | 传输层详解 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 内部架构设计 |
| [TESTING.md](TESTING.md) | 测试指南 |

## 快速开始

```bash
# 构建
cargo build --release

# 运行
./target/release/dae run --config config.toml

# 查看状态
./target/release/dae status

# 验证配置
./target/release/dae validate --config config.toml
```

## 项目信息

- **语言**: Rust (零成本抽象 + 内存安全)
- **架构**: 异步 I/O (Tokio runtime)
- **许可**: MIT
- **测试覆盖**: 500+ 测试用例
