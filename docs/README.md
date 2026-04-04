# dae-rs 文档索引

dae-rs 项目完整文档目录。

## 📚 入门文档 (Getting Started)

| 文档 | 内容 |
|------|------|
| [README.md](../README.md) | 项目主页 - 功能特性、协议支持、快速开始 |
| [INSTALL.md](INSTALL.md) | 安装指南 - 源码构建、Docker、依赖 |
| [CONFIG.md](CONFIG.md) | 配置参考 - 完整配置项、订阅格式、规则语法 |

## 🔧 使用文档 (User Guides)

| 文档 | 内容 |
|------|------|
| [PROTOCOLS.md](PROTOCOLS.md) | 协议详情 - 各代理协议实现状态和配置示例 |
| [TRANSPORTS.md](TRANSPORTS.md) | 传输层 - TCP/TLS/WebSocket/Meek 等传输方式 |
| [TESTING.md](TESTING.md) | 测试指南 - 单元测试、集成测试、覆盖率 |

## 🏗️ 开发文档 (Development)

| 文档 | 内容 |
|------|------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 内部架构 - 连接池、eBPF、规则引擎、节点管理 |

## 📋 模块文档 (Module Documentation)

### 协议模块 (12 个)

| 文件 | 协议 | 状态 |
|------|------|------|
| `01-vless-reality.md` | VLESS + Reality | ✅ 完整 |
| `02-vmess-protocol.md` | VMess AEAD-2022 | ✅ 完整 |
| `03-shadowsocks.md` | Shadowsocks AEAD | ✅ 完整 |
| `04-trojan-protocol.md` | Trojan | ✅ 完整 |
| `05-socks5-proxy.md` | SOCKS5 | ✅ 完整 |
| `06-http-proxy.md` | HTTP CONNECT | ✅ 完整 |
| `07-dns-system.md` | DNS 系统 | ✅ 完整 |
| `08-nat-implementation.md` | NAT 实现 | ✅ 完整 |
| `09-anytls-proxy-chain.md` | AnyTLS | ✅ 完整 |
| `10-tuic.md` | TUIC | ✅ 完整 |
| `11-hysteria2.md` | Hysteria2 | ✅ 完整 |
| `12-juicity.md` | Juicity | ✅ 完整 |

### 核心模块 (4 个)

| 文件 | 模块 | 说明 |
|------|------|------|
| `13-ebpf-xdp.md` | eBPF/XDP | 内核级流量拦截 |
| `14-proxy-core.md` | Proxy Core | 核心协调器 |
| `15-rule-engine.md` | Rule Engine | 规则引擎 |
| `16-cli.md` | dae-cli | 命令行工具 |

### 基础设施模块 (5 个)

| 文件 | 模块 | 说明 |
|------|------|------|
| `17-config.md` | dae-config | 配置解析 |
| `18-transport-layer.md` | Transport Layer | 传输层抽象 |
| `19-control-api.md` | Control API | 控制接口 |
| `20-node-management.md` | Node Management | 节点管理 |

## 其他文档

| 文档 | 内容 |
|------|------|
| `../PRD.md` | 产品需求文档 |
| `../ARCHITECTURE.md` | 顶层架构设计 |
| `../DEPLOYMENT.md` | 部署指南 |
| `../DEVELOPMENT_PLAN.md` | 开发计划 |

## 快速链接

- **协议实现**: [PROTOCOLS.md](PROTOCOLS.md)
- **配置参考**: [CONFIG.md](CONFIG.md)
- **架构设计**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **测试指南**: [TESTING.md](TESTING.md)

---

文档更新日期: 2026-04-04
