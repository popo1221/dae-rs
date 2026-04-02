# dae-rs 文档索引

本文档目录包含 dae-rs 项目的完整模块文档。

## 文档列表

### 核心模块
| 文件 | 描述 |
|------|------|
| `01-vless-reality.md` | VLESS 协议与 Reality 透明代理 |
| `02-vmess-protocol.md` | VMess 协议 (VMess-AEAD-2022) |
| `03-shadowsocks.md` | Shadowsocks AEAD 协议 |
| `04-trojan-protocol.md` | Trojan 协议与 Trojan-Go WebSocket |
| `05-socks5-proxy.md` | SOCKS5 RFC 1928 代理服务器 |
| `06-http-proxy.md` | HTTP CONNECT 隧道代理 |
| `07-dns-system.md` | DNS 解析与循环检测 |
| `08-nat-implementation.md` | Full-Cone NAT (NAT1) 实现 |
| `09-anytls-proxy-chain.md` | AnyTLS 协议与代理链 |
| `10-tuic.md` | TUIC QUIC 代理协议 |
| `11-hysteria2.md` | Hysteria2 QUIC 代理协议 |
| `12-juicity.md` | Juicity UDP 代理协议 |
| `13-ebpf-xdp.md` | eBPF/XDP 数据包分类 |
| `14-proxy-core.md` | Proxy 核心协调器 |
| `15-rule-engine.md` | 规则引擎与路由决策 |
| `16-cli.md` | dae-cli 命令行工具 |
| `17-config.md` | 配置解析与验证 |
| `18-transport-layer.md` | 传输层抽象 (TCP/TLS/WS/gRPC) |
| `19-control-api.md` | Control Socket 管理 API |
| `20-node-management.md` | 节点管理与健康检查 |

## 项目结构

```
dae-rs/
├── packages/
│   ├── dae-proxy/         # 代理核心 (20 个协议模块)
│   │   ├── protocol/      # 协议抽象层
│   │   ├── vless.rs       # VLESS
│   │   ├── vmess.rs       # VMess
│   │   ├── shadowsocks.rs  # Shadowsocks
│   │   ├── trojan_protocol/ # Trojan
│   │   ├── socks5.rs      # SOCKS5
│   │   ├── http_proxy.rs  # HTTP CONNECT
│   │   ├── dns/           # DNS 系统
│   │   ├── nat/           # NAT 实现
│   │   ├── anytls.rs      # AnyTLS
│   │   ├── tuic/          # TUIC
│   │   ├── hysteria2/      # Hysteria2
│   │   ├── juicity/       # Juicity
│   │   ├── connection_pool.rs # 连接池
│   │   ├── rule_engine.rs # 规则引擎
│   │   ├── control.rs     # 控制接口
│   │   └── proxy.rs       # 主入口
│   │
│   ├── dae-ebpf/         # eBPF 程序
│   │   ├── dae-ebpf-common/ # 共享类型
│   │   └── dae-xdp/       # XDP 程序
│   │
│   ├── dae-cli/          # 命令行工具
│   │
│   └── dae-config/       # 配置解析
│
└── docs/                 # 本文档目录
```

## 协议支持矩阵

| 协议 | 支持 | 传输加密 | UDP |
|------|------|----------|-----|
| SOCKS5 | ✅ | ❌ | ✅ (UDP Associate) |
| HTTP CONNECT | ✅ | ❌ | ❌ |
| Shadowsocks | ✅ | AEAD | ✅ |
| VLESS | ✅ | TLS/XTLS/Reality | ✅ |
| VMess | ✅ | TLS | ✅ |
| Trojan | ✅ | TLS | ✅ |
| TUIC | ✅ | QUIC | ✅ |
| Hysteria2 | ✅ | QUIC | ✅ |
| Juicity | ✅ | QUIC | ✅ |
| AnyTLS | ✅ | TLS | ❌ |

## 快速导航

- **透明代理**: 规则引擎 (`15-rule-engine.md`) + eBPF (`13-ebpf-xdp.md`)
- **VPN 协议**: VLESS (`01-vless-reality.md`), VMess (`02-vmess-protocol.md`)
- **代理协议**: SOCKS5 (`05-socks5-proxy.md`), HTTP (`06-http-proxy.md`)
- **混淆协议**: Shadowsocks (`03-shadowsocks.md`), Trojan (`04-trojan-protocol.md`)
- **高性能 QUIC**: TUIC (`10-tuic.md`), Hysteria2 (`11-hysteria2.md`), Juicity (`12-juicity.md`)
- **运维管理**: CLI (`16-cli.md`), Control API (`19-control-api.md`)
