# dae-cli 命令行接口 - 功能描述

## 概述
dae-cli 是 dae-rs 的命令行工具，提供代理运行、状态查看、配置验证、热重载等功能。

## 命令列表

### dae run
运行代理服务。
```bash
dae run <config.toml> [OPTIONS]
```

### dae status
查看代理运行状态。
```bash
dae status [--socket <path>]
```

### dae validate
验证配置文件。
```bash
dae validate <config.toml>
```

### dae reload
热重载配置。
```bash
dae reload [--socket <path>]
```

### dae test
测试特定节点连通性。
```bash
dae test <node_name> [--socket <path>]
```

### dae shutdown
关闭守护进程。
```bash
dae shutdown [--socket <path>]
```

## 使用示例

### 运行代理
```bash
# 前台运行
dae run /etc/dae/config.toml

# 后台守护进程运行
dae run /etc/dae/config.toml -d --pid-file /var/run/dae/dae.pid
```

### 查看状态
```bash
dae status --socket /var/run/dae/control.sock
```

### 验证配置
```bash
dae validate /etc/dae/config.toml
```

### 测试节点
```bash
dae test my-trojan-node --socket /var/run/dae/control.sock
```

## 配置项 (命令行参数)

| 参数 | 缩写 | 类型 | 说明 |
|------|------|------|------|
| `config` | `c` | PathBuf | 配置文件路径 |
| `daemon` | `d` | bool | 后台守护进程模式 |
| `pid-file` | - | Option<String> | PID 文件路径 |
| `control-socket` | - | String | 控制 socket 路径 |
| `socket` | - | String | status/reload/test/shutdown 用 |

## 流程图/数据流

### dae run 流程
```
1. 解析命令行参数
2. 读取配置文件 (TOML)
3. 验证配置
4. 构建 ProxyConfig
5. 创建 ControlServer
6. 创建 Proxy 实例
7. 启动 tokio runtime
8. 等待 shutdown 信号
9. 优雅关闭
```

### dae status 流程
```
1. 连接 Unix Domain Socket
2. 发送 "status\n"
3. 读取 JSON 响应
4. 打印状态信息
```

## 入口点
```rust
// packages/dae-cli/src/main.rs

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>

async fn run_proxy(config, daemon, pid_file, control_socket)
```

## 错误处理

| 错误类型 | 场景 | 处理方式 |
|----------|------|----------|
| `ConfigParseError` | 配置文件解析失败 | 打印错误，退出码 1 |
| `ValidationError` | 配置验证失败 | 打印错误，退出码 1 |
| `ConnectionFailed` | 无法连接 control socket | 打印错误 |
| `ResponseError` | control 命令执行失败 | 打印错误信息 |

## 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 1 | 配置错误或执行失败 |
| 2 | 无效命令 |

## 依赖

- `clap`: 命令行参数解析
- `tokio`: 异步运行时
- `dae_config`: 配置解析
- `dae_proxy`: 代理核心
- `tracing_subscriber`: 日志追踪
