# 测试指南

## 测试概述

dae-rs 项目拥有全面的测试覆盖，包括：

| 测试类型 | 数量 | 运行方式 |
|----------|------|----------|
| 单元测试 | 180+ | `cargo test` |
| 集成测试 | 19+ | `tests/e2e_*` |
| 性能测试 | 压力测试 | `make pressure-test` |
| 覆盖率报告 | HTML | `make coverage` |

## 运行测试

### 运行所有测试

```bash
# 工作区所有包
cargo test --workspace

# 指定包
cargo test -p dae-proxy
cargo test -p dae-config
```

### 运行特定测试

```bash
# 按名称过滤
cargo test vless
cargo test vmess
cargo test connection_pool

# 忽略特定测试
cargo test -- --skip slow_test
```

### 并行测试

```bash
# 使用所有 CPU 核心
cargo test -- --test-threads=0

# 使用指定数量
cargo test -- --test-threads=4
```

## 单元测试

### 代理协议测试

```bash
# 测试所有代理协议
cargo test -p dae-proxy protocol_

# 测试特定协议
cargo test -p dae-proxy vless_
cargo test -p dae-proxy vmess_
cargo test -p dae-proxy shadowsocks_
```

### 配置解析测试

```bash
# 测试配置解析
cargo test -p dae-config

# 测试订阅格式
cargo test -p dae-config subscription_
```

### 规则引擎测试

```bash
# 测试规则匹配
cargo test -p dae-proxy rule_engine_

# 测试规则类型
cargo test rule_domain
cargo test rule_geoip
```

### 连接池测试

```bash
# 测试连接池
cargo test -p dae-proxy connection_pool

# 测试连接复用
cargo test connection_reuse
```

## 集成测试 (E2E)

### E2E 测试列表

| 测试文件 | 测试内容 |
|----------|----------|
| `tests/e2e_config_tests.rs` | 配置加载和验证 |
| `tests/e2e_vless.rs` | VLESS 协议端到端 |
| `tests/e2e_vmess.rs` | VMess 协议端到端 |
| `tests/e2e_shadowsocks.rs` | Shadowsocks 端到端 |
| `tests/e2e_proxy_chain.rs` | 代理链测试 |

### 运行 E2E 测试

```bash
# 运行所有 E2E 测试
cargo test --test e2e_*

# 运行特定 E2E 测试
cargo test --test e2e_config_tests
cargo test --test e2e_vless

# 带日志运行
RUST_LOG=debug cargo test --test e2e_vless
```

### E2E 测试前提条件

某些 E2E 测试需要：

```bash
# 启动测试服务器
docker-compose up -d test-server

# 或使用本地测试服务器
./target/release/dae run --config tests/fixtures/test-server.toml
```

## 代码覆盖率

### 生成覆盖率报告

```bash
# 安装 tarpaulin (首次)
cargo install cargo-tarpaulin

# 生成 HTML 报告
make coverage

# 打开报告
open coverage/tarpaulin-report.html
```

### 覆盖率目标

| 模块 | 目标覆盖率 |
|------|------------|
| dae-proxy | > 80% |
| dae-config | > 90% |
| dae-core | > 70% |
| dae-cli | > 60% |

### 查看详细覆盖率

```bash
# 文本报告
cargo tarpaulin --workspace --out Text --output-dir coverage/

# Cobertura XML (CI 集成)
cargo tarpaulin --workspace --out Cobertura --output-dir coverage/

# LLVM profdata
cargo tarpaulin --workspace --out lcov --output-dir coverage/
```

## 压力测试

### 运行压力测试

```bash
# 查看压力测试文档
cat docs/PRESSURE_TEST.md

# 运行测试套件
make pressure-test
```

### 压力测试配置

```toml
[pressure_test]
# 并发连接数
connections = 1000
# 测试持续时间 (秒)
duration = 60
# 目标 QPS
target_qps = 10000
```

## TestNAT 行为

dae-rs 使用 `TestNAT` 进行 NAT 行为模拟测试：

### NAT 测试场景

| 场景 | 说明 |
|------|------|
| Full-Cone NAT | 所有外部连接都可穿越 |
| Address-Restricted | 仅允许已访问的 IP |
| Port-Restricted | 仅允许已访问的 IP:Port |
| Symmetric NAT | 每个目标使用不同映射 |

### 运行 NAT 测试

```bash
# 测试 Full-Cone NAT
cargo test nat fullcone

# 测试 UDP NAT 行为
cargo test nat udp

# 测试连接超时
cargo test nat timeout
```

### NAT 配置

```rust
pub struct NatConfig {
    pub nat_type: NatType,
    pub mapping_timeout: Duration,
    pub filtering_timeout: Duration,
}
```

## 性能基准测试

### 运行基准测试

```bash
# 启动基准测试服务器
cargo bench --no-run

# 运行所有基准测试
cargo bench

# 运行特定基准测试
cargo bench connection_pool
```

### 基准测试结果

基准测试会输出：

```
connection_pool/basic_insert/1000
                        time:   [1.2345 µs 1.5678 µs 1.8901 µs]
connection_pool/basic_lookup/1000
                        time:   [0.9876 µs 1.1234 µs 1.3456 µs]
```

## CI/CD 测试

### GitHub Actions 工作流

```yaml
# .github/workflows/test.yml
name: Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          profile: minimal
          toolchain: stable
      - name: Run tests
        run: cargo test --workspace --all-features
      - name: Run clippy
        run: cargo clippy --all -- -D warnings
      - name: Coverage
        run: make coverage
```

### 本地 CI 模拟

```bash
# 运行完整 CI 检查
make ci

# 或分步执行
make format
make clippy
make test
make coverage
```

## 测试开发

### 编写单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_uuid_validation() {
        let valid_uuid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        assert!(VlessHandler::validate_uuid(valid_uuid.as_bytes()));
    }

    #[tokio::test]
    async fn test_connection_pool_insert() {
        let pool = ConnectionPool::new();
        // 测试代码
    }
}
```

### 编写 E2E 测试

```rust
#[cfg(test)]
mod e2e_tests {
    use dae_proxy::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_vless_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // 启动服务器
        let server = VlessServer::new(config).start(listener);
        
        // 连接客户端
        let client = VlessClient::new(client_config).connect(addr).await;
        
        // 验证通信
        assert!(client.is_connected());
    }
}
```

### Mock 测试

```rust
use mockall::predicate::*;

// 创建 Mock 节点管理器
mock_node_manager! {
    MockNodeManager => {
        fn select_node() -> NodeHandle;
        fn health_check(NodeId) -> HealthCheckResult;
    }
}

#[test]
fn test_node_selection() {
    let mut mock = MockNodeManager::new();
    mock.expect_select_node()
        .returning(|| NodeHandle::new("node-1"));
    
    let node = mock.select_node();
    assert_eq!(node.name(), "node-1");
}
```

## 测试调试

### 查看详细日志

```bash
# RUST_LOG 环境变量
RUST_LOG=debug cargo test test_name

# 所有模块日志
RUST_LOG=trace cargo test

# 仅特定模块
RUST_LOG=dae_proxy::vless=debug cargo test
```

### 调试模式

```bash
# Debug 构建
cargo build
cargo test --no-run

# 使用 rust-gdb
rust-gdb target/debug/dae

# 使用 rust-lldb
rust-lldb target/debug/dae
```

### 常见测试失败排查

| 问题 | 解决方案 |
|------|----------|
| 超时 | 增加 timeout 或检查网络 |
| 端口占用 | 修改测试端口或清理进程 |
| Mock 不匹配 | 检查 mock expectations |
| 竞态条件 | 使用 mutex 或 barrier 同步 |
