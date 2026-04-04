# 安装指南

## 前置要求

### 系统依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| **Rust** | 1.75+ | Rust 工具链 |
| **clang** | 最新 | eBPF 编译支持 |
| **llvm** | 最新 | eBPF 目标 |
| **libelf-dev** | 最新 | eBPF 对象加载 |
| **linux-headers** | 最新 | 内核头文件 |

### 安装 Rust

```bash
# 使用 rustup 安装
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 或使用包管理器
# Ubuntu/Debian
apt install rustc cargo

# macOS
brew install rust
```

### 安装 eBPF 构建依赖

```bash
# Ubuntu/Debian
apt install clang llvm libelf-dev linux-headers-$(uname -r)

# CentOS/RHEL
yum install clang llvm-libelf-devel kernel-headers

# Arch Linux
pacman -S clang llvm linux-headers
```

## 从源码构建

### 克隆项目

```bash
git clone https://github.com/popo1221/dae-rs.git
cd dae-rs
```

### Debug 构建

```bash
cargo build
```

构建产物位于：
```
target/debug/dae
```

### Release 构建（推荐）

```bash
cargo build --release
```

构建产物位于：
```
target/release/dae
```

### 交叉编译

```bash
# 使用 musl 工具链静态链接
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## 验证构建

```bash
# 检查二进制
./target/release/dae --version

# 验证配置语法
./target/release/dae validate --config config/config.toml
```

## Docker 构建

```bash
# 构建镜像
docker build -t dae-rs:latest .

# 运行容器
docker run -d \
  --cap-add NET_ADMIN \
  --network host \
  -v $(pwd)/config.toml:/etc/dae/config.toml \
  dae-rs:latest
```

## 目录结构

构建完成后，主要目录结构：

```
dae-rs/
├── target/
│   ├── debug/          # Debug 构建
│   │   └── dae
│   └── release/        # Release 构建
│       └── dae         # 主程序
├── packages/
│   ├── dae-cli/        # CLI 源码
│   ├── dae-config/     # 配置解析
│   ├── dae-core/       # 核心引擎
│   ├── dae-proxy/      # 代理实现
│   └── dae-ebpf/       # eBPF 模块
├── config/             # 配置文件示例
└── docs/               # 文档目录
```

## 性能优化

### Release 优化

Release 构建会自动应用以下优化：
- LTO (Link-Time Optimization)
- CPU 特定优化 (`-C target-cpu=native`)
- 优化级别 3 (`-O3`)

### 运行时优化

```bash
# 启用内核级加速
echo 1 > /proc/sys/net/core/busy_read
echo 1 > /proc/sys/net/core/busy_poll
```

## 常见问题

### Q: 构建失败，提示缺少 libclang
```bash
# Ubuntu
apt install libclang-dev

# 或使用系统 clang
export LIBCLANG_PATH=/usr/lib/llvm-14/lib/
```

### Q: eBPF 编译失败
```bash
# 检查内核支持
cat /proc/sys/kernel/bpf_stats_enabled

# 加载 bpf 内核模块
modprobe bpf
modprobe xdp
```

### Q: 权限问题
```bash
# 需要 CAP_NET_ADMIN 运行透明代理
sudo setcap cap_net_admin+ep ./target/release/dae
```
