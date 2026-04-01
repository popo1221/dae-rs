# ===================================================================
# dae-rs - Multi-stage Dockerfile for production
# ===================================================================
# Stage 1: Build
FROM rust:1.75-alpine AS builder

# Install build dependencies for eBPF/XDP
RUN apk add --no-cache \
    clang \
    llvm \
    libelf-dev \
   elfutils-dev \
    linux-headers \
    musl-dev \
    make \
    git \
    llvm16-dev

# Set working directory
WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock* ./
COPY packages/ ./packages/
COPY benches/ ./benches/

# Build all packages (this caches dependencies)
RUN mkdir -p packages/dae-cli/src && \
    echo 'fn main() {}' > packages/dae-cli/src/main.rs && \
    cargo build --release --workspace 2>/dev/null || true

# Restore actual source
COPY packages/dae-cli/src/main.rs packages/dae-cli/src/

# Build the actual project
RUN cargo build --release --package dae-cli

# ===================================================================
# Stage 2: Runtime - Minimal distroless-like image
# ===================================================================
FROM ubuntu:22.04 AS runtime

# metadata
LABEL maintainer="dae-rs"
LABEL description="High-performance transparent proxy in Rust with eBPF"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libelf1 \
    libpcap0.11 \
    iptables \
    ipset \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for dae
RUN groupadd -r dae && useradd -r -g dae dae

# Copy binary from builder
COPY --from=builder /build/target/release/dae /usr/local/bin/dae

# Copy eBPF objects (if available)
COPY --from=builder /build/target/release/deps/*.so* /usr/local/lib/ 2>/dev/null || true

# Create config and data directories
RUN mkdir -p /etc/dae /var/log/dae /var/lib/dae && \
    chown -R dae:dae /etc/dae /var/log/dae /var/lib/dae

# Config file (mount or embed default)
COPY config/ /etc/dae/

# Set capabilities for eBPF/XDP (requires CAP_SYS_ADMIN)
# Note: Container must run with --privileged or --cap-add=SYS_ADMIN
# and --security-opt seccomp=unconfined

USER dae

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep dae || exit 1

ENTRYPOINT ["/usr/local/bin/dae"]
CMD ["run", "--config", "/etc/dae/config.yml"]
