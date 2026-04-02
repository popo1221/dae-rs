# ===================================================================
# dae-rs - Multi-stage Dockerfile for production
# ===================================================================
# Stage 1: Build
FROM rust:1.85 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    make \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy all workspace members needed for dae-cli
COPY Cargo.toml Cargo.lock* ./
COPY packages/ ./packages/
COPY benches/ ./benches/

# Build only dae-cli package
RUN cargo build --release --package dae-cli

# ===================================================================
# Stage 2: Runtime - Ubuntu-based for broad compatibility
# ===================================================================
FROM ubuntu:22.04 AS runtime

# metadata
LABEL maintainer="dae-rs"
LABEL description="High-performance transparent proxy in Rust with eBPF"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libelf1 \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for dae
RUN groupadd -r dae && useradd -r -g dae dae

# Copy binary from builder
COPY --from=builder /build/target/release/dae /usr/local/bin/dae

# Create config and data directories
RUN mkdir -p /etc/dae /var/log/dae /var/lib/dae && \
    chown -R dae:dae /etc/dae /var/log/dae /var/lib/dae

# Config file (mount or embed default)
COPY config/ /etc/dae/

USER dae

ENTRYPOINT ["/usr/local/bin/dae"]
CMD ["run", "--config", "/etc/dae/config.yml"]
