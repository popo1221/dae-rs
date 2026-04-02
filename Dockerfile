# ===================================================================
# dae-rs - Single-stage Dockerfile for production
# ===================================================================
FROM ubuntu:22.04

# metadata
LABEL maintainer="dae-rs"
LABEL description="High-performance transparent proxy in Rust with eBPF"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libelf1 \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (for building in container if needed)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88
ENV PATH="/root/.cargo/bin:$PATH"

# Create non-root user
RUN groupadd -r dae && useradd -r -g dae dae

# Copy source and build
WORKDIR /build
COPY . .
RUN cargo build --release --package dae-cli

# Install binary
RUN cp target/release/dae /usr/local/bin/dae && chmod +x /usr/local/bin/dae

# Create directories
RUN mkdir -p /etc/dae /var/log/dae /var/lib/dae && \
    chown -R dae:dae /etc/dae /var/log/dae /var/lib/dae

# Config file
COPY config/ /etc/dae/

USER dae

ENTRYPOINT ["/usr/local/bin/dae"]
CMD ["run", "--config", "/etc/dae/config.yml"]
