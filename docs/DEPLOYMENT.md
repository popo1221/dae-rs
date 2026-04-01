# dae-rs Deployment Guide

This document covers deployment methods for dae-rs, including Docker, Kubernetes, and Helm Chart installations.

## Table of Contents

- [Quick Start with Docker](#quick-start-with-docker)
- [Docker Compose](#docker-compose)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Helm Chart](#helm-chart)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Quick Start with Docker

### Prerequisites

- Docker 20.10+
- Linux kernel 5.8+ (for XDP support)
- Privileged container support

### Build Image

```bash
# Clone repository
git clone https://github.com/popo1221/dae-rs.git
cd dae-rs

# Build Docker image
docker build -t dae-rs:latest .
```

### Run Container

dae-rs requires privileged mode for eBPF/XDP operations:

```bash
# Run with full privileges (required for eBPF)
docker run -d \
  --name dae-rs \
  --network host \
  --privileged \
  --security-opt seccomp=unconfined \
  --cap-add=SYS_ADMIN \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_RESOURCE \
  -v /path/to/config.yml:/etc/dae/config.yml:ro \
  -v dae-data:/var/lib/dae \
  -v dae-logs:/var/log/dae \
  -e RUST_LOG=info \
  dae-rs:latest
```

### Multi-Architecture Build

The Dockerfile supports both amd64 and arm64:

```bash
# Enable docker buildx
docker buildx create --use
docker buildx inspect --bootstrap

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t dae-rs:latest \
  --push \
  .
```

---

## Docker Compose

### Basic Usage

```bash
# Start dae-rs
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Development Mode

For development with live source mounting:

```bash
# Start development container (with source mounted)
docker-compose --profile dev up -d dae-dev

# Attach to development shell
docker exec -it dae-rs-dev /bin/bash
```

### Configuration

Edit `config/config.yml` before starting:

```bash
# Create config directory
mkdir -p config

# Copy example config
cp your-config.yml config/config.yml
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |
| `DAE_VERBOSE` | `false` | Enable verbose output |
| `DAE_INTERFACE` | (auto) | Network interface for XDP |

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.19+
- kubectl configured with cluster access
- Privileged Pod Security Policy or Pod Security Standards

### Quick Deploy

```bash
# Create namespace and RBAC
kubectl apply -f k8s/rbac.yaml

# Apply ConfigMap
kubectl apply -f k8s/configmap.yaml

# Deploy DaemonSet
kubectl apply -f k8s/deployment.yaml

# Check status
kubectl get pods -n dae-rs
kubectl get daemonset -n dae-rs
```

### Verify Deployment

```bash
# Check pods are running on each node
kubectl get pods -n dae-rs -o wide

# View logs
kubectl logs -n dae-rs -l app=dae-rs --tail=100

# Test from a pod
kubectl run test --rm -it --image=curlimages/curl --restart=Never -- \
  curl --socks5-hostname dae-rs-control.dae-rs.svc.cluster.local:1080 http://example.com
```

### Update Configuration

```bash
# Edit ConfigMap
kubectl edit configmap dae-rs-config -n dae-rs

# Restart pods to apply changes
kubectl rollout restart daemonset/dae-rs -n dae-rs
```

### Uninstall

```bash
kubectl delete -f k8s/deployment.yaml
kubectl delete -f k8s/service.yaml
kubectl delete -f k8s/configmap.yaml
kubectl delete -f k8s/rbac.yaml
kubectl delete namespace dae-rs
```

---

## Helm Chart

### Prerequisites

- Helm 3.8+
- Kubernetes 1.19+

### Install

```bash
# Add repository (if published)
helm repo add dae-rs https://popo1221.github.io/dae-rs
helm repo update

# Or install from local chart
cd charts/dae-rs

# Install with default config
helm install dae-rs . -n dae-rs --create-namespace

# Install with custom values
helm install dae-rs . -n dae-rs --create-namespace \
  --set dae.logLevel=debug \
  --set config.inline="$(cat /path/to/config.yml)"
```

### Configuration

#### Basic Configuration

```yaml
# values.yaml
image:
  repository: ghcr.io/popo1221/dae-rs
  tag: latest

config:
  inline: |
    global:
      log_level: info
    inbound:
      - name: socks5
        type: socks5
        listen: 0.0.0.0:1080
    outbound:
      - name: direct
        type: direct
    rules:
      - type: default
        outbound: direct

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 2000m
    memory: 1Gi
```

#### Advanced Configuration

```yaml
# With persistence
persistence:
  enabled: true
  storageClass: "fast-ssd"
  size: 10Gi

# With custom inbound/outbound
config:
  inline: |
    global:
      log_level: info
      tcp_timeout: 300
      udp_timeout: 600

    inbound:
      - name: socks5
        type: socks5
        listen: 0.0.0.0:1080
        udp: true
      - name: http
        type: http
        listen: 0.0.0.0:8080

    outbound:
      - name: direct
        type: direct
      - name: vmess-us
        type: vmess
        server: 203.0.113.1
        port: 10086
        uuid: your-uuid
        security: auto
        alter_id: 0

    rules:
      - type: field
        ip_cidr:
          - 10.0.0.0/8
          - 172.16.0.0/12
        outbound: direct
      - type: default
        outbound: vmess-us
```

### Helm Commands

```bash
# Upgrade
helm upgrade dae-rs . -n dae-rs

# Rollback
helm rollback dae-rs -n dae-rs

# Uninstall
helm uninstall dae-rs -n dae-rs

# List releases
helm list -n dae-rs

# Get all values
helm get values dae-rs -n dae-rs
```

---

## Configuration

### Example Configuration

```yaml
global:
  log_level: info
  tcp_timeout: 300
  udp_timeout: 600

inbound:
  - name: socks5
    type: socks5
    listen: 0.0.0.0:1080
    udp: true

  - name: http
    type: http
    listen: 0.0.0.0:8080

outbound:
  - name: direct
    type: direct

  - name: vmess-sg
    type: vmess
    server: 203.0.113.1
    port: 10086
    uuid: 00000000-0000-0000-0000-000000000001
    security: auto
    alter_id: 0

  - name: vless-us
    type: vless
    server: 203.0.113.2
    port: 443
    uuid: 00000000-0000-0000-0000-000000000002
    tls: true
    sni: example.com

rules:
  # Direct connect for private networks
  - type: field
    ip_cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 127.0.0.0/8
    outbound: direct

  # Default to VMess
  - type: default
    outbound: vmess-sg
```

### Configuration Reference

See [CONFIG.md](CONFIG.md) for full configuration reference.

---

## Troubleshooting

### Docker Issues

#### eBPF Load Failure

```
Error: failed to load XDP program
```

**Solution:**
```bash
# Check kernel support
dmesg | grep -i xdp
cat /proc/sys/kernel/bpf_stats_enabled

# Verify capabilities
docker run --rm --privileged dae-rs:latest capsh --print
```

#### Permission Denied

```
Error: operation not permitted
```

**Solution:**
```bash
# Ensure privileged mode
docker run --privileged ...

# Or specific capabilities
docker run \
  --cap-add=SYS_ADMIN \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_RESOURCE \
  ...
```

### Kubernetes Issues

#### Pods Not Starting

```bash
# Check RBAC
kubectl auth can-i use podsecuritypolicy/dae-rs-privileged -n dae-rs

# Check node resources
kubectl describe nodes | grep -A5 "Allocated resources"

# View pod events
kubectl describe pod -n dae-rs <pod-name>
```

#### eBPF on Specific Nodes

```bash
# Check which nodes have dae-rs pods
kubectl get pods -n dae-rs -o wide

# Check kernel version on nodes
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}: {.status.nodeInfo.kernelVersion}{"\n"}{end}'
```

#### Network Conflicts

If dae-rs conflicts with CNI:
1. Use `--force` flag to override interface checks
2. Exclude dae-rs interfaces in CNI config
3. Consider using Cilium CNI (XDP-compatible)

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `XDP attach failed` | Interface in use | Stop other XDP programs |
| `bpf() operation not permitted` | Missing capabilities | Add SYS_ADMIN capability |
| `failed to open BPF map` | Kernel module issue | Load required modules |
| `No such device` | Interface not found | Check interface name |

### Debug Mode

Enable debug logging:

```bash
# Docker
docker run -e RUST_LOG=debug dae-rs:latest

# Kubernetes
kubectl set env daemonset/dae-rs -n dae-rs RUST_LOG=debug

# View verbose logs
kubectl logs -n dae-rs -l app=dae-rs --tail=1000 | grep -i debug
```

### Health Check

```bash
# Check if dae is running
docker exec dae-rs pgrep dae

# Kubernetes
kubectl exec -n dae-rs -l app=dae-rs -- pgrep dae

# Check control plane (if exposed)
curl http://localhost:9090/status
```

---

## Security Considerations

### Production Checklist

- [ ] Use read-only root filesystem where possible
- [ ] Run as non-root user (if functionality allows)
- [ ] Use Secrets for sensitive configuration
- [ ] Enable audit logging
- [ ] Regular security scans with Trivy
- [ ] Keep kernel and Docker updated
- [ ] Use network policies to restrict access

### Capabilities

dae-rs requires these capabilities for eBPF/XDP:

| Capability | Purpose |
|------------|---------|
| SYS_ADMIN | eBPF system operations |
| NET_ADMIN | Network configuration |
| SYS_RESOURCE | Increase resource limits |
| NET_RAW | Raw packet processing |
| IPC_LOCK | Lock memory |

---

## Support

- GitHub Issues: https://github.com/popo1221/dae-rs/issues
- Documentation: https://github.com/popo1221/dae-rs/docs
