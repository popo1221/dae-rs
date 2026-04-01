# ===================================================================
# dae-rs - Kubernetes Deployment Notes
# ===================================================================

## Overview

dae-rs uses eBPF/XDP for high-performance packet processing. This requires
special deployment considerations that differ from typical Kubernetes workloads.

## Architecture

dae-rs runs as a DaemonSet, with one instance per Kubernetes node. Each instance:
- Attaches XDP programs to network interfaces on its node
- Processes packets in the kernel for maximum performance
- Applies routing rules defined in the configuration
- Exposes SOCKS5/HTTP proxy endpoints for workloads

## Requirements

### Kernel Requirements
- Linux kernel 5.8+ (for XDP native mode)
- eBPF subsystem enabled
- Kernel modules: xdp-util, cls_flower (optional)

### Node Requirements
- x86_64 or ARM64 CPU
- 1GB RAM minimum (2GB recommended)
- Privileged container support enabled

### Kubernetes Requirements
- Kubernetes 1.19+
- CNI plugin that doesn't conflict with XDP (Cilium recommended)
- For PSP/Pod Security: namespace must be privileged

## Deployment Steps

### 1. Create Namespace and RBAC

```bash
kubectl apply -f rbac.yaml
```

### 2. Apply ConfigMap

```bash
kubectl apply -f configmap.yaml
# Edit config with your actual proxy settings
kubectl edit configmap dae-rs-config -n dae-rs
```

### 3. Deploy dae-rs

```bash
kubectl apply -f deployment.yaml
```

### 4. Verify Deployment

```bash
# Check DaemonSet status
kubectl get daemonset -n dae-rs

# Check pods are running on each node
kubectl get pods -n dae-rs -o wide

# View logs
kubectl logs -n dae-rs -l app=dae-rs --tail=100
```

### 5. Test Connectivity

```bash
# From a test pod
kubectl run test --rm -it --image=curlimages/curl --restart=Never -- \
  curl --socks5-hostname dae-rs-control:1080 http://example.com
```

## Exposing dae-rs to Workloads

### Method 1: ClusterIP (Internal)

dae-rs is accessible within the cluster at:
- SOCKS5: `dae-rs-control.dae-rs.svc.cluster.local:1080`
- HTTP: `dae-rs-control.dae-rs.svc.cluster.local:8080`

### Method 2: NodePort

For external access, modify service.yaml to use NodePort:

```yaml
spec:
  type: NodePort
  ports:
    - name: socks5
      port: 1080
      nodePort: 30080
```

### Method 3: LoadBalancer

For cloud environments with LoadBalancer support:

```yaml
spec:
  type: LoadBalancer
  ports:
    - name: socks5
      port: 1080
      targetPort: 1080
```

## Configuration Updates

### Hot Reload

dae-rs supports configuration hot reload via:
1. ConfigMap update: `kubectl apply -f configmap.yaml`
2. Pod annotation to trigger reload (requires in-app support)

### Full Restart

For major config changes:

```bash
kubectl rollout restart daemonset/dae-rs -n dae-rs
```

## Troubleshooting

### eBPF Load Failure

Check kernel logs:
```bash
dmesg | grep -i xdp
dmesg | grep -i bpf
```

### Permission Denied

Ensure RBAC is properly applied:
```bash
kubectl auth can-i use podsecuritypolicy/dae-rs-privileged -n dae-rs
```

### Network Conflicts

If dae-rs conflicts with CNI:
1. Check CNI type (Cilium is XDP-compatible)
2. Use `--force` flag to override interface checks
3. Exclude dae-rs interfaces in CNI config

## Uninstall

```bash
# Remove dae-rs
kubectl delete -f deployment.yaml
kubectl delete -f service.yaml
kubectl delete -f configmap.yaml
kubectl delete -f rbac.yaml

# Remove namespace
kubectl delete namespace dae-rs

# Clean up host data
# (run on each node)
rm -rf /var/lib/dae
rm -rf /var/log/dae
```
