#!/bin/bash
# =============================================================================
# T5: Prometheus Metrics 测试 (Prometheus Metrics Test)
# =============================================================================
# 场景: 验证 Prometheus metrics 导出功能
# 前置条件: dae-proxy 运行，Prometheus metrics enabled
# =============================================================================

set -e

# 配置
API_HOST="${API_HOST:-localhost}"
API_PORT="${API_PORT:-8080}"
API_BASE="http://${API_HOST}:${API_PORT}"
METRICS_PATH="${METRICS_PATH:-/metrics}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 日志函数
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

echo "=========================================="
echo "T5: Prometheus Metrics 测试"
echo "=========================================="
echo ""

# Step 1: 检查 Metrics 端点
log_info "Step 1: 检查 Prometheus Metrics 端点..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE}${METRICS_PATH}")
if [ "$HTTP_CODE" = "200" ]; then
    log_info "Metrics 端点可访问 (HTTP $HTTP_CODE)"
else
    log_fail "Metrics 端点不可访问 (HTTP $HTTP_CODE)"
    log_info "尝试备用端口..."
    # 可能配置在不同端口
    for PORT in 8080 9090 8081; do
        ALT_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://${API_HOST}:${PORT}${METRICS_PATH}" || echo "000")
        if [ "$ALT_CODE" = "200" ]; then
            API_PORT="$PORT"
            log_info "找到 Metrics 端点在端口 $PORT"
            break
        fi
    done
fi
echo ""

# Step 2: 获取 Metrics 内容
log_info "Step 2: 获取 Metrics 内容..."
METRICS=$(curl -s "${API_BASE}:${API_PORT}${METRICS_PATH}")
METRICS_LINES=$(echo "$METRICS" | wc -l)
log_info "Metrics 内容行数: $METRICS_LINES"
echo ""

# Step 3: 检查必要指标
log_info "Step 3: 检查必要指标..."

REQUIRED_METRICS=(
    "dae_packets_total"
    "dae_bytes_total"
    "dae_connections_total"
    "dae_connections_active"
    "dae_dns_queries_total"
)

PASS_COUNT=0
FAIL_COUNT=0

for metric in "${REQUIRED_METRICS[@]}"; do
    if echo "$METRICS" | grep -q "^${metric} "; then
        VALUE=$(echo "$METRICS" | grep "^${metric} " | awk '{print $2}')
        log_info "  [OK] $metric = $VALUE"
        ((PASS_COUNT++))
    else
        log_warn "  [MISSING] $metric"
    fi
done
echo ""

# Step 4: 检查 DNS 指标
log_info "Step 4: 检查 DNS 指标..."
DNS_METRICS=$(echo "$METRICS" | grep "^dae_dns" | head -10)
if [ -n "$DNS_METRICS" ]; then
    log_info "DNS 指标存在:"
    echo "$DNS_METRICS" | while read line; do
        log_info "  $line"
    done
    ((PASS_COUNT++))
else
    log_warn "DNS 指标未找到 (可能未启用 DNS 追踪)"
fi
echo ""

# Step 5: 检查协议指标
log_info "Step 5: 检查协议指标..."
PROTOCOL_METRICS=$(echo "$METRICS" | grep "^dae_protocol" | head -10)
if [ -n "$PROTOCOL_METRICS" ]; then
    log_info "协议指标存在:"
    echo "$PROTOCOL_METRICS" | while read line; do
        log_info "  $line"
    done
    ((PASS_COUNT++))
else
    log_warn "协议指标未找到"
fi
echo ""

# Step 6: 验证指标格式
log_info "Step 6: 验证 Prometheus 格式..."

# 检查格式: metric_name{labels} value
FORMAT_VALID=true
for metric in $(echo "$METRICS" | grep -E "^[a-z].*{" | head -5); do
    if ! echo "$metric" | grep -qE "^[a-z_]+{[^}]*} [0-9.e+-]+"; then
        FORMAT_VALID=false
        log_warn "  格式可能不标准: $metric"
    fi
done

if [ "$FORMAT_VALID" = true ]; then
    log_info "Prometheus 格式验证 PASS"
    ((PASS_COUNT++))
else
    log_warn "部分指标格式可能不标准"
fi
echo ""

# Step 7: 检查 Content-Type
log_info "Step 7: 检查 Content-Type..."
CONTENT_TYPE=$(curl -s -I "${API_BASE}:${API_PORT}${METRICS_PATH}" | grep -i "content-type" | head -1)
log_info "Content-Type: $CONTENT_TYPE"
if echo "$CONTENT_TYPE" | grep -qi "text/plain"; then
    log_info "Content-Type 正确 (text/plain)"
    ((PASS_COUNT++))
else
    log_warn "Content-Type 可能不正确"
fi
echo ""

# =============================================================================
# 验证结果
# =============================================================================

echo "=========================================="
echo "T5 验证结果"
echo "=========================================="
echo ""

# 统计 PASS/FAIL
TOTAL_CHECKS=${#REQUIRED_METRICS[@]}
METRICS_PRESENT=$(echo "$METRICS" | grep -c "^dae_")
DNS_METRICS_PRESENT=$(echo "$METRICS" | grep -c "^dae_dns")

log_info "必要指标存在: $PASS_COUNT/${#REQUIRED_METRICS[@]}"
log_info "dae_* 指标总数: $METRICS_PRESENT"
log_info "dae_dns_* 指标数: $DNS_METRICS_PRESENT"
echo ""

# 最终判定
if [ "$METRICS_LINES" -gt 10 ] && [ "$PASS_COUNT" -ge 4 ]; then
    echo -e "${GREEN}T5 测试结果: PASS${NC}"
    echo "Prometheus Metrics 导出功能正常"
    exit 0
else
    echo -e "${YELLOW}T5 测试结果: PARTIAL${NC}"
    echo "部分 Metrics 可能缺失，建议检查配置"
    exit 1
fi
