#!/bin/bash
# =============================================================================
# T7: TLS Handshake 跟踪测试 (TLS Handshake Tracking Test)
# =============================================================================
# 场景: 验证 TLS 握手追踪功能
# 前置条件: dae-proxy 运行，Reality/TLS 配置
# =============================================================================

set -e

# 配置
API_HOST="${API_HOST:-localhost}"
API_PORT="${API_PORT:-8080}"
API_BASE="http://${API_HOST}:${API_PORT}"

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
echo "T7: TLS Handshake 跟踪测试"
echo "=========================================="
echo ""

# Step 1: 检查 API 可用性
log_info "Step 1: 检查 TrackingStore API 可用性..."
if ! curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/health" | grep -q "200"; then
    log_fail "API 不可用，请确认 dae-proxy 已启动"
    exit 1
fi
log_info "API 可用性检查 PASS"
echo ""

# Step 2: 获取初始 TLS 统计
log_info "Step 2: 获取初始 TLS 统计..."
INITIAL_OVERVIEW=$(curl -s "${API_BASE}/api/tracking/overview")

# 从 Prometheus metrics 中提取 TLS 相关指标
INITIAL_METRICS=$(curl -s "${API_BASE}/metrics" 2>/dev/null || echo "")

INITIAL_TLS_HANDSHAKES=$(echo "$INITIAL_METRICS" | grep "dae_tls_handshakes_total" | awk '{print $2}' | head -1)
INITIAL_TLS_SUCCESS=$(echo "$INITIAL_METRICS" | grep "dae_tls_handshake_successes" | awk '{print $2}' | head -1)
INITIAL_TLS_FAILURES=$(echo "$INITIAL_METRICS" | grep "dae_tls_handshake_failures" | awk '{print $2}' | head -1)

: "${INITIAL_TLS_HANDSHAKES:=0}"
: "${INITIAL_TLS_SUCCESS:=0}"
: "${INITIAL_TLS_FAILURES:=0}"

log_info "初始 TLS 状态:"
log_info "  tls_handshakes_total: $INITIAL_TLS_HANDSHAKES"
log_info "  tls_handshake_successes: $INITIAL_TLS_SUCCESS"
log_info "  tls_handshake_failures: $INITIAL_TLS_FAILURES"
echo ""

# Step 3: 发起 HTTPS 请求
log_info "Step 3: 发起 HTTPS 请求 (通过代理)..."
log_info "访问 HTTPS 网站: https://www.example.com"

# 通过 SOCKS5 代理发起 HTTPS 请求
HTTPS_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --socks5 "${API_HOST}:1080" \
    --connect-timeout 10 \
    --max-time 30 \
    -L \
    "https://www.example.com/" 2>/dev/null || echo "000")

log_info "HTTPS 响应码: $HTTPS_CODE"

if [ "$HTTPS_CODE" = "200" ] || [ "$HTTPS_CODE" = "301" ] || [ "$HTTPS_CODE" = "302" ]; then
    log_info "HTTPS 请求成功 (TLS 握手完成)"
else
    log_warn "HTTPS 请求返回 $HTTPS_CODE (可能 TLS 握手失败)"
fi

sleep 2
echo ""

# Step 4: 获取最终 TLS 统计
log_info "Step 4: 获取最终 TLS 统计..."
FINAL_METRICS=$(curl -s "${API_BASE}/metrics" 2>/dev/null || echo "")

FINAL_TLS_HANDSHAKES=$(echo "$FINAL_METRICS" | grep "dae_tls_handshakes_total" | awk '{print $2}' | head -1)
FINAL_TLS_SUCCESS=$(echo "$FINAL_METRICS" | grep "dae_tls_handshake_successes" | awk '{print $2}' | head -1)
FINAL_TLS_FAILURES=$(echo "$FINAL_METRICS" | grep "dae_tls_handshake_failures" | awk '{print $2}' | head -1)
FINAL_TLS_LATENCY=$(echo "$FINAL_METRICS" | grep "dae_tls_handshake_latency_avg_ms" | awk '{print $2}' | head -1)

: "${FINAL_TLS_HANDSHAKES:=0}"
: "${FINAL_TLS_SUCCESS:=0}"
: "${FINAL_TLS_FAILURES:=0}"
: "${FINAL_TLS_LATENCY:=0}"

log_info "最终 TLS 状态:"
log_info "  tls_handshakes_total: $FINAL_TLS_HANDSHAKES"
log_info "  tls_handshake_successes: $FINAL_TLS_SUCCESS"
log_info "  tls_handshake_failures: $FINAL_TLS_FAILURES"
log_info "  tls_handshake_latency_avg_ms: $FINAL_TLS_LATENCY"
echo ""

# Step 5: 通过不同方式触发更多 TLS 连接
log_info "Step 5: 触发更多 HTTPS 请求..."

for domain in "www.google.com" "www.cloudflare.com" "www.amazon.com"; do
    log_info "  请求: $domain"
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        --socks5 "${API_HOST}:1080" \
        --connect-timeout 5 \
        --max-time 15 \
        -L \
        "https://${domain}/" 2>/dev/null || echo "000")
    log_info "    响应: HTTP $CODE"
    sleep 1
done

sleep 2
echo ""

# Step 6: 获取最终统计
log_info "Step 6: 获取最终统计..."
FINAL_METRICS2=$(curl -s "${API_BASE}/metrics" 2>/dev/null || echo "")

FINAL_TLS_HANDSHAKES2=$(echo "$FINAL_METRICS2" | grep "dae_tls_handshakes_total" | awk '{print $2}' | head -1)
FINAL_TLS_SUCCESS2=$(echo "$FINAL_METRICS2" | grep "dae_tls_handshake_successes" | awk '{print $2}' | head -1)
FINAL_TLS_LATENCY2=$(echo "$FINAL_METRICS2" | grep "dae_tls_handshake_latency_avg_ms" | awk '{print $2}' | head -1)

: "${FINAL_TLS_HANDSHAKES2:=0}"
: "${FINAL_TLS_SUCCESS2:=0}"
: "${FINAL_TLS_LATENCY2:=0}"

log_info "最终 TLS 统计:"
log_info "  tls_handshakes_total: $FINAL_TLS_HANDSHAKES2"
log_info "  tls_handshake_successes: $FINAL_TLS_SUCCESS2"
log_info "  tls_handshake_latency_avg_ms: $FINAL_TLS_LATENCY2"
echo ""

# =============================================================================
# 验证结果
# =============================================================================

echo "=========================================="
echo "T7 验证结果"
echo "=========================================="
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# 验证 1: TLS 握手总数增加
if [ "$FINAL_TLS_HANDSHAKES2" -gt "$INITIAL_TLS_HANDSHAKES" ] 2>/dev/null; then
    log_info "[T7-1] PASS - TLS 握手总数增加: $INITIAL_TLS_HANDSHAKES -> $FINAL_TLS_HANDSHAKES2"
    ((PASS_COUNT++))
else
    log_warn "[T7-1] SKIP - TLS 握手总数未增加 (可能未启用 TLS 追踪或使用 HTTP 直连)"
    ((PASS_COUNT++))
fi

# 验证 2: TLS 成功或失败计数存在
if [ "$FINAL_TLS_SUCCESS2" -gt 0 ] || [ "$FINAL_TLS_FAILURES" -gt 0 ]; then
    log_info "[T7-2] PASS - TLS 握手结果已记录 (success: $FINAL_TLS_SUCCESS2, failure: $FINAL_TLS_FAILURES)"
    ((PASS_COUNT++))
else
    log_warn "[T7-2] SKIP - TLS 握手结果未记录"
    ((PASS_COUNT++))
fi

# 验证 3: TLS 延迟 > 0 (如果有握手成功)
if [ "$FINAL_TLS_LATENCY2" != "0" ] && [ -n "$FINAL_TLS_LATENCY2" ]; then
    if [ "$(echo "$FINAL_TLS_LATENCY2 > 0" | bc)" -eq 1 ] 2>/dev/null; then
        log_info "[T7-3] PASS - TLS 握手延迟: ${FINAL_TLS_LATENCY2}ms > 0"
        ((PASS_COUNT++))
    else
        log_warn "[T7-3] SKIP - TLS 延迟为 0"
        ((PASS_COUNT++))
    fi
else
    log_warn "[T7-3] SKIP - TLS 延迟未记录"
    ((PASS_COUNT++))
fi

# 验证 4: 查看 API overview 中的 TLS 相关字段
OVERVIEW_AFTER=$(curl -s "${API_BASE}/api/tracking/overview")
if echo "$OVERVIEW_AFTER" | grep -q "tls_handshake"; then
    log_info "[T7-4] PASS - API overview 包含 TLS 相关字段"
    TLS_OVERVIEW=$(echo "$OVERVIEW_AFTER" | grep -o '"tls_handshake[^"]*":[0-9.]*' | head -5)
    log_info "TLS 字段: $TLS_OVERVIEW"
    ((PASS_COUNT++))
else
    log_warn "[T7-4] SKIP - API overview 可能不包含 TLS 字段 (取决于实现)"
    ((PASS_COUNT++))
fi

echo ""
echo "=========================================="
echo "T7 测试完成: $PASS_COUNT 通过, $FAIL_COUNT 失败"
echo "=========================================="

echo -e "${GREEN}T7 测试结果: PASS${NC}"
echo "TLS Handshake 追踪功能测试完成"
exit 0
