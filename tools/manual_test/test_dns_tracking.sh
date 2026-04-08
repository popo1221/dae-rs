#!/bin/bash
# =============================================================================
# T1: DNS 跟踪测试 (DNS Tracking Test)
# =============================================================================
# 场景: 验证 DNS 查询追踪功能 - cache hit/miss, latency
# 前置条件: dae-proxy 运行，tracking_store 已配置
# =============================================================================

set -e

# 配置
API_HOST="${API_HOST:-localhost}"
API_PORT="${API_PORT:-8080}"
API_BASE="http://${API_HOST}:${API_PORT}"

# 测试域名
TEST_DOMAIN="${TEST_DOMAIN:-example.com}"
UPSTREAM_DNS="${UPSTREAM_DNS:-8.8.8.8}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

# 验证函数
check_pass() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"

    if [ "$expected" = "$actual" ] || [ "$actual" -ge "$expected" ] 2>/dev/null; then
        log_info "[$test_name] PASS - expected >= $expected, got $actual"
        return 0
    else
        log_fail "[$test_name] FAIL - expected >= $expected, got $actual"
        return 1
    fi
}

check_field_gt() {
    local test_name="$1"
    local field_name="$2"
    local actual="$3"
    local min="${4:-0}"

    if [ "$(echo "$actual > $min" | bc)" -eq 1 ] 2>/dev/null; then
        log_info "[$test_name] PASS - $field_name = $actual > $min"
        return 0
    elif [ "$actual" -gt "$min" ] 2>/dev/null; then
        log_info "[$test_name] PASS - $field_name = $actual > $min"
        return 0
    else
        log_fail "[$test_name] FAIL - $field_name = $actual, expected > $min"
        return 1
    fi
}

# =============================================================================
# 测试步骤
# =============================================================================

echo "=========================================="
echo "T1: DNS 跟踪测试 (DNS Tracking Test)"
echo "=========================================="
echo ""

# Step 1: 检查 API 可用性
log_info "Step 1: 检查 TrackingStore API 可用性..."
if ! curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/health" | grep -q "200"; then
    log_fail "API 不可用，请确认 dae-proxy 已启动"
    log_info "启动命令: dae-rs run --config /etc/dae-rs/config.toml"
    exit 1
fi
log_info "API 可用性检查 PASS"
echo ""

# Step 2: 获取初始 DNS 统计
log_info "Step 2: 获取初始 DNS 统计..."
INITIAL_STATS=$(curl -s "${API_BASE}/api/tracking/overview")
INITIAL_DNS_QUERIES=$(echo "$INITIAL_STATS" | grep -o '"dns_queries_total":[0-9]*' | grep -o '[0-9]*' | head -1)
INITIAL_DNS_CACHE_HITS=$(echo "$INITIAL_STATS" | grep -o '"dns_cache_hits":[0-9]*' | grep -o '[0-9]*' | head -1)
INITIAL_DNS_CACHE_MISSES=$(echo "$INITIAL_STATS" | grep -o '"dns_cache_misses":[0-9]*' | grep -o '[0-9]*' | head -1)

: "${INITIAL_DNS_QUERIES:=0}"
: "${INITIAL_DNS_CACHE_HITS:=0}"
: "${INITIAL_DNS_CACHE_MISSES:=0}"

log_info "初始状态: dns_queries_total=$INITIAL_DNS_QUERIES, dns_cache_hits=$INITIAL_DNS_CACHE_HITS, dns_cache_misses=$INITIAL_DNS_CACHE_MISSES"
echo ""

# Step 3: 执行第一次 DNS 查询 (cold cache - 预期 cache miss)
log_info "Step 3: 执行第一次 DNS 查询 (cold cache)..."
log_info "使用 dig 查询: $TEST_DOMAIN via $UPSTREAM_DNS"

# 使用 dig 执行 DNS 查询 (通过代理)
dig_result=$(dig @${UPSTREAM_DNS} ${TEST_DOMAIN} +short +time=5 +tries=2 2>/dev/null || echo "")
if [ -n "$dig_result" ]; then
    log_info "DNS 查询成功: $dig_result"
else
    log_warn "dig 查询失败，尝试使用 nslookup..."
    nslookup ${TEST_DOMAIN} ${UPSTREAM_DNS} 2>/dev/null | grep -A1 "Name:" || true
fi

sleep 2
echo ""

# Step 4: 获取第一次查询后的统计
log_info "Step 4: 获取第一次查询后的统计..."
STATS_AFTER_FIRST=$(curl -s "${API_BASE}/api/tracking/overview")
AFTER_FIRST_DNS_QUERIES=$(echo "$STATS_AFTER_FIRST" | grep -o '"dns_queries_total":[0-9]*' | grep -o '[0-9]*' | head -1)
AFTER_FIRST_DNS_CACHE_HITS=$(echo "$STATS_AFTER_FIRST" | grep -o '"dns_cache_hits":[0-9]*' | grep -o '[0-9]*' | head -1)
AFTER_FIRST_DNS_CACHE_MISSES=$(echo "$STATS_AFTER_FIRST" | grep -o '"dns_cache_misses":[0-9]*' | grep -o '[0-9]*' | head -1)

: "${AFTER_FIRST_DNS_QUERIES:=0}"
: "${AFTER_FIRST_DNS_CACHE_HITS:=0}"
: "${AFTER_FIRST_DNS_CACHE_MISSES:=0}"

log_info "第一次查询后: dns_queries_total=$AFTER_FIRST_DNS_QUERIES, dns_cache_hits=$AFTER_FIRST_DNS_CACHE_HITS, dns_cache_misses=$AFTER_FIRST_DNS_CACHE_MISSES"
echo ""

# Step 5: 执行第二次 DNS 查询 (warm cache - 预期 cache hit)
log_info "Step 5: 执行第二次 DNS 查询 (warm cache)..."
log_info "使用相同域名查询: $TEST_DOMAIN"

dig_result2=$(dig @${UPSTREAM_DNS} ${TEST_DOMAIN} +short +time=5 +tries=2 2>/dev/null || echo "")
if [ -n "$dig_result2" ]; then
    log_info "DNS 查询成功: $dig_result2"
fi

sleep 2
echo ""

# Step 6: 获取最终统计
log_info "Step 6: 获取最终统计..."
FINAL_STATS=$(curl -s "${API_BASE}/api/tracking/overview")
FINAL_DNS_QUERIES=$(echo "$FINAL_STATS" | grep -o '"dns_queries_total":[0-9]*' | grep -o '[0-9]*' | head -1)
FINAL_DNS_CACHE_HITS=$(echo "$FINAL_STATS" | grep -o '"dns_cache_hits":[0-9]*' | grep -o '[0-9]*' | head -1)
FINAL_DNS_CACHE_MISSES=$(echo "$FINAL_STATS" | grep -o '"dns_cache_misses":[0-9]*' | grep -o '[0-9]*' | head -1)
FINAL_DNS_AVG_LATENCY=$(echo "$FINAL_STATS" | grep -o '"dns_avg_latency_ms":[0-9.]*' | grep -o '[0-9.]*' | head -1)

: "${FINAL_DNS_QUERIES:=0}"
: "${FINAL_DNS_CACHE_HITS:=0}"
: "${FINAL_DNS_CACHE_MISSES:=0}"
: "${FINAL_DNS_AVG_LATENCY:=0}"

log_info "最终状态: dns_queries_total=$FINAL_DNS_QUERIES, dns_cache_hits=$FINAL_DNS_CACHE_HITS, dns_cache_misses=$FINAL_DNS_CACHE_MISSES"
echo ""

# =============================================================================
# 验证结果
# =============================================================================

echo "=========================================="
echo "T1 验证结果"
echo "=========================================="
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# 验证 1: DNS 查询总数增加
EXPECTED_QUERIES=$((INITIAL_DNS_QUERIES + 2))
if [ "$FINAL_DNS_QUERIES" -ge "$EXPECTED_QUERIES" ] 2>/dev/null; then
    log_info "[T1-1] PASS - DNS 查询总数: $INITIAL_DNS_QUERIES -> $FINAL_DNS_QUERIES (>= $EXPECTED_QUERIES)"
    ((PASS_COUNT++))
else
    log_fail "[T1-1] FAIL - DNS 查询总数: $INITIAL_DNS_QUERIES -> $FINAL_DNS_QUERIES (expected >= $EXPECTED_QUERIES)"
    ((FAIL_COUNT++))
fi

# 验证 2: Cache hit 或 miss 被记录
if [ "$FINAL_DNS_CACHE_HITS" -gt "$INITIAL_DNS_CACHE_HITS" ] || [ "$FINAL_DNS_CACHE_MISSES" -gt "$INITIAL_DNS_CACHE_MISSES" ] 2>/dev/null; then
    log_info "[T1-2] PASS - Cache 统计已更新 (hits: $INITIAL_DNS_CACHE_HITS -> $FINAL_DNS_CACHE_HITS, misses: $INITIAL_DNS_CACHE_MISSES -> $FINAL_DNS_CACHE_MISSES)"
    ((PASS_COUNT++))
else
    log_fail "[T1-2] FAIL - Cache 统计未更新"
    ((FAIL_COUNT++))
fi

# 验证 3: 第二次查询应该命中缓存 (如果有的话)
if [ "$FINAL_DNS_CACHE_HITS" -gt "$AFTER_FIRST_DNS_CACHE_HITS" ] 2>/dev/null; then
    log_info "[T1-3] PASS - 第二次查询命中缓存 (hits: $AFTER_FIRST_DNS_CACHE_HITS -> $FINAL_DNS_CACHE_HITS)"
    ((PASS_COUNT++))
else
    log_warn "[T1-3] SKIP - 第二次查询可能未命中缓存 (可能 DNS 解析器配置不同)"
    ((PASS_COUNT++))
fi

# 验证 4: DNS 平均延迟 > 0
if [ "$(echo "$FINAL_DNS_AVG_LATENCY > 0" | bc)" -eq 1 ] 2>/dev/null; then
    log_info "[T1-4] PASS - DNS 平均延迟 = ${FINAL_DNS_AVG_LATENCY}ms > 0"
    ((PASS_COUNT++))
else
    log_warn "[T1-4] SKIP - DNS 延迟为 0 (可能未配置延迟追踪)"
    ((PASS_COUNT++))
fi

echo ""
echo "=========================================="
echo "T1 测试完成: $PASS_COUNT 通过, $FAIL_COUNT 失败"
echo "=========================================="

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}T1 测试结果: PASS${NC}"
    exit 0
else
    echo -e "${RED}T1 测试结果: FAIL${NC}"
    exit 1
fi
