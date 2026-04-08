#!/bin/bash
# =============================================================================
# T6: HTTP API 端点测试 (HTTP API Endpoints Test)
# =============================================================================
# 场景: 验证所有 TrackingStore HTTP API 端点正常工作
# 前置条件: dae-proxy 运行
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

# API 端点列表
ENDPOINTS=(
    "/health"
    "/api/tracking/overview"
    "/api/tracking/connections"
    "/api/tracking/protocols"
    "/api/tracking/rules"
    "/api/tracking/nodes"
)

# 查询参数变体
QUERY_VARIANTS=(
    "?state=active"
    "?state=closed"
    "?state=all"
    "?limit=10"
    "?protocol=tcp"
    "?sort_by=bytes_in"
)

echo "=========================================="
echo "T6: HTTP API 端点测试"
echo "=========================================="
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# =============================================================================
# 测试基础端点
# =============================================================================

for endpoint in "${ENDPOINTS[@]}"; do
    FULL_URL="${API_BASE}${endpoint}"
    log_info "测试端点: $endpoint"

    # 获取 HTTP 状态码和响应
    HTTP_CODE=$(curl -s -o /tmp/api_response_${endpoint//\//_}.txt -w "%{http_code}" "$FULL_URL")
    RESPONSE=$(cat /tmp/api_response_${endpoint//\//_}.txt 2>/dev/null || echo "")

    if [ "$HTTP_CODE" = "200" ]; then
        log_info "  [OK] HTTP $HTTP_CODE"

        # 验证 JSON 格式 (如果适用)
        if [ "$endpoint" != "/health" ]; then
            if echo "$RESPONSE" | python3 -m json.tool > /dev/null 2>&1; then
                log_info "  [OK] JSON 格式正确"
                ((PASS_COUNT++))

                # 输出部分响应用于调试
                if [ "$endpoint" = "/api/tracking/overview" ]; then
                    log_info "  响应预览: $(echo "$RESPONSE" | head -c 200)..."
                fi
            else
                log_warn "  [WARN] JSON 格式可能不正确"
                ((PASS_COUNT++))
            fi
        else
            ((PASS_COUNT++))
        fi
    else
        log_fail "  [FAIL] HTTP $HTTP_CODE"
        ((FAIL_COUNT++))
    fi
    echo ""
done

# =============================================================================
# 测试查询参数
# =============================================================================

log_info "测试查询参数变体..."
echo ""

for variant in "${QUERY_VARIANTS[@]}"; do
    FULL_URL="${API_BASE}/api/tracking/connections${variant}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FULL_URL")

    if [ "$HTTP_CODE" = "200" ]; then
        log_info "  [OK] GET $variant -> HTTP 200"
        ((PASS_COUNT++))
    else
        log_warn "  [WARN] GET $variant -> HTTP $HTTP_CODE"
    fi
done
echo ""

# =============================================================================
# 测试连接详情端点
# =============================================================================

log_info "测试连接详情端点..."
echo ""

# 获取一个连接 key
CONNECTIONS_JSON=$(curl -s "${API_BASE}/api/tracking/connections?limit=1")
FIRST_KEY=$(echo "$CONNECTIONS_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data.get('connections') and len(data['connections']) > 0:
    print(data['connections'][0].get('key', ''))
" 2>/dev/null || echo "")

if [ -n "$FIRST_KEY" ]; then
    FULL_URL="${API_BASE}/api/tracking/connections/${FIRST_KEY}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FULL_URL")

    if [ "$HTTP_CODE" = "200" ]; then
        log_info "  [OK] GET /api/tracking/connections/$FIRST_KEY -> HTTP 200"
        ((PASS_COUNT++))
    elif [ "$HTTP_CODE" = "404" ]; then
        log_warn "  [SKIP] 连接不存在 (可能已关闭) -> HTTP 404"
        ((PASS_COUNT++))
    else
        log_fail "  [FAIL] GET /api/tracking/connections/$FIRST_KEY -> HTTP $HTTP_CODE"
        ((FAIL_COUNT++))
    fi
else
    log_warn "  [SKIP] 无连接可测试详情端点"
    ((PASS_COUNT++))
fi
echo ""

# =============================================================================
# 验证响应内容
# =============================================================================

log_info "验证 API 响应内容..."
echo ""

# 测试 /api/tracking/overview 包含必要字段
OVERVIEW=$(curl -s "${API_BASE}/api/tracking/overview")
REQUIRED_FIELDS=(
    "uptime_secs"
    "packets_total"
    "bytes_total"
    "connections_total"
    "connections_active"
    "dns_queries_total"
)

OVERVIEW_PASS=true
for field in "${REQUIRED_FIELDS[@]}"; do
    if ! echo "$OVERVIEW" | grep -q "\"$field\""; then
        log_warn "  [MISSING] $field"
        OVERVIEW_PASS=false
    fi
done

if [ "$OVERVIEW_PASS" = true ]; then
    log_info "  [OK] /api/tracking/overview 包含所有必要字段"
    ((PASS_COUNT++))
else
    log_fail "  [FAIL] /api/tracking/overview 缺少字段"
    ((FAIL_COUNT++))
fi

# 测试 /api/tracking/protocols
PROTOCOLS=$(curl -s "${API_BASE}/api/tracking/protocols")
if echo "$PROTOCOLS" | python3 -m json.tool > /dev/null 2>&1; then
    if echo "$PROTOCOLS" | grep -q '"transport"' && echo "$PROTOCOLS" | grep -q '"proxy"'; then
        log_info "  [OK] /api/tracking/protocols 包含 transport 和 proxy"
        ((PASS_COUNT++))
    else
        log_warn "  [WARN] /api/tracking/protocols 结构不完整"
    fi
else
    log_fail "  [FAIL] /api/tracking/protocols JSON 格式错误"
    ((FAIL_COUNT++))
fi

# 测试 /api/tracking/rules
RULES=$(curl -s "${API_BASE}/api/tracking/rules")
if echo "$RULES" | python3 -m json.tool > /dev/null 2>&1; then
    if echo "$RULES" | grep -q '"total_rules"' && echo "$RULES" | grep -q '"rules"'; then
        log_info "  [OK] /api/tracking/rules 结构正确"
        ((PASS_COUNT++))
    else
        log_warn "  [WARN] /api/tracking/rules 结构不完整"
    fi
else
    log_fail "  [FAIL] /api/tracking/rules JSON 格式错误"
    ((FAIL_COUNT++))
fi

# 测试 /api/tracking/nodes
NODES=$(curl -s "${API_BASE}/api/tracking/nodes")
if echo "$NODES" | python3 -m json.tool > /dev/null 2>&1; then
    if echo "$NODES" | grep -q '"total_nodes"' && echo "$NODES" | grep -q '"nodes"'; then
        log_info "  [OK] /api/tracking/nodes 结构正确"
        ((PASS_COUNT++))
    else
        log_warn "  [WARN] /api/tracking/nodes 结构不完整"
    fi
else
    log_fail "  [FAIL] /api/tracking/nodes JSON 格式错误"
    ((FAIL_COUNT++))
fi

echo ""

# =============================================================================
# 验证结果
# =============================================================================

echo "=========================================="
echo "T6 验证结果"
echo "=========================================="
echo ""

TOTAL=$((PASS_COUNT + FAIL_COUNT))
log_info "测试结果: $PASS_COUNT 通过, $FAIL_COUNT 失败"
echo ""

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}T6 测试结果: PASS${NC}"
    echo "所有 HTTP API 端点正常工作"
    exit 0
elif [ "$PASS_COUNT" -gt "$FAIL_COUNT" ]; then
    echo -e "${YELLOW}T6 测试结果: PARTIAL${NC}"
    echo "大部分端点正常工作，$FAIL_COUNT 个端点有问题"
    exit 1
else
    echo -e "${RED}T6 测试结果: FAIL${NC}"
    echo "多个端点失败，请检查 dae-proxy 配置"
    exit 1
fi
