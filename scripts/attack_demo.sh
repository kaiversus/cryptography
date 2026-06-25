#!/usr/bin/env bash
# =============================================================================
#  attack_demo.sh — Bắn 6 vector tấn công vào Gateway LIVE bằng curl + openssl.
#  KHÔNG cần Python/demo.py. Chạy:  bash scripts/attack_demo.sh
#  Yêu cầu: stack đang chạy (cd infra && docker compose up -d) và có openssl, curl.
# =============================================================================
set -u

GATEWAY="${GATEWAY_URL:-http://localhost:8000}"
KEYCLOAK="${KEYCLOAK_URL:-http://localhost:8081}"
REALM="${REALM:-nt219}"
CLIENT_ID="${CLIENT_ID:-service-account}"
CLIENT_SECRET="${CLIENT_SECRET:-CaXVcmwkeRNHP5lls0pTL8BPbFLD0Bo5}"
HMAC_KEY_ID="dev-key-01"
HMAC_SECRET="dev-shared-secret"
HOST="${GATEWAY#http://}"; HOST="${HOST#https://}"

PASS=0; TOTAL=0
hr()    { echo; echo "===================================================================="; echo "  $1"; echo "===================================================================="; }
check() { TOTAL=$((TOTAL+1)); if [ "$2" = "$3" ]; then echo "  [PASS] $1  (kỳ vọng=$2 thực tế=$3)"; PASS=$((PASS+1)); else echo "  [FAIL] $1  (kỳ vọng=$2 thực tế=$3)"; fi; }
code()  { curl -s -o /dev/null -w "%{http_code}" "$@"; }       # in ra HTTP status code

# ---- tiện ích mật mã ----
sha256hex() { printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}'; }
b64url()    { printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
uuid4() {  # sinh UUID v4 hợp lệ (regex server yêu cầu) từ openssl
  local h; h=$(openssl rand -hex 16)
  local y; y=$(printf '%x' $(( (0x${h:16:1} & 0x3) | 0x8 )))
  echo "${h:0:8}-${h:8:4}-4${h:13:3}-${y}${h:17:3}-${h:20:12}"
}
sign_hmac() {  # $1=body $2=ts $3=nonce -> in ra chữ ký hex (khớp gateway-internal/v1)
  local body="$1" ts="$2" nonce="$3" bh ch canon sts
  bh=$(sha256hex "$body")
  canon=$(printf 'POST\n/api/service\n\nhost:%s\nx-key-id:%s\nx-nonce:%s\nx-timestamp:%s\n\nhost;x-key-id;x-nonce;x-timestamp\n%s' \
          "$HOST" "$HMAC_KEY_ID" "$nonce" "$ts" "$bh")
  ch=$(sha256hex "$canon")
  sts=$(printf 'HMAC-SHA256\n%s\ngateway-internal/v1\n%s' "$ts" "$ch")
  printf '%s' "$sts" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $NF}'
}
post_service() {  # $1=body_ký $2=body_gửi $3=ts $4=nonce -> in HTTP code
  local sig; sig=$(sign_hmac "$1" "$3" "$4")
  code -X POST "$GATEWAY/api/service" \
       -H "Content-Type: application/json" \
       -H "X-Timestamp: $3" -H "X-Nonce: $4" -H "X-Key-Id: $HMAC_KEY_ID" -H "X-Signature: $sig" \
       --data-binary "$2"
}

# =========================== CẢNH 0: hạ tầng ===========================
hr "CẢNH 0 — Gateway sống?"
check "GET /health" 200 "$(code "$GATEWAY/health")"

# =========================== CẢNH 1: token thật + JWT hợp lệ ===========================
hr "CẢNH 1 — Lấy token thật (client_credentials) + JWT hợp lệ"
TOKEN=$(curl -s -X POST "$KEYCLOAK/realms/$REALM/protocol/openid-connect/token" \
        -d grant_type=client_credentials -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET" \
        | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
if [ -z "$TOKEN" ]; then echo "  [WARN] không lấy được token (Keycloak chưa sẵn sàng?)"; fi
check "GET /api/protected có Bearer token thật" 200 "$(code "$GATEWAY/api/protected" -H "Authorization: Bearer $TOKEN")"

# =========================== CẢNH 2: tấn công JWT (Vector 1) ===========================
hr "CẢNH 2 — Vector 1: giả danh bằng token (đều phải 401)"
check "Thiếu Bearer header" 401 "$(code "$GATEWAY/api/protected")"
FORGED="${TOKEN:0:${#TOKEN}-3}xyz"   # đổi 3 ký tự cuối -> hỏng chữ ký
check "SEC-01: token bị sửa/ký sai" 401 "$(code "$GATEWAY/api/protected" -H "Authorization: Bearer $FORGED")"
NONE_TOK="$(b64url '{"alg":"none","typ":"JWT"}').$(b64url '{"sub":"attacker","iss":"x","aud":"account","iat":1700000000,"exp":1900000000}')."
check "SEC-02: alg=none downgrade" 401 "$(code "$GATEWAY/api/protected" -H "Authorization: Bearer $NONE_TOK")"

# =========================== CẢNH 3: tấn công HMAC (Vector 2) ===========================
hr "CẢNH 3 — Vector 2: HMAC hợp lệ → replay → sửa body → timestamp cũ"
TS=$(date +%s); NONCE=$(uuid4); BODY='{"id":1}'
check "Ký HMAC hợp lệ"                 200 "$(post_service "$BODY" "$BODY" "$TS" "$NONCE")"
check "SEC-07: replay (lặp nonce)"     401 "$(post_service "$BODY" "$BODY" "$TS" "$NONCE")"
TS2=$(date +%s); NONCE2=$(uuid4)
check "SEC-09: ký body A gửi body B"   401 "$(post_service "$BODY" '{"id":999}' "$TS2" "$NONCE2")"
TS3=$(( $(date +%s) - 1000 )); NONCE3=$(uuid4)
check "SEC-08: timestamp ngoài cửa sổ" 401 "$(post_service "$BODY" "$BODY" "$TS3" "$NONCE3")"

# =========================== CẢNH 3b: biến thể HMAC (cho đủ lý do dashboard) ===========================
hr "CẢNH 3b — Biến thể HMAC: invalid_format / missing_header / unknown_key (đều 401)"
SIG64=$(printf 'a%.0s' $(seq 1 64))   # chuỗi 64 hex hợp lệ định dạng nhưng sai chữ ký
check "invalid_format: timestamp không phải số" 401 \
  "$(code -X POST "$GATEWAY/api/service" -H "X-Timestamp: abc" -H "X-Nonce: $(uuid4)" -H "X-Key-Id: $HMAC_KEY_ID" -H "X-Signature: $SIG64" --data-binary '{}')"
check "missing_header: thiếu X-Signature" 401 \
  "$(code -X POST "$GATEWAY/api/service" -H "X-Timestamp: $(date +%s)" -H "X-Nonce: $(uuid4)" -H "X-Key-Id: $HMAC_KEY_ID" --data-binary '{}')"
check "unknown_key: X-Key-Id không tồn tại" 401 \
  "$(code -X POST "$GATEWAY/api/service" -H "X-Timestamp: $(date +%s)" -H "X-Nonce: $(uuid4)" -H "X-Key-Id: ghost-key" -H "X-Signature: $SIG64" --data-binary '{}')"

# =========================== CẢNH 4: leo thang quyền (Vector 6) ===========================
hr "CẢNH 4 — Vector 6: token thiếu role admin gọi /api/admin (phải 403)"
check "SEC-11: leo thang quyền -> 403" 403 "$(code "$GATEWAY/api/admin" -H "Authorization: Bearer $TOKEN")"

# =========================== CẢNH 5: thu hồi token (SEC-10) ===========================
hr "CẢNH 5 — Thu hồi token tức thời (jti blacklist)"
check "POST /auth/revoke" 200 "$(code -X POST "$GATEWAY/auth/revoke" -H "Authorization: Bearer $TOKEN")"
check "Dùng lại token đã revoke -> 401" 401 "$(code "$GATEWAY/api/protected" -H "Authorization: Bearer $TOKEN")"

# =========================== CẢNH 6: rate-limit (Vector 5) ===========================
hr "CẢNH 6 — Vector 5: flood /api/public (10/phút) -> 429"
codes=""
for i in $(seq 1 12); do codes="$codes $(code "$GATEWAY/api/public")"; done
echo "  12 lần gọi -> $codes"
case "$codes" in *429*) check "Có request bị chặn 429" yes yes ;; *) check "Có request bị chặn 429" yes no ;; esac

# =========================== CẢNH 7: audit chống chối bỏ (Vector 3) ===========================
hr "CẢNH 7 — Vector 3: sổ audit ghi danh tính (chống chối bỏ)"
TSA=$(date +%s); post_service '{"id":1}' '{"id":1}'   "$TSA"     "$(uuid4)" >/dev/null   # allow
TSB=$(date +%s); post_service '{"id":1}' '{"id":999}' "$TSB"     "$(uuid4)" >/dev/null   # deny (tamper)
AUDIT=$(curl -s "$GATEWAY/audit/recent?limit=10")
echo "  --- 4 bản ghi audit gần nhất ---"
echo "$AUDIT" | tr '}' '\n' | grep -o '"actor":"[^"]*"[^,]*,.*"decision":"[a-z]*"' | tail -4 | sed 's/^/  /'
if echo "$AUDIT" | grep -q '"actor":"dev-key-01"' && echo "$AUDIT" | grep -q '"decision":"allow"' && echo "$AUDIT" | grep -q '"decision":"deny"'; then
  check "Audit ghi cả allow lẫn deny kèm dev-key-01" yes yes
else
  check "Audit ghi cả allow lẫn deny kèm dev-key-01" yes no
fi

# =========================== Observability ===========================
hr "QUAN SÁT — mở trình duyệt cho thầy"
echo "  Grafana   : http://localhost:3001  (admin/admin — panel Auth Failures)"
echo "  Jaeger    : http://localhost:16686 (Service=secure-api-gateway, xem auth.* trên span)"
echo "  Prometheus: http://localhost:9090  (gõ auth_failures_total)"

# =========================== Tổng kết ===========================
hr "TỔNG KẾT"
echo "  KẾT QUẢ: $PASS/$TOTAL bước đạt kỳ vọng."
[ "$PASS" = "$TOTAL" ] && exit 0 || exit 1
