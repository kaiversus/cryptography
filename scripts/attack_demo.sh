#!/usr/bin/env bash
# =============================================================================
#  attack_demo.sh - Demo 10 kich ban TAN CONG -> PHONG THU (moi KB = 1 payload).
#  Chay:  bash scripts/attack_demo.sh   (yeu cau: stack chay + co openssl, curl)
#  LUU Y (Windows): WSL2 bash KHONG goi duoc cong Docker Windows va khong nhan $env:
#  tu PowerShell -> dung ban PowerShell: scripts/attack_demo.ps1
#
#  10 kich ban. Cai nao CHUA CO HA TANG -> in [SKIP] + ghi ro ly do:
#    KB1 token gia | KB2 sua body HMAC | KB3 choi bo | KB4 nghe len (TLS) | KB5 DoS
#    KB6 leo quyen | KB7 vong gateway [SKIP] | KB8 backend header [SKIP]
#    KB9 trao JWKS [SKIP] | KB10 Vault khong ma hoa [SKIP]
# =============================================================================
set -u

GATEWAY="${GATEWAY_URL:-http://localhost:18000}"
KEYCLOAK="${KEYCLOAK_URL:-http://localhost:18081}"
HTTPS="${GATEWAY_TLS:-https://localhost:9443}"
REALM="${REALM:-nt219}"
CLIENT_ID="${CLIENT_ID:-service-account}"
CLIENT_SECRET="${CLIENT_SECRET:-CaXVcmwkeRNHP5lls0pTL8BPbFLD0Bo5}"
HMAC_KEY_ID="dev-key-01"
HMAC_SECRET="dev-shared-secret"
HOST="${GATEWAY#http://}"; HOST="${HOST#https://}"

PASS=0; TOTAL=0; SKIP=0
CURKB=""   # nhan kich ban hien tai -> header X-Demo-KB -> tag demo.kb tren Jaeger
hr()    { echo; echo "===================================================================="; echo "  $1"; echo "===================================================================="; }
check() { TOTAL=$((TOTAL+1)); if [ "$2" = "$3" ]; then echo "  [PASS] $1  (ky vong=$2 thuc te=$3)"; PASS=$((PASS+1)); else echo "  [FAIL] $1  (ky vong=$2 thuc te=$3)"; fi; }
skip()  { SKIP=$((SKIP+1)); echo "  [SKIP] $1"; }
code()  { curl -s -o /dev/null -w "%{http_code}" ${CURKB:+-H X-Demo-KB:$CURKB} "$@"; }
sha256hex() { printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}'; }
b64url()    { printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
uuid4() { local h; h=$(openssl rand -hex 16); local y; y=$(printf '%x' $(( (0x${h:16:1} & 0x3) | 0x8 ))); echo "${h:0:8}-${h:8:4}-4${h:13:3}-${y}${h:17:3}-${h:20:12}"; }
sign_hmac() {
  local body="$1" ts="$2" nonce="$3" bh ch canon sts
  bh=$(sha256hex "$body")
  canon=$(printf 'POST\n/api/service\n\nhost:%s\nx-key-id:%s\nx-nonce:%s\nx-timestamp:%s\n\nhost;x-key-id;x-nonce;x-timestamp\n%s' \
          "$HOST" "$HMAC_KEY_ID" "$nonce" "$ts" "$bh")
  ch=$(sha256hex "$canon")
  sts=$(printf 'HMAC-SHA256\n%s\ngateway-internal/v1\n%s' "$ts" "$ch")
  printf '%s' "$sts" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $NF}'
}
post_service() {   # $1=body_ky $2=body_gui $3=ts $4=nonce
  local sig; sig=$(sign_hmac "$1" "$3" "$4")
  code -X POST "$GATEWAY/api/service" -H "Content-Type: application/json" \
       -H "X-Timestamp: $3" -H "X-Nonce: $4" -H "X-Key-Id: $HMAC_KEY_ID" -H "X-Signature: $sig" --data-binary "$2"
}

# =========================== SETUP ===========================
hr "SETUP - Gateway song? + lay token that"
CURKB="SETUP"
check "GET /health -> 200" 200 "$(code "$GATEWAY/health")"
TOKEN=$(curl -s -X POST "$KEYCLOAK/realms/$REALM/protocol/openid-connect/token" \
        -d grant_type=client_credentials -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET" \
        | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -z "$TOKEN" ] && echo "  [WARN] khong lay duoc token (Keycloak chua san sang? doi them ~30s)"
check "GET /api/protected co Bearer token that -> 200" 200 "$(code "$GATEWAY/api/protected" -H "Authorization: Bearer $TOKEN")"

# =========================== KB1 ===========================
hr "KB1 - Gia mao token: hacker tu che token, ky bang khoa la"
CURKB="KB1"
FORGED="${TOKEN:0:${#TOKEN}-3}xyz"   # 1 payload: doi 3 ky tu cuoi -> chu ky hong
check "Token gia/ky sai -> 401" 401 "$(code "$GATEWAY/api/protected" -H "Authorization: Bearer $FORGED")"

# =========================== KB2 ===========================
hr "KB2 - Sua body request M2M nhung giu chu ky HMAC cu (Tampering)"
CURKB="KB2"
# (a) chu ky DUNG -> 200 = HMAC hoat dong
TS2=$(date +%s); N2=$(uuid4)
check "Ky DUNG (body khop chu ky) -> 200" 200 "$(post_service '{"id":1}' '{"id":1}' "$TS2" "$N2")"
# (b) SUA body (ky cho {"id":1} nhung gui {"id":999}) -> 401 = bi chan
check "SUA body (ky A gui B) -> 401" 401 "$(post_service '{"id":1}' '{"id":999}' "$(date +%s)" "$(uuid4)")"

# =========================== KB3 ===========================
hr "KB3 - Choi bo hanh vi M2M: gui request xau -> so audit ghi danh tinh (chong choi bo)"
CURKB="KB3"
post_service '{"id":1}' '{"id":999}' "$(date +%s)" "$(uuid4)" >/dev/null   # 1 request xau (deny)
AUDIT=$(curl -s "$GATEWAY/audit/recent?limit=10")
echo "$AUDIT" | tr '}' '\n' | grep -o '"actor":"dev-key-01"[^}]*"decision":"deny"[^}]*' | tail -1 | sed 's/^/  ban ghi audit: /'
if echo "$AUDIT" | grep -q '"actor":"dev-key-01"' && echo "$AUDIT" | grep -q '"decision":"deny"'; then
  check "Audit ghi request xau kem danh tinh dev-key-01" yes yes
else
  check "Audit ghi request xau kem danh tinh dev-key-01" yes no
fi

# =========================== KB4 ===========================
hr "KB4 - Nghe len duong truyen: chong bang TLS (kenh ma hoa, sniffer khong doc duoc token)"
CURKB="KB4"
TLSLINE=$(curl -sv -k "$HTTPS/health" 2>&1 | grep -iE "SSL connection|TLSv|cipher" | head -1 | sed 's/^[* ]*//')
[ -n "$TLSLINE" ] && echo "  bang chung ma hoa: $TLSLINE"
check "Kenh HTTPS/TLS hoat dong -> 200 (token KHONG di plaintext)" 200 "$(curl -sk -o /dev/null -w '%{http_code}' -H X-Demo-KB:KB4 "$HTTPS/health")"

# =========================== KB5 ===========================
hr "KB5 - Flood lam nghen dich vu (DoS): ban hang loat request"
CURKB="KB5"
codes=""; for i in $(seq 1 12); do codes="$codes $(code "$GATEWAY/api/public")"; done
echo "  12 lan goi /api/public (gioi han 10/phut) -> $codes"
case "$codes" in *429*) check "Co request bi chan 429 (rate-limit)" yes yes ;; *) check "Co request bi chan 429 (rate-limit)" yes no ;; esac

# =========================== KB6 ===========================
hr "KB6 - Leo thang quyen: token user hop le goi endpoint chi danh cho admin"
CURKB="KB6"
check "Token thieu role admin goi /api/admin -> 403" 403 "$(code "$GATEWAY/api/admin" -H "Authorization: Bearer $TOKEN")"

# =========================== KB7-10 (chua co ha tang) ===========================
hr "KB7 - Dung trong mang noi bo goi thang backend, vong qua Gateway (Spoofing S1-GB)"
skip "CHUA CO HA TANG: PoC khong co backend rieng -> chua co mTLS. Phong thu = co lap mang (prod compose) + mTLS cua 2."
hr "KB8 - Backend tin header Gateway -> spoof X-Role de leo quyen (Elevation E2-GB)"
skip "CHUA CO BACKEND THAT. Test nguyen ly: python -m pytest tests/security/test_backend_zerotrust.py -v (SEC-14)."
hr "KB9 - Trao JWKS: phong thu = fetch JWKS qua TLS (MITM khong tra noi JWKS gia)"
CURKB="KB9"
JWKS_URL="$HTTPS/realms/$REALM/protocol/openid-connect/certs"
TLSLINE9=$(curl -sv -k "$JWKS_URL" 2>&1 | grep -iE "SSL connection|TLSv|cipher" | head -1 | sed 's/^[* ]*//')
[ -n "$TLSLINE9" ] && echo "  kenh JWKS ma hoa: $TLSLINE9"
JWKS=$(curl -sk -H X-Demo-KB:KB9 "$JWKS_URL")
if echo "$JWKS" | grep -q '"keys"' && echo "$JWKS" | grep -q '"kid"'; then
  check "JWKS tai qua TLS tra ve bo khoa that" yes yes
else
  check "JWKS tai qua TLS tra ve bo khoa that" yes no
fi
echo "  Vi sao can TLS: chay  python -m tests.security.sec_jwks_substitution_demo"
echo "  -> khi JWKS bi trao, verify_token CHAP NHAN token gia (app-logic bat luc) => phai pin TLS/CA."
hr "KB10 - Gateway<->Vault khong ma hoa / cau hinh sai secret -> lo khoa"
skip "Vault dev HTTP + root token. Da fail-closed (F4): vault_client.py:17,32-36. TLS+policy least-priv la control trien khai."

# =========================== TONG KET ===========================
hr "TONG KET"
echo "  DEMO LIVE: $PASS/$TOTAL buoc dat ky vong.  |  SKIP (chua co ha tang): $SKIP kich ban (KB7, KB8, KB10)."
echo "  Quan sat luong: http://localhost:16686 (Jaeger, Service=secure-api-gateway, xem cay span auth.*)"
[ "$PASS" = "$TOTAL" ] && exit 0 || exit 1
