# KỊCH BẢN DEMO TRỰC TIẾP (cho team & thầy xem)

Mục tiêu: trình diễn Gateway cưỡng chế mật mã — JWT, HMAC, revocation, rate-limit,
observability — bằng bằng chứng chạy thật. Có **2 cách**: chạy tự động 1 lệnh
(khuyến nghị khi present) hoặc gõ tay từng cảnh (khi thầy muốn xem chi tiết).

---

## 0. Chuẩn bị (làm TRƯỚC buổi demo ~10 phút)

```bash
cd infra
docker compose up -d            # đợi tất cả service Up (keycloak mất ~30-60s)
docker compose ps               # xác nhận 8 service Up: keycloak, redis, vault,
                                # vault-seed (exited 0 là đúng), prometheus, jaeger,
                                # grafana, gateway
curl -s localhost:8000/health   # -> {"status":"ok"}
```

Mở sẵn 3 tab trình duyệt để lát chuyển nhanh:
- Grafana    http://localhost:3001  (admin/admin)
- Jaeger     http://localhost:16686
- Prometheus http://localhost:9090/targets

> Nếu vừa demo xong, **đợi ~60s** rồi mới chạy lại để rate-limit của lần trước reset.

---

## CÁCH A — Chạy tự động (1 lệnh, có bảng tổng kết PASS/FAIL)

```bash
python scripts/demo.py
```

Script tự lấy token thật từ Keycloak rồi diễn 7 cảnh, in `[PASS]/[FAIL]` cho từng
bước và bảng tổng kết cuối. Đây là cách gọn nhất để present. Output mong đợi (rút gọn):

```
CẢNH 0 — Pre-flight ...            [PASS] GET /health
CẢNH 1 — JWT hợp lệ ...            [PASS] GET /api/protected = 200
CẢNH 2 — Tấn công JWT ...          [PASS] missing/SEC-01/SEC-02/tamper = 401
CẢNH 3 — HMAC ...                  [PASS] valid=200, replay/tamper/old-ts=401
CẢNH 4 — Revocation ...            [PASS] revoke=200, gọi lại=401
CẢNH 5 — Rate limit ...            [PASS] xuất hiện 429
CẢNH 6 — Observability ...         [PASS] /metrics có auth_failures_total
TỔNG KẾT: N/N bước đạt kỳ vọng.
```

---

## CÁCH B — Gõ tay từng cảnh (thuyết minh chi tiết)

### Cảnh 1 — JWT hợp lệ (ES256) ✅
```bash
# Lấy access_token thật (ES256) từ Keycloak
TOKEN=$(curl -s -X POST \
  http://localhost:8081/realms/nt219/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=service-account \
  -d client_secret=CaXVcmwkeRNHP5lls0pTL8BPbFLD0Bo5 | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/protected   # -> 200
```
**Nói:** Gateway fetch JWKS từ Keycloak, verify chữ ký ES256, kiểm `exp/iss/aud`.

### Cảnh 2 — Tấn công JWT bị chặn ✅ (SEC-01, SEC-02)
```bash
curl -s -o /dev/null -w "no-bearer    -> %{http_code}\n" http://localhost:8000/api/protected
curl -s -o /dev/null -w "tampered     -> %{http_code}\n" \
  -H "Authorization: Bearer ${TOKEN}XX" http://localhost:8000/api/protected
```
Đều **401**. Forge token / alg=none: xem `tests/security/test_jwt_attacks.py` (chạy
`pytest tests/security -v`).

### Cảnh 3 — HMAC: hợp lệ → replay → tamper ✅ (SEC-07/08/09)
```bash
python clients/test_hmac.py
# PHA 1: 200 | PHA 2 (replay): 401 replay_detected | PHA 3 (tamper): 401 invalid_signature
```
**Nói:** mỗi request ký canonical (method+path+headers+body-hash) → string-to-sign →
HMAC-SHA256; nonce dùng-một-lần (Redis TTL 600s) chống replay.

### Cảnh 4 — Thu hồi token tức thời ✅ (SEC-10)
```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/auth/revoke   # {"status":"revoked",...}
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/protected               # -> 401
```
**Nói:** đẩy `jti` vào blacklist Redis với TTL = exp-now; middleware chặn ngay,
không cần gọi lại Keycloak.

### Cảnh 5 — Rate limit ✅
```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code} " http://localhost:8000/api/public; done; echo
# 200 200 ... rồi 429 (sau 10 req/phút)
```

### Cảnh 6 — Observability ✅
```bash
# tạo vài lần auth fail cho dashboard nhảy số
for i in $(seq 1 5); do curl -s -o /dev/null -H "Authorization: Bearer bad.$i" \
  http://localhost:8000/api/protected; done
curl -s localhost:8000/metrics | grep auth_failures_total | head
```
- **Grafana** (:3001): panel *Auth Failures per minute* tăng.
- **Jaeger** (:16686): chọn service `secure-api-gateway` → trace có
  `auth.method / auth.result / auth.user_id / auth.latency_ms`.
- **Prometheus** (:9090/targets): target `gateway` = **UP**.

### Cảnh 7 (tuỳ chọn) — K8s self-heal
```bash
kubectl apply -f k8s/ && kubectl get pods            # 2 replica gateway Running
kubectl delete pod -l app=gateway --field-selector ... # xoá 1 pod
curl -s $(minikube ip):30080/health                  # vẫn 200, pod mới spawn
```

---

## Bằng chứng chạy lại offline (khi không tiện bật full stack)

```bash
pytest tests/security -v          # 12/12 PASS — toàn bộ SEC tự động hóa
python -m tests.security.sec03_weak_hs256_demo   # SEC-03: crack HS256 yếu
```

## Phòng sự cố nhanh
| Triệu chứng | Xử lý |
|-------------|-------|
| `/health` không phản hồi | `docker compose ps`; `docker compose logs gateway` |
| Cảnh 1 trả 401 | token hết hạn (mặc định ngắn) → lấy lại `$TOKEN` |
| Cảnh 5 ra 429 ngay từ đầu | lần demo trước chưa reset → đợi 60s |
| HMAC 401 "unknown_key" | vault-seed chưa chạy xong → `docker compose up -d vault-seed` |
