# Module 6 — Đối chiếu code thật

> Mục tiêu: nối thiết kế (M1–M5) với code AI-gen, để bạn HIỂU từng đoạn code làm gì
> và TẠI SAO (truy về threat/MT/chốt). Không học thuộc — đọc hiểu, gắn về thiết kế.

---

## Bản đồ: file code → phần thiết kế nó hiện thực

| File code | Làm gì | Thiết kế tương ứng |
|---|---|---|
| `gateway/main.py` | Lắp ráp app + thứ tự middleware | Dây chuyền chốt (tầng App); thứ tự LIFO |
| `gateway/crypto/jwt_verifier.py` | Verify chữ ký JWT qua JWKS | **MT-AUTHN**, chốt 6, S1-IG, SEC-01/02/04/05/06 |
| `gateway/crypto/hmac_verifier.py` | Verify HMAC body + nonce + timestamp | **MT-INTEG**, chốt 4-5, T1/RP1-IG, SEC-07/08/09 |
| `gateway/middleware/auth.py` | Middleware gọi jwt_verifier | Nối chốt 6 vào luồng |
| `gateway/middleware/hmac_auth.py` | Middleware gọi hmac_verifier | Nối chốt 4-5 vào luồng |
| `gateway/middleware/rate_limit.py` | Giới hạn tần suất | **MT-AVAIL**, chốt 1, D1-IG |
| `gateway/storage/revocation.py` | jti blacklist (Redis) | Thu hồi token, SEC-10 |
| `gateway/storage/vault_client.py` | Lấy secret từ Vault | **MT-CONF**, secret store |
| `gateway/routes/auth.py` | Endpoint token | Luồng tương tác với IdP |
| `gateway/observability/*` | Log/metric/trace | **MT-NONREP** (audit) + quan sát |

---

## Phát hiện bảo mật (đối chiếu code vs thiết kế)

> Ghi lại chỗ code KHÔNG khớp mục tiêu — đây là phần ăn điểm khi bảo vệ.

| # | Vị trí | Vấn đề | Vi phạm MT | Sửa |
|---|---|---|---|---|
| F1 | `jwt_verifier.py:74-77` | **Hardcode secret fallback** `"hs256-realm-shared-secret-32b!!"` (fallback VÔ ĐIỀU KIỆN) | MT-CONF (secret trong source) + I1-IG (secret yếu) | Bỏ fallback, bắt buộc đọc từ Vault, thiếu → fail |
| F2 | `hmac_verifier.py:20-24` | Hardcode `_DEV_SECRETS` — nhưng CÓ công tắc `HMAC_REQUIRE_VAULT=1` fail-closed | MT-CONF (nhẹ hơn F1 vì tắt được) | Bật `HMAC_REQUIRE_VAULT=1` ở prod; lý tưởng xóa hẳn dev secret |
| F3 | `middleware/auth.py` + `main.py` | **Authorization (chốt 7) chưa hiện thực** — code đọc `roles` nhưng KHÔNG endpoint nào enforce "phải có role X" | MT-AUTHZ (E1-IG) | Thêm kiểm scope/role → 403; giải thích vì sao E1-IG chưa có SEC test |
| F4 | `vault_client.py:15` | Default `VAULT_TOKEN="dev-root-token"` = đọc MỌI secret, ngược least-privilege | MT-CONF (I1-Vault) | Prod dùng AppRole/K8s auth, mỗi service policy hẹp |

> **Mẫu chung F1/F2/F4:** secret/quyền nới lỏng cho dev, phải siết (fail-closed +
> least-privilege) cho prod. Gộp thành 1 checklist hardening khi bảo vệ.

---

## Checklist đọc code (tự tick tiến độ)

Thứ tự: lõi mật mã trước → middleware nối → lưu trữ → phụ trợ.

**Nhóm 1 — Lõi mật mã (quan trọng nhất)**
- [x] `gateway/crypto/jwt_verifier.py` — MT-AUTHN, chốt 6, SEC-01/02/04/05/06/10 *(đã đọc)*
- [x] `gateway/crypto/hmac_verifier.py` — MT-INTEG, chốt 4-5, SEC-07/08/09 *(đã đọc)*

**Nhóm 2 — Middleware (nối chốt vào luồng request)**
- [x] `gateway/main.py` — lắp ráp app, thứ tự middleware LIFO *(đã đọc)*
- [x] `gateway/middleware/auth.py` — gọi jwt_verifier, gắn user vào request *(đã đọc)*
- [x] `gateway/middleware/hmac_auth.py` — gọi hmac_verifier *(đã đọc)*
- [x] `gateway/middleware/rate_limit.py` — MT-AVAIL, chốt 1, D1-IG *(đã đọc)*

**Nhóm 3 — Lưu trữ & secret**
- [x] `gateway/storage/revocation.py` — jti blacklist (Redis), SEC-10 *(đã đọc)*
- [x] `gateway/storage/vault_client.py` — MT-CONF, secret store *(đã đọc)*

**Nhóm 4 — Phụ trợ**
- [x] `gateway/routes/auth.py` — endpoint /auth/revoke (hoàn tất SEC-10) *(đã đọc)*
- [x] `gateway/observability/logger.py` — MT-NONREP (audit log) *(đã đọc)*
- [x] `gateway/observability/metrics.py` + `tracing.py` — quan sát *(đã đọc)*

> Tổng: ~11 file. Đọc xong mỗi file → tick + ghi 1-2 dòng "file này làm gì, gắn MT nào"
> vào mục Ghi chú dưới.

---

## Ghi chú đọc code (điền dần khi học từng file)

### jwt_verifier.py ✅ — MT-AUTHN (chốt 6)
Verify chữ ký JWT. Cache JWKS 300s. Chặn alg=none (SEC-02). Nhánh HS256 (đối xứng) vs
ES256/RS256 (bất đối xứng qua JWKS + kid). **Phát hiện F1**: hardcode secret fallback
(dòng 74-77) vi phạm MT-CONF.

### main.py ✅ — lắp ráp + thứ tự middleware
Đăng ký middleware LIFO (đăng ký sau chạy trước): hmac_auth → jwt_auth. Định nghĩa
endpoint /health, /api/public, /api/protected (5/min), /api/service (100/min).

### hmac_verifier.py ✅ — MT-INTEG (chốt 4-5)
Canonical request (gộp method+path+query+header+hash body) → ký HMAC-SHA256. 10 bước
verify: format(rẻ) → timestamp window 300s (SEC-08) → nonce exists (SEC-07 replay) →
recompute signature → compare_digest (SEC-09, thời gian hằng định) → set nonce sau cùng.
NONCE_TTL 600 > WINDOW 300 → kho nonce không phình. **Phát hiện F2** (hardcode dev secret,
có fail-closed switch).

### middleware/auth.py ✅ — nối JWT vào luồng
Chỉ chạy trên `/api/protected`. Lấy Bearer token → `verify_token` (chốt 6) → kiểm
`is_revoked(jti)` (SEC-10) → gắn `request.state.user` (identity chảy xuống route). Mọi
nhánh ghi metric/trace (audit). **Phát hiện F3**: authorization (chốt 7) chưa enforce —
chỉ đọc role, không chặn.

### middleware/hmac_auth.py ✅ — nối HMAC vào luồng
Song song auth.py, chạy trên `/api/service`. Tạo `redis_client` (nơi vai trò "kho nonce"
M4 = Redis M5, host/port từ env). Đọc raw body → `verify_hmac_request(nonce_store=redis_client)`.
Hỏng → 401. Audit dùng `x-key-id` làm danh tính M2M.

### middleware/rate_limit.py ✅ — MT-AVAIL (chốt 1)
Khởi tạo `Limiter` per-IP (`get_remote_address`), bộ đếm trong Redis, fixed-window. Áp
giới hạn qua `@limiter.limit` trên route. Vượt → 429. Redis làm việc thứ 3 (nonce +
blacklist + rate). Quan sát: mới per-IP, chưa per-client.

### storage/revocation.py ✅ — jti blacklist (SEC-10)
Giải bài toán JWT self-contained không thu hồi được. `revoke(jti, exp)` đẩy jti vào
Redis với **TTL = exp − now** (tự hết hạn đúng lúc token chết → blacklist không phình).
`is_revoked(jti)` được auth.py gọi sau khi verify chữ ký. Mẫu "store tự dọn" lặp lại
từ nonce.

### storage/vault_client.py ✅ — MT-CONF (secret store client)
`get_secret()` gọi HTTP API Vault với `X-Vault-Token`, cache 300s. **Phát hiện F4**:
default `dev-root-token` = ngược least-privilege. Cùng họ dev-shortcut với F1/F2.

### routes/auth.py ✅ — hoàn tất vòng đời thu hồi (SEC-10)
`/auth/revoke`: verify token → `revoke(jti, exp)` đẩy vào blacklist. Idempotent. Đây là
nơi `revoke()` được gọi, khớp với `is_revoked()` ở auth middleware.

### observability/logger.py ✅ — audit (MT-NONREP)
JSON structured log ra stdout. Hỗ trợ audit; non-repud thật cần thêm tamper-proof + ký.

### observability/metrics.py ✅ — detection
Counter `auth_failures_total{method,reason}` + `auth_success_total`. Cho phép NHÌN thấy
tấn công (spike replay_detected...). Prevention + detection.

### observability/tracing.py ✅ — trace + fail-safe
OTel→Jaeger, gắn `auth.*` attribute mỗi request. Thiết kế: Jaeger chết → drop span, KHÔNG
sập gateway (observability không phá dịch vụ chính). OTel optional qua try/except ImportError.

---

## ✅ MODULE 6 HOÀN THÀNH — 11/11 file. 4 phát hiện: F1-F4 (xem bảng trên).
