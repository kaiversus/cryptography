# Module 7 — Giải thích từng file test bảo mật

> Mục tiêu: hiểu **mỗi test mô phỏng tấn công kiểu gì**, **vì sao nó "thành công"**,
> và **đoạn code nào trong gateway chặn vector đó**. Đọc xong là tự trình bày được
> cho thầy từng test một.

---

## PHẦN 0 — Hai điều phải hiểu trước

### 0.1 "Test bảo mật PASS" nghĩa là TẤN CÔNG BỊ CHẶN

Đây là chỗ dễ hiểu ngược nhất. Test thường (test chức năng) PASS khi chương trình
**làm được việc tốt**. Test bảo mật thì ngược: nó dựng một **request độc**, gửi vào
gateway, rồi **mong gateway TỪ CHỐI** nó (trả 401/403). Test PASS = "đòn tấn công đã bị
chặn đúng như thiết kế".

```
make request ĐỘC  ──►  gateway xử lý  ──►  assert status == 401/403
                                            ▲
                         nếu gateway lỡ cho qua (200) → test FAIL → có lỗ hổng
```

Vậy `assert r.status_code == 401` không phải "lỗi", mà là **bằng chứng phòng thủ hoạt
động**. Còn `test_smoke_...` (gửi request **hợp lệ**, mong 200) là để chứng minh hệ
thống không "chặn nhầm tất cả" — tức phòng thủ đúng chỗ, không phải hỏng toàn bộ.

### 0.2 Cỗ máy giả lập (test harness) — vì sao test chạy được mà không cần Keycloak/Redis thật

Test không dựng cả stack Docker. Nó **thay các thành phần ngoài bằng đồ giả** để chỉ
soi đúng logic gateway. Tất cả nằm ở `tests/security/conftest.py`:

| Thành phần thật | Bị thay bằng | Để làm gì |
|---|---|---|
| Keycloak (JWKS) | `mock_jwks` trả về 1 khóa HS256 cố định | Test tự ký token bằng đúng khóa đó → kiểm logic verify mà không cần Keycloak |
| Redis (nonce store) | `FakeRedis` (dict trong RAM) | Lưu nonce trong bộ nhớ, reset mỗi test |
| Redis (revocation) | `_NoopRevocationStore` | Mặc định "không token nào bị thu hồi" |
| HTTP server | `TestClient(app)` | Gọi thẳng app FastAPI trong tiến trình, không mở cổng mạng |

> Nhờ vậy mỗi test **cô lập**, chạy nhanh, và chỉ kiểm **đúng một quyết định bảo mật**.

---

## PHẦN 1 — Hai "xưởng chế tạo tấn công": `helpers.py`

Mọi test JWT/HMAC đều gọi 2 hàm trong `tests/security/helpers.py` để **dựng request**.
Hiểu 2 hàm này là hiểu 80% cách test hoạt động.

### 1.1 `make_token(...)` — máy đúc JWT, đổi 1 tham số = thành 1 đòn tấn công

Hàm này tạo một token **hợp lệ mặc định**, nhưng cho phép **override từng claim** để biến
nó thành token độc:

```python
def make_token(secret=TEST_SECRET, alg="HS256", kid=TEST_KID,
               iss=ISSUER, aud=AUDIENCE, exp_offset=300, extra=None):
    payload = {"sub": "testuser", "iss": iss, "aud": aud,
               "iat": now, "exp": now + exp_offset, "jti": ...}
    if extra: payload.update(extra)
    return jwt.encode(payload, secret, algorithm=alg, headers={"kid": kid})
```

| Đổi tham số | Token biến thành | Phục vụ test |
|---|---|---|
| `secret="khóa lạ"` | token ký bằng khóa **không** có trong JWKS | SEC-01 forgery |
| `exp_offset=-60` | token **đã hết hạn** từ 60s trước | SEC-04 expired |
| `aud="wrong"` | token gửi **nhầm đối tượng** | SEC-05 |
| `iss="evil..."` | token **giả nguồn phát hành** | SEC-06 |
| `extra={"realm_access":{"roles":["admin"]}}` | token **có** role admin | SEC-11 (mặt cho qua) |
| (mặc định) | token thường, **không** role admin | SEC-11 (mặt chặn) |

### 1.2 `make_alg_none_token()` — token "alg=none" tự bịa

`jwt.encode` của thư viện không cho ký kiểu `alg=none`, nên test **tự ghép tay** 3 phần
base64 với phần chữ ký **rỗng**:

```python
header  = b64({"alg":"none","typ":"JWT","kid":...})
payload = b64({"sub":"attacker", ...})
return f"{header}.{payload}."   # <- dấu chấm cuối: signature TRỐNG
```

Đây mô phỏng đòn **algorithm downgrade**: kẻ tấn công khai báo "token này không cần chữ
ký", hòng lừa verifier bỏ qua bước kiểm chữ ký.

### 1.3 `sign_hmac(...)` — máy ký HMAC, đổi 1 tham số = 1 đòn tấn công M2M

Hàm này tạo bộ 5 header HMAC **đúng chuẩn** `gateway-internal/v1` (giống hệt cách server
tính), rồi cho override để dựng tấn công:

```python
signed = {host, x-key-id, x-nonce, x-timestamp}      # các trường được đưa vào ký
canonical = METHOD\n path\n query\n <headers>\n <signed_keys>\n sha256(body)
sts = "HMAC-SHA256\n{ts}\ngateway-internal/v1\n" + sha256(canonical)
sig = HMAC-SHA256(secret, sts)                        # chữ ký cuối
→ trả headers: X-Timestamp, X-Nonce, X-Key-Id, X-Signature
```

| Đổi tham số | Request biến thành | Phục vụ test |
|---|---|---|
| (mặc định) | request ký đúng | smoke 200 |
| gửi lại y hệt lần 2 | **cùng nonce** → replay | SEC-07 |
| `ts = now-1000` | timestamp **quá cũ** | SEC-08 |
| ký body A, `content=` body B | **chữ ký không khớp body** | SEC-09 |
| `key_id="ghost-key"` | **key không tồn tại** trong store | unknown_key |

**Điểm cốt lõi để hiểu SEC-09:** chữ ký được tính **từ hash của body**. Test ký lúc body
là `{"id":1}` nhưng lúc gửi lại đổi `content` thành `{"id":999}`. Server tính lại hash của
body **999** → ra chữ ký khác → không khớp → chặn. Đó là cách HMAC "phát hiện sửa body".

---

## PHẦN 2 — `test_jwt_attacks.py` (luồng user, endpoint `/api/protected`, `/api/admin`)

Mỗi test gửi token qua header `Authorization: Bearer <token>`. Đường đi:
**middleware `jwt_auth_middleware` (auth.py) → `verify_token` (jwt_verifier.py)**.

### test_smoke_valid_token → 200
Token mặc định (đúng khóa, còn hạn, đúng iss/aud). Chứng minh setup đúng: phòng thủ
không chặn nhầm request sạch.

### SEC-01 — `test_sec01_forgery_wrong_key` (giả token, ký khóa lạ) → 401
- **Tấn công:** `make_token(secret="attacker-secret-key-not-in-jwks")` — kẻ tấn công tự
  chế token, tự ký bằng khóa của nó.
- **Chặn ở đâu:** `jwt_verifier.py` dòng `jwt.decode(token, secret/key, ...)` với
  `verify_signature=True`. Server verify bằng **khóa thật** (khóa trong JWKS / HS256_SECRET),
  không phải khóa của attacker → chữ ký **không khớp** → `JWTError` → bọc thành
  `TokenInvalid` → middleware trả **401**.
- **Vì sao an toàn:** attacker không có khóa ký thật của IdP nên **không giả được chữ ký**.
  Đây chính là lý do chọn chữ ký bất đối xứng (MT-AUTHN).

### SEC-02 — `test_sec02_alg_none_downgrade` (ép bỏ chữ ký) → 401
- **Tấn công:** token `alg=none`, chữ ký rỗng.
- **Chặn ở đâu:** `jwt_verifier.py` dòng 56:
  `if alg not in ("HS256","RS256","ES256"): raise TokenInvalid(...)`. `none` **không nằm
  trong whitelist** → bị từ chối **trước cả khi** thử verify → 401.
- **Vì sao an toàn:** dùng **danh sách trắng thuật toán**, không bao giờ tin trường `alg`
  do client khai để "tự bỏ" bước kiểm chữ ký.

### SEC-04 — `test_sec04_expired_token` (token hết hạn) → 401
- **Tấn công:** `exp_offset=-60` → `exp` nằm ở quá khứ.
- **Chặn ở đâu:** `decode_options` có `verify_exp=True` (dòng 62). `jwt.decode` thấy
  `exp < now` → ném "Signature has expired" → 401.
- **Vì sao an toàn:** token bị lộ cũng **chỉ sống trong cửa sổ ngắn**, hết hạn là vô dụng.

### SEC-05 — `test_sec05_wrong_audience` (sai đối tượng) → 401
- **Tấn công:** `aud="wrong-audience"`.
- **Chặn ở đâu:** `verify_aud=True` + tham số `audience=AUDIENCE` trong `jwt.decode`. `aud`
  trong token ≠ `account` → từ chối → 401.
- **Vì sao an toàn:** token cấp cho **dịch vụ khác** không xài lại được ở gateway này
  (chống token "đi lạc" giữa các service).

### SEC-06 — `test_sec06_wrong_issuer` (giả nguồn phát hành) → 401
- **Tấn công:** `iss="http://evil.example.com/..."`.
- **Chặn ở đâu:** `verify_iss=True` + `issuer=ISSUER`. `iss` ≠ realm nt219 → từ chối.
- **Vì sao an toàn:** chỉ chấp nhận token do **đúng IdP của mình** phát hành, không nhận
  token từ một IdP giả mạo.

### SEC-11 — `test_sec11_privilege_escalation_no_role` (user thường đòi vào admin) → 403
- **Tấn công:** `make_token()` — token **hợp lệ hoàn toàn** nhưng **không có** role admin,
  gọi `/api/admin`.
- **Chặn ở đâu:** `auth.py` khối AUTHORIZATION (dòng 45-56): sau khi authentication PASS,
  kiểm `if required_role not in payload["realm_access"]["roles"]: return 403`.
- **Điểm tinh tế phải nói với thầy:** đây là **401 ≠ 403**. Token đúng chữ ký (anh **là**
  ai — authentication OK), nhưng **không đủ quyền** (anh được **làm gì** — authorization
  fail) → trả **403**, không phải 401. Hai tầng tách biệt.
- **Mặt còn lại** `test_sec11_admin_role_allowed`: token có `roles:["admin"]` → 200,
  chứng minh không chặn nhầm admin thật.

### SEC-10 — `test_sec10_revoked_jti` (token bị thu hồi) → 401
- **Tấn công 2 pha:** (1) token hợp lệ đi qua được (200). (2) Đẩy `jti` của nó vào
  blacklist (`_RevokedStore`), gửi **lại đúng token đó** → giờ phải bị chặn.
- **Chặn ở đâu:** `auth.py` dòng 34-40: `if jti and is_revoked(jti): return 401`. Token
  vẫn đúng chữ ký, nhưng `jti` nằm trong sổ đen → chặn.
- **Vì sao cần:** chữ ký đúng + còn hạn vẫn **chưa đủ** — phải thu hồi được token trước
  hạn (ví dụ user logout, lộ token). Đây là lớp kiểm trạng thái, khác với kiểm mật mã.

---

## PHẦN 3 — `test_hmac_attacks.py` (luồng M2M, endpoint `/api/service`)

Đường đi: **middleware `hmac_auth_middleware` → `verify_hmac_request` (hmac_verifier.py)**,
chạy đúng 10 bước trong file verifier.

### test_smoke_valid_hmac → 200
Ký đúng → server tính lại chữ ký khớp → cho qua. Chứng minh đường M2M sạch hoạt động.

### SEC-07 — `test_sec07_replay_same_nonce` (phát lại request) → 401
- **Tấn công:** gửi **2 lần** cùng một request (cùng nonce). Lần 1 → 200. Lần 2 → phải 401.
- **Chặn ở đâu:** `hmac_verifier.py` bước 4 (dòng 113-115): `if nonce_store.exists(...)
  raise "replay_detected"`; và bước 10 (dòng 136): sau khi pass, **ghi nonce vào store**.
  Lần 2 thấy nonce đã có → chặn.
- **Vì sao an toàn:** mỗi nonce **dùng đúng một lần**. Kẻ nghe lén có bắt được nguyên request
  cũng không phát lại được (RP1-IG).

### SEC-08 — `test_sec08_timestamp_out_of_window` (request quá cũ) → 401
- **Tấn công:** `ts = now - 1000` (cũ hơn 1000 giây).
- **Chặn ở đâu:** bước 3 (dòng 109): `if abs(now - ts) > 300: raise "invalid_timestamp"`.
- **Vì sao an toàn:** giới hạn cửa sổ 5 phút → kho nonce **không phình vô hạn** (chỉ cần
  nhớ nonce trong 5 phút) và thu hẹp thời gian kẻ tấn công có thể thử phát lại.

### SEC-09 — `test_sec09_body_tampering` (sửa body giữ chữ ký) → 401
- **Tấn công:** ký lúc body `{"id":1}`, nhưng gửi `content={"id":999}`.
- **Chặn ở đâu:** chữ ký được tính từ `sha256(body)` (hàm `_build_canonical_request`
  dòng 63). Server tính lại hash của body **999** → chữ ký kỳ vọng khác → bước 9
  `hmac.compare_digest(expected, signature)` **không khớp** → `invalid_signature` → 401.
- **Vì sao an toàn:** **đây chính là vector số 2 của bạn.** Sửa dù 1 byte body là chữ ký
  hỏng. Kẻ tấn công không có secret nên **không ký lại được** cho body mới (MT-INTEG, T1-IG).

### test_unknown_key_id (key không tồn tại) → 401
- **Tấn công:** `key_id="ghost-key"`.
- **Chặn ở đâu:** bước 5 (dòng 117-120): `_resolve_secret` không tìm thấy secret cho key
  này → trả `None` → `raise "unknown_key"`.
- **Vì sao an toàn:** chỉ những client đã được cấp secret (trong Vault) mới gọi được; key
  bịa ra bị loại ngay.

> **Lưu ý so khớp body trong test:** server đọc body **đúng dạng raw bytes**. Hàm
> `sign_hmac` ký trên `body=` còn `client.post(..., content=...)` gửi bytes nguyên — không
> để FastAPI tự encode lại — nên hash hai bên khớp khi hợp lệ, lệch khi tamper.

---

## PHẦN 4 — `test_availability.py` (SEC-12, chống DoS, endpoint `/api/public`)

### SEC-12 — `test_sec12_rate_limit_blocks_flood` → 10×200 rồi 429
- **Tấn công:** bắn **12 request liên tiếp** vào `/api/public` (giới hạn 10/phút).
- **Code test:**
  ```python
  statuses = [client.get("/api/public").status_code for _ in range(12)]
  assert all(s == 200 for s in statuses[:10])   # 10 đầu trong hạn mức
  assert all(s == 429 for s in statuses[10:])    # vượt ngưỡng → chặn
  ```
- **Chặn ở đâu:** `main.py` dòng `@limiter.limit("10/minute")` trên endpoint; thư viện
  `slowapi` đếm theo IP, vượt ngưỡng ném `RateLimitExceeded` → **429**.
- **Vì sao chứng minh được MT-AVAIL:** khi một IP bắn quá nhiều, nó **tự bị chặn**, băng
  thông/CPU dành lại cho user thật → flood không đánh sập được dịch vụ (D1-IG).
- **Mẹo môi trường test:** `conftest.py` đặt `REDIS_URL="memory://"` để slowapi đếm trong
  RAM, không cần Redis thật.

---

## PHẦN 5 — `test_audit.py` (SEC-13, chống chối bỏ, endpoint `/api/service`)

Đây là test cho **tính năng mới thêm**: sổ audit. Code phòng thủ ở
`gateway/observability/audit.py` + lời gọi `record_audit(...)` trong 2 middleware.

### SEC-13a — `test_sec13_audit_records_allowed_request` → có bản ghi "allow"
- **Kịch bản:** gửi request M2M **hợp lệ**, rồi kiểm sổ audit có ghi lại.
- **Code test:**
  ```python
  before = len(audit.RECENT_AUDIT)          # đánh dấu vị trí trước
  r = client.post("/api/service", content=body, headers=sign_hmac(body=body))
  new = list(audit.RECENT_AUDIT)[before:]   # chỉ lấy bản ghi MỚI sinh
  assert any(rec["actor"]=="dev-key-01" and rec["decision"]=="allow" for rec in new)
  ```
- **Chặn/ghi ở đâu:** `hmac_auth.py` nhánh success gọi
  `record_audit(channel="hmac", actor=X-Key-Id, decision="allow", ...)`. Hàm này thêm bản
  ghi vào `RECENT_AUDIT` (RAM) **và** ghi 1 dòng JSON vào `logs/audit.log`.
- **Vì sao chứng minh được MT-NONREP:** danh tính service (`dev-key-01`) **được ghi lại
  cùng thời điểm** → sau này service không thể chối "tôi không gửi".

### SEC-13b — `test_sec13_audit_records_denied_request` → có bản ghi "deny"
- **Kịch bản:** gửi request **tamper** (ký A gửi B) → bị 401, nhưng **vẫn phải vào sổ**.
- **Chặn/ghi ở đâu:** `hmac_auth.py` nhánh `except HMACInvalid` cũng gọi `record_audit(...
  decision="deny", reason=...)`.
- **Vì sao quan trọng:** không chỉ ghi việc tốt — **hành vi xấu cũng bị ghi kèm danh tính**.
  Đây mới là bằng chứng đầy đủ để quy trách nhiệm (R1-IG).

> **Vì sao test đọc `audit.RECENT_AUDIT` thay vì đọc log?** Buffer trong RAM cho kết quả
> **xác định, không phụ thuộc** cấu hình logging hay file IO → test ổn định. Còn
> `logs/audit.log` là artifact để trình bày cho người xem.

---

## Bảng tổng — test ↔ vector ↔ code phòng thủ

| Test | Vector (STRIDE/MT) | Mong đợi | Code chặn |
|---|---|---|---|
| SEC-01 forgery | Spoofing / AUTHN | 401 | `jwt.decode` verify_signature (jwt_verifier) |
| SEC-02 alg=none | Spoofing / AUTHN | 401 | whitelist `alg` (jwt_verifier:56) |
| SEC-04 expired | — / AUTHN | 401 | `verify_exp` |
| SEC-05 aud | — / AUTHN | 401 | `verify_aud` |
| SEC-06 iss | Spoofing / AUTHN | 401 | `verify_iss` |
| SEC-10 revoked | — / AUTHN | 401 | `is_revoked(jti)` (auth.py:35) |
| SEC-11 priv-esc | Elevation / AUTHZ | **403** | role check (auth.py:45-56) |
| SEC-07 replay | Replay / INTEG | 401 | nonce store (hmac_verifier:113,136) |
| SEC-08 timestamp | Replay / INTEG | 401 | window 300s (hmac_verifier:109) |
| SEC-09 tamper body | Tampering / INTEG | 401 | `compare_digest` chữ ký (hmac_verifier:132) |
| SEC-12 flood | DoS / AVAIL | 429 | `@limiter.limit` (main.py) |
| SEC-13 audit | Repudiation / NONREP | ghi sổ | `record_audit` (audit.py) |

> Vector "nghe lén / MT-CONF" không có test pytest — đó là control **tầng truyền dẫn**
> (TLS/mTLS), chứng minh bằng cấu hình triển khai (`docker-compose.prod.yml`) và demo
> `curl -v` cho thấy HTTP để lộ token còn HTTPS thì không.
