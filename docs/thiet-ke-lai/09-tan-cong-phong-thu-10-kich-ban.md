# Tài liệu học & báo cáo — 10 kịch bản TẤN CÔNG ↔ PHÒNG THỦ

> File này dành cho cả 3 thành viên học và trình bày. Mỗi kịch bản gồm 2 phần đúng
> yêu cầu: **(A) Hướng tấn công** (cách đánh + vì sao có lỗ hổng + payload chính) và
> **(B) Hướng phòng thủ** (mindset + code chặn ở đâu + giải thích code chạy thế nào).

---

## Phân công 3 người (công sức cân bằng)

| Người | Mảng | Kịch bản | Số lượng | Ghi chú cân bằng |
|---|---|---|---|---|
| **Người 1** | JWT / Định danh (Authentication & Authorization) | KB1, KB6, KB9 | 3 | Code sâu trong `jwt_verifier.py` + `auth.py` |
| **Người 2** | HMAC / M2M (Integrity, Availability, Non-repudiation) | KB2, KB3, KB5 | 3 | Code sâu trong `hmac_verifier.py`, `audit.py`, `rate_limit.py` |
| **Người 3** | Hạ tầng / Truyền dẫn (Confidentiality & Trust boundary) | KB4, KB7, KB8, KB10 | 4 | Mỗi cái nhẹ code hơn (thiết kế/triển khai) → 4 cái ≈ 3 cái của người kia |

> **Lý do chia vậy:** Người 1 & 2 mỗi người 3 kịch bản nhưng *đào sâu code mật mã*;
> Người 3 nhận 4 kịch bản nhưng phần lớn là *control tầng triển khai* (TLS/mTLS/Vault,
> ít dòng code hơn) nên tổng công sức tương đương.

---

## Nền tảng chung — đọc trước (cả 3 người)

Toàn bộ phòng thủ của Gateway là một **dây chuyền chốt** xếp theo thứ tự **rẻ → đắt →
quyền**. Request phải qua lần lượt; rớt chốt nào bị chặn ngay tại đó:

```
[1] rate-limit        quá ngưỡng → 429   (rẻ)
[2] token/format      thiếu/méo  → 401
[3] exp/timestamp     hết/cũ     → 401
[4] nonce             trùng      → 401   (chống replay)
[5] HMAC body         sai        → 401   (chống sửa body)
[6] verify chữ ký JWT sai        → 401   ← AUTHENTICATION ("anh là ai")
[7] scope/role        thiếu      → 403   ← AUTHORIZATION  ("được làm gì")
[8] backend tự kiểm lại (zero-trust)
```

**Hai quy tắc vàng nhắc lại liên tục trong file:**
1. **401 ≠ 403.** 401 = chưa chứng minh được "anh là ai" (authentication). 403 = biết anh
   là ai rồi nhưng "không đủ quyền" (authorization). Không bao giờ trộn.
2. **Rẻ trước, đắt sau.** Kiểm rẻ (format/timestamp/nonce) đặt TRƯỚC kiểm tốn CPU (verify
   chữ ký) để rác bị loại sớm, chống DoS tầng ứng dụng.

File code tham chiếu chính:
- `gateway/crypto/jwt_verifier.py` — verify JWT
- `gateway/middleware/auth.py` — middleware JWT (authn + authz + revocation + audit)
- `gateway/crypto/hmac_verifier.py` — verify HMAC (10 bước)
- `gateway/middleware/hmac_auth.py` — middleware HMAC
- `gateway/observability/audit.py` — sổ audit (chống chối bỏ)
- `gateway/middleware/rate_limit.py` + `gateway/main.py` — rate limit
- `infra/docker-compose.prod.yml` — cô lập mạng (control triển khai)

---
---

# NGƯỜI 1 — JWT / ĐỊNH DANH

## KB1 — Giả mạo token (Spoofing · MT-AUTHN)

### (A) Hướng tấn công
**Cách đánh:** kẻ tấn công tự tạo một JWT, tự điền `sub`, `roles`, rồi **tự ký**. Có 2
biến thể:
- **Ký bằng khóa lạ** (SEC-01): nó không có khóa thật của IdP nên ký bằng khóa của nó.
- **Hạ cấp thuật toán `alg=none`** (SEC-02): nó khai báo "token này không cần chữ ký",
  hòng lừa verifier bỏ qua bước kiểm.

**Vì sao lỗ hổng xảy ra:** nếu Gateway tin "có token là được", hoặc verify bằng khóa do
*chính token* chỉ định, hoặc chấp nhận `alg` tùy client khai → ai cũng giả được danh tính.

**Payload chính:**
```python
# Biến thể 1 — ký bằng khóa KHÔNG nằm trong JWKS:
make_token(secret="attacker-secret-key-not-in-jwks")

# Biến thể 2 — alg=none, chữ ký RỖNG (tự ghép tay vì lib không cho ký):
header  = b64({"alg": "none", "typ": "JWT", "kid": ...})
payload = b64({"sub": "attacker", "iss": ISSUER, "aud": "account", ...})
token   = f"{header}.{payload}."        # <- dấu chấm cuối: signature TRỐNG
```

### (B) Hướng phòng thủ
**Mindset:** *không bao giờ tin metadata do token tự khai.* Khóa verify phải do **server
chọn** từ nguồn tin cậy; thuật toán phải nằm trong **danh sách trắng**; chữ ký phải verify
bằng **toán**, không bằng lời.

**Code chặn — `gateway/crypto/jwt_verifier.py`:**

1. **Whitelist thuật toán** (chặn `alg=none`):
```python
if alg not in ("HS256", "RS256", "ES256"):
    raise TokenInvalid(f"... Algorithm '{alg}' is blacklisted")
```
→ `none` không nằm trong danh sách → bị loại **trước khi** thử verify. Đây là lý do
biến thể 2 trả 401 ngay.

2. **Bắt buộc verify chữ ký bằng khóa THẬT:**
```python
decode_options = {"verify_signature": True, ...}
# nhánh bất đối xứng: khóa lấy từ JWKS theo kid, KHÔNG từ token
key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
jwt.decode(token, key, algorithms=[alg], audience=AUDIENCE, issuer=ISSUER, options=...)
```
→ `jwt.decode` tính lại chữ ký bằng khóa công khai thật của IdP. Token ký bằng khóa lạ →
chữ ký **không khớp** → `JWTError` → bọc thành `TokenInvalid` → middleware trả **401**.

3. **Vì sao an toàn về bản chất:** chọn **chữ ký bất đối xứng** (ES256) → IdP giữ khóa
*riêng* để ký, Gateway chỉ giữ khóa *công khai* để verify. Khóa ở Gateway có lộ cũng
**không ký giả được token**. (Trả lời câu "vì sao ES256 hơn HS256".)

---

## KB6 — Leo thang quyền (Elevation of Privilege · MT-AUTHZ)

### (A) Hướng tấn công
**Cách đánh:** kẻ tấn công có **token hợp lệ hoàn toàn** của một user thường (đăng nhập
thật), nhưng gọi endpoint **chỉ dành cho admin** (`/api/admin`).

**Vì sao lỗ hổng xảy ra:** nếu hệ thống chỉ kiểm "token có hợp lệ không" (authentication)
mà **quên kiểm quyền** (authorization), thì mọi user đăng nhập đều vào được khu admin.

**Payload chính:**
```python
tok = make_token()                       # token THẬT, hợp lệ, nhưng KHÔNG có role admin
GET /api/admin   Authorization: Bearer <tok>
```

### (B) Hướng phòng thủ
**Mindset:** *authentication xong CHƯA đủ — phải hỏi tiếp "được làm gì".* Và phân biệt
rạch ròi 401 (chưa biết anh là ai) với 403 (biết rồi nhưng thiếu quyền).

**Code chặn — `gateway/middleware/auth.py`, khối AUTHORIZATION (chốt 7):**
```python
REQUIRED_ROLES = {ADMIN_PREFIX: "admin"}
...
for prefix, required_role in REQUIRED_ROLES.items():
    if request.url.path.startswith(prefix):
        roles = payload.get("realm_access", {}).get("roles", [])
        if required_role not in roles:
            record_failure("jwt", "insufficient_role")
            return JSONResponse(status_code=403,
                content={"detail": f"forbidden: requires role '{required_role}'"})
```
→ Sau khi authentication PASS (đã biết "anh là ai"), code đọc danh sách role **từ claim
đã ký trong token** (`realm_access.roles`). Nếu thiếu `admin` → trả **403** (không phải
401). Role lấy từ token đã ký nên client **không thể tự thêm** (nếu sửa token thì hỏng
chữ ký → rớt ở KB1).

> Điểm nhấn báo cáo: cùng một token, gọi `/api/protected` thì 200, gọi `/api/admin` thì
> 403 — chứng minh tầng authz hoạt động độc lập với authn.

---

## KB9 — Đánh tráo JWKS (Spoofing IdP · S1-IdP)

### (A) Hướng tấn công
**Cách đánh:** Gateway tải khóa công khai từ IdP qua URL JWKS. Nếu kênh đó **không có
TLS** (hoặc DNS bị đầu độc), kẻ tấn công đứng giữa (MITM) trả về **JWKS giả** chứa public
key **của nó**, rồi ký token bằng private key tương ứng, đặt `iss/aud/kid` khớp.

**Vì sao lỗ hổng xảy ra:** Gateway tin tuyệt đối nội dung tải về từ URL JWKS. Nếu URL đó
không được bảo vệ truyền dẫn, "nguồn khóa tin cậy" bị thay → mọi verify sau đó vô nghĩa.

**Payload chính:**
```python
# Hacker tạo cặp khóa ES256 của nó, nhét public key vào JWKS bị tráo:
jv._get_jwks = lambda: {"keys": [attacker_jwk]}        # kênh JWKS bị MITM
forged = jwt.encode({"sub": "attacker", "iss": ISSUER, "aud": AUDIENCE,
                     "realm_access": {"roles": ["admin"]}, ...},
                    attacker_private_pem, algorithm="ES256",
                    headers={"kid": "attacker-kid-001"})
```

### (B) Hướng phòng thủ
**Mindset quan trọng nhất của kịch bản này:** *có những đòn mà tầng ứng dụng KHÔNG tự
cứu được — phải đẩy control xuống tầng truyền dẫn.* Mọi kiểm tra app-layer (whitelist
alg, verify iss/aud, tra kid) **đều PASS** vì token khớp bộ khóa đã bị tráo.

**Áp dụng:**
- **Control bắt buộc = fetch JWKS qua HTTPS/TLS** (chống MITM thay nội dung) + pin
  issuer/CA. Ở code, điểm cần siết là URL trong `jwt_verifier.py`:
```python
JWKS_URL = os.getenv("JWKS_URL", "http://keycloak:8080/.../certs")   # dev: HTTP nội bộ
```
→ Production phải đặt `JWKS_URL=https://...` để response JWKS được TLS bảo vệ.
- **Bằng chứng (demo `sec_jwks_substitution_demo.py`):** khi tráo JWKS, `verify_token`
  **chấp nhận token giả** → đúng như dự đoán, chứng minh app-logic bất lực, **PHẢI có
  TLS**. Đây là cách trình bày trung thực giới hạn của tầng ứng dụng.

> Cách đọc demo: kết quả "đòn LỌT" là cố ý, để minh chứng vì sao cần TLS — khác với pytest
> bảo mật (PASS = đòn bị chặn).

---
---

# NGƯỜI 2 — HMAC / M2M

## KB2 — Sửa nội dung request M2M (Tampering · MT-INTEG)

### (A) Hướng tấn công
**Cách đánh:** trên luồng máy-gọi-máy (M2M), kẻ tấn công chặn một request đã ký HMAC, rồi
**sửa body** (ví dụ đổi số tiền, đổi id) nhưng **giữ nguyên chữ ký cũ**, hòng tuồn dữ
liệu độc vào backend.

**Vì sao lỗ hổng xảy ra:** nếu backend chỉ tin "có chữ ký là được" mà không **gắn chữ ký
với nội dung body**, thì sửa body không bị phát hiện.

**Payload chính:**
```python
headers = sign_hmac(body=b'{"id":1}')          # ký cho body {"id":1}
POST /api/service  body = b'{"id":999}'  + headers  # nhưng GỬI body {"id":999}
```

### (B) Hướng phòng thủ
**Mindset:** *chữ ký phải phủ lên chính nội dung* — đổi 1 byte body là chữ ký phải hỏng.
Và phải so sánh chữ ký theo kiểu **constant-time** để không lộ thông tin qua thời gian.

**Code chặn — `gateway/crypto/hmac_verifier.py`:**

1. Chữ ký được tính **từ hash của body**:
```python
body_hash = hashlib.sha256(body).hexdigest() if body else EMPTY_BODY_HASH
canonical = method + "\n" + path + "\n" + query + "\n" + canonical_headers + "\n" \
            + signed_headers + "\n" + body_hash      # body_hash nằm trong chuỗi ký
```

2. Server **tự tính lại** chữ ký kỳ vọng rồi so sánh:
```python
expected = compute_signature(method, path, query, signed_headers_values, body, secret)
if not hmac.compare_digest(expected, signature):     # so sánh constant-time
    raise HMACInvalid("invalid_signature")
```
→ Server nhận body `{"id":999}` → `sha256` ra hash **khác** → `expected` khác chữ ký đính
kèm (ký cho `{"id":1}`) → `compare_digest` thất bại → **401 invalid_signature**. Kẻ tấn
công **không có secret** nên không ký lại được cho body mới. `compare_digest` so sánh
constant-time → không rò rỉ qua đo thời gian.

---

## KB3 — Chối bỏ hành vi (Repudiation · MT-NONREP)

### (A) Hướng tấn công
**Cách đánh:** một service M2M gửi một request gây hại, sau đó **chối** "tôi không gửi".
Nếu hệ thống không lưu vết, không có bằng chứng → **không quy trách nhiệm được**.

**Vì sao lỗ hổng xảy ra:** thiếu **sổ ghi (audit trail)** gắn mỗi hành động với **danh
tính** người gọi tại thời điểm xảy ra.

**Payload chính:** (không phải payload phá hệ thống, mà là *tình huống chối bỏ*)
```python
POST /api/service  + headers HMAC hợp lệ (X-Key-Id: dev-key-01)   # service gửi
# ... sau đó service chối: "không phải tôi"  -> cần sổ audit để đối chất
```

### (B) Hướng phòng thủ
**Mindset:** *mọi quyết định auth (cho qua HAY từ chối) phải được ghi lại kèm danh tính,
không sửa được.* Ghi cả việc tốt lẫn việc xấu.

**Code chặn — `gateway/observability/audit.py` + gọi trong `hmac_auth.py`/`auth.py`:**
```python
# audit.py
def record_audit(*, channel, actor, decision, method, path, reason=""):
    record = {"ts": ..., "channel": channel, "actor": actor,
              "method": method, "path": path, "decision": decision, "reason": reason}
    RECENT_AUDIT.append(record)          # buffer RAM (cho test/endpoint đọc)
    audit_logger.info("AUDIT %s", json.dumps(record))
    # + ghi append-only ra logs/audit.log
```
```python
# hmac_auth.py — ghi ở CẢ nhánh cho qua lẫn nhánh từ chối:
except HMACInvalid as e:
    record_audit(channel="hmac", actor=X-Key-Id, decision="deny",  reason=...)   # việc xấu
...
record_audit(channel="hmac", actor=X-Key-Id, decision="allow")                   # việc tốt
```
→ Mỗi request M2M ghi lại `X-Key-Id` (danh tính service) + quyết định + thời điểm. Service
**không thể chối** vì danh tính của nó đã nằm trong sổ. Xem bằng chứng qua
`GET /audit/recent` hoặc file `logs/audit.log` (SEC-13).

---

## KB5 — Làm nghẽn dịch vụ (Denial of Service · MT-AVAIL)

### (A) Hướng tấn công
**Cách đánh:** kẻ tấn công bắn **hàng loạt request cùng lúc** vào Gateway, làm cạn CPU/băng
thông → **user thật không truy cập được**.

**Vì sao lỗ hổng xảy ra:** nếu không giới hạn tần suất, một nguồn xấu chiếm hết tài nguyên;
và nếu đặt kiểm tốn CPU (verify chữ ký) lên trước, rác cũng ngốn CPU.

**Payload chính:**
```python
for _ in range(12):                     # vượt ngưỡng 10/phút
    GET /api/public
# -> 10 request đầu 200, từ request 11 trở đi: 429 Too Many Requests
```

### (B) Hướng phòng thủ
**Mindset:** *giới hạn tần suất theo nguồn (per-IP)* + *kiểm rẻ trước, đắt sau* để rác bị
loại mà không tốn crypto.

**Code chặn — `gateway/middleware/rate_limit.py` + `gateway/main.py`:**
```python
# rate_limit.py — đếm theo IP, cửa sổ cố định
limiter = Limiter(key_func=get_remote_address, storage_uri=REDIS_URL, strategy="fixed-window")
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```
```python
# main.py — đặt ngưỡng từng endpoint
@app.get("/api/public")
@limiter.limit("10/minute")             # quá 10/phút/IP -> ném RateLimitExceeded -> 429
```
→ Mỗi IP vượt ngưỡng bị chặn **429** ngay, tài nguyên dành cho user thật. Kết hợp nguyên
tắc dây chuyền "rẻ → đắt": rate-limit là chốt **[1]** rẻ nhất, đặt trước mọi kiểm tra
crypto. (SEC-12.)

---
---

# NGƯỜI 3 — HẠ TẦNG / TRUYỀN DẪN

> 4 kịch bản này phần lớn là **control tầng triển khai** (TLS/mTLS/Vault/cô lập mạng).
> Một số *đã thiết kế nhưng chưa hiện thực* trong PoC — phải trình bày trung thực, đó
> chính là tư duy "kiến trúc ≠ triển khai" mà thầy yêu cầu.

## KB4 — Nghe lén đường truyền (Information Disclosure · MT-CONF)

### (A) Hướng tấn công
**Cách đánh:** kẻ tấn công nghe lén/đọc trộm giao tiếp giữa user/service ↔ backend, và
**lấy access token ngay tại thời điểm đó** để mạo danh.

**Vì sao lỗ hổng xảy ra:** nếu kênh truyền **không mã hóa** (HTTP trần), mọi header
`Authorization: Bearer ...` đi dạng chữ thường — ai bắt gói tin cũng đọc được.

**Payload chính:** (không cần code, chỉ cần bắt gói)
```bash
# Dev HTTP: token hiện nguyên văn trên đường truyền
curl -v http://localhost:8000/api/protected -H "Authorization: Bearer <token>"
#  -> trong gói tin, header Authorization là plaintext, sniffer đọc được
```

### (B) Hướng phòng thủ
**Mindset:** *bí mật chống nghe lén là việc của tầng truyền dẫn, không phải logic ứng
dụng* — phải mã hóa kênh.

**Áp dụng:**
- **TLS termination ở ingress:** prod đặt reverse-proxy/ingress giữ chứng chỉ, người dùng
  luôn nói **HTTPS** → sniffer chỉ thấy rác. Mô tả trong `infra/docker-compose.prod.yml`
  (chú thích cổng gateway sau ingress giữ TLS).
- **mTLS cửa 2** Gateway↔Backend: mã hóa cả chặng nội bộ.
- **Demo trình bày:** chạy `curl -v http://...` cho thầy thấy token plaintext (phản chứng),
  rồi giải thích prod dùng HTTPS thì không lộ. Đây là control **không test bằng pytest**
  (transport-level).

---

## KB7 — Vòng qua Gateway gọi thẳng Backend (Spoofing · S1-GB)

### (A) Hướng tấn công
**Cách đánh:** kẻ tấn công bằng cách nào đó đứng **trong mạng nội bộ** (chiếm 1 container
phụ, hoặc qua SSRF) và gọi **thẳng vào backend**, **bỏ qua toàn bộ** dây chuyền chốt của
Gateway.

**Vì sao lỗ hổng xảy ra:** nếu backend tin "ai trong mạng nội bộ cũng hợp lệ" (mô hình
phẳng), thì thủng 1 chỗ bất kỳ bên trong là vào thẳng backend — Gateway thành lính gác bị
vô hiệu.

**Payload chính:**
```bash
# Đứng trong gw-net, gọi thẳng backend không qua gateway:
curl http://backend:8000/internal/...      # mong backend xử lý vì "cùng mạng"
```

### (B) Hướng phòng thủ
**Mindset:** *zero-trust ở tầng mạng* — vị trí trong mạng KHÔNG phải là bằng chứng tin
cậy. Hai lớp:
1. **Cô lập mạng:** backend **không publish** cổng ra ngoài, chỉ tồn tại bằng IP nội bộ.
   Áp dụng: `infra/docker-compose.prod.yml` chỉ phơi Gateway, các service khác bỏ `ports:`.
2. **mTLS cửa 2:** backend chỉ chấp nhận peer **trình chứng chỉ hợp lệ = Gateway**. Kể cả
   đã ở trong mạng, không có cert thì không nói chuyện được.

**Trạng thái PoC (trung thực):** PoC **chưa có service backend riêng** nên **chưa hiện
thực mTLS** — đây là GAP thiết kế-vs-triển khai. Lớp cô lập mạng đã demo qua prod compose;
mTLS là hạng mục hardening trước prod (cần sinh cert + thêm backend).

---

## KB8 — Backend tin header Gateway chuyển xuống (Elevation · E2-GB)

### (A) Hướng tấn công
**Cách đánh:** Gateway sau khi xác thực thường chuyển danh tính/quyền xuống backend qua
header (vd `X-User`, `X-Role`). Nếu backend **tin header này vô điều kiện**, kẻ tấn công có
token user thường nhưng **tự đặt lại header** `X-Role: admin` để leo quyền.

**Vì sao lỗ hổng xảy ra:** backend coi header nội bộ là "đã được Gateway đảm bảo" mà không
tự kiểm lại — nhưng header có thể bị giả nếu request đi vòng (xem KB7) hoặc nếu tin mù.

**Payload chính:**
```python
user_token = make_token()                        # token user THƯỜNG (không admin)
headers = {"Authorization": f"Bearer {user_token}", "X-Role": "admin"}   # tự nhét X-Role
```

### (B) Hướng phòng thủ
**Mindset — "chốt 8 zero-trust":** *backend KHÔNG tin header trần.* Nó tự **verify lại
token gốc** (chữ ký IdP) và đọc quyền từ **claim ĐÃ KÝ**, bỏ qua header do client gửi.

**Code chặn (nguyên lý, `tests/security/test_backend_zerotrust.py`):**
```python
def naive_backend(headers):                      # SAI: tin header
    return headers.get("x-role") == "admin"      # -> bị lừa bởi X-Role giả

def zerotrust_backend(headers):                  # ĐÚNG: verify lại token
    claims = verify_token(headers["authorization"][7:])   # đọc role từ claim ĐÃ KÝ
    return "admin" in claims.get("realm_access", {}).get("roles", [])
```
→ `zerotrust_backend` lấy role từ token đã ký, không thấy `admin` → **chặn** spoof; chỉ cho
qua khi admin thật. (SEC-14.) **Trạng thái PoC:** chưa có backend thật nên đây là test
nguyên lý — khi thêm backend phải áp pattern này.

---

## KB10 — Lộ khóa ở kênh Gateway↔Vault (Information Disclosure · I1-Vault)

### (A) Hướng tấn công
**Cách đánh:** nếu kênh Gateway↔Vault **không mã hóa** hoặc cấu hình sai (token quá rộng,
để root token), bất kỳ ai nghe lén/đứng trong nội bộ đều **đọc được secret/khóa**.

**Vì sao lỗ hổng xảy ra:** kho bí mật là tài sản quý nhất; nếu kênh truy cập nó không TLS
và quyền không tối thiểu, "nội bộ ai cũng đọc được khóa".

**Payload chính:**
```bash
# Vault dev mở HTTP + root token -> đọc thẳng secret nếu chạm được:
curl -H "X-Vault-Token: dev-root-token" http://vault:8200/v1/secret/data/gateway/hs256
```

### (B) Hướng phòng thủ
**Mindset:** *least-privilege + mã hóa kênh + không dùng root token.*

**Áp dụng:**
1. **TLS tới Vault** (chống nghe lén in-transit).
2. **Least-privilege policy:** mỗi service token chỉ đọc đúng path của mình, **bỏ root
   token**.
3. **Fail-closed ở code (ĐÃ LÀM — F4), `gateway/storage/vault_client.py`:**
```python
VAULT_TOKEN = os.getenv("VAULT_TOKEN")           # bỏ default "dev-root-token"
def _require_token():
    if not VAULT_TOKEN:
        raise VaultError("vault_token_not_configured")   # không có token -> từ chối
```
→ Code đã buộc phải có token (không hardcode root). Còn **TLS + policy least-priv** là
control triển khai: prod đặt Vault internal-only (đã mô tả trong `docker-compose.prod.yml`)
và bật TLS thật. **Trạng thái PoC:** dev dùng Vault HTTP + root token (lối tắt dev).

---
---

## Bảng tra nhanh toàn bộ (in ra trình bày)

| KB | Tên | STRIDE / MT | Người | Code/Artifact chặn | Kết quả |
|---|---|---|---|---|---|
| 1 | Token giả / alg=none | Spoofing / AUTHN | 1 | `jwt_verifier.py` (whitelist alg + verify chữ ký) | 401 |
| 6 | Leo thang quyền | Elevation / AUTHZ | 1 | `auth.py` khối authz (role check) | 403 |
| 9 | Tráo JWKS | Spoofing IdP / AUTHN | 1 | JWKS-over-TLS (demo SEC-15) | cần TLS |
| 2 | Sửa body HMAC | Tampering / INTEG | 2 | `hmac_verifier.py` (hash body + compare_digest) | 401 |
| 3 | Chối bỏ | Repudiation / NONREP | 2 | `audit.py` (record_audit) | ghi sổ |
| 5 | Flood DoS | DoS / AVAIL | 2 | `rate_limit.py` + `main.py` (@limiter) | 429 |
| 4 | Nghe lén token | Info Disclosure / CONF | 3 | TLS ingress (prod compose) | mã hóa kênh |
| 7 | Vòng qua gateway | Spoofing / S1-GB | 3 | cô lập mạng + mTLS (thiết kế) | cách ly |
| 8 | Backend tin header | Elevation / E2-GB | 3 | zero-trust re-verify (SEC-14) | chặn spoof |
| 10 | Lộ khóa Vault | Info Disclosure / I1-Vault | 3 | TLS+least-priv + fail-closed F4 | từ chối |

> **Mỗi người trình bày 3–4 kịch bản theo bảng trên, mỗi kịch bản nói đủ 2 ý: tấn công
> (cách + vì sao + payload) và phòng thủ (mindset + code + giải thích).**
