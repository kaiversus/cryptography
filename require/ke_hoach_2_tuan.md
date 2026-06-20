# KẾ HOẠCH 2 TUẦN - SECURE API GATEWAY WITH CRYPTOGRAPHIC ENFORCEMENT

> **Bối cảnh:** Đồ án 4 tuần nén còn 14 ngày. Nhóm xuất phát từ nền **Python + Git cơ bản**, các stack còn lại (Docker, FastAPI, Keycloak, Vault, K8s, OAuth2/JWT, HMAC) vừa học vừa làm. Benchmark wrk/Locust được đẩy xuống **giai đoạn cuối** - làm khi còn thời gian.

---

## MỤC LỤC
1. [Nguyên tắc vận hành 14 ngày](#nguyên-tắc-vận-hành-14-ngày)
2. [Bản đồ tổng thể 14 ngày](#bản-đồ-tổng-thể-14-ngày)
3. [TASK CHI TIẾT - SINH VIÊN A (Auth & Crypto)](#sinh-viên-a)
4. [TASK CHI TIẾT - SINH VIÊN B (Gateway & Infra)](#sinh-viên-b)
5. [TASK CHI TIẾT - SINH VIÊN C (Security & QA)](#sinh-viên-c)
6. [Milestone & nghiệm thu](#milestone--nghiệm-thu)
7. [Phụ lục: tài liệu học theo từng chủ đề](#phụ-lục-tài-liệu-học)

---

## NGUYÊN TẮC VẬN HÀNH 14 NGÀY

### Quy ước task
Mỗi task có 4 phần cố định, đọc xong là biết phải làm gì:
- **WHAT** - làm cái gì, output cụ thể (tên file, endpoint, command).
- **HOW** - các bước cụ thể, có lệnh/snippet để bắt chước.
- **HỌC NHANH** - 1-3 link/keyword học vừa đủ làm (không học sâu).
- **DONE KHI** - tiêu chí nghiệm thu để check ✅.

### Daily rhythm
- **Sáng (15 phút):** đọc task của ngày, comment vào issue GitHub "Tôi đang làm X, kẹt sẽ ping".
- **Cuối ngày (15 phút):** push code dù chưa xong (branch `feat/<member>-<topic>`), update progress vào file `PROGRESS.md`.
- **Kẹt > 2h:** ping nhóm ngay, không tự bơi đến tối.

### Git workflow tối giản
- `main` luôn chạy được → ai push thẳng `main` bị **phạt cà phê** 😄.
- Branch: `feat/A-keycloak-setup`, `feat/B-vault-client`, `fix/C-test-jwt`…
- PR tối thiểu 1 reviewer khác role review (A review code B, B review C…).
- Commit message: `[A] add keycloak realm config` (prefix theo role).

### Khi đụng task lạ
1. Đọc HỌC NHANH (max 30 phút).
2. Copy snippet trong task này, chạy được rồi mới sửa.
3. Vẫn không chạy → ping nhóm + paste error.

---

## BẢN ĐỒ TỔNG THỂ 14 NGÀY

| Ngày | A (Auth & Crypto) | B (Gateway & Infra) | C (Security & QA) | Milestone |
|------|-------------------|---------------------|-------------------|-----------|
| D1 | Học OAuth2/JWT + chạy Keycloak | Khung repo + docker-compose skeleton | Học HMAC + viết spec ký | 🟢 Hạ tầng thô lên |
| D2 | Cấu hình realm `nt219` + lấy token đầu tiên | FastAPI skeleton 4 endpoints | Hoàn thiện HMAC spec + 10 kịch bản tấn công | |
| D3 | `jwt_verifier.py` (ES256 + JWKS cache) | Auth middleware nối với verifier của A | `test_jwt_attacks.py` (pytest) | |
| D4 | PKCE demo + bật ES256/HS256 trên Keycloak | `hmac_verifier.py` + Redis nonce | `test_hmac_attacks.py` | |
| D5 | **🔥 Integration day** - cả 3 ngồi ráp end-to-end | **🔥** | **🔥** Chạy toàn bộ test, fix bug | 🟢 **v0.1 - JWT+HMAC chạy được** |
| D6 | Token revocation (jti blacklist Redis) | Vault dev mode + `vault_client.py` | Prometheus + Grafana dashboard | |
| D7 | Key rotation script + grace period 1h | Rate limit slowapi + structlog JSON | OpenTelemetry + Jaeger | |
| D8 | Báo cáo crypto-analysis (500 từ) | K8s manifests + Minikube deploy | Chạy SEC-01→09, viết test results | 🟢 **v0.2 - KMS + Observability** |
| D9 | Mục 3 + Mục 8 báo cáo | GitHub Actions CI | OWASP ZAP active scan | |
| D10 | wrk benchmark JWT 3 thuật toán | Vault overhead benchmark | Locust 200 users + wrk LUA 4 scenarios | 🟢 **v0.3 - K8s + CI xanh** |
| D11 | Phân tích số liệu benchmark, viết Mục 8 | `deployment-runbook.md` | STRIDE matrix + tổng hợp biểu đồ | |
| D12 | Hardening checklist 15 điểm | Tag `v1.0.0` + cleanup repo | Quay demo video 8-10 phút | |
| D13 | Code review final pass | Mục 4 + 5 báo cáo | Mục 6, 7, 9, 10 + references | |
| D14 | **🔥 Final dry-run + buffer fix** | **🔥** | **🔥** Nộp `final_report.pdf` | 🟢 **NỘP** |

> **Quy tắc cứu hộ:** Nếu đến D10 chưa xong v0.2 (KMS) → bỏ ngay K8s (chỉ giữ Docker Compose) và Locust 200 users (chỉ giữ wrk).

---

# SINH VIÊN A
## Vai trò: Identity & Token Engineer
## Trọng tâm: Keycloak · JWT · OAuth2 · Key Rotation · Báo cáo crypto

---

### 🅰️ A-D1: Học nền tảng + Chạy Keycloak (4-5h)

**WHAT**
- Hiểu OAuth2, JWT, OpenID Connect ở mức biết phân biệt `access_token` vs `id_token`.
- Có Keycloak chạy được trên máy bạn qua Docker (chưa cấu hình realm).

**HOW**
1. Học (90 phút):
   - Xem video: "OAuth 2.0 explained" của OktaDev (15p).
   - Đọc lướt RFC 6749 - chỉ cần Section 1, 4.1 (Authorization Code), 4.4 (Client Credentials).
   - Đọc lướt RFC 7519 - JWT structure (header.payload.signature).
   - Trả lời được 3 câu trên giấy: (1) JWT có mấy phần ngăn cách bằng dấu gì? (2) `access_token` dùng để làm gì khác `id_token`? (3) PKCE giải quyết vấn đề gì so với Authorization Code thường?
2. Chạy Keycloak:
   ```bash
   docker run -d --name keycloak \
     -p 8080:8080 \
     -e KEYCLOAK_ADMIN=admin \
     -e KEYCLOAK_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:24.0 start-dev
   ```
3. Vào http://localhost:8080 → login admin/admin → screenshot màn hình Master realm.
4. Tạo file `docs/keycloak-setup.md`, viết 3 dòng đầu: lệnh chạy + URL admin + ảnh chụp.

**HỌC NHANH**
- `oauth.com/playground` - bấm thử từng flow để hiểu.
- Keycloak docs: "Getting Started with Docker".

**DONE KHI**
- ✅ `docker ps` thấy keycloak chạy.
- ✅ Vào được admin console.
- ✅ `docs/keycloak-setup.md` có lệnh + screenshot.
- ✅ Tự trả lời được 3 câu hỏi ở bước HOW.1.

**Sau task này có:** Keycloak chạy local + bạn biết JWT/OAuth2 nói gì.

---

### 🅰️ A-D2: Cấu hình Realm `nt219` + Lấy token đầu tiên (4-5h)

**WHAT**
- Realm `nt219` có: 2 client (`web-app` PKCE + `service-account` Client Credentials), 1 user `testuser`, 2 role (`user`, `admin`).
- Lấy được token thật qua `curl` và decode được nội dung.

**HOW**
1. Admin console → tạo realm tên `nt219`.
2. Tạo client `web-app`:
   - Client type: OpenID Connect
   - Authentication flow: chỉ tick **Standard flow** (Authorization Code)
   - Client authentication: **Off** (public client cho PKCE)
   - Valid redirect URIs: `http://localhost:3000/*`
   - Settings → Advanced → **Proof Key for Code Exchange Code Challenge Method = S256**.
3. Tạo client `service-account`:
   - Client authentication: **On** (confidential)
   - Authentication flow: chỉ tick **Service accounts roles**
   - Vào tab **Credentials** copy `Client secret` (lưu vào file ghi chú riêng, **không commit**).
4. Tạo 2 role ở **Realm roles**: `user`, `admin`.
5. Tạo user `testuser`:
   - Users → Add user → username `testuser`
   - Credentials → set password `Test@123` (uncheck Temporary)
   - Role mapping → assign `user`.
6. Lấy token bằng curl (client credentials):
   ```bash
   curl -X POST http://localhost:8080/realms/nt219/protocol/openid-connect/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials" \
     -d "client_id=service-account" \
     -d "client_secret=<paste-secret>"
   ```
7. Copy `access_token` trả về, paste vào https://jwt.io → screenshot phần payload (thấy `iss`, `exp`, `aud`).
8. Viết tiếp `docs/keycloak-setup.md`: hướng dẫn step-by-step + screenshot từng bước (5-7 ảnh) + đoạn curl + payload decode.

**HỌC NHANH**
- Keycloak: "Securing Applications and Services Guide" - chỉ đọc phần "OIDC Clients".

**DONE KHI**
- ✅ `curl` trả về JSON có `access_token` không lỗi.
- ✅ Token decode trên jwt.io có `iss=http://localhost:8080/realms/nt219`.
- ✅ `docs/keycloak-setup.md` đầy đủ để **B copy theo cũng làm được** (test bằng cách bảo B làm thử).
- ✅ Push branch `feat/A-keycloak-setup`, mở PR.

**Sau task này có:** IdP thật, token thật, doc cho cả nhóm xài lại.

---

### 🅰️ A-D3: Viết `jwt_verifier.py` (5-6h)

**WHAT**
- Module Python xác thực JWT ES256, tự fetch JWKS từ Keycloak, cache 5 phút.
- Hàm `verify_token(token: str) -> dict` trả payload nếu hợp lệ, raise exception nếu không.

**HOW**
1. Cài thư viện: `pip install python-jose[cryptography] cachetools httpx`.
2. Tạo file `gateway/crypto/jwt_verifier.py` với khung này:
   ```python
   import httpx
   from cachetools import TTLCache
   from jose import jwt, JWTError

   JWKS_URL = "http://keycloak:8080/realms/nt219/protocol/openid-connect/certs"
   ISSUER = "http://keycloak:8080/realms/nt219"
   AUDIENCE = "account"  # hoặc client_id tùy cấu hình
   _jwks_cache = TTLCache(maxsize=1, ttl=300)  # 5 phút

   def _get_jwks() -> dict:
       if "jwks" in _jwks_cache:
           return _jwks_cache["jwks"]
       resp = httpx.get(JWKS_URL, timeout=5.0)
       resp.raise_for_status()
       jwks = resp.json()
       _jwks_cache["jwks"] = jwks
       return jwks

   class TokenInvalid(Exception): ...

   def verify_token(token: str) -> dict:
       try:
           unverified_header = jwt.get_unverified_header(token)
           kid = unverified_header["kid"]
           alg = unverified_header["alg"]
           if alg not in ("ES256", "HS256"):
               raise TokenInvalid(f"alg {alg} not allowed")
           jwks = _get_jwks()
           key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
           if not key:
               raise TokenInvalid("kid not found in JWKS")
           payload = jwt.decode(
               token, key, algorithms=[alg],
               issuer=ISSUER, audience=AUDIENCE,
               options={"require": ["exp", "iat", "iss", "aud"]},
           )
           return payload
       except JWTError as e:
           raise TokenInvalid(str(e))
   ```
3. Viết file `tests/test_jwt_verifier.py` với 3 test:
   - Token hợp lệ → trả payload có `sub`.
   - Token sai chữ ký (sửa 1 ký tự ở chữ ký) → raise `TokenInvalid`.
   - Token hết hạn (lấy token cũ chờ qua `exp`) → raise `TokenInvalid`.
4. Chạy `pytest tests/test_jwt_verifier.py -v`, đảm bảo 3 pass.

**HỌC NHANH**
- `python-jose` docs: phần "Verifying a Token".
- Tìm "JWKS" trên Google học khái niệm 10 phút.

**DONE KHI**
- ✅ 3 unit test pass.
- ✅ B có thể `from gateway.crypto.jwt_verifier import verify_token` dùng được.
- ✅ Push PR có description nói rõ: "Cung cấp hàm `verify_token(token)` cho B nhúng vào middleware ở D3-D4".

**Sau task này có:** Module xác thực JWT dùng được cho cả nhóm.

---

### 🅰️ A-D4: PKCE demo + Bật ES256/HS256 song song trên Keycloak (4h)

**WHAT**
- Script `clients/pkce_flow.py` mô phỏng full PKCE flow (sinh verifier → challenge → đổi token).
- Realm `nt219` mặc định ký bằng **ES256**, có realm phụ `nt219-hs256` ký bằng HS256 để C đo benchmark sau.

**HOW**
1. PKCE script:
   ```python
   # clients/pkce_flow.py
   import secrets, hashlib, base64, urllib.parse, webbrowser, httpx

   verifier = secrets.token_urlsafe(64)
   challenge = base64.urlsafe_b64encode(
       hashlib.sha256(verifier.encode()).digest()
   ).rstrip(b"=").decode()

   auth_url = (
       "http://localhost:8080/realms/nt219/protocol/openid-connect/auth?"
       + urllib.parse.urlencode({
           "client_id": "web-app",
           "response_type": "code",
           "redirect_uri": "http://localhost:3000/callback",
           "code_challenge": challenge,
           "code_challenge_method": "S256",
           "scope": "openid",
       })
   )
   print("Open this URL:", auth_url)
   webbrowser.open(auth_url)
   code = input("Paste 'code' from redirect URL: ").strip()

   token_resp = httpx.post(
       "http://localhost:8080/realms/nt219/protocol/openid-connect/token",
       data={
           "grant_type": "authorization_code",
           "client_id": "web-app",
           "code": code,
           "redirect_uri": "http://localhost:3000/callback",
           "code_verifier": verifier,
       },
   )
   print(token_resp.json())
   ```
2. Đổi thuật toán ký Keycloak sang **ES256**:
   - Realm settings → Keys → tab Providers → Add `ecdsa-generated` → priority cao nhất.
   - Tab Keys → đảm bảo có key Active loại ES256.
   - Xóa hoặc giảm priority key RS256 mặc định.
3. Tạo realm phụ `nt219-hs256`:
   - Import lại config tương tự `nt219` (export realm → sửa tên → import).
   - Realm settings → Tokens → Default Signature Algorithm = `HS256`.
4. Export 2 realm ra JSON:
   ```bash
   docker exec keycloak /opt/keycloak/bin/kc.sh export \
     --dir /tmp/export --realm nt219
   docker cp keycloak:/tmp/export ./idp-config/
   ```
   → commit `idp-config/nt219-realm.json` và `idp-config/nt219-hs256-realm.json`.

**HỌC NHANH**
- "PKCE in plain English" trên auth0.com blog.

**DONE KHI**
- ✅ Chạy `python clients/pkce_flow.py` ra JSON có `access_token` không lỗi.
- ✅ Token mới decode thấy `"alg": "ES256"`.
- ✅ 2 file JSON export commit vào `idp-config/`.

**Sau task này có:** Bạn hiểu PKCE flow ở mức demo được; realm sẵn sàng cho benchmark sau.

---

### 🅰️ A-D5: 🔥 Integration day - làm cùng B & C (full day)

**WHAT**
- Ngồi cùng B & C (offline hoặc voice call cả ngày).
- Cuối ngày: gọi được `GET /api/protected` với Bearer token thật, trả 200; sai token trả 401. HMAC endpoint ký đúng trả 200, replay trả 401.

**HOW**
- Pair với B: chạy thử middleware của B, A cấp token, B nhúng `verify_token`, debug lỗi `aud`, `iss`, CORS.
- Pair với C: chạy test suite của C, fix các token expectations.
- Khi rảnh: viết phần "Token Lifecycle" 200 từ trong `docs/crypto-analysis.md` (chuẩn bị cho D8).

**DONE KHI**
- ✅ Demo end-to-end thành công, quay screen record 1 phút làm bằng chứng.
- ✅ Tag commit `v0.1` trên `main`.

**Sau task này có:** Hệ thống chạy được phiên bản đầu tiên.

---

### 🅰️ A-D6: Token Revocation - jti blacklist (4-5h)

**WHAT**
- Endpoint `POST /auth/revoke` nhận token → đẩy `jti` vào Redis với TTL = `exp - now`.
- Auth middleware (của B) sau khi verify chữ ký phải hỏi thêm Redis xem `jti` có trong blacklist không.

**HOW**
1. Tạo `gateway/storage/revocation.py`:
   ```python
   import redis, time
   r = redis.Redis(host="redis", port=6379, decode_responses=True)
   PREFIX = "revoked_jti:"

   def revoke(jti: str, exp: int) -> None:
       ttl = max(1, exp - int(time.time()))
       r.setex(PREFIX + jti, ttl, "1")

   def is_revoked(jti: str) -> bool:
       return r.exists(PREFIX + jti) == 1
   ```
2. Thêm route `/auth/revoke` trong `gateway/main.py` (phối hợp B):
   ```python
   @app.post("/auth/revoke")
   def revoke_endpoint(payload: dict = Depends(get_verified_token)):
       revoke(payload["jti"], payload["exp"])
       return {"status": "revoked"}
   ```
3. Sửa middleware (cùng B) để gọi `is_revoked(payload["jti"])` sau verify chữ ký, raise 401 nếu true.
4. Test thủ công bằng REST Client/Postman: gọi `/api/protected` → 200; gọi `/auth/revoke` cùng token → 200; gọi lại `/api/protected` → 401.

**HỌC NHANH**
- Redis `SETEX` command (1 phút).
- JWT claim `jti` là gì (1 phút - Google).

**DONE KHI**
- ✅ Test thủ công 3 bước ở trên đúng.
- ✅ TTL trong Redis check bằng `redis-cli TTL revoked_jti:<jti>` ra số dương hợp lý.

**Sau task này có:** Cơ chế revoke token tức thời mà không cần thêm cuộc gọi tới Keycloak.

---

### 🅰️ A-D7: Key Rotation Script + Grace Period (4-5h)

**WHAT**
- Script bash gọi Keycloak Admin API tạo key mới (kid=v2), giữ key cũ (kid=v1) active **1 tiếng**, rồi disable v1.
- Demo: token cũ vẫn xác thực được trong 1h, sau đó hết.

**HOW**
1. Lấy admin token qua `master` realm trong script:
   ```bash
   # scripts/rotate_keycloak_key.sh
   #!/usr/bin/env bash
   set -e
   KC=http://localhost:8080
   ADMIN_TOKEN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
     -d "client_id=admin-cli" -d "username=admin" -d "password=admin" \
     -d "grant_type=password" | jq -r .access_token)

   # Tạo key provider mới (ecdsa) priority 200 (cao hơn cũ)
   curl -s -X POST "$KC/admin/realms/nt219/components" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "ecdsa-v2",
       "providerId": "ecdsa-generated",
       "providerType": "org.keycloak.keys.KeyProvider",
       "config": {"priority":["200"],"enabled":["true"],"active":["true"],"ecdsaEllipticCurveKey":["P-256"]}
     }'
   echo "v2 created. Grace period 1h."
   ```
2. Viết `scripts/disable_old_key.sh` (gọi sau 1h):
   - Liệt kê key providers, tìm cái priority thấp nhất, PUT `enabled=false`.
3. Trong báo cáo crypto-analysis ghi rõ: vì JWKS endpoint vẫn trả cả 2 key, gateway cache JWKS 5 phút nên token cũ vẫn verify được - đó chính là grace period.
4. Demo: lấy token1 → chạy rotate.sh → lấy token2 → cả 2 đều decode được trong 1h.

**HỌC NHANH**
- Keycloak Admin REST API: endpoint `/admin/realms/{realm}/components`.

**DONE KHI**
- ✅ Chạy script không lỗi.
- ✅ JWKS endpoint trả về 2 keys với kid khác nhau.
- ✅ 2 token (trước và sau rotate) đều verify thành công.

**Sau task này có:** Cơ chế xoay khóa zero-downtime cho production.

---

### 🅰️ A-D8: Báo cáo phân tích mật mã `docs/crypto-analysis.md` (3-4h)

**WHAT**
- File markdown ≥ 500 từ so sánh đối xứng vs bất đối xứng theo 3 trục: **phân phối khóa**, **chi phí CPU**, **kiến trúc an toàn**.

**HOW**
1. Outline:
   - 1.1 Định nghĩa & ví dụ (HS256 vs ES256/RS256).
   - 1.2 Bài toán phân phối khóa: HMAC cần shared secret → khó scale; Asym chỉ phân phối public key → JWKS endpoint là lý do hệ thống dùng ES256 cho client-facing.
   - 1.3 Chi phí CPU: HMAC-SHA256 chỉ bitwise + 64 vòng → cực nhanh; ECDSA cần modular exponentiation trên curve → chậm hơn 10-50x (kèm số liệu sẽ điền từ benchmark D10).
   - 1.4 Kiến trúc: HS256 dùng cho service-to-service nội bộ (ít client, đã trust nhau, ưu tiên tốc độ); ES256 dùng cho mọi thứ public-facing.
   - 1.5 Kết luận: vì sao gateway này dùng **ES256 production + HS256 chỉ để benchmark đối chứng**.
2. Mỗi mục viết 100-150 từ, có ít nhất 2 nguồn (RFC 7518, NIST SP 800-57).

**DONE KHI**
- ✅ Word count ≥ 500.
- ✅ Có bảng so sánh 3 thuật toán.
- ✅ Có ít nhất 3 reference đúng định dạng (RFC/NIST/textbook).

**Sau task này có:** 1 section báo cáo gần như xong, không phải vá ở phút 90.

---

### 🅰️ A-D9 → D14: Benchmark + Báo cáo

| Ngày | Việc | Output |
|------|------|--------|
| D9 | Viết Mục 3 (Cơ sở lý thuyết mật mã) trong báo cáo - dùng nội dung từ `crypto-analysis.md` mở rộng | `final_report.md` Mục 3 |
| D10 | Chạy wrk benchmark: 4 threads, 100 connections, 60s, **lặp 3 lần** cho HS256/ES256/RS256. Xuất CSV. | `benchmarks/results/jwt_algo_comparison.csv` |
| D11 | Phân tích số liệu: viết Mục 8 báo cáo + đồ thị (matplotlib hoặc Excel) giải thích vì sao HS256 nhanh hơn | Biểu đồ + 400 từ phân tích |
| D12 | `docs/security-checklist.md` - 15 mục Hardening (ví dụ bên dưới) | File checklist |
| D13 | Code review final pass: đọc mọi PR đã merge tìm `print(token)`, secret hardcode, debug=True | Issue list nếu có |
| D14 | Buffer + nộp | - |

**Gợi ý 15 hardening items cho D12:**
1. `Authorization` header bị strip ra khỏi log.
2. Không log `access_token`, `refresh_token`, secret.
3. `debug=False` trên FastAPI production.
4. CORS whitelist cụ thể, không `*`.
5. TLS terminate ở reverse proxy (mention trong runbook).
6. `alg` whitelist trong verifier (đã làm).
7. Required claims check: `exp, iat, iss, aud` (đã làm).
8. Nonce TTL ≤ replay window (600s ≥ 300s OK).
9. Rate limit per-identity (B đã làm).
10. Secret rotate qua Vault không hardcode.
11. Container chạy non-root.
12. Image base = `python:3.11-slim` không `latest`.
13. Healthcheck endpoint không leak version.
14. Dependency scan (pip-audit) trong CI.
15. `requirements.txt` pin version cụ thể không `>=`.

---

# SINH VIÊN B
## Vai trò: Platform Engineer
## Trọng tâm: FastAPI Gateway · Docker · Kubernetes · Vault · CI/CD

---

### 🅱️ B-D1: Khung repo + Docker Compose skeleton (5-6h)

**WHAT**
- GitHub repo có cấu trúc thư mục chuẩn, README ban đầu, `docker-compose.yml` start được Keycloak + Redis (chưa cần gateway).

**HOW**
1. Cấu trúc thư mục - tạo bằng lệnh:
   ```bash
   mkdir -p gateway/{crypto,middleware,storage,routes} \
            services/backend \
            infra/k8s \
            idp-config vault-config \
            benchmarks/{scripts,results} \
            tests/{unit,security,results} \
            docs scripts clients
   touch gateway/__init__.py gateway/main.py \
         README.md PROGRESS.md .gitignore .env.example
   ```
2. `.gitignore`:
   ```
   __pycache__/
   *.pyc
   .env
   .venv/
   *.egg-info/
   benchmarks/results/*.txt
   ```
3. `infra/docker-compose.yml` ban đầu:
   ```yaml
   version: "3.9"
   services:
     keycloak:
       image: quay.io/keycloak/keycloak:24.0
       command: start-dev
       environment:
         KEYCLOAK_ADMIN: admin
         KEYCLOAK_ADMIN_PASSWORD: admin
       ports: ["8080:8080"]
     redis:
       image: redis:7-alpine
       ports: ["6379:6379"]
   networks:
     default:
       name: gw-net
   ```
4. Test: `cd infra && docker compose up -d && docker compose ps` → 2 service Up.
5. README ban đầu: tên đồ án, 3 thành viên, "Cách chạy: `cd infra && docker compose up -d`".
6. Push branch `init/repo-structure`, merge thẳng `main` (chỉ lần này).

**HỌC NHANH**
- Docker Compose: "Networking in Compose" - hiểu service name = hostname.
- 1 video 10p "Docker for Python developers".

**DONE KHI**
- ✅ Cấu trúc thư mục có đủ trên GitHub.
- ✅ `docker compose ps` thấy keycloak + redis Up.
- ✅ A truy cập được `http://localhost:8080` để làm A-D1.

**Sau task này có:** Repo có cấu trúc để mọi người commit vào đúng chỗ; hạ tầng Keycloak/Redis lên ngay.

---

### 🅱️ B-D2: FastAPI Skeleton 4 endpoints (5-6h)

**WHAT**
- `gateway/main.py` chạy được, có 4 endpoint trả JSON. Đóng gói Dockerfile và thêm vào compose.

**HOW**
1. `gateway/requirements.txt`:
   ```
   fastapi==0.110.0
   uvicorn[standard]==0.29.0
   httpx==0.27.0
   redis==5.0.3
   python-jose[cryptography]==3.3.0
   cachetools==5.3.3
   ```
2. `gateway/main.py`:
   ```python
   from fastapi import FastAPI, Header, HTTPException

   app = FastAPI(title="Secure API Gateway")

   @app.get("/health")
   def health(): return {"status": "ok"}

   @app.get("/api/public")
   def public(): return {"message": "public, no auth"}

   @app.get("/api/protected")
   def protected(authorization: str | None = Header(None)):
       if not authorization or not authorization.startswith("Bearer "):
           raise HTTPException(401, "missing bearer")
       return {"message": "TODO: verify token", "token_preview": authorization[:30]}

   @app.get("/api/service")
   def service(): return {"message": "TODO: HMAC check"}
   ```
3. `gateway/Dockerfile`:
   ```dockerfile
   FROM python:3.11-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY . .
   CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
   ```
4. Thêm vào `infra/docker-compose.yml`:
   ```yaml
     gateway:
       build: ../gateway
       ports: ["8000:8000"]
       depends_on: [keycloak, redis]
       environment:
         KEYCLOAK_URL: http://keycloak:8080
         REDIS_URL: redis://redis:6379
   ```
5. Test bằng REST Client (VSCode) hoặc curl:
   ```
   curl http://localhost:8000/health
   curl http://localhost:8000/api/public
   curl http://localhost:8000/api/protected  # → 401
   curl -H "Authorization: Bearer abc" http://localhost:8000/api/protected  # → 200
   ```

**HỌC NHANH**
- FastAPI "First Steps" tutorial (30 phút).
- `uvicorn` reload flag để dev nhanh.

**DONE KHI**
- ✅ 4 endpoint trả đúng kỳ vọng.
- ✅ `docker compose up --build` chạy gateway thành công.
- ✅ Push PR, A và C review.

**Sau task này có:** Khung gateway sẵn cho A nhúng JWT verify, C viết test.

---

### 🅱️ B-D3: Auth Middleware nối với `jwt_verifier` của A (4-5h)

**WHAT**
- Middleware FastAPI trích Bearer token → gọi `verify_token` của A → gắn payload vào `request.state.user` → block 401 nếu sai.

**HOW**
1. Cần đợi A merge `jwt_verifier.py` trước (sync vào sáng).
2. Tạo `gateway/middleware/auth.py`:
   ```python
   from fastapi import Request, HTTPException
   from gateway.crypto.jwt_verifier import verify_token, TokenInvalid

   PROTECTED_PREFIX = "/api/protected"

   async def jwt_auth_middleware(request: Request, call_next):
       if request.url.path.startswith(PROTECTED_PREFIX):
           auth = request.headers.get("authorization", "")
           if not auth.startswith("Bearer "):
               raise HTTPException(401, "missing bearer")
           try:
               payload = verify_token(auth[7:])
           except TokenInvalid as e:
               raise HTTPException(401, f"invalid token: {e}")
           request.state.user = payload
       return await call_next(request)
   ```
3. Gắn vào `main.py`:
   ```python
   from fastapi import Request
   from gateway.middleware.auth import jwt_auth_middleware
   app.middleware("http")(jwt_auth_middleware)

   @app.get("/api/protected")
   def protected(request: Request):
       return {"user": request.state.user.get("preferred_username"),
               "roles": request.state.user.get("realm_access", {}).get("roles", [])}
   ```
4. Test với token thật A đưa: gọi `/api/protected` với Bearer → 200 có username; bỏ Bearer → 401; sửa 1 ký tự token → 401.

**DONE KHI**
- ✅ 3 case test thủ công đúng.
- ✅ Không bị crash khi A revoke key (sau 5p cache hết).

**Sau task này có:** Tầng xác thực JWT đầu tiên hoạt động.

---

### 🅱️ B-D4: HMAC Verifier + Redis Nonce (5-6h)

**WHAT**
- `gateway/crypto/hmac_verifier.py` tái dựng Canonical Request, tính HMAC-SHA256, so sánh bằng `hmac.compare_digest`. Nonce check qua Redis với TTL 600s.

**HOW**
1. Đọc spec HMAC của C ở `docs/hmac-signing-spec.md` trước. Đảm bảo nắm rõ:
   - Headers bắt buộc: `X-Timestamp`, `X-Nonce`, `X-Signature`.
   - Canonical: `METHOD\nPATH\nSORTED_QUERY\nX-Timestamp\nX-Nonce\nSHA256(BODY)`.
   - Replay window 300s.
2. `gateway/crypto/hmac_verifier.py`:
   ```python
   import hmac, hashlib, time
   from fastapi import Request, HTTPException
   import redis

   r = redis.Redis(host="redis", port=6379, decode_responses=True)
   REPLAY_WINDOW = 300
   NONCE_TTL = 600
   SECRET = b"dev-shared-secret"  # D6 sẽ thay bằng Vault

   def _canonical(method, path, query, ts, nonce, body: bytes) -> bytes:
       q = "&".join(f"{k}={v}" for k,v in sorted((query or {}).items()))
       body_hash = hashlib.sha256(body).hexdigest()
       s = f"{method}\n{path}\n{q}\n{ts}\n{nonce}\n{body_hash}"
       return s.encode()

   async def verify_hmac(request: Request):
       ts = request.headers.get("x-timestamp")
       nonce = request.headers.get("x-nonce")
       sig = request.headers.get("x-signature")
       if not (ts and nonce and sig):
           raise HTTPException(401, "missing hmac headers")
       try: ts_int = int(ts)
       except: raise HTTPException(401, "bad timestamp")
       if abs(time.time() - ts_int) > REPLAY_WINDOW:
           raise HTTPException(401, "timestamp out of window")
       if r.exists(f"nonce:{nonce}"):
           raise HTTPException(401, "replay detected")
       body = await request.body()
       expected = hmac.new(SECRET,
           _canonical(request.method, request.url.path, dict(request.query_params), ts, nonce, body),
           hashlib.sha256).hexdigest()
       if not hmac.compare_digest(expected, sig):
           raise HTTPException(401, "bad signature")
       r.setex(f"nonce:{nonce}", NONCE_TTL, "1")
   ```
3. Gắn vào `/api/service` route:
   ```python
   from gateway.crypto.hmac_verifier import verify_hmac
   @app.post("/api/service")
   async def service(request: Request):
       await verify_hmac(request)
       return {"message": "hmac ok"}
   ```
4. Viết script test thủ công `clients/hmac_call.py` cho C dùng làm test fixture (bạn viết version "đúng", C viết version "sai").

**HỌC NHANH**
- Python `hmac.compare_digest` vs `==` (chống timing attack) - 5 phút Google.
- Redis `SETEX` lệnh đơn giản.

**DONE KHI**
- ✅ Gọi đúng → 200.
- ✅ Gửi lại request y hệt → 401 (replay).
- ✅ Sửa 1 byte body → 401.

**Sau task này có:** Tầng HMAC sống động cho C đập attack.

---

### 🅱️ B-D5: 🔥 Integration day (full day, làm cùng A & C)
- Sync sáng: cả nhóm chạy `docker compose up`, xác nhận mọi service Up.
- Pair với A debug middleware audience claim.
- Pair với C khi test suite của C fail vì lý do hạ tầng.
- Cuối ngày: viết `docs/quickstart.md` 1 trang "Cách chạy hệ thống trong 5 phút" để D-D9 ta dùng làm material quay video.

**DONE KHI**
- ✅ Tag `v0.1`.

---

### 🅱️ B-D6: HashiCorp Vault + `vault_client.py` (5-6h)

**WHAT**
- Vault dev mode chạy trong compose, KV-v2 engine bật, có sẵn 2 secret (`hmac-secret`, `hs256-secret`).
- Module Python lấy secret + cache 5 phút.

**HOW**
1. Thêm vào `docker-compose.yml`:
   ```yaml
     vault:
       image: hashicorp/vault:1.15
       cap_add: [IPC_LOCK]
       environment:
         VAULT_DEV_ROOT_TOKEN_ID: dev-root-token
         VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
       ports: ["8200:8200"]
   ```
2. Sau khi up:
   ```bash
   export VAULT_ADDR=http://localhost:8200
   export VAULT_TOKEN=dev-root-token
   vault kv put secret/gateway/hmac value="prod-shared-secret-32bytes-min!!"
   vault kv put secret/gateway/hs256 value="hs256-realm-shared-secret-32b!!"
   ```
   (Nếu chưa có CLI, dùng curl với `X-Vault-Token` header.)
3. `gateway/storage/vault_client.py`:
   ```python
   import os, httpx
   from cachetools import TTLCache
   _cache = TTLCache(maxsize=32, ttl=300)
   ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
   TOKEN = os.getenv("VAULT_TOKEN", "dev-root-token")

   def get_secret(path: str) -> str:
       if path in _cache: return _cache[path]
       url = f"{ADDR}/v1/secret/data/{path}"
       resp = httpx.get(url, headers={"X-Vault-Token": TOKEN}, timeout=3.0)
       resp.raise_for_status()
       val = resp.json()["data"]["data"]["value"]
       _cache[path] = val
       return val
   ```
4. Thay `SECRET = b"dev-shared-secret"` trong `hmac_verifier.py` thành `SECRET = get_secret("gateway/hmac").encode()` (lazy load lần đầu).
5. Thêm `VAULT_ADDR`, `VAULT_TOKEN` vào env của gateway service trong compose.

**HỌC NHANH**
- Vault: "Getting Started → Dev Server" - 20 phút.
- Khái niệm KV-v2 vs KV-v1 (1 dòng: v2 có versioning).

**DONE KHI**
- ✅ `vault kv get secret/gateway/hmac` ra value.
- ✅ Gateway gọi HMAC vẫn pass sau khi đổi sang Vault.
- ✅ Tắt Vault → gateway log error rõ ràng, không crash silent.

**Sau task này có:** Không còn secret hardcode trong code; tick được hardening item #10.

---

### 🅱️ B-D7: Rate Limit + Structured Logging (4-5h)

**WHAT**
- `slowapi` giới hạn 100 req/phút per identity (user_id từ JWT hoặc IP nếu không có).
- `structlog` ghi log JSON, ẩn các field nhạy cảm.

**HOW**
1. Rate limit:
   ```python
   # gateway/main.py thêm
   from slowapi import Limiter
   from slowapi.util import get_remote_address
   from starlette.requests import Request

   def identity_key(request: Request) -> str:
       user = getattr(request.state, "user", None)
       return user.get("sub") if user else get_remote_address(request)

   limiter = Limiter(key_func=identity_key, default_limits=["100/minute"])
   app.state.limiter = limiter
   ```
2. Structlog:
   ```python
   import structlog, logging
   structlog.configure(
       processors=[
           structlog.processors.add_log_level,
           structlog.processors.TimeStamper(fmt="iso"),
           structlog.processors.JSONRenderer(),
       ],
   )
   log = structlog.get_logger()
   ```
   Mọi middleware/route đổi `print(...)` → `log.info("event_name", key=value)`. **Không log** `authorization`, `x-signature`, `password`, `secret`.
3. Test: gọi `/api/protected` 101 lần với cùng token → request thứ 101 trả 429.

**DONE KHI**
- ✅ 101 lần gọi → có request 429.
- ✅ `docker compose logs gateway` ra JSON đẹp, grep `"event_name"` được.

---

### 🅱️ B-D8: Kubernetes Manifest + Minikube Deploy (6-7h)

**WHAT**
- Minikube chạy local, các manifest deploy gateway + redis (Keycloak/Vault có thể giữ ngoài cluster cho đơn giản, mention trong runbook).

**HOW**
1. Cài Minikube: `brew install minikube` / `choco install minikube` / Linux script. Start: `minikube start --driver=docker`.
2. Build image vào registry của minikube:
   ```bash
   eval $(minikube docker-env)
   cd gateway && docker build -t gateway:v1 .
   ```
3. `infra/k8s/configmap.yaml`:
   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata: { name: gateway-config }
   data:
     KEYCLOAK_URL: "http://host.minikube.internal:8080"
     VAULT_ADDR: "http://host.minikube.internal:8200"
   ```
4. `infra/k8s/deployment.yaml`:
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata: { name: gateway }
   spec:
     replicas: 2
     selector: { matchLabels: { app: gateway } }
     template:
       metadata: { labels: { app: gateway } }
       spec:
         containers:
         - name: gateway
           image: gateway:v1
           imagePullPolicy: IfNotPresent
           ports: [{ containerPort: 8000 }]
           envFrom: [{ configMapRef: { name: gateway-config } }]
           env:
           - { name: VAULT_TOKEN, value: dev-root-token }  # production: dùng Secret
           livenessProbe:
             httpGet: { path: /health, port: 8000 }
             periodSeconds: 10
   ```
5. `infra/k8s/service.yaml` (NodePort cho dễ test):
   ```yaml
   apiVersion: v1
   kind: Service
   metadata: { name: gateway }
   spec:
     type: NodePort
     selector: { app: gateway }
     ports: [{ port: 8000, targetPort: 8000, nodePort: 30080 }]
   ```
6. `kubectl apply -f infra/k8s/`; test `curl $(minikube ip):30080/health`.
7. Demo self-healing: `kubectl delete pod -l app=gateway` → vẫn còn pod thứ 2 phục vụ, pod mới spawn lên.

**HỌC NHANH**
- Minikube Quickstart (30 phút).
- 1 video "Kubernetes Pods, Deployments, Services in 10 minutes".

**DONE KHI**
- ✅ `kubectl get pods` thấy 2 gateway Running.
- ✅ `curl $(minikube ip):30080/health` → 200.
- ✅ Delete 1 pod, vẫn nhận response.

**Sau task này có:** Demo K8s self-healing cho video; tick deliverable hạ tầng đóng gói.

---

### 🅱️ B-D9: GitHub Actions CI (3-4h)

**WHAT**
- `.github/workflows/integration-test.yml` chạy mỗi PR: lint, unit test, build image.

**HOW**
```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      redis: { image: redis:7-alpine, ports: ["6379:6379"] }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r gateway/requirements.txt
      - run: pip install pytest pytest-asyncio ruff
      - run: ruff check gateway tests
      - run: pytest tests/unit -v
      - run: docker build -t gateway:ci gateway/
```

**DONE KHI**
- ✅ Workflow xanh ít nhất 1 lần trên `main`.
- ✅ Có badge `![CI](...)` ở README.

---

### 🅱️ B-D10 → D14: Vault overhead, Runbook, Release

| Ngày | Việc | Output |
|------|------|--------|
| D10 | Benchmark: gọi `/api/protected` 1000 lần với Vault cache OFF (TTL=0) vs ON (TTL=300). Đo qua wrk hoặc Python `time.perf_counter`. | `benchmarks/results/vault_overhead.csv` |
| D11 | `docs/deployment-runbook.md`: setup từ scratch (10 bước), recovery khi xoay key lỗi (5 bước), troubleshooting (5 lỗi thường gặp). | File runbook |
| D12 | Cleanup repo: xóa file `.bak`, `*.pyc`, log thừa. Tag `v1.0.0`: `git tag -a v1.0.0 -m "..." && git push --tags`. README chuẩn (badge, install, demo gif). | Tag v1.0.0 |
| D13 | Mục 4 (Kiến trúc tổng quan) + Mục 5 (Triển khai) báo cáo - bạn đã có sẵn diagram từ runbook. | 2 section báo cáo |
| D14 | Buffer, fix bug found | - |

---

# SINH VIÊN C
## Vai trò: Security Engineer & Tech Writer
## Trọng tâm: HMAC spec · Security tests · Monitoring · Benchmark · Báo cáo

---

### 🅲 C-D1: Học HMAC + Draft `hmac-signing-spec.md` (5-6h)

**WHAT**
- Hiểu HMAC, AWS SigV4 ở mức nắm canonical request là gì.
- File `docs/hmac-signing-spec.md` v0 (sẽ hoàn thiện D2).

**HOW**
1. Học (90p):
   - Xem video "AWS Signature Version 4 explained" 15p.
   - Đọc HMAC trên Wikipedia: chỉ cần hiểu HMAC(key, message) = hash(key XOR opad || hash(key XOR ipad || message)).
   - Trả lời được: tại sao HMAC chống được length-extension attack mà raw `SHA256(secret||msg)` thì không?
2. Viết `docs/hmac-signing-spec.md`:
   ```markdown
   # HMAC Request Signing Spec

   ## 1. Headers bắt buộc
   | Header | Mô tả | Format |
   |---|---|---|
   | X-Timestamp | Unix epoch (giây) tại thời điểm ký | "1735689600" |
   | X-Nonce | UUID v4 random, dùng 1 lần | "550e8400-e29b-41d4-a716-446655440000" |
   | X-Signature | HMAC-SHA256(secret, canonical) dạng hex thường | "9f86d081..." |

   ## 2. Canonical Request
   Format (newline = LF):
   <METHOD>\n<PATH>\n<SORTED_QUERY>\n<X-Timestamp>\n<X-Nonce>\n<SHA256_HEX(BODY)>
   - METHOD: GET/POST/... viết hoa
   - PATH: từ URL, có leading slash
   - SORTED_QUERY: "k1=v1&k2=v2" theo alphabet key, body empty → ""
   - BODY: bytes, nếu empty → SHA256 của chuỗi rỗng = "e3b0c4..."

   ## 3. Cửa sổ replay
   - Server reject nếu |now - X-Timestamp| > 300s.
   - Server reject nếu X-Nonce đã thấy trong 600s gần nhất.

   ## 4. Pseudocode ký phía client
   canonical = f"{method}\n{path}\n{sorted_q}\n{ts}\n{nonce}\n{sha256(body)}"
   sig = hmac_sha256(secret, canonical).hex()
   ```

**HỌC NHANH**
- AWS docs: "Create a signed AWS API request" (lướt phần Canonical Request).

**DONE KHI**
- ✅ Spec đủ để B đọc và implement được mà không hỏi lại bạn (test bằng cách hỏi B sau D2).

---

### 🅲 C-D2: Hoàn thiện spec + 10 kịch bản tấn công (4-5h)

**WHAT**
- `docs/hmac-signing-spec.md` thêm: ví dụ canonical concrete (1 GET, 1 POST có body) + signature đáp án.
- `tests/security_test_plan.md` liệt kê 10 kịch bản từ SEC-01 đến SEC-10.

**HOW**
1. Ví dụ cụ thể trong spec - dùng để A/B test:
   ```
   Request: POST /api/service?type=read
   Body: {"id":1}
   X-Timestamp: 1735689600
   X-Nonce: 550e8400-e29b-41d4-a716-446655440000
   Secret: "dev-shared-secret"

   Canonical:
   POST
   /api/service
   type=read
   1735689600
   550e8400-e29b-41d4-a716-446655440000
   <sha256 hex của body>

   Expected signature: <bạn tự tính bằng Python rồi paste>
   ```
2. `tests/security_test_plan.md`:
   | ID | Tên | Vector | Expected |
   |----|-----|--------|----------|
   | SEC-01 | JWT forgery | Token tự ký bằng key khác | 401 |
   | SEC-02 | alg=none downgrade | Header `alg:none` + no signature | 401 |
   | SEC-03 | Weak HS256 key brute force | Test key 8 byte | Demo crack bằng `jwtcrack` |
   | SEC-04 | Token expired | `exp` quá khứ | 401 |
   | SEC-05 | Wrong audience | `aud` sai | 401 |
   | SEC-06 | Wrong issuer | `iss` sai | 401 |
   | SEC-07 | HMAC replay | Gửi 2 lần request hợp lệ | Lần 2 → 401 |
   | SEC-08 | HMAC timestamp out of window | Timestamp -1000s | 401 |
   | SEC-09 | HMAC body tampering | Sửa body, giữ signature | 401 |
   | SEC-10 | Revoked JWT (jti blacklist) | Revoke rồi gọi lại | 401 |

**DONE KHI**
- ✅ Spec có 1 ví dụ concrete có signature đúng (B verify bằng cách tính tay).
- ✅ Bảng 10 kịch bản đầy đủ.

---

### 🅲 C-D3: Pytest cho JWT attacks (5h)

**WHAT**
- `tests/security/test_jwt_attacks.py` cover SEC-01, 02, 04, 05, 06 - chạy `pytest` xanh.

**HOW**
1. Đợi A merge `jwt_verifier.py` (xin token thật từ A).
2. Cài `pip install pytest pytest-asyncio PyJWT` (PyJWT để tự ký token sai cho test).
3. Mẫu:
   ```python
   # tests/security/test_jwt_attacks.py
   import jwt, time, pytest
   from fastapi.testclient import TestClient
   from gateway.main import app
   client = TestClient(app)

   def test_sec01_forgery():
       fake = jwt.encode({"sub":"x","exp":time.time()+60}, "attacker-key", algorithm="HS256")
       r = client.get("/api/protected", headers={"Authorization": f"Bearer {fake}"})
       assert r.status_code == 401

   def test_sec02_alg_none():
       # encode với alg=none
       fake = jwt.encode({"sub":"x"}, "", algorithm="none")
       r = client.get("/api/protected", headers={"Authorization": f"Bearer {fake}"})
       assert r.status_code == 401

   def test_sec04_expired(real_expired_token):
       r = client.get("/api/protected", headers={"Authorization": f"Bearer {real_expired_token}"})
       assert r.status_code == 401
   # ... viết tiếp SEC-05, 06
   ```
4. Cho `real_expired_token`: viết fixture lấy token thật rồi sleep cho hết hạn (set Keycloak token lifetime = 30s cho dev).
5. Chạy `pytest tests/security -v`.

**DONE KHI**
- ✅ 5 test pass, mỗi test có comment "SEC-XX: <name>".

---

### 🅲 C-D4: Pytest cho HMAC attacks (5h)

**WHAT**
- `tests/security/test_hmac_attacks.py` cover SEC-07, 08, 09.

**HOW**
1. Viết helper sign đúng:
   ```python
   import hmac, hashlib, uuid, time
   def sign(method, path, body=b"", ts=None, nonce=None, secret=b"dev-shared-secret"):
       ts = ts or int(time.time())
       nonce = nonce or str(uuid.uuid4())
       canonical = f"{method}\n{path}\n\n{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}"
       sig = hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()
       return {"X-Timestamp": str(ts), "X-Nonce": nonce, "X-Signature": sig}
   ```
2. Test:
   ```python
   def test_sec07_replay():
       h = sign("POST", "/api/service")
       r1 = client.post("/api/service", headers=h)
       r2 = client.post("/api/service", headers=h)  # same nonce
       assert r1.status_code == 200
       assert r2.status_code == 401

   def test_sec08_old_timestamp():
       h = sign("POST", "/api/service", ts=int(time.time())-1000)
       assert client.post("/api/service", headers=h).status_code == 401

   def test_sec09_body_tamper():
       h = sign("POST", "/api/service", body=b'{"id":1}')
       # gửi body khác nhưng giữ signature cũ
       r = client.post("/api/service", headers=h, content=b'{"id":2}')
       assert r.status_code == 401
   ```

**DONE KHI**
- ✅ 3 test pass.

---

### 🅲 C-D5: 🔥 Integration day (full day)
- Chạy toàn bộ test suite của bạn → tổng hợp pass/fail.
- Pair với B/A debug môi trường.
- Bắt đầu chuẩn bị `prometheus.yml` cho D6.

**DONE KHI**
- ✅ `pytest tests/security -v` 8/8 pass (SEC-01,02,04,05,06,07,08,09).
- ✅ Tag `v0.1` cùng A & B.

---

### 🅲 C-D6: Prometheus + Grafana (5-6h)

**WHAT**
- Metric Prometheus scrape được từ gateway. Grafana có 1 dashboard với panel "Auth Failures per minute".

**HOW**
1. Trong gateway: `pip install prometheus-fastapi-instrumentator`. Thêm vào `main.py`:
   ```python
   from prometheus_fastapi_instrumentator import Instrumentator
   Instrumentator().instrument(app).expose(app)  # /metrics
   ```
2. Thêm vào compose:
   ```yaml
     prometheus:
       image: prom/prometheus:v2.51.0
       volumes:
         - ./prometheus.yml:/etc/prometheus/prometheus.yml
       ports: ["9090:9090"]
     grafana:
       image: grafana/grafana:10.4.0
       ports: ["3001:3000"]
       environment:
         GF_SECURITY_ADMIN_PASSWORD: admin
   ```
3. `infra/prometheus.yml`:
   ```yaml
   global: { scrape_interval: 5s }
   scrape_configs:
   - job_name: gateway
     static_configs: [{ targets: ["gateway:8000"] }]
   ```
4. Thêm custom metric trong gateway:
   ```python
   from prometheus_client import Counter
   AUTH_FAIL = Counter("auth_failures_total", "auth failures", ["reason"])
   # trong middleware: AUTH_FAIL.labels(reason="expired").inc()
   ```
5. Vào http://localhost:3001 (admin/admin) → Data source Prometheus URL `http://prometheus:9090` → tạo dashboard panel với query `rate(auth_failures_total[1m])*60`.
6. Export dashboard JSON → commit `infra/grafana-dashboard.json`.

**DONE KHI**
- ✅ http://localhost:9090/targets thấy gateway `UP`.
- ✅ Grafana có dashboard, gọi 5 token sai → panel nhảy số.
- ✅ Screenshot commit vào `docs/img/`.

---

### 🅲 C-D7: OpenTelemetry + Jaeger (5h)

**WHAT**
- Mỗi request gateway tạo trace, gửi sang Jaeger. Span có attribute `auth.method`, `auth.result`, `auth.user_id`, `auth.latency_ms`.

**HOW**
1. Thêm Jaeger vào compose:
   ```yaml
     jaeger:
       image: jaegertracing/all-in-one:1.55
       ports: ["16686:16686", "4318:4318"]
       environment: { COLLECTOR_OTLP_ENABLED: "true" }
   ```
2. Trong gateway:
   ```python
   from opentelemetry import trace
   from opentelemetry.sdk.resources import Resource
   from opentelemetry.sdk.trace import TracerProvider
   from opentelemetry.sdk.trace.export import BatchSpanProcessor
   from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
   from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

   resource = Resource.create({"service.name": "gateway"})
   provider = TracerProvider(resource=resource)
   provider.add_span_processor(BatchSpanProcessor(
       OTLPSpanExporter(endpoint="http://jaeger:4318/v1/traces")))
   trace.set_tracer_provider(provider)
   FastAPIInstrumentor.instrument_app(app)
   tracer = trace.get_tracer(__name__)
   ```
3. Trong middleware auth, set attribute:
   ```python
   span = trace.get_current_span()
   span.set_attribute("auth.method", "jwt")
   span.set_attribute("auth.result", "success")
   span.set_attribute("auth.user_id", payload.get("sub", ""))
   ```
4. Test: gọi 5 request → vào http://localhost:16686 → service `gateway` → thấy trace có span attributes.

**DONE KHI**
- ✅ Jaeger UI có trace.
- ✅ Span attributes hiện đủ 4 field.
- ✅ Screenshot trace commit.

---

### 🅲 C-D8: Chạy SEC tests + Báo cáo kết quả (4h)

**WHAT**
- `tests/results/security_test_results.md` ghi nhận chạy SEC-01→09: bằng chứng (response body, status code, screenshot).

**HOW**
1. Chạy `pytest tests/security -v --html=tests/results/report.html` (cần `pip install pytest-html`).
2. Cho mỗi SEC, copy 1 đoạn output, ghi:
   ```markdown
   ### SEC-07: HMAC Replay Attack
   **Vector:** Gửi request hợp lệ 2 lần với cùng X-Nonce.
   **Expected:** Lần 2 trả 401.
   **Actual:** Lần 2 trả 401 "replay detected". ✅
   **Bằng chứng:** [log snippet]
   ```
3. Tổng hợp đầu file: bảng tóm tắt 9 SEC, tỷ lệ pass.

**DONE KHI**
- ✅ 9/9 SEC pass, file `security_test_results.md` đầy đủ bằng chứng.

---

### 🅲 C-D9: OWASP ZAP Active Scan (4-5h)

**WHAT**
- Quét bằng OWASP ZAP, xuất PDF `docs/zap-report.pdf`.

**HOW**
1. Tải ZAP Desktop từ owasp.org/www-project-zap.
2. Start gateway local `localhost:8000`.
3. ZAP → Automated Scan → URL `http://localhost:8000` → check "Use Ajax spider" → Start.
4. Đợi 15-30 phút.
5. Tab Alerts xem kết quả. Tab "Report" → "Generate Report" → PDF.
6. Trong báo cáo D11, comment các finding chính (nếu có Medium/High → fix luôn cùng B).

**HỌC NHANH**
- ZAP "Getting Started Guide" 20 phút.

**DONE KHI**
- ✅ `docs/zap-report.pdf` tồn tại.
- ✅ Không có finding Critical (nếu có → fix trước D14).

---

### 🅲 C-D10: Locust + wrk benchmark scripts (5h)

**WHAT**
- 4 file wrk LUA cho 4 scenario; 1 Locust file cho 200 user simulation.

**HOW**
1. `benchmarks/scripts/wrk_es256.lua`:
   ```lua
   wrk.method = "GET"
   wrk.headers["Authorization"] = "Bearer <paste-es256-token>"
   ```
2. Tương tự `wrk_hs256.lua`, `wrk_hmac.lua` (cần body + signature precomputed), `wrk_baseline.lua` (không header).
3. `benchmarks/scripts/locustfile.py`:
   ```python
   from locust import HttpUser, task, between
   class GatewayUser(HttpUser):
       wait_time = between(0.1, 0.5)
       @task(3)
       def protected(self):
           self.client.get("/api/protected", headers={"Authorization": "Bearer ..."})
       @task(1)
       def public(self):
           self.client.get("/api/public")
   ```
4. Dry-run 30s mỗi script, đảm bảo không lỗi.

**DONE KHI**
- ✅ 4 LUA + 1 locustfile chạy được, dry-run không error.

---

### 🅲 C-D11 → D14: Báo cáo + Demo

| Ngày | Việc | Output |
|------|------|--------|
| D11 | STRIDE matrix: 6 threat × asset (Token, Secret, Channel, Identity, Log, Gateway). Mục 6, 7 báo cáo. Vẽ biểu đồ benchmark từ CSV của A & B (matplotlib hoặc Excel chart) | Báo cáo Mục 6, 7 + biểu đồ |
| D12 | Quay demo video 8-10 phút: kịch bản (1) tổng quan kiến trúc 1p, (2) auth flow + JWT verify 2p, (3) HMAC + replay protection 2p, (4) Vault rotate 1p, (5) revoke + blacklist 1p, (6) K8s self-heal 1p, (7) monitoring dashboard 1p. Upload YouTube unlisted. | Link video trong README |
| D13 | Mục 9 (Đánh giá kết quả), Mục 10 (Hạn chế & hướng phát triển), References (≥15 nguồn IEEE format) | Báo cáo hoàn chỉnh |
| D14 | Convert `final_report.md` → `final_report.pdf` (Pandoc hoặc Google Docs), kiểm tra đủ 11 mục | `docs/final_report.pdf` |

**Outline 11 mục báo cáo (chốt trong D11):**
1. Tóm tắt
2. Đặt vấn đề
3. Cơ sở lý thuyết mật mã (A)
4. Kiến trúc tổng quan (B)
5. Triển khai (B)
6. Thiết kế bảo mật & STRIDE (C)
7. Kiểm thử an ninh (C)
8. Quản lý khóa & xoay vòng (A)
9. Đánh giá hiệu năng (C)
10. Hạn chế & hướng phát triển (C)
11. Kết luận + References (tất cả)

---

## MILESTONE & NGHIỆM THU

| Mốc | Ngày | Tiêu chí | Ai kiểm |
|-----|------|----------|---------|
| 🟢 v0.1 | Hết D5 | Tag git `v0.1`; demo curl JWT pass/fail + HMAC pass/replay | Cả 3 cùng demo |
| 🟢 v0.2 | Hết D8 | Vault hoạt động; revoke chạy; Grafana dashboard có data; 9/9 SEC pass | C verify |
| 🟢 v0.3 | Hết D10 | Minikube chạy 2 replica; CI xanh; ZAP report không Critical | B + C verify |
| 🟢 NỘP | D14 | Tag `v1.0.0`; `final_report.pdf` đủ 11 mục; demo video link trong README | Cả nhóm |

---

## PHỤ LỤC: TÀI LIỆU HỌC

### OAuth2 / JWT / OIDC
- Video: "OAuth 2.0 Explained With Simple Terms" (OktaDev YouTube).
- RFC 6749 (OAuth2 - đọc Section 1, 4.1, 4.4).
- RFC 7519 (JWT structure).
- jwt.io - tool decode token.
- "OpenID Connect explained" - openid.net/connect.

### Keycloak
- Keycloak Server Admin Guide - "Configuring Realms".
- Keycloak Securing Apps Guide - "OIDC Clients".

### FastAPI
- FastAPI official tutorial - chỉ phần "First Steps", "Path Parameters", "Middleware", "Dependencies".

### Docker / Compose
- "Docker Compose Tutorial for Beginners" YouTube TechWorld with Nana.
- Docs: docs.docker.com/compose/networking.

### Kubernetes / Minikube
- "Kubernetes Tutorial for Beginners" (TechWorld with Nana, 4h - chỉ cần xem 1h đầu).
- Minikube quickstart trang chủ.

### HMAC & AWS SigV4
- "AWS Signature Version 4 Explained" YouTube.
- HMAC trên Wikipedia (đọc 5 phút).

### Vault
- Learn HashiCorp "Vault Quickstart" - 30 phút.

### Prometheus / Grafana
- "Prometheus and Grafana Tutorial" TechWorld with Nana - chỉ cần 30 phút đầu.

### OpenTelemetry / Jaeger
- "OpenTelemetry in 100 seconds" Fireship.
- otel-python docs.

### OWASP ZAP
- "Getting Started with OWASP ZAP" official video.

### Pytest
- "Pytest tutorial" Real Python.

---

## CUỐI CÙNG

3 quy tắc khi bí:
1. **Đừng ngồi 1 mình quá 2h.** Ping nhóm + paste lỗi cụ thể.
2. **Push code chưa hoàn thiện vẫn tốt hơn không push.** Branch `wip/` cho cũng được.
3. **Đọc lại task này đầu mỗi ngày.** Mỗi task đã có "DONE KHI" - check xong mới qua task tiếp.

Good luck team. Hết tuần 2 nhậu mừng.
