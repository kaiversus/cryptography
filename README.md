# Secure API Gateway with Cryptographic Enforcement

## 0. TL;DR — chạy trong 3 phút

```bash
git clone <repo> && cd cryptography
cd infra && docker compose up -d        # đợi ~30-60s cho Keycloak khởi động
docker compose ps                       # tất cả service phải Up (vault-seed Exited 0 là đúng)
curl localhost:8000/health              # -> {"status":"ok"}

# Demo tự động toàn bộ feature, in PASS/FAIL:
cd .. && python scripts/demo.py
```

Mở 3 tab để trình chiếu observability:
- **Grafana** → http://localhost:3001 (admin/admin)
- **Jaeger** → http://localhost:16686
- **Prometheus** → http://localhost:9090/targets

---

## 1. Đồ án này giải quyết vấn đề gì?

Bám theo **OWASP API Security Top 10 – 2023**, trọng tâm là:

| Mối đe doạ (OWASP API 2023) | Biện pháp trong Gateway |
|---|---|
| **API2 – Broken Authentication** ⭐ | Verify chữ ký JWT qua JWKS, chặn `alg=none`, chặn token giả/sửa, thu hồi `jti` |
| **API2 – (toàn vẹn service-to-service)** ⭐ | Ký **HMAC-SHA256** mỗi request: chống replay (nonce 1 lần) + chống tamper |
| **API4 – Unrestricted Resource Consumption** | Rate-limit theo IP (slowapi + Redis), trả `429` |
| **API8 – Security Misconfiguration** | Bí mật để trong **Vault**, tách dev/prod, không lộ debug |

> Ngoài scope (gateway không xử lý business object/phân quyền per-object): API1/3/5
> (BOLA/BFLA), API6, API7 (SSRF), API9, API10.

---

## 2. Kiến trúc

```
                         ┌────────────────────────────────────────────┐
   Client / Service ───► │              API GATEWAY (FastAPI :8000)     │
   (JWT hoặc HMAC)       │                                              │
                         │  middleware (chạy LIFO):                     │
                         │   1) jwt_auth      -> verify ES256/RS256/HS  │
                         │   2) hmac_auth     -> verify chữ ký + nonce  │
                         │   3) structured_logging (JSON)               │
                         │   + rate-limit (slowapi)                     │
                         │   + /metrics (Prometheus)                    │
                         │   + OTel traces -> Jaeger                    │
                         └───┬───────────┬───────────┬──────────┬───────┘
                             │           │           │          │
                      Keycloak:8081   Redis:6379  Vault:8200   Jaeger:16686
                      (OIDC, JWKS)   (jti blacklist  (HMAC &    (tracing)
                                      + nonce store   HS256
                                      + rate store)   secrets)
                             │
                       Prometheus:9090 ──► Grafana:3001
```

### Service & cổng (docker-compose)
| Service | Cổng | Vai trò |
|---|---|---|
| `gateway` | **8000** | API Gateway chính |
| `keycloak` | **8081**→8080 | IdP, realm `nt219`, cấp token + JWKS |
| `redis` | 6379 | jti blacklist, nonce replay store, rate-limit store |
| `vault` | 8200 | KV secret (HMAC key, HS256 secret) — dev mode |
| `vault-seed` | — | nạp secret 1 lần rồi thoát (Exited 0 = OK) |
| `prometheus` | 9090 | scrape `/metrics` |
| `jaeger` | 16686 | UI tracing (OTLP nhận ở 4318) |
| `grafana` | **3001**→3000 | dashboard |

---

## 3. Các endpoint

| Method | Path | Bảo vệ | Rate limit | Mô tả |
|---|---|---|---|---|
| GET | `/health` | — | — | health check |
| GET | `/api/public` | — | 10/phút | endpoint công khai (demo rate-limit) |
| GET | `/api/protected` | **JWT** | 5/phút | cần `Authorization: Bearer <token>` |
| POST | `/api/service` | **HMAC** | 100/phút | M2M, cần header ký HMAC |
| POST | `/auth/revoke` | JWT | — | thu hồi chính token đang gửi (đẩy `jti` vào blacklist) |
| GET | `/metrics` | — | — | số liệu Prometheus |

### Header ký HMAC (`gateway-internal/v1`)
Mỗi request tới `/api/service` cần: `X-Key-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`.
Chữ ký = `HMAC-SHA256(secret, canonical_request)` với
`signed_headers = host;x-key-id;x-nonce;x-timestamp`. Cửa sổ timestamp **300s**,
nonce sống trong Redis **600s** để chống replay. Chi tiết: [`docs/hmac-signing-spec.md`](docs/hmac-signing-spec.md).

---

## 4. Setup chi tiết

### Yêu cầu
- Docker + Docker Compose
- Python 3.11+ (chỉ cần khi chạy script demo/test ở host)

### Bật stack
```bash
cd infra
docker compose up -d
docker compose ps          # đợi keycloak + vault healthy
docker compose logs -f gateway   # xem log khi cần debug
```

### Cài deps Python ở host (để chạy demo.py / pytest)
```bash
pip install -r gateway/requirements.txt
```

### Lấy access token thật từ Keycloak (client_credentials)
```bash
curl -s -X POST \
  http://localhost:8081/realms/nt219/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=service-account \
  -d client_secret=CaXVcmwkeRNHP5lls0pTL8BPbFLD0Bo5
```
> ⚠️ Secret/token ở repo (`dev-root-token`, `dev-shared-secret`, client secret trên)
> là **artifact dev-mode**, chỉ dùng local. Production phải lấy từ Vault thật + biến môi trường.

---

## 5. Demo cho team & thầy

Có 2 cách — chi tiết đầy đủ trong [`docs/demo-runbook.md`](docs/demo-runbook.md).

### Cách A — tự động (khuyến nghị khi present)
```bash
python scripts/demo.py
```
Script tự lấy token rồi diễn **7 cảnh**, in `[PASS]/[FAIL]` + bảng tổng kết:

| Cảnh | Nội dung | Kỳ vọng |
|---|---|---|
| 0 | Pre-flight `/health` | 200 |
| 1 | JWT hợp lệ → `/api/protected` | 200 |
| 2 | Tấn công JWT: no-bearer, forge (SEC-01), `alg=none` (SEC-02), tamper | 401 hết |
| 3 | HMAC: hợp lệ → replay → tamper body → timestamp cũ | 200 rồi 401×3 |
| 4 | Revoke token rồi gọi lại (SEC-10) | 200 → 401 |
| 5 | Rate-limit `/api/public` 12 lần | xuất hiện 429 |
| 6 | Observability: bơm fail + check `/metrics` | metric có |

### Cách B — gõ tay từng cảnh (khi thầy muốn xem chi tiết)
Xem [`docs/demo-runbook.md`](docs/demo-runbook.md) — mỗi cảnh có lệnh `curl` + output kỳ vọng.

### Bằng chứng chạy offline (không cần stack)
```bash
pytest tests/security -v                          # bộ test tấn công SEC-01..10
python -m tests.security.sec03_weak_hs256_demo    # SEC-03: brute-force HS256 yếu
python clients/test_hmac.py                        # demo ký/replay/tamper HMAC
```

> 💡 Demo lại trong vòng 1 phút có thể dính rate-limit của lần trước → **đợi ~60s**.

---

## 6. Bộ kiểm thử bảo mật (SEC-01 → SEC-10)

| ID | Tấn công | Phòng thủ |
|---|---|---|
| SEC-01 | Token giả ký bằng key lạ | verify chữ ký qua JWKS |
| SEC-02 | `alg=none` downgrade | whitelist thuật toán |
| SEC-03 | Brute-force HS256 secret yếu | bắt buộc secret ≥32 byte, ưu tiên ES256 |
| SEC-04 | Token hết hạn | kiểm `exp` |
| SEC-05 | Sai `iss`/`aud` | kiểm claim |
| SEC-06 | Token thiếu claim bắt buộc | validate schema |
| SEC-07 | **Replay** request HMAC | nonce 1-lần (Redis TTL 600s) |
| SEC-08 | Timestamp ngoài cửa sổ | window 300s |
| SEC-09 | **Tamper** body giữ chữ ký cũ | hash body vào canonical request |
| SEC-10 | Dùng token đã thu hồi | `jti` blacklist trong Redis |

Kế hoạch & kết quả: [`tests/security_test_plan.md`](tests/security_test_plan.md),
[`tests/results/`](tests/results/). Quét DAST: [`docs/zap-scan-guide.md`](docs/zap-scan-guide.md).

---

## 7. Cấu trúc thư mục

```
gateway/            # ứng dụng FastAPI
  crypto/           #   jwt_verifier.py, hmac_verifier.py
  middleware/       #   auth.py (JWT), hmac_auth.py, rate_limit.py
  storage/          #   revocation.py (jti), vault_client.py
  observability/    #   logger.py, metrics.py, tracing.py
  routes/           #   auth.py (/auth/revoke)
infra/              # docker-compose, prometheus, grafana provisioning
idp-config/         # realm export Keycloak (ES256 + HS256)
clients/            # pkce_flow.py, test_hmac.py
tests/              # pytest: test_*, security/ (SEC-01..10)
benchmarks/         # wrk lua scripts, locustfile, vẽ biểu đồ
scripts/            # demo.py, zap_scan.sh, rotate_keycloak_key.sh
k8s/                # manifest Kubernetes (Minikube)
docs/               # spec, báo cáo, runbook, hướng dẫn
require/            # đề bài + kế hoạch 2 tuần (nguồn chân lý)
```

---

## 8. Phân công nhóm

| | Thành viên | Vai trò | Phụ trách |
|---|---|---|---|
| **A** | **Nguyễn Viết Đăng** | *Identity & Token Engineer* (Auth & Crypto) | Keycloak realm `nt219`, `jwt_verifier.py` (ES256/RS256/HS256), PKCE + client_credentials, token revocation (`jti`), key rotation, `docs/crypto-analysis.md` |
| **B** | **Ngô Quang Đạt** | *Platform Engineer* (Gateway & Infra) | Khung FastAPI + 4 endpoint, Docker Compose, auth middleware nối verifier của A, `hmac_verifier.py` + Redis nonce, Vault (`vault_client.py`), rate-limit + structured log, K8s, CI |
| **C** | **Đinh Thiên Bảo** *(nhóm trưởng)* | *Security Engineer & Tech Writer* (Security & QA) | Spec HMAC, 10 kịch bản tấn công + pytest SEC-01..10, Prometheus/Grafana, OpenTelemetry/Jaeger, OWASP ZAP, benchmark (wrk/Locust) + biểu đồ, STRIDE matrix, báo cáo & demo |

> Lịch chi tiết 14 ngày theo từng người: [`require/ke_hoach_2_tuan.md`](require/ke_hoach_2_tuan.md).
> Tiến độ: [`PROGRESS.md`](PROGRESS.md).

---

## 9. Tài liệu tham khảo trong repo

- [`docs/final_report.md`](docs/final_report.md) — báo cáo tổng
- [`docs/report-C-sections.md`](docs/report-C-sections.md) — Mục bảo mật + STRIDE + references
- [`docs/hmac-signing-spec.md`](docs/hmac-signing-spec.md) — đặc tả ký HMAC
- [`docs/crypto-analysis.md`](docs/crypto-analysis.md) — phân tích thuật toán
- [`docs/keycloak-setup.md`](docs/keycloak-setup.md) — cấu hình IdP
- [`docs/demo-runbook.md`](docs/demo-runbook.md) — kịch bản demo trực tiếp
- [`docs/zap-scan-guide.md`](docs/zap-scan-guide.md) — quét DAST

---

## 10. Phòng sự cố nhanh

| Triệu chứng | Xử lý |
|---|---|
| `/health` không phản hồi | `docker compose ps`; `docker compose logs gateway` |
| `/api/protected` trả 401 dù token đúng | token hết hạn → lấy lại; hoặc HS256 secret lệch |
| HMAC 401 `unknown_key` | `vault-seed` chưa chạy xong → `docker compose up -d vault-seed` |
| Cảnh rate-limit ra 429 ngay từ đầu | lần demo trước chưa reset → đợi 60s |
| Keycloak chưa lên | đợi thêm 30-60s, xem `docker compose logs keycloak` |
