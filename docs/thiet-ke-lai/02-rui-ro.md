# Module 2 — Rủi ro (Threat Modeling)

> Ngữ cảnh (Module 1) cho biết "có gì để mất, ranh giới ở đâu". Module này trả lời:
> "nó hỏng KIỂU GÌ, và lo cái nào TRƯỚC". Đầu ra: một bảng các mối đe dọa (threat
> register) có xếp hạng — chính là gốc đẻ ra bộ test SEC-01..10.

## Công cụ 1 — STRIDE: 6 câu hỏi để moi hết mọi kiểu tấn công

Với MỖI ranh giới / asset / luồng dữ liệu, hỏi đủ 6 câu. STRIDE đảm bảo không bỏ sót.

| Chữ | Mối đe dọa | Câu hỏi | Phá vỡ thuộc tính | Đối phó bằng |
|---|---|---|---|---|
| **S** | Spoofing (giả mạo danh tính) | "Có kẻ giả làm người/service khác được không?" | Authenticity | Xác thực (chữ ký, token) |
| **T** | Tampering (sửa đổi) | "Có sửa được dữ liệu/message giữa đường không?" | Integrity | Hash, ký HMAC/JWT |
| **R** | Repudiation (chối bỏ) | "Có chối là 'tôi không làm' mà ta không chứng minh được không?" | Non-repudiation | Log, chữ ký |
| **I** | Information disclosure (lộ tin) | "Có đọc trộm được dữ liệu nhạy cảm không?" | Confidentiality | Mã hóa (TLS), redact log |
| **D** | Denial of Service (từ chối dịch vụ) | "Có làm hệ thống sập/quá tải không?" | Availability | Rate-limit, dư thừa |
| **E** | Elevation of privilege (leo thang quyền) | "Có giành được quyền cao hơn mức cho phép không?" | Authorization | Kiểm scope/quyền |

Mẹo nhớ: 6 chữ STRIDE ↔ 6 thuộc tính bảo mật ↔ 6 nhóm mục tiêu (Module 3). Một chuỗi.

## Công cụ 2 — Xếp hạng: Rủi ro = Impact × Likelihood

Không phải threat nào cũng đáng lo như nhau. Chấm mỗi threat:
- **Impact** (thiệt hại nếu xảy ra): Cao / Trung / Thấp — dựa vào asset nó đụng (P1?).
- **Likelihood** (khả năng xảy ra): dựa vào Exposure + độ khó tấn công.
→ Ưu tiên xử lý threat **Impact cao × Likelihood cao** trước.

## Công cụ 3 — Neo vào chuẩn: OWASP API Security Top 10 (2023)

STRIDE giúp *moi* threat; OWASP API Top 10 là **danh sách chuẩn ngành** dùng để (1)
*đối chiếu độ phủ* — threat model của ta có bỏ sót loại phổ biến nào không, (2) *chỉ
ra ranh giới trách nhiệm* — cái nào gateway lo, cái nào ngoài phạm vi. Nguồn:
https://owasp.org/API-Security/editions/2023/en/0x11-t10/

| OWASP 2023 | Tên | Đồ án này lo ở đâu |
|---|---|---|
| **API1** | Broken Object Level Authz (BOLA) | ⚠️ **Ngoài phạm vi gateway** — việc của backend (object thuộc về ai) |
| **API2** | Broken Authentication | ✅ Trọng tâm: verify token, JWKS, chống forgery/alg=none/expired |
| API3 | Broken Object Property Level Authz | ⚠️ Backend |
| **API4** | Unrestricted Resource Consumption | ✅ Rate-limit (D1-IG) |
| **API5** | Broken Function Level Authz | ✅ Scope/quyền cho endpoint admin (E1-IG, E2-GB) |
| API6 | Unrestricted Access to Sensitive Business Flows | ⚠️ Backend (logic nghiệp vụ) |
| API7 | Server Side Request Forgery | ~ Gateway fetch JWKS/Vault có kiểm URL cố định |
| **API8** | Security Misconfiguration | ✅ Khóa yếu/secret/TLS/trust phẳng (I1, S1-IdP, S1-GB) |
| API9 | Improper Inventory Management | ~ Quản lý route/endpoint deprecated |
| API10 | Unsafe Consumption of APIs | ~ Gateway tiêu thụ IdP/JWKS |

Độ phủ chính: **API2, API4, API5, API8** (đúng vai một API Gateway). **API1/API3 lộ
ra giới hạn kiến trúc** — phải nói rõ với thầy: gateway lo *authentication +
function-level authz*; *object-level authz là của backend*.

## Bảng Threat Register (hoàn chỉnh — output của Module 2)

> Mỗi dòng truy được về: một **asset** (Module 1) + một **ranh giới** + một **STRIDE**,
> và đẻ ra một **đối phó** (→ sẽ lên đời thành Mục tiêu bảo mật ở Module 3).
> `*` = likelihood có điều kiện (cao nếu thiếu TLS/phân quyền).

| ID | Ranh giới | STRIDE | Mối đe dọa (tóm) | Impact | Likelihood | Đối phó (cơ chế) | map SEC | OWASP |
|---|---|---|---|---|---|---|---|---|
| S1-IG | Internet↔GW | S | Giả mạo / tự ký token | Cao | Cao | Verify chữ ký qua JWKS; chặn `alg=none` | SEC-01,02,04,05,06,10 | API2 |
| T1-IG | Internet↔GW | T | Sửa body giữa đường | Cao | Trung | HMAC ký body | SEC-09 | API2 |
| R1-IG | Internet↔GW | R | M2M chối đã gửi request | Trung | Thấp | HMAC signature = non-repudiation | — | API2 |
| I1-IG | Internet↔GW | I | Token HS256 secret yếu bị dò | Cao | Trung | Bắt buộc ES256 / khóa mạnh | SEC-03 | API8 |
| D1-IG | Internet↔GW | D | Flood request làm nghẽn | Cao | Trung | Rate-limit; từ chối rẻ trước crypto đắt | — | API4 |
| E1-IG | Internet↔GW | E | Token user gọi endpoint admin | Cao | Cao | Kiểm scope/quyền (authz) → 403 | — | API5 |
| RP1-IG | Internet↔GW | T/R | Gửi lại request hợp lệ (replay) | Cao | Trung | Nonce (Redis) + timestamp window 300s | SEC-07,08 | API2 |
| S1-GB | GW↔Backend | S | Vòng qua gateway, gọi thẳng backend | Cao | Trung | mTLS; backend không tin IP nguồn | — | API8 |
| E2-GB | GW↔Backend | E | Giả header `X-Roles: admin` | Cao | Trung | Verify token gốc / ký claim nội bộ | — | API5 |
| S1-IdP | GW↔IdP | S | Tráo JWKS, nhét public key lạ | Cao | Cao* | TLS endpoint JWKS + pin issuer + cache | — | API8 |
| I1-Vault | GW↔Vault | I | Lộ secret (truyền hở / quyền rộng) | Cao | Cao* | TLS + least-privilege + audit | — | API8 |

### Lỗ hổng test (threat chưa có SEC) — phần cần nói với thầy

Các threat **nội bộ** chưa có test tự động: **S1-GB, E2-GB, S1-IdP, I1-Vault**. Đây
không phải thiếu sót tư duy — threat model **rộng hơn** bộ test hiện có. Hướng bổ
sung: test mTLS bắt buộc (S1-GB), test backend từ chối header danh tính trần (E2-GB),
test policy Vault least-privilege (I1-Vault).
