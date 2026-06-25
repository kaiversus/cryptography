# Bản đồ truy vết: SEC test ↔ Threat ↔ Mục tiêu ↔ OWASP API Top 10 (2023)

> Một file tra cứu duy nhất. Mỗi kịch bản tấn công SEC của nhóm được truy ngược về:
> threat (Module 2) → STRIDE → mục tiêu bảo mật (Module 3) → mã chuẩn OWASP API 2023.
> Nguồn: `tests/security_test_plan.md` (định nghĩa test) + `02-rui-ro.md` (threat) +
> `03-muc-tieu-bao-mat.md` (mục tiêu).

## 1. Bảng truy vết đầy đủ

| SEC | Tên test | Vector tấn công | Mã mong đợi | Threat | STRIDE | Mục tiêu | OWASP 2023 |
|-----|----------|-----------------|-------------|--------|--------|----------|------------|
| SEC-01 | JWT forgery | Token tự ký bằng key ngoài JWKS | 401 | S1-IG | S | MT-AUTHN | **API2** |
| SEC-02 | alg=none downgrade | Header `alg:none`, bỏ chữ ký | 401 | S1-IG | S | MT-AUTHN | **API2** |
| SEC-03 | Weak HS256 brute force | Dò khóa HS256 yếu offline | Crack được (chứng minh rủi ro) | I1-IG | I | MT-CONF | **API8** (+API2) |
| SEC-04 | Token expired | `exp` ở quá khứ | 401 | S1-IG | S | MT-AUTHN | **API2** |
| SEC-05 | Wrong audience | `aud` không khớp | 401 | S1-IG | S | MT-AUTHN | **API2** |
| SEC-06 | Wrong issuer | `iss` không khớp IdP | 401 | S1-IG | S | MT-AUTHN | **API2** |
| SEC-07 | HMAC replay | Gửi lại request với cùng nonce | 401 (lần 2) | RP1-IG | T/R | MT-INTEG | **API2** |
| SEC-08 | HMAC timestamp out of window | `X-Timestamp` lệch > 300s | 401 | RP1-IG | T | MT-INTEG | **API2** |
| SEC-09 | HMAC body tampering | Ký body A, gửi body B | 401 | T1-IG | T | MT-INTEG | **API2** |
| SEC-10 | Revoked JWT (jti blacklist) | Dùng lại token đã thu hồi | 401 | S1-IG | S | MT-AUTHN | **API2** |
| Bonus | Unknown key id | `X-Key-Id` không tồn tại | 401 | S1-IdP | S | MT-AUTHN | API2/API8 |

## 2. Độ phủ OWASP

| OWASP 2023 | Có SEC test phủ? | Test nào |
|---|---|---|
| **API2 — Broken Authentication** | ✅ Đậm | SEC-01,02,04,05,06,07,08,09,10 |
| **API8 — Security Misconfiguration** | ✅ | SEC-03 (khóa yếu) |
| **API4 — Unrestricted Resource Consumption** | ⚠️ Một phần | (rate-limit có code, chưa có SEC test riêng — D1-IG) |
| **API5 — Broken Function Level Authz** | ⚠️ Chưa có test | E1-IG, E2-GB (threat có, test chưa) |
| API1/API3 — Object/Property Level Authz | ❌ Ngoài phạm vi gateway | việc của backend |
| API6/7/9/10 | ~ Cận biên | không trọng tâm gateway |

## 3. Threat CHƯA có SEC test (lỗ hổng kiểm thử — phần bổ sung)

| Threat | Mô tả | Đề xuất test bổ sung |
|---|---|---|
| D1-IG | Flood DoS | Test rate-limit trả 429 khi vượt ngưỡng |
| E1-IG | Token user gọi endpoint admin | Test scope thiếu → 403 |
| E2-GB | Giả header `X-Roles: admin` | Test backend từ chối header danh tính trần |
| S1-GB | Bypass gateway gọi thẳng backend | Test mTLS bắt buộc ở cửa 2 |
| I1-Vault | Lộ secret từ kho | Test policy Vault least-privilege |

> Kết luận cho báo cáo: bộ SEC hiện tại phủ rất tốt **API2** (xác thực token) và một
> phần **API8**. Threat model (Module 2) **rộng hơn** bộ test — các dòng ở mục 3 là
> hướng mở rộng, không phải thiếu sót tư duy.
