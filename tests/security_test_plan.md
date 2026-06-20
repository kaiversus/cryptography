# Security Test Plan — Secure API Gateway (NT219)

Bảng kịch bản tấn công SEC-01 → SEC-10 dùng để kiểm thử khả năng cưỡng chế mật mã
của Gateway. Mỗi kịch bản có vector tấn công cụ thể và kết quả mong đợi; phần lớn
được tự động hóa bằng `pytest` trong `tests/security/`.

## 1. Bảng kịch bản

| ID | Tên | Vector tấn công | Expected | Tự động hóa |
|----|-----|-----------------|----------|-------------|
| SEC-01 | JWT forgery | Token tự ký bằng key không nằm trong JWKS | 401 | `test_jwt_attacks.py::test_sec01_forgery_wrong_key` |
| SEC-02 | alg=none downgrade | Header `alg:none`, bỏ chữ ký | 401 | `test_jwt_attacks.py::test_sec02_alg_none_downgrade` |
| SEC-03 | Weak HS256 brute force | IdP ký HS256 bằng secret yếu → dò khóa offline | Crack được → chứng minh rủi ro | `sec03_weak_hs256_demo.py` (demo) |
| SEC-04 | Token expired | `exp` ở quá khứ | 401 | `test_jwt_attacks.py::test_sec04_expired_token` |
| SEC-05 | Wrong audience | `aud` không khớp | 401 | `test_jwt_attacks.py::test_sec05_wrong_audience` |
| SEC-06 | Wrong issuer | `iss` không khớp Keycloak | 401 | `test_jwt_attacks.py::test_sec06_wrong_issuer` |
| SEC-07 | HMAC replay | Gửi lại request hợp lệ với cùng `X-Nonce` | Lần 2 → 401 | `test_hmac_attacks.py::test_sec07_replay_same_nonce` |
| SEC-08 | HMAC timestamp out of window | `X-Timestamp` lệch > 300s | 401 | `test_hmac_attacks.py::test_sec08_timestamp_out_of_window` |
| SEC-09 | HMAC body tampering | Ký body A, gửi body B, giữ chữ ký cũ | 401 | `test_hmac_attacks.py::test_sec09_body_tampering` |
| SEC-10 | Revoked JWT (jti blacklist) | Revoke token rồi gọi lại bằng chính token đó | 401 | `test_jwt_attacks.py::test_sec10_revoked_jti` |

> Bonus (ngoài 10 kịch bản chuẩn): `test_unknown_key_id` — gửi `X-Key-Id` không tồn
> tại trong key store → 401 `unknown_key`.

## 2. Cách chạy

```bash
# Toàn bộ test bảo mật + sinh báo cáo HTML
pytest tests/security -v --html=tests/results/report.html --self-contained-html

# Riêng demo brute force HS256 (SEC-03, không thuộc pytest)
python -m tests.security.sec03_weak_hs256_demo
```

## 3. Phạm vi & giới hạn

- SEC-01/02/04/05/06/10 mock JWKS (HS256) để không phụ thuộc Keycloak đang chạy —
  xem `tests/security/conftest.py`. Logic verifier (`verify_token`) là thật.
- SEC-07/08/09 dùng Redis in-memory fake (`FakeRedis`) cho nonce store.
- SEC-03 chạy trên token tự sinh trong phòng lab, **không** nhắm hệ thống thật.
- Quét động (DAST) bằng OWASP ZAP nằm ngoài phạm vi pytest — xem
  `docs/zap-scan-guide.md` và `docs/zap-report.pdf`.
