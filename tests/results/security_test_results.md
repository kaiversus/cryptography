# Security Test Results — SEC-01 → SEC-10

**Ngày chạy:** 2026-06-20
**Lệnh:** `pytest tests/security -v --html=tests/results/report.html --self-contained-html`
**Môi trường:** verifier/HMAC thật, JWKS + nonce/revocation/rate-limit mock in-memory
(không phụ thuộc Keycloak/Redis chạy — xem `tests/conftest.py`).

## 1. Bảng tổng hợp

| ID | Kịch bản | Kỳ vọng | Kết quả | Trạng thái |
|----|----------|---------|---------|------------|
| SEC-01 | JWT forgery (key lạ) | 401 | 401 | ✅ PASS |
| SEC-02 | alg=none downgrade | 401 | 401 | ✅ PASS |
| SEC-03 | Weak HS256 brute force | Crack được | cracked `secret` (0.21 ms), `739` (13.97 ms) | ✅ PASS (demo) |
| SEC-04 | Token expired | 401 | 401 | ✅ PASS |
| SEC-05 | Wrong audience | 401 | 401 | ✅ PASS |
| SEC-06 | Wrong issuer | 401 | 401 | ✅ PASS |
| SEC-07 | HMAC replay (cùng nonce) | 401 lần 2 | 401 `replay detected` | ✅ PASS |
| SEC-08 | HMAC timestamp out-of-window | 401 | 401 `timestamp out of window` | ✅ PASS |
| SEC-09 | HMAC body tampering | 401 | 401 `invalid_signature` | ✅ PASS |
| SEC-10 | Revoked JWT (jti blacklist) | 401 | 200 trước revoke → 401 `token revoked` sau | ✅ PASS |

**Tỷ lệ: 10/10 kịch bản đạt (9 tự động hóa pytest + 1 demo brute force).**
Bonus `test_unknown_key_id` (X-Key-Id lạ → 401 `unknown_key`) cũng PASS.

Output pytest gốc:

```
tests/security/test_hmac_attacks.py::test_smoke_valid_hmac PASSED        [  8%]
tests/security/test_hmac_attacks.py::test_sec07_replay_same_nonce PASSED [ 16%]
tests/security/test_hmac_attacks.py::test_sec08_timestamp_out_of_window PASSED [ 25%]
tests/security/test_hmac_attacks.py::test_sec09_body_tampering PASSED    [ 33%]
tests/security/test_hmac_attacks.py::test_unknown_key_id PASSED          [ 41%]
tests/security/test_jwt_attacks.py::test_smoke_valid_token PASSED        [ 50%]
tests/security/test_jwt_attacks.py::test_sec01_forgery_wrong_key PASSED  [ 58%]
tests/security/test_jwt_attacks.py::test_sec02_alg_none_downgrade PASSED [ 66%]
tests/security/test_jwt_attacks.py::test_sec04_expired_token PASSED      [ 75%]
tests/security/test_jwt_attacks.py::test_sec05_wrong_audience PASSED     [ 83%]
tests/security/test_jwt_attacks.py::test_sec06_wrong_issuer PASSED       [ 91%]
tests/security/test_jwt_attacks.py::test_sec10_revoked_jti PASSED        [100%]
====================== 12 passed, 12 warnings in 12.61s =======================
```

## 2. Chi tiết từng kịch bản

### SEC-01: JWT Forgery
**Vector:** Attacker tự ký token bằng `attacker-secret-key-not-in-jwks`.
**Expected:** 401. **Actual:** 401 — chữ ký không khớp khóa hợp lệ. ✅

### SEC-02: alg=none Downgrade
**Vector:** Header `{"alg":"none"}`, chữ ký rỗng (`make_alg_none_token`).
**Expected:** 401. **Actual:** 401 — verifier whitelist `HS256/RS256/ES256`, từ chối `none`. ✅

### SEC-03: Weak HS256 Brute Force (demo)
**Vector:** IdP giả định ký HS256 bằng secret yếu; attacker dò khóa offline.
**Lệnh:** `python -m tests.security.sec03_weak_hs256_demo`
**Actual:**
```
[Dictionary] token ký bằng 'secret'
  -> cracked = 'secret' trong 0.21 ms (5 lần thử)
[Brute force] token ký bằng '739' (charset=digits, len<=3)
  -> cracked = '739' trong 13.97 ms
```
**Kết luận:** secret HS256 ngắn/từ điển → forgery toàn hệ thống. Đây là minh chứng
cho quyết định kiến trúc dùng **ES256 + JWKS** cho client-facing (xem `docs/crypto-analysis.md`). ✅

### SEC-04: Expired Token
**Vector:** `exp = now - 60`. **Expected:** 401. **Actual:** 401 `Signature has expired`. ✅

### SEC-05: Wrong Audience
**Vector:** `aud = "wrong-audience"`. **Expected:** 401. **Actual:** 401 `Invalid audience`. ✅

### SEC-06: Wrong Issuer
**Vector:** `iss = "http://evil.example.com/realms/fake"`. **Expected:** 401. **Actual:** 401 `Invalid issuer`. ✅

### SEC-07: HMAC Replay
**Vector:** Gửi request hợp lệ 2 lần với cùng `X-Nonce`.
**Expected:** lần 2 → 401. **Actual:** lần 1 → 200, lần 2 → 401 `replay detected`. ✅

### SEC-08: HMAC Timestamp Out-of-Window
**Vector:** `X-Timestamp = now - 1000` (> cửa sổ 300s).
**Expected:** 401. **Actual:** 401 `timestamp out of window`. ✅

### SEC-09: HMAC Body Tampering
**Vector:** Ký `{"id":1}`, gửi `{"id":999}` giữ chữ ký cũ.
**Expected:** 401. **Actual:** 401 `invalid_signature` (body hash không khớp). ✅

### SEC-10: Revoked JWT
**Vector:** Token chữ ký hợp lệ, `jti` được đẩy vào blacklist Redis.
**Expected:** 401. **Actual:** 200 trước revoke → 401 `token revoked` sau khi blacklist. ✅

## 3. Đánh giá

- Toàn bộ vector tấn công JWT (forgery, downgrade, expired, aud/iss, revocation) và
  HMAC (replay, clock skew, tampering) đều bị Gateway chặn đúng kỳ vọng.
- SEC-03 không phải lỗ hổng của hệ thống mà là minh chứng định lượng cho lựa chọn
  thuật toán: hệ thống production tránh HS256 cho token public-facing.
- Báo cáo HTML chi tiết: `tests/results/report.html`.
