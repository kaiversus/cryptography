# HMAC Request Signing Spec — `gateway-internal/v1`

Spec ký request machine-to-machine cho `/api/service`. Phong cách: **AWS Signature
Version 4 rút gọn** (bỏ bước derive signing key theo ngày/region, thêm nonce store
chống replay). Đây là tài liệu chuẩn mà `gateway/crypto/hmac_verifier.py` và client
(`clients/test_hmac.py`, `tests/security/helpers.py`) phải tuân thủ giống hệt.

## 1. Headers bắt buộc

| Header | Mô tả | Format |
|--------|-------|--------|
| `X-Timestamp` | Unix epoch (giây) lúc ký | chuỗi chỉ chứa chữ số, vd `"1735689600"` |
| `X-Nonce` | UUID v4 ngẫu nhiên, dùng một lần | `"550e8400-e29b-41d4-a716-446655440000"` |
| `X-Key-Id` | Định danh khóa để tra secret (Vault/dev) | vd `"dev-key-01"` |
| `X-Signature` | HMAC-SHA256 hex thường (64 ký tự) | `"9f86d081..."` |
| `Host` | Host đích, nằm trong tập signed headers | `"localhost:8000"` |

## 2. Canonical Request

```
<METHOD>\n
<PATH>\n
<SORTED_QUERY>\n
<CANONICAL_HEADERS>\n
<SIGNED_HEADERS>\n
<SHA256_HEX(BODY)>
```

- `METHOD`: viết hoa (`GET`/`POST`/...).
- `PATH`: path có leading slash, vd `/api/service`.
- `SORTED_QUERY`: query string nguyên trạng (rỗng → `""`).
- `CANONICAL_HEADERS`: với mỗi signed header (sắp theo alphabet key, lowercase):
  `"{key}:{value.strip()}\n"`. Tập signed headers = `host;x-key-id;x-nonce;x-timestamp`.
- `SIGNED_HEADERS`: danh sách key sắp xếp, nối bằng `;`:
  `host;x-key-id;x-nonce;x-timestamp`.
- `SHA256_HEX(BODY)`: hash hex của body bytes; body rỗng →
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## 3. String To Sign

```
HMAC-SHA256\n
<X-Timestamp>\n
gateway-internal/v1\n
<SHA256_HEX(CANONICAL_REQUEST)>
```

`Signature = HMAC_SHA256(secret, string_to_sign).hexdigest()`, với `secret` tra từ
`X-Key-Id` (Vault path `gateway/hmac/{key_id}`, fallback dev `dev-key-01` →
`dev-shared-secret`).

## 4. Cửa sổ chống Replay

- Server từ chối nếu `|now - X-Timestamp| > 300s` → `invalid_timestamp`.
- Server từ chối nếu `X-Nonce` đã thấy (Redis key `nonce:<nonce>`) → `replay_detected`.
- Sau khi pass toàn bộ, server `SETEX nonce:<nonce> 600 1` (TTL 600s ≥ cửa sổ 300s).

## 5. Thứ tự kiểm tra phía server (10 bước)

1. Parse 4 header (`X-Timestamp/Nonce/Key-Id/Signature`) → thiếu = `missing_header`.
2. Validate format: timestamp là số, nonce khớp UUIDv4, signature là hex 64 ký tự.
3. Kiểm tra cửa sổ timestamp 300s.
4. Kiểm tra nonce trong Redis (replay).
5. Tra secret theo `X-Key-Id` (Vault → dev fallback). Không có → `unknown_key`.
6-8. Dựng lại canonical request → string-to-sign → tính chữ ký kỳ vọng.
9. So sánh `hmac.compare_digest` (constant-time) → lệch = `invalid_signature`.
10. `SETEX` nonce (TTL 600s).

## 6. Ví dụ cụ thể (để test chéo)

```
Request : POST /api/service
Body    : {"id":1}
Host    : localhost:8000
X-Key-Id: dev-key-01
Secret  : dev-shared-secret
```

Sinh chữ ký hợp lệ bằng đúng hàm của Gateway:

```bash
python benchmarks/scripts/gen_hmac_lua.py   # in ts, nonce, signature hợp lệ
```

hoặc trong Python:

```python
from gateway.crypto.hmac_verifier import compute_signature
signed = {"host": "localhost:8000", "x-key-id": "dev-key-01",
          "x-nonce": "<uuid4>", "x-timestamp": "<ts>"}
sig = compute_signature("POST", "/api/service", "", signed, b'{"id":1}', b"dev-shared-secret")
```

## 7. Mã lỗi (HTTP 401 + `detail`)

`missing_header` · `invalid_format` · `invalid_timestamp` · `replay_detected` ·
`unknown_key` · `invalid_signature`.
