"""SEC-15 (S1-IdP / MT-AUTHN) — DEMO: tráo JWKS thì app-logic KHÔNG cứu được.

Vector 9: gateway fetch public key từ IdP qua URL JWKS. Nếu kênh đó KHÔNG có TLS
(hoặc DNS bị đầu độc), kẻ tấn công chặn giữa đường, trả về JWKS GIẢ chứa public
key CỦA NÓ. Sau đó nó ký token bằng private key tương ứng, đặt iss/aud/kid khớp.

Demo này chứng minh: mọi kiểm tra ở tầng ứng dụng (whitelist alg, verify iss/aud,
tra kid trong JWKS) ĐỀU PASS — vì token "hợp lệ" với bộ khóa đã bị tráo. Tức là
app-logic một mình KHÔNG chống được substitution; control BẮT BUỘC nằm ở tầng
truyền dẫn: **fetch JWKS qua HTTPS/TLS** (+ pin issuer/CA).

Đây KHÔNG phải pytest (kết quả là "đòn lọt"), mà là demo minh chứng vì sao cần TLS.
Chạy:  python -m tests.security.sec_jwks_substitution_demo
"""
import base64
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from jose import jwt

import gateway.crypto.jwt_verifier as jv


def _b64url_uint(n: int, size: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(size, "big")).rstrip(b"=").decode()


def main() -> None:
    print("=== SEC-15: DEMO tráo JWKS (vì sao PHẢI fetch qua TLS) ===\n")

    # --- 1. Kẻ tấn công tạo CẶP KHÓA của riêng nó (P-256/ES256) ---
    attacker_priv = ec.generate_private_key(ec.SECP256R1())
    nums = attacker_priv.public_key().public_numbers()
    attacker_jwk = {
        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
        "kid": "attacker-kid-001",
        "x": _b64url_uint(nums.x, 32),
        "y": _b64url_uint(nums.y, 32),
    }
    priv_pem = attacker_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    # --- 2. Mô phỏng kênh JWKS bị tráo: _get_jwks trả về khóa CỦA HACKER ---
    jv._jwks_cache.clear()
    jv._get_jwks = lambda: {"keys": [attacker_jwk]}
    print("  [MITM] JWKS bị thay bằng public key của hacker (kid=attacker-kid-001)")

    # --- 3. Hacker tự ký token, đặt iss/aud/kid khớp đúng cấu hình gateway ---
    now = int(time.time())
    forged = jwt.encode(
        {"sub": "attacker", "iss": jv.ISSUER, "aud": jv.AUDIENCE,
         "iat": now, "exp": now + 300,
         "realm_access": {"roles": ["admin"]}},  # tự phong admin luôn
        priv_pem, algorithm="ES256", headers={"kid": "attacker-kid-001"},
    )
    print("  [ATTACK] Token do hacker ký, tự gán role admin\n")

    # --- 4. Gateway verify: mọi kiểm tra app-layer đều PASS ---
    try:
        claims = jv.verify_token(forged)
        print("  >>> verify_token CHẤP NHẬN token giả!")
        print(f"      sub  = {claims.get('sub')}")
        print(f"      role = {claims.get('realm_access', {}).get('roles')}")
        print("\n  KẾT LUẬN: whitelist alg + verify iss/aud + tra kid ĐỀU không phát")
        print("  hiện ra, vì token khớp bộ khóa đã bị tráo. App-logic BẤT LỰC.")
        print("  => Control duy nhất chặn được: FETCH JWKS QUA TLS (+ pin issuer/CA).")
    except jv.TokenInvalid as e:
        print(f"  verify_token từ chối (ngoài dự kiến trong demo này): {e}")


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    main()
