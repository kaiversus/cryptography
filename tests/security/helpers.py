import time
import base64
import json
from jose import jwt

# Đồng bộ với mock của A trong tests/test_jwt_verifier.py
TEST_SECRET = "nt219-secret-key"
TEST_KID = "test-key-1"

TEST_PUBLIC_KEY = {
    "kty": "oct",
    "kid": TEST_KID,
    "alg": "HS256",
    "k": "bnQyMTktc2VjcmV0LWtleQ",  # base64url(TEST_SECRET)
}

# Đồng bộ với gateway/crypto/jwt_verifier.py
ISSUER = "http://localhost:8081/realms/nt219"
AUDIENCE = "account"


def make_token(
    secret: str = TEST_SECRET,
    alg: str = "HS256",
    kid: str = TEST_KID,
    iss: str = ISSUER,
    aud: str = AUDIENCE,
    exp_offset: int = 300,
    extra: dict | None = None,
) -> str:
    """Mint token với các claim chuẩn, cho phép override để dựng attack vector."""
    now = int(time.time())
    payload = {
        "sub": "testuser",
        "preferred_username": "testuser",
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
        "jti": f"test-jti-{now}",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, secret, algorithm=alg, headers={"kid": kid})


def make_alg_none_token() -> str:
    """Tự chế token alg=none vì hầu hết lib từ chối ký kiểu này."""
    def _b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    header = _b64({"alg": "none", "typ": "JWT", "kid": TEST_KID})
    payload = _b64({
        "sub": "attacker",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    })
    return f"{header}.{payload}."  # signature rỗng