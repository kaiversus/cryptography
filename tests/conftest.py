"""Fixtures và helpers cho security tests.

Chiến lược: mock JWKS endpoint giống pattern của A trong test_jwt_verifier.py,
để test không phụ thuộc Keycloak chạy. Mock dùng HS256 cho đơn giản;
verify_token() của A vẫn whitelist HS256 nên signature check vẫn hoạt động.
"""
import os

# Tắt OpenTelemetry SDK trong test/CI (không có Jaeger collector). Phải set
# TRƯỚC khi import gateway.main vì setup_tracing() chạy lúc import.
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

# Verifier nhánh HS256 đọc HS256_SECRET từ env (fallback là secret của Vault).
# Test ký token bằng TEST_SECRET nên phải đồng bộ env, nếu không token hợp lệ
# cũng bị từ chối (mọi /api/protected trả 401) làm smoke test sai lệch.
os.environ.setdefault("HS256_SECRET", "nt219-secret-key")

# slowapi Limiter dùng storage Redis (REDIS_URL). Trong unit test không có Redis,
# ép dùng in-memory storage để rate-limit không gọi mạng. Phải set trước khi
# import gateway.main vì limiter khởi tạo lúc import.
os.environ.setdefault("REDIS_URL", "memory://")

import time
import pytest
from jose import jwt as jose_jwt
from fastapi.testclient import TestClient

import gateway.crypto.jwt_verifier as jv
from gateway.main import app
from gateway.storage import revocation as _revocation


class _NoopRevocationStore:
    """Stub mặc định cho mọi test: không token nào bị revoke. Test riêng cho
    revocation tự override bằng set_client()."""
    def setex(self, name, ttl, value): return True
    def exists(self, name): return 0
    def ttl(self, name): return -2


@pytest.fixture(autouse=True)
def _stub_revocation_store():
    _revocation.set_client(_NoopRevocationStore())
    yield
    _revocation.set_client(None)

# Khóa "thật" mà JWKS của mình giả lập sẽ trả về
TEST_SECRET = "nt219-secret-key"
TEST_KID = "test-key-1"
TEST_PUBLIC_KEY = {
    "kty": "oct",
    "kid": TEST_KID,
    "alg": "HS256",
    "k": "bnQyMTktc2VjcmV0LWtleQ",  # base64url của TEST_SECRET
}


@pytest.fixture(autouse=True)
def mock_jwks(monkeypatch):
    """Mọi test trong tests/security/ đều dùng JWKS giả này."""
    monkeypatch.setattr(jv, "_get_jwks", lambda: {"keys": [TEST_PUBLIC_KEY]})


@pytest.fixture(scope="session")
def client():
    return TestClient(app)


def make_token(
    *,
    sub: str = "testuser",
    iss: str | None = None,
    aud: str | None = None,
    expires_in: int = 300,
    alg: str = "HS256",
    secret: str = TEST_SECRET,
    kid: str = TEST_KID,
    extra: dict | None = None,
) -> str:
    """Helper tạo token tùy biến để test attack.

    Default = token hợp lệ. Override từng tham số để mô phỏng tấn công:
    - secret khác TEST_SECRET → SEC-01 forgery
    - alg='none' → SEC-02 downgrade
    - expires_in âm → SEC-04 expired
    - aud sai → SEC-05
    - iss sai → SEC-06
    """
    now = int(time.time())
    payload = {
        "sub": sub,
        "iss": iss if iss is not None else jv.ISSUER,
        "aud": aud if aud is not None else jv.AUDIENCE,
        "iat": now,
        "exp": now + expires_in,
        "jti": f"jti-{now}-{sub}",
    }
    if extra:
        payload.update(extra)
    return jose_jwt.encode(payload, secret, algorithm=alg, headers={"kid": kid})