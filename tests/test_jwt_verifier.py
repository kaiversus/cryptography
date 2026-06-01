import time
import pytest
from jose import jwt

import gateway.crypto.jwt_verifier as jwt_verifier
from gateway.crypto.jwt_verifier import verify_token, TokenInvalid

# ---------------------------------------------------------
# MOCK DATA: CHUẨN FILE KẾ HOẠCH (TĨNH 100%)
# Sử dụng HS256 để tránh bug của thư viện python-jose trên Python 3.13
# ---------------------------------------------------------
TEST_SECRET = "nt219-secret-key"

# Định dạng JWK chuẩn cho khóa đối xứng (thuật toán HS256)
TEST_PUBLIC_KEY = {
    "kty": "oct",
    "kid": "test-key-1",
    "alg": "HS256",
    "k": "bnQyMTktc2VjcmV0LWtleQ"  # Đây là mã hóa Base64Url của TEST_SECRET
}

# --- HELPER & MOCKING ---
def create_test_token(expires_in=60):
    payload = {
        "sub": "testuser",
        "iss": jwt_verifier.ISSUER,
        "aud": jwt_verifier.AUDIENCE,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in
    }
    # Ký token tĩnh bằng HS256
    return jwt.encode(payload, TEST_SECRET, algorithm="HS256", headers={"kid": "test-key-1"})

@pytest.fixture(autouse=True)
def mock_jwks(monkeypatch):
    """Đánh lừa hàm gọi mạng để trả về Mock Data tĩnh"""
    def fake_get_jwks():
        return {"keys": [TEST_PUBLIC_KEY]}
    monkeypatch.setattr(jwt_verifier, "_get_jwks", fake_get_jwks)

# ---------------------------------------------------------
# 3 KỊCH BẢN TEST CỐT LÕI (Không thay đổi)
# ---------------------------------------------------------
def test_verify_valid_token():
    token = create_test_token(expires_in=300)
    payload = verify_token(token)
    assert payload["sub"] == "testuser"

def test_verify_invalid_signature():
    token = create_test_token(expires_in=300)
    tampered_token = token[:-5] + "abcde"
    with pytest.raises(TokenInvalid):
        verify_token(tampered_token)

def test_verify_expired_token():
    token = create_test_token(expires_in=-10)
    with pytest.raises(TokenInvalid) as exc_info:
        verify_token(token)
    assert "Signature has expired" in str(exc_info.value)