import httpx
from cachetools import TTLCache
from jose import jwt, JWTError

# SỬA 1: Dùng mạng nội bộ Docker để gọi Keycloak
JWKS_URL = "http://keycloak:8080/realms/nt219/protocol/openid-connect/certs"

# SỬA 2: ISSUER khớp với Token cấp từ bên ngoài
ISSUER = "http://localhost:8081/realms/nt219"
AUDIENCE = "account"
_jwks_cache = TTLCache(maxsize=1, ttl=300)

class TokenInvalid(Exception): ...

def _get_jwks() -> dict:
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]
    resp = httpx.get(JWKS_URL, timeout=5.0)
    resp.raise_for_status()
    jwks = resp.json()
    _jwks_cache["jwks"] = jwks
    return jwks

def verify_token(token: str) -> dict:
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]
        alg = unverified_header["alg"]
        
        # GỘP: Cho phép cả ES256 (Đạt), RS256 (Đăng) và HS256 (Unit Test)
        if alg not in ("ES256", "RS256", "HS256"):
            raise TokenInvalid(f"alg {alg} not allowed")
            
        jwks = _get_jwks()
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
        if not key:
            raise TokenInvalid("kid not found in JWKS")
            
        # GỘP: Giữ nguyên cấu hình kiểm tra nghiêm ngặt của Đăng nhưng dùng [alg] động
        payload = jwt.decode(
            token, key, algorithms=[alg],
            issuer=ISSUER, audience=AUDIENCE,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
        return payload
    except JWTError as e:
        raise TokenInvalid(str(e))