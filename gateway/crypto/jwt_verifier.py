import httpx
from cachetools import TTLCache
from jose import jwt, JWTError

# Đã cập nhật cổng thành 8081 theo yêu cầu của bạn
JWKS_URL = "http://keycloak:8081/realms/nt219/protocol/openid-connect/certs"
ISSUER = "http://keycloak:8081/realms/nt219"
AUDIENCE = "account"  # hoặc client_id tùy cấu hình nhóm
_jwks_cache = TTLCache(maxsize=1, ttl=300)  # Cache trong 5 phút

def _get_jwks() -> dict:
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]
    resp = httpx.get(JWKS_URL, timeout=5.0)
    resp.raise_for_status()
    jwks = resp.json()
    _jwks_cache["jwks"] = jwks
    return jwks

class TokenInvalid(Exception): ...

def verify_token(token: str) -> dict:
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]
        alg = unverified_header["alg"]
        if alg not in ("ES256", "HS256"):
            raise TokenInvalid(f"alg {alg} not allowed")
        jwks = _get_jwks()
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
        if not key:
            raise TokenInvalid("kid not found in JWKS")
        payload = jwt.decode(
            token, key, algorithms=[alg],
            issuer=ISSUER, audience=AUDIENCE,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
        return payload
    except JWTError as e:
        raise TokenInvalid(str(e))