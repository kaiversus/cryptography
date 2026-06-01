import httpx
from cachetools import TTLCache
from jose import jwt, JWTError

# SỬA 1: Dùng cổng 8080 để Gateway bên trong Docker nói chuyện với Keycloak
JWKS_URL = "http://keycloak:8080/realms/nt219/protocol/openid-connect/certs"

# SỬA 2: ISSUER phải khớp với giá trị trong payload của token (lấy từ localhost:8081)
ISSUER = "http://localhost:8081/realms/nt219" 

AUDIENCE = "account" 
_jwks_cache = TTLCache(maxsize=1, ttl=300)

def _get_jwks() -> dict:
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]
    # Gateway gọi nội bộ tới keycloak:8080
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
        
        # SỬA 3: Keycloak dùng RS256, phải cho phép nó!
        if alg != "RS256":
            raise TokenInvalid(f"alg {alg} not allowed, expected RS256")
            
        jwks = _get_jwks()
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
        if not key:
            raise TokenInvalid("kid not found in JWKS")
            
        # Giải mã
        payload = jwt.decode(
            token, key, algorithms=["RS256"], # Chỉ nhận RS256
            issuer=ISSUER, audience=AUDIENCE,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
        return payload
    except JWTError as e:
        # Debug nhẹ ở đây nếu vẫn lỗi
        print(f"DEBUG LỖI: {e}") 
        raise TokenInvalid(str(e))