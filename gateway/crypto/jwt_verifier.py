import httpx
from jose import jwt, JWTError
from cachetools import TTLCache
from jose import jwt, JWTError
import base64 
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
        # BỔ SUNG KHỐI NÀY: KIỂM TRA TÍNH DUY NHẤT CỦA BASE64 (Chống Malleability)
        parts = token.split('.')
        if len(parts) == 3:
            sig_b64 = parts[2]
            # Bù lại dấu '=' bị thiếu của chuẩn Base64URL để giải mã
            pad_len = 4 - (len(sig_b64) % 4)
            sig_padded = sig_b64 + ('=' * pad_len if pad_len != 4 else '')
            
            # Giải mã ra bytes rồi mã hóa ngược lại thành string chuẩn
            sig_bytes = base64.urlsafe_b64decode(sig_padded)
            canonical_sig = base64.urlsafe_b64encode(sig_bytes).decode('utf-8').rstrip('=')
            
            # Nếu chuỗi khách gửi không giống chuỗi chuẩn (VD: gửi B nhưng chuẩn là A) -> Báo lỗi!
            if sig_b64 != canonical_sig:
                raise TokenInvalid("Strict Base64 Validation Failed: Malleable signature detected!")

        # ... (Giữ nguyên đoạn code giải mã và check JWT cũ của anh em mình từ đây trở xuống)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]
        alg = unverified_header["alg"]
        
        if alg not in ("ES256", "RS256", "HS256"):
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
    except Exception as e:
        raise TokenInvalid(f"Invalid token format: {str(e)}")

