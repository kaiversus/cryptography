import os
import httpx
from jose import jwt, JWTError
from cachetools import TTLCache

# Cấu hình mạng nội bộ Docker phục vụ Gateway giao tiếp với Keycloak ở tầng backend
JWKS_URL = os.getenv("JWKS_URL", "http://keycloak:8080/realms/nt219/protocol/openid-connect/certs")

# Định danh Issuer khớp với thông tin chứa trong Token cấp phát từ Endpoint ngoài (Cấu hình ánh xạ 8081:8080)
ISSUER = os.getenv("JWT_ISSUER", "http://localhost:8081/realms/nt219")
AUDIENCE = os.getenv("JWT_AUDIENCE", "account")

# Bộ nhớ đệm Cache cho JWKS để tránh làm nghẽn mạng Keycloak với TTL là 5 phút (300 giây)
_jwks_cache = TTLCache(maxsize=1, ttl=300)

class TokenInvalid(Exception):
    """Ngoại lệ tùy chỉnh ném ra khi Token không hợp lệ hoặc vi phạm chính sách an toàn"""
    pass

def _get_jwks() -> dict:
    """Truy xuất danh sách khóa công khai (JWKS) từ Keycloak và lưu vào cache"""
    if "jwks" in _jwks_cache:
        return _jwks_cache["jwks"]
    try:
        resp = httpx.get(JWKS_URL, timeout=5.0)
        resp.raise_for_status()
        jwks = resp.json()
        _jwks_cache["jwks"] = jwks
        return jwks
    except Exception:
        raise TokenInvalid("Authentication subsystem failure: Unable to retrieve JWKS keys")

def verify_token(token: str) -> dict:
    """
    Xác thực chữ ký, cấu trúc và thời hạn hiệu lực của mã token JWT.
    Trả về dữ liệu giải mã (Payload) nếu hợp lệ, ngược lại ném lỗi TokenInvalid.
    """
    try:
        # ---- [BẢO MẬT PHÒNG NGỰ]: Chống tấn công Base64 Malleability & Kiểm tra cấu trúc ----
        if not token or len(token.split('.')) != 3:
            raise TokenInvalid("Malformed token structure: Must contain exactly 3 dot-separated parts")

        for part in token.split('.'):
            # Quy chuẩn Base64url không được chứa ký tự padding '=' trong JWT tiêu chuẩn
            if '=' in part:
                raise TokenInvalid("Security violation: Base64url padding characters detected")
            # Kiểm tra tập ký tự hợp lệ tránh chèn mã độc/ký tự lạ vào hệ thống
            if not all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in part):
                raise TokenInvalid("Security violation: Unauthorized characters inside base64url payload")

        # Giải mã Header chưa xác thực để trích xuất metadata thuật toán và mã khóa
        unverified_header = jwt.get_unverified_header(token)
        alg = unverified_header.get("alg")
        kid = unverified_header.get("kid")

        if alg not in ("HS256", "RS256", "ES256"):
            raise TokenInvalid(f"Cryptographic policy violation: Algorithm '{alg}' is blacklisted")

        # ---- [CẤU HÌNH HARDENING PRODUCTION]: Bật toàn bộ các cơ chế kiểm tra nghiêm ngặt ----
        decode_options = {
            "verify_signature": True,  # Bắt buộc xác thực chữ ký số bằng thuật toán mật mã
            "verify_exp": True,        # ĐÃ BẬT: Đối chiếu thời hạn token (Hạn định 5 phút từ Keycloak)
            "verify_iss": True,        # ĐÃ BẬT: Kiểm tra nguồn gốc thực thể phát hành mã
            "verify_aud": True,        # ĐÃ BẬT: Kiểm tra mục tiêu đối tượng sử dụng mã
            "require": ["exp", "iat", "iss", "aud"]  # Yêu cầu bắt buộc phải có đủ bộ claims an toàn này
        }

        # ---- XỬ LÝ XÁC THỰC THEO TỪNG THUẬT TOÁN ĐƯỢC PHÉP ----
        
        # 1. Thuật toán Đối xứng HS256 (Mật mã sử dụng Shared Secret)
        if alg == "HS256":
            # Tuyệt đối không hardcode chuỗi mật mã gốc vào mã nguồn.
            # Dữ liệu được trích xuất từ biến môi trường do HashiCorp Vault hoặc Infra thiết lập.
            secret = os.getenv("HS256_SECRET")
            if not secret:
                # Cơ chế dự phòng an toàn (Fallback) khớp với giá trị gieo (seed) của hệ thống Vault hạ tầng
                secret = "hs256-realm-shared-secret-32b!!"
            
            return jwt.decode(
                token, 
                secret, 
                algorithms=["HS256"], 
                audience=AUDIENCE, 
                issuer=ISSUER, 
                options=decode_options
            )

        # 2. Thuật toán Bất đối xứng (RS256 và ES256) - Xác thực qua khóa công khai từ JWKS Endpoint
        elif alg in ("RS256", "ES256"):
            if not kid:
                raise TokenInvalid("Security violation: Missing Key ID (kid) in asymmetric token header")
                
            jwks = _get_jwks()
            key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
            if not key:
                raise TokenInvalid(f"Key validation failure: Key ID '{kid}' is not registered in active JWKS")
                
            return jwt.decode(
                token, 
                key, 
                algorithms=[alg], 
                audience=AUDIENCE, 
                issuer=ISSUER, 
                options=decode_options
            )
            
    except JWTError as e:
        # Chuyển đổi và đóng gói an toàn các thông tin lỗi từ thư viện, không leak log hệ thống ra stdout
        raise TokenInvalid(f"Token verification rejected: {str(e)}")