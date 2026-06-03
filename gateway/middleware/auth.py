# file: middleware/auth.py
from fastapi import Request
from fastapi.responses import JSONResponse
from crypto.jwt_verifier import verify_token, TokenInvalid
from storage.revocation import is_revoked # Import hàm kiểm tra Redis

# Đổi thành Tuple để bảo vệ nhiều route cùng lúc
PROTECTED_PREFIXES = ("/api/protected", "/auth/revoke")

async def jwt_auth_middleware(request: Request, call_next):
    # Dùng any() để kiểm tra xem request path có khớp với bất kỳ prefix nào không
    if any(request.url.path.startswith(prefix) for prefix in PROTECTED_PREFIXES):
        auth = request.headers.get("authorization", "")
        
        if not auth.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "missing bearer"})
            
        try:
            payload = verify_token(auth[7:])
        except TokenInvalid as e:
            return JSONResponse(status_code=401, content={"detail": f"invalid token: {e}"})
            
        # --- LOGIC MỚI: DAY 6 - KIỂM TRA REDIS BLACKLIST ---
        jti = payload.get("jti")
        if jti and is_revoked(jti):
            return JSONResponse(
                status_code=401, 
                content={"detail": "Token has been revoked (Logged out)"}
            )
        # ---------------------------------------------------
            
        request.state.user = payload
        
    return await call_next(request)