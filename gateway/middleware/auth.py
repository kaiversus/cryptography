from fastapi import Request
from fastapi.responses import JSONResponse
from gateway.crypto.jwt_verifier import verify_token, TokenInvalid

PROTECTED_PREFIX = "/api/protected"

async def jwt_auth_middleware(request: Request, call_next):
    if request.url.path.startswith(PROTECTED_PREFIX):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "missing bearer"})
        try:
            payload = verify_token(auth[7:])
        except TokenInvalid as e:
            # Trả về 401 thay vì làm crash app sinh ra lỗi 500
            return JSONResponse(status_code=401, content={"detail": f"invalid token: {e}"})
            
        request.state.user = payload
        
    return await call_next(request)
