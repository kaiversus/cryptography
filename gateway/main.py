# file: main.py
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from middleware.auth import jwt_auth_middleware
from middleware.hmac_auth import hmac_auth_middleware
from storage.revocation import revoke # THÊM DÒNG NÀY

app = FastAPI(title="Secure API Gateway")

# Đăng ký các lớp giáp bảo mật
app.middleware("http")(hmac_auth_middleware)
app.middleware("http")(jwt_auth_middleware)

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/api/public")
def public(): return {"message": "public, no auth"}

@app.get("/api/protected")
def protected(request: Request):
    username = request.state.user.get("preferred_username") if hasattr(request.state, "user") else "Unknown"
    roles = request.state.user.get("realm_access", {}).get("roles", []) if hasattr(request.state, "user") else []
    return {"user": username, "roles": roles}

@app.get("/api/service")
def service(): 
    return {"message": "HMAC signature verified successfully! Welcome, trusted service."}

# --- THÊM ENDPOINT DAY 6 ---
@app.post("/auth/revoke")
def revoke_endpoint(request: Request):
    # Lấy thông tin user đã được lưu từ request.state do middleware giải mã
    payload = getattr(request.state, "user", None)
    if not payload:
        return JSONResponse(status_code=401, content={"detail": "Missing valid token in state"})
    
    jti = payload.get("jti")
    exp = payload.get("exp")
    
    if not jti or not exp:
        return JSONResponse(status_code=400, content={"detail": "Token lacks jti or exp claims"})
        
    # Gọi hàm revoke để đưa jti vào Redis
    revoke(jti, exp)
    
    return {"status": "revoked", "jti": jti}