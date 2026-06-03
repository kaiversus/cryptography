from fastapi import FastAPI, Request
from middleware.auth import jwt_auth_middleware
from middleware.hmac_auth import hmac_auth_middleware

app = FastAPI(title="Secure API Gateway")

# Đăng ký các lớp giáp bảo mật (Middleware chạy từ dưới lên trên)
app.middleware("http")(hmac_auth_middleware)  # Lớp chặn HMAC cho M2M
app.middleware("http")(jwt_auth_middleware)   # Lớp chặn JWT cho User

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