from fastapi import FastAPI, Request
from middleware.auth import jwt_auth_middleware
from middleware.hmac_auth import hmac_auth_middleware

app = FastAPI(title="Secure API Gateway")

# Middleware FastAPI chạy LIFO theo thứ tự đăng ký:
# hmac đăng ký trước → chạy SAU; jwt đăng ký sau → chạy TRƯỚC.
# Vì JWT chỉ guard /api/protected và HMAC chỉ guard /api/service nên không xung đột.
app.middleware("http")(hmac_auth_middleware)
app.middleware("http")(jwt_auth_middleware)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/public")
def public():
    return {"message": "public, no auth"}

@app.get("/api/protected")
def protected(request: Request):
    username = request.state.user.get("preferred_username") if hasattr(request.state, "user") else "Unknown"
    roles = request.state.user.get("realm_access", {}).get("roles", []) if hasattr(request.state, "user") else []
    return {"user": username, "roles": roles}

@app.post("/api/service")
def service():
    return {"message": "HMAC signature verified successfully"}