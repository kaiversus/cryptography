from fastapi import FastAPI, Header, HTTPException, Request
from gateway.middleware.auth import jwt_auth_middleware

app = FastAPI(title="Secure API Gateway")

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
def service(): return {"message": "TODO: HMAC check"}
