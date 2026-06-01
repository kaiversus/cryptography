from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Secure API Gateway")

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/api/public")
def public(): return {"message": "public, no auth"}

@app.get("/api/protected")
def protected(authorization: str | None = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer")
    return {"message": "TODO: verify token", "token_preview": authorization[:30]}

@app.get("/api/service")
def service(): return {"message": "TODO: HMAC check"}

