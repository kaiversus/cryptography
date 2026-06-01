from fastapi import FastAPI, Header, HTTPException
# 1. Import module của bạn
from crypto.jwt_verifier import verify_token, TokenInvalid

app = FastAPI(title="Secure API Gateway")

@app.get("/health")
def health(): 
    return {"status": "ok"}

@app.get("/api/public")
def public(): 
    return {"message": "public, no auth"}

# 2. Sửa lại endpoint /api/protected
@app.get("/api/protected")
def protected(authorization: str | None = Header(None)):
    # Kiểm tra format Bearer
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    
    # Lấy token (bỏ chữ "Bearer ")
    token = authorization.replace("Bearer ", "")
    
    # 3. Gọi hàm verify_token của bạn
    try:
        payload = verify_token(token)
        # Nếu thành công, trả về thông tin user
        return {
            "message": "Authenticated successfully", 
            "user": payload.get("sub"),
            "full_payload": payload
        }
    except TokenInvalid:
        # Nếu lỗi (hết hạn, sai chữ ký), trả về 401
        raise HTTPException(status_code=401, detail="Invalid token or signature")

@app.get("/api/service")
def service(): 
    return {"message": "TODO: HMAC check"}