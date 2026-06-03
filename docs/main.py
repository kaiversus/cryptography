from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from jwt import PyJWKClient

app = FastAPI()

# 1. Khai báo URL lấy Public Key của Keycloak (Realm nt219)
JWKS_URL = "http://localhost:8081/realms/nt219/protocol/openid-connect/certs"

# Tự động tải và cache Public Key từ Keycloak
jwks_client = PyJWKClient(JWKS_URL)

# Báo cho FastAPI biết chúng ta dùng Bearer Token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 2. Hàm middleware kiểm tra và giải mã Token
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        # Lấy đúng Public Key để giải mã dựa vào header của token
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Giải mã và kiểm tra tính hợp lệ (thuật toán, hạn sử dụng, audience)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="account",
            options={"verify_exp": True} # Bắt buộc token phải còn hạn
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn!")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Token không hợp lệ: {str(e)}")

# 3. Route API cần bảo vệ (Protected Route)
@app.get("/api/protected")
def protected_route(user_data: dict = Depends(verify_token)):
    # Nếu code chạy được xuống đây, nghĩa là Token hợp lệ 100%
    return {
        "message": "Truy cập thành công với Token hợp lệ!",
        "status": 200,
        "user_id": user_data.get("sub") # Trích xuất ID người dùng từ token
    }