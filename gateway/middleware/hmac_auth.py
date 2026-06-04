import redis
from fastapi import Request
from fastapi.responses import JSONResponse
from crypto.hmac_verifier import verify_hmac_signature, HMACInvalid

SERVICE_PREFIX = "/api/service"

# Kết nối tới container Redis qua hostname 'redis' nội bộ Docker
# Cấu hình decode_responses=True để nhận về chuỗi string thay vì dạng bytes
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

async def hmac_auth_middleware(request: Request, call_next):
    if request.url.path.startswith(SERVICE_PREFIX):
        # 1. Trích xuất các tham số bảo mật từ Header
        signature = request.headers.get("X-Signature")
        timestamp = request.headers.get("X-Timestamp")
        nonce = request.headers.get("X-Nonce")
        
        if not all([signature, timestamp, nonce]):
            return JSONResponse(
                status_code=401, 
                content={"detail": "Missing HMAC security headers (X-Signature, X-Timestamp, X-Nonce)"}
            )
            
        # 2. CHỐNG REPLAY ATTACK: Kiểm tra Nonce trong Redis
        # Nếu nonce đã tồn tại tức là kẻ tấn công đang gửi lại gói tin cũ
        if redis_client.exists(f"nonce:{nonce}"):
            return JSONResponse(
                status_code=401, 
                content={"detail": "Replay attack detected! Nonce already used."}
            )
            
        try:
            # 3. Xác thực chữ ký mật mã
            verify_hmac_signature(timestamp, nonce, signature)
            
            # 4. Nếu hợp lệ, lưu Nonce vào Redis kèm thời gian sống (TTL = 5 phút)
            # Hết 5 phút Nonce tự xóa vì lúc này Timestamp của request cũng đã hết hạn
            redis_client.setex(f"nonce:{nonce}", 300, "used")
            
        except HMACInvalid as e:
            return JSONResponse(status_code=401, content={"detail": str(e)})
            
    return await call_next(request)