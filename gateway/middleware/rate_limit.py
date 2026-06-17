import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI

# Kết nối thẳng tới container Redis đang chạy
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# Khởi tạo Limiter: Định danh user qua IP, lưu bộ đếm vào Redis
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=REDIS_URL,
    strategy="fixed-window"
)

def setup_rate_limit(app: FastAPI):
    # Nhúng bộ đếm vào ứng dụng FastAPI
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
