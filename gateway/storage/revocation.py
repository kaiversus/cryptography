# file: storage/revocation.py
import os
import redis
import time

# Lấy URL kết nối Redis từ biến môi trường (đã có trong docker-compose.yml)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
r = redis.from_url(REDIS_URL, decode_responses=True)

PREFIX = "revoked_jti:"

def revoke(jti: str, exp: int) -> None:
    """Đưa jti vào blacklist của Redis với thời gian sống (TTL) vừa đủ"""
    ttl = max(1, exp - int(time.time()))
    r.setex(PREFIX + jti, ttl, "1")

def is_revoked(jti: str) -> bool:
    """Kiểm tra token có nằm trong blacklist không"""
    return r.exists(PREFIX + jti) == 1