"""JWT revocation store backed by Redis.

Phương án: blacklist theo `jti` với TTL = exp - now để Redis tự dọn entry hết hạn.
Middleware JWT sau khi verify chữ ký phải gọi is_revoked(jti) trước khi cho qua.
"""
import os
import time
from typing import Protocol

import redis


PREFIX = "revoked_jti:"


class _RedisLike(Protocol):
    def setex(self, name: str, time: int, value: str) -> bool: ...
    def exists(self, name: str) -> int: ...
    def ttl(self, name: str) -> int: ...


_client: _RedisLike | None = None


def _get_client() -> _RedisLike:
    global _client
    if _client is None:
        _client = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=0,
            decode_responses=True,
        )
    return _client


def set_client(client: _RedisLike) -> None:
    """Inject Redis client for tests (monkeypatch)."""
    global _client
    _client = client


def revoke(jti: str, exp: int) -> int:
    """Đẩy jti vào blacklist với TTL = exp - now. Trả về TTL thực tế đã set."""
    ttl = max(1, int(exp) - int(time.time()))
    _get_client().setex(PREFIX + jti, ttl, "1")
    return ttl


def is_revoked(jti: str) -> bool:
    if not jti:
        return False
    return _get_client().exists(PREFIX + jti) == 1
