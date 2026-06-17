"""HashiCorp Vault KV-v2 client với TTLCache.

Mặc định trỏ Vault dev mode (token tĩnh `dev-root-token`). Production sẽ thay
bằng AppRole hoặc Kubernetes auth method — chỉ cần đổi cách lấy token, lookup
logic giữ nguyên.
"""
import os
from typing import Any

import httpx
from cachetools import TTLCache


VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "dev-root-token")
VAULT_MOUNT = os.getenv("VAULT_MOUNT", "secret")
CACHE_TTL = int(os.getenv("VAULT_CACHE_TTL", "300"))

_cache: TTLCache = TTLCache(maxsize=64, ttl=CACHE_TTL)


class VaultError(Exception):
    """Lỗi khi đọc Vault — caller quyết định fail-closed hay fallback."""


def _kv_url(path: str) -> str:
    return f"{VAULT_ADDR.rstrip('/')}/v1/{VAULT_MOUNT}/data/{path.lstrip('/')}"


def get_secret(path: str, field: str = "value") -> str:
    """Đọc 1 field trong KV-v2 secret. Cache 5 phút."""
    cache_key = f"{path}::{field}"
    if cache_key in _cache:
        return _cache[cache_key]
    try:
        resp = httpx.get(
            _kv_url(path),
            headers={"X-Vault-Token": VAULT_TOKEN},
            timeout=3.0,
        )
        resp.raise_for_status()
        data = resp.json()["data"]["data"]
    except httpx.HTTPError as e:
        raise VaultError(f"vault_read_failed: {path}: {e}")
    except KeyError as e:
        raise VaultError(f"vault_bad_payload: missing {e}")
    if field not in data:
        raise VaultError(f"vault_field_missing: {field} in {path}")
    value = data[field]
    _cache[cache_key] = value
    return value


def get_secret_dict(path: str) -> dict[str, Any]:
    """Đọc toàn bộ KV-v2 secret. Cache 5 phút."""
    cache_key = f"{path}::__all__"
    if cache_key in _cache:
        return _cache[cache_key]
    try:
        resp = httpx.get(
            _kv_url(path),
            headers={"X-Vault-Token": VAULT_TOKEN},
            timeout=3.0,
        )
        resp.raise_for_status()
        data = resp.json()["data"]["data"]
    except httpx.HTTPError as e:
        raise VaultError(f"vault_read_failed: {path}: {e}")
    except KeyError as e:
        raise VaultError(f"vault_bad_payload: missing {e}")
    _cache[cache_key] = data
    return data


def clear_cache() -> None:
    """Cho test / rotation script gọi để force re-fetch."""
    _cache.clear()
