"""SEC-10: Revoked JWT (jti blacklist) — end-to-end qua TestClient.

Mock Redis bằng fakeredis-like in-memory dict để test không cần Redis chạy.
"""
import time

import pytest

from tests.conftest import make_token
from gateway.storage import revocation as rev


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, tuple[str, float]] = {}  # key → (value, expires_at)

    def setex(self, name, ttl, value):
        self.store[name] = (value, time.time() + int(ttl))
        return True

    def exists(self, name):
        v = self.store.get(name)
        if v is None:
            return 0
        if time.time() >= v[1]:
            del self.store[name]
            return 0
        return 1

    def ttl(self, name):
        v = self.store.get(name)
        if v is None:
            return -2
        return max(0, int(v[1] - time.time()))


@pytest.fixture(autouse=True)
def fake_redis():
    fake = _FakeRedis()
    rev.set_client(fake)
    yield fake
    rev.set_client(None)  # reset


def test_revoke_then_protected_returns_401(client):
    token = make_token(sub="alice", expires_in=300)

    # 1. Token còn hạn → 200
    r1 = client.get("/api/protected", headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 200

    # 2. Revoke
    r2 = client.post("/auth/revoke", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "revoked"
    assert r2.json()["ttl"] > 0

    # 3. Gọi lại bằng token vừa revoke → 401
    r3 = client.get("/api/protected", headers={"Authorization": f"Bearer {token}"})
    assert r3.status_code == 401
    assert "revoked" in r3.json()["detail"]


def test_revoke_is_idempotent(client):
    token = make_token(sub="bob", expires_in=300)
    r1 = client.post("/auth/revoke", headers={"Authorization": f"Bearer {token}"})
    r2 = client.post("/auth/revoke", headers={"Authorization": f"Bearer {token}"})
    assert r1.json()["status"] == "revoked"
    assert r2.json()["status"] == "already_revoked"


def test_revoke_invalid_token_returns_401(client):
    r = client.post("/auth/revoke", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_revoke_without_bearer_returns_401(client):
    r = client.post("/auth/revoke")
    assert r.status_code == 401


def test_ttl_matches_exp_minus_now(fake_redis):
    rev.revoke("test-jti", int(time.time()) + 120)
    ttl = fake_redis.ttl("revoked_jti:test-jti")
    assert 115 <= ttl <= 121
