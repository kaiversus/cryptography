import pytest
from fastapi.testclient import TestClient

import gateway.crypto.jwt_verifier as jv
import middleware.hmac_auth as hmac_auth_module
from gateway.main import app
from tests.security.helpers import TEST_PUBLIC_KEY


class FakeRedis:
    """In-memory replacement cho redis_client trong unit test."""
    def __init__(self):
        self.store = {}
    def exists(self, key):
        return 1 if key in self.store else 0
    def setex(self, key, ttl, value):
        self.store[key] = value


@pytest.fixture(autouse=True)
def mock_jwks(monkeypatch):
    monkeypatch.setattr(jv, "_get_jwks", lambda: {"keys": [TEST_PUBLIC_KEY]})


@pytest.fixture(autouse=True)
def mock_redis(monkeypatch):
    """Thay redis client thật bằng in-memory fake, reset mỗi test."""
    fake = FakeRedis()
    monkeypatch.setattr(hmac_auth_module, "redis_client", fake)
    return fake


@pytest.fixture(scope="session")
def client():
    return TestClient(app)