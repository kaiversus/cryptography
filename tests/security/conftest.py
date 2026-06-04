import pytest
from fastapi.testclient import TestClient

import gateway.crypto.jwt_verifier as jv
from gateway.main import app
from tests.security.helpers import TEST_PUBLIC_KEY


@pytest.fixture(autouse=True)
def mock_jwks(monkeypatch):
    """Patch _get_jwks để verifier dùng key test của mình, không gọi Keycloak."""
    monkeypatch.setattr(jv, "_get_jwks", lambda: {"keys": [TEST_PUBLIC_KEY]})


@pytest.fixture(scope="session")
def client():
    return TestClient(app)