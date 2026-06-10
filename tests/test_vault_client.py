"""Unit test cho Vault KV-v2 client. Mock httpx.get để không cần Vault chạy."""
import httpx
import pytest

from gateway.storage import vault_client as vc


@pytest.fixture(autouse=True)
def reset_cache():
    vc.clear_cache()
    yield
    vc.clear_cache()


def _mock_resp(status: int, payload: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        json=payload or {},
        request=httpx.Request("GET", "http://vault.test"),
    )


def test_get_secret_returns_value(monkeypatch):
    calls = {"n": 0}

    def fake_get(url, headers=None, timeout=None):
        calls["n"] += 1
        assert headers["X-Vault-Token"] == vc.VAULT_TOKEN
        assert "gateway/hmac/dev-key-01" in url
        return _mock_resp(200, {"data": {"data": {"value": "s3cret"}}})

    monkeypatch.setattr(vc.httpx, "get", fake_get)
    assert vc.get_secret("gateway/hmac/dev-key-01") == "s3cret"
    # Lần 2 dùng cache, không gọi httpx nữa
    assert vc.get_secret("gateway/hmac/dev-key-01") == "s3cret"
    assert calls["n"] == 1


def test_get_secret_field_missing_raises(monkeypatch):
    monkeypatch.setattr(
        vc.httpx, "get",
        lambda *a, **k: _mock_resp(200, {"data": {"data": {"other": "x"}}}),
    )
    with pytest.raises(vc.VaultError, match="vault_field_missing"):
        vc.get_secret("some/path", field="value")


def test_get_secret_http_error_raises(monkeypatch):
    def fake_get(*a, **k):
        return _mock_resp(403, {"errors": ["denied"]})
    monkeypatch.setattr(vc.httpx, "get", fake_get)
    with pytest.raises(vc.VaultError, match="vault_read_failed"):
        vc.get_secret("denied/path")


def test_clear_cache_forces_refetch(monkeypatch):
    calls = {"n": 0}
    def fake_get(*a, **k):
        calls["n"] += 1
        return _mock_resp(200, {"data": {"data": {"value": "v"}}})
    monkeypatch.setattr(vc.httpx, "get", fake_get)
    vc.get_secret("p")
    vc.clear_cache()
    vc.get_secret("p")
    assert calls["n"] == 2
