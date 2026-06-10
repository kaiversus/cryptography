"""Smoke test cho /metrics endpoint và custom counters."""
from tests.conftest import make_token


def test_metrics_endpoint_exposes_counters(client):
    # Gọi 1 protected pass, 1 protected fail để counter có giá trị
    token = make_token(sub="metric-user")
    client.get("/api/protected", headers={"Authorization": f"Bearer {token}"})
    client.get("/api/protected", headers={"Authorization": "Bearer not.a.jwt"})

    r = client.get("/metrics")
    assert r.status_code == 200
    body = r.text
    assert "auth_success_total" in body
    assert "auth_failures_total" in body
    assert 'method="jwt"' in body


def test_metrics_no_auth_required(client):
    # /metrics nằm ngoài /api/protected nên không bị JWT middleware chặn
    r = client.get("/metrics")
    assert r.status_code == 200
