from tests.security.helpers import make_token, make_alg_none_token

PROTECTED = "/api/protected"


def _auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def test_smoke_valid_token(client):
    """Smoke: token hợp lệ phải qua được — để chứng minh setup đúng."""
    r = client.get(PROTECTED, headers=_auth(make_token()))
    assert r.status_code == 200, r.text


def test_sec01_forgery_wrong_key(client):
    # SEC-01: JWT forgery — attacker ký bằng key không nằm trong JWKS
    tok = make_token(secret="attacker-secret-key-not-in-jwks")
    r = client.get(PROTECTED, headers=_auth(tok))
    assert r.status_code == 401


def test_sec02_alg_none_downgrade(client):
    # SEC-02: alg=none downgrade — verifier whitelist không có "none"
    r = client.get(PROTECTED, headers=_auth(make_alg_none_token()))
    assert r.status_code == 401


def test_sec04_expired_token(client):
    # SEC-04: Token hết hạn (exp ở quá khứ)
    tok = make_token(exp_offset=-60)
    r = client.get(PROTECTED, headers=_auth(tok))
    assert r.status_code == 401


def test_sec05_wrong_audience(client):
    # SEC-05: aud sai
    tok = make_token(aud="wrong-audience")
    r = client.get(PROTECTED, headers=_auth(tok))
    assert r.status_code == 401


def test_sec06_wrong_issuer(client):
    # SEC-06: iss sai
    tok = make_token(iss="http://evil.example.com/realms/fake")
    r = client.get(PROTECTED, headers=_auth(tok))
    assert r.status_code == 401