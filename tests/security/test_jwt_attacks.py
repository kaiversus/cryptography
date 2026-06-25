from tests.security.helpers import make_token, make_alg_none_token
from gateway.storage import revocation as _revocation

PROTECTED = "/api/protected"
ADMIN = "/api/admin"


def _auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


class _RevokedStore:
    """Store coi mọi jti trong `revoked` là đã thu hồi."""
    def __init__(self, revoked: set[str]):
        self.revoked = revoked
    def setex(self, name, ttl, value): return True
    def exists(self, name):
        return 1 if name.removeprefix(_revocation.PREFIX) in self.revoked else 0
    def ttl(self, name): return -2


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


def test_sec11_privilege_escalation_no_role(client):
    # SEC-11 (E1-IG): token hợp lệ của user thường gọi endpoint admin -> 403.
    # Authentication pass (đúng chữ ký) nhưng authorization fail (thiếu role admin).
    tok = make_token()  # không có role "admin"
    r = client.get(ADMIN, headers=_auth(tok))
    assert r.status_code == 403, r.text
    assert "forbidden" in r.text.lower()


def test_sec11_admin_role_allowed(client):
    # Mặt còn lại: token có role admin thì vào được -> 200.
    tok = make_token(extra={"realm_access": {"roles": ["admin"]}})
    r = client.get(ADMIN, headers=_auth(tok))
    assert r.status_code == 200, r.text


def test_sec10_revoked_jti(client):
    # SEC-10: Token chữ ký hợp lệ nhưng jti đã nằm trong blacklist -> 401
    revoked_jti = "revoked-token-xyz"
    tok = make_token(extra={"jti": revoked_jti})
    # Trước khi revoke: token qua được.
    assert client.get(PROTECTED, headers=_auth(tok)).status_code == 200
    # Sau khi đẩy jti vào blacklist: cùng token bị chặn.
    _revocation.set_client(_RevokedStore({revoked_jti}))
    r = client.get(PROTECTED, headers=_auth(tok))
    assert r.status_code == 401
    assert "revoked" in r.text.lower()