import time
from tests.security.helpers import sign_hmac

SERVICE = "/api/service"
BODY = b'{"id":1}'


def test_smoke_valid_hmac(client):
    """Smoke: request ký đúng → 200."""
    headers = sign_hmac(body=BODY)
    r = client.post(SERVICE, headers=headers, content=BODY)
    assert r.status_code == 200, r.text


def test_sec07_replay_same_nonce(client):
    # SEC-07: Gửi lại request với cùng nonce → 401 replay
    headers = sign_hmac(body=BODY)
    r1 = client.post(SERVICE, headers=headers, content=BODY)
    assert r1.status_code == 200
    r2 = client.post(SERVICE, headers=headers, content=BODY)
    assert r2.status_code == 401
    assert "replay" in r2.text.lower()


def test_sec08_timestamp_out_of_window(client):
    # SEC-08: Timestamp quá cũ (>300s) → 401
    old_ts = int(time.time()) - 1000
    headers = sign_hmac(body=BODY, ts=old_ts)
    r = client.post(SERVICE, headers=headers, content=BODY)
    assert r.status_code == 401
    assert "timestamp" in r.text.lower()


def test_sec09_body_tampering(client):
    # SEC-09: Ký body A, gửi body B → 401 invalid_signature
    headers = sign_hmac(body=b'{"id":1}')
    tampered = b'{"id":999}'
    r = client.post(SERVICE, headers=headers, content=tampered)
    assert r.status_code == 401
    assert "signature" in r.text.lower()


def test_unknown_key_id(client):
    # Bonus: X-Key-Id không tồn tại trong store → 401 unknown_key
    headers = sign_hmac(body=BODY, key_id="ghost-key")
    r = client.post(SERVICE, headers=headers, content=BODY)
    assert r.status_code == 401
    assert "unknown_key" in r.text.lower()