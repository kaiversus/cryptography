"""SEC-13 (R1-IG / MT-NONREP): chống chối bỏ bằng audit trail.

Vector: một service M2M gửi request rồi chối "tôi không gửi" → không quy
trách nhiệm được. Phòng thủ: mọi quyết định xác thực được ghi vào sổ audit
kèm danh tính người gọi (X-Key-Id với HMAC, sub/jti với JWT). Có sổ này thì
service không thể chối — danh tính của nó đã nằm trong bản ghi.
"""
from gateway.observability import audit
from tests.security.helpers import sign_hmac


def test_sec13_audit_records_allowed_request(client):
    body = b'{"id":1}'
    headers = sign_hmac(body=body)

    before = len(audit.RECENT_AUDIT)
    r = client.post("/api/service", content=body, headers=headers)
    new = list(audit.RECENT_AUDIT)[before:]

    assert r.status_code == 200
    # Sổ audit phải ghi key-id của service + quyết định "allow"
    assert any(rec["actor"] == "dev-key-01" and rec["decision"] == "allow"
               for rec in new), new


def test_sec13_audit_records_denied_request(client):
    # Ký body A nhưng gửi body B (tamper) → bị từ chối, nhưng VẪN phải vào sổ
    headers = sign_hmac(body=b'{"id":1}')

    before = len(audit.RECENT_AUDIT)
    r = client.post("/api/service", content=b'{"id":999}', headers=headers)
    new = list(audit.RECENT_AUDIT)[before:]

    assert r.status_code == 401
    # Hành vi xấu cũng bị ghi lại kèm danh tính → không thể chối
    assert any(rec["actor"] == "dev-key-01" and rec["decision"] == "deny"
               for rec in new), new
