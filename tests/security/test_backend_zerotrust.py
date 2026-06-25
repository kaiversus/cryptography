"""SEC-14 (E2-GB / MT-AUTHZ): backend KHÔNG được tin header gateway chuyển xuống.

Vector 8: gateway sau khi xác thực thường chuyển danh tính/quyền xuống backend
qua header (vd X-Role). Nếu backend tin header này VÔ ĐIỀU KIỆN, kẻ tấn công có
token user thường nhưng tự đặt thêm `X-Role: admin` để leo quyền.

Phòng thủ = "chốt 8 zero-trust": backend KHÔNG tin header trần, mà tự verify lại
token gốc và đọc quyền từ CLAIM ĐÃ KÝ. Test mô phỏng 2 backend để đối chiếu:
- naive_backend  : tin X-Role  -> bị lừa (chứng minh tại sao KHÔNG được làm vậy)
- zerotrust_backend: verify lại token -> chặn được đòn spoof header.

Lưu ý: PoC hiện chưa có service backend riêng. Đây là test NGUYÊN LÝ cho chốt 8,
dùng chính verify_token của gateway làm bước "backend kiểm lại".
"""
from gateway.crypto.jwt_verifier import verify_token, TokenInvalid
from tests.security.helpers import make_token


def naive_backend(headers: dict) -> bool:
    """Backend NGÂY THƠ: tin tuyệt đối header gateway chuyển xuống."""
    return headers.get("x-role") == "admin"


def zerotrust_backend(headers: dict) -> bool:
    """Backend ZERO-TRUST (chốt 8): bỏ qua header trần, verify lại token gốc,
    đọc role từ claim đã ký."""
    auth = headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return False
    try:
        claims = verify_token(auth[7:])
    except TokenInvalid:
        return False
    return "admin" in claims.get("realm_access", {}).get("roles", [])


def test_sec14_naive_backend_is_fooled_by_header_spoof():
    # Token user THƯỜNG (không role admin) + tự nhét X-Role: admin.
    user_token = make_token()  # không có realm_access.roles = admin
    spoof = {"authorization": f"Bearer {user_token}", "x-role": "admin"}

    # Backend ngây thơ bị lừa -> đây CHÍNH LÀ lỗ hổng, nên không được tin header.
    assert naive_backend(spoof) is True


def test_sec14_zerotrust_backend_blocks_header_spoof():
    user_token = make_token()  # user thường
    spoof = {"authorization": f"Bearer {user_token}", "x-role": "admin"}

    # Backend zero-trust đọc role từ token đã ký -> không thấy admin -> CHẶN.
    assert zerotrust_backend(spoof) is False


def test_sec14_zerotrust_backend_allows_real_admin():
    # Mặt còn lại: admin thật (role nằm trong token ĐÃ KÝ) -> cho qua.
    admin_token = make_token(extra={"realm_access": {"roles": ["admin"]}})
    headers = {"authorization": f"Bearer {admin_token}"}
    assert zerotrust_backend(headers) is True
