"""Kịch bản DEMO trực tiếp cho team & thầy xem — chạy 1 lệnh ra toàn bộ kết quả.

Driver tự động: lấy token thật từ Keycloak, lần lượt diễn 7 cảnh (JWT pass/fail,
HMAC pass/replay/tamper, revocation, rate-limit, observability) và in PASS/FAIL
rõ ràng kèm bảng tổng kết.

YÊU CẦU: stack đang chạy -> `cd infra && docker compose up -d` (đợi mọi service Up).

CHẠY:
    python scripts/demo.py
    # tuỳ chỉnh:
    GATEWAY_URL=http://localhost:8000 KEYCLOAK_URL=http://localhost:8081 python scripts/demo.py

Lưu ý: chạy lại trong vòng 1 phút có thể dính rate-limit của cảnh trước —
đợi ~60s giữa 2 lần demo cho sạch số liệu.
"""
import os
import sys
import time
import uuid
import base64
import json

# Console Windows mặc định cp1252 -> ép UTF-8 để in tiếng Việt.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):  # pragma: no cover
    pass

import httpx
from jose import jwt as jose_jwt

# compute_signature thật của Gateway -> chữ ký HMAC luôn khớp verifier.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from gateway.crypto.hmac_verifier import compute_signature

GATEWAY = os.getenv("GATEWAY_URL", "http://localhost:8000").rstrip("/")
KEYCLOAK = os.getenv("KEYCLOAK_URL", "http://localhost:8081").rstrip("/")
REALM = os.getenv("REALM", "nt219")
CLIENT_ID = os.getenv("CLIENT_ID", "service-account")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "CaXVcmwkeRNHP5lls0pTL8BPbFLD0Bo5")

HMAC_KEY_ID = "dev-key-01"
HMAC_SECRET = b"dev-shared-secret"
HOST = GATEWAY.replace("http://", "").replace("https://", "")

RESULTS: list[tuple[str, str, bool]] = []  # (scene, detail, ok)


# ----------------------------- helpers -----------------------------
def banner(title: str) -> None:
    print("\n" + "=" * 68)
    print(f"  {title}")
    print("=" * 68)


def check(scene: str, desc: str, expected, actual) -> bool:
    ok = expected == actual
    mark = "[PASS]" if ok else "[FAIL]"
    print(f"  {mark} {desc}\n         kỳ vọng={expected}  thực tế={actual}")
    RESULTS.append((scene, desc, ok))
    return ok


def hmac_headers(body: bytes, ts: int | None = None, nonce: str | None = None) -> dict:
    ts = str(ts if ts is not None else int(time.time()))
    nonce = nonce or str(uuid.uuid4())
    signed = {"host": HOST, "x-key-id": HMAC_KEY_ID, "x-nonce": nonce, "x-timestamp": ts}
    sig = compute_signature("POST", "/api/service", "", signed, body, HMAC_SECRET)
    return {
        "Host": HOST, "Content-Type": "application/json",
        "X-Timestamp": ts, "X-Nonce": nonce, "X-Key-Id": HMAC_KEY_ID, "X-Signature": sig,
    }


def make_alg_none(real_payload: dict) -> str:
    def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f'{b64({"alg": "none", "typ": "JWT"})}.{b64(real_payload)}.'


# ----------------------------- scenes -----------------------------
def get_token(c: httpx.Client) -> str | None:
    try:
        r = c.post(
            f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
            data={"grant_type": "client_credentials",
                  "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
            timeout=10.0,
        )
        if r.status_code == 200:
            return r.json()["access_token"]
        print(f"  [WARN] không lấy được token ({r.status_code}): {r.text[:120]}")
    except Exception as e:
        print(f"  [WARN] Keycloak không truy cập được: {e}")
    return None


def scene0_preflight(c: httpx.Client) -> bool:
    banner("CẢNH 0 — Pre-flight: hạ tầng có sống không?")
    try:
        r = c.get(f"{GATEWAY}/health", timeout=5.0)
        return check("0", "GET /health (Gateway up)", 200, r.status_code)
    except Exception as e:
        print(f"  [FAIL] Gateway không truy cập được tại {GATEWAY}: {e}")
        print("         -> Hãy chạy: cd infra && docker compose up -d")
        RESULTS.append(("0", "Gateway reachable", False))
        return False


def scene1_jwt_ok(c: httpx.Client, token: str | None):
    banner("CẢNH 1 — JWT hợp lệ (ES256) đi qua Gateway")
    if not token:
        print("  [SKIP] chưa có token thật (Keycloak chưa sẵn sàng).")
        return
    r = c.get(f"{GATEWAY}/api/protected", headers={"Authorization": f"Bearer {token}"})
    check("1", "GET /api/protected với Bearer token thật", 200, r.status_code)
    if r.status_code == 200:
        print(f"         payload: {r.json()}")


def scene2_jwt_attacks(c: httpx.Client, token: str | None):
    banner("CẢNH 2 — Tấn công JWT đều bị chặn (SEC-01/02 + tamper + missing)")
    P = f"{GATEWAY}/api/protected"

    r = c.get(P)  # missing bearer
    check("2", "Không có Bearer header", 401, r.status_code)

    forged = jose_jwt.encode({"sub": "attacker", "iss": "x", "aud": "account",
                              "iat": int(time.time()), "exp": int(time.time()) + 300},
                             "attacker-key-not-in-jwks", algorithm="HS256",
                             headers={"kid": "x"})
    r = c.get(P, headers={"Authorization": f"Bearer {forged}"})
    check("2", "SEC-01: token giả ký bằng key lạ", 401, r.status_code)

    none_tok = make_alg_none({"sub": "attacker", "aud": "account",
                              "iat": int(time.time()), "exp": int(time.time()) + 300})
    r = c.get(P, headers={"Authorization": f"Bearer {none_tok}"})
    check("2", "SEC-02: alg=none downgrade", 401, r.status_code)

    if token:
        tampered = token[:-2] + ("A" if token[-1] != "A" else "B")
        r = c.get(P, headers={"Authorization": f"Bearer {tampered}"})
        check("2", "Token thật bị sửa chữ ký", 401, r.status_code)


def scene3_hmac(c: httpx.Client):
    banner("CẢNH 3 — HMAC request signing: hợp lệ → replay → tamper")
    S = f"{GATEWAY}/api/service"
    body = b'{"id":1}'

    h = hmac_headers(body)
    r1 = c.post(S, content=body, headers=h)
    check("3", "Ký HMAC hợp lệ", 200, r1.status_code)

    r2 = c.post(S, content=body, headers=h)  # gửi lại y hệt
    check("3", "SEC-07: replay cùng nonce", 401, r2.status_code)

    h2 = hmac_headers(body)  # nonce mới, nhưng đổi body
    r3 = c.post(S, content=b'{"id":999}', headers=h2)
    check("3", "SEC-09: sửa body giữ chữ ký", 401, r3.status_code)

    h3 = hmac_headers(body, ts=int(time.time()) - 1000)  # timestamp cũ
    r4 = c.post(S, content=body, headers=h3)
    check("3", "SEC-08: timestamp ngoài cửa sổ 300s", 401, r4.status_code)


def scene4_revocation(c: httpx.Client, token: str | None):
    banner("CẢNH 4 — Thu hồi token tức thời (SEC-10, jti blacklist)")
    if not token:
        print("  [SKIP] cần token thật.")
        return
    auth = {"Authorization": f"Bearer {token}"}
    r = c.post(f"{GATEWAY}/auth/revoke", headers=auth)
    check("4", "POST /auth/revoke", 200, r.status_code)
    if r.status_code == 200:
        print(f"         {r.json()}")
    r2 = c.get(f"{GATEWAY}/api/protected", headers=auth)
    check("4", "Gọi lại /api/protected bằng token đã revoke", 401, r2.status_code)


def scene5_rate_limit(c: httpx.Client):
    banner("CẢNH 5 — Rate limit (/api/public: 10 req/phút)")
    codes = []
    for _ in range(12):
        codes.append(c.get(f"{GATEWAY}/api/public").status_code)
    got_429 = 429 in codes
    print(f"         12 lần gọi -> mã trả về: {codes}")
    check("5", "Có request bị chặn 429 sau ngưỡng", True, got_429)


def scene6_observability(c: httpx.Client):
    banner("CẢNH 6 — Observability: tạo dữ liệu cho dashboard")
    for i in range(5):
        c.get(f"{GATEWAY}/api/protected", headers={"Authorization": f"Bearer bad.token.{i}"})
    r = c.get(f"{GATEWAY}/metrics")
    has_metric = "auth_failures_total" in r.text
    check("6", "/metrics expose auth_failures_total", True, has_metric)
    print("         Mở để trình chiếu:")
    print("           - Grafana   : http://localhost:3001  (panel Auth Failures nhảy số)")
    print("           - Jaeger    : http://localhost:16686 (trace có auth.* attributes)")
    print("           - Prometheus: http://localhost:9090/targets (gateway UP)")


def scene7_authz(c: httpx.Client, token: str | None):
    banner("CẢNH 7 — Chống leo thang quyền (SEC-11, /api/admin chỉ cho role admin)")
    if not token:
        print("  [SKIP] cần token thật.")
        return
    # Token client_credentials thường KHÔNG có role admin -> phải bị 403 (authz),
    # khác với 401 (authn). Đây là vector 6: user hợp lệ gọi endpoint admin.
    r = c.get(f"{GATEWAY}/api/admin", headers={"Authorization": f"Bearer {token}"})
    check("7", "SEC-11: token thiếu role admin gọi /api/admin -> 403", 403, r.status_code)
    if r.status_code == 403:
        print(f"         {r.json()}")


def scene8_audit(c: httpx.Client):
    banner("CẢNH 8 — Sổ audit chống chối bỏ (SEC-13, MT-NONREP)")
    body = b'{"id":1}'
    # 1 request hợp lệ (allow) + 1 request tamper (deny) -> cả hai phải vào sổ.
    c.post(f"{GATEWAY}/api/service", content=body, headers=hmac_headers(body))
    c.post(f"{GATEWAY}/api/service", content=b'{"id":999}', headers=hmac_headers(body))
    r = c.get(f"{GATEWAY}/audit/recent?limit=10")
    recs = r.json().get("records", []) if r.status_code == 200 else []
    has_allow = any(x["actor"] == "dev-key-01" and x["decision"] == "allow" for x in recs)
    has_deny = any(x["actor"] == "dev-key-01" and x["decision"] == "deny" for x in recs)
    check("8", "Audit ghi cả allow lẫn deny kèm danh tính dev-key-01", True,
          has_allow and has_deny)
    for x in recs[-4:]:
        print(f"         {x['ts']} {x['channel']} actor={x['actor']} "
              f"{x['decision']} {x.get('reason', '')}")


def summary() -> int:
    banner("TỔNG KẾT")
    passed = sum(1 for *_, ok in RESULTS if ok)
    total = len(RESULTS)
    for scene, desc, ok in RESULTS:
        print(f"  [{'PASS' if ok else 'FAIL'}] (cảnh {scene}) {desc}")
    print("-" * 68)
    print(f"  KẾT QUẢ: {passed}/{total} bước đạt kỳ vọng.")
    return 0 if passed == total else 1


def main() -> int:
    print(f"Gateway = {GATEWAY} | Keycloak = {KEYCLOAK} | realm = {REALM}")
    with httpx.Client(timeout=10.0) as c:
        if not scene0_preflight(c):
            return summary()
        token = get_token(c)
        scene1_jwt_ok(c, token)
        scene2_jwt_attacks(c, token)
        scene3_hmac(c)
        scene4_revocation(c, token)
        scene5_rate_limit(c)
        scene6_observability(c)
        # Cảnh 4 đã thu hồi `token` -> lấy token mới (jti khác) cho cảnh authz,
        # nếu không sẽ dính 401 revoked thay vì 403 thiếu quyền.
        scene7_authz(c, get_token(c))
        scene8_audit(c)
    return summary()


if __name__ == "__main__":
    raise SystemExit(main())
