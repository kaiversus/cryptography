"""Client demo HMAC request signing — ký theo ĐÚNG spec gateway-internal/v1.

(Bản cũ dùng sơ đồ ký lỗi thời `timestamp.nonce`, thiếu X-Key-Id nên bị Gateway
từ chối. Bản này ký bằng chính hàm compute_signature của Gateway.)

Demo 3 pha: (1) request hợp lệ → 200, (2) replay cùng nonce → 401,
(3) sửa body giữ chữ ký → 401.

Chạy (cần stack up):  python clients/test_hmac.py
"""
import os
import sys
import time
import uuid

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from gateway.crypto.hmac_verifier import compute_signature

URL = os.getenv("GATEWAY_URL", "http://localhost:8000") + "/api/service"
HOST = URL.replace("http://", "").replace("https://", "").split("/")[0]
KEY_ID = "dev-key-01"
SECRET = b"dev-shared-secret"
BODY = b'{"id":1}'


def sign(body: bytes, nonce: str, ts: str) -> dict:
    signed = {"host": HOST, "x-key-id": KEY_ID, "x-nonce": nonce, "x-timestamp": ts}
    sig = compute_signature("POST", "/api/service", "", signed, body, SECRET)
    return {
        "Host": HOST, "Content-Type": "application/json",
        "X-Timestamp": ts, "X-Nonce": nonce, "X-Key-Id": KEY_ID, "X-Signature": sig,
    }


def main() -> None:
    nonce = str(uuid.uuid4())
    ts = str(int(time.time()))
    headers = sign(BODY, nonce, ts)

    with httpx.Client(timeout=10.0) as c:
        print("=== PHA 1: request HỢP LỆ (lần đầu) ===")
        r1 = c.post(URL, content=BODY, headers=headers)
        print(f"  HTTP {r1.status_code} | {r1.text}  (kỳ vọng 200)\n")

        print("=== PHA 2: REPLAY (gửi lại y hệt) ===")
        r2 = c.post(URL, content=BODY, headers=headers)
        print(f"  HTTP {r2.status_code} | {r2.text}  (kỳ vọng 401 replay)\n")

        print("=== PHA 3: TAMPER body (nonce mới, đổi body) ===")
        h3 = sign(BODY, str(uuid.uuid4()), str(int(time.time())))
        r3 = c.post(URL, content=b'{"id":999}', headers=h3)
        print(f"  HTTP {r3.status_code} | {r3.text}  (kỳ vọng 401 invalid_signature)")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    main()
