"""Sinh benchmarks/scripts/hmac.lua với chữ ký HMAC hợp lệ tại thời điểm chạy.

wrk/LuaJIT không tính được HMAC-SHA256 per-request, nên ta precompute 1 request
hợp lệ bằng đúng hàm verifier của Gateway rồi ghi vào hmac.lua.

LƯU Ý: nonce dùng-một-lần + cửa sổ timestamp 300s nên file này CHỈ hợp lệ cho
request đầu tiên trong vòng 5 phút. Để đo throughput HMAC thực sự (mọi request
200), dùng Locust (`benchmarks/scripts/locustfile.py`) — Locust ký lại mỗi request.

Chạy:
    python benchmarks/scripts/gen_hmac_lua.py
    wrk -t4 -c100 -d10s -s benchmarks/scripts/hmac.lua http://localhost:8000
"""
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from gateway.crypto.hmac_verifier import compute_signature  # noqa: E402

PATH = "/api/service"
BODY = b'{"id":1}'
KEY_ID = "dev-key-01"
SECRET = b"dev-shared-secret"
HOST = os.getenv("WRK_HOST", "localhost:8000")


def main() -> None:
    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())
    signed = {"host": HOST, "x-key-id": KEY_ID, "x-nonce": nonce, "x-timestamp": ts}
    sig = compute_signature("POST", PATH, "", signed, BODY, SECRET)

    lua = f'''-- AUTO-GENERATED bởi gen_hmac_lua.py lúc {time.ctime()}
-- Chỉ hợp lệ cho request ĐẦU TIÊN trong 300s (nonce dùng-một-lần).
-- Throughput HMAC chuẩn: dùng locustfile.py.
wrk.method = "POST"
wrk.body   = '{BODY.decode()}'
wrk.headers["Host"]        = "{HOST}"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["X-Timestamp"] = "{ts}"
wrk.headers["X-Nonce"]     = "{nonce}"
wrk.headers["X-Key-Id"]    = "{KEY_ID}"
wrk.headers["X-Signature"] = "{sig}"
wrk.path = "{PATH}"
'''
    out = os.path.join(os.path.dirname(__file__), "hmac.lua")
    with open(out, "w", encoding="utf-8") as f:
        f.write(lua)
    print(f"[OK] wrote {out}")
    print(f"     ts={ts} nonce={nonce}")


if __name__ == "__main__":
    main()
