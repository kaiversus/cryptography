"""Locust load test — 200 user mô phỏng tải hỗn hợp lên Gateway (C-D10).

3 loại traffic theo trọng số thực tế:
- public  (1): GET /api/public  — không auth.
- protected(3): GET /api/protected — Bearer JWT (token thật từ Keycloak).
- service (2): POST /api/service — ký HMAC-SHA256 lại MỖI request (nonce mới),
  nên không dính replay-protection → đo throughput HMAC chuẩn xác.

Chạy:
    # Lấy token thật: client_credentials từ Keycloak, export ra env.
    export GATEWAY_JWT="<access_token>"
    locust -f benchmarks/scripts/locustfile.py --host http://localhost:8000 \
           --users 200 --spawn-rate 20 --run-time 2m --headless \
           --csv benchmarks/results/locust_mixed

Web UI: bỏ --headless rồi mở http://localhost:8089.
"""
import os
import sys
import time
import uuid

from locust import HttpUser, task, between

# Ký HMAC bằng đúng hàm của Gateway để chữ ký luôn khớp verifier.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from gateway.crypto.hmac_verifier import compute_signature

JWT = os.getenv("GATEWAY_JWT", "")
HMAC_KEY_ID = os.getenv("HMAC_KEY_ID", "dev-key-01")
HMAC_SECRET = os.getenv("HMAC_SECRET", "dev-shared-secret").encode()
SERVICE_BODY = b'{"id":1}'


def _hmac_headers(host: str) -> dict:
    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())
    signed = {"host": host, "x-key-id": HMAC_KEY_ID, "x-nonce": nonce, "x-timestamp": ts}
    sig = compute_signature("POST", "/api/service", "", signed, SERVICE_BODY, HMAC_SECRET)
    return {
        "Host": host,
        "Content-Type": "application/json",
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Key-Id": HMAC_KEY_ID,
        "X-Signature": sig,
    }


class GatewayUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task(1)
    def public(self):
        self.client.get("/api/public", name="GET /api/public")

    @task(3)
    def protected(self):
        headers = {"Authorization": f"Bearer {JWT}"} if JWT else {}
        self.client.get("/api/protected", headers=headers, name="GET /api/protected")

    @task(2)
    def service_hmac(self):
        host = self.host.replace("http://", "").replace("https://", "")
        self.client.post(
            "/api/service",
            data=SERVICE_BODY,
            headers=_hmac_headers(host),
            name="POST /api/service",
        )
