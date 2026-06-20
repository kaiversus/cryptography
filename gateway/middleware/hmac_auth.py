import os
import time

import redis
from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.crypto.hmac_verifier import verify_hmac_request, HMACInvalid
from gateway.observability.metrics import record_failure, record_success
from gateway.observability.tracing import annotate_auth_span

SERVICE_PREFIX = "/api/service"

# Cho phép override host bằng env (test có thể monkeypatch redis_client luôn)
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=0,
    decode_responses=True,
)


async def hmac_auth_middleware(request: Request, call_next):
    if not request.url.path.startswith(SERVICE_PREFIX):
        return await call_next(request)

    start = time.perf_counter()
    body = await request.body()
    try:
        verify_hmac_request(
            method=request.method,
            path=request.url.path,
            query=str(request.url.query),
            headers=dict(request.headers),
            body=body,
            nonce_store=redis_client,
        )
    except HMACInvalid as e:
        reason = str(e).split(":")[0]
        record_failure("hmac", reason)
        annotate_auth_span("hmac", "failure", reason=reason,
                           latency_ms=(time.perf_counter() - start) * 1000)
        return JSONResponse(status_code=401, content={"detail": str(e)})

    record_success("hmac")
    annotate_auth_span("hmac", "success",
                       user_id=request.headers.get("x-key-id", ""),
                       latency_ms=(time.perf_counter() - start) * 1000)
    return await call_next(request)
