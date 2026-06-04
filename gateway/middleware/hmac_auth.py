import os
import redis
from fastapi import Request
from fastapi.responses import JSONResponse
from crypto.hmac_verifier import verify_hmac_request, HMACInvalid

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
        return JSONResponse(status_code=401, content={"detail": str(e)})

    return await call_next(request)