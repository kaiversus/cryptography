import time

from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.crypto.jwt_verifier import verify_token, TokenInvalid
from gateway.storage.revocation import is_revoked
from gateway.observability.metrics import record_failure, record_success
from gateway.observability.tracing import annotate_auth_span

PROTECTED_PREFIX = "/api/protected"


async def jwt_auth_middleware(request: Request, call_next):
    if request.url.path.startswith(PROTECTED_PREFIX):
        start = time.perf_counter()
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            record_failure("jwt", "missing_bearer")
            annotate_auth_span("jwt", "failure", reason="missing_bearer",
                               latency_ms=(time.perf_counter() - start) * 1000)
            return JSONResponse(status_code=401, content={"detail": "missing bearer"})
        try:
            payload = verify_token(auth[7:])
        except TokenInvalid as e:
            record_failure("jwt", "invalid_token")
            annotate_auth_span("jwt", "failure", reason="invalid_token",
                               latency_ms=(time.perf_counter() - start) * 1000)
            return JSONResponse(status_code=401, content={"detail": f"invalid token: {e}"})

        jti = payload.get("jti")
        if jti and is_revoked(jti):
            record_failure("jwt", "token_revoked")
            annotate_auth_span("jwt", "failure", reason="token_revoked",
                               user_id=payload.get("sub", ""),
                               latency_ms=(time.perf_counter() - start) * 1000)
            return JSONResponse(status_code=401, content={"detail": "token revoked"})

        record_success("jwt")
        annotate_auth_span("jwt", "success", user_id=payload.get("sub", ""),
                           latency_ms=(time.perf_counter() - start) * 1000)
        request.state.user = payload

    return await call_next(request)
