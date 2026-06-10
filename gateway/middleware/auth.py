from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.crypto.jwt_verifier import verify_token, TokenInvalid
from gateway.storage.revocation import is_revoked
from gateway.observability.metrics import record_failure, record_success

PROTECTED_PREFIX = "/api/protected"


async def jwt_auth_middleware(request: Request, call_next):
    if request.url.path.startswith(PROTECTED_PREFIX):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            record_failure("jwt", "missing_bearer")
            return JSONResponse(status_code=401, content={"detail": "missing bearer"})
        try:
            payload = verify_token(auth[7:])
        except TokenInvalid as e:
            record_failure("jwt", "invalid_token")
            return JSONResponse(status_code=401, content={"detail": f"invalid token: {e}"})

        jti = payload.get("jti")
        if jti and is_revoked(jti):
            record_failure("jwt", "token_revoked")
            return JSONResponse(status_code=401, content={"detail": "token revoked"})

        record_success("jwt")
        request.state.user = payload

    return await call_next(request)
