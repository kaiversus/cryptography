import time

from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.crypto.jwt_verifier import verify_token, TokenInvalid
from gateway.storage.revocation import is_revoked
from gateway.observability.metrics import record_failure, record_success
from gateway.observability.tracing import annotate_auth_span, checkpoint_span, mark_checkpoint
from gateway.observability.audit import record_audit

PROTECTED_PREFIX = "/api/protected"
# Route đòi quyền admin: xác thực xong còn phải có role "admin" mới được vào.
ADMIN_PREFIX = "/api/admin"
REQUIRED_ROLES = {ADMIN_PREFIX: "admin"}


async def jwt_auth_middleware(request: Request, call_next):
    if request.url.path.startswith((PROTECTED_PREFIX, ADMIN_PREFIX)):
        start = time.perf_counter()
        auth = request.headers.get("authorization", "")

        # Chốt [2] — có Bearer header & đúng định dạng?
        with checkpoint_span("jwt.check_bearer") as sp:
            if not auth.startswith("Bearer "):
                mark_checkpoint(sp, "fail", "missing_bearer")
                record_failure("jwt", "missing_bearer")
                annotate_auth_span("jwt", "failure", reason="missing_bearer",
                                   latency_ms=(time.perf_counter() - start) * 1000)
                return JSONResponse(status_code=401, content={"detail": "missing bearer"})

        # Chốt [6] — verify chữ ký JWT bằng khóa thật (AUTHENTICATION)
        with checkpoint_span("jwt.verify_signature") as sp:
            try:
                payload = verify_token(auth[7:])
            except TokenInvalid as e:
                mark_checkpoint(sp, "fail", "invalid_token")
                record_failure("jwt", "invalid_token")
                annotate_auth_span("jwt", "failure", reason="invalid_token",
                                   latency_ms=(time.perf_counter() - start) * 1000)
                return JSONResponse(status_code=401, content={"detail": f"invalid token: {e}"})

        jti = payload.get("jti")
        actor = payload.get("sub", "") or jti or "unknown"

        # Chốt — token có bị thu hồi (jti blacklist)?
        with checkpoint_span("jwt.check_revocation") as sp:
            if jti and is_revoked(jti):
                mark_checkpoint(sp, "fail", "token_revoked")
                record_failure("jwt", "token_revoked")
                annotate_auth_span("jwt", "failure", reason="token_revoked",
                                   user_id=payload.get("sub", ""),
                                   latency_ms=(time.perf_counter() - start) * 1000)
                record_audit(channel="jwt", actor=actor, decision="deny",
                             method=request.method, path=request.url.path,
                             reason="token_revoked")
                return JSONResponse(status_code=401, content={"detail": "token revoked"})

        # Chốt [7] — AUTHORIZATION. Đã biết "anh là ai", giờ kiểm "anh được làm gì".
        # Authentication trả 401, authorization trả 403 — hai tầng tách biệt.
        with checkpoint_span("jwt.check_authorization") as sp:
            for prefix, required_role in REQUIRED_ROLES.items():
                if request.url.path.startswith(prefix):
                    roles = payload.get("realm_access", {}).get("roles", [])
                    if required_role not in roles:
                        mark_checkpoint(sp, "fail", "insufficient_role")
                        record_failure("jwt", "insufficient_role")
                        annotate_auth_span("jwt", "failure", reason="insufficient_role",
                                           user_id=payload.get("sub", ""),
                                           latency_ms=(time.perf_counter() - start) * 1000)
                        record_audit(channel="jwt", actor=actor, decision="deny",
                                     method=request.method, path=request.url.path,
                                     reason="insufficient_role")
                        return JSONResponse(
                            status_code=403,
                            content={"detail": f"forbidden: requires role '{required_role}'"},
                        )

        record_success("jwt")
        annotate_auth_span("jwt", "success", user_id=payload.get("sub", ""),
                           latency_ms=(time.perf_counter() - start) * 1000)
        record_audit(channel="jwt", actor=actor, decision="allow",
                     method=request.method, path=request.url.path)
        request.state.user = payload

    return await call_next(request)
