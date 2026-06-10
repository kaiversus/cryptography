"""Auth admin routes: revoke active access tokens by jti."""
from fastapi import APIRouter, Header, HTTPException

from gateway.crypto.jwt_verifier import verify_token, TokenInvalid
from gateway.storage.revocation import revoke, is_revoked


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/revoke")
def revoke_token(authorization: str | None = Header(None)):
    """Revoke chính token đang gửi kèm Bearer header.

    Trả 200 luôn nếu token đã từng bị revoke (idempotent), 401 nếu token sai.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer")
    token = authorization[7:]
    try:
        payload = verify_token(token)
    except TokenInvalid as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}")

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        raise HTTPException(status_code=400, detail="token missing jti or exp")

    if is_revoked(jti):
        return {"status": "already_revoked", "jti": jti}

    ttl = revoke(jti, exp)
    return {"status": "revoked", "jti": jti, "ttl": ttl}
