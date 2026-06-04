"""HMAC-SHA256 request signing verifier — spec gateway-internal/v1.

Spec reference: docs/hmac-signing-spec.md
Style: AWS SigV4-simplified (bỏ derive signing key, thêm nonce store).
"""
import hashlib
import hmac
import re
import time
from typing import Mapping

ALGORITHM = "HMAC-SHA256"
SCOPE = "gateway-internal/v1"
TIMESTAMP_WINDOW = 300
NONCE_TTL = 600
EMPTY_BODY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Secret store. TODO B-D6: thay bằng Vault lookup.
_SECRETS = {
    "dev-key-01": b"dev-shared-secret",
}

_UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class HMACInvalid(Exception):
    """Raised khi request không qua được HMAC verification."""


def _build_canonical_request(method, path, query, signed_headers_values, body):
    sorted_keys = sorted(signed_headers_values.keys())
    canonical_headers = "".join(
        f"{k}:{signed_headers_values[k].strip()}\n" for k in sorted_keys
    )
    signed_headers = ";".join(sorted_keys)
    body_hash = hashlib.sha256(body).hexdigest() if body else EMPTY_BODY_HASH
    return (
        method.upper() + "\n"
        + path + "\n"
        + query + "\n"
        + canonical_headers
        + "\n"
        + signed_headers + "\n"
        + body_hash
    )


def _build_string_to_sign(ts, canonical_request):
    canonical_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
    return f"{ALGORITHM}\n{ts}\n{SCOPE}\n{canonical_hash}"


def compute_signature(method, path, query, signed_headers_values, body, secret):
    """Pure function dùng được cho cả client và server."""
    canonical = _build_canonical_request(method, path, query, signed_headers_values, body)
    sts = _build_string_to_sign(signed_headers_values["x-timestamp"], canonical)
    return hmac.new(secret, sts.encode(), hashlib.sha256).hexdigest()


def verify_hmac_request(method, path, query, headers, body, nonce_store):
    """Verify HMAC request, raise HMACInvalid nếu sai. Theo 10 bước trong spec."""
    h = {k.lower(): v for k, v in headers.items()}

    # 1. Parse 4 header
    try:
        ts = h["x-timestamp"]
        nonce = h["x-nonce"]
        key_id = h["x-key-id"]
        signature = h["x-signature"]
    except KeyError as e:
        raise HMACInvalid(f"missing_header: {e.args[0]}")

    # 2. Validate format
    if not ts.isdigit():
        raise HMACInvalid("invalid_format: timestamp")
    if not _UUID_V4_RE.match(nonce):
        raise HMACInvalid("invalid_format: nonce")
    if not _HEX64_RE.match(signature):
        raise HMACInvalid("invalid_format: signature")

    # 3. Timestamp window
    if abs(int(time.time()) - int(ts)) > TIMESTAMP_WINDOW:
        raise HMACInvalid("invalid_timestamp")

    # 4. Nonce check
    nonce_key = f"nonce:{nonce}"
    if nonce_store.exists(nonce_key):
        raise HMACInvalid("replay_detected")

    # 5. Secret lookup
    secret = _SECRETS.get(key_id)
    if secret is None:
        raise HMACInvalid("unknown_key")

    # 6-8. Recompute signature
    signed_headers_values = {
        "host": h.get("host", ""),
        "x-key-id": key_id,
        "x-nonce": nonce,
        "x-timestamp": ts,
    }
    expected = compute_signature(method, path, query, signed_headers_values, body, secret)

    # 9. Constant-time compare
    if not hmac.compare_digest(expected, signature):
        raise HMACInvalid("invalid_signature")

    # 10. SET nonce sau khi pass tất cả
    nonce_store.setex(nonce_key, NONCE_TTL, "1")