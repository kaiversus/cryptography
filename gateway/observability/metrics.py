"""Custom Prometheus metrics cho gateway.

Phân biệt 2 tầng:
- auth_failures_total: đếm từng lần auth fail, label theo method (jwt|hmac) và
  reason (missing_bearer, invalid_signature, replay_detected, token_revoked, …).
- auth_success_total: đếm pass — dùng tính tỉ lệ thất bại theo identity.
"""
from prometheus_client import Counter


AUTH_FAILURES = Counter(
    "auth_failures_total",
    "Total authentication failures at the gateway.",
    ["method", "reason"],
)

AUTH_SUCCESS = Counter(
    "auth_success_total",
    "Total authentication successes at the gateway.",
    ["method"],
)


def record_failure(method: str, reason: str) -> None:
    AUTH_FAILURES.labels(method=method, reason=reason).inc()


def record_success(method: str) -> None:
    AUTH_SUCCESS.labels(method=method).inc()
