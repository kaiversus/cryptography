# PROGRESS

## D6 — KMS + Observability (done solo)

### A-D6: Token revocation (jti blacklist Redis)
- `gateway/storage/revocation.py`: revoke(jti, exp) → setex; is_revoked(jti) → exists. TTL = exp - now.
- `gateway/routes/auth.py`: POST /auth/revoke — verify token, blacklist jti, idempotent.
- `gateway/middleware/auth.py`: check is_revoked() sau verify chữ ký.
- Test: `tests/test_revocation.py` (5/5 pass) — cover SEC-10 + idempotent + TTL + bearer missing.

### B-D6: Vault dev mode + vault_client.py
- `gateway/storage/vault_client.py`: KV-v2 read + TTLCache 5 phút, env override VAULT_ADDR/TOKEN/MOUNT.
- `gateway/crypto/hmac_verifier.py`: `_resolve_secret(key_id)` thử Vault → fallback dev. HMAC_REQUIRE_VAULT=1 để fail-closed prod.
- `infra/docker-compose.yml`: thêm vault dev + vault-seed (3 secret: hmac/dev-key-01, hmac/prod-key-01, hs256).
- Test: `tests/test_vault_client.py` (4/4 pass) — cache hit, field missing, HTTP error, clear_cache.

### C-D6: Prometheus + Grafana
- `gateway/observability/metrics.py`: Counter auth_failures_total{method,reason}, auth_success_total{method}.
- Instrument vào cả 2 middleware (jwt + hmac).
- `gateway/main.py`: prometheus-fastapi-instrumentator expose /metrics.
- `infra/prometheus.yml`, `infra/grafana-dashboard.json` (4 panel: failures/min, success rate, HTTP status, p95 latency).
- `infra/grafana-provisioning/`: auto-load datasource Prometheus + dashboard.
- Test: `tests/test_metrics.py` (2/2 pass).

**Tổng test: 25/25 pass.**

### Cách verify thủ công
```
cd infra && docker compose up -d --build
curl http://localhost:8000/metrics            # → counter raw
# Prometheus UI: http://localhost:9090/targets (gateway phải UP)
# Grafana UI:    http://localhost:3001 (admin/admin) → dashboard "Secure API Gateway"
# Vault UI:      http://localhost:8200 (token: dev-root-token)
```
