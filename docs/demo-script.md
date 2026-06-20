# Kịch bản Demo Video (8–10 phút) — C-D12

Quay screen record theo 7 phân cảnh dưới. Chuẩn bị trước: `cd infra && docker compose up -d`
(đợi mọi service Up), 1 terminal, trình duyệt, và 1 access token thật từ Keycloak.

| # | Phân cảnh | Thời lượng | Nội dung quay | Lệnh / URL |
|---|-----------|-----------|---------------|------------|
| 1 | Tổng quan kiến trúc | 1' | Sơ đồ Gateway ↔ Keycloak/Redis/Vault/backend, nói 3 trust boundary | slide kiến trúc + `docker compose ps` |
| 2 | Auth flow + JWT verify | 2' | Lấy token (client_credentials), gọi `/api/protected` 200; sửa 1 ký tự → 401 | xem block lệnh bên dưới |
| 3 | HMAC + replay protection | 2' | Ký request hợp lệ → 200; gửi lại y hệt → 401 `replay detected`; sửa body → 401 | `python clients/test_hmac.py` |
| 4 | Vault key rotation | 1' | `vault kv get`, chạy `scripts/rotate_keycloak_key.sh`, JWKS trả 2 kid | `scripts/rotate_keycloak_key.sh` |
| 5 | Revoke + jti blacklist | 1' | Gọi `/auth/revoke`, gọi lại cùng token → 401 `token revoked` | xem block bên dưới |
| 6 | K8s self-heal | 1' | `kubectl delete pod` 1 replica → request vẫn 200, pod mới spawn | `kubectl get pods -w` |
| 7 | Observability | 1' | Grafana panel auth failures nhảy số; Jaeger trace có `auth.*` attributes | `:3001` Grafana, `:16686` Jaeger |

## Block lệnh sẵn (copy khi quay)

```bash
# (2) JWT
TOKEN=$(curl -s -X POST http://localhost:8081/realms/nt219/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=service-account \
  -d client_secret=<secret> | jq -r .access_token)
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/protected           # -> 200
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer ${TOKEN}x" \
  http://localhost:8000/api/protected           # -> 401

# (3) HMAC happy-path + replay + tamper
python clients/test_hmac.py

# (5) Revocation
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/auth/revoke
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/protected           # -> 401 token revoked

# (7) Sinh data cho dashboard: bắn 5 token sai
for i in $(seq 1 5); do
  curl -s -o /dev/null -H "Authorization: Bearer bad.$i" http://localhost:8000/api/protected
done
```

## Sau khi quay
- Upload YouTube **unlisted**, dán link vào `README.md` (badge Demo).
- Đối chiếu milestone `🟢 NỘP`: video + `final_report.pdf` đủ 11 mục + tag `v1.0.0`.
