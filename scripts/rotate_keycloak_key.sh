#!/usr/bin/env bash
# File: scripts/rotate_keycloak_key.sh
set -e

KC="http://localhost:8081"
REALM="nt219"

echo "1. Getting Admin Token..."
ADMIN_TOKEN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" -d "username=admin" -d "password=admin" \
  -d "grant_type=password" | jq -r .access_token)

if [ "$ADMIN_TOKEN" == "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "Lỗi: Không lấy được Admin Token. Kiểm tra lại Keycloak."
    exit 1
fi

echo "2. Creating new ECDSA Key Provider (v2) with priority 200..."
# Tạo key provider mới, ưu tiên (priority) cao hơn để Keycloak dùng nó ký token mới
curl -s -X POST "$KC/admin/realms/$REALM/components" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ecdsa-v2-'$(date +%s)'",
    "providerId": "ecdsa-generated",
    "providerType": "org.keycloak.keys.KeyProvider",
    "config": {
      "priority": ["200"],
      "enabled": ["true"],
      "active": ["true"],
      "ecdsaEllipticCurveKey": ["P-256"]
    }
  }'

echo "✅ Đã tạo Key v2 thành công! Bắt đầu Grace Period 1 giờ."