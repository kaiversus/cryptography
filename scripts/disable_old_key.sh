#!/usr/bin/env bash
# File: scripts/disable_old_key.sh
set -e

KC="http://localhost:8081"
REALM="nt219"

echo "1. Getting Admin Token..."
ADMIN_TOKEN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" -d "username=admin" -d "password=admin" \
  -d "grant_type=password" | jq -r .access_token)

echo "2. Fetching Key Providers..."
COMPONENTS_URL="$KC/admin/realms/$REALM/components?type=org.keycloak.keys.KeyProvider"
COMPONENTS=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$COMPONENTS_URL")

# NÂNG CẤP: Chỉ lọc những provider là ecdsa-generated, sau đó mới sort theo priority
OLD_COMP_ID=$(echo "$COMPONENTS" | jq -r 'map(select(.providerId == "ecdsa-generated")) | sort_by(.config.priority[0] | tonumber?) | .[0].id')
OLD_COMP_NAME=$(echo "$COMPONENTS" | jq -r 'map(select(.providerId == "ecdsa-generated")) | sort_by(.config.priority[0] | tonumber?) | .[0].name')

if [ "$OLD_COMP_ID" == "null" ] || [ -z "$OLD_COMP_ID" ]; then
    echo "Lỗi: Không tìm thấy Key Provider ECDSA nào để tắt."
    exit 1
fi

echo "-> Tìm thấy khóa ECDSA cũ nhất: $OLD_COMP_NAME (ID: $OLD_COMP_ID)"

# Lấy cấu hình hiện tại của component đó
COMP_JSON=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$KC/admin/realms/$REALM/components/$OLD_COMP_ID")

# Sửa trường enabled và active thành false
NEW_COMP_JSON=$(echo "$COMP_JSON" | jq '.config.enabled = ["false"] | .config.active = ["false"]')

echo "3. Disabling old key provider..."
curl -s -X PUT "$KC/admin/realms/$REALM/components/$OLD_COMP_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$NEW_COMP_JSON"

echo "✅ Đã vô hiệu hóa thành công khóa cũ: $OLD_COMP_NAME"