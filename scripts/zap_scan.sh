#!/usr/bin/env bash
# C-D9 — OWASP ZAP active/baseline scan cho API Gateway.
#
# Chạy ZAP trong Docker (không cần cài ZAP Desktop) quét gateway local.
# Yêu cầu: Gateway đang chạy (docker compose up) và truy cập được tại TARGET.
#
# Usage:
#   ./scripts/zap_scan.sh                       # baseline scan (nhanh, passive)
#   ./scripts/zap_scan.sh full                  # full active scan (chậm, ~15-30')
#   TARGET=http://host.docker.internal:8000 ./scripts/zap_scan.sh
set -euo pipefail

TARGET="${TARGET:-http://host.docker.internal:8000}"
MODE="${1:-baseline}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/docs"
REPORT_HTML="zap-report.html"

mkdir -p "$OUT_DIR"

if [ "$MODE" = "full" ]; then
  SCAN_IMG_CMD="zap-full-scan.py"
else
  SCAN_IMG_CMD="zap-baseline.py"
fi

echo "[ZAP] mode=$MODE target=$TARGET -> $OUT_DIR/$REPORT_HTML"

# -I: không fail exit code khi có warning. -r: xuất report HTML.
# Mount thư mục docs vào /zap/wrk để ZAP ghi report ra ngoài container.
docker run --rm \
  -v "$OUT_DIR:/zap/wrk/:rw" \
  --add-host=host.docker.internal:host-gateway \
  -t ghcr.io/zaproxy/zaproxy:stable \
  "$SCAN_IMG_CMD" \
  -t "$TARGET" \
  -r "$REPORT_HTML" \
  -I

echo "[ZAP] xong. Mở $OUT_DIR/$REPORT_HTML rồi In ra PDF -> docs/zap-report.pdf"
echo "[ZAP] Lưu ý: /api/protected & /api/service trả 401 khi chưa có token là ĐÚNG."
