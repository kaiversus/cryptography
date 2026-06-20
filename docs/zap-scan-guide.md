# OWASP ZAP Scan Guide (C-D9)

Hướng dẫn quét DAST (Dynamic Application Security Testing) bằng OWASP ZAP và xuất
`docs/zap-report.pdf` — deliverable C-D9.

## Cách 1 — Tự động hóa bằng Docker (khuyến nghị, lặp lại được)

1. Bật stack: `cd infra && docker compose up -d` (gateway lắng nghe `localhost:8000`).
2. Chạy scan:
   ```bash
   ./scripts/zap_scan.sh            # baseline (passive, ~2-3 phút)
   ./scripts/zap_scan.sh full       # full active scan (~15-30 phút)
   ```
3. Mở `docs/zap-report.html`, dùng trình duyệt **Print → Save as PDF** →
   lưu `docs/zap-report.pdf`.

## Cách 2 — ZAP Desktop (theo plan gốc)

1. Tải ZAP Desktop: https://www.zaproxy.org/download/
2. Quick Start → **Automated Scan** → URL `http://localhost:8000` → tick
   "Use Ajax spider" → **Attack**.
3. Đợi spider + active scan hoàn tất (15-30 phút).
4. Tab **Report → Generate Report → PDF** → lưu `docs/zap-report.pdf`.

## Diễn giải kết quả

| Finding thường gặp | Đánh giá | Hành động |
|--------------------|----------|-----------|
| 401 trên `/api/protected`, `/api/service` | ✅ Đúng thiết kế (cưỡng chế auth) | Không cần fix |
| Missing `X-Content-Type-Options`, `X-Frame-Options` | Low/Info | Thêm security headers ở middleware (tùy chọn) |
| Server banner `uvicorn` lộ version | Low | Ẩn header `Server` (xem checklist SEC-10) |
| CORS `*` | Medium nếu bật | Whitelist origin cụ thể (checklist SEC-08) |

**Tiêu chí DONE (theo milestone v0.3):** report tồn tại và **không có finding
Critical**. Nếu có Medium/High → phối hợp B fix trước D14 và ghi lại trong báo cáo Mục 7.

> File `docs/zap-report.pdf` sinh ra từ lần quét thực tế trên máy có Docker/ZAP;
> không commit kèm vì là artifact nhị phân (đã liệt kê trong checklist deliverable).
