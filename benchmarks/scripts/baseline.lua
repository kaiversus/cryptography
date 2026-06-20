-- baseline.lua — đo overhead thuần của Gateway (không xác thực mật mã).
-- Dùng làm mốc 0 để so sánh chi phí thêm vào của JWT (es256/hs256/rs256) và HMAC.
--
--   wrk -t4 -c100 -d60s -s benchmarks/scripts/baseline.lua http://localhost:8000/health
wrk.method = "GET"
