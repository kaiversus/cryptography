-- AUTO-GENERATED bởi gen_hmac_lua.py lúc Sat Jun 20 11:10:44 2026
-- Chỉ hợp lệ cho request ĐẦU TIÊN trong 300s (nonce dùng-một-lần).
-- Throughput HMAC chuẩn: dùng locustfile.py.
wrk.method = "POST"
wrk.body   = '{"id":1}'
wrk.headers["Host"]        = "localhost:8000"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["X-Timestamp"] = "1781928644"
wrk.headers["X-Nonce"]     = "98b31f63-bd06-48d8-b0a7-83a9c62b7542"
wrk.headers["X-Key-Id"]    = "dev-key-01"
wrk.headers["X-Signature"] = "dce38355232d5430e9e207427c3b6dd67a934a76f553d32bd82e811b4fbb80dd"
wrk.path = "/api/service"
