# API GATEWAY HARDENING SECURITY CHECKLIST (PRODUCTION-READY)

Bảng kiểm kê kỹ thuật gồm 15 hạng mục bảo mật bắt buộc phải rà soát, cấu hình nghiêm ngặt trước khi đóng gói bàn giao đồ án hệ thống API Gateway.

## 1. Cryptographic & Token Validation Hardening
- [X] **SEC-01 (No Hardcoded Secrets):** Tuyệt đối không lưu vết trực tiếp chuỗi Private Key, Shared Secret hoặc tài khoản quản trị trong mã nguồn. Toàn bộ thông tin nhạy cảm phải nạp qua biến môi trường (`.env`), cấu hình file `.gitignore` để không push file này lên Git repository công khai.
- [X] **SEC-02 (Strict Claim Verification):** Cấu hình thư viện kiểm tra JWT bắt buộc phải kích hoạt kiểm thử toàn diện các giá trị: `exp` (thời gian hết hạn), `iss` (đúng đường dẫn định danh Identity Provider), và `aud` (trùng khớp với Client ID được phân quyền).
- [ ] **SEC-03 (JWKS Cache Management):** Giới hạn vòng đời tồn tại (TTL) của bộ nhớ đệm JWKS tại Gateway tối đa là 5 phút nhằm giảm tải tần suất request đến Keycloak, đồng thời ngăn chặn kiểu tấn công lụt (DDoS) bằng cách gửi liên tục các chuỗi `kid` ngẫu nhiên không có thật để bắt Gateway quay sang truy vấn Keycloak.
- [X] **SEC-04 (Alg None Mitigation):** Cấu hình middleware kiểm tra token bắt buộc phải tường minh danh sách thuật toán được phép (`allowed_algs=['ES256']`). Từ chối tuyệt đối các token có thuộc tính header `"alg": "none"` (lỗ hổng bypassed phổ biến của kiến trúc JWT).
- [ ] **SEC-05 (Token Revocation Memory Policy):** Thiết lập cơ chế lưu trữ danh sách token bị thu hồi (Blacklist JTI) trên Redis với giá trị TTL động bằng đúng công thức `exp - thời gian_hiện_tại`. Không sử dụng khóa vĩnh viễn nhằm chống rủi ro gây cạn kiệt dung lượng bộ nhớ RAM của cụm Redis cache.

## 2. Network & Infrastructure Isolation
- [ ] **SEC-06 (Port Isolation):** Trong file cấu hình `docker-compose.yml`, chỉ ánh xạ cổng `8081` (hoặc cổng routing gateway) ra môi trường bên ngoài cho client gọi. Toàn bộ các kết nối từ Gateway đến Keycloak, Redis phải chạy ngầm thông qua Docker network nội bộ sử dụng cổng mặc định `8080` và `6379`.
- [ ] **SEC-07 (Admin Endpoint Protection):** Cấu hình quy tắc định tuyến (Routing Rules) trên API Gateway chặn hoàn toàn mọi traffic có đường dẫn chứa các endpoint quản trị của cấu phần định danh như `/admin` hoặc `/realms/master` từ bên ngoài internet đổ vào.
- [ ] **SEC-08 (Strict CORS Policy):** Cấu hình Middleware CORS với danh sách nguồn cụ thể được phép truy cập (`allow_origins=["https://trusted-app.com"]`). Tuyệt đối không sử dụng ký tự đại diện lỏng lẻo `allow_origins=["*"]` trên môi trường phân phối dịch vụ thực tế.
- [ ] **SEC-09 (Transport Layer Security):** Kích hoạt cấu hình chứng chỉ mã hóa TLS/HTTPS trên đầu bến tiếp nhận của API Gateway nhằm mã hóa toàn vẹn dữ liệu truyền trên kênh truyền, chống tấn công nghe lén đường truyền (Sniffing / Man-in-the-Middle).
- [ ] **SEC-10 (Server Banner Grabbing Defense):** Cấu hình ghi đè hoặc loại bỏ hoàn toàn các trường thông tin định danh hệ thống trong HTTP Response Header (ví dụ xóa bỏ trường `Server: uvicorn` hoặc `X-Powered-By`) để hạn chế kẻ tấn công thu thập thông tin rà quét lỗ hổng nền tảng.

## 3. Code Quality & Operating System Hardening
- [ ] **SEC-11 (Production Environment State):** Đảm bảo cấu hình ứng dụng backend (FastAPI/Flask) chạy ở trạng thái Production bằng cách thiết lập biến môi trường `DEBUG=False`. Ngăn chặn việc rò rỉ thông tin cấu trúc mã nguồn qua màn hình StackTrace khi phát sinh lỗi hệ thống.
- [X] **SEC-12 (No Raw Print Operations):** Rà soát và xóa bỏ toàn bộ các câu lệnh `print(token)` hoặc các dòng mã log ghi nhận thô thông tin nhạy cảm của người dùng (như mật khẩu, dữ liệu thẻ, khóa mật mã) vào hệ thống file log dùng chung.
- [ ] **SEC-13 (Least Privilege Container Execution):** Cấu hình file `Dockerfile` chạy tiến trình của API Gateway dưới quyền một user định danh hạn chế quyền lực (ví dụ: `USER nonroot` hoặc `USER appuser`), tuyệt đối không để mặc định chạy bằng quyền tối cao `root` bên trong container.
- [ ] **SEC-14 (Dependency Vulnerability Scanning):** Chạy công cụ quét tự động lỗ hổng bảo mật của các thư viện mã nguồn mở bên thứ ba đang sử dụng trong dự án bằng lệnh `pip-audit` hoặc công cụ Snyk để đảm bảo không chứa mã độc hoặc lỗ hổng CVE nguy hiểm.
- [ ] **SEC-15 (Rate Limiting Enforcement):** Kích hoạt cơ chế giới hạn tần suất gọi API (Rate Limiting Middleware) dựa trên định danh địa chỉ IP của client (ví dụ: tối đa 60 requests/phút) để bảo vệ hệ thống khỏi các hành vi cào dữ liệu tự động hoặc tấn công brute-force tài khoản.