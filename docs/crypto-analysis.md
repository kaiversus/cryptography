## Cơ chế Xoay vòng khóa (Key Rotation) & Cửa sổ ân hạn (Grace Period)

Để đảm bảo Zero-Downtime trong quá trình xoay vòng khóa mật mã (Key Rotation), hệ thống áp dụng cơ chế Cửa sổ ân hạn (Grace Period) kéo dài 1 giờ. Cụ thể:

1. **Phát hành khóa mới:** Quản trị viên (hoặc Cronjob) gọi Keycloak Admin REST API để khởi tạo một Key Provider (thuật toán ECDSA) mới với mức ưu tiên (`priority`) cao hơn. Từ thời điểm này, Keycloak sẽ sử dụng khóa mới (v2) để ký (sign) các JWT mới được phát hành.
2. **Trạng thái JWKS Endpoint:** Tại thời điểm này, Keycloak chưa xóa khóa cũ (v1) mà trả về **cả 2 khóa (v1 và v2)** thông qua `jwks_uri`. Các khóa được phân biệt bằng trường `kid` (Key ID).
3. **Bộ nhớ đệm (Cache) tại Gateway:** API Gateway duy trì một `TTLCache` cho JWKS với vòng đời 5 phút. Nếu Gateway nhận được một token cũ ký bằng khóa v1, do khóa v1 vẫn tồn tại trong JWKS cache (hoặc fetch mới từ Keycloak), hàm `verify_token` vẫn tra cứu thành công và xác thực hợp lệ. 
4. **Vô hiệu hóa khóa cũ:** Sau 1 giờ (đủ dài để các `access_token` cũ đạt đến `exp`), hệ thống sẽ vô hiệu hóa hoàn toàn khóa v1 (`enabled=false`). Mọi nỗ lực sử dụng token cũ sau thời điểm này (nếu chưa quá hạn) cũng sẽ bị từ chối do không tìm thấy `kid` tương ứng. Điều này cân bằng giữa trải nghiệm người dùng (không bị log out đột ngột) và tính an toàn của hệ thống mật mã.