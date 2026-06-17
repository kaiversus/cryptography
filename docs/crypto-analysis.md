# PHÂN TÍCH MẬT MÃ: LỰA CHỌN THUẬT TOÁN KÝ JWT CHO API GATEWAY

## 1.1 Định nghĩa và Phân loại thuật toán
Trong kiến trúc bảo mật của API Gateway, JSON Web Token (JWT) được sử dụng để xác thực và phân quyền. Tính toàn vẹn của JWT được bảo đảm thông qua chữ ký điện tử. Các thuật toán ký được chia làm hai nhóm chính:
- **Mật mã đối xứng (Symmetric Cryptography):** Tiêu biểu là thuật toán HS256 (HMAC sử dụng SHA-256). Ở cơ chế này, cả bên phát hành token (Identity Provider) và bên xác thực token (API Gateway) đều sử dụng chung một khóa bí mật (shared secret) để tạo và kiểm chứng chữ ký.
- **Mật mã bất đối xứng (Asymmetric Cryptography):** Tiêu biểu là ES256 (ECDSA sử dụng đường cong P-256 và SHA-256) và RS256 (RSA sử dụng SHA-256). Cơ chế này sử dụng một cặp khóa: Khóa riêng tư (Private Key) được giữ bí mật tuyệt đối tại máy chủ phát hành để ký, và Khóa công khai (Public Key) được phân phối rộng rãi để các dịch vụ khác xác thực chữ ký.

## 1.2 Bài toán phân phối khóa (Key Distribution)
Điểm yếu lớn nhất của kiến trúc dùng mã hóa đối xứng (HS256) nằm ở bài toán phân phối khóa. Khi hệ thống mở rộng, việc chia sẻ khóa bí mật an toàn cho hàng chục microservices hoặc các đối tác bên ngoài là cực kỳ rủi ro. Nếu một node bị xâm nhập, toàn bộ hệ thống sẽ sụp đổ vì kẻ tấn công có thể tự ký các JWT giả mạo (SEC-01 forgery attack).

Ngược lại, mã hóa bất đối xứng giải quyết triệt để bài toán này. Khóa riêng tư không bao giờ rời khỏi Keycloak. Các client và API Gateway chỉ cần lấy Khóa công khai thông qua endpoint JSON Web Key Set (JWKS). Trong dự án này, gateway có thể linh hoạt lấy bộ khóa công khai tại endpoint `http://localhost:8081/realms/nt219/protocol/openid-connect/certs`, cho phép hệ thống mở rộng (scale) không giới hạn mà không làm lộ khóa ký.

## 1.3 Cơ chế Xoay vòng khóa (Key Rotation) & Cửa sổ ân hạn (Grace Period)
Để đảm bảo Zero-Downtime trong quá trình xoay vòng khóa mật mã (Key Rotation), hệ thống áp dụng cơ chế Cửa sổ ân hạn (Grace Period) kéo dài 1 giờ nhằm xử lý quá trình chuyển giao mượt mà:
1. **Phát hành khóa mới:** Quản trị viên (hoặc Cronjob) gọi Keycloak Admin REST API để khởi tạo một Key Provider (thuật toán ECDSA) mới với mức ưu tiên (`priority`) cao hơn. Từ thời điểm này, Keycloak sẽ sử dụng khóa mới (v2) để ký (sign) các JWT mới được phát hành.
2. **Trạng thái JWKS Endpoint:** Tại thời điểm này, Keycloak chưa xóa khóa cũ (v1) mà trả về **cả 2 khóa (v1 và v2)** thông qua `jwks_uri`. Các khóa được phân biệt rõ ràng bằng trường `kid` (Key ID) trong header của JWT.
3. **Bộ nhớ đệm (Cache) tại Gateway:** API Gateway duy trì một `TTLCache` cho JWKS với vòng đời 5 phút để giảm tải lượng request truy vấn đến Keycloak. Nếu Gateway nhận được một token cũ ký bằng khóa v1, do khóa v1 vẫn tồn tại trong JWKS cache (hoặc fetch mới từ Keycloak), hàm `verify_token` vẫn tra cứu thành công và xác thực hợp lệ.
4. **Vô hiệu hóa khóa cũ:** Sau 1 giờ (thời gian đủ dài để các `access_token` cũ đạt đến thời điểm hết hạn `exp`), hệ thống sẽ vô hiệu hóa hoàn toàn khóa v1 (`enabled=false`). Mọi nỗ lực sử dụng token cũ sau thời điểm này (nếu chưa quá hạn) cũng sẽ bị từ chối do hệ thống không tìm thấy `kid` tương ứng trong danh sách certs. Cơ chế này cân bằng hoàn hảo giữa trải nghiệm người dùng không bị gián đoạn và tính an toàn cao của hệ thống mật mã.

## 1.4 Chi phí tính toán (CPU Cost)
Sự đánh đổi của mã hóa bất đối xứng là tài nguyên phần cứng. HS256 sử dụng hàm băm HMAC-SHA256, chủ yếu bao gồm các phép toán thao tác bit (bitwise operations) và 64 vòng lặp, mang lại tốc độ thực thi cực nhanh.

Trong khi đó, ES256 (ECDSA) yêu cầu các phép toán nhân điểm (point multiplication) trên đường cong elliptic, và RS256 yêu cầu phép tính lũy thừa module (modular exponentiation) với các số nguyên rất lớn (2048-bit). Theo lý thuyết, ECDSA sẽ chậm hơn HMAC từ 10 đến 50 lần.

*(Ghi chú: Nhóm sẽ cập nhật số liệu chính xác chênh lệch hiệu năng phần trăm % tại đây sau khi hoàn thành kết quả benchmark wrk với 100 connections trong Day 10).*

## 1.5 Kiến trúc an toàn trong thực tế
Việc chọn thuật toán phụ thuộc vào ranh giới tin cậy (trust boundary) của hệ thống:
- **HS256:** Phù hợp cho mạng nội bộ (Service-to-Service), nơi các dịch vụ đã tin tưởng lẫn nhau, số lượng client ít và hiệu năng xử lý (latency) được ưu tiên hàng đầu.
- **ES256 / RS256:** Là tiêu chuẩn bắt buộc cho kiến trúc Zero-Trust hoặc Public-facing API. Gateway trong đồ án này nhận token từ các client bên ngoài (Web App, Mobile), do đó ES256 là lựa chọn tối ưu để ngăn chặn rủi ro rò rỉ khóa.

## 1.6 Kết luận quyết định của dự án
Dựa trên các phân tích về bảo mật và hiệu năng, hệ thống API Gateway của dự án quyết định:
1. Sử dụng **ES256** làm thuật toán mặc định cho môi trường Production (Client-facing) nhờ ưu điểm vượt trội về bảo mật, kích thước khóa nhỏ gọn hơn RS256 nhưng vẫn đảm bảo độ an toàn tương đương.
2. Thiết lập song song một realm phụ hỗ trợ **HS256** chỉ nhằm mục đích đo lường benchmark đối chứng trong giai đoạn kiểm thử, không triển khai thực tế.

---

## Bảng so sánh các thuật toán

| Tiêu chí | HS256 (HMAC) | RS256 (RSA) | ES256 (ECDSA) |
|---|---|---|---|
| **Loại khóa** | Đối xứng (Symmetric) | Bất đối xứng (Asymmetric) | Bất đối xứng (Asymmetric) |
| **Kích thước chữ ký** | 32 bytes | 256 bytes (với khóa 2048-bit) | 64 bytes |
| **Tốc độ ký** | Rất nhanh | Chậm | Nhanh hơn RS256 |
| **Tốc độ xác thực**| Rất nhanh | Nhanh | Chậm hơn RS256 |
| **Phân phối khóa** | Khó (Cần bảo mật kênh truyền) | Dễ (Qua JWKS) | Dễ (Qua JWKS) |
| **Mức độ khuyên dùng**| Nội bộ (Internal Network) | Tiêu chuẩn cũ (Public) | Hiện đại / Tiêu chuẩn mới (Public) |

---

## Tài liệu tham khảo
1. IETF. (2015). *RFC 7518: JSON Web Algorithms (JWA)*. Section 3.
2. IETF. (2015). *RFC 7519: JSON Web Token (JWT)*. Section 8.
3. Barker, E. (2020). *NIST Special Publication 800-57 Part 1 Revision 5: Recommendation for Key Management*. National Institute of Standards and Technology.