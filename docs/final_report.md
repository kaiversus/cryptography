# BÁO CÁO ĐỒ ÁN: SECURE API GATEWAY WITH CRYPTOGRAPHIC ENFORCEMENT

*(Lưu ý: Dưới đây là trích xuất riêng phần báo cáo của Sinh viên A phụ trách - Chương 3 và Chương 8)*

---

## CHƯƠNG 3: CƠ SỞ LÝ THUYẾT MẬT MÃ VÀ XÁC THỰC AN TOÀN TRÊN API GATEWAY

### 3.1 Cơ chế mã hóa đối xứng và giải thuật HMAC-SHA256 (HS256)
Mã hóa đối xứng (Symmetric Cryptography) là nền tảng lâu đời nhất của mật mã học, đặc trưng bởi việc sử dụng một khóa duy nhất (Shared Secret) cho cả hai tiến trình: tạo chữ ký (signing) và kiểm chứng chữ ký (verification). Trong tiêu chuẩn JSON Web Signature (JWS), thuật toán HS256 là sự kết hợp giữa cơ chế mã xác thực thông điệp dựa trên hàm băm (HMAC) và hàm băm an toàn SHA-256.

Biểu thức toán học thiết lập nên mã HMAC cho một thông điệp $m$ với khóa bí mật $K$ được định nghĩa nghiêm ngặt bởi RFC 2104 như sau:
$$HMAC(K, m) = SHA256((K^+ \oplus opad) \parallel SHA256((K^+ \oplus ipad) \parallel m))$$

Trong đó:
- $K^+$ là chuỗi khóa được đệm thêm các ký tự zero để đạt kích thước bằng kích thước khối của hàm băm (64 bytes đối với SHA-256).
- $\oplus$ biểu thị phép toán logic XOR tác động trên từng bit (bitwise XOR).
- $\parallel$ đại diện cho phép toán nối chuỗi dữ liệu (concatenation).
- $ipad$ (inner padding) là hằng số lặp lại của byte `0x36` dài 64 lần.
- $opad$ (outer padding) là hằng số lặp lại của byte `0x5C` dài 64 lần.

Về mặt kiến trúc hệ thống, HS256 thu hẹp ranh giới tin cậy (trust boundary). Mô hình này đòi hỏi API Gateway và cấu thành Identity Provider (Keycloak) phải chia sẻ một bí mật chung tuyệt đối. Khi hệ thống mở rộng quy mô, bài toán phân phối khóa (Key Distribution Problem) trở thành điểm yếu chí mạng: nếu một node trung gian bị chiếm quyền kiểm soát, kẻ tấn công sẽ sở hữu khóa $K$ và có khả năng tự sinh các mã token giả mạo (Arbitrary Token Forgery), phá vỡ toàn bộ kiến trúc an toàn.

### 3.2 Hệ mật mã bất đối xứng RSA và giải thuật chữ ký số RS256
Để giải quyết triệt để bài toán phân phối khóa, hệ mật mã bất đối xứng (Asymmetric Cryptography) sử dụng một cặp khóa: Khóa riêng tư (Private Key) dùng để ký, giữ bí mật tại Keycloak; Khóa công khai (Public Key) dùng để xác thực, phân phối tự do tới API Gateway thông qua endpoint JWKS.

Nền tảng toán học của RSA dựa trên bài toán khó tính toán: **Phân tích số nguyên lớn thành các thừa số nguyên tố (Integer Factorization Problem)**. 
Khi tiến hành ký token tại Keycloak, chữ ký số $S$ của thông điệp băm $H = SHA256(m)$ được tính bằng số mũ bí mật $d$ và mô-đun $n$:
$$S \equiv H^d \pmod{n}$$

Tại API Gateway, quá trình xác thực chữ ký số kiểm tra tính hợp lệ bằng số mũ công khai $e$ (thường là $65537$ hoặc $2^{16} + 1$) thông qua hệ thức đồng dư:
$$S^e \equiv H \pmod{n}$$

Do số mũ công khai $e$ được chọn rất nhỏ, phép tính lũy thừa mô-đun tại API Gateway tiêu tốn ít chu kỳ CPU. Tuy nhiên, nhược điểm lớn nhất của RS256 là kích thước chữ ký tỷ lệ thuận với độ dài mô-đun $n$, chiếm tới 256 bytes không gian lưu trữ cho chuẩn khóa 2048-bit, làm tăng kích thước payload của hệ thống.

### 3.3 Mật mã đường cong Elliptic và giải thuật chữ ký số ES256
Thuật toán ES256 khắc phục nhược điểm kích thước của RSA bằng cách ứng dụng thuật toán chữ ký số đường cong Elliptic (ECDSA) trên đường cong chuẩn hóa NIST P-256. Cơ sở an toàn của hệ mật này dựa trên bài toán **Logarit rời rạc trên đường cong Elliptic (Elliptic Curve Discrete Logarithm Problem - ECDLP)**.

Phương trình đường cong Elliptic áp dụng trên trường hữu hạn số nguyên tố $F_p$ có dạng tổng quát:
$$y^2 \equiv x^3 + a \cdot x + b \pmod{p}$$

Trong thuật toán này, khóa riêng tư là một số ngẫu nhiên $d$, khóa công khai là điểm $Q$ được tạo ra qua phép nhân vô hướng điểm gốc $G$: $Q = d \cdot G$. Chữ ký sinh ra là một cặp tọa độ $(r, s)$ cố định 64 bytes, trong đó $s$ được tính bằng:
$$s \equiv k^{-1}(SHA256(m) + d \cdot r) \pmod{n}$$

Để kiểm chứng tại Gateway, hệ thống phải thực hiện các phép nhân điểm vô hướng phức tạp. Mặc dù ES256 cung cấp độ an toàn cao với kích thước khóa nhỏ gọn, nhưng chi phí tính toán hình học trên đường cong Elliptic khiến tốc độ xác thực của Gateway chậm hơn so với thuật toán RSA.

### 3.4 Kiến trúc xoay vòng khóa (Key Rotation) và Cửa sổ ân hạn (Grace Period)
Nhằm giảm thiểu nguy cơ thỏa hiệp khóa khi vận hành trong thời gian dài, dự án triển khai mô hình xoay vòng khóa tự động (Key Rotation) kết hợp cơ chế cửa sổ ân hạn (Grace Period) kéo dài 1 giờ.

1. **Giai đoạn phát hành:** Kể từ thời điểm $t_{rotation}$, Keycloak tạo một khóa ES256 mới (v2) và sử dụng để ký toàn bộ token mới.
2. **Giai đoạn ân hạn (Grace Period):** Từ mốc $t_{rotation}$ đến $t_{rotation} + 1\text{ giờ}$, endpoint JWKS trả về đồng thời cả 2 khóa v1 và v2, phân biệt qua `kid` (Key ID). Bộ nhớ đệm `TTLCache` tại API Gateway giúp duy trì các xác thực token cũ một cách trơn tru, đảm bảo Zero-Downtime.
3. **Giai đoạn vô hiệu hóa:** Vượt ngưỡng $t_{rotation} + 1\text{ giờ}$, khóa v1 bị vô hiệu hóa (`enabled=false`) và gỡ bỏ khỏi JWKS. Token cũ lập tức bị Gateway từ chối do không tìm thấy `kid` tương ứng.

### 3.5 Cơ chế thu hồi chứng chỉ động (Dynamic Token Revocation)
Bên cạnh việc chờ token tự hết hạn theo trường `exp`, hệ thống thiết kế cơ chế thu hồi tức thời sử dụng Blacklist ID Token (`jti`) trên cụm Redis Cache. 
Để ngăn chặn nguy cơ cạn kiệt tài nguyên RAM của Redis do lưu trữ dữ liệu vĩnh viễn, thuật toán áp dụng vòng đời tự hủy (TTL - Time to Live) động cho mỗi bản ghi bị thu hồi theo công thức toán học thời gian thực:
$$TTL = \max(1, exp - t_{current})$$
Cơ chế này đảm bảo Redis tự động dọn dẹp các ID token rác ngay thời điểm token đó thực sự hết hạn về mặt thời gian, kết hợp giữa an toàn tuyệt đối và tối ưu hóa hạ tầng lưu trữ.

---

## CHƯƠNG 8: THỰC NGHIỆM VÀ PHÂN TÍCH HIỆU NĂNG XÁC THỰC MẬT MÃ

### 8.1 Thiết lập cấu hình hệ thống đo lường
Quá trình đo lường hiệu năng xử lý (Throughput và Latency) sử dụng công cụ kiểm thử áp lực `wrk`. Kịch bản thực nghiệm áp dụng cấu hình tải cực đại: `4 threads` mô phỏng, duy trì `100 connections` liên tục trong khoảng thời gian `60s`. Để triệt tiêu sai số ngẫu nhiên do hệ điều hành nền, tiến trình được lặp lại 3 vòng độc lập cho mỗi cấu hình thuật toán mật mã. Bộ nhớ đệm xác thực tĩnh (Token Validation Cache) tại Gateway được vô hiệu hóa để ép hệ thống bắt buộc phải giải mã toán học trong mọi request.

**Cấu hình phần cứng & môi trường:**
- CPU Host: 12th Gen Intel(R) Core(TM) i5-12500H
- RAM Host: 16.0 GB DDR4
- Hạ tầng: Docker Desktop, phân bổ [ĐIỀN SỐ CORE] vCPUs, [ĐIỀN SỐ RAM] GB RAM cho container Gateway.

### 8.2 Bảng tổng hợp kết quả đo lường thực tế

| Thuật toán | Vòng 1 (RPS) | Vòng 2 (RPS) | Vòng 3 (RPS) | Trung bình (RPS) | Latency Avg (ms) | Latency Max (ms) |
|---|---|---|---|---|---|---|
| **HS256** | 489.00 | 474.09 | 481.72 | **481.60** | 221.75 | 1290 |
| **RS256** | 372.68 | 366.35 | 371.73 | **370.25** | 279.38 | 1173 |
| **ES256** | 359.71 | 362.23 | 360.07 | **360.67** | 286.49 | 1440 |

### 8.3 Biểu đồ trực quan so sánh thông lượng (Throughput)

```text
Thuật toán | Năng suất xử lý hệ thống (Requests Per Second - RPS)
-----------|-----------------------------------------------------------------
HS256      | ████████████████████████████████████████████████ -> ~481.72 req/s
RS256      | █████████████████████████████████████ -> ~370.25 req/s
ES256      | ████████████████████████████████████ -> 360.67 req/s
```

### 8.4 Biện luận và Phân tích chuyên sâu kết quả thực nghiệm

Dựa trên bộ dữ liệu thực nghiệm thu được sau 3 vòng kiểm thử áp lực độc lập (Bảng 8.2), nhóm nghiên cứu tiến hành phân tích, biện luận các đặc tính hiệu năng của API Gateway dưới góc độ toán học mật mã và kiến trúc hệ thống như sau:

#### 8.4.1 Phân tích hiệu năng cơ chế mã hóa đối xứng HS256
Kết quả đo lường thực tế chứng minh thuật toán đối xứng HS256 tối ưu vượt trội về mọi chỉ số hiệu năng, đạt thông lượng trung bình **481.60 RPS** (cao hơn RS256 khoảng 30.1% và ES256 khoảng 33.5%) đồng thời duy trì độ trễ phản hồi thấp nhất ở mức **221.75 ms**. 

Về mặt bản chất, sự vượt trội này hoàn toàn tương thích với biểu thức thiết lập mã HMAC định nghĩa tại Mục 3.1:
$$HMAC(K, m) = SHA256((K^+ \oplus opad) \parallel SHA256((K^+ \oplus ipad) \parallel m))$$

Quá trình xác thực chữ ký HS256 tại API Gateway thực chất chỉ là việc tính toán lại hàm băm trên payload nhận được và so sánh chuỗi. Tiến trình này hoàn toàn bao gồm các phép toán logic sơ cấp như bitwise XOR ($\oplus$) và nối chuỗi ($\parallel$), được thực thi trực tiếp trên các thanh ghi (registers) của CPU ở tầng phần cứng với chi phí thời gian tuyến tính $O(N)$. Hệ thống hoàn toàn không phải gánh chịu các chi phí phân bổ bộ nhớ phức tạp hay tính toán số nguyên lớn.

Tuy nhiên, nhóm nghiên cứu nhận định rằng, mức hiệu năng lý tưởng này phải đánh đổi bằng việc thu hẹp ranh giới tin cậy (trust boundary) như đã cảnh báo trong lý thuyết. Việc phải chia sẻ chuỗi bí mật `Shared Secret` giữa Keycloak và API Gateway làm phát sinh bài toán phân phối khóa nguy hiểm. Do đó, điểm số RPS cao của HS256 chỉ phản ánh hiệu năng tính toán thuần túy, không đại diện cho một kiến trúc phân tán an toàn và bền vững trên môi trường Production.

#### 8.4.2 Biện luận kỹ thuật về sự chênh lệch hiệu năng giữa RS256 và ES256
Một phát hiện thực nghiệm quan trọng là thuật toán mã hóa bất đối xứng cổ điển RS256 (đạt trung bình **370.25 RPS**, độ trễ **279.38 ms**) lại cho hiệu năng xử lý tốt hơn thuật toán hiện đại ES256 (đạt trung bình **360.67 RPS**, độ trễ **286.49 ms**). Kết quả này thoạt nhìn có vẻ nghịch lý vì ES256 sử dụng các cặp khóa có kích thước nhỏ gọn hơn rất nhiều so với RS256 (256-bit so với 2048-bit). Tuy nhiên, nếu đối chiếu sâu vào bản chất toán học của quá trình xác thực (Verification) tại API Gateway, hiện tượng này hoàn toàn logic:

1. **Đối với RS256 (Hệ mật RSA):** Như đã phân tích ở Mục 3.2, hệ thức kiểm tra chữ ký tuân thủ phép đồng dư: $S^e \equiv H \pmod{n}$. Trong các cấu hình tiêu chuẩn của Keycloak, số mũ công khai $e$ luôn được lựa chọn là số nguyên tố Fermat nhỏ $e = 65537$ ($2^{16} + 1$). Phép lũy thừa mô-đun với một số mũ có trọng số Hamming cực thấp (chỉ chứa hai bit 1) cho phép CPU của Gateway tối ưu hóa số lượng phép nhân thông qua thuật toán bình phương và nhân (Square-and-Multiply). Do đó, chi phí chu kỳ xung nhịp CPU cho một thao tác xác thực RSA là tương đối nhỏ.
2. **Đối với ES256 (Hệ mật ECDSA):** Quá trình kiểm chứng chữ ký $(r, s)$ yêu cầu Gateway giải quyết bài toán logarit rời rạc ngược, cụ thể là tính toán phương trình kiểm tra điểm trên đường cong Elliptic NIST P-256 (Mục 3.3): $s \equiv k^{-1}(SHA256(m) + d \cdot r) \pmod{n}$. Thao tác này bắt buộc CPU phải thực hiện hàng loạt các phép nhân điểm vô hướng (Scalar Point Multiplication) trên trường hữu hạn $F_p$. Các phép toán hình học không gian này (bao gồm cộng điểm và nhân đôi điểm liên tục trên tọa độ Jacobian) phức tạp hơn rất nhiều so với phép nhân số nguyên lớn của RSA.

Sự chênh lệch về thông lượng giữa hai thuật toán chính là bằng chứng định lượng rõ ràng nhất cho thấy chi phí tính toán hình học đường cong của ES256 đè nặng lên tài nguyên xử lý của CPU tại API Gateway nhiều hơn so với toán học số mũ của RSA.

#### 8.4.3 Đánh giá thực tiễn và Phán quyết lựa chọn thiết kế kiến trúc
Mặc dù thuật toán ES256 xếp cuối cùng về các chỉ số thông lượng, năng suất xử lý thực tế của nó dưới áp lực tải cực đại (100 connections đồng thời) vẫn đạt tới **360.67 RPS**. Năng suất xử lý này tương đương với khả năng đáp ứng hơn **31 triệu request mỗi ngày** trên một Node Gateway duy nhất — một con số dư sức vượt qua ngưỡng tải kỳ vọng của hệ thống microservices trong phạm vi nghiên cứu.

Xét trên bức tranh tổng thể về thiết kế hệ thống, nhóm nghiên cứu quyết định lựa chọn **ES256** làm giải pháp mật mã cốt lõi cho toàn bộ hệ thống vì các lý do chiến lược sau:

* **Tối ưu hóa Payload và Băng thông mạng:** Chữ ký số ES256 có kích thước cố định chỉ 64 bytes (so với 256 bytes của RS256). Khi Token liên tục được luân chuyển qua hàng trăm microservices phía sau Gateway, việc tiết kiệm 192 bytes trên mỗi request sẽ tích lũy thành một lượng tài nguyên băng thông cực kỳ lớn, giảm thiểu độ trễ mạng tổng thể (Network Latency Overhead).
* **Đảm bảo kiến trúc an toàn Zero-Trust:** ES256 cho phép triển khai hoàn hảo cơ chế xoay vòng khóa tự động (Key Rotation) và endpoint JWKS động (đã phân tích tại Mục 3.4). Gateway hoàn toàn đóng vai trò một thực thể xác thực độc lập, không nắm giữ khóa mật, loại bỏ hoàn toàn nguy cơ thỏa hiệp cấu trúc như HS256.

Tóm lại, bộ số liệu thực nghiệm đã phản ánh một cách tường minh và khách quan các định luật mật mã học. Quyết định chấp nhận mức đánh đổi khoảng 2.6% về thông lượng xử lý của ES256 so với RS256 để đổi lấy lợi ích vượt trội về băng thông mạng và kiến trúc an toàn bảo mật là một quyết định kỹ thuật hoàn toàn chính xác, có cơ sở khoa học vững chắc.