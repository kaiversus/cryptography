# Module 3 — Mục tiêu bảo mật (Security Objectives)

> Module 2 cho ta một bảng threat + cơ chế đối phó. Module này nâng mỗi cơ chế lên
> đúng cao độ: **CÁI GÌ phải đạt được** (mục tiêu), CHƯA nói **bằng công nghệ gì**.
> Đây là bản lề: thầy hỏi "vì sao chọn ES256/HMAC/mTLS?" → ta chỉ vào mục tiêu, mục
> tiêu chỉ vào threat, threat chỉ vào asset. Không có "vì đề bài bảo thế".

---

## Cao độ: Mục tiêu ≠ Cơ chế ≠ Triển khai

```
NGỮ CẢNH → THREAT → ┌── MỤC TIÊU (cái gì) ──┐ → CƠ CHẾ (bằng gì) → TRIỂN KHAI (chạy sao)
                    │ "request phải được     │   "JWT ES256 +        "Keycloak realm
                    │  xác thực, bất khả giả" │    verify qua JWKS"     nt219, :8081"
```

| | Mục tiêu | Cơ chế | Triển khai |
|---|---|---|---|
| Trả lời | **Cái gì** phải đạt | **Bằng kỹ thuật gì** | Chạy bằng sản phẩm gì, ở đâu |
| Nhắc tên công nghệ? | ❌ Không | ✅ Có (JWT, HMAC, mTLS) | ✅ Có (Keycloak, Redis, port) |
| Ví dụ | "Mọi request tới tài nguyên bảo vệ PHẢI được xác thực danh tính, không thể giả mạo" | "JWT ES256, verify chữ ký qua JWKS" | "Keycloak phát token, gateway cache JWKS" |

❌ "Dùng JWT ES256" làm **mục tiêu** = sai cao độ (chọn công nghệ quá sớm — đúng lỗi
thầy chê). ✅ Mục tiêu nói *kết quả*, cơ chế nói *cách*.

---

## 6 thuộc tính bảo mật (chính là STRIDE lật ngược)

Mỗi mục tiêu neo vào **một thuộc tính**. Đây là cùng một chuỗi xuyên suốt:

| STRIDE (threat) | → Thuộc tính (mục tiêu bảo vệ) |
|---|---|
| **S** Spoofing | **Authenticity** — danh tính thật, không giả được |
| **T** Tampering | **Integrity** — dữ liệu không bị sửa lén |
| **R** Repudiation | **Non-repudiation** — không chối được đã làm |
| **I** Information disclosure | **Confidentiality** — chỉ người được phép đọc |
| **D** Denial of Service | **Availability** — dịch vụ luôn sẵn sàng |
| **E** Elevation of privilege | **Authorization** — chỉ làm đúng quyền cho phép |

---

## Công thức viết một mục tiêu ĐẠT

> **[Phạm vi/asset]** + **PHẢI** + **[thuộc tính]** + **[điều kiện/ngưỡng]**
> — đo được, trung lập công nghệ.

Tiêu chí một mục tiêu tốt:
1. **Trung lập công nghệ** — không có chữ JWT/HMAC/Vault/Keycloak.
2. **Đo được / kiểm được** — đọc xong biết cách chứng minh đạt hay không.
3. **Truy được nguồn** — gắn vào ít nhất một threat ID ở Module 2.

---

## Ví dụ mẫu (tôi làm 1 cái — bạn theo mẫu này viết phần còn lại)

**MT-AUTHN (Authenticity)** — từ threat **S1-IG**:

> *Mọi request truy cập tài nguyên được bảo vệ PHẢI mang một danh tính được xác thực
> bằng bằng chứng mật mã mà gateway có thể kiểm độc lập; request không có hoặc mang
> bằng chứng không hợp lệ PHẢI bị từ chối (401).*

- Trung lập công nghệ? ✅ (không nhắc JWT/ES256/JWKS — đó là *cơ chế* sẽ chọn ở Module 4)
- Đo được? ✅ ("request bằng chứng không hợp lệ → 401" — chính là SEC-01/02)
- Truy nguồn? ✅ S1-IG (+ SEC-01,02,04,05,06,10)

---

## Bảng Mục tiêu (TODO — bạn tự viết)

Mỗi threat/nhóm threat ở Module 2 → một mục tiêu. Điền theo mẫu trên.

| ID | Thuộc tính | Mục tiêu (cái gì phải đạt) | Từ threat | Cơ chế (điền ở M4) |
|---|---|---|---|---|
| MT-AUTHN | Authenticity | Mọi request truy cập tài nguyên được bảo vệ PHẢI mang một danh tính được xác thực bằng bằng chứng mật mã mà gateway kiểm độc lập được; request không có / mang bằng chứng không hợp lệ PHẢI bị từ chối (401). Backend cũng PHẢI xác thực được nguồn gọi tới (không tin vị trí mạng). | S1-IG, S1-IdP, S1-GB | JWT/JWKS, mTLS, TLS |
| MT-INTEG | Integrity | Nội dung mỗi request (body + tham số quan trọng) PHẢI được bảo toàn nguyên vẹn từ lúc gửi tới lúc xử lý — phát hiện được mọi sửa đổi — VÀ không thể bị dùng lại: mỗi request chỉ có hiệu lực một lần trong một cửa sổ thời gian giới hạn. | T1-IG, RP1-IG | |
| MT-NONREP | Non-repudiation | Mọi hành động quan trọng (đặc biệt giao dịch máy-máy) PHẢI gắn được với chủ thể thực hiện bằng bằng chứng mà chỉ chủ thể đó tạo ra được; bằng chứng + dấu vết PHẢI được lưu bất khả sửa/xóa → chủ thể không thể chối đã thực hiện. | R1-IG | |
| MT-CONF | Confidentiality | Mọi thông tin bí mật/được bảo vệ (khóa, secret) PHẢI được mã hóa khi lưu trữ và khi truyền; chỉ chủ thể được cấp quyền mới đọc được. | I1-IG, I1-Vault | |
| MT-AVAIL | Availability | Hệ thống PHẢI duy trì khả năng phục vụ người dùng hợp lệ ngay cả khi có lưu lượng bất thường/lạm dụng; không một nguồn đơn lẻ nào được làm cạn kiệt tài nguyên xử lý. | D1-IG | |
| MT-AUTHZ | Authorization | Mỗi truy cập tới một chức năng/tài nguyên PHẢI được kiểm quyền — chủ thể chỉ thực hiện được đúng phần danh tính nó được cấp; quyền PHẢI được kiểm lại ở mỗi tầng (gateway và backend), không uỷ thác mù; vượt quyền → 403. | E1-IG, E2-GB | |

> Lưu ý cao độ: cột "Cơ chế" để TRỐNG bây giờ — đó là việc Module 4. Ở đây chỉ viết
> CÁI GÌ. Nếu thấy mình đang gõ "JWT", "HMAC" vào cột Mục tiêu → dừng, đó là cơ chế.
>
> Kiểm độ phủ ngược: cả 11 threat của Module 2 đều xuất hiện trong cột "Từ threat" —
> không threat nào không có mục tiêu lo. ✅
