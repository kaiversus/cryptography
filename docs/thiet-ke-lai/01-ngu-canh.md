# Module 1 — Ngữ cảnh (Context)

> Mục tiêu: trước khi nói tới rủi ro hay giải pháp, phải mô tả CHÍNH XÁC ta đang bảo
> vệ cái gì, cho ai, trong môi trường nào. Thiếu bước này → mọi thứ sau đều đoán mò.

Ngữ cảnh gồm 5 thành phần. Thiếu bất kỳ cái nào, thầy sẽ hỏi và bạn sẽ đứng hình.

---

## 1.1 Mục đích hệ thống (1 đoạn, không kỹ thuật)

Hệ thống làm gì, vì ai, giải quyết vấn đề gì. Viết như giải thích cho người không
biết IT. KHÔNG nhắc JWT/HMAC/Keycloak ở đây.

> **TODO (bạn viết):**
>
> _..._

---

## 1.2 Actors — ai/cái gì tương tác với hệ thống?

Mỗi actor: tên, là người hay máy, mục đích, mức tin cậy (trusted/semi/untrusted).

| Actor | Người/Máy | Mục đích | Mức tin cậy |
|---|---|---|---|
| _(ví dụ mẫu, tôi cho sẵn)_ Người dùng cuối | Người | Đăng nhập, gọi API thay mình | Untrusted |
| **TODO** | | | |
| **TODO** | | | |

> Gợi ý tự hỏi: ai *khởi tạo* request? Ai *cấp* danh tính? Ai *nhận* request sau
> gateway? Ai *vận hành* hệ thống? Và — **kẻ tấn công có phải một actor không?**

---

## 1.3 Assets — tài sản phải bảo vệ (PHẦN QUAN TRỌNG NHẤT)

Đây là gốc của mọi mục tiêu bảo mật sau này. Không có asset → không có gì để bảo vệ
→ không có rủi ro. Với mỗi asset, ghi: nó là gì, **tại sao quý**, mất nó thì sao.

| Asset | Tại sao quý | Hậu quả nếu lộ/mất/sửa |
|---|---|---|
| **TODO** | | |
| **TODO** | | |

> Gợi ý: nghĩ về thứ mà *nếu kẻ tấn công có được* thì game over. (Khóa ký? Token?
> Danh tính người dùng? Chính các API backend?)

---

## 1.4 Trust boundaries — ranh giới tin cậy

Ranh giới = chỗ mức tin cậy thay đổi. **Mỗi lần dữ liệu vượt ranh giới = chỗ BẮT
BUỘC phải có một control bảo mật.** Đây là thứ thầy nói nhóm thiếu.

> **TODO:** liệt kê các cặp "A nói chuyện với B" và đánh dấu đâu là ranh giới tin cậy:
>
> - Internet ↔ ? : ranh giới? control gì?
> - Gateway ↔ ? : ...
> - Gateway ↔ ? : ...

---

## 1.5 Giả định & ràng buộc (Assumptions & Constraints)

Những thứ ta *coi là đúng* (vd: TLS đã chặn ở đâu? mạng nội bộ tin được tới mức nào?)
và những *ràng buộc* bắt buộc (vd: phải dùng OAuth2/OIDC, chạy trên cloud/k8s).

> **TODO:**
> - Giả định: _..._
> - Ràng buộc: _..._

---

## 1.6 Use-cases / luồng dữ liệu chính

Đề bài có 2 luồng. Mô tả mỗi luồng bằng lời (ai → làm gì → qua đâu):

> **TODO:**
> - Luồng A (người dùng tương tác): _..._
> - Luồng B (service-to-service / máy-với-máy): _..._
