# Thiết kế lại đồ án — Sổ tay học & làm song song

> Đây là tài liệu thiết kế MỚI, xây lại theo đúng chuỗi tư duy security-by-design.
> Mỗi module = một buổi học + một phần tài liệu thật. Học tới đâu, điền tới đó.

## Tại sao phải làm lại?

Thầy nhận xét: nhóm **nhảy thẳng tới triển khai**, bỏ qua toàn bộ chuỗi lý luận
giải thích *tại sao* lại làm như vậy. Cái mà README gọi là "Kiến trúc" thực ra là
**kịch bản triển khai** (có port `:8081`, `:6379`, tên sản phẩm Keycloak/Redis...).

## Chuỗi tư duy chuẩn (mỗi bước ĐẺ ra từ bước trước)

```
① NGỮ CẢNH    →  ② RỦI RO   →  ③ MỤC TIÊU    →  ④ KIẾN TRÚC      →  ⑤ KỊCH BẢN
   (Context)      (Risk)        BẢO MẬT          GIẢI PHÁP            TRIỂN KHAI
                                (Objectives)     net/host/app         (Deployment)
```

Luật vàng: **không được chọn công nghệ nào** (JWT, HMAC, Vault...) nếu chưa chỉ ra
nó giết **rủi ro nào**, mà rủi ro đó sinh từ **ngữ cảnh nào**.

## Phân biệt Kiến trúc giải pháp vs Kịch bản triển khai

| | Kiến trúc giải pháp | Kịch bản triển khai |
|---|---|---|
| Trả lời | **Cái gì** + **tại sao** | **Chạy bằng gì, ở đâu** |
| Port/IP? | Không | Có |
| Tên sản phẩm? | Hạn chế (nói "IdP", "Secret Store") | Có (Keycloak, Redis, Vault) |
| Đổi Docker→K8s | Không đổi | Đổi hết |

## Lộ trình (7 module)

- [x] **Module 1 — Ngữ cảnh** → `01-ngu-canh.md`
- [x] **Module 2 — Rủi ro / Threat model** → `02-rui-ro.md`  *(11 threat, 4 ranh giới, map STRIDE+SEC+OWASP)*
- [x] **Module 3 — Mục tiêu bảo mật** → `03-muc-tieu-bao-mat.md`  *(6 mục tiêu, phủ 11 threat)*
- [x] **Module 4 — Kiến trúc giải pháp (net/host/app+dataflow)** → `04-kien-truc-giai-phap.md`  *(cơ chế truy về MT + 3 tầng net/host/app)*
- [x] **Module 5 — Kịch bản triển khai** → `05-kich-ban-trien-khai.md`  *(map vai trò→sản phẩm, published vs internal, dev vs prod)*
- [x] **Module 6 — Đối chiếu code thật** → `06-doi-chieu-code.md`  *(11/11 file, 4 phát hiện F1-F4)*
- [ ] **Module 7 — Chuẩn bị bảo vệ (Q&A với thầy)** → `07-bao-ve.md`  *(đang học)*

## Cách làm việc

1. Tôi dạy khung tư duy của module.
2. Bạn **tự điền** phần TODO trong file module (tự nghĩ, đừng hỏi AI gen).
3. Bạn báo "xong", tôi phản biện như thầy sẽ phản biện.
4. Chốt phần đó → tick checkbox → sang module sau.
