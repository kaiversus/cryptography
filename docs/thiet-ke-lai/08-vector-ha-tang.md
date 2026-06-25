# Module 8 — Bốn vector tầng HẠ TẦNG (kiến trúc & triển khai)

> Khác 6 vector ở Module 7 (lỗ hổng logic *trong* gateway, test xanh được). Bốn
> vector này nhắm vào **control kiến trúc/triển khai** (mTLS, backend zero-trust,
> JWKS-over-TLS, Vault-TLS). Một số control **chưa được hiện thực** trong PoC — phần
> này ghi TRUNG THỰC trạng thái, không ngụy tạo "test xanh".

---

## Bảng tổng — 4 vector, phòng thủ, trạng thái

| # | Vector | Threat | Phòng thủ đúng | Hiện trạng PoC | Bằng chứng |
|---|---|---|---|---|---|
| 7 | Đứng nội bộ gọi thẳng backend, vòng qua gateway | S1-GB | mTLS cửa 2 + backend không publish | **Chưa có backend & mTLS** | Cô lập mạng (prod compose) — mTLS phải build |
| 8 | Backend tin header gateway → spoof header leo quyền | E2-GB | Backend verify lại token gốc (chốt 8) | **Chưa có backend**; nguyên lý đã test | `test_backend_zerotrust.py` (SEC-14) |
| 9 | Tráo JWKS (DNS/non-TLS) nhét key hacker | S1-IdP | Fetch JWKS **qua TLS** + pin issuer | JWKS qua HTTP (dev) | `sec_jwks_substitution_demo.py` (SEC-15) |
| 10 | Gateway↔Vault không mã hóa → nội bộ đọc khóa | I1-Vault | TLS tới Vault + least-priv + bỏ root token | Vault HTTP + root token; F4 bắt buộc có token | Cấu hình prod compose |

---

## Vector 7 — Vòng qua gateway gọi thẳng backend (S1-GB)

**Đòn:** kẻ tấn công đã đặt chân vào mạng nội bộ (chiếm 1 container phụ, hoặc lỗ
SSRF). Nếu backend tin "ai trong mạng cũng hợp lệ", nó gọi thẳng backend, **bỏ qua
toàn bộ dây chuyền chốt** của gateway.

**Phòng thủ đúng (2 lớp):**
1. **Cô lập mạng:** backend KHÔNG publish cổng ra ngoài — chỉ tồn tại bằng IP riêng
   trong `gw-net`. (Đã thể hiện trong `docker-compose.prod.yml`: chỉ gateway phơi ra.)
2. **mTLS cửa 2:** backend chỉ chấp nhận kết nối từ peer **trình được chứng chỉ hợp
   lệ = gateway**. Kể cả đã ở trong mạng, không có cert thì không nói chuyện được
   (zero-trust ở tầng net).

**Trạng thái PoC:** PoC hiện **không có service backend riêng** (gateway trả JSON trực
tiếp), nên **chưa có mTLS**. Đây là **GAP thiết kế-vs-hiện thực**, phải nêu rõ. Lớp 1
(cô lập mạng) đã demo được qua prod compose; lớp 2 (mTLS) cần build cert + backend.

---

## Vector 8 — Backend tin header gateway chuyển xuống (E2-GB)

**Đòn:** mẫu hình phổ biến: gateway xác thực xong, chuyển danh tính/quyền xuống backend
qua header (vd `X-User`, `X-Role`). Nếu backend **tin header này vô điều kiện**, kẻ tấn
công có token user thường nhưng tự đặt `X-Role: admin` → **leo quyền**.

**Phòng thủ đúng — "chốt 8 zero-trust":** backend KHÔNG tin header trần. Nó **tự verify
lại token gốc** (chữ ký IdP) và đọc quyền từ **claim ĐÃ KÝ**, không từ header do client
gửi. Header chỉ là tiện ích, không phải nguồn tin cậy.

**Bằng chứng (SEC-14, `test_backend_zerotrust.py`):** mô phỏng 2 backend:
- `naive_backend` tin `X-Role` → **bị lừa** (test khẳng định nó trả True với token user
  + header spoof — chứng minh tại sao KHÔNG được làm vậy).
- `zerotrust_backend` verify lại token → đọc role từ claim ký → **chặn** spoof; chỉ cho
  qua khi role admin thật nằm trong token.

**Trạng thái PoC:** chưa có backend thật nên đây là **test nguyên lý** (dùng chính
`verify_token` làm bước backend kiểm lại). Khi thêm backend thật, bắt buộc áp dụng pattern
zero-trust này.

---

## Vector 9 — Tráo JWKS (S1-IdP)

**Đòn:** gateway fetch public key từ IdP qua URL JWKS. Nếu kênh đó **không TLS** (hoặc
DNS bị đầu độc), kẻ tấn công chặn giữa đường, trả **JWKS giả** chứa public key **của
nó**. Rồi nó ký token bằng private key tương ứng, đặt `iss/aud/kid` khớp.

**Điểm cốt lõi — app-logic BẤT LỰC:** mọi kiểm tra trong `verify_token` (whitelist alg,
verify iss/aud, tra `kid`) **đều PASS**, vì token "hợp lệ" với bộ khóa đã bị tráo. Kẻ tấn
công kiểm soát cả token lẫn khóa nên mọi thứ tự khớp.

**Bằng chứng (SEC-15, `sec_jwks_substitution_demo.py`):** demo tạo cặp khóa ES256 của
hacker, thay `_get_jwks` trả về key đó, ký token tự phong `admin` → `verify_token` **chấp
nhận**. Kết quả "đòn lọt" này chính là thông điệp:

> **Control duy nhất chặn được substitution nằm ở TẦNG TRUYỀN DẪN: fetch JWKS qua
> HTTPS/TLS, kèm pin issuer/CA.** Không có cách nào sửa logic ứng dụng để tự cứu.

**Trạng thái PoC:** dev fetch JWKS qua `http://keycloak:8080` (nội bộ). Prod **bắt buộc**
HTTPS tới IdP. Hardening thêm: pin CA, hoặc nạp sẵn key tin cậy.

---

## Vector 10 — Lộ khóa ở kênh Gateway↔Vault (I1-Vault)

**Đòn:** nếu kênh Gateway↔Vault **không mã hóa** hoặc cấu hình sai (token quá rộng, để
root token), bất kỳ ai nghe lén/đứng trong nội bộ đều đọc được secret/khóa.

**Phòng thủ đúng:**
1. **TLS** tới Vault (chống nghe lén in-transit).
2. **Least-privilege policy:** mỗi service chỉ đọc đúng path của mình, không dùng root
   token.
3. **At-rest + audit** trong Vault.

**Trạng thái PoC:** dev dùng Vault `server -dev` (HTTP, root token, in-memory) — lối tắt
dev. Đã siết một phần: **F4** bắt `vault_client` phải có token (fail-closed, bỏ default
"dev-root-token"). Còn lại (TLS + policy least-priv) là **deployment**, mô tả trong
`docker-compose.prod.yml` (Vault internal-only) — bật TLS thật là bước hardening tiếp.

---

## Tóm tắt cho thầy

- Vector **8, 9** demo được ngay: `test_backend_zerotrust.py` (chốt 8) và
  `sec_jwks_substitution_demo.py` (vì sao JWKS phải qua TLS).
- Vector **7, 10** là control **kiến trúc/triển khai** — chứng minh bằng cô lập mạng
  (`docker-compose.prod.yml`) và cấu hình TLS, KHÔNG phải test logic. mTLS + Vault-TLS là
  hạng mục build hạ tầng riêng (cert, backend), nêu rõ là phần hardening trước prod.
- **Thành thật là điểm cộng:** nêu đúng cái nào đã làm, cái nào mới thiết kế — đó chính là
  tư duy "kiến trúc ≠ triển khai" mà thầy yêu cầu.
