# Module 4 — Kiến trúc giải pháp (Solution Architecture)

> Đây là nơi LẦN ĐẦU được chọn công nghệ. Nhưng luật vàng: **mỗi lựa chọn phải truy
> ngược về một MT (Module 3) → MT về threat (M2) → threat về asset (M1)**. Không có
> "vì đề bài bảo dùng JWT". Và: kiến trúc **KHÔNG có port/IP/tên sản phẩm** — cái đó
> để Module 5 (triển khai). Lẫn hai cái này = đúng lỗi thầy chê.

---

## Kiến trúc giải pháp vs Kịch bản triển khai (nhắc lại, vì đây là lỗi lớn nhất)

| | Kiến trúc giải pháp (Module này) | Kịch bản triển khai (Module 5) |
|---|---|---|
| Nói | "IdP", "Secret Store", "Gateway" | "Keycloak", "Vault", port `:8081` |
| Cơ chế | "chữ ký bất đối xứng", "khóa công bố qua key-set" | "ES256 + JWKS endpoint Keycloak" |
| Đổi Docker→K8s | **Không đổi** | Đổi hết |

Mẹo tự kiểm: nếu trong sơ đồ có **số cổng, IP, hoặc logo sản phẩm** → bạn đang vẽ
triển khai, không phải kiến trúc.

---

## Kiến trúc chia 3 TẦNG (đúng chữ thầy: net / host / app+dataflow)

| Tầng | Trả lời câu hỏi | Phục vụ MT nào |
|---|---|---|
| **Net** (mạng) | Ai được nói chuyện với ai? Ranh giới chặn ở đâu? Vùng tin cậy? | MT-AUTHN (mTLS), MT-AVAIL, chữa flat-trust |
| **Host** (máy/container) | Mỗi thành phần chạy ở đâu? Cô lập & lưu bí mật thế nào? | MT-CONF, cô lập backend |
| **App + Data flow** (logic) | Trên LUỒNG request, control đặt ở ĐIỂM nào? | MT-AUTHN/INTEG/AUTHZ/NONREP |

---

## Bước A — Chọn CƠ CHẾ cho từng mục tiêu (điền cột trống của Module 3)

Với mỗi MT: cơ chế nào đạt được nó, và **tại sao cơ chế NÀY** (không phải cái khác).

### Ví dụ mẫu (tôi làm MT-AUTHN — bạn theo mẫu)

**MT-AUTHN → Cơ chế: chữ ký số BẤT ĐỐI XỨNG, khóa công khai công bố qua key-set + mTLS ở tầng net.**

*Tại sao bất đối xứng (không phải đối xứng)?*
- Đối xứng (HMAC/HS256): cùng một khóa vừa ký vừa verify → gateway phải giữ khóa *ký*
  → khóa đó lộ ở gateway = giả được mọi token. **Exposure cao** (nhớ asset Module 1).
- Bất đối xứng (ES256): IdP giữ khóa *riêng* để ký, gateway chỉ giữ khóa *công khai* để
  verify. Khóa ở gateway có lộ cũng **không ký giả được**. → đạt MT-AUTHN với exposure thấp.
- ⇒ Đây là câu trả lời cho RQ1 của đề: "vì sao ES256 hơn HS256" — truy từ asset→exposure.

*Khóa công khai tới gateway bằng gì?* Một **key-set công bố** (mỗi khóa có định danh
`kid`): gateway đọc key-set, chọn khóa theo `kid` trong header token, verify bằng
toán — không phụ thuộc mạng mỗi request, và **xoay khóa** được (nhiều kid).

*Còn S1-GB (bypass gateway)?* Thuộc MT-AUTHN ở tầng **net**: **mTLS** — backend chỉ
nhận kết nối từ peer trình được chứng chỉ hợp lệ = gateway.

| MT | Cơ chế chọn | Tại sao cơ chế này (truy về threat/asset) |
|---|---|---|
| MT-AUTHN | Chữ ký bất đối xứng + key-set công bố; mTLS | Bất đối xứng → gateway chỉ giữ public key, exposure thấp (S1-IG); key-set + `kid` để xoay khóa (S1-IdP); mTLS để backend xác thực gateway (S1-GB) |
| MT-INTEG | MAC (HMAC) trên body + nonce + timestamp | MAC dùng khóa chung đã cấp sẵn cho M2M, rẻ-nhanh hơn chữ ký, phát hiện sửa body (T1-IG); nonce+timestamp → mỗi request hiệu lực 1 lần trong cửa sổ, kho nonce không phình (RP1-IG) |
| MT-NONREP | Chữ ký số (khóa riêng chủ thể) + audit log append-only | Chỉ chủ thể giữ khóa riêng → không chối được (R1-IG). *Lưu ý:* M2M hiện dùng HMAC → chỉ non-repudiation tương đối; muốn tuyệt đối phải dùng chữ ký bất đối xứng |
| MT-CONF | TLS + mã hóa at-rest (secret store) + least-privilege + audit | TLS chống sniff in-transit; at-rest bảo vệ secret trong kho; least-privilege trị "nội bộ ai cũng đọc" (I1-Vault); chọn bất đối xứng → gateway không giữ secret ký (I1-IG) |
| MT-AVAIL | Rate-limiting (per-IP + per-client) + thứ tự "rẻ trước, crypto đắt sau" | Rate-limit chặn flood (D1-IG); kiểm rẻ (format/exp/timestamp/nonce) trước verify chữ ký → rác bị loại không tốn CPU, chống DoS tầng ứng dụng |
| MT-AUTHZ | Scope/RBAC + kiểm quyền mọi tầng; backend chỉ tin nguồn có chữ ký | Endpoint kiểm scope → 403 nếu thiếu (E1-IG); backend verify token gốc/claim ký, không tin header trần (E2-GB) |

> Bẫy cao độ ngược: ở đây ĐƯỢC nói cơ chế ("chữ ký bất đối xứng"), nhưng CHƯA nói sản
> phẩm ("Keycloak"). "Chữ ký bất đối xứng" = cơ chế ✅. "ES256" = thuật toán cụ thể,
> ranh giới mờ — chấp nhận. "Keycloak realm nt219" = triển khai ❌ (để M5).

---

## Bước B — Tầng NET: vùng tin cậy & ranh giới (chữa flat-trust)

Vẽ hệ thống thành các **vùng tin cậy (trust zones)**, đánh dấu mỗi ranh giới phải có
control gì. KHÔNG vẽ port/IP.

4 vùng tin cậy, 3 cửa — mỗi cửa một lính gác (defense in depth, không "phẳng"):

```
[ Internet ]──cửa1──►[ Gateway zone ]──cửa2──►[ Backend zone ]   [ Secret zone ]
  untrusted          semi-trusted             trusted-internal    ▲
                                                                  └─cửa3─ Gateway zone
```

| Cửa | Nối 2 vùng | Control (tầng net) | Phục vụ |
|---|---|---|---|
| 1 | Internet → Gateway | TLS + rate-limit | MT-AUTHN, MT-AVAIL |
| 2 | Gateway → Backend | **mTLS** (backend xác thực gateway, không tin vị trí mạng) | MT-AUTHN (S1-GB) |
| 3 | Gateway → Secret store | TLS + least-privilege (service tự xác thực, đọc đúng secret của mình) | MT-CONF (I1-Vault) |

**Vì sao backend zone KHÔNG được "phẳng + tin tất cả":** nếu backend tin mọi thứ
trong mạng, hacker chỉ cần đặt chân vào *một* chỗ bất kỳ bên trong (chiếm 1 container
phụ) là **vòng qua gateway gọi thẳng backend** (threat S1-GB) — gateway thành lính gác
*duy nhất*, thủng 1 chỗ là thủng tất. mTLS ở cửa 2 → kể cả đã ở trong mạng, không có
chứng chỉ thì không nói chuyện được với backend (zero-trust).

---

## Bước C — Tầng HOST: cô lập & lưu bí mật

Hai nguyên tắc: **(1) mỗi thành phần một hộp riêng** (vỡ hộp này không vỡ hộp kia);
**(2) bí mật nạp từ secret store lúc chạy, KHÔNG hardcode / nướng vào image / commit git.**

| Thành phần | Cô lập | Bí mật nó giữ & sống ở đâu |
|---|---|---|
| Gateway | Hộp riêng, chỉ mở cho cửa 1 | Secret HMAC + (khóa riêng mTLS) → nạp từ secret store, không vào image. Public key verify token = công khai |
| Backend | Cô lập với Internet, chỉ nhận từ vùng Gateway (cửa 2) | **Khóa riêng + chứng chỉ mTLS của nó** → secret store, không nướng vào image. CA/IdP public key (để verify) = công khai |
| IdP | Hộp riêng | **Khóa riêng để ký token** → bảo vệ nghiêm ngặt nhất (lộ = giả mọi token) |
| Secret store | Hộp riêng, chỉ vùng được phép chạm | Là *kho* của mọi secret; least-privilege từng service |

> Bài học lặp: **khóa riêng = giấu trong secret store; khóa/chứng chỉ công khai = phơi
> ra vô hại.** Cùng logic chọn bất đối xứng ở MT-AUTHN.

---

## Bước D — Tầng APP + DATA FLOW: đặt control lên luồng

Lấy 2 luồng từ Module 1 (người dùng tương tác; M2M), vẽ lại và đánh dấu **mỗi điểm
control** trên đường đi.

Luồng "User có token → Gateway → Backend" thành một **dây chuyền chốt kiểm**, rớt chốt
nào chặn ngay. Thứ tự: **rẻ → đắt → quyền**.

```
Request tới Gateway
 ├─[1] Rate-limit            quá ngưỡng → 429   (MT-AVAIL · rẻ)
 ├─[2] Token? định dạng?     thiếu/méo  → 401   (rẻ)
 ├─[3] exp / timestamp       hết/quá cũ → 401   (rẻ)
 ├─[4] nonce đã dùng?        trùng      → 401   (rẻ · chống replay RP1-IG)
 ├─[5] HMAC body khớp?       sai        → 401   (MT-INTEG · đắt)
 ├─[6] Verify chữ ký token   sai        → 401   (MT-AUTHN · đắt ← AUTHENTICATION)
 ├─[7] Scope/role đủ?        thiếu      → 403   (MT-AUTHZ ← AUTHORIZATION)
 │
 └─► [mTLS cửa 2] ──► Backend
        └─[8] Backend tự kiểm lại (zero-trust): verify token gốc/claim ký +
              re-check scope, KHÔNG tin header trần   (MT-AUTHN/AUTHZ · E2-GB)
```

Hai nguyên lý tầng App:
1. **Rẻ → đắt → quyền:** chặn rác bằng check rẻ (1-4) *trước* khi tốn crypto (5-6), rồi
   mới xét quyền (7). → chống DoS tầng ứng dụng (MT-AVAIL).
2. **authn (401) ≠ authz (403):** chốt 6 hỏi "anh là ai" (sai → 401); chốt 7 hỏi "anh
   được làm gì" (thiếu quyền → 403). Không bao giờ trộn.

> mTLS KHÔNG nằm trong dây chuyền app — nó là bắt tay tầng Net (cửa 2), xảy ra trước
> khi request tới backend. Chốt 8 = backend *không tin mù*, tự kiểm lại (zero-trust).

---

## Sơ đồ kiến trúc (vẽ cuối, sau khi xong A–D)

Quy ước: hộp = vai trò (IdP/Gateway/Backend/Secret Store), mũi tên = luồng + control
trên đó, vùng = trust zone. **Không** port, **không** tên sản phẩm.

### Hình 1 — Luồng REQUEST + vùng tin cậy (tầng Net)

```
   UNTRUSTED              SEMI-TRUSTED               TRUSTED-INTERNAL
 ┌────────────┐  cửa 1  ┌─────────────┐   cửa 2    ┌────────────┐
 │ Người dùng │  TLS    │             │   mTLS     │            │
 │   / M2M    │ ──────► │   GATEWAY   │ ─────────► │  BACKEND   │
 │            │  rate   │             │            │            │
 └────────────┘         └─────────────┘            └────────────┘
```

### Hình 2 — Luồng SECRET (tầng Host) — hub, KHÔNG đi qua backend

```
   ┌─────────┐      ┌─────────┐      ┌─────────┐
   │   IdP   │      │ GATEWAY │      │ BACKEND │
   └────┬────┘      └────┬────┘      └────┬────┘
        │ khóa riêng     │ secret HMAC    │ khóa riêng
        │ ký token       │ + khóa mTLS    │ mTLS của nó
        │ (giữ tại chỗ)  ▼                ▼
        │           ┌──────────────────────────┐
        └ public ──►│   SECRET STORE (hub)      │  cửa 3: TLS + least-privilege
          key-set   │   mỗi service lấy đúng    │  (mỗi service tự xác thực,
          (JWKS)    │   phần của mình           │   đọc đúng secret của mình)
                    └──────────────────────────┘
```

### Hình 3 — Bên trong GATEWAY: dây chuyền chốt (tầng App)

```
  [1] rate-limit ───────────────── 429
  [2] token / format ──┐
  [3] exp / timestamp ─┼─ rẻ ────── 401
  [4] nonce (replay) ──┘
  [5] HMAC body ───────┐ đắt
  [6] verify chữ ký ───┘ (crypto) ─ 401   ← AUTHENTICATION ("anh là ai")
  [7] scope / role ──────────────── 403   ← AUTHORIZATION  ("được làm gì")
        │
        └─► [mTLS cửa 2] ─► BACKEND: [8] tự kiểm lại (zero-trust) → 401/403
```

**Đọc 3 hình = trả lời mọi câu của thầy:** mỗi mũi tên có control (Net), mỗi hộp cô
lập + giữ bí mật đúng chỗ qua hub (Host), trong gateway là dây chuyền rẻ→đắt→quyền
(App). **Luồng request (Hình 1) tách khỏi luồng nạp secret (Hình 2)** — đừng trộn.
Không một số cổng / tên sản phẩm nào — đó là việc Module 5.
