# Module 5 — Kịch bản triển khai (Deployment Scenario)

> M4 nói "vai trò + cơ chế" (trừu tượng: IdP, Secret Store, chữ ký bất đối xứng).
> M5 = **hiện thực hóa**: vai trò nào là sản phẩm nào, chạy trên máy/IP nào, mở cổng
> ra sao, secret bơm vào kiểu gì. Đây là tầng **cụ thể nhất** — và là nơi câu hỏi của
> thầy "triển khai ở IP gì?" thuộc về. Quan trọng nhất: **deployment là nơi các quyết
> định bảo mật của M4 được THỰC THI hoặc bị PHÁ VỠ.**

---

## PHẦN 0 — Giải đáp thẳng: "IP" là số cụ thể hay nói chung chung?

Thầy hỏi "triển khai ở IP gì" không phải để nghe một con số kiểu `203.0.113.5`. Thầy
đang dò xem **bạn có hiểu hệ thống của mình ngồi ở đâu trong mạng, cái gì lộ ra ngoài,
cái gì giấu bên trong** hay không. Nhưng để trả lời được câu đó, bạn phải hiểu rõ "IP"
thực sự là gì. Có **4 loại địa chỉ** bạn bắt buộc phân biệt — đây là gốc rễ mọi nhầm lẫn.

### 4 loại địa chỉ phải phân biệt

| Địa chỉ | Tên gọi | Ý nghĩa | Ai gọi được? |
|---|---|---|---|
| `127.0.0.1` | **loopback / localhost** | "Chính máy này, gọi vào chính nó" | Chỉ tiến trình **trên cùng máy đó** |
| `0.0.0.0` | **bind-all / mọi interface** | "Nghe trên TẤT CẢ card mạng của máy" | Bất kỳ ai **tới được máy này qua mạng** |
| `10.x / 172.16–31.x / 192.168.x` | **IP riêng (private, RFC 1918)** | Địa chỉ chỉ có giá trị **trong mạng nội bộ** (LAN, mạng Docker, VPC) | Chỉ máy **trong cùng mạng nội bộ** |
| Ví dụ `203.0.113.5` | **IP công khai (public)** | Địa chỉ **định tuyến được trên Internet** | **Bất kỳ ai trên Internet** |

Hai khái niệm này thường bị nhầm là một, nhưng khác nhau hoàn toàn:

- **IP nào** một dịch vụ *nghe* (bind/listen) → quyết định **ai chạm được tới nó**.
- **IP riêng vs công khai** → quyết định **phạm vi** một địa chỉ có ý nghĩa (chỉ trong
  nhà, hay cả thế giới).

> **Chốt hiểu:** "bind `0.0.0.0`" nghĩa là *nghe trên mọi đường vào*. Nếu máy đó có một
> IP công khai, thì `0.0.0.0` = **phơi ra Internet**. Nếu máy đó chỉ có IP riêng trong
> mạng nội bộ, thì `0.0.0.0` = phơi ra *mạng nội bộ thôi*. Cùng một dòng config
> `0.0.0.0`, mức độ nguy hiểm phụ thuộc máy đó nằm ở đâu. Đây chính là thứ thầy hỏi.

### Trong đồ án này, "IP" cụ thể là gì?

Đồ án chạy bằng **Docker Compose** trên một máy. Docker tạo một **mạng ảo riêng** tên
`gw-net` (xem dòng cuối `docker-compose.yml`). Khi đó có **hai mặt phẳng địa chỉ**:

**(a) Bên trong mạng `gw-net` — IP riêng do Docker tự cấp.**
Mỗi container được Docker gán một IP riêng kiểu `172.x.x.x` (ví dụ `172.20.0.3`). Nhưng
**bạn gần như không bao giờ gõ số đó**, vì Docker có sẵn **DNS nội bộ theo tên service**:
container `gateway` muốn gọi Vault thì chỉ cần gọi `http://vault:8200` — chữ `vault` tự
được Docker phân giải thành đúng IP `172.x` của container Vault. Bằng chứng trong file:

```yaml
gateway:
  environment:
    KEYCLOAK_URL: http://keycloak:8080   # "keycloak" = tên service, KHÔNG phải IP số
    REDIS_HOST: redis                    # "redis"   = tên service
    VAULT_ADDR: http://vault:8200        # "vault"   = tên service
```

→ Đây là câu trả lời cho "IP nội bộ là gì": **các service gọi nhau bằng TÊN (Docker DNS),
Docker dịch tên đó ra IP riêng `172.x` trong mạng `gw-net`.** Người Internet **không hề
biết và không chạm được** những IP `172.x` này.

**(b) Ra ngoài máy host — qua "publish port".**
Để bạn (hay người dùng) gọi được từ ngoài container, Docker phải **ánh xạ cổng** từ máy
host vào container. Đó là ý nghĩa dòng `ports`:

```yaml
gateway:
  ports: ["8000:8000"]   # host:container — mở cổng 8000 của MÁY HOST, nối vào 8000 trong container
```

`ports: ["8000:8000"]` mặc định bind vào `0.0.0.0` của **máy host** — tức nghe trên mọi
card mạng của host. Nếu host này là một server có IP công khai, thì cổng 8000 đó **ai
trên Internet cũng gọi tới được**. Nếu chỉ chạy ở laptop của bạn (localhost), thì chỉ máy
bạn gọi được. **Chính dòng `ports` này là "biên giới" giữa trong và ngoài.**

> **Tóm lại cho thầy hỏi "IP gì":** "Các thành phần nói chuyện nội bộ qua mạng riêng
> Docker `gw-net`, dùng tên service (Docker DNS) ánh xạ sang IP riêng `172.x`, không phơi
> ra ngoài. Chỉ những service có khai báo `ports:` mới được ánh xạ ra IP của máy host;
> ở production chúng tôi **chỉ** ánh xạ cổng của Gateway ra IP công khai, còn Vault/Redis/
> Backend **không** publish — chúng chỉ tồn tại bằng IP riêng nội bộ." Đó là câu trả lời
> đúng tầng, đúng trọng tâm — không cần đọc một con số IP nào.

---

## PHẦN 1 — Tư duy cốt lõi: M5 hiện thực hóa M4

Đừng nghĩ M5 chỉ là "bảng port". Mỗi quyết định kiến trúc ở M4 phải có một **hành động
triển khai tương ứng** ở M5, nếu không nó chỉ là lời nói suông:

| M4 nói (kiến trúc) | M5 phải làm (triển khai) | Nếu M5 làm sai → |
|---|---|---|
| "Backend ở vùng trusted-internal, Internet không chạm" | KHÔNG publish cổng backend ra host | Publish cổng backend → ai cũng gọi thẳng (vỡ S1-GB) |
| "Secret store chỉ vùng được phép chạm" | KHÔNG publish `:8200` ra ngoài; policy least-priv | Phơi Vault → lộ toàn bộ secret |
| "Kho nonce trong nội bộ" | Redis chỉ nghe trong mạng `gw-net` | Publish `:6379` → ai cũng xóa/đọc nonce |
| "Cửa 1 có TLS" | Cấu hình TLS termination ở ingress | HTTP trần → sniff được token |

> **Phép kiểm M4 ↔ M5:** mỗi vùng tin cậy / control trong M4 có được *thực thi* bằng một
> cấu hình triển khai cụ thể không? Khoảng trống = lỗ hổng thật.

---

## PHẦN 2 — Từng công nghệ: LÀ GÌ, LÀM GÌ, VÌ SAO CHỌN

Đây là phần để bạn hiểu rõ công nghệ. Mỗi sản phẩm = hiện thực của một **vai trò M4**.

### 2.1 FastAPI (Python) — hiện thực vai trò **Gateway**

- **Là gì:** một web framework Python để dựng API tốc độ cao (chạy trên ASGI server
  Uvicorn). Trong đồ án nó là tiến trình lắng nghe cổng `8000`.
- **Làm gì ở đây:** chạy toàn bộ **dây chuyền chốt** của M4 — rate-limit, kiểm token,
  exp/timestamp, nonce, HMAC body, verify chữ ký, kiểm scope/role — rồi mới chuyển tiếp
  vào backend. Nó là **cửa 1 và lính gác duy nhất ở biên**.
- **Vì sao chọn:** nhẹ, async (chịu tải tốt → phục vụ MT-AVAIL), hệ sinh thái crypto
  Python (PyJWT, cryptography) sẵn để verify ES256/RS256/HMAC. Có middleware để cắm
  chuỗi chốt theo đúng thứ tự rẻ→đắt→quyền.
- **Cổng:** `8000:8000` → **đây là service DUY NHẤT đáng được phơi ra ngoài.**

### 2.2 Keycloak — hiện thực vai trò **IdP (Identity Provider)**

- **Là gì:** một máy chủ định danh mã nguồn mở (Identity & Access Management), nói chuẩn
  **OAuth2 / OpenID Connect**. Image `quay.io/keycloak/keycloak:24.0`, chạy `start-dev`.
- **Làm gì ở đây:** là nơi **người dùng đăng nhập** và là nơi **phát hành token** (JWT).
  Nó giữ **khóa riêng** để ký token, và công bố **khóa công khai** qua endpoint **JWKS**
  (`/protocol/openid-connect/certs`) để Gateway tải về mà verify chữ ký. Realm `nt219`
  định nghĩa user, client, role.
- **Vì sao chọn:** chuẩn hóa OIDC, có sẵn JWKS + xoay khóa theo `kid` (phục vụ S1-IdP),
  hỗ trợ Authorization Code + PKCE và Client Credentials — đúng 2 luồng (người dùng + M2M)
  đã mô tả ở M1. Không phải tự viết hệ phát hành token (việc cực kỳ dễ sai về bảo mật).
- **Cổng:** `8081:8080` → container nghe `8080`, host map ra `8081`. Ở prod **chỉ phơi
  chọn lọc** endpoint token/JWKS qua ingress; **admin console phải đóng**.

### 2.3 HashiCorp Vault — hiện thực vai trò **Secret Store**

- **Là gì:** một kho quản lý bí mật (secrets manager). Image `hashicorp/vault:1.15`, đang
  chạy `server -dev` (chế độ dev: lưu trong RAM, tự mở khóa, có sẵn root token).
- **Làm gì ở đây:** giữ tập trung các bí mật — **secret HMAC** (`gateway/hmac/...`) và
  **khóa HS256** (`gateway/hs256`). Gateway lúc chạy gọi Vault để **lấy secret theo đường
  dẫn**, thay vì hardcode trong code/image. Đây là cách hiện thực MT-CONF + chống I1-Vault.
- **Vì sao chọn:** tách bí mật ra khỏi mã nguồn (không commit secret vào git), có
  **least-privilege policy** (mỗi service chỉ đọc đúng phần của mình), có **audit log**,
  mã hóa at-rest. Đáp đúng nguyên tắc M4 "bí mật nạp lúc chạy, không nướng vào image".
- **Cổng:** `8200:8200`. **Lý tưởng phải internal-only** — kho quý nhất, tuyệt đối không
  phơi ra Internet.

### 2.4 `vault-seed` — job nạp secret một lần (operational, không phải vai trò bảo mật)

- **Là gì:** một container **chạy một lần rồi thoát** (`restart: "no"`). Nó dùng cùng
  image Vault nhưng chỉ để gõ vài lệnh `vault kv put` rồi tắt.
- **Làm gì ở đây:** **nạp sẵn** các secret vào Vault khi mới dựng stack (dev-key,
  prod-key, hs256). Đây là **cơ chế bơm secret (secret injection)** ở dạng "seed job".
- **Vì sao có:** để môi trường dev có dữ liệu sẵn mà demo, không phải gõ tay. Ở prod, bước
  này được thay bằng quy trình nạp secret an toàn (CI/CD, KMS, không hiển thị giá trị).

### 2.5 Redis — hiện thực vai trò **Kho nonce / blacklist / rate-state**

- **Là gì:** một cơ sở dữ liệu khóa–giá trị trong bộ nhớ (in-memory), cực nhanh. Image
  `redis:7-alpine`.
- **Làm gì ở đây:** lưu **nonce đã dùng** (chống replay RP1-IG), **jti blacklist** (token
  bị thu hồi — SEC-10), và **trạng thái rate-limit** per-IP/per-client (MT-AVAIL). Vì
  nonce/rate cần đọc–ghi cực nhanh mỗi request nên in-memory là phù hợp.
- **Vì sao chọn:** độ trễ rất thấp (cần cho check mỗi request), có TTL tự hết hạn (nonce
  không phình mãi), đơn giản tin cậy.
- **Cổng:** `6379:6379`. **Phải internal-only** — ai chạm được Redis là xóa được nonce
  (mở đường replay) và xóa được blacklist (token đã thu hồi sống lại).

### 2.6 Prometheus + Grafana + Jaeger — hiện thực vai trò **Quan sát (Observability)**

- **Prometheus** (`:9090`): thu thập **metric** (số request, độ trễ, tỉ lệ lỗi) từ
  Gateway theo chu kỳ. Là "đồng hồ đo" của hệ thống.
- **Grafana** (`:3001→3000`): **bảng trực quan** vẽ biểu đồ từ dữ liệu Prometheus. Là
  "màn hình hiển thị".
- **Jaeger** (`:16686` UI, `:4318` nhận OTLP): **truy vết phân tán (tracing)** — theo dấu
  một request đi qua những chốt nào, mất bao lâu ở mỗi chốt. Là "camera hành trình".
- **Làm gì cho bảo mật:** giúp phát hiện tấn công (đột biến 401/429), đo hiệu năng dây
  chuyền chốt, chứng minh MT-AVAIL hoạt động. Nhưng **chính chúng lại lộ thông tin nội
  bộ** nếu phơi ra → phải internal-only, chỉ admin xem.
- **Cổng:** `9090 / 3001 / 16686` → **tất cả phải đóng với Internet.**

> **Đọc bảng map này một lần là thấy:** cột "vai trò M4" bất biến, cột "sản phẩm" có thể
> đổi (Keycloak→Auth0, Vault→AWS Secrets Manager, Redis→Memcached) mà **kiến trúc M4 không
> đổi**. Đó là bằng chứng đã tách đúng tầng kiến trúc và triển khai.

---

## PHẦN 3 — Topology thật của đồ án (đọc từ `docker-compose.yml`)

### 3.1 Bảng service đầy đủ (số liệu thật từ file compose)

| Service | Sản phẩm (image) | Cổng host→container | Gọi nội bộ bằng | Nên phơi ra ngoài? |
|---|---|---|---|---|
| gateway | FastAPI (build `../gateway`) | `8000:8000` | `gateway:8000` | ✅ **Có** — là cửa 1 duy nhất |
| keycloak | `keycloak:24.0` | `8081:8080` | `keycloak:8080` | ⚠️ Chỉ endpoint token/JWKS |
| vault | `vault:1.15` (dev) | `8200:8200` | `vault:8200` | ❌ Không (internal-only) |
| vault-seed | `vault:1.15` (job) | — (không cổng) | — | ❌ Không (chạy 1 lần rồi thoát) |
| redis | `redis:7-alpine` | `6379:6379` | `redis:6379` | ❌ Không (internal-only) |
| prometheus | `prometheus:v2.51.0` | `9090:9090` | `prometheus:9090` | ❌ Không (chỉ admin) |
| grafana | `grafana:10.4.0` | `3001:3000` | `grafana:3000` | ❌ Không (chỉ admin) |
| jaeger | `jaeger:1.55` | `16686:16686`, `4318:4318` | `jaeger:4318` | ❌ Không (chỉ admin) |

> **Mạng:** tất cả nằm trên cùng một mạng Docker tên **`gw-net`** (khai báo cuối file).
> Trong mạng này chúng gọi nhau bằng **tên service** (Docker DNS) → IP riêng `172.x`.

### 3.2 Sơ đồ hai mặt phẳng địa chỉ

```
        ┌─────────────────── MÁY HOST ───────────────────┐
        │  (publish port = mở cổng host ra ngoài)          │
 NGOÀI  │   8000   8081   8200   6379   9090  3001  16686  │
 ───────┼────┬──────┬──────┬──────┬──────┬─────┬─────┬─────┤
        │    │      │      │      │      │     │     │     │   ← các cổng này hiện
        │    ▼      ▼      ▼      ▼      ▼     ▼     ▼     │     ĐỀU publish (dev)
        │ ┌──────────────── gw-net (mạng riêng Docker) ──┐ │
        │ │ gateway  keycloak  vault  redis  prom graf jg │ │  ← gọi nhau bằng TÊN:
        │ │ 172.x    172.x     172.x  172.x  ...          │ │     http://vault:8200 ...
        │ └───────────────────────────────────────────────┘ │     (IP riêng 172.x)
        └────────────────────────────────────────────────────┘
```

**Điểm mấu chốt để hiểu IP:** bên trong khung `gw-net`, mọi thứ dùng IP riêng `172.x` và
gọi nhau bằng tên — **không ai ngoài Internet chạm được**. Chỉ những mũi tên chọc lên hàng
cổng phía trên (do `ports:`) mới thò ra **IP của máy host**. Hiện cả 7 service đều thò ra
→ đó là **lối tắt dev**, và cũng là chỗ phải siết cho prod (Phần 5).

---

## PHẦN 4 — Mạng triển khai: published vs internal-only ở Production

| Cổng | Production | Vùng tin cậy M4 | Lý do |
|---|---|---|---|
| `:8000` Gateway | ✅ **MỞ** (ra IP công khai) | cửa 1 (untrusted→semi) | Cửa vào DUY NHẤT |
| `:8081` Keycloak | ⚠️ **NỬA** | IdP | token/JWKS mở qua ingress; admin console đóng |
| `:6379` Redis | ❌ **ĐÓNG** | trusted-internal | Phơi → xóa nonce (phá replay RP1-IG), xóa jti blacklist (token thu hồi sống lại SEC-10) |
| `:8200` Vault | ❌ **ĐÓNG** | secret zone | Kho secret, quý nhất — lộ là vỡ tất |
| `:9090/:3001/:16686` | ❌ **ĐÓNG** | quan sát (admin) | Lộ metric/trace nội bộ = info disclosure |

> **Nguyên tắc một câu:** ở prod **chỉ Gateway phơi hoàn toàn ra IP công khai**; IdP phơi
> chọn lọc endpoint qua ingress; còn lại internal-only — nghĩa là **bỏ dòng `ports:`** của
> chúng đi, để chúng chỉ tồn tại bằng IP riêng `172.x` trong `gw-net`. Đây chính là lúc
> vùng tin cậy M4 được *thực thi* bằng cấu hình mạng.

### Cách "đóng" một service trong thực tế

- **Cách đúng nhất:** xóa hẳn khối `ports:` của service đó → Docker không map ra host →
  nó chỉ còn IP riêng nội bộ, chỉ service cùng mạng gọi được.
- **Nếu vẫn cần truy cập local để debug:** bind vào loopback thôi:
  `ports: ["127.0.0.1:8200:8200"]` → chỉ máy host gọi được, người ngoài mạng thì không.
- **Tránh tuyệt đối ở prod:** `ports: ["8200:8200"]` (mặc định `0.0.0.0`) trên một server
  có IP công khai = **phơi Vault ra Internet**.

---

## PHẦN 5 — Lỗ hổng triển khai hiện tại & cách siết (tự đánh giá trung thực)

File compose hiện tại **publish TẤT CẢ cổng** (`8000, 8081, 8200, 6379, 9090, 3001,
16686`) ra `0.0.0.0` của host. Trên laptop dev (localhost) thì vô hại, nhưng nếu bê
nguyên lên một server công khai thì **mọi vùng tin cậy M4 bị xóa sạch**: ai cũng gọi thẳng
Vault, Redis, Keycloak admin. Đây là **đánh đổi dev-mode**, phải ghi rõ và siết trước khi
lên prod.

Ngoài port, vài "lối tắt dev" khác trong file (phải sửa cho prod):

| Trong compose (dev) | Vì sao là lối tắt | Prod phải làm |
|---|---|---|
| Vault `server -dev` + `VAULT_DEV_ROOT_TOKEN_ID: dev-root-token` | Lưu RAM, mất khi restart, root token cố định in trong file | Vault thật có storage backend, sealed, auto-unseal qua KMS, token least-priv |
| `VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200` | Vault nghe mọi interface | Bind nội bộ + không publish + TLS |
| Keycloak `start-dev`, admin/admin | Chế độ dev, mật khẩu yếu | `start` (prod mode), mật khẩu mạnh từ secret store, admin console đóng |
| Grafana anonymous Viewer + admin/admin | Ai cũng xem được dashboard | Tắt anonymous, mật khẩu mạnh, đặt sau mạng nội bộ |
| HMAC/HS256 secret seed yếu (`dev-shared-secret`) | Giá trị demo trong file | Secret mạnh ≥32 byte, bơm từ kho thật, không nằm trong compose |
| Mọi `ports:` publish | Lộ service nội bộ | Chỉ giữ `ports` của gateway; còn lại internal-only |

---

## PHẦN 6 — Bơm secret (secret injection): secret đi từ kho vào container thế nào

Đây là phần thầy hay hỏi "khóa/secret nằm ở đâu, vào app bằng cách nào".

1. **Lúc dựng stack:** job `vault-seed` chạy một lần, gõ `vault kv put` để nạp secret vào
   Vault tại các path `secret/gateway/hmac/...` và `secret/gateway/hs256`, rồi tự thoát.
2. **Lúc Gateway chạy:** Gateway đọc biến môi trường `VAULT_ADDR=http://vault:8200`,
   `VAULT_TOKEN`, `HMAC_VAULT_PATH=gateway/hmac/{key_id}` → gọi Vault **lấy secret theo
   đường dẫn**, KHÔNG đọc secret từ code hay image.
3. **Hệ quả bảo mật:** đổi secret = đổi trong Vault, **không phải build lại image**; secret
   không bao giờ commit vào git. Đây là MT-CONF + chống I1-Vault được thực thi.

> Ở **dev**, token Vault là `dev-root-token` cố định (tiện demo). Ở **prod**, token phải
> là token least-privilege (chỉ đọc đúng path của gateway), cấp động qua AppRole/Kubernetes
> auth, và **không bao giờ in trong compose/env tĩnh**.

---

## PHẦN 7 — TLS chấm dứt (terminate) ở đâu

M4 nói "cửa 1 có TLS". M5 trả lời cụ thể TLS kết thúc ở đâu:

- **Dev (hiện tại):** HTTP trần trên `localhost:8000` — chấp nhận vì chỉ chạy nội bộ máy,
  không có ai sniff giữa đường. **Phải ghi rõ đây là rủi ro chỉ chấp nhận ở dev.**
- **Prod:** đặt một **reverse proxy / ingress** (Nginx, Traefik, hoặc LB của cloud) trước
  Gateway. TLS **chấm dứt tại ingress** (ingress giữ chứng chỉ, giải mã HTTPS), rồi
  chuyển tiếp vào Gateway qua mạng nội bộ. Người dùng luôn nói HTTPS với IP công khai của
  ingress; Gateway và các service phía sau ở trong `gw-net`.
- **Giữa Gateway↔Backend (cửa 2):** dùng **mTLS** — không chỉ mã hóa mà còn để backend
  **xác thực** rằng peer đúng là Gateway (chống S1-GB), không tin vị trí mạng.

---

## PHẦN 8 — Dev vs Prod: cùng KIẾN TRÚC (M4), khác TRIỂN KHAI (M5)

Bằng chứng mạnh nhất cho "kiến trúc ≠ triển khai": **cùng một M4, deploy 2 kiểu khác
nhau**. Kiến trúc bất biến; cấu hình triển khai đổi. Cũng cho thấy độ chín bảo mật: biết
các "lối tắt dev" là không an toàn và phải siết lại cho prod.

| Mối quan tâm | Dev (local) | Prod | M4 có đổi không? |
|---|---|---|---|
| Địa chỉ phơi ra | Mọi cổng publish ra `0.0.0.0` host (localhost) | Chỉ Gateway ra IP công khai; còn lại internal-only | ❌ Không |
| Secret store | Vault dev-mode (RAM, auto-unseal, root token) | Vault thật (storage, sealed, auto-unseal KMS, policy least-priv) | ❌ Không |
| TLS | HTTP trần (localhost) | HTTPS chấm dứt ở ingress; mTLS cửa 2 | ❌ Không |
| Cổng nội bộ | publish hết để debug (Redis, Vault lộ) | bỏ `ports:`, internal-only | ❌ Không |
| Secret values | dev seed yếu (artifact local) | secret mạnh, bơm qua CI/KMS từ kho thật | ❌ Không |
| Thuật toán token | cho phép cả HS256 để test | ES256-only | ❌ Không |
| Số bản sao | 1 container mỗi service | nhiều replica + load balancer + health check | ❌ Không |

> Cột phải-cùng "❌ Không" = chốt hạ: **đổi cả loạt thứ này, kiến trúc M4 vẫn y nguyên.**
> Đó chính xác là định nghĩa "triển khai khác kiến trúc".

---

## PHẦN 9 — Câu trả lời mẫu khi thầy hỏi "triển khai ở IP gì?"

Học thuộc khung này, trả lời gọn 3 ý:

1. **"Các thành phần nội bộ không dùng IP công khai."** Chúng chạy trong một mạng riêng
   Docker (`gw-net`), gọi nhau bằng **tên service** (Docker DNS) tương ứng IP riêng `172.x`
   — Internet không định tuyến tới được.

2. **"Chỉ Gateway được phơi ra biên."** Ở production, chỉ cổng Gateway được map ra **IP
   công khai** (qua reverse proxy/LB giữ TLS). Backend, Vault, Redis, Keycloak-admin,
   observability **không publish** — chúng chỉ tồn tại bằng IP riêng nội bộ.

3. **"Mọi request từ ngoài bắt buộc qua Gateway."** Vì không có đường nào khác chạm tới
   vùng nội bộ, kẻ tấn công không thể đi vòng qua dây chuyền chốt (chống S1-GB). Đó là lý
   do vùng tin cậy M4 được thực thi đúng ở tầng triển khai.

> Nếu thầy hỏi gặng "thế con số IP cụ thể?": "IP nội bộ do Docker tự cấp động (`172.x`),
> chúng tôi không phụ thuộc số cụ thể vì gọi qua DNS theo tên; IP công khai là địa chỉ của
> server/ingress nơi deploy — chỉ Gateway nghe trên đó." Vậy là đủ và đúng tầng.
