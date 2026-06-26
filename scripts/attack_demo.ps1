# =============================================================================
#  attack_demo.ps1 - Demo 10 kich ban TAN CONG -> PHONG THU (moi KB = 1 payload).
#  Thuan PowerShell: KHONG can bash / WSL / openssl. HMAC+SHA256 dung .NET.
#  Chay:  .\scripts\attack_demo.ps1     (hoac: pwsh -File scripts\attack_demo.ps1)
#  Yeu cau: stack dang chay (docker compose up -d) va da san sang.
#
#  10 kich ban. Cai nao CHUA CO HA TANG -> in [SKIP] + ghi ro ly do:
#    KB1  Gia mao token (ky khoa la)                  -> DEMO LIVE
#    KB2  Sua body request M2M, giu chu ky HMAC cu     -> DEMO LIVE
#    KB3  Choi bo hanh vi M2M (so audit)              -> DEMO LIVE
#    KB4  Nghe len duong truyen -> chong bang TLS      -> DEMO LIVE (Caddy edge HTTPS 9443)
#    KB5  Flood lam nghen dich vu (DoS)               -> DEMO LIVE
#    KB6  Token user goi endpoint admin (leo quyen)    -> DEMO LIVE
#    KB9  Trao JWKS -> JWKS qua TLS (Caddy)            -> DEMO LIVE (kenh phong thu) + demo vuln standalone
#    KB7  Goi thang backend, vong gateway             -> [SKIP] chua co backend/mTLS
#    KB8  Backend tin header gateway -> spoof header    -> [SKIP] chua co backend (co test nguyen ly)
#    KB10 Gateway<->Vault khong ma hoa -> lo khoa       -> [SKIP] Vault dev HTTP (da fail-closed F4)
# =============================================================================

# ---- Cau hinh ----
$GATEWAY  = if ($env:GATEWAY_URL)  { $env:GATEWAY_URL }  else { "http://localhost:18000" }
$KEYCLOAK = if ($env:KEYCLOAK_URL) { $env:KEYCLOAK_URL } else { "http://localhost:18081" }
$HTTPS    = if ($env:GATEWAY_TLS)  { $env:GATEWAY_TLS }  else { "https://localhost:9443" }
$REALM    = "nt219"
$CID      = "service-account"
$CSECRET  = "CaXVcmwkeRNHP5lls0pTL8BPbFLD0Bo5"
$KEYID    = "dev-key-01"
$SECRET   = "dev-shared-secret"
$HOSTHDR  = $GATEWAY -replace '^https?://', ''

$script:PASS = 0; $script:TOTAL = 0; $script:SKIP = 0
$script:CURKB = ""   # nhan kich ban hien tai -> dinh vao header X-Demo-KB -> tag demo.kb tren Jaeger
$nl = "`n"

# ---- Tien ich ----
function Hr($t) { "`n===================================================================="; "  $t"; "====================================================================" }
function Check($name, $expect, $actual) {
    $script:TOTAL++
    if ("$expect" -eq "$actual") { "  [PASS] $name  (ky vong=$expect thuc te=$actual)"; $script:PASS++ }
    else                         { "  [FAIL] $name  (ky vong=$expect thuc te=$actual)" }
}
function Skip($why) { $script:SKIP++; "  [SKIP] $why" }
function Sha256Hex([string]$s) { $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($s)); ($h | ForEach-Object { $_.ToString('x2') }) -join '' }
function HmacHex([string]$key, [string]$msg) { $hm = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($key)); $h = $hm.ComputeHash([Text.Encoding]::UTF8.GetBytes($msg)); ($h | ForEach-Object { $_.ToString('x2') }) -join '' }
function Uuid4 { [guid]::NewGuid().ToString() }
function NowTs { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString() }
# Bat tay TLS truc tiep (TcpClient+SslStream) -> doc TLS version + cipher that su (bang chung KB4).
function TlsInfo([string]$h, [int]$port) {
    try {
        $tcp = [Net.Sockets.TcpClient]::new($h, $port)
        $ssl = [Net.Security.SslStream]::new($tcp.GetStream(), $false, { param($s,$c,$ch,$e) $true })
        $ssl.AuthenticateAsClient($h)
        $info = "$($ssl.SslProtocol) / $($ssl.CipherAlgorithm) $($ssl.CipherStrength)-bit"
        $ssl.Dispose(); $tcp.Dispose()
        return $info
    } catch { return "" }
}

function HttpCode {
    param([string]$Uri, [string]$Method = "GET", [hashtable]$Headers = @{}, $Body = $null, [string]$ContentType = $null)
    try {
        $Headers = $Headers.Clone()
        if ($script:CURKB) { $Headers["X-Demo-KB"] = $script:CURKB }
        $p = @{ Uri = $Uri; Method = $Method; Headers = $Headers; TimeoutSec = 8; UseBasicParsing = $true }
        if ($null -ne $Body) { $p.Body = $Body }
        if ($ContentType)    { $p.ContentType = $ContentType }
        return [int](Invoke-WebRequest @p).StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}
function Sign([string]$body, [string]$ts, [string]$nonce) {
    $bh = Sha256Hex $body
    $canon = "POST${nl}/api/service${nl}${nl}host:$HOSTHDR${nl}x-key-id:$KEYID${nl}x-nonce:$nonce${nl}x-timestamp:$ts${nl}${nl}host;x-key-id;x-nonce;x-timestamp${nl}$bh"
    $ch = Sha256Hex $canon
    $sts = "HMAC-SHA256${nl}$ts${nl}gateway-internal/v1${nl}$ch"
    HmacHex $SECRET $sts
}
function PostService([string]$bodySign, [string]$bodySend, [string]$ts, [string]$nonce) {
    $sig = Sign $bodySign $ts $nonce
    $h = @{ "X-Timestamp" = $ts; "X-Nonce" = $nonce; "X-Key-Id" = $KEYID; "X-Signature" = $sig }
    HttpCode -Uri "$GATEWAY/api/service" -Method POST -Headers $h -Body $bodySend -ContentType "application/json"
}

# =========================== SETUP ===========================
Hr "SETUP - Gateway song? + lay token that"
$script:CURKB = "SETUP"
Check "GET /health -> 200" 200 (HttpCode "$GATEWAY/health")
$TOKEN = ""
try {
    $tk = Invoke-RestMethod -Uri "$KEYCLOAK/realms/$REALM/protocol/openid-connect/token" -Method POST `
            -Body @{ grant_type = "client_credentials"; client_id = $CID; client_secret = $CSECRET } -TimeoutSec 8
    $TOKEN = $tk.access_token
} catch { }
if (-not $TOKEN) { "  [WARN] khong lay duoc token (Keycloak chua san sang? doi them ~30s)" }
Check "GET /api/protected co Bearer token that -> 200" 200 (HttpCode "$GATEWAY/api/protected" "GET" @{ Authorization = "Bearer $TOKEN" })

# =========================== KB1 ===========================
Hr "KB1 - Gia mao token: hacker tu che token, ky bang khoa la"
$script:CURKB = "KB1"
# 1 payload: token that bi doi 3 ky tu cuoi -> chu ky hong (mo phong 'ky bang khoa la')
$FORGED = if ($TOKEN.Length -gt 3) { $TOKEN.Substring(0, $TOKEN.Length - 3) + "xyz" } else { "x.y.z" }
Check "Token gia/ky sai -> 401" 401 (HttpCode "$GATEWAY/api/protected" "GET" @{ Authorization = "Bearer $FORGED" })

# =========================== KB2 ===========================
Hr "KB2 - Sua body request M2M nhung giu chu ky HMAC cu (Tampering)"
$script:CURKB = "KB2"
# (a) chu ky DUNG (ky va gui cung body) -> 200 = HMAC hoat dong
$ts2 = NowTs; $n2 = Uuid4
Check "Ky DUNG (body khop chu ky) -> 200" 200 (PostService '{"id":1}' '{"id":1}' $ts2 $n2)
# (b) SUA body (ky cho {"id":1} nhung gui {"id":999}) -> 401 = bi chan
Check "SUA body (ky A gui B) -> 401" 401 (PostService '{"id":1}' '{"id":999}' (NowTs) (Uuid4))

# =========================== KB3 ===========================
Hr "KB3 - Choi bo hanh vi M2M: gui request xau -> so audit ghi danh tinh (chong choi bo)"
$script:CURKB = "KB3"
# 1 payload: gui 1 request xau (tamper) -> kiem so audit co ghi dev-key-01 + deny
PostService '{"id":1}' '{"id":999}' (NowTs) (Uuid4) | Out-Null
$auditOk = $false
try {
    $a = Invoke-RestMethod -Uri "$GATEWAY/audit/recent?limit=10" -TimeoutSec 8
    $rec = $a.records | Where-Object { $_.actor -eq "dev-key-01" -and $_.decision -eq "deny" } | Select-Object -Last 1
    $auditOk = [bool]$rec
    if ($rec) { "  ban ghi audit: actor=$($rec.actor) decision=$($rec.decision) reason=$($rec.reason) ts=$($rec.ts)" }
} catch { }
Check "Audit ghi request xau kem danh tinh dev-key-01" $true $auditOk

# =========================== KB4 ===========================
Hr "KB4 - Nghe len duong truyen: chong bang TLS (kenh ma hoa, sniffer khong doc duoc token)"
# 1 payload: goi qua HTTPS (Caddy edge). Bat tay TLS thanh cong + 200 = kenh da ma hoa.
$tlsHost = ($HTTPS -replace '^https?://','') -replace ':.*$',''
$tlsPort = [int](($HTTPS -split ':')[-1])
$tlsInfo = TlsInfo $tlsHost $tlsPort
if ($tlsInfo) { "  bang chung ma hoa: bat tay $tlsInfo  (sniffer chi thay ciphertext)" }
$k4 = 0
try { $k4 = [int](& curl.exe -sk -o NUL -w "%{http_code}" -H "X-Demo-KB: KB4" "$HTTPS/health") } catch { $k4 = 0 }
Check "Kenh HTTPS/TLS hoat dong -> 200 (token KHONG di plaintext)" 200 $k4

# =========================== KB5 ===========================
Hr "KB5 - Flood lam nghen dich vu (DoS): ban hang loat request"
$script:CURKB = "KB5"
# 1 payload: ban 12 request /api/public (gioi han 10/phut) -> phai co 429
$codes = @(); 1..12 | ForEach-Object { $codes += (HttpCode "$GATEWAY/api/public") }
"  12 lan goi -> $($codes -join ' ')"
Check "Co request bi chan 429 (rate-limit)" $true ($codes -contains 429)

# =========================== KB6 ===========================
Hr "KB6 - Leo thang quyen: token user hop le goi endpoint chi danh cho admin"
$script:CURKB = "KB6"
# 1 payload: token that (thieu role admin) goi /api/admin -> 403
Check "Token thieu role admin goi /api/admin -> 403" 403 (HttpCode "$GATEWAY/api/admin" "GET" @{ Authorization = "Bearer $TOKEN" })

# =========================== KB7 ===========================
Hr "KB7 - Dung trong mang noi bo goi thang backend, vong qua Gateway (Spoofing S1-GB)"
Skip "CHUA CO HA TANG: PoC khong co backend rieng -> chua co mTLS. Phong thu = co lap mang (prod compose) + mTLS cua 2."

# =========================== KB8 ===========================
Hr "KB8 - Backend tin header Gateway -> spoof X-Role de leo quyen (Elevation E2-GB)"
Skip "CHUA CO BACKEND THAT. Test nguyen ly: python -m pytest tests/security/test_backend_zerotrust.py -v (SEC-14)."

# =========================== KB9 ===========================
Hr "KB9 - Trao JWKS: phong thu = fetch JWKS qua TLS (MITM khong tra noi JWKS gia)"
$script:CURKB = "KB9"
# 1 payload: tai JWKS qua HTTPS (Caddy) -> phai tra ve bo khoa that qua kenh ma hoa.
$jwksUrl = "$HTTPS/realms/$REALM/protocol/openid-connect/certs"
$jwksBody = ""
try { $jwksBody = (& curl.exe -sk -H "X-Demo-KB: KB9" "$jwksUrl") } catch { }
$tlsInfo9 = TlsInfo $tlsHost $tlsPort
if ($tlsInfo9) { "  kenh JWKS ma hoa: bat tay $tlsInfo9" }
$jwksOk = ($jwksBody -match '"keys"') -and ($jwksBody -match '"kid"')
Check "JWKS tai qua TLS tra ve bo khoa that" $true $jwksOk
"  Vi sao can TLS: chay  python -m tests.security.sec_jwks_substitution_demo"
"  -> khi JWKS bi trao, verify_token CHAP NHAN token gia (app-logic bat luc) => phai pin TLS/CA."

# =========================== KB10 ===========================
Hr "KB10 - Gateway<->Vault khong ma hoa / cau hinh sai secret -> lo khoa"
Skip "Vault dev HTTP + root token. Da fail-closed (F4): vault_client.py:17,32-36. TLS+policy least-priv la control trien khai."

# =========================== TONG KET ===========================
Hr "TONG KET"
"  DEMO LIVE: $script:PASS/$script:TOTAL buoc dat ky vong.  |  SKIP (chua co ha tang): $script:SKIP kich ban (KB7, KB8, KB10)."
"  Quan sat luong: http://localhost:16686 (Jaeger, Service=secure-api-gateway, xem cay span auth.*)"
if ($script:PASS -eq $script:TOTAL) { exit 0 } else { exit 1 }
