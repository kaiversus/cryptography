# show-kb.ps1 <KB1..KB9> - in log Docker cua dung container cho 1 kich ban demo.
#   KB1,2,3,5,6 -> log container 'gateway'   |   KB4,9 -> log container 'edge' (Caddy/TLS)
# Vi du:  .\scripts\show-kb.ps1 KB2     .\scripts\show-kb.ps1 KB9
param([Parameter(Mandatory)][string]$KB)

$compose = Join-Path $PSScriptRoot "..\infra\docker-compose.yml"
$KB = $KB.ToUpper()

function Parse-Json($line) {
    try { return ($line -replace '^.*?({.*})\s*$', '$1') | ConvertFrom-Json } catch { return $null }
}

if ($KB -in @('KB4', 'KB9')) {
    Write-Host "== $KB == (log 'edge' - kenh TLS)" -ForegroundColor Cyan
    docker compose -f $compose logs --since=10m edge |
        Select-String "handled request" |
        ForEach-Object {
            $j = Parse-Json $_; if (-not $j) { return }
            $k = $j.request.headers.'X-Demo-Kb'
            if ($k -contains $KB) {
                "  {0,-5} uri={1,-50} status={2}  tls_ver={3} cipher={4}" -f `
                    $KB, $j.request.uri, $j.status, $j.request.tls.version, $j.request.tls.cipher_suite
            }
        }
}
else {
    Write-Host "== $KB == (log 'gateway')" -ForegroundColor Cyan
    docker compose -f $compose logs --since=10m gateway |
        Select-String "`"demo_kb`": `"$KB`"" |
        ForEach-Object {
            $j = Parse-Json $_; if (-not $j) { return }
            "  {0,-5} {1,-5} {2,-18} -> {3}  ({4}ms)" -f $j.demo_kb, $j.method, $j.path, $j.status_code, $j.latency_ms
        }
}
