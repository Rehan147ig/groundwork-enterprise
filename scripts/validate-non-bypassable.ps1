<#
.SYNOPSIS
  Validates the Groundwork non-bypassable deployment profile.

.DESCRIPTION
  Checks that:
    - query-runtime is reachable through the gateway
    - /mcp is reachable (and requires an API key)
    - Qdrant / SpiceDB / PostgreSQL / Elasticsearch are NOT reachable on host ports
    - (optional) an authenticated query still works through /mcp
    - (sovereign, Phase 4) when GROUNDWORK_DEPLOYMENT_REGION is set (directly or
      via -EnvFile), the region/tenant/identity/key/audit environment is sound
      and demo identity is off

  Requires PowerShell 7+ (uses -SkipHttpErrorCheck). Exit code 0 = only Groundwork
  ingress is exposed; non-zero = a check failed.

.EXAMPLE
  ./scripts/validate-non-bypassable.ps1 -GwUrl http://localhost
  $env:GW_API_KEY="gw_live_xxx"; ./scripts/validate-non-bypassable.ps1
  ./scripts/validate-non-bypassable.ps1 -EnvFile deploy/sovereign/.env
#>
param(
    [string]$GwUrl  = "http://localhost",
    [string]$ApiKey = $env:GW_API_KEY,
    [string]$EnvFile = $env:GW_ENV_FILE
)

$script:fail = $false
function Pass($m) { Write-Host "PASS: $m" }
function Bad($m)  { Write-Host "FAIL: $m"; $script:fail = $true }

# Reads a value from -EnvFile (if given) or from the current environment.
function Get-EnvVal {
    param([string]$Key)
    if ($EnvFile -and (Test-Path $EnvFile)) {
        $m = Get-Content $EnvFile | Where-Object { $_ -match "^$([regex]::Escape($Key))=" } | Select-Object -Last 1
        if ($m) { return ($m -split '=', 2)[1].Trim().Trim('"') }
    }
    return [Environment]::GetEnvironmentVariable($Key)
}

function Get-HttpCode {
    param([string]$Method, [string]$Url, [hashtable]$Headers, [string]$Body)
    try {
        $p = @{ Method = $Method; Uri = $Url; TimeoutSec = 5; SkipHttpErrorCheck = $true }
        if ($Headers) { $p.Headers = $Headers }
        if ($Body)    { $p.Body = $Body; $p.ContentType = 'application/json' }
        return (Invoke-WebRequest @p).StatusCode
    } catch { return -1 }
}

Write-Host "== Groundwork non-bypassable validation =="
Write-Host "gateway: $GwUrl`n"

# 1. query-runtime reachable through the gateway.
$c = Get-HttpCode -Method GET -Url "$GwUrl/healthz"
if ($c -eq 200) { Pass "query-runtime /healthz reachable (200)" } else { Bad "/healthz expected 200, got $c" }

# 2. /mcp reachable AND auth-protected (401 without an API key).
$c = Get-HttpCode -Method POST -Url "$GwUrl/mcp" -Body '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
if ($c -eq 401) { Pass "/mcp reachable and requires API key (401)" } else { Bad "/mcp expected 401 without key, got $c" }

# 3-6. Backend host ports MUST be closed.
function Test-Closed {
    param([int]$Port, [string]$Name)
    $r = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -WarningAction SilentlyContinue
    if ($r.TcpTestSucceeded) { Bad "$Name ($Port) is reachable from the host — it must be internal-only" }
    else { Pass "$Name ($Port) not reachable from the host" }
}
Test-Closed 6333 "Qdrant"
Test-Closed 50051 "SpiceDB gRPC"
Test-Closed 8443 "SpiceDB HTTP"
Test-Closed 5432 "PostgreSQL"
Test-Closed 9200 "Elasticsearch"

# 7. Optional: a real authenticated query still works through /mcp.
if ($ApiKey) {
    try {
        $resp = Invoke-WebRequest -Method POST -Uri "$GwUrl/mcp" `
            -Headers @{ 'X-Groundwork-API-Key' = $ApiKey } -ContentType 'application/json' `
            -Body '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' `
            -TimeoutSec 8 -SkipHttpErrorCheck
        if ($resp.Content -match 'groundwork_search') { Pass "authenticated /mcp tools/list works (Groundwork query path is live)" }
        else { Bad "authenticated /mcp tools/list failed: $($resp.Content)" }
    } catch { Bad "authenticated /mcp call error: $_" }
} else {
    Write-Host "INFO: set GW_API_KEY to also verify an authenticated query through /mcp"
}

# 8-13. Sovereign deployment env checks (Phase 4).
$region = Get-EnvVal "GROUNDWORK_DEPLOYMENT_REGION"
if ($region) {
    Write-Host "`n== Sovereign deployment env validation (region: $region) =="

    $tenants = Get-EnvVal "GROUNDWORK_TENANT_REGIONS"
    if ($tenants -split ',' | Where-Object { ($_ -split ':')[1] -eq $region }) {
        Pass "tenant region map covers this deployment region"
    } else {
        Bad "GROUNDWORK_TENANT_REGIONS='$tenants' does not assign any tenant to region $region"
    }

    $bootstrapRegion = Get-EnvVal "BOOTSTRAP_TENANT_REGION"
    if ($bootstrapRegion -eq $region) { Pass "BOOTSTRAP_TENANT_REGION matches the deployment region" }
    else { Bad "BOOTSTRAP_TENANT_REGION='$bootstrapRegion' must equal the deployment region '$region'" }

    if ((Get-EnvVal "GROUNDWORK_OIDC_ISSUER") -or (Get-EnvVal "GROUNDWORK_JWT_HS_SECRET")) {
        Pass "identity material configured (OIDC issuer or JWT secret)"
    } else {
        Bad "no identity material: set GROUNDWORK_OIDC_ISSUER or GROUNDWORK_JWT_HS_SECRET"
    }

    if ((Get-EnvVal "GROUNDWORK_DELEGATION_RS_PRIVATE_KEY") -or (Get-EnvVal "GROUNDWORK_DELEGATION_HS_SECRET")) {
        Pass "delegation key material present (RS private key or HS secret)"
    } else {
        Bad "no delegation key material: set GROUNDWORK_DELEGATION_RS_PRIVATE_KEY or GROUNDWORK_DELEGATION_HS_SECRET"
    }
    if (Get-EnvVal "GROUNDWORK_OUTBOX_WEBHOOK_SECRET") { Pass "GROUNDWORK_OUTBOX_WEBHOOK_SECRET present" }
    else { Bad "GROUNDWORK_OUTBOX_WEBHOOK_SECRET missing — purpose webhook has no key material" }
    if (Get-EnvVal "GROUNDWORK_AUDIT_DIGEST_KEY") { Pass "GROUNDWORK_AUDIT_DIGEST_KEY present" }
    else { Bad "GROUNDWORK_AUDIT_DIGEST_KEY missing — purpose audit_digest has no key material" }

    if ((Get-EnvVal "DATABASE_URL") -or (Get-EnvVal "POSTGRES_PASSWORD")) { Pass "DATABASE_URL set (or compose-managed postgres) — immutable audit ledger configured" }
    else { Bad "DATABASE_URL missing — audit storage is not configured" }

    if ((Get-EnvVal "ALLOW_DEMO_IDENTITY") -eq "true") { Bad "ALLOW_DEMO_IDENTITY=true is forbidden in production" }
    else { Pass "ALLOW_DEMO_IDENTITY is off" }

    foreach ($key in @("GROUNDWORK_POSTGRES_EXPOSED", "GROUNDWORK_SPICEDB_EXPOSED", "GROUNDWORK_QDRANT_EXPOSED", "GROUNDWORK_ES_EXPOSED", "GROUNDWORK_MINIO_EXPOSED")) {
        if (Get-EnvVal $key) { Bad "$key is set — a backend is published on the host interface" }
    }
} else {
    Write-Host "INFO: GROUNDWORK_DEPLOYMENT_REGION unset — skipping sovereign env checks (pass -EnvFile deploy/sovereign/.env)"
}

Write-Host ""
if (-not $script:fail) {
    Write-Host "ALL CHECKS PASSED — only Groundwork ingress is exposed."
    exit 0
} else {
    Write-Host "CHECKS FAILED — a backend is exposed or Groundwork ingress is broken."
    exit 1
}
