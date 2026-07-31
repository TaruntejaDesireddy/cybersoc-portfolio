<#
.SYNOPSIS
    Deploys the analytics-rules/**/*.json detection set into a Microsoft Sentinel workspace.

.DESCRIPTION
    Each rule JSON carries its own GUID in the "name" field, so deployment is idempotent:
    re-running updates rules in place rather than creating duplicates.

    Requires an authenticated Azure CLI session (az login) with permission to write
    Microsoft.SecurityInsights/alertRules in the target workspace.

.EXAMPLE
    ./deploy-rules.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -ResourceGroup rg-soc -WorkspaceName law-soc

.EXAMPLE
    ./deploy-rules.ps1 -SubscriptionId $s -ResourceGroup $rg -WorkspaceName $ws -WhatIf
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$WorkspaceName,
    [string]$RulesPath = (Join-Path $PSScriptRoot "analytics-rules"),
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$apiVersion = "2023-02-01"

$az = Get-Command az -ErrorAction SilentlyContinue
if (-not $az) {
    $fallback = "C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
    if (Test-Path $fallback) { $az = $fallback } else { throw "Azure CLI not found. Install it or add az to PATH." }
} else { $az = $az.Source }

$files = Get-ChildItem -Path $RulesPath -Filter *.json -Recurse | Sort-Object FullName
if ($files.Count -eq 0) { throw "No rule JSON files found under $RulesPath" }
Write-Host "Found $($files.Count) rule definitions." -ForegroundColor Cyan

if ($WhatIf) {
    $files | ForEach-Object {
        $r = Get-Content $_.FullName -Raw | ConvertFrom-Json
        "{0,-10} {1}" -f $r.properties.severity, $r.properties.displayName
    }
    return
}

$token = (& $az account get-access-token --subscription $SubscriptionId --query accessToken -o tsv 2>&1 |
          Where-Object { $_ -notmatch "WARNING" })
if (-not $token) { throw "Could not acquire an access token. Run 'az login' first." }
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
        "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
        "/providers/Microsoft.SecurityInsights/alertRules"

$ok = 0; $failed = @()

foreach ($f in $files) {
    $rule = Get-Content $f.FullName -Raw | ConvertFrom-Json
    $body = @{ kind = $rule.kind; properties = $rule.properties } | ConvertTo-Json -Depth 20
    $url  = "$base/$($rule.name)?api-version=$apiVersion"

    $attempt = 0; $done = $false; $msg = ""
    while (-not $done -and $attempt -lt 4) {
        $attempt++
        try {
            Invoke-RestMethod -Uri $url -Headers $headers -Method PUT -Body $body -ErrorAction Stop | Out-Null
            $ok++; $done = $true
            Write-Host ("  OK    " + $rule.properties.displayName) -ForegroundColor Green
        } catch {
            $msg = $_.Exception.Message
            $isApiError = [bool]$_.ErrorDetails.Message
            if ($isApiError) {
                try { $msg = (ConvertFrom-Json $_.ErrorDetails.Message).error.message } catch { $msg = $_.ErrorDetails.Message }
                break   # API rejections are deterministic - retrying will not help
            }
            if ($attempt -lt 4) { Start-Sleep -Seconds ($attempt * 3) }   # transient network fault
        }
    }
    if (-not $done) {
        $failed += [PSCustomObject]@{ Rule = $rule.properties.displayName; Error = $msg }
        Write-Host ("  FAIL  " + $rule.properties.displayName) -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "$ok succeeded, $($failed.Count) failed." -ForegroundColor Cyan
if ($failed.Count -gt 0) {
    $failed | ForEach-Object { Write-Host ""; Write-Host $_.Rule -ForegroundColor Yellow; Write-Host $_.Error }
    exit 1
}
