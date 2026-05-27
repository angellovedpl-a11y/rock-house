# Rock House — Security Headers Checker (Windows)
# Tests security headers on a live URL
# Usage: .\check-headers.ps1 -Url https://your-site.com

param([Parameter(Mandatory)][string]$Url)

Write-Host "Rock House — Checking security headers for $Url"
Write-Host "================================================"

try {
    $response = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec 10 -UseBasicParsing
} catch {
    $curlAvailable = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curlAvailable) {
        $raw = & curl.exe -sI --max-time 10 $Url 2>$null
        if (-not $raw) {
            Write-Host "ERROR: Could not reach $Url" -ForegroundColor Red
            exit 1
        }
        $headers = @{}
        foreach ($line in $raw -split "`r?`n") {
            if ($line -match "^([^:]+):\s*(.+)$") {
                $headers[$matches[1].Trim().ToLower()] = $matches[2].Trim()
            }
        }
    } else {
        Write-Host "ERROR: Could not reach $Url" -ForegroundColor Red
        exit 1
    }
}

if ($response) {
    $headers = @{}
    foreach ($key in $response.Headers.Keys) {
        $headers[$key.ToLower()] = $response.Headers[$key]
    }
    Write-Host "Status: $($response.StatusCode)" -ForegroundColor Cyan
}
Write-Host ""

$pass = 0; $fail = 0

$required = @(
    @{ Name = "strict-transport-security"; Display = "HSTS" },
    @{ Name = "x-frame-options"; Display = "X-Frame-Options" },
    @{ Name = "x-content-type-options"; Display = "X-Content-Type-Options" },
    @{ Name = "content-security-policy"; Display = "CSP" },
    @{ Name = "referrer-policy"; Display = "Referrer-Policy" },
    @{ Name = "permissions-policy"; Display = "Permissions-Policy" }
)

foreach ($h in $required) {
    $value = $headers[$h.Name]
    if ($value) {
        Write-Host "PASS $($h.Display): $value" -ForegroundColor Green
        $pass++
    } else {
        Write-Host "FAIL $($h.Display): MISSING" -ForegroundColor Red
        $fail++
    }
}

Write-Host ""
Write-Host "================================================"
Write-Host "Results: $pass passed, $fail missing"
