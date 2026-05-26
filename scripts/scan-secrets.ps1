# Rock House — Secret Scanner (PowerShell)
# Scans project files for hardcoded secrets using regex patterns
# Usage: .\scan-secrets.ps1 [-Path .]

param([string]$Path = ".")

Write-Host "Rock House — Scanning for secrets in $Path" -ForegroundColor Cyan
Write-Host "================================================"

$found = 0
$extensions = @("*.js", "*.ts", "*.py", "*.jsx", "*.tsx", "*.json", "*.env*")
$exclude = @("node_modules", ".git", "dist", "build", ".next")

$files = Get-ChildItem -Path $Path -Recurse -Include $extensions -File | Where-Object {
    $fullPath = $_.FullName
    -not ($exclude | Where-Object { $fullPath -like "*\$_\*" })
}

foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    # AWS Access Key
    if ($content -match "AKIA[0-9A-Z]{16}") {
        Write-Host "AWS KEY: $($file.FullName)" -ForegroundColor Red; $found++
    }
    # OpenAI Key
    if ($content -match "sk-[a-zA-Z0-9]{48}") {
        Write-Host "OPENAI KEY: $($file.FullName)" -ForegroundColor Red; $found++
    }
    # Stripe Live Key
    if ($content -match "sk_live_[a-zA-Z0-9]{24}") {
        Write-Host "STRIPE KEY: $($file.FullName)" -ForegroundColor Red; $found++
    }
    # Password patterns
    if ($content -match "(?i)(password|passwd|pwd|senha)\s*[:=]\s*[`"'][^`"']{4,}") {
        Write-Host "PASSWORD: $($file.FullName)" -ForegroundColor Yellow; $found++
    }
    # NEXT_PUBLIC_ sensitive
    if ($content -match "NEXT_PUBLIC_.*(SERVICE|SECRET|PRIVATE|ADMIN)") {
        Write-Host "NEXT_PUBLIC EXPOSURE: $($file.FullName)" -ForegroundColor Red; $found++
    }
}

Write-Host "================================================"
if ($found -gt 0) {
    Write-Host "Warning: $found suspicious patterns found. Review above." -ForegroundColor Yellow
} else {
    Write-Host "OK: No secrets found in checked patterns." -ForegroundColor Green
}
