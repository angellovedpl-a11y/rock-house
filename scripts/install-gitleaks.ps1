# Rock House — Gitleaks Installer (Windows)
# Downloads latest gitleaks binary with SHA256 verification
# Usage: .\install-gitleaks.ps1

$ErrorActionPreference = "Stop"

$InstallDir = "$env:LOCALAPPDATA\Programs\gitleaks"
New-Item -ItemType Directory -Force $InstallDir | Out-Null

$release = Invoke-RestMethod "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
$version = $release.tag_name -replace '^v', ''
$tag = $release.tag_name

$filename = "gitleaks_${version}_windows_x64.zip"
$url = "https://github.com/gitleaks/gitleaks/releases/download/${tag}/${filename}"
$checksumUrl = "https://github.com/gitleaks/gitleaks/releases/download/${tag}/gitleaks_${version}_checksums.txt"

$tempZip = "$env:TEMP\$filename"
$tempChecksums = "$env:TEMP\gitleaks_checksums.txt"

Write-Host "Downloading gitleaks ${version} for Windows x64..."
Invoke-WebRequest -Uri $url -OutFile $tempZip
Invoke-WebRequest -Uri $checksumUrl -OutFile $tempChecksums

$expected = (Get-Content $tempChecksums | Where-Object { $_ -match $filename }) -split '\s+' | Select-Object -First 1
$actual = (Get-FileHash $tempZip -Algorithm SHA256).Hash.ToLower()

if ($expected -ne $actual) {
    Write-Host "SHA256 mismatch! Expected: $expected Got: $actual" -ForegroundColor Red
    Write-Host "Download may be corrupted or tampered with. Aborting." -ForegroundColor Red
    Remove-Item $tempZip, $tempChecksums -Force
    exit 1
}

Write-Host "SHA256 verified." -ForegroundColor Green
Expand-Archive -Path $tempZip -DestinationPath $InstallDir -Force
Remove-Item $tempZip, $tempChecksums -Force

$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "Added $InstallDir to user PATH."
}

Write-Host "gitleaks ${version} installed to $InstallDir" -ForegroundColor Green
& "$InstallDir\gitleaks.exe" version
