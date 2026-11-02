#Requires -Version 5.1
<#
.SYNOPSIS
    Official One-Liner Zero-Friction Web Installer for CVE Security Operations Suite (v11.5 Master Edition)
.DESCRIPTION
    Downloads, verifies SHA-256 cryptographic checksums, unblocks, and installs CVE Security Operations Suite.
.EXAMPLE
    irm https://raw.githubusercontent.com/anon-wu/CVE_Checker_Anon_X/main/install.ps1 | iex
#>
param(
    [string]$InstallDir = (Join-Path $HOME "CVE_Security_Suite"),
    [switch]$Launch,
    [switch]$SkipShortcut
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "   CVE Security Operations Suite - Automated Zero-Friction Installer     " -ForegroundColor White
Write-Host "   Version: v11.5 Master Edition  |  CVE DB: 2026-11-02 (249,120 CVEs)   " -ForegroundColor Gray
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

$repoBase = "https://raw.githubusercontent.com/anon-wu/CVE_Checker_Anon_X/main"
$zipUrl   = "$repoBase/releases/CVE_Security_Operations_Suite_Portable.zip"
$shaUrl   = "$repoBase/SHA256SUMS.txt"

$tempZip  = Join-Path $env:TEMP ("CVE_Suite_Install_" + [Guid]::NewGuid().ToString("N") + ".zip")
$tempSha  = Join-Path $env:TEMP ("CVE_Suite_SHA_" + [Guid]::NewGuid().ToString("N") + ".txt")

try {
    Write-Host "[1/5] Downloading SHA-256 integrity verification manifest..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $shaUrl -OutFile $tempSha -UseBasicParsing
    $shaContent = Get-Content $tempSha -Raw

    $expectedZipHash = $null
    foreach ($line in ($shaContent -split "`r?`n")) {
        if ($line -match "^([A-Fa-f0-9]{64})\s+.*CVE_Security_Operations_Suite_Portable\.zip") {
            $expectedZipHash = $matches[1].ToUpper()
            break
        }
    }

    if (-not $expectedZipHash) {
        throw "Could not parse expected Portable ZIP SHA-256 hash from $shaUrl"
    }

    Write-Host "  -> Expected Portable ZIP SHA-256: $expectedZipHash" -ForegroundColor DarkGray

    Write-Host "[2/5] Downloading CVE Security Operations Suite Portable Package..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip -UseBasicParsing

    Write-Host "[3/5] Verifying cryptographic SHA-256 hash..." -ForegroundColor Cyan
    $actualZipHash = (Get-FileHash -LiteralPath $tempZip -Algorithm SHA256).Hash.ToUpper()
    Write-Host "  -> Computed SHA-256: $actualZipHash" -ForegroundColor DarkGray

    if ($actualZipHash -ne $expectedZipHash) {
        throw "Security Error: SHA-256 hash mismatch! Download may be corrupted or intercepted.`nExpected: $expectedZipHash`nActual:   $actualZipHash"
    }
    Write-Host "  [OK] Hash verified 100%! Binary integrity confirmed." -ForegroundColor Green

    Write-Host "[4/5] Unblocking and extracting to: $InstallDir" -ForegroundColor Cyan
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Remove Mark-of-the-Web before extraction
    Unblock-File -LiteralPath $tempZip -ErrorAction SilentlyContinue
    Expand-Archive -LiteralPath $tempZip -DestinationPath $InstallDir -Force

    # Unblock all extracted files
    Get-ChildItem -LiteralPath $InstallDir -Recurse | ForEach-Object {
        Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue
    }
    Write-Host "  [OK] Package extracted and unblocked successfully." -ForegroundColor Green

    Write-Host "[5/5] Creating Desktop & Start Menu Shortcuts..." -ForegroundColor Cyan
    if (-not $SkipShortcut) {
        $desktop = [Environment]::GetFolderPath("DesktopDirectory")
        $wshShell = New-Object -ComObject WScript.Shell

        $intExe = Join-Path $InstallDir "DeviceInternalScanner.exe"
        $extExe = Join-Path $InstallDir "DeviceExternalScanner.exe"

        if (Test-Path $intExe) {
            $intLink = $wshShell.CreateShortcut((Join-Path $desktop "Device Internal CVE Scanner.lnk"))
            $intLink.TargetPath = $intExe
            $intLink.WorkingDirectory = $InstallDir
            $intLink.Description = "CVE Security Operations Suite - Host Vulnerability Auditor (v11.5)"
            $intLink.Save()
        }

        if (Test-Path $extExe) {
            $extLink = $wshShell.CreateShortcut((Join-Path $desktop "Device External CVE Scanner.lnk"))
            $extLink.TargetPath = $extExe
            $extLink.WorkingDirectory = $InstallDir
            $extLink.Description = "CVE Security Operations Suite - Perimeter Vulnerability Auditor (v11.5)"
            $extLink.Save()
        }
        Write-Host "  [OK] Desktop shortcuts created." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] CVE Security Operations Suite v11.5 Installed Successfully! " -ForegroundColor Green
    Write-Host "========================================================================" -ForegroundColor Green
    Write-Host " Install Location : $InstallDir" -ForegroundColor White
    Write-Host " Internal Scanner : $(Join-Path $InstallDir 'DeviceInternalScanner.exe')" -ForegroundColor Gray
    Write-Host " External Scanner : $(Join-Path $InstallDir 'DeviceExternalScanner.exe')" -ForegroundColor Gray
    Write-Host ""
    Write-Host " Quick Terminal Commands:" -ForegroundColor Yellow
    Write-Host "   & '$InstallDir\DeviceInternalScanner.exe' --help" -ForegroundColor DarkCyan
    Write-Host "   & '$InstallDir\DeviceInternalScanner.exe' --scan-tier fast --batch" -ForegroundColor DarkCyan
    Write-Host "   & '$InstallDir\DeviceExternalScanner.exe' --target 127.0.0.1 --batch" -ForegroundColor DarkCyan
    Write-Host ""

    if ($Launch) {
        Write-Host "Launching DeviceInternalScanner.exe..." -ForegroundColor Cyan
        Start-Process (Join-Path $InstallDir "DeviceInternalScanner.exe")
    }
}
finally {
    if (Test-Path $tempZip) { Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempSha) { Remove-Item -LiteralPath $tempSha -Force -ErrorAction SilentlyContinue }
}
