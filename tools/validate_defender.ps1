# Local Windows Defender validation (lab)
# Scans a built implant EXE. Not a full EDR suite - only local Defender.
#
# Exit codes:
#   0 - no detection reported
#   1 - detection / quarantine / threat found
#   2 - Defender / MpCmdRun unavailable (skipped)

param(
    [string]$ExePath = "",
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Root) { $Root = (Get-Location).Path }

if ($Build) {
    Write-Host "[*] Building Release..."
    cmake -S "$Root\client" -B "$Root\client\build" -G "Visual Studio 17 2022" -A x64
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
    cmake --build "$Root\client\build" --config Release
    if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }
}

if (-not $ExePath) {
    $candidates = @(
        "$Root\client\build\Release\RuntimeBroker.exe",
        "$Root\client\build\Release\c2_client.exe",
        "$Root\client\build\x64\Release\RuntimeBroker.exe",
        "$Root\client\build\x64\Release\c2_client.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $ExePath = $c; break }
    }
}

if (-not $ExePath -or -not (Test-Path $ExePath)) {
    Write-Error "EXE not found. Pass -ExePath or -Build."
    exit 2
}

$ExePath = (Resolve-Path $ExePath).Path
Write-Host "[*] Target: $ExePath"

$mp = @(
    "${env:ProgramFiles}\Windows Defender\MpCmdRun.exe",
    "${env:ProgramFiles(x86)}\Windows Defender\MpCmdRun.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $mp) {
    Write-Warning "MpCmdRun.exe not found - Defender CLI unavailable."
    # Fallback: try Start-MpScan if module present
    try {
        Start-MpScan -ScanPath $ExePath -ScanType CustomScan -ErrorAction Stop
    Write-Host "[!] DETECTION - see $scanLog"
        exit 0
    } catch {
        Write-Warning "Start-MpScan also unavailable: $_"
        exit 2
    }
}

$logDir = Join-Path $env:TEMP "c2_defender_validate"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$scanLog = Join-Path $logDir "scan.log"

Write-Host "[*] Scanning with MpCmdRun..."
& $mp -Scan -ScanType 3 -File $ExePath 2>&1 | Tee-Object -FilePath $scanLog
$scanExit = $LASTEXITCODE

$detected = $false
$content = Get-Content $scanLog -Raw -ErrorAction SilentlyContinue
if ($null -eq $content) { $content = "" }

$cleanHints = @(
    "found no threats",
    "0 threats",
    "no threats were found",
    "scanning .* finished"
)
$hitHints = @("threat", "detected", "quarantine", "found")

$looksClean = $false
foreach ($h in $cleanHints) {
    if ($content -imatch $h) { $looksClean = $true; break }
}
$looksHit = $false
foreach ($h in $hitHints) {
    if ($content -imatch $h) { $looksHit = $true; break }
}
if ($looksHit -and -not $looksClean) { $detected = $true }
if (($scanExit -ne 0) -and ($null -ne $scanExit) -and $looksHit) { $detected = $true }

try {
    $base = [IO.Path]::GetFileName($ExePath)
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Where-Object { $_.Resources -like "*$base*" -or $_.Resources -like "*$ExePath*" }
    if ($threats) { $detected = $true; $threats | Format-List | Out-String | Write-Host }
} catch {
    # optional
}

if ($detected) {
    Write-Host "[!] DETECTION - see $scanLog"
    exit 1
}

    Write-Host "[!] DETECTION - see $scanLog"
Write-Host "    Log: $scanLog"
exit 0

