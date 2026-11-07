<#
.SYNOPSIS
Build the full-trust payload of the HotspotShade Windows package.

.DESCRIPTION
Builds the Rust engine, publishes the broker and the elevated starter, and
copies them with the official wintun.dll into windows\out\payload:

  Broker\   HotspotShade.WinUI2.Broker.exe and its files
  Elevate\  HotspotShade.WinUI2.Elevate.exe and its files
  Engine\   hotspotshade.exe and wintun.dll

The UWP project packages this folder. The script deletes and recreates only
windows\out\payload. It never installs, signs, or starts anything.

.PARAMETER Wintun
Path to the official x64 wintun.dll from https://www.wintun.net. The file must
be named wintun.dll and carry a valid Authenticode signature from WireGuard
LLC. Without it the package builds, and Turn on is shown as unavailable.

.PARAMETER SkipEngine
Use an engine that is already built instead of running cargo.

.PARAMETER FrameworkDependent
Publish the broker against the installed .NET 8 runtime instead of with its
own runtime. The elevated starter is always published with NativeAOT, so it
has no .NET host at all.
#>
[CmdletBinding()]
param(
    [string]$Wintun = "",
    [switch]$SkipEngine,
    [switch]$FrameworkDependent
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

$windows = Split-Path -Parent $PSScriptRoot
$repo = Split-Path -Parent $windows
$payload = Join-Path $windows "out\payload"

if (Test-Path -LiteralPath $payload) {
    Remove-Item -LiteralPath $payload -Recurse -Force
}
foreach ($name in @("Broker", "Elevate", "Engine")) {
    New-Item -ItemType Directory -Path (Join-Path $payload $name) | Out-Null
}

if (-not $SkipEngine) {
    Write-Host "Building the engine with cargo (release, locked)."
    & cargo build --release --locked --manifest-path (Join-Path $repo "rust\Cargo.toml")
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE." }
}
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo "rust\target" }
$engine = Join-Path $targetDir "release\hotspotshade.exe"
if (-not (Test-Path -LiteralPath $engine)) { throw "The engine is missing: $engine" }
Copy-Item -LiteralPath $engine -Destination (Join-Path $payload "Engine\hotspotshade.exe")

$contained = if ($FrameworkDependent) { "false" } else { "true" }
Write-Host "Publishing the broker (self-contained: $contained)."
& dotnet publish (Join-Path $windows "src\HotspotShade.WinUI2.Broker\HotspotShade.WinUI2.Broker.csproj") -c Release -r win-x64 --self-contained $contained -o (Join-Path $payload "Broker")
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for the broker with exit code $LASTEXITCODE." }

# The elevated starter runs with administrator rights. NativeAOT removes the
# .NET host, so no startup hook, profiler, or DOTNET_ROOT value from the user
# environment can load code into it. This needs the MSVC linker from the
# Visual Studio "Desktop development with C++" workload.
Write-Host "Publishing the elevated starter (NativeAOT)."
& dotnet publish (Join-Path $windows "src\HotspotShade.WinUI2.Elevate\HotspotShade.WinUI2.Elevate.csproj") -c Release -r win-x64 -p:PublishAot=true -o (Join-Path $payload "Elevate")
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for the elevated starter with exit code $LASTEXITCODE." }
$managed = Get-ChildItem -LiteralPath (Join-Path $payload "Elevate") -Filter "*.dll" -ErrorAction SilentlyContinue
if ($managed) { throw "The elevated starter folder holds DLLs; the NativeAOT publish did not produce a single native program." }
Get-ChildItem -LiteralPath (Join-Path $payload "Elevate") -Filter "*.pdb" | Remove-Item

if ($Wintun -ne "") {
    $file = Get-Item -LiteralPath $Wintun
    if ($file.Name -ne "wintun.dll") { throw "The adapter file must be named wintun.dll." }
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($signature.Status -ne "Valid" -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch "WireGuard LLC") {
        throw "wintun.dll does not carry a valid WireGuard LLC signature. Use the x64 file from the official Wintun zip."
    }
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    if ($machine -ne 0x8664) { throw "wintun.dll is not the x64 build. Use bin\amd64\wintun.dll from the official zip." }
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $payload "Engine\wintun.dll")
} else {
    Write-Warning "No -Wintun path. The package builds, and Turn on is shown as unavailable."
}

Write-Host ""
Write-Host "Payload ready in $payload"
foreach ($path in @("Broker\HotspotShade.WinUI2.Broker.exe", "Elevate\HotspotShade.WinUI2.Elevate.exe", "Engine\hotspotshade.exe", "Engine\wintun.dll")) {
    $full = Join-Path $payload $path
    if (Test-Path -LiteralPath $full) {
        $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
        Write-Host ("  {0}  {1}" -f $hash, $path)
    } else {
        Write-Host ("  missing  {0}" -f $path)
    }
}
