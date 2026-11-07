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

# The build needs .NET SDK 8.0.427 or later 8.0.x. Older 8.0 SDKs and every
# 10.x SDK pull a NativeAOT compiler and runtime from the 8.0.31 patch level.
# That level has a known advisory (GHSA-p3jp-9v83-76w9, fixed in 8.0.33), and
# the elevated starter build treats the advisory as an error. windows\global.json
# asks for 8.0.427. dotnet reads global.json from the current folder, so run
# every dotnet command from the windows folder.
$minimumSdk = [Version]"8.0.427"
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
Push-Location -LiteralPath $windows
try {
    $sdkText = (& dotnet --version 2>&1 | Out-String).Trim()
    $sdkOk = ($LASTEXITCODE -eq 0)
} catch {
    $sdkText = $_.Exception.Message
    $sdkOk = $false
} finally {
    Pop-Location
    $ErrorActionPreference = $previousPreference
}
if (-not $sdkOk -or $sdkText -notmatch '^(\d+\.\d+\.\d+)') {
    throw ("No usable .NET SDK was found. Install .NET SDK 8.0.427 or a later 8.0.x SDK " +
        "from https://dotnet.microsoft.com/download/dotnet/8.0 (it can sit next to newer SDKs). " +
        "dotnet said: $sdkText")
}
$sdkVersion = [Version]$Matches[1]
if ($sdkVersion.Major -ne 8 -or $sdkVersion -lt $minimumSdk) {
    throw ("The .NET SDK in use is $sdkText. This build needs .NET SDK 8.0.427 or a later 8.0.x SDK. " +
        "Install it from https://dotnet.microsoft.com/download/dotnet/8.0 and run this script again.")
}
# Run dotnet from the windows folder so it reads windows\global.json.
function Invoke-WindowsDotnet([string]$Failure, [string[]]$Arguments) {
    Push-Location -LiteralPath $windows
    try {
        & dotnet @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Failure with exit code $LASTEXITCODE." }
    } finally {
        Pop-Location
    }
}

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
Invoke-WindowsDotnet -Failure "dotnet publish failed for the broker" -Arguments @("publish", (Join-Path $windows "src\HotspotShade.WinUI2.Broker\HotspotShade.WinUI2.Broker.csproj"), "-c", "Release", "-r", "win-x64", "--self-contained", $contained, "-o", (Join-Path $payload "Broker"))
if ($contained -eq "true") {
    # A self-contained broker carries its own runtime. Refuse a payload whose
    # runtime is older than 8.0.33, the first patch without the advisory.
    $coreLib = Join-Path $payload "Broker\System.Private.CoreLib.dll"
    if (-not (Test-Path -LiteralPath $coreLib)) { throw "The self-contained broker has no System.Private.CoreLib.dll." }
    $runtimeText = (Get-Item -LiteralPath $coreLib).VersionInfo.ProductVersion
    if ($runtimeText -notmatch '^(\d+\.\d+\.\d+)' -or [Version]$Matches[1] -lt [Version]"8.0.33" -or ([Version]$Matches[1]).Major -ne 8) {
        throw "The broker runtime is $runtimeText. It must be .NET 8.0.33 or later 8.0.x. Install .NET SDK 8.0.427 or later and run this script again."
    }
    Write-Host "Broker runtime: $runtimeText."
}

# The elevated starter runs with administrator rights. NativeAOT removes the
# .NET host, so no startup hook, profiler, or DOTNET_ROOT value from the user
# environment can load code into it. This needs the MSVC linker from the
# Visual Studio "Desktop development with C++" workload. PublishAot comes from
# Elevate.csproj. Do not pass PublishAot as a global -p property here: it also
# reaches the netstandard2.0 Core reference and fails with NETSDK1207.
Write-Host "Publishing the elevated starter (NativeAOT)."
Invoke-WindowsDotnet -Failure "dotnet publish failed for the elevated starter" -Arguments @("publish", (Join-Path $windows "src\HotspotShade.WinUI2.Elevate\HotspotShade.WinUI2.Elevate.csproj"), "-c", "Release", "-r", "win-x64", "-o", (Join-Path $payload "Elevate"))
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
