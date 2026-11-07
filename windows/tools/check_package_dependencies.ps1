<#
.SYNOPSIS
Check that a built HotspotShade package matches its bundled dependency packages.

.DESCRIPTION
Add-AppxPackage fails with 0x80073CF3 when the package manifest asks for a
dependency version that the dependency files next to the package do not meet.
The first native Windows build hit this with .NET Native Framework and Runtime
2.3: the manifest asked for 2.3.60521.0 and the bundled files were 2.3.60518.0.

This script reads the manifest inside the .msix and the manifest inside each
.appx in the Dependencies folder. For every PackageDependency it finds a
bundled package with the same name and a version at or above MinVersion. It
changes nothing, installs nothing, and needs no administrator rights.

.PARAMETER PackageDir
The folder that holds the .msix and the Dependencies folder, for example
C:\hs-test\packages\HotspotShade.WinUI2_0.2.0.0_x64_Test

.PARAMETER Architecture
The dependency subfolder to check. The default is x64.

.EXAMPLE
.\windows\tools\check_package_dependencies.ps1 -PackageDir C:\hs-test\packages\HotspotShade.WinUI2_0.2.0.0_x64_Test
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageDir,
    [string]$Architecture = "x64"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-Manifest([string]$Path) {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entry = $zip.GetEntry("AppxManifest.xml")
        if ($null -eq $entry) { throw "No AppxManifest.xml inside $Path." }
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { return [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally {
        $zip.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $PackageDir -PathType Container)) { throw "The folder does not exist: $PackageDir" }
$msix = Get-ChildItem -LiteralPath $PackageDir -File | Where-Object { $_.Extension -in ".msix", ".appx" } | Select-Object -First 1
if ($null -eq $msix) { throw "No .msix or .appx package is in $PackageDir." }
$depDir = Join-Path $PackageDir (Join-Path "Dependencies" $Architecture)
if (-not (Test-Path -LiteralPath $depDir -PathType Container)) { throw "The dependency folder does not exist: $depDir" }

$manifest = Read-Manifest $msix.FullName
$required = @($manifest.Package.Dependencies.PackageDependency)
Write-Host ("Package: {0} {1}" -f $manifest.Package.Identity.Name, $manifest.Package.Identity.Version)

$bundled = @()
foreach ($file in Get-ChildItem -LiteralPath $depDir -File | Where-Object { $_.Extension -in ".appx", ".msix" }) {
    $identity = (Read-Manifest $file.FullName).Package.Identity
    $bundled += [pscustomobject]@{ Name = $identity.Name; Version = [Version]$identity.Version; File = $file.Name }
}

$failed = 0
foreach ($dependency in $required) {
    if ($null -eq $dependency) { continue }
    $name = $dependency.Name
    $minimum = [Version]$dependency.MinVersion
    $found = @($bundled | Where-Object { $_.Name -eq $name } | Sort-Object Version -Descending)
    if ($found.Count -eq 0) {
        Write-Host ("  NOT BUNDLED  {0} needs {1} (Windows may already have it)" -f $name, $minimum)
    } elseif ($found[0].Version -lt $minimum) {
        Write-Host ("  MISMATCH     {0} needs {1}, bundled {2} ({3})" -f $name, $minimum, $found[0].Version, $found[0].File)
        $failed++
    } else {
        Write-Host ("  ok           {0} needs {1}, bundled {2}" -f $name, $minimum, $found[0].Version)
    }
}

if ($failed -gt 0) {
    throw ("$failed dependency version mismatch(es). Add-AppxPackage would fail with 0x80073CF3. " +
        "Use the pinned Microsoft.NETCore.UniversalWindowsPlatform version, or choose a version whose runtime package agrees with itself.")
}
Write-Host "Dependency versions match."
