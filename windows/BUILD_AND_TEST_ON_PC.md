# Build and test HotspotShade on your Windows PC

This guide is for the first real build and the first real test of the Windows
app on your own PC. The code was checked on a Mac with the .NET 8 SDK (the Core
test runner, and builds of the broker, the elevated starter, and the console
launcher with Windows targeting) and with the static checks. A first native
build on Windows Server 2025 (build 26100, Visual Studio Community 2026 18.10,
Windows SDK 10.0.26100) found build and packaging problems. This guide now
covers them: the SDK pin in section 2, the package dependency check in section
4.4, and the install notes in sections 5 and 6. Windows behavior at Turn on is
unverified until you run these steps.

Read every step before you start. The tunnel changes the routes of this PC. The
cleanup and rollback sections tell you how to check and undo that.

## 1. What you build

| Part | Where it runs | Rights |
|---|---|---|
| `HotspotShade.WinUI2` (UWP, WinUI 2.8.7) | The window, in an AppContainer | Standard user |
| `Broker\HotspotShade.WinUI2.Broker.exe` | Full-trust process started by the window | Standard user, medium integrity |
| `Engine\hotspotshade.exe` (user engine) | Started by the broker at app open | Standard user |
| `Elevate\HotspotShade.WinUI2.Elevate.exe` | Started by the broker at Turn on only, with one UAC prompt | Administrator |
| `Engine\hotspotshade.exe` (elevated engine) | Started by the elevated starter | Administrator |
| `Engine\wintun.dll` | Loaded by the elevated engine | Official WireGuard build, not in this repository |

Opening the app, pairing, Forget, Settings, Activity, Recent failures, and Copy
diagnostics never ask for administrator approval. Only Turn on shows the UAC
prompt. Turn off and Quit stop the elevated engine and return to the user
engine.

## 2. Prerequisites

1. **Windows 10 version 2004 (build 19041) or later, x64.** Windows 11 23H2 or
   24H2 is the best target. Check with `winver`. The package needs build 19041
   for the `allowElevation` capability.
2. **An administrator account that you sign in with.** The UAC prompt must be
   approved by the signed-in account. Approval with a different account
   (over-the-shoulder credentials on a standard account) is refused by
   design, because the elevated starter must open the signed-in broker.
3. **Visual Studio 2022 17.10 or later, or Visual Studio 2026** (Community is
   fine). Visual Studio 2026 18.10 has been tested. Install:
   - the **WinUI application development** workload, and in its details
     **Universal Windows Platform tools** (on 17.10 to 17.12 the workload is
     called **Windows application development**; if your Visual Studio lists
     no such workload, use **Universal Windows Platform development**),
   - a **Windows SDK**. The default is 10.0.22621.0. Windows SDK 10.0.26100 is
     fine: build with `/p:HotspotShadeSdkVersion=10.0.26100.0` (see section
     4.4),
   - the **Desktop development with C++** workload. It provides the MSVC
     linker for Rust and for the NativeAOT elevated starter.
   The UWP project also references the **Windows Desktop Extensions for the
   UWP** SDK, which the Windows SDK installs.
4. **.NET SDK 8.0.427 or a later 8.0.x SDK** from
   https://dotnet.microsoft.com/download/dotnet/8.0. It builds the broker, the
   starter, the console launcher, and the test runner, and its runtime runs
   the broker and the starter. `windows\global.json` requires it. You can keep
   a newer SDK (such as 10.x) installed next to it: inside the `windows`
   folder, `dotnet` then picks 8.0.427 or a later 8.0.x. Check with
   `dotnet --list-sdks`, and run `dotnet --version` from the `windows` folder.
   Why: an older 8.0 SDK, and every 10.x SDK, builds the NativeAOT starter
   with a compiler and runtime at patch level 8.0.31. That level has a known
   advisory (GHSA-p3jp-9v83-76w9, fixed in 8.0.33). The starter project turns
   the advisory into an error (NU1903), and a self-contained broker would
   carry the same runtime. SDK 8.0.427 uses 8.0.33. `stage_payload.ps1` stops
   with a plain message when the SDK is too old, and when the broker runtime
   it published is older than 8.0.33.
5. **Rust stable for `x86_64-pc-windows-msvc`** from https://rustup.rs. Check
   with `rustup show` and `cargo --version`.
6. **Git for Windows** and **Node.js 18 or later** (optional, for the C#
   delimiter check). Use Git Bash only for the optional static checks in
   section 4.1. Do not build in Git Bash (see section 3).
7. **The official Wintun build.** Download `wintun-0.14.1.zip` from
   https://www.wintun.net, extract it, and use `bin\amd64\wintun.dll`. Do not
   use a copy from another program. The staging script refuses a file without
   a valid WireGuard LLC signature or a non-x64 file.
8. **An iPhone with the HotspotShade source app** installed and Personal
   Hotspot available, for the live test. See `ios/README.md`.

Developer Mode is not needed to install a signed package. It is needed only
for a Visual Studio F5 loose-file deployment, and that deployment cannot turn
the tunnel on (see section 6).

## 3. Get the source on the PC

Clone or copy the repository to a short path, for example `C:\src\hs`. Keep it
short. The NativeAOT publish and the UWP build create deep folders, and many
Windows tools stop at 260 characters (MAX_PATH), so a long checkout path fails
with confusing errors. Do not build from a path such as
`C:\Users\name\Documents\GitHub\...`.

All commands below run from that folder in **PowerShell** or in **Developer
PowerShell for VS** unless a step says otherwise. Do not build in Git Bash.
The NativeAOT publish of the elevated starter finds the MSVC linker through
the Visual Studio install, and Git Bash drops the `ProgramFiles(x86)`
environment variable that the lookup needs. If the linker is not found, open
Developer PowerShell for VS and run the command again.

With Visual Studio 2026 (version 18), `vswhere.exe` must be on `PATH` inside
the developer shell. If `vswhere` is not found, add
`C:\Program Files (x86)\Microsoft Visual Studio\Installer` to `PATH`.

Git for Windows may check text files out with CRLF line endings. The
repository has a `.gitattributes` that keeps text files as LF, so the source
checks work either way. If you copied the source some other way, run the
checks from a fresh `git clone`.

## 4. Build

### 4.1 Hermetic checks first

```powershell
dotnet run --project windows\tests\HotspotShade.WinUI2.Core.Tests\HotspotShade.WinUI2.Core.Tests.csproj -c Release
```

Expected: every line starts with `PASS`, the last lines print the passed count
and `ALL WINUI2 PROTOTYPE CHECKS PASSED`, and the exit code is 0.

Optional, from Git Bash:

```bash
sh windows/tools/check_static_contract.sh
node windows/tools/check_csharp_balance.mjs windows
```

Expected: `STATIC CONTRACT CHECK PASSED` and `C# delimiter check passed`.

Optional, the Rust engine tests: `cargo test --locked --manifest-path rust\Cargo.toml`.

### 4.2 Stage the full-trust payload

```powershell
powershell -ExecutionPolicy Bypass -File windows\tools\stage_payload.ps1 -Wintun C:\path\to\wintun-0.14.1\wintun\bin\amd64\wintun.dll
```

This runs `cargo build --release --locked`, publishes the broker
(self-contained, x64) and the elevated starter (NativeAOT, one native
program), checks the `wintun.dll` signature and machine type, and fills
`windows\out\payload`. It prints a SHA-256 hash for each file. Keep that
output with your test notes. The NativeAOT publish needs the MSVC linker from
the **Desktop development with C++** workload. Add `-FrameworkDependent` to
publish the broker against the installed .NET 8 runtime instead.

### 4.3 Create a local test certificate (once)

The package Publisher is `CN=HotspotShade Test`. In an **elevated** PowerShell:

```powershell
New-Item -ItemType Directory -Force C:\hs-test | Out-Null
$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=HotspotShade Test" -KeyUsage DigitalSignature -FriendlyName "HotspotShade Test" -CertStoreLocation "Cert:\CurrentUser\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
$password = Read-Host -AsSecureString "Password for the test certificate"
Export-PfxCertificate -Cert $cert -FilePath C:\hs-test\HotspotShadeTest.pfx -Password $password
Export-Certificate -Cert $cert -FilePath C:\hs-test\HotspotShadeTest.cer
Import-Certificate -FilePath C:\hs-test\HotspotShadeTest.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
```

Keep `C:\hs-test` outside the repository. Never commit the `.pfx` or `.cer`.
Trusting this certificate lets packages signed with it install on this PC
only. Section 9 removes it.

### 4.4 Build and sign the package

```powershell
msbuild windows\src\HotspotShade.WinUI2\HotspotShade.WinUI2.csproj /restore /p:Configuration=Release /p:Platform=x64 /p:UapAppxPackageBuildMode=SideloadOnly /p:AppxBundle=Never /p:GenerateAppxPackageOnBuild=true /p:AppxPackageDir=C:\hs-test\packages\ /p:AppxPackageSigningEnabled=true /p:PackageCertificateKeyFile=C:\hs-test\HotspotShadeTest.pfx /p:PackageCertificatePassword=YOUR_PASSWORD
```

- Use another installed SDK with `/p:HotspotShadeSdkVersion=10.0.26100.0`. A
  PC that has only Windows SDK 10.0.26100 needs this property.
- The project pins `Microsoft.NETCore.UniversalWindowsPlatform` to 6.2.14 on
  purpose. Version 6.2.15 made a package that `Add-AppxPackage` refused with
  `0x80073CF3`. Its manifest required Microsoft .NET Native Framework and
  Runtime 2.3 at 2.3.60521.0 or later, but the dependency files in
  `Dependencies\x64` were 2.3.60518.0. Those two disagree inside the
  `runtime.win10-x64.Microsoft.Net.Native.SharedLibrary` 2.3.15-rel-2605-2102
  package. Version 6.2.14 agrees with itself and installed on the test host.
  To try a newer version, add `/p:HotspotShadeUwpVersion=6.2.NN`, build, and
  run the dependency check below before you install. Change the pin in the
  project only after a package from that version passes the check and
  installs.
- The build stops with a clear error when the broker, the starter, or the
  engine is missing from `windows\out\payload`. It warns when `wintun.dll` is
  missing; that package shows Turn on as unavailable.
- CI compiles the app; the PC build stages and checks the payload. The CI
  compile-check step passes `/p:HotspotShadeSkipPayloadCheck=true` because it
  does not stage `windows\out\payload`. Do not pass that property for a
  package that you install. The check stays on by default.
- The password goes only on this command line. Do not put it in a file in the
  repository.

Expected: `C:\hs-test\packages\HotspotShade.WinUI2_0.2.0.0_x64_Test\` holds
`HotspotShade.WinUI2_0.2.0.0_x64.msix` and a `Dependencies\x64` folder.

Check that the package manifest and the bundled dependency files agree before
you install. This reads files only and changes nothing:

```powershell
powershell -ExecutionPolicy Bypass -File windows\tools\check_package_dependencies.ps1 -PackageDir C:\hs-test\packages\HotspotShade.WinUI2_0.2.0.0_x64_Test
```

Expected: one `ok` line for each bundled dependency and `Dependency versions
match.` A `MISMATCH` line means `Add-AppxPackage` would fail with
`0x80073CF3`. Do not install that package.

## 5. Install

In a normal (not elevated) PowerShell:

```powershell
$dir = "C:\hs-test\packages\HotspotShade.WinUI2_0.2.0.0_x64_Test"
$deps = Get-ChildItem "$dir\Dependencies\x64\*.appx" | ForEach-Object FullName
Add-AppxPackage -Path "$dir\HotspotShade.WinUI2_0.2.0.0_x64.msix" -DependencyPath $deps
Get-AppxPackage HotspotShade.Windows
```

The install folder is under `C:\Program Files\WindowsApps\` (or
`X:\WindowsApps\` when new apps go to another drive), which only Windows can
change. The elevated engine loads `wintun.dll` from there.

If `Add-AppxPackage` fails with `0x80073CF3`, run the dependency check from
section 4.4 on the package folder and read its output first.

At Turn on the elevated starter checks the install itself before it starts
anything: it opens the package folder, the `Engine` folder, the engine, and
`wintun.dll`, follows each to its final path, and requires that path to be in a
WindowsApps package store, the owner to be TrustedInstaller or SYSTEM, and no
access entry to let an account other than TrustedInstaller, SYSTEM, or
Administrators change it. The folder name alone is not enough. To see what it
checks, run in PowerShell:

```powershell
$root = (Get-AppxPackage HotspotShade.Windows).InstallLocation
foreach ($p in @($root, "$root\Engine", "$root\Engine\hotspotshade.exe", "$root\Engine\wintun.dll", "$root\Elevate\HotspotShade.WinUI2.Elevate.exe")) {
    $p
    (Get-Item -LiteralPath $p).Target   # empty: not a link
    (Get-Acl -LiteralPath $p).Owner
    (Get-Acl -LiteralPath $p).Sddl
    icacls $p
}
```

Expected: owner `NT SERVICE\TrustedInstaller` (or `NT AUTHORITY\SYSTEM`),
and `BUILTIN\Users` with `(RX)` only. On the first real install (Windows
Server 2025) this check returned Trusted: the owner was SYSTEM, and only
TrustedInstaller and SYSTEM had full control. The starter also requires the package
folder name to be the broker's package full name, the folder to be the path
that Windows reports for that package, and the volume to be a fixed disk (not
removable media or a network drive). If Turn on reports "not installed from a
package in a protected Windows apps folder" on an installed package, send this
output with the report.

## 6. First launch, no hotspot yet

Before you start, check two things about the account and Windows:

- **UAC must be on.** A UWP app does not launch when UAC is turned off
  (`EnableLUA` set to 0 in
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`). Windows
  shows no useful message; the app just does not open. Turn UAC on and restart
  Windows.
- **Test with your own administrator account and UAC on** (the normal Windows
  setup). The app and the user engine then run with a standard user token, and
  Turn on shows one Yes/No UAC prompt. Do not use the built-in Administrator
  account or an already elevated session: Windows shows no prompt there, so you
  cannot confirm the one-prompt behavior. Do not test from a standard (non
  admin) account either: its prompt asks for a different administrator's
  password, and the starter refuses approval by a different account (section 2,
  item 2). Write down the account type, what the prompt asked for, and whether
  Turn on succeeded.

1. Start **HotspotShade** from the Start menu. **No UAC prompt may appear.** If
   one appears at launch, stop and report it.
2. The Dashboard shows "Starting HotspotShade", then "Not paired" or another
   real state within a few seconds.
3. Settings, Advanced, App details shows "Engine: Standard user engine".
4. Check the processes in Task Manager, Details: one
   `HotspotShade.WinUI2.Broker.exe` and one `hotspotshade.exe`, both with your
   user name and "Elevated: No" (add the Elevated column).
5. If the Dashboard says Turn on is unavailable, read the reason:
   - "This engine build cannot pass the pairing to the administrator engine":
     the staged engine refused `--handoff-fd`. Rebuild the engine from the
     current source (see section 10).
   - "wintun.dll is missing": restage with `-Wintun` and rebuild.
   - "not installed from a package in a protected Windows apps folder": you
     started a Visual Studio loose-file deployment, or the install folder
     failed the starter's owner and access check (see section 5). Install the
     signed package instead.

## 7. First real test with an iPhone hotspot

Record the routes before you start:

```powershell
route print -4 > C:\hs-test\routes-before-v4.txt
route print -6 > C:\hs-test\routes-before-v6.txt
netsh interface show interface > C:\hs-test\interfaces-before.txt
```

1. On the iPhone: turn on Personal Hotspot and open HotspotShade. Keep it in
   the foreground.
2. Connect the PC to the iPhone hotspot over Wi-Fi. Disconnect any VPN.
3. In the Windows app, press **Pair with source device**. Compare the six
   digits on both screens and tap **Allow** on the iPhone.
4. The Dashboard shows **Ready** and **Turn on**, with the line "Windows asks
   for administrator approval when you turn on the tunnel."
5. Press **Turn on**. Approve the one UAC prompt. It names
   `HotspotShade.WinUI2.Elevate.exe`.
6. The Dashboard shows "Starting the tunnel", then **On**. Settings, Advanced
   shows "Engine: Administrator engine".
7. Check the routes:

   ```powershell
   route print -4 | findstr /C:"0.0.0.0        128.0.0.0" /C:"128.0.0.0        128.0.0.0"
   route print -6 | findstr 2000::/3
   netsh interface show interface
   ```

   Expected: two IPv4 `/1` routes and the IPv6 `2000::/3` route on the
   `HotspotShade-Tunnel` adapter.
8. Browse a few sites. Run `ping 1.1.1.1` (with Let ping work on). Open
   Activity and check that log lines appear.
9. Settings, Advanced: press **Copy diagnostics** and paste it into your
   notes. The Dashboard shows a TTL audit line if any outer socket had the
   wrong TTL; there must be none.
10. Press **Turn off**. The Dashboard shows "Turning off", then Ready. App
    details shows "Standard user engine" again.
11. Test Quit while On: Turn on again, then use HotspotShade, Quit HotspotShade.
    Confirm the dialog. The elevated engine must stop and its routes must go.
12. Automatic stop: while On, turn off Personal Hotspot on the iPhone. Within
    a few seconds the engine should turn the tunnel off. The Dashboard should
    return to the standard user engine and the Connection card should show
    "Last stop: The hotspot turned off, so HotspotShade turned the tunnel
    off." Run the cleanup checks right after. This path has not run on
    Windows; note exactly what you see.
13. Gate check: connect a VPN, then press Turn on. The engine must refuse with
    "The source device must be the default gateway of a physical hotspot
    adapter. Turn off any VPN, connect to the source device hotspot, then try
    again." No route may change.

## 8. Cleanup checks after every test

```powershell
route print -4 > C:\hs-test\routes-after-v4.txt
route print -6 > C:\hs-test\routes-after-v6.txt
netsh interface show interface > C:\hs-test\interfaces-after.txt
fc C:\hs-test\routes-before-v4.txt C:\hs-test\routes-after-v4.txt
fc C:\hs-test\routes-before-v6.txt C:\hs-test\routes-after-v6.txt
Get-Process hotspotshade, HotspotShade.WinUI2.Broker, HotspotShade.WinUI2.Elevate -ErrorAction SilentlyContinue
```

Expected after Turn off: no `0.0.0.0/1`, `128.0.0.0/1`, or `2000::/3` route
on `HotspotShade-Tunnel`, and no `HotspotShade-Tunnel` adapter. After Quit: no
HotspotShade process. Small metric or gateway differences from a Wi-Fi change
are normal; a leftover `/1` route is not.

If the app shows "HotspotShade could not confirm that the tunnel stopped" or
"The administrator engine exited without a confirmed stop", run the checks
above before anything else.

## 9. Rollback and uninstall

1. Quit HotspotShade (menu HotspotShade, Quit HotspotShade).
2. Remove the package:

   ```powershell
   Get-AppxPackage HotspotShade.Windows | Remove-AppxPackage
   ```

3. If a tunnel route is left behind, remove only routes on the
   `HotspotShade-Tunnel` adapter, in an elevated PowerShell:

   ```powershell
   Get-NetRoute -InterfaceAlias "HotspotShade-Tunnel*" -ErrorAction SilentlyContinue
   Get-NetRoute -InterfaceAlias "HotspotShade-Tunnel*" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
   ```

   Do not delete a route on another adapter. If the adapter itself is left,
   restart Windows; Wintun removes an adapter whose owner is gone.
4. Remove the test certificate:

   ```powershell
   Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object Subject -eq "CN=HotspotShade Test" | Remove-Item
   Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq "CN=HotspotShade Test" | Remove-Item
   Remove-Item -Recurse C:\hs-test
   ```

5. Delete `windows\out` from the source folder if you want the disk space back.

## 10. Known dependencies and limits

- **Engine pairing handoff on Windows.** Turn on needs the engine to accept
  `--handoff-fd` (user engine) and `--credentials-fd` (elevated engine) on
  Windows and to serve `POST /api/pairing/handoff`. The current engine source
  does (`rust/src/windows_credential_handoff.rs`, `rust/src/gui_backend_windows.rs`).
  An older engine that refuses the switches makes the broker start it without
  the handoff, and the app shows Turn on as unavailable with that reason.
  Neither side has run on Windows yet.
- **Gated token use.** The engine checks the physical adapter and the default
  gateway before any token use. A VPN, a second default route, or a virtual
  adapter makes it refuse; the app shows the engine message.
- The v1 source device token crosses the hotspot link in cleartext.
- Automatic stop exists in the engine and is unverified on Windows. No
  notifications, no launch at login, no notification area icon, and no direct
  mode. See README.md.
- The package can live in `C:\Program Files\WindowsApps` or in
  `X:\WindowsApps` when Windows installs apps on another volume. Any other
  folder refuses Turn on. The folder name is only a pre-filter: the elevated
  starter also requires the final path (after links), a TrustedInstaller or
  SYSTEM owner, and a DACL that gives no change right to Users, Authenticated
  Users, Everyone, the creator SIDs, or any account other than
  TrustedInstaller, SYSTEM, and Administrators. A `WindowsApps` folder that a
  user created on another drive fails that check, and so does any folder that
  is not the one Windows reports for the broker's package, or that is on
  removable media or a network drive. This check has not run on
  Windows yet; if real package folders carry an extra entry, Turn on reports
  the install as untrusted.
- A Visual Studio F5 deployment is for UI work only. Turn on is refused there
  because its folder is user-writable.
