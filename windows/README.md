# HotspotShade for Windows (WinUI 2 prototype)

> **Status: user interface prototype. Not production ready.**
>
> This directory contains a native WinUI 2 user interface prototype. It has no
> engine connection, tunnel, routes, service, network listener, or credentials.
> All displayed data is simulated. Do not attach it to the Rust engine.

This is an isolated prototype. It does not claim Windows tunnel support. The
macOS arm64 tunnel remains the only verified tunnel.

The Rust command-line engine now has a source device proxy start path on
Windows. This WinUI app does not use it. The Windows target still needs a
protected service boundary, a live hotspot test, and a signed package before
production. The root platform status is in [../README.md](../README.md).

## What this is

- A UWP app with WinUI 2.8.7 controls. The window has a native title bar, a
  native in-window menu bar, and a `NavigationView` with Dashboard, Activity,
  and Settings.
- A translation of the macOS target app states: Dashboard, pairing, Activity,
  Settings, attention lines, status freshness, ping text, recent failures, and
  simulated reports.
- A labeled demo. A persistent `InfoBar` says that all data is simulated. The
  Dashboard, Activity, Settings, recent failures, and reports repeat the label.
- A pure state machine in `src/HotspotShade.WinUI2.Core` with a deterministic
  clock and no Windows UI dependency.
- A dependency-free test runner. It checks the state machine and static
  contracts. It needs no test framework package.

## What this is not

- It is not a tunnel. It creates no adapter, route, socket, or listener.
- It is not a service client. It has no HTTP client, no loopback API, no IPC,
  and no engine bearer secret.
- It is not a source device app. It never contacts a phone.
- It is not production ready. It has no signed package, installer, update path,
  crash reporting, localization, or support lifecycle.
- It is not proof that a Windows tunnel works.

## Architecture decision

The prototype uses **UWP with WinUI 2.8.7**. This is the supported WinUI 2 app
model that Microsoft documents for a self-contained native app:

- Microsoft documents WinUI 2 for UWP apps and for desktop apps that use XAML
  Islands.
- Microsoft documents XAML Islands for WPF and Windows Forms as supported only
  in apps that target .NET Core 3.x. .NET Core 3.1 is out of support. The
  Community Toolkit host control is archived. WinUI controls in an unpackaged
  island also need MSIX or dynamic dependencies. That path is not a viable base
  for a new app.
- WinUI 3 is a different framework and is outside the user choice for this
  prototype.

UWP has critical tradeoffs for this product. The prototype stops at the user
interface because those tradeoffs cannot be solved inside the UI process:

| Area | UWP limit | Consequence for this product |
|---|---|---|
| Process | The app runs in an AppContainer at low integrity. | It cannot create a Wintun adapter, change routes, or install a Windows service. |
| Privilege | A UWP process cannot elevate. | The privileged engine must live in a separate full-trust process or service. It is not implemented. |
| Loopback | An AppContainer blocks loopback by default. | The app cannot use the macOS loopback service API. A future bridge needs an app service or another supported boundary. `CheckNetIsolation` is a development workaround, not a shipping design. |
| Lifecycle | UWP is suspended when minimized and may be terminated. | A tunnel cannot live in the UI process. The prototype runs only a short UI timer. |
| Engine | The package has no engine and no service. | Every value is simulated. There is no hidden real mode. |
| Notifications | Toast notifications need package identity and a manifest declaration. | Not implemented. The app does not request permission. |
| Startup | Launch at login needs a startup task declaration. | Not implemented. The setting is disabled and explained. |
| Windows | UWP has no global menu bar and no tray icon. | The app uses a WinUI 2 `MenuBar` in the window. There is no menu bar extra. |
| Windows | UWP `ApplicationView.SetPreferredMinSize` caps the preferred minimum at 500 by 500. | The app sets 500 by 500. It cannot enforce the macOS minimum of 780 by 560. |
| Settings | A second UWP view adds lifecycle and activation complexity. | Settings is a page in the main window. This also matches the native `NavigationView` pattern. |
| Theme | `Application.RequestedTheme` cannot change at runtime. | The page changes `FrameworkElement.RequestedTheme`. Menu flyouts and dialogs can keep the system theme. Verify this on the target host. |
| Packaging | No certificate is included and signing is disabled. | Local deployment from Visual Studio is the intended test path. A signed MSIX is not produced. |

### Why this is not the final Windows architecture

WinUI 2 can draw the UI, but it cannot hold the privileged engine. A production
Windows app needs a separate design:

1. A full-trust broker or Windows service that owns Wintun, routes, DNS, and
   cleanup.
2. A protected boundary between the UI and the broker. A loopback socket is not
   available to an AppContainer without an exemption.
3. A packaging and signing decision, an installer, and a Windows host test with
   a real source device.

A packaged full-trust helper started with `FullTrustProcessLauncher` and an app
service connection is one documented direction. It is not implemented here.
Do not invent it in the UI prototype. If the product requires the engine inside
a WinUI 2 process, stop: that shape is not supported by the documented UWP
model.

## Layout

```text
windows/
  HotspotShade.WinUI2.sln
  NuGet.config
  README.md
  PARITY.md
  src/
    HotspotShade.WinUI2/              UWP app, WinUI 2.8.7
      App.xaml, App.xaml.cs
      MainPage.xaml, MainPage.xaml.cs
      Package.appxmanifest
      Assets/                        tile logos copied from assets/logo
      Converters/ValueConverters.cs
      Properties/Default.rd.xml
      Properties/AssemblyInfo.cs
      Services/ClipboardService.cs
      Services/LocalSettingsStore.cs
      ViewModels/DemoViewModel.cs
      ViewModels/Rows.cs
    HotspotShade.WinUI2.Core/         netstandard2.0 pure state
      DemoEnums.cs
      DemoModels.cs
      DemoReports.cs
      DemoScenarios.cs
      DemoSession.cs
      DemoText.cs
  tests/
    HotspotShade.WinUI2.Core.Tests/   net8.0 console test runner
  tools/
    check_csharp_balance.mjs
    check_static_contract.sh
```

The app project is an old-style UWP project. It lists every XAML and C# file
explicitly. The test runner checks that the list is complete.

## Dependencies

| Dependency | Version | Reason |
|---|---|---|
| `Microsoft.UI.Xaml` | 2.8.7 | WinUI 2 controls: `MenuBar`, `NavigationView`, `InfoBar`, `ProgressRing`. |
| `Microsoft.NETCore.UniversalWindowsPlatform` | 6.2.15 | UWP runtime and build support. |
| .NET SDK | 8.0.100 or later (8.0.x) | Builds the core library and the console test runner. |
| Windows 11 SDK | 10.0.22621.0 | UWP target platform for the app project. |
| Visual Studio 2022 | 17.10 or later | UWP workload, XAML compiler, deployment. |

The package versions are exact pins. The app has no other NuGet package and no
Tauri, WinUI 3, Windows App SDK, Rust, or Node dependency. Node is used only for
an optional local delimiter check.

A NuGet lock file is not committed because this host cannot restore the UWP
graph. The package versions are exact pins. Generate and review a lock file on
the Windows test host before a production change. Do not invent lock file
contents.

## Build prerequisites

Test on a Windows 10 or Windows 11 x64 host.

1. Install Visual Studio 2022 version 17.10 or later.
2. In the Visual Studio Installer, select **WinUI application development**.
   In the installation details, select **Universal Windows Platform tools** for
   C#. On Visual Studio 17.10 to 17.12 the workload is called **Windows
   application development**.
3. Install Windows 11 SDK **10.0.22621.0**. The project targets that version by
   default. To build with another installed SDK, pass for example
   `/p:HotspotShadeSdkVersion=10.0.26100.0` to MSBuild. This property changes
   only the app project's target SDK. It does not change the minimum Windows
   version. Use a version installed on the host.
4. Install the .NET SDK **8.0.100 or later**. It builds the core library and the
   test runner.
5. Turn on **Developer Mode** in Windows Settings, System, For developers. It is
   needed for local UWP deployment.
6. Allow NuGet access to `https://api.nuget.org/v3/index.json`. No other feed is
   used.
7. Do not install WinUI 3 or the Windows App SDK for this prototype. Do not
   install a certificate. The project includes no signing material.

## Build and test

Run these commands from the repository root on Windows.

| Command | Expected result |
|---|---|
| `dotnet run --project windows/tests/HotspotShade.WinUI2.Core.Tests/HotspotShade.WinUI2.Core.Tests.csproj -c Release` | Prints `ALL WINUI2 PROTOTYPE CHECKS PASSED` and exits 0. |
| `dotnet build windows/src/HotspotShade.WinUI2.Core/HotspotShade.WinUI2.Core.csproj -c Release` | Builds the pure state library. This also works on macOS and Linux with the .NET SDK. |
| `msbuild windows/HotspotShade.WinUI2.sln /restore /p:Configuration=Debug /p:Platform=x64 /m` | Builds the app and the core library. Run it from a Developer Command Prompt for Visual Studio 2022. It does not deploy or run the app. |
| `node windows/tools/check_csharp_balance.mjs windows` | Prints `C# delimiter check passed for 18 files`. Node is optional. |
| `bash windows/tools/check_static_contract.sh` | Prints `STATIC CONTRACT CHECK PASSED`. It needs `bash` and `xmllint`. Use Git Bash or WSL on Windows. |

`dotnet build` and `dotnet test` cannot build the UWP app project. Use Visual
Studio or MSBuild for the app.

For a test host with Microsoft.NET.Native.Framework 2.2 already installed, an
isolated Release preview can use the explicit `HotspotShadeTestUwp6214`
override. This selects UWP 6.2.14 only for that build. The default stays
6.2.15. The command below also selects .NET Native. It does not sign or deploy
the package.

```powershell
msbuild windows/src/HotspotShade.WinUI2/HotspotShade.WinUI2.csproj /restore /p:Configuration=Release /p:Platform=x64 /p:HotspotShadeSdkVersion=10.0.26100.0 /p:HotspotShadeTestUwp6214=true /p:UseDotNetNativeToolchain=true /p:AppxPackageSigningEnabled=false /p:GenerateAppxPackageOnBuild=false
```

On the Windows Server 2025 test host, this native configuration activated the
simulated app. The managed Debug configuration failed during startup. Its
underlying exception is not yet known. A loose unsigned package needs an
appropriate development deployment policy. The EXE is an AppContainer entry
point and is not a standalone desktop executable.

### Deploy and run

1. Open `windows/HotspotShade.WinUI2.sln` in Visual Studio 2022.
2. Set `HotspotShade.WinUI2` as the startup project.
3. Select `Debug` and `x64`.
4. Press F5. Visual Studio builds and deploys a loose debug package.
5. If Visual Studio asks to create a temporary developer certificate, use a
   local-only certificate. Do not commit it. This project sets
   `AppxPackageSigningEnabled` to false and contains no certificate.
6. The window title is `HotspotShade (simulated)`. The top banner says that all
   data is simulated.

If deployment fails, read the Visual Studio Output window. Do not switch to
WinUI 3 or add a certificate to the repository to work around a missing UWP
workload.

## What the UI does

### Main window

- Native title bar and native window controls.
- A WinUI 2 menu bar with View, Demo, and Help.
- A `NavigationView` with Dashboard and Activity. The built-in Settings item is
  at the bottom.
- A persistent `InfoBar` above the page content:
  "Demo mode. All data is simulated." and "No tunnel, routes, network listener,
  or credentials. This prototype is not production ready."
- Dashboard and Activity share a maximum content width of 720. Settings uses the
  same width.
- The settings page uses a `Pivot` with General, Pairing, and Advanced.

### Demo behavior

All values are local and simulated. The only timed work is one
`DispatcherTimer` of 900 ms in the page. It completes the visible loading state.
It stops when the page unloads. No work continues in the background.

1. The app starts unpaired. The primary action is **Pair with source device**.
2. Pair shows the pairing panel with a waiting spinner.
3. After 900 ms, the code `482 193` appears.
4. **Copy code** copies the simulated code. **Simulate approval** completes the
   pairing. **Simulate a failed pairing** shows the pairing error state.
5. Ready has **Turn on**. Turn on shows a loading state, then On.
6. On shows the ping line, three active connections, the last check time, and
   **Turn off**.
7. Forget while the tunnel runs is blocked. The app offers **Turn off and
   forget**.
8. Activity has a loaded list, details, refresh loading, an empty state, and an
   unavailable state.
9. Recent failures need the simulated tunnel. Refresh loads three simulated
   groups. The panel also has an empty state and a clear action.
10. The Demo lab and the Demo menu switch among 14 states. Reset returns to
    Unpaired.

Every action changes only the local demo session. The app does not send a
request, open a socket, or read a real status.

### States that the prototype covers

| State | How to reach it |
|---|---|
| Unpaired | Start, Demo lab, or Reset |
| Pairing starting | Select Pair |
| Pairing code | Wait 900 ms |
| Pairing failed | Select Simulate a failed pairing |
| Not trusted | Demo lab |
| Waiting for source device | Demo lab |
| Ready | Approve the simulated pairing, or Demo lab |
| On | Turn on, or Demo lab |
| On, source device stopped | Demo lab |
| On, not trusted | Demo lab |
| On, stale status | Demo lab |
| Status unavailable | Demo lab |
| Error | Demo lab |
| Activity empty | Demo lab |
| Activity loading | Refresh on Activity |
| Activity unavailable | Status unavailable scenario, then Activity |
| After forget | Forget, or Demo lab |
| Recent failures loading | Turn on, then Refresh in Advanced |
| Recent failures empty | Turn on, Refresh, then Clear simulated failures |
| Forget blocked | Turn on, then Forget |

The recent failure unavailable and read error states exist in the core enum but
are not reachable from the UI. There is no engine that can return those errors.
They are not faked.

## Menu and keyboard

| Command | Shortcut | Notes |
|---|---|---|
| Dashboard | Ctrl+1 | Shows the Dashboard |
| Activity | Ctrl+2 | Shows Activity |
| Settings | Ctrl+3 | Shows the Settings page |
| Refresh status | F5 | Runs the simulated Check now flow |
| Check source device now | Ctrl+K | Runs the simulated Check now flow |
| Use system setting, Light appearance, Dark appearance | none | Changes the page theme at once |
| Demo, Scenarios | none | Applies one simulated state |
| Demo, Reset demo | none | Asks for confirmation, then resets |
| Help, Demo limitations | none | Opens a `ContentDialog` with the limits |
| Help, About HotspotShade | none | Opens a `ContentDialog` with the version |

The menu is inside the window. UWP has no global menu bar and no tray icon. The
shortcuts are page-level `KeyboardAccelerator` objects, so they work while the
window is active.

## Light, dark, and accessibility

- The app follows the Windows theme by default. Settings, General, Appearance
  can force Light or Dark for the page content. The native title bar follows
  the Windows theme.
- All custom colors are in `App.xaml` theme dictionaries for Default (dark),
  Light, and HighContrast. Components use theme resources only.
- Menu flyouts and `ContentDialog` windows can keep the system theme because
  UWP cannot change `Application.RequestedTheme` at runtime. Verify this on the
  target host.
- The dashboard title is a level 1 heading. Card titles are level 2 headings.
  The dashboard title and the Settings pairing state are polite live regions.
- Status marks are decorative and hidden from assistive technology. The state
  text always sits next to the mark.
- Text uses native text styles and wrapping. It respects the Windows text size
  setting. There are no fixed-height text blocks.
- Interactive controls use the default WinUI focus visuals. There are no custom
  focus outlines and no focus suppression.
- The app uses no custom storyboards. A `ProgressRing` is the only motion. Check
  reduced motion behavior on the host.
- Narrator has not been tested. This is a required manual check.

## Manual test checklist for the Windows host

Run this checklist before anyone calls the prototype reviewed. A build is not a
visual or accessibility test.

### Launch and frame

1. Deploy and start the app.
2. Check the title bar text `HotspotShade (simulated)` and the native window
   controls.
3. Check the persistent demo banner on every page.
4. Resize to 1000 by 720 and to 780 by 560. Check for clipping, horizontal
   scroll bars, and overlapping buttons. UWP may allow a smaller window; check a
   narrow size and record the result.
5. Minimize, restore, and close. Confirm that no process and no background task
   remain. The app has no tray icon.

### Dashboard and pairing

1. Start at Unpaired. Check the title, subtitle, cards, and Pair action.
2. Select Pair. Check the waiting spinner and the "Waiting for the code." text.
3. Wait for `482 193`. Select Copy code and paste into Notepad.
4. Select Cancel. Check the calm Unpaired state.
5. Pair again. Select Simulate a failed pairing. Check the attention state and
   Pair again.
6. Pair again. Select Simulate approval. Check Ready and Turn on.
7. Turn on. Check the loading state, then On. Check "Ping is on.", three active
   connections, and the check time.
8. Open Settings, General, and set Let ping work to Off. Turn off, then on.
   Check "Ping is off.".
9. Turn off. Check Ready and the last stop line.
10. Turn on. Open Dashboard, select Forget. Check the blocked line and Turn off
    and forget. Use it. Check the forgotten state.
11. Use Settings, Pairing, to pair again. Use Forget while the tunnel is off.
    Check the forgotten text.

### Scenarios and failure states

1. Open the Demo menu and apply each of the 14 scenarios. Check the title,
   subtitle, action, cards, and attention list for each.
2. Open Settings, Advanced, Demo lab. Apply the same scenarios from the picker.
   Check the description text.
3. Select Status unavailable. Check that the app does not claim On or Off, and
   that both cards say the status is unavailable.
4. Select Error. Check Try again. Use Check now from the menu. Check recovery.
5. Select On, stale status. Check the stale line and Check now. Check recovery.
6. Select On, source device stopped. Check the attention line.
7. Select Activity empty. Open Activity. Check the empty state and Refresh.
8. Select Status unavailable. Open Activity. Check the unavailable state.
9. Apply Ready. Turn on. In Settings, Advanced, Recent failures, select Refresh.
   Check the loading state and three rows. Select Copy report and paste it.
   Check that the report says simulated and contains example addresses.
10. Select Clear simulated failures. Check the empty state.

### Settings and reports

1. General: check Let ping work and the two ToggleSwitch states. Check the
   notifications text and the disabled Launch at login control.
2. Appearance: select System, Light, Dark. Check every page and every card after
   each change. Then open a menu and a dialog and record whether the popup
   follows the page theme.
3. Pairing: check the state, Pair, Cancel while pairing, Forget, and Turn off
   and forget.
4. Advanced: check Wi-Fi empty text, app details, Copy diagnostics, and the
   Demo lab.
5. Paste the diagnostics report. Check that it says simulated, no engine, no
   route, and no credential.
6. Check **Prototype limits** text.

### Menus and keyboard

1. Use the View menu for Dashboard, Activity, Settings, Refresh status, Check
   source device now, and the three appearance choices.
2. Use Ctrl+1, Ctrl+2, Ctrl+3, F5, and Ctrl+K.
3. Use the Demo menu for every scenario and Reset demo. Confirm the reset dialog.
4. Use the Help menu for Demo limitations and About.
5. Use the keyboard only: Tab through the sidebar, page actions, Settings
   controls, and dialogs. Check that focus is always visible and that the
   binding order is sensible.
6. Use the arrow keys in the sidebar and in the Settings `Pivot`.
7. Close a dialog with Escape. Check that focus returns to a sensible control.

### Accessibility and display

1. Start Narrator. Read the demo banner, the dashboard heading, the subtitle,
   the cards, the attention lines, and the action buttons.
2. Confirm that the dashboard title is announced when the state changes.
3. Confirm that status marks are not announced as separate controls.
4. Check the pairing code announcement. It should read the digits, not only
   "code".
5. Check the Activity list with Details on and off.
6. Check the failures table header and rows.
7. Set Windows text size to 200 percent. Check every page for clipping.
8. Turn on a high contrast theme. Check text, borders, buttons, focus, and
   status marks.
9. Turn on reduced motion. Check the progress rings and page changes.
10. Check the app in Light, Dark, and high contrast at 1000 by 720 and 780 by
    560.

### Isolation checks

1. Open Resource Monitor or Process Monitor. Confirm that the app opens no TCP
   or UDP endpoint and makes no external connection.
2. Open `Package.appxmanifest`. Confirm that it has no `Capabilities` element.
3. Confirm that no `wintun.dll`, certificate, token, or source device data is in
   the package or the repository.
4. Confirm that the copy actions contain only simulated data and documentation
   addresses.

## Security and isolation

- The package declares no capabilities. It cannot use the internet, a private
  network, location, a microphone, or a camera.
- The app has no `System.Net`, `Windows.Networking`, socket, process, service,
  or tunnel API. The test runner checks this.
- The app has no engine, no loopback call, no IPC, and no credential.
- The clipboard is used only after a person selects Copy code, Copy report, or
  Copy diagnostics.
- Local settings hold only the theme, the ping choice, and the Activity details
  choice. They hold no source device data.
- Reports use documentation addresses: `example.com`, `dns.example`,
  `192.0.2.0/24`, and `2001:db8::/32`.
- There is no fake service. The simulated state machine is local and is named
  `DemoSession`. It has no transport and no hidden real mode.

## Incomplete parity

See `PARITY.md` for the area-by-area comparison with the macOS target app.
The main gaps are:

- No engine, tunnel, routes, DNS, IPv6 policy, or automatic stop.
- No automatic pairing, status polling, or source device presence check.
- No notifications, launch at login, tray icon, or separate Settings window.
- No menu bar extra. The menu is inside the window.
- No real recent failures or diagnostics. The reports are simulated.
- No signed package, installer, updates, localization, or ARM64 build. CI
  runs the demo state and source contract checks and builds the unsigned x64
  UWP demo. It does not deploy the demo or verify its appearance.
- Narrator, high contrast, text scaling, reduced motion, and theme behavior in
  popups need the manual checks above.

## Local verification in this change

Performed on the macOS development host:

- `xmllint --noout` on every XAML, project, manifest, config, and XML file:
  pass.
- `node windows/tools/check_csharp_balance.mjs windows`: pass for 18 C# files.
- `bash windows/tools/check_static_contract.sh`: pass. It checks XML, package
  capabilities, signing material, forbidden APIs, simulated labels, pinned
  versions, assets, project includes, docs, and ASCII punctuation.
- The .NET SDK and MSBuild were not used on the macOS host.

Performed on the Windows test host:

- The pure state-model tests passed in a scratch .NET 10 harness. The harness
  omitted the source-contract checks.
- The solution built in Debug x64 with Visual Studio Community 2026 and
  `HotspotShadeSdkVersion=10.0.26100.0`. Signing and package generation were
  disabled. The scratch copy used placeholder images. It did not verify the
  final artwork.
- No UWP deployment, Narrator session, or live tunnel test ran.

The Windows host must run the test runner, the MSBuild build, the Visual Studio
deployment, and the manual checklist. Report the exact results. Do not describe
this prototype as production ready or as Windows tunnel support.

## References

Microsoft primary documentation:

- WinUI 2 overview: https://learn.microsoft.com/en-us/windows/apps/winui/winui2/
- Get started with WinUI 2 for UWP:
  https://learn.microsoft.com/en-us/windows/apps/winui/winui2/getting-started
- WinUI 2.8 release notes:
  https://learn.microsoft.com/en-us/windows/apps/winui/winui2/release-notes/winui-2.8
- XAML Islands and its limits:
  https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/xaml-islands
- UWP app lifecycle:
  https://learn.microsoft.com/en-us/windows/uwp/launch-resume/app-lifecycle
- AppContainer isolation:
  https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-for-legacy-applications-
- Menu bar guidance:
  https://learn.microsoft.com/en-us/windows/apps/design/controls/menus
- NavigationView:
  https://learn.microsoft.com/en-us/windows/apps/design/controls/navigationview
- Keyboard accelerators:
  https://learn.microsoft.com/en-us/windows/apps/design/input/keyboard-accelerators
- Accessibility:
  https://learn.microsoft.com/en-us/windows/apps/design/accessibility/accessibility
- App capability declarations:
  https://learn.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations
