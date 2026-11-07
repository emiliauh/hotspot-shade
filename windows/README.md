# HotspotShade for Windows (WinUI 2)

> **Status: release candidate for the first real test. It is not production ready.**
>
> The WinUI 2 app is wired to the real engine. It has no demo mode and no
> simulated data. It has not been built or run on Windows yet: the first build
> and the first live test happen on the owner's PC with
> [BUILD_AND_TEST_ON_PC.md](BUILD_AND_TEST_ON_PC.md). Features that are not
> built for Windows are not offered and are listed in
> [Not available on Windows](#not-available-on-windows).

The macOS arm64 tunnel remains the only verified tunnel. The root platform
status is in [../README.md](../README.md). The UI translation status is in
[PARITY.md](PARITY.md).

## Architecture

```text
UWP window (AppContainer, standard user)
  |  in-process app service "hotspotshade.engine", fixed operations only
  v
Broker\HotspotShade.WinUI2.Broker.exe (full trust, standard user, medium integrity)
  |-- user engine:  Engine\hotspotshade.exe gui --token-fd --parent-fd --handoff-fd
  |                 started at app open, never elevated
  |
  |   Turn on only: ShellExecuteEx "runas" -> one UAC prompt
  v
Elevate\HotspotShade.WinUI2.Elevate.exe (administrator, exits after the start)
  |-- elevated engine: Engine\hotspotshade.exe gui --token-fd --parent-fd --credentials-fd
                       loads Engine\wintun.dll, owns the adapter and the routes
```

### Window

`src/HotspotShade.WinUI2` is a UWP app with WinUI 2.8.7 controls. It runs in
an AppContainer and cannot reach the loopback engine, so it never holds a
bearer secret. At launch it starts the packaged broker with
`FullTrustProcessLauncher`, which asks for no administrator approval. The
broker opens the app service; the window accepts the connection only when
`CallerPackageFamilyName` is its own package family. The window sends its
process id in `hello`, then fixed operations: `status`, `pair_status`, `pair`,
`pair_cancel`, `forget`, `probe`, `logs`, `diagnostics`, `failures`,
`turn_on`, and `turn_off` (`BrokerProtocol.cs`). Every value is a short
string; unknown operations and fields are refused.

All window logic is in the Core library (`src/HotspotShade.WinUI2.Core/App`),
so it is tested without Windows:

- `JsonValue` is a bounded JSON reader (size, depth, duplicate keys).
- `EngineSnapshot.cs` reads `/api/status`, `/api/phone/pair`, `/api/logs`, and
  `/api/failures` in the shape that the Rust engine writes.
- `DashboardPresenter` is a port of the macOS derive table, screen
  presentation, and card content (`AppModel.derive`, `ScreenPresentation`,
  `DashboardContent`). It computes every title, subtitle, action, card,
  attention line, and the enablement and reason of Turn on, Turn off, Pair,
  Cancel, and Forget.
- `AppSession` holds the window state: freshness (stale after 3 seconds,
  unavailable after 10), pairing polls, Forget, Turn on, Turn off, Turn off and
  forget, Activity, Recent failures, and Copy diagnostics. `WindowState` is
  the bindable view of one session.

### Broker

`src/HotspotShade.WinUI2.Broker` is a full-trust `WinExe` in the package. It
requires package identity and one instance per session, accepts no
command-line argument, and lives as long as the window process. A suspended
window that closes the app-service connection does not stop a tunnel; on resume
the window starts the broker again, and the second copy only signals the first
one to reconnect. When the window process ends, the broker stops the elevated
tunnel, closes every parent-liveness pipe, and waits for the engines to exit.
It never terminates an engine.

The broker starts the user engine with `Win32EngineHost`: three anonymous
pipes, one explicit inherited-handle list, no shell, and the bearer secret on
the token pipe only. Before every request it reads the IPv4 and IPv6 listener
tables and sends only when the launched engine alone holds the port; then it
sends one fixed request to `127.0.0.1` with WinHTTP, no proxy, and no
redirects (`LauncherHttp.cs` and `ListenerTable.cs`, shared with the console
launcher). It removes the log copy from status answers and trims the logs so
each reply fits the app-service message budget.

### Turn on, the only elevation

Turn on is the only operation that asks Windows for administrator approval
(`ElevationPolicy`). The broker:

1. Checks that the user engine is paired and has no tunnel, that the starter,
   the engine, and `wintun.dll` are in the package, and that the package is
   installed in a WindowsApps package store (`Program Files\WindowsApps` or
   `X:\WindowsApps` on another volume).
2. Creates the token pipe and the parent-liveness pipe (not inheritable) and a
   one-instance named pipe with a random 128-bit name, `PIPE_REJECT_REMOTE_CLIENTS`,
   and an access list that admits only elevated Administrators and SYSTEM and
   limits the owner to READ_CONTROL (OWNER RIGHTS), so a same-user process
   cannot rewrite it.
3. Starts `Elevate\HotspotShade.WinUI2.Elevate.exe <token>` with
   `ShellExecuteEx` and the `runas` verb, on its own STA thread. Windows
   shows one UAC prompt, owned by the app window.
4. Accepts the pipe client only when its process id is the one that
   `ShellExecuteEx` returned.
5. Asks the user engine for the pairing handoff (`POST /api/pairing/handoff`).
   The user engine writes one frame into the handoff pipe. The broker never
   reads it.
6. Sends the three pipe handle values and the port.

The starter is published with NativeAOT. It has no .NET host, so no
`DOTNET_STARTUP_HOOKS`, profiler, or `DOTNET_ROOT` value that a medium
process writes into the user environment can load code into the elevated
process. It checks elevation with the token's `TokenElevation` value,
refuses to run unelevated, opens the pipe with
identification-level impersonation only, checks that the pipe server is the
packaged broker by image path, duplicates the three handles into itself,
checks that each one is a pipe, and starts the packaged engine with a fixed
argument list, `--credentials-fd`, an explicit inherited-handle list, and a
fixed environment block (`SystemRoot`, `windir`, `PATH`, `TEMP`, and a few
system values from `GetWindowsDirectoryW`), never the user environment. It
answers with the engine process id and exits. It never reads the secret or
the pairing frame. The broker opens the engine process, checks its image path,
waits for its listener, writes a new bearer secret, keeps the parent-liveness
write end, and sends `POST /api/start` with `mode` `phone` and the Let ping
work choice.

This mirrors the macOS credential handoff: the user engine passes the pairing
on a private inherited descriptor, the privileged side passes the descriptor
and never reads it, and the root (here, elevated) engine imports it.

### Turn off and quit

Turn off sends `POST /api/stop` to the elevated engine. The stop is confirmed
only when the engine then reports `running` false with a normal service state
and no cleanup block. The broker then closes the parent-liveness pipe, waits
for the engine to exit, and returns to the user engine, which kept the
pairing. Any other outcome keeps the elevated engine as the status source and
shows "HotspotShade could not confirm that the tunnel stopped", with Turn off
available again and Turn on, Pair, and Forget disabled. An elevated engine
that exits without a stop that the broker asked for is a final mark: the app
says the routes are not verified and keeps Turn on disabled until HotspotShade
restarts. Quit stops the tunnel the same way.

### Security limits

- The bearer secret never appears on a command line, in the environment, in an
  app-service message, or in a log. The source device token never leaves the
  engines.
- The listener check is repeated before every request but is not atomic. The
  engine listener uses `SO_EXCLUSIVEADDRUSE`.
- A process that runs as the same user at medium integrity can already act as
  that user. The design does not defend the broker against such a process.
- Approval with another account is refused, because the starter must open the
  signed-in broker to duplicate its handles.
- The v1 source device token crosses the hotspot link in cleartext.
- No part of this design has run on Windows. It needs the owner's PC test and
  an independent review on a Windows host.

## Engine dependency

The app programs against the engine HTTP API that macOS and Linux use:
`/api/status`, `/api/phone/pair`, `/api/phone/pair/cancel`,
`/api/phone/forget`, `/api/phone/probe`, `/api/start`, `/api/stop`,
`/api/diagnostics`, `/api/failures`, `/api/logs`, and
`/api/pairing/handoff`. The Windows engine implements all of them with the
macOS and Linux JSON (2026-11-06). None of it has run on a Windows host.

Launch flags:

- `gui --token-fd N --parent-fd N [--port N] [--port-file PATH] [--wintun PATH]`
  starts the real engine. Both handles are inherited anonymous pipe read
  ends.
- `--handoff-fd N` gives the user engine the write end of the pairing handoff
  pipe. `--credentials-fd N` gives the elevated engine the read end. One
  engine accepts only one of the two. Each handle must be a pipe that is not
  the token, parent, or a standard handle, and not the same pipe object as
  the token or parent handle. The engine clears its inherit flag at launch.
  The elevated engine reads the newest complete frame that is already queued
  before it binds its listener. An empty or malformed pipe ends the launch
  with "The pairing handoff is not valid."

Pairing and handoff answers:

| Request | Answer |
|---|---|
| `POST /api/phone/pair` with `{}` | Starts pairing with the discovered hotspot gateway; the client never names a host. Returns the pairing view. A second start returns HTTP 400 "A pairing is already running." |
| `GET /api/phone/pair` | `state` (`idle`, `connecting`, `confirm`, `paired`, `failed`), `code` (the code to compare during `confirm`, else null), `host`, `port`, `error` (fixed text or null). |
| `POST /api/phone/pair/cancel` with `{}` | Cancels a pairing in progress and returns the view. |
| `POST /api/phone/forget` with `{}` | Clears the pairing, sends up to three best-effort FORGET requests, probes once, and returns `{"ok":true}`. HTTP 409 "Turn off the tunnel first." while a tunnel runs or a start is in progress. |
| `POST /api/pairing/handoff` with `{}` | User engine only. Writes one frame to the `--handoff-fd` pipe and returns `{"ok":true}`. HTTP 409 with `tunnel_running`, `handoff_unavailable` (no pipe, or the write did not finish in 2 seconds), `handoff_busy` (an earlier write is still blocked), or `not_paired`. |

Status fields: `paired`, `phone_host`, `phone_port`, `api` (1), `forget`
(`state` is `none`, `pending`, `confirmed`, or `not_delivered`, plus
`attempts`), `last_stop`, `last_stop_message`, and `phone` with `state`,
`message`, `port_changed`, `connections`, `checked_at`, and
`trusted_by_source`.

`POST /api/start` with `{"mode":"phone","options":{}}` uses the last typed
target that passed `POST /api/phone/check`, or else the paired credentials. A
new pairing or a forget clears the typed target. Only `phone` mode exists on
Windows.

The token gate: before each use of the source device token, and about every 2
seconds during a run, the engine checks that the source device is the default
gateway of the physical Ethernet or Wi-Fi adapter that the tunnel pins to. A
VPN, a split default route, a virtual adapter, or an unclear read fails the
check. A start or check then fails with HTTP 400 "The source device must be
the default gateway of a physical hotspot adapter. Turn off any VPN, connect
to the source device hotspot, then try again." A failure during a run turns
the tunnel off with `last_stop.reason` `hotspot_lost`. The check does not
prove that the gateway is the person's source device, and the v1 token
crosses the hotspot link in cleartext.

The C# source-contract check in `windows/tests` now requires the gate
(`require_token_destination_proof`, `observe_token_destination`, and the
fixed `TOKEN_DESTINATION_REFUSED` refusal) instead of the old closed guard.

### Automatic stop

The engine turns the tunnel off on the first refused gateway check during a
run, with `last_stop.reason` `hotspot_lost`, and after 90 seconds of sustained
source device silence, with `last_stop.reason` `source_device_gone` (see
Engine dependency and `rust/src/autostop.rs`). The elevated engine then
reports `running` false with a normal state. The broker treats that as a
confirmed stop: it closes the elevated engine, returns to the user engine, and
keeps the elevated engine's `last_stop` and `last_stop_message` in the status
answers, so the Connection card shows "Last stop: The hotspot turned off, so
HotspotShade turned the tunnel off." or "Last stop: The source device stopped
answering, so HotspotShade turned the tunnel off." and Turn on works again.
This path has not run on Windows.

## Not available on Windows

These features are not built for Windows. The app does not offer them and does
not simulate them. Settings, General, and the Help dialog name the four that
a person may look for: notifications, launch at login, a notification area
icon, and direct mode.

| Feature | Why |
|---|---|
| Direct mode without the source device app | Gated closed in the engine. The macOS app offers the proxy only as well. |
| Notifications | Not implemented. |
| Launch at login | Not implemented. |
| Notification area icon | UWP has no tray icon. |
| Wi-Fi advice | The window does not read the Wi-Fi band or signal. |
| Automatic pairing at launch | The person presses Pair. |
| Turn on from a Visual Studio loose-file deployment | Its folder is user-writable, so an elevated engine must not load `wintun.dll` from it. |

## Layout

```text
windows/
  BUILD_AND_TEST_ON_PC.md        prerequisites, build, install, live test, cleanup
  HotspotShade.WinUI2.sln
  PARITY.md
  SERVICE_BOUNDARY.md            the separate service foundation, not used by the app
  src/
    HotspotShade.WinUI2/         UWP window: App, MainPage, MainViewModel,
                                 BrokerConnection, WindowHandle, Rows
    HotspotShade.WinUI2.Core/    netstandard2.0 window core: App/ state,
                                 presenter, JSON, and protocols; Engine/
                                 launch rules, older broker and service
                                 foundations, and the release-probe report
    HotspotShade.WinUI2.Broker/  full-trust broker: app service, user engine,
                                 Turn on starter, Turn off, and quit
    HotspotShade.WinUI2.Elevate/ NativeAOT elevated starter; runs once and
                                 exits after it starts the elevated engine
    HotspotShade.WinUI2.ReleaseProbe/  read-only x64 probe of version and
                                 probe output
    HotspotShade.WinUI2.Service/ unapproved SCM service executable; not
                                 installed and not wired to the app
    HotspotShade.WinUI2.ServiceHost/  unapproved named-pipe service host
                                 foundation; not wired to the app
    HotspotShade.WinUI2.TestLauncher/  console diagnostic fallback that talks
                                 to the real engine
  tests/
    HotspotShade.WinUI2.Core.Tests/  hermetic checks for the window core, the
                                 broker rules, and the release probe
    HotspotShade.WinUI2.ServiceHost.Tests/  hermetic checks for the service
                                 host foundation
  tools/
    stage_payload.ps1            builds windows/out/payload for the package
    check_static_contract.sh     checks the package contract, docs, and ASCII
    check_csharp_balance.mjs     checks C# delimiters
```

The UWP project packages `windows/out/payload` (`Broker\`, `Elevate\`,
`Engine\hotspotshade.exe`, `Engine\wintun.dll`) and fails the build with a
clear error when the broker, the starter, or the engine is missing. The
repository does not bundle `wintun.dll`; `stage_payload.ps1 -Wintun PATH`
checks its WireGuard signature and x64 machine type before it copies it. CI
compiles the app with `HotspotShadeSkipPayloadCheck=true` because it does not
stage the payload; the PC build stages and checks the payload. The check stays
on by default.

The older `Engine/EngineBrokerService.cs`, `EngineBoundary`, `EngineSession`,
and `Engine/Service/` code is the earlier version 1 broker contract and the
service foundation. The app does not use them. Their hermetic tests still run.

## Dependencies

| Dependency | Version | Reason |
|---|---|---|
| `Microsoft.UI.Xaml` | 2.8.7 | WinUI 2 controls: `MenuBar`, `NavigationView`, `ProgressBar`, `ProgressRing`. |
| `Microsoft.NETCore.UniversalWindowsPlatform` | 6.2.15 | UWP runtime and build support. |
| Windows Desktop Extensions for the UWP | the target SDK | `FullTrustProcessLauncher`. |
| .NET SDK | 8.0.100 or later (8.0.x) | Builds the Core library, the broker, the starter, and the test runner. |
| Windows 11 SDK | 10.0.22621.0 | UWP target platform. |
| Visual Studio 2022 | 17.10 or later | UWP workload, XAML compiler, packaging. |

The package versions are exact pins. The broker and the starter use the Windows
SDK projection and kernel32, advapi32, shell32, winhttp, and iphlpapi through
P/Invoke, loaded from System32 only. They add no NuGet package. No NuGet lock
file is committed because this Mac cannot restore the UWP graph; generate and
review one on the Windows build PC.

## Build and test

The exact steps are in [BUILD_AND_TEST_ON_PC.md](BUILD_AND_TEST_ON_PC.md). In
short, on Windows:

| Command | Expected result |
|---|---|
| `dotnet run --project windows/tests/HotspotShade.WinUI2.Core.Tests/HotspotShade.WinUI2.Core.Tests.csproj -c Release` | Every check passes, then `ALL WINUI2 PROTOTYPE CHECKS PASSED` and exit 0. |
| `powershell -ExecutionPolicy Bypass -File windows\tools\stage_payload.ps1 -Wintun PATH` | Builds the engine, publishes the broker and the starter, fills `windows\out\payload`. |
| `msbuild windows\src\HotspotShade.WinUI2\HotspotShade.WinUI2.csproj /restore /p:Configuration=Release /p:Platform=x64 ...` | Builds and signs the sideload package with your local test certificate. |
| `sh windows/tools/check_static_contract.sh` | `STATIC CONTRACT CHECK PASSED`. Needs `sh` and `xmllint`. |
| `node windows/tools/check_csharp_balance.mjs windows` | `C# delimiter check passed`. |

On 2026-11-06 the Core test runner makes 250 `Check` calls and the
ServiceHost test runner makes 250. `check_static_contract.sh` reports 15 XML
files, and the C# delimiter check reports 125 C# files. These are source
counts. No Windows host has run the checks.

`dotnet build` cannot build the UWP project. Use MSBuild from a Developer
Command Prompt or Developer PowerShell for VS 2022.

## What the UI does

- Native title bar and window controls. A WinUI 2 `MenuBar` with HotspotShade
  (Turn on, Turn off, Pair, Cancel pairing, Settings, Quit), View (sections,
  Refresh status F5, Check source device now Ctrl+K, appearance), and Help.
- A `NavigationView` with Dashboard and Activity and the built-in Settings item.
  Ctrl+1, Ctrl+2, and Ctrl+3 select them.
- Dashboard: status dot, title (a polite live region with the full status as
  its accessible name), subtitle, checked time, one primary action, one
  secondary action, the line "Windows asks for administrator approval when you
  turn on the tunnel." before Turn on, the
  Source device and Connection cards, and the Needs attention list with inline
  actions.
- Pairing replaces the cards: a waiting ring, then the six digits in two groups
  (read digit by digit by Narrator), three steps, Copy code, and Cancel (Esc).
- Activity: the engine log, newest first, with a Details toggle for the level
  and the sequence number, Refresh, and loading, empty, and unavailable states.
  It refreshes every 2 seconds while visible.
- Settings `Pivot`: General (Let ping work, stored locally and sent on the next
  Turn on; Appearance; the not-available list), Pairing (state, Pair, Cancel,
  Forget or Turn off and forget with a confirmation), and Advanced (Recent
  failures with Refresh and Copy report, App details with the engine role and
  Copy diagnostics, and the read-only destination privacy card).
- The status polls every second while the window is visible and every 5
  seconds while it is hidden.
- Light, dark, and high contrast come from theme dictionaries. The appearance
  choice changes the page theme at once.

## Manual test checklist

Use section 7 of BUILD_AND_TEST_ON_PC.md for the live test. Also check:

1. No UAC prompt at launch, at pairing, at Forget, or in Settings.
2. Exactly one UAC prompt at Turn on; Cancel on it shows "The administrator
   prompt was cancelled, so the tunnel did not start." and Try again.
3. Keyboard only: Tab reaches every control in order; Esc cancels pairing;
   the menu accelerators work.
4. Narrator reads the status title, the cards, the pairing code, and the
   attention lines.
5. Light, dark, and high contrast; 200 percent text scale; a narrow window.
6. Minimize the window for a minute while On, then restore it: the tunnel stays
   on and the status comes back.

## Release probe (read-only x64 evidence)

`src/HotspotShade.WinUI2.ReleaseProbe` is a separate console tool for a Windows
x64 test PC. It runs only two engine commands, `--version` and `probe`,
validates the answer, and writes a redacted report. It starts no tunnel, creates
no adapter or route, and uses no credential.

The shared parser, policy, and report writer are in
`src/HotspotShade.WinUI2.Core/Engine/Release/`. The core test runner covers them.
The console tool is not in the solution or the app package. CI compiles it in
Release, but publishes no Windows binary.

Run it from the repository root on the Windows test PC:

```text
dotnet run --project windows/src/HotspotShade.WinUI2.ReleaseProbe/HotspotShade.WinUI2.ReleaseProbe.csproj -c Release -- --engine C:\path\to\hotspotshade.exe --out release-probe.json
```

- `--engine PATH` is required when the engine is not next to the tool. It must
  be an absolute path that ends in `hotspotshade.exe`. A relative path, a dot
  segment, or another file name is refused before a process starts.
- `--json` prints the report as JSON instead of text.
- `--out PATH` also writes the JSON report to that path.
- Exit codes: 0 pass, 2 warning, 1 failure, 3 usage, 4 harness error.

The tool targets `net8.0`. The test PC needs the .NET 8 runtime. A
self-contained win-x64 publish needs the win-x64 runtime pack on the publishing
host. The probe also needs a real `hotspotshade.exe`. CI publishes no Windows
binary, so build one with the engine instructions in the root `README.md`.

The tool checks:

1. The host is Windows and 64-bit. A non-Windows host is a warning. A 32-bit
   operating system is a failure. A process architecture other than x64 is a
   warning.
2. The engine file exists, has a non-zero length, and has a SHA-256. The report
   holds the file name, length, and hash, not the full path.
3. `--version` prints exactly one `hotspotshade <version>` line.
4. `probe` prints the administrator value, one default interface with a
   positive index, the UDP TTL, the audit count, and the fixed privilege line.
5. The UDP TTL is exactly 65 and the audit count is 0.

The TTL and audit checks are the first real evidence for the Windows
normalization path. A pass does not prove an adapter, a route, a tunnel, DNS,
IPv6 policy, source device pairing, or a live hotspot. Both Windows start modes
still fail closed in the engine.

The tool runs each command with no shell, removes inherited `HOTSPOTSHADE_*`
variables, uses a fixed argument, and bounds the answer. It refuses any other
command, so it cannot run `tun`, `gui`, a source device probe, or a token
prompt. It kills only the read-only probe command when that command exceeds its
time limit.

The tool runs the file you name with your own rights. It does not elevate and it
passes no credential, so name a file you trust. A malformed or hostile engine
file is outside this tool's model.

The report format is version 1. `schema` is
`hotspotshade.windows.release-probe/1`. The JSON writer is deterministic and
ASCII only, refuses no value silently, and never writes an engine error stream
to the report. A missing hash or version is an empty string in JSON and `none`
or `unknown` in text. A file that is missing, an answer that is malformed, a
non-zero exit, a timeout, or an answer above 16384 characters is a failure.

## Service boundary foundation

The separate service boundary foundation, its ServiceHost transport, and the
unapproved SCM service project are described in
[SERVICE_BOUNDARY.md](SERVICE_BOUNDARY.md) and the project READMEs. They are
not installed, not in the app package, and not used by the window or the
broker.

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
