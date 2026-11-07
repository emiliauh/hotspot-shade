# HotspotShade console app for Windows

This console app is a diagnostic fallback for the Windows test. The app to
test is the WinUI 2 app in `../HotspotShade.WinUI2`; see
`../../BUILD_AND_TEST_ON_PC.md`. This console app has no demo mode. Every
command talks to the real engine. A feature that the engine refuses, or that
is not built, is shown as unavailable with the reason. The broker reuses its
`LauncherHttp.cs`, `ListenerTable.cs`, and `LauncherRules.cs`.

The app has not run on Windows yet. It has been read and reviewed, and its
pure rules have hermetic checks. Treat the first run as a test.

## What it does

1. It starts `hotspotshade.exe gui --no-open --port N --token-fd H --parent-fd H`
   from its own folder. It reuses the broker engine host in
   `../HotspotShade.WinUI2.Broker/Win32EngineHost.cs`: two anonymous pipes,
   one explicit inherited-handle list, and no shell.
2. It writes a new 64-character bearer secret to the token pipe. The secret
   never appears on a command line, in the environment, or on the console.
3. It holds the parent-liveness pipe. When the app exits, for any reason, the
   pipe closes and the engine runs its own stop path, which removes its routes
   and closes its adapter. The app never terminates the engine.
4. Before every request it reads the IPv4 and IPv6 listener tables and
   requires that the launched engine alone holds the port. It then sends one
   fixed request to `127.0.0.1` with WinHTTP, no proxy, and no redirects.

## Commands

| Command | What it does | Current state |
|---|---|---|
| `status` | Shows the real engine status: tunnel, interface, elevation, source device state, ping relay, cleanup block, TTL audit failures, last stop. | Works. |
| `watch` | Shows the status every 2 seconds until a key is pressed. | Works in an interactive console. |
| `probe` | Shows the engine capability probe. | Works. |
| `diag` | Shows the diagnostics counters. They hold no address or token. | Works. |
| `failures` | Shows the recent failures. | Works. |
| `json` | Shows the full status answer. | Works. |
| `check` | Sends a typed source device address and token to the engine, which checks them with the source device. | Unavailable while the engine reports `source_proxy_unavailable`. The app asks for no token in that state. |
| `start` | Starts the source device proxy tunnel with a typed token, or with the target that the engine already holds. | Unavailable while the guard is closed, and unavailable in a console that is not elevated. |
| `stop` | Stops the tunnel. | Works. With no tunnel it reports done. |
| `quit` | Stops the tunnel, stops the engine, and exits. | Works. |

Not offered at all: pairing, forget, direct mode, SOCKS5 mode, notifications,
launch at login, and a tray icon. The Windows engine has no pairing backend,
and the other features are not built for Windows.

## Run it

1. Build with the .NET 8 SDK or later on Windows:
   `dotnet build windows/src/HotspotShade.WinUI2.TestLauncher/HotspotShade.WinUI2.TestLauncher.csproj -c Release`.
   The output is framework dependent. The PC needs the .NET 8 runtime
   (`Microsoft.NETCore.App` 8.x).
2. Build the engine on Windows: `cargo build --release --locked --manifest-path rust/Cargo.toml`.
3. As an administrator, create a folder inside Program Files, for example
   `C:\Program Files\HotspotShade`. Copy the launcher build output and
   `hotspotshade.exe` into it. For a tunnel start, also copy `wintun.dll`
   (x64, from the official Wintun release) into the same folder. The project
   does not bundle it.
4. Open a console and run `HotspotShade.WinUI2.TestLauncher.exe`. A standard
   console is enough for status. Use an elevated console only for a tunnel
   start. An elevated launch from a folder outside Program Files is refused,
   because the engine loads `wintun.dll` from its own folder.

## Limits

- The listener check is repeated before every request, but it is not atomic.
  The engine listener also uses `SO_EXCLUSIVEADDRUSE`, so another socket cannot
  share the port.
- The app does not check the folder access list. Use a folder that only
  administrators can write.
- A job object that kills its processes on close can stop the engine during
  cleanup. Do not run the app under such a job.
- A manual token typed here crosses the hotspot link in cleartext, like every
  v1 source device proxy token.
