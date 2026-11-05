# HotspotShade for Linux

This directory holds the Linux target app. The app uses Electron 45.2.3.

The app has two backends. With no engine setting it uses the in-memory demo
backend, and every view says that the data is simulated. With an engine setting
it starts the real HotspotShade Rust engine and reads the engine status through
a protected main-process boundary. A packaged build starts the fixed engine
through a pkexec helper.

The Linux tunnel start path exists in the Rust engine and has a VM test. The
Electron app starts the packaged engine in source device proxy mode. Direct
mode is not implemented in the app. A live hotspot and source device test is
still open.

The app runs as the desktop user. The helper runs only the packaged engine. The
window, the renderer, and the engine client never run as root.

## What the app contains

- One main window with native frame, title bar, window controls, and menu bar.
- A separate Settings window with General, Pairing, and Advanced sections. The
  page inside hides the sidebar and shows the three sections.
- Dashboard: one status header, one primary action, source device and
  connection cards, an attention list, and a pairing panel.
- Activity: an event list from the selected backend with a Details toggle,
  refresh, and loading, empty, and error states.
- Settings General: Launch at login, Let ping work, Appearance, and
  Notifications.
- Settings Pairing: Pair, Cancel, Forget, Turn off and forget, and blocked
  Forget.
- Settings Advanced: Recent failures, Wi-Fi advice, app details, Copy
  diagnostics, limitations, and demo scenarios.
- Desktop notifications for automatic stop reasons and pairing results.
- A tray item with Start, Stop, Open, and Quit when the desktop provides a
  status notifier.
- Launch at login through one XDG autostart `.desktop` file.
- Light, dark, and high contrast appearance. System follows the operating
  system, including the high contrast preference.
- Keyboard access, visible focus, landmarks, live status regions, reduced
  motion, forced color support, and screen-reader names.
- Native menus for Dashboard, Activity, Settings, Refresh, Check source device,
  appearance, Window, and Help.

## Backends

### Demo backend, the default

The app selects the demo backend when no engine is configured, or when
`--demo` is present. The demo backend keeps all state in memory. Every view that
shows demo data says that the data is simulated. The demo backend cannot start
a tunnel. It sends no desktop notification.

### Engine backend

The app selects the engine backend when `--engine <absolute path>` or the
`HOTSPOTSHADE_ENGINE` environment variable names an absolute path to the
HotspotShade binary. The app never searches PATH. A relative name is refused
with a plain error.

To let the app start the engine with the engine's own demo backend, set
`HOTSPOTSHADE_ENGINE_DEMO=1` or pass `--engine-demo`. The app passes `--demo` to
the engine. The app then labels the data as an engine demo. This mode needs no
root, route, TUN device, or source device.

The engine backend reads the real status, failure record, diagnostics, pairing
state, and activity from the engine. The Start, Stop, Pair, Cancel, and Forget
controls call the engine routes. The app shows the engine `last_stop_message`
when the engine sends one.

The main process starts a development engine with the same arguments as the
macOS app:

```
gui --no-open --port 0 --port-file <private-file> \
    --token-fd 3 --parent-fd 4 [--demo]
```

The per-launch bearer secret travels on descriptor 3. Descriptor 4 stays open
as the parent-liveness channel. The engine stops when Electron closes it. The
app learns the loopback port from a private temporary file, removes that file
after the stop, and never sends the secret or the port file to the page.

The main process can call only these fixed operations:

| Operation | Method and path |
|---|---|
| Status | `GET /api/status` |
| Failure record | `GET /api/failures` |
| Diagnostics | `GET /api/diagnostics` |
| Pairing state | `GET /api/phone/pair` |
| Pair, Cancel, Forget, Probe | `POST /api/phone/pair`, `/cancel`, `/forget`, `/probe` |
| Start and Stop | `POST /api/start`, `POST /api/stop` |
| Activity | `GET /api/logs?since=N` |

The Start body is fixed: `{"mode":"phone","options":{"experimental_icmp":<bool>}}`.
No caller can name a path, URL, host, command, or request body.

On close the app sends SIGTERM and waits. If the engine does not stop, the app
closes the parent-liveness descriptor and waits again. A forced stop is the last
step. The app never restarts the engine after a crash. A crash becomes a plain
error in the page. The status becomes stale after 3 seconds and unavailable
after 10 seconds.

## Packaged engine start with pkexec

A packaged app uses the fixed helper:

- Program: `/usr/bin/pkexec`
- Helper: `/usr/lib/hotspotshade/hotspotshade-helper`
- Engine: `/opt/hotspotshade/resources/engine/hotspotshade`
- Polkit action: `local.hotspotshade.tunnel`

The app calls `pkexec` with the helper path and no other argument. The helper
accepts no argument. A packaged launch asks for authorization before the engine
starts. It reads one short request from stdin:

```
HS1
<64 hex character per-launch secret>
```

The helper starts the engine as root with this fixed argument list:

```
gui --no-open --port 0 --port-file <root temporary file> \
    --token-fd 3 --parent-fd 4
```

The secret goes to the engine on descriptor 3. The helper holds descriptor 4
until its stdin closes. A closed stdin stops the engine. This is the stop path
and the parent-loss path.

The helper prints only `HS_PORT <number>` on stdout after the engine reports
its port. The app reads that line and then uses the normal loopback HTTP client.
The app cannot signal a root helper, so the stop path closes stdin and waits.
The helper sends SIGTERM to the engine after 8 seconds and SIGKILL after 3 more
seconds if the engine does not stop.

The helper sets `HOME` to `/var/lib/hotspotshade`. The engine keeps the target
identity key there with root-only access. The app never reads or copies that
key. The package creates the directory with mode 0700.

The polkit action uses `auth_admin_keep` for an active session. The
`org.freedesktop.policykit.exec.path` annotation names the fixed helper path.
The helper checks `PKEXEC_UID`, refuses arguments, and checks that the engine
file is owned by root and is not writable by another user. A missing pkexec
path, helper, or engine becomes a plain error before a process starts.

The app refuses to start when `getuid()` is 0. Start the window as your desktop
user. The helper is the only root process.

## Tray, notifications, and launch at login

### Tray item

The app creates an Electron `Tray` item with the local app icon. On a desktop
with a status notifier host, Electron uses StatusNotifierItem. The menu has one
disabled status row and these actions:

- Start tunnel
- Stop tunnel
- Open HotspotShade
- Quit HotspotShade

Start uses the saved ping choice. Stop calls the engine stop route. The status
row follows the real engine status. A desktop without a status notifier gets
the plain fallback: the tray item is absent, the app continues, and closing the
window quits the app. On a desktop with a tray item, closing the window hides
it and the tray item keeps the app alive. Quit from the tray stops the engine.

### Notifications

The main process polls the backend every 2 seconds. It sends a desktop
notification for:

- A hotspot loss stop.
- A source device loss stop.
- A tunnel error stop when the app is not focused.
- A completed pairing.
- A failed pairing.
- An engine that stopped after three failed status polls.

The app never notifies for a user stop. Each message kind is limited to one
message in 60 seconds. The notification body comes from the engine stop message
when one exists. It holds no address, host, token, key, or traffic. A click
opens the main window. The Settings toggle turns notifications on or off. The
choice is stored in `settings.json` under the app user data directory. Demo
data never sends a notification.

### Launch at login

The Settings toggle in a packaged app writes or removes one file:

```
${XDG_CONFIG_HOME:-$HOME/.config}/autostart/hotspotshade.desktop
```

The file starts the packaged app as the desktop user, not the helper. The app
writes a temporary file in the same directory, syncs it, and renames it over the
target. The remove path is one unlink. A missing file reports off. A failed
write reports a plain error. The test override `HS_AUTOSTART_DIR` points the
writer at a temporary directory.

## Settings window

The Settings item in the File menu and the Settings sidebar item open a second
BrowserWindow. It loads the same local page with
`--hs-window-kind=settings`. The preload reports `windowKind: "settings"`. The
page hides the sidebar, shows the Settings view, and keeps the three tabs.

The Settings window uses the same sandbox, context isolation, session policy,
and fixed IPC. The main process accepts IPC from the main window and the
Settings window only, with the exact page URL and the main frame. The window
has no menu bar of its own.

## Run

Use a Linux host with Node.js 22 or later and a desktop session.

```sh
cd linux
npm ci
npm start
```

With no engine setting, the app uses the labeled demo backend and writes only
its Electron profile, its `settings.json`, and the local theme and ping choices.
It does not need root. Do not run it with `sudo`.

To use the real engine:

```sh
HOTSPOTSHADE_ENGINE=/absolute/path/to/hotspotshade npm start
```

To use the engine in its demo mode without root:

```sh
HOTSPOTSHADE_ENGINE=/absolute/path/to/hotspotshade \
HOTSPOTSHADE_ENGINE_DEMO=1 npm start
```

The same settings work as arguments:

```sh
npm start -- --engine /absolute/path/to/hotspotshade --engine-demo
```

`--demo` forces the in-memory demo backend and wins over an engine setting.

For a headless test host, use Xvfb:

```sh
xvfb-run -a npm start
```

## Test

The Node tests do not need Electron and do not open a window.

```sh
npm test
```

The suite covers the demo backend, the fixed IPC allowlist, the page model, the
engine setting, the HTTP boundary with a fake engine server, the process
lifecycle with a fake engine script, the settings store, the XDG autostart file,
the notification policy, the tray menu, the status monitor, the privileged
client contract with a fake helper, the in-tree accessibility rules, and the
packaging files.

The Electron checks use a temporary profile and a real sandbox. Run them with a
display or Xvfb.

```sh
xvfb-run -a npm run test:smoke
xvfb-run -a npm run test:settings-window
xvfb-run -a npm run test:a11y
```

`test:a11y` is an in-tree axe-style check, not axe-core. It checks names,
landmarks, heading order, labels, ARIA states, target size, scroll regions,
color contrast, and keyboard focus on the dashboard, pairing panel, activity
view, the three Settings sections, the dark theme, the high contrast token
layer, the Settings window layout, and eight keyboard focus stops.

The engine smoke test needs a built `hotspotshade` binary. It starts the real
engine in demo mode and checks the real status, pairing, start, stop, failures,
and diagnostics paths through the Electron app.

```sh
HOTSPOTSHADE_ENGINE=/absolute/path/to/hotspotshade \
HOTSPOTSHADE_ENGINE_DEMO=1 \
xvfb-run -a npm run test:engine-smoke
```

The main entry point test loads `src/main/main.js`, selects the engine backend,
waits for the page, and quits through the normal app quit path. It checks that
the engine process and its temporary directory are gone. It writes a report to
`/tmp/hotspotshade-main-engine-report.json`.

```sh
HOTSPOTSHADE_ENGINE=/absolute/path/to/hotspotshade \
HOTSPOTSHADE_ENGINE_DEMO=1 \
xvfb-run -a npm run test:main-engine
```

The memory and responsiveness checks use the same page and the same wait:

```sh
xvfb-run -a npm run measure:memory
xvfb-run -a npm run measure:responsiveness
```

On a host without a display, use `scripts/test-container.sh` with `smoke`,
`a11y`, `memory`, or `responsiveness`. The image does not include an engine
binary, so the engine smoke test runs from a host or virtual machine that has
the binary.

No test changes a route, creates a TUN device, opens a listener outside the
engine loopback port, reads a source device credential, or writes the user
autostart directory.

## Packaging

The package script builds one unsigned Debian package for one architecture.
Run it on a Linux host with Node.js 22 or later, Rust, and `dpkg-deb` for the
matching architecture.

```sh
cd linux
npm ci
ARCH=x64 npm run package:deb
# or: ARCH=arm64 npm run package:deb
```

The output is `linux/build/hotspotshade_<version>_<arch>.deb`. The script builds
the Rust engine and the pkexec helper with their committed lockfiles, builds the
Electron app with `@electron/packager`, and writes this layout:

```
/opt/hotspotshade/HotspotShade
/opt/hotspotshade/resources/engine/hotspotshade
/usr/lib/hotspotshade/hotspotshade-helper
/usr/bin/hotspotshade
/usr/share/applications/hotspotshade.desktop
/usr/share/pixmaps/hotspotshade.png
/usr/share/polkit-1/actions/local.hotspotshade.tunnel.policy
/var/lib/hotspotshade           (created by postinst, mode 0700)
```

The package depends on the GTK and NSS runtime libraries, `libgbm1`, `libxss1`,
`xdg-utils`, and `pkexec`. The package is unsigned. Install it with your package
manager and your own trust decision:

```sh
sudo apt install ./hotspotshade_0.1.0_amd64.deb
```

Remove it with:

```sh
sudo apt remove hotspotshade
```

The remove path does not delete your user settings or your autostart entry. Turn
off Launch at login first if you do not want the entry to remain.

## Security model

The window uses these Electron settings:

- `contextIsolation: true`
- `sandbox: true`
- `nodeIntegration: false`
- `nodeIntegrationInWorker: false`
- `nodeIntegrationInSubFrames: false`
- `webviewTag: false`
- `devTools: false`
- `webSecurity: true`
- `allowRunningInsecureContent: false`
- `navigateOnDragDrop: false`

The page has this Content Security Policy:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'none'; media-src 'none'; object-src 'none';
frame-src 'none'; child-src 'none'; worker-src 'none'; base-uri 'none';
form-action 'none'
```

The main process allows only files inside `src/renderer` with a short extension
list. It denies every other request. It denies all permission requests, device
permissions, display capture, webviews, downloads, new windows, redirects, and
external navigation.

The sandboxed preload exposes one frozen object with fixed methods. It does not
expose `ipcRenderer`, `require`, `process`, or a generic invoke call. It exposes
only `process.argv` to read the fixed window kind argument. The main process
checks the sender, the frame, the window, and the exact page URL for every call.
Every payload is a plain object with exact keys and bounded values. The routes
cannot name a path, URL, host, command, or channel.

Only `src/backend/engine-client.js` uses `child_process` and `http`. It runs in
the main process. It starts one configured binary, or the fixed pkexec helper,
and talks to one loopback port. Every other source file is free of process and
network APIs. A static test checks this split. The memory check reads `/proc`
directly. It starts no child process.

The autostart entry holds one absolute program path. It holds no secret. The
notification body is sanitized and holds no address, host, token, key, or
traffic. The settings file holds two booleans. The helper request holds the
secret on stdin only.

## Protected engine boundary

`src/backend/engine-client.js` holds the transport.
`src/backend/engine-backend.js` maps the fixed backend methods to it.
`src/backend/engine-boundary.js` holds the disconnected boundary that the demo
backend reports in the bootstrap answer.

The transport keeps these properties:

1. A per-launch bearer secret travels on descriptor 3 in development mode, and
   on stdin to the pkexec helper in packaged mode. The secret is never on a
   command line, in the environment, in a log, or in the renderer.
2. Descriptor 4 is the parent-liveness channel. The engine shuts down when the
   descriptor closes. In packaged mode the helper holds the channel.
3. The caller can use only the fixed operation list. It sends no generic path,
   URL, request, or shell command.
4. The secret stays in the main process. The page receives status values only.
5. Stop sends SIGTERM first in development mode. In packaged mode it closes the
   helper stdin, then waits. The engine removes every route, address, and device
   that it owns on a graceful stop.
6. The app starts no untrusted binary, no other privileged helper, and no
   auto-restart loop.

The engine path is an absolute file path from `--engine` or
`HOTSPOTSHADE_ENGINE`. The app checks that the file exists and is executable.
It never searches PATH. The engine's private temporary directory is created
with mode 0700. The port file inside it is removed after the stop.

The app does not fall back to the demo backend when a configured engine fails.
It shows the engine error instead. This prevents simulated data from appearing
as real status. A startup failure or an engine crash needs an app restart. The
app never restarts the engine by itself.

## Demo backend

`src/backend/demo-backend.js` holds all demo state in memory. It uses an
injected clock, so the tests are deterministic and the app does not need
background timers. It simulates pairing, start, stop, probe, Forget, recent
failures, diagnostics, and activity.

- The failure record stays in memory.
- Activity stays in memory and is capped at 400 entries in the backend and 800
  in the page.
- The theme and ping choices use the app settings and local storage.
- The recent failures and diagnostics reports are generated from simulated
  values and say so.
- The failure table shows the setup stage. A missing stage shows "Not reported".
  An unknown stage shows "Unknown stage". The copy report uses fixed stage words.
- The source device, token, and network are never present.

The Settings demo scenario controls change simulated state only. They cannot
start a tunnel.

## macOS parity

| Area | State on Linux |
|---|---|
| Dashboard status, action, cards, attention | Implemented from the macOS text and state table. |
| Pairing panel, code, copy, cancel | Implemented. Calls the engine pairing routes in engine mode. |
| Activity list, Details, refresh, states | Implemented. Reads the engine log in engine mode. |
| Settings General | Launch at login, Let ping work, Appearance, and Notifications. |
| Settings Pairing | Pair, Cancel, Forget, Turn off and forget, and blocked Forget. |
| Settings Advanced | Failures, Wi-Fi empty state, app details, diagnostics copy, limitations, demo scenarios. Demo scenarios are hidden in engine mode. |
| Light, dark, and high contrast themes | Implemented. System follows the operating system, including the high contrast preference. |
| Native window controls and menus | Implemented. |
| Separate Settings window | Implemented. It is one BrowserWindow with the three sections. |
| Menu bar extra | The macOS menu bar extra is a tray item on Linux. Start, Stop, Open, and Quit. |
| Notifications | Implemented for automatic stops, pairing results, and engine loss. The app setting controls them. |
| Launch at login | Implemented with one XDG autostart file. |
| Keyboard and screen-reader access | Skip link, landmarks, live regions, focus rings, tab and arrow keys, target size, reduced motion, forced colors, and the in-tree axe-style check. |
| Real source device discovery and pairing | Implemented through the engine pairing routes, with token authentication on the engine. Not tested with a live source device. |
| Real tunnel, source device proxy mode | The engine path exists and the packaged app starts the engine through the helper. A live hotspot test is still open. |
| Direct mode | The Rust CLI supports it. The app does not start it. |
| Recent failures and diagnostics from a real engine | Implemented in engine mode. Simulated in demo mode. |
| Automatic stop when the hotspot or source device is gone | The engine owns this behavior. The app shows the stop message and sends a notification. Not verified on a live Linux hotspot. |

## Verification in a disposable VM

Run on 5 November 2026 in a disposable VM cloned from a prepared image. The guest was Ubuntu 24.04 on x86_64 with Node.js
26.13.0, Electron 45.2.3, Chromium 156, Rust 1.99.1, and Xvfb. The app and the
tests ran as the non-root user `ubuntu` with the normal sandbox. The VM used its
own sudo only to install the Electron runtime libraries and to install the
built package. The package test used the real helper with a fake engine. It
changed no route, created no TUN device, and used no source device.

The current Rust source built in the VM. The engine tests started that binary.

| Check | Command | Result |
|---|---|---|
| Node test suite | `npm test` | 127 tests passed, 0 failed. |
| Electron demo smoke | `xvfb-run -a npm run test:smoke` | All checks passed. No external request. |
| Separate Settings window | `xvfb-run -a npm run test:settings-window` | All checks passed. The second window used the settings preload and the fixed IPC. |
| Accessibility rules | `xvfb-run -a npm run test:a11y` | 9 states and 8 keyboard focus stops, 0 violations. |
| Container smoke | `scripts/test-container.sh smoke` on the macOS host | All checks passed. |
| Engine smoke, real engine demo | `HOTSPOTSHADE_ENGINE=<binary> HOTSPOTSHADE_ENGINE_DEMO=1 xvfb-run -a npm run test:engine-smoke` | 40 checks, 0 failed. |
| Real app entry point | `HOTSPOTSHADE_ENGINE=<binary> HOTSPOTSHADE_ENGINE_DEMO=1 xvfb-run -a npm run test:main-engine` | 10 checks, 0 failed. The engine child and its temporary directory were gone after the quit. |
| Package build | `ARCH=x64 npm run package:deb` | Wrote one unsigned `.deb`. |
| Package install | `sudo dpkg -i build/hotspotshade_0.1.0_amd64.deb` | Installed. The polkit action and helper files were present. |
| Packaged app, engine demo | `xvfb-run -a /opt/hotspotshade/HotspotShade --engine-demo` | The app started the packaged engine at `/opt/hotspotshade/resources/engine/hotspotshade` with `--demo`. No engine child or temporary directory remained after SIGTERM. |
| Packaged app, default privileged path | `xvfb-run -a /opt/hotspotshade/HotspotShade` | The app called pkexec and showed the plain authorization error because the VM has no polkit agent. The window stayed unprivileged. |
| Real helper, fake engine | Helper run as root with `PKEXEC_UID set` and a fake engine at the packaged path | The helper printed one port, the fake engine answered `GET /api/status` with HTTP 200 and the bearer secret from descriptor 3, and the helper exited 0 when stdin closed. The helper refused one argument with exit 1. |

The engine smoke test proved these paths against the real Rust engine:

- The real engine accepted the authenticated loopback requests. This proves
  that the per-launch secret arrived on its descriptor. The page bootstrap
  carried no secret or token. The fake engine test also proves that the secret
  is absent from the command line and the environment.
- The page showed the engine demo labels and the connected engine boundary.
- Cancel stopped a pairing request. Pair completed through the engine.
- Start reached the engine and the page showed the tunnel state on with ping on.
- Stop reached the engine. The page showed the engine last stop message when
  one is present.
- Forget reached the engine.
- The failure record and the diagnostics had the real engine shapes.
- A forced engine crash became the plain error "The engine stopped
  unexpectedly". The page showed a stale status and did not fall back to the
  demo labels.

The main entry point test used the real `src/main/main.js` with the tray,
notification sink, status monitor, settings store, and lifecycle. It quit
through `app.quit()`. The engine child and its temporary directory were gone.

These runs do not prove Linux tunnel support. The engine ran its demo backend,
not a tunnel. The helper test used a fake engine with the real helper. A polkit
password prompt, a live desktop session, a live hotspot, and a source device
test are still open.

## Measured memory

Measured on 5 November 2026 in a disposable VM.
The test used Electron 45.2.3, Chromium 156.0.8078.80, Node.js 26.13.0, and
Xvfb at 1280x1024. The app ran as a non-root user with the normal sandbox. The
values are the median of three runs.

| State | Process tree RSS | Process tree PSS | App metrics working set | Processes |
|---|---:|---:|---:|---:|
| Idle dashboard | 585.4 MiB | 273.5 MiB | 462.0 MiB | 7 |
| Active demo, paired, activity open, failures loaded | 623.5 MiB | 295.2 MiB | 500.5 MiB | 7 |
| Change | +38.2 MiB | +21.8 MiB | +38.5 MiB | 0 |

The active state added about 38 MiB of RSS and 22 MiB of PSS. Most of the
increase is in the renderer and GPU processes. Run-to-run values varied by up to
about 7 MiB.

The idle PSS is about 13 MiB higher than the 4 November run. The page now has
the launch at login toggle, the notification toggle, the status line, the
settings store, and the impact of the new checks. This is a measured cost, not
an estimate. The renderer holds about 53 MiB PSS at idle. The GPU process holds
about 70 MiB PSS in this software-rendered VM.

The process tree holds the main process, one renderer, the GPU process, the
network utility, and three zygote processes. RSS counts a shared page once in
every process that maps it. PSS divides a shared page by the number of
processes that map it. It is the fairer comparison value. PSS still includes
the share of a page that is shared with a process outside the tree, such as
Xvfb.

### Measured responsiveness

The same VM and display produced these values:

| Metric | Value |
|---|---:|
| Page load | 147 ms |
| Idle frame p95 | 16.8 ms |
| Scroll frame p95 | 16.8 ms |
| Click latency p95 | 17.2 ms |
| Process tree CPU during the frame sample | 4 percent |

The window was visible, the document was visible, and the page produced 180
frames in each sample. Two idle frames and three scroll frames exceeded 33 ms.

## Dependency reason

Electron is the runtime dependency. It provides the Chromium renderer, the
native window, the native menu, the tray item, the notification API, the
sandbox, and the process model that the Linux target app needs. It is pinned to
one exact version and the lockfile is committed. There are no runtime npm
packages and no UI framework.

`@electron/packager` 20.3.0 is a development dependency. It builds the app
directory and the asar archive for the `.deb`, and it does not run at app
runtime. It has no install script that runs a remote command. It is pinned and
present in the lockfile. The package script states every file that it copies.

The desktop demo in `desktop/` uses Tauri. This Linux app does not change or
reuse that shell. The two apps share the design and the demo state ideas, not
code.

## Open integration work

- Run a live hotspot test with a real source device. The packaged app and the
  helper are ready for it, but a demo engine, a compile, a container, or a fake
  engine does not prove tunnel support.
- Test the polkit prompt and the helper on a real GNOME, KDE, and tiling window
  manager session. The VM had no polkit daemon, DBus session bus, or status
  notifier host.
- Test the tray item and desktop notifications on those desktops. The plain
  fallback is implemented. The StatusNotifierItem path is not tested on a real
  desktop.
- Test launch at login through a real session manager. The file format and the
  atomic write are tested. The login start is not.
- Wire direct mode to the app if the product needs it. The app start body is
  source device proxy mode.
- Fix the engine items that the Linux roadmap records: cleanup of policy rules
  after a crash and the periodic route re-check.
- Add a signed package and a repository, or an AppImage with a documented trust
  path. The current `.deb` is unsigned.
- Keep memory work open. The app is still larger than a small native utility.
