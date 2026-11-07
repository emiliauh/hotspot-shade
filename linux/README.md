# HotspotShade for Linux

This directory holds the Linux target app. The app uses Electron 45.2.3.

The app has two backends. With no engine setting it uses the in-memory demo
backend, and every view says that the data is simulated. With an engine setting
it starts the real HotspotShade Rust engine and reads the engine status through
a protected main-process boundary. A packaged build has no demo mode.

Opening a packaged app asks for no administrator authorization. The app runs
the packaged engine as the signed-in user, and the Dashboard, pairing, forget,
Settings, status, Activity, diagnostics, and Recent failures use that user
engine. Turning the tunnel on is the only step that asks: the app calls pkexec,
and the helper starts a root engine for the tunnel. For source device proxy
mode the user engine passes its pairing to the root engine on a private
inherited socket. See "Opening the app and turning the tunnel on" below.

The Linux tunnel start path exists in the Rust engine and has a VM test. The
Electron app sends both modes through the same fixed authenticated engine
service. A live hotspot, source device, and direct-mode
route test are still open. The polkit prompt at tunnel start and the live root tunnel have not run
on a real Linux desktop.

The app runs as the desktop user. The helper runs only the packaged engine. The
window, the renderer, the engine clients, and the user engine never run as
root.

## What the app contains

- One main window with native frame, title bar, window controls, and menu bar.
- A separate Settings window with General, Pairing, and Advanced sections. The
  page inside hides the sidebar and shows the three sections.
- Dashboard: one status header, one primary action, a fixed tunnel mode choice,
  source device and connection cards, an attention list, and a pairing panel.
- Activity: an event list from the selected backend with a Details toggle,
  refresh, and loading, empty, and error states.
- Settings General: Launch at login, Let ping work, Appearance, and
  Notifications.
- Settings Pairing: Pair, Cancel, Forget, Turn off and forget, a recovery stop attempt, and blocked
  Forget.
- Settings Advanced: Recent failures, Wi-Fi advice, app details, Copy
  diagnostics, limitations, and demo scenarios.
- Desktop notifications for automatic stop reasons, pairing results, engine
  loss, and tray action failures.
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
with a plain error. A packaged build ignores the environment variable and uses
the fixed helper. It accepts an explicit `--engine` only as a deliberate
development override.

For development and tests only, an unpackaged run can start the engine with the
engine's own demo backend: set `HOTSPOTSHADE_ENGINE_DEMO=1` or pass
`--engine-demo`. The app passes `--demo` to the engine and labels the data as an
engine demo. This mode needs no root, route, TUN device, or source device. A
packaged build ignores `--demo`, `--engine-demo`, and
`HOTSPOTSHADE_ENGINE_DEMO`, so the installed app always shows real engine state
and never shows a demo label, a demo banner, or the demo scenario controls.

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
| Pairing handoff (user engine only) | `POST /api/pairing/handoff` |

The Start body is fixed by the selected mode. Source device proxy mode sends
`{"mode":"phone","options":{"experimental_icmp":<bool>}}`. Direct mode sends
`{"mode":"tun","options":{"ipv6":"block"}}`. No caller can name a path, URL,
host, interface, DNS server, command, token, or other request body. Direct mode
uses the engine default physical hotspot interface, keeps interface pinning on,
blocks IPv6 by default, and uses no source device app.

### Tunnel modes

The dashboard has one fixed mode choice. The choice is stored in
`settings.json` and applies to the next start and to the tray Start action. The
choice is locked while the tunnel runs or while a start, stop, or pairing action
is in progress.

- Source device proxy mode needs the HotspotShade app on the source device. It
  keeps the existing token authentication and forwards IPv6 through the source
  device.
- Direct mode needs no source device app. The engine uses the physical hotspot
  interface of the default route, pins every outer socket to it, and blocks IPv6
  by default. The app sends no interface, DNS server, host, or token.

The status header and the Connection card report the mode that the engine
reports. In direct mode the Source device card says "Not used". The page never
claims that a direct route, TUN device, or cleanup succeeded. The engine status
is the only source of that state.

A start or stop request can time out, lose its connection, or receive an
unusable response after the engine has accepted it. A timeout closes the app's
request, but does not cancel the engine operation. In these cases the warning
asks the person to check the current status because the operation may still
finish after the warning appears.

If a fresh status reports interrupted service state or blocked cleanup while
the tunnel may still be running, the dashboard and tray offer "Try to turn
off". This requests a stop and does not prove that cleanup succeeded. The
engine can still report that cleanup is uncertain; inspect the routes and
devices before another start. In some interrupted states the stop request
reports uncertainty without retrying cleanup. The dashboard does not offer the
attempt from a stale status; the tray keeps the last status until its monitor
marks the engine unavailable.

On close in a development start the app sends SIGTERM and waits up to 5 seconds
for the engine to exit. If it is still running, the app closes the
parent-liveness descriptor and waits up to 2 seconds more. The direct-engine
stop budget is therefore about 7 seconds. It does not force-kill the engine. If
the engine remains running or its exit does not confirm cleanup, the app reports
that the engine or tunnel may still need attention before another start.

On close in a packaged start the app closes the helper request pipe and waits
for the real helper exit. It sends no signal to a root helper and never force
kills the tunnel. If authorization is still pending, it first waits up to
3 seconds for readiness or an exit; readiness changes the wait to the helper
budget. That budget covers 8 seconds before the helper signals
the engine, then up to 45 seconds for the engine route and rule cleanup. If the
helper is still alive after 65 seconds, the app reports the timeout and refuses
to start another engine while the old process may still be alive. A helper exit
code other than zero is a failed stop, not a clean one. That includes an engine
killed by a signal, an engine that exited non-zero, and a helper killed by a
signal. The app never restarts the engine after a crash. A crash becomes a plain
error in the page. The status becomes stale after 3 seconds and unavailable
after 10 seconds.

The authorization wait is separate from the engine startup wait. The app waits
up to 120 seconds for the helper to report `HS_READY` after pkexec authorizes
the launch. Password prompt time does not consume the 10 second engine startup
budget. If the authorization wait ends, the app closes the request pipe. A
helper that finishes authorization afterwards sees the closed pipe before it
launches an engine and exits with code 7 without starting one. If the pipe
closes after the launch, the helper stops the new engine gracefully instead of
claiming that none started; its exit code then describes that stop, and code 7
is not reported. If the helper reports `HS_STOP_TIMEOUT`,
the app records a failed stop immediately and keeps the start blocked while the
helper holds the lock. A failed authorization needs a new app start; the app
does not prompt again by itself.

## Opening the app and turning the tunnel on

The packaged app follows AGENTS.md invariant 14. The code is in
`src/backend/session-backend.js`.

1. At app open the main process runs
   `/opt/hotspotshade/resources/engine/hotspotshade` as the signed-in user, with
   the usual secret on descriptor 3 and the parent-liveness channel on
   descriptor 4. It also passes `--handoff-fd 0`: descriptor 0 is a private
   socket that Node creates and never reads. The engine `HOME` is
   `${XDG_DATA_HOME:-$HOME/.local/share}/hotspotshade/engine` (mode 0700), so
   the pairing identity key is
   `.../hotspotshade/engine/Library/Application Support/hotspotshade/identity.key`.
   No pkexec, helper, or root engine runs.
2. The Dashboard, pairing, Cancel, Forget, Check now, Settings, Activity,
   diagnostics, and Recent failures use this user engine.
3. Turn on in source device proxy mode first asks the user engine for
   `POST /api/pairing/handoff`. A user engine with no pairing answers
   `not_paired`, and the app shows "Pair with the source device first." without
   calling pkexec. Otherwise the user engine writes one frame with its identity
   and the source device credentials into its descriptor 0 socket. The app then
   calls pkexec and passes the other end of that socket as the helper's
   descriptor 2, because pkexec closes every inherited descriptor above 2. The
   request is `HS2`. The helper moves descriptor 2 to the root engine's
   descriptor 5 with `--credentials-fd 5` and never reads it. The root engine
   reads the newest queued frame before it binds its listener, imports the same
   identity, and holds the credentials in memory. Direct mode sends `HS1` and
   passes no handoff. Every Linux root engine accepts only the tunnel start
   modes, `phone` and `tun`; any other mode, such as a SOCKS5 listener, returns
   `mode_not_allowed`, because the authorization covers the tunnel only.
4. While the root engine exists it is the status source for the Dashboard,
   Activity, diagnostics, and failures. Pairing and forget are refused while its
   tunnel runs. A root engine whose tunnel stopped by itself, for example after
   `hotspot_lost`, stays the status source so the stop reason stays visible. A
   new start, a pairing, or a forget first stops it through the helper.
5. Turn off sends `POST /api/stop` to the root engine and then closes the
   helper request pipe. A clean helper exit is a confirmed stop: the app returns
   to the user engine, which still holds the pairing.
6. A stop that the app cannot confirm keeps the root engine as the status
   source. The app marks every status answer as uncertain (`state: unknown`,
   `cleanup_blocked: true`) with a route warning, so the Dashboard never shows
   Off for it, and a `running: false` answer does not clear the mark. Start,
   pairing, and forget are refused. A later Turn off, Turn on, pairing, forget,
   or Quit clears the mark only when the helper has since exited in a way that
   proves the state: exit 0 after a stop timeout, or exit 126, 127, or 7 after
   a stop during the authorization prompt with no engine port ever announced.
   A mark that remains is reported in the quit notice. A start is refused
   while a pairing or a forget is still running, so a handoff never carries a
   pairing that is changing.
7. Quit stops the root engine first, then the user engine.

The descriptor 0 socket of the user engine can hold old frames from a start
that the person cancelled at the prompt. The root engine reads all queued frames
and uses the newest. A frame stays in the kernel socket buffer until a root
engine reads it or the user engine exits.

In `HS2` mode the helper descriptor 2 is the handoff socket until the helper
moves it. Anything written to descriptor 2 before that point goes toward the
user engine, which never reads it: pkexec messages such as "Not authorized" or
"No authentication agent found", and the helper reasons `bad_arguments`,
`not_root`, `not_pkexec`, and an invalid version line. That output cannot reach
the frames that the root engine reads, which travel the other way. The app then
shows its fixed message for the exit code (126 or 127 for a refused or
dismissed prompt, the generic preparation message for exit 1).

### Migration from the root identity

Earlier packaged builds ran every engine as root with `HOME` set to
`/var/lib/hotspotshade`, so their identity key is in that root-owned directory.
The app never reads it. The new user engine creates its own identity key in the
user data directory, so the source device sees a new target public key and the
person pairs again once. The old root key stays unused in
`/var/lib/hotspotshade`; an administrator can remove it. The root engine now
imports the user engine's key for each source device proxy start and does not
create a root key for it.

## Packaged engine start with pkexec

A packaged app uses the fixed helper:

- Program: `/usr/bin/pkexec`
- Helper: `/usr/lib/hotspotshade/hotspotshade-helper`
- Engine: `/opt/hotspotshade/resources/engine/hotspotshade`
- Polkit action: `local.hotspotshade.tunnel`

The app calls `pkexec` with the helper path and no other argument, and only when
a person turns the tunnel on. The helper accepts no argument. It asks for
authorization before the root engine starts. It reads one short request from
stdin:

```
HS1 or HS2
<64 hex character per-launch secret>
```

`HS1` starts an engine with no pairing handoff, for direct mode. `HS2` means
that descriptor 2 is the user engine's pairing handoff socket. The helper reads
the version line first. For `HS2` it moves descriptor 2 to a private
close-on-exec descriptor, checks only that it is a socket, and points its own
descriptor 2 at stdout, so its reason lines still reach the app. It never reads
the socket.

The helper starts the engine as root with this fixed argument list:

```
gui --no-open --port 0 --port-file <root temporary file> \
    --token-fd 3 --parent-fd 4 [--credentials-fd 5]
```

The secret goes to the engine on descriptor 3. For `HS2` the handoff socket is
descriptor 5, and the helper closes its own copy after the spawn. The helper holds descriptor 4
until its stdin closes. A closed stdin, or a write half-close on a child stdio
socketpair, stops the engine. This is the stop path and the parent-loss path.

The helper prints `HS_READY` after authorization and before it starts the
engine. It prints `HS_PORT <number>` after the engine reports its port. The app
reads those lines and then uses the normal loopback HTTP client. The app cannot
signal a root helper, so the stop path closes stdin and waits for the real
helper exit, up to 65 seconds. The helper sends SIGTERM to the engine 8 seconds
after stdin closes and waits up to 45 seconds for the engine to remove its
routes, rules, address, and TUN device. It never sends SIGKILL: a forced kill
skips that cleanup and leaves the policy rules and the IPv6 blackhole behind.
If the engine still has not stopped, the helper prints `HS_STOP_TIMEOUT`, keeps
running, and retries SIGTERM every 30 seconds. It holds its lock until the
engine is gone, so a later helper cannot start a second engine. The person must
inspect the routing table. The engine also receives SIGTERM when the helper
itself dies, so a helper killed with SIGKILL still gives the engine its SIGTERM
stop path. An engine that ignores SIGTERM can still survive; the state record
makes a later helper refuse to start over it.

The helper uses these exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean stop |
| 1 | Invalid request or local setup failure |
| 4 | The engine exited on a signal |
| 5 | The engine failed to start or exited non-zero |
| 6 | Another helper or a previous engine is still alive |
| 7 | Authorization finished after the app stopped waiting; the helper starts no engine |
| 8 | The previous engine state could not be verified; the state is kept for inspection |
| 9 | The engine stopped, but the helper could not remove its state or private directory; inspect the routes |

The helper holds `/var/lib/hotspotshade/helper.lock` with `flock` for its whole
life. The file and the engine home are root-owned and private. The helper also
writes `/var/lib/hotspotshade/engine.state`. The state record is version 2 and
names the kernel boot id, the helper's PID namespace, and either a pending start
or the engine process id and kernel start time.

The helper writes a `PENDING` record before it spawns the engine, then replaces
it with an `ENGINE` record after the spawn and before any post-spawn
abandonment check. A helper killed after the first write therefore never leaves
an unrecorded engine. A later helper refuses to start while the exact recorded
process is alive, even if an earlier helper died and released the lock.

The recovery rules are deliberately conservative:

- A record from another boot is stale. No process survives a reboot.
- A record from another PID namespace is uncertain and is kept. An engine in
  another PID namespace could still share the host routing table. The namespace
  identity is the device and inode of `/proc/self/ns/pid`. Namespace inodes can
  be reused after a namespace is destroyed. The boot id, namespace inode, pid,
  and start time together are a practical identity, not a kernel-issued
  permanent one.
- A `PENDING` record with no live writer is uncertain and is kept. The helper
  cannot prove whether an engine was spawned before the writer died. This is
  the visible cost of the write-ahead record. Inspect the routes and remove the
  record only after proving that no engine remains.
- A missing or reused process id is stale only after `/proc` is proven readable.
- A zombie leader is stale only after a bounded scan observes no live task in
  its thread group. The scan is not an atomic proof. A task created after the
  last pass, or one hidden by a concurrent directory change, is not seen. The
  engine does not call `exit()` from its leader thread and then create threads,
  so this is sufficient for this engine, not for an arbitrary process. The
  record names the engine thread group, not a child process that the engine
  could create. The packaged engine does not fork a route-owning child.
- An older version, an unknown version, trailing data, an oversized file, a
  FIFO, a symlink, or any other unverifiable record fails closed and is kept
  for inspection.

If the app reports that the previous engine state cannot be verified, an
administrator must first confirm that no old engine remains and inspect the
routing table. Do not delete the state file merely to bypass the refusal. The
helper does not signal a process after it has reaped that process, and it never
signals a process id read from the state file. The state write and the record
removal sync the parent directory, so a power loss after the write does not
silently lose the record. The record check and the unlink are not one atomic
operation; a same-uid writer that replaces the file between them is not
excluded. Only root can write the private state directory.

A clean exit is reported only when the engine exits cleanly, the state record is
removed, and the private port directory is removed. A cleanup failure returns
code 9 even when the engine exited 0, so the app does not report a clean stop.

The helper creates its port directory under `/tmp` with mode 0700 at creation
time, before the engine can write the port file. It does not widen the mode
afterward. The engine writes the port file with mode 0600.

The helper sets `HOME` to `/var/lib/hotspotshade`. The engine keeps the target
identity key there with root-only access. The app never reads or copies that
key. The package creates the directory with mode 0700.

The polkit action uses `auth_admin` for every session state: any, inactive, and
active. The `org.freedesktop.policykit.exec.path` annotation names the fixed
helper path. Each launch needs its own authorization, so another process in the
same desktop session cannot start the root helper through a cached approval.
The helper checks `PKEXEC_UID`, refuses arguments, and resolves the engine to
one canonical path. It checks that the engine file and every parent directory
are owned by root and are not writable by another user, then starts the engine
through that same checked canonical path. A missing pkexec path, helper, or
engine becomes a plain error before a process starts.

The helper cannot prove which process called it, and polkit authentication is
per launch. Do not use `auth_admin_keep` here: it would let any process in the
same session start the fixed root helper without a fresh prompt for about five
minutes after one approval. `auth_admin` still accepts only the fixed engine
and the fixed request, so a launch is not arbitrary code execution. No real
polkit agent has been tested.

The root engine home is shared by every user who can authorize a launch. A
source device proxy start no longer uses a key from it: the root engine imports
the user engine's key. A direct start needs no key. The helper reads
`PKEXEC_UID` but does not create a per-user home.

A packaged build ignores the `HOTSPOTSHADE_ENGINE`, `HOTSPOTSHADE_PKEXEC`,
`HOTSPOTSHADE_HELPER`, and `HOTSPOTSHADE_PRIVILEGED_ENGINE` environment
variables. It uses the fixed packaged paths. A development `--privileged`
launch may still use those variables for tests and local work.

No real polkit agent, logout, shutdown, or desktop teardown has been tested.
The authorization and lock tests use fake helpers and one root container. A
helper killed with SIGKILL can leave a root-owned directory under `/tmp`,
possibly with its numeric port file, and can leave a `PENDING` or `ENGINE` state
record. A SIGKILL cannot run the cleanup path, so the normal code 9 cleanup
failure is not available in that case. The directory holds no bearer secret. The
app discards the loopback client when the
helper exits, but a request already in flight can still race a freed port. The
operation allowlist carries no source device token, so such a race cannot read
one.

The app refuses to start when `getuid()` is 0. Start the window as your desktop
user.

Root processes, stated plainly: the helper and the engine it starts both run as
root, from Turn on until a confirmed stop. The engine is the full Rust engine
with its authenticated loopback HTTP service, not a small stub. Treat that
service as a root-owned service: its protection is the per-launch bearer secret
on descriptor 3 and the loopback bind, nothing more. The window, the renderer,
the engine clients, and the user engine never run as root. The app no longer
starts a root engine or asks for authorization at app open.

Untested on a real Linux desktop: the polkit prompt at Turn on, the `HS2`
handoff through real pkexec and the real helper, the root engine import from
that socket, a live tunnel, and the confirmed and unconfirmed stop paths with
real routes. The helper changes were type-checked on macOS only, with the
Linux-only `prctl` call stubbed; the helper tests need Linux. The real-engine
backend test drives the session against the real engine through the labeled
JavaScript helper stand-in as a normal user.

### Helper failure reasons

Exit code 1 covers several preparation failures. Before its human text the
helper writes one fixed line on stderr, `HS_REASON <slug>`. The slug is a short
lowercase word from a fixed list (for example `engine_unsafe_permissions`,
`engine_missing`, `home_unsafe`, `lock_unavailable`, `request_invalid`). It
holds no secret and no path. The app keeps a bounded tail of helper stderr (4 KiB),
takes the last such line, and maps only a slug it knows to a plain-English message;
for example, unsafe permissions on `/opt/hotspotshade` produce a message that
names the install directory and says to reinstall the package. An unknown slug, a
malformed line, or no line at all keeps the generic message. The exit codes are
unchanged.

### Closed output pipe

The helper writes `HS_READY` and `HS_PORT` with `writeln!`, not `println!`, and
handles a write error. If the app's read end is gone before the engine starts,
a failed `HS_READY` write takes the abandoned path: the helper removes its
private directory and exits 7. If the `HS_PORT` write fails after the engine
started, the helper stops the engine through the normal SIGTERM path and exits
with the engine's stop code, or 5 if that stop reported none, never 0.

## Tray, notifications, and launch at login

### Tray item

The app creates an Electron `Tray` item with the local app icon. On a desktop
with a status notifier host, Electron uses StatusNotifierItem. The menu has one
disabled status row and these actions:

- Start tunnel
- Stop tunnel
- Open HotspotShade
- Quit HotspotShade

Start uses the saved tunnel mode and ping choice. Direct mode does not require
a source device pairing; source device proxy mode does. The tray updates its
mode on the next status poll and checks the saved mode again when Start is
clicked. Stop calls the engine stop route. One tray action runs at a time; a second Start or Stop click is ignored while the first
one is pending. A synchronous backend throw and an asynchronous rejection both
clear the pending state and report one failure. The status row follows the real
engine status. An invalid engine setting has no status to report, so the status
row says "Not available" instead of staying on "Starting". A missing status
after repeated polls also shows "Not available". A refresh that overlaps an
existing poll can leave the prior row visible until the next poll. A desktop
without a status notifier gets the plain fallback: the tray item is absent, the app
continues, and closing the window quits the app. On a desktop with a tray item,
closing the window hides it and the tray item keeps the app alive. Quit from the
tray stops the engine.

### Notifications

The main process polls the backend every 2 seconds. It sends a desktop
notification for:

- A hotspot loss stop.
- A source device loss stop.
- A tunnel error stop when the app is not focused.
- A completed pairing.
- A failed pairing.
- An engine that stopped after three failed status polls.
- A tray Start or Stop action that failed.

The app never notifies for a user stop. Each message kind is limited to one
message in 60 seconds. Start and Stop failures use fixed text and separate
limits, and never show the backend error text. The notification body comes from
the engine stop message when one exists. It holds no address, host, token, key,
or traffic. A click opens the main window. The Settings toggle turns
notifications on or off. The choice is stored in `settings.json` under the app
user data directory. Demo data and an invalid engine setting never send a
notification.

### Launch at login

The Settings toggle in a packaged app writes or removes one file:

```
${XDG_CONFIG_HOME:-$HOME/.config}/autostart/hotspotshade.desktop
```

The file starts the packaged app as the desktop user, not the helper. The app
writes a temporary file in the same directory, syncs it, and renames it over the
target. The remove path is one unlink. A missing file reports off. A failed
write reports a plain error. The environment variable `HS_AUTOSTART_DIR` points the
writer at another directory. It is a test override, but the code does not gate it
on a development build: a packaged build honors it too, so it redirects where
Launch at login writes. Unset it for normal use.

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

The suite covers the demo backend, the fixed IPC allowlist, the fixed tunnel
mode choice, the page model, the engine setting, the HTTP boundary with a fake
engine server, the process lifecycle with a fake engine script, the settings
store, the XDG autostart file, the notification policy, the tray action runner,
the tray menu, the status monitor, the privileged client contract with a fake
helper, the in-tree accessibility rules, and the packaging files. The fake
helper covers a slow password prompt, an authorization that finishes after the
app gave up, a helper signal, an engine failure, a stop timeout, and a surviving
engine.

One more test runs the app's engine client, engine backend, and IPC router
against the real engine binary. Build the engine and name it. The test skips
without `HOTSPOTSHADE_BIN`, and it skips as root:

```sh
cargo build --locked --manifest-path ../rust/Cargo.toml
HOTSPOTSHADE_BIN=$PWD/../rust/target/debug/hotspotshade node --test test/real-engine-backend.test.mjs
```

`test/real-engine-backend.test.mjs` starts a non-demo engine as your user with
a temporary `HOME`. It checks the secret and liveness descriptors, the idle
status, pairing state, failure record, diagnostics, and activity, and that a
phone start without pairing and a direct start without root are both refused.
It also checks that the engine exits when its parent is killed. It compares the
interface list and the routing table before and after, and never calls Pair,
Forget, or Probe, because those contact the default gateway. A second case runs
the pkexec client path against the real engine through
`test/fixtures/real-engine-helper-standin.js`. That script is a JavaScript
stand-in, not the real helper: it refuses to run as root, writes no state
records, and cannot prove polkit, root, or tunnel behavior. This test creates no
TUN device and changes no route.

The helper has its own Linux-only tests for the private temporary directory,
the canonical engine path, safe signaling after a child is reaped, SIGTERM-only
stop, the secret format, the private lock, lock contention, the version 2 state
record, the boot and PID namespace identity, the write-ahead `PENDING` record,
the previous-boot and foreign-namespace refusals, the bounded zombie and task
scan, the cleanup-failure exit code, the socketpair half-close guard, and the
abnormal exit codes. Run them on Linux:

```sh
cargo test --locked --manifest-path helper/Cargo.toml
```

The lifecycle tests run the real helper binary and create the fixed `/opt` and
`/var/lib/hotspotshade` paths. They are skipped unless `HS_HELPER_INTEGRATION=1`,
the effective user is root, and a container marker is present. If the opt-in is
set but those prerequisites are absent, they fail. A normal-user `cargo test`
skips these cases and is not integration evidence. `helper_lifecycle`
uses a fake engine, a real child stdio socketpair, and half-close with
`shutdown(Write)` at the points where Node `end()` can close the request
channel. It also kills the real helper at staged points to prove that the
write-ahead `PENDING` record blocks a second start, that an `ENGINE` record is
recovered once its engine is gone, that a failed pre-spawn write starts no
engine, and that an unremovable state returns code 9. `real_engine_demo` starts
the real engine through the real helper. It
starts no tunnel. The test code sets no route and opens no TUN device. The
wrapper disables container networking; its demo request uses loopback.

### Helper integration tests

Run them only on a disposable Docker host. The image and all locked crates must
already exist locally. The script does not pull images or fetch crates. Set
`HS_HELPER_IMAGE` or `HS_HELPER_CARGO_HOME` to select local inputs. It builds
offline in a fresh volume, then checks the staged file hashes and runs both test
executables. All containers use `--pull=never`, `--network none`, drop all capabilities, and
have a 20-minute phase limit. The build mounts the source and Cargo registry
read-only. Neither phase mounts a host path on `/opt`, `/var/lib`, or `/tmp`.

```sh
bash linux/helper/tests/run-container.sh
```

Each executable must list exactly the tests in its checked-in inventory and
print one named start marker for each. Both executables must succeed. A missing prerequisite or missing marker fails the wrapper. This
is execution evidence, not an independent attestation. The container marker
and mount checks do not prove that a Docker host is disposable; verify the host
before running. The helper path is embedded in the test executable as
`/target/debug/hotspotshade-helper`. Hashes detect changes between staging and
the run, but do not establish source provenance or trustworthy build inputs.

On failure or a handled HUP, INT, or TERM, the wrapper reports its private
host `mktemp` directory and records any Docker volume ID returned by Docker in
`volume.id`. It reports the volume as possibly present because interruption
or a later cleanup error can occur after removal. It retains any failed or
unremoved phase container, plus logs and metadata in the directory containing
the image reference, checkout HEAD, build log, checksums, phase output, and
container ID files. The container writable layer retains any residual `/opt`
and `/var/lib` trees. A daemon failure or interruption before writing an ID
may leave a container or volume that the wrapper cannot identify. SIGKILL
cannot be handled. HEAD does not identify
uncommitted source changes. Successful phase containers are removed promptly.
After investigation, use only the exact IDs and volume printed for that run:

```sh
docker inspect "$(cat /absolute/path/to/evidence/PHASE.cid)"
docker diff "$(cat /absolute/path/to/evidence/PHASE.cid)"
docker rm "$(cat /absolute/path/to/evidence/PHASE.cid)" # repeat for each reported ID file
docker volume rm EXACT_REPORTED_VOLUME
rm -r /absolute/path/to/evidence
```

Inspect or copy any needed files from each stopped container before removal.
If a container is still running, stop that exact container first. Do not use
Docker prune commands. A failure before volume creation can leave only the
temporary directory. Run the mock wrapper checks in
a separate disposable container using a locally available image:

```sh
docker run --rm --pull=never --network none --cap-drop=ALL --security-opt no-new-privileges \
  -v "$PWD:/work:ro" -w /work "$HS_HELPER_IMAGE" \
  bash linux/helper/tests/run-container-test.sh
```

The guards leave directories in place when metadata or removal checks fail,
including ancestors needed for inspection. Identity uncertainty also prevents
cleanup. The parent directory is held open during final removal, but the last
identity check and removal are separate operations. A same-user process can
replace the final directory in that interval; this is not atomic ownership
proof. Use a disposable container without concurrent untrusted processes. The
test guard counts a recorded zombie as exited. The production helper adds a
bounded live-task scan and the boot and PID namespace identity, and keeps an
uncertain record. The helper supervisor still reaps its own child. The listener
check examines both IPv4 and IPv6 socket tables for the GUI port in the
container network namespace.

The liveness test observes release of the helper's socket, then freezes the
helper within the source-defined grace period. It checks that the engine is
still alive after the freeze and exits while the helper remains frozen. Socket
release precedes the freeze; the observations do not establish the exact time
the engine received EOF or exclude every other exit cause. Timing or identity
uncertainty fails the test. The grace value comes from the helper source at test
build time. The test uses real helper and engine
processes and a liveness socketpair; it does not exercise the Electron client's
real request socketpair, the kernel parent-death signal, or the helper's timeout fallback. It starts no
real tunnel, route, TUN device, polkit service, or physical device. Container
results do not establish hotspot, carrier, or physical-device behavior.

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

The quit-warning variant deliberately terminates its own demo engine to check
that the main process requests the unconfirmed-cleanup warning. It intercepts
the dialog call, so it does not check how the desktop displays the dialog. It
refuses this scenario unless `HOTSPOTSHADE_ENGINE_DEMO=1` is set. Use only a
demo engine for this test; it does not exercise route or tunnel cleanup.

```sh
HOTSPOTSHADE_ENGINE=/absolute/path/to/hotspotshade \
HOTSPOTSHADE_ENGINE_DEMO=1 \
xvfb-run -a npm run test:main-engine-warning
```

The memory and responsiveness checks use the same page and the same wait:

```sh
xvfb-run -a npm run measure:memory
xvfb-run -a npm run measure:responsiveness
```

On a host without a display, use `scripts/test-container.sh` with `smoke`,
`a11y`, `memory`, or `responsiveness`. The `main-engine-warning` mode also
accepts an absolute Linux engine binary through `HOTSPOTSHADE_BIN`, mounts it
read-only, and runs the warning test in demo mode with container networking
disabled and all capabilities dropped. The binary must match the container's
architecture. The first image build needs network access. Set
`HS_TEST_USE_EXISTING_IMAGE=1` only when intentionally reusing an already-built
image; that choice does not prove the image matches the current Dockerfile.

```sh
HOTSPOTSHADE_BIN=/absolute/path/to/linux/hotspotshade \
scripts/test-container.sh main-engine-warning
```

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

### Platform

The package is for Debian and Ubuntu only. It needs `dpkg`, `pkexec`, and a
glibc system. The baseline is **Ubuntu 24.04 with glibc 2.39**. The engine and the
helper are built on the build host and link against its glibc, so build on Ubuntu
24.04. The script reads `/etc/os-release` and `getconf GNU_LIBC_VERSION` first. It
stops on a host that is not Debian-family, whose glibc it cannot read, or whose
glibc is newer than 2.39, because that package would not run on 24.04. Set
`HOTSPOTSHADE_ALLOW_NEWER_GLIBC=1` to build anyway for newer hosts only; the
script then prints a warning. Another Debian-family host with an older or equal
glibc builds with a note that it is outside the tested baseline.

Starting the tunnel runs a root helper through `pkexec`. The desktop session
therefore needs a **polkit authentication agent** to show the password prompt.
GNOME and KDE provide one. A bare tiling window manager often does not; install
one before you start the app. The package lists common agents under Recommends and
does not depend on one. No real polkit agent has been tested with this package.

### Depends

When `dpkg-shlibdeps` (package `dpkg-dev`) is installed, the script derives the
shared-library Depends from the built Electron, engine, and helper binaries. It
merges that list with the runtime libraries named in `scripts/Dockerfile.test`,
using the Ubuntu 24.04 `t64` names with the older names as alternatives (for
example `libasound2t64 | libasound2`, `libgtk-3-0t64 | libgtk-3-0`,
`libcups2t64 | libcups2`), plus `xdg-utils` and `pkexec`. Without
`dpkg-shlibdeps` the script prints a warning and lists the known libraries plus
`libc6 (>= <the build host's glibc>)`; that list is not derived and can miss a
library. The Depends was not checked by installing the package on a clean 24.04
host.

### Install, upgrade, remove, and purge

The package is unsigned. Install it with your package manager and your own trust
decision:

```sh
sudo apt install ./hotspotshade_0.1.0_amd64.deb
```

The package ships three maintainer scripts, from `packaging/debian`:

- `postinst` creates `/var/lib/hotspotshade` (root, mode 0700) and repairs file
  modes.
- `prerm` refuses `remove`, `upgrade`, and `deconfigure` while the helper or an
  engine may still be running, and exits 1 so dpkg stops. The helper is running
  when it holds the root-only lock `/var/lib/hotspotshade/helper.lock` (probed
  with a non-blocking shared `flock`). A `/var/lib/hotspotshade/engine.state`
  record from this boot also blocks, because with no helper alive nothing proves
  that the engine is gone. A record from an earlier boot cannot name a live
  process and does not block. If `flock` is missing or fails, `prerm` refuses
  rather than guess. The message names the reason and the recovery: quit the app
  and wait up to a minute; check `pgrep -af
  /opt/hotspotshade/resources/engine/hotspotshade` and `ip rule show; ip route
  show table all; ip -6 route show table all`; if the helper exited and nothing
  remains, remove the stale record with `sudo rm /var/lib/hotspotshade/engine.state`
  and run the command again; ask an administrator to send SIGTERM to a stuck
  engine, never SIGKILL. `prerm` never signals, kills, or stops a root process.
- `postrm` removes `/var/lib/hotspotshade` on `purge` only. That directory holds
  the root engine identity key, the pairing trust list, and the helper lock and
  state records. A plain remove keeps it, so a reinstall keeps its pairing. If a
  purge finds the helper lock held or a same-boot record (dpkg can skip `prerm`),
  `postrm` keeps the directory, prints why and the command to delete it, and
  exits 0 so the package is not left half-purged. It never follows a symbolic link.

The protection starts with the version that ships `prerm`. Upgrading from a
version that has no `prerm` runs no check, because dpkg runs only the old
version's `prerm`.

Remove it with:

```sh
sudo apt remove hotspotshade     # keeps /var/lib/hotspotshade
sudo apt purge hotspotshade      # also deletes /var/lib/hotspotshade
```

Neither command deletes your user settings or your autostart entry. Those live in
your home directory. Turn off Launch at login first if you do not want the entry
to remain. The maintainer scripts have been tested against fixtures and a
`flock` shim; they have not run under a real `apt` on a Linux host.

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
traffic. The settings file holds two booleans and one fixed tunnel mode value.
The helper request holds the secret on stdin only.

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
   helper stdin, then waits. The helper sends only SIGTERM and allows the
   engine's full cleanup window. The engine removes every route, address, and
   device that it owns on a graceful stop. A non-zero helper exit, a helper
   signal, or a stop timeout is reported as a failed stop. It is never reported
   as a clean one.
6. The engine sends the proxy token only to the gateway of the current private
   default route. A saved credential from an earlier network is refused until
   that network returns. A manual start or check cannot name another host.
   The token connection is pinned to the revalidated interface.
7. The app starts no untrusted binary, no other privileged helper, and no
   auto-restart loop.

A development engine path is an absolute file path from `--engine` or
`HOTSPOTSHADE_ENGINE`. The app checks that the file exists and is executable.
It never searches PATH. A packaged build ignores those environment overrides
and uses the fixed helper and engine paths. The engine's private temporary
directory is created with mode 0700. The port file inside it is removed after
the stop.

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
| Settings Pairing | Pair, Cancel, Forget, Turn off and forget, a recovery stop attempt, and blocked Forget. |
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
| Direct mode | Implemented through the same authenticated engine service. The packaged app starts the root engine; a development engine needs root outside the app. Live direct routing and route cleanup are not verified. |
| Recent failures and diagnostics from a real engine | Implemented in engine mode. Simulated in demo mode. |
| Automatic stop when the hotspot or source device is gone | The engine owns this behavior. The app shows the stop message and sends a notification. Not verified on a live Linux hotspot. |

## Verification in a disposable VM

The real-engine status contract can also be checked without a tunnel. Build a
Linux engine, then run the following inside a disposable environment with no
external network and a private temporary directory:

```sh
cd linux
HS_TEST_NETWORK_CONFINED=1 HS_REAL_ENGINE_BIN=/absolute/path/to/hotspotshade \
  node --test test/real-engine-status.test.mjs
```

This starts the non-demo engine as the current user, reads status through the
Linux client, and closes the parent channel. It does not start a tunnel or
verify the Electron window. The environment variable records the caller's
isolation setup; it does not enforce isolation itself. On 6 November 2026 the
check passed in an offline, non-root arm64 container with a read-only source
mount. The shared working tree was changing during the build, so this result
does not identify a release snapshot.

`HOTSPOTSHADE_BIN=/absolute/path/to/linux/hotspotshade HS_TEST_USE_EXISTING_IMAGE=1 scripts/test-container.sh real-engine-window`
exercises the same non-demo engine through the Electron window in an offline
Linux container using the existing test image. It passes an unprivileged
engine client directly to the window and checks the rendered source-device
state, then stops the engine. It does not exercise the packaged app's default
pkexec launcher or start a tunnel. The isolated check passed on 6 November
2026 using the local shared tree, which was changing during the build.

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
| Packaged app, default privileged path | `xvfb-run -a /opt/hotspotshade/HotspotShade` | The app called pkexec and showed the plain authorization error because the VM has no polkit agent. The window stayed unprivileged. This run predates the change that starts the user engine at app open and calls pkexec only at Turn on, and the change that ignores `--engine-demo` in a packaged build. Both need a fresh VM run. |
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

- Test source device proxy mode and direct mode on a live hotspot. The packaged
  app and the helper are ready for the source mode path, but a demo engine, a
  compile, a container, or a fake engine does not prove tunnel support. The
  packaged non-demo start, live direct routing, and route cleanup remain
  unverified.
- Test the polkit prompt and the helper on a real GNOME, KDE, and tiling window
  manager session. The VM had no polkit daemon, DBus session bus, or status
  notifier host.
- Test the tray item and desktop notifications on those desktops. The plain
  fallback is implemented. The StatusNotifierItem path is not tested on a real
  desktop.
- Test launch at login through a real session manager. The file format and the
  atomic write are tested. The login start is not.
- Fix the engine items that the Linux roadmap records: cleanup of policy rules
  after a crash and the periodic route re-check.
- Add a signed package and a repository, or an AppImage with a documented trust
  path. The current `.deb` is unsigned.
- Keep memory work open. The app is still larger than a small native utility.
