# HotspotShade for macOS

HotspotShade on the target device contains the Rust engine. The app has no demo
mode. It always starts the bundled engine as the signed-in user when it opens.
That user engine serves the Dashboard, pairing, status, Settings, Activity,
diagnostics, and Recent failures, so the ad-hoc build shows real data and can
pair without an administrator prompt. Only Turn on needs the signed protected
helper. Without it, Turn on shows a plain message that the signed helper is
needed and starts no tunnel. The current helper installer refuses installation
and has not been validated. The command-line `phone` adapter can exercise a source
device proxy for a configured application without installing the helper. See
the source device proxy section of the [main README](../README.md).

Run `scripts/build_mac_app.sh build/HotspotShade-unsigned.zip` from the
repository root. The script builds the engine and the app for the host
architecture. On arm64 it uses the `aarch64-apple-darwin` Rust target. On Intel
it uses `x86_64-apple-darwin`. Install the matching Rust target before the
build. Set `CARGO_TARGET_DIR` to select the Rust build directory. Set
`HS_MAC_DERIVED_DATA` to select the app build directory. A build without the
script does not include the engine. A failed build leaves any existing output
zip unchanged; do not mistake that older file for the failed build's result.

The bundle has an ad-hoc signature. Unzip the app and move it to Applications.
Right-click the app and select Open for the first launch. The release app runs
on arm64 target devices only.

To use a real signing identity, sign the nested engine first. Sign the app next.
Use a Developer ID Application identity, enable the hardened runtime, and keep
`com.apple.security.get-task-allow` out of the entitlements:

```sh
codesign --force --options runtime --timestamp --identifier dev.hotspotshade.engine --sign "<Developer ID Application>" HotspotShade.app/Contents/Resources/bin/hotspotshade
codesign --force --options runtime --timestamp --sign "<Developer ID Application>" HotspotShade.app
codesign --verify --deep --strict HotspotShade.app
```

The protected helper and the root-owned engine need the same team, the hardened
runtime, and no debugger entitlement. The app reads its team from this
signature. An ad-hoc or development signature fails the protected helper check.
Signing the bundle alone does not install or validate the helper and does not
make the real app ready for use.

For a future local preview, the helper trust code also has an explicit
`HOTSPOTSHADE_LOCAL_PREVIEW` compile-time policy for an Apple Development
certificate. The app, helper, and installer must all be built with that policy
and signed by the same team. It still rejects ad-hoc signatures and debugger
entitlements. Ordinary builds retain the Developer ID policy. The app build
script accepts `HS_MAC_LOCAL_PREVIEW=1` with an Apple Development identity in
`HS_MAC_SIGN_IDENTITY`; the helper and installer must also be built with
`-Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW`. The installer remains disabled, so
these are not install instructions or a usable preview yet.

`scripts/build_mac_local_preview.sh NEW_OUTPUT_DIRECTORY VERSION` builds the
app, helper, and installer staging tool with the same preview policy, then
stages the signed components. It also builds a signed sandbox-only installer
coordinator and checks that its signing team matches the app. It takes the
Apple Development identity from `HS_MAC_SIGN_IDENTITY`. It does not install
anything, and staging is still
blocked from live installation. Staging has passed with a local Apple Development
identity; its compatibility with a personal-team certificate is not yet verified.
A local preview's development key may be usable by other processes
in that account, so its same-team signature is not a separate protection from
other code running as that user. The administrator authorization still applies
to each tunnel start.

The app starts the bundled engine as a child process in both modes. The engine
listens on loopback only. The app sends a new secret on a private pipe for each
launch. Real mode runs that engine as the signed-in user, so the Dashboard,
pairing, status, Settings, Activity, diagnostics, and Recent failures work
without an administrator prompt. Opening the app starts no root helper and no
root engine. The app offers the source device proxy tunnel only. Direct mode
stays a command-line feature until the app has a mode choice and a direct start
body.

macOS asks for administrator authorization only when a person turns the tunnel
on. Before that request, the user engine writes its pairing identity and the
source device credentials into a private socket pair that the app passed at
launch. The app holds the read end and never reads it. The app sends that
descriptor to the protected helper over XPC, and the helper passes it to the
root engine as an inherited descriptor. The root engine imports the same
identity and credentials before it binds its listener, so the source device
continues to see the same target public key and the person does not pair again.
The token never enters the app process, a browser, a status answer, a log, a
command line, or a file.

A stop that the helper cannot confirm stays marked uncertain. While it is
uncertain, a new start is refused before the administrator prompt, the pairing
handoff, and the root engine start. Pairing, a pairing handoff, and forget are
refused too, because the user engine cannot see the root tunnel. A running
false status never clears that mark; only a later helper stop that confirms the
stop does. The mark is owned by the app, not by one built model, so a user
engine restart, a retry, or a quit that the person cancels does not forget it.
The launch screen offers Retry cleanup, and the Dashboard shows the same state
without claiming a clean On or Off. A pending stop with no elevated process is
still retryable: the app reconnects and reads the helper's session record.

The helper protocol returns a session id at start. A stop reply says whether
the connection owned the stopped session. A reconnect that owns nothing cannot
use its own successful stop acknowledgement as proof. It asks for the exact
session id and accepts only a completed clean result for that id, with no live
or stopping session and no cleanup block. A helper restart loses its in-memory
session record, so the app keeps the uncertainty. A status that says a
different session is running or stopping also keeps it. The app also keeps the
mark when the helper reports that another launch is still starting.

An unconfirmed stop is held in app memory. If the helper is restarted and the
person completes the documented recovery, relaunch the app to drop that
in-memory mark. The next start still checks the helper status, the session
record, and the durable cleanup block.

An elevated engine that stopped its tunnel on its own, for example after a
hotspot loss, is still a live root process. A new start first asks the helper
for a confirmed stop and clears the old session only after that confirmation. An
uncertain stop keeps the old session and the refusal.

Turn off and Quit share one stop flight. A concurrent caller waits for the same
confirmed or uncertain result instead of starting a second helper stop. A
caller that arrives after a stop finished starts a new stop instead of reading
the old result. The quit path asks the helper even when an earlier stop is
still pending, because that helper stop is idempotent and the helper owns the
engine process and its grant directory. A quit that races a tunnel start waits
a bounded time for the start to settle. If it cannot, the quit is uncertain and
a late start stays aborted, even when the person chooses Stay. After Stay, the
app resumes the status poll and the user engine monitor, so a later user engine
loss still stops the tunnel and shows the lost screen. A tunnel start in flight
is also owned by the app, not by one built model. A user engine loss or a
rebuild during the start keeps it: Pair, a pairing handoff, and forget stay
refused, the lost user engine is not restarted over it, and a quit still waits
for it. Turn off and forget returns a visible failure when the stop fails and
does not call forget. A lost user engine carries an
uncertain cleanup into the lost screen instead of restarting over a root
session. A confirmed helper stop is not overridden by the dead user engine's
own error.

A stop also cancels every tunnel start that began before it. If Turn off,
Retry cleanup, a quit, or a lost user engine lands while a start is in its
pairing handoff, its root engine start, or its administrator prompt, that start
stops what it prepared and does not show it as On. A press that began before a
quit stays cancelled after Stay, even when it reaches the tunnel session late.

If the elevated engine's own stop reply is lost and the helper cannot confirm
the stop either, the app records the lost reply. A later answer from the helper
alone, such as Retry cleanup on the launch screen, cannot show that the routes
were removed. When the helper then confirms that the engine is gone, the mark
becomes final: the app says that it did not see the route cleanup and offers no
retry. Only a later stop answer from the same elevated engine clears the lost
reply, because the engine refuses a stop while its own cleanup is uncertain.

Each mark keeps its own recovery text. A durable cleanup block says that this
preview has no approved way to clear it, and it never says that relaunching the
app clears it. A final route mark says to check for leftover routes and that
relaunching the app forgets the warning. A retryable mark offers Retry cleanup.

These lifecycle rules are hermetic tests with fake engines. No signed helper,
live XPC credential handoff, or live hotspot recovery path has been run.

The helper verifies the fixed right, writes a one-time grant into the root
engine's runtime directory, and the root engine consumes that grant before it
changes a route. While the tunnel runs, the app reads live status, logs,
diagnostics, and failures from the root engine. The user engine stays alive and
keeps the pairing. A confirmed stop returns the app to the user engine. A
cancelled or denied authorization starts no tunnel and stops the root engine.

On quit, the app stops the root engine and its helper session first, then the
user engine. If it cannot confirm the stop, it offers Stay or Quit Anyway
instead of reporting a clean stop. A quit can take about a minute while the
tunnel turns off.

## Protected helper boundary

Every tunnel start uses the protected helper. The helper must be
installed by a root package at
`/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper` with its launch
daemon file at
`/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist`. The helper, engine,
and app must carry one Developer ID team, use the hardened runtime, and carry no
`get-task-allow` entitlement.

The production policy verifies a separate root-owned helper and engine under
`/Library`; it does not use the app bundle in `/Applications` as the root code
source. The app is checked by its signature and the live XPC caller identity.
The package remains blocked pending a reviewed installation and upgrade
coordinator and signed-host validation.

The current engine and helper cleanup contract is also under repair: a zero
engine exit has not yet been shown to prove that every owned route was removed.
Direct starts do not yet have a durable start record. Do not interpret the
helper's normal-stop description below as proof that crash or cleanup recovery
is complete.

The app reads its own team from its signature, verifies the root-owned install
and the launch daemon, and pins the helper's code signature on the XPC
connection in the privileged system bootstrap. The helper checks the caller
again with the kernel audit token, not a PID, and requires a real login session.
Before the app asks for administrator authorization, the connection completes a
fresh, harmless handshake. The app sends one client nonce, the helper returns it
with one server nonce, and an authorization request must return that nonce. The
authorization form is never the first message on a connection. The app also
reads the helper status first, so a running tunnel, a durable cleanup block, or
an unreadable status fails before a person sees a prompt.

The helper starts one root-owned engine for one authenticated connection and
returns that engine's loopback port, per-launch secret, and session id in the
XPC reply. The handshake protocol version is 2. An older app or helper fails
closed at the handshake instead of running a mixed stop protocol. The app asks
for that start only when a person turns the tunnel on. The start request may
carry one pairing handoff descriptor. The helper passes the descriptor to the
engine and never reads it; a start without a descriptor is allowed for direct
mode. The engine start carries no administrator form. A tunnel start is a
separate `authorize` request on the same connection: the helper checks the right
and the form, then writes `tunnel-grant` into the engine's private runtime
directory. The engine reads and removes that file before a phone or direct
start. A grant is single use and expires after 60 seconds. A missing, stale,
malformed, symlinked, or wrongly owned grant is a refused start. A manually
started root GUI has no grant file and keeps the root command line as its
authority.

Closing the connection, a stop request, or a helper shutdown stops the engine.
A second connection is refused while one runs or while a stop is still in
progress. A cancel during a launch cannot interrupt the launch, but the caller
never receives the late engine and the helper stops it.

The start right `dev.hotspotshade.tunnel.start` must be added by the root
install. The helper reads the configured definition before every tunnel
authorization. It accepts the installed shape:
`class=user`, `group=admin`, `authenticate-user=true`, `shared=false`,
`allow-root=false`, and a positive `timeout` from 1 to 60 seconds, with an
optional `comment`. The shipped template uses 30 seconds. A zero timeout
stores no authorization credential, so the helper check a few milliseconds
after the administrator prompt is denied. The ceiling keeps a grant from
staying reusable for long. It also
accepts the metadata authd writes into the stored definition: `created` and
`modified` timestamps, `version`, `identifier`, `requirement`,
`session-owner=false`, and `tries` from 1 to 10000. Each has a fixed type and
value, and each metadata key is optional. `identifier` and `requirement` do not
grant access. A missing installed key, a zero or out-of-window timeout, an
`authenticate-admin` class, a delegated rule, a
root-permitting definition, a shared grant, `rule`, `mechanisms`, `k-of-n`,
`entitlement`, or any unknown key is refused. A missing right is not treated as
a safe default. An installed right with the old zero timeout is refused. The
older app and helper also refuse the new right, so update the app, helper,
engine, and right together; changing the right alone breaks the old preview.
The current helper starts the engine and shows the full interface even when the
right is stale, but every tunnel authorization is refused with the
right-not-configured message and no administrator prompt is shown. The older
helper still fails closed before it opens its listener.
These constraints come from read-only reads of built-in rights;
the custom right read-back and the live prompt are still unverified.

Before an engine can spawn, the helper creates a root-owned write-ahead intent at
`/var/db/hotspotshade/engine-session` and syncs the file and its directory. A
clean stop removes it. A helper crash, a `SIGKILL`, an unclean or timed-out
stop, an unprompted engine exit, or a failed intent clear leaves it in place, and
a restarted helper refuses every start until a person follows the recovery
steps. The intent holds no pid, so recovery never signals a reused pid.

A stop that times out, an engine that exits with a signal or a non-zero status,
an engine that exits before it reports its port, or an unreadable wait status is
not a clean stop. Each sets a durable root-owned marker at
`/var/db/hotspotshade/cleanup-blocked`, and every later start is refused. The
marker survives a helper restart and is never removed automatically. An engine
that exits on its own also sets the marker, keeps the launch intent, and the app
shows the cleanup message.

Recovery is an authorized human step. It requires a process check that no
engine remains, a check of the IPv4 and IPv6 routes and utun devices, and a
helper stop before the state files are removed. Restart the helper after
recovery and confirm that the app can start a tunnel. Do not flush routes,
delete the default route, or tear down an interface. Another VPN can use the
same `/1` or `utun` shapes. If any check is uncertain, stop and escalate. The
exact steps are in
[`Helper/README.md`](Helper/README.md#recovery-after-a-cleanup-block-or-leftover-intent).

The engine's port file is read through held descriptors under
`/var/db/hotspotshade`, with `openat`, `O_NOFOLLOW`, and an owner, mode, inode,
and device check. `/var/run` is not used because it is group-writable on macOS.
A stale `port.tmp` from an interrupted publish is removed with the private
runtime directory. The tunnel grant uses the same private directory: the helper
writes it as a 0600 root-owned file, and the engine checks the file, its
one-link inode, and the 0700 parent before it removes the file and starts.

There is no longer an `osascript` elevation path. A non-root macOS GUI returns
`protected_helper_required` for a phone start, and the Rust `--privileged-helper`
command fails closed. The app never runs a user-writable bundled engine with
administrator privileges.

An unsigned or ad-hoc build, or a machine without the root install, shows a
plain unavailable message at Turn on and starts no tunnel. The Dashboard,
pairing, status, and Settings still use the real user engine. The
source files and hermetic tests are in
`HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/`,
`HotspotShadeKit/Sources/HotspotShadeHelper/`, and `Helper/`.

This integration is compile-checked and unit-tested only. No Developer ID
certificate or root installation was used, so a signed helper launch, the XPC
peer check, the root engine spawn, the live administrator prompt at tunnel
start, the one-time grant, and the live route cleanup are untested. The
session-id stop confirmation and the non-owning reconnect refusal are hermetic
tests with a fake transport; no live helper has answered them. The change
that lets the helper start the engine without an administrator prompt moves the
authorization to the route-changing start; it needs an independent privilege
review and a live signed-host test before release. See
[`Helper/README.md`](Helper/README.md) for the exact blockers.

## No demo mode

The app has no demo mode, no launch argument or setting that selects one, and
no simulated data. Every visible control acts on the real engine. The engine
keeps a hidden `gui --demo` flag only as a CI test seam; the app never passes
it. If an engine answers with its test data anyway, for example a wrong binary,
the app treats it as an engine error. A launch fails with "The engine answered
with test data instead of real status." A running app shows "Status
unavailable" with the same sentence, keeps the last real status, disables Pair,
Forget, Turn on, and Turn off, and sends no notification for that data.

## The main window

The app has one main window. The sidebar has two pages and a Settings row:

| Row | Content |
|---|---|
| Dashboard | Status card, source device card, connection card, pairing view, and attention lines |
| Activity | The engine log. Details adds the level and the sequence number |
| Settings | Opens the standard Settings window |

Closing the window keeps the app and its menu bar item alive. The Dock icon
opens the same window again.

The Dashboard shows one state at a time. The title, the subtitle, and the action
come from one table. The app uses the engine message when the engine sends one.
An empty or unknown status shows a safe row. The app does not claim that the
tunnel is on when the engine does not report it.

The paired line is "Paired" or "Not paired". The connection card shows the
active connection count, the ping state, the last stop, and the time of the last
source device check.

The app shows "Starting the tunnel..." as soon as you press Turn on. A failed
start or stop stays on the screen with the Try again button. Try again repeats
the action that failed. A later status poll does not clear the message.

The Dashboard Refresh button shows a spinner in place of its symbol while it
works. The button keeps its size, so the toolbar does not move. The Activity
page uses the same Refresh button. Destructive actions use red text.

### Pairing view

The dashboard shows the pairing view while a pairing runs. It shows the code in
groups of three digits, for example `482 193`. It shows these steps:

1. Open HotspotShade on your source device.
2. Check that both screens show the same code.
3. Tap Allow on the source device.

The view has Copy code and Cancel. A code without a ready listener is stale, so
the app does not show a code that cannot work.

## Settings

Settings is a standard macOS Settings window with three tabs.

### General

- Launch at login. It needs a signed app.
- Let ping work. It applies the next time you turn the tunnel on.
- Notifications. The row says "Notifications are on.", "Notifications are asked
  for the first time you turn the tunnel on.", or the denied text below.

### Pairing

The tab shows the pairing state and the source device message. It has Pair, and
Cancel while a pairing runs. When a pairing is saved, it has Forget.

Forget is blocked while the tunnel runs. The text is "Turn off the tunnel to
forget this source device." The tab offers "Turn off and forget". That action
stops the tunnel, waits for the stop, then forgets.

### Advanced

- Recent failures. The table has Count, Kind, Target, Stage, and Reason. The Target
  cell shows details in a tooltip. It has Refresh and Copy report.
- Wi-Fi advice.
- App details. This section has Copy diagnostics.

## Menu bar menu

The menu bar item is a native menu, not a window or a popover. Its icon shows
the state: `network.slash` for off, `network` for on, `exclamationmark.triangle`
for attention, and `hourglass` for busy.

The menu has these rows in this order:

| Row | Shortcut | Notes |
|---|---|---|
| Status header | none | The current title, for example On, Ready, or Needs attention |
| Checked line | none | The status subtitle, or the last check time when the subtitle is empty |
| Turn on or Turn off | Command Return | One toggle row. The shortcut is present only when the action is enabled |
| Pair with source device | none | Present when pairing is possible |
| Cancel | none | Present while a pairing runs |
| Check now | Command R | Present when a probe is possible. The shortcut is present only when enabled |
| Notices | none | Up to 3 plain attention lines, including the last stop |
| Open HotspotShade | none | Opens the main window |
| Copy diagnostics | none | Writes the combined report to the pasteboard |
| Settings... | Command , | Opens the Settings window |
| Quit HotspotShade | Command Q | Stops the tunnel first. The row shows "Turning off..." and is disabled during the stop |

The app also has a Tunnel menu in the main menu bar. It has Refresh (Command R)
and the Turn on or Turn off row (Command Return). New Window is removed.

## Automatic pairing and sync

The app starts automatic pairing once for each launch when it is unpaired. It
tries again every 10 seconds while the source device is reachable. A successful
pairing replaces stale credentials. A failed attempt keeps them.

The app reads the engine status every second while the main window is visible,
and every 5 seconds while the window is hidden. Pairing polls every 700 ms.

The app probes the source device at once after a successful Pair, Check now,
and Forget.

### Cancel and Forget

Cancel stops automatic pairing for the current launch only. A new launch can
pair again.

Forget is an intent that the app saves in UserDefaults under `forgotIntent`.
After a Forget request, the app does not pair again until the person selects
Pair. The intent survives a restart. A token rejected at start also stops
automatic pairing until Pair.

The Forget states are:

| `forget.state` | Text |
|---|---|
| `none` | No message |
| `pending` | Forgetting... |
| `confirmed` | Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it. |
| `not_delivered` | Could not confirm that the source device removed this pairing. This target device forgot the pairing, but the source device may still trust it. |

A blocked Forget shows "Turn off the tunnel to forget this source device." and
the "Turn off and forget" action.

When the local pairing is gone and the source device still knows the target key,
the app shows "The source device still knows this target device. Press Pair to
continue." and the Pair action.

## Status freshness

The app shows the last screen when a status request fails.

- For the first 3 seconds the status stays fresh.
- After 3 seconds it is stale. The app adds "The engine did not answer. This
  status may be out of date."
- After 10 seconds it is unavailable. The main state becomes "Status
  unavailable", and the app does not claim On or Off. Turn on, Turn off,
  Pair, and Forget stay disabled. Check now is the action that can restore a
  live status.

The "Checked just now", "Checked N seconds ago", and "Checked N minutes ago"
text comes from the engine `phone.checked_at` value. The text is absent when the
engine has no value. An old value does not start the source device warning. The
engine reports `checking` until a fresh probe answers, and the app does not
claim that the source device failed from data that the engine marks as old.

### Interrupted service state

The engine can answer a status request with HTTP 200 and a conservative guard
shape: `running` is true, `state` is `"unknown"`, and `cleanup_blocked` is true.
In that shape `running` is not evidence that a tunnel is on.

The app shows "Status unknown" with this fixed text:

> The service state is unavailable after an interrupted operation. Inspect
> routes, devices, and the start record before restarting.

The tunnel and source device cards show "Unknown", not "Tunnel off" or "Not
paired". Turn on, Turn off, Pair, and Forget stay disabled, and Check now is the
only action. The app does not start, stop, pair, forget, read failures, or send
an automatic-stop or source device notification from this state.

A status with `cleanup_blocked` true and `running` false is a known stopped
tunnel whose cleanup did not finish. The app shows "Tunnel cleanup did not
finish" with the same recovery text, keeps the last stop line, and keeps a new
start disabled.

An older engine sends no `state` and no `cleanup_blocked`. The app then keeps
the old meaning of `running`, so a normal old-format status still shows On,
Ready, or the source device row.

### Attention lines

The Dashboard and the menu bar menu can show these plain lines:

| Condition | Text |
|---|---|
| The source device does not answer for 10 seconds while the tunnel runs | "The source device stopped answering. New connections fail." |
| The source device forgot this target device while the tunnel runs | "The source device forgot this target device. The tunnel keeps running until you turn it off." |
| The status is older than 3 seconds | "The engine did not answer. This status may be out of date." |
| Notification permission is denied | "Notifications are off. You will not see a message when the tunnel turns off." |
| The Wi-Fi link is 2.4 GHz | The 2.4 GHz advice text below |
| The Wi-Fi signal is weak | The weak signal advice text below |
| Forget is blocked by a running tunnel | "Turn off the tunnel to forget this source device." |

The menu shows at most 3 notices. The last stop line can also appear as a notice.

## Notifications

The app asks for notification permission once, at the first tunnel start, and
only when macOS has not answered yet. The request runs in the background. The tunnel start
does not wait for the answer. If the alert gets no answer, the start still
continues. The app does not ask again after a denial.

The policy sends at most one message of each kind in 60 seconds. It sends no
message for a user stop. It sends no source device, pairing, or error message
while the app is frontmost. The automatic stop message is also sent while the
app is frontmost. A healthy status removes a delivered warning.

| Kind | Title | Body |
|---|---|---|
| Automatic stop, hotspot | HotspotShade | "The hotspot turned off, so HotspotShade turned the tunnel off." |
| Automatic stop, source device | HotspotShade | "The source device stopped answering, so HotspotShade turned the tunnel off." |
| Source device stopped | HotspotShade | "The source device stopped answering. New connections fail." |
| Pairing needs attention | HotspotShade | "Check the code on your source device." |
| Tunnel error | HotspotShade | The engine error text, or "Needs attention" |

The engine supplies the automatic stop message when it has one. The app replaces
the retired product name in engine text.

When macOS denies permission, Settings shows "Notifications are off. You will
not see a message when the tunnel turns off." and an Open System Settings
button.

## Wi-Fi advice

The app reads the Wi-Fi band, channel width, signal, and interface at most once
every 10 seconds while the window is visible. It never reads the network name
and never asks for location permission. The advice applies only when the tunnel
runs and its pinned interface is the Wi-Fi interface.

| Condition | Text |
|---|---|
| 2.4 GHz | "This connection uses 2.4 GHz Wi-Fi, which is slower and less steady. On your source device, turn off Maximize Compatibility in the Personal Hotspot settings, or use a cable." |
| Signal below -75 dBm | "The Wi-Fi signal is weak. Move the target device closer to the source device." |

Turn off Maximize Compatibility on the source device to allow 5 GHz.

## Recent failures

The engine keeps a short record of failed source device connection attempts.
Open Settings, Advanced, "Recent failures". Select Refresh to load the list.
Select "Copy report" to copy the groups as text.

The panel shows up to 50 groups. The table has Count, Kind, Target, Stage, and Reason.
The Target cell shows details in a tooltip. The report holds one header line and
one line per group. It uses the
engine data. The record stays in target device memory. It is never written to
disk and never sent to the source device. It is cleared when the tunnel starts or
stops. The panel shows "Turn the tunnel on to see failures." while the tunnel is
off.

The engine reports groups as `tcp`, `udp`, or `dns`, with an `ipv4` or `ipv6`
family, a port, a reason, a count, an optional name, an example address, and an
optional SOCKS reply code. The names come from DNS answers that the relay sees.
The app does not invent a name.

## Copy diagnostics

Copy diagnostics is in the menu bar menu and in Settings, Advanced. It writes
one plain-text report to the pasteboard. The report holds:

- The line "HotspotShade diagnostics"
- The time in UTC
- The macOS version and the app version
- The Wi-Fi band, channel width, signal, and interface, or "unavailable"
- The ping state
- The last stop: reason, time, and message, or "none"
- The notification permission: allowed, denied, or not asked
- The engine version, uptime, and worker count, or "unavailable"
- The setup times for connect, greeting, auth, and request
- The DNS counts and time
- The input and output queue peaks and oldest packet ages
- The UDP flow and age-drop counts
- The TCP peak flow, retransmit, and zero-window values
- The recent local relay timeline when the engine provides it. It reports
  observation gaps and local events. It does not measure end-to-end loss.
- The failure report, or "unavailable"

The failure report can hold example destination addresses and names, as the
Recent failures panel does. The report holds no token and no pairing code.

## Ping

"Let ping work" is on by default. Find it in Settings, General. The setting
applies the next time you turn the tunnel on. While the tunnel runs, the
connection card shows "Ping is on." or "Ping is off." from the engine status.

The echo path is experimental. It uses the source device cellular path only. It
allows 8 outstanding echoes. Traceroute and path-MTU discovery are not
supported. The reply that the app receives always has TTL 64, or hop limit 64
for IPv6. The source device connection counters do not count ICMP.

If ping does not answer, check the setting, then turn the tunnel off and on.
Also check that the source device has a working cellular path. A tunnel that
turned itself off does not answer ping.

## Previews and development

The Swift package has Xcode previews for every dashboard state, the pairing
states, the Settings tabs, the activity states, the failures table, the menu bar
menu states. The previews use `PreviewData`, so they need no engine, no
network, and no route.

The Swift package tests use fakes for the HTTP backend, the notification sink,
the pasteboard, the Wi-Fi link, and the clock. Run them with:

```sh
swift test --package-path macos/HotspotShadeKit
```

The `macos-app` CI job builds the engine, runs the package tests, and builds
the unsigned app bundle. With `HS_TEST_DEMO_BINARY` set, three engine contract
tests start the real engine through a test-only wrapper that adds `--demo`.
They check the status and failure fields and that the app refuses that engine.
`scripts/macos_unprivileged_engine_test.sh` runs the real engine as a normal
user in a loopback-only sandbox. It uploads `HotspotShade-macos-unsigned`.
