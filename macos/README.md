# HotspotShade for macOS

HotspotShade on the target device contains the Rust engine. Open HotspotShade on
your source device. Pair the source device in HotspotShade on your target
device.

Run `scripts/build_mac_app.sh build/HotspotShade-unsigned.zip` from the
repository root. The script builds the engine and the app for the host
architecture. On arm64 it uses the `aarch64-apple-darwin` Rust target. On Intel
it uses `x86_64-apple-darwin`. Install the matching Rust target before the
build. Set `CARGO_TARGET_DIR` to select the Rust build directory. Set
`HS_MAC_DERIVED_DATA` to select the app build directory. A build without the
script does not include the engine.

The bundle has an ad-hoc signature. Unzip the app and move it to Applications.
Right-click the app and select Open for the first launch. The release app runs
on arm64 target devices only.

To use a real signing identity, sign the nested engine first. Sign the app next:

```sh
codesign --force --sign "<identity>" HotspotShade.app/Contents/Resources/bin/hotspotshade
codesign --force --deep --sign "<identity>" HotspotShade.app
codesign --verify --deep --strict HotspotShade.app
```

The app starts the bundled engine as a child process. The engine listens on
loopback only. The app sends a new secret on a private pipe for each launch. The
engine shows the administrator prompt when the tunnel starts. The app stops the
engine on quit. A quit can take about a minute while the tunnel turns off.

## Demo mode

Start the app with `--demo`, or set `HS_DEMO=1` in the environment. The app
starts its own engine with `--demo`. The data is simulated. It creates no route
and no tunnel device. The Dashboard and Settings label the data as simulated.
Restart the app to change demo mode.

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
| `confirmed` | Forgotten. The source device removed this target device. |
| `not_delivered` | The source device did not answer. This target device forgot the pairing, but the source device may still trust it. |

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
  unavailable", and the app does not claim On or Off.

The "Checked just now", "Checked N seconds ago", and "Checked N minutes ago"
text comes from the engine `phone.checked_at` value. The text is absent when the
engine has no value. An old value does not start the source device warning. The
engine reports `checking` until a fresh probe answers, and the app does not
claim that the source device failed from data that the engine marks as old.

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

The app asks for notification permission once, at the first Start, and only when
macOS has not answered yet. The request runs in the background. The tunnel start
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
menu states, and the demo banner. The previews use `PreviewData`, so they need no
engine, no network, and no route.

The Swift package tests use fakes for the HTTP backend, the notification sink,
the pasteboard, the Wi-Fi link, and the clock. Run them with:

```sh
swift test --package-path macos/HotspotShadeKit
```

The `macos-app` CI job builds the demo engine, runs the package tests, and builds
the unsigned app bundle. It uploads `HotspotShade-macos-unsigned`.
