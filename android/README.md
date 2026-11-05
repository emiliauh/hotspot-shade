# HotspotShade for Android, source device app

This directory holds the Android source device app. It has three parts:

- The app UI. It controls the real source proxy and the real pairing listener.
  It shows the real proxy state, the real connection counts, the real trusted
  target list, and the real token rotation action.
- A source proxy foreground service with a hotspot address finder, a cellular
  network selection, remote name resolution, IPv6 forwarding, an ICMP echo
  path, and the SOCKS5 server.
- A pairing responder and listener with the same protocol as the Rust target
  device and the iOS source app.

The app UI starts and stops the proxy service. The Start control asks for the
notification permission on Android 13 or later. The Dashboard shows the real
state from the controller. The Settings page shows the real pairing listener,
the real trusted targets, and the real token rotation action.

The app has a separate preview mode. Preview mode shows simulated states for
layout and motion comparison with the iOS app. A banner and a badge label the
simulated values. Preview mode does not change the real proxy, the trust list,
or the token. The real pairing prompt and the simulated preview prompt are
separate. The app does not implement the Android target tunnel.

## Source proxy service

`SourceProxyService` is a foreground service of type `specialUse`. It has a
notification channel and one persistent notification that says what the proxy
does. The notification has an explicit Stop action. The service is not
exported.

The Dashboard Start control calls `SourceProxyService.start`. The Stop control
calls `SourceProxyService.stop`. On Android 13 or later the first Start asks for
the `POST_NOTIFICATIONS` permission. A denied permission does not stop the
proxy. Android hides the notification, and the Settings page offers a link to
the notification settings. The service uses `START_NOT_STICKY` and never starts
itself again.

The service reports each state change to `SourceProxyRuntime`. The app reads
that report every second while it is visible. The report holds the state, the
plain stop reason, the bound port, the open relay count, the relay count since
the start, and the stop time. It holds no token, address, or host. The Dashboard
shows these states:

- `Starting`: the service accepted the start request.
- `Waiting for the hotspot`: the controller found no hotspot address. The run
  ended. The person turns on the hotspot and taps Start again.
- `Waiting for the cellular network`: the hotspot is ready and the controller
  waits for one eligible cellular network.
- `On`: the listener serves the hotspot address.
- `Pair first`: the source token is missing. The person pairs a target device,
  then starts again.
- `Off` or `Needs attention` with a plain stop reason.

`SourceSocksServer` exposes `activeConnections` and `totalConnections`. The
values are counts only. They hold no address, host, or port. The app shows them
in the Dashboard and in Advanced. The authenticated status answer also reports
the open count to a paired target device.

The server also serves the private ICMP echo commands of the source device
protocol and forwards IPv6 destinations. The relay cap follows the open-file
limit of the app process. The open-file limit is read at each start. A start
with an unreadable or too low limit stops with `START_FAILED`.

The service does one run:

1. It checks that a hotspot address exists. If no address exists, it shows
   "Hotspot not found. Turn on the hotspot and start again." and stops. It
   does not start the listener.
2. It reads the source token from `TokenStore`. If no token is stored, it
   shows "No source token is stored. Pair a target device first." and stops.
3. It waits for one eligible cellular network. The selection needs a cellular
   transport, internet access, and no VPN.
4. It binds `SourceSocksServer` to the hotspot address only. It never binds
   `0.0.0.0`. The server accepts the SOCKS5 contract from the iOS source proxy.
5. It shows a running notification. The notification has no address, no port,
   and no token.
6. It stops on the first of these events: Stop, cellular network loss,
   capability loss, or hotspot loss. It closes the listener, the flows, and the
   network request. It returns `START_NOT_STICKY` and never starts itself again.

The service passes the selected `Network` to `NetworkResolver`, which calls
`Network.getAllByName()` on that network only. It never uses the process
default resolver. A later change can move the Network into `CellularBinding`
and remove `AndroidSourceCellularSelection`, which repeats the eligibility
rules of `AndroidCellularNetworkSelection` to keep that handle.

`AndroidKeystoreTokenStore` writes an AES-GCM ciphertext into one app-private
file. The AES key stays in the Android Keystore. The store is a placeholder for
`EncryptedSharedPreferences`; see the TODO in `TokenStore.kt`. A successful
pairing writes a token through `TokenWriter`, so a production start finds it.
If no token exists before a start and no pairing has run, the start still stops
with `TOKEN_MISSING`. The instrumented service test injects a fixed test token
in memory.

The service and the controller do not log the token, a local address, or a
host name. The status reports hold a state, a reason code, and a port.

## Pairing

`PairingResponder` implements the source device side of protocol v1 in Kotlin.
It has the same wire format, key schedule, labels, limits, and fixed parity
vectors as `rust/src/source_pairing.rs` and `ios/HotspotProxy/Pairing.swift`.
The three implementations must change together.

The wire format uses:
- a two-byte big-endian frame length and a 512-byte payload limit;
- HELLO, CHALLENGE, REVEAL, and RESULT messages;
- the status, forget, and challenge labels from protocol v1;
- X25519, HKDF-SHA256, HMAC-SHA256, and ChaCha20-Poly1305.

Android API 26 has no platform X25519 key agreement and no
ChaCha20-Poly1305 cipher. The app therefore has a small in-tree implementation:
- `X25519.kt` is a Kotlin port of the public-domain TweetNaCl scalar
  multiplication.
- `ChaCha20Poly1305.kt` is a Kotlin port of the RFC 8439 functions.
- `Hkdf.kt` uses the platform HMAC-SHA256.

The project adds no dependency. The JVM tests hold the RFC 7748, RFC 8439, and
RFC 5869 vectors, and the fixed pairing parity vectors.

`PairingServer` binds the hotspot address and TCP port 18090. It never binds
`0.0.0.0`. It accepts at most eight sockets and the responder allows four
sessions. It closes a connection after a rejection, a timeout, or a completed
status or forget request. A successful result keeps the connection for one
authenticated status request until the five-second deadline. The listener uses
a daemon accept thread, a bounded daemon connection pool, and one timer thread.

`PairingViewModel` starts the listener when the activity starts and stops it
when the activity stops. A hotspot change closes the old listener and binds the
new address. The listener does not run while the activity is not visible.

A real request shows an Allow or Deny dialog with the six-digit code. The text
says "Real pairing request". The preview dialog keeps the "simulated" label.
The settings page shows the real listener state and the real trusted target
list. The preview pairing states are in the preview controls.

A request that arrives while the activity is not visible posts a notification.
The notification holds no code, key, address, or token. The person must open the
app to see the code and choose Allow or Deny. The app never approves a request
from a notification. The listener stops when the activity stops, so a request
cannot arrive while the app is fully in the background. This is a limit of the
foreground-only listener.

The Settings page lists each trusted target device with a short public label.
The label is the first four bytes of the SHA-256 digest of the stored public
key. It does not show the key. Each row has a Forget action. "Forget all target
devices" removes every trusted key. A forgotten target device keeps its copy
until it contacts the source device again, and it must pair again.

The "Rotate source token" action writes a new random 32-byte token to the
`AndroidKeystoreTokenStore` and reloads the pairing listener. The action is
refused while the proxy is active. Rotation does not remove trust: a known
target device can pair again without a new prompt. Every paired target device
must pair again before it can use the new token.

The responder applies these limits:
- four unknown challenges from one source address in 60 seconds;
- eight unknown challenges in total in 60 seconds;
- both budgets are charged before the ephemeral key is created, and only when
  the source device has pairing credentials;
- a trusted key skips the challenge budgets;
- an approval must name the connection, the prompt ID, the code, and a live
  deadline;
- three denials in 60 seconds lock that source address for 30 seconds;
- a hidden app can extend one live prompt by at most 120 seconds from the first
  hidden notice.

A successful pairing saves the proxy token with `TokenWriter`. The production
store is the same `AndroidKeystoreTokenStore` that the proxy reads. A start
after a pairing therefore finds a token instead of `TOKEN_MISSING`. If no token
exists, the app generates a 32-byte random token and holds it in memory until
the pairing succeeds.

`ProxyPortPolicy` picks and saves a free proxy port from 20000 to 59999. It
never picks 18090. The pairing result names the hotspot address and this port.
The source proxy service binds the same port. A bind failure clears the saved
port, and the next start chooses a new port. A paired target device learns the
new port from an authenticated status answer.

Target-device public keys are stored in SharedPreferences as base64 strings.
They are public values. The token is not in SharedPreferences.

## Foundations

`CellularSockets` prepares unconnected TCP and UDP sockets for a selected
Android cellular network. It checks that the network has cellular and internet
capabilities and is not a VPN, binds each socket, and checks the network again.
A failed check or bind closes the socket. JVM tests use a fake binding. The
reported transport capabilities alone do not prove the physical carrier path.

`CellularSession` tracks up to 288 sockets, including sockets still binding.
Closing a session closes its tracked sockets and prevents new flows. The
service closes the session on stop or network loss. A socket close failure is
reported and retried when the service stops. Closing a socket does not
guarantee that a blocked platform bind returns. The service reports the stop at
once; a blocked platform bind still needs a real-device test.

`SourceSocksServer` implements the source device SOCKS5 contract: password
authentication with the `hotspotshade` user, TCP CONNECT, the UDP-over-TCP
command, and the two private echo commands, with the same reply codes as the
iOS app. It takes every outer socket from `CellularSession` and resolves names
only through an injected resolver.

A TCP CONNECT and a UDP associate flow accept an IPv4 literal, an IPv6 literal,
or a domain name. A domain name goes through `NetworkResolver` on the selected
cellular network only. The destination rules and the reply codes are the same
for both families.

The server applies the phase rule in `SourceSocksCapacity`, which follows
`ios/HotspotProxy/SessionCapacity.swift`:

| Phase | Bound |
|---|---|
| Handshake | 30 seconds |
| Destination connect | 8 seconds (the connect itself has a 4 second socket deadline) |
| Relay slot request | 2 seconds |
| UDP flow | 300 second idle window |
| Half-closed TCP flow | 300 second idle window |
| Open TCP relay | No bound. Silence never closes it. |

The relay cap follows the open-file limit. The server reads
`/proc/self/limits` at start. The total is `min(288, (soft limit - 32) / 9)`.
The setup reserve is `ceil(total / 9)`, capped at 32. The relay cap is the
total minus the reserve. The Android default of 32768 open files gives 256
relays and 32 setup sessions. A limit of 1024 gives 97 relays and 13 setup
sessions.

A new connection beyond the total cap closes the most overdue stale session
first. It closes the client before the greeting when no session is stale. A
relay request beyond the relay cap closes only a stale UDP or half-closed
session. It never closes an open TCP relay. It refuses with code 1 when no
relay phase is stale.

The client and destination TCP sockets set no-delay and keepalive. Android
applies its system keepalive values. The app cannot set the iOS 60 second idle,
10 second interval, and 3 probe values through the Java socket API.

### ICMP echo

`SourceSocksServer` serves the private echo commands of the source device
protocol. The wire format matches `ios/HotspotProxy/CellularICMPEcho.swift` and
`rust/src/relay.rs`:

- Command `0x81` sends one echo. After the success reply the client sends a
  two-byte payload length and the payload. The server sends one status frame
  and closes.
- Command `0x82` keeps one echo session open. Each frame holds a two-byte
  payload length and the payload. The server answers each frame with one status
  frame.
- A request has a 5 second bound. A persistent session has a 30 second idle
  window and a 300 second lifetime.
- The server grants at most 16 persistent echo sessions. It refuses the next
  session with code 1.
- Only numeric unicast targets are accepted. Port zero is reserved for echo.
  An IPv4 loopback, unspecified, link local, multicast, or reserved address is
  rejected. An IPv6 loopback, unspecified, link local, multicast, or
  IPv4-mapped address is rejected. A rejected target gets code 8.
- An echo session holds no relay slot. The connection counters do not count it.

`AndroidNetworkEcho` uses an unprivileged ICMP datagram socket: `AF_INET` or
`AF_INET6` with `SOCK_DGRAM` and `IPPROTO_ICMP` or `IPPROTO_ICMPV6`. It binds
the socket to the selected `Network` before the connect. The socket waits with
`Os.poll`, so the timeout works on Android 8.0 and later. The sender sets a 16
byte nonce and a random sequence number. It validates the reply type, code,
sequence, nonce, and IPv4 checksum. At most 8 echo attempts run at one time.

The status values match iOS:

| Status | Meaning |
|---|---|
| 0 | Success. The payload follows. |
| 1 | No cellular network. |
| 2 | All 8 echo attempts are busy. |
| 3 | The echo timed out. |
| 4 | The echo failed. |
| 5 | The path did not report an update. |
| 6 | The path is not satisfied. Android uses it when the network cannot bind the socket. |
| 7 | The path is not cellular. |
| 8 | No cellular interface was found. |
| 9 | More than one cellular interface was found. |

Android has no iOS path monitor. The server returns 3, 4, or 6 for the
conditions that iOS reports as 1, 5, 7, 8, or 9. The reply codes are unchanged.

The echo path has no TTL control. The kernel default applies to the echo
request. The target device builds its inner reply with TTL 64. This matches the
documented iOS behavior.

A device whose kernel or security policy refuses an ICMP datagram socket
returns status 4 for every echo request. The app cannot detect this before the
first request. The Pixel 8 API 36 emulator permits the socket. A real phone
test is needed.

### IPv6 forwarding

A TCP CONNECT and a UDP associate flow accept an IPv6 literal or a domain name
that resolves to an IPv6 address. The destination socket comes from
`CellularSession`, so it is bound to the selected cellular network. A domain
name is resolved through `NetworkResolver` on that network only. The reply
codes and the destination rules are the same as for IPv4.

The source device proxy forwards IPv6 by product decision. It does not filter
an IPv6 destination. The target device keeps its own IPv6 policy in direct
mode.

The emulator has no IPv6 route on its cellular interface. The interop test
serves an IPv6 echo listener on the emulator loopback `::1` and connects to it
through the source server. That proves the IPv6 parse, socket, and relay path.
It does not prove a live IPv6 carrier path. When the emulator cannot bind the
`::1` listener, the test reports port 0 and the host test skips the case with a
message. It never fakes a reply.

`CellularNetworkMonitor` selects one eligible cellular network through a small
`CellularNetworkSelection` interface. The Android adapter uses
`ConnectivityManager.requestNetwork`. On network loss or capability loss the
monitor closes the existing `CellularSession`, releases the request, and never
opens another session. The service creates a new monitor for a new start.

`HotspotAddressFinder` reads the interface list through `NetworkInterface`. It
skips loopback, down, cellular, VPN, and excluded interfaces. It accepts a
private IPv4 address. A named tethering interface (`swlan*`, `ap*`, `softap*`,
`wlan*`, `rndis*`, `bt-pan*`) wins over a generic private interface. When both
a Wi-Fi access point and USB tethering are up, the Wi-Fi access point wins. The
caller excludes the cellular and Wi-Fi client interface names from
`ConnectivityManager`. A fake interface source drives the JVM tests.

`SourceProxyController` holds the state machine: start, wait for the network,
run, stop. It reports `HOTSPOT_NOT_FOUND`, `TOKEN_MISSING`, `BIND_FAILED`,
`START_FAILED`, `NETWORK_LOST`, `CAPABILITIES_LOST`, `NETWORK_UNAVAILABLE`,
`HOTSPOT_LOST`, or `USER_STOP`. A stopped controller refuses a restart. A late
network callback or hotspot callback never starts a second run.

## What the app contains

- Dashboard: one real status header, one primary action, the real usage card,
  the keep-awake card, and the last-stop card. The Start and Stop control
  starts and stops the real foreground service. The status text comes from the
  controller. The usage card shows the real trusted count and the real
  connection counts.
- Settings: background, notifications, the real pairing listener, the real
  paired target devices, Advanced, and Preview. Advanced holds the real state,
  the real port, the real connection counts, token rotation, diagnostics, and
  the version. The Preview group turns preview mode on and opens the preview
  controls.
- Recent activity: a preview sheet with Activity and Details views. It has
  loading, empty, and filled states. It is available in preview mode only.
- Pairing: a real Allow or Deny dialog with a six digit code and a "Real
  pairing request" label. The preview dialog has a separate simulated-data
  label.
- Preview controls: a preview mode switch, proxy state, pairing state, last
  stop, notification state, simulated Location off, activity samples, theme,
  reduce motion, a state animation, and reset. The state controls are disabled
  while preview mode is off.
- Semantic light and dark themes. The system theme is the default. The preview
  controls can force Light or Dark.
- Animation for tab changes, status changes, the button, expanding rows, the
  token block, the activity sheet, and the starting status mark.
- Reduced motion from the Android animator scale and from the preview switch.
- TalkBack labels, live status announcements, headings, 48 dp actions, and
  scrolling for small screens and large text.

Preview mode shows a persistent banner and a PREVIEW badge on the status card.
The banner opens the preview controls. Numbers in the preview usage card start
with "Simulated sample:". The preview token is a fixed demo value. Preview copy
actions copy the preview value locally. The real Dashboard has no preview
banner.

## Build

Use JDK 17 or later and Android SDK platform 36. The build uses the Gradle
wrapper and downloads its dependencies from the official Google and Maven
Central repositories.

```sh
cd android
./gradlew assembleDebug
```

The APK is at `app/build/outputs/apk/debug/app-debug.apk`. The earlier copy for
this preview is at the repository root:
`build/HotspotShade-Android-demo.apk`. The corrected ledger build is at
`build/HotspotShade-Android-demo-v2.apk`. Both are signed with the standard
Android debug key from the build host. The key is not in this repository.
Install one on a test device or a disposable emulator:

```sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The APK carries the small AndroidX native path library for four ABIs, so the
same file installs on arm64 and x86_64 devices. The demo code has no native
library of its own. Android 8.0 (API 26) is the minimum version.

## Test

The JVM tests do not open a screen and they need no device.

```sh
cd android
./gradlew testDebugUnitTest
```

The suite has 217 tests. The preview tests cover the pairing display,
Dashboard texts, start and stop transitions, pairing allow and deny, forget,
port rules, token expiry, the activity cap, the simulated connection ledger,
simulated labels, diagnostics, reset, notification text, preview mode, and the
preview state controls. The source tests cover the cellular socket and
session boundaries, the network monitor, the SOCKS5 contract and its
connection counters, the hotspot address finder, the hotspot watch, the network
resolver, the service state machine and its counter read-back, the proxy port
policy, the coordinator token save, the real proxy state display, the status
map, the trust fingerprints, Forget one and Forget all, and token rotation. The
pairing tests cover the RFC 7748, RFC 8439, and RFC 5869 vectors, the fixed
parity vectors, the state machine budgets and binding, the loopback listener,
and the token save after a successful pairing.

The capacity tests cover the six phases, the setup and relay split, the phase
bounds, the stale session selection, the protected session rule, the open TCP
relay rule, the idle action, the open-file limit math, and the capacity
warning. The echo tests cover the wire targets, the IPv4 checksum, the reply
validation with and without the IP header, the nonce and sequence checks, the
one-shot and persistent commands, the 16 session cap, the request, idle, and
lifetime bounds, and the payload limit. The server tests also cover the IPv6
UDP associate round trip, an IPv6 domain resolved by the injected resolver, an
open TCP relay that stays open for silence, a UDP flow that closes at the idle
bound, a half-closed flow that closes at the idle bound, a stale handshake
closed for a new connection, and the relay cap from the open-file limit.

The real state tests cover the plain titles and messages for Starting, Waiting
for the hotspot, Waiting for the cellular network, On, Off, Needs attention, and
Pair first. They cover the real connection lines and the diagnostics report.
The trust tests cover the short public label, Forget one, Forget all, and the
token rotation policy. The rotation tests hold the write, the refusal while the
proxy runs, and the failed write.

The pairing tests cover the per-address challenge budget, the global challenge
budget, the budget charge before key generation, the pairing-off path, the
canonical peer keys, the decision binding, the hidden-prompt extension cap, the
known target path, forget, the lockout, the session cap, and the redacted text.
They use fixed public keys and nonces.

The service state machine tests cover start, hotspot missing before and after
the network arrives, network loss, capability loss, network unavailable, user
stop, double start, restart refusal, late callbacks after stop, hotspot loss,
token missing, bind failure, resolver failure, watch failure, and a snapshot
with no token or address.

The `android-demo` CI job runs the JVM tests, lint, and a debug build. It does
not run an emulator or compare screenshots. CI does not publish the debug key.

Run lint with:

```sh
cd android
./gradlew lintDebug
```

On 2026-11-05, Android Lint reported 0 errors and 7 warnings. Every warning
reports a newer available Gradle or AndroidX version.

## Emulator interop test

Three instrumented test classes exist. An emulator loopback does not prove
carrier, hotspot, or physical-device behavior.

`SourceSocksInteropTest` runs `SourceSocksServer` on the emulator loopback with
a no-op network binding and a failing resolver. It binds `127.0.0.1` on port 0.
It prints the bound port, the relay limit, and the IPv6 loopback echo port with
the `HS_INTEROP` log tag. It stops after 120 seconds or when the host creates
`files/hs-interop-stop`.

The served server uses the real `AndroidNetworkEcho` on the emulator default
network. It also serves a TCP echo listener on `::1` for the IPv6 destination
case. The second test method `echoToTheEmulatorHost` sends one echo request
directly and checks the returned payload. A device that refuses the ICMP
datagram socket reports the status and skips the method. The Rust test
`rust/tests/android_emulator_interop.rs` connects through `adb forward`.

`PairingInteropTest` runs the real `PairingServer` and `PairingResponder` on
the emulator loopback. It uses a fixed public test token and a fixed proxy
port. The test approves each prompt automatically, because no person taps the
emulator during the run. The real Rust target client
`rust/tests/android_pairing_interop.rs` completes two pairings through
`adb forward`: one unknown target with a prompt, and one known target without a
prompt. The test logs only the bridge port and counts with the
`HS_PAIRING_INTEROP` tag.

`SourceProxyServiceInstrumentedTest` starts the real service. It uses these
test-only substitutions:

- The emulator's own address `10.0.2.15` is the mimicked hotspot address.
- The emulator default network is the mimicked cellular network, injected
  through a test-only `CellularNetworkSelection`.
- The source token is a fixed test value in memory. It is not a secret and it
  is not written to storage or a log.
- The service logs only the bridge port with the `HS_SERVICE_INTEROP` tag.

The test adds a loopback bridge. `adb forward` connects to the emulator
loopback, while the service binds the hotspot address only. The bridge forwards
each loopback connection to `10.0.2.15` and the bound port. The bridge exists in
the test APK only. It is not part of the app.

The test methods are:

- `serviceServesTheSocksContractOnTheMimickedHotspotAddress`: start the
  service, wait for the running state, send a second start request, check that
  one run continues and the running notification text stays correct, serve
  until the host creates `files/hs-service-interop-stop`, then stop with the
  Stop action.
- `networkLossStopsTheServiceWithoutARestart`: start the service, report a
  network loss, check the `NETWORK_LOST` state, and check that the service stays
  stopped after 2 seconds.
- `runtimeObservationReportsRunningStateAndRealConnectionCount`: start the
  service, check the running report, open one authenticated TCP flow to a
  test echo server, check that the open count becomes 1 and the total becomes
  1, close the flow, and check that the open count returns to 0.
- `sharedPreferencesTrustStoreForgetsOneAndAll`: add two fixed public keys to a
  test preferences file, list the targets, forget one, and forget all.
- `pairingAdminRotatesTheRealTokenFile`: write a fixed token with the real
  Android Keystore store, rotate it through `PairingAdmin`, and check the new
  value.
- `keystoreTokenStoreRoundTrip`: save, load, and clear a fixed test token with
  the real Android Keystore store.
- `networkResolverResolvesOnTheDefaultNetwork`: check one lookup on the
  emulator default network.

Build and install both APKs:

```sh
cd android
./gradlew assembleDebug assembleDebugAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
```

A fresh install has no notification permission. The test grants the permission
through UiAutomation. If the emulator cannot complete that grant, grant it
first:

```sh
adb shell pm grant com.hotspotshade.demo android.permission.POST_NOTIFICATIONS
```

Start the service test in the background and read the bridge port:

```sh
adb logcat -c
adb shell am instrument -w \
  -e class 'com.hotspotshade.source.SourceProxyServiceInstrumentedTest#serviceServesTheSocksContractOnTheMimickedHotspotAddress' \
  com.hotspotshade.demo.test/androidx.test.runner.AndroidJUnitRunner &
adb logcat -d -s HS_SERVICE_INTEROP:I
```

Forward a free host port to the emulator bridge port. Replace `41117` with the
logged port and `18080` with a free host port:

```sh
adb forward tcp:18080 tcp:41117
```

Run the Rust test from the repository root:

```sh
HS_EMULATOR_PORT=18080 cargo test --locked \
  --manifest-path rust/Cargo.toml --test android_emulator_interop -- --ignored
```

End the instrumented test and remove the forward:

```sh
adb shell run-as com.hotspotshade.demo touch files/hs-service-interop-stop
adb forward --remove tcp:18080
```

On 2026-11-04, on the Pixel 8 API 36 emulator, all four service tests passed.
The Rust interop test passed with the real service: the correct token was
accepted, a 64 KiB echo through a TCP CONNECT to `10.0.2.2` returned every
byte, a wrong token was rejected, and an unreachable destination failed inside
the bound. The Rust audit counted 4 outer sockets and 0 TTL failures. The
service ran as a `specialUse` foreground service with the `source_proxy`
notification channel. A second start request kept one run and the running
notification text. The test used the emulator default network, not a
cellular bearer. A real phone and a real hotspot test are still needed.

On 2026-11-05, on the same emulator, the 6 service test methods passed. The
serving method passed after `adb shell pm grant` supplied the notification
permission. Without the permission the first run failed the running
notification check, because the UiAutomation grant did not complete. The test
runner still crashed at teardown after the result, as the roadmap records.

### SOCKS and echo interop

Build and install both APKs, then start the serving test in the background:

```sh
adb logcat -c
adb shell am instrument -w \
  -e class 'com.hotspotshade.source.SourceSocksInteropTest#serveUntilStopFileOrTimeout' \
  com.hotspotshade.demo.test/androidx.test.runner.AndroidJUnitRunner &
adb logcat -d -s HS_INTEROP:I
```

The log shows the file limit, the relay limit, the IPv6 echo port, and the SOCKS
port:

```
HS_INTEROP: file limit=32768
HS_INTEROP: relay limit=256 total=288
HS_INTEROP: ipv6 echo port=41537
HS_INTEROP: listening port=47245
```

Forward a free host port to the SOCKS port. Replace `47245` with the logged
port and `18080` with a free host port:

```sh
adb forward tcp:18080 tcp:47245
```

Run the Rust test from the repository root. Replace `41537` with the logged
IPv6 echo port:

```sh
HS_EMULATOR_PORT=18080 HS_EMULATOR_IPV6_PORT=41537 cargo test --locked \
  --manifest-path rust/Cargo.toml --test android_emulator_interop -- --ignored
```

End the instrumented test and remove the forward:

```sh
adb shell run-as com.hotspotshade.demo touch files/hs-interop-stop
adb forward --remove tcp:18080
```

On 2026-11-05 the direct echo test returned status `SUCCESS` with 7 bytes. The
Rust test passed the token check, a 64 KiB TCP echo to `10.0.2.2`, the wrong
token rejection, the unreachable destination, one `0x81` echo to `10.0.2.2`,
and one IPv6 CONNECT to the emulator `::1` echo on port `41537`. The audit
counted 5 outer sockets and 0 TTL failures. The file limit was 32768, so the
relay limit was 256 and the total was 288. The emulator has no cellular IPv6
route. The IPv6 case used the emulator loopback. This is development evidence,
not a release-matrix result.

### Pairing interop

Build and install both APKs, or reuse the two files from the service test:

```sh
cd android
./gradlew assembleDebug assembleDebugAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
```

Start the pairing test in the background and read the bridge port:

```sh
adb logcat -c
adb shell am instrument -w \
  -e class 'com.hotspotshade.source.PairingInteropTest#serveRealPairingsUntilStopFileOrTimeout' \
  com.hotspotshade.demo.test/androidx.test.runner.AndroidJUnitRunner &
adb logcat -d -s HS_PAIRING_INTEROP:I
```

Forward a free host port to the logged guest port. Replace `43605` with the
logged port and `18091` with a free host port:

```sh
adb forward tcp:18091 tcp:43605
```

Run the Rust pairing test from the repository root:

```sh
HS_PAIRING_PORT=18091 cargo test --locked \
  --manifest-path rust/Cargo.toml --test android_pairing_interop -- --ignored
```

End the instrumented test and remove the forward:

```sh
adb shell run-as com.hotspotshade.demo touch files/hs-pairing-interop-stop
adb forward --remove tcp:18091
```

On 2026-11-05, on the Pixel 8 API 36 emulator, the pairing interop test passed.
The real Rust target client completed two pairings. The first pairing was
unknown, so the responder created a prompt and the instrumented test approved
it. The second pairing used the trusted key and needed no prompt. Both results
named the fixed test host, port, and token. The Rust audit counted 2 outer
sockets and 0 TTL failures. The listener logged `pairings=2 trusted=1`.

The real app on the same emulator showed the Settings pairing listener as
"Off. Turn on the hotspot and open this app." The emulator has one Wi-Fi client
interface (`wlan0`) and one cellular interface (`eth0`). The production finder
excludes both, so it did not treat either as a hotspot. The real app's prompt
dialog was therefore not rendered on this emulator. The instrumented test
exercises the same responder prompt path with an automatic approval. A real
source phone with a hotspot is still needed for the UI prompt and carrier test.

## Preview screenshots

The `screenshots/` folder holds earlier captures from a Pixel 7 emulator. Most
images are 1080 by 2400 pixels. The small-screen image is 720 by 1280 pixels.

- `dashboard-light.png` and `dashboard-dark.png`: the in-use Dashboard.
- `settings-light.png` and `settings-dark.png`: the Settings page.
- `activity-light.png` and `details-light.png`: Recent activity.
- `controls-top.png` and `controls-bottom.png`: the preview controls.
- `pairing.png`: the simulated pairing prompt.
- `needs-attention.png` and `starting.png`: the attention and starting states.
- `small-screen.png`: 360 by 640 dp.
- `large-text.png`: 1.5 times the system font size.

These older screenshots hold simulated data only. On 2026-11-05 the Pixel 8 API
36 emulator showed the real Off, Waiting for the hotspot, and On states, the
real Settings page, the real Advanced values, and the labeled preview mode.
The device tools captured the screens. The emulator has no hotspot interface,
so the On state used the test-only hotspot address. This is development
evidence, not a release-matrix result.

## Package and signing

- Application ID: `com.hotspotshade.demo`
- Version: `0.1.0-demo` (version code 1)
- Minimum SDK: 26
- Target SDK: 36
- Permissions: `INTERNET`, `ACCESS_NETWORK_STATE`, `CHANGE_NETWORK_STATE`,
  `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, and
  `POST_NOTIFICATIONS`. The debug build repeats `INTERNET` for the
  instrumented test.
- Exported components: the launcher activity only. The source proxy service is
  not exported.
- Backup: disabled
- Cleartext traffic: disabled

The app is a debug build. Sign it with your own key if you want to keep it
installed next to another build. Do not use the debug key for a real product.

## Limits

- The app UI controls the real source proxy. The pairing listener runs only
  while the activity is visible. Android background execution limits are not
  handled, so pairing does not continue while the app is fully in the
  background. A request that arrives while the activity is paused but the
  listener is still open posts a notification. This is a difference from the
  iOS source app.
- A production start before any pairing stops with "Pair first". A successful
  pairing writes a token and prevents that state.
- The pair-at interop test binds the emulator loopback, not the hotspot
  address. It does not prove hotspot-only binding, carrier behavior, or
  physical-device behavior.
- The emulator has a Wi-Fi client interface and a cellular interface, and no
  hotspot interface. The real app therefore showed the pairing listener as off
  and the proxy as "Waiting for the hotspot". The real prompt dialog was not
  rendered on the emulator. The instrumented test approves the responder prompt
  automatically. The running state screenshot used the test-only hotspot
  address.
- The pairing crypto is in-tree, not independently reviewed. The tests hold the
  RFC 7748, RFC 8439, and RFC 5869 vectors, but a security review is still
  needed before release.
- The real Forget one, Forget all, and token rotation actions change the real
  stores. The store actions are tested on the emulator with the real Android
  Keystore and a test preferences file. The app's real trusted list stays empty
  on the emulator because it has no hotspot. A real phone and a paired target
  device test are still needed. Token rotation does not remove trust. A paired
  target device must pair again before it can use the new token.
- The real trusted target label is a short digest of the public key. It is not
  a device name. A person identifies a target device by its pairing time and
  its label.
- The pairing listener stops when the activity stops. A pending prompt ends
  when its socket closes.
- The Android target tunnel is not implemented. This app is a source device
  only.
- The emulator test does not prove carrier, hotspot, or physical-device
  behavior. It uses the emulator default network and the emulator address
  `10.0.2.15`.
- The emulator test injects the hotspot address and the cellular network. The
  real `NetworkInterface` finder, the `ConnectivityManager` interface
  exclusions, and `AndroidSourceCellularSelection` need a real-phone test.
- The resolver test used the emulator default network, not a cellular bearer.
- The loopback bridge is a test tool. The service binds one hotspot address.
- A phone with both Wi-Fi tethering and USB tethering up gets one listener on
  the Wi-Fi hotspot address.
- The service has no automatic restart. Android Doze, battery settings, and
  vendor background limits need a real-phone test.
- The echo path needs an unprivileged ICMP datagram socket. A device that
  refuses it returns status 4 for every echo request. Android version, kernel,
  and vendor policy decide. The Pixel 8 API 36 emulator permits the socket. A
  real phone test is needed.
- The echo path has no TTL control. The kernel default applies to the echo
  request. The target device builds its inner reply with TTL 64.
- The one-shot echo command `0x81` passed the emulator interop test. The
  persistent echo command `0x82` has JVM coverage for multiple frames, the 16
  session cap, the idle window, and the lifetime. A live target device run of
  the persistent command is still needed.
- The Android server does not produce echo status 1, 5, 7, 8, or 9. It has no
  iOS path monitor. It returns 3, 4, or 6 for those conditions.
- The 30 second handshake, 8 second connect, 2 second relay grant, 30 second
  echo idle, and 300 second idle and lifetime values are policy values. A live
  hotspot test must confirm them.
- An open TCP relay is never closed for silence. The client and destination
  sockets set keepalive, but Android applies its system values. The app cannot
  set the iOS 60 second idle, 10 second interval, and 3 probe values.
- The relay cap follows `/proc/self/limits`. A low open-file limit gives fewer
  relays. A limit that is unreadable or too low stops the start with
  `START_FAILED`.
- The IPv6 interop case used the emulator loopback `::1`. The emulator has no
  IPv6 route on its cellular interface. No live carrier IPv6 test exists.
- The IPv6 and ICMP sockets are unprivileged. A VPN or a vendor filter can
  still block them. The app does not detect that before the first request.
- The token store uses an AES key in the Android Keystore. Replace it with
  `EncryptedSharedPreferences` if the project approves that dependency.
- The saved proxy port can be taken by another process. The service then stops
  with `BIND_FAILED`, and a later start chooses a new port. A paired target
  device learns the new port only from an authenticated status answer.
- A build with a different debug key needs an uninstall before it can replace
  the installed app. An uninstall removes the stored token and trust. Ask the
  user before installing on their phone.

The glass cards use a subtle tonal surface and a light border. Android does not
give Compose a portable backdrop blur, so the cards do not copy the iOS Liquid
Glass effect exactly. The app follows the Android system font. It does not ship
SF Pro.
