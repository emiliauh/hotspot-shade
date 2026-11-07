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

The app has no demo or preview mode. Every control in it acts on the real
proxy, the real trust list, or the real token. The app does not implement the
Android target tunnel.

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

The background status host is enabled (2026-11-06). The
`BACKGROUND_STATUS_ENABLED` constant in `SourceProxyServiceLifecycle` is
`true`. While the proxy runs and the activity is hidden, the host answers the
target device's authenticated status checks on the hotspot address only, for a
target confirmed in this app process. It never pairs, forgets, prompts, or sends
the token. Without it, a target that gets no fresh answer for 90 seconds stops
the tunnel with the reason `source_device_gone`. JVM and loopback tests cover
it. A real-device test (screen lock, OEM background limits, a real hotspot) is
still open.

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
The save path writes a temporary file, syncs it, and replaces the token file
with one atomic rename, then syncs its parent directory. A failure after the
rename has an uncertain outcome: the new token may already be visible. The file lives
in the app no-backup directory. Every load and save resolves an older token file
in the files directory under the process lock and retries a failed move, so a
long-lived store cannot keep writing the legacy path. A readable target wins;
legacy cleanup depends on the marker and whether the copies agree. The unused
clear operation is blocked until guarded, durable deletion is
implemented. The supersession marker described below remains in place. A stored token
that cannot be read throws `TokenReadException`; that is not a missing
token. The coordinator does not generate or save a replacement over it, and a
proxy start reports `TOKEN_UNREADABLE` instead of `TOKEN_MISSING`. A stopped
source proxy clears its in-memory token copy. Pairing saves the token before it
seals a successful result.
If no token exists before a start and no pairing has run, the start still stops
with `TOKEN_MISSING`. The instrumented service test injects a fixed test token
in memory.

Path checks. The store rejects a path with a parent component. The kernel
resolves `..` after any symlink in front of it, so a normalized path and the
path the filesystem uses can name different entries. The store normalizes the
remaining absolute paths once and uses those values for every read, write,
delete, and marker operation. It does not check one path and operate on another.
The production store anchors the check at the app data directory. That anchor
must already exist as a directory. A missing anchor, a symlink in a checked
path, a hard-linked duplicate, and two paths that name one entry fail closed.
These checks are not descriptor-relative. They assume app-private directories
and one process that owns them.

Read errors. `FileInputStream` reports EACCES, EMFILE, and a directory with the
same `FileNotFoundException` that it reports for a missing file, so that type is
not proof of absence. The store reads with `Files.readAllBytes` through an
injectable `TokenFileReader`. A `NoSuchFileException` counts as absence only
when path inspection also establishes that the entry is missing. A symlink or
non-directory ancestor is unclassifiable. Other read errors are transient: `load`
throws `TokenReadException` with the transient kind, `stateOf` reports a
transient state, and neither path selects the legacy copy, reports a missing
token, or lets a caller generate a replacement. A directory at the token path is
transient too. A delete is skipped only when path inspection proves the entry is
missing. Hermetic tests inject the reader, including a pairing
commit with the real store.

Keystore key loss. Token decryption now looks up the existing key without
creating one. A missing or unreadable key is a transient read failure, so it
does not select a legacy token or permit replacement of the existing target.
The lookup-only repair has host JVM tests and instrumented tests that passed on
an Android emulator. Its independent review remains pending. Do not treat those
tests as evidence of hardware-backed Keystore behavior or
power-loss durability. A wrong but present key can produce an authentication
failure indistinguishable from damaged ciphertext. The store classifies that
as corruption but retains an unreadable legacy ciphertext and records a
supersession marker before replacing the target. This behavior also requires
independent review.

Stale pairing cache. Two coordinators in one process share the store and the
guard. When a commit finds a different stored token or cannot read the stored
token, the pairing is rejected and that coordinator drops its cached token,
bumps its generation, and clears its address. The old listener answers
NOT_ACTIVE from then on. When the read failed, the coordinator also publishes
the unreadable-token state without waiting for a refresh. The next scheduled
refresh closes the old listener and attempts to load the stored token; if the
store is still unreadable, pairing remains unavailable. The refresh interval is
3 seconds while the coordinator is active, but scheduling can delay it.
Invalidation runs after the guarded store operation returns. It takes the
coordinator lock and may read the guard epoch under that lock; the order is
coordinator lock, then guard. An independent JVM review found no lock cycle;
an already-admitted callback can still arrive late.

Legacy-token supersession marker. The target is in the app's no-backup
storage. The marker `source-token.bin.legacy-superseded` is a one-way latch
next to it. Its contents are not proof of a token: an existing marker, even an
empty or damaged one, prevents an old legacy copy from becoming active after
the target is lost. Clearing app data or uninstalling removes the marker and
stored trust, so neither is an automatic recovery step.

For a readable legacy token, save writes and verifies the target first and
syncs its directory. If the legacy token differs, it then records and syncs the
marker before removing the legacy copy. A failure before the target write keeps
the readable legacy copy without creating a new latch. A marker or sync failure
after the target may have changed reports an uncertain write and advances the
token guard epoch. The token may have changed even though the operation did not
report success. For an unreadable legacy copy, save records the marker before
changing the target and keeps the ciphertext. This can leave that copy latched
off even when the later save fails. No legacy seed is written before the target.

On load, a readable target wins. A different readable legacy copy is retained
and latched before the target is returned. A corrupt or transient legacy copy
is also retained and latched. If a needed marker cannot be classified or made
durable, load fails rather than selecting a potentially stale copy. An already
present marker avoids a redundant target-directory sync when the legacy copy is
retained. An equal readable copy can be removed after the returned target has
been decoded and its directory sync has succeeded. A failed final read keeps
the duplicate. If the target is missing or corrupt and the marker is present,
the old copy is not restored; an unclassifiable marker also prevents fallback.
With no marker, a readable legacy copy can still be used for a legacy-only
upgrade. No automatic path deletes unreadable legacy ciphertext.

The marker does not resolve every history. Older builds may write a legacy
file while ignoring the no-backup target and marker; on re-upgrade this version
prefers a readable target, so a token or trust change made while downgraded may
not carry forward. If a target write took effect but marker recording failed,
a later target loss before a latch is durable can make an old readable legacy
copy eligible again. A previously durable marker can also leave a readable
legacy copy unavailable when the target is damaged. Do not clear a marker or
restore a copy by hand as an automatic recovery procedure.

Target and marker writes require atomic rename and directory sync. A failed
legacy-directory sync after deletion can leave the deleted entry visible again
after power loss; the marker or equal-token check determines whether
it can be used. Real filesystem sync and power-loss behavior remain unverified
on physical devices. If the target write is lost while a marker survives, an
older readable target may be selected on a later load. A confirmed rotation is
therefore not proven to revoke an older token across power loss or restore.
The process lock and token guard do not coordinate another
process or an external writer. The post-target marker failure and lazy-sync
repair has independent JVM review; its uncertain pairing-commit path is still
getting additional tests. The emulator result below does not establish hardware
Keystore or power-loss behavior.

A source proxy run holds a process-wide token guard from the token load until
its listener closes. A token rotation takes the same guard and is refused while
the run holds it, so a rotation cannot replace the token under a starting or
live proxy. Each pairing server records the guard epoch it was created in. A
result that was sealed before a rotation is not saved over the new token. A
rotation through the pairing coordinator updates the in-memory token and
rebinds the listener as one operation.

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
`0.0.0.0`. It accepts at most eight sockets, and at most four of them may be
idle. A socket that sends no complete frame within 10 seconds is closed. A new
connection evicts the oldest idle socket, so a silent set cannot block a real
target device. The responder allows four sessions. It closes a connection after
a rejection, a timeout, or a completed status or forget request. A successful
result keeps the connection for one authenticated status request until the
five-second deadline. The listener uses a daemon accept thread, a bounded daemon
connection pool, and one timer thread.

`PairingViewModel` starts the listener when the activity starts and stops it
when the activity stops. A hotspot change closes the old listener and binds the
new address. The listener does not run while the activity is not visible.

A request shows an Allow or Deny dialog with the six-digit code. The settings
page shows the real listener state and the real trusted target list.

A request that arrives while the activity is not visible posts a notification.
The notification holds no code, key, address, or token. The person must open the
app to see the code and choose Allow or Deny. The app never approves a request
from a notification. The listener stops when the activity stops, so a request
cannot arrive while the app is fully in the background. This is a limit of the
foreground-only listener.

The Settings page lists each trusted target device with a short public label.
The label is the first four bytes of the SHA-256 digest of the stored public
key. It does not show the key. Each row has a Forget action. "Forget all target
devices" removes every trusted key. Forgetting a target device removes its
trust, so it must pair again with a prompt. The source token does not change.
A forgotten device that still has the current token can use the proxy. Rotation
changes the token, but has not been proven to survive every power loss or restore.

An upgrade with a nonempty legacy trust list requires the person to choose
"Forget all target devices" and pair each target again. The older format cannot
distinguish a confirmed key from one left by a failed write. The app does not
automatically promote those keys. The legacy list remains in the older
preferences, so a compatible older app can restore it after a downgrade. After
downgrading, remove trust in the older app and change the source token in the
version you will use. A restore or loss of a write can still bring older data
back, so this is not a proven revocation procedure. The downgrade policy remains open.

The current trust store also requires a new pairing confirmation after each app
process restart. Until then, a saved target cannot use status or remote Forget.
The Settings list identifies whether confirmation is current or required.

The Settings page has a Manual connection block with the real SOCKS5 username,
hotspot address, port, and source token. "Show token" opens a 30 second reveal.
The visible value is for sighted reading only. TalkBack hears "Source token
shown" and never the value. While the reveal is open, the activity window sets
`WindowManager.LayoutParams.FLAG_SECURE`, so screenshots and the recents
thumbnail cannot capture the token. The block clears when the reveal closes,
when the app goes to the background, and when the 30 second deadline passes.
The copy action and its 120 second clipboard clear are unchanged.

The "Rotate source token" action writes a new random 32-byte token to the
`AndroidKeystoreTokenStore` and reloads the pairing listener. The action is
refused while a proxy run starts or serves flows. Rotation does not remove
trust: a target device confirmed in the current app process can pair again
without a new prompt. Every paired target device must pair again before it can
use the new token. The token write is read back and synced, but its survival
across power loss or restore has not been established on a physical device.

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

A successful pairing saves the proxy token with `TokenWriter` before the result
is sealed and sent and before the target key is trusted. A failed save sends a
fixed rejection, adds no trust, and shows a message without the token. The
production store is the same `AndroidKeystoreTokenStore` that the proxy reads.
A start after a pairing therefore finds a token instead of `TOKEN_MISSING`. If
no token exists, the app generates a 32-byte random token in memory and saves
it before sealing a success. A later failure can leave that saved token without
a completed pairing.

`ProxyPortPolicy` first tries up to eight random ports from 20000 to 59999. It
skips 18090. If those attempts find no free port, it asks the kernel for a free
port (a bind on port 0) and keeps that result only when it is from 1024 to
65535 and is not 18090. A saved port is accepted under the same 1024 to 65535 rule, so a port
chosen by the kernel fallback can lie outside 20000 to 59999. The pairing
result names the hotspot address and this port. The source proxy service
prefers the same port. While a proxy run is starting or live, a pairing answer
names only the port and address that the controller actually bound, and it
answers `NOT_ACTIVE` during the bind section instead of probing. With no run
active the saved port is an advisory free-port probe, not a reservation:
another process can take it, and a bind failure keeps the remembered value for
a later probe. A paired target device learns the port that actually bound from
an authenticated status answer.

Target-device public keys are stored as base64 strings in one app-private file,
`pairing-trust`, in the app no-backup directory (`context.noBackupFilesDir`).
The store writes the v2 header and one sorted key per line, with `.intent` and
`.migrated` sidecar files. The SharedPreferences set `paired-targets` is read
only for the one-time legacy migration: a nonempty legacy list is refused
rather than promoted, and the preferences copy is left in place so a downgraded
app can still read it. The keys are public values. The token is not in the
trust file and not in SharedPreferences. One process-wide lock makes each load,
change, and save one operation across the pairing listener and the settings
page. A read or write failure throws and writes nothing, so the caller fails
closed and the list is not cleared.

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

### Hotspot discovery

`HotspotAddressFinder` reads the interface list through `NetworkInterface` and
one observation from `ConnectivityManager`. Every interface name that any
reported network holds is excluded. The platform can report upstream, client,
or access point interfaces; every reported name is excluded even if that makes
a real hotspot unavailable. The rule covers cellular, Wi-Fi, VPN, Ethernet, and
Bluetooth PAN. The finder returns only an interface that passes the rules below.
With the name rules, a strong tethering name is admitted by the heuristic: `swlan*`, `ap*`,
`softap*`, and `rndis*`. `bt-pan*` is not a strong name. Android uses the
same prefix for a Bluetooth tether and a Bluetooth PAN client, so the finder
does not guess. A `wlan*` name is a weak candidate: it needs a complete
observation that names a separate, unambiguous Wi-Fi station, and the candidate
must not be a reported network. Reported `wlan*` and tether-style names cannot
provide that station evidence. That is an inference from station plus access
point concurrency, not proof.

A missing capability, a missing link-properties value, a missing interface
name, or a failed platform call makes the observation partial. A partial read
keeps every name that it read, so a known client interface stays excluded. It
never confirms a `wlan*` name, because one missing client name could hide the
station. The finder never treats an unread name as an absent client. When two
interfaces or two private addresses hold the best rank, a new start waits
because the finder cannot choose between them. An existing run can continue
while its bound address remains a candidate. With the name rules, a generic name such as `eth*`, `usb*`, or
`wg*` is never a hotspot. The finder returns null when it cannot confirm an
interface. The
pairing listener and the proxy then stop instead of binding a client or VPN
address. A strong Wi-Fi access point name ranks above `rndis` USB; an inferred
weak `wlan` candidate ranks below it. Fake sources drive the
JVM tests.

An interface name alone does not prove that the interface is tethering. A
vendor ROM can hide the Wi-Fi client network while the access point is up, name
both roles with the same prefix, or report the access point as a network. The
app can report no hotspot and wait. A vendor name that appears to be a Wi-Fi
station may instead identify an access point, so the inference can also select
an unreported client interface. The name rules cannot prove tethering.
Binding the address also does not prove that the interface is tethering. A
local-only hotspot has its own lifecycle and is not detected. The hotspot watch
checks every 2 seconds. It stops the proxy at once when the bound address
belongs to an interface that a reported network holds. It stops after 3
consecutive uncertain checks, about 6 seconds, when the observation is missing
or incomplete. One good check clears the count. The watch reports at most one
loss and never restarts the proxy.

On Android 16 (API 36) or later the finder also reads the public
`TetheringManager` callback `onTetheredInterfacesChanged`.
`TetheringInterface.getInterface()` names the current tethered interfaces. The
app registers one callback for the process, and the callback needs only
`ACCESS_NETWORK_STATE`. A complete reading is positive evidence:

- A complete set is authoritative, including an empty set. An empty set means
  the platform reports no tethering. The finder returns no candidate and does
  not fall back to the name rules.
- A non-empty set admits only the named interfaces. The name rules do not apply
  on this path, so a named `bt-pan*`, `eth*`, `usb*`, or `wlan*` interface can
  be a candidate. The platform type ranks it, not the name. A named interface
  that is down, loopback, cellular, virtual, or has an unknown or WiGig type is
  still rejected, and it needs one private IPv4 address. The virtual AVF tap
  `avf_tap_fixed` is never a candidate.
- A named interface that a reported `ConnectivityManager` network also holds is
  a conflict between two platform views. The finder fails closed and returns no
  candidate for that reading.
- A null, blank, or partial delivery, a failed registration, or Android 15 or
  earlier is unavailable, not empty. The finder then uses the name rules. A
  missing callback can leave a hotspot unidentified, and a vendor's unexpected
  naming or incomplete network observations can make the heuristic select a
  client interface.
- A registered callback that has not delivered its first reading is pending,
  not unavailable. The finder returns no candidate and does not use the name
  rules while the state is pending. It does not block. The wait is bounded at
  3 seconds (`TetheredInterfaceEvidence.DEFAULT_PENDING_TIMEOUT_MILLIS`). After
  that bound the evidence reports unavailable, so the finder uses the name
  rules. The callback stays registered, and a late reading still replaces the
  fallback. The bound stops a callback that never fires from hiding a lost
  hotspot from the watch.

The callback is process scoped. The first finder creation on API 36 or later
registers it on one daemon executor. Registration runs outside the shared
lock, and two creators keep one callback and close the other before it
registers. A callback that arrives while registration is still running is
kept. The pairing listener and the proxy share one reading. A process lease
holds the callback, so an explicit service lease release does not close it.
A service stop does not unregister it, and a later finder reuses it. A failed
registration is retried on the next finder creation. A test environment reset
or process teardown closes it. A stale event after close is ignored. The finder
reads the callback reading before the interface list, so a callback that
arrives during a probe applies to the next probe.

The watch treats a named set that no longer contains the bound interface as an
uncertain probe. It stops after 3 consecutive misses, about 6 seconds, because
a callback can arrive late. A pending first reading does not advance the miss
count for a bounded run. The evidence turns that probe into an unavailable
probe within 3 seconds, and the watch policy counts a stuck pending probe as
uncertain after 4 consecutive probes, about 8 seconds. A callback that never
fires therefore cannot blind the watch to a loss. A bound address that a
reported network holds still stops the watch at once.

A start that arrives before the first reading waits a bounded time instead of
reporting a missing hotspot. `SourceProxyController` runs the first probe and
the session setup on one background task queue. It retries a pending probe
with a 250 ms poll until `SourceProxyController.DEFAULT_PENDING_WAIT_MILLIS`,
which aliases the evidence pending timeout. The wait holds no controller lock
and never runs on the caller or network monitor thread. A second start during
the wait is refused, a user stop ends it at once, and a late result after a
terminal state binds nothing. A pending `openSession()` keeps its cellular
session open and sets up the listener when the reading arrives. A deadline
reports `HOTSPOT_NOT_FOUND` once and closes the session. See
`docs/ANDROID_HOTSPOT_START_PENDING.md`.

The app wraps the platform callback in a dynamic proxy, so a null delivery
becomes unavailable instead of a thrown null check or an empty set. The JVM
tests supply a fake registration and fake interfaces. They do not load
`TetheringManager`, run on a device, or prove that a phone or an OEM ROM
delivers the callback as documented. A real phone hotspot test on several
vendor ROMs is still open.

Android 15 and earlier have no public API that names the system tethering
interfaces. The hidden and system APIs, such as
`ConnectivityManager.getTetheredIfaces` and the system-only `TetheringManager`,
are not available to a normal app, and some need the signature permission
`TETHER_PRIVILEGED`. The app requests no system or proprietary permission. On
those versions the name rules and the network observation are the only
evidence, and their accuracy varies by vendor ROM. That discovery gap and the
OEM compatibility question remain open.

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
  paired target devices, destination privacy, the manual connection values,
  and Advanced. Advanced holds the real state, the real port, the real
  connection counts, token rotation, diagnostics, and the version. The port is
  read-only. See "Not in the app" below.
- Pairing: a real Allow or Deny dialog with a six digit code.
- Semantic light and dark themes. The app follows the system theme.
- Animation for tab changes, status changes, the button, expanding rows, the
  token block, and the starting status mark.
- Reduced motion from the Android animator scale.
- TalkBack labels, live status announcements, headings, 48 dp actions, and
  scrolling for small screens and large text.

### Not in the app

The app has no demo or preview mode, no banner, no simulated values, and no
simulated pairing dialog. Two controls from an earlier prototype have no real
implementation, so the app does not show them:

- A recent-activity sheet. The app keeps no activity log. A real log would need
  a stored list of events, and the app has not been designed to store one.
- An editable proxy port. The real port policy (`ProxyPortPolicy`) prefers a
  port from 20000 to 59999, accepts the kernel fallback and a saved port from
  1024 to 65535, never chooses 18090, and saves the port that bound. A
  user-set port would change which port paired target devices learn, and the
  change must be refused while the proxy runs. That is a proxy behavior change
  that the owner has not approved. Advanced and Manual connection show the
  real port, read-only.

## Build

Use JDK 17 and Android SDK platform 36. Java 25 fails with the current Gradle
wrapper. The build downloads its dependencies from the official Google and
Maven Central repositories.

```sh
cd android
export JAVA_HOME="$(/usr/libexec/java_home -v 17)" # macOS with a registered JDK 17
./gradlew assembleDebug
```

If `java_home` does not find a Homebrew JDK 17 on Apple silicon, use
`export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home`
instead. Confirm the selected version with `"$JAVA_HOME/bin/java" -version`.
If Gradle reports `25.0.4`, it is using Java 25; set `JAVA_HOME` to JDK 17
in the same terminal before rerunning the build. Set `ANDROID_HOME` to your SDK
directory if the build cannot find it.

The newly built APK is at `app/build/outputs/apk/debug/app-debug.apk`. It is
signed with the standard Android debug key from the build host. The key is not
in this repository. Install it on a test device or a disposable emulator. A phone installation
needs the owner's approval; `-r` replaces an existing app and may preserve its
saved token and trust data:

```sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The APK carries the small AndroidX native path library for four ABIs, so the
same file installs on arm64 and x86_64 devices. The app code has no native
library of its own. Android 8.0 (API 26) is the minimum version.

## Test

The JVM tests do not open a screen and they need no device.

```sh
cd android
./gradlew testDebugUnitTest
```

The suite had 899 JVM tests in 52 classes on 2026-11-06, all passing with JDK 17. The app model tests cover the manual connection values, the token reveal and
clipboard rules, the secure-window block, the privacy capability report, the
real state display, and diagnostics. The source tests cover the cellular socket and
session boundaries, the network monitor, the SOCKS5 contract and its
connection counters, the hotspot address finder and its partial-read
exclusions, the network observation, the hotspot watch and its loss policy,
the API 36 tethering evidence lifecycle, its known-empty and unavailable
readings, its conflicts with the network observation, and its watch
integration, the network resolver, the service state machine and its counter
read-back, the proxy port policy, the coordinator token save, the real proxy
state display, the status map, the trust fingerprints, Forget one and Forget
all, and token rotation. The token tests cover the guard that refuses a
rotation during a run, a start that loads the old token, a stale pairing save,
a failed start, an unreadable token, the no-backup migration race, the
cleared token copy after a failed listener start, and the secure-window block
on reveal, hide, background, and timeout. The
pairing tests cover the RFC 7748, RFC 8439, and RFC 5869 vectors, the fixed
parity vectors, the state machine budgets and binding, the loopback listener,
a throwing host callback, and token-save failure before a pairing success.

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
proxy starts or runs, the failed write, the stale pairing save, and the guard
epoch. The token tests cover the no-backup migration and its concurrent calls,
the unreadable-token path, and a cleared token copy after a failed start.

The pairing tests cover the per-address challenge budget, the global challenge
budget, the budget charge before key generation, the pairing-off path, the
canonical peer keys, the decision binding, the hidden-prompt extension cap, the
known target path, forget, the lockout, the session cap, the invalid-message
backoff and its bounded map, the idle-connection cap and deadline, the redacted
text, the trust store process lock, the failed read and write paths, and the
atomic token file write. They use fixed public keys and nonces.

The service state machine tests cover start, hotspot missing before and after
the network arrives, network loss, capability loss, network unavailable, user
stop, double start, restart refusal, late callbacks after stop, hotspot loss,
token missing, bind failure, resolver failure, watch failure, and a snapshot
with no token or address.

The `android-demo` CI job runs the JVM tests, lint, and a debug build. It does
not run an emulator. CI does not publish the debug key.

Run lint with:

```sh
cd android
./gradlew lintDebug
```

On 2026-11-05, Android Lint reported 0 errors and 7 warnings. Every warning
reports a newer available Gradle or AndroidX version.

## Emulator interop test

Five instrumented test classes exist under
`app/src/androidTest/java/com/hotspotshade/source/`:

- `SourceSocksInteropTest` serves the SOCKS5, UDP-over-TCP, and echo contract
  on the emulator loopback.
- `SourceProxyServiceInstrumentedTest` starts the real foreground service
  behind a loopback bridge.
- `PairingInteropTest` serves the real pairing responder for the Rust target
  client.
- `PairingLifecycleInteropTest` runs an unknown pairing, a trusted pairing, a
  trusted and an unknown status request, a remote Forget, and a rejected
  status after that Forget.
- `AndroidKeystoreTokenStoreForContextInstrumentedTest` exercises the real
  Android Keystore with a disposable alias and private temporary directories.

`TestOnlyHotspot.kt` is a test helper in the same source set, not a test class.
An emulator loopback does not prove carrier, hotspot, or physical-device
behavior.

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

`PairingInteropTest` runs the real `PairingCoordinator`, `PairingServer`, and
`PairingResponder` on the emulator loopback. It uses a fixed public test token
and a fixed proxy port. The test approves each prompt automatically, because no
person taps the emulator during the run. The real Rust target client
`rust/tests/android_pairing_interop.rs` completes two pairings through
`adb forward`: one unknown target with a prompt, and one known target without a
prompt. The test logs only the bound port and counts with the
`HS_PAIRING_INTEROP` tag.

On 2026-11-06 the separate `PairingLifecycleInteropTest` and the Rust
`android_source_pairing_lifecycle_interop` test both passed on the Pixel 8
Android 16 emulator through a temporary loopback forward. The fixture reported
two pairings, one prompt, no denials, and no remaining trusted target. The Rust
test checked trusted and unknown status requests, Forget, and a rejected status
after Forget; its audit asserted six outer sockets and zero TTL failures. The
forward was removed and the fixture stopped. The app APK SHA-256 was
`3bb20f3c6a56f1d570ec7c94243f039ce368464f88fd12612770fd7a1fe3bbee`;
the test APK was
`2766af6960803161b2924ed366fb626401e25a3b89802e8c19cca648cc039afc`.
The Rust test source SHA-256 was
`674e60796dafd04f2744c1c9a510e31cf28114866f6f3657c1cdcf6d909f898d`.
These working-tree and artifact hashes are not complete build provenance. The
fixture uses in-memory trust, so this run does not prove durable revocation or
physical hotspot and carrier behavior.

The emulator has no hotspot interface. The test therefore uses
`TestOnlyHotspotFinder` from the `androidTest` source set. Gradle compiles that
file only for the debug instrumented test APK. A release build does not compile
it, so the production app cannot get a test hotspot address. The finder reports
the loopback address, so the test needs no bridge.

`SourceProxyServiceInstrumentedTest` starts the real service. It uses these
test-only substitutions:

- The emulator's own address `10.0.2.15` is the mimicked hotspot address.
- The emulator default network is the mimicked cellular network, injected
  through a test-only `CellularNetworkSelection`.
- The source token is a fixed test value in memory. It is not a secret and it
  is not written to storage or a log.
- The service logs only the bridge port with the `HS_SERVICE_INTEROP` tag.

### Isolated Keystore test on an emulator

`AndroidKeystoreTokenStoreForContextInstrumentedTest` exercises the real
Android Keystore through a test context with a disposable alias and private
temporary directories. Its former-key test checks that an unreadable legacy
ciphertext survives a load and save, and that the supersession marker prevents
the old token from becoming active if the target disappears. It uses fixed
test tokens and does not replace the app's token or trust list.

On an already running Android emulator, build both debug APKs and run this
one test with the instrumentation runner. Replace `emulator-5554` with the
emulator serial reported by the device tools. Do not use a physical device
for this procedure without the device owner's approval. Installing an APK
with `-r` preserves app data but can interrupt a running app in the emulator.

```sh
cd android
./gradlew --offline assembleDebug assembleDebugAndroidTest
adb -s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5554 install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s emulator-5554 shell am instrument -w \
  -e class 'com.hotspotshade.source.AndroidKeystoreTokenStoreForContextInstrumentedTest#aSaveKeepsCiphertextFromAFormerKeyAndLatchesTheMarker' \
  com.hotspotshade.demo.test/androidx.test.runner.AndroidJUnitRunner
```

Check the runner output for `OK (1 test)` rather than relying only on the
command exit status. Record both APK hashes and a complete manifest of the
source used for the build. If sources change during the build, discard that
run as evidence for the later revision. This direct runner avoids Gradle's
connected-test platform download; it does not establish hardware-backed
Keystore behavior, power-loss durability, backup behavior, or a real hotspot.

On November 6, 2026, the full instrumented Keystore test class passed all 12
tests on a Pixel 8 Android 16 emulator. The isolated service pairing-admin
token rotation test also passed with the same APKs. The build and test source
manifests matched; `TokenStore.kt` had SHA-256 `531ed84cb9920a81c16746b6428123636d2536e0737c355ceffdeb59672c0ced`.
These emulator results have the same hardware and durability limits above.
After the post-target marker repair, the same 12-test class and the isolated
pairing-admin rotation test passed again on the emulator. The second run's
matching source manifests recorded `TokenStore.kt` SHA-256
`063a15433f1e17fa0077c99485fb84519a7bb05a8c7cf6da429acfbaa6ab2fb6`.
These results do not test a power cut or a physical device.

A later November 6 emulator run rebuilt the debug app and test APK offline
with the local Gradle cache and ran the full Keystore test class: 12 tests
passed on the Pixel 8 Android 16 emulator. The app APK SHA-256 was
`3bb20f3c6a56f1d570ec7c94243f039ce368464f88fd12612770fd7a1fe3bbee`;
the test APK was
`c040eb1b5cdea588004b81dafb72d522aecf895b5ea13c777956429b74289cb3`.
`TokenStore.kt` was
`c74e36c0794aab5b215f0b3c145da0df18f03e10d441f46d8225ce1e157f909a`.
Before and after the run, a sorted SHA-256 manifest of the non-ignored files
listed by `rg --files android` had digest
`4a98a1365c4bfe409aead915f457b3f4da5fd164d971b2acdf49679e92b90ae8`.
That digest describes the dirty source snapshot before this README update; it
is not a commit or a complete build provenance record. The run does not prove
hardware-backed Keystore behavior, power-loss durability, restore behavior, or
a physical hotspot or carrier path.

The same installed APKs then passed the isolated
`pairingAdminRotatesTheRealTokenFile` instrumentation test. Its disposable
Keystore alias and directory were removed by the test. The non-ignored Android
file manifest before and after that test had SHA-256
`d91e7eccf050dea4f756595694a5bece192ff5fd100c5c67996e8ed54bffec08`;
the difference from the prior manifest includes the README update above. This
later manifest is also a dirty working-tree record, not build provenance.

The same installed APKs also passed `networkLossStopsTheServiceWithoutARestart`.
The test used a fixed test token, the emulator default network, and an injected
network-loss callback. It reported a stopped service without a restart; the
service was absent from the emulator service list afterward. The non-ignored
Android file manifest before and after this run had SHA-256
`cd3e202e4f3dba724d9a347100469efbe51f0495e71b8287e79b38e9ec80d706`.
The working tree had changed since the APK build, so that manifest does not
identify the APK source. This test does not establish physical hotspot or
carrier behavior.

Another offline build and emulator run passed the connection-count test after
adding a TCP payload round trip through the authenticated proxy to an echo
listener on the emulator. The app APK SHA-256 was
`3bb20f3c6a56f1d570ec7c94243f039ce368464f88fd12612770fd7a1fe3bbee`;
the test APK was
`2766af6960803161b2924ed366fb626401e25a3b89802e8c19cca648cc039afc`.
The non-ignored Android file manifest before and after the build and test was
`4d3873bf26f68f00775fdf1847d283c0064efae81a9d714d7c0c8c90349c24b5`.
It describes the dirty tree before this README update, not complete build
provenance. The service was absent from the emulator service list afterward.
The test used an injected address and network and does not prove physical
hotspot or carrier behavior.

### Source proxy service interop

`SourceProxyServiceInstrumentedTest` adds a loopback bridge. `adb forward` connects to the emulator
loopback, while the service binds the hotspot address only. The bridge forwards
each loopback connection to `10.0.2.15` and the bound port. The bridge exists in
the test APK only. It is not part of the app.

The test methods are:

- `serviceServesTheSocksContractOnTheMimickedHotspotAddress`: start the
  service, wait for the running state, send a second start request, check that
  one run continues and the running notification text stays correct, serve
  until the host creates `files/hs-service-interop-stop`, then stop with the
  Stop action. It also reports an emulator-loopback IPv6 echo port when one
  can be opened, so the host can require the IPv6 destination case.
- `networkLossStopsTheServiceWithoutARestart`: start the service, report a
  network loss, check the `NETWORK_LOST` state, and check that the service stays
  stopped after 2 seconds.
- `runtimeObservationReportsRunningStateAndRealConnectionCount`: start the
  service, check the running report, open one authenticated TCP flow to a
  test echo server, check that the open count becomes 1 and the total becomes
  1, exchange a payload, close the flow, and check that the open count returns
  to 0.
- `sharedPreferencesTrustStoreForgetsOneAndAll`: add two fixed public keys to a
  test preferences file, list the targets, forget one, and forget all.
- `pairingAdminRotatesTheRealTokenFile`: write a fixed token with the real
  Android Keystore store, rotate it through `PairingAdmin`, and check the new
  value. It uses a disposable alias, isolated token directory, and in-memory
  trust store.
- `keystoreTokenStoreRoundTrip`: save, load, and check blocked clear for a fixed test token with
  the real Android Keystore store and a disposable alias and directory. Both
  tests remove their disposable key and directory after the test.
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

On 2026-11-06 the serving method and the current Rust
`android_source_server_interop` test both passed on the Pixel 8 Android 16
emulator. This run included authenticated TCP and UDP flows, the in-memory
Rust relay, rejection of a wrong token, an unreachable destination, and ICMP
echo. The Rust test asserted five audited client outer sockets and zero TTL
failures; it skipped the optional IPv6 destination because this service
fixture supplies no IPv6 echo port. The service stopped and the temporary
forward was removed. The app and test APK SHA-256 values were
`3bb20f3c6a56f1d570ec7c94243f039ce368464f88fd12612770fd7a1fe3bbee`
and `2766af6960803161b2924ed366fb626401e25a3b89802e8c19cca648cc039afc`.
The Rust test source SHA-256 was
`b0caa6a74ec6bd73fcc54a48fe833ba9637d19702bae3f044f4a36a79a230fba`.
These hashes are not complete build provenance. The test injected the hotspot
address and network selection; it does not establish physical hotspot,
cellular bearer, or carrier behavior.

A later 2026-11-06 service run added an IPv6 loopback echo listener to the
instrumented fixture and required the IPv6 case in the Rust interop test. Both
tests passed, including the TCP, UDP, relay, authentication, and ICMP cases;
the Rust client audit asserted six outer sockets and zero TTL failures. The
service stopped and the temporary forward was removed. The app APK SHA-256 was
`3bb20f3c6a56f1d570ec7c94243f039ce368464f88fd12612770fd7a1fe3bbee`, and
the test APK was
`911487d68e6aed9f2cfe83fd8e39ae3cf0c5ae7936c337592301c7cbf47c7536`.
The non-ignored Android file manifest before and after the build and run was
`0819de488b564c464afb098eacb1496c53536ff2468ce2a64a2da0b30981e5a6`.
It describes the dirty tree before this README update, not complete build
provenance. The IPv6 destination was emulator loopback, and the hotspot and
network selection were injected. Physical and carrier behavior remain untested.

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

On 2026-11-06 the `SourceSocksInteropTest` serving fixture and the Rust
`android_source_server_interop` test passed again on the Pixel 8 Android 16
emulator. IPv6 was required and used an emulator-loopback echo listener. The
test also exercised TCP and UDP through the in-memory Rust relay, checked that
distinct UDP flows used distinct outer sockets, and asserted six audited client
outer sockets with zero TTL failures. The fixture used a no-op network binding
and the emulator default network for ICMP; it did not prove cellular binding.
The temporary forward was removed and the fixture stopped. The app and test APK
SHA-256 values were `3bb20f3c6a56f1d570ec7c94243f039ce368464f88fd12612770fd7a1fe3bbee`
and `2766af6960803161b2924ed366fb626401e25a3b89802e8c19cca648cc039afc`.
The Rust test source SHA-256 was
`b0caa6a74ec6bd73fcc54a48fe833ba9637d19702bae3f044f4a36a79a230fba`.
These hashes are not complete build provenance, and this run does not establish
physical hotspot or carrier behavior.

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
sockets and 0 TTL failures. The listener logged `pairings=2`.

The real app on the same emulator showed the Settings pairing listener as
"Off. Turn on the hotspot and open this app." The emulator has one Wi-Fi client
interface (`wlan0`) and one cellular interface (`eth0`). The production finder
excludes both, so it did not treat either as a hotspot. The real app's prompt
dialog was therefore not rendered on this emulator. The instrumented test
exercises the same responder prompt path with an automatic approval. A real
source phone with a hotspot is still needed for the UI prompt and carrier test.

## Package and signing

- Application ID: `com.hotspotshade.demo`
- Version: `0.1.0` (version code 1)
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
- The background status host is on but has no real-device test. If an OEM
  limit stops it, the target gets no answer and can stop the tunnel after 90
  seconds (`source_device_gone`). A target saved before an app process restart
  gets no status answer until it pairs again.
- A production start before any pairing creates the source token itself, so a
  manual SOCKS5 client can connect. An unreadable stored token is never
  replaced.
- The pair-at interop test binds the emulator loopback, not the hotspot
  address. It does not prove hotspot-only binding, carrier behavior, or
  physical-device behavior.
- The emulator has a Wi-Fi client interface and a cellular interface, and no
  hotspot interface. The real app therefore showed the pairing listener as off
  and the proxy as "Waiting for the hotspot". The real prompt dialog was not
  rendered on the emulator. The instrumented test approves the responder prompt
  automatically. The instrumented service test used the test-only hotspot
  address.
- The pairing crypto is in-tree, not independently reviewed. The tests hold the
  RFC 7748, RFC 8439, and RFC 5869 vectors. A security review of the pairing
  code found two P2 and eight P3 findings. This revision fixes them. An external
  review is still needed before release.
- The real Forget one, Forget all, and token rotation actions change the real
  stores. The store actions are tested on the emulator with the real Android
  Keystore and a test preferences file. The app's real trusted list stays empty
  on the emulator because it has no hotspot. A real phone and a paired target
  device test are still needed. Token rotation does not remove trust. A paired
  target device must pair again before it can use the new token. Forget removes
  trust but does not change the token, so a forgotten device that still has the
  current token can use the proxy. Rotation durability is not device-verified.
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
- The strict finder excludes every interface name that a reported
  `ConnectivityManager` network holds, whatever the transport. A missing or
  failed capability, link properties, or interface name makes the observation
  partial, and the observation keeps the names it already saw. A partial
  observation never confirms a `wlan*` address. On Android 15 and earlier, and
  whenever the API 36 reading is unavailable, a `wlan*` address needs one
  complete observation that names a separate, unambiguous Wi-Fi station;
  reported `wlan*` and tether-style names do not supply that evidence. This is
  an inference, not proof. Two candidates with the same rank also fail closed. A
  vendor ROM that hides the Wi-Fi client while the access point is up therefore
  shows "Waiting for the hotspot". This is fail closed, and it needs a
  real-phone test.
- The hotspot watch closes at once when the bound address belongs to an
  interface that a reported network holds. It debounces only an uncertain
  probe: a missing or incomplete read, or an API 36 set that no longer names
  the bound interface. It stops after 3 consecutive misses at 2 seconds. One
  good check clears the count. The watch reports at most one loss and never
  restarts the proxy.
- Bluetooth PAN tethering uses the name rules on Android 15 and earlier and is
  not detected there. `bt-pan*` names both a tether and a client, and the
  public API before Android 16 does not say which is active. On Android 16
  (API 36) or later a named `bt-pan*` interface is accepted from the
  `TetheringManager` callback. Real OEM and device behavior is unverified.
- Android 15 and earlier have no public API that names the tethering
  interface. The app requests no system or proprietary permission, so the name
  rules remain the only discovery evidence there. OEM builds can hide the
  client, report the access point as a network, or use an unknown name.
- The API 36 tethering callback has JVM tests only. The fake registration and
  fake interfaces do not prove that a phone delivers the callback, that an OEM
  ROM names every tethered interface, or that the platform reports no
  tethering when it delivers an empty set. A conflict between the callback and
  the network observation fails closed and shows "Waiting for the hotspot".
  The app trusts the platform list, so a ROM that names a different up,
  non-cellular interface with a private IPv4 address can still make the finder
  choose that address. The conflict rule covers only networks that
  `ConnectivityManager` reports. The callback arrives asynchronously. The
  finder waits while the initial reading is pending, then uses the name rules
  if the bounded wait expires without a usable reading.
- The pairing listener closes a connection that sends no complete frame within
  10 seconds. It allows at most four idle sockets and evicts the oldest idle
  socket when a new target device connects.
- The resolver test used the emulator default network, not a cellular bearer.
- The loopback bridge is a test tool. The service binds one hotspot address.
- With both Wi-Fi and USB tethering, a strong Wi-Fi name ranks above `rndis`;
  an inferred `wlan` name ranks below it. Actual OEM naming remains unverified.
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
