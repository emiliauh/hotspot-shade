# Source Device Proxy Mode

This document describes the optional source device proxy mode. The source
device provides the connection. The target device needs internet access.

In this mode, the target device runs a local SOCKS5 listener. The listener
forwards every TCP CONNECT to the HotspotShade app on the source device. The
source device resolves the domain name and opens the connection on its
cellular path. The carrier therefore sees source device traffic.

This mode is separate from the direct mode in `README.md`. It creates no utun
and changes no route. It needs no root. It does not replace the direct mode.
The behavior and the measurements are experimental. The first section records
them.

## Experimental target device tunnel

The Rust source enables `TCP_NODELAY` on source device proxy mode outer TCP
sockets. This includes TCP forwarding, DNS, UDP over TCP, and experimental
echo. This change has passed loopback tests. Its live latency effect is not yet
measured.

### TCP reliability changes (not yet measured live)

These changes target the TCP-carried path. They have passed hermetic tests and
an iOS typecheck. They have not been run on a physical source device. Rebuild
and reinstall the source device app to get the source device changes.

- The source device app sets `noDelay` on the listener and on the cellular
  outbound TCP connection. Replies from the source device to the target device
  no longer wait for a delayed ACK. The earlier source device build did not set
  it.
- The source device keeps a UDP-over-TCP flow after a transient cellular
  error. The errors are `ENOBUFS`, `EAGAIN`, `ECONNREFUSED`, `EHOSTUNREACH`,
  and `ENETUNREACH`. The source device drops that one datagram. It closes the
  flow after 16 errors in a row. Other errors still close the flow at once.
- The target device queue for one UDP-over-TCP flow is 128 KiB. It was
  512 KiB. At 1.16 MB/s of upload, 512 KiB is about 450 ms of queued delay.
  128 KiB is about 110 ms. When the queue is full, the target device drops the
  new datagram and counts it in `udp_dropped`. The 512 KiB limit for incoming
  frames is unchanged.
- The target device drops a queued UDP-over-TCP datagram that waits more than
  250 ms for the source device stream. The target device never cuts a frame
  that the stream has partly accepted. The age limit does not apply to DNS
  flows. It starts after the source device handshake ends. The target device
  counts each aged drop in `udp_dropped`. `udp_datagrams_out` counts the
  datagram when it enters the queue. A dropped datagram thus appears in both
  counters.
- When the source device closes a UDP-over-TCP flow after transient cellular
  errors, the source device log line states how many sent and received
  datagrams it dropped. The source device cannot count a datagram that the
  kernel drops when the target device stops reading. That loss stays invisible.
- The IPv6 route check runs every 5 seconds. A route that does not match the
  policy still stops the tunnel at once. A check that cannot finish (timeout or
  spawn error) now needs 3 failures in a row. The stop message now states the
  reason. The earlier build stopped on the first failed check.

### Source device connect hold

In source device proxy mode the target device holds the inner SYN-ACK until the
source device app answers the connect request with SOCKS reply 0. The browser
therefore stays in "connecting" until the source device path is ready. The
earlier build completed the inner handshake at once, so a failed source device
connect left a "connected" socket that hung for 4 to 5 seconds and defeated
Happy Eyeballs.

- A duplicate SYN is a retransmit. The target device ignores it and never starts
  a second outer connection.
- Inner data that arrives while the start is held is ignored. The correct client
  cannot send data before the SYN-ACK.
- A refused, unreachable, or timed out source device connect gets a TCP reset at
  once. The destination is not reported as connected.
- A SOCKS success reply releases the held SYN-ACK. The flow then carries data as
  before.
- Direct mode is unchanged. It completes the inner handshake as soon as the
  outer kernel socket exists.

The relay tests cover a delayed reply, a duplicate SYN, and reply codes 3, 4, and
5.

### Target device connect deadline and connect log

- Normalized TCP connects measure their deadline from socket setup. They check
  cancellation and the deadline again when readiness is reported and before
  returning a connected stream. A cancellation observed at those checks closes
  the socket. This does not prevent a cancellation that happens after the last
  check from racing with the caller.
- The source device gives each outbound destination connection (TCP and UDP)
  4 seconds to become ready. The target device CONNECT timeout is 5 seconds.
  The timers are independent. The target timer starts before the request
  reaches the source device, so it can fire first. The source deadline does not
  guarantee an answer before the target timeout.
- A connection that reports `.waiting` is retried once after 1.5 seconds. The
  retry uses the same host, port, and cellular pin, and it stays inside the 4
  second deadline. A second wait does not start a second retry. A short wait
  keeps the same connection: Network framework can make it ready when the path
  returns. An earlier build canceled the connection after 250 ms. That discarded
  connections that were still viable and started many extra connects. `.unreachable`
  is reported only for a real unreachable error. A deadline that follows an
  unreachable wait is reported as "not ready", not as a slow website and not as
  an unreachable host. A refusal is an answer from the network, so it stays
  `refused`.
- When the deadline fires, the source device cancels the connection. It replies
  with SOCKS code 5 (connection refused) when the last error was
  `ECONNREFUSED`. It replies with code 1 (general failure) in all other cases,
  also when the connection state never changed. A deadline does not prove that
  the destination is unreachable, so code 4 would blame the destination. A
  failed connection gets code 4 for an unreachable network or host, code 5 for a
  refusal, and code 1 for every other error, including a DNS error or a local
  permission error. The source device sends exactly one reply for each request.
- Earlier builds handled only the ready, failed, and cancelled states. A
  connection that stayed in the waiting state got no reply. It held one of the
  128 session slots until the 300 second idle timeout.
- The target device counts reply codes 3 and 4 in `tcp_setup_phone_unreachable`.
  Code 5 counts in `tcp_setup_refused`. Code 1 counts in `tcp_setup_other`, so a
  source device deadline does not look like a destination failure. A code 1
  reply can have other causes. The target also counts a local setup deadline in
  `tcp_setup_timed_out`. The `tcp_setup_timeout_phone_destination` field stays
  in the report for compatibility. These counters do not identify which timer
  fired first or prove that the destination timed out.
- The source device log shows one line for each failed, cancelled, or slow
  destination, in plain words. Examples: "A web connection timed out.", "A web
  connection did not become ready in time.", "A connection to another service
  was slow.", and "A name lookup did not finish." The line names the kind and
  the result. It holds no host, address, port, or timing. A connection is slow
  when it is ready after more than 1500 ms. The source device shows at most 8
  such lines in 10 seconds. It then shows one line "N more connect log lines
  suppressed". The log holds the last 50 lines.
- These lines stay in the on-screen log only. The source device never stores
  them, never sends them to the target device, and never writes them to a file.
- The proxy section shows up to four lines. The first line counts finished
  attempts, for example "12 attempts. 9 worked. 3 did not." When an attempt was
  cancelled, the next line says "1 was cancelled by the target device." or "C
  were cancelled by the target device." The third line counts the failed
  attempts by kind, for example "Did not work: 96 web, 24 DNS lookups, 15 other
  connections." The last line gives the most common reason over real failures
  only. Examples: "Most common reason: the website refused the connection.",
  "Most common reason: the connection did not become ready in time.", "Most
  common reason: the connection timed out.", and "Most common reason: the name
  lookup did not finish." A timeout with no definitive answer does not blame
  the website.
- The full attempt ledger is: attempts = worked + did not work + cancelled +
  closed before a result + still running. A cancelled attempt is not a failure
  and not a success. The target device gave up on the connection. An attempt
  that ends before a result is not a failure.
- The kinds are web (TCP port 80 or 443), other TCP, UDP, and DNS lookups on
  port 53. A tie uses that order. The counters count final results only. They
  reset when the proxy starts. They hold no addresses. ICMP is not counted.
  The number is not a tunnel failure rate. A slow cellular connection can miss
  the 4 second source device deadline, so a reachable destination can count as
  "did not work". A deadline after an unreachable wait counts as "not ready".
  The wait counters show how many waits were unreachable, refused, or other.
  The diagnostics also count waits and failures by destination family: IPv4,
  IPv6, or a name. These counts show where events occurred, but they do not
  show a failure rate because total attempts by family are not recorded. One
  attempt can produce multiple waits. The family counts do not
  show whether the cause was the cellular path, the destination, or the
  network. They are cumulative and do not record when a wait or failure
  happened. A delta before and after a test is needed to tie a failure to an
  event.
- The target device keeps its own record of failed source device connections.
  The source device app does not receive that record. See "Recent failures".

### Long-lived flows

- The source device sets TCP keepalive on its listener and destination sockets:
  60 seconds idle, 10 seconds interval, 3 probes. A carrier NAT can drop an idle
  mapping with no error at either end. The keepalive keeps an idle mapping and
  can detect a peer that is gone. It is not application traffic. The source
  device does not close an open TCP relay solely because it is idle. UDP and
  half-closed sessions still have an idle limit. This policy needs a live
  source-device test.
- The target device answers a TCP keepalive probe on an inner flow with an ACK.
  Without the ACK, a remote desktop or terminal client resets an idle
  connection.
- After 600 seconds of silence, the target device sends up to three inner TCP
  probes at 60-second intervals. It resets a flow that does not answer. It also
  resets a flow when a FIN retransmit limit is reached. A zero-window flow with
  data or a FIN waiting uses separate probes, starting at 300 ms and backing
  off to 60 seconds. It resets after 12 unanswered probes. A peer that answers
  can keep the flow slot while its window remains closed. This behavior needs a
  live paused-reader test.
- The target attempts to enable TCP keepalive on outer relay sockets: 60 seconds
  idle, 10 seconds interval, and 3 probes. A local option failure does not
  reject the flow. Keepalive does not prove that the source device app answers
  its separate presence checks.
- The local SOCKS adapter retries a write that makes no progress, up to 30
  seconds. It does not close an established flow after one 2 second write
  timeout. A busy hotspot can delay a write without breaking the flow.

## Architecture

```
app on the target device
    |
    | SOCKS5, no authentication, 127.0.0.1:1081
    v
hotspotshade phone (target device adapter)
    |
    | SOCKS5, username and password, 172.20.10.1:PORT
    v
HotspotShade app on the source device
    |
    | one cellular connection for each flow
    v
carrier and destination
```

The local listener accepts only loopback addresses. The source device listener
requires the token. The target device sends a domain name to the source device
unchanged. The target device does not call `getaddrinfo()` for a target name.
An app must use remote DNS, for example a `socks5h` URL or the Firefox "Proxy
DNS" option. If an app resolves a name locally, the source device still exits
the flow, but the target device resolves the name first. That is a DNS leak.

The socket to the source device is an outer socket. It uses the helpers in
`rust/src/normalization.rs` and sets TTL 65. The source device link does not
carry the packet to the carrier. The source device re-originates the flow, so
the carrier sees the source device TTL.

## Requirements

- A target device with the `hotspotshade` binary. macOS is verified on a live
  hotspot. Linux and Windows have a source device proxy start path but no live
  hotspot test. Build it as `README.md` describes. On Windows, install
  `wintun.dll` next to the program and run it as Administrator.
- A source device with the HotspotShade app from `ios/`. The app is an iOS
  app built with Xcode.
- Personal Hotspot enabled on the source device.
- The target device connected to the hotspot.
- The hotspot IPv4 address of the source device. The usual value is
  `172.20.10.1`.

## Source device setup

1. Build and install the app. Follow `ios/README.md`.
2. Enable cellular data and Personal Hotspot.
3. Connect the target device to the hotspot.
4. Open HotspotShade. Keep the app open.
5. Set the port. The app chooses a port from 20000 to 59999 by default. You
   can select a port in Settings, Advanced.
6. Tap Start. Allow local network access when iOS asks.
7. Allow Location when iOS asks. The app uses it to stay awake.
8. To see the token, open Settings, Advanced, and tap Show token. The token
   hides again after 30 seconds.

The app shows the local addresses of the source device. Select the address on
the hotspot network. A free Apple ID profile expires after seven days. Build
and install the app again when the profile expires.

## Target device setup

Check the token first. Use the proxy port that the source device shows in
Settings, Advanced:

```
hotspotshade phone --phone 172.20.10.1:PROXYPORT --check
```

The command asks for the token with a hidden prompt. It can also read the
token from the `HOTSPOTSHADE_PHONE_TOKEN` environment variable or from a
private descriptor (`--secrets-fd`). Do not put the token on the command line.
The command checks authentication and exits. A nonzero exit code means that
the check failed. The message does not print the token.

Start the local listener:

```
hotspotshade phone --phone 172.20.10.1:PROXYPORT
```

The default listen address is `127.0.0.1:1081`. Change it with `--listen`:

```
hotspotshade phone --phone 172.20.10.1:PROXYPORT --listen 127.0.0.1:1081
```

Stop the listener with Ctrl-C. The listener closes every active flow.

The GUI can also find the source device. It checks the default gateway and
tries ports 1080 and 18080. A TCP response does not prove that the listener is
the source device proxy. Enter the token and select Check connection to
authenticate it. The service holds the token. The browser never receives it.

## Full tunnel mode

The optional `tun --phone` mode forwards captured IPv4 and IPv6 TCP flows
through the authenticated source device proxy. It forwards captured UDP DNS
queries as DNS over TCP to `1.1.1.1:53` through the source device. Other
captured UDP uses one framed TCP connection per flow and a UDP connection from
the source device.

This path is experimental. It can add delay to games and calls. The mode adds a
tunnel address and a `2000::/3` route, so global IPv6 goes through the source
device proxy. The mode rejects `--ipv6 block` and `--ipv6 inherit`. More
specific IPv6 routes can bypass the tunnel. See "IPv6 in source device proxy
mode" below.

ICMP echo is off by default on this command line. Add `--experimental-icmp` to
relay IPv4 and IPv6 echo requests. Add `--experimental-icmp-persistent` to use
one authenticated echo stream per inner 4-tuple. The GUI and the target device
app turn the relay on by default.

Keep the source device app open. Leave "Keep running in the background" on. The
source device app must use the hotspot address and port shown on its screen.

The mode requires root for the device and routes. The token comes from
`--secrets-fd`, the `HOTSPOTSHADE_PHONE_TOKEN` environment variable, or a hidden
prompt. Preserve the variable when you start `hotspotshade tun --phone` as root.
Do not put the token in a command line or a shell history file. Stop the process
with Ctrl-C so it can remove its routes.

The relay allows one outstanding DNS query per UDP flow. Concurrent queries on
the same flow can time out. The resolver and the DNS traffic between the source
device and the resolver are not encrypted by this mode.

This mode is not a system-wide fail-closed solution. More-specific routes can
bypass the tunnel. In particular, DNS addressed to the hotspot gateway can use
its existing local route. Network extensions can intercept traffic before the
tunnel. Local networks and some IPv6 traffic can also bypass the tunnel. The
route changes do not prevent bypass when the service stops or crashes. Do not
rely on this mode to keep all traffic on the source device proxy.

A live test on 2026-11-02 sent one HTTPS request and one DNS query through the
tunnel and the source device proxy. Both succeeded. The TTL audit reported zero
bad sockets. The hotspot gateway route bypassed the tunnel. The test does not
establish system-wide coverage or long-term reliability.

The same HTTPS and DNS tests passed while the source device app was on the Home
screen with background operation on. A separate proxy request also passed after
30 seconds in the background. These short tests do not establish reliability
after screen lock, extended use, or iOS suspension.

## IPv6 in source device proxy mode

The IPv6 policy is not the same in both modes.

- Direct mode uses `--ipv6 block` by default. It installs a blackhole route for
  `2000::/3` and drops IPv6 packets in the relay.
- Source device proxy mode always forwards IPv6. It adds a tunnel address and a
  `2000::/3` route to the utun. IPv6 TCP, UDP, DNS, and ICMP echo go through the
  source device proxy. The mode rejects `--ipv6 block` and `--ipv6 inherit`.
  The GUI and the target device app do not offer a policy choice.

The carrier sees the source device connection, not the inner IPv6 packet. More
specific IPv6 routes can bypass the tunnel. Loopback and link-local traffic is
not captured. The mode does not offer an IPv6 block policy today.

## Automatic stop

The GUI and target device app check the hotspot link every 2 seconds while a
tunnel runs. The check needs the pinned interface, an up state, and a usable
IPv4 address. In source device proxy mode the check also uses the presence
probe. The command-line tunnel also uses this policy when the interface is
known. While a source device tunnel runs, GUI presence probes continue even if
no app or web page polls the service. The probes use the source device address
and interface selected at start. An unknown interface or an interface
observation error is not evidence of link loss. If the interface for a source
device probe cannot be resolved, the service does not send an unpinned probe.
It cannot use that probe to decide that the source device is gone. One probe
allows 2 seconds for the connection and 2 seconds for the exchange. A slow
connect does not use up the exchange budget.

| Condition | Reason | Message |
|---|---|---|
| The link is down for 20 seconds | `hotspot_lost` | The hotspot turned off, so HotspotShade turned the tunnel off. |
| The link is up, and the source device app does not answer for 90 seconds | `source_device_gone` | The source device stopped answering, so HotspotShade turned the tunnel off. |

`not_running` and `not_responding` count as silence. `proxy_off`, `ready`,
`connected`, `unpaired`, and `not_trusted` count as an answer. One good sample
resets the timer. The stop uses the normal graceful path, so it removes the
routes, the IPv6 address, and the utun. The reason and the message are in
`GET /api/status` under `last_stop` and `last_stop_message`. A new start clears
them.

Nothing turns the tunnel back on. The person turns it on again after the
hotspot or the source device returns. The target device app and the web page show the
message. The source device app stops its proxy after 20 seconds of observed
absence of its bound hotspot address. Gaps and unreadable observations restart
the interval. Its pairing listener uses a separate check. See [ios/README.md](ios/README.md)
for its timing.

## Recent failures

When the source device tunnel runs, the target device keeps a short record of
failed source device connection attempts. Use it to find the cause when some
sites or apps do not work. The record is local to the target device. It is not a
source device counter and it is not sent to the source device.

The web page shows a "Recent failures" card with "Copy as text". The target
device app shows Settings, Advanced, "Recent failures", with Refresh and "Copy
report". The card lists groups with the largest count first. The app and the web
page show at most 50 groups. Both show the setup stage in plain words: "Source
connection", "Greeting", "Sign-in", or "Destination request". A missing stage
shows "Not reported" in the app and no stage in the web page. An unknown stage
shows "Unknown stage".

Limits:

- The record holds the last 200 failures and at most 100 groups.
- The name hints come from DNS answers that the relay forwards. A name is
  absent when no relayed answer supplied one. The name map holds at most 2000
  addresses.
- The record is memory only. It is never written to disk, never sent to the
  source device, and never put in a log. It holds no token.
- The record is cleared when the tunnel starts or stops. It is empty when no
  tunnel runs.
- A dropped count above zero means that the recorder was busy or that the group
  table was full. The total still counts those failures.

### `GET /api/failures`

The route needs the Bearer secret when the GUI has one. A normal answer is
HTTP 200. The shape is:

```json
{
  "ok": true,
  "since": 1760000000,
  "total": 3,
  "dropped": 0,
  "groups": [
    {
      "proto": "tcp",
      "family": "ipv4",
      "port": 443,
      "reason": "unreachable",
      "phase": "request",
      "count": 2,
      "name": "example.com",
      "example_ip": "203.0.113.5",
      "code": 4
    }
  ],
  "recent": [
    {
      "ts": 1760000001,
      "proto": "tcp",
      "family": "ipv4",
      "ip": "203.0.113.5",
      "port": 443,
      "reason": "unreachable",
      "phase": "request",
      "name": "example.com",
      "code": 4
    }
  ]
}
```

`since` is the Unix time in seconds when the tunnel started. It is null when no
tunnel runs. `total` counts all failed attempts. `dropped` counts the failures
that the recorder could not keep. Each group has these fields:

| Field | Values |
|---|---|
| `proto` | `tcp`, `udp`, or `dns` |
| `family` | `ipv4` or `ipv6` |
| `port` | Destination port. A DNS group uses 53 |
| `reason` | `unreachable`, `refused`, `timed_out`, `denied`, or `other` |
| `phase` | `connect`, `greeting`, `auth`, or `request`, or null |
| `count` | Failures in the group |
| `name` | A name from a relayed DNS answer, or null |
| `example_ip` | One destination address in the group |
| `code` | The SOCKS reply code, or null |

The `phase` field names the setup stage where the source device connection
stopped. The field is additive. An older engine sends no `phase`, and the apps
must show the row without a stage. A newer engine can send a word that the apps
do not know, and the apps must show "Unknown stage".

| Phase | Meaning |
|---|---|
| `connect` | The target device opened the connection to the source device |
| `greeting` | The devices exchanged the proxy greeting |
| `auth` | The target device signed in to the source device |
| `request` | The target device sent the destination request and waited for the source device answer |

A local timeout at any source device phase is `other`, not `timed_out`. It means
that the target device stopped waiting. It does not prove that the destination
timed out. A SOCKS reply code is the only proof that the destination answered.
For example, code 4 at phase `request` is a real unreachable report.

An authentication method or token rejection from the source device is
`denied`. A local socket permission error is `other`. The aggregate
`tcp_setup_permission_denied` diagnostic counter includes both kinds of
permission error.

The `recent` list holds the latest failures, newest first. Each item has `ts`
in Unix seconds, `proto`, `family`, `ip`, `port`, `reason`, `phase`, `name`, and
`code`. The list shows at most 100 items.

In demo mode the answer also has `"demo": true` and simulated values. When no
tunnel runs, `since` is null, `total` is 0, `dropped` is 0, and both lists are
empty.

### Failure report formats

"Copy as text" in the web page writes one line per group:

```text
2x web ipv4 443 unreachable request example.com 203.0.113.5
1x dns ipv4 53 timed_out request 1.1.1.1
```

The word after the count is the web page kind: `web`, `tcp`, `udp`, `dns`, or
`other`. The remaining fields are the family, the port, the reason, the phase,
the name when present, and the example address. A missing phase shows as `-`.
An unknown phase shows as `unknown`. The phase keeps two groups apart when every
other field is equal.

"Copy report" in the target device app writes one header line and one line per
group:

```text
HotspotShade failures since 2026-11-03T12:00:00Z: 3 failed connections, 0 dropped.
2x tcp ipv4 443 unreachable request example.com 203.0.113.5 code 4
1x dns ipv4 53 timed_out request - 1.1.1.1
```

A missing name, address, or phase shows as `-`. The code appears only when the
engine sends one. An unknown phase shows as `unknown`.

## Pairing

The GUI gets the source device token, port, and host. Confirm the six-digit
code on the source device. A known target device can pair again without a tap.
The service holds the credentials in memory. The browser never receives the
token.

The pairing listener runs while the source device app is open and the hotspot
interface is present. It runs when the proxy is stopped. A status-only HELLO
adds a flags byte with bit 0 set. A known target device proves its key before
it requests encrypted status. The source device does not send the token or
log a pairing for this exchange. An unknown target device receives status 3
without a prompt. A 66-byte HELLO retains the original pairing behavior.

The app checks the hotspot interface every 2 seconds while the proxy runs and
every 5 seconds while the proxy is stopped. It does not check while the app is
inactive. The pairing listener stops after 15 missed checks. It re-arms the
pairing listener when the app returns to the foreground if the listener is not
ready.

The app shows the pairing prompt only while it is in the foreground. A pending
decision gets 120 seconds when the app goes to the background.

On Android, `android/app/src/main/java/com/hotspotshade/source/pairing/`
implements the same responder and test vectors in Kotlin. The listener binds
the hotspot address and TCP port 18090 only. It runs while the activity is
visible. The activity stops it on `onStop`, so it does not pair in the
background and the hidden-prompt extension is not used by the app. The prompt
has a "Real pairing request" label. A separate preview dialog stays simulated.
A successful pairing writes the proxy token to the Android Keystore store. The
pairing result names a saved proxy port from 20000 to 59999. Android API 26 has
no platform X25519 or ChaCha20-Poly1305, so the app has small in-tree
implementations of RFC 7748 and RFC 8439 and uses the platform HMAC-SHA256.
The JVM tests hold the RFC vectors and the same parity vectors as the Rust and
iOS suites. `android/README.md` has the build and emulator interop commands.

Forget clears the local credentials. When the tunnel runs or is starting or
stopping, the target device refuses the request with this message:

> Turn off the tunnel first.

The API answers with HTTP 409 and the code `tunnel_running` in that case.
Forget also cancels a pairing that is in progress.

When the tunnel is off, the target device sends a best-effort FORGET message
after a HELLO with bit 1 set and probes the source device at once. It clears the
local credentials in all cases, also when the source device is unreachable. A
rejected FORGET counts as success: the source device no longer trusts the key.
A failed attempt stays pending. The service retries after the next presence
probes, for 3 attempts in total, whether or not the source device answers. The
state is `pending` while attempts remain. It ends as `confirmed` or
`not_delivered`, unless a new pairing clears it. A new pairing cancels a pending
FORGET.

The source device removes that target device key and answers with an empty
successful RESULT. A later pairing needs confirmation.

The service reports one of these states for the source device. The text is
fixed and holds no credentials.

| State | Message | Meaning |
|---|---|---|
| `no_hotspot` | Turn on Personal Hotspot on your source device. | The default route has no gateway. |
| `not_running` | HotspotShade is not running on your source device. | The TCP connection to port 18090 was refused. |
| `unpaired` | Not paired. Open HotspotShade on your source device, then pair. | The app answered a status-only HELLO, and this target device has no credentials. |
| `not_trusted` | The source device does not know this target device. Pair again. | The app answered an authenticated status request with a rejection. |
| `not_responding` | Open HotspotShade on your source device and keep it open. | The connection opened, but no valid status answer arrived. A timeout, an unreachable path, or a local error is not proof that the app is off. |
| `checking` | Checking the source device. | A phone tunnel runs, but the last probe is old or monitoring failed before an answer. This is not proof of a failure. |
| `proxy_off` | Start the proxy on your source device. | The authenticated status answer reports a stopped proxy. |
| `ready` | The source device is ready. | The authenticated status answer reports a running proxy. |
| `connected` | Connected to the source device. | The tunnel runs in source device proxy mode, and the last probe is `ready` or no probe has finished yet. |

The status answer is authenticated and encrypted. A TCP connection alone does not
set `proxy_off`, `ready`, or `connected`. The unpaired probe sends one status-only
HELLO. It uses the optional flags byte that protocol v1.1 already defines. It adds
no new message or field, and the parity vectors do not change. An unknown target
device gets a rejection without a prompt.

A manual-token tunnel has `paired: false` when the service holds no paired
credentials. Its unpaired probe can report `unpaired` while the tunnel runs.
Probe failures stay visible. Before the first probe finishes, the state can be
`connected`. If monitoring fails or its result becomes stale, the status
reports `checking`. It does not keep reporting a stale connection as current,
and it does not claim that the source device failed.

A running tunnel keeps the port that it started with. When the learned port
differs from that port, the target device shows this message instead:

> The source device changed its port. Turn the tunnel off and on.

The target device rejects a status answer that names a host other than the
address it connected to.

### Use it

1. Start the proxy in the source device app.
2. Open the GUI. Select the Source device proxy mode.
3. Select "Pair with source device". The GUI shows a code, for example
   "482 193".
4. Check that the source device shows the same code. Tap Allow on the source
   device.
5. The GUI shows "Paired." Select Start session.

If you start before you pair, the GUI pairs first. It starts after the pairing
succeeds. The credentials stay in the GUI process memory. Pair again after the
GUI restarts. A paired target device gets the result with no tap. Pair again
after you rotate the token on the source device. Trust survives a token
rotation.

In the target device app, the app starts automatic pairing for each launch and
tries again every 10 seconds while the source device is reachable. Cancel stops
automatic pairing for the current launch only. Forget is saved: the app does
not pair again until the person selects Pair. A token rejected at
start also stops automatic pairing until Pair. After a successful pairing, Check
now, or Forget, the app probes the source device at once.

### Proxy port

The source device owns the proxy port. On the first run it picks a random port
from 20000 to 59999 and saves it. It never picks 18090, because the pairing
listener uses that port.

The user can select a port in the source device app. The app accepts a port
from 1024 to 65535, except 18090.

The target device learns the port from the pairing result and from the STATUS
answer on the pairing channel. Both messages are authenticated and encrypted.
The target device does not learn the port from a TCP connect or from an
unauthenticated packet. It accepts a new port only when the STATUS answer names
the hotspot gateway and a usable port. The token never changes.

A running tunnel keeps the port that it started with. Turn the tunnel off and
on to use a new port. The target device does not set the port on the source
device. That feature is not implemented.

A port gives no security by itself. The token and the pairing channel protect
the proxy.

### Protocol v1.1

The target device connects to the source device hotspot address on TCP port
`18090`. The source device listens on its hotspot address while the app is open
and the hotspot interface is present. The target device uses a normalized outer
socket with TTL 65 and pins it to the hotspot interface. The target device uses
the discovered gateway. The browser cannot choose the host.

Each message is a u16 big-endian length and a payload of 1 to 512 bytes. Both
sides reject a larger frame. All integers are big-endian.

Names: `L_s` is the target device static public key. `L_e` is the target device
ephemeral public key. `P_e` is the source device ephemeral public key. All keys
are X25519.

| Message | Direction | Bytes |
|---|---|---|
| HELLO | target to source | `[0x01][0x01][L_s:32][C:32][flags:1 optional]`, `C = SHA256("hotspotshade-commit-v1" \|\| L_e \|\| L_s)` |
| CHALLENGE | source to target | `[0x02][P_e:32][known:1]` |
| REVEAL | target to source | `[0x03][L_e:32][proof:32]` |
| RESULT | source to target | `[0x04][status:1]`, then `[nonce:12][ciphertext and tag]` when status is 0 |
| STATUS_REQ | target to source | `[0x05][nonce:12][ciphertext and tag]` |
| STATUS | source to target | `[0x06][nonce:12][ciphertext and tag]` |
| FORGET | target to source | `[0x07][nonce:12][tag]`, with empty encrypted plaintext |

The source device can send a non-zero RESULT instead of CHALLENGE, for example
when it is busy.

Key schedule:

- `ee = X25519(L_e, P_e)` and `es = X25519(L_s, P_e)`. Both sides reject an
  all-zero (low-order) result.
- `h = SHA256("hotspotshade-pair-v1" || L_s || L_e || P_e)`
- `prk = HKDF-Extract(salt = h, ikm = ee || es)`
- `k_enc`, `k_proof` (32 bytes each), and `sas` (4 bytes) are HKDF-Expand
  outputs with the info strings `enc`, `proof`, and `sas`.
- The code is the u32 of `sas` modulo 1000000, as 6 digits with leading zeros.
  Both screens show it as two groups of three digits.
- `proof = HMAC-SHA256(k_proof, "laptop" || h)`. The label `laptop` is a wire
  label. The source device checks the proof in constant time.
- The RESULT plaintext is `[port:u16][token_len:u8][token][host_len:u8][host]`.
  It is sealed with ChaCha20-Poly1305, key `k_enc`, a random 12-byte nonce, and
  `h` as associated data. The target device checks every length. It rejects a
  host that differs from the address it connected to.

After proof, a trusted target device can request status. Each status message
uses ChaCha20-Poly1305 with `k_enc`, a new random nonce, and `h` as associated
data. STATUS_REQ plaintext is `[challenge:16][flags:1]`. STATUS plaintext is
`[challenge:16][seq:u32][proxy_running:1][foreground:1][connections:u16][port:u16][host_len:1][host]`.
The source device app sends sequence 0. The target device checks the challenge
and requires an IPv4 host. The version byte stays 1.

The source device allows one decision prompt at a time. It accepts at most
three verified unknown handshakes from one source address in ten minutes. A
busy response does not consume that budget. A denial counts toward the source
address lockout. A timeout counts only if the prompt was visible and the app is
active. A timeout-only lockout is not reachable. The failure record drops an
entry that is 60 seconds old. A visible prompt has a 60 second deadline and an
inactive prompt has a 120 second deadline, so three timeout failures cannot
stay in the record together. A denial can still reach the lockout. A timeout
can be part of a mixed set of three failures. The lockout applies to that
source address only. A lockout clears the prompt-attempt budget of that source
address, so the source device serves a REVEAL after the lockout ends. A known
target device can pair during an unknown peer lockout. Invalid messages use a
separate back-off. The trust list contains public keys.

Both responders limit an unknown source address to four CHALLENGE
messages in 60 seconds and all unknown source addresses to eight CHALLENGE
messages in 60 seconds. They charge both budgets before they create the
ephemeral secret, so a refused handshake creates no session. The Rust responder
checks the pairing credentials first. It answers NotActive and charges no
budget while pairing is off.

Both responders bind an approval to the connection, the prompt ID, and the
code that the person saw. They reject a stale connection, a stale prompt ID, a
different code, and an expired deadline. They read no prompt after the deadline
and extend a prompt only while it is live.

The target device allows 2 seconds for the connection and the first reply
together. A silent source device produces "Open HotspotShade on your source
device and keep it open." The fixed port does not provide security. The key
exchange, commitment, code, and trust list provide the pairing protection.

Both test suites hold the same fixed vectors (private keys of all `0x11`,
`0x22`, and `0x33` bytes, a nonce of `0x44` bytes, token
`test-token-0123456789abcdef`, port 1080, host `172.20.10.1`). The expected
code is `500 104`. A change on one side breaks both suites.

### Local API

The GUI accepts `--port 0` for an ephemeral loopback port. `--port-file PATH`
writes the selected port to a private file. `--token-fd N` reads a
64-character lowercase hex secret. With a secret set, `/api/` requests require
a Bearer header. Static assets remain available without it.

The `/api/` routes are:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | Service status, pairing state, forget state, last stop, and ping state |
| GET | `/api/failures` | Failed source device connection record |
| GET | `/api/diagnostics` | Relay counters and timing reservoirs. It holds no address |
| POST | `/api/start` | Start a tunnel. The body names the mode and its options |
| POST | `/api/stop` | Stop the tunnel |
| GET | `/api/logs?since=N` | Service log lines with a sequence number |
| GET | `/api/probe` | Local network facts. It changes nothing |
| GET | `/api/phone/discover` | Check the hotspot gateway and likely proxy ports |
| POST | `/api/phone/check` | Test one source device token |
| GET | `/api/phone/pair` | Read the pairing state |
| POST | `/api/phone/pair` | Start pairing |
| POST | `/api/phone/pair/cancel` | Cancel pairing |
| POST | `/api/phone/forget` | Forget the paired source device |
| POST | `/api/phone/probe` | Probe the source device now. At most one probe per 500 ms |

`POST /api/phone/pair` starts pairing. `GET /api/phone/pair` reads the state.
`POST /api/phone/pair/cancel` cancels pairing. `POST /api/phone/forget` clears
the in-memory credentials and cancels a pairing that is in progress. It refuses
the request while the tunnel runs or is starting or stopping. The response is an
error with the message "Turn off the tunnel first." The HTTP status is 409 and
the code is `tunnel_running`. Otherwise it sends a best-effort FORGET to the
source device, probes at once, and always clears the local credentials. A
rejected FORGET counts as success. A failed attempt stays pending. The service
retries after presence probes for 3 attempts in total, whether or not the source
device answers. The attempt ends as `confirmed` or `not_delivered`, unless a new
pairing clears it.

`POST /api/phone/probe` runs one source device presence probe now and returns
the latest phone object. The service runs at most one probe in 500 ms. A second
call inside that window returns the cached result. The answer is
`{"ok": true, "phone": {...}}`. Demo mode adds `"demo": true`.

The web page has Check now, Forget, and Copy diagnostics. It shows
`last_stop_message` in an alert above the status. Copy diagnostics writes the
plain-text summary of `GET /api/diagnostics`.

Pairing can start from the `unpaired` state and from the `not_trusted` state.
A new pairing replaces stale credentials. A failed pairing attempt keeps the
existing credentials, so the target device stays `not_trusted` and can try
again.

`GET /api/status` has this shape. `stats` is shortened here. It holds the relay
counters that the page shows:

```json
{
  "api": 1,
  "running": true,
  "mode": "phone",
  "started_at": 1760000000,
  "icmp_enabled": true,
  "stats": {
    "ttl_bad": 0,
    "dns_flows": 1,
    "dns_setup_ok": 1,
    "dns_setup_failed": 0
  },
  "error": null,
  "logs": [],
  "demo": false,
  "platform": {
    "os": "macos",
    "arch": "aarch64",
    "admin": false,
    "default_iface": "en5",
    "default_iface_name": "en5"
  },
  "iface": "en5",
  "paired": true,
  "phone_host": "172.20.10.1",
  "phone_port": 20000,
  "phone": {
    "state": "connected",
    "message": "Connected to the source device.",
    "port_changed": false,
    "connections": 3,
    "checked_at": 1760000001,
    "trusted_by_source": null
  },
  "forget": {
    "state": "none",
    "attempts": 0
  },
  "last_stop": {
    "reason": null,
    "at": null
  },
  "last_stop_message": null
}
```

`icmp_enabled` is true only when the tunnel runs in phone mode and the echo
relay is on. It is false in the other modes and when the tunnel is off.
`iface` is the interface that the tunnel pins to. When no tunnel runs it is the
physical default interface, or null.

`paired` is true only when the service holds paired credentials. A manual-token
tunnel without stored credentials has `paired: false` and can report
`unpaired`. `phone.connections` is the active connection count from the last
authenticated STATUS answer. It is null when no valid answer arrived.

`phone.state` is the real presence probe result while a tunnel runs. The value
is `connected` only when the tunnel runs and the probe is `ready`, or when no
probe has finished yet and the observer has not failed. A probe that reports `not_trusted` stays visible while
the tunnel runs. `phone.checked_at` is the Unix time of the last completed
probe, or null. `phone.trusted_by_source` is true or false only after an unpaired
probe receives a CHALLENGE. It is true when the source device still knows this
target device key. It is null in the other cases.

`forget.state` is `none`, `pending`, `confirmed`, or `not_delivered`.
`forget.attempts` counts the completed best-effort FORGET attempts. It is 0 to
3. A new pairing clears the state.

| `forget.state` | Meaning | Target device app text |
|---|---|---|
| `none` | No forget ran, or a new pairing cleared it | No message |
| `pending` | A FORGET is in flight or waits for a retry | Forgetting... |
| `confirmed` | The source device removed the target device key, or rejected the request | Forgotten. The source device removed this target device. |
| `not_delivered` | 3 attempts ended without a confirmed answer | The source device did not answer. This target device forgot the pairing, but the source device may still trust it. |

`last_stop` holds the reason and Unix time of the last completed stop. The
reason is `user`, `hotspot_lost`, `source_device_gone`, or `error`. The object is
`{"reason":null,"at":null}` before the first stop. A new start clears it.
`last_stop_message` is the fixed automatic-stop text for `hotspot_lost` and
`source_device_gone`. It is null for a user stop and for an error stop.

| `last_stop.reason` | Meaning | `last_stop_message` |
|---|---|---|
| `user` | The person stopped the tunnel | null |
| `hotspot_lost` | The hotspot link was down for 20 seconds | The hotspot turned off, so HotspotShade turned the tunnel off. |
| `source_device_gone` | Fresh probes said the source device app was silent for 90 seconds | The source device stopped answering, so HotspotShade turned the tunnel off. |
| `error` | The service stopped after an error | null. Read `error` and the log |

Nothing restarts the tunnel after any stop. A new start clears `last_stop`.

`GET /api/status` also has a `stats` object. The DNS counters are `dns_flows`,
`dns_setup_ok`, and `dns_setup_failed`. The backend probes while the page makes
requests. It probes every 2 seconds for 10 seconds after a request, then every
10 seconds. When no source device tunnel runs, it stops after 5 minutes without
a request. During a source device tunnel it probes every 2 seconds. Demo responses are
simulated.

### `GET /api/diagnostics`

The route needs the Bearer secret when the GUI has one. It returns the relay
counters and bounded timing reservoirs. The shape when no tunnel runs is:

```json
{
  "ok": true,
  "running": false,
  "engine": {
    "version": "0.1.0",
    "uptime_s": 0,
    "workers": 0
  },
  "setup": {
    "connect_ms": {"count": 0, "p50": 0, "p95": 0, "max": 0},
    "greeting_ms": {"count": 0, "p50": 0, "p95": 0, "max": 0},
    "auth_ms": {"count": 0, "p50": 0, "p95": 0, "max": 0},
    "request_ms": {"count": 0, "p50": 0, "p95": 0, "max": 0}
  },
  "dns": {
    "lookups": 0,
    "ok": 0,
    "failed": 0,
    "ms": {"count": 0, "p50": 0, "p95": 0, "max": 0}
  },
  "queues": {
    "input": [{"peak": 0, "max_age_us": 0}],
    "output": {"peak": 0, "max_age_us": 0}
  },
  "udp": {
    "flows": 0,
    "age_drops": 0,
    "evicted": 0
  },
  "tcp": {
    "flows_peak": 0,
    "capacity_refused": 0,
    "retransmits": 0,
    "zero_window_ms": 0
  },
  "established": {
    "bucket_s": 1,
    "window_s": 60,
    "buckets": []
  },
  "failures": {
    "total": 0,
    "dropped": 0
  }
}
```

When a tunnel runs, `running` is true. `engine.uptime_s` and `engine.workers`
hold the live values. `queues.input` has one entry per relay worker. The values
have these meanings:

| Field | Meaning |
|---|---|
| `setup.*_ms` | Time for the source device connect, greeting, auth, and request phases. Each value is `count`, `p50`, `p95`, and `max` in milliseconds |
| `dns.lookups`, `dns.ok`, `dns.failed` | DNS lookup counts. `dns.ms` is the lookup time object |
| `queues.input` | Input queue peak packet count and oldest packet age for each worker. `max_age_us` is microseconds |
| `queues.output` | Output queue peak packet count and oldest packet age |
| `udp.flows` | UDP-over-TCP flow count |
| `udp.age_drops` | Datagrams dropped because they waited too long |
| `udp.evicted` | Idle UDP flows closed to make room for a TCP flow |
| `tcp.flows_peak` | Largest number of open inner TCP flows |
| `tcp.capacity_refused` | TCP connections refused because the worker was full |
| `tcp.retransmits` | Inner TCP retransmits |
| `tcp.zero_window_ms` | Time that an inner TCP flow had a full receive window |
| `established.bucket_s`, `established.window_s` | Timeline bucket length and count. The values are 1 second and 60 buckets |
| `established.buckets[].age_s` | Age of the bucket in seconds. 0 is the current, partial bucket |
| `established.buckets[].observed` | True when a worker saw an established flow in that second |
| `established.buckets[].tcp_retransmits` | Inner TCP retransmits in that second |
| `established.buckets[].window_limited_ms` | Total time that inner TCP flows had a full receive window in that second |
| `established.buckets[].tcp_teardowns` | Established TCP flows that closed in that second |
| `established.buckets[].udp_teardowns` | UDP flow entries that closed in that second, including failed source device setup |
| `established.buckets[].udp_drops` | Datagrams dropped inside the relay in that second |
| `established.buckets[].relay_drops` | Packets dropped at a relay input or output queue, or when packet construction failed, in that second |
| `established.buckets[].outer_errors` | Outer TCP socket read or write errors in that second |
| `failures.total`, `failures.dropped` | Failure record counts for the current tunnel |

The `established` timeline keeps the last 60 seconds. It starts when the relay
starts. A bucket that is absent is before the relay started or older than the
window. `observed` is
false when no worker saw an established flow in that second. A false value means
no observation. It does not mean zero packet loss. Use a bucket with
`observed` true to tie an event to a second. The newest bucket is partial.

The target and source device timelines use different start events. The target
observes a TCP flow after the outer connection is ready. It can observe a UDP
flow after its socket is ready. Neither event requires payload. The source
device counts an established relay start only after the first TCP payload or
UDP datagram. Do not compare the two start counts as equal events.

`outer_errors` is an error on the outer socket of the relay. `udp_drops` and
`relay_drops` are local drops inside the relay. The fields do not prove a
source path loss, a carrier drop, or end-to-end packet loss. One bucket does not
prove the cause of a blip. Read the buckets with the application event time to
find a repeated second.

Each timing metric keeps the last 512 samples in a lock-free reservoir. `count`
counts every sample, including samples that replaced an older one. The
percentiles use the nearest rank. The data stays in target device memory. It
holds no address, host name, token, key, or payload. Demo mode adds
`"demo": true` and simulated values. The web page uses this route for Copy
diagnostics. The report shows how many seconds in the timeline had an
established flow. It lists up to eight buckets with an event, newest first.

`POST /api/start` takes one object with a mode and an options object:

```json
{
  "mode": "phone",
  "options": {
    "experimental_icmp": true,
    "experimental_icmp_persistent": true
  }
}
```

The two echo fields are optional booleans. In phone mode they default to true.
If the request names `experimental_icmp` but not
`experimental_icmp_persistent`, the persistent value follows the enabled value.
A wrong type, or `experimental_icmp_persistent` true with `experimental_icmp`
false, gives HTTP 400 with the text "The ping setting must be true or false."
The direct modes ignore both fields. A change applies to the next start. A
running tunnel keeps the setting that it started with.

On success, the answer is `{"ok": true, "status": {...}, "result": {"mode":
"phone"}}`. On failure, the answer is HTTP 400 with fixed text. It never echoes
the token. If the source device rejects the saved token, the answer is HTTP 409
with this shape:

```json
{
  "ok": false,
  "code": "phone_token_rejected",
  "error": "The source device changed its token. Open HotspotShade on your source device, then pair again."
}
```

Pair again to replace the saved token. The target device app shows the same message and
offers Pair again.

See "Recent failures" for `GET /api/failures`.

The GUI runs as the current user. On macOS it asks for administrator approval
when it starts the source device tunnel. A separate helper changes routes and
owns the tunnel. The helper receives the token over a private local socket. It
stops the service when the GUI disconnects. The helper is the `hotspotshade`
binary that the GUI starts with administrator rights. Run it only when you
trust that binary and the target device that runs it. The GUI binds to loopback.
Other local processes can access its HTTP API. The administrator prompt and the
live helper path need device testing.

The source device app supplies the live status for the status answer. The
fields are the proxy state, the foreground state, the active connection count,
the proxy port, and the hotspot host. It also supplies the source address of
each pairing connection, so the source device budgets requests for each source
address.

### Target device identity

The target device static key is at
`$HOME/Library/Application Support/hotspotshade/identity.key`. The service
creates it on first use with `getentropy`. The directory has mode 0700. The
file has mode 0600 and holds 32 bytes. The service refuses a file with another
length, another owner, or permissions for group or others. It never logs the
key. Delete the file to get a new identity. The source device then treats the
target device as unknown. Remove the old key on the source device with "Forget
paired target devices".

### Threat model

The pairing protocol provides these checks:

- A device on the hotspot that pretends to be the target device. The source
  device shows a code, and the user must allow the target device. The proof
  shows that the target device holds the private key of `L_s`.
- An active man in the middle can try separate handshakes to find matching
  six-digit codes. The commitment does not prevent that search. The Rust
  and iOS responders charge four challenges for each source address and eight
  challenges in total in 60 seconds before they create the ephemeral secret.
  These limits reduce the search rate, but they do not remove the risk.
- A trusted public key skips both challenge budgets. The source device does
  not limit the total number of challenges to a known key. This exemption is
  intentional. It keeps a paired target device from a lockout. The budgets are
  an availability limit, not an authentication limit. A device that lacks the
  private key still fails the proof.
- Both responders bind approval to the connection, the prompt ID, and the
  displayed code. They reject a stale connection, a stale prompt, a wrong code,
  and an expired deadline. The challenge limit
  and prompt binding do not make a six-digit code a complete defense against
  an active attacker.
- A passive listener on the hotspot link. The token travels encrypted.
- Repeated decisions. The per-address lockout limits denied attempts. The
  challenge limit can also delay legitimate pairing after rapid retries or
  under hostile traffic.

The design does not defend against these cases:

- A malicious app on the source device, or a jailbroken source device. Such
  code can read the token in the app storage.
- A target device with a stolen identity key. The source device trusts the key,
  not the target device. Delete the key file and forget the paired target
  devices on the source device.
- A man in the middle when the target device is already known. The source
  device sends the result with no prompt, and the user compares no code. The
  target device does not authenticate the source device.
- The existing SOCKS5 control channel. It still sends the token in clear on
  the hotspot link for each proxy connection. Pairing protects the delivery of
  the token, not its later use.

### Pairing hardening follow-up

The Rust responder in `rust/src/source_pairing.rs` and the iOS responder in
`ios/HotspotProxy/Pairing.swift` implement the same hardening. The Rust tests
in `rust/src/source_pairing.rs` and the shared tests in
`ios/tests/PairingTests.swift` cover the same cases.

- Each source address gets at most four challenges in 60 seconds. All unknown
  source addresses together get at most eight challenges in 60 seconds. Both
  responders check the pairing credentials first. A source device with pairing
  off answers NotActive and charges no budget. Both charge the challenge
  budgets before they create the ephemeral key. A refused challenge sends Busy
  and creates no session.
- A REVEAL checks the pairing credentials before it charges the prompt attempt
  budget. A source device with pairing off answers NotActive and uses no
  attempt. Both responders allow three prompt attempts for each source address
  in 600 seconds.
- An invalid frame removes the session and the pending decision before the
  responder checks the peer text. A failed peer check cannot hold a session
  slot or leave a prompt that nobody can answer.
- A prompt is visible only before its deadline. A frame or an activation after
  the deadline does not mark the prompt visible. A timeout counts as a prompt
  failure only for a visible prompt while the app is active.
- An approval names the connection, the prompt ID, and the displayed code. A
  stale connection, a stale prompt, a different code, or an expired deadline
  does not approve a prompt.
- `deactivate` extends a live prompt by 120 seconds at most, counted from the
  first inactive notice. A repeated notice cannot extend the prompt past that
  limit. An expired prompt gets TimedOut and is removed.
- Both responders reject an empty, control-byte, or overlong peer identifier.
  Both reject a peer text with a port or a zone. Both canonicalize an IP
  address, so alternate spellings and IPv4-mapped forms share one budget. A
  refused peer text creates no key and no session.
- The prompt debug text redacts the displayed code in both responders.

The pending-prompt accessor returns nil after the deadline. The iOS accessor
checks the last observed time. The Rust accessor takes the current time from
the clock.

The wire format and the fixed parity vectors are unchanged.

The earlier paragraphs in this document already describe the corrected iOS
behavior. They are current.

The iOS responder does not track AEAD nonces. The injected nonce source must
return a fresh nonce for each sealed message. The host still enforces the
four-connection cap. The challenge budget reduces the six-digit code search
rate. It does not remove the risk.

### Pairing troubleshooting

The left column holds the fixed text from `rust/src/pairing.rs` and
`rust/src/gui_backend.rs`.

| Message | Check |
|---|---|
| HotspotShade is not running on your source device. | The source device app runs. Nothing answered on port 18090. A connection error other than a refusal shows "Open HotspotShade on your source device" instead. |
| Turn on Personal Hotspot on your source device. | The target device default route has no gateway. |
| Not paired. Open HotspotShade on your source device, then pair. | The target device has no credentials. Start Pair. |
| The source device does not know this target device. Pair again. | The source device removed this target device from its trust list. Start Pair again. |
| Open HotspotShade on your source device and keep it open. | The source device did not answer in time, or no valid status arrived. |
| The source device is busy with another pairing. Try again in a minute. | Another target device pairs now. Wait one minute. |
| The source device refuses pairings for 30 seconds after repeated failures. Wait and try again. | Wait 30 seconds. |
| The source device denied the pairing. | The person tapped Deny on the source device. Start the pairing again. |
| Nobody answered on the source device within 60 seconds. Try again. | The prompt stayed unanswered. Start the pairing again. |
| The source device rejected the pairing message. | The app and the target device use different versions. Update both. |
| The source device sent an invalid pairing message. | The answer did not authenticate. Something on the link changed it. Pair again on a link you trust. |
| The target device identity key cannot be used. Check its file permissions. | Run `ls -l "$HOME/Library/Application Support/hotspotshade"`. The file needs mode 0600. The directory needs mode 0700. |
| The pairing was cancelled. | The person cancelled the pairing on the target device. Start it again. |
| A pairing is already running. | Wait for the current pairing to end. |
| The pairing could not start. | Try again. Restart the target device app if the message stays. |
| Pair with the source device first. | The Start action in source device proxy mode found no paired credentials and no manual token. |
| Turn off the tunnel first. | Select Stop on the target device, then select Forget again. |
| The source device changed its token. Open HotspotShade on your source device, then pair again. | The source device rejected the saved token. Pair again. A new pairing replaces the old credentials. |

## Throughput and latency diagnostics

These tools measure the source device proxy while another network, for example
Wi-Fi, stays the default route. They create no route, no utun, and no listener.
They do not need root. They pin every outer socket to `--iface` with the
normalized socket factory, with TTL 65 and a read-back audit. They use one
outer socket for each inner flow. The target device resolves no host name. They
read the source device token from a hidden prompt or a private descriptor
(`--secrets-fd`), never from arguments or the environment. The reports contain
no token and no payload.

### Scoped UDP diagnostic with a primary network

`hotspotshade phone-udp-diag` tests the source device proxy UDP-over-TCP path
while another network, for example Wi-Fi, stays the default route. It is in
`rust/src/udp_diag.rs`. It is a diagnostic, not a tunnel.

- It changes no route. It creates no utun and no listener. It does not need
  root. It reads the default route before and after the run and reports
  `default_route_unchanged`.
- It pins every outer socket to `--iface` with the normalized socket factory.
  Each socket has TTL 65 and a read-back audit. The report shows
  `outer_sockets` and `ttl_bad`.
- It requires the source device address on the IPv4 subnet of `--iface`. It
  rejects `utun`, `lo`, and `bridge` names.
- The run uses one inner flow and one outer socket. It uses one authenticated
  source device stream with length-framed datagrams and `TCP_NODELAY`, as the
  relay does.
- The inner flow sends sequenced STUN binding requests to one numeric IPv4 or
  IPv6 address. The test destination must be a public unicast address. The tool
  does not resolve host names.
- The tool reads the source device token from a hidden terminal prompt.
  Alternatively, it reads one JSON object, `{"token":"..."}`, from
  `--secrets-fd N`. The descriptor must be a pipe, a socket, or a file with
  mode 0600 that the current user owns. The tool rejects secret options in
  arguments. It does not read the environment. The report contains no token or
  payload.

The report contains these values:

| Value | Meaning |
|---|---|
| `scheduled`, `sent` | Requests in the schedule, and requests that the outer socket accepted |
| `induced_drops` | Requests that `--drop-percent` skipped on purpose. They are not counted as loss |
| `local_would_block`, `local_no_buffer`, `send_errors` | Local send failures. They are not counted as sent |
| `received`, `lost`, `loss_percent` | Replies and loss for sent requests |
| `loss_runs`, `longest_loss_run`, `unrecovered_tail_run` | Loss shape. A tail run that does not end shows a dead flow |
| `lost_per_second` | Loss for each second of the schedule |
| `rtt_ms` | Minimum, p50, p90, p99, and maximum round trip |
| `setup_ms`, `stream_end`, `tcp_info` | UDP-over-TCP setup and end, and kernel TCP counts such as retransmitted bytes and smoothed RTT |
| `interface_deltas` | Kernel counts for `--iface` during the run: packets, bytes, errors, input queue drops |

`--wait` is 8 seconds by default. It is longer than the 5 second source device
path hold, so a datagram that the source device sends late is not counted as
lost. The report includes `rate`, `seconds`, `burst`, `pad`, and `wait`.

The report includes `payload_bytes`, `sent_payload_mbps`, and
`received_payload_mbps`. They count STUN payload bytes only, without UDP, IP,
framing, or encryption overhead. `received_payload_mbps` assumes that each
reply has the size of the request, as `udp-responder` does. These rates are not
throughput with a public STUN server at a low rate. A run at 10 or 50 requests
per second is a loss and liveness result.

The link report includes `link_baudrate_bps` and `routes_before` and
`routes_after`: the primary default, the default in the scope of `--iface`, the
source device, and the test destination. `routes_unchanged` compares them. The
test destination lookup shows the unscoped route. The pinned outer sockets do
not use it.

`--burst N` sends N requests back to back at each tick. The average rate stays
at `--rate`. Use it to test the burst drop hypothesis on the target device.
`--drop-percent P` skips a deterministic part of the requests before the outer
socket. Use it to confirm that the loss accounting is correct.

Limits:

- The interface counts include all traffic on the interface. With Wi-Fi as the
  default route, the hotspot interface carries little other traffic. Some
  system services can still use it.
- A STUN server can rate-limit or ignore requests. Loss can be server loss.
  Start with a low rate.
- The tool does not measure one-way loss.
- The token exchange is not encrypted on the hotspot link. A USB link is
  harder to observe than Wi-Fi, but the tool does not depend on that.
- The results do not predict tunnel speed or latency. The tunnel adds the
  utun, the relay, and many flows.

### ICMP echo relay

The Rust and iOS sources include an experimental ICMP echo path. It uses an
authenticated private source device command for each echo request. In the GUI
and the target device app it is on by default. A change applies the next time
the tunnel starts. The CLI `tun --phone` command needs `--experimental-icmp`.
The updated source device app is required. The source device listener accepts
the echo command from any client that has the token, even when the target
device option is off.

Limits:

- The echo path uses the source device cellular interface only.
- The target device allows 8 outstanding echo flows at one time. Further
  requests are dropped.
- Only echo requests are relayed. ICMP errors, traceroute, and path MTU
  discovery are not supported.
- The echo path has no TTL control. The target device builds each reply with TTL
  64, or hop limit 64 for IPv6. A native source device reply can show another
  value. The carrier does not see the inner reply.
- The source device connection counters do not count ICMP.

The experimental persistent echo option permits inner payloads up to 1184
bytes. It uses a fresh nonce in each request to detect stale replies.

When the source device proxy starts, it tests reported cellular interfaces in
the order supplied by iOS. It sends empty echo probes to `1.1.1.1` and
`2606:4700:4700::1111`. It records the first working interface for each address
family. It repeats the checks on the next proxy start. It can retry other
reported cellular interfaces if a selected interface stops working. On a source
device with multiple cellular subscriptions, a retry can use a different
cellular interface. Each probe requires interface binding and read-back.

On 2026-11-02, a short live test received three IPv4 and three IPv6 replies
through the source device proxy. The average round trips were about 79 ms and
73 ms. The reported inner TTL and hop limit are generated by the target device
relay. They do not measure the values on the source device cellular path. A
missing echo reply does not identify which part of the path failed.

Five IPv6 echo requests to a test server on the carrier network averaged about 58 ms,
with a 52 ms minimum. The source device test and the target device test were
not simultaneous, so they do not isolate the proxy added latency. After the
source device began reusing a cellular path monitor, five requests to the same
address averaged 74 ms, with a 53 ms minimum. These short samples do not show a
latency improvement. Network conditions can change between tests.

In a later 20-packet test to 8.8.8.8, the direct path averaged 46 ms and the
proxy path averaged 51 ms in sequential samples. The source device aggregate
for its first 20 successful echo replies showed about 40 ms in the send and
receive wait, less than 1 ms in socket setup, and 1 ms of other work. The source
device aggregate can include other echo targets. The wait includes scheduling
and is not a pure cellular round trip. Failed replies are excluded.

### Official Speedtest CLI through the source device proxy

The Ookla `speedtest` CLI 1.2.0.84 cannot use the source device proxy without a
route change. `speedtest --help` lists no proxy option. The binary contains no
SOCKS or proxy option strings. `--interface` and `--ip` bind the CLI to the
hotspot interface. That is the target device direct path through the hotspot
NAT, not the source device proxy.

- A direct `speedtest --interface en6` result does not measure the source
  device proxy. Do not compare it with a proxy result. A low direct result can
  show hotspot traffic management of the target device path. One result does
  not prove that.
- Do not use a library injection shim or a pf or route redirect for the CLI. A
  shim can break the CLI UDP loss test. The CLI also resolves names on the
  target device. The result is not a fair comparison.
- The official CLI can measure the source device path only through the full
  tunnel. The tunnel adds `/1` routes. See "Temporary full tunnel with Wi-Fi as
  the default route".
- Use the Speedtest app on the source device as a reference for native speed.

### TCP through the source device proxy: `phone-speed-diag`

`hotspotshade phone-speed-diag` measures TCP download and upload throughput
through the authenticated source device proxy. It measures latency on the same
path, with the same probe, while the path is idle and while the load runs.
Source: `rust/src/speed_diag.rs`.

```
hotspotshade phone-speed-diag --phone 172.20.10.1:PROXYPORT --iface en6 \
  --host HOST --address IP --port 8080 \
  --download-path /PATH --upload-path /PATH --probe-path /SMALLPATH \
  --paths phone,direct --streams 4 --seconds 20 --idle-seconds 10 \
  --warmup 3 --repeat 3 --max-mb 200
```

- The load is plain HTTP/1.1 with `Connection: close`. The tool has no TLS. It
  rejects port 443 and URLs. Use a test server whose operator permits this use.
  Carrier middleboxes can treat plain HTTP differently from HTTPS.
- Each load stream is one flow. A finished response starts a new flow on a new
  outer socket. Three consecutive failures stop a stream.
- Each run has an idle phase, then a download phase, then an upload phase.
  Probes start after `--warmup` seconds in a load phase. The steady rate
  `mbps_after_warmup` counts bytes after the warmup.
- A probe opens a new flow on the same path. `connect_ms` on the source device
  path includes the target device to source device session, the
  authentication, and the source device cellular TCP handshake. The source
  device replies after its connection is ready. With `--probe-path`, the probe
  sends one small GET and records `ttfb_ms`. On the source device path,
  `phone_auth_ms` measures an authentication with no destination. It isolates
  the target device to source device hop and the source device app.
- Percentiles are nearest-rank: p50, p95, p99, minimum, and maximum. The report
  shows `success_percent` for the probes.
- `--paths phone,direct` runs the target device direct path through the
  hotspot NAT with the same address. It needs `--address`. Repetitions
  alternate the order: `phone` then `direct`, and `direct` then `phone`.
- `--udp-target IP:PORT` adds a UDP latency probe through the source device at
  5 requests per second during each phase. It uses UDP over TCP and reuses
  `phone-udp-diag`.
- Bounds: 1 to 16 streams, 2 to 30 seconds for each load phase, 0 to 30 idle
  seconds, 1 to 5 repetitions, and 1 to 2000 MB for each phase.
  `planned_max_bytes` shows the largest possible transfer. Cellular data can
  cost money.
- Aggregate counts: requests, open, HTTP, and I/O errors, TCP retransmitted
  bytes, out-of-order bytes, smoothed RTT percentiles of the flows, target
  device process CPU, and interface counter deltas. The tool has no source
  device CPU count.
- An upload counts bytes that the socket accepted. At the end, it subtracts the
  bytes still in the send buffer (`SO_NWRITE`). The first interval includes the
  buffer fill. Use the steady rate.

The load and the probes do not measure QUIC. A QUIC bulk test needs a QUIC
client and server.

For a test with HTTPS, use the local adapter and curl. The adapter reads the
token from a hidden prompt or from `--secrets-fd`:

```
hotspotshade phone --phone 172.20.10.1:PROXYPORT --iface en6 --listen 127.0.0.1:1081
curl -4 --socks5 127.0.0.1:1081 --resolve HOST:443:IPV4 \
  -o /dev/null -w 'connect=%{time_connect} tls=%{time_appconnect} first=%{time_starttransfer} speed=%{speed_download}\n' \
  https://HOST/PATH
```

`--resolve` gives curl the address, so curl does not query DNS. Label the
result "TCP through the source device proxy". For loaded latency, run a 30
second download through the adapter. After 3 seconds, send one small request
each second for 20 seconds through the same adapter. Run the same probe while
the path is idle.

### UDP bulk with a user-controlled responder

A public STUN server is not a bulk UDP destination. `phone-udp-diag` limits the
rate to 500 requests per second. With `--own-responder`, it permits up to 5000
requests per second. Use that option only with a responder that you control.

`hotspotshade udp-responder --listen ADDRESS:PORT --seconds 300 --max-pps 5000`
runs the responder on a destination host that you control. It is a test
destination, not a relay. It forwards nothing. It answers each valid
diagnostic request with a reply of the same size, so it does not amplify
traffic. It locks to the first peer IP address, or to `--peer IP`. It stops
after `--seconds`. It counts aggregate values only. It takes no token, and it
does not pin an outer socket.

```
hotspotshade phone-udp-diag --phone 172.20.10.1:PROXYPORT \
  --iface en6 --target RESPONDER_IP:PORT --own-responder \
  --rate 2000 --burst 8 --pad 1200 --seconds 10
```

Limits:

- The target device queue for one UDP-over-TCP flow is 128 KiB and drops data
  older than 250 ms. A bulk test can reach this limit before a carrier limit.
  Check `udp_dropped` before and after each run.
- A responder on the target device itself, reached through the source device,
  needs an inbound port on another network. Do not open such a port without a
  plan.

### Statistics for small samples

Zero losses in N exchanges give a 95 percent upper bound of about 3/N on the
loss rate. For 2450 exchanges, the bound is about 0.12 percent. Zero holds in
15 path events are consistent with a per-event failure rate up to about 18
percent at 95 percent. Report the deltas of each run. Do not report cumulative
totals.

### Link speed

The report includes `link_baudrate_bps` from the kernel. A USB tether can report
a nominal value. Check the USB link before you attribute a ceiling to the
cellular path. Do not mix USB and Wi-Fi hotspot results.

### Temporary full tunnel with Wi-Fi as the default route

The CLI tunnel accepts an explicit hotspot interface. It does not need the
hotspot as the default route:

```
sudo hotspotshade tun --phone 172.20.10.1:PROXYPORT --iface en6
```

- The tunnel adds `0.0.0.0/1` and `128.0.0.0/1` to the utun and `2000::/3` to
  the utun for IPv6. These routes are more specific than the Wi-Fi default, so
  public traffic uses the tunnel. The Wi-Fi default route stays in the table.
  The outer sockets are pinned to `en6`.
- The token comes from `--secrets-fd`, the existing environment variable, or a
  hidden prompt on the terminal. Use the prompt. Do not put the token in the
  `sudo` command line.
- Stop the tunnel with Ctrl-C. The cleanup removes the routes, the IPv6
  address, and the utun. Do not use `kill -9`. After the stop, check
  `netstat -rn -f inet` and `netstat -rn -f inet6` for the utun routes.
- The GUI discovery, check, and start read the default route. They do not
  support this case.
- Bypass: on-link networks use their own routes. A DNS server on the Wi-Fi
  network, for example the Wi-Fi router, is reached over Wi-Fi. Names then
  resolve through the Wi-Fi resolver. Network extensions and VPN utuns can
  intercept traffic before the tunnel. A transparent proxy can intercept flows
  even when this diagnostic shows no error. Check for VPN clients before a
  live test.
- Select a fixed Speedtest server with `--server-id` for every run. Do not use
  `--interface` or `--ip` with the tunnel.

## Point curl at the listener

Use `--socks5-hostname`. This option sends the domain name to the proxy.

```
curl --socks5-hostname 127.0.0.1:1081 https://example.com/
```

Do not use `--socks5`. That option resolves the name on the target device.

You can set a proxy environment variable:

```
export ALL_PROXY=socks5h://127.0.0.1:1081
curl https://example.com/
```

The `socks5h` scheme means remote DNS.

## Point a browser at the listener

### Firefox

1. Open Settings.
2. Search for "proxy".
3. Select Manual proxy configuration.
4. Set SOCKS Host to `127.0.0.1`.
5. Set Port to `1081`.
6. Select SOCKS v5.
7. Enable "Proxy DNS when using SOCKS v5".
8. Clear the HTTP proxy fields. SOCKS5 carries TCP flows.
9. Open `about:networking#dns` and confirm that DNS lookups use the proxy path.

### Chromium or Google Chrome

Start the browser with a SOCKS5 proxy:

```
open -a "Google Chrome" --args \
  --proxy-server="socks5://127.0.0.1:1081" \
  --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
```

The resolver rule blocks local DNS. Test the browser with a new profile. A
running browser instance can ignore the flags.

### Safari and system proxy

Safari uses the macOS proxy settings. Open System Settings, Network, the active
service, Details, Proxies. Enable SOCKS Proxy and set `127.0.0.1` and `1081`.
macOS can resolve names locally for some apps. Use Firefox with remote DNS when
a DNS leak matters.

## Verify the exit path

1. Run the `--check` command. Confirm exit code 0.
2. Fetch the public address through the proxy:

```
curl --socks5-hostname 127.0.0.1:1081 https://api.ipify.org
```

3. Open the same address in the source device browser over cellular. Compare
   the two addresses. They can differ when the carrier uses different address
   pools. Use the source device app flow counter to confirm the target device
   flow.
4. Watch the HotspotShade app. The active flow count must increase when the
   target device sends a request.
5. Stop the source device proxy. Repeat the curl command. The command must
   fail. A success means that the target device used another path.
6. Confirm that the local listener is loopback only:

```
lsof -nP -iTCP:1081 -sTCP:LISTEN
```

The output must show `127.0.0.1:1081`, not `*:1081`.

7. Confirm that the target device has no utun from this mode:

```
ifconfig | grep utun
```

The source device proxy mode creates no device. An existing utun can belong to
another tool.

## Security limits

- The token authenticates the target device to the source device. It does not
  encrypt the link. Anyone who can observe the local link can read the token
  and the SOCKS5 control messages.
- Pairing delivers the token encrypted. The SOCKS5 control channel still sends
  it in clear. See "Pairing" for the threat model.
- The local listener has no authentication. It binds to `127.0.0.1` only. Any
  local process can use it. Do not change the listen address to a non-loopback
  value. The code rejects such a value.
- SOCKS5 carries the application traffic. It does not add TLS. Use HTTPS or
  another TLS protocol in each application.
- The app must stay open. iOS can suspend it when background operation is off.
  Screen lock can interrupt it.
- The source device derives its session limit from the file descriptor limit.
  When the limit permits, it allows 256 relays plus 32 setup sessions. It
  refuses a new relay when no safe slot is available. It does not evict an open
  TCP relay for silence. Presence checks use the separate pairing listener.
- The local `phone` SOCKS5 adapter supports TCP CONNECT only. BIND and UDP
  ASSOCIATE return code `0x07`.
- Full tunnel mode adds UDP over TCP. It uses one TCP stream for each inner
  4-tuple (command `0x80`). QUIC uses this path. When the source device closes a
  flow, the target device drops the inner flow without an ICMP error, so QUIC
  waits for its own timeout. The source device gives each destination
  connection 4 seconds to become ready. A cellular handover can produce a
  "not ready" result for a destination that is reachable. The source device
  reports it as code 1 (general failure), not as an unreachable host. This is
  reasoning from the deadline and the error mapping. The project has not run a
  handover test.
- The failure record stays on the target device. It is memory only and it is
  never sent to the source device.
- The source device resolves domain names. The target device must use remote
  DNS. A local resolver call is a leak. The adapter does not call
  `getaddrinfo()` on a destination name.
- The token is stored in UserDefaults on the source device. Rotate the token
  after exposure. Stop the proxy before you rotate it.
- This mode depends on the source device app and the hotspot link. It adds a
  hop and can reduce throughput. Measure it before you depend on it.
- This mode is not a VPN. It does not capture traffic from apps that ignore
  proxy settings.

## Test plan

The goal is a fair comparison of four paths. Use the same destination, the
same file, and the same time window. Run each test five times. Record the
median. Do not compare results from different carriers, signal levels, or times
of day.

### Paths

| Path | Command or setup |
|---|---|
| A. Source device native | Use Safari or a speed test app on the source device over cellular. Disable Wi-Fi. |
| B. Target device direct | Connect the target device to the hotspot. Do not start a proxy. |
| C. Target device TTL-65 SOCKS5 | Run `hotspotshade socks5 --port 1082`. Use `curl --socks5-hostname 127.0.0.1:1082`. |
| D. Source device proxy | Run `hotspotshade phone --phone 172.20.10.1:PROXYPORT`. Enter the token at the prompt. Use `curl --socks5-hostname 127.0.0.1:1081`. |

Path C re-originates the flow on the target device with TTL 65. Path D
re-originates the flow on the source device. Path B uses the target device
stack and the hotspot NAT.

### Throughput

Use a 10 MB or larger file from a stable HTTPS server. Replace `URL` with the
file address.

```
curl --socks5-hostname 127.0.0.1:1081 \
  -o /dev/null \
  -w 'bytes=%{size_download} time=%{time_total} speed=%{speed_download}\n' \
  URL
```

Run the command for path C and path D. For path B, remove the proxy option. For
path A, use the source device browser or a source device speed test. Record the
speed in bytes per second and convert it to Mbit/s.

### Latency

Use a small HTTPS endpoint and the time to the first byte:

```
curl --socks5-hostname 127.0.0.1:1081 \
  -o /dev/null -s \
  -w 'connect=%{time_connect} tls=%{time_appconnect} first=%{time_starttransfer}\n' \
  https://example.com/
```

Record `time_connect`, `time_appconnect`, and `time_starttransfer`.

### Correctness checks

1. Domain name: confirm that the source device app shows the domain name, not a
   resolved address. Use a domain that the target device cannot resolve, for
   example a name in `/etc/hosts` with a wrong address. The flow must still
   work when the source device resolves the name.
2. DNS leak: use `curl --socks5-hostname` and confirm that no local DNS query
   appears in a packet capture on the target device.
3. Half-close: use a test client that sends a request and closes only its write
   side. Confirm that the destination receives the end of the request and that
   the client receives the complete response. `Connection: close` alone does
   not test a client half-close. The state logic has hermetic tests. The updated
   Network.framework path still needs a live source device test.
4. Parallel flows: run ten downloads at the same time. Confirm that each
   download is complete.
5. Cleanup: stop the listener with Ctrl-C. Confirm that `lsof` shows no
   listener and that the source device app shows no active flow.
6. Failure: stop the source device app. Confirm that a new curl request fails
   with a clear SOCKS5 error. The target device must not fall back to a direct
   connection.

### Results table

Record the measured values. Leave a cell empty until you measure it.

| Path | Median speed (Mbit/s) | Connect (ms) | First byte (ms) | Notes |
|---|---:|---:|---:|---|
| A. Source device native |  |  |  |  |
| B. Target device direct |  |  |  |  |
| C. Target device TTL-65 SOCKS5 |  |  |  |  |
| D. Source device proxy |  |  |  |  |

Record the environment with the results:

- Date and time.
- Source device model and iOS version.
- Target device model and macOS version.
- Carrier and radio type, for example LTE or 5G.
- Signal bars or a field test value.
- Hotspot band, for example 2.4 GHz or 5 GHz.
- The server and the file used for the test.

Do not publish a number that you did not measure. A slow source device proxy
result is a valid result. It shows the cost of the extra hop.

## Troubleshooting

| Symptom | Check |
|---|---|
| `Source device authentication failed. Check the token and hotspot connection.` | The source device and the target device are on the same hotspot. The source device address is correct. The app is running. |
| The GUI cannot pair | See "Pairing troubleshooting". |
| `listen address must be 127.0.0.1:port` | Use `127.0.0.1` with a nonzero port. The adapter accepts IPv4 loopback only. The local listener has no authentication. |
| `source device must be a numeric IPv4 address and port` | Use the numeric hotspot address, not a host name. |
| `source device must be a numeric unicast IPv4 address and port` | Use the hotspot IPv4 address of the source device. Do not use a loopback, unspecified, multicast, or broadcast address. |
| Local port is in use | Use another `--listen` port. |
| A browser ignores the proxy | Close every browser instance. Start it with the proxy flags. Check the browser proxy settings. |
| A page hangs in "connecting" | The engine holds the inner SYN-ACK until the source device answers the connect request. A refused, unreachable, or timed out connect resets at once. A slow source device path can take up to 4 seconds. Check the connect times in `GET /api/diagnostics`. |
| The tunnel turned itself off | The engine stops after 20 seconds without the hotspot link, or 90 seconds without an answer from the source device. Read `last_stop` and `last_stop_message` in `GET /api/status`. Connect the hotspot, open the source device app, then turn the tunnel on again. |
| The tunnel is slow on Wi-Fi | A 2.4 GHz link is slower and less steady. On the source device, turn off Maximize Compatibility in the Personal Hotspot settings to allow 5 GHz, or use a cable. Move the target device closer when the signal is weak. |
| `phone_token_rejected` at start | The source device changed its token. Open HotspotShade on the source device, then pair again. |
| Forget keeps coming back | Forget is saved in the target device app. The app does not pair again until Pair. If the source device did not answer, the state is `not_delivered` and the source device can still trust the old key. Use Forget paired target devices on the source device, then pair again. |
| Ping does not answer | Check "Let ping work" in the web page or in the target device app. Turn the tunnel off and on after a change. The tunnel must be on, the echo path needs a cellular path, and it allows 8 outstanding echoes. Traceroute and path-MTU discovery are not supported. |
| Some connections did not work | Open "Recent failures" in the web page, or Settings, Advanced, "Recent failures" in the target device app. Select "Copy as text" or "Copy report". Read the groups with the largest count first. The `family` field separates IPv4 from IPv6. A code 1 reply can come from the source device 4 second deadline, so an `other` group can mean a slow or changing path. A code 4 reply is a real unreachable report. On the source device, Copy diagnostics shows waits and failures by family. These counts do not show the failure rate for each family. |
| "Recent failures" is empty | The record is empty when no tunnel runs. It is also empty when every connection worked. The record is cleared when the tunnel starts or stops. |
| A QUIC app stalls after the source device loses the cellular path | The target device drops the flow without an ICMP error. The app waits for its own timeout. Retry the connection. |
| DNS still resolves locally | Use `socks5h`, `--socks5-hostname`, or the Firefox "Proxy DNS" option. |
| The flow stops when the source device locks | Keep the app open. Check that "Keep running in the background" is on. Disable the screen lock for the test. |

## Tests

Run the hermetic Rust tests:

```
cargo test --locked --manifest-path rust/Cargo.toml
```

The relay tests use a mock source device on loopback. They need no source
device and no root. They create no route and no tunnel device.

Run the iOS logic tests (macOS and Xcode):

```
scripts/swift_tests.sh
```

The tests use fake links and fake clocks. They open no socket. The pairing
tests in `ios/tests/PairingTests.swift` and the Rust tests in
`rust/src/pairing.rs` hold the same parity vectors.

CI runs both on every push. See `.github/workflows/ci.yml`.
