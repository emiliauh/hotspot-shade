# Technical Reference

This document holds the design and reference material that is too detailed for
[README.md](../README.md). Start with the README for install and use. This file
covers the architecture, privileges, DNS and IPv6 behavior, the security model,
platform notes, cleanup, limits, troubleshooting, and tests.

## Architecture

### The TTL problem

An app on the target device sends IPv4 packets with TTL 64. The source device
hotspot normally decrements the TTL once, so the carrier is expected to see 63.
Native source device traffic leaves the source device with 64. A TTL of 63 or
lower is a common tethering signal. If only some flows are proxied, the carrier
can also see different TTL values from one device and one account.

The evidence is target-side TTL and a one-decrement assumption. The project did
not capture packets inside the carrier network.

### The fix

Every outer socket is created through the helpers in
`rust/src/normalization.rs` (`tcp_start`, `tcp_connect`, `udp_socket`). The
helpers set these options:

- `IPPROTO_IP / IP_TTL = 65`
- `IP_BOUND_IF = <physical hotspot interface>`, and the IPv6 equivalent when
  needed

If the source device NAT decrements the TTL once, the carrier is expected to see
64, which matches native source device traffic. Pinning stops relay traffic from
following the `/1` routes back into the utun.

In `tun` mode, the data path is:

```text
app
  -> utun (IPv4 packets)
  -> hotspotshade userspace
       TCP: terminate the inner flow, then connect one kernel TCP socket
       UDP: one kernel UDP socket for each inner 4-tuple
       all outer sockets: TTL 65, pinned to the hotspot interface
  -> Wi-Fi -> source device NAT (TTL 65 to 64, expected) -> carrier
```

The return path mirrors this path. The utun is a lossless kernel channel, so
the inner stack does not need to survive real packet loss. The outer TCP uses
the host kernel stack.

The inner endpoint follows RFC 9293, RFC 5961, and RFC 1122 for the segments
the utun can produce. A segment whose sequence space is outside the receive
window gets an ACK and changes no state. A data or FIN segment without the ACK
flag is dropped. A reset outside the receive window is dropped silently. A reset
inside the window but not at the next expected byte gets a challenge ACK and
does not close the flow. An ACK outside the range `SND.UNA - MAX.SND.WND` to
`SND.NXT` gets an ACK and drops the whole segment, so it cannot advance the send
state or refresh the keepalive or zero-window probe budgets. A zero receive
window still accepts a valid ACK at `RCV.NXT`, and a keepalive probe at
`RCV.NXT - 1` is answered. In the SYN-RECEIVED state, an ACK must acknowledge
the SYN-ACK exactly. Any other value resets the half-open flow.

A bare SYN with a different initial sequence number on an occupied 4-tuple gets a
challenge ACK and does not replace the flow. The tunnel can carry forwarded
traffic as well as local sockets, so a forged SYN must not close a live flow
without a sequence number. A local client answers the challenge with a reset at
the next expected byte, and its SYN retransmit then opens a new flow. That costs
one SYN retransmission delay. A retransmitted SYN keeps its initial sequence
number and gets another SYN-ACK from the same flow. A SYN with FIN is rejected.

### Why there is no external terminator

A conventional normalizer terminates a tunnel at a VPS and re-originates traffic
there. In Personal Hotspot, the source device already does this work. It
rewrites source addresses and ports, and it normally decrements the TTL once
for each tethered flow.

The target device terminates each inner flow locally and re-originates it as one
ordinary socket with TTL 65. The source device NAT is the terminator. There is
no tunnel header, no nested IP packet, and no shared tunnel flow. One inner
4-tuple maps to one outer socket. This removes a class of tunnel fingerprints.
It does not make the traffic identical to source device traffic at every layer.

## Privileges

| Operation | Administrator? | Why |
|---|---|---|
| `IP_TTL = 65` on outer sockets | No | macOS allows this for UDP and TCP without root. |
| `IP_BOUND_IF` and IPv6 pinning | No | Verified unprivileged on macOS. |
| `probe` | No | It opens one UDP socket and reads back the TTL. It creates no device. |
| `socks5` | No | It uses ordinary sockets and the options above. |
| `phone` adapter and `phone-*` diagnostics | No | They pin ordinary sockets to the hotspot interface. |
| Create a utun | Yes | An unprivileged `connect()` returns EPERM. |
| Set the utun address and routes | Yes | These are kernel network configuration changes. |
| `tcpdump` capture | Yes | BPF device access. |

On macOS the app runs its engine as the signed-in user. That engine serves the
Dashboard, pairing, status, Settings, diagnostics, and failures. Opening the app
starts no root helper and no root engine, so it asks for no administrator
authorization. When a person turns the tunnel on, the user engine writes its
pairing identity and source device credentials into a private inherited
descriptor. The app asks Authorization Services for one administrator
authorization. The protected helper verifies the fixed right, starts one root
engine with that descriptor, and writes a one-time grant into the engine's
runtime directory. The root engine imports the same identity and credentials and
consumes the grant before it creates the utun or changes a route. A missing,
stale, or malformed grant is a refused start. The app reads live tunnel status
and diagnostics from the root engine. A confirmed stop removes the routes and
the utun and returns the app to the user engine. The same root engine handles the
stop, so no administrator prompt is needed to turn the tunnel off. The helper
start reply carries a session id. A reconnect confirms a stop only from that
exact session's completed clean record, with no live or stopping session and no
cleanup block. A non-owning connection's successful stop reply is not proof. The
app keeps the pending stop and the elevated session outside any one model, so a
user engine restart, a quit that the person cancels, or a retry does not clear
them. A pending stop with no elevated process is retried by reading the helper
record.

Windows source device proxy starts and token-bearing probes are disabled.
Reviewed physical adapter and gateway checks are needed before reconsidering
the guard. They cannot authenticate the source device; v1 compatibility and
source authentication remain open decisions. The existing Wintun
start path would need Administrator rights and would change routes if enabled;
it has not passed a live Windows hotspot test. The read-only `probe` needs no
Administrator rights and changes nothing. There is no Windows privileged helper.
The real Windows GUI requires a per-launch bearer secret and parent-liveness
handle. A root GUI on macOS or Linux has the same requirement. A non-root Unix
GUI may run without a secret.

## DNS behavior

- **Direct `tun` mode:** an inner UDP datagram to port 53 goes to the original
  destination through a normalized outer socket. Set `--dns-upstream` to send it
  to another IPv4 resolver. The explicit upstream rejects loopback, `0/8`,
  link-local, multicast, and limited broadcast addresses. A mapped IPv4
  literal supplied through the CLI is normalized to IPv4. Nothing falls back
  to mDNSResponder.
- **`tun --phone`:** DNS goes over the source device TCP connection to
  `1.1.1.1:53`. Each new DNS flow opens a source device connection. A carrier that
  blocks that path breaks name resolution.
- **`socks5` mode:** `TinyResolver` in `rust/src/dns.rs` builds its own A and
  AAAA queries and sends them through the audited socket helpers with TTL 65.
  Explicit servers reject `0/8`, link-local, multicast, and limited broadcast
  IPv4 addresses, and IPv6 scope or flow information. Mapped IPv4 servers are
  normalized before validation. Production SOCKS also rejects loopback DNS
  servers because they can be local stubs.
  It never calls `getaddrinfo()` on an egress path. On macOS the target device
  reads `scutil --dns` and requires an unambiguous resolver associated with the
  selected interface. A full VPN resolver, a split-DNS resolver, an mDNS
  resolver, a loopback stub, and a link-local address are not candidates. A
  matching scoped block and a matching general block must agree, or the
  association is ambiguous and the start fails.
  On Linux, `/etc/resolv.conf` and the systemd-resolved upstream file are one
  aggregate list. A server in that list can belong to a VPN, a container, or
  another link, and the files do not prove that it belongs to the pinned
  interface even when that interface is the default route. The start therefore
  fails closed and requires an explicit `--dns-servers` list. The list is
  bounded to 8 numeric servers with optional ports and is deduplicated; a
  malformed, empty, or oversized list is an error. Queries still use a
  normalized socket pinned to the selected interface, so an explicit server
  does not create a raw egress path. The person who names the server accepts
  that it is appropriate for that link.
  An explicit list must not relax the interface guard: a tunnel, VPN, container,
  bridge, or loopback interface is refused. A loopback server is also a local
  stub and is refused in a production start. The loopback interface with a
  loopback resolver exists only as a hermetic test seam that is compiled into
  unit tests and is not reachable from the GUI or CLI. The server list shares one
  bounded timeout; a long list can exhaust the budget before later servers are
  tried. A missing name, a missing address type, a rejected query, and a silent
  server produce different errors. A SOCKS server with no interface index may
  reach only a loopback destination. SOCKS5 has no `--no-pin` option.
  Limits: a renamed tunnel can pass the name guard, and an OS or VPN client that
  binds its own resolver socket to the physical interface can bypass the tunnel.
  macOS resolver discovery, the Linux explicit path, and the VPN cases have not
  been tested with a live VPN or hotspot.
- **Client responsibility:** use `socks5h` or remote DNS. A client that resolves
  a name locally leaks the name before the proxy sees it. This is a documented
  leak, not a fixed issue.
- **Linux interface-bound traffic:** the policy rule for the physical interface
  sends any socket bound to that interface to table main, including sockets
  owned by other processes. Such traffic bypasses the tunnel and is not
  normalized by it. A resolver that binds its socket this way can bypass the
  tunnel; whether a particular desktop resolver does so needs a VM or device
  check. This is an unverified leak hypothesis for `systemd-resolved`: its
  per-link resolver sockets might bind to the hotspot interface, which rule
  17000 would send to table main. No test has shown either behavior, so do not
  claim that this path is contained.
- **Caveats:** `TinyResolver` validates CNAME chains in one answer. It does
  not issue a follow-up query for a CNAME-only answer, so that lookup can fail.
  Apps that use DoH, DoT, or their own resolver do not use these DNS paths.
  Some carriers block third-party DNS. In direct `tun` mode, use
  `--dns-upstream` with a resolver that works on that hotspot. The source device
  proxy DNS destination cannot be changed from the target device.

## IPv6 policy

The policy depends on the mode.

- **Direct `tun`, `--ipv6 block` (default):** the service installs a blackhole
  route for global unicast (`2000::/3`) and drops IPv6 packets in the relay.
  On macOS the route is in the main IPv6 table. On Linux it is in table 700 and
  the start gate proves the blackhole from a table dump and one fake FIB lookup
  per probe. More-specific routes can bypass the blackhole. Loopback and
  link-local traffic is not touched. Apps normally fall back to IPv4.
- **Direct `tun`, `--ipv6 forward`:** the tunnel forwards captured IPv6 TCP and
  UDP with the same one-flow-one-outer-socket rule. Use it explicitly.
- **Direct `tun`, `--ipv6 inherit`:** the tool does not touch IPv6 routes. IPv6
  stays on the hotspot native path. This is an explicit leak. Those flows are
  not re-originated or TTL-normalized. It never becomes the default.
- **Source device proxy mode (GUI, target app, `tun --phone`):** IPv6 is always
  forwarded. The service adds a tunnel address and a `2000::/3` route to the
  utun. IPv6 TCP, UDP, DNS, and ICMP echo go through the source device proxy.
  The mode rejects `--ipv6 block` and `--ipv6 inherit`. More-specific IPv6 routes
  can still bypass the tunnel.

## Security model

### What the design addresses

| Signal | How it is addressed |
|---|---|
| TTL 63 or lower on tethered flows | Outer sockets use TTL 65. If the source device NAT decrements once, the carrier is expected to see 64. |
| Different TTLs from one device | Every outer socket uses the helpers in `rust/src/normalization.rs`. The code reads the TTL back and counts mismatches in `ttl_bad`. |
| DNS leaks through mDNSResponder | In `tun` mode, inner UDP:53 goes to the original destination or `--dns-upstream` through a normalized socket. In `socks5` mode, `TinyResolver` sends its own queries. This assumes that the client sends host names (`socks5h`). |
| IPv6 bypass by default | Direct mode blocks IPv6 by default. Source device proxy mode forwards it through the source device and rejects the block and inherit policies. |
| Tunnel header or encapsulation fingerprint | There is no tunnel protocol and no encapsulation. The outer wire is ordinary TCP or UDP. |
| Many destinations on one tunnel flow | Each inner 4-tuple gets its own outer socket. |

### What remains

| Signal | Why it remains |
|---|---|
| Carrier DPI, volume, and time analysis | Tethered traffic often differs in volume, burstiness, active hours, and concurrency. TTL normalization does not change those patterns. |
| SIM and account profiling, plan quotas | The carrier can still measure bytes per account and compare them with the normal profile. |
| TLS, SNI, and TCP option fingerprints | TLS ClientHello data, HTTP User-Agent, TCP options, and retransmission behavior remain visible. Direct mode uses the target OS TCP stack. In source device proxy mode, the source device opens the destination connection. |
| Destinations | Software updates, cloud APIs, video calls, and large downloads are visible as destinations and SNI regardless of TTL. No destination privacy control is implemented today. See "Destination privacy". |
| Behavioral anomalies | Several devices behind one source device, unusual concurrency, or a traffic mix unlike the account history can still be flagged. |
| Bearer or account throttling | If the carrier throttles the hotspot bearer or the tethering bucket, every byte uses that throttled bearer. See "Measured results". |
| Transparent proxies and VPN extensions | A local Network Extension can accept TCP handshakes before the routing table. Those flows never enter the utun, and the wire TTL is the proxy TTL. `probe` does not detect this. |
| Local leaks | Apps that bypass the proxy or tunnel, browser DoH or private resolvers, and `--ipv6 inherit` create traffic that the tool does not normalize. |

TTL normalization addresses the tethering signal this project targets. It does not
defeat every possible signal. It cannot defeat carrier policy that applies at the
bearer or account level. A carrier that combines DPI, destination profiling,
TCP/IP fingerprinting, volume and time analysis, and account history can still
distinguish tethered use in principle.

### Destination privacy

Destination-name privacy is a different question from tethering detection.
Normalizing the outer TTL addresses one tethering signal. It does not reduce
what the carrier can learn about a destination.

Two questions are separate:

1. **What destination names and metadata the carrier can see.** Today this
   can include the TLS server name and DNS queries, as well as the destination
   IP address and network, flow size, and timing. Applications or resolvers may
   independently protect names with ECH or encrypted DNS; no current project
   mode adds those protections.
2. **How the carrier bills, throttles, meters, or classifies the connection.**
   No mode is shown to change billing, throttling, or metering. TTL normalization
   addresses one classification signal; it does not defeat multi-signal
   detection or change the terms that apply.

Why the relay cannot change the server name:

- In source device proxy mode the source device is a byte relay. The target
  application originates its own TLS connection, and the relay copies the
  bytes. The engine is not a party to that handshake, so no engine wrapper can
  insert Encrypted Client Hello or rewrite the server name in a relayed
  application ClientHello.
- Even inside a relay that parsed TLS, changing a ClientHello byte would break
  the TLS 1.3 transcript and the server's `Finished`, independently of
  certificates. In-place server name rewriting is not an implementation
  option.
- A name is chosen by the TLS client that builds the ClientHello: an
  application, a product-owned TLS client, or a TLS terminator. Phone-side
  termination is out of scope: it needs a CA that the target device trusts and
  it breaks certificate pinning.

Proposed controls are opt-in and unavailable:

| Mode | Status | Scope |
|---|---|---|
| `off` | Current behavior, default | TTL normalization only. Destinations are visible. |
| `shape` | Experimental code, unavailable to users | Byte-preserving TLS record re-framing might affect naive first-packet parsers, but this is unmeasured and can itself look unusual. It would not hide the server name, destination address, DNS, flow size, or timing. Cannot pad. |
| `hide` | Application-wide ECH unsupported | A byte relay cannot add ECH to another application's TLS handshake. Encrypted DNS is a separate, unapproved proposal; it would not add ECH to application traffic. |
| `cover` | Deferred | A TLS tunnel to an endpoint the user owns. Needs the user's own endpoint. The project has no third-party relay, VPS, or cloud hop and does not add one. It reintroduces TLS-in-TLS. |
| `terminate` | Out of scope | Phone-side TLS termination. Needs a target-trusted CA and breaks certificate pinning. |

Do not describe TTL normalization, `shape`, or the current byte relay as hiding
destinations. Do not claim that a destination-name control changes billing or
defeats carrier detection. No ECH coverage is demonstrated.

The iOS app has a background keep-awake option, but iOS can suspend it. The
project does not guarantee a sustained background relay. The
proposal and its open questions are in
[SNI_HIDING_PLAN.md](SNI_HIDING_PLAN.md). It is a plan, not an implemented
feature.

You are responsible for your carrier's terms and for local law.

## Automatic stop and probing

The automatic stop policy runs in the GUI service and the target device app.
The CLI commands also use it when the hotspot interface is known. The CLI
checks once per second and probes the source device every 5 seconds with a
2 second deadline. It prints the stop reason but has no `last_stop` API.
If local permissions or the TTL audit prevent a CLI probe, that probe is not
evidence of source device loss. Link monitoring continues. The CLI watches the
interface selected at start. It does not switch to a new hotspot interface.
An operating system error reading the interface is not evidence of link loss.

While a GUI tunnel runs, the service checks the hotspot link every 2 seconds. In
source device proxy mode it also checks the source device presence. On Linux the
tunnel worker runs the same link check even when no GUI monitor runs. After 20
seconds without the physical link, the worker stops and records `hotspot_lost`
in the service status. The Linux check uses `RTM_GETLINK` and an IPv4 address
read. A missing link is down; a netlink read failure is unknown.

| Condition | `last_stop.reason` | Message |
|---|---|---|
| The link is down for 20 seconds | `hotspot_lost` | The hotspot turned off, so HotspotShade turned the tunnel off. |
| The link is up, and the source device app does not answer for 90 seconds | `source_device_gone` | The source device stopped answering, so HotspotShade turned the tunnel off. |

One good sample resets the timer. In the GUI, an unknown link observation or a
stale source device probe also breaks the relevant continuous failure interval.
A fresh source device report that its hotspot is off remains link loss evidence.
The stop uses the normal cleanup path, so the
routes, the IPv6 address, and the utun are removed. The reason and message stay
in `GET /api/status` under `last_stop` and `last_stop_message`. Nothing turns the
tunnel back on. A person stop has the reason `user`. An engine error stop has the
reason `error`.

While a source device tunnel runs, the GUI service probes every 2 seconds even
if the page is closed. It probes the source device address and interface used
at start, even if the system default route changes. An unknown interface or an
interface observation error is not evidence of link loss. If the source device
probe cannot resolve the pinned interface, it sends no unpinned probe and cannot
establish that the source device is gone. When no source device tunnel runs, the
service probes every 2 seconds for 10 seconds after a request, then every 10
seconds, and stops after 5 idle minutes.
`POST /api/phone/probe` runs one probe on demand. If the observer cannot run,
stale data cannot establish source device loss.

## Ping

"Let ping work" is on by default in the target app and the web page. The setting
applies to the next start. `tun --phone` needs `--experimental-icmp`.

The echo path is experimental. It uses the source device cellular path only. It
allows 8 outstanding echo flows and relays echo requests only. Traceroute and
path-MTU discovery are not supported. The reply always has TTL 64, or hop limit
64 for IPv6. An older source device app can reject the echo command.

## Platform notes

### macOS

- There is no `/dev/utun`. The utun uses the AF_SYSTEM and SYSPROTO_CONTROL
  control path in `rust/src/platform.rs`.
- The data frame is `[4-byte big-endian address family][IP packet]`. `AF_INET`
  is 2 and `AF_INET6` is 30. The header is not a length. A write without the
  prefix returns success, but the packet is not delivered.
- The interface name comes from
  `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`. Do not read it from the packet
  descriptor.
- Creating a utun needs root. TTL normalization and `socks5` mode do not.
- `IP_TTL` above 64 is allowed without root on macOS. Do not assume a Linux
  privilege requirement for this option. Verify it on the target kernel.
- `IP_BOUND_IF` and `IPV6_BOUND_IF` pin the socket. Their Darwin values are 25
  and 125.
- The route hijack uses two more-specific routes (`0.0.0.0/1` and
  `128.0.0.0/1`). It does not replace the default route.
- A frame larger than the interface MTU returns EINVAL. The relay does no IPv4
  fragment reassembly.

### Windows

The Windows target has a source device proxy start path, but the current build
refuses its token-bearing starts and probes. Retaining and checking the physical
adapter and gateway needs implementation and review before that guard can be
reconsidered. Those checks cannot authenticate the source device: proxy v1
sends a reusable token in cleartext on the hotspot link. The CLI and
command-line `gui` retain their Wintun options for the disabled path. Direct mode and pairing in that GUI are not
implemented. The WinUI app is still a simulated
preview and does not connect to the engine. A live Windows hotspot test is
still needed. Windows CI type-checks and runs hermetic tests only. It creates
no adapter and changes no route.

The Windows direct service lifecycle exists behind a closed evidence gate;
the shipped CLI and GUI do not expose it. Its start-time route check rejects
global IPv6 local-subnet exceptions in block mode. An IPv6-enabled hotspot
with an on-link global route can therefore make block mode refuse to start.
Forward-mode local exceptions require a proven prefix of `/64` or longer on the
retained adapter. The proof is a caller assertion until the live adapter reader
is implemented. Route integrity is checked at start, not continuously, and
the source-device proxy path has no equivalent route proof yet. Neither gate
is ready to open on the basis of these checks.

An independent review of the proposed direct-mode adapter proof found that the
existing physical-path verifier assumes a source device destination and cannot
serve direct mode unchanged. A production proof still needs a destination-free
adapter observation, unambiguous name-to-identity binding, and a measured
socket-option sample tied to that retained identity. Reading the pin and TTL
options confirms what the socket provider reports; it does not prove packet
egress on the hotspot interface. The direct worker also needs a bounded policy
for persistent link-observation errors and protection against adapter index
reuse between observations. Those requirements remain open even if the
isolated reader's hermetic tests pass.

The loader takes an explicit absolute path to `wintun.dll`. The default is the
file next to the executable. `--wintun PATH` selects another path. The file
name must be `wintun.dll`. A missing file is a plain not-found error that names
the path. The repository does not bundle or commit the DLL. The loader uses
`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR` and `LOAD_LIBRARY_SEARCH_SYSTEM32`. It does
not search `PATH` or the current directory. Treat the install directory as
trusted. An attacker who can replace the DLL can run code as the tunnel
process. Only an Administrator must be able to write to that directory.

The tunnel needs Administrator rights. There is no Windows privileged helper
yet. The CLI and the command-line GUI run the engine in the elevated process.
Keep the protected service boundary open for the WinUI app.

If the guard is eventually removed, the existing start path opens the Wintun adapter, sets the IPv4 address and the MTU with
`netsh`, and installs two IPv4 `/1` routes and the IPv6 `2000::/3` route with
`CreateIpForwardEntry2` in `rust/src/windows_native_routes.rs`. Before every
create and delete, the boundary proves the retained adapter LUID and GUID. A
mismatch fails closed and keeps the route record. The relay forwards IPv6
because the mode requires it. Every outer socket uses
`rust/src/normalization_windows.rs`, which sets TTL 65 and pins with
`IP_UNICAST_IF` (index in network byte order) or `IPV6_UNICAST_IF` (index in
host byte order). The read-back audit must report `ttl_bad == 0`.

TCP keepalive uses `SIO_KEEPALIVE_VALS`. The idle time and the interval are
whole milliseconds. Windows fixes the probe count at 10 and cannot read the
time values back. The helper reads back `SO_KEEPALIVE`. The source device
values are 60 seconds idle and 10 seconds interval, so the Windows dead-peer
age is about 160 seconds. This differs from the 90-second macOS and Linux
value.

Cleanup removes the routes first and closes the adapter second. Drop guards,
an idempotent stop, and a console control handler cover normal stop, Ctrl-C,
console close, logoff, and shutdown. A failed route install removes the routes
that the call created. A cleanup failure blocks a later start until a person
inspects the routing table.

Windows has no enabled hotspot link observer. The disabled start path has
silence-based stop logic, but the current build cannot start a source device
proxy tunnel. Its automatic-stop behavior has not been verified on Windows.

`hotspotshade probe` is read-only on Windows. It reports the elevation state,
the default interface, one UDP TTL, and the audit count. It creates no adapter
and changes no route. `socks5`, `phone`, the diagnostic commands, and
`--privileged-helper` are not available on Windows.

The earlier Python design is in git history at commit `f5cfd68`. A Windows host
must verify the result. CI is a compile and test signal only. See
[PORTABILITY.md](../PORTABILITY.md) for the porting plan.

### Linux

The Linux target implements direct mode and source device proxy mode. A
disposable VM test passed direct IPv4 flows with a clean TTL audit, a verified
IPv6 block, an explicit IPv6 forward start, source device proxy TCP and IPv6
flows, and automatic stop after the hotspot link went down. The test restored
the routing state and left no link, rule, route, or TUN device. A live hotspot
test is still needed. The Electron app has a `pkexec` helper for the packaged
engine, but the non-demo desktop path and real authorization prompt have not
been validated on a live hotspot. See [docs/LINUX_TEST_VM.md](LINUX_TEST_VM.md) and
[PORTABILITY.md](../PORTABILITY.md).

A crash that skips cleanup closes the TUN device but leaves the policy rules,
and in block mode the `2000::/3` blackhole. The next start reads a private route
claim at `/run/hotspotshade/route-claim` and adopts the recorded objects only
when the lock is free, the locked descriptor is still the single-link file at
the path, the device lookup proves that the claimed TUN is gone, and every live
rule and route is an exact match for the record. A device lookup error other
than `ENODEV` or `ENXIO` is inconclusive. An inconclusive recovery deletes
nothing and leaves the claim in place. Linux gives a route and a rule no creator
identity, so this is not complete ownership proof. See
[docs/LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md).

A source device start that supplies a frozen outer interface index also freezes
the hotspot route that the caller checked. The service resolves the interface
name and reads the default route again before the source device token leaves the
process. A changed index or name returns `outer_interface_changed`. A changed or
missing gateway returns `source_device_moved`.

## Cleanup and leftover routes

Route cleanup runs on every normal exit path. Use guards that clean up on drop.
Handle SIGINT and SIGTERM. On Windows, handle the console control events for
Ctrl-C, console close, logoff, and shutdown. Keep stop idempotent. Remove every
route, address, and device that the process created.

On Windows, remove the routes before you close the adapter. The route boundary
proves the adapter LUID and GUID before each delete. If the proof is
inconclusive, keep the record, report the failure, and close the adapter. Do not
delete a route on an adapter that you cannot prove.

Windows does not have a durable route claim for recovery after a process
crash. A later start must not adopt or delete an existing route based on its
prefix alone. The current route boundary also assumes that Windows removes
device-bound routes when the adapter is absent; that assumption has not been
verified on a live Windows host. Inspect the routing table after a crash or an
unconfirmed stop before attempting another start.

Do not use `kill -9`. A forced kill can leave routes that point at a utun that no
longer exists. Check the routes after a crash:

```sh
netstat -rn -f inet
netstat -rn -f inet6
ifconfig
```

Do not delete a route based only on its prefix. A VPN or another tool can own
a similar route, and a route can change between inspection and deletion. Stop
and ask an experienced administrator to inspect the recorded pre-test state and
the current routing table. Any manual cleanup needs the device owner's approval
and evidence that the test created the route. If ownership is uncertain, do not
delete it. The macOS IPv6 blackhole is not bound to the utun and can survive a
crash even after the device disappears.

## Known limits

At the per-worker flow limit, the relay can evict a UDP flow that has been idle
for 30 seconds and has no pending work. Its next datagram creates a new outer
socket and source port. A long-lived UDP or QUIC session can need to reconnect.
If no flow is eligible, a new TCP connection is reset instead of waiting for a
slot. The diagnostics count both cases.

- **No IPv4 fragment reassembly.** Fragmented datagrams are dropped and counted
  in `fragments_dropped`. Large UDP payloads that need fragmentation can fail.
  TCP is unaffected.
- **UDP.** Direct mode uses one kernel UDP socket per inner 4-tuple and has no
  TCP fallback. Source device proxy mode carries UDP over TCP.
- **Minimal inner TCP.** The user-space TCP engine uses a 64 KiB receive window
  and no window scaling. It is not a general TCP stack.
- **Relay output pressure.** The output queue reserves 64 extra slots for TCP
  FIN and reset packets. The reserve is bounded and keeps FIFO order. It does
  not reserve slots for probes or guarantee packet delivery. A full queue can
  still drop a TCP control packet. When the relay rejects a probe or a data or
  FIN retransmission, the TCP endpoint restores its retry budget and tries again
  after 250 ms. Queue admission does not prove delivery to the device. The
  relay retains up to 64 rejected resets per worker and tries each reset up to
  three times. It discards a retained reset when a new flow uses the same
  tuple. A reset that already entered the output queue cannot be recalled.
  `tcp.resets_lost` counts resets discarded after the retry or capacity limit.
  The relay drop counters record local queue drops; they do not establish
  carrier loss. After a graceful close, the relay keeps up to 128 short-lived
  close records per worker for 30 seconds. A matching retransmitted FIN gets
  another ACK. The match allows PSH, ECE, CWR, and URG, and the same trailing
  data, because a real retransmission can repeat them. The record expires on a
  timer even when the worker has no other traffic. A new SYN removes the
  record. The record does not guarantee delivery: its ACK can also be dropped,
  and the record expires or can be evicted under load.
- **Outer TCP close.** A graceful inner close, or one whose upload direction
  already ended with a FIN, closes the outer socket with a normal FIN. An
  abortive inner teardown of an established flow that did not shut its upload
  direction down sets `SO_LINGER` to zero first, so the close sends a reset and
  the destination reads a truncated upload as an error. The setting is best
  effort and applies on macOS, Linux, and Windows. A flow that never completed
  the inner handshake forwards no upload and keeps the normal close.
- **Outer TCP stack.** In direct mode, wire-facing TCP options come from the
  target OS and can differ from iOS. In source device proxy mode, the source
  device makes the destination connection.
- **Transparent proxies.** A userspace transparent TCP proxy can accept flows
  before the utun. The flows show zero in the counters, and the wire TTL is the
  proxy TTL. `probe` does not detect this. Quit VPN clients and Network
  Extensions when the counters stay at zero.
- **Captive portals.** The tunnel cannot make a portal work. Complete the portal
  login before you start `tun` mode.
- **No roaming or reconnect.** An automatic stop is final. Nothing restarts the
  tunnel.
- **No multi-user support.** There is no hardening against a hostile local
  process.
- **Not a privacy tool.** The tool normalizes transit at the IP/TTL layer. It
  does not hide destinations from the carrier and does not protect traffic from
  the local network. See "Destination privacy".

## Troubleshooting

| Problem | What to do |
|---|---|
| `utun connect() returned EPERM` | `tun` mode needs root. Run `sudo hotspotshade tun`. SOCKS5 mode needs none. |
| No traffic in `tun` mode | Check the pinned interface, `netstat -rn -f inet`, and `route -n get <destination>`. Quit VPN clients and Network Extensions. |
| The flow counters stay at zero | A transparent proxy or Network Extension can intercept flows before the utun. Quit the VPN app or disable the extension, then start the tunnel again. |
| A page stalls in "connecting" | The target holds the inner SYN-ACK until the source device answers the connect request. A refused, unreachable, or timed-out connect resets the inner connection at once. The source device allows 4 seconds for each destination. Check the Wi-Fi band, or select Check now. |
| The tunnel turned itself off | Read the message in the app, page, or CLI. Connect the hotspot, open the source device app, then turn the tunnel on again. |
| The GUI port is in use | Run `hotspotshade gui --port 8788`, or stop the process that uses 8787. |
| Routes remain after a crash | Check with `netstat` and `ifconfig`. Delete only the routes that this process added. See "Cleanup and leftover routes". |
| DNS fails in direct `tun` mode | The carrier resolver can be unreachable through the tunnel. Try `--dns-upstream 1.1.1.1`. Some carriers block third-party DNS. |
| DNS fails in SOCKS5 mode | Use `socks5h` or remote DNS. On Linux pass `--dns-servers <IP>[,<IP>...]`; the aggregate resolver file is not used. A CNAME-only answer can fail because `TinyResolver` does not issue a follow-up query for the alias. |
| A captive portal does not work | Complete the portal login before you start `tun` mode. |
| Ping does not answer | Turn "Let ping work" on, turn the tunnel off and on, and check that the tunnel is on and the source device has a cellular path. Update an older source device app. |
| The source device app stops | Keep it open and keep "Keep running in the background" on. Allow Location. iOS can suspend the app otherwise. |

## Testing and CI

All automated tests are hermetic. They create no route and no tunnel device. They
use loopback servers, mock tunnel devices, and fakes.

| Command | What it checks |
|---|---|
| `cargo check --all-targets --locked --manifest-path rust/Cargo.toml` | Type check |
| `cargo test --locked --manifest-path rust/Cargo.toml` | Unit and integration tests |
| `scripts/gui_smoke.sh rust/target/release/hotspotshade` | GUI demo backend, status API, headers, no external asset |
| `swift test --package-path macos/HotspotShadeKit` | Target app Swift package tests |
| `scripts/swift_tests.sh` | Source device app logic tests with fake links and clocks |
| `scripts/build_mac_app.sh build/HotspotShade-unsigned.zip` | Unsigned target app bundle |
| `scripts/build_ipa.sh build/HotspotShade-iOS-unsigned.ipa` | Unsigned source device IPA |
| `bash -n scripts/*.sh` | Shell script syntax |

CI runs these jobs on GitHub Actions. A failure is an independent signal. See
[AGENTS.md](../AGENTS.md#test-commands-and-expected-results) for the full list.

| Job | Runner | Purpose |
|---|---|---|
| `rust-macos` | `macos-latest` | Type check, tests, release build, GUI smoke test |
| `macos-app` | `macos-latest` | Demo engine, Swift package tests, unsigned app bundle |
| `ios` | `macos-latest` | Logic tests, simulator build, unsigned IPA |
| `rust-windows` | `windows-latest` | Windows type check, hermetic tests, and clippy. The tests create no adapter or route |
| `rust-linux` | `ubuntu-latest` | Linux type check, full hermetic test suite, clippy, and mock VM cleanup tests. No Linux tunnel |
| `desktop-demo` | `macos-latest` | Shared desktop demo bridge, asset, shim, page model, and hidden-webview tests, clippy, and formatting |
| `desktop-windows` | `windows-latest` | Shared desktop demo build and tests. No Windows tunnel |
| `lint` | `macos-latest` | Clippy with warnings as errors, formatting check |
| `release` | `ubuntu-latest` | Release assets on a `v*` tag |

## Measured results

The project measured these results on macOS 27.2 (Darwin 27.2.0), arm64, uid
501. The raw packet captures are not published, because they contain the
addresses of real destinations. The numbers below are summaries. They are TTL
evidence, not a throughput study.

- Unprivileged `setsockopt(IPPROTO_IP, IP_TTL, 65)` works on UDP and TCP on
  macOS. A capture on the hotspot interface showed a datagram with TTL 65.
- Unprivileged `IP_BOUND_IF` and IPv6 hop-limit settings work.
- Creating a utun through `com.apple.net.utun_control` fails with EPERM as uid
  501. Root is necessary for `tun` mode.
- On a live hotspot, direct traffic showed TTL 64 on the target device and the
  same traffic through the TTL-65 proxy showed TTL 65. With one NAT decrement, the carrier is expected to see
  63 and 64. The tests did not measure packets inside the carrier network.
- The TTL audit reported zero bad sockets in the live tests.
- Throughput depends on the link. A 2.4 GHz hotspot gave about 50 to 80 Mbps
  down. The same tunnel over USB measured 494 and 383 Mbps down, and 62 and 48
  Mbps up. The source device alone measured 697 Mbps down. These were single
  runs under different conditions.
- On one throttled hotspot, the source device measured about 600/50 Mbps and
  the target device about 0.27 to 0.3 Mbps. TTL-65 traffic was equally
  throttled. TTL normalization cannot recover the native speed on a throttled
  bearer.
- A short source device proxy run on 2026-11-02 passed IPv4 and IPv6 HTTPS,
  IPv6 DNS, and IPv6 NTP. One Ookla run measured about 462 Mbps down and 50 Mbps
  up, with 44 ms idle latency and about 405 ms under download load. The TTL
  audit showed zero violations. One run does not establish reliability or speed
  on other networks.

See [PHONE_PROXY.md](../PHONE_PROXY.md) for the source device proxy
measurements.
