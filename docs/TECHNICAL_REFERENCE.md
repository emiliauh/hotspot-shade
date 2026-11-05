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

The GUI starts `tun` through a small privileged helper. macOS shows an
administrator prompt. The helper removes the routes and the utun when the tunnel
stops.

On Windows, the source device proxy tunnel needs Administrator rights. It
creates a Wintun adapter and changes routes. `probe` needs no Administrator
rights and changes nothing. There is no Windows privileged helper yet, so the
CLI and the command-line GUI run the engine in the elevated process.

## DNS behavior

- **Direct `tun` mode:** an inner UDP datagram to port 53 goes to the original
  destination through a normalized outer socket. Set `--dns-upstream` to send it
  to another IPv4 resolver. Nothing falls back to mDNSResponder.
- **`tun --phone`:** DNS goes over the source device TCP connection to
  `1.1.1.1:53`. Each new DNS flow opens a source device connection. A carrier that
  blocks that path breaks name resolution.
- **`socks5` mode:** `TinyResolver` in `rust/src/dns.rs` builds its own A and
  AAAA queries and sends them through the audited socket helpers with TTL 65.
  It never calls `getaddrinfo()` on an egress path.
- **Client responsibility:** use `socks5h` or remote DNS. A client that resolves
  a name locally leaks the name before the proxy sees it. This is a documented
  leak, not a fixed issue.
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
| Destinations | Software updates, cloud APIs, video calls, and large downloads are visible as destinations and SNI regardless of TTL. |
| Behavioral anomalies | Several devices behind one source device, unusual concurrency, or a traffic mix unlike the account history can still be flagged. |
| Bearer or account throttling | If the carrier throttles the hotspot bearer or the tethering bucket, every byte uses that throttled bearer. See "Measured results". |
| Transparent proxies and VPN extensions | A local Network Extension can accept TCP handshakes before the routing table. Those flows never enter the utun, and the wire TTL is the proxy TTL. `probe` does not detect this. |
| Local leaks | Apps that bypass the proxy or tunnel, browser DoH or private resolvers, and `--ipv6 inherit` create traffic that the tool does not normalize. |

TTL normalization addresses the tethering signal this project targets. It does not
defeat every possible signal. It cannot defeat carrier policy that applies at the
bearer or account level. A carrier that combines DPI, destination profiling,
TCP/IP fingerprinting, volume and time analysis, and account history can still
distinguish tethered use in principle.

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

The Windows target implements the source device proxy start path. The CLI
command is `hotspotshade tun --phone <gateway>:<port>`. The command-line `gui`
uses the same mode with the manual source device fields and accepts the same
`--wintun PATH` option. Direct mode and pairing in that GUI are not
implemented. The WinUI app is still a simulated
preview and does not connect to the engine. A live Windows hotspot test is
still needed. Windows CI type-checks and runs hermetic tests only. It creates
no adapter and changes no route.

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

The start path opens the Wintun adapter, sets the IPv4 address and the MTU with
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

Windows has no hotspot link observer yet. The CLI source device probe stops the
tunnel after continuous silence. Hotspot loss alone does not stop the Windows
CLI tunnel. Do not claim full automatic stop on Windows.

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
test is still needed. The Electron app remains a labeled demo and has no
privileged helper. See [docs/LINUX_TEST_VM.md](LINUX_TEST_VM.md) and
[PORTABILITY.md](../PORTABILITY.md).

## Cleanup and leftover routes

Route cleanup runs on every normal exit path. Use guards that clean up on drop.
Handle SIGINT and SIGTERM. On Windows, handle the console control events for
Ctrl-C, console close, logoff, and shutdown. Keep stop idempotent. Remove every
route, address, and device that the process created.

On Windows, remove the routes before you close the adapter. The route boundary
proves the adapter LUID and GUID before each delete. If the proof is
inconclusive, keep the record, report the failure, and close the adapter. Do not
delete a route on an adapter that you cannot prove.

Do not use `kill -9`. A forced kill can leave routes that point at a utun that no
longer exists. Check the routes after a crash:

```sh
netstat -rn -f inet
netstat -rn -f inet6
ifconfig
```

Delete only the routes that this process added. Check them first, because a VPN
or another tool can own a similar route.

```sh
sudo route -n delete -inet 0.0.0.0/1
sudo route -n delete -inet 128.0.0.0/1
sudo route -n delete -inet6 2000::/3
```

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
  another ACK. A new SYN removes the record. The record does not guarantee
  delivery: its ACK can also be dropped, and the record expires or can be
  evicted under load.
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
  the local network.

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
| DNS fails in SOCKS5 mode | Use `socks5h` or remote DNS. A CNAME-only answer can fail because `TinyResolver` does not issue a follow-up query for the alias. |
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
