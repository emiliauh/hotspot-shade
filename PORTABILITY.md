# Windows and Linux porting plan

HotspotShade does not yet have a verified Windows or Linux tunnel. A successful
compile or a hermetic test does not prove that a tunnel works on a host. The
macOS arm64 tunnel remains the only verified implementation. The Windows and
Linux source device proxy start paths are implemented and have hermetic tests.

## Shared requirements

- Keep one inner 4-tuple per outer socket. Set and audit TTL or hop limit 65.
  Pin each outer socket to the physical hotspot interface by default.
- Keep DNS on normalized sockets. Do not use the system resolver on the
  target device egress path. Do not forward a Linux local DNS stub address as
  if it were an external resolver.
- Keep direct mode IPv6 blocked by default. Source device proxy mode must
  forward IPv6. The explicit inherit option remains a leak path.
- Track every route, address, and device created by the process. Clean up on
  normal stop, failed setup, SIGINT, and SIGTERM. Never remove a route that
  another process owns. Keep stop idempotent.
- Keep the service API local. Protect the desktop engine with a per-launch
  secret passed on a descriptor. Do not expose the source device token to a
  browser. Do not add automatic restart or a persistent proxy.

## Windows

Wintun supplies layer 3 IP packets without the macOS utun address-family
header. The application must obtain the signed driver separately. Do not
commit `wintun.dll`. The start path loads it from an explicit absolute path,
opens one adapter and session, and gives the raw IP frames to the portable
relay. The relay uses the normalized Windows socket helpers and the native route
boundary. Direct mode, a privileged helper, full hotspot link monitoring,
Windows DNS discovery, the WinUI service boundary, and end-to-end shutdown still
need Windows work.

The read-only route-verification foundation checks the managed prefixes and
selected probe routes against an adapter index and LUID. The start path installs
the routes through `rust/src/windows_native_routes.rs`, which proves the retained
adapter LUID and GUID before every create and delete. Before production,
verify the Windows API results on a real host. Check the loopback flag for
on-link routes, IPv6 source selection in forward mode, and route convergence
after installation. The check covers finite destinations and does not prove that
more-specific routes cannot bypass the tunnel.

Use the Windows socket constants and verify each option on a Windows host.
Microsoft documents `IP_UNICAST_IF` with the interface index in network byte
order and `IPV6_UNICAST_IF` with the index in host byte order. Interface
indices can change when an adapter is re-enabled. Do not persist an index
across link changes. TCP keepalive uses `SIO_KEEPALIVE_VALS` with milliseconds.
Windows fixes the probe count at 10 and cannot read the time values back.

For a nonblocking Windows connect, register `FD_CONNECT` before starting the
connection. Read the event result when the attempt completes. Windows CI covers both
successful and refused loopback connections, but it does not verify traffic on
a hotspot interface.

The Windows CI job checks the portable Rust code and the Windows start path. It
does not create a Wintun device or test routes. Do not claim tunnel support
until a person tests a Windows host and the checklist below passes.

## Linux

Linux TUN uses `/dev/net/tun` and `TUNSETIFF`. `IFF_TUN | IFF_NO_PI` provides
raw IP frames. `IFF_TUN_EXCL` rejects an existing device. The port has a
verified route and address guard, interface binding, DNS upstream discovery,
link monitoring, and signal cleanup. Test the socket options and privileges on
each supported kernel. Route and interface changes need appropriate privileges;
do not assume that setting TTL 65 itself requires `CAP_NET_ADMIN`.

Direct mode and source device proxy mode now start a tunnel on Linux. Both
install the IPv4 `/1` routes and one IPv6 route only in a dedicated routing
table (700), selected by two policy rules per address family. An `oif` rule
keeps pinned outer sockets on the main table. Direct mode blocks IPv6 by
default with a blackhole in table 700, accepts explicit forward, and rejects
inherit, `--no-pin`, and `--no-routes`. The start gate verifies the IPv4 routes
and the selected IPv6 policy. The worker stops after 20 seconds without the
physical link. A crash leaves the policy rules, and the next start refuses
until an operator removes them. See `docs/LINUX_TEST_VM.md`. A disposable VM
test with a real TUN device, a veth pair, a network namespace, and a mock source
device passed direct IPv4, source-proxy TCP and IPv6, block, forward, SIGTERM,
SIGKILL, and link-loss stop cases. No live hotspot test and no packet capture
exist. Linux CI checks the build, the full test suite, and clippy and creates no
route or TUN device.

## Desktop interface

The macOS target app uses SwiftUI. The Windows target app uses WinUI 2 native
controls to translate the same layout, states, and interactions. Evaluate a
UWP host and a desktop host with legacy XAML Islands against the privilege,
packaging, and engine-lifecycle requirements. The Linux target app uses
Electron. Measure its idle and active memory use and keep its local assets and
process count bounded.

The separate `desktop/` Tauri prototype uses an in-memory demo backend. It
does not connect the real service and is not the finished Windows or Linux
app. Keep the existing apps until replacements have equivalent behavior and
tests. A desktop demo build does not prove that a tunnel works.

A shared shell must preserve the existing service boundary. Its Rust side must
hold the per-launch engine secret and use a narrow allowlist of API methods and
paths. It must not expose a generic HTTP bridge, a secret, or a remote host to the
page. The page's manual token field remains an explicit fallback for a person
who types a token. The shell must stop the service and release its
parent-liveness handle on quit.
Windows needs a protected inherited-handle or equivalent design before its real
engine can use this pattern.

On macOS, the current app passes the secret on descriptor 3 and keeps a
parent-liveness pipe open on descriptor 4. The engine writes its selected port
to a file in a private temporary directory. A replacement must preserve these
properties, handle startup failure and shutdown, and keep the secret outside
the webview. The current Windows CLI rejects these descriptor options, so this
macOS mechanism is not a Windows implementation.

Parity includes pairing, Cancel and Forget, automatic pairing policy, ping,
start and stop, status freshness, recent failures, diagnostics, logs, settings,
notifications, menu and tray controls, keyboard access, light and dark themes,
and labeled demo mode. Test screen readers on each target OS and verify that no
external resource is requested. Linux tray behavior and Windows notification
delivery depend on the desktop environment or installation format. Check both on
their target systems. A working shell does not establish tunnel support.

## Verification

Use mock devices, fake route operations, and loopback endpoints in automated
tests. Test partial setup, failure, repeated stop, route ownership, packet
framing, DNS, socket option byte order, TTL audit, IPv6 policy, and shutdown.
CI must not need a source device or administrator rights.

Before claiming support, test on a Windows or Linux host with a source device.
Check physical-interface pinning and TTL with a packet capture. Check DNS and
IPv6 policies, source device proxy mode, automatic stop, and route cleanup.
Check the route table and interfaces after each test. A compile or VM-only test
does not replace the live hotspot test. Ask before a live test.

## References

- [Wintun API](https://git.zx2c4.com/wintun/about/#reference)
- [Microsoft IPv4 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)
- [Microsoft IPv6 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options)
- [Microsoft Winsock select](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select)
- [Microsoft interface address data](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row)
- [Linux TUN/TAP](https://docs.kernel.org/networking/tuntap.html)
- [WinUI 2](https://learn.microsoft.com/windows/uwp/get-started/winui2/)
- [Electron documentation](https://www.electronjs.org/docs/latest/)
