# Portable relay tests on Windows

These tests run the relay with loopback sockets and an in-process mock source
device. They create no tunnel device, no route, no address, and no Wintun
driver. They need no administrator rights and no source device.

A pass proves that the portable relay code compiles and that its flow, packet,
audit, and shutdown behavior is correct on the Windows host. A pass does not
prove that the Windows tunnel works. A live hotspot test is still needed. See
[docs/MULTIPLATFORM_ROADMAP.md](../docs/MULTIPLATFORM_ROADMAP.md). The `tun`
command starts source device proxy mode when the Wintun DLL and Administrator
rights are present. This script does not test that path.

## Requirements

- Windows 10 version 2004 or later, or Windows 11, on x64 or x86. Older
  Windows 10 versions do not report a failed nonblocking connect through
  `WSAPoll`.
- Rust stable with the MSVC target.
- Visual Studio Build Tools with the "Desktop development with C++" workload
  for the linker.
- IPv6 enabled on the loopback interface. Several tests bind `[::1]`.
- A normal user shell. Do not elevate it.

## Commands

Run these commands from the repository root in PowerShell.

1. Fetch the locked dependencies once:

       cargo fetch --locked --manifest-path rust/Cargo.toml

2. Check every target of the crate:

       cargo check --locked --all-targets --manifest-path rust/Cargo.toml

3. Run the portable relay unit tests:

       cargo test --locked --manifest-path rust/Cargo.toml --lib relay::

4. Run the relay end-to-end tests:

       cargo test --locked --manifest-path rust/Cargo.toml --test relay_e2e

5. Run the readiness abstraction tests:

       cargo test --locked --manifest-path rust/Cargo.toml --lib relay_poll::

6. Run the Windows wait foundation tests:

       cargo test --locked --manifest-path rust/Cargo.toml --lib windows_relay_wait::

7. Run the Windows command contract tests:

       cargo test --locked --manifest-path rust/Cargo.toml --test windows_unsupported

8. Run the full suite and the lint gate:

       cargo test --locked --manifest-path rust/Cargo.toml
       cargo clippy --all-targets --locked --manifest-path rust/Cargo.toml -- -D warnings
       cargo fmt --manifest-path rust/Cargo.toml --check

Add `--offline` to a Cargo command only after step 1 has filled the crate
cache.

## Expected results

- Every command exits with code 0.
- `relay_e2e` runs `concurrent_ipv4_ipv6_tcp_bulk_and_udp_flows` and
  `stop_closes_an_active_outer_socket_and_rejects_packets`. Both pass.
- The relay tests report no failure and keep `ttl_bad` at 0.
- The `windows_relay_wait` native tests pass, including
  `wait_set_handles_more_than_sixty_four_sockets`. The Windows wait uses
  `WSAPoll`, so the set has no 64-socket limit.
- The `windows_unsupported` test reports one pass. Each tunnel command still
  prints the unsupported message.
- No test asks for elevation, creates a route, or opens a tunnel device.

## What the tests cover

- Inner IPv4 and IPv6 TCP bulk flows and UDP flows through the relay.
- One outer socket per inner flow.
- The TTL read-back audit. `ttl_bad` stays 0.
- The bounded output queue and its wake channel.
- Graceful close, reset, and stop with an active outer socket.
- Source device proxy setup over a mock server on loopback.
- DNS over the source device path with a mock server.
- Source device ICMP echo and its failure counters.
- Readiness waits and the wake channel in `relay_poll`.
- The connect readiness path, including a refused loopback connect.

## What the tests do not cover

- Wintun, the Windows service boundary, and a live tunnel.
- Route install and cleanup on a real host.
- Interface pinning on a physical hotspot adapter.
- A real source device, a real hotspot, a carrier, or a packet capture.
- Power loss and reboot cleanup.

Do not claim Windows tunnel support from these results.

## Unix-only parts

No relay test is Unix-only as a whole. These parts are Unix-only:

- `relay::tests::phone_tcp_socket_disables_nagle_and_preserves_audit` runs on
  Windows. The two `keepalive_enabled` checks run only on Unix. Reason: the
  Windows socket layer (`rust/src/normalization_windows.rs`) has no
  `TcpKeepalive` type and no `set_tcp_keepalive` function. The relay skips the
  keepalive call on Windows. The flow still gets Nagle off and the TTL audit.
- The same test passes an interface index on Unix. On Windows it passes
  `None`. Reason: the loopback adapter name is localized, so the test does not
  guess a name.
- `relay::tests::failure_reason_distinguishes_local_errors_from_source_replies`
  uses `EACCES` and `EPERM` on Unix and `ERROR_ACCESS_DENIED` (5) on Windows.
  The test runs on both platforms.
- `relay::tests::tcp_failure_counters_distinguish_setup_and_io` sets
  `SO_LINGER` to zero to send a reset. Unix uses `libc`; Windows uses the
  Winsock call. The test runs on both platforms.
- `rust/tests/relay_e2e.rs` has no Unix gate. Both tests use loopback
  addresses only.

The Unix-only modules include `service.rs`, `privileged.rs`, `socks.rs`,
`phone_server.rs`, and the macOS and Linux platform code. They do not compile
on Windows, and the service-level tunnel tests do not run there. The Windows
tunnel remains unwired by design.

## Cleanup check

These tests open loopback sockets only. They add no route, address, or
adapter. For evidence, run these commands before and after the test run:

    route print
    ipconfig /all

The two outputs must match, except for normal DHCP or interface state changes
from the operating system.
