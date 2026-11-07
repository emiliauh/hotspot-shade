# Windows socket non-inheritance feasibility, 2026-11-05

This is a standalone Windows API probe, not a HotspotShade product test. The
current uncommitted Mac source snapshot was not transferred to the Windows
host. This evidence does not approve Windows source device proxy use or prove
hotspot, carrier, interface pinning, TTL, or tunnel behavior.

The [Windows test thread](t3-thread://v2/15d335f8-ab23-4b29-8e91-c8898b759c9d/mcp:9e94994d-da35-4829-bb03-9093ce62ac73)
reports Windows Server 2025 Standard, 64-bit, build 26100, and Rust 1.99.1 for
`x86_64-pc-windows-msvc`. A standalone Rust program called `WSAStartup`, then
created IPv4 and IPv6 TCP and UDP sockets with `WSASocketW` and flags
`WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT` (`0x81`). All four socket
creations succeeded. `GetHandleInformation` reported flags `0x00000000` for
each handle, so `HANDLE_FLAG_INHERIT` was clear. All sockets closed and
`WSACleanup` succeeded; the program exited 0.

The source, executable, and output remain in the Windows thread's scratch
directory. The thread recorded these SHA-256 values:

```text
7861cacee66761884f0e22b0cef0049ba76375988fe8449a511ade5282dac0b4  socket_inherit_probe.rs
9e4c1f47459d5eece420580df68328fc5b5de22e4306809b94cd0b4674256d92  socket_inherit_probe.exe
85cc9ca9c2b738b9585502c53308c5c3bb663164ab27061cf3a1684423087363  socket_inherit_results.txt
```

The recorded build command, run in that directory, was:

```powershell
& 'C:\Users\Administrator\.cargo\bin\rustc.exe' --edition 2024 socket_inherit_probe.rs -o socket_inherit_probe.exe
```

The probe created and closed sockets without connecting to an external host.
It did not create an adapter, change routes, or run the product.

## Current socket module harness

The same Windows host later received three files from a reviewed, pinned Mac
source snapshot through the linked T3 thread. It verified the archive SHA-256
and each extracted source hash before compiling a standalone test harness. The
archive and source hashes were:

```text
30483f42e234c02335fe3d43209711d4e20cf763824c8b1060ff6ae27ca40b1d  socket-harness.tar.gz
6f835c35085b97bf9c1e9d78105fa6e93b7e00bb6a9ff547384552715b0c4f03  normalization_windows.rs
f05e29daa9cbe7e0729c11a0d7c8495044946c4b44c98e071c88135dab669e73  normalized_udp.rs
d7b099ac7d602e646761f6d78e8df0d53f7456c38376198ae27d7ebda5fe3363  connect_deadline.rs
```

The exact non-inheritance test passed alone. It checked IPv4 and IPv6 TCP and
UDP factory handles and both UDP wrapper handles; its audit was `(6, 0)`. The
complete isolated harness passed 33 tests. The Windows host retained its
archive, harness, executable, logs, and evidence file in its scratch directory.
The host did not enumerate the selected Winsock provider.

The generated harness source SHA-256 was
`fc1e484840206824e26d180a091b0684fdd4aa341e4d35906c564280b6dfc958`;
the test executable SHA-256 was
`8a66e026ebffc515b202a9753e15b22066550015671baeef2a67ebb86cd92ad1`.
The thread recorded these commands:

```powershell
& 'C:\Users\Administrator\.cargo\bin\rustc.exe' --edition 2021 --test source/lib.rs -o socket_harness.exe
.\socket_harness.exe --exact normalization::tests::normalized_tcp_and_udp_handles_are_not_inheritable
.\socket_harness.exe
```

This is a native test of these three exact modules, not a complete HotspotShade
build, a Windows compile-fail doctest run, or a live tunnel test. The rest of the
reviewed source snapshot remains on the Mac. Testing other Windows socket
providers and physical devices remains open.
