# Linux desktop HTTP contract on the macOS host, 2026-11-06

This is a host-side demo contract test. The Linux desktop HTTP client ran on
macOS against a locally built macOS engine in demo mode over loopback. It did
not run the Linux Electron window, privileged helper, a Linux kernel tunnel,
a source device, or a hotspot. It does not establish route cleanup, packet
normalization, physical interoperability, or carrier behavior.

Commands from the repository root:

```sh
cargo build --locked --offline --manifest-path rust/Cargo.toml
(cd linux && HOTSPOTSHADE_BIN="$PWD/../rust/target/debug/hotspotshade" \
  node --test test/engine-contract.test.mjs)
```

The build passed. The contract test passed 15 tests, with no failures or skips.
It covered bearer authentication, host and origin checks, demo pairing and
status, source device proxy and direct start envelopes, stop, diagnostics,
error envelopes, and shutdown on parent-liveness descriptor closure. The
server and client used loopback. No route or tunnel device was created.

SHA-256 values recorded around the run:

```text
81c43e83203d3650a7b8c140e3f57a4926ac231cd81cbd487fafc0e8f204dd18  rust/src/service.rs
4208cdfecc25cddd5f675c418ff8a876fb59030833f0e42eefda869406b8d3ab  rust/src/gui.rs
5a088075cdbd3e4824b2cb3af7c8b496ae8265143d33b461a0d48d778d203ca9  linux/src/backend/engine-client.js
724dc1cc4b5d756acc6f5463a0a7edec5e3bc0dfe77738282560b072697e2f05  rust/target/debug/hotspotshade
```

The three source hashes matched before and after the build and test. They are
not a complete source manifest. The working tree was uncommitted and other
files were not frozen, so this record does not prove a reproducible build from
a committed revision. Repeat the test against a frozen revision and retain a
complete source manifest for release evidence.
