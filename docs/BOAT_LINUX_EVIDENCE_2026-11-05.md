# Boat Linux library test evidence

On 2026-11-05 a disposable Boat Ubuntu sandbox ran the Rust library tests
against a previously captured source snapshot. This is a snapshot result, not
a result for later changes to the working tree. The sandbox was removed after
the test log was copied back.

- Source archive: `/tmp/hs-windows-source.kKh4DP/hotspotshade-rust.tar.gz`
- Archive SHA-256: `f56e05df581284ea0669882e3263cc3f05607fd686a898a0f2ebf3e87f0bb082`
- The 66-file [source manifest](evidence/boat-linux-2026-11-05/source-manifest.txt)
  was independently reviewed for the Windows Rust test. Its SHA-256 is
  `c5cfc290093d0d3a4f9c9296c808c63f0ba6ff661386c972fd05258c4947120f`.
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`.
- Command: `cargo test --offline --locked --manifest-path rust/Cargo.toml --lib`.
- Result: 1102 passed, 0 failed, 0 ignored. The run took 49.95 seconds.
- [Test log](evidence/boat-linux-2026-11-05/library-tests.log), SHA-256
  `021232ce91feff5af59bda1cb133e1d89840a45a33f3387363da67ac785e0fa5`.

The first offline attempt could not find cached dependencies. Cargo then
downloaded the locked dependencies from crates.io for a focused test; the full
library suite above ran offline using that cache. The source archive remains in
temporary storage. The manifest and log are uncommitted working-tree evidence,
not release artifacts; their hashes identify the recorded inputs and output.

These unit tests do not prove packaged desktop authorization, a real tunnel,
physical hotspot interoperability, or carrier behavior. They do not validate
changes made after the source archive was captured.
