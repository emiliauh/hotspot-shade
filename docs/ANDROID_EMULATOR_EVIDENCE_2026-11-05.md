# Android emulator interoperability, 2026-11-05

This is snapshot-specific emulator evidence. It does not prove hotspot-only
binding, a cellular bearer, physical-device behavior, or carrier behavior.
The test used Android 16 on `Pixel_8_API_36`, a test-only hotspot finder,
emulator loopback, and temporary port forwards.

The snapshot was copied from base commit
`1a37ed738519af849bc0880755b3ba92bd9f92e1` with uncommitted edits. Other
writers changed the shared checkout during the run, so these results do not
establish the behavior of the current working tree. The local result and the
captured source are at
`/private/var/folders/gy/4x14dl7525nfqd0srpnfqnqr0000gn/T/opencode/hs-android-interop-20261105T164608Z-76662/RESULT.md`.

The 221-entry source manifest has SHA-256
`7e22c7ce999ae7052e3f30a95a13f85894b5e3616f4077ed36a2d8e709dc6757`.
An independent post-run check matched all available files, but one listed
Kotlin compiler session marker under `android/.kotlin/sessions/` had already
disappeared. It is transient build state, not a source file. The complete
original manifest therefore cannot currently be verified. A derived
[source-only manifest](ANDROID_EMULATOR_EVIDENCE_2026-11-05.sha256) excludes
both `.kotlin` build-state entries; all 219 remaining files verified after the
run. Its SHA-256 is
`58b60d090650a20ab1aa4e7887f30f1deffbac29e0099afae107b3cf07847757`.
This derived manifest does not prove the missing marker or establish that the
snapshot matches the current checkout. A path-name check found no build,
cache, log, identity-key, `.pem`, or `.p12` paths in the derived list;
that check does not inspect file contents or approve the snapshot for transfer.
A future run needs a source-only manifest made before building and a settled
snapshot.

The app APK and instrumentation APK were independently rehashed after the run:

| Artifact | SHA-256 |
|---|---|
| `app-debug.apk` | `9afba82a5a510877df18dbb5105cf20b79d18b111dc203d3e3d9452c241b76af` |
| `app-debug-androidTest.apk` | `9e1bdc3170b2c846761aa0f12923940ff24c413975eb0c8dcfcdb8ef7fb3fc2c` |

The recorded run passed the Rust-to-Android pairing flow for an unknown and a
known target, a 64 KiB plus 37 byte TCP echo, wrong-token rejection, a bounded
unreachable destination, ICMP echo, and IPv6 CONNECT. The proxy test asserted
five outer sockets with `ttl_bad == 0`; the pairing test asserted two outer
sockets with `ttl_bad == 0`. The installed app opened to its Off dashboard.

The runner removed its own port forwards. No host route or TUN device was
created. See `RESULT.md` and `SNAPSHOT_DRIFT_AFTER_RUN.txt` in the local
snapshot for the commands and drift record. The temporary snapshot is not a
release artifact and may be removed by the operating system.

## Later run: 18:12 UTC snapshot

A second run used a separate 182-file snapshot captured at 18:12:26 UTC from
the same base commit with uncommitted edits. Its source manifest SHA-256 was
`083063fdb18206d5ea4e253a3eb9d7bb4f144ed98221e73a8b684583921336de`.
The [source manifest](ANDROID_EMULATOR_EVIDENCE_2026-11-05_1812.sha256)
matched all 182 snapshot files when rechecked after the run. Its full
report and source snapshot are temporary local files at
`/private/var/folders/gy/4x14dl7525nfqd0srpnfqnqr0000gn/T/opencode/hs-android-interop/`;
they are not release artifacts and may be removed by the operating system.
The run does not establish the behavior of later changes in the shared tree.

The Rust target completed two pairings, first with a prompt and then with a
known key. The pairing audit reported two outer sockets and `ttl_bad == 0`.
The source proxy served a 64 KiB TCP echo, ICMP echo, and an IPv6 connection;
its audit reported five outer sockets and `ttl_bad == 0`. A dedicated emulator
Keystore round-trip also passed.

The instrumented pairing test **failed** after those host pairings. Its fixture
expected two token writes, but the implementation now skips a write when the
same token is already stored. The test assertion needs repair and a fresh run;
the Rust client success does not turn the failed instrumented test into a pass.
The test used an emulator and loopback, not a real hotspot or carrier path.

## Re-run of the pairing assertion

The repaired `PairingInteropTest` later passed on the same Android 16 emulator:
the instrumented test reported `pairings=2 prompts=1`, and the real Rust target
completed the unknown-key and known-key pairings. Its audit reported two outer
sockets and `ttl_bad == 0`. The test used loopback and a temporary port forward;
it did not use a physical hotspot or carrier.

This run used a separate 224-file source snapshot. Its
[manifest](ANDROID_PAIRING_EVIDENCE_2026-11-05.sha256) has SHA-256
`756b644b767c4caeabc21d0ea6bb4ab651779e4d358e287ea7207e6de60c9fac`;
all listed files matched the retained temporary snapshot after the run. The
debug app and test APKs had SHA-256 values
`6f402998f11e41be870eee7fac35b7c883e7ea7f8a894e6c82bedbbb05781219` and
`7747c2420cf18553fbc42da9159ebeb1930169f6d4141df28f3277da843e9aaf`,
respectively. Both were installed on the emulator with app data preserved.

The runner reported one emulator process-start failure and an aborted setup run
before the final pass. Rust GUI and Linux platform files changed in the shared
tree during the run; the post-run comparison found no Android source change
between the snapshot and that comparison.
The snapshot and detailed report are temporary files under
`/private/var/folders/gy/4x14dl7525nfqd0srpnfqnqr0000gn/T/opencode/hs-pairing-verify2.7QWkQU/`.
This result does not prove the later working tree or a physical-device result.

## Later pairing run: 19:24 UTC snapshot

A separate pairing-only run passed on the same Android 16 emulator. The
instrumented test reported `pairings=2 prompts=1`; the real Rust target
completed both pairings and reported two outer sockets with `ttl_bad == 0`.
The run used loopback and a temporary port forward, not a physical hotspot or
carrier. The installed app data was preserved.

The 181-file [snapshot manifest](ANDROID_PAIRING_EVIDENCE_2026-11-05_1924.sha256)
has SHA-256 `f762b7c04b041ad207a8e0240250a8fa9e659029b6d44b57356c72654b5fd726`.
The app and test APK hashes were
`324f194821bda1c80cc67d28e0e09823a75b08813c037f8d142e673feda530c5` and
`7747c2420cf18553fbc42da9159ebeb1930169f6d4141df28f3277da843e9aaf`.
The source snapshot and run logs remain temporary local files at
`/private/tmp/claude-501/-Users-emi-mbp--t3-scratch-2026-11-02-goal-build-a-laptop-side-424959e4/d76ba04a-cc7e-4b95-8259-8207fcba1171/scratchpad/run/`.

The snapshot matched its manifest after the run. Three Windows-related files
already differed from the live tree during the copy, and later concurrent edits
changed the live token store, pairing coordinator, responder, and Rust pairing client.
This result does not verify those later changes. Earlier attempts encountered
emulator system restarts and startup failures under load; the final run passed.

## Later pairing run: current credential changes

A fresh pairing-only run passed on the Pixel 8 API 36 emulator over loopback.
The Rust client completed two pairings, and the Android test reported
`pairings=2 prompts=1`. The Rust audit reported two outer sockets and
`ttl_bad == 0`. Both APKs were built offline with JDK 17 and installed with
app data preserved. The temporary forward and stop file were removed; the
pre-existing emulator forward was left in place.

The 212-file [source manifest](ANDROID_PAIRING_EVIDENCE_2026-11-05_CURRENT.sha256)
has SHA-256 `9a325284a461edda84fb80bad4afdbaafc7844aae25bfe95ef229f0df0066546`.
The snapshot archive has SHA-256
`53e7439caa85dcdae51fca3170dbb786ee68cd341402fc1c102f4cac2ac4f950` and
remains at `/tmp/hs-pairing-source.IyII7p/source.tar.gz`. The runner reported
that the captured files matched the working tree immediately after capture
and after the run, and that the snapshot matched its manifest after testing.
The initial build failed under Java 25; the Java 17 retry succeeded. This is
emulator and loopback evidence for the captured files, not a physical-hotspot
or carrier test and not evidence for later source edits.

A later manifest comparison found changes in `TokenStore.kt`,
`PairingCoordinator.kt`, `SourceTokenGuard.kt`, `platform_linux.rs`, and
`service.rs`; the other 207 captured files still matched. The pairing result
does not verify those later changes.

## Later pairing run: shared checkout

The pairing fixture passed again on the Pixel 8 API 36 emulator. The Rust
client completed two pairings; the Android instrumentation reported
`pairings=2 prompts=1`. The Rust test asserted two audited outer sockets and
`ttl_bad == 0`. Both debug APKs were built offline with JDK 17 and installed
with app data retained. The test's loopback forward and stop file were removed;
the Device panel's pre-existing forward was left intact.

The app APK SHA-256 was
`1b4f67fa8faab577f2464ed1e778cbe4d43d63aed4a092b043c5bf4ee0b8414f`;
the instrumentation APK SHA-256 was
`ea4facd849ee55c745af2254057bdee08130a2c052e9652606877a33376f517e`.
These hashes were recorded after the run. This run used the shared, modified
checkout without a captured pre-build source manifest, so the APK hashes do
not establish the exact source inputs. It is emulator and loopback evidence,
not evidence of a physical hotspot or carrier path.

## Later pairing run: source-only snapshot

The pairing fixture passed on the Pixel 8 API 36 emulator using a 229-file
source snapshot captured before the build. The Rust client completed two
pairings with two audited outer sockets and `ttl_bad == 0`; Android reported
`pairings=2 prompts=1`. The test used loopback, not a physical hotspot or a
carrier path. Both APKs were built offline with JDK 17 and installed with app
data retained. The test's temporary forward and stop file were removed. The
Device panel's existing forward was left in place.

The [source manifest](ANDROID_PAIRING_EVIDENCE_2026-11-05_SNAPSHOT2.sha256)
has SHA-256 `4c9e683110b6d445bf302ed88322d6d1f530b7e8e7fe49377de070a33e2bb498`.
Every listed file matched both the captured snapshot and the shared checkout
before and after the run. The source archive remains at
`/tmp/hs-pairing-repro.cxmnwPea/source.tar.gz`, with SHA-256
`ec6068042e113807b7ce6b74414b81c51d5065aafada7b18b128a857803c0683`.
The snapshot build used the existing Gradle cache and shared Cargo target
directory; Cargo reused its previously built test executable. This result
therefore does not demonstrate a clean build from the archive.

The app APK SHA-256 was
`039ad46dac61c3fe3f5fb5bef078136d5510b20e489b0bf8b2e8edf9924f5944`;
the instrumentation APK SHA-256 was
`963b4c418f0e58cf61a55be88470a19530b20f011b62acbdfcec293cffc222b7`.

The same snapshot and installed APKs also passed the separate Android SOCKS
fixture and Rust source-server interop test. The test checked authentication,
a 64 KiB TCP echo, wrong-token rejection, a bounded unreachable destination,
the private ICMP echo command, and an IPv6 loopback echo. The Rust test asserted
five audited outer sockets and `ttl_bad == 0`. It did not test a UDP relay
flow. Cargo compiled the interop test using the shared target directory. The
snapshot and shared checkout again matched the manifest before and after the
run. The test forward and stop file were removed; the Device panel forward
remained. This is emulator and loopback evidence, not physical-hotspot or
carrier evidence.

## UDP source-proxy interop

A later Pixel 8 API 36 emulator run added two UDP datagrams to the Rust
source-server interop test. Both datagrams crossed one authenticated
UDP-over-TCP flow and were echoed by a host loopback UDP socket reached via
the emulator's `10.0.2.2` alias. The existing TCP, authentication, ICMP, and
IPv6 cases also passed. The Rust test asserted six audited outer sockets and
`ttl_bad == 0`; the emulator instrumentation test passed. This is loopback
evidence and does not establish hotspot, carrier, or physical-device behavior.

The 229-file [source manifest](ANDROID_UDP_EVIDENCE_2026-11-05.sha256) has
SHA-256 `731d681f336a398b3610127a3e0ab3a06a90d4b2998e4ad5b06b53e1fc60c26d`.
The captured snapshot and shared checkout matched it before and after the run.
The archive is `/tmp/hs-udp-repro.YxaXIoKB/source.tar.gz`, SHA-256
`297962600a7d439566ea94182aa1bc0510f8abfdebf2ab2d3ab5fdd014602584`.
The installed APKs were those from the prior snapshot run; all Android source
hashes matched between snapshots. Cargo reused its shared target directory and
the test executable built from the matching shared checkout, so this is not a
clean-build test. The temporary forward and stop file were removed.

## Relay UDP interop

A follow-up run submitted two raw inner UDP packets to the Rust relay's
in-memory API. The relay sent them through the Android source proxy, and the
host loopback echo server returned both packets. The test checked the inner
reply addresses, ports, and payloads, the relay's UDP counters and `ttl_bad`,
and that the two packets used the same source UDP peer. A separate `PhoneUdp`
flow used a different peer. The instrumentation and Rust tests passed, and
the other TCP, ICMP, and IPv6 interop cases passed in the same run. No tunnel
device or route was created.

The 229-file [source manifest](ANDROID_RELAY_EVIDENCE_2026-11-05.sha256) has
SHA-256 `551634a8bc77353d3a38b5088d2e9602b9155068890fc887e721ef72e5ca94eb`.
The snapshot and shared checkout matched it before and after the run. The
archive remains at `/tmp/hs-relay-repro.pAwf8TmI/source.tar.gz`, SHA-256
`3c3fd3d00303eb6e9aa6b12b94844d8cab24baaa25568c9226d064e6828f8668`.
The Android inputs matched the APKs used in the prior snapshot run; Cargo
reused the shared target directory. The temporary forward and stop file were
removed. This emulator loopback result does not establish physical hotspot or
carrier behavior.

## Relay TCP interop

A subsequent run added an inner TCP handshake and payload echo through the
Rust relay and Android source proxy. It checked the SYN-ACK, sequence numbers,
reply addresses and ports, payload, one relay TCP flow, and `ttl_bad == 0`.
The relay UDP cases and the other source-proxy cases also passed. The test
submitted packets through the in-memory relay API and created no route or
tunnel device.

The 229-file [source manifest](ANDROID_TCP_RELAY_EVIDENCE_2026-11-05.sha256)
has SHA-256 `85aa82576f9d386358776b5a104deec5eb170d208aa825846658c9ea94ae6588`.
The snapshot and shared checkout matched it before and after the run. The
archive remains at `/tmp/hs-tcp-relay.uWA2xisD/source.tar.gz`, SHA-256
`7988f82946662a549d8902ed48c2f477cdc8a2c56367846f2c90dbc2a5169ed1`.
Android inputs matched the prior APKs. Cargo reused its shared target and the
test executable built from the matching shared checkout; this was not a clean
build. The temporary forward and stop file were removed. The result covers
emulator loopback, not physical-hotspot or carrier behavior.
