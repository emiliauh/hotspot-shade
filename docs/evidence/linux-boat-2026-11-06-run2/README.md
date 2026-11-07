# Linux evidence on a disposable Boat sandbox, run 2, commit dc2e281c

Run date: 2026-11-06 (sandbox clock 2026-11-07 01:59:01Z to 02:15:43Z).
Method: run 1 in `docs/evidence/linux-boat-2026-11-06/README.md`, repeated on a fresh
sandbox. This is evidence for the named commit only. It is not a release artifact
and not an independent attestation. It proves nothing about a live hotspot, a
carrier, a polkit prompt, a real desktop session, or a tunnel. No TUN device was
created and no route was changed.

**Result: not a clean pass, but run 1's three failures are gone.** The clippy
dead-code error, the dash `fd>9` descriptor test, and the `flock` fork test all pass
now. One new finding: the opt-in helper integration test
`the_real_engine_serves_authenticated_loopback_status_and_stops_cleanly` failed in the
required run and in 1 of 3 supplementary reruns (2 of 4 runs failed). It passed in
run 1 once. Everything else passed.

## Input

| Item | Value |
|---|---|
| Commit | `dc2e281c669f5d24d448f2870fbd89ea42d9d716` ("Windows elevation hardening, UWP fixes, Linux evidence fixes"; child of `417c6d43`) |
| Archive command | `git -C <repo> archive --format=tar --prefix=hotspotshade/ dc2e281c669f5d24d448f2870fbd89ea42d9d716 -o hs-dc2e281c.tar` |
| Archive SHA-256 | `c1ea94fb11c88ffc80a81be2f16fe603a27f15bed951c16dab9c070513c97589` (computed on the Mac; recomputed inside the sandbox with `sha256sum -c` and compared with the Mac value) |
| Archive size, members | 28,764,160 bytes, 1025 members (887 regular files, 138 directories) |
| Host checkout state | dirty (`M docs/COMPLETION_TASKS.md`, `?? noref/`); not an input. The archive is the commit tree only. |
| Pre-upload checks (Mac) | `git ls-tree -r` lists no symlink (120000), no submodule (160000), no `.gitattributes`. No path has a non-printable byte (checked with `tr -d '[:print:]\n'`; my first `grep` attempt for this was wrong on BSD grep and I replaced it). No member is absolute or has a `..` component; no link member; no member other than a regular file or directory; no setuid/setgid mode; none of `build/`, `noref/`, `.git/`, `*.mobileprovision`, `*.p12`, `identity.key`, `*.pem`, `*.key`, `.env`. The tar member list equals the member list read back in the sandbox. |
| Uploaded | only `hs-dc2e281c.tar`, plus `hs-dc2e281c.paths` (the `git ls-tree` path list), `hs-dc2e281c.sha256`, and my own helper shell scripts (text). No working tree, `build/`, credentials, keys, tokens, or profiles. `boat push` and `source_snapshot.sh` were not used. |
| Mac disk before / after | 57 GiB free on `/System/Volumes/Data` before (gate 25 GiB); 60 GiB after |

Inside the sandbox, as the unprivileged `user` (uid 1000): `sha256sum -c` OK and the
digest equals the Mac value; the tar is a regular file with one link; refuse-if
checks for absolute, `..`, link, special-file, control-byte, and
outside-`hotspotshade/` members all passed; extracted into a new empty mode-700
directory with `tar --no-same-owner --no-same-permissions -xf` (GNU tar 1.35), umask
022. After extraction: no symlink or special file, no multi-link file, no
setuid/setgid bit; 887 files; the extracted file list equals both the tar member list
and `git ls-tree -r --name-only` (`diff` empty). Output: `logs/extract-verify.log`;
lists in `inputs/`.

## Host

Boat sandbox `bx_x96uexbd`, type `default` (4 vCPU, 8 GB), created with
`--no-env --no-snapshots --no-monitoring --ttl 7200`. Same image family as run 1:
Ubuntu 24.04.4 LTS, kernel `6.8.0-117-generic` x86_64, glibc 2.39 (Ubuntu
2.39-0ubuntu8.8), `/bin/sh` is dash. Full list in `logs/versions.log`.

| Tool | Version |
|---|---|
| Rust / cargo | 1.97.1 (stable, rustup, preinstalled; no `rust-toolchain` file in the commit, so stable with `--locked`) |
| clippy / rustfmt | 0.1.97 / 1.9.0-stable |
| Node / npm | 24.22.1 / 11.19.1 (preinstalled; `linux/package.json` needs `>=22`) |
| Electron | 45.2.3 (lockfile pin; binary fetched as in run 1) |
| Xvfb | `2:21.1.12-1ubuntu1.9` |
| dpkg-dev / dpkg-deb | `1.22.6ubuntu6.6` / 1.22.6 |
| flock | util-linux 2.39.3 |
| Docker | 29.7.0 |
| Helper container image | `rust@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd` (linux/amd64, rustc 1.99.1) |

Deviations and bookkeeping errors, stated plainly:

- Same as run 1: Rust, Node, Docker, `dpkg-dev` were preinstalled and not installed by
  me. From apt I installed only `xvfb xauth fonts-dejavu-core libgtk-3-0t64 libnss3
  libasound2t64 libgbm1 libdrm2 libxkbcommon0 libxshmfence1 libx11-xcb1 libxss1
  libcups2t64 libatk-bridge2.0-0t64 libatspi2.0-0t64 libcairo2 libpango-1.0-0 libgl1
  ca-certificates`. The sandbox is a desktop image, so `apt install ./hotspotshade.deb`
  pulled no new dependency and does not show what a clean host would install.
- Same as run 1: `npm ci` does not fetch the Electron binary. I ran the first two
  `npm test` runs without it, then fetched it with `node -e 'console.log(require("electron"))'`,
  set `chrome-sandbox` to root:root 4755 with `sudo`, and re-ran both. No `--no-sandbox`.
- Python was not installed or used. The base image has `/usr/bin/python3`; I did not
  call it.
- **Lost log:** the apt log of the dependency install (`apt-install.log`) was
  overwritten by the later package-install step, which reused the step name. It
  exited 0 after 39 s (seen live). I added `logs/apt-deps-install-history.log`
  afterwards from `/var/log/apt/history.log` and `dpkg -l`.
- **Invalid first pass of the install/remove/purge network check:** my `net` snapshot
  was a shell function that `bash -c` could not see, so both snapshots were empty and
  the "identical" diff meant nothing. The install, remove, and purge themselves ran
  and exited 0. I kept those logs as `apt-*-pass1-empty-netsnapshot.log`, and re-ran
  the whole install/remove/purge sequence with a real snapshot script. The
  unsuffixed `apt-*` logs and `inputs/net-before.txt`/`net-after.txt` are the valid
  ones.
- Unlike run 1, I did not add the `diag-*`, `*-no-fail-fast`, or `*-allow-dead-code`
  supplementary runs, because the three failures they diagnosed no longer occur. I
  did add three supplementary reruns of the helper integration (below).
- The first `final-residue-check` call wrote nothing (the call did not load the env
  file); I re-ran it. Only the second is in `logs/`.

## Commands and results

Exit codes and log SHA-256 values are in `results.tsv`. Logs are in `logs/`.
Commands run from the extracted `hotspotshade/` root as `user`, except `sudo` where
noted.

| # | Step | Command | Exit | Result |
|---|---|---|---|---|
| 4a | fmt | `cargo fmt --check --manifest-path rust/Cargo.toml` | 0 | pass |
| 4a | check | `cargo check --all-targets --locked --manifest-path rust/Cargo.toml` | 0 | pass, **no warning** (run 1 had the dead-code warning) |
| 4a | clippy | `cargo clippy --all-targets --locked --manifest-path rust/Cargo.toml -- -D warnings` | 0 | **pass** (run 1: exit 101) |
| 4a | test | `cargo test --locked --manifest-path rust/Cargo.toml` | 0 | lib 1359 pass; `main.rs` 38 pass, 0 fail (run 1: 37 pass, 1 fail); integration binaries and 7 doc-tests pass. Summed "passed" lines 1717, failed 0, ignored 15 (`logs/test-counts.log`). The sum includes one 1-test line printed for `main.rs` ("37 filtered out") in addition to the 38, as in run 1, so unique tests are probably 1716; I did not verify that. The 15 ignored: `android_emulator_interop` 1, `android_pairing_interop` 2, `ios_simulator_pairing` 1, `linux_tunnel_vm` 10, `tcp_bench` 1 |
| 4b | helper test | `cargo test --locked --manifest-path linux/helper/Cargo.toml` | 0 | 65 unit + 24 `helper_lifecycle` + 2 `real_engine_demo` pass, 0 failed, 0 ignored (summed "passed" lines 92, one a 1-test line as above). The 24 lifecycle and 2 real-engine tests pass by returning early without the opt-in; this is not integration evidence |
| 4b | helper clippy | `cargo clippy --all-targets --locked --manifest-path linux/helper/Cargo.toml -- -D warnings` | 0 | pass |
| 4b | engine build | `cargo build --locked --manifest-path rust/Cargo.toml` | 0 | debug engine for `HOTSPOTSHADE_BIN` |
| 4b | helper integration, **required run** | `HS_HELPER_CARGO_HOME=$HOME/.cargo bash linux/helper/tests/run-container.sh` | **101** | **FAIL**: `helper_lifecycle` 24 passed (all 24 `HS_HELPER_TEST_STARTED` markers); `real_engine_demo` 1 passed, **1 failed** (excerpt below). Staged-file SHA-256 checks OK. The wrapper kept its failure-evidence directory, copied to `logs/helper-integration-fail1-evidence/`; I then removed the container, volume, and directory |
| 4b | helper integration, rerun 1 (supplementary) | same | 0 | pass: 24 + 2 passed, 26 markers |
| 4b | helper integration, rerun 2 (supplementary) | same | **101** | **FAIL**, same test, same line, same message (`logs/helper-integration-rerun2-evidence/`) |
| 4b | helper integration, rerun 3 (supplementary) | same | 0 | pass: 24 + 2 passed, 26 markers |
| 4b | cleanup | `docker ps -a`, `docker volume ls`, `/tmp/hs-helper-evidence.*`, `/opt/hotspotshade`, `/var/lib/hotspotshade` | 2, then clean | the first check (right after the failed run) exits 2 because the failed run keeps its evidence directory; after I removed it and after the reruns, `final-residue-check` shows no container, volume, evidence directory, or `/opt`/`/var/lib` residue |
| 4c | npm ci | `cd linux && npm ci` | 0 | 51 packages (npm reports 5 moderate advisories; not acted on) |
| 4c | npm test (no binary) | `npm test` | 0 | 349 tests, **341 pass, 0 fail**, 8 skipped (7 real-engine tests need `HOTSPOTSHADE_BIN`; 1 needs an isolated network and `HS_REAL_ENGINE_BIN`) |
| 4c | npm test (real engine) | `HOTSPOTSHADE_BIN=$PWD/../rust/target/debug/hotspotshade npm test` | 0 | 363 tests, **362 pass, 0 fail**, 1 skipped (`the Linux client reads a real unprivileged engine and parent loss stops it`) |
| 4c | both again with the Electron binary present | same two commands | 0, 0 | identical counts (`*-with-electron.log`) |
| 4d | Settings window | `xvfb-run -a npm run test:settings-window` | 0 | 12 checks `"ok": true`, none false |
| 4d | accessibility | `xvfb-run -a npm run test:a11y` | 0 | `"ok": true`, `"violations": []`, 9 page states, 8 focus stops |
| 4e | package | `ARCH=x64 npm run package:deb` | 0 | `hotspotshade_0.1.0_amd64.deb`, 99,124,648 bytes, SHA-256 `2c82fc63893bc3991e9d835ebb2d86d91f6fb2dde20d8cb89b57b2312ebbbd24` (not copied back) |
| 4e | inspect | `dpkg-deb -I`, `-c`, `-f`; `-e` plus `sh -n` on the maintainer scripts | 0 | 93 entries; control + postinst + prerm + postrm, all pass `sh -n`; `Depends` derived |
| 4e | install | `sudo apt-get install -y --no-install-recommends ./hotspotshade_0.1.0_amd64.deb` | 0 | postinst ran; `/var/lib/hotspotshade` root:root 0700; `chrome-sandbox` 4755 root; polkit action `local.hotspotshade.tunnel.policy` present; `ldd` of all 8 ELF files shows 0 missing libraries; no hotspotshade process; network unchanged right after install |
| 4e | remove | `sudo apt-get remove -y hotspotshade` | 0 | `/opt/hotspotshade` and `/usr/lib/hotspotshade` gone; `/var/lib/hotspotshade` kept (0700); dpkg state `deinstall ok config-files` |
| 4e | purge | `sudo apt-get purge -y hotspotshade` | 0 | `/var/lib/hotspotshade` removed; package not installed; no polkit action left |
| 4e | network | `ip -br link; ip rule; ip route show table all; ip -6 rule` before install and after purge | 0 | identical (39 lines each, `diff` empty); no pkexec prompt, no helper, no tunnel |

`npm-ls` (exit 2) in `results.tsv` is my own check for `chrome-sandbox` before the
Electron binary was fetched. It is not a project test.

The sandbox already had a WireGuard interface `wg0` (10.77.0.0/16) and a `docker0`
bridge before I ran anything; both are in the "before" snapshot. I did not create
them and did not touch them.

### `.deb` details

- `dpkg-deb -f`: `Package: hotspotshade`, `Version: 0.1.0`, `Architecture: amd64`.
- The script's own `WARNING: dpkg-shlibdeps` line is absent, but `dpkg-shlibdeps`
  itself printed the same kinds of warnings as in run 1 (`logs/package-deb.log`,
  summary in `logs/package-deb-warning-check.log`): two "diversions involved - output
  may be incorrect", two "can't extract name and version from library name
  'libffmpeg.so'", and two "could avoid a useless dependency" (HotspotShade not using
  `libdl.so`, `libpthread.so`). The plan said "no `dpkg-shlibdeps` warning"; read it
  as in run 1: the script's missing-tool warning is absent, the tool's own warnings
  are not.
- `Depends` (derived, glibc 2.39) is the same list as run 1 and ends with
  `xdg-utils, pkexec`. Full text in `logs/deb-info.log`.
- Notable modes: `/opt/hotspotshade/chrome-sandbox` 4755 root, engine 0755, helper
  `/usr/lib/hotspotshade/hotspotshade-helper` 0755, polkit policy 0644.

## Failures

### Helper integration: `real_engine_demo::the_real_engine_serves_authenticated_loopback_status_and_stops_cleanly` fails intermittently (2 of 4 runs)

```
test the_real_engine_serves_authenticated_loopback_status_and_stops_cleanly ... HS_HELPER_TEST_STARTED ...
thread 'the_real_engine_serves_authenticated_loopback_status_and_stops_cleanly' (18) panicked at tests/real_engine_demo.rs:418:9:
inconclusive: engine exited before helper was frozen
test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.70s
```

Logs: `logs/helper-integration.log` (required run), `logs/helper-integration-rerun2.log`;
raw wrapper evidence in `logs/helper-integration-fail1-evidence/` and
`logs/helper-integration-rerun2-evidence/`.

What I know:

- The assertion is in `close_and_prove_liveness_exit` (`linux/helper/tests/real_engine_demo.rs`,
  around lines 380 to 420). It closes the request pipe, waits for the helper to
  release its liveness socket, freezes the helper with SIGSTOP, and then requires
  that the engine had not already exited. The two earlier assertions (helper state
  `T`, frozen inside the grace window) were satisfied; the engine had nevertheless
  already exited when the third check ran. The test's own comment says a late freeze
  "fails as inconclusive; it never passes", so it fails closed.
- `git diff --stat 417c6d43 dc2e281c -- linux/helper` is empty: the helper and its
  tests are the same bytes as in run 1, where this test passed. Only
  `rust/src/main.rs` changed under `rust/src` or `linux/helper` (13 lines).
- The 24 `helper_lifecycle` tests passed in all four runs.
- Passed in run 1 (1 run), failed in this run's required execution, passed in rerun 1,
  failed in rerun 2, passed in rerun 3.

What I do not know: whether the engine exits on EOF faster than a SIGSTOP can reach
the helper on this 4 vCPU VM (a test race that cannot prove anything when it loses),
or whether the engine's shutdown path changed. I did not instrument it. I did not
test for load sensitivity. This is a test-reliability finding, not shown to be a
production defect, but the step is not a clean pass.

### Fixed since run 1 (all three confirmed on this sandbox)

- `cargo clippy -- -D warnings`: exit 0, no dead-code finding (`logs/rust-clippy.log`).
- `tests::control_descriptors::a_spawned_child_does_not_inherit_the_control_descriptors`:
  `ok` (`logs/rust-test.log`, line 1442).
- `prerm sees a lock that a real flock process holds`: `✔` in all four `npm test`
  logs.

## Other observations

- The Electron runs print `dbus/bus.cc: Failed to connect to the bus` lines. The
  sandbox has no session bus. Both checks still exit 0.
- `npm test` on Linux without the binary: 349 tests, 341 pass, 8 skipped; with it:
  363 tests, 362 pass, 1 skipped. The count in the docs for macOS differs; I did
  not investigate why. The skipped names are in
  `logs/npm-test*.log` (lines starting with `﹣`).
- The helper integration used rustc 1.99.1 inside the pinned image, while the host
  tests ran on 1.97.1.
- `logs/*.log` are raw. They contain the sandbox's private paths and addresses. The
  sandbox is deleted.

## What this does not cover

No polkit prompt, no real desktop session, no tray or notifications, no real
hotspot or carrier, no live tunnel. `chrome-sandbox` setuid was exercised only
under Xvfb. The `Depends` list was not installed on a clean minimal host. The
`linux_tunnel_vm` suite (10 tests) stayed ignored and was not run. No
`source_snapshot.sh`, no `linux_vm_test.sh --tunnel`.

## Cost and limits

| Item | Value |
|---|---|
| Sandbox | `bx_x96uexbd`, `default`, 998 s of VM time at `boat usage` (taken at 02:15:40Z, just before delete), $0.00998 |
| Account | trial plan; `creditUsedSeconds` 1169 before, 2167 after; `trialComputeUsedSeconds` 2167 of 90,000 |
| Starts | 3 of 75 today; 0 active sandboxes now |
| Teardown | `boat delete bx_x96uexbd --yes` at 02:15:40Z; deletion operation `bdop_3d5c604a88124190b2a977b65a6eea31` status `completed` (02:15:43Z, via `boat deletion status`); `boat list --all` returns `"sandboxes":[]`; `boat info` and `boat usage` for the id return 404 |
| Local archive | the Mac copy `hs-dc2e281c.tar` and the scratch directory holding it were removed after the sandbox was deleted |

## Files

- `results.tsv`: step, exit code, SHA-256 of each log, note
- `logs/`: all command logs, the helper wrapper failure evidence, versions, counts
- `inputs/`: `git-ls-tree-paths.txt`, `tar-members.txt`, `tar-members-verbose.txt`,
  `extracted.paths`, `net-before.txt`, `net-after.txt`, and the two empty first-pass
  snapshots
- My helper scripts (step logger, extraction, package sequence) were not copied
  back; the commands they ran are in the first line of each log.
