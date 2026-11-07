# Linux evidence on a disposable Boat sandbox, commit 417c6d43

Run date: 2026-11-06 (sandbox clock 2026-11-07 01:36 to 01:50 UTC).
Plan: `docs/LINUX_EVIDENCE_PROPOSAL.md`, options 1 and 3. This is evidence for the
named commit only. It is not a release artifact and not an independent
attestation. It proves nothing about a live hotspot, a carrier, a polkit prompt,
a real desktop session, or a tunnel. No TUN device was created and no route was
changed.

**Result: not a clean pass.** Three real findings on Linux (see "Failures"):
clippy `-D warnings` fails, one Rust test fails, one Node test fails. Everything
else passed.

## Input

| Item | Value |
|---|---|
| Commit | `417c6d43567815a60a1619cc90316e1b10e82740` |
| Archive command | `git -C <repo> archive --format=tar --prefix=hotspotshade/ 417c6d43567815a60a1619cc90316e1b10e82740 -o hs-417c6d43.tar` |
| Archive SHA-256 | `1809bc1b5dab5681a6735bd4ee1abe6182c26ba3514ab52d8aeb6a8be7b74b83` (computed on the Mac, re-computed and matched inside the sandbox with `sha256sum -c`) |
| Archive size, members | 28,528,640 bytes, 1017 members (881 regular files) |
| Host checkout state | dirty (`M windows/.../EngineSnapshot.cs`, `?? noref/`); not an input. The archive is the commit tree only. |
| Pre-upload checks | no absolute or `..` member, no link member, no control byte in any path, none of `build/`, `noref/`, `*.mobileprovision`, `*.p12`, `identity.key`, `*.pem`, `*.key`, `.env`, `.git/`. `git ls-tree` lists no symlink, submodule, or `.gitattributes`. Names matching `token`, `credential`, `Keystore` are Kotlin/Swift/Rust source files, not secrets. |
| Uploaded | only `hs-417c6d43.tar`, plus my own helper shell scripts and the `git ls-tree` path list (text). No working tree, `build/`, credentials, keys, tokens, or profiles. |
| Mac disk before | 68 GiB free on `/System/Volumes/Data` (gate 25 GiB) |

Inside the sandbox, as the unprivileged `user` (uid 1000): refused-if checks for
absolute, `..`, link, and control-byte members all passed; extracted into a new
empty mode-700 directory with `tar --no-same-owner --no-same-permissions -xf`
(GNU tar 1.35). After extraction: no symlink or special file, no multi-link file,
no setuid/setgid bit; 881 files; the extracted file list equals both the tar
member list and `git ls-tree -r --name-only` (`diff` empty). Lists are in
`inputs/`.

## Host

Boat sandbox `bx_sgfsab38`, type `default` (4 vCPU, 8 GB), created with
`--no-env --no-snapshots --no-monitoring --ttl 7200`.
Ubuntu 24.04.4 LTS, kernel `6.8.0-117-generic` x86_64, glibc 2.39 (Ubuntu
2.39-0ubuntu8.8). Full list in `logs/versions.log`.

| Tool | Version |
|---|---|
| Rust / cargo | 1.97.1 (stable, rustup, preinstalled; no `rust-toolchain` file in the commit, so stable with `--locked`) |
| clippy / rustfmt | 0.1.97 / 1.9.0-stable |
| Node / npm | 24.22.1 / 11.19.1 (preinstalled via nvm; `linux/package.json` needs `>=22`) |
| Electron | 45.2.3 (lockfile pin) |
| Xvfb | `2:21.1.12-1ubuntu1.9` |
| dpkg-dev / dpkg-deb | `1.22.6ubuntu6.6` / 1.22.6 |
| Docker | 29.7.0 |
| Helper container image | `rust@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd` (Debian 12, rustc 1.99.1) |

Deviations from the plan, stated plainly:

- Rust, Node, Docker, and `dpkg-dev` were already on the Boat image, so I did not
  install them. I installed from apt only `xvfb xauth fonts-dejavu-core
  libgtk-3-0t64 libnss3 libasound2t64 libgbm1 libdrm2 libxkbcommon0 libxshmfence1
  libx11-xcb1 libxss1 libcups2t64 libatk-bridge2.0-0t64 libatspi2.0-0t64 libcairo2
  libpango-1.0-0 libgl1 ca-certificates`.
- The sandbox image is a desktop image (gnome-menus, lightdm, bamf present), not a
  minimal 24.04. `apt install ./hotspotshade.deb` pulled no new dependency, so it
  does not show the `Depends` list installs on a clean host.
- Electron 45 has no postinstall and npm 11.19 did not fetch its binary during
  `npm ci`. I ran `node -e 'console.log(require("electron"))'`, the same step as
  `linux/scripts/Dockerfile.test`, to download the binary. Then I set
  `chrome-sandbox` to root:root 4755 with `sudo` as the proposal says. No
  `--no-sandbox` was used.
- The helper container image was pulled from Docker Hub by the pinned digest. The
  helper wrapper ran as `user` (docker group), not root. The containers wrote
  `/opt` and `/var/lib/hotspotshade` only in their own layers.
- Python was not installed or used in the sandbox. The image has `/usr/bin/python3`
  from the base OS; nothing I ran called it, and the npm tree has no native build.
- The proposal's order stops on a failed command. I kept going so one failure did
  not hide the rest, and I added labeled supplementary runs (`diag-*`,
  `*-no-fail-fast`, `*-allow-dead-code`). They do not replace the required runs.

## Commands and results

Exit codes and log SHA-256 values are in `results.tsv` (log SHA-256 matches the
copied files). Logs are in `logs/`.

| # | Step | Command (from the extracted `hotspotshade/` root) | Exit | Result |
|---|---|---|---|---|
| 4a | fmt | `cargo fmt --check --manifest-path rust/Cargo.toml` | 0 | pass |
| 4a | check | `cargo check --all-targets --locked --manifest-path rust/Cargo.toml` | 0 | pass, 1 warning (dead code, below) |
| 4a | clippy | `cargo clippy --all-targets --locked --manifest-path rust/Cargo.toml -- -D warnings` | **101** | **FAIL**: 1 error |
| 4a | test | `cargo test --locked --manifest-path rust/Cargo.toml` | **101** | **FAIL**: stopped at the `main.rs` test binary, 37 passed, 1 failed |
| 4a+ | test, all targets | `cargo test --locked --no-fail-fast --manifest-path rust/Cargo.toml` | 101 | lib 1359 pass; `main.rs` 37 pass + 1 fail; integration binaries and 7 doc-tests pass; 15 ignored. Summed "passed" lines: 1716 (one is a 1-test re-run line inside the `main.rs` section), failed 1, ignored 15 (`logs/test-counts.log`) |
| 4a+ | clippy, dead code allowed | `... clippy --all-targets ... -- -D warnings -A dead_code` | 0 | pass: the dead-code error is the only clippy finding |
| 4b | helper test | `cargo test --locked --manifest-path linux/helper/Cargo.toml` | 0 | 65 unit + 24 `helper_lifecycle` + 2 `real_engine_demo` = 92 passed, 0 failed, 0 ignored. The 24 lifecycle and 2 real-engine tests pass by returning early without the opt-in; this is not integration evidence |
| 4b | helper clippy | `cargo clippy --all-targets --locked --manifest-path linux/helper/Cargo.toml -- -D warnings` | 0 | pass |
| 4b | helper integration | `HS_HELPER_CARGO_HOME=$HOME/.cargo bash linux/helper/tests/run-container.sh` | 0 | pass: `helper_lifecycle` 24 passed, `real_engine_demo` 2 passed, each with its `HS_HELPER_TEST_STARTED` marker, 7 staged-file SHA-256 checks OK, no TUN, no route, container network `none` |
| 4b | cleanup | `docker ps -a`, `docker volume ls`, `/tmp/hs-helper-evidence.*`, `/opt/hotspotshade` | 0 | no container, volume, evidence dir, or `/opt`/`/var/lib` residue |
| 4c | npm ci | `cd linux && npm ci` | 0 | 51 packages |
| 4c | npm test (no binary) | `npm test` | **1** | 349 tests, 340 pass, **1 fail**, 8 skipped (7 real-engine tests need `HOTSPOTSHADE_BIN`, 1 needs an isolated network and `HS_REAL_ENGINE_BIN`) |
| 4c | npm test (real engine) | `HOTSPOTSHADE_BIN=$PWD/../rust/target/debug/hotspotshade npm test` | **1** | 363 tests, 361 pass, **1 fail**, 1 skipped (`the Linux client reads a real unprivileged engine and parent loss stops it`, needs `HS_REAL_ENGINE_BIN` and an isolated network) |
| 4c | both again with the Electron binary present | same two commands | 1, 1 | identical counts (`*-with-electron.log`) |
| 4d | Settings window | `xvfb-run -a npm run test:settings-window` | 0 | 12 checks `"ok": true`, none false |
| 4d | accessibility | `xvfb-run -a npm run test:a11y` | 0 | `"ok": true`, `"violations": []`, 9 page states, 8 focus stops |
| 4e | package | `ARCH=x64 npm run package:deb` | 0 | `hotspotshade_0.1.0_amd64.deb`, 99,123,640 bytes, SHA-256 `a4a426c838ee8aa4fb5a7722993afbdc2c553946f6b30c4cc3a591dc2f1e3b93` (not copied back) |
| 4e | inspect | `dpkg-deb -I`, `-c`, `-f`; `-e` for maintainer scripts | 0 | 93 entries; control + postinst + prerm + postrm; `Depends` derived (below) |
| 4e | install | `sudo apt-get install -y --no-install-recommends ./hotspotshade_0.1.0_amd64.deb` | 0 | postinst ran; `/var/lib/hotspotshade` root:root 0700; no missing library in `ldd` of the app, engine, or helper |
| 4e | remove | `sudo apt-get remove -y hotspotshade` | 0 | prerm passed with no helper; `/opt` and `/usr/lib/hotspotshade` gone; `/var/lib/hotspotshade` kept (0700) |
| 4e | purge | `sudo apt-get purge -y hotspotshade` | 0 | `/var/lib/hotspotshade` removed; package not installed |
| 4e | network | `ip -br link; ip rule; ip route show table all; ip -6 rule` before install and after purge | 0 | identical (35 lines each, `diff` empty); no pkexec prompt, no helper, no tunnel |

`npm-ls` (exit 2) in `results.tsv` is my own check for `chrome-sandbox` before the
Electron binary was fetched. It is not a project test.

### `.deb` details

- `dpkg-deb -f`: `Package: hotspotshade`, `Version: 0.1.0`, `Architecture: amd64`.
- The script's own `WARNING: dpkg-shlibdeps` line is absent (`dpkg-shlibdeps` ran),
  but `dpkg-shlibdeps` itself printed warnings (`logs/package-deb.log`): two
  "diversions involved - output may be incorrect" (libc6 `ld-linux-x86-64.so.2`),
  two "can't extract name and version from library name 'libffmpeg.so'", and two
  "could avoid a useless dependency" (HotspotShade not using `libpthread.so.0`,
  `libdl.so.2`). The plan said "no `dpkg-shlibdeps` warning"; read this as: the
  script's missing-tool warning is absent, the tool's own warnings are not.
- `Depends` (derived, glibc 2.39): `libatspi2.0-0t64 (>= 2.9.90), libc6 (>= 2.39),
  libdbus-1-3 (>= 1.9.14), libexpat1 (>= 2.1~beta3), libgcc-s1 (>= 4.2),
  libglib2.0-0t64 (>= 2.50.0), libnspr4 (>= 2:4.9-2~), libudev1 (>= 183),
  libx11-6 (>= 2:1.4.99.1), libxcb1 (>= 1.9.2), libxcomposite1 (>= 1:0.4.5),
  libxdamage1 (>= 1:1.1), libxext6, libxfixes3, libxrandr2, libasound2t64 |
  libasound2, libatk-bridge2.0-0t64 | libatk-bridge2.0-0, libatk1.0-0t64 |
  libatk1.0-0, libcairo2, libcups2t64 | libcups2, libdrm2, libgbm1, libgl1,
  libgtk-3-0t64 | libgtk-3-0, libnss3, libpango-1.0-0, libx11-xcb1, libxkbcommon0,
  libxshmfence1, libxss1, xdg-utils, pkexec`. Full text in `logs/deb-info.log`.
- `Recommends: policykit-1-gnome | polkit-kde-agent-1 | lxqt-policykit | mate-polkit`.
- Notable file modes: `/opt/hotspotshade/chrome-sandbox` 4755 root, helper 0755,
  engine 0755, polkit policy 0644.

## Failures

### 1. `cargo clippy -- -D warnings` fails: dead code, `rust/src/main.rs:183`

```
error: variant `Socket` is never constructed
   --> src/main.rs:183:5
179 | enum ControlDescriptorKind {
183 |     Socket,
    = note: `-D dead-code` implied by `-D warnings`
error: could not compile `hotspotshade` (bin "hotspotshade" test) due to 1 previous error
```

`Socket` is built only by `HANDOFF` under `#[cfg(target_os = "macos")]`
(`main.rs:192`), so on Linux no code constructs it. The same warning appears in
`cargo check`, `cargo build --release`, and the `.deb` build. With `-A dead_code`
clippy is clean for all targets. Log: `logs/rust-clippy.log`,
`logs/rust-clippy-allow-dead-code.log`.

### 2. Rust test `tests::control_descriptors::a_spawned_child_does_not_inherit_the_control_descriptors` fails, `rust/src/main.rs:4097` (helper `child_inherits` at `main.rs:4077-4088`)

```
thread '...a_spawned_child_does_not_inherit_the_control_descriptors' panicked at src/main.rs:4097:17:
the unsealed descriptor must reach a child, or the check proves nothing
test result: FAILED. 37 passed; 1 failed; 0 ignored
```

The test's precondition runs `/bin/sh -c '{ : >&<fd>; } 2>/dev/null'` with
descriptors moved to fd 64 or above. On Ubuntu `/bin/sh` is dash, which accepts
only single-digit descriptors in a redirection, so the shell exits 2 before it
can show inheritance. Diagnostic on the sandbox (`logs/diag-dash-fd64.log`):
`sh -c ': >&64'` prints `Bad fd number` and exits 2; the same redirect with fd 9
and under bash exits 0. So the precondition fails regardless of whether the
production code seals the descriptors. This is a test portability defect, not
shown to be a production defect, but the sealing assertion after it never ran on
Linux. Log: `logs/rust-test.log`, `logs/rust-test-no-fail-fast.log`.

### 3. Node test `prerm sees a lock that a real flock process holds` fails, `linux/test/packaging.test.mjs:694`

```
✖ prerm sees a lock that a real flock process holds (307.0ms)
  AssertionError: hotspotshade: refusing to remove the package: the privileged
  helper is running (it holds /tmp/hotspotshade-maint-inkjcX/state/helper.lock).
  1 !== 0
      at ... packaging.test.mjs:694:14
```

The test (starts at `:679`) holds the lock with `flock -x -n <lock> sleep 30`
(`:684`), kills only the `flock` process with SIGTERM (`:691`), and expects the
lock to be free at `:694`. util-linux 2.39.3 `flock` forks the command by
default, so the `sleep 30` child keeps the lock fd after its parent dies and
`prerm` correctly refuses. Diagnostic (`logs/diag-flock-fork.log`): after the
parent is killed a shared non-blocking lock attempt returns 99 (held), the
`sleep` child is still alive, and the lock frees only after it is killed;
`flock --no-fork` frees it at once. `prerm` behaved correctly; the test needs
`--no-fork` or to kill the process group. Same failure with and without
`HOTSPOTSHADE_BIN`, and with and without the Electron binary. Logs:
`logs/npm-test*.log`.

## Other observations

- The Electron runs print `dbus/bus.cc: Failed to connect to the bus` lines. The
  sandbox has no session bus. Both checks still exit 0.
- `npm test` counts: the documented "337 passed, 4 skipped" (macOS) differs from
  Linux (340 pass, 1 fail, 8 skipped without the binary; 361 pass, 1 fail,
  1 skipped with it). The skipped names are in `logs/npm-test*.log` (lines
  starting with `﹣`).
- Helper unit tests pass "ok" for the lifecycle cases without `HS_HELPER_INTEGRATION`
  because they skip by returning; only `helper-integration.log` is integration
  evidence.
- The rust image used for the helper wrapper has rustc 1.99.1, while the host
  tests ran on 1.97.1; the helper integration therefore used a different compiler
  than 4a, 4b, 4c.
- `logs/*.log` are raw. They contain the sandbox's private paths and, in
  `apt-pre-state.log` and `apt-purged-state.log`, the sandbox's addresses. The
  sandbox is deleted.

## What this does not cover

No polkit prompt, no real desktop session, no tray or notifications, no real
hotspot or carrier, no live tunnel. `chrome-sandbox` setuid was exercised only
under Xvfb. The `Depends` list was not installed on a clean minimal host. The
`linux_tunnel_vm` suite (10 tests) stayed ignored and was not run.

## Cost and limits

| Item | Value |
|---|---|
| Sandbox | `bx_sgfsab38`, `default`, 791 s of VM time at `boat usage`, $0.00791 |
| Account | trial plan; `creditUsedSeconds` 377 before, 1169 after; `trialComputeUsedSeconds` 1169 of 90,000; 25 h trial compute still available |
| Starts | 2 of 75 today (one earlier run, this run); 0 active sandboxes now |
| Teardown | `boat delete bx_sgfsab38 --yes` at 2026-11-07 01:50:03Z; deletion operation `bdop_9978dba0a1504681a74fe61e0b15c874` status `completed` (01:50:07Z); `boat list --all` returns `"sandboxes":[]`; `boat info bx_sgfsab38` returns 404 |

The local archive is still on the Mac in a private scratchpad directory (mode 700)
and can be removed.

## Files

- `results.tsv`: step, exit code, SHA-256 of each log
- `logs/`: all command logs, diagnostics, and version output
- `inputs/git-ls-tree-paths.txt`, `inputs/tar-members.txt`, `inputs/extracted.paths`
