# Linux evidence proposal

Status: proposal. No transfer, VM, or container was run for this document. It is
not evidence.

## Purpose

This proposes a minimal, reviewable path to Linux evidence for the commit on
`completion-2026-11-06` without using the closed source snapshot verifier or the
diagnostic VM harness.

The evidence covers:

- Rust tests on Linux, including the Linux privileged helper tests.
- The opt-in helper integration tests in a disposable container.
- `cd linux && npm test` with `HOTSPOTSHADE_BIN` naming a Linux engine.
- The Xvfb Settings window check and the accessibility check.
- One `.deb` build on Ubuntu 24.04 with `dpkg-shlibdeps`.
- A separate live tunnel test in a disposable VM, only with owner approval.

None of these proves a live hotspot, a carrier, a real desktop authorization
prompt, or a physical source device.

## Current gate

`AGENTS.md` and [LINUX_TEST_VM.md](LINUX_TEST_VM.md) close the Linux VM source
snapshot transfer gate. The reviewed verifier could misclassify an untracked or
ignored file as tracked and clean. It could also write through a planted
extraction hard link. The current `scripts/source_snapshot.sh` contains repairs
for both defects, but those repairs and the exact archive have not passed a new
independent review.

The `scripts/linux_vm_test.sh --tunnel` path is diagnostic only and always
reports failure. Its root test process can alter the status file it uses to
report its own result. Passing the transfer gate alone would not provide a
trusted tunnel result.

The prepared VM image is not an input for this proposal. Its cached source was
found stale and partial, and it had no `linux/` directory or Linux helper
source.

Do not run `scripts/source_snapshot.sh` or `scripts/linux_vm_test.sh` for this
evidence.

## Candidate commit and preconditions

Candidate commit at the time of writing:

```
f7ade3eb4616276fdd25616f6726b577e7cb006c
```

Resolve it again before the run. Do not copy the hash from this document
without checking it.

The archive is built from the commit, never from the worktree. The commit is
the source of truth. At the time of writing, `git status --porcelain=v1` in the
checkout showed modified tracked paths and untracked source paths. Those paths
are not inputs. If any required Linux source is only in the worktree, stop,
commit it through the normal review, and use the new commit. Do not add a
working-tree overlay to the archive.

Before the run, the owner or an independent reviewer must confirm:

- The commit SHA is the intended evidence commit.
- `git ls-tree -r` lists no `.git`, build output, cache, `noref/`, probe data,
  private key, credential, certificate, packet capture, or personal data.
- No tracked path contains a newline or another control byte. A line-oriented
  path list cannot represent it safely.
- The commit has no `.gitattributes` export rules, submodule, or symlink entry.
  If it has any, review each one and record the decision.
- The archive file list and SHA-256 are recorded outside the archive set.

## The two verifier defects

### Untracked or ignored files could look tracked

The verifier built a manifest from tracked names and compared the worktree with
the index and HEAD. A path with a newline, a crafted tar header numeric field,
or an assume-unchanged or skip-worktree bit could make an untracked, ignored, or
dirty path look tracked and clean. The repaired script rejects those cases, but
the repair is unreviewed.

`git archive <commit>` does not read the index or the worktree. It exports the
tree of the named commit. An untracked or ignored file cannot enter the archive
because it is not in the tree. There is no manifest classification step to
fool. The remaining review is of the commit and its tracked contents, not of a
dirty-tree classifier.

### Extraction could write through a planted hard link

The verifier published verified files with hard links into a caller-named
destination. A planted hard link in that destination could share an inode with
a sensitive file, so the write changed that file. The repaired script uses
`ln -n` and identity checks, but the repair is unreviewed.

This proposal does not use `--extract-to` or the verifier's publication path.
It extracts with `tar` into a newly created empty directory owned by an
unprivileged user, with `--no-same-owner`. No destination file exists to link
through. The archive is pinned by SHA-256, inspected for link entries, and the
extracted tree is checked for symlinks, hard links, special files, and setuid or
setgid bits.

The remaining risks are the tar parser, the archive contents, and a same-user
race on the host. The archive is generated locally by git from a reviewed
commit, not supplied by a third party. The extraction host must be disposable
and free of concurrent untrusted processes. This is evidence input handling,
not a sandbox boundary.

## Evidence matrix

| Evidence | Command | Expected result | Environment |
|---|---|---|---|
| Rust tests | `cargo check --all-targets --locked --manifest-path rust/Cargo.toml`, `cargo test --locked --manifest-path rust/Cargo.toml`, `cargo clippy --all-targets --locked --manifest-path rust/Cargo.toml -- -D warnings` | No errors, all tests pass, no clippy findings | Ubuntu 24.04, Rust version recorded |
| Helper tests | `cargo test --locked --manifest-path linux/helper/Cargo.toml` | Helper unit tests pass; integration cases skip without the opt-in | Same host |
| Helper integration | `bash linux/helper/tests/run-container.sh` | Both test executables start every inventory marker and pass | Root plus Docker, container marker |
| Node tests | `cd linux && HOTSPOTSHADE_BIN="$PWD/../rust/target/debug/hotspotshade" npm test` | 0 failures; only documented skips | Unprivileged user, Node 22 or later |
| Settings window | `cd linux && xvfb-run -a npm run test:settings-window` | All checks pass | Xvfb, Electron, unprivileged user |
| Accessibility | `cd linux && xvfb-run -a npm run test:a11y` | `"ok": true`, 0 violations, 9 page states, 8 focus stops | Xvfb, Electron, unprivileged user |
| Package | `cd linux && ARCH=x64 npm run package:deb` | One `hotspotshade_0.1.0_amd64.deb`; no `dpkg-shlibdeps` warning | Ubuntu 24.04 amd64, `dpkg-dev` |
| Live tunnel | Manual `linux_tunnel_vm` suite | Exploratory only; 8 scenarios and 2 filtered helpers | Disposable VM with root, owner approval |

The first seven are userspace and build evidence. The live tunnel row is a
separate test with a separate approval.

## Option 1: committed archive transfer

This is a transfer method, not a test host. It proves only that the bytes on
the host are the reviewed commit. A test result still depends on the host and
the command logs.

### What it proves

- The archive contains the tree of the named commit, subject to any reviewed
  export attributes.
- No untracked, ignored, or working-tree-only file can enter.
- The SHA-256 pin binds the transferred archive.
- Extraction into an empty directory as an unprivileged user produces a tree
  with no symlink, hard link, special file, or setuid or setgid bit, when the
  post-extraction checks pass.
- The extracted file list can be compared with `git ls-tree -r`.

### What it cannot prove

- That the commit is correct, complete, or free of secrets.
- That the host is clean, that the toolchain is genuine, or that a test result
  is trustworthy.
- A real polkit agent, a real desktop session, a live hotspot, or a physical
  source device.
- A live tunnel result. That is the separate test below.

### Exact commands

Run these from the repository root on the reviewer machine. The output
directory must be private.

```sh
set -eu
REPO=$PWD
COMMIT=$(git -C "$REPO" rev-parse --verify 'completion-2026-11-06^{commit}')
printf '%s\n' "$COMMIT"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/hs-archive.XXXXXXXX")
chmod 700 "$WORK"

git -C "$REPO" status --porcelain=v1 > "$WORK/status"
git -C "$REPO" ls-tree -r --name-only "$COMMIT" \
  | LC_ALL=C sort > "$WORK/paths"
wc -l "$WORK/paths"

# Both outputs must be empty. Review any entry before continuing.
git -C "$REPO" ls-tree -r "$COMMIT" \
  | awk '$1=="120000" || $1=="160000" {print}'
git -C "$REPO" ls-tree -r --name-only "$COMMIT" \
  | grep -E '(^|/)\.gitattributes$' || true

git -C "$REPO" archive --format=tar \
  --prefix="hotspotshade-$COMMIT/" \
  -o "$WORK/hotspotshade-$COMMIT.tar" "$COMMIT"
gzip -n -9 "$WORK/hotspotshade-$COMMIT.tar"

SHA=$(shasum -a 256 "$WORK/hotspotshade-$COMMIT.tar.gz" | awk '{print $1}')
printf '%s  %s\n' "$SHA" "hotspotshade-$COMMIT.tar.gz" \
  > "$WORK/hotspotshade-$COMMIT.sha256"
printf '%s\n' "$SHA"
printf '%s\n' "$WORK"
```

On a Linux reviewer host, use `sha256sum` in place of `shasum -a 256`. The
`gzip -n` flag keeps the timestamp and original name out of the gzip header.

Inspect the archive before transfer:

```sh
tar -tzf "$WORK/hotspotshade-$COMMIT.tar.gz" \
  | grep -E '(^/|(^|/)\.\.(/|$))' || true
tar -tvzf "$WORK/hotspotshade-$COMMIT.tar.gz" \
  | awk '$1 ~ /^[lh]/ {print}'
```

Both outputs must be empty. Stop on an absolute path, a parent component, a
symlink, or a hard link.

Transfer only the three files. Do not use `boat push`, a recursive copy, or a
directory upload. `boat push` copies tracked working-tree files, including
uncommitted edits, which is the defect this proposal avoids. Use the same shell
as the archive block, or set `WORK` and `COMMIT` to the values printed there.

```sh
SANDBOX=<sandbox-id>
boat scp "$WORK/hotspotshade-$COMMIT.tar.gz" \
  "$SANDBOX:hotspotshade-$COMMIT.tar.gz"
boat scp "$WORK/paths" "$SANDBOX:hs-$COMMIT.paths"
boat scp "$WORK/hotspotshade-$COMMIT.sha256" \
  "$SANDBOX:hotspotshade-$COMMIT.sha256"
```

Verify and extract as the unprivileged account on the host. Compare the
printed digest with the digest recorded outside the archive set. Do not trust
the uploaded checksum file alone.

```sh
cd "$HOME"
RUN="$HOME/hs-evidence-$COMMIT"
test ! -e "$RUN"
mkdir -m 700 "$RUN"
mkdir -m 700 "$RUN/src"

test -f "hotspotshade-$COMMIT.tar.gz"
test ! -L "hotspotshade-$COMMIT.tar.gz"
test "$(stat -c '%h' "hotspotshade-$COMMIT.tar.gz")" = 1
mv "hotspotshade-$COMMIT.tar.gz" "hs-$COMMIT.paths" \
  "hotspotshade-$COMMIT.sha256" "$RUN/"
cd "$RUN"

sha256sum -c "hotspotshade-$COMMIT.sha256"
sha256sum "hotspotshade-$COMMIT.tar.gz"

umask 022
tar -xzf "hotspotshade-$COMMIT.tar.gz" -C "$RUN/src" \
  --no-same-owner --delay-directory-restore

SRC="$RUN/src/hotspotshade-$COMMIT"
test -d "$SRC"
test "$(stat -c '%a' "$RUN")" = 700
test "$(stat -c '%u' "$SRC")" = "$(id -u)"

test -z "$(find "$SRC" \
  \( -type l -o -type p -o -type s -o -type b -o -type c \) \
  -print -quit)"
test -z "$(find "$SRC" -type f -links +1 -print -quit)"
test -z "$(find "$SRC" -perm /6000 -print -quit)"

( cd "$SRC" && find . -type f | sed 's|^\./||' | LC_ALL=C sort ) \
  > "$RUN/extracted.paths"
diff -u "hs-$COMMIT.paths" "$RUN/extracted.paths"
```

Do not pass `-p`, and do not pass `--no-same-permissions`. The first can try to
restore elevated ownership, and the second can strip the executable bit from
scripts. Extract as the unprivileged user with `umask 022`.

### Approval needed

The owner must approve:

- The exact commit and the exact archive SHA-256.
- The destination host and the upload of the source archive.
- The deletion of the host and all copies of the archive after the evidence is
  copied back.

The archive must not contain credentials, identity keys, tokens, certificates,
provisioning profiles, packet captures, or personal data.

### Risks

- A wrong commit or a committed secret defeats the review.
- An export attribute, submodule, or symlink changes what the archive means.
- A path with a newline or another control byte defeats the line-oriented path
  list and diff.
- A tar parser defect or a same-user race on the host changes the extracted
  tree.
- A digest recorded by the same process that made the archive is not an
  independent review record.
- A public transfer path exposes the source archive.

## Option 2: local Docker or Colima container

### What it proves

- Linux kernel and userspace behavior for the container architecture.
- The Rust tests, the Node tests, and the Xvfb checks when the image has the
  needed libraries.
- The helper integration through the host Docker daemon, using the real helper
  and a real engine inside a container.

### What it cannot prove

- Native amd64 behavior on an Apple Silicon Mac. The default Docker
  architecture is `aarch64`. An `amd64` container runs under QEMU emulation.
  Timing, Electron rendering, and process races can differ.
- Ubuntu 24.04 `dpkg-shlibdeps` evidence on the existing test image. That image
  is `node:24-bookworm` with glibc 2.36, not Ubuntu 24.04 with glibc 2.39.
- A real polkit agent, a real desktop session, a tray, or desktop notifications.
- A live hotspot or a live tunnel.

### Exact commands

Check the architecture first:

```sh
uname -m
docker version
docker info --format '{{.Architecture}}'
docker run --rm --platform linux/amd64 ubuntu:24.04 uname -m
```

The last command must print `x86_64`. If it does not, the amd64 path is not
available.

Run the Electron and Node checks with the existing test image:

```sh
cd /path/to/reviewed/source
bash linux/scripts/test-container.sh smoke
bash linux/scripts/test-container.sh a11y
```

The Settings check has no `test-container.sh` mode. Use the same image and the
same mounted layout with an explicit Electron target:

```sh
docker run --rm --init --security-opt seccomp=unconfined --shm-size=512m \
  -v "$PWD/linux:/work:ro" \
  hotspotshade-linux-test:45.2.3 \
  bash -lc 'cd /work && xvfb-run -a /opt/hs-deps/node_modules/.bin/electron test/settings-window-main.js'
```

The image must be built from `linux/scripts/Dockerfile.test` first. The image
mounts the `linux/` directory at `/work` and runs as `appuser` by default. It
carries the setuid Electron sandbox helper and its own `node_modules` under
`/opt/hs-deps`.

The Rust, helper, and Node suites need a Linux image with Rust, Node 22 or
later, and the Electron libraries. Enter the prepared image and run:

```sh
docker run --rm -it --platform linux/amd64 \
  -v "$PWD:/work" -w /work \
  hs-ubuntu-2404-evidence:local bash
```

Inside the container:

```sh
cargo test --locked --manifest-path rust/Cargo.toml
cargo test --locked --manifest-path linux/helper/Cargo.toml
cd linux
npm ci
HOTSPOTSHADE_BIN="$PWD/../rust/target/debug/hotspotshade" npm test
```

The helper integration uses the host Docker daemon, not the container shell:

```sh
cd /path/to/reviewed/source
HS_HELPER_CARGO_HOME="$HOME/.cargo" \
  bash linux/helper/tests/run-container.sh
```

The `.deb` baseline needs a separate Ubuntu 24.04 image. Do not use the Debian
test image for that result. A one-off container needs Node 22 or later, Rust,
`dpkg-dev`, `dpkg-deb`, and the Electron libraries. If the owner prepares that
image, run:

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD:/work" -w /work/linux \
  hs-ubuntu-2404-evidence:local \
  bash -lc 'npm ci && ARCH=x64 npm run package:deb'
```

The image name and digest must be recorded. Do not build it from unpinned
network downloads during the evidence run. Run the container as a non-root
user, or mount a disposable copy. A root container must not write the host
checkout.

### Approval needed

The owner must approve:

- Installing or using Docker Desktop or Colima on the Mac.
- Pulling images and using network access for dependency installation.
- Running containers with `seccomp=unconfined` and the setuid Electron sandbox
  helper.
- The CPU, disk, and time cost.

No route or TUN change is part of this option.

### Risks

- `aarch64` results are not `amd64` results. QEMU can hide or create races.
- The Debian test image is not the Ubuntu 24.04 package baseline.
- The Docker daemon is root-equivalent on the host. A container escape is a
  host compromise.
- The setuid sandbox helper and `seccomp=unconfined` widen the container
  boundary.
- There is no polkit agent or real desktop session, so the authorization path
  remains untested.

## Option 3: Boat Ubuntu sandbox

### What it proves

- A native Ubuntu amd64 machine with root, systemd, and Docker. The run
  requires Ubuntu 24.04 and stops on another release.
- Native `.deb` build and `dpkg-shlibdeps` behavior for `amd64`.
- Xvfb Settings and accessibility checks on the real target architecture.
- The helper integration inside the sandbox Docker daemon.
- The Rust and Node suites on a full Ubuntu userland, not a minimal container.

### What it cannot prove

- A real hotspot, carrier, or physical source device. A Boat sandbox has a
  public IPv4 address, not a Wi-Fi hotspot.
- A real polkit agent or a real desktop authorization prompt. A desktop stream
  may exist, but this run does not test the prompt unless the owner approves a
  separate interactive test.
- Ubuntu 24.04 if the sandbox reports another release. Check
  `/etc/os-release` in the preflight and stop on a different release.
- Native macOS or Windows behavior.
- An independent attestation. The sandbox result is only as good as the
  command logs and the reviewed inputs.
- The Electron client's real request socketpair, the kernel parent-death
  signal, or the helper timeout fallback. The helper integration uses a fake
  engine for the lifecycle cases and a real engine only for the demo case. It
  starts no tunnel.
- That the `.deb` installs or runs on a clean Ubuntu 24.04 host. The build
  proves the package layout and the derived `Depends` list. It is unsigned.
  Installation changes `/opt`, `/var/lib`, and the polkit action, so it needs a
  separate approval.

### Exact commands

These commands assume the `boat` CLI is installed and signed in, and `jq` is
present. Create a sandbox with no account secrets and no snapshots. The owner
must approve the cost and the data flow first.

```sh
boat limits
SANDBOX=$(boat new --type default --ttl 7200 --no-env --no-snapshots \
  --name hs-linux-evidence --json \
  | jq -r 'select(.event == "ready") | .id')
printf '%s\n' "$SANDBOX"
```

Preflight the image:

```sh
boat exec "$SANDBOX" -- bash -lc '
  set -eu
  id
  printf "%s\n" "$HOME"
  uname -m
  . /etc/os-release
  printf "%s\n" "$PRETTY_NAME"
  node --version
  npm --version
  rustc --version
  cargo --version
  dpkg-deb --version | head -1
  command -v dpkg-shlibdeps || true
  sudo -n docker version
  sudo -n true
'
```

Stop if the host is not Ubuntu 24.04, is not `x86_64`, has Node older than 22,
lacks Rust or Docker, or does not allow `sudo -n`. Do not add an unreviewed
Node or Rust installer to work around a missing tool.

Install only the missing build and display packages:

```sh
boat exec "$SANDBOX" -- sudo apt-get update
boat exec "$SANDBOX" -- sudo env DEBIAN_FRONTEND=noninteractive \
  apt-get install -y --no-install-recommends \
  dpkg-dev xvfb xauth \
  libgtk-3-0t64 libnss3 libasound2t64 libgbm1 libdrm2 \
  libxkbcommon0 libxshmfence1 libx11-xcb1 libxss1 libcups2t64 \
  libatk-bridge2.0-0t64 libatspi2.0-0t64 libcairo2 \
  libpango-1.0-0 fonts-dejavu-core
```

Transfer and extract with option 1. Set the remote paths in the local shell
that drives the sandbox. Each `boat exec` passes them explicitly because each
call starts a new remote shell.

```sh
COMMIT=f7ade3eb4616276fdd25616f6726b577e7cb006c
RUN="/home/user/hs-evidence-$COMMIT"   # use the $HOME printed in preflight
SRC="$RUN/src/hotspotshade-$COMMIT"
```

Run the Rust and helper unit tests as the default unprivileged account. The
usual Boat account is `user`; if `id -u` returns 0, create a separate
unprivileged account first and use it for every test except the helper
integration.

```sh
boat exec "$SANDBOX" --timeout 0 -- env RUN="$RUN" SRC="$SRC" bash -lc '
  set -euo pipefail
  cd "$SRC/rust"
  cargo check --all-targets --locked 2>&1 | tee "$RUN/rust-check.log"
  cargo test --locked 2>&1 | tee "$RUN/rust-test.log"
  cargo clippy --all-targets --locked -- -D warnings \
    2>&1 | tee "$RUN/rust-clippy.log"
  cargo test --locked --manifest-path ../linux/helper/Cargo.toml \
    2>&1 | tee "$RUN/helper-test.log"
  cargo clippy --all-targets --locked \
    --manifest-path ../linux/helper/Cargo.toml -- -D warnings \
    2>&1 | tee "$RUN/helper-clippy.log"
  cargo build --locked 2>&1 | tee "$RUN/engine-debug-build.log"
'
```

Run the Node suite as `user`, not as root. The real-engine test skips as root.

```sh
boat exec "$SANDBOX" --timeout 0 -- env RUN="$RUN" SRC="$SRC" bash -lc '
  set -euo pipefail
  cd "$SRC/linux"
  npm ci 2>&1 | tee "$RUN/npm-ci.log"
  HOTSPOTSHADE_BIN="$SRC/rust/target/debug/hotspotshade" \
    npm test 2>&1 | tee "$RUN/npm-test.log"
'
```

The Xvfb checks need the setuid Electron sandbox helper. If Electron refuses
the sandbox, fix the helper permissions as root and run as `user`. Do not use
`--no-sandbox` for evidence.

```sh
boat exec "$SANDBOX" -- env SRC="$SRC" bash -lc '
  sudo chown root:root \
    "$SRC/linux/node_modules/electron/dist/chrome-sandbox"
  sudo chmod 4755 \
    "$SRC/linux/node_modules/electron/dist/chrome-sandbox"
'

boat exec "$SANDBOX" --timeout 0 -- env RUN="$RUN" SRC="$SRC" bash -lc '
  set -euo pipefail
  cd "$SRC/linux"
  xvfb-run -a npm run test:settings-window \
    2>&1 | tee "$RUN/settings-window.log"
  xvfb-run -a npm run test:a11y 2>&1 | tee "$RUN/a11y.log"
'
```

Run the helper integration as root with Docker. The script requires a local
Cargo registry cache and the pinned Rust image. Pull the image first, then run
the wrapper from the repository root. It runs its own containers with no
network.

```sh
boat exec "$SANDBOX" --timeout 0 -- env RUN="$RUN" SRC="$SRC" bash -lc '
  set -euo pipefail
  sudo docker pull \
    rust@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd
  cd "$SRC"
  sudo env PATH="$PATH" \
    HS_HELPER_CARGO_HOME="$HOME/.cargo" \
    bash linux/helper/tests/run-container.sh \
    2>&1 | tee "$RUN/helper-integration.log"
'
```

Build the package as `user` on the native amd64 host. The source tree is owned
by `user`. `dpkg-shlibdeps` must be present, and the log must not contain its
warning.

```sh
boat exec "$SANDBOX" --timeout 0 -- env RUN="$RUN" SRC="$SRC" bash -lc '
  set -euo pipefail
  cd "$SRC/linux"
  ARCH=x64 npm run package:deb 2>&1 | tee "$RUN/package-deb.log"
  ! grep -q "WARNING: dpkg-shlibdeps" "$RUN/package-deb.log"
  test -f build/hotspotshade_0.1.0_amd64.deb
  dpkg-deb -f build/hotspotshade_0.1.0_amd64.deb \
    Package Version Architecture Depends \
    2>&1 | tee "$RUN/package-deb-control.log"
  sha256sum build/hotspotshade_0.1.0_amd64.deb \
    2>&1 | tee "$RUN/package-deb-sha256.log"
'
```

Copy the logs and package metadata out before deleting the sandbox. Do not
copy `node_modules`, `rust/target`, or the archive back.

```sh
boat exec "$SANDBOX" -- env RUN="$RUN" bash -lc '
  set -euo pipefail
  cd "$RUN"
  tar -czf evidence.tar.gz -- *.log hs-*.paths *.sha256
'

mkdir -p build
test ! -e "build/linux-evidence-$COMMIT.tar.gz"
boat scp "$SANDBOX:$RUN/evidence.tar.gz" \
  "build/linux-evidence-$COMMIT.tar.gz"
boat scp "$SANDBOX:$SRC/linux/build/hotspotshade_0.1.0_amd64.deb" \
  "build/linux-evidence-$COMMIT.deb"

boat delete "$SANDBOX" --yes
```

Use `boat delete`, not `boat stop`. `--no-snapshots` plus a stop erases the
disk, but delete is the explicit end state. Confirm the sandbox is gone with
`boat list --all`.

### Approval needed

The owner must approve:

- Creating a paid Boat sandbox and the expected cost.
- The source archive upload and the sandbox network access.
- Running root commands inside the sandbox.
- Copying the evidence back and deleting the sandbox.

The sandbox must use `--no-env`. Do not attach a repository, secret file, or
account credential.

### Risks

- The sandbox has a public IPv4 address. Treat the source archive as exposed
  until the sandbox is deleted.
- A sandbox is a remote machine with its own trust boundary. A same-user
  process on the sandbox can change the source or the logs.
- Nested Docker adds a second boundary and a second place for stale images.
- The archive and evidence remain in the snapshot unless `--no-snapshots` is
  set and the sandbox is deleted.
- A headless sandbox does not test the polkit prompt or a real desktop.

## Option 4: GitHub Actions rust-linux after a push

### What it proves

- The pushed commit passes the existing `rust-linux` job on `ubuntu-latest`.
- That job runs type check, `cargo test`, Linux clippy, the helper unit tests,
  the helper clippy, the snapshot helper tests, the VM cleanup fixture, the
  Linux Electron Node suite with `HOTSPOTSHADE_BIN`, and the sandboxed webview
  smoke test.
- The result is attached to a public commit and a workflow run, which is easy
  for another person to inspect.

### What it cannot prove

- The Settings window check, the accessibility check, the `.deb` build, and
  `dpkg-shlibdeps`. The current job does not run them.
- The opt-in helper integration. The current job runs the helper unit tests
  without `HS_HELPER_INTEGRATION=1`.
- A real polkit agent, a real desktop session, a tray, notifications, a live
  hotspot, or a live tunnel.
- That the workflow policy and cache are trustworthy. The release audit and
  scanner are under review, and the job uses a Rust cache.

### Exact commands

```sh
git status --porcelain=v1
git push origin completion-2026-11-06
gh run list --workflow ci.yml --branch completion-2026-11-06 --limit 1
gh run watch <run-id>
gh run view <run-id> --log-failed
```

Record the commit, the run URL, and the `rust-linux` job log. Do not disable a
job or add `continue-on-error` to make it pass.

### Approval needed

The owner must approve:

- Pushing the branch to GitHub. This publishes the commit.
- GitHub Actions use and any artifact or log retention.
- The workflow change if the missing checks are added later.

### Risks

- A push makes the commit public or visible to the repository audience.
- The runner image can change. `ubuntu-latest` is not a pinned 24.04 image.
- A build cache can supply stale or substituted artifacts.
- The current job does not cover the evidence that is still missing.
- A CI pass is a second signal, not proof of a live tunnel or a desktop
  authorization path.

## Comparison

| Option | What it proves | What it cannot prove | Approval | Main risk |
|---|---|---|---|---|
| 1. Committed archive | The transferred bytes are the reviewed commit tree; no untracked or worktree content; extraction has no links or special files | Any test result by itself; a clean host; a real hotspot or polkit session | Commit, archive hash, destination, deletion | Wrong commit, committed secret, tar parser or same-user race |
| 2. Local Docker or Colima | Linux container behavior; Rust, Node, Xvfb, helper integration; `.deb` if a native amd64 24.04 image exists | Native amd64 on Apple Silicon; the 24.04 baseline on the existing Debian image; polkit; real desktop; hotspot | Docker use, image pulls, unconfined seccomp and setuid sandbox, resources | QEMU and architecture mismatch; Docker daemon is root-equivalent |
| 3. Boat Ubuntu sandbox | Native Ubuntu amd64 that reports 24.04; root and Docker; `.deb` and `dpkg-shlibdeps`; Xvfb; helper integration | A real hotspot, carrier, or physical device; a real polkit prompt unless separately tested | Cost, source upload, root commands, network, deletion | Public IPv4, remote trust, snapshot retention, nested Docker |
| 4. GitHub Actions | The existing `rust-linux` job on the pushed commit | Settings, a11y, `.deb`, `dpkg-shlibdeps`, helper integration, polkit, desktop, hotspot | Push and Actions use | Publishes the commit; cache and runner drift; does not cover the missing checks |

## Recommendation

Use option 1 as the source transfer, onto a disposable Boat Ubuntu `amd64`
sandbox that reports 24.04 in preflight, from option 3. Do not use the snapshot
verifier, the VM harness, `boat push`, or a recursive copy.

This is the smallest path that covers the whole evidence list:

- It avoids both verifier defects by construction. The archive is the commit
  tree, not a dirty-tree classification, and extraction is into a new empty
  directory, not the verifier's hard-link publication path.
- It gives native `amd64` and glibc 2.39 for `dpkg-shlibdeps`, without QEMU.
- It gives root and Docker for the opt-in helper integration.
- It gives Xvfb and a full Ubuntu userland for the Settings and accessibility
  checks.
- It is reviewable from a short list: commit, path list, archive SHA-256,
  extraction checks, command logs, and package control fields.

Option 2 is the fallback if the owner rejects a remote sandbox. Treat its
`amd64` package result as emulated evidence, not native `amd64` evidence.
Option 4 is a useful CI supplement after a push. It is not a substitute for
the missing Settings, accessibility, `.deb`, and helper integration checks.

## Run order for the recommended path

1. Resolve the commit and record `git status --porcelain=v1`.
2. Build the archive, record its path list and SHA-256, and review both.
3. Create the Boat sandbox with `--no-env --no-snapshots`.
4. Upload only the archive, the path list, and the checksum file.
5. Verify the SHA-256, extract as `user`, and run the link and file-list checks.
6. Run the Rust and helper unit tests, then the Node tests.
7. Run the Settings and accessibility checks under Xvfb.
8. Run the helper integration through Docker.
9. Build the `.deb` and record the control fields and `dpkg-shlibdeps` result.
10. Copy the logs and package metadata out, delete the sandbox, and confirm it
    is gone.

Capture each command's exit code and output. Do not rely on terminal
scrollback. A failed command stops the run; do not continue with a partial
result.

## Evidence record

Record the result in a new evidence file in a follow-up change, not in this
proposal. The record should include:

- The commit, branch, and `git status --porcelain=v1` output.
- The archive path, size, file count, SHA-256, and path-list SHA-256.
- The host: Boat sandbox ID or Docker image digest, OS, kernel, architecture,
  glibc, Node, npm, Rust, cargo, Electron, Xvfb, and dpkg versions.
- Each command, its exit code, and the SHA-256 of its log.
- Test counts: passed, failed, skipped, and the exact skipped test names.
- The accessibility JSON and the Settings window result.
- The `.deb` path, SHA-256, architecture, version, and `Depends` field.
- The helper integration marker output and the container cleanup result.
- The cleanup result: sandbox deleted, no containers, volumes, or temporary
  directories left.
- A limits section: no polkit prompt, no real desktop session, no real hotspot,
  no live tunnel.

The record is evidence for the named commit only. It is not a release artifact
and does not establish production readiness.

## Separate live tunnel test

This test is not part of the recommended evidence run. It needs a separate
owner approval, a disposable VM, and root inside that VM.

### What it proves

Inside the disposable VM, it exercises the Linux TUN device, the dedicated
routing table, the two policy rules, the direct-mode and source-device-proxy
flows, the IPv4 and IPv6 paths, the TTL audit of 65, the link-loss stop, the
SIGTERM cleanup, and the SIGKILL leftovers.

### What it cannot prove

- A real hotspot, carrier, or physical source device. The source device is a
  network namespace and a veth pair.
- A real polkit prompt or a real desktop authorization path.
- A trusted pass. The current `--tunnel` harness is diagnostic only, and the
  root test process can alter the status file it uses to report its own result.
  A future trusted result needs a separately reviewed result boundary and
  cleanup evidence.
- A host with no IPv6 source address cannot run the IPv6 scenario. Check
  `ip -6 addr` first.

### Exact commands

Use a fresh `CARGO_TARGET_DIR` so an older binary cannot be selected.

```sh
SRC=/path/to/extracted/hotspotshade-$COMMIT
cd "$SRC/rust"
export CARGO_TARGET_DIR="$(mktemp -d /tmp/hotspotshade-cargo.XXXXXXXX)"
cargo build --locked --test linux_tunnel_vm --bin hotspotshade

binary=$(find "$CARGO_TARGET_DIR/debug/deps" -maxdepth 1 -type f \
  -name 'linux_tunnel_vm-*' -perm -u+x)
test -n "$binary"
test "$(printf '%s\n' "$binary" | wc -l | tr -d ' ')" = 1

sudo -n -E env HS_DISPOSABLE_LINUX_VM=1 "$binary" \
  --ignored --test-threads=1 --nocapture \
  --skip linux_vm_mock_source --skip linux_vm_direct_echo
```

The opt-in is a consent marker, not proof that the host is disposable. Do not
set it on a host that carries traffic you need to keep.

Check cleanup after the run:

```sh
ip -br link
ip rule show
ip route show table 700
ip -6 route show table 700
ip netns list
```

The expected result is no `hs-tun`, `hs-host0`, or `hs-src0` link, no network
namespace, no policy rule at priority 17000 or 17001, and no route in table 700.
A pass requires the empty diff, not only the process exit code. Do not delete a
route or rule you cannot match to the recorded run. Manual cleanup needs the
owner's approval.

### Approval needed

The owner must approve:

- Creating the disposable VM and running it with root.
- The route, rule, TUN, namespace, and veth changes inside that VM.
- The live test itself and the cleanup review.

Do not run it on the Mac, on a shared host, or on any machine whose network
must be preserved.

### Risks

- A SIGKILL can leave policy rules and the IPv6 blackhole after the TUN is
  gone. The next start may recover them only if its ownership checks pass.
- A broken cleanup can disrupt the VM network. It must not reach the host.
- The test process can alter its own status file. Do not call the result a
  trusted pass.
- The test uses a mock source device, not a real hotspot or carrier.
- The test needs IPv6 for the IPv6 flow, and it needs a non-local outer
  destination for the pin check.

## What this proposal does not claim

- It does not claim that the current commit is ready to release.
- It does not claim that a Linux userspace test proves a live hotspot, a
  carrier, or a physical source device.
- It does not claim that the snapshot verifier or the VM harness is repaired.
- It does not claim that a Boat sandbox is a trusted execution environment or
  an independent attestation.
- It does not claim that a polkit prompt, a real desktop session, a tray, or
  desktop notifications have been tested.
