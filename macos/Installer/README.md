# macOS installer foundation (not installable)

This package builds one unsigned component package from signed artifacts that a
release builder supplies. It checks the inputs against the rules that the
protected helper applies at runtime. It installs nothing, runs no installation
script, uses no `sudo`, writes no system path, and changes no route or tunnel
device.

Status: **NOT INSTALLABLE AND NOT APPROVED FOR USE.** The generated `preinstall`
script refuses before it reads a process, a state marker, or a launchd job, and
before it can stop a helper or change anything. The package is a build and audit
artifact only. A sandbox-only coordinator core, a sandbox-only launchd and
authorization-right transaction, and fault-injection suites now exist, but the
repository does not yet have one reviewed lock name shared by the helper, the
Rust engine, and the coordinator. See `COORDINATOR.md`,
`SERVICE_TRANSACTION.md`, "Why this package must not be installed", and
"Required design before approval".

No real Developer ID signature, no signed package, no helper install, no live
start right write, no live launchd registration, no live coordinator run, and no
XPC connection has been verified. See "Blockers".

## What it does

`hotspotshade-installer-build stage|build` takes these inputs:

| Option | Input |
|---|---|
| `--helper` | Signed helper executable, identifier `dev.hotspotshade.mac.helper`. |
| `--engine` | Signed engine executable, identifier `dev.hotspotshade.engine`. |
| `--launch-daemon` | `macos/Helper/dev.hotspotshade.mac.helper.plist` or an equal file. |
| `--start-right` | `macos/Helper/dev.hotspotshade.tunnel.start.plist` or an equal file. |
| `--app` | Signed `HotspotShade.app`. It is checked for its team and is not packaged. |
| `--version` | One to three numeric fields, for example `0.1.0`. |
| `--output` | A new directory. It must not exist. |

Steps:

1. Refuse to run as root. Refuse an output path under a system directory, after
   symlinks resolve, or a path that already exists.
2. Read the team identifier from the app signature. This is the same source the
   helper uses. The team never comes from an argument, a plist, or the
   environment.
3. Copy each input into a private `0700` staging directory with `O_NOFOLLOW`
   and a size bound. Every later check reads the staged copy, so a supplied file
   that changes after the copy cannot pass a check and then differ in the
   package.
4. Check the architecture of the helper, the engine, and the app's main
   executable (`Contents/MacOS/<CFBundleExecutable>`). Each must be one thin
   arm64 Mach-O executable (`MachOPolicy`): ARM64_ALL subtype, `MH_EXECUTE`,
   well-formed load commands, and a code signature command that lies inside the
   file. A universal (fat) file is refused whole, even when its slices are
   signed, because the Security framework checks one slice by default. arm64e,
   x86_64, a dylib, and a script are refused. This check runs before the
   signature check.
5. Check each executable with the helper's own rules
   (`HelperRequirement.make`, `isProtectedIdentity`): the exact identifier, the
   app team, Developer ID, hardened runtime, and none of `get-task-allow`,
   `disable-library-validation`, or `allow-dyld-environment-variables`. The
   default checker (`StrictSecurityCodeSignatureChecker`) adds a second,
   strict pass over the same path: strict validation, every architecture, and
   nested code.
6. Check the launch daemon file with a stricter rule than the helper uses: a key
   allowlist, `RunAtLoad` and `KeepAlive` explicitly false, one Mach service,
   and `ProgramArguments` equal to the fixed helper path. Then apply
   `HelperLaunchDaemonPolicy`.
7. Check the start right plist: install-time keys only, then
   `HelperStartRightValidator.isSafe`.
8. Build the payload, the two scripts, and `manifest.json`. The manifest records
   `installationApproved: false` and carries the same refusal in its notes.
   Re-hash the payload and re-check the signatures.
9. `build` only: run `pkgbuild --ownership recommended`, then audit the finished
   package. The audit expands it with `pkgutil --expand-full` and compares the
   exact file set, the digests, the modes, the `root:wheel` ownership in the
   bill of materials, the scripts byte for byte, and the signatures and
   architecture of the extracted executables. It checks `PackageInfo` against
   an exact policy: the root attributes (identifier, version, install location,
   `auth=root`, `relocatable=false`, `overwrite-permissions=true`,
   `postinstall-action=none`, format version), the payload item count, exactly
   the `preinstall` and `postinstall` script entries, and empty bundle and
   relocation elements. Any other attribute or element fails. The package is
   hashed before and after the audit, and a change during the audit fails the
   build. A passing build writes `HotspotShade-<version>-unsigned.pkg.sha256`
   (one `shasum -a 256` line) beside the package. A failed build removes the
   output directory it created.

All destinations come from constants in `HotspotShadeKit` (`HelperRequirement`,
`RootEnginePaths`, `RootCleanupBlockStore`). A test pins them to the paths in
`macos/Helper/README.md`.

## Sandbox-only coordinator

`hotspotshade-installer-coordinator` implements the file transaction that a
future root coordinator needs. It is sandbox-only. It has no live mode, refuses
to run as root, and writes only under a marked private temporary root. The
details and the unresolved lock mismatch are in `COORDINATOR.md`.

What is implemented:

- One kernel-backed lock abstraction with descriptor checks and a
  cross-process test probe.
- A transition lock set covering `start.lock`, `start-exclusion`, and
  `upgrade.lock`. The helper and the Rust engine both use `start-exclusion`
  today, so the set contends with them, but it is not the approved single lock.
- A fixed install tree with `openat`, `O_NOFOLLOW`, owner, group, mode, link
  count, and access control list checks. Every installed file is set to the
  tree's expected owner and group, so the system preview writes `root:wheel`
  files instead of inheriting the process group.
- A clean host without `/Library/PrivilegedHelperTools` is supported: the
  coordinator checks `/Library` with create disabled, then creates only that
  standard directory `0755` and checks it through its descriptor. An existing
  directory is never changed, and an unsafe object at that name is refused.
- A durable install journal with `preparing`, `replacing`, and `committed`
  phases, per-file backups, atomic replacement, and idempotent recovery. A
  journal read requires mode `0600`, one link, no special bit, and no access
  control list. Before recovery acts on an observed journal it rewrites the
  exact observed bytes through the atomic seam and requires the file and parent
  sync. A namespace read-back is a consistency check, not a durability proof.
  A failure after the journal rename but before its directory sync is an
  unknown outcome: the coordinator stops, keeps the journal and every backup,
  and leaves the phase decision to recovery. A journal removal requires the
  exact observed digest and mode; a changed record is kept. An unlink whose
  parent sync fails is an unknown removal and stops the run before the next
  mutation. A cross-directory backup or restore rename syncs the gaining parent
  before the losing parent, so a crash between the two syncs can duplicate a
  name but cannot lose the file. A post-rename copy sync failure is reported as
  an unknown file outcome, not as a clean pre-rename failure.
- Signed artifact and digest revalidation of the staged payload.
- Crash injection after every replacement and cleanup step.
- A start journal probe that refuses while a helper start record may exist.
- A sandbox service transaction for the launch daemon and the start right, with
  fixed command shapes, injected runtimes, a durable service journal,
  read-back, rollback, and fault injection. It revalidates the installed helper
  and engine signatures when the caller supplies the expected team. It refuses
  a live runtime while `installationApproved` is false. A previous and an
  installed right may use the same policy; recovery uses the journal phase to
  decide whether that definition is previous or installed, refreshes the
  packaged right before `rightReplaced`, and never writes it from a rollback
  phase. See `SERVICE_TRANSACTION.md`.
- A first-install cleanup seam and a gated `preview-uninstall` command. It
  removes only the fixed file set, the launch daemon job, and the start right,
  with content, mode, team, and policy checks, an exclusion lease, and
  interruption and retry tests. See "First-install cleanup" below.

What is not implemented or not proven:

- One reviewed lock name shared by all binaries.
- Initial migration of old binaries that do not take any lock.
- Integration of the service transaction into `InstallCoordinator`. The file
  journal and the service journal do not yet have one reviewed ordering.
- A live root coordinator, live launch daemon bootout/bootstrap, or live
  authorization database write. The launch daemon read-back runs immediately
  after the command with no settle or retry, so live launchd timing is not
  proven. See `SERVICE_TRANSACTION.md`.
- A live preview removal. `preview-uninstall` has the same approval gate, and
  its tests use a sandbox tree and a fake runtime. See "First-install cleanup".
- Live contention tests with the real helper and the real Rust engine.
- A real Developer ID signature, notarization, or a real install.
- A real failed directory sync after a journal rename. The classification and
  the stop-and-keep behavior are covered with an injected sync failure only.
  The hermetic tests do not establish APFS power-loss behavior, and they do not
  prove that a real launchd or authorization database transaction survives a
  power cut.

## Install layout

The package install location is `/Library/Application Support/HotspotShade`, a
directory the package owns. The payload never lists `/Library`,
`/Library/Application Support`, or any other system directory, because
`pkgbuild` marks entries to overwrite permissions and an existing system
directory must keep its own owner, group, and mode.

| Payload path | Mode | Final place |
|---|---|---|
| `engine/hotspotshade` | 0755 | Same path. The root launcher looks here. |
| `install-support/dev.hotspotshade.mac.helper` | 0644 | Copied to `/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper` (0755) by the postinstall script. |
| `install-support/dev.hotspotshade.mac.helper.plist` | 0644 | Copied to `/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist` (0644). |
| `install-support/dev.hotspotshade.tunnel.start.plist` | 0644 | Read in place when the script writes the right. |

The package scripts are generated text from fixed constants. They hold no value
from an input.

- `preinstall` refuses with one fixed message before the first check or change:
  "this package is a build-only foundation and is not approved for
  installation." It does not read a state marker, run `pgrep`, read a launchd
  job, stop a helper, wait for a process, or remove anything. No argument,
  environment variable, or file selects another branch. Installer therefore
  stops before payload replacement.
- `postinstall` is future code that Installer cannot reach while the gate is
  fixed. It checks that `/Library`, `/Library/Application Support`, the
  install location, and its two payload directories are root-owned with no
  group or other write bit, no set-id bit, and no access control list. It
  checks the four payload files for `root:wheel`, one link, no access control
  list, and the exact mode. It creates a missing helper or launch daemon
  directory and refuses an existing one that fails the same directory check.
  It installs the helper and its launch daemon file with `install -S` and
  compares them to the packaged copies. It prepares `/var/lib/hotspotshade` and
  `/var/db/hotspotshade` as root `0700`: a missing one is created, an existing
  one must already be root-owned, and the result is read back. It writes the
  start right and reads it back. The key check is structured: the script
  checks the original XML for a duplicate direct key when the XML reader can
  parse it, converts the read-back to XML1, and asks `xmllint` for an XPath
  verdict over the parsed property list. It does not parse `plutil -p` lines.
  Every direct child key must equal a known name, so an empty key, a key with a
  line break, an unknown key, a duplicate XML key, and a merged definition that
  kept a `rule`, `mechanisms`, or other extra key all fail. The value checks
  then match the exact allowlist. An optional field is absent only when the XML
  reader and `plutil -type` agree that it is absent; a tool error or a
  disagreement refuses. A failed `plutil -extract` refuses before the sentinel
  can turn it into an empty value, and the sentinel plus one newline removal
  keeps a trailing newline in the value. A failed `tr` filter refuses instead
  of looking like a clean value. Then it registers the launch daemon with
  `launchctl bootstrap`. It never touches the cleanup state files, a route, an
  interface, or a process signal. Mode checks use integer arithmetic on the
  octal text, not character positions. An access control list is refused
  because the script does not interpret one. The `ls -lde` status is checked
  on its own, so a failed listing refuses, and any line after the header is an
  entry.

## First-install cleanup

`PreviewFirstInstallCleanup` is the removal seam for the fixed set that a
first-time preview install attempt may create. The `preview-uninstall` command
calls it through `PreviewSystemInstaller`. The same approval flag, root
requirement, and coordinator identity apply, so the command refuses today
before it opens a system path.

The preview has no live upgrade path: `preview-install` refuses an existing
file, an existing right, and an existing job. Both journals are removed when
that install commits, so the seam cannot read a durable ownership record. It
checks each object against the publisher and fixed layout instead; those checks
do not prove which install attempt created it:

- every present file must pass the same regular-file checks as the tree, carry
  the exact layout mode, and be one of the four fixed artifacts;
- the helper and the engine must carry the protected identity and the team of
  the running signed coordinator;
- the launch daemon file and the start right must pass the installer's plist
  checks;
- a stored start right must have the same policy as the installed right file,
  and a loaded job must name the fixed label, launch daemon path, and helper
  path.

It removes the launch daemon job, then the start right, then the present fixed
files. Each unlink is guarded by the digest and mode it validated. It removes
`HotspotShade`, `engine`, and `install-support` only when they are empty and
carry owner and mode `0755`. It never removes `/Library/PrivilegedHelperTools`,
the state directory, `/var/lib/hotspotshade`, a journal, a marker, a lock file, the installed app, or
the placed preview tree. A non-empty directory is kept and named in the report.

The seam refuses, with nothing removed, when a file journal, a service journal,
a cleanup block, a launch intent, a start journal, or an orphan backup is present, and when an
installed object, stored right, or loaded job is not the preview's. The
exclusion lease is the guard against an active tunnel: a participating helper
or engine holds a shared lock, so the cleanup cannot take its exclusive lock
and refuses. An old binary that takes no lock is not excluded.

A run that is interrupted after a step leaves only objects the next run can
identify again. Removing a file twice, a right twice, or a job twice is
idempotent, and a missing journal is normal after a successful install. A
cleanup that finds nothing to remove reports that and changes nothing.

Exact limits:

- launchd records no creator identity. A loaded job that names the fixed
  program, path, and label is treated as the preview's. That is the same limit
  the service transaction documents.
- authd metadata is not byte-compared. Only the reviewed policy fields must
  match the installed right file.
- The app installed into `/Applications` and the placed
  `/Library/Application Support/HotspotShade/local-preview` tree are outside
  this seam. A person removes those by hand.
- No live removal has run. `localPreviewInstallationApproved` remains false,
  and the tests use a sandbox tree and a fake runtime. They do not prove
  `launchctl bootout`, `security authorizationdb remove`, or live launchd
  timing.
- If a future live upgrade path is added, the "first install only" assumption
  no longer holds and this seam must be revisited before it can remove an
  upgraded set.

## Why this package must not be installed

An earlier draft checked for the cleanup and launch-intent markers, ran
`pgrep -x hotspotshade`, called `launchctl print`, stopped a loaded helper with
`bootout`, and checked again. Those checks are observations. They are not
mutual exclusion:

- A direct `sudo hotspotshade tun` start does not use launchd. `bootout` does
  not disable it. A start can happen before, during, or after any check.
- The helper-absent branch has no stop and no second check. Adding a second
  check there would still leave the same window after it.
- `preinstall` and `postinstall` are different processes. A lock held by
  `preinstall` ends before Installer replaces the payload and before
  `postinstall` runs.
- Installer can crash between the scripts. A marker, a process identifier, or
  a launchd print result then names no owner of the install transaction, and a
  stale marker either wedges a later start or invites an unsafe clear.

The payload replacement is the point that must not overlap a running helper or
engine. A check just before it is not enough: the start can occur after the
check and before or during the replacement. This package therefore refuses
before any observation and remains unapproved.

The sandbox coordinator now holds a kernel lock set for its whole transaction.
That does not make the package installable. The helper and the Rust engine agree
on `start-exclusion` in this checkout, but the coordinator's primary name is
still `start.lock`, and old binaries take no lock at all. The coordinator holds
`start.lock`, `start-exclusion`, and `upgrade.lock` exclusively, so a
participant that uses one of those names contends. A participant that uses
another name does not. The transition set, the start journal probe, and the
exact remaining gaps are in `COORDINATOR.md`. The sandbox launchd and
authorization-right boundary is in `SERVICE_TRANSACTION.md`; it is not called by
`InstallCoordinator`.

## Required design before approval

An approved install and upgrade needs all of the following. The sandbox core
implements some pieces, but none of the live prerequisites is complete.

1. **One reviewed kernel-backed exclusion.** The goal is one root-owned lock
   file under `/var/db/hotspotshade`, opened with `O_NOFOLLOW` and `O_CLOEXEC`,
   with ownership, mode, link count, and regular-file type checked through the
   descriptor. Every start participant takes `flock(LOCK_SH | LOCK_NB)` and the
   coordinator takes `flock(LOCK_EX | LOCK_NB)`. The kernel releases the lock
   when the owning process exits, including a crash. A marker, a pid file, a
   launchd job, `pgrep`, and a recheck are not a substitute. An expiring lease
   is also not enough. The sandbox coordinator implements the checks and the
   exclusive side. The repository does not yet have one name shared by every
   binary. The current transition set is not approval.

2. **Every start path holds the same lock.** Every engine process takes a
   shared lock (`LOCK_SH`) before any route or TUN change and holds it until
   route and device cleanup completes. That includes a helper-spawned engine,
   the direct `sudo hotspotshade tun` path, source device proxy mode, and any
   root engine start from a GUI. The helper also takes a shared lock before it
   asks its launcher to spawn and keeps it until that session's engine is
   stopped, so the spawn window is covered. A failed or held lock is a start
   failure, not a warning. The helper alone is not enough, because the direct
   command line path does not use it.

3. **One coordinator holds the exclusive lock for the whole transaction.**
   The coordinator is a root-owned executable, not a `preinstall`/`postinstall`
   pair. It first boots out the helper without the lock, then acquires the
   exclusive lock. If a helper or engine start won the race, its shared lock
   makes the exclusive acquisition fail, and the coordinator refuses or
   retries the stop. While holding the exclusive lock it checks the cleanup
   marker, launch intent, and start journal, waits for every engine to exit, and
   only then replaces files. Each file replacement uses a temporary file in the
   destination directory and one atomic rename; the helper and launch daemon
   are not visible in a partial state. It then writes and reads back the start
   right, bootstraps the helper, and releases the lock. A crash releases the
   kernel lock; the next start validates the installed signatures and fails
   closed on an incomplete set. The coordinator must be the only supported
   install entry point, because Installer can run the package directly.
   `Coordinator.swift` implements the lock, journal, replacement, and recovery
   in a sandbox. `PrivilegedServiceTransaction.swift` implements the bootout,
   bootstrap, and authorization write with injected runtimes and a service
   journal, also in a sandbox. `InstallCoordinator` does not call it, and the
   ordering between the two journals is not reviewed.

4. **Tests that prove exclusion, not just observation.** Hermetic contention
   tests for every lock taker, a crash-injection test that kills the
   coordinator between each replacement step, and a disposable VM test that
   attempts a helper start and a direct command line start while the exclusive
   lock is held. The VM test must also attempt the upgrade with a live helper
   and no helper, and must verify that no route or device is owned after each
   failure. The sandbox package has cross-process contention tests with a
   compiled probe and crash injection at every step. No live VM test with the
   real helper or engine has run.

This package remains refused until those pieces exist, the owners converge on
one lock, and an independent review accepts the implementation.

## Build and test

```sh
swift build --package-path macos/Installer
swift test --package-path macos/Installer
swift test --package-path macos/Installer --filter InstallLockTests
swift test --package-path macos/Installer --filter CoordinatorInstallTests
swift test --package-path macos/Installer --filter ServiceTransactionTests
swift test --package-path macos/Installer --filter ServiceCommandTests
swift test --package-path macos/Installer --filter ServiceJournalTests
mkdir -m 700 "$TMPDIR/example-sandbox"
swift run --package-path macos/Installer hotspotshade-installer-coordinator sandbox-init \
  --sandbox-root "$TMPDIR/example-sandbox"
```

The coordinator command has no live mode. Every sandbox root needs the fixed
marker file and private ownership. The command refuses to run as root.

The service tests use a fake runtime with the fixed paths and command shapes.
They never run `launchctl`, `security authorizationdb`, or a child process for
the service transaction. The live command runner is compiled but gated by
`installationApproved == false`; a test asserts that it refuses before spawn.
The service journal tests prove the phase, backup, fixed-name, and digest
checks. They do not prove live launchd or authd behavior. See
`SERVICE_TRANSACTION.md`.

Tests need no signing identity. They use a fake signature checker to show how
the installer reacts to each signing fact, and the real Security checker on
thin arm64 files that the test builds with `clang` and signs ad-hoc or leaves
unsigned, to show that it fails closed. They build real universal files with
`lipo` to show that a mixed fat file is refused before the signature check.
They also use the repository templates, the kit's malicious right fixtures,
and `sh -n` on the scripts. The real `pkgbuild`, `pkgutil`, and `lsbom` run on
a package of fake artifacts in a temporary directory, including packages with a
wrong owner, wrong modes, a symlink, and a missing file. Crafted bill of
materials listings and crafted `PackageInfo` files cover the cases that no real
tool run produces. Tests for a failed build check that no output directory
remains.

The tests never run a script against a system path and never run as root. They
run three kinds of shell text with `/bin/sh`: the pure mode, access control
list, and start right functions, which the tests compare to
`HelperStartRightValidator` on a table of definitions (the shell check must
never accept what the helper validator refuses); the generated `preinstall`
script, which must refuse before it touches a process, marker, or launchd job;
and `sh -n` on both scripts. The right table includes an empty key, a key with
a line break, a key that impersonates a quoted key line, unknown keys, and the
helper's accepted metadata shape. Raw XML fixtures cover duplicate keys, a
nested dictionary inside a known field, and malformed nested XML; the helper
comparison runs on each one. Hermetic stubs replace one tool path at a time to
prove that a failed `ls`, `plutil -type`, `plutil -extract`, `xmllint`, or
`tr`, and a disagreement between the XML reader and `plutil`, refuse instead
of looking like absence or a clean value. The postinstall flow as a whole has
no hermetic test, because it writes system paths and the authorization
database. Package and compiler tests skip when a tool is missing. Tests write
only under the temporary directory and `.build`.

The structured key check needs `/usr/bin/xmllint`. It is part of macOS on the
test host. If it is missing, or if it reports anything other than `true`, the
postinstall script refuses. The `--nonet` flag stops a plist doctype from
fetching an external file.

A real build still needs release inputs. It produces an audit artifact, not an
installable package:

```sh
swift run --package-path macos/Installer hotspotshade-installer-build build \
  --helper PATH --engine PATH \
  --launch-daemon macos/Helper/dev.hotspotshade.mac.helper.plist \
  --start-right macos/Helper/dev.hotspotshade.tunnel.start.plist \
  --app PATH/HotspotShade.app --version 0.1.0 --output build/installer
```

Without a Developer ID signed app the tool stops with "The app does not carry a
protected Developer ID identity" and creates no output. That is the expected
result in this repository.

## Blockers and unverified claims

1. **No single reviewed lock name.** The helper and the Rust engine both use
   `start-exclusion` in this checkout. The sandbox coordinator's primary name is
   still `start.lock`, and its transition set holds `start.lock`,
   `start-exclusion`, and `upgrade.lock` exclusively, so a participant that
   uses `start-exclusion` contends today. It is still not one shared lock. Old
   binaries take no lock, and a fourth name would bypass the set. The source
   guard in the tests fails if the helper or engine names a lock outside the
   set, but it is not proof of live exclusion. The package is not installable
   for this reason. See `COORDINATOR.md`.
2. **No Developer ID.** No certificate exists here. The real signature path has
   run only against ad-hoc and unsigned files, where it refuses. A valid
   Developer ID chain is unverified. The check is static: it does not check
   revocation, notarization, or a stapled ticket.
3. **The package is unsigned.** A package with scripts needs a Developer ID
   Installer certificate, which is separate from the Application certificate,
   plus notarization. `productsign` and `notarytool` are not part of this
   package. The manifest records `packageSigned: false`.
4. **No install has run, and the package refuses one.** The generated
   `preinstall` script has run only as a normal user in the tests, where it
   exits 1 before any other action. The `postinstall` flow is future code that
   Installer cannot reach while the gate is fixed. Its behavior as root is
   unverified, including `install -S`, `launchctl bootstrap`, the `stat` and
   `ls -lde` output formats on other macOS versions, and the structured
   `plutil`/`xmllint` read-back. The gate also means no payload replacement,
   helper stop, or upgrade behavior has been exercised.
5. **`authorizationdb` read-back.** `macos/Helper/README.md` asks for a test
   host check that the write replaces a pre-existing definition. The script
   reads the stored right back and applies an exact allowlist, so a merged
   definition that keeps an extra key fails. The key list is a structured
   XPath check over the parsed XML property list, not a line parse of
   `plutil -p`; empty, newline, unknown, and duplicate keys are refused, and
   the tests compare it with `HelperStartRightValidator` on a hostile table.
   Optional fields are absent only when the XML reader and `plutil -type`
   agree; a tool error or a reader disagreement refuses. It is still a shell
   restatement, not the same code, and the helper's own validator stays the
   full check at helper startup and before every start. A failed read-back
   leaves the written right in place and the helper unregistered; the script
   never removes a right. Whether `authorizationdb write` replaces or merges on
   a real host is unverified. The `xmllint` behavior on the minimum supported
   macOS version is also unverified; a missing tool refuses the install.
6. **Installer overwrite behavior.** The package install location is the
   directory the package owns, so the payload lists no system directory. How
   Installer treats an existing `HotspotShade` directory with other permissions
   is unverified.
7. **The uninstaller is a gated foundation, not a live tool.** The helper and
   launch daemon file are copied outside the package install location, so a
   package receipt does not own them. `preview-uninstall` implements the
   first-install cleanup seam: it stops the job, removes the right, and removes
   only the four fixed files and the empty install directories. It refuses an
   unfinished transaction, a participant record, a foreign object, and a held
   exclusion lock, and it is retryable after an interruption. The approval gate
   is still false, so no live removal has run. `launchctl bootout`,
   `security authorizationdb remove`, live launchd timing, and the loaded-job
   creator limit are unverified. The seam also assumes no live upgrade path
   exists; adding one invalidates that assumption. The installed app and the
   placed preview tree are removed by hand.
8. **Thin arm64 only.** The helper, the engine, and the app's main executable
   must each be one thin arm64 file. This follows the arm64-only release app. A
   universal release, an arm64e build, or a second architecture needs a policy
   change and an all-slice signature check on a real Developer ID signed file.
   Only the app's main executable is checked for architecture; nested code in
   the app is covered by the strict signature pass only. The strict pass
   (`StrictSecurityCodeSignatureChecker`) has run only against ad-hoc and
   unsigned files, where it refuses.
   `pkgbuild` and `pkgutil` output formats (the `PackageInfo` attributes and
   elements) were checked on one macOS version. A different Xcode release that
   adds an attribute or element fails the audit until the policy lists it.
   ACL and mode checks use `ls -lde` and `stat -f`; a host with an access
   control list on `/Library` would refuse the future postinstall flow.
9. **Live XPC and the audit-token accessors** remain unverified on a signed host
   (see `macos/Helper/README.md`, Production gaps 3 and 4).
10. **CI.** The working-tree macOS job runs the installer tests in normal and
    local-preview modes and the preview preparation fixtures. The signed
    artifact test still needs a local signing identity, and this workflow change
    has not yet run on GitHub Actions.
11. **Service transaction integration and live evidence.** `InstallCoordinator`
    calls the sandbox service transaction during first install and resume. The file
    journal and service journal have no reviewed ordering. Live
    `security authorizationdb` and `launchctl` behavior, a power loss, and the
    ambiguous bootstrap window need a disposable VM with root and a signed set.
    See `SERVICE_TRANSACTION.md`.
12. **Independent review.** Review f04ca3e4 found blockers in an earlier pass.
    A later pass refused installation, documents the required lock design,
    replaced the right read-back parser, and added hostile key tests. This pass
    checks the `ls` status directly in the access control list check, refuses a
    failed or ambiguous `plutil -type` instead of treating it as absence,
    refuses a failed `plutil -extract` before the sentinel can hide it, fixes
    the newline removal, checks the `tr` status, and adds hermetic failure,
    duplicate key, nested XML, and parser disagreement fixtures. It also adds
    the sandbox-only coordinator, the transition lock set, the install journal,
    the start journal probe, the sandbox service transaction, the service
    journal, and fault-injection tests. A later pass makes same-policy previous
    and installed rights phase-aware, adds the production read-back and absence
    probe tests, and records the live launchd timing limits. The package is
    still not installable. These repairs and the new boundary have not had
    their own independent review.
