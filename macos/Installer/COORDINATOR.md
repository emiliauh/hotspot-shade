# Install coordinator contract (system preview disabled, not approved)

The internal `installFirstTime` path runs the file transaction and the service
transaction under one lease. The tested path uses a marked sandbox and a fake
service runtime. A system preview entry point is present but disabled by
`localPreviewInstallationApproved`; it has not been run against the system.
The first-install path refuses existing destination files and a pre-existing
right or job. The transactions
are still separate: after the file commit, a service failure can leave the files
in place. The sandbox `resumeFirstTime` path can retry service setup when the
service has rolled back, both journals are absent, and all four installed files
match a newly validated payload. A crash just after bootstrap can leave a loaded job whose ownership
cannot be established; recovery keeps the service journal and requires
inspection. The disabled system command cannot yet install on the Mac.
The disabled preview system command has separate file-recovery,
service-recovery, status, and first-install cleanup operations; these do not
require the original app or staged payload. Recovery uses the signed
coordinator's own team. The status operation reports journals and markers, but
does not prove that a launchd job is running or that a tunnel has stopped. The
cleanup operation checks the fixed set a first-install attempt may leave;
it is implemented and hermetically tested, but the same closed gate refuses it.

Before either transaction, the path copies the four supplied payload files to
a private workspace owned by the installer, and checks the copied files against
the manifest and signing requirements. It removes the copy after the attempt.
An abrupt process exit can leave the private workspace behind; recovery and
cleanup of that residue still need integration before a live installer is used.
The sandbox transaction seam still accepts a team from its caller. The signed
coordinator's `verify-preview` command instead checks its own running signature,
derives the team, and requires both the signed app and manifest to match it.
A future live entry point must use that binding before it invokes either
transaction.

To exercise the path with a staged local preview and its actual signatures, set
`HS_MAC_STAGED_PREVIEW` to the absolute path of its `staged` directory, then run
`swift test --package-path macos/Installer -Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW --filter CoordinatorInstallTests.testCombinedFirstInstallWithSignedPreviewArtifacts`.
The test installs and removes the signed files in a sandbox with both the
ordinary and mapped `/var` layouts. The service runtime remains a
fake, so this check does not run launchd or modify the authorization database.
On 2026-11-06, a signed local-preview coordinator also passed `self-check`
as root from a temporary root-owned copy. Both temporary copies were removed.
This checked only its running signature; it did not install or start a service.

The ordinary build and the ordinary local-preview build keep the system
entry points disabled. A separate test candidate can be built with both
`-Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW` and
`-Xswiftc -DHOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE`. That combination enables
the root-only local-preview entry points in that binary. The release installer
and package remain disabled. The candidate has not been tested on a live
system and is not a ready-to-install product.

Status: **NOT READY FOR INSTALLATION.** The generated package `preinstall`
still refuses before any check or change, and `installationApproved` is false.
The ordinary build disables live preview commands; the explicit candidate above
enables them for future testing only. Sandbox tests
never write a system path, call `launchctl`, write the authorization database,
change a route or a TUN device, or signal a system process. The read-only
`self-check` can run as root to verify a signed coordinator.

This document records what is implemented, the exact lock mismatch that still
blocks approval, and the contract every participant must meet before the gate
can change.

## Implemented in `macos/Installer`

| Piece | File | What it does |
|---|---|---|
| Lock | `InstallLock.swift` | Opens a root-owned or sandbox-owned lock file with `O_NOFOLLOW`, validates type, owner, link count, mode, and access control list through the descriptor, takes a nonblocking `flock`, and rechecks the path inode. |
| Lock set | `InstallLock.swift` | `InstallExclusionLease` holds an exclusive lock on every name in `InstallLockLayout.heldFileNames` in sorted order and releases in reverse order. |
| Safe tree | `InstallTree.swift` | Opens one target root, walks every child with `openat(O_NOFOLLOW)`, rejects `..`, absolute paths, symlinks, hard links, wrong owners, wrong groups, group or other permissions, and access control lists. Every file it writes is set to the expected owner and group, and every file it verifies must carry that group. |
| Journal | `InstallJournal.swift` | A bounded, owner-checked JSON record. A read requires mode `0600`, one link, and no special bit. The destination set is fixed. A backup path is derived from the transaction id and index, never read from the journal. A write is classified as clean only when the rename did not happen; a post-rename directory-sync failure is an unknown outcome. Recovery confirms the exact observed bytes durably before it acts, and removal requires the same digest and mode. |
| Start journal probe | `StartJournal.swift` | Reads a `start-journal` refusal record when one exists and compares its recorded lock device and inode with the held lock set. The record requires mode `0600`, one link, and no special bit. The current helper writes `engine-session` instead; the coordinator refuses both. |
| Coordinator | `Coordinator.swift` | Sandbox-only install, upgrade, status, and recovery state machine. |
| Service command seam | `PrivilegedServiceCommand.swift` | Six fixed launchd and authorization-right command shapes, plus a real runner that refuses while the approval gate is false. |
| Start-right store | `AuthorizationRightDatabase.swift` | Read, write, remove, and an explicit absence probe for the fixed start right. |
| Launchd controller | `LaunchdJobController.swift` | Print, bootout, and bootstrap with an exact read-back parser. |
| Service journal | `ServiceJournal.swift` | Durable launchd and authorization-right journal with a bounded previous-right backup. |
| Service transaction | `PrivilegedServiceTransaction.swift` | Apply and recover state machine with rollback, crash injection, and exact ambiguity refusals. |
| First-install cleanup | `PreviewFirstInstallCleanup.swift` | Checks the fixed files, launch daemon job, and start right against the publisher and layout before removal. It holds the exclusion lease; these checks do not prove which transaction created an object. |
| Command | `hotspotshade-installer-coordinator` | `sandbox-init`, `verify`, `install`, `recover`, `status`, and the disabled preview system commands. Every sandbox command refuses to run as root. |
| Tests | `Tests/HotspotShadeInstallerCoreTests` | Lock validation, cross-process contention, crash injection at every install step, recovery idempotence, journal and payload refusals, start journal compatibility, service command and service transaction fault tests, and source-name guards. |

The install target set is fixed by `InstallerLayout`:

| Role | Installed path | Owner:group | Mode |
|---|---|---|---|
| Engine | `/Library/Application Support/HotspotShade/engine/hotspotshade` | `root:wheel` | `0755` |
| Helper | `/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper` | `root:wheel` | `0755` |
| Launch daemon file | `/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist` | `root:wheel` | `0644` |
| Start right source | `/Library/Application Support/HotspotShade/install-support/dev.hotspotshade.tunnel.start.plist` | `root:wheel` | `0644` |

The system preview tree expects owner and group `0`. The sandbox tree expects
the installer's own effective user and group. `InstallTree` sets both on every
file it writes with `fchown` before `fchmod`, and `snapshot` refuses a file whose
group differs. This matters because the helper trust check refuses a helper, an
engine, or a launch daemon file whose group is not wheel. Resume and upgrade
verification use the same snapshot check, so an installed file with an
incompatible group is reported as a mismatch or an unsafe existing file, never
as a successful resume.

### Clean host without the helper directory

A clean macOS host has `/Library`, `/Library/Application Support`, and
`/Library/LaunchDaemons`, but it can lack `/Library/PrivilegedHelperTools`. The
package postinstall already creates that directory when it is absent. The
coordinator does the same:

- It first checks `/Library` with create disabled. A missing or unsafe parent
  fails closed; the coordinator never walks above the fixed layout.
- It creates only `/Library/PrivilegedHelperTools`, mode `0755`, through the
  safe tree, so the new directory is checked through its descriptor.
- An existing helper directory is checked and never changed.
- The created helper directory is not recorded in the install journal, so a
  rolled-back first install can leave it empty. This matches the package
  postinstall, which also leaves the standard directory in place.

The coordinator does not write the authorization database and does not
bootstrap the launch daemon. `PrivilegedServiceTransaction.swift` now implements
that boundary with injected runtimes, a durable service journal, read-back, and
rollback, but it is not called by `InstallCoordinator` and has no live mode. Its
exact rollback limits and the missing root integration are in
`SERVICE_TRANSACTION.md`.

## First-install cleanup

`PreviewFirstInstallCleanup` removes the fixed set that one successful
`installFirstTime` left. The system entry point `preview-uninstall` uses the
same closed approval gate, the root requirement, the coordinator's own signing
team, and the same `root:wheel` tree at `/`.

The seam has no durable ownership record to read: the file and service journals
are removed on a successful commit. It identifies each object instead:

- every present file must pass the tree's regular-file checks, carry the exact
  layout mode, and be one of the four fixed artifacts;
- the helper and the engine must carry the protected identity and the
  coordinator's team;
- the launch daemon file and the start right must pass the installer's plist
  checks;
- a stored right must have the same policy as the installed right file, and a
  loaded job must name the fixed label, path, and helper.

It removes the job, then the right, then the present files. Every unlink is
guarded by the validated digest and mode. It removes `HotspotShade`, `engine`,
and `install-support` only when they are empty and `0755`. It keeps the state
directory, its journals, markers, and lock files, the standard
`/Library/PrivilegedHelperTools` directory, the installed app, and the placed
preview tree.

It refuses, with nothing removed, while a file journal, a service journal, a
cleanup block, a launch intent, or a start journal is present, and when an
installed object, stored right, or loaded job is foreign. The exclusion lease
is the guard against an active tunnel: a participating helper or engine holds a
shared lock. An old binary that takes no lock is not excluded.

The assumption is "first install only". `preview-install` refuses an existing
file, an existing right, and an existing job, and there is no live upgrade
path. A future upgrade path invalidates this assumption. launchd records no
creator identity, so a loaded job with the fixed fields is treated as the
preview's. authd metadata is not byte-compared. No live removal has run.

## Current lock mismatch

The repository is mid-migration. At the time of this writing:

| Participant | Lock name in source | Journal | Handoff |
|---|---|---|---|
| Swift helper | `start-exclusion` | `engine-session` launch intent; it does not write `start-journal` | Descriptor `5`, environment variables, device and inode |
| Rust engine | `start-exclusion` | none of its own; it refuses `start-journal`, `engine-session`, and `cleanup-blocked` | Validates helper descriptor `5` against its own lock |
| Installer coordinator | Holds `start.lock`, `start-exclusion`, and `upgrade.lock` exclusively | `install-journal.json` | None |

The helper and the Rust engine agree on `start-exclusion`. The coordinator's
primary name is still `start.lock`, but its transition set contains
`start-exclusion`, so it contends with the current helper and engine today. That
is a transition set, not the approved final design. The `upgrade.lock` name
comes from an independent review note and no current binary uses it. The
`start-journal` name is a conservative refusal record in the Rust engine and in
`StartJournalProbe`; the current helper source writes `engine-session` instead.

The coordinator therefore holds a **transition lock set** for the whole
transaction. This is not a single reviewed lock and must not be described as
complete exclusion:

- A helper or engine that uses any held name contends with the coordinator.
- A process that uses a fourth name does not.
- A build that predates every one of these locks does not participate.
- The same-process `flock` behavior on Darwin does not show contention, so the
  tests use a separately compiled process. A same-process test would pass
  without proving anything.

The source guard in `StartJournalTests` reads the helper and Rust lock-name
constants and fails if either names a lock outside `heldFileNames`. That guard
does not prove interoperability. It only fails closed when the names drift
again.

## Required final participant contract

The lead and the owners of the helper and the Rust engine must choose one name.
This build uses `start.lock` as the primary label only because that was the
installer's existing name. It is not a decision. If the owners choose
`start-exclusion` or another name, update `InstallLockLayout.fileName`, remove
the transition set, and update the source guard. Every program must use that one
name.

### Every start participant

1. Open the single root-owned lock file under `/var/db/hotspotshade` with
   `O_RDWR` or `O_RDONLY`, `O_NOFOLLOW`, and `O_CLOEXEC`.
2. Validate one regular file, owner `root`, one link, no group or other
   permission, no set-uid, set-gid, or sticky bit, and no access control list
   through the descriptor.
3. Take `flock(fd, LOCK_SH | LOCK_NB)`. A busy lock is a start failure. Do not
   retry in a loop that can overlap an install.
4. Recheck that the path still names the locked inode. A replaced path is a
   start failure.
5. Hold the shared lock from before the first route or TUN change until route
   and device cleanup completes. Do not drop it after reading configuration.
6. Never remove, rename, truncate, or replace the lock file.

### Helper

The current helper source writes `engine-session` as its write-ahead launch
intent and does not write a separate `start-journal`. The steps below describe
the second record that `StartJournalProbe` and the Rust engine already refuse.
If the owners keep one record, the same protocol version, session, lock device,
lock inode, and handoff descriptor belong in `engine-session`. The coordinator
refuses either record and never removes one.

1. Take its own shared lock before writing the start journal and before the
   privilege prompt's start action.
2. Write `start-journal` with the protocol version, session UUID, lock device,
   lock inode, and handoff descriptor. Sync the file and the directory.
3. Duplicate the locked descriptor to descriptor `5` for the child. Set exactly
   these values in the child environment:
   - `HOTSPOTSHADE_START_EXCLUSION_FD=5`
   - `HOTSPOTSHADE_START_EXCLUSION_VERSION=1`
   - `HOTSPOTSHADE_START_EXCLUSION_DEVICE=<device>`
   - `HOTSPOTSHADE_START_EXCLUSION_INODE=<inode>`
4. Keep the helper's own descriptor until the engine stops and cleanup is
   complete. A clean stop removes the journal. An unclean stop keeps the journal
   and the lock until the helper exits.
5. Never call `LOCK_UN` on a duplicated descriptor. On Darwin, unlock from one
   duplicate releases the lock for every duplicate. Close the descriptor or
   exit.

### Rust engine

1. If descriptor `5` and the handoff variables are present, validate all four
   values. A partial handoff is a start failure.
2. Check that descriptor `5` is the same device and inode as the lock file that
   the engine opens and checks itself. Never trust the environment alone.
3. Keep the inherited descriptor open until route and device cleanup completes.
   Never call `LOCK_UN` on it. Do not close it early.
4. Direct mode and any start without the helper must open the same lock file and
   take its own shared lock before the first route or TUN change.
5. Hold the shared lock in the tunnel state guard, not in a temporary scope.
   Drop it only after the worker has removed every route and device.
6. A failed cleanup keeps the shared lock until process exit, so the coordinator
   cannot take the exclusive lock while routes may remain.

### Install coordinator

1. Take an exclusive nonblocking lock on the approved name set before reading
   the install journal or changing a file. The final design has one name; the
   current sandbox design holds the transition set.
2. Refuse a present start journal, cleanup marker, launch intent, or install
   journal. Refuse a start-journal inode that is outside the held set.
3. Hold the exclusive lock through payload validation, backup moves, file
   replacement, journal commit, backup removal, and journal removal.
4. Release only after the final `fsync` and journal removal. A crash releases
   the kernel lock; the next process must recover from the journal.
5. Never remove the start journal, cleanup marker, or launch intent. Those
   records belong to the helper and to a person following the recovery steps.

## Install journal and crash recovery

The install journal is `install-journal.json` under the state directory, mode
`0600`, owned by the target root owner.

- Schema version `1`.
- Exactly the four fixed destinations.
- New digest, new size, new mode, and previous presence, digest, size, and mode.
- Created directory list limited to the install root, its two subdirectories,
  the backup root, and the transaction backup directory.
- No path, backup name, process id, port, secret, token, or address from an
  input is trusted.

Phases:

| Phase | Durable meaning | Recovery action |
|---|---|---|
| `preparing` | No file has been moved. The directory plan and previous records are durable. | Restore nothing, remove only objects the journal names, remove empty created directories, remove the journal. |
| `replacing` | A previous file may be in the backup directory and a new file may be in place. | Restore each previous file from its backup, or remove a new file when no previous file existed. Remove temporary files, verify the previous set, remove created directories, remove the journal. |
| `committed` | Every new file was verified and the commit record is durable. | Verify the new set again. If it verifies, remove backups and the journal. If it does not verify, keep the journal and backups and report the damage. |

Crash windows:

- Before the journal exists: no install file changed.
- After `preparing` before any backup: recovery removes the journal and any
  empty directories.
- After a backup move before the new file: recovery restores the backup.
- After the temporary file before the rename: recovery removes the temporary
  file and restores the backup.
- After the rename before the next record: recovery restores the backup over
  the new file.
- After the last verify before the commit write: recovery rolls back.
- After the commit write: recovery finishes forward and never rolls back.
- After a journal write whose directory sync failed: the visible record may be
  the old phase or the new phase, and a crash may keep either, or leave a
  damaged record. The coordinator stops at once, keeps the journal and every
  backup, and leaves the decision to recovery.
- After backups are removed before the journal is removed: recovery sees
  `committed`, verifies the new set, and removes the journal.
- After the journal is removed: nothing remains to recover.

### Journal write contract

The journal is the record that decides whether recovery rolls forward or back,
so a failed write cannot be treated as an ordinary file error. `InstallTree`
classifies the write by the step that failed.

- A failure before `renameat` is a clean failure. The temporary file is
  removed, the destination name is untouched, and the previous record is still
  authoritative. That includes a write, `fchmod`, or temporary-file `fsync`
  failure, and a `renameat` that returns an error: POSIX rename is one atomic
  operation, so a reported failure leaves the destination name in place.
- A `renameat` that succeeds followed by a failed directory `fsync` is an
  unknown outcome. The new bytes are visible at the journal name, but the
  directory entry may not survive a crash. `InstallTree` reports
  `.writeUncertain`, the journal store reports `journalWriteUncertain`, and the
  coordinator performs no further file change.
- A read-back after a failed directory sync is not used to classify the write.
  It shows the current namespace, not whether the entry is durable. Only
  recovery, which reads the record it finds, may decide the phase.
- Before recovery acts on an observed record it durably confirms that exact
  record. It rewrites the same bytes through the atomic seam, requires the file
  and parent sync to succeed, and reads the bytes back. The sync success is the
  durability claim; the read-back only checks that the current namespace still
  matches. A failed or unknown confirmation stops the run before the first
  mutation. That is why a visible `committed` record cannot remove a backup
  before the phase is durable.
- A journal removal requires the exact digest and mode that the decision
  observed, through a no-follow descriptor, with one link and no access control
  list. A changed record is kept. An unlink whose parent sync fails is an
  unknown removal and stops the run before the next mutation.
- The contract applies to every phase write: `preparing`, `replacing`, and
  `committed`. In particular, the coordinator does not set an in-memory
  `committed` flag and then roll back with the old `replacing` phase when the
  commit write outcome is unknown. A committed journal over restored files
  would block recovery.
- A clean pre-rename failure of the `replacing` write rolls back inline under
  the still-authoritative `preparing` record. A clean pre-rename failure of the
  `committed` write rolls back under the durable `replacing` record.
- A recovery also reads the journal with the exact `0600` mode. A journal with a
  group or other permission, a different mode, an access control list, a
  symlink, a hard link, or another owner is refused and left in place.
- A cross-directory backup move or restore makes the gaining parent durable
  before the losing parent. A crash between the two syncs can leave the file
  under both names, which recovery resolves, but cannot leave it under neither
  name.
- A copy whose rename succeeded and whose parent sync failed is an unknown file
  outcome, not a clean pre-rename failure. The install stops before the next
  file mutation, keeps the journal and backups, and leaves the re-observation
  to recovery.

The start journal probe also requires mode `0600`, one link, no special bit, and
no access control list. A `0644`, `0400`, set-id, or hard-linked start journal is
refused as unreadable and kept.

Recovery is idempotent. A second crash during recovery leaves the journal and
the same recoverable state. Recovery refuses a damaged committed set, an
unreadable journal, an orphan backup directory without a journal, and a start
journal. It never deletes a backup that no journal names.

### Rollback destination guard

Recovery restores a previous file only when the destination is absent or holds
exactly the file this transaction installed. It compares the destination
digest, size, and mode with the journal record, refuses an object that is
neither, and rechecks the destination immediately before the restoring rename.
A host object with the same owner and a safe mode is never overwritten. The
journal and the backup stay for a person to inspect. Darwin has no whole-file
compare-and-rename, so this guard narrows the window; it cannot close a race
with an uncooperative root writer.

## Safety boundaries

- Sandbox root only. The root must be an absolute, marked, private directory
  under the user's temporary directory. The marker content and mode are fixed.
- Never run as root. Effective user id `0` is refused before a path is opened.
- No system path is written in this build.
- Every path is relative and component-checked. File operations use `openat`
  against held directory descriptors and `O_NOFOLLOW`.
- The generic tree file check requires a regular file owned by the expected
  account and group, one link, no group or other write bit, and no access
  control list. It does not itself reject every group or other read or execute
  bit, or every special bit. Callers apply their own exact mode checks where
  required. Lock files have the stricter special-bit and permission checks
  described above.
- Every file the tree writes is set to the expected owner and group with
  `fchown` before its mode is applied. A failed `fchown` is a clean pre-rename
  failure: the temporary file is removed and the destination is untouched. The
  system preview expects `root:wheel`; a sandbox tree expects the installer's
  own effective user and group.
- A host without `/Library/PrivilegedHelperTools` is supported. The coordinator
  creates that one standard directory after it has checked `/Library` with
  create disabled. A host without `/Library`, `/Library/Application Support`,
  `/Library/LaunchDaemons`, `/var`, or `/var/db` fails closed and nothing is
  created.
- The staged payload must be the exact tree. No extra file, symlink, hard link,
  or special object.
- Payload digests and sizes are rechecked while copying. The copy is synced and
  renamed atomically.
- The helper and engine signatures are checked with the helper's own
  requirement builder. The launch daemon file and start right use the helper
  validators.
- The package preinstall refusal and `installationApproved: false` remain.

## Hermetic tests

The tests never run as root, never use a system path, and never create a route,
TUN device, launchd job, or authorization entry. They cover:

- Path, owner, mode, link count, symlink, directory, and access control list
  refusals for the lock files and install tree.
- Cross-process shared and exclusive contention on every held lock name with a
  compiled probe, plus release when the holder exits or is terminated.
- Install and upgrade with exact file bytes and modes.
- Installed file owner and group: every installed file carries the tree's
  expected group, an upgrade refuses an existing file with another group, a
  resume refuses an installed file with another group instead of reporting
  success, and committed recovery reports damage and keeps the journal.
- A clean host without `/Library/PrivilegedHelperTools`: the first install
  creates it `0755` and installs into it. An existing directory is unchanged.
  A symlink, a writable directory, or a regular file at that name is refused.
  A missing required parent such as `/Library/LaunchDaemons` fails closed and is
  not recreated.
- Crash injection after every install step and after every removable step.
- A crash during recovery followed by a second recovery.
- A post-rename directory-sync failure at every journal phase, which must stop
  with no rollback and keep the journal and every backup.
- A pre-rename journal failure, which must stay an ordinary clean error.
- A real mid-install failure caused by a removed staged source file, which must
  run the inline rollback.
- Cleanup marker, launch intent, start journal, install journal, orphan backup,
  unreadable journal, a journal with a loose mode, and committed-set damage
  refusals.
- Payload digest, signature, tree, owner, and manifest approval refusals.
- First-install cleanup: the full removal, a second run that removes nothing, a
  held shared exclusion lock, a foreign file, right, or job, a changed file
  after validation, every unfinished transaction and participant record, an
  interruption after every cleanup step followed by a retry, a retry with a
  partly removed set, a non-empty install root that is kept, and the closed
  system gate.
- A source guard that reads the helper and Rust lock-name constants.
- A guard that `installationApproved` stays false.

The tests do not prove live exclusion. They do not run the real helper or the
real Rust engine against the coordinator.

## Residual risks and deferred verification

These are known limits of the sandbox model. They do not block the hermetic
tests, but they block a live install:

- The created-directory list is planned before the journal is written. A
  cooperating participant cannot create a missing path while the coordinator
  holds the exclusive locks. An uncooperative root could create one of those
  paths first, and recovery could then remove it if it is empty and has the
  expected mode. A live version must record only directories that the process
  actually created and recheck that list before removal.
- The helper directory `/Library/PrivilegedHelperTools` is created when it is
  missing but is not recorded in the install journal. A rolled-back first
  install can therefore leave that standard directory empty. The coordinator
  never removes a directory it cannot prove it created, and the package
  postinstall behaves the same way. The created directory is checked for owner,
  mode, and access control list, not group; the helper's own directory check
  does not require the wheel group.
- The installed file group is checked through one descriptor at one point in
  time. An uncooperative root can change the group after that check. The group
  is set on every file the tree writes, so the normal first-install and upgrade
  path does not depend on inheritance from the parent directory or the process.
- A recovery removes a file only after checking its owner, link count, mode, and
  either its recorded digest or its deterministic temporary name. The rollback
  destination guard is a check and a rename, not one atomic operation. An
  uncooperative root that replaces a file with an identical-name object can
  still interfere. Advisory locks do not protect against that actor.
- A journal write that fails after the rename is reported as unknown and stops
  the install, but the sandbox tests simulate the directory-sync error; no test
  causes a real device write to fail after a rename. The classification depends
  on the POSIX rule that a failed `renameat` did not replace the destination.
  The live result on the target filesystem, including a full disk and a power
  loss, is unverified.
- After an unknown journal write, recovery can see the old phase, the new
  phase, an absent record, or a damaged record. The first three are handled
  from the record found. A damaged record is refused and kept. Recovery cannot
  prove which record the failed `fsync` would have kept across a power loss.
- A journal read requires mode `0600`, but the `0600` bound is a point-in-time
  check through one descriptor. An uncooperative root can still change a path
  between checks. The same actor can also replace the record with an
  identical-mode object that validates.
- The start journal probe reads the helper record but does not prove that the
  helper process that wrote it is gone. A present record is a refusal, not a
  liveness check. The `status` command is a read-only view and does not prove
  exclusion either.
- The coordinator holds a transition lock set. It is not the approved single
  lock.
- Disk pressure interrupted an earlier verification pass. This pass ran
  `swift test --package-path macos/Installer` and the full suite passed.
  Re-run it after any later edit.

## Remaining prerequisites before approval

1. **One reviewed lock name.** All owners choose one name, remove the transition
   set, and update both source guards and tests.
2. **Initial migration.** Every old engine and helper must be stopped and
   replaced under a separately established maintenance condition. A process scan
   cannot make an old binary participate. The new release must be installed
   before any live install transaction.
3. **Live cross-process tests.** In a disposable macOS VM with root and a real
   signed helper and engine:
   - hold the coordinator exclusive lock and prove helper and direct CLI starts
     fail before a route or TUN change;
   - hold a helper or engine shared lock and prove the coordinator refuses;
   - crash the holder and prove the kernel releases the lock;
   - verify the FD `5` handoff and a partial or mismatched handoff refusal;
   - verify cleanup removes every route, address, and device before the shared
     lock drops.
4. **Signed and notarized artifacts.** The team identifier still comes from a
   caller in the sandbox core. A live coordinator must derive it from the
   installed app signature. The package needs a Developer ID Installer
   signature and notarization. No real Developer ID chain has been tested.
5. **Privileged coordinator delivery and service integration.** The future
   coordinator needs a root-owned executable, a trusted install path, and an
   ordering that keeps the install journal and backups until the launch daemon
   and authorization-right transaction commits. The sandbox service
   transaction implements the external actions with injected runtimes, but
   `InstallCoordinator` does not call it. A `recoveryRequired` service journal
   must block file rollback. See `SERVICE_TRANSACTION.md`.
6. **Live launchd and authorization-right evidence.** In a disposable macOS VM
   with root, prove `authorizationdb write` replaces or merges as expected,
   prove the stored metadata shape and `remove` behavior, prove the
   `launchctl print` format and status 113, and prove bootout/bootstrap and
   power-loss recovery. No live action has run.
7. **Installer script gate.** `preinstall` still refuses. `postinstall` remains
   unreachable future code. Neither is executed by these tests.
8. **Independent review.** The transition lock set, journal schema, recovery
   matrix, service journal ordering, ambiguous bootstrap window, and live test
   evidence need a review separate from the author.

Until all eight are complete, the package is a build and audit artifact only.

## Build and test commands

```sh
swift build --package-path macos/Installer
swift test --package-path macos/Installer
swift test --package-path macos/Installer --filter InstallLockTests
swift test --package-path macos/Installer --filter CoordinatorInstallTests
```

The command needs no signing identity and no root. It writes only under the
temporary directory and `.build`.
