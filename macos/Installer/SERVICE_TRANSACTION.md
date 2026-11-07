# Launchd and start-right service transaction (sandbox only, not approved)

Status: **NOT APPROVED AND NOT INSTALLABLE.** `installationApproved` remains
false and the package `preinstall` still refuses. The service transaction in
this directory has no live mode. It refuses a live runtime while the approval
gate is false, and the system command runner repeats the gate before it can
spawn a child. No test calls `launchctl` or `security authorizationdb`. No test
runs as root, writes a system path, changes a route or TUN device, or touches a
personal device.

Two independent refusal fences now block a mixed state. The helper and the
direct engine refuse to start while `service-journal.json` is present, and the
sandbox file coordinator refuses file install and file recovery while it is
present. This document's service transaction adds the reverse fence: it refuses
while `install-journal.json` is present. These are simple presence refusals, not
a binding and not a recovery order. Neither journal may be recovered while the
other one exists until a reviewed two-journal ordering is added.

This document covers the part of an install that a file tree cannot express:
the launch daemon registration and the authorization right. It records what is
implemented, the exact rollback limits, and the steps that remain before a root
coordinator may use it.

## Implemented files

| File | Purpose |
|---|---|
| `Sources/HotspotShadeInstallerCore/PrivilegedServiceCommand.swift` | Six fixed command shapes and the real command runner. No shell, no PATH lookup, no argument from an input. |
| `.../AuthorizationRightPolicy.swift` | Parses the packaged right and the authd read-back with the helper's own safe-definition rule. |
| `.../AuthorizationRightDatabase.swift` | Read, write, remove, and an explicit absence probe. A failed read is not treated as absence by itself. |
| `.../LaunchdJobController.swift` | Print, bootout, and bootstrap with an exact read-back parser. |
| `.../ServiceJournal.swift` | Durable service journal, bounded previous-right backup, fixed-name validation, and atomic rewrite. |
| `.../PrivilegedServiceTransaction.swift` | Apply and recover state machine with fault injection. |
| `Tests/.../ServiceTransactionTests.swift` | Apply, rollback, crash, recovery, and refusal tests. |
| `Tests/.../ServiceCommandTests.swift` | Exact command shapes and read-back parsing. |
| `Tests/.../ServiceJournalTests.swift` | Journal validation and store behavior. |

The installed inputs are read from the same sandbox tree that the file
coordinator uses:

| Input | Fixed path |
|---|---|
| Start right source | `/Library/Application Support/HotspotShade/install-support/dev.hotspotshade.tunnel.start.plist` |
| Launch daemon file | `/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist` |
| Helper executable | `/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper` |
| Engine executable | `/Library/Application Support/HotspotShade/engine/hotspotshade` |

The right source and the launch daemon file are validated with the same
`InstallerValidator` rules and digests that the file transaction used. The
helper and engine must be present with mode `0755`; when the caller supplies the
expected Developer ID team, both signatures are revalidated before any service
change. A live runtime requires that team. The service journal is
`/var/db/hotspotshade/service-journal.json`, mode `0600`, owned by the target
root owner. A read requires that exact mode.

A future root coordinator must pass two `InstallTree` roots. The installed files
need the system root `/`. The state directory needs `/private`, not `/`, because
`InstallTree` refuses a symlink path component and `/var` is a symlink to
`/private/var` on macOS. The transaction then reads
`/private/var/db/hotspotshade` while the helper and the Rust engine continue to
name `/var/db/hotspotshade`; both names reach the same directory. The sandbox
tests use one root for both trees. This split is a fixed-path requirement, not
an input.

## Apply sequence

The transaction takes the same exclusive lock set as the file coordinator
unless the caller passes a lease it already holds. A passed lease must name the
same lock inodes in the state directory, so a lease from another directory is
refused. It then:

1. Refuses a file install journal, a cleanup block, an engine launch intent, or
   a start journal. The file journal refusal is the reverse fence described
   above.
2. Reads and validates the installed right, launch daemon file, helper, and
   engine.
3. Observes the current start right and launch daemon job. An unsafe right or
   a loaded job that does not name the fixed helper and plist is refused before
   any change.
4. Writes `service-journal.json` in phase `preparing`. The journal records the
   new digests and a bounded base64 backup of the previous right.
5. Boots out the previous job when it was loaded. A command failure is accepted
   only when the read-back proves the job is absent.
6. Rechecks the start right, writes the packaged definition, and requires the
   read-back to match the helper policy. A command exit status alone is not
   proof.
7. Rechecks the right and the job. A job with the fixed label that is loaded
   before this transaction bootstrapped it makes the transaction refuse.
8. Bootstraps the installed launch daemon file and requires the exact read-back.
9. Writes `jobBootstrapped`, re-verifies both states, writes `committed`,
   removes the journal, and returns.
10. On an ordinary failure before the commit record, runs the rollback. A
    rollback that can restore the previous job state writes `rollbackStarted`
    before its first mutation. If the rollback completes, it writes `rolledBack`
    and only then removes the journal. A failed upgrade whose previous job was
    already booted out cannot restore that job; it keeps the journal for forward
    recovery. A failure after the commit record is durable keeps the journal and
    never rolls back the new service state. On a simulated crash, leaves the
    journal for `recover()`.

`recover()` rolls a non-committed install journal forward when the installed
files still match the journal. It rolls a committed journal forward by verifying
both new states and removing the journal. It completes a `rolledBack` journal
by verifying the previous state and removing only the journal, and it completes
a `rollbackStarted` journal by restoring the previous state or refusing. It
never installs from a rollback phase. It never deletes a backup or a job that
the journal does not name. Before it acts on any observed journal phase it
rewrites the exact observed bytes through the atomic seam, requires the file and
parent sync, and checks the read-back. An unknown confirmation stops before the
first service action and keeps the journal. Removal requires the exact digest
and mode that the decision observed; a changed record is kept.

An ordinary upgrade can keep the same right policy. A stored definition whose
policy equals both the previous and the installed policy is classified as
ambiguous, not installed first. The durable journal phase decides which state it
represents:

- `preparing` and `jobBootedOut` mean the transaction has not recorded a right
  write. The definition is previous. A loaded previous job may be booted out,
  and forward recovery writes the packaged definition before bootstrap so old
  authd metadata is not retained silently.
- `rightReplaced` is the first phase that proves the packaged definition was
  written. An installed or same-policy ambiguous definition is accepted there
  without another write, unless its bytes are exactly the previous backup;
  then recovery writes the packaged definition before bootstrap.
- `rollbackStarted` and `rolledBack` mean the definition is previous. Recovery
  never writes the packaged definition from those phases, so a rollback cannot
  become an install.

A definition is never attributed to a transaction from bytes alone. authd
normalizes its own metadata, so the read-back and the backup are not expected to
be byte-equal.

## Journal phases and crash windows

| Phase | Durable meaning | Recovery |
|---|---|---|
| `preparing` | The journal exists. No external action is recorded. | Reconcile observed state. A same-policy right is previous here. If the previous job is loaded, boot it out and write `jobBootedOut`. Then write the packaged right, including a same-policy refresh, and bootstrap. If a job is loaded but the journal cannot prove it is the previous one, refuse. |
| `jobBootedOut` | The previous job was verified absent, or none was loaded. | Write the installed right, including a same-policy refresh, write `rightReplaced`, then bootstrap. |
| `rightReplaced` | The installed right was written and its read-back verified. | Reobserve the job immediately before bootstrap. Bootstrap only when the job is absent. A loaded job in this phase is ambiguous and refused. An installed or same-policy right is accepted without another write, unless its bytes are exactly the previous backup; then the packaged right is written forward. A previous or absent right is written forward. |
| `jobBootstrapped` | The installed launch daemon was bootstrapped and its read-back verified. | Verify both states, write `committed`, and remove the journal. |
| `committed` | Both new states were verified and the commit record is durable. | Verify both new states and the installed launch daemon digest. If they verify, remove the journal. If not, keep it and report damage. |
| `rollbackStarted` | The transaction durably began restoring the previous right and job state. | Finish the rollback or refuse. A same-policy right is previous, not installed. Never write the installed right or bootstrap from this phase. |
| `rolledBack` | The previous right and job state were verified restored. | Verify the previous state again and remove only the journal. A same-policy right counts as previous. Never install. |

Recovery writes `jobBootedOut` and `rightReplaced` before the next privileged
action. It does not infer those phases from the observed state alone. A crash
after a successful bootstrap and before the `jobBootstrapped` record leaves
`rightReplaced` plus a loaded job; recovery refuses because launchd records no
creator identity.

Specific windows:

- Before the journal exists: no privileged action has run.
- After `preparing` before bootout: the previous state is still present.
- After bootout before `jobBootedOut`: the job is absent. Recovery finishes
  forward.
- After the right write before `rightReplaced`: the right is new. Recovery
  records `rightReplaced` before it bootstraps.
- After `bootstrap` succeeds before `jobBootstrapped`: **ambiguous.** The job
  is loaded, but launchd records no creator identity. Recovery does not boot it
  out and does not claim the install. It keeps the journal.
- When a bootstrap command fails but the read-back shows a loaded job:
  **ambiguous.** Recovery never treats the loaded job as the result of its failed
  command, never boots it out, and never writes `jobBootstrapped`.
- After `jobBootstrapped` before `committed`: the new states are proven.
  Recovery finishes the commit.
- After `committed` before journal removal: recovery verifies and removes.
- After `rollbackStarted` before `rolledBack`: recovery finishes the rollback
  or refuses. It never installs or bootstraps.
- After `rolledBack` before journal removal: recovery verifies the previous
  state and removes only the journal. It never installs.
- With the same previous and installed policy before `rightReplaced`: the
  right is previous, the previous job can be booted out, and forward recovery
  writes the packaged definition. This is the ordinary same-policy upgrade.
- With the same previous and installed policy in `rollbackStarted` or
  `rolledBack`: the right is previous. Recovery removes the journal after the
  previous job state verifies. It never writes the packaged definition or
  bootstraps.
- After journal removal: nothing remains to recover.

The ambiguous bootstrap window is fault-injected at
`ServiceTransactionStep.recoveryBootstrapSucceeded`, immediately after the
successful bootstrap read-back and before the `jobBootstrapped` record. A
second recovery refuses the loaded job. The install window is tested at
`bootstrapCompleted` and by a bootstrap command failure that leaves a loaded
job. All three tests assert that recovery keeps the journal and does not call
bootout.

## Exact rollback limits

### Authorization right

`security authorizationdb write` and authd are not transactional. authd adds
`created`, `modified`, `version`, `session-owner`, and `tries` to a stored
definition, and the installed right may also carry `identifier` and
`requirement`. A rollback therefore cannot promise byte equality.

The transaction stores the previous read-back and restores it. It calls the
rollback exact only when the restored bytes equal the backup. This check runs in
both rollback branches: when the right is already the previous policy and no
restore command is needed, and when the transaction writes the previous
definition back. When the helper policy is equal but authd changed metadata, it
returns `operationFailedWithInexactRightRollback`. When the restored definition
is not safe or does not match the previous policy, it keeps the journal and
returns `recoveryRequired`.

A completed rollback first writes the terminal `rolledBack` phase and then
removes the journal. If journal removal fails, the journal stays in `rolledBack`
and the install call reports `recoveryRequired`. Recovery verifies the previous
state and removes only the journal. It does not turn the completed rollback into
a new installation. Recovery reports the same byte difference through
`finishedRollback(transactionID:rightMetadataChanged:)` when a later recovery
finishes a rollback whose restored bytes differ from the backup.

The transaction refuses to overwrite a previous right that the helper's
validator does not accept. It never removes a right during a successful
install; removal is used only to roll back a first install whose previous state
was absent. A failed read command is not treated as absence. The production
absence probe uses `AuthorizationRightGet`, whose documented result for a
missing definition is `errAuthorizationDenied`; any other status is an error. A
failed write or remove command is reported as a privileged command failure, not
as an unreadable right, because it is not an observation failure.

A same-policy upgrade is the hard case for classification. The previous
read-back and the packaged definition parse to the same policy, so policy
equality proves neither state. The transaction uses the journal phase:

- Before `rightReplaced`, forward recovery treats the definition as previous
  and writes the packaged definition. It does not skip the write merely because
  the policy already matches, which would retain the old authd metadata.
- `rightReplaced` is proof that this transaction wrote the definition. Forward
  recovery accepts the installed or same-policy definition without another
  write. If the stored bytes are exactly the previous backup and the packaged
  definition differs, recovery writes the packaged definition before
  bootstrap. That exact match catches a journal left by an earlier recovery
  that classified the same policy as installed and skipped the write.
- `rollbackStarted` and `rolledBack` treat the definition as previous. The
  rollback path does not write the packaged definition, remove a previous
  right, or bootstrap a job from this state.
- A terminal rollback accepts the same-policy definition as the previous
  state. It does not report the policy as the installed state and does not
  require a byte-equal backup.

Apart from the exact-backup case, a stored definition that differs from the
previous backup but has the same policy cannot prove whether it is the new
write or an external write. The journal phase is the only proof; do not infer a
missing write from the policy alone.

Live behavior is unverified:

- whether `authorizationdb write` replaces or merges on a real host;
- the exact metadata authd adds to this custom right;
- `authorizationdb remove` behavior when the right is already absent;
- the printed `security authorizationdb read` form on each supported macOS.

### Launch daemon

`launchctl` has no creator identity. The transaction can prove loaded or
absent, but not who loaded a job. It therefore:

- never boots out a job that it did not observe `bootstrap` succeed for in the
  same process;
- never boots out a job whose printed `path` or `program` differs from the
  fixed installed values;
- keeps the journal when a bootstrap result is ambiguous;
- does not recreate the previous job after a failed upgrade. The previous
  launch daemon file has already been replaced by the new file set, so
  re-bootstrapping the old job would run the new helper under an old
  registration. The previous job stays booted out and the journal records the
  state.

`launchctl print` is parsed for three exact lines: `system/<label> = {`,
`path = <fixed plist>`, and `program = <fixed helper>`. A format change fails
closed. A missing job is accepted only when `launchctl print` exits 113 **and**
stderr contains `Could not find service`. Any other failure is unknown, never
absence.

### Live launch daemon timing

The transaction runs `launchctl print` immediately after `bootout` or
`bootstrap`. It never sleeps and never retries the read-back. The command
timeouts are 10 seconds for `print` and 30 seconds for a mutation. Those values
bound the child process, not the launchd daemon's own completion:

- launchd can return from `bootout` or `bootstrap` before its job state is
  visible in the next `print`;
- a read-back can therefore report the old state even though the action was
  accepted, or report a state that changes again after the record is written;
- a timed-out or killed `launchctl` process does not prove that launchd stopped
  processing the request;
- a status 113 with the fixed diagnostic is the only absence proof. A timeout
  is unknown, never absence.

No live run has measured this timing, delayed registration, or the state after
a timed-out command. The current code does not claim that an immediate read-back
is stable on a live host. A future live implementation needs a bounded,
documented settle and re-read policy, or a launchd API with a stronger result.

### Command runner limits

The runner uses bounded pipe drains and stops supplying input when a command
times out or exceeds the output limit. It attempts to terminate the direct
child and its confirmed process group, but bounded return does not prove that
every descendant has exited. A descendant may leave the group or outlive the
direct child. An open output pipe after the drain deadline is an incomplete
result, not evidence of a successful command.

The fixed-tool check does not verify an Apple code signature or pin the
executable inode through spawn. The command runs with an inherited working
directory. The right-write command accepts a bounded property list; its caller
must establish that the bytes are the intended reviewed policy. These limits,
and actual `launchctl` and `authorizationdb` behavior, require review before
the live gate can be opened.

### Journal write sync uncertainty

`InstallTree.writeAtomic` writes a temporary file, syncs it, renames it into
place, and syncs the parent directory. It classifies the write by the step that
failed. A failure before the rename, including a `renameat` that returns an
error, leaves the previous record authoritative and is an ordinary `io` error.
If the directory sync fails after a successful rename, the new record is visible
but its durability is unknown. `writeAtomic` reports `.writeUncertain` and the
journal store reports `writeOutcomeUnknown` without reading the record back. A
read-back would show the current namespace, not whether the directory entry
survives a power loss. The service transaction then keeps the journal and
refuses instead of rolling back a state whose phase cannot be proven. The
install call returns `recoveryRequired`, and recovery re-observes the journal
and external state.

This applies to the initial `preparing` write too. There it returns
`recoveryRequired`, not a separate error, even though no privileged action has
run. The visible record may survive a power loss, so every caller must keep the
journal and block file rollback. `serviceJournalWriteOutcomeUnknown` is an
internal mapping; it does not reach an apply or recover caller.

A clean pre-rename failure is still an ordinary `io` error under the
cooperative lock assumption. The previous record is intact and the normal
rollback or refusal path runs. An uncooperative root writer can still change
the file between the failed write and the next check; that actor is outside the
lock and outside every ownership check in this design.

Journal removal has a separate limit. `removeFile` unlinks first and syncs the
directory second. If the unlink succeeds and the directory sync fails, the live
journal is gone even though the call reports an error. The terminal
`rolledBack` or `committed` phase was durable before that removal, so a power
loss can only re-create the terminal record, never an earlier roll-forward
phase. On the running host, a retry after the reported `recoveryRequired`
cannot be distinguished from a new transaction by the journal, because the
journal is absent. Do not retry an install after a failed journal removal
without reconciling the observed service state.

## Reverse fences and the two-journal gap

The current tree has simple presence refusals, not one binding:

- The helper refuses a start while `install-journal.json` or
  `service-journal.json` is present.
- The direct Rust engine refuses a start while either journal is present.
- The sandbox file coordinator refuses file install and file recovery while
  `service-journal.json` is present.
- The service transaction refuses while `install-journal.json` is present.

The refusals preserve both journals. They do not define which journal is
recovered first, and they do not let a transaction span both. A state with both
journals needs manual reconciliation until a reviewed two-journal order exists.
The helper's `service-journal.json` refusal is a presence check that maps to its
existing `installJournalPresent` result; it is not evidence that an engine or a
job is live.

## Old lock-free binaries and non-participants

The exclusive lock excludes only processes that take it. At the time of this
writing:

- The helper and the Rust engine both use `/var/db/hotspotshade/start-exclusion`.
- The installer coordinator uses `start.lock` as its primary name and holds
  `start-exclusion` and `upgrade.lock` in the transition set. It therefore
  contends with the current helper and engine through `start-exclusion`, but
  this is a transition set, not one reviewed name.
- A binary that predates the lock takes no lock and is not excluded.
- A direct `sudo hotspotshade tun` start from a participating engine takes the
  shared lock. A direct start from an old engine does not.
- `launchctl bootout`, `launchctl print`, `pgrep`, a marker, and a process scan
  are observations. None is mutual exclusion.
- An uncooperative root process can change authd, launchd, the lock inode, or
  the installed files during or after any check. Advisory locks do not stop it.

The service transaction refuses a cleanup block, an engine launch intent, and a
start journal as refusal records. A present record is not proof that an engine
is live, and an absent record is not proof that it is gone. Initial migration
of every old binary under a separately established maintenance condition is
still required. Do not describe this boundary as complete install exclusion.

## Integration with a future root coordinator

The service transaction is not called by `Coordinator.swift` today. A future
root coordinator must:

1. Hold one reviewed exclusive lock for the whole file and service
   transaction, not only for the file replacement. Use an installed-file tree
   rooted at `/` and a state tree rooted at `/private`, then pass both to the
   service transaction.
2. Replace the file set and keep the install journal and backups until the
   service transaction commits.
3. Call `PrivilegedServiceTransaction.apply(installTransactionID:using:)` with
   its held lease and the file journal's transaction identifier after the new
   files verify and before the install journal is removed.
4. Treat `recoveryRequired` from the service transaction as a block on file
   rollback. This includes an unknown initial `preparing` journal write: the
   record may be durable even though no privileged action ran. If the files are
   rolled back while a service journal exists, the service journal's installed
   digests no longer match and service recovery refuses. A person must then
   reconcile the service state by hand.
5. Call `PrivilegedServiceTransaction.recover(using:)` before another install
   and before removing the file journal. The current reverse fence refuses this
   call while the file journal exists, so a reviewed binding must replace the
   simple refusal before integration.
6. Take the team identifier from the installed app signature, sign and notarize
   the package, and deliver the coordinator as a root-owned executable.

Two separate journals are a reviewable foundation, not the final ordering. A
single combined record, or a documented two-record recovery order, still needs
an independent review and a live power-loss test. The present refusals are
deliberately conservative and leave a both-journal state for manual handling;
they do not bind the file transaction and the service transaction.

## Tests

`swift test --package-path macos/Installer` runs the hermetic suite. The new
tests cover:

- initial install from an absent right and job;
- upgrade from a safe previous right and a loaded job;
- a same-policy upgrade from `preparing` with a loaded previous job, which
  boots it out and writes the packaged right instead of retaining the old authd
  metadata;
- a same-policy `rightReplaced` journal whose stored bytes are exactly the
  previous backup, which is rewritten before bootstrap;
- a same-policy recovery that is interrupted after a durable `jobBootstrapped`
  record, followed by an idempotent second recovery;
- a same-policy terminal rollback whose journal removal fails, followed by a
  recovery that removes only the journal and never installs, with and without
  a loaded previous job;
- a same-policy `rollbackStarted` journal with a loaded previous job, which
  finishes without writing the packaged right, removing the previous right, or
  bootstrapping;
- a same-policy `rollbackStarted` journal whose previous job was absent, which
  refuses a loaded job without booting it out;
- right write failure, read-back mismatch, and metadata-inexact rollback;
- bootstrap failure with an absent previous job;
- failure after a successful bootstrap, with the new job booted out;
- bootout failure and a bootout that does not take effect;
- a failed upgrade that leaves the journal because the previous job cannot be
  recreated;
- a bootstrap command that fails while a job is loaded, which is not attributed
  to the transaction;
- a job that appears immediately before recovery bootstrap, which is refused
  without a bootstrap;
- a recovery bootstrap command that fails while a job is loaded, which is not
  attributed to the recovery;
- a fault after a successful recovery bootstrap and before its journal record,
  with the next recovery refusing the loaded job;
- durable `jobBootedOut` and `rightReplaced` recovery phases before the next
  action;
- a completed rollback whose journal removal fails, followed by a recovery that
  removes only the journal and never installs, plus a terminal-rollback refusal
  when the previous state changed;
- byte-inexact previous-right reporting in both the already-previous and restore
  branches;
- a post-rename directory sync failure, which keeps the visible journal and
  refuses instead of rolling back, and a pre-rename failure, which stays an
  ordinary io error; an unknown initial `preparing` write returns
  `recoveryRequired`, makes no privileged action, and leaves a reconcilable
  journal;
- a launch daemon file that changes after the recovery right record and before
  bootstrap, which reports `recoveryRequired` and keeps the journal;
- a file install journal, which refuses both apply and recover and is preserved;
- a fault at every install step, followed by recovery or a fail-closed refusal;
- a fault after the durable commit record, which keeps the new service state
  and never rolls it back;
- a second crash during recovery and a second recovery;
- a fault at every recovery step, with a second recovery completing the work;
- unsafe previous rights, unexpected loaded jobs, participant-state records,
  and a present service journal;
- installed helper and engine signature revalidation before any service change;
- exact command shapes, the production launchd read-back wrapper, the
  production authorization read-back wrapper, the write and remove status
  checks, the absence-probe status mapping, and the live-runner approval
  refusal;
- a lease from another state directory, which is refused before any change;
- journal names that match the helper start-exclusion protocol and the Rust
  engine source, plus round-trip, fixed-name, digest, backup, policy,
  rollback-phase, and write-outcome validation.

The tests do not run as root, execute `launchctl` or `security`, write authd,
create a launchd job, change a system path, or prove a live install. They use a
fake runtime with the same fixed paths and command contracts.

## Remaining review blockers

The recovery repairs in this document are hermetic. These blockers remain open
and the package stays a build and audit artifact:

1. **Two-journal ordering.** There is no reviewed recovery order between
   `install-journal.json` and `service-journal.json`. Both simple refusals must
   be replaced by one binding, or a documented two-record order, with a live
   power-loss test. A both-journal state currently needs manual handling.
2. **Live roots and trust.** No run uses `/` as the installed-file root and
   `/private` as the state root. No root-owned coordinator, signed helper
   install, XPC launch, or promotion to a prior signed set has run. The live
   runtime gate and team requirement are compile-tested only.
3. **Command runner and timing.** The real `launchctl` and
   `security authorizationdb` command runner has not executed. The printed
   launchd format, status 113, bootout, bootstrap, immediate read-back, and the
   settle behavior after a mutation are unverified on a live host. No live run
   shows whether an immediate `launchctl print` is stable, or what state a
   timed-out or killed `launchctl` child leaves behind.
4. **authd metadata.** Whether `authorizationdb write` replaces or merges, which
   metadata authd adds, `authorizationdb remove` when absent, and the printed
   read form on each supported macOS are unverified. Byte-inexact reporting is
   implemented and tested with a fake, not proven against authd.
5. **Real VM evidence.** No disposable macOS VM power-loss test covers the
   successful-bootstrap-before-journal window, the terminal rollback window, the
   post-rename sync window, or route, launchd, and authd recovery together.
6. **Lock name and old binaries.** One reviewed lock name must replace the
   transition set, and every old helper and engine binary must be migrated under
   a maintenance condition. A pre-lock or uncooperative root process is not
   excluded.
7. **Package trust.** The package is unsigned and not notarized. A real
   Developer ID chain and package script read-back have not run.
8. **Independent review.** The service journal phases, the ambiguous bootstrap
   window, the two-journal ordering, and the command runner still need
   independent review.

Until those steps complete, the package remains a build and audit artifact.
