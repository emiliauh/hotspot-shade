# macOS bound recovery design (design only, not approved)

Status: **DESIGN ONLY. NOT IMPLEMENTED. NOT INSTALLABLE. NOT APPROVED.**

This document proposes three-record recovery with a binding (B) between a file
install journal (FJ) and a service journal (SJ). The matrix below is a draft. An
independent re-review found contradictions and cases that it does not safely
classify. It is not an implementation specification.

**Review hold, 2026-11-06:** The following restrictions override the draft
actions and claims elsewhere in this document until the matrix, executor, and
tests are revised and independently reviewed:

- A loaded job in a `Bd` state does not authorize `CLEAN-ROLLBACK` or
  `REMOVE-B`. The proposed `WL0` predicate cannot establish which plist
  launchd loaded. A boot UUID recorded before rollback also cannot prove a
  reboot happened after `Bd`. Keep the binding and refuse on this observation.
- The move-to-backup window can leave a previous-present destination absent.
  The revised draft classifies that state with its verified backup and proposes
  a restore rule. The complete classification and restore durability still need
  independent review and fault tests; do not treat the matrix as complete.
- The current service recovery can refuse a loaded job in `Sb` or `Sr`.
  `FINISH-SERVICE` is not a guarantee that those states complete forward.
- Residue and record temporaries are decision inputs. Their sweep, empty backup
  root, nonempty directories, and planned-versus-actually-created directories
  need an explicit, identity-aware cleanup contract. Keep records on doubt.
- A restore rename and both parent-directory syncs need an explicit unknown
  outcome rule before `Bd` can be written. The pre-action binding comparison
  must also precede the SJ `preparing` write. `apply` must refuse `Bc`.
- `P0` cannot prove that destinations or created directories stayed unchanged
  after FJ removal. It cannot authorize a file or directory mutation, and the
  consequences of removing the last binding fence need a separate decision.

The review also found that an observed right can be ambiguous with the
installed right, that `G8a` must not accidentally prohibit the legacy sandbox
path, and that the proposed legacy rollback gate is not present in source.
The test plan must include residue, the absent-destination window, restore-sync
failures, loaded-job cases, and independently specified expected decisions.
Any statements below that claim these matters are resolved are superseded by
this hold. The source hashes in section 0 describe an earlier observation and
may have changed during concurrent work.

Nothing here changes source, tests, scripts, or the package. The installer
remains not installable. `CoordinatorPolicy.liveInstallationApproved` remains
`false`. No live install mode is added. No argument, environment variable, or
file can turn the gate on.

## 0. Revision provenance and observed drift

This revision answers the independent review of the design text whose SHA-256
was `c39aa4c4dd171a8f8139af21d734a46788acda041a638255a680283d0a3a034a`.
That text is the previous version of this file. The review findings are
captured in section 17 and are not silently dropped.

The design was reasoned from the working tree on 2026-11-06. These files were
read. The hashes are the bytes observed. They are provenance, not a trust
anchor.

| File | SHA-256 observed |
|---|---|
| `macos/Installer/Sources/HotspotShadeInstallerCore/Coordinator.swift` | `54717cb0cc67b4f2d8435ce0afed0510e2a894a3cd0af97a6941b2499c34fb4c` |
| `.../InstallJournal.swift` | `4ccffc52dc485c0472d253d064361384c4d5ff497c2574a79e225467a681d172` |
| `.../ServiceJournal.swift` | `0ecb929732a057436870ffae0766aa60da484326aede73dbb6fff26b7bc79a44` |
| `.../PrivilegedServiceTransaction.swift` | `a1637eec28442f858f18e690e81d3e536e33380a0c942d2277c51ff8564c80b9` |
| `.../InstallTree.swift` | `193fb6deadc5e3be9504f147e58d25be767f9cc0ab78465e9fd37ea7ae3f5c3b` |
| `.../InstallLock.swift` | `d41b4747dd51d3e044269cc223d7e9d7053d8cae29f91ff76b65ab4fd7206f1a` |
| `.../StartJournal.swift` | `e4aed37cb8d185ffae28c03ca54425f3d9e39ad85dc5ff6858f5a5a4e8ae3673` |
| `macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperStartExclusion.swift` | `23ba335c03355b284141f9bea531acbdd8bb699e11fc02188a0143dde160cdd6` |
| `.../RootStateDirectory.swift` | `5652b4d4835290ed5b8cc63a60dd35ed7e3531314200598c177a35fbc3b4f334` |
| `rust/src/macos_upgrade_lock.rs` | `08cb80e83bb9fa3aef9b5a6c803f2b2124a73a889cb49101853e2c6c724fe947` |

Drift is real and deliberate. `macos/Installer` is untracked work in this
tree, and `InstallJournal.swift` was modified after
`PrivilegedServiceTransaction.swift` while this revision was being prepared.
A worker is changing installer journal durability. This design does not edit
`macos/Installer`. It names current functions, not fixed line numbers, because
the line numbers moved between the reviewed text and this read. Where the
reviewed text made a claim about the current code that is no longer true, this
revision says so in section 17. An implementer must re-read the files before
coding and must not treat a hash above as a requirement.

No root, launchd, authorization database, network, route, TUN device, physical
device, Python, subagent, or commit was used to write this document.

## 1. Goal and non-goals

The goal is one recovery decision for a macOS install that has an FJ, an SJ, or
both, with no state where either journal is recovered on an assumption. The
binding is a durable tie. It is not a second source of truth for file content.

Non-goals:

- No live installer mode. No package change. No signed helper install.
- No change to the source device, the target engine, routes, TUN devices, DNS,
  or the tunnel.
- No new privilege boundary beyond the root coordinator and service runtime
  that a future implementation needs.
- No claim that a cooperative lock excludes root, an old binary, or a process
  that uses another lock name.
- No claim that the binding proves file integrity after the FJ is gone.

## 2. Gate, reachability, initializers, and the lease

The gate is a compile-time constant. This design does not add a runtime switch.

### 2.1 Two initializers, one operation lease

The reviewed text said the bound coordinator is "constructed only with a
validated exclusive lease". That mixed construction with operation lifetime and
left the root case undefined. This revision separates them.

**Initializer A, sandbox legacy path.** `InstallCoordinator.init(sandboxRoot:...)`
keeps its current call shape. The two new parameters are defaulted to nil, and a
non-nil value throws. It requires `geteuid() != 0`, a marked sandbox root,
`bindingStore == nil`, and `service == nil`. It is the only initializer the
`hotspotshade-installer-coordinator` command uses. It never reads or writes
`upgrade-binding.json`. It is the legacy path. It is not the target recovery
and it must be deleted before the gate opens. It is unreachable in production
today because the gate is false.

**Initializer B, root bound path.** A future
`InstallCoordinator.init(rootStateDirectory:bindingStore:service:validator:faults:)`
requires `geteuid() == 0`, the fixed root `/var/db/hotspotshade` with owner root
and mode `0700`, a non-nil `BindingStore`, and a non-nil
`PrivilegedServiceRuntime`. It is internal to the installer module. It is
available only to the future root coordinator binary. It does not accept a
sandbox root, a marker, or a caller-supplied path. Tests use a temporary root
through an internal test seam and a fake runtime. The seam is not compiled into
the production command.

**Both components or neither.** The root initializer requires both
`bindingStore` and `service` to be non-nil. The sandbox initializer requires both
to be nil. A call with exactly one non-nil throws
`CoordinatorError.incompleteBoundConfiguration`. A non-nil binding store or
service runtime in the sandbox initializer throws the same error.

**One lease per operation.** Neither initializer accepts a lease. Each public
operation (`install`, `recover`) acquires the exclusive transition lock set at
the start of the operation and releases it on every return path. The bound
operation passes that held lease to
`PrivilegedServiceTransaction.apply(using:)` and
`PrivilegedServiceTransaction.recover(using:)`. The service transaction
validates that every held lock reports `isHeld` and that the state directory
matches the lease, as `acquireOrValidate` does today. It does not acquire a
second lease. A caller-supplied lease is a test seam only and is validated the
same way. The lease is cooperative. It is not proof of exclusion against root,
an old binary, or a non-participant.

This policy makes the binding write, the FJ write, the service actions, and the
removal order one lease span. It also removes the impossible requirement that a
lease exist before the coordinator can be constructed.

### 2.2 Gate and CLI

- The bound path is reachable only from tests and from a future root
  coordinator. The live service transaction still refuses a live runtime while
  the gate is false, and the real command runner repeats the gate.
- `hotspotshade-installer-coordinator` keeps its current arguments. It calls
  `InstallCoordinator(sandboxRoot:)` with both new parameters nil. No command
  writes `upgrade-binding.json`. A test asserts this.
- The package `preinstall` still refuses. No script is generated or changed by
  this design.
- The gate opens only after this document is implemented, reviewed again, and
  tested on a disposable macOS VM. This document does not propose opening it.

## 3. Records and codes

### 3.1 Names, paths, object checks, and modes

All records live in the private state directory `/var/db/hotspotshade` (mode
`0700`, owner root), or under `var/db/hotspotshade` in a sandbox or test root.

| Record | File name | Mode | Writer |
|---|---|---|---|
| File install journal (FJ) | `install-journal.json` | `0600` | File coordinator |
| Service journal (SJ) | `service-journal.json` | `0600` | Service transaction |
| Binding (B) | `upgrade-binding.json` | `0600` | Bound coordinator |

Fixed names are constants. A record is never located by a value read from
another record. A symlink, a non-regular object, another owner, a group or other
permission, an access control list, or a hard link at one of these names is
unsafe.

The two existing readers do not apply the same checks today. This is a source
fact, not a preference.

- `InstallTree.snapshot`, `readFile`, and `removeFile` check regular type,
  owner, `st_nlink == 1`, no group or other write bit (`0o022`), and no
  extended ACL. `readFile(requiredMode:)` additionally requires the exact mode,
  so the FJ and SJ reads require `0600`. The removal path does not require the
  exact mode and does not verify a digest when `expectedDigest` is `nil`.
- `RootStateDirectory.contains` checks regular type, owner, no group or other
  permission (`0o077 == 0`), and no set-user-ID, set-group-ID, or sticky bit,
  and it checks the ACL. It does **not** check `st_nlink == 1` and it does not
  require an exact mode. A `0400` binding would pass that presence check, and a
  hard link to a safe file would also pass.

The design therefore adds two rules, not zero:

1. The coordinator's binding read uses the same exact-mode and single-link
   checks as the FJ and SJ, with `requiredMode: 0o600`.
2. The helper's and the engine's presence check for `upgrade-binding.json`
   requires a regular single-link file owned by root with no group or other
   permission and no set-id or sticky bit. The helper adds a
   `containsSingleLink` form of the existing check for the three refusal names.
   The engine adds `st_nlink == 1` and owner `0` to its `fstatat` refusal check.

The old sentence "the binding adds a name to those checks; it does not add a new
rule about object type" was wrong about hard links and exact mode. This revision
does not repeat it.

Temporary names:

- FJ: `.install-journal.json.hs-<transactionID>.tmp`
- B: `.upgrade-binding.json.hs-<transactionID>.tmp`
- SJ: `.service-journal.json.hs-<transactionID>.tmp`

`InstallTree.writeAtomic` builds the name as `.<name>.hs-<suffix>.tmp`, so the
temporary suffix is the transaction identifier. A temporary file is removed by
exact name before every write of that record, and by exact prefix sweep at the
start of every recovery run. A leftover temporary is never a decision input.

### 3.2 Binding record

The binding is small on purpose. It records what the file side and the service
side must agree on, and the service state observed before the first file
mutation. It does not duplicate file digests.

```
schemaVersion: 1
transactionID: 32 lowercase hex
fileJournalSchemaVersion: 1
fileJournalIdentitySHA256: 64 lowercase hex
bootSessionUUID: canonical lowercase UUID
previousJobLoaded: 0 or 1
previousRightPresent: 0 or 1
previousRightPolicy: policy fields when present
phase: bound | rollingBack | rolledBack | committed
```

`previousRightPolicy` carries the parsed safe definition fields: `rightClass`,
`group`, `authenticateUser`, `shared`, `allowRoot`, `timeout`, and `comment`
when present. The policy is compared for equality. Exact authd bytes are not
compared. authd normalizes metadata, and the service transaction already
documents that limit. The `timeout` value is the bounded positive
authorization window: the helper and installer accept 1 to 60 seconds, and the
shipped template uses 10. A stored right with a different window is a
different policy, not a match to restore over.

The binding deliberately does not carry `fromVersion`.
`Coordinator.swift` still writes `InstallJournal.fromVersion: nil`, so a binding
field could not be validated against it. If a later change records the previous
version, the FJ identity digest covers it and the binding still does not need
it.

The binding deliberately does not carry per-file new or previous digests. The
FJ is the only record that authorizes a file restore or a backup removal. A
binding without a readable FJ cannot authorize either. This keeps one owner for
file content and prevents two records from disagreeing.

The binding is not signed and is not a security boundary. A root process can
rewrite it. It is a coordination record that fails closed on structural damage.
Do not describe it as tamper-proof.

The pre-state fields are observed under the lease immediately before B is
written. A job that is `unexpected` or `unknown`, or a right that cannot be
classified, refuses before B is written. The observation is not reused from an
earlier step.

### 3.3 Canonical file journal identity digest

`fileJournalIdentitySHA256` is SHA-256 over UTF-8 bytes with this exact
encoding. The domain line comes first. Every later line is `name=value` followed
by a single `\n`. There is no CR, no space, and no trailing blank line.

```
hotspotshade.install-journal-identity.v1
schemaVersion=<decimal>
transactionID=<32 lowercase hex>
fromVersion=-|<version string>
toVersion=<version string>
teamIdentifier=<team identifier>
createdDirectories=<count>
<path>
... repeated count times, in the file journal order
operations=<count>
index=<decimal>
artifact=<raw value>
destination=<relative path>
newSHA256=<64 lowercase hex>
newSize=<decimal, no leading zero except zero>
newMode=<4 lowercase hex digits of the UInt16 value>
previousPresent=<0|1>
previousSHA256=<64 lowercase hex>        only when present
previousSize=<decimal>                   only when present
previousMode=<4 lowercase hex>           only when present
... the seven to ten operation lines repeat for each operation, in order
```

The FJ `phase` is excluded on purpose. The identity must stay stable when
`preparing` is rewritten to `replacing` and `committed`. A digest over the whole
file would change on every phase write and could not bind anything.

The coordinator recomputes this digest from the decoded, validated FJ. A
caller-supplied digest, including a future `BoundServiceRequest.bindingDigest`,
is never authoritative. It may be used as a test assertion only.

`InstallerBuilder.isValidVersion` and `SafeRelativePath` already bound the
string fields and exclude newlines. `newSize` and `previousSize` are nonnegative
and at most the artifact maximum: 256 MiB for an executable and 64 KiB for a
plist. `mode` is the 16-bit mode value, so `0o755` is `01ed` and `0o644` is
`01a4`. There is no byte-order question because the encoding is text.

### 3.4 State codes

Each code names exactly one record and phase. No code is reused.

File journal:

| Code | Phase | Meaning |
|---|---|---|
| `F0` | absent | No file journal. |
| `Fp` | `preparing` | Journal durable, no file mutation recorded. |
| `Fr` | `replacing` | File mutation may have started. |
| `Fc` | `committed` | New file set was verified. File rollback is forbidden. |
| `Fx` | damaged | Unreadable, unsafe, foreign schema, or failed validation. |

Binding:

| Code | Phase | Meaning |
|---|---|---|
| `B0` | absent | No binding. |
| `Bb` | `bound` | Binding durable, file mutation may be authorized. |
| `Bk` | `rollingBack` | Rollback intent durable, previous file set may be incomplete. |
| `Bd` | `rolledBack` | Previous file set was verified; only removal remains. |
| `Bc` | `committed` | New file set and new service were verified; only cleanup remains. |
| `Bx` | damaged | Unreadable, unsafe, foreign schema, or failed validation. |

Service journal:

| Code | Phase | Meaning |
|---|---|---|
| `S0` | absent | No service journal. |
| `Sp` | `preparing` | Service journal durable, no privileged action recorded. |
| `Sb` | `jobBootedOut` | Previous job verified absent or none was loaded. |
| `Sr` | `rightReplaced` | Installed right written and read back. |
| `Sj` | `jobBootstrapped` | Installed launch daemon bootstrapped and read back. |
| `Sc` | `committed` | New service state verified and commit record durable. |
| `Sk` | `rollbackStarted` | Service rollback intent durable. Never a file rollback input. |
| `Sd` | `rolledBack` | Previous service state verified restored. |
| `Sx` | damaged | Unreadable, unsafe, foreign schema, or failed validation. |

File set:

| Code | Meaning |
|---|---|
| `P` | Every destination matches its FJ previous record. Computed only when a readable FJ has phase `Fp` or `Fr`. |
| `N` | Every destination matches its FJ new record. |
| `M` | A readable `Fr` journal exists; each destination matches its previous or new record, or is absent for a previous-present operation whose verified backup is present. Every previous-present operation whose destination is not already previous has its verified backup. The set is not uniformly `P` or `N`. |
| `U` | Any destination or required backup is foreign, unsafe, unreadable, or missing where restoration requires it. |
| `P0` | The FJ is absent. This is not a file-content predicate. A terminal `Bd` or `Bc` record reports an earlier decision; it does not establish the current file set or directory contents. |

`P0` labels the state after the FJ is removed. A later run cannot recompute
`P` or `N`, so it must not pretend to. The draft rows below propose removal of
the binding and, when present, the service journal when the transaction's
backup directory and temporaries are absent. Whether that can safely release
the last fence is unresolved and remains under the review hold. `P0` never
authorizes removing a backup, a destination file, or a created directory. Those
actions require a readable FJ and a fresh `P`. A `Bd` row that needs to remove a
backup or a directory requires `Fp` or `Fr` and `P`.

Service observation for a bound transaction:

| Code | Meaning |
|---|---|
| `W0` | Stored right matches B previous presence and policy. Job absent. |
| `WL0` | Stored right matches B previous presence and policy. Job loaded, and B `previousJobLoaded` is `1`. This observation does not prove the job's origin and never authorizes cleanup. |
| `WL` | Stored right matches B previous presence and policy. Job loaded. Allowed only for a forward service action. |
| `WN` | Stored right **policy** equals the installed right policy. Job loaded. |
| `WX` | Anything else: right other or unreadable, job unexpected or unknown, or an observation failure. |

`WN` does not compare the stored authd bytes to the FJ digest. authd adds
metadata, so the raw bytes differ after a correct write. The FJ `newSHA256` for
the start-right artifact is the digest of the installed plist file on disk. The
service journal's `installedRightSHA256` is that same file digest. `WN` parses
the stored right with `AuthorizationRightPolicyParser` and compares the
resulting `AuthorizationRightPolicy` to the policy parsed from the installed
right file and recorded in the service journal. This is the same predicate that
`sameRight` and `classifyRight` use today.

## 4. Durable order

The corrected one-line order is:

> file journal, binding, preparative directories, file replacement, file
> commit, service journal, service actions, service commit, binding commit,
> backups, file journal, service journal, binding.

The service journal is written after the file commit and before the first
service action. In bound mode it is removed after the FJ removal and before the
binding removal. An implementer who writes the service journal after a service
action has inverted the order and broken the design.

The binding is written before the first file mutation and removed last. The file
journal commit is the pivot: before it, a file rollback is possible; after it,
recovery is forward only. The service journal is written only after the FJ
commit, so the transaction cannot write the right or bootstrap the job without a
committed file set. This structural fact is necessary but not sufficient. It
does not prove that launchd has not loaded the installed plist at a boot. That
is why every file restore also requires a fresh service observation in section
8.

The preparative directories are created after B `bound` and before FJ
`replacing`, not after `replacing` as the reviewed ladder said. The backup
directory must be durable before the first `moveToBackup`. Creating it after
`Fr` would leave a durable `replacing` journal whose first move has no backup
parent, and a crash would need a special case. The reviewed ladder is corrected
below. `Coordinator.install` already creates `requiredDirectories` before it
writes `replacing`, so this revision matches the source rather than the earlier
text.

The install ladder:

| Step | Durable point | Crash observation |
|---|---|---|
| 1 | Lease and global refusals | No record. |
| 2 | FJ `preparing` | `B0 Fp S0 P`. |
| 3 | Observe pre-state, B `bound` | `Bb Fp S0 P`. |
| 4 | Create planned directories, sync each | `Bb Fp S0 P`. No file moved. |
| 5 | FJ `replacing` | `Bb Fr S0 P`. |
| 6 | Move backups, copy new files, verify each | `Bb Fr S0 M`. |
| 7 | Verify the new set | `Bb Fr S0 N`. |
| 8 | FJ `committed` | `Bb Fc S0 N`. |
| 9 | SJ `preparing` | `Bb Fc Sp N`. |
| 10 | Boot out previous job, SJ `jobBootedOut` | `Bb Fc Sb N`. |
| 11 | Write installed right, SJ `rightReplaced` | `Bb Fc Sr N`. |
| 12 | Bootstrap, SJ `jobBootstrapped` | `Bb Fc Sj N`. |
| 13 | Verify new service, SJ `committed` | `Bb Fc Sc N`. |
| 14 | B `committed` | `Bc Fc Sc N`. |
| 15 | Remove backups, backup directory, temporaries | `Bc Fc Sc N`. |
| 16 | Remove FJ | `Bc F0 Sc P0`. |
| 17 | Remove SJ | `Bc F0 S0 P0`. |
| 18 | Remove B | Nothing. |

The rollback ladder, entered only before step 8:

| Step | Durable point | Crash observation |
|---|---|---|
| 1 | Observe service, require `W0`, write B `rollingBack` | `Bk Fp S0 P`, `Bk Fr S0 P`, or `Bk Fr S0 M`. |
| 2 | Restore each destination from its backup | `Bk Fr S0 M`. |
| 3 | Verify the previous set | `Bk Fp S0 P` or `Bk Fr S0 P`. |
| 4 | Write B `rolledBack` | `Bd Fp S0 P` or `Bd Fr S0 P`. |
| 5 | Remove backups, temporaries, backup directory, created directories | `Bd Fp S0 P` or `Bd Fr S0 P`. |
| 6 | Remove FJ | `Bd F0 S0 P0`. |
| 7 | Remove B | Nothing. |

`Bd` means "the previous file set was verified; only removal remains". It never
means "the journals are gone". The FJ removal happens after `Bd` is durable, so
a crash can never leave `Bk` with no FJ.

The removal order inside steps 15 and 5 is fixed:

1. Exact record temporaries in the state directory.
2. Exact file temporaries for this transaction in the destination directories.
3. Transaction backups, each with its previous digest.
4. The transaction backup directory, only when empty.
5. Created directories, in reverse order, only when empty.
6. The FJ.
7. The SJ.
8. The B.

The order prevents a non-empty directory from blocking a removal and prevents a
record from being removed before the operations it authorizes have finished. A
failure at any step stops the run. No later step runs.

## 5. Durable write, confirm, and removal rules

These rules apply to the FJ, the B, and the SJ. There is no record-specific
exception.

### 5.1 One write contract

Every phase write goes through one store contract:

1. Validate the record.
2. Encode it with sorted keys.
3. Remove the exact temporary name for this record and transaction.
4. Create the temporary with `O_EXCL | O_NOFOLLOW`, write all bytes, set the
   mode, and `fsync` the file.
5. Rename the temporary over the record.
6. `fsync` the parent directory.
7. Read the record back and compare it to the intended record.

The write is **durable** only when steps 1 through 7 all succeeded. A return
from `rename` without a successful directory `fsync` is not durable.

The reviewed text said `InstallJournalStore.write` "has no read-back today" and
"gains the same `AtomicWriter` seam". The seam already exists:
`InstallJournalStore` has the same `AtomicWriter` type and test initializer as
`ServiceJournalStore`, and it already maps `InstallTreeError.writeUncertain` to
`CoordinatorError.journalWriteUncertain`. What it does not have is the
read-back classification in section 5.2 and the digest-verified removal in
section 5.5. The FJ store is not missing the seam. The reviewed disposition
(F19) was inaccurate and is corrected in section 17.

The FJ and the B use the same seam so the hermetic tests can fail the
post-rename sync. The test sequence in section 15 covers the FJ, B, and SJ.

### 5.2 The unknown-write rule and the install catch

If a write reports any error, the run stops. It performs no file mutation, no
service action, and no removal. It does not "complete the rollback", "remove the
record", or "treat the written phase as written".

Before it stops, it reads the record back once and classifies the report:

- Intended bytes visible: report `writeOutcomeUnknown`. The record may or may
  not survive a power loss. Nothing else runs.
- Intended bytes not visible: report `writeFailed`. The old phase is the
  state. Nothing else runs.

The read-back is an observation of the current namespace. It is not proof of
durability and it never authorizes an action. It only selects the report and the
phase that the next run will confirm. This is compatible with the current
`InstallTree.writeAtomic` comment that a read-back is not a durability proof.

The next run that acts on the record starts with **confirm**: it rewrites the
observed phase durably, with the same content, and reads it back. Confirm is
allowed only when no mutation happened in the failed run, which is guaranteed by
this rule. Confirm is not a new phase and performs no external action. If
confirm fails, the run stops again. The executor calls confirm before its first
decision, for every phase record it observed. An absent record is not confirmed.

This rule closes the first review counterexample. A `B rollingBack` record that
is visible but unsynced never authorizes a restore. The restore begins only
after the directory sync returns success. If the record is lost, the binding is
still `bound` and the file set is still `P`, because no restore ran.

This rule also closes the `FJ committed` counterexample. If the commit write is
visible but unsynced, no `finishCommitted` runs, no backup is removed, and no
binding commit is written. If the commit is lost, the FJ is still `replacing`
and the rollback ladder restores `P`. If the commit survives, the forward ladder
continues. Both outcomes are in the matrix.

`InstallCoordinator.install` has one extra obligation, stated here so an
implementer cannot miss it. Every FJ write in `install` must pass through the
same classifying wrapper, including the first `preparing` write, and the
`catch` around the replacement and commit section must check
`.journalWriteUncertain` **before** it considers a rollback or a
`finishCommitted`. The order is:

1. `simulatedCrash`: rethrow.
2. `journalWriteUncertain`: rethrow. Write nothing. Roll back nothing. Remove
   nothing. Call no service action.
3. A committed cleanup failure: throw `recoveryRequired` and keep the FJ and
   backups.
4. A known pre-commit failure: run the rollback ladder with `NoFaults()`.
5. Any other error: map and throw.

The first `preparing` write is currently outside a local `do`/`catch`, so the
error propagates before any mutation and the outer `run` maps it. That is safe
today but it is not a stated rule and it has no post-rename test. The design
requires the wrapper and the test. Section 15.3 names the three write points.

### 5.3 The unknown-removal rule

A record or backup removal is:

1. Open the object with `O_NOFOLLOW`.
2. Read and hash its exact bytes.
3. Compare the digest to the digest captured for this object in this run.
4. Compare the device and inode to the name.
5. `unlinkat`.
6. `fsync` the parent directory.

A missing object is clean only when the step that removed it was authorized and
the expected digest is known. If `unlink` succeeds and the directory `fsync`
fails, the removal outcome is unknown. The run stops. It performs no further
removal and no further mutation.

The next run re-observes the object. Both outcomes are legal matrix inputs:
present and absent. No removal is retried in the same run.

An unproven service journal removal cannot be followed by an FJ or binding
removal in the same run, because the ladder stops. Recovery after a lost unlink
still depends on the matrix and remaining evidence; it may require manual
repair.

### 5.4 Temporary collision

All writes of one record use one transaction-derived temporary name. A crash
mid-write can leave it. `writeAtomic` uses `O_EXCL`, so the next write would
otherwise fail with `alreadyExists`. The proposed store removes only an exact,
authorized temporary name before a write or recovery observation. A similar
prefix alone is not authority to delete an object. Ownership and identity checks
for this sweep are not yet specified; until they are reviewed, a temporary that
cannot be proven safe stops recovery and stays in place.

### 5.5 Digest-verified removal

The earlier stores passed `expectedDigest: nil` and did not check exact mode or
bytes at removal. The current uncommitted journal repair captures an observed
digest and uses exact-mode, digest, owner, type, link-count, and ACL checks before
unlink. An independent review found that contract sound under its documented
cooperative-writer assumption, while noting the remaining check-to-unlink race.
This does not implement the binding or its executor. A damaged or changed
record must still be kept by any future bound implementation.

The reviewed text said both methods "check only type, owner, and mode". That was
also imprecise: they check type, owner, link count, and no group or other write
bit, not the exact mode. The design uses the precise list.

### 5.6 Pure decision and re-observation

`decide(observation) -> action` is pure and total. It reads no file, calls no
command, and writes nothing. The executor:

1. Acquires the lease.
2. Inspects and, only when authorized, sweeps exact record temporaries. A
   failed or unproven sweep stops the run and keeps the records.
3. Observes under the lease, including remaining residue.
4. Confirms every observed phase record (section 5.2).
5. Calls `decide`.
6. Performs exactly one action.
7. Re-observes.
8. Repeats until a terminal outcome or a refusal.

The executor stops after 32 actions. If the same action is chosen twice with an
identical observation digest, it refuses. An observation digest covers the
three record digests, the file set state, the service observation, the boot
identifier, and the residue class. Progress is a changed digest. This makes
"the second recovery is idempotent" a testable property: the second run either
returns the same terminal outcome or advances one step with a changed digest,
never repeats an action.

## 6. Global refusals

These checks run before the decision matrix and outrank every row, including
terminal cleanup.

| Code | Condition | Result |
|---|---|---|
| `G1` | No valid exclusive lease, a busy lock, or a passed lease that does not match the current inodes. | Refuse. |
| `G2` | State directory missing, wrong owner or mode, or unsafe. | Refuse. |
| `G3` | `cleanup-blocked` marker present. | Refuse. |
| `G4` | `engine-session` launch intent present. | Refuse. |
| `G5` | `start-journal` present, unreadable, or malformed. | Refuse. |
| `G6` | Any FJ, B, or SJ is unreadable, unsafe, a symlink or other non-regular object, a hard link, wrong owner or mode, an unsupported schema, or fails validation. | Refuse. `status()` reports it without throwing. |
| `G7` | Record identity mismatch: B file journal schema differs from the FJ schema, B transaction differs from FJ, B identity digest differs from the recomputed FJ identity, SJ `installTransactionID` differs from B, SJ installed **file** digests differ from the FJ new digests, or SJ previous right presence or policy differs from B. | Refuse. |
| `G8a` | Bound install: no service adapter, no binding store, or a binding already present before install. | Refuse. |
| `G8b` | Recovery: a binding is present and no service adapter is configured, or an SJ is present and no service adapter is configured. | Refuse. A configured adapter with no binding can serve a service-only recovery. |
| `G8c` | Exactly one of the binding store and the service runtime is configured, or the sandbox initializer receives either. | `init` throws; recovery refuses. |
| `G9` | Service observation unavailable, `unexpected`, or `unknown` where the row needs it. | Refuse. |
| `G10` | Boot session identifier unavailable where the rollback boot rule needs it, or the settle rule in section 8.3 cannot be met. | Refuse. |
| `G11` | Step budget exceeded, or the same non-terminal action repeats without a changed observation. | Refuse. |
| `G12` | A caller-supplied digest is offered as authority. | Refuse; recompute. |
| `G13` | The service transaction is asked to act on a bound transaction without a valid bound context, or a bound context names a different transaction or identity. | Refuse before any service action. |

`G8a` and `G8b` replace the reviewed `G8`. The reviewed rule forbade a service
adapter when B was absent, which made a first bound install impossible because
the adapter must exist before B can be written. The rule is now split by
operation. `G3`, `G4`, and `G5` outrank a terminal binding. A terminal binding
is not removed while a cleanup marker or a start journal is present. This is
deliberate: a started engine may still own routes, and a cleanup block is a
person's stop signal. The availability cost is stated in section 16.

The binding is not a global refusal for the coordinator. It is a decision
input. For the helper and the direct engine, the binding name is a global
refusal file, like the two journals.

## 7. Actions

Every action below starts with confirm of the records it reads (section 5.2) and
a fresh service observation where the row needs one. Any failure stops the run
and keeps every record. The numbered steps are logical steps. When an action
removes more than one class of object, it uses the eight-step removal order in
section 4. The numbers below are not a second removal order.

**`NONE`**: return `nothingToRecover`.

**`REFUSE`**: return a stable reason code. Write nothing. Remove nothing.

For every cleanup action below, a planned directory name is not proof that the
transaction created the current directory. Unless a future durable record
proves its actual identity and a fresh check matches it, leave that directory
in place and retain the FJ and B. A nonempty transaction backup directory,
backup root, or removable created directory also stops cleanup and retains the
records. Do not ignore a failed or false `removeDirectoryIfEmpty` result. The
current FJ does not provide the proposed actual-directory identity proof, so
these cases remain blocked pending a separately reviewed schema and race model.

**`REMOVE-FJ`**: require `Fp`, require `P`, require no residue. Remove each
created directory in reverse order when empty, remove exact record temporaries,
remove the FJ through the digest-verified helper. This is the only action for a
pre-binding journal. A directory that is not empty stops the run and keeps the
journal. A backup file or transaction backup directory present under `Fp` is
residue and is refused, never removed. `Fp` cannot authorize a backup removal
because no backup can exist under a `preparing` journal in this build. If one
exists, the state is incoherent and a person must inspect it. This resolves the
`Fp` backup deletion conflict: the reviewed `REMOVE-FJ` said "remove created
directories" without saying that a backup under `Fp` is a refusal, and a
transaction backup directory that is not empty would otherwise be treated as a
failed empty removal rather than as residue.

**`ABORT`**: the pre-commit file rollback.

1. If B is `bound`, re-observe and require `W0` (section 8). Write B
   `rollingBack` durably.
2. If B is `rollingBack`, confirm it.
3. Re-observe and require `W0` again, including the settle rule. A change stops
   the run.
4. Restore each operation in reverse order. If the destination matches its
   previous record, leave it alone; remove a redundant backup only after its
   previous digest, size, and mode are verified. If a previous-present
   destination is absent or matches the recorded new file, restore its verified
   previous backup. Recheck the destination immediately before the rename. If a
   previous-absent destination matches the new file, remove that file. Any
   missing required backup, foreign destination, failed check, or ambiguous
   state stops the run and keeps the records.
   A restore completes only after the rename and both affected parent-directory
   syncs succeed. A failure after rename has unknown outcome: stop immediately,
   do not write `Bd` or delete another backup, and re-observe on the next run.
   The gaining parent is synced before the losing parent. This ordering and its
   power-loss behavior require independent review and disposable-VM evidence;
   they are not proven by a visible read-back.
5. Remove exact file temporaries and record temporaries.
6. Verify the previous set.
7. Re-observe the job and require absence under the settle rule in section 8.3.
   A loaded job stops the run before `Bd` is written. This is the post-restore
   observation. It catches a load that settled during the restore. It does not
   catch a job that loaded from the new plist before the restore.
8. Write B `rolledBack` durably.
9. Remove each created directory in reverse order when empty. Remove the
   transaction backup directory and the backup root when empty. Remove the FJ
   durably. Remove B durably. Stop after any unproven removal.

**`FORWARD`**: the post-commit forward path. It is used only when no service
journal exists.

1. Require `Fc`, `N`, and `W0` or `WL`. Require the observed previous right to
   equal B's previous right. `WN` and `WX` refuse here because no service
   journal exists to prove who wrote the installed right.
2. Call the service transaction's `apply` with `installTransactionID` equal to
   the binding transaction and with the bound context. `apply` writes the SJ
   `preparing` itself and checks the reverse binding fence (section 11.3). It
   requires its previous right and job observations to equal the context before
   writing SJ `preparing`, then rechecks the relevant observations before the
   bootout and before the right write. A mismatch stops before the next write
   or service action. It keeps the SJ through `committed`.
3. Read the SJ back and require `Sc`, the same install transaction, the same
   installed file digests, and the same previous right as B. A mismatch stops
   the run and keeps everything.
4. Re-observe and require `Sc` and `N`, and require `WN` by policy.
5. Write B `committed` durably.
6. `CLEAN-COMMIT`.

**`FINISH-SERVICE`**: the service journal exists and the file set is committed.

1. Require `Fc`, `N`, and the SJ phase.
2. Run the service transaction's recovery with the bound context and with
   journal retention. It may reach `Sc`, `Sd`, or refuse.
3. `Sc` becomes `CLEAN-COMMIT` after writing B `committed`.
4. `Sd` refuses. The service rolled back after the file set committed. A person
   must decide.
5. `Sk` is finished to `Sd` or refuses. It is then `Sd` and refuses. It is never
   routed to the file rollback ladder.

**`CLEAN-COMMIT`**:

1. Require `Bc`, a fresh `WN`, and `N` whenever the FJ is present. Require `Sc`
   whenever the SJ is present.
2. If the FJ is present, verify `N`. Then remove exact record and file
   temporaries, remove each backup with its previous digest, remove the
   transaction backup directory and the backup root when empty, and remove the
   FJ durably. A missing backup is clean. A changed backup stops the run. Do not
   remove the install root or its `engine` and `install-support` directories:
   they hold the new file set.
3. Remove the SJ durably when present.
4. Remove B durably.
5. Stop after any unproven removal.

**`CLEAN-ROLLBACK`**:

1. Require `Bd` and a fresh `W0`. Any loaded job refuses and keeps the binding.
2. If the FJ is present, verify `P` again. Remove exact record and file
   temporaries. Remove each backup named by a previous-present operation with
   its previous digest. A backup for a previous-absent operation, or a digest
   mismatch, stops the run. Then remove the transaction backup directory and
   backup root when empty and authorized, and remove each proven-created
   directory in reverse order when empty. An unproven or nonempty directory
   stops the run before FJ or B removal.
3. If the FJ is absent, require `P0` and require that the transaction backup
   directory, any transaction-named backup, and any transaction temporary are
   absent. `P0` authorizes only record removal. It never authorizes a file
   removal.
4. Remove the FJ durably.
5. Remove B durably.
6. Stop after any unproven removal.

`CLEAN-ROLLBACK` never restores, creates, replaces, or removes a destination
file. It never writes the right and never boots a job out or bootstraps one.
An earlier version allowed `WL0` here. That is unsafe to infer from a loaded
job: removing the binding also removes a start fence while the loaded job's
origin remains unknown.

**`REMOVE-SJ`**: require `Sc` and a fresh `WN`, remove the SJ through the
digest-verified helper.

**`REMOVE-B`**: require the row's file and service conditions, remove B through
the digest-verified helper. This is the last action of a transaction.

**`SERVICE-ONLY`**: no FJ and no B. Delegate to the service transaction's own
recovery. A service adapter is required. It removes the SJ only at its own
terminal states. This action never touches a file.

## 8. Rollback preconditions

A file restore runs only when all of these hold in the same run, after the
`B rollingBack` record is durable.

### 8.1 Service state is observed, not inferred

The rule is: **no service action is provable and the job is absent**. "The
service journal is absent" is not enough. The new launch daemon plist is
installed at its fixed path during the file replacement. launchd may act on that
plist at any boot, with no journal at all. The coordinator therefore observes
the launchd job and the stored right before every restore.

A restore requires `W0`:

- The stored right matches the presence and policy recorded in B.
- No job with the fixed label is loaded.
- The rollback boot rule and settle rule in section 8.3 hold.

Any loaded job refuses a restore. This includes a job that was loaded before the
binding and a job that a boot loaded from the new plist. The read-back cannot
attribute a registration: the label, plist path, and program path are fixed, so
an old and a new registration print the same three lines. A loaded job with no
service journal is ambiguous and is never booted out or rolled back by recovery.

A forward action may accept `WL`. Forward replaces the service rather than
inferring it: it writes the SJ, boots out the loaded job through the service
transaction, and bootstraps the installed plist. That is a deliberate replace,
not an attribution.

### 8.2 The right is compared by policy

The right must match B's previous presence and policy. Exact bytes are not
required. The comparison uses the same policy equality predicate as the service
transaction, including the optional comment field. The service transaction
already classifies a stored definition whose policy equals both the previous and
installed policies as ambiguous and uses the journal phase to decide. The
binding has no service journal in a rollback, so it never treats such a right as
installed. It compares policy equality only.

The installed side uses the same rule. `WN` compares the stored right policy to
the installed right policy. It does not compare raw authd bytes to the FJ digest.

### 8.3 The boot rule and the settle rule

B records the boot session identifier from `kern.bootsessionuuid`, lowercased.
The value is readable without root and is not a secret.

- If `previousJobLoaded` is `0`, a job must be absent. The boot identifier is
  not needed for attribution, but absence is accepted only after the settle
  rule below.
- If `previousJobLoaded` is `1` and the current boot differs from B, an absent
  job is explained by the boot cycle. The restore may proceed after the settle
  rule.
- If `previousJobLoaded` is `1` and the current boot equals B, an absent job is
  not explained. Something else removed the registration. The run refuses.
- If the boot identifier cannot be read, the last case refuses. The first case
  may proceed because it never depended on the boot, but it still needs the
  settle rule.

**Settle rule.** launchd can settle after a command or a boot. One observation
is not enough even when the previous job was absent. A restore requires two
consecutive absent observations of the fixed label, separated by at least 2
seconds of monotonic time and at most 10 seconds total, with the right also
observed consistently. If a job appears during the window, the run refuses. For
`previousJobLoaded == 1`, the two observations plus the boot rule are required.
For `previousJobLoaded == 0`, the two observations are required and the boot
identifier is not used.

No finite observation proves that launchd will not load the plist later. The
settle rule narrows the window. It does not close it. To narrow the remaining
race, the rollback observes the job again after the last file is restored and
before it writes `Bd`. A job that is loaded at that observation stops the run
and keeps the FJ and every backup. That catches a load that settled during the
restore. It does not catch a job that loaded from the new plist before the
restore and remains loaded while the files are replaced. That is the residual
race in section 17. This design does not claim the race is closed. The reverse
restore order restores the start right, the launch daemon plist, the helper, and
the engine, so a job can load the previous plist before the helper and engine
are restored and then run against a partly restored file set. The post-restore
observation is the only check this design can make.

This rule applies even when the previous job was absent. The reviewed text said
the boot identifier was "not needed" in that case, which read as if one
observation were sufficient. It was not. The settle rule is the correction.

A cross-boot restore leaves the previous plist in place, so launchd loads the
previous job at the next boot. The job is absent until then. This is an
availability difference, not a safety difference. It is reported.

### 8.4 Cleanup after a reboot at `Bd`

After a crash and reboot, launchd may load a job while `Bd` is present. The
previous file at the fixed path does not prove the loaded job's origin, and
the binding's earlier boot UUID does not prove that the reboot occurred after
`Bd`. This draft refuses cleanup and keeps the binding while any job is loaded.
That can require manual recovery. A future automatic path needs durable
terminal boot evidence and a separately reviewed attribution argument.

### 8.5 No abort after the service journal exists

`recover()` never writes `rollbackStarted`. Only `apply`'s failure path writes
it. Recovery attempts to move forward from `preparing`, `jobBootedOut`,
`rightReplaced`, or `jobBootstrapped`, but current recovery can refuse a loaded
job in `jobBootedOut` or `rightReplaced`. No automatic completion is claimed for
those cases. It does not offer a cancel.

The binding does not add a cancel. An operator who wants to abandon an install
can do so only before the service journal exists, and only when the job is
absent. Once the SJ is durable, recovery is forward only unless the SJ itself is
`rollbackStarted` or `rolledBack`. This is a product limit, not an oversight.
It is stated in the operator text so nobody expects a cancel after a crash.

## 9. Decision matrix

Rows are evaluated in order. Global refusals run first. A row that says `REFUSE`
writes nothing. The final default row refuses every combination not named. The
matrix is a partition, not a sample. Section 9.7 defines the completeness test.

`W0`, `WL0`, `WL`, `WN`, and `WX` are defined in section 3.4. `P0` is the
no-FJ terminal predicate and is defined in section 3.4.

### 9.1 No binding

| Row | B | FJ | SJ | Files | Other | Action |
|---|---|---|---|---|---|---|
| R01 | `B0` | `F0` | `S0` | any | no residue | `NONE` |
| R02 | `B0` | `F0` or `Fp` | `S0` | any | residue present | `REFUSE` (unnamed residue) |
| R03 | `B0` | `Fp` | `S0` | `P` | no residue | `REMOVE-FJ` |
| R04 | `B0` | `Fp` | `S0` | `N`, `M`, or `U` | any | `REFUSE` |
| R05 | `B0` | `Fr` or `Fc` | `S0` | any | any | `REFUSE` (legacy file transaction, no binding) |
| R06 | `B0` | `F0` | any present | any | no residue | `SERVICE-ONLY` |
| R07 | `B0` | `F*` present | `S*` present | any | any | `REFUSE` |
| R08 | default | any | any | any | any | `REFUSE` |

R03 is the window between the FJ write, the B write, and the preparative
directories. No mutation is possible before B `bound` is durable, and the
directories are empty, so a `preparing` FJ with `P` is removed. A backup under
`Fp` is residue and is R02, not R03. R05 is the legacy path. The earlier design
allowed a legacy file rollback; this design refuses it, because without B there
is no recorded pre-state, no boot identifier, and no proof that the service was
not acted on.

### 9.2 Binding bound

| Row | B | FJ | SJ | Files | Service | Action |
|---|---|---|---|---|---|---|
| R10 | `Bb` | `Fp` | `S0` | `P` | `W0` | `ABORT` |
| R11 | `Bb` | `Fp` | `S0` | `P` | `WL`, `WN`, or `WX` | `REFUSE` |
| R12 | `Bb` | `Fp` | `S0` | `N`, `M`, or `U` | any | `REFUSE` |
| R13 | `Bb` | `Fr` | `S0` | `P`, `M`, or `N` | `W0` | `ABORT` |
| R14 | `Bb` | `Fr` | `S0` | `U` | any | `REFUSE` |
| R15 | `Bb` | `Fr` | `S0` | any | `WL`, `WN`, or `WX` | `REFUSE` |
| R16 | `Bb` | `Fc` | `S0` | `N` | `W0` or `WL` | `FORWARD` |
| R17 | `Bb` | `Fc` | `S0` | `N` | `WN` or `WX` | `REFUSE` |
| R18 | `Bb` | `Fc` | `S0` | not `N` | any | `REFUSE` |
| R19 | `Bb` | `Fc` | `Sc` | `N` | `WN` | `FINISH-SERVICE`, then `CLEAN-COMMIT` |
| R20 | `Bb` | `Fc` | `Sp`, `Sb`, `Sr`, or `Sj` | `N` | observable and permitted by service recovery | `FINISH-SERVICE` |
| R20a | `Bb` | `Fc` | `Sp`, `Sb`, `Sr`, or `Sj` | `N` | unavailable, unknown, or refused by service recovery | `REFUSE` |
| R21 | `Bb` | `Fc` | `Sk` | `N` | any | `FINISH-SERVICE`, then `REFUSE` |
| R22 | `Bb` | `Fc` | `Sd` | `N` | any | `REFUSE` |
| R23 | `Bb` | `Fc` | `Sx` | `N` | any | `REFUSE` |
| R24 | `Bb` | `Fp` or `Fr` | `S*` present | any | any | `REFUSE` (cannot exist under this order) |
| R25 | `Bb` | `F0` | any | any | any | `REFUSE` (binding without FJ) |
| R26 | `Bb` | `Fx` | any | any | any | `REFUSE` |
| R27 | default | any | any | any | any | `REFUSE` |

R12 is the added `Bb Fp S0 N` row, and it also covers `M` and `U`. `N` under
`Fp` cannot be produced by this build: no file is copied before `Fr`. If it is
observed, it is from an older build, an external actor, or a bug. The file set
is not restored and the binding is kept, because `Fp` does not authorize a
restore of a set that is newer than the journal. This row was missing from the
reviewed matrix and is the first completeness defect the review found.

R13 with `N` looks like a completed replacement that never wrote `Fc`. That is
possible only if the process died between verification and the commit write.
`ABORT` restores `P`. R13 with `M` restores the mixed set.

R15 with `WL` is the exact case where a job may have loaded the new plist at
boot. The files are not rolled back and the job is not booted out.

R16 with `WL` is a forward replace, not an attribution. The service transaction
observes, boots out, and bootstraps. It records `previousJobLoaded` in the new
SJ.

R20 is an attempt, not a guarantee of forward completion. The current service
recovery refuses some loaded-job observations in `Sb` and `Sr`; R20a keeps the
records for those cases. The exact permitted service observations and any future
forward action remain under the review hold and need an independent matrix and
test review before implementation.

### 9.3 Binding rolling back

| Row | B | FJ | SJ | Files | Service | Action |
|---|---|---|---|---|---|---|
| R30 | `Bk` | `Fp` | `S0` | `P` | `W0` | `ABORT` |
| R30a | `Bk` | `Fr` | `S0` | `P`, `M`, or `N` | `W0` | `ABORT` |
| R31 | `Bk` | `Fp` | `S0` | `M`, `N`, or `U` | any | `REFUSE` |
| R31a | `Bk` | `Fr` | `S0` | `U` | any | `REFUSE` |
| R32 | `Bk` | `F0` | `S0` | `P0` | `W0` | `REFUSE` (unreachable; keep B) |
| R33 | `Bk` | `F0` | `S0` | not `P0` | any | `REFUSE` |
| R34 | `Bk` | `Fc` | any | any | any | `REFUSE` |
| R35 | `Bk` | any | `S*` present | any | any | `REFUSE` |
| R36 | `Bk` | `Fp` or `Fr` | `S0` | `P` or `M` | not `W0` | `REFUSE` |
| R37 | default | any | any | any | any | `REFUSE` |

R32 is the state the earlier draft could produce: `rollingBack` with no
journals. With `Bd` written before the FJ removal, this build cannot produce it.
If it is observed, it is from an older build or an external change. The binding
is kept, never removed, because the file set and the missing FJ cannot be
reconciled. `P0` here is a label for the observed absence of the FJ, not a claim
that the previous set was verified.

### 9.4 Binding rolled back

| Row | B | FJ | SJ | Files | Service | Action |
|---|---|---|---|---|---|---|
| R40 | `Bd` | `Fp` or `Fr` | `S0` | `P` | `W0` | `CLEAN-ROLLBACK` |
| R41 | `Bd` | `Fp` or `Fr` | `S0` | `M`, `N`, or `U` | any | `REFUSE` (no destructive cleanup) |
| R42 | `Bd` | `F0` | `S0` | `P0` | `W0`, no residue | `REMOVE-B` |
| R43 | `Bd` | `F0` | `S0` | `P0` | any, residue present | `REFUSE` |
| R44 | `Bd` | `F0` | `S0` | `P0` | `WL0`, `WL`, `WN`, or `WX` | `REFUSE` |
| R45 | `Bd` | `Fc` | any | any | any | `REFUSE` |
| R46 | `Bd` | any | `S*` present | any | any | `REFUSE` |
| R47 | `Bd` | `Fx` | any | any | any | `REFUSE` |
| R48 | default | any | any | any | any | `REFUSE` |

R41 is the added row for `Bd` with `Fp`/`Fr` and a mixed, new, or unsafe file
set. The reviewed matrix had no row for `Bd Fp/Fr S0 M/N/U`, so a reader could
mistake the missing row for a cleanup permission. It is a refusal: `Bd` says the
previous set was verified, but a fresh observation that no longer matches `P`
means something changed after the rollback. No backup or directory is removed.

R42 uses `P0`, not `P`. After the FJ is removed, `P` cannot be recomputed. The
durable `Bd` record plus the absence of transaction residue is the only
reconstructible evidence, and it authorizes only the binding removal. R43
refuses if the transaction backup directory, a transaction-named backup, or a
transaction temporary is present. R44 refuses a loaded job even when
`previousJobLoaded == 1`. With an FJ still present, the default R48 refuses a
loaded job as well.

### 9.5 Binding committed

| Row | B | FJ | SJ | Files | Service | Action |
|---|---|---|---|---|---|---|
| R50 | `Bc` | `Fc` | `Sc` | `N` | `WN` | `CLEAN-COMMIT` |
| R51 | `Bc` | `Fc` | `Sc` | any other | any other | `REFUSE` (keep backups) |
| R52 | `Bc` | `F0` | `Sc` | `P0` | `WN`, no residue | `REMOVE-SJ`, then `REMOVE-B` |
| R53 | `Bc` | `F0` | `S0` | `P0` | `WN`, no residue | `REMOVE-B` |
| R54 | `Bc` | `F0` | `S0` or `Sc` | `P0` | not `WN` | `REFUSE` |
| R55 | `Bc` | `Fc` | `S0` | any | any | `REFUSE` (unreachable) |
| R56 | `Bc` | `F0` or `Fc` | `Sp` to `Sj` | any | any | `REFUSE` (unreachable) |
| R57 | `Bc` | any | `Sk` or `Sd` | any | any | `REFUSE` |
| R58 | `Bc` | `Fx` | any | any | any | `REFUSE` |
| R59 | `Bc` | any | `Sx` | any | any | `REFUSE` |
| R60 | default | any | any | any | any | `REFUSE` |

R50 requires a fresh `WN` and a fresh `N` before any backup is removed. A
service or file change after the binding commit is not rolled back. It is
reported and kept.

R52 is the point where the FJ is gone and the SJ remains. R53 is the point where
only B remains. Both can occur between authorized removals or after an unknown
removal outcome. Neither `P0` nor `WN` proves that destination bytes or created
directories stayed unchanged after the FJ was removed. Whether to release the
last fence in these rows remains unresolved under the review hold. R53 uses
`WN`, not `W0`: a committed transaction must still observe the installed
service policy.

### 9.6 Binding damaged

| Row | B | Action |
|---|---|---|
| R61 | `Bx` | `REFUSE`; keep every record; `status()` reports damage without throwing. |

### 9.7 Completeness and no destructive cleanup on unmatched states

Every durable point in section 4 maps to a row:

- Install step 2 maps to R03. Step 3 maps to R10. Step 4 maps to R10 with `P`.
  Step 5 maps to R13 with `P`. Step 6 maps to R13 with `M`. Step 7 maps to R13
  with `N`. Step 8 maps to R16.
- Install steps 9 to 12 map to R20. Step 13 maps to R19. Step 14 maps to R50.
  Step 15 maps to R50. Step 16 maps to R52. Step 17 maps to R53. Step 18 maps to
  R01.
- Rollback steps 1 to 3 map to R30. Step 4 maps to R40. Step 5 maps to R40.
  Step 6 maps to R42. Step 7 maps to R01.

The matrix is a total function over the product of `B` (6), `FJ` (5), `SJ` (9),
`files` (5), and `service` (5). The named rows cover the reachable and
review-relevant combinations. The default rows R08, R27, R37, R48, and R60
refuse every combination not named. The decision function must be written with
an explicit `default: return .refuse(.unmatchedState)` and must not fall
through to an action.

The rule that makes the default safe is:

> A `REFUSE` row, and the default row, remove nothing, write nothing, and call
> no service action. Only a named row whose action is `ABORT`, `CLEAN-COMMIT`,
> `CLEAN-ROLLBACK`, `REMOVE-FJ`, `REMOVE-SJ`, or `REMOVE-B` may remove an
> object, and only the objects that action names.

A test enumerates the full product, applies `decide`, and asserts:

1. Every combination returns exactly one decision.
2. Every refusal returns the same records it observed and performs no write or
   removal.
3. The only destructive decisions are on the exact rows listed above.
4. The `B0` + `Fr`/`Fc` legacy state is a refusal (R05), not a rollback, in the
   bound decision function.
5. `Bd` + `Fp`/`Fr` + `M`, `N`, or `U` is R41, not `CLEAN-ROLLBACK`.

The reviewed matrix lacked `Bb Fp S0 N` and `Bd Fp/Fr S0 M/N/U`, and it used an
undefined `P` after the FJ removal. This revision adds R12, R41, R43, R44, and
`P0`, and the enumeration test prevents a future edit from leaving a hole.

## 10. Reachability and the review counterexamples

### 10.1 Unknown binding write

A `B rollingBack` write is visible but its directory sync fails. The restore
does not run. Power loss loses the rename. The next observation is `Bb Fr S0 P`
or `Bb Fr S0 M`, depending on how far the file replacement got. Both are R13.
The rollback restarts from the observed file set. There is no `Bb` with a partly
restored `P` set that the matrix cannot name.

### 10.2 Unknown file commit write

An `Fc` write is visible but unsynced. No backup is removed and no `Bc` is
written. Power loss loses the rename. The next observation is `Bb Fr S0 N` and
the row is R13, which restores `P`. If the rename survives, the row is R16 or
R17 and the forward path continues. There is no replay of an `Fc` that names a
backup set already removed.

### 10.3 Unknown service journal removal, all six sites

The service journal removal's unlink succeeds but its directory sync fails. The
run stops before the FJ and B removals. Power loss may restore the SJ. The next
observation is `Bc Fc Sc` (R50), `Bc F0 Sc` (R52), or `Bc F0 S0` (R53). None of
them requires a person. The same rule applies to all six removal sites in
section 11.2, including the forward recovery success site. The reviewed text
counted five and missed `recover`'s completed-install removal. The count is six.

### 10.4 A boot loads the new plist before the service journal

Files are new, `Fc` is durable, `Bb` is durable, no SJ exists, and a reboot
happens before the service step. launchd loads the plist at the fixed path. The
next observation is `Bb Fc S0 N WL`. R16 allows forward: the service transaction
boots the job out and bootstraps the installed plist. A file rollback is not
allowed from this state. If an operator wants to abandon the install, the answer
is no: the file set is committed and a job is loaded. The transaction is forward
only.

If the reboot happened before `Fc`, the observation is `Bb Fr S0 N WL`. R15
refuses. The file set is not restored while a job may be running new bytes. A
person must resolve the service first. This is the availability cost of the
loaded-job rule.

### 10.5 A damaged FJ with a binding

B is `bound` or `committed`, the FJ is damaged, and backups remain. G6 refuses.
B never authorizes a backup removal, because B does not name backups. Install
remains blocked. There is no automated exit. This is deliberate: the earlier
draft removed B and left residue that made every later preflight throw
`orphanArtifacts`. The new rule keeps the evidence and blocks.

### 10.6 A reboot after `Bd`

The previous set is verified and `Bd` is durable. The process crashes and the
host later observes a loaded job. `Bd Fp/Fr S0 P WL0` reaches R48; `Bd F0 S0
P0 WL0` reaches R44. Both refuse and keep B. A reboot does not by itself prove
that the currently loaded job was loaded after `Bd`.

### 10.7 An incoherent `Bb Fp S0 N`

The FJ says `preparing`, but the destinations already match the new set. This
build does not produce it. It could come from an older build, a manual copy, or
a fault. R12 refuses and keeps the binding, the FJ, and the new files. No
rollback runs because `Fp` does not authorize restoring files it never recorded
as moved.

### 10.8 A `Bd` with a changed destination

The FJ is `Fp` or `Fr`, B is `Bd`, and one destination no longer matches `P`.
R41 refuses. The binding is kept, the FJ is kept, and no backup is removed, even
when the other destinations still match. A person must inspect. This is the
"no destructive cleanup on unmatched states" rule.

## 11. Service transaction integration

### 11.1 Bound context

The service transaction currently refuses any file journal
(`PrivilegedServiceTransaction.refuseInstallJournal`, called from `apply` and
`recover`). Under the binding, an FJ is present during every service step. The
bound coordinator passes an opaque `BoundContext` containing the validated FJ
and B identities. The service transaction re-validates that the context matches
the observed records: B transaction equals FJ transaction, the identity digest
recomputes, and the SJ, when present, names the same install transaction and the
same installed **file** digests. The context also carries B's previous right
presence and policy and B's `previousJobLoaded`. Before writing SJ `preparing`,
`apply` requires its own previous-right and job observations to match those
values. It rechecks the relevant observations before bootout and before the
right write. A mismatch must not create a journal with a different pre-state.

The context relaxes only the FJ refusal. It does not relax the cleanup marker,
launch intent, start journal, lock, reverse binding fence, or service
observation checks.

### 11.2 Keep the service journal: six sites

The service journal is removed by the binding, not by the service transaction
in bound mode. Six current removal sites must be routed through one helper with
a retention flag. In bound mode the flag is on and the site keeps the journal.
The reviewed text counted five and missed the forward recovery success site.
This is the corrected table. The line numbers moved during the drift described
in section 0, so the function names are the stable identifiers.

| Site | Function and current behavior | Bound behavior |
|---|---|---|
| 1 | `apply`, after the commit phase is durable: `store.remove()`. | Keep. Return `committed`. |
| 2 | `recover`, `journal.phase == .committed`: `store.remove()`. | Keep. Return `finishedCommit`. |
| 3 | `recover`, completed forward install after the recovery commit: `store.remove()`. | Keep. Return `finishedInstall`. |
| 4 | `finishTerminalRollback`, after verifying the previous right and job: `store.remove()`. | Keep. Return `finishedRollback`. |
| 5 | `finishInterruptedRollback`, after writing `rolledBack`: `store.remove()`. | Write `rolledBack`, keep the SJ. |
| 6 | `rollback`, after writing `rolledBack`: `store.remove()`. | Write `rolledBack`, keep the SJ. |

A bound recovery must not call `recover()` or `finishTerminalRollback`
unchanged. A test asserts that after each of the six outcomes the SJ is still
present. The binding removes the SJ after the FJ and before B, and only for an
`Sc` service state in a bound transaction. An `Sd` service state is refused and
kept. The test matrix covers the `recover` forward success path (site 3), not
only `apply` and rollback.

### 11.3 The reverse binding fence

The coordinator refuses a present SJ (`refuseServiceJournal`). The service
transaction has the matching `refuseInstallJournal`. The binding needs a third
fence on the service side, because the service transaction can remove the SJ,
write the right, or bootstrap a job while a file transaction is active. The
fence is a read-only `BindingProbe` shared by the coordinator and the service
transaction.

`apply` and `recover` call `refuseBindingFence(context:)` before any action:

1. If B is absent and the context is non-nil: refuse
   `boundContextWithoutBinding`.
2. If B is present and the context is nil: refuse
   `boundTransactionRequiresCoordinator`.
3. If B is present and its transaction, file journal identity, previous right
   policy, or `previousJobLoaded` differs from the context: refuse
   `boundContextMismatch`.
4. If B is `rollingBack` or `rolledBack`: refuse `boundRollbackInProgress`. The
   service must not write the installed right or bootstrap while the file side
   is rolling back.
5. If B is `committed`: `apply` always refuses. Only `recover` may verify an
   existing `Sc` journal for removal by the binding coordinator. Never write
   the right, never bootstrap, never boot out.
6. If B is present: set `retainServiceJournal = true` for every removal site.
   The caller cannot turn retention off while B is present.
7. If B is damaged: refuse. The service transaction does not repair it.

The fence also makes the retention flag a derived value, not a caller promise.
A caller that forgets the flag cannot remove the SJ from a bound transaction.

### 11.4 Service journal schema

The service journal schema does not change. The binding does not add a schema 2
service journal. The tie is:

- B names the FJ transaction and its identity digest.
- The SJ's `installTransactionID` names the same transaction.
- The SJ's `installedRightSHA256` and `installedLaunchDaemonSHA256` equal the
  FJ new **file** digests for the start right and the launch daemon.
- The SJ's `installedRightPolicy` is the policy parsed from the installed right
  file. `WN` compares the stored right policy to it.

A terminal service journal with no binding and no file journal is R06. It is
service-only recovery, not a bound transaction. A reinstall does not recreate a
binding for it. A schema 2 service journal cannot exist from this design. If an
experimental build produced one, it is `Sx`, and G6 refuses it.

### 11.5 No service rollback after the file commit

A service rollback after `Fc` leaves new files with the previous service. The
binding does not roll back files and does not remove B. An `Sd` service state is
R22 when the binding is `bound`, and R57 when it is `committed`. Both refuse. A
person decides whether to finish forward or repair by hand. This is the only
honest outcome: the FJ no longer authorizes a restore after it is removed, and B
never did.

## 12. Deletion, residue, and manual repair

### 12.1 Authorized deletions

Only these objects may be removed:

- The exact temporary file for a record and transaction, before a write and by
  exact prefix sweep.
- A backup file named by a readable, validated FJ, with a digest match.
- The transaction backup directory named by the FJ transaction, when empty.
- A created directory named by the FJ, when empty and when its exact mode still
  matches.
- The FJ, SJ, or B, after a digest-verified read-back and only from the phase
  that authorizes the removal.

Never removed: a damaged record; a backup the FJ does not name; a backup under
an `Fp` journal; a record whose phase does not authorize the removal; the lock
files; the sandbox marker; the cleanup marker; the launch intent; the start
journal.

### 12.2 Residue classes and the `Fp` conflict

`install-backup` residue and temporary files are classified, not guessed:

| Class | Condition | Action |
|---|---|---|
| `A0` | No backup root, no residue, and no record temporary. | None. |
| `A1a` | Every backup-root entry is a transaction identifier of a readable, validated FJ whose phase is `replacing` or `committed`. | Removable only by that FJ's bound ladder. A legacy FJ with no binding stays blocked. |
| `A1b` | Any backup-root entry is not such an identifier, or the FJ is absent, damaged, or still `preparing`. | Refuse. Install stays blocked. |
| `A1c` | A file temporary whose exact name is derived from a readable FJ. | Removable by that FJ's ladder. |
| `A1d` | A record temporary with an exact known prefix. | Removable. |
| `A1e` | Any other object under the backup root, or any other temporary-looking object. | Refuse. |

A damaged FJ with residue is `A1b`. There is no automated exit. This is the F5
decision. B does not carry backup digests, so B cannot authorize the cleanup. A
manual repair is out of scope for automation and for this document. Only a
person with a reviewed procedure may remove the residue, and only after
confirming the installed file set. Install remains blocked until then.

The `Fp` conflict is resolved in `REMOVE-FJ` (section 7) and in `A1b`: a backup
entry under a `preparing` journal is residue, not a cleanup input. The
transaction backup directory may be removed only when it is empty and only after
the residue check. The backup root may be removed only when it has no entries.
The action never removes another transaction's backup directory.

### 12.3 What a person sees

`status()` returns:

- `binding`: absent, phase code, damaged reason code, or foreign schema.
- `fileJournal`: absent, phase, damaged, or foreign.
- `serviceJournal`: absent, phase, damaged, or foreign.
- `startJournal`: absent, valid, or damaged with a reason code.
- `serviceAdapter`: configured or absent.
- `residue`: the highest class present, with the entry names.
- `startBlocked`: true when any of `cleanup-blocked`, `engine-session`,
  `start-journal` (present or damaged), `install-journal.json`,
  `service-journal.json`, or `upgrade-binding.json` (present or damaged) is
  present.
- `requiredAction`: none, recover, or manual.

`status()` must not throw for a damaged binding, FJ, SJ, or start journal. It
returns `damaged` with a reason code for wrong type, hard link, owner, mode,
access control list, decode failure, validation failure, or unsupported schema.
It may still throw when no observation is possible: an unreadable state
directory or an unsafe lock file. It does not print the right policy, any token,
or any identity key.

The start journal is included because the reviewed `status()` could throw from
`StartJournalProbe.read` on a malformed record. A malformed start journal is a
refusal, not a status crash. `status()` catches
`CoordinatorError.startJournalUnreadable` and reports `damaged`.

## 13. Refusal lists and drift guards

### 13.1 One list per binary, with the injection seam preserved

The Swift helper has two copies of the journal-name list today:
`isInstallJournalPresent` and `prepare` in `HelperStartExclusion.swift`. One
change can bypass the other. Replace both with one default list:

```
HelperStartExclusionProtocol.refusableFileNames = [
    installJournalFileName,
    serviceJournalFileName,
    bindingFileName,
]
```

`RootStartExclusionStore` keeps its internal injection seam. The initializer
becomes:

```
init(
    directoryPath: String,
    lockFileName: String,
    refusableFileNames: [String],
    expectedOwner: UInt32
)
```

with the public initializer defaulting `refusableFileNames` to the protocol
list. The current `installJournalFileName:` test initializer can remain as a
thin wrapper for tests that inject one name. Tests that cover the full refusal
set use the new list. The seam is not deleted. The hermetic tests still inject
names and an owner; they must not need to create a root directory.

The Rust engine gets one constant and one refusal call:

```
const BINDING_NAME: &str = "upgrade-binding.json";
```

`refuse_start_files` adds it to the existing `fstatat` checks. The check
requires a regular single-link file owned by root, with no group or other
permission and no set-id or sticky bit. A symlink is not followed. Any error
other than `ENOENT` refuses. The check adds no parsing.

`RootStateDirectory.contains` does not check `st_nlink` today. The new
`containsSingleLink` check does. It is used for the three refusal names in the
helper. The engine gets the same `st_nlink == 1` and owner `0` checks directly.

### 13.2 Ordering of the refusal checks

For the helper and the engine, the order is: lock, start journal, launch intent,
cleanup block, install journal, service journal, binding. The order is not a
security property; every check refuses. It is fixed so the reported reason is
stable.

### 13.3 Cross-language guard and its limit

The existing Swift test `testCanonicalLockNameMatchesTheHelperAndRustEngineSource`
reads the Rust source, but it extracts only the lock name. It does not compare
refusal lists today. The reviewed text implied more than the test does. The
extension is:

1. Add a coordinator constant for the three record names.
2. Extract the helper refusal list and the Rust refusal constants from source
   text.
3. Require set equality with the coordinator's three record names.
4. Require every coordinator record name to appear in both lists.

Add a POSIX shell audit, `scripts/macos_refusal_name_check.sh`, that performs the
same comparison for CI without building Swift. It must be plain shell, with no
Python.

The limit: a source-text guard detects drift. It does not prove that an
installed binary refuses the name. An old helper or engine that predates
`upgrade-binding.json` will not refuse it. The binding relies on the lock (if
the old binary participates) and on the file replacement itself. Do not claim
that a present binding blocks every older participant.

## 14. Claims this design rejects

| Claim | Status | Reason |
|---|---|---|
| A visible record is durable. | Rejected. | The rename can be visible before the directory sync. Only a successful sync authorizes the next step. A read-back is an observation, not a durability proof. |
| No service journal means no service action. | Rejected. | launchd can load the installed plist at any boot. The job must be observed and absent. |
| A loaded job can be attributed from `launchctl print`. | Rejected. | Label, plist path, and program path are fixed. Old and new registrations print the same lines. |
| A file rollback may follow a service journal. | Rejected. | The SJ is written after the file commit. A file rollback with an SJ is refused. |
| A binding can authorize backup cleanup. | Rejected. | B does not name backups. Only a readable FJ does. |
| A damaged record may be deleted to unblock installs. | Rejected. | A person must inspect. Automation keeps the record. |
| A caller-supplied digest is authoritative. | Rejected. | The coordinator recomputes it. |
| A phase code may be reused. | Rejected. | Each code names one record and one phase. |
| `rollbackStarted` may route to the file rollback ladder. | Rejected. | It is a service rollback, and the file set is committed. It routes to `FINISH-SERVICE` and then refuses. |
| The lock excludes every process. | Rejected. | It is cooperative. Old binaries, non-participants, and root bypass it. |
| authd stored bytes must match the installed right digest. | Rejected. | authd adds metadata. `WN` compares the parsed policy. The FJ digest is the installed plist file, not the stored bytes. |
| `launchctl` status 113 is universal. | Rejected. | The parser fails closed on any other status or text. |
| One absent observation proves the job is absent. | Rejected. | launchd can settle. The settle rule requires two observations and still does not prove the future. |
| `P` can be recomputed after the FJ is removed. | Rejected. | The digests are gone. `P0` is a record-only terminal predicate, not a file-content check. |
| This design is tested or live. | Rejected. | It is a design. The gate is closed. |
| This design makes the installer installable. | Rejected. | The package and gate are unchanged. |

## 15. Test plan

All tests are hermetic. No test runs as root, calls `launchctl`, writes authd,
changes a route, creates a TUN device, uses the network, or touches a personal
device. The fake `PrivilegedServiceRuntime` and the fake launchd and right
stores provide service observations.

### 15.1 Record and store tests

| Test | What it proves |
|---|---|
| `BindingRecordTests` | Schema, fixed fields, phase set, policy presence rules, no `fromVersion`, no per-file digests. |
| `BindingIdentityTests` | Fixed public vectors for the canonical identity digest, `nil` version encoding, mode hex width, size encoding, operation order, phase excluded. |
| `RecordStoreTests` | FJ, B, and SJ all use the atomic seam; post-rename sync failure returns `outcomeUnknown`; the classification read-back happens; a visible unsynced record stops the run; `install` rethrows before any rollback. |
| `RecordTemporaryTests` | An exact leftover temporary does not cause `alreadyExists`; the sweep removes only exact prefixes; the order in section 4 is used. |
| `RecordRemovalTests` | A changed or damaged record is not removed; a removal sync failure stops the run; a missing record is clean only when authorized; a `0400` record is not accepted as `0600`; a hard link is refused. |
| `BindingStatusTests` | `status()` reports damaged, foreign, unsafe, and absent without throwing for B, FJ, SJ, and the start journal; it prints no policy or secret. |
| `RefusalNameGuardTests` | Helper list equals Rust list equals coordinator names; the shell audit passes; the helper injection seam still works. |
| `BoundPreStateTests` | A mismatched right or job observation refuses before SJ `preparing`; `apply` refuses a committed binding even with an `Sc` journal. |
| `DirectoryOwnershipTests` | A planned-only or replaced directory is never removed; a nonempty backup or created directory keeps FJ and B; an empty authorized backup root is handled before FJ removal. |

### 15.2 Matrix and destructive-cleanup tests

One test per named row R01 to R61, built from a fixture that writes the record
bytes and the fake state directly. Each test asserts:

- The chosen action.
- The exact writes, in order.
- The exact removals, in order.
- The exact refusal reason for a refusal.
- That no record was removed on a refusal.
- That no destination file was removed on a refusal or a `CLEAN-*` action.

The deterministic completeness test enumerates the full product of `B`, `FJ`,
`SJ`, `files`, and `service` (6 x 5 x 9 x 5 x 5) and asserts the properties in
section 9.7. It does not sample. It also asserts the positive cases:

- `Bb Fp S0 N` is R12.
- `Bd Fp S0 M`, `Bd Fr S0 N`, and `Bd Fp S0 U` are R41.
- `Bd F0 S0 P0 WL0` with `previousJobLoaded == 1` is R44.
- A loaded job with `previousJobLoaded == 0` is `WX` and is R44.
- `Bb Fp S0 P W0` is R10.
- `Bd Fp S0 P WL0` is R48 and refuses.
- `Bb Fr S0 M W0`, with one previous-present destination absent and its
  verified backup present, is R13. `Bk Fr S0 N W0` is R30a. Both attempt
  rollback only after confirming B and the absence of a loaded job.
- An absent previous-present destination with no matching backup is `U` and
  refuses. A post-rename failure of either restore-directory sync stops before
  `Bd`, retains the records, and requires re-observation on the next run.

Cross-cutting tests:

- `G3`, `G4`, and `G5` block the terminal rows R50, R52, and R53, and leave
  every record in place.
- Same-boot, absent job, `previousJobLoaded == 1` refuses. Cross-boot, absent
  job allows after two observations. An unavailable boot identifier refuses only
  the first.
- The settle rule: one absent observation refuses; two separated observations
  allow; a job that appears between them refuses.
- A loaded job with no SJ refuses rollback (R15) and is allowed forward (R16).
- A damaged FJ with a binding refuses and never removes B or a backup.
- `Bd` with a loaded job refuses both before and after a simulated reboot;
  matching the previous right or boot UUID alone does not prove job origin.

### 15.3 Fault and reachability tests

For every durable point in section 4:

1. Run the ladder with a fault that stops after the point.
2. Assert the observation maps to the row in the table.
3. Run recovery twice. The first run must take the row's action. The second run
   must be a no-op or advance to the same terminal state. The binding must never
   be removed before its terminal phase.
4. For every write point, add a post-rename directory sync failure and assert
   the run stops before the next mutation.
5. For every removal point, add an unlink-then-sync failure and assert the run
   stops before the next removal.
6. For the FJ `preparing`, `replacing`, and `committed` writes, assert that
   `install()` rethrows `.journalWriteUncertain` and performs no file mutation,
   no removal, and no service call. This is the explicit install-catch test from
   section 5.2.

The specific counterexamples from section 10 are separate named tests:
`testRollingBackWriteVisibleButUnsyncedDoesNotRestore`,
`testCommittedWriteVisibleButUnsyncedDoesNotRemoveBackups`,
`testServiceJournalRemovalUnprovenKeepsFileJournalAndBinding`,
`testInstallPreparingWriteUncertainStopsBeforeDirectories`,
`testInstallReplacingWriteUncertainStopsBeforeBackupMove`,
`testInstallCommittedWriteUncertainStopsBeforeCleanup`,
`testBoundRecoveryFinishServiceKeepsTheJournal`,
`testBdAfterRebootWithPreviousJobLoadedCleansUp`,
`testBdWithMixedFilesRefuses`,
`testBbFpNewRefuses`.

### 15.4 Service integration tests

- `apply` and `recover` accept a `BoundContext` only when the FJ and B
  identities match; otherwise they refuse.
- Each of the six removal sites keeps the SJ when retention is on, including
  the `recover` completed-install site.
- A bound forward leaves the SJ present after `committed`.
- `Sk` is finished to `Sd` and the SJ is kept, then the binding refuses.
- No bound path removes the SJ before the FJ.
- The reverse binding fence refuses a present B with no context, a context with
  no B, a mismatched transaction, `B rollingBack`, and `B committed` with a
  right write attempt.
- `WN` accepts a stored right whose policy matches and whose bytes differ, and
  rejects a policy mismatch. A byte-equal but policy-different definition is
  rejected.

### 15.5 Gate, CLI, and legacy tests

- `InstallCoordinator(sandboxRoot:)` with both new parameters nil never creates
  `upgrade-binding.json`.
- The CLI usage has no new option.
- Exactly one non-nil parameter throws in `init`.
- The sandbox initializer with a service runtime throws.
- The root initializer refuses a non-root effective user, a wrong root, or a
  missing component.
- A live runtime still throws `notApproved` while the gate is false.
- `CoordinatorPolicy.liveInstallationApproved` cannot be true while
  `legacyUnboundRollbackApproved` is true. A test asserts the conjunction.
- The legacy sandbox `recover()` refuses a `Fr` rollback when
  `legacyUnboundRollbackApproved` is false. A `Fc` journal is finished forward,
  not rolled back. Tests set the seam true only for the legacy behavior they
  still cover.

### 15.6 Power-loss VM tests, not approved here

The following need a disposable macOS VM and root inside the VM. They are not
run by this design and are not approved. They are the only way to confirm the
power-loss reasoning. Prerequisites:

1. A disposable macOS VM with a snapshot and no personal account, data, token,
   key, or network share.
2. A scripted harness that records the boot session UUID, the installed file
   digests, the launchd job state, the authorization right policy, the record
   bytes, and the directory entry state before the cut.
3. A power cut at the VM boundary, not `kill -9`, and not a process signal.
4. A post-boot read-only capture before any recovery.
5. A second snapshot after recovery, and a second boot to check that the
   recovery result is stable.
6. No route, TUN, hotspot, or source device. The service is fake or the VM has
   no carrier.

Points to cut:

- Power loss at the `B rollingBack` durable point.
- Power loss after the `Fp` to `Fr` transition and before the first backup move.
- Power loss between the file commit and the backup removal.
- Power loss between the FJ removal and the SJ removal.
- Power loss during the binding removal.
- Power loss after `Bd` and a reboot with the previous job loaded.
- A delayed launchd load that appears between two settle observations.
- A delayed load after the plist restore and before the next file restore.

A real launchd settle timing test, a real authd merge test, and a real `flock`
contention test with the signed helper are also future work. Do not describe the
design as confirmed until they run.

## 16. Availability and security limits

Availability:

- A present binding blocks both the helper and the direct engine in a build that
  includes the name in its refusal list. A failed or refused recovery leaves the
  binding in place, so the tunnel stays blocked. This is intended.
- The legacy both-nil coordinator path still exists for the sandbox command.
  The proposed `legacyUnboundRollbackApproved` constant and its conjunction
  test do not exist yet. The current sandbox recovery can roll back a
  `replacing` journal and finish a `committed` journal forward. The legacy
  rollback must be blocked and then deleted before the live gate opens.
- Nothing retries. After the installer exits, no daemon, timer, or login item
  runs recovery. A person must run it. If the transaction is terminal and the
  removal fails, the tunnel stays blocked until a root recovery run succeeds.
- A loaded launchd job in the pre-service window is refused, not resolved. On a
  normal upgrade the previous job is usually loaded, so a crash in that window
  needs a person. This is the cost of never attributing a fixed-path job.
- After the file commit, recovery is forward only. A service failure cannot
  restore the previous file set automatically.
- A damaged FJ or B has no automated exit. Install and starts stay blocked until
  a person repairs the state. Manual repair is out of scope.
- A crash after `Bd` can require manual recovery if a job is loaded. `WL0`
  does not attribute the job and does not authorize cleanup.
- Cross-boot rollback with a previously loaded job leaves the job unloaded until
  the next boot. The previous plist is in place, so the next boot restores it.
- A boot identifier that cannot be read refuses the cross-boot rollback case.
  The previous-absent case still works, with the settle rule.
- When a binding blocks a start, the target app must show: "Tunnel start is
  blocked because a macOS installer transaction did not finish. Run installer
  recovery. Do not delete files under /var/db/hotspotshade." The app must not
  offer a retry that clears the record. The installer documentation must say that
  a root recovery run is required and that no background process retries.

Security:

- The binding is not signed. A root process can rewrite it. It is a coordination
  record, not a trust anchor.
- The lock is cooperative. Old binaries, binaries that use another name, and a
  process that does not participate can bypass it. The transition lock set is
  not proof of exclusion.
- The helper and engine refusal additions only affect future binaries. An old
  binary does not refuse the binding name.
- The helper's existing state-file check does not reject a hard link. The design
  adds that check for the three refusal names. Until the added check exists, the
  presence check cannot claim a hard-link refusal.
- The design does not authenticate the source device and does not change the
  tunnel, routes, DNS, or TTL behavior. It is an installer recovery design.
- The design does not make the installer live, signed, notarized, or safe to
  run as root.

Unverified platform behavior:

- `launchctl print` status 113 and its exact diagnostic text.
- launchd settle timing after bootout and bootstrap, and after a boot.
- authd merge, normalization, and metadata shape.
- Real `flock` contention with the signed helper and the Rust engine.
- APFS behavior at each power-loss point.
- Whether a boot can load a plist between the two settle observations and the
  first restore.

## 17. Review disposition and residual uncertainty

This table replaces the earlier F1 to F23 table. The earlier table overstated
several resolutions. The "Status" column says what this document does, not what
the code does. No item is marked implemented.

| ID | Review item | Resolution in this revision | Status |
|---|---|---|---|
| V1 | `G8` forbids a first bound install because the service adapter exists before B. | Split into `G8a` (install requires adapter and no B), `G8b` (recovery requires an adapter when B or an SJ is present), and `G8c` (exactly one component throws). | Resolved in design. |
| V2 | Sandbox and root initializers and the lease policy are incoherent. | Section 2.1 defines two initializers, one operation lease, no caller lease, and root-only fixed path. | Resolved in design. |
| V3 | There are six service journal removal sites, including forward recovery success. | Section 11.2 lists six by function name, including `recover` completed install. Tests cover all six. | Resolved in design. |
| V4 | Matrix lacks `Bb Fp S0 N`. | R12 refuses it, and the enumeration test asserts it. | Resolved in design. |
| V5 | Matrix lacks `Bd Fp/Fr S0 M/N/U`. | R41 refuses them. The enumeration test asserts no destructive cleanup. | Resolved in design. |
| V6 | `P` is undefined after the FJ removal. | `P0` is defined as a record-only terminal predicate. It authorizes only B and SJ removal, never a file, backup, or directory removal. | Resolved in design, with a stated limit. |
| V7 | `Bd` cleanup with `W0` blocks after a reboot when a job loads. | `WL0` cannot establish the job's origin. Cleanup refuses while a job is loaded. | Availability remains unresolved; manual recovery may be needed. |
| V8 | `install()` must stop on an unknown FJ write, with post-rename tests. | Section 5.2 states the catch order and the three write points. Section 15.3 names the tests. | Resolved in design. |
| V9 | `WN` must compare the installed right policy, not the raw authd digest. | Section 3.4 and section 11.4 define `WN` by policy. The FJ digest is the installed plist file. | Resolved in design. |
| V10 | Add a reverse binding fence to the service transaction. | Section 11.3 defines `refuseBindingFence` and derived journal retention. | Resolved in design. |
| V11 | Correct the nlink and mode claims. | Section 3.1 states the actual checks. `RootStateDirectory` lacks nlink; the design adds it. The coordinator requires exact `0600`. Section 5.5 corrects the removal claim. | Resolved in design. |
| V12 | Preserve the helper injection seam. | Section 13.1 keeps the internal initializer with `refusableFileNames`. | Resolved in design. |
| V13 | Preparatory backup directory ordering. | Section 4 creates and syncs the directories before `Fr`, before the first backup move. | Resolved in design. |
| V14 | `Fp` backup deletion conflict. | Section 7 and section 12.2 treat a backup under `Fp` as residue and refuse. `REMOVE-FJ` never removes a backup. | Resolved in design. |
| V15 | Temporary cleanup order. | Section 4 fixes the eight-step removal order. | Resolved in design. |
| V16 | Block legacy unbound rollback before the live gate. | Section 15.5 and section 16 use `legacyUnboundRollbackApproved == false` and a test that it cannot be true with the gate. | Resolved in design, not implemented. |
| V17 | Boot settle ambiguity even when the previous job is absent. | Section 8.3 requires two observations and a post-restore observation. It states that this narrows but does not close the race. | Resolved in design, with residual risk. |
| V18 | Status damage reporting must include the start journal. | Section 12.3 adds `startJournal` and a non-throwing probe. | Resolved in design. |
| V19 | Inaccurate review-resolution claims and stale site counts. | This section and the corrections below. Five became six. The FJ seam claim, the hard-link claim, the `WN` digest claim, and the `P` claim are corrected. | Resolved in design. |
| V20 | Capture every review item and residual uncertainty; refuse instead of inventing proof. | This table, section 14, and the residual list below. | Resolved in design. |
| V21 | Deterministic matrix and fault tests, and power-loss VM prerequisites. | Section 9.7, section 15.2, section 15.3, and section 15.6. | Resolved in design, not run. |

Corrections to the earlier disposition:

- The earlier F8 said "five named sites". The source has six. The sixth is the
  completed forward install in `recover`.
- The earlier F19 said the FJ store "has no atomic seam". It has the seam. It
  lacks the classification read-back and digest-verified removal.
- The earlier text said `RootStateDirectory.contains` rejects a hard link. It
  does not. It rejects symlinks, non-regular objects, a wrong owner, group or
  other access, set-id or sticky bits, and an ACL.
- The earlier `WN` compared an installed digest. authd normalizes metadata. The
  corrected predicate is policy equality.
- The earlier `P` after the FJ removal was undefined. The corrected terminal
  predicate is `P0`.
- The earlier `G8` forbade a first bound install. The corrected rules are
  operation-specific.
- The earlier ladder created directories after `Fr`. The source creates them
  before `Fr`, and so does this design.
- `Bd` cleanup still requires `W0`. A loaded job may block recovery after a
  reboot; `WL0` is not sufficient evidence to remove the fence.
- The earlier `CLEAN-ROLLBACK` removed directories without stating that a
  non-empty backup directory or a changed file set is a refusal. R41 and the
  eight-step order state it.
- The earlier cross-language guard implied the existing test compares refusal
  lists. It compares lock names. The refusal comparison is new work.

Residual uncertainty. These are not resolved by this document:

1. No observation proves that launchd will not load a plist after the settle
   window. The two-observation rule and the post-restore observation narrow the
   race. They do not close it. A live VM test is required.
2. `launchctl print` parsing and status 113 are still platform guesses. A change
   in the printed format fails closed but may require a parser update.
3. authd may add metadata or normalize fields differently on a future macOS.
   Policy equality is the reviewed predicate, but the parser's accepted key set
   is a compatibility risk.
4. The lock is cooperative. An old helper, an old engine, a non-participant, or
   a root process can bypass it.
5. The binding is not signed. A root process can rewrite it.
6. APFS power-loss behavior at each point is unverified. The VM tests are
   prerequisites, not evidence.
7. The current `macos/Installer` tree is under active change. The hashes in
   section 0 can change. The design names functions, but an implementer must
   reconcile the actual code.
8. The helper's hard-link check and the engine's owner and nlink checks do not
   exist yet. Until they do, a present binding is not refused against a hard
   link on those paths.
9. A job that loads from the new plist between the settle observations and the
   first restore can still run new bytes after the files are replaced. The
   post-restore observation catches a job that appears before it, not one that
   loaded earlier and remains loaded. A person must resolve the service.
10. `P0` is evidence of a durable `Bd` and absent residue, not proof that the
    current destination bytes are the verified previous bytes. It is safe only
    because it authorizes no file action.
11. The legacy unbound rollback is blocked by a constant and a test, not removed.
    The removal is implementation work.
12. The service transaction's reverse fence is a design. The current service
    transaction still refuses any FJ and does not know about B.

## 18. Implementation sequence (not started)

This document changes no code. When implementation is authorized, the order is:

1. Add the binding record, its store, the canonical identity digest, and
   versioned test vectors.
2. Add the shared classification read-back to the FJ store and the shared
   digest-verified removal helper to all three stores. Do not remove the
   existing atomic seam.
3. Add `BoundContext`, `refuseBindingFence`, the derived retention flag, and the
   six retention sites to the service transaction. Name and test all six.
4. Add the pure `decide()` and the re-observing executor with the step budget
   and the total default.
5. Add the two initializers and the operation lease policy. Keep the CLI path
   with both nil.
6. Add the binding name to the helper and Rust refusal lists, including the
   single-link and owner checks, then extend the source guard and add the shell
   audit. Keep the helper injection seam.
7. Add the matrix, destructive-cleanup, settle, reboot, and fault tests.
8. Set `legacyUnboundRollbackApproved` false, add the gate conjunction test, and
   keep `liveInstallationApproved` false.
9. Do not build, sign, or install a package from this work.

The gate stays closed until an independent review of the implementation and the
disposable VM power-loss tests are complete.

## 19. Requested re-review

This revision is design only. It does not open the gate, change the package, or
make the installer installable. An independent reviewer should check:

1. The two initializers and the one-lease policy are coherent for sandbox and
   root.
2. The six removal sites are all named and the retention test covers the
   `recover` forward success path.
3. The matrix is total and the default refuses. `Bb Fp S0 N`, `Bd Fp/Fr S0
   M/N/U`, `P0`, and `WL0` are correctly classified.
4. No `REFUSE`, `CLEAN-*`, or default row removes a destination file.
5. A loaded job cannot authorize `Bd` cleanup or binding removal, and the
   remaining reboot availability limit is stated accurately.
6. `install()` stops on an unknown FJ write at all three write points.
7. `WN` uses policy equality, not raw bytes.
8. The reverse binding fence cannot be bypassed by a caller that forgets the
   retention flag.
9. The nlink, mode, and helper-seam claims match the source.
10. The backup directory order, the `Fp` residue rule, and the temporary order
    are consistent.
11. The legacy rollback is blocked before the gate and the settle rule is
    honest about what it cannot prove.
12. The status view reports a damaged binding, FJ, SJ, and start journal without
    throwing.
