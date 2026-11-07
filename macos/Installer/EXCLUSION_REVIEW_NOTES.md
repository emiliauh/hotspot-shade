# Install and engine exclusion: open review questions

Status: **UNAPPROVED.** The package remains build-only and its preinstall
refuses. These notes are not an installation procedure.

A sandbox-only coordinator core and journal now exist under `macos/Installer`.
They do not make the package installable. The independent review identified
prerequisites that still block approval. This file records the exact state and
the remaining gaps.

## What the sandbox core now does

- Takes a nonblocking exclusive `flock` on every name in a transition lock set
  for the whole file transaction. The set is `start.lock`, `start-exclusion`,
  and `upgrade.lock`.
- Rechecks the path inode after every lock and refuses a symlink, wrong owner,
  wrong link count, group or other permission, set-uid, set-gid, or sticky bit, or access control
  list.
- Opens one target root and walks every child with `openat` and `O_NOFOLLOW`.
- Records the exact four-file layout and the previous file digests, sizes, and
  modes in a durable journal.
- Moves each previous file to a per-transaction backup, writes the new file
  through a temporary file, syncs it, and renames it into place.
- Commits only after every new file and signature verifies.
- Recovers after a crash at any phase. It rolls back a non-committed
  transaction and finishes a committed one. A second crash during recovery
  leaves the same recoverable state.
- Refuses a present cleanup marker, launch intent, start journal, install
  journal, orphan backup directory, unreadable journal, or damaged committed
  set.
- Never removes a start journal, cleanup marker, or launch intent.
- Has no live mode and refuses to run as root.

## Exact lock mismatch

The repository is mid-migration. At the time of this writing:

| Participant | Source lock name | Journal | Handoff |
|---|---|---|---|
| Swift helper | `start-exclusion` | `engine-session` launch intent; it does not write `start-journal` | Descriptor `5`, version, device, inode |
| Rust engine | `start-exclusion` | none of its own; it refuses `start-journal`, `engine-session`, and `cleanup-blocked` | Validates helper descriptor `5` |
| Installer coordinator | Holds all three transition names exclusively | `install-journal.json` | None |

The transition set is not a single reviewed lock. A participant that uses a
fourth name, or an old binary that takes no lock, is not excluded. The source
guard in `StartJournalTests` fails if either the helper or the Rust engine names
a lock outside the set. It does not prove interoperability.

The helper and the Rust engine both use `start-exclusion`. The coordinator's
primary name is still `start.lock`, but the transition set includes
`start-exclusion`, so the coordinator and the current helper and engine contend
today. `upgrade.lock` has no current writer. The final name is still the lead's
decision.

## Prerequisites that prevent approval

- **One delivery path.** Choose one lock name and one coordinator delivery path.
  The current coordinator is a sandbox CLI, not a root-owned install entry
  point.
- **Old binaries do not participate.** Initial migration requires a separately
  established maintenance condition. Process scans alone cannot make an
  uncooperative binary take a new advisory lock.
- **Lock acquisition, lifetime, descriptor ownership, spawn actions, and
  cleanup order across helper, direct CLI, and root GUI are not validated
  live.** The helper and engine source now describe a descriptor `5` handoff,
  but no real helper-to-engine run has been observed. The coordinator does not
  participate in the handoff.
- **A released lock does not prove route cleanup.** The Rust engine keeps a
  guard in the tunnel state and the service retains it on a failed cleanup. The
  sandbox coordinator can only refuse the start journal and the cleanup marker.
  Live route inspection, uncertain ownership, and recovery without deleting
  another process's objects remain unvalidated.
- **The start journal is a separate record.** The coordinator reads it and
  refuses while it is present. It never removes it. The helper must remove it
  only after a verified clean stop. A crash of the helper or engine, a timeout,
  or an unreadable journal keeps the block.
- **The install journal needs a live recovery test.** The journal covers file
  sets and partial replacement. The sandbox service transaction now covers
  launchd registration and the authorization right with its own durable
  journal, but `InstallCoordinator` does not call it and the two journal
  ordering is not integrated. A live coordinator must perform the external
  actions while the file journal and backups still exist and must block file
  rollback while a service recovery is required. No such coordinator is
  implemented. See `SERVICE_TRANSACTION.md`.
- **No real signed artifacts.** The team identifier comes from a caller in the
  sandbox. A live coordinator must derive it from the installed app signature.
  The package is unsigned and not notarized.
- **No independent review of this pass.** The transition lock set, journal
  schema, recovery matrix, and the source-name guard need a review separate from
  the author.

## Required next steps

1. Choose one canonical lock name and one FD handoff contract. Update the
   helper, the Rust engine, and the coordinator. Remove the transition set.
2. Stop every old binary under a maintenance condition and install a coherent
   signed set. Do not enable the live path while any non-participating binary
   can start.
3. In a disposable macOS VM with a real signed helper and engine:
   - hold the coordinator exclusive set and prove helper and direct CLI starts
     fail before a utun or route change;
   - hold a helper or engine shared lock and prove the coordinator refuses;
   - crash the holder and prove the kernel releases the lock;
   - verify descriptor `5`, the environment values, a partial handoff refusal,
     and a mismatched inode refusal;
   - verify every route, address, and device is gone before the shared lock
     drops.
4. Add a root-owned coordinator with a trusted delivery path. Integrate the
   sandbox service transaction into the same exclusive lease, keep the file
   journal and backups until the service commit, and block file rollback while
   a service recovery is required. Verify live launchd and authorization-right
   behavior in a disposable VM.
5. Run a new independent review.

Do not enable the installer gate until these are complete. The current code is a
reviewable sandbox model, not an approved install mechanism.
