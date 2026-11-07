# Protected helper for macOS

This directory holds the production shape for a root-owned macOS helper. The
app uses this helper for every tunnel start. The helper, its XPC client,
and its tests are in `HotspotShadeKit/`. The app does not run a user-writable
bundled engine with administrator privileges.

The signed root install has not run on a real host. No Developer ID certificate
or root installation is available in this repository. An unsigned or ad-hoc
build fails closed at Turn on. The app has no demo mode; the Dashboard, pairing,
status, and Settings use the real user engine without the helper.

## Signing identifiers

The installer must set the signing identifiers explicitly. The SwiftPM product
name is not the required identifier.

```sh
codesign --force --options runtime \
  --identifier dev.hotspotshade.mac.helper \
  --sign "Developer ID Application: <team>" \
  /Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper
codesign --force --options runtime \
  --identifier dev.hotspotshade.engine \
  --sign "Developer ID Application: <team>" \
  "/Library/Application Support/HotspotShade/engine/hotspotshade"
codesign --force --options runtime \
  --identifier dev.hotspotshade.mac \
  --sign "Developer ID Application: <team>" \
  /Applications/HotspotShade.app
```

All three need the same team, the hardened runtime, and no
`com.apple.security.get-task-allow` entitlement. A missing or ad-hoc signature
fails closed before a listener or engine starts.

## The start right

The helper checks one custom right, `dev.hotspotshade.tunnel.start`. It is not a
built-in signed right, and the helper does not assume that a missing right falls
to a safe default. The installer must add it from
`dev.hotspotshade.tunnel.start.plist`:

```sh
sudo security authorizationdb write dev.hotspotshade.tunnel.start < \
  macos/Helper/dev.hotspotshade.tunnel.start.plist
```

The helper reads the definition before every tunnel authorization. It refuses
a missing right, an unreadable policy database, a delegated `rule`, a
definition that allows root, and a definition that shares the grant. Starting
the engine itself creates no route and no tunnel device, so it is not gated by
this right. A stale or missing right therefore does not hide the dashboard; it
refuses only the tunnel start. It accepts the shape in
`dev.hotspotshade.tunnel.start.plist`:
`class=user`, `group=admin`, `authenticate-user=true`, `shared=false`,
`allow-root=false`, and a positive `timeout` from 1 to 60 seconds. The shipped
template uses 30 seconds. The optional `comment` is the only other
install-time key. `authenticate-user`, `shared`, and `allow-root` must be plist
booleans; a number or string is refused. `timeout` must be an integer inside
that window. A zero timeout stores no authorization credential, so the helper
check a few milliseconds after the administrator prompt is denied. A
missing key is a refusal, not a default. An omitted `shared` or `allow-root`
does not pass as "not true". An existing right with `timeout=0` from an earlier
install is refused, so replace it from the current template before a real
tunnel start. Until then a tunnel start is refused with the right-not-configured
message and no administrator prompt is shown. The older helper still fails
closed before it opens its listener.

authd writes metadata back into a stored definition. A read-only
`security authorizationdb read` on macOS 27.2 showed that authd adds `created`,
`modified`, `session-owner`, `tries`, and `version` to built-in user rights even
when the source plist does not contain them. A right installed by another
application can also carry `identifier` and `requirement`, which record that
application's code signing identity. The helper tolerates these keys, but only
with fixed types and values:

- `created` and `modified`: a finite non-negative number.
- `version`: a non-negative integer up to 1,000,000.
- `identifier`: non-empty printable ASCII of at most 1024 bytes.
- `requirement`: non-empty printable ASCII with tabs and line breaks of at most
  4096 bytes.
- `session-owner`: absent or `false`. This is a real authorization field, not a
  comment. The installed class is a plain user right.
- `tries`: absent or an integer from 1 to 10000. This keeps the attempt budget
  from being widened.

The validator never treats `identifier` or `requirement` as a grant or as a
substitute for required settings. Their effect on who can later change the
right has not been verified on the installed custom right.
The helper continues to refuse `rule`, `mechanisms`, `k-of-n`, `entitlement`,
`entitled`, `entitled-group`, `vpn-entitled-group`, `password-only`,
`default-prompt`, and every unknown key because it does not validate their
semantics. The canned `authenticate-admin` class and every delegated definition
are refused. A missing right refuses every tunnel authorization; it is never an
unauthenticated tunnel start.

These values came from read-only reads of built-in rights, not from the
installed HotspotShade right. The custom right read-back and the administrator
prompt remain unverified. See Production gaps.

## The problem this fixes

The old macOS start path ran the bundled engine as root through `osascript`
with administrator privileges. The engine is in the app bundle. A user-owned
app bundle can be replaced by code that already runs as the user, so root may
execute a file the user controls. A code signature check on a user-writable or
ad-hoc file is not a trust boundary. That path is gone: a non-root macOS GUI
returns `protected_helper_required`, and the Rust `--privileged-helper` command
fails closed. The helper must be root-owned, installed into a directory the user
cannot write, and signed with a Developer ID that the helper checks.

## Trust chain

1. A root-owned package writes the helper to
   `/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper`. The file is
   `root:wheel`, mode `0755`, with no group or other write bit.
2. The launch daemon file is
   `/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist`. It is
   `root:wheel`, mode `0644`, and names exactly that helper path.
3. The helper and the engine are signed with the same Developer ID team. The
   requirement names the Developer ID intermediate and Developer ID
   Application markers, requires the hardened runtime, and rejects
   `com.apple.security.get-task-allow`. An ad-hoc signature, an Apple
   Development or Apple Distribution signature, a different team, a different
   identifier, or a file owned by a user is rejected before a listener opens.
4. The helper checks its own install path and signature at startup. On any
   failure it writes one generic line and exits. It never opens XPC.
5. The XPC listener sets a peer code signing requirement with
   `xpc_connection_set_peer_code_signing_requirement`. The runtime drops every
   message from another team or identifier before the helper reads it. The app
   connects with `XPC_CONNECTION_MACH_SERVICE_PRIVILEGED`, so it looks up the
   service in the system bootstrap namespace. A per-user LaunchAgent cannot
   shadow the name.
6. For every request the helper reads the peer audit token from the live XPC
   connection and checks the live code with `SecCodeCopyGuestWithAttributes`
   and the `kSecGuestAttributeAudit` attribute. It never checks a PID alone,
   because the kernel recycles PIDs. If the audit-token getter is unavailable,
   the helper rejects the caller instead of falling back to a PID.
7. The audit session id is read with the libbsm `audit_token_to_asid` accessor,
   not from a guessed field. The helper also requires the fixed word positions
   to agree with `audit_token_to_asid` and `audit_token_to_pid`, and it requires
   a positive session. A token without a login session is rejected. The
   external authorization form does not expose the session that created it, so
   the helper cannot prove the form came from that exact session. It proves the
   caller is the signed app in a login session and that the form carries the
   fixed right.
8. Before the app asks for an administrator authorization, the connection
   completes a harmless handshake. The app sends a fresh 32-byte client nonce,
   the helper returns it with a fresh 32-byte server nonce, and a start or
   authorization request must return that server nonce. One nonce is accepted
   once. The handshake proves the pinned peer answers this connection. The
   authorization external form is never the first message on a connection. The
   app reads the helper status on that connection before it starts the engine
   and before it prompts, so a running tunnel, a durable cleanup block, or an
   unreadable status fails without a prompt.
9. The helper starts one root engine for one authenticated connection. The
   app makes that request only when a person turns the tunnel on. The start
   carries no administrator form and creates no route or tunnel device. It may
   carry one pairing handoff descriptor. The helper passes that descriptor to
   the root engine as an inherited descriptor and never reads it. The engine
   imports the same target identity and proxy credentials, so the source device
   does not see a new pairing. The engine path is root-owned and signed. The
   helper verifies it before spawn.
   A separate `authorize` request on the same connection carries the external
   authorization form. The helper checks the fixed right and the form, then
   writes one fresh `tunnel-grant` file into the engine's root-only runtime
   directory. The engine checks the file, its one-link inode, its 0600 mode,
   its 0700 parent, and its 60-second timestamp, removes it, and only then
   changes a route. A missing, stale, malformed, symlinked, or wrongly owned
   grant is a refused start. A manually started root GUI has no grant file and
   keeps the root command line as its authority.
10. The per-launch secret goes to the engine on descriptor 3. The engine sees
    descriptor 4 as its liveness channel. The start-exclusion lock goes to
    descriptor 5 and the pairing handoff socket to descriptor 6. The launcher
    first duplicates every inherited source to a close-on-exec descriptor at
    or above 10, then adds one `dup2` per target, so no file action can
    replace a source that a later action still needs. The 2026-11-06 release
    candidate skipped this step: the XPC handoff descriptor arrived before the
    pipes existed and had a low number, `dup2(token, 3)` replaced it, and the
    engine received the token pipe on descriptor 6. Every start then failed
    before the port was published. The engine now refuses a credentials
    descriptor that is not a socket on macOS. Standard error is a capture
    pipe that the helper drains for the life of the engine and bounds to the
    last 4 KiB in memory. The helper returns the loopback port
    and secret only in the authenticated XPC reply. The secret is never written
    to disk, a command line, a log, or a status answer.
11. The engine's port file lives in a private directory under
    `/var/db/hotspotshade`. `/var/run` is not used because it is group-writable
    on macOS. The launcher holds descriptors for the parent and the new
    `run-<uuid>` directory, opens the port file with `openat` and `O_NOFOLLOW`,
    and checks the owner, mode, inode, and device before it reads the port. A
    path rename or symlink swap cannot substitute another file. The engine
    publishes the port through `port.tmp` and a rename; removal of the private
    runtime directory also removes a stale temporary file and any unconsumed
    `tunnel-grant` so an interrupted publish cannot leave the directory behind.
12. One connection owns one session. A second connection is refused with the
    busy code; it cannot stop a tunnel that is in use. A connection
    invalidation or interruption stops only its own engine. A start is refused
    while a stop is still finishing, so two engines cannot overlap.
13. Before the launcher can spawn an engine, the session controller creates a
    root-owned write-ahead intent at `/var/db/hotspotshade/engine-session`. The
    file is created with `O_CREAT | O_EXCL | O_NOFOLLOW`, its data is synced,
    and the containing directory is synced, so the intent survives a helper
    crash or `SIGKILL` in the start window. The launcher reads the intent again
    next to `posix_spawn` and refuses when it is absent or unreadable. The
    intent stores no process id and no secret.
14. A stop closes descriptor 4 first, sends SIGTERM, and waits up to 60
    seconds. It does not send SIGKILL. A timed-out stop, a signaled exit, a
    non-zero exit, or a wait status the helper cannot read is not a clean stop.
    Each one sets a durable cleanup block, and every later start is refused
    until a person inspects the host. There is no automatic restart and no
    automatic clear. One case is different: an engine that the helper reaped
    (so its exit is known) before the helper ever began a grant write for its
    session cannot have changed a route, because the engine changes a route
    only after it consumes a grant. That exit, including an exit before the
    port was ready, is a failed start: the helper clears the launch intent,
    releases its shared lock, sets no block, and records one fixed reason. A
    grant write that was attempted, even one that failed, keeps the block path.
    A requested stop (Turn off, cancel, lost connection, or the authorization
    deadline) of such an engine is a clean stop even when its exit status is
    not zero, and writes no failure record.
15. The launch intent is removed only after a verified clean engine stop. A
    failed spawn clears it only when the launcher can prove that no child was
    created, and a spawned engine that exits cleanly clears it through the same
    verified stop path. It stays after a helper crash, an unclean stop, a
    timed-out stop, an engine exit that nobody requested, or any clear failure.
    A helper restart that finds the intent refuses every start until a person
    completes the inspection and escalation in the recovery section below. The
    helper never signals a process named by the intent, because the intent
    carries no pid and a pid can be reused.
16. The cleanup block is a root-owned marker at
    `/var/db/hotspotshade/cleanup-blocked`, in a root-owned `0700` directory.
    The helper creates it once with `O_CREAT | O_EXCL | O_NOFOLLOW`, syncs the
    file and the containing directory, and never removes it. The marker
    survives a helper restart. A symlink, a non-root owner, a group or other
    permission, or an unreadable state is treated as blocked, never as clean.
    No helper path removes the marker. A person must follow the inspection in
    the recovery section below; on a preview host the coordinator command
    `preview-clear-cleanup-block` then removes it after its own checks.
17. An engine that exits on its own is not a clean stop. The liveness watch
    frees the session slot, records the durable block, keeps the launch intent,
    and tells the owning connection. The app shows the cleanup message, not a
    normal stop. The exception in item 14 applies: a reaped exit before any
    grant write is a failed start. The `engine_exited` notice then carries
    `failed_start` and the fixed reason, and the app says that the tunnel did
    not start and why.
18. An app-side start timeout is ambiguous. The app cancels and closes the XPC
    connection, so the helper's connection-loss path stops any engine that was
    already started. It never leaves a root engine serving a request that the
    app counted as failed. A cancel during a launch cannot interrupt
    `posix_spawn`. It guarantees that the caller will not receive the late
    engine and that the helper stops it. The cancel reply can arrive before the
    child spawns. A tunnel authorization is a separate request and never
    spawns an engine.
19. The engine owns route and device cleanup. The helper only stops the engine
    and waits for its exit. It does not create a route or a tunnel device.
20. Closing descriptor 4 is a signal to the engine, not proof that cleanup
    finished. If the helper exits or launchd ends it while an engine is
    unaccounted for, the launch intent and the durable marker are the remaining
    guards. The helper cannot inspect the routing table.

The Rust side in `rust/src/privileged.rs` keeps the same caller rule for a
Unix socket helper: peer UID, peer PID, peer audit token, an exact Developer ID
requirement, and a root-owned install check. `serve_connection_verified` is the
public protected entry point. The UID-only listener, `connect_as_root`, and
`serve_connection` are compiled only for the hermetic tests, so they cannot
become a production boundary again by accident.

## Start exclusion and the install journal

The helper and the Rust engine use one lock file and one handoff contract. The
installer coordinator foundation takes a transition set that includes this
lock, so participating versions contend. Older binaries may not participate.
The installer package remains disabled and unapproved. Cross-binary contention
and the migration from older binaries still need review and live evidence.

| Item | Value |
|---|---|
| State directory | `/var/db/hotspotshade`, root-owned, mode `0700` |
| Lock file | `start-exclusion`, root-owned, one link, mode `0600` |
| Installer transition locks | `start.lock`, `start-exclusion`, `upgrade.lock` |
| Install journal | `install-journal.json`, owned by the installer coordinator |
| Service journal | `service-journal.json`, owned by the service transaction |
| Helper start record | `engine-session`, the existing launch intent |
| Engine handoff descriptor | `5` |
| Protocol version | `1` |

The helper and `rust/src/macos_upgrade_lock.rs` share this contract:

- Path `/var/db/hotspotshade/start-exclusion`.
- Open with `O_NOFOLLOW`, `O_CLOEXEC`, and `O_NONBLOCK`; create with `O_EXCL`
  and mode `0600` when absent.
- Check a regular file, expected owner, one link, no group or other permission
  bit, and no set-uid, set-gid, or sticky bit, through the descriptor. The helper also refuses an
  extended access control list.
- The helper takes `flock(LOCK_SH | LOCK_NB)` before the launch intent and
  before it asks the launcher to spawn. It holds that shared lock until the
  engine has stopped.
- The Rust engine takes its own independent shared lock before the first route
  or TUN change and holds it until route and device cleanup finishes.
- A future coordinator must take `flock(LOCK_EX | LOCK_NB)` for the whole
  replacement transaction and never replace the lock inode.

The launcher duplicates the helper's locked descriptor to descriptor `5` in the
child with a `posix_spawn` file action. The child inherits the same open file
description. The engine independently locks the same inode, then validates the
handoff. It receives these non-secret values in its environment:

- `HOTSPOTSHADE_START_EXCLUSION_FD=5`
- `HOTSPOTSHADE_START_EXCLUSION_VERSION=1`
- `HOTSPOTSHADE_START_EXCLUSION_DEVICE=<device>`
- `HOTSPOTSHADE_START_EXCLUSION_INODE=<inode>`

The engine must keep descriptor `5` open until its route and device cleanup
finishes. It must not call `flock(LOCK_UN)` on it: a Darwin lock belongs to the
open file description, and an unlock from one duplicate releases it for every
duplicate. Closing the descriptor, or process exit, is the release path. The
engine refuses a partial or mismatched handoff.

A busy lock refuses the helper engine start with `start_exclusion_busy`; an
unsafe or unreadable lock refuses it with `start_exclusion_unavailable`. No
engine is started in either case. A probe checks the lock before the engine
start, so an install or upgrade that already holds the exclusive lock does not
start an engine. The engine start carries no administrator prompt. A tunnel
authorization is a separate request and does not take the start lock.

The helper does not write the installer journals. It checks
`install-journal.json` and `service-journal.json` through the root state
directory. A present, unsafe, or unreadable journal blocks a start, including
after an installer crash. The two journal recovery procedures are not yet
integrated. The helper's own durable start record is the existing
`engine-session` launch intent: it is written before spawn and removed only
after a verified clean stop. There is no second helper start journal.

The journal refusal is latched for the life of one helper process. A journal
that is present or unreadable at startup, or a prepare that finds one under the
shared lock, keeps every later start refused. A journal that later disappears is
not proof that the coordinator finished its file transaction, and the two
journal recoveries are not integrated. A restarted helper re-reads the directory
from disk.

A failed `engine-session` create removes only the inode that it created. The
rollback first proves that the held descriptor and the name still reach the same
regular file, with one link and no extended ACL, and it syncs the removal. A
replacement from another participant, a hard-linked record, an ACL-bearing
record, an unreadable ACL, or a removal that cannot be synced is kept as
ambiguous evidence and reported as uncertain. The session controller latches
that refusal for its whole process, and a later presence read cannot clear it.
macOS has no unlink-by-inode call, so a cooperative root participant is still
assumed between the final identity check and the unlink. The hermetic tests force
the failure through an internal seam and check that a replacement, a hard link,
and an ACL-bearing record survive.

An unclean stop, a stop timeout, a failed exit, or an engine exit that nobody
requested keeps the launch intent and the helper's shared lock. The lock stays
held for the rest of the helper process, so a coordinator cannot take the
exclusive lock while this helper lives. A clean stop releases the helper's lock
even if the intent clear fails, because the engine is gone; the remaining
intent makes the next preflight refuse.

The helper checks that the lock path still names the locked inode after it
takes the lock and again before spawn. A replaced path fails the start instead
of adopting the replacement. The coordinator must never replace the lock inode
during a transaction; a new inode would let a start and an install hold
different locks. This is a cooperative protocol and does not protect against an
uncooperative root process or a binary that predates the lock.

The Rust start lease retains the shared lock if setup or worker handoff panics,
and leaves a direct-start record in place until cleanup is proved. Hermetic
tests cover setup panics; the worker handoff and spawn-failure branches remain
inspection-only. A panic can poison the service mutex, so normal status may
fail rather than display cleanup uncertainty. An abort or process exit releases
the lock. The record and lock are cooperative fences, not protection against an
uncooperative root process.

A helper-launched engine that exits before reporting its port is a failed start
with a fixed reason, not an unclean exit: no session existed, so the helper
never wrote a grant and the engine cannot have changed a route. The helper
releases the exclusion and clears the launch intent. A launch whose child the
helper could not stop or reap keeps the exclusion and requires inspection.

The installer coordinator is still not approved or enabled. Its transition set
includes `start-exclusion`, but older binaries and incomplete coordination of
the two installer journals remain open. The helper tests cover the lock file,
the handoff, and the installer journal presence
gate in a temporary directory. No signed install, live XPC start, direct command
line start, or cross-binary contention test has run. The package refusal gate is
unchanged.

## Recovery after a cleanup block or leftover intent

This section is an inspection and containment procedure. On a local preview
host, step 6 clears the two records with the coordinator command
`preview-clear-cleanup-block` after the checks below. Outside the preview there
is still no approved removal; a reviewed recovery for direct and helper engines
is still required.

The cleanup marker and the launch intent are helper refusal records. They are
not proof that an engine is gone. The helper cannot inspect the routing table. A
person must verify the host, and the recovery must run with the owner's explicit
authorization. If `install-journal.json` or `service-journal.json` is present,
stop here. Their combined recovery is not yet approved. Do not delete or edit
either installer journal by hand.

1. Turn the tunnel off through the app if it still answers. Do not send
   `SIGKILL` to an engine or to the helper.
2. Verify that no HotspotShade engine remains, including direct CLI or GUI
   engines started from another path. The installed helper engine path alone
   is not a complete process check. An empty process search does not prove
   that an engine is absent or replace the route and device checks below.
3. Inspect the IPv4 and IPv6 route tables and the interface list. Confirm that
   no HotspotShade-owned route remains: the two IPv4 `/1` routes and the IPv6
   `2000::/3` route, whether a blackhole or a route through the utun. Confirm
   that no HotspotShade utun remains. Do not
   assume that every `utun` or every `/1` route belongs to HotspotShade;
   another VPN can use the same shapes.
4. Stop the helper through its launch daemon and wait for it to exit. For
   example:
   `sudo launchctl bootout system/dev.hotspotshade.mac.helper`.
   Perform this step only after step 2 found no remaining engine. Repeat the
   process, route, and interface checks after the stop. If an engine remains,
   stop and escalate instead of removing the state files.
5. Stop and escalate if an engine or lock holder cannot be ruled out. A direct
   engine also owns an `engine-session` record. Removing it while that engine
   is active can defeat the single-start slot. Do not remove the record or the
   cleanup marker by hand based on this procedure. A reviewed recovery procedure
. On a local preview host only, after steps 1 to 4 found no engine, no
   HotspotShade route, and no utun that HotspotShade owns, run the placed
   preview coordinator as root:
   `sudo "/Library/Application Support/HotspotShade/local-preview/coordinator/hotspotshade-installer-coordinator" preview-clear-cleanup-block`.
   It is gated like the other preview commands (root, the system preview
   build, and the coordinator's own signing team). It refuses when the
   protected helper process runs (stop it with
   `sudo launchctl bootout system/dev.hotspotshade.mac.helper`), when a root
   process named `hotspotshade` runs, when `netstat -rn` shows a `0/1` or
   `128.0/1` route through a utun or any `2000::/3` route (a lo0 blackhole or a
   utun route), when a file, service, or start journal is present, or when it
   cannot take the exclusive start-exclusion lease, which a starting, running,
   or stopping session holds shared. It refuses when any check cannot
   complete. Otherwise it removes `cleanup-blocked` and `engine-session`, each
   guarded by its digest and mode, reads both names back, and prints every
   check and every removal. It never deletes a route, an interface, or a lock
   file, and never signals a process. It also refuses when another VPN uses
   the same route shapes, because it cannot tell them apart. Load the helper
   again with `sudo launchctl bootstrap system
   /Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist`, or use
   `preview-uninstall` and a fresh `preview-install`.

Do not use a route flush, a default-route delete, a broad `route delete`, or an
interface teardown as part of this recovery. Those commands can remove another
VPN's route, a required local route, or the network that the person needs to
recover. If any route or device check is uncertain, or if an engine remains,
stop and escalate. Do not clear the marker or the intent to make a start pass.

## Start failure diagnostics

A root engine that fails before it serves a request prints one fixed line on
standard error: `hotspotshade-start-failure: <code>`. The codes are
`arguments_invalid`, `control_descriptor_invalid`,
`credentials_descriptor_invalid`, `token_invalid`,
`credentials_handoff_invalid`, `listener_failed`, `port_file_failed`,
`credentials_import_failed`, and `start_exclusion_descriptor_invalid`
(`StartupStage` in `rust/src/main.rs`). The helper drains the engine's
standard error for the engine's whole life, keeps at most the last 4 KiB in
memory, and accepts only a line that is exactly the prefix and one of these
codes. It never stores, logs, or sends any other engine output. When the
engine printed no known line the helper uses `exited_without_reason`,
`no_port_in_time`, or `secret_not_delivered`.

On a failed start the helper writes the code to
`/var/db/hotspotshade/last-start-failure` (root-owned, mode 0600, one line,
at most 4 KiB, replaced on each failed start). It is diagnostics only: no
start, stop, or cleanup decision reads it, and `preview-uninstall` and
`preview-clear-cleanup-block` keep it. The helper also returns the code to the
app: in the `engine_start` start error as `reason`, in the `engine_exited`
notice with `failed_start`, and in the status reply as `last_reason` with
`last_result` `failed_start`. The app then shows "The tunnel did not start."
with one plain sentence for the code, never the cleanup block text.

## Files

| File | Purpose |
|---|---|
| `macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperIdentity.swift` | Signing identity, audit token value, requirement builder, caller policy. |
| `.../ProtectedHelper/HelperInstallTrust.swift` | Root-owned path, launch daemon, app bundle, and engine signature checks. |
| `.../ProtectedHelper/HelperLifecycle.swift` | One-session ownership, cancellation, parent loss, durable cleanup block. |
| `.../ProtectedHelper/HelperCleanupBlock.swift` | Root-owned durable cleanup marker; fails closed on an unsafe or unreadable state. |
| `.../ProtectedHelper/HelperLaunchIntent.swift` | Root-owned write-ahead launch intent; created before spawn and cleared only after a verified clean stop. |
| `.../ProtectedHelper/HelperStartFailure.swift` | Fixed engine start failure reasons, the bounded stderr capture, and the root-only last-start-failure record. |
| `.../ProtectedHelper/HelperStartExclusion.swift` | `start-exclusion` shared lock, descriptor handoff, and install journal presence gate. |
| `.../ProtectedHelper/RootStateDirectory.swift` | Root-owned state directory and durable file create, read, sync, and remove. |
| `.../ProtectedHelper/HelperHandshake.swift` | Fresh one-use connection handshake and nonce gate. |
| `.../ProtectedHelper/RootEngineLauncher.swift` | Root engine spawn with descriptor secret, liveness channel, and held-descriptor port file read. |
| `.../ProtectedHelper/ProtectedHelperClient.swift` | App-side install check, XPC server pin, bounded start and stop. |
| `.../ProtectedHelper/ProtectedEngineProcess.swift` | App-side root engine adapter used by the SwiftUI app. |
| `.../ProtectedHelper/XPCHelperPeer.swift` | Kernel audit token for one live XPC peer; fails closed without it. |
| `macos/HotspotShadeKit/Sources/HotspotShadeHelper/main.swift` | XPC daemon entry, peer requirement, request handling. |
| `macos/Helper/dev.hotspotshade.mac.helper.plist` | Launch daemon template for a root-owned install. |
| `macos/Helper/dev.hotspotshade.tunnel.start.plist` | Required administrator-right definition for the start right. |
| `macos/HotspotShadeKit/Tests/HotspotShadeKitTests/ProtectedHelperTests.swift` | Hermetic trust, lifecycle, exclusion ordering, and journal-state tests. |
| `macos/HotspotShadeKit/Tests/HotspotShadeKitTests/ProtectedHelperExclusionTests.swift` | Real Darwin flock, cross-process contention, lock safety, and install journal gate tests in a temporary directory. |
| `macos/HotspotShadeKit/Tests/HotspotShadeKitTests/ProtectedHelperStartFailureTests.swift` | Failed start before a grant, descriptor placement in a real child, stderr reason parsing, and the record. |
| `rust/tests/macos_root_launch_shape.rs` | Runs the real engine in the helper launch shape (descriptors 3 to 6, environment, argv) as the test user, including the old descriptor order that failed on 2026-11-06. |

## What is tested

`swift test --package-path macos/HotspotShadeKit` compiles the helper and runs
the trust and lifecycle tests. The tests cover:

- a root-owned, Developer ID helper is accepted;
- a user-owned helper, group or other write, a write ACL, a symlink, an ad-hoc
  signature, a missing or invalid team, and a path outside the protected root
  are rejected;
- a launch daemon that names another program is rejected;
- a signed, root-owned app bundle is accepted only when no parent is writable,
  and a stock 0775 `/Applications` is rejected;
- a caller must satisfy the exact team and identifier requirement;
- the expected team comes from the running app signature, and an ad-hoc app
  has no usable team;
- requirement strings cannot be injected;
- a user-owned engine is rejected;
- a writable engine subdirectory is rejected;
- the root engine launcher fails closed without root;
- the app client refuses to connect when install trust fails;
- the app client starts and stops through a verified transport;
- the app-side `ProtectedEngineProcess` starts and stops through the client and
  refuses to connect when install trust fails;
- connection loss leaves the client unavailable and never restarts it;
- a busy reply does not stop another session;
- a second connection cannot stop the first session;
- a connection close stops only its own engine;
- a close during launch stops the late engine;
- a cancel during launch stops the late engine and does not block a later
  start;
- a timed-out stop blocks the next start;
- a non-zero or signaled stop blocks the next start;
- a launcher that cannot stop an engine it just spawned blocks every later
  start;
- an engine that exits before it reports its port is a failed start with its
  fixed reason: no block, the launch intent cleared, the shared lock released,
  and a later start allowed; a failed intent clear still blocks;
- an engine that exits on its own after a grant attempt (even a failed grant
  write), or whose exit the helper could not read, records the durable block
  and refuses a later start, while a reaped exit before any grant attempt is a
  failed start whose session record is `failed_start` with its reason;
- an unclean stop before any grant is a failed start, and a timed-out stop
  still blocks;
- the launcher duplicates every inherited descriptor above the target numbers
  first, and a real child receives the token, liveness, lock, and pairing
  channels on 3, 4, 5, and 6; a mapping whose source could be a target is
  refused;
- the engine stderr capture drains to end of file, keeps at most 4 KiB, and
  yields only a fixed engine reason code; a near match or extra text is no
  reason; the engine codes match the Rust startup stages;
- the last-start-failure record is one fixed code in a 0600 file;
- the app says "The tunnel did not start" with the reason, never the cleanup
  block text, and a `failed_start` record confirms the stop;
- a durable marker is read by a new controller and is never cleared
  automatically;
- an unreadable durable marker fails closed, and a marker write failure keeps
  the running helper blocked;
- the root marker store rejects a symlink, a group-writable directory, and a
  marker that another program made group or other readable;
- the launch intent exists before the launcher runs, survives a simulated
  helper restart, and refuses every start until an authorized recovery clears
  it. No reviewed recovery for a direct or helper engine is approved here;
- a clean stop clears the intent and allows a later start;
- an unclean stop, a timed-out stop, an unprompted engine exit, and a failed
  intent clear keep the intent and refuse every later start;
- a launch that proves no engine survived clears the intent, while an intent
  write or read failure fails closed;
- the root launch intent store persists across instances, refuses a second
  create, clears only through the explicit clean-stop path, and rejects a
  symlink, a readable intent, a non-regular intent, and an unsafe directory;
- a failed intent create removes only its own record, while a replacement, a
  hard link, an ACL-bearing record, or an unsynced removal is kept and blocks;
- the controller latches a create-rollback uncertainty even when the record
  later reads absent, and re-reads a safe record that another participant
  retained;
- the private runtime directory removes a stale `port.tmp` file;
- a root engine reports only a zero exit as a clean stop, while a signal and a
  non-zero exit are failures;
- the handshake gate issues one fresh nonce, accepts it once, rejects a replay,
  a wrong nonce, an expired nonce, and a malformed client nonce;
- the app completes the handshake before it asks for authorization, and a
  failed handshake never prompts;
- the app refuses a running, cleanup-blocked, or unreachable helper before it
  asks for authorization;
- the start-right validator accepts the installed dictionary before authd
  writes it and after authd adds `created`, `modified`, `session-owner`,
  `tries`, and `version`, with fixed type and value constraints;
- it accepts `identifier` and `requirement` only as bounded printable ASCII
  metadata, and refuses an empty, binary, non-string, control-character, or
  oversized value;
- it accepts `session-owner` only when it is absent or false, and `tries` only
  when it is absent or an integer from 1 to 10000;
- it refuses a missing `class`, `group`, `authenticate-user`, `shared`,
  `allow-root`, or `timeout`, an `authenticate-admin` class, a non-`admin`
  group, an unprompted user, a zero, negative, non-integer, or above-ceiling
  timeout, `rule`, `mechanisms`, `k-of-n`, `entitlement`, `entitled`,
  `entitled-group`, `password-only`, `default-prompt`, and every unknown key;
- sanitized fixtures from read-only `security authorizationdb read` output
  cover the authd metadata shape and malicious extra access-granting keys;
- the start gate refuses a missing right before it checks the form;
- the runtime directory reads the port through held descriptors and rejects a
  symlink, a path substitution, a group-writable port file, a directory at the
  port path, an oversized file, and an empty file;
- a start is refused while another stop is still finishing;
- an app start timeout cancels and closes the connection so the helper stops
  any engine that did not answer;
- a failed launch creates no session;
- shutdown stops the owned engine;
- shutdown waits for an in-flight launch and stops the late engine;
- the start gate checks one fixed administrator right before any launch, and a
  missing, malformed, or refused form never launches;
- the caller check uses the kernel audit token, not a PID;
- a partial or missing audit token is rejected;
- a Developer ID signature without the hardened runtime is rejected;
- a signature with `com.apple.security.get-task-allow` is rejected;
- a root-owned copy without its launch daemon is rejected;
- a write ACL on the helper, install directory, launch daemon, or engine is
  rejected;
- the engine launcher fails closed without root;
- the helper refuses a start before the launch intent when the exclusive lock
  is held, and refuses before spawn when the shared lock cannot be established;
- the helper refuses a start while `install-journal.json` is present, before it
  writes the launch intent or spawns an engine;
- a clean stop clears the intent and releases the helper's shared lock, while a
  timeout, a failed exit, or an unprompted engine exit keeps the intent and
  shared lock;
- a present install journal at helper startup blocks every start;
- both start-exclusion refusal results map to fixed plain sentences that name
  no path, lock, journal, token, or engine;
- the protocol names are pinned to `/var/db/hotspotshade`, `start-exclusion`,
  `install-journal.json`, handoff descriptor 5, and version 1;
- two shared locks coexist and block an exclusive lock, while an existing
  exclusive lock refuses a shared prepare and the advisory probe;
- another process cannot take the exclusive lock while the helper holds its
  shared lock;
- the lock path is refused when it is a symlink, a directory, a multi-link file,
  or group or other accessible;
- a spawned child inherits the shared lock on descriptor 5 through the exact
  file action that the launcher uses;
- replacing the lock inode creates a second lock and fails the handoff check,
  which is why the coordinator must not replace the lock file;
- closing an independent duplicate keeps the lock while one copy remains open.

`cargo test --locked --manifest-path rust/Cargo.toml` runs the Rust checks. On
macOS they cover the audit token, peer PID, an ad-hoc caller rejection, an
ad-hoc static code rejection, requirement injection, the root install metadata
rule, and a user path rejection.

These are hermetic tests. They do not start XPC, install a helper, run root, or
change a route or tunnel device. The helper executable built by SwiftPM is
unsigned, so the real helper refuses to start. That is the fail-closed result,
not a test of a signed helper.

## Production gaps that remain

The following work is required before this can be called secure or shipped.

1. **No installer.** There is no root package that writes the helper, its
   launch daemon file, the start-right definition, and the root-owned engine.
   The files here are templates and source. No installation was performed. The
   helper now fails closed at startup when the start right is absent, so a host
   without the right shows the helper as unavailable. Add the right from
   `dev.hotspotshade.tunnel.start.plist` in the same root package. The helper
   side of the start lock and journal exists, but there is still no coordinator
   that takes the exclusive lock, replaces the file set, registers launchd, and
   performs journal-based recovery. The current coordinator foundation uses
   `start.lock` while the helper and engine use `start-exclusion`, so install
   exclusion is not established. The package remains refused.
2. **No Developer ID.** The helper, engine, and app need one team identity. An
   ad-hoc or unsigned build fails closed. There is no test key and no
   certificate in this repository.
3. **No live XPC test.** The XPC listener, the peer requirement, and the
   engine spawn have not run under a signed helper. They compile, and their
   pure rules are tested. A signed test host is still needed.
4. **The audit-token accessors are not validated on the minimum macOS.** The
   app and helper use the live XPC transport, but `xpc_connection_get_audit_token`
   is a libxpc symbol that the public SDK does not declare. The session id is
   read with the libbsm `audit_token_to_asid` accessor, and the helper also
   requires the fixed word positions to agree with it. The helper resolves both
   and rejects the caller when either is absent or disagrees. Validate them on
   the minimum supported macOS version; a missing symbol makes real mode fail
   closed, not insecure.
5. **No signed engine install.** The engine path
   `/Library/Application Support/HotspotShade/engine/hotspotshade` is a
   proposal. The package and its root ownership do not exist yet.
6. **SMAppService is not enabled.** `SMAppService.daemon` runs a helper from the
   app bundle. A stock `/Applications` folder is root-owned but writable by the
   admin group. The verifier rejects that layout because a user process could
   replace the bundle. A production decision is required: use the root-owned
   package and launch daemon above, or define a stricter bundle location and
   verify it on a real host. Do not relax the verifier to make
   `SMAppService` pass.
7. **No live route or tunnel test.** The helper does not create a utun or a
   route. The existing engine cleanup paths still need the live hotspot test.
8. **The durable state cannot inspect the host.** The marker at
   `/var/db/hotspotshade/cleanup-blocked` survives a helper restart, and no
   helper path removes it. The write-ahead intent at
   `/var/db/hotspotshade/engine-session` covers the crash window before a stop
   can record a marker. The installer journal at
   `/var/db/hotspotshade/install-journal.json` is a separate refusal record; the
   helper reads its presence but does not own its recovery or removal. None of
   these files proves that an engine is gone. The helper cannot inspect the
   routing table. Route cleanup remains the engine's job. The documented
   authorized human step is: verify that no engine remains, inspect the IPv4 and
   IPv6 routes and utun devices, stop the helper, keep `start-exclusion` in
   place, and on a preview host run `preview-clear-cleanup-block`, which repeats
   those checks and removes only the two records; otherwise stop and escalate.
   Removing `cleanup-blocked` or `engine-session` by hand is not approved. A
   reviewed recovery outside the preview is still required. If an install journal is present, stop and
   use the installer coordinator recovery instead. A running helper keeps its
   in-memory block and its shared lock, so removing the helper files under it
   does not re-open starts or release the lock. Do not delete routes or
   interfaces to clear the block, and do not assume that an unowned `utun` or
   `/1` route belongs to HotspotShade. If any check is uncertain, stop and
   escalate. If the helper cannot write the intent or marker, or cannot read the
   install journal, it refuses the start; a marker write failure after a bad
   stop keeps the running helper blocked for its own lifetime, and that case
   cannot survive a restart. The helper log says so.
9. **No live administrator authorization with the fixed right.** A read-only
   `security authorizationdb read` of built-in rights on macOS 27.2 confirmed
   the authd metadata keys and value types. The validator now accepts that
   shape with fixed constraints and still fails closed on any unknown or
   access-granting key. A 2026-11-06 local preview showed the administrator
   prompt and recorded an approval, then the helper check was denied because
   the installed right had `timeout=0`. The current template uses a 30 second
   window and the helper accepts 1 to 60 seconds, but that changed right has
   not run with a live helper. The old app and helper require the zero value,
   so replace the app, helper, engine, and right together. Writing only the new
   right makes the old preview fail its check. The actual custom right
   read-back, the exact values authd adds to it, and the fixed administrator prompt have not been
   observed. The fixtures are sanitized built-in reads, not the installed
   right. Confirm the printed definition on a signed test host before release.
   Live authd behavior remains gated. The `authenticate-admin` class and every
   delegated definition stay refused.
10. **No root-owned state, home, or runtime test.** The engine home
    `/var/lib/hotspotshade`, the state directory `/var/db/hotspotshade`, and the
    per-launch `run-<uuid>` directory are proposals. The launcher creates and
    verifies the home and state directories with root ownership and mode 0700,
    and the state store syncs a first-created directory and its parent, but no
    package test has run. The package must create `/var/db/hotspotshade` as root
    `0700`; the helper also creates it on demand.
11. **The launch daemon can end the helper.** The helper stays alive when a
    stop is not clean, but launchd can still end it. The write-ahead intent and
    the durable marker are the guards in that case. They cannot prove that the
    old engine finished. A person must follow the recovery section above.
12. **Windows and Linux are separate.** This helper changes no Windows or
    Linux boundary. The Linux helper and the Windows elevation path need their
    own reviews.

## Integration order for the file owners

1. Add the helper sources to the Xcode project and sign the helper, engine, and
   app with one Developer ID team with the hardened runtime.
2. Add a root package that installs the helper, the launch daemon file, the
   start-right definition, and the engine at the paths above with `root:wheel`
   ownership and no group/other write, then creates `/var/lib/hotspotshade` and
   `/var/db/hotspotshade` as root with mode 0700. Run
   `security authorizationdb write dev.hotspotshade.tunnel.start` unconditionally
   from the packaged right definition, then read it back and validate it. On the
   reviewed host, authd permits a local process to create a non-wildcard right
   before installation. Do not assume a pre-existing right was installed by
   this package. Verify on a test host that the write replaces, rather than
   merges with, a pre-existing definition, and record the resulting identifier.
3. The app-side XPC client is `ProtectedEngineProcess` in
   `HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/`. It reads the
   expected team from the running app, verifies the install, pins the helper
   signature, starts the engine, and fails closed without a fallback.
4. The `osascript` start is removed. Do not restore it. A non-root macOS GUI
   returns `protected_helper_required`, and `hotspotshade --privileged-helper`
   fails closed.
5. The verified Unix entry point in `rust/src/privileged.rs` remains for a
   future non-macOS caller. It uses the audit token and the Developer ID
   requirement. The UID-only listener and `serve_connection` are test-only, so
   do not make them a production boundary again.

## Build and test

```sh
swift build --package-path macos/HotspotShadeKit
swift test --package-path macos/HotspotShadeKit
cargo test --locked --manifest-path rust/Cargo.toml
cargo clippy --all-targets --locked --manifest-path rust/Cargo.toml -- -D warnings
```

The Swift package builds `HotspotShadeHelper` as an executable. The build is
unsigned. Running it outside the root-owned install path exits with the generic
unavailable line. That is the expected result.
