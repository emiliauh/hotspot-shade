# Response to the independent reviews

Status: **UNAPPROVED**. Revision 4. This is a design response. It does not
implement the changes and it does not run any test.

Sources:

1. First review: thread "Review Windows broker security and lifecycle", item
   position 68. Thread id
   `thread:delegated-task:command%3Amcp%3A03268a16-2f62-4147-8102-f7277104e15e%3Adelegate-task%3A62fb4e4e-7ce4-435f-8a95-583ca3b523c6`.
2. Second review: thread "Review Windows service boundary design", final item.
   Thread id
   `thread:delegated-task:command%3Amcp%3A03268a16-2f62-4147-8102-f7277104e15e%3Adelegate-task%3A98a30f79-07a6-43c1-8ab8-61f0d80a8cf7`.
3. Third review: task 82046682, an independent review of the existing Windows
   broker. It found the preview path unreachable and listed the conditions
   before production enablement.
4. Fourth review: id `c0b94fca-d9ea-4d4f-8aa8-87de7c508503`. The task record was
   not reachable when revision 3 was written. The review content was supplied
   with the revision task and is treated as the complete independent review. It
   found B1 to B5 and H1 to H4.
5. Fifth review: id `e1b9ed6a-3041-4221-873f-3a406392400b`. The task record was
   not reachable when revision 4 was written. The review content was supplied
   with the revision task and is treated as the complete independent review. It
   found E1 to E11. Section 10 answers it.

The first two source threads were reachable and both reviews were read in full.
The third review was read in full. The fourth and fifth review contents were
supplied, not read from a reachable task record; revisions 3 and 4 say so rather
than implying a record they did not open. All five are static reviews. The
reviewers built nothing, ran nothing, and used no Windows host. That is also
true of this response.

Each finding has four parts: the finding, the design change, the residual risk,
and the evidence the finding still needs. A design change does not close a
finding. Only the named evidence closes it.

## 0. The verdict

The first review found four design blockers and eight lower findings. Revision 1
answered all twelve.

The second review accepted some of that answer and found seven blockers in it:

1. The threat table claimed that same-user processes were blocked. They are not.
2. The app's proof that the pipe server is the real service was not feasible as
   written, and the first-instance pipe flag was missing.
3. A crash between `CreateProcess` and the state write could start a second
   engine, and an inconclusive recovery check could lock the product out.
4. The `%ProgramData%` directory could be pre-created by a standard user.
5. A source credential at rest before identity-bound pairing would extend an
   existing exposure across reboots.
6. The automatic stop behavior was at risk of being dropped, and the summary
   made a Windows hotspot-loss claim that the product does not support.
7. Anonymous pipes cannot time out a blocking read without a stated mechanism.

Revision 2 accepts all seven. It corrects the threat table, removes the false
pipe-server step, adds `FILE_FLAG_FIRST_PIPE_INSTANCE`, writes a launch intent
before `CreateProcess`, adds a read-only absence proof and an explicit manual
recovery path, protects the `ProgramData` directory at install time, refuses an
at-rest credential before phase 2 pairing, keeps the source-silence loop, removes
the Windows hotspot-loss claim, and specifies bounded pipe I/O.

The second review also found lower problems: framing endianness and cap
mismatches, an incomplete error code table, the wrong stop reason, a missing
live connection gauge, missing diagnostics and failure operations, the WinUI 3
conflict with AGENTS.md, handle inheritance through `std::process::Command`, an
overstated HTTP fallback claim, an unspecified installing-person SID, an
unspecified installer technology, missing shutdown and sleep handling, an
unexplained 20 second wait, elevated-caller usability, and the .NET 8 end of
support. Revision 2 answers each one.

The fourth review found five blockers and four higher findings:

- B1: the Windows source-silence stop was described as working in a path where
  it does not. The CLI path has a coded source-silence timer. The GUI path does
  not.
- B2: a crash record can lack the adapter LUID and GUID, so the recovery check
  is inconclusive.
- B3: an image-path orphan search can be spoofed.
- B4: the app proof needs `SERVICE_QUERY_CONFIG`, and the design did not grant
  it.
- B5: stopped status rules required a zero target-side gauge, which contradicts
  an unavailable gauge.
- H1: the same gateway IP cannot identify a different hotspot.
- H2: a later pipe instance needs `FILE_CREATE_PIPE_INSTANCE`, and the design
  did not state the right.
- H3: the engine parses untrusted data as `LocalSystem`.
- H4: a normal automatic stop and a crash were not distinguished.

Revision 3 answers all nine on paper in section 9. It also fixes the session
and SCM timeout precedence. It does not close any of them.

No review gate is passed. Nothing in this directory is approved. G1 and G2 are
still blocked, now by missing evidence rather than by design errors. Revision 3
adds G2 and G4 evidence for B2 to B5 and H1 to H4.

## 1. Second review blockers

### 1.1 Same-user callers are not blocked, and the threat table said they were

**Finding.** The pipe DACL includes the person's own user SID, so any process
running as that user passes the DACL. The caller check tested only the user SID,
not elevation, and required an AppContainer SID that a full-trust packaged app
does not have. The response claimed V03 proved a same-user process was denied,
but V03 tested a second local account. The honest statement is that any
same-user process can start, stop, set the credential, and hold the single
session.

**Design change.** The threat table and sections 0, 5.2, 5.3, and 14 now state
the same-user result in plain words. The DACL and the caller check authorize the
account, not one process of the account. The service does not reject an elevated
caller of the same account. It does not require an AppContainer SID. Package
identity is optional defense in depth and does not change the same-user result.

The design keeps the parts that still matter: the caller cannot read the
bearer, the source credential, or the identity key; it cannot choose the engine
path, host, port, or arguments; it cannot make the service delete a route the
service did not record. A
same-user process can deny service to the real app by holding the single
session. That is recorded as accepted residual risk.

**Residual risk.** A same-user process can inject into the app at the same
integrity level and inherit its authority. The boundary does not isolate
processes of one account. It isolates the privileged engine from other accounts
and from remote clients.

**Evidence needed.** V03 shows a same-user process connects and controls the
tunnel, and cannot read the secret. R13 shows a second non-administrator account
is denied. R14 shows an elevated process of the same account is allowed. S24
checks the threat table for any row that claims a protection the design does not
provide.

### 1.2 The app's server check was not feasible, and the first-instance flag was missing

**Finding.** Section 5.4 had a medium-integrity app open the `LocalSystem`
service token. That is very likely denied, and the design did not label it as a
hypothesis. V01 used an unprivileged console host, so it could not exercise that
step. `FILE_FLAG_FIRST_PIPE_INSTANCE` was never required, so a squatter's pipe
instance could coexist with the service's. The claim that a standard user could
not create the pipe was false while the service was demand stopped.

**Design change.** The service creates the pipe with
`FILE_FLAG_FIRST_PIPE_INSTANCE` and fails closed with `pipe_name_in_use` if the
name already exists. The app does not open the service token. It uses six
checks that do not require opening the service token:

1. Query the SCM for the service state and PID. For a status read, do not start
   the service. For a person start action, call `StartService` and repeat.
2. Connect with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`.
3. Compare `GetNamedPipeServerProcessId` to the SCM PID.
4. Read the pipe owner with `GetSecurityInfo` and require `SYSTEM`. This is a
   hypothesis with test V01b.
5. Compare the SCM `lpBinaryPathName` to the installed service path.
6. Re-query the SCM state and PID after the connection.

If any check fails, the app closes the pipe and reports `boundary_auth_failed`.
It sends no frame to a squatter.

**Residual risk.** A squatter can create a later pipe instance. The SCM PID
check rejects it. A squatter that wins the name first makes the service fail to
start, which is a denial of service, not a secret leak. `GetSecurityInfo` with
`SE_KERNEL_OBJECT` on a pipe handle is not yet proven on a Windows host.

**Evidence needed.** V01: a first-instance squatter makes the service fail
closed and the app report `engine_unavailable`. V01b: a later-instance squatter
is rejected by the SCM PID check, and the injected owner seam fails closed when
it reports a non-`SYSTEM` owner. V11: the app refuses the squatted name. R12:
the installed service passes all six checks, including the real
`GetSecurityInfo` owner read.

### 1.3 Crash and restart could still produce a second engine, or a permanent lockout

**Finding.** The design never said when the state record was written. A fresh
service defaulted to `cleanup=ok`. If the service crashed between
`CreateProcess` and the record write, the restarted service could start a second
engine beside the orphan. The documents also let a start proceed once an old
engine exited even though it wrote no final frame, which contradicts the rule
that a missing final frame is `cleanup_unknown`. An inconclusive `recheck` kept
the latch forever, and the manual recovery path was not designed. Whether the
Wintun adapter survives an engine crash was not stated as a hypothesis.

**Design change.** The state record is written before the process is created:

1. Before `CreateProcess`, choose a unique adapter name and write
   `phase=launching`, a new `intent_id` and `launch_nonce`, `cleanup=unknown`,
   `routes_may_exist=0`, the planned adapter name, and no PID. Flush the temp
   file, then replace the record with `MoveFileExW` using
   `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` on the same volume. Do
   not rely on `ReplaceFileW`'s write-through flag; it is not supported.
2. Only then create the pipes and the process. The nonce travels on a
   descriptor, never a command line.
3. Immediately after `CreateProcess` returns, write the PID and creation time
   with `phase=running`. If that write fails, close the parent, wait a bounded
   time, and record `cleanup=unknown`.
4. The engine creates the adapter and reports its LUID and GUID before it
   installs a route. The service writes `phase=adapter_ready` and sets
   `routes_may_exist=1` before it acknowledges route installation.
5. On the final frame, write `phase=stopped` with `cleanup=ok` or
   `cleanup=failed` and the stop reason.

Recovery reads the record, never defaults to `ok`, and refuses a start until the
absence proof is clean. A `launching` record with no PID triggers an image-path
observation, not adoption (B3). A matching process is recorded as
`orphan_candidate`, blocks a start, and receives no frame. A `running` record is
matched by PID and creation time, so PID reuse is detected. A missing,
unreadable, or version-mismatched record is `cleanup=unknown`.

Revision 4 note: the image-path block above is narrowed by E7 (section 10.7),
and the launch gate in E6 (section 10.6) adds a `launched` phase.

The latch clears only through a person `recheck` that returns `Clean`, or
through an explicit administrator override in
`HotspotShade.ServiceRepair.exe --acknowledge-cleanup-unknown`. The override
records the observed route and adapter snapshot, the administrator account, and
a fixed acknowledgement string. It never deletes a route. A start after an
observed orphan exits still needs a clean `recheck`, because the new service
cannot read the old event pipe and did not adopt it.

H1: whether the Wintun adapter and its device-bound routes disappear when the
engine dies is unknown. The design does not assume that they do. If the adapter
survives, `recheck` reports `Present` and keeps the latch. A live Windows test
must answer H1.

**Residual risk.** The manual override is an administrator action and needs
maintainer approval. Without it, an inconclusive check is a permanent lockout,
which is not acceptable shipped behavior. The state record is only as good as
the file system; a torn write is detected by the sequence and version fields
and is treated as `cleanup=unknown`, not as clean.

**Evidence needed.** V54: restart the host with a live fake engine, observe it
without adoption, refuse a start, and require a clean `recheck` after it exits.
V67: crash injection between the intent write and `CreateProcess`. V68: crash
injection between `CreateProcess` and the PID write. V80 to V83: the adapter
identity and route gate. V57 and V58: final frame and `recheck` behavior. V63
and V64: no credential at rest. H1: a disposable Windows VM with a real engine
crash and a route table read.

### 1.4 The ProgramData directory can be pre-created by a standard user

**Finding.** The default `%ProgramData%` ACL lets users create subfolders. A
`LocalSystem` service that does an atomic replace inside a folder a user owns is
open to link and junction redirection. The installer must create the folder with
a protected DACL, and the service must check its owner before every write.

**Design change.** The installer creates `%ProgramData%\HotspotShade\` with a
protected DACL, owner `SYSTEM`, full control for `SYSTEM` and `Administrators`,
and no write or create-child right for `Users` or `Authenticated Users`. If the
directory already exists, the installer checks the owner, the protected DACL,
and the absence of a reparse point. It accepts only `SYSTEM` or `Administrators`
as owner, a protected DACL, and no non-administrator write or create-child
right. Otherwise it stops and tells the person to remove the directory with
administrator help. It never adopts or silently repairs a user-owned directory.

Before every state or credential write, the service re-checks the directory
owner and the final path, opens the file with `FILE_FLAG_OPEN_REPARSE_POINT`,
and refuses a reparse point. The replace uses a temp file in the same directory
and a same-volume `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`.

**Residual risk.** An administrator can replace the directory. Administrator
actions are out of scope. A backup operator with restore rights can also write
there. The design does not claim protection from either.

**Evidence needed.** V66: a standard user pre-creates the directory; the
installer refuses it. V55: the state record DACL is `SYSTEM` only. R09: the
installed directory owner and DACL are exactly as specified. V67 covers the
write path after a failed owner check.

### 1.5 A credential at rest before identity-bound pairing extends the exposure

**Finding.** The credential is bound only to a gateway address and port. Every
iPhone hotspot commonly uses `172.20.10.1`, so a stored token would match any
of them. The Windows presence loop already sends the cleartext SOCKS token to
the stored target every 2 seconds while it runs. Today that exposure ends when
the session ends. With DPAPI on disk it would last across reboots. Machine-scope
DPAPI adds nothing beyond the file DACL.

**Design change.** Phase 1 keeps no credential at rest. Manual entry is memory
only. The app holds the typed value only until `credential.set` completes. The
service keeps a `Zeroizing` buffer and clears it on stop, app loss, engine loss,
gateway change, `credential.forget`, and service stop. The service does not use
DPAPI in phase 1. It does not write a credential file at install time.

The background presence loop runs only while a tunnel is running and the app
session is live. The app may run one explicit `probe` before start, rate
limited. The token is sent only to the stored private gateway. The engine
checks the physical default gateway before every probe and stops with
`gateway_changed` if it moved.

Phase 2, identity-bound pairing, is the only path that may write a credential
at rest. It writes `source-device.dat` only after pairing proves the source
device identity. The file is in the protected directory with a `SYSTEM`-only
DACL. Machine-scope DPAPI is defense in depth, not the primary control.

**Residual risk.** The token still crosses the hotspot link in cleartext. The
source device app compares it in constant time. That is existing behavior and
the design does not change it.

**Evidence needed.** V48: neither the event pipe nor the state record contains
the bearer or the credential. V63: a fresh install writes no credential file and
the service starts with `paired=0`. V64: after stop, app loss, and service stop,
the in-memory credential is gone and a new session starts unpaired. V65: the
physical gateway check detects a changed gateway. O5 records the decision.

### 1.6 The automatic stop was at risk, and the summary claimed a Windows hotspot stop

**Finding.** The source-silence stop lives inside `GuiServer::run` through
`start_presence` and `auto_stop_loop`. The second review said that on Windows
`observe_link` returns `Some(true)`, so only probe silence stops a Windows
tunnel. That statement was overbroad and revision 3 corrects it. The new
`engine` command also did not say it keeps these loops. The summary claimed "a
lost hotspot stops the tunnel", which AGENTS.md forbids for Windows.

**Design change.** The engine command owns the monitor. `start_presence` and
`auto_stop_loop` are extracted into a monitor that uses the same
`AutoStopPolicy`, not a duplicate. The monitor samples every 2 seconds. The
source probe runs only while a tunnel runs and the app session is live. It stops
on stop, app loss, engine loss, or `shutdown`.

Revision 3 corrects the Windows path statement:

- The Windows CLI `tun` branch supplies `|| Some(true)` as its link closure, so
  its source-silence timer runs when a physical hotspot interface resolves. If
  the interface is missing or invalid, the CLI warns and auto-stop is off.
- The command-line GUI's `observe_link` returns `None` on Windows, and
  `auto_stop_sample` resets the policy on `None`, so the GUI path does not
  currently stop on source silence.
- The service monitor gets a three-state link observation. `Unknown` never
  produces `hotspot_lost` and never clears the source-silence interval. A probe
  that cannot run is `Unavailable` and clears it. This is the B1 correction.

There is no `hotspot_lost` stop and no automatic stop on link loss. The app and
the docs must not claim one. Windows has no enabled hotspot link observer. The
monitor writes a final cleanup frame on the normal stop path. A hard crash
cannot, and the service records `cleanup=unknown`.

**Residual risk.** A source device that answers but is otherwise broken keeps
the tunnel open. That is the same behavior as the current Windows CLI. It is not
a hotspot loss claim. The GUI gap remains until its monitor is changed.

**Evidence needed.** T3.20: the CLI-shaped monitor stops after 90 seconds of
silence with `source_device_gone`. T3.21: the GUI-shaped monitor resets on an
unknown link and does not stop; this records the gap, not desired behavior.
T3.22: the service monitor with `Unknown` link stops after 90 seconds and does
not stop on link loss. V96: a Windows VM check with an unknown link. V64: the app
shows `source_device_gone` and not `hotspot_lost`. L02 records that a Windows
hotspot loss alone does not stop the tunnel, and that no claim is made.

### 1.7 Anonymous pipes cannot time out a blocking read

**Finding.** Pipes from `CreatePipe` do not support overlapped I/O. "One bounded
read" and "remaining budget as its timeout" needed a stated mechanism, such as
`CancelSynchronousIo`, peek-and-poll, or uniquely named overlapped pipes. The
"anonymous pipe has no name" statement should not carry the security argument.

**Design change.** The design specifies the mechanism:

- All pipes use a 131072 byte buffer, so a 65536 byte frame and its 4 byte
  length prefix fit. The frame cap is 65536.
- The service reader uses `PeekNamedPipe` in a loop, checks the absolute
  deadline every 25 ms, reads only bytes the kernel reports available, and
  returns `timeout` at the deadline.
- The engine reader uses the same loop for `control_in` and watches the parent
  pipe.
- A write runs on a dedicated writer thread. The caller waits on a bounded
  channel with the same deadline. On timeout it calls `CancelSynchronousIo` on
  that thread and closes the handle.
- One request is in flight, so one full frame fits in the buffer.

The security argument is the explicit `SYSTEM`-only security descriptor on each
anonymous pipe, not the absence of a name. A medium-integrity process cannot
open it. Handle duplication needs `PROCESS_DUP_HANDLE` on the `LocalSystem`
engine, which Windows denies.

**Residual risk.** `CancelSynchronousIo` on a pipe handle is documented but its
interaction with a handle close needs a Windows test. A malicious peer can
still make the service wait until the deadline. The deadline bounds it.

**Evidence needed.** V40 and V41 for read deadlines, V69 for `PeekNamedPipe`
partial frames, and V70 for a blocked write and `CancelSynchronousIo`.

## 2. Second review other findings

| Finding | Change in revision 2 | Evidence |
|---|---|---|
| Framing said little-endian and gave 64 KiB and 256 KiB for the same pipe. | All Windows pipes are 4 byte big-endian length with a 65536 byte cap. The Unix 262144 constant is named only as a pattern source. | S25, T3.01 |
| Error codes: `cleanup_blocked` arrives as `service_start`, the table omits `protocol_mismatch`, `engine_stop_timeout`, `launch_timeout`, `boundary_busy`, `busy`, and `forbidden`. | `cleanup_blocked` gets its own typed engine error. The table in section 11.2 includes every code the design uses. | S10 to S17, V43 |
| The engine stop reason is `source_device_gone`; the design said `source_lost`. | The design uses `source_device_gone` everywhere. | S17, V64 |
| A live target-side `tcp_flows_active` gauge exists but is not exported. | The service exports it under the explicit name `relay.tcp_flows_active`. It does not substitute it for `phone.connections`, which comes from the phase 2 authenticated status. | T3.14, T3.17, V45 |
| The operation set has no diagnostics, recent failures, or Check now probe. | `diagnostics`, `failures`, and `probe` are in the fixed operation set. `probe` uses a short-lived helper with no adapter or route. `ttl_bad` remains visible. | S18, S25, V62, V74 |
| O1 offered WinUI 3, which conflicts with AGENTS.md. | O1 offers a full-trust WinUI 2 XAML Islands desktop host, a UWP preview, and a packaged broker bridge. WinUI 3 is not offered. | S05, V30 |
| `std::process::Command` always inherits handles, so `bInheritHandles = FALSE` cannot be met through `SystemRunner`. | The design clears `HANDLE_FLAG_INHERIT` on every control handle and uses a native launcher for children that need `bInheritHandles = FALSE`. Rule 7.3.2 is the control that works today. | V50 to V52, T3.06 |
| The HTTP fallback sent the bearer before checking the reply instance id, and the docs overstated the protection. | The docs say the bearer may reach a squatter and is dead. The instance check prevents trusting the reply, not the send. | V12, V56 |
| The installing person's SID is undefined when a standard user elevates with administrator credentials. | The installer resolves the interactive logon SID, not the elevated token SID, and accepts an explicit `--user-sid` or stops. | S27, R11 |
| The installer technology is unspecified. | A per-machine MSI built with WiX or an equivalent elevated installer is assumed. MSIX is not chosen. O16 records the prerequisite. | R01 to R03 |
| Shutdown, preshutdown, sleep, and resume are unspecified. | Section 8.6 handles shutdown, preshutdown, and session logoff with the bounded stop path. Sleep and resume are hypothesis H2. | V72, V73, R10 |
| The 20 second wait hint was called "below the SCM default" without support. | The design says to confirm the target host SCM timeout and uses 20 seconds only as a bounded wait hint. | R04, S28 |
| Refusing elevated callers would lock out accounts with UAC off. | The service does not reject an elevated caller of the same account. It records `elevated_caller` for visibility. | R14, S24 |
| A second local account needs an administrator. | The second-account and elevated-caller rows moved to tier R, which already needs administrator approval per run. Tier V stays unprivileged. | R13, R14 |
| .NET 8 support ends on 2026-11-10, and tiers H and V pin .NET 8. | The service targets a supported runtime, recommended .NET 10 LTS. The broker's `net8.0` target is existing code and must be retargeted before implementation. | O15, S26 |

## 3. First review findings

### 3.1 Who holds the privilege and who holds the secret

**Finding.** `Win32EngineHost` assumes that the process that holds the bearer is
also the elevated parent of the engine. The only real launch path needs a
privileged owner. The elevation check must not be relaxed, because a secret held
at medium integrity could be read by any process of the same user.

**Design change.** The `HotspotShadeEngineSvc` Win32 service owns the privilege
and the secret. It is installed once with administrator consent, runs as
`LocalSystem` by default, and is demand started. The app is medium integrity and
holds no bearer and no stored credential. In phase 1 manual entry it holds the
typed token only until `credential.set` completes. The app authenticates by
caller identity over a named pipe, not by a shared secret.

**Residual risk.** The engine runs as `LocalSystem`. Its control surface is the
highest value target on the machine. The design reduces it to one authenticated
pipe with a fixed operation set and a redacted status schema. It does not remove
the risk. O2 records the narrower token option.

**Evidence needed.** V02: the service starts the engine and the app controls it
with no bearer or stored credential in the app process. V03: a same-user process
is allowed and cannot read the secret. R13: a second account is denied. S01: no
`Automatic` start and no recovery action.

### 3.2 The client never proves it talks to the real engine

**Finding.** The broker picks a fixed port with no retry. The engine binds with
a plain `TcpListener::bind` and no exclusive-address option. `TryGetEndpoint`
checks only that a process handle exists. A same-user process that takes the
port first receives the bearer and can fake status.

**Design change.** The primary design removes the port. The engine binds no
socket in service mode. The service talks to it over inherited anonymous pipes
with explicit security descriptors. There is no port to squat, no reserved range
to collide with, and no bearer header on any request.

If review rejects the control pipe, the HTTP fallback requires `--port 0`, an
exclusive bind, a `GetExtendedTcpTable` PID proof, an instance id from the
readiness frame, and the bearer sent only after those checks. The docs say the
bearer may still reach a squatter and is dead.

**Residual risk.** In the fallback, the service trusts a TCP table read and the
process handle. A race can make the engine bind fail, which produces
`engine_unavailable`, not a usable bearer.

**Evidence needed.** V10: a squatter binds the port and receives no usable
bearer. V11: a squatter creates the pipe name first and the app refuses. V12:
after the engine exits, a new listener on the same port receives no request.

### 3.3 Nothing watches the engine process

**Finding.** No code waits on `processHandle`. `HostLost` is called only from
tests. If the engine crashes, the broker keeps polling a dead port with the
bearer and reports "unavailable" instead of `EngineLost`. The host also allows
one launch per broker run.

**Design change.** The service registers one blocking wait on the process handle
on a dedicated thread. The wait calls `HostLost`. A `HostLost` state is terminal
for the generation. No relaunch happens. A retry creates a new generation with
new pipes, a new plan, and a new bearer. Every asynchronous result carries its
generation. `closed` is a generation state, not a process lifetime flag.

**Residual risk.** A crash can leave routes. In the prototype the service does
not know which route objects the engine created, so the read-only absence check
and the latch are the honest answer. The preferred split in architecture section
4.6 records the adapter identity and the route set before the first route, so the
service can remove only its own objects after the engine exits. That split is
unproven. Neither path claims clean removal on a crash.

**Evidence needed.** V20: terminate the fake engine and assert `engine_lost` and
no relaunch within 30 seconds. V21: the wait fires within 250 ms. V22: a late
generation result is ignored. V23: a failed launch can be retried.

### 3.4 The app service host does not exist

**Finding.** The UWP side must host `hotspotshade.engine`, check
`CallerPackageFamilyName`, and never relay another app's connection. In-process
app service connections are typically closed when the UWP app is suspended, for
example when minimized. The broker reaction is verified. The suspension trigger
is a hypothesis.

**Design change.** The privileged boundary no longer depends on the app service.
The boundary is a named pipe with caller identity checks. The primary app host
is a full-trust desktop app built with WinUI 2 controls in a XAML Islands host.
It speaks the pipe directly and has no suspension problem. The UWP app stays the
labeled preview. The UWP compatibility path, if needed, is a packaged full-trust
broker that bridges the app service to the same pipe. It does not change the
tunnel stop path, because a lost session is a stop by design.

**Residual risk.** Choosing a desktop host is a product change. It replaces the
current UWP real-mode base. That is O1 and it is blocking. WinUI 3 is not part
of this design and would need an AGENTS.md change.

**Evidence needed.** S05: the UWP package still declares no extension and no
capability. V30: a desktop host client connects to the pipe and survives a
window close. V30b: a minimized window does not stop the session.

### 3.5 Request time is not held to the stated bound

**Finding.** `Send` ignores the cancellation token. `ReadStatusAsync` and
`StartAsync` pass the token only to `Task.Run`. Each phase has its own timeout
and `ReadBody` resets the receive timeout on every read, so one call can exceed
the 5 second limit while it holds the service gate.

**Design change.** One absolute deadline per request, computed before the first
byte. The remaining budget, not a fresh timeout, is applied to every blocking
step. The control pipe makes this a single bounded read with `PeekNamedPipe` and
a 25 ms poll.

For the HTTP fallback the design adds a deadline watchdog that closes the
request handle, a minimum connect retry count, a per-read deadline check with no
timeout reset, and readiness from the event pipe instead of a poll window. The
exact WinHTTP option number must be checked against `winhttp.h` at
implementation time. It is not guessed here.

**Residual risk.** `WinHttpCloseHandle` from a watchdog is the documented way to
abort a blocking receive, but its interaction with the gate release must be
tested. A late completion after the handle closes must not write state.

**Evidence needed.** V40: a fake engine accepts and never replies; every request
ends within the deadline plus 250 ms. V41: the gate is released after a timeout
and the next request is served. V42: a refused connect consumes no more than one
attempt and reports within the deadline.

### 3.6 Status codes lose information

**Finding.** `MapPost` turns every 400 into `NotReady`. That hides
`cleanup_blocked`, `manual_phone`, and the administrator error. A 401 maps to
`EngineUnavailable`. 404, 415, and 500 also collapse.

**Design change.** The engine returns a fixed machine code on every error. The
service maps the code, not the HTTP status and not the message text. The full
table is in `WINDOWS_SERVICE_ARCHITECTURE.md` section 11.2.

Key decisions:

- A 401 equivalent is `boundary_auth_failed` and is fatal for the generation. It
  is never retried with the same bearer.
- `cleanup_blocked` is its own code and disables Start. It is not `not_ready`.
- `manual_phone` has its own code and tells the person what to enter.
- 404 and 415 are `protocol_mismatch`, not `engine_unavailable`.
- A timeout is `timeout` and the app shows unknown. It is never "off".

**This requires an engine change.** The current generic `error()` body has no
code. `cleanup_blocked` currently arrives as `service_start`. Without those
changes, the mapping is guesswork and the finding stays open.

**Residual risk.** A new code can be added on one side and not the other. The
protocol test must fail closed on an unknown code and must not fall back to the
HTTP status.

**Evidence needed.** S10 to S17: a table driven test over every code. V43: a
live fake engine returns each code and the app text is exact. S18 proves no
mapping branch reads the human message.

### 3.7 Redirects

**Finding.** Redirects are handled correctly today. Option 88 with `NEVER` is
set on each request and the request fails closed if the option cannot be set,
before the bearer header is added. A 3xx becomes `EngineUnavailable`.

**Design change.** Keep the behavior. In the pipe design, redirects do not
exist. If the HTTP fallback is kept, a 3xx becomes `protocol_mismatch` and is
fatal for the generation, not a generic unavailable.

**Residual risk.** None beyond the fallback path. The current behavior is
correct and must not regress.

**Evidence needed.** V44: a fake engine returns 302 and the service reports
`protocol_mismatch` and sends no second request.

### 3.8 Engine contract gaps

**Finding.** The start body carries no token, so the Windows engine falls back to
a stored target or returns `manual_phone`. `phone.connections` is always null, so
once running every status becomes `BadResponse`. The engine needs a pairing path
that keeps the stored credential and bearer out of the app, a source connection
count from the phase 2 authenticated status, and a separately named target-side
gauge.

**Design change.**

- Credential: the service holds it and passes it to a start request that the app
  never builds. The app sends only `start` with a ping boolean. The service adds
  the credential. The engine keeps it zeroized.
- Source count: `phone.connections` is the connection count reported in the
  source device's authenticated pairing status answer. That answer requires a
  paired identity, so phase 1 manual mode keeps `phone.connections` empty with
  `phone.connections_known=0`. Phase 2 supplies it. It is never filled from a
  target-side relay counter.
- Target gauge: the engine exports the existing `tcp_flows_active` gauge from
  `rust/src/relay.rs` under the explicit name `relay.tcp_flows_active`, with
  `relay.tcp_flows_active_known`. It counts open TCP relay flows that the target
  device carries. The app labels it "local relay TCP flows", never "source
  device connections". It is not a substitute for `phone.connections`.
- Unknown counts: an unavailable source count and an unavailable target gauge
  are shown as unknown and do not invalidate the status. The current rule that
  turns a missing count into `BadResponse` is removed.
- Pairing: version 1 keeps manual credential entry as a labeled memory-only
  fallback that runs the app's `probe` operation on demand. Version 2 adds
  identity-bound pairing. The app never receives the token back from the service
  in either phase. It holds the typed value only until `credential.set`
  completes.

**Residual risk.** The source device count can be stale if its answer is old.
The design clears it rather than showing an old value. The target gauge can be
wrong if a flow is half-closed or reset; if a test shows a mismatch, it publishes
`relay.tcp_flows_active_known=0` rather than a guess. The two counts must never
be added, compared, or substituted.

**Evidence needed.** T3.14 and T3.17: a loopback relay creates and closes flows
and the target gauge matches the observed live sockets. V45: a running status
with a fresh source count shows it; an unavailable source count stays unknown
while a separate target gauge is shown. S19 and V62 check that no path fills
`phone.connections` from `relay.tcp_flows_active`.

### 3.9 Uncleared copies of the secret

**Finding.** Each request builds immutable strings from the secret. Those copies
stay on the managed heap although the comments say every copy is cleared.

**Design change.** No managed `string` ever holds the secret. The service keeps
one sealed buffer and unseals it only to write the pipe. In the HTTP fallback the
header is built in a pinned `char[88]`, passed with an explicit length, and
cleared immediately.

**Residual risk.** A managed buffer can still be moved by the garbage collector
if it is not pinned. The design pins it for the write. A memory dump of a
`LocalSystem` process needs administrator rights, which is out of scope.

**Evidence needed.** S20: a source contract test proves no secret conversion and
no string concatenation in the boundary client. V46: a round trip through
`CryptProtectMemory` returns the exact 64 bytes and the buffer is zero after
clear.

### 3.10 Handle inheritance

**Finding.** The broker side is correct. The read ends are inheritable from
`TryCreate` until the launch. On the engine side the parent handle stays
inheritable and `netsh` probably inherits it. `read_gui_token` did not check
`GetFileType == PIPE` when the first review was written.

**Design change.**

- Create the pipes inside the launch critical section, not at service start.
- Make the service ends non-inheritable immediately. Keep only the engine ends
  inheritable, and only until `CreateProcess` returns.
- Hold a service wide launch mutex across the creation and the launch.
- On the engine side, check `GetFileType == FILE_TYPE_PIPE` on every control
  handle and clear `HANDLE_FLAG_INHERIT` before any child starts. The tree now
  does this for `token` and `parent` through `seal_windows_control_handle`; the
  new `engine` command must use it for `control_in`, `control_out`, and `event`.
- Launch `netsh` with `bInheritHandles = FALSE`. Until that native launcher
  exists, rule 7.3.2, clearing the inherit flag, is the control that works.

**Residual risk.** Windows requires handles in
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to be inheritable, so a very short window
cannot be removed entirely. The launch mutex and the creation order bound it to
the `CreateProcess` call.

**Evidence needed.** V50: a fake engine reports its inheritable handles and the
list is exactly five. V51: a child of the fake engine reports zero control
handles. V52: after a failed launch the service has zero inheritable handles.

### 3.11 The single-instance mutex can be squatted

**Finding.** `Local\HotspotShade.WinUI2.Broker` uses the default DACL. Any
process in the session can hold it, and the broker exits silently with code 0.

**Design change.** The privileged layer relies on the SCM, which guarantees one
service instance. The broker mutex is removed with the broker. If a single
instance guard remains anywhere, it has an explicit DACL and a failure to
acquire is reported, never a silent exit 0.

**Residual risk.** A squat on a non-privileged guard is a denial of service only.
It cannot grant control of the engine.

**Evidence needed.** S21: a source contract test proves the service has no
single-instance mutex and that no path exits 0 on an acquisition failure.

### 3.12 A second engine can start during cleanup

**Finding.** If the engine does not exit within the 8 second grace, the broker
closes the handle and exits. A restarted broker can then launch a second engine
while the first is still removing routes. `cleanup_blocked` is per process, so it
does not prevent this.

**Design change.** Four layers:

1. The service holds the lifecycle gate across the process wait, so a start
   cannot overlap a stop.
2. A process that does not exit inside 12 seconds keeps its handle. The state
   becomes `Stopping(waiting)`, the service reports `engine_stop_timeout`, and a
   later start is refused. The process handle is not closed.
3. The state record holds the PID and the process creation time. A restarted
   service reopens that process, compares the creation time to defeat PID reuse,
   and refuses to start until it exits and a clean `recheck` passes.
4. A `launching` record with no PID triggers an image-path observation before
   any new launch. A matching process blocks a start and is never adopted by
   image path (B3).

**Residual risk.** After a service crash the record is the only memory. If the
record is lost or unreadable, the service fails closed and reports
`cleanup_unknown`, not clean.

**Evidence needed.** V53: a fake engine hangs for 20 seconds; a start is refused
and no second process is created. V54: restart the service host with a live fake
engine and assert the refusal, then assert the start stays refused after it exits
until `recheck` is clean. V67 and V68 cover crash injection around the launch.

## 4. The 82046682 review

An independent review of the existing Windows broker (task 82046682) found the
preview path unreachable and listed the remaining conditions before production
enablement. Revision 2 incorporates them. None is closed.

| Finding | Design answer | Evidence |
|---|---|---|
| The preview is unreachable: `asInvoker` plus `Win32EngineHost` returns `AdminRequired`. | The preview is not a capability. Real mode uses the installed service. O1 decides the host. | S31, V02 |
| A loopback endpoint can be squatted, and the port can be taken over after the engine exits. | The primary design removes the port. The fallback proves the endpoint for every generation with `--port 0`, an exclusive bind, a PID check, and an instance id. A cached endpoint is never reused after an engine exit. | V10, V12, V56 |
| The app service must check `CallerPackageFamilyName` and accept one peer. | The primary design replaces the app service with the pipe. A UWP bridge, if used, checks the caller package family and accepts one broker peer. A second peer is refused. | S29, V75 |
| Loose-file developer registration can place the broker and engine outside a trusted root. | Real mode is a per-machine MSI under `%ProgramFiles%`. Developer registration and an unpackaged layout are preview-only. The engine path is checked for reparse points and must resolve under the install root. | S30, V76, R15 |
| Process exit and stop timeout must be observed, and a second engine must be prevented. | The state record, launch intent, process wait, 12 second cleanup wait, latch, and image-path observation without adoption are the controls. No `TerminateProcess`. | V20 to V24, V53, V54, V67, V68, V84 |
| UWP suspension can stop the real-mode session. | The primary host is a full-trust WinUI 2 desktop app. The UWP app stays the labeled preview. A bridge inherits the suspension stop for the app session. | V30, V30b, V77 |
| The current status schema and source token provisioning are not the new contract. | Section 11 of the architecture defines the fixed schema, `ttl_bad`, separate source and relay counts, fresh-only source counts, phase 1 manual provisioning, and phase 2 pairing. | S18, S19, S25, V43, V45, V62, V63, V64 |
| Retry behavior is implicit and can leave a dead host. | Generations, one launch per 2 seconds, late-result discard, and explicit retry only from a person action. | S07 to S09, V22, V23 |
| There is no Windows runtime evidence. | The design claims no Windows host result. Tier V and tier R must run on a Windows VM before production enablement. | Tier V, tier R |

No production enablement is approved. The preview is unreachable. The design is
UNAPPROVED.

## 5. Confirmed correct items that must not regress

The first review confirmed these. The design keeps them and adds a test id.

| Item | Keep | Test |
|---|---|---|
| The secret never appears on the command line; the argument list is fixed | Yes. A new command adds only handle numbers. | S02, S03 |
| The secret is copied before the launch task and cleared on every failure | Yes, extended to one sealed buffer per generation | S20 |
| The token pipe is written once and closed, so the engine sees end of file if the parent dies | Yes | T3.15 |
| The broker never calls `TerminateProcess` | Yes. The service never terminates either. | S21 |
| Broker entry rules: no arguments, package identity, field validation, credential keys refused | Yes, adapted to the service pipe | S04, S06 |
| `NO_PROXY`, IP literal, 256 KiB cap, redirect never | Yes in the fallback; absent in the pipe design | V44 |

## 6. Findings this response amends

1. **The first review suggests `SO_EXCLUSIVEADDRUSE` as the endpoint fix.** It is
   necessary in the fallback and it is not sufficient alone. The service also
   needs the PID proof and the instance id, because an exclusive bind ends when
   the engine exits. The design adds both. The primary design removes the port.

2. **The second review asks for proof that a pipe handle returns its owner
   through `GetSecurityInfo`.** The design includes that check and labels it a
   hypothesis. It is not used as the only proof. The SCM PID and the installed
   service path are the primary proofs. The app fails closed if any check is
   inconclusive.

3. **The first review's route check note.** `rust/src/windows_route_verify.rs`
   proves that the expected routes are present and owned. It does not prove
   absence. Clearing a cleanup latch needs the inverse proof: no route with the
   recorded prefixes is bound to the recorded adapter LUID and GUID, and the
   recorded adapter is absent. That is `verify_absence`, derived requirement D1.

## 7. Derived requirements not in the reviews

| Id | Requirement | Why |
|---|---|---|
| D1 | A bounded absence proof for owned routes and the adapter before a cleanup latch clears | `verify` proves presence, not absence |
| D2 | A final cleanup frame from the engine before exit | `cleanup_blocked` dies with the process |
| D3 | An event pipe for readiness and final state | Windows has no port file, and stdout is not available in a service |
| D4 | Server authentication in the app, using the SCM PID and the pipe owner | A medium process can create the pipe name first |
| D5 | An engine error `code` on every error reply | The HTTP status cannot carry the cause |
| D6 | A source device count from the phase 2 authenticated status, and a separate target-side `relay.tcp_flows_active` gauge with explicit known flags | An unknown source count must be shown, not filled with a target-side flow count |
| D7 | A service instance id on the wire | Cached samples must be discarded after a service restart |
| D8 | A launch intent record written before `CreateProcess` | A crash must not hide an orphan engine |
| D9 | A read-only manual recovery path for an inconclusive absence proof | A permanent latch is a lockout |
| D10 | A protected `ProgramData` directory with an owner check before every write | The default ACL lets a standard user pre-create the folder |
| D11 | Bounded pipe I/O through `PeekNamedPipe` and `CancelSynchronousIo` | Anonymous pipes cannot time out a blocking read |
| D12 | A source-silence monitor that treats an unknown link as unknown and does not clear the interval | The GUI resets on `None`; Windows has no link observer |
| D13 | An adapter identity and route-install gate recorded before any route exists | A crash before the identity write otherwise leaves an inconclusive check |
| D14 | No orphan adoption by image path; a nonce proof before any future adoption | Any same-user process can run the installed image |
| D15 | `SERVICE_QUERY_CONFIG` in the service descriptor and the app open rights | The server path check calls `QueryServiceConfig` |
| D16 | Unknown counts when no live engine status exists | A stopped status has no confirmed gauge |
| D17 | A link identity of interface LUID or GUID plus gateway, and no same-IP hotspot claim | A private gateway address is not unique |
| D18 | No `FILE_CREATE_PIPE_INSTANCE` for the interactive user | A later instance needs the specific right |
| D19 | A final stop frame, an event drain, and a crash classification rule | A normal auto-stop also exits the process |

## 8. What still blocks integration

The design answers all three reviews on paper. Integration is still blocked by
the review gates in `OPEN_DECISIONS_AND_REVIEW_GATES.md`:

- G1 architecture approval, including the app host decision O1 and the runtime
  decision O15
- G2 boundary threat model approval, including acceptance of the same-user
  residual risk and the no-at-rest credential decision O5
- G3 engine protocol and transport approval
- G4 lifecycle and cleanup approval, including the manual recovery path O7,
  the adapter identity and route gate (B2), the no-adoption rule (B3), the
  automatic-stop versus crash rule (review H4), and the session and SCM
  precedence
- G5 test matrix approval
- G6 live test approval by the device owner

In addition, B1 needs a code-level monitor test, B4 needs the real service
descriptor, B5 needs the stopped-status rule in the schema, review H1 needs the
link identity check, review H2 needs the exact DACL, and review H3 needs either
a proven split or a written owner acceptance. None exists.

No gate is passed. Nothing in this directory is approved. No production
enablement is approved.

## 9. Fourth review findings

Review id `c0b94fca-d9ea-4d4f-8aa8-87de7c508503`. The task record was not
reachable; the supplied content is treated as complete. The review is a static
read. Revision 3 answers each item on paper and closes none.

### 9.1 B1: the Windows source-silence stop is not one behavior

**Finding.** Revision 2 said the Windows automatic stop is 90 seconds of source
device silence and, separately, that `observe_link` returns `Some(true)` on
Windows. That was overbroad. The Windows CLI `tun` branch in `rust/src/main.rs`
supplies `|| Some(true)`, so its source-silence timer runs. The command-line
GUI's `observe_link` returns `None` because `autostop::link_observation` returns
`Unsupported` on Windows, and `auto_stop_sample` resets the policy on `None`.
The GUI path therefore does not stop on source silence. It is not true that
neither path can stop, and it is not true that both can.

**Design change.** Section 0 and section 6.1 of the architecture separate the
paths. The service monitor takes `Up`, `Down`, or `Unknown`. On Windows the
observation is `Unknown`. `Unknown` never produces `hotspot_lost` and never
clears the continuous source-silence interval. A probe that cannot run is
`Unavailable`, which is no evidence and clears the interval. A probe that runs
and gets no answer feeds the 90 second timer. A cancelled probe changes
nothing. The monitor writes a final frame with `stop=source_device_gone` on the
normal path. O20 records the monitor decision.

**Residual risk.** The command-line GUI gap is not fixed by this design. The
service monitor is a design, not code. A source device that answers but is
otherwise broken keeps the tunnel open. There is still no hotspot-loss stop.

**Evidence needed.** T3.20 records the CLI-shaped behavior. T3.21 records the
GUI-shaped gap and must be labeled as current behavior, not desired behavior.
T3.22 is the service monitor test. V96 checks a Windows VM with an unknown link.
V64 checks the app text. L02 records no hotspot-loss claim.

### 9.2 B2: a crash record without adapter identity is inconclusive

**Finding.** The state record described `adapter.name`, `adapter.luid`, and
`adapter.guid` as planned or observed. A service crash between the launch intent
and the adapter observation leaves a record with no LUID or GUID. Section 8.4
then returns `Inconclusive`, the latch stays, and the only exit is the
administrator override. That is a lockout path and it makes recovery depend on a
manual action for an ordinary crash.

**Design change.** The state record now holds the exact planned adapter name,
the managed prefixes, `adapter.identity_source`, and `routes_may_exist`.
`routes_may_exist` is 0 in the launch intent. The engine creates the adapter and
reports `adapter_identity` before it installs any route. The service writes the
LUID and GUID and sets `routes_may_exist=1` before it sends the `install_routes`
acknowledgement. A crash before the acknowledgement cannot have installed a
route from this intent, so `verify_absence` can return a route-scope `Clean`
when no adapter with the exact recorded name exists. A present adapter is
`Present`, not `Clean`. If the name exists and the identity cannot be read, the
result is `Inconclusive`. The preferred split in architecture section 4.6 goes
further: the service creates and owns the adapter, so it knows the identity
before launch. That split is unproven. O19 records the choice.

**Residual risk.** A crash after the acknowledgement still needs the normal
absence proof. An exact name can collide with a foreign adapter, and a read can
fail. The preferred split needs proof that Wintun open works across processes
and that the service can close only its own adapter. Manual recovery remains for
the truly inconclusive case.

**Evidence needed.** V80: the intent record has no route installed. V81: crash
before the identity frame leaves a clean route scope. V82: crash after the
identity write and before route install. V83: crash after route install requires
the full proof. V90: service-owned adapter feasibility.

### 9.3 B3: image-path orphan adoption can be spoofed

**Finding.** A `launching` record with no PID triggered an image-path orphan
search and adopted the matching process. Any same-user process can run the
installed engine image and match the path. The service could then wait on,
adopt, or send frames to a process that is not the engine. The nonce was not
used for the search.

**Design change.** Revision 3 removes adoption by image path. A matching process
is recorded as `orphan_candidate` with its PID and creation time and treated as
`cleanup_pending`. A start stays refused while it lives. The service sends no
control frame, does not assume it owns routes, and does not clear the latch. A
future adoption requires a challenge over a service-only channel with the
per-launch nonce, an exact image path, and a matching creation time. That proof
is not designed or approved; O21 records the decision.

**Residual risk.** A same-user process can still deny service by keeping a
matching image alive. That is a denial of service, not a secret leak or a latch
clear. A real orphan must exit before a start.

Revision 4 note: E7 (section 10.7) removes this denial of service. A
user-token process of the image no longer blocks a start.

**Evidence needed.** S32: source check that no image-path adoption exists. V84:
a fake same-image process blocks a start and receives no frame. V85: the nonce
path, if approved, rejects a wrong nonce.

### 9.4 B4: `SERVICE_QUERY_CONFIG` is required and was missing

**Finding.** Section 5.4 step 5 calls `QueryServiceConfig` to compare
`lpBinaryPathName`. Revision 2 granted the installing person query status,
start, stop, and interrogate, but not `SERVICE_QUERY_CONFIG`. On a real install,
step 5 would return access denied. The server proof would then be either skipped
or unimplementable.

**Design change.** The installer grants exactly `SERVICE_QUERY_STATUS`,
`SERVICE_QUERY_CONFIG`, `SERVICE_START`, `SERVICE_STOP`, and
`SERVICE_INTERROGATE`, plus `SC_MANAGER_CONNECT` on the SCM. The app opens the
service with those rights. An access-denied result at step 5 is
`boundary_auth_failed`; the app does not connect and does not fall back to the
pipe name. This is B4.

**Residual risk.** A service security descriptor can drift from the installer
contract. The app fails closed, so the result is unusable rather than unsafe.
Administrators can change the descriptor; administrator actions are out of
scope.

**Evidence needed.** S33: source check of the requested and granted rights. R16:
the installed descriptor grants query configuration to the interactive user and
the real `QueryServiceConfig` call succeeds.

### 9.5 B5: a stopped status cannot publish a confirmed zero gauge

**Finding.** The consistency rules required `!running` to have
`relay.tcp_flows_active=0`. A stopped tunnel has no live engine status, so the
gauge is unknown, not zero. The rule either turned a correct stopped status into
`bad_response` or forced a false zero. The same contradiction affected a stale
cached sample.

**Design change.** When `running=0`, both `phone.connections` and
`relay.tcp_flows_active` are empty and both known flags are 0. A zero is
published only with `running=1`, a fresh live engine status, and
`relay.tcp_flows_active_known=1`. The app shows "not running", not "0 local
relay flows". `engine=unavailable` requires both known flags to be 0. This is B5.

**Residual risk.** A cached running sample can outlive the engine for up to the
freshness bound. The instance and generation checks discard it; the app shows
unknown, not a stale zero.

**Evidence needed.** S34: the consistency table. V86: a stopped status with a
stale nonzero sample is rejected, and a live zero with a fresh sample is
accepted.

### 9.6 Review H1: one gateway IP does not identify one hotspot

**Finding.** The physical gateway check compared the stored credential host to
the current default IPv4 gateway. Every iPhone hotspot commonly uses
`172.20.10.1`. A replacement hotspot with the same address passes the check,
so the old credential can be sent to a different source device. The check was
described as a hotspot change detector when it is only an address check.

**Design change.** Phase 1 binds the credential to the interface LUID or GUID,
the interface type, and the gateway IPv4 address. A change in any of them clears
the credential with `gateway_changed` or `link_changed`. An unreadable identity
refuses the credential with `link_unknown` and never sends a probe. The design
states that two hotspots that reuse both the address and the interface identity
cannot be distinguished before phase 2. It does not claim otherwise. Phase 2
source device identity is the only binding that separates them. The token stays
memory-only.

**Residual risk.** A same-IP, same-identity swap in phase 1 can receive the
token after a person starts a session. That is the accepted phase 1 exposure. A
WLAN SSID or BSSID is not used: the project does not have that permission path,
and the design does not add one.

**Evidence needed.** V87: same IP with a changed LUID clears the credential and
sends nothing. V88: same IP and same LUID cannot be distinguished; the test
records that limitation rather than a detection.

### 9.7 Review H2: a later pipe instance needs a specific right

**Finding.** A later instance of a named pipe needs `FILE_CREATE_PIPE_INSTANCE`
on the existing instance. Revision 2 assumed a same-user process could create
one and relied on the SCM PID check. It did not state the right. A DACL review
could accidentally grant it, and the threat table described a squat that the
DACL may already deny.

**Design change.** The user ACE grants read and write data access and does not
grant `FILE_CREATE_PIPE_INSTANCE`. A same-user process can open the first
instance as a client but cannot create another. An administrator still can, and
the app's SCM PID check rejects it. The exact SDDL is reviewed at G2. This is
review H2.

**Residual risk.** If a future DACL grants the right, the SCM PID check remains
the only later-instance defense. An administrator can replace the service
binary; administrator actions are out of scope.

**Evidence needed.** V89: a same-user later-instance create is denied. R17: the
installed DACL omits the right and an administrator-created instance is rejected
by the SCM PID check.

### 9.8 Review H3: the data plane runs as `LocalSystem`

**Finding.** The prototype engine runs as `LocalSystem` and parses untrusted
inner packets, runs the inner TCP stack, and carries user traffic. A
memory-safety or logic defect in the data plane is a system compromise. The
design described the engine as reduced surface but did not state this exposure.

**Design change.** Architecture section 4.6 records the exposure and recommends
a split: the service creates and owns the Wintun adapter and routes; the engine
runs under a restricted service SID, opens the adapter by name, and carries only
the data plane. The service removes routes and closes the adapter on every stop
path. This is a hypothesis, not a capability. If the split cannot be built, the
prototype stays `LocalSystem` and G2 requires a written owner acceptance before
real mode. The design does not call the engine least-privilege. O2b records the
decision.

**Residual risk.** A data-plane defect can still compromise the process. The
split reduces the token but does not make the parser safe. A restricted engine
may not be able to open the adapter without a broader DACL, which would weaken
the split. That is the feasibility question.

**Evidence needed.** S35: the threat table states the exposure and makes no
least-privilege claim. V90: a restricted engine opens the service-owned adapter
and cannot change a route. V91: a `LocalSystem` fallback is labeled and cannot
pass G2 without owner acceptance.

### 9.9 Review H4: normal automatic stop versus crash

**Finding.** The design treated any process exit as `engine_lost`. A normal
automatic stop also exits the engine. Without a final frame and a drain, a
correct source-silence stop could be reported as a crash, set the cleanup latch,
and disable Start. The reverse race could treat a crash as a clean stop.

**Design change.** A normal stop writes a final frame with the stop reason and
`cleanup=ok` or `cleanup=failed` before the engine exits. The service drains the
event pipe for up to 2 seconds after process exit. A final frame means a normal
stop; no frame means `engine_lost` and `cleanup=unknown`. A normal automatic stop
keeps the app session, preserves `stop=source_device_gone`, and does not set the
latch. A frame with `cleanup=failed` sets the latch but is still not a crash.
This is review H4.

**Residual risk.** A torn or lost final frame is treated as unknown, which is
safe but can require `recheck`. A malicious engine cannot be distinguished from
a buggy engine; the service trusts only the frame and the process handle.

**Evidence needed.** V92: auto-stop final frame before process exit is a normal
stop. V93: crash with no frame is `engine_lost` and unknown. T3.18 checks the
record and frame agreement.

### 9.10 Session and SCM timeout precedence

The review asked for session and SCM timeout and lifecycle concerns to be
explicit. Architecture section 8.10 owns the precedence table. The key choices:

- `hello` has 5 seconds; a connection without it is closed.
- A request has one absolute deadline. A timeout closes the in-flight request
  and, if a tunnel is live, runs the pipe-break stop.
- A start has 25 seconds; an engine launch has 20; a late launch result is
  discarded and never adopted by a later request.
- Cleanup has 12 seconds; the event drain has 2; the SCM wait hint is 20. The
  hint covers 12 plus 2 plus a 2 second record margin. If a host's SCM timeout is
  shorter than 12 seconds, G1 records that the design is not viable.
- An SCM stop or shutdown wins over a pipe break. It runs one stop path and
  writes `stop=service_stop` or `stop=shutdown`.
- No timeout path starts, restarts, or retries anything. Only a person action
  starts a new generation.

Evidence: V94 (app loss during an SCM stop), V95 (SCM stop with a hung engine),
R18 (real SCM wait hint). No test has run.

### 9.11 Traceability

`TEST_MATRIX.md` section 9 maps B1 to B5 and H1 to H4 to the adversarial
scenario, the control, the residual risk, the test id, and the gate. The
architecture traceability table in section 17 points the other way. A finding is
closed only when its named evidence exists and a reviewer records it.

## 10. Fifth review findings

Review id `e1b9ed6a-3041-4221-873f-3a406392400b`. Each answer has the finding,
the design change, the residual risk, and the evidence. No finding is closed. No
code was written. Every Windows behavior below is standard or a hypothesis until
its tier V or tier R test runs.

### 10.1 E1: the pipe mask and the client request were not exact

Finding: revision 3 wrote `GRGW` in an example SDDL and opened the pipe with
`GENERIC_READ | GENERIC_WRITE`. On a pipe, `GENERIC_WRITE` maps to a mask that
includes `0x4`, `FILE_CREATE_PIPE_INSTANCE`. So the example granted the right it
claimed to omit, and the client asked for it.

Change: architecture section 5.2 gives one exact SDDL string,
`O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120183;;;<user SID>)`, with a bit
table. The user gets read data, write data, read and write attributes,
`READ_CONTROL`, and `SYNCHRONIZE`, and nothing else. Section 5.4 step 2 opens
with exactly `0x00120183`. A wider request is denied and reported as
`boundary_auth_failed`, never retried wider. A framework constructor that asks
for `GENERIC_WRITE` must not be used.

Residual risk: a later edit widens one side to make an open succeed. The two
constants live in one reviewed place, and a change needs a G2 re-review.
Administrators keep the create-instance right and are out of scope.

Evidence: S37, V97, R19.

### 10.2 E2: unknown or unavailable evidence had no bound

Finding: an unknown link and an unrun probe were both "no evidence", so a tunnel
could run forever without supervision. Revision 3 also sent an unreadable
gateway to `source_device_gone` after 90 seconds, which turned missing evidence
into a loss claim.

Change: architecture section 6.1 defines five probe results and two intervals.
The silence interval stops at 90 seconds with `source_device_gone` only for
continuous `Silent` results. The unsupervised interval counts from the last
`Accepted` answer and stops at 300 seconds with `observation_unavailable`. The
constant Windows `Unknown` link never starts or resets either interval. Section
11.4 removes the revision 3 text. Sections 11.1, 11.2, and 11.5 keep the new
stop apart from loss and pairing claims: phase 1 clears the credential on every
stop, so `paired=0` after any stop means re-entry, not rejection; phase 2 keeps
`paired`; the app never shows a pairing failure or a loss for this stop.

Residual risk: the 300 second value trades availability against invariant 13.
It is an owner decision, O23. A long sleep may stop the tunnel at the first
sample after resume. Whether the CLI and the GUI adopt the bound is open. The
bound is not implemented anywhere.

Evidence: T3.23, V98, S38, L06, and the O23 decision.

### 10.3 E3: the restricted-token split was not shown feasible

Finding: the split assumed the engine could open a service-owned Wintun adapter
under a restricted token, and the probe helper, another privileged parser of
untrusted input, was missing from the threat model.

Change: architecture section 4.6 states that a Wintun session is created in the
calling process and cannot be handed to another process. It lists three
options: a restricted engine that opens the adapter itself (needs R20, expected
to fail), a service-side frame pump that parses nothing (needs R20 for cost and
R21 for sockets), and `LocalSystem` with a written owner acceptance. It names
how the restricted token is built and which socket options R21 must prove. The
probe helper is in the exposure table and the threat table. Its restricted
token needs only R21. O2b lists the fields the owner acceptance must hold, and
a G2 approval cannot stand in for it.

Residual risk: if R20 and R21 fail, the exposure stays, under the owner's
signature. Option B adds a privileged copy loop on the hot path.

Evidence: S35, S46, V90, V91, R20, R21, and the O2b decision.

### 10.4 E4: hotspot identity used only target-side evidence

Finding: same-interface, same-gateway hotspots are common, and revision 3
dismissed SSID and BSSID without modelling them.

Change: architecture section 11.4.1 separates three kinds of evidence. The
target-side link identity says which local interface and gateway address are in
use. The hotspot-side guard, gateway MAC and, for Wi-Fi, SSID and BSSID, is
compared when readable; a change clears the credential with `link_changed`; a
match is never identity; an unreadable value blocks nothing. The source device
answer is identity only in phase 2. A phase 1 token acceptance proves only that
the peer at the gateway accepted the token, which any device can do. Guard
values stay in memory and never appear in status or logs.

Residual risk: a spoofer passes phase 1. A source device that randomizes its
hotspot address forces a re-entry. Wi-Fi values may need location permission and
may be unreadable to the service.

Evidence: S39, V99, R22, L07, and the O24 decision.

### 10.5 E5: the planned GUID was ambiguous

Finding: a planned identity that is reused across intents cannot tell a leftover
adapter from the current one.

Change: architecture section 8.3.1 mints a fresh `guid_planned` per intent and
passes it to Wintun as the requested GUID. A live match is `Present` or
`Inconclusive`, never `Clean`. Section 8.4 uses the name and the planned GUID
together for the `routes_may_exist=0` case.

Residual risk: a fresh GUID may add one network profile per start. O19 records
the trade-off with a fixed GUID.

Evidence: V100, R23.

### 10.6 E6: the suspended launch and the PID phase

Finding: the PID was written after `CreateProcess`, and the window between the
two was unresolved.

Change: architecture section 8.3.2 compares `CREATE_SUSPENDED` with a launch
gate and chooses the gate. A suspended engine left by a service crash never
runs its parent-loss watcher and stays until reboot. A gated engine exits on
parent loss and has done nothing. The engine may not touch Wintun, a socket, a
probe, or a route API before `go`. `go` follows the durable PID record, and the
route acknowledgement follows the durable adapter identity. Section 8.3.4 adds
recovery rows for `launching` and `launched`.

Residual risk: an engine defect that ignores the gate. V101 checks it.

Evidence: S43, V101, V102.

### 10.7 E7: an image-path orphan could deny service

Finding: revision 3 blocked a start on any process of the installed image, and a
standard user can run that image.

Change: architecture section 8.7 blocks only on the recorded PID and creation
time, or for at most 12 seconds on a `SYSTEM`-token process of the image created
inside the recorded launch window. Any other match is recorded, sent nothing,
never adopted, and never blocks.

Residual risk: an unreadable token is treated as non-blocking. An administrator
can still create a `SYSTEM` process and is out of scope.

Evidence: S44, V103.

### 10.8 E8: preshutdown, checkpoints, and logoff were too thin

Finding: revision 3 named the controls but gave no budgets, no checkpoint rule,
and no session filter.

Change: architecture section 8.6 accepts preshutdown with an explicit 20 second
timeout set by the installer, advances checkpoints once per second only inside
bounded steps, adds a shutdown fallback that writes the record without waiting,
and stops only on logoff of the controlling session, identified by the
`TokenSessionId` from the caller token. Lock and disconnect do not stop. The
first of logoff and pipe break sets the reason, and only one stop runs.

Residual risk: a hung engine can delay shutdown by up to 20 seconds. During fast
user switching the machine-wide routes keep serving other accounts. That scope
is owner decision O25.

Evidence: S40, V104, V105, R24, and the O25 decision.

### 10.9 E9: a failed final frame could look like a failed cleanup

Finding: on parent loss the service may be gone, so the engine's final-frame
write fails, and the design did not say that this is harmless.

Change: architecture section 8.8 has the engine finish cleanup before it tries
a 1 second best-effort write. A failed write changes nothing. The service sets
the latch only from a received `cleanup=failed` frame. No frame is
`cleanup=unknown`, which a clean `recheck` clears without the override. The exit
code is diagnostics only.

Residual risk: a clean stop without a frame still needs `recheck`.

Evidence: T3.24, V106, S41.

### 10.10 E10: caller authentication by PID has a reuse race

Finding: `GetNamedPipeClientProcessId` followed by `OpenProcess` can name a
different process if the client exits and its PID is reused.

Change: architecture section 5.3 reads one bounded first frame without parsing
it, because impersonation needs a prior read, then calls
`ImpersonateNamedPipeClient`, `OpenThreadToken` with `OpenAsSelf`, reads
`TokenUser` and `TokenSessionId`, and calls `RevertToSelf` on every path before
it parses anything. The client limits the server to identification level. The
PID is diagnostics only. A failed revert ends the session and stops from a
thread that never impersonated.

Residual risk: one unauthenticated bounded read per connection, available only
to a process that passes the DACL.

Evidence: S42, V107, V108, R25.

### 10.11 E11: citations were behind the GUI fix

Finding: the documents described the GUI auto-stop as it was before an
in-progress working-tree change.

Change: architecture sections 0, 2, 6.1, 10, and 12, the test matrix, and the
decisions file cite the uncommitted `LinkWatch::Unobservable` path in
`rust/src/gui.rs` as in progress and unverified. T3.21 now runs against both the
committed and the working-tree behavior. The service monitor keeps its own
contract.

Residual risk: the GUI change may land differently. S45 rechecks the citations
at G3.

Evidence: S45, T3.21, V96.

### 10.12 What stays with the owner

- The O2b acceptance for any component that stays at `LocalSystem`.
- The O23 value and whether the CLI and the GUI adopt it.
- O25, the controlling-session scope on a shared machine.
- Approval of every tier R run, including the Wintun exception in R20 and R23,
  and every tier L run.

## 11. Revision history

- Revision 1 answered the first review.
- Revision 2 answers the second review and the 82046682 review. It corrects the
  same-user threat, the pipe server proof, the launch intent ordering, the
  `ProgramData` ownership contract, the credential-at-rest policy, the automatic
  stop claim, and the bounded pipe I/O mechanism. It also fixes the lower
  findings listed in section 2 and the 82046682 conditions in section 4.
- Revision 3 answers the fourth review, id
  `c0b94fca-d9ea-4d4f-8aa8-87de7c508503`. It separates the Windows CLI and GUI
  source-silence behavior, records the adapter identity and route gate for
  crash recovery, removes image-path orphan adoption, grants
  `SERVICE_QUERY_CONFIG`, makes a stopped gauge unknown, binds phase 1 to the
  interface identity as well as the gateway, omits `FILE_CREATE_PIPE_INSTANCE`,
  records the `LocalSystem` data-plane exposure with a recommended split, and
  separates a normal automatic stop from a crash. It adds the session and SCM
  timeout precedence and the adversarial matrix. No finding is closed.
- Revision 4 answers the fifth review, id
  `e1b9ed6a-3041-4221-873f-3a406392400b`, in section 10. It fixes the pipe mask
  and the client request, proposes the bounded unsupervised interval, records
  the Wintun split options and the owner acceptance, adds the hotspot-side
  guard, the planned GUID, the launch gate, the narrower orphan rule,
  preshutdown and logoff handling, the nonfatal final frame, caller identity by
  impersonation, and the GUI citation correction. It also corrects the revision
  3 text that sent an unreadable gateway to `source_device_gone`. No finding is
  closed. The revision 3 sections are kept; revision 4 adds to them.
