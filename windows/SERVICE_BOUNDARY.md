# Windows engine service boundary foundation

Status: **FOUNDATION ONLY. UNAPPROVED. Not installed. Not wired to the app.
This build is not production ready. No tunnel is claimed.**

The foundation now includes an app-side bridge from the service status dialect
to the app engine state machine. It is still not loaded by the app and no
service is installed.

This file describes the transport-free and policy-only foundation for a
Windows engine service boundary. It is not the approved service design. The
design in `../experiments/windows-service-design/` remains UNAPPROVED and its
G1 and G2 gates are still open. There is no Windows host run for this
foundation, and the code is not installed.

The design's no-code rule applies to a service implementation and its
enablement. This foundation implements no installer, route, adapter, or
tunnel. It is contract and policy code that a future approved design can
reuse or reject.

A separate project at `src/HotspotShade.WinUI2.Service/` now provides the
first SCM adapter and executable entry point over this foundation. It
registers one control handler, maps the host states to `SERVICE_STATUS`, runs
one generation with the real account, durable-state, caller, pipe, session,
and guarded-backend seams, and refuses every engine start because the Windows
source-proxy guard is closed. It is UNAPPROVED, is not installed, is not in
the solution, is not loaded by the app, and has not run on Windows. Its
hermetic tests run in CI. Its own README lists the fixed exit codes and the
remaining blockers. The foundation described below remains transport and
policy code.

The ServiceHost foundation now also has the service half of the engine control
transport in `rust/src/desktop_control.rs`. `EngineControlProtocol.cs` and
`EngineControlSession.cs` implement the `HSDC` frame codec, the session key
descriptor reader, the HMAC handshake, monotonic request ids with no replay,
the parent-liveness close order, and an engine status source. The guarded
backend sends one authenticated stop when a session exists. The default
channel factory is unavailable, so this build still has no engine session and
reports `engine_unavailable`. There is no launcher, pipe create, process
start, or Rust `ControlHandler` yet.

The UWP app does not load this code and does not connect to a service. It
controls the engine through the packaged full-trust broker instead; see
README.md.

## What is in this tree

The foundation is in
`src/HotspotShade.WinUI2.Core/Engine/Service/` and in the core test runner.

| File | Purpose |
|---|---|
| `EngineServiceFrame.cs` | One 4-byte big-endian length and one bounded JSON object. Strict UTF-8, no trailing bytes, no duplicate keys, no arrays, no fractions, no deeper objects. A reply may nest one `fields` object. |
| `EngineServiceBoundary.cs` | The fixed pipe name, service name, exact client access mask `0x00120183`, exact service rights `0xB5`, SID syntax and user-ACE validation, the server pipe creation policy (`FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, one instance), and the pipe and service SDDL builders. |
| `EngineServiceCallerPolicy.cs` | A caller identity record, the account, session, impersonation, and optional package-family checks, the exact Win32 impersonation value mapping, the failed-revert rule, and the same-user limit. |
| `EngineServiceStateRecord.cs` | The version 1 durable state schema, the launch and adapter gates, the cleanup latch, the start refusal rules, the load gate for a missing or unreadable record, and the launched-process failure rule. It performs no file I/O. |
| `EngineServiceStatus.cs` | The closed status schema, the stop vocabulary, the two separate connection counts, operation-specific reply validation, instance matching, source freshness from `checked_at`, and the phase-one pairing clear. |
| `EngineServiceSession.cs` | The one-session state machine: hello binds, hello and status launch nothing, requests are serialized and cancellable, parent loss and service stop run one stop, a missing durable state blocks a start, and no path restarts anything. |
| `EngineServiceClient.cs` | The app-side `IEngineBroker` adapter over one `IEngineServiceChannel` frame seam. It does no input or output by itself. It applies a per-operation call budget and reports a request that may have been applied without a validated reply as an ambiguous outcome. The same budget table and the ambiguous outcome are carried through the app-side `EngineSession`. |
| `EngineServiceBroker.cs` | The app-side bridge from the service status dialect to the app status dialect. It reads a service status with `EngineServiceStatus.TryParse`, keeps `checked_at`, an unknown connection count, the cleanup gate, the TTL audit count, and the precise stop words, and writes the app fields. It implements `IEngineBroker`, so `EngineSession` and `EngineBoundary` keep their safety rules without a second state machine. |

The tests are in
`tests/HotspotShade.WinUI2.Core.Tests/ServiceBoundaryTests.cs`. They create no
pipe, process, service, route, or endpoint. The channel is a fake.

## What the hermetic tests prove

- The frame length is big-endian, matches the payload, and is capped at 65536
  bytes.
- A zero length, an oversized length, trailing bytes, invalid UTF-8, duplicate
  keys, arrays, fractions, leading zeros, and deeper objects are refused.
- A credential key is refused in both directions.
- The client access mask is exactly `0x00120183` and contains no
  `FILE_CREATE_PIPE_INSTANCE` bit.
- `GENERIC_WRITE` maps to the create-instance bit on a pipe, so a default
  framework open that asks for it is denied by design.
- The pipe SDDL names only SYSTEM, Administrators, and the installing user. The
  service SDDL grants query configuration and not change configuration.
- The server pipe policy requires `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`, and exactly one instance. A missing flag, a
  second instance, or the unlimited value is refused before a pipe is created.
- A numeric SID with a separator, parenthesis, space, leading zero, or no
  sub-authority is refused before it can change the descriptor. The user ACE
  form check also refuses Everyone, Authenticated Users, Users, Administrators,
  SYSTEM, service SIDs, and every authority-only value. `IsValidUserSid` is
  syntax; `IsAllowedPipeUserSid` is the ACE form rule. A local or domain account
  has the form `S-1-5-21-a-b-c-rid`. A Microsoft account or Azure AD account
  uses authority 11 or 12. The form check cannot tell a custom group from a
  user. The future host must resolve the SID with `LookupAccountSid` and require
  `SidTypeUser`. The installer must stop if it cannot resolve a person SID.
- The Win32 impersonation values map exactly: 0 is anonymous, 1 is
  identification, 2 is impersonation, and 3 is delegation. The values 4 and -1
  are unreadable and are denied. An undefined enum value is denied.
- A failed `RevertToSelf` closes the connection, parses no frame, sends no
  reply, and runs one stop from a thread that never impersonated.
- The same account is allowed at identification level and is allowed when
  elevated. Another account, an anonymous caller, a bad session, and a package
  mismatch are denied. The same-user text says the boundary does not block a
  same-user process. Remote clients are rejected by
  `PIPE_REJECT_REMOTE_CLIENTS`, and other accounts are denied by the DACL and
  the caller policy.
- A never-launched record and a clean stopped record are the only clean start
  states. A launch intent blocks a start. The adapter gate precedes the running
  state. A clean stop allows a later start; failed or unknown cleanup blocks it.
  Only a launch that the launcher proves did not create a process is clean. A
  `Launching` record without that proof, and any `Launched` record, is
  `cleanup_unknown`, because a crash can leave a process after the intent write
  and before the PID write.
- A missing, unreadable, damaged, or version-mismatched durable record is
  `cleanup_unknown`. It never becomes a never-launched clean record. A session
  built without a readable state gate refuses every start.
- A missing final frame is `cleanup_unknown`, never clean.
- A running status can carry both counts separately. A stopped status carries
  neither count as a measured zero.
- A running status with clean cleanup, a stopped count, a missing check time, a
  wrong pairing, or a future check time is refused.
- A status from another service instance is refused with `engine_restarted`.
  Source freshness uses `checked_at` and the sample time, whichever is older,
  so a status read now cannot make an old source answer look fresh.
- The stop text for `observation_unavailable` does not claim a hotspot loss or
  a source device loss.
- The app-side client frames a request, validates the reply for the exact
  operation, and turns a missing, malformed, throwing, or slow channel into a
  fixed code. After handoff, either channel form reports an unknown outcome
  for exceptions, missing replies, and invalid replies. Only an evidence-bearing
  channel can prove a pre-delivery refusal.
- The app-side client uses one budget per operation. A start waits thirty five
  seconds and a stop twenty five, so neither is cut at the five second budget
  that serves hello and status. The app-side `EngineSession` keeps that table,
  preserves `EngineReply.OutcomeUnknown` through its second validation, and
  returns `EngineCommandResult.OutcomeUnknown` for a start, stop, or forget
  that may have been applied. A validated `timeout` failure reply is treated as
  ambiguous too, because the service uses it for a canceled operation whose
  work may still have run. The result is never a success and never a clean
  refusal; the action stays pending until a status read confirms it.
- A failed request write keeps its delivery evidence. A write that never
  started a kernel call and a successful write that proves zero transfer are
  clean refusals. Failed native calls do not prove their transfer count, even
  if their output count or OVERLAPPED field is zero. A positive or unknown count, including a
  cancellation or budget expiry inside the write, is ambiguous and closes the
  pipe.
- The inactive legacy BrokerRuntime still uses uniform five second budgets at
  several layers. A slow start or stop can time out before its work settles.
  Its timeout and cancellation behavior needs an end-to-end review before it
  can use the service boundary's per-operation budgets. It is not a production
  service path.
- A service session binds only after a successful hello; a failed hello leaves
  it unbound and retryable. Hello and status launch nothing. A
  second session is refused. A start needs a held credential, a paired source
  device, a fresh ready status, a readable durable state, a clean cleanup gate,
  and a source device that is present.
- Requests are serialized. A request waiting for the session can be cancelled
  and returns `timeout`. A start cannot overlap a stop in the same session.
- Every stop trigger for a started generation calls the backend once. A second
  user stop, parent loss, service stop, logoff, or shutdown returns the first
  result and keeps the first reason. A stop trigger always clears the
  credential and the phase-one pairing, even when the backend stop already ran.
  A clean stop can be followed by a new start attempt, and the next stop calls
  the backend again. A failed start attempt after reaching the backend can also
  be stopped. A failed stop clears the credential, clears phase-one pairing,
  and closes the session.
- A phase-one stop clears `paired` and `paired_scope` and clears source, trust,
  check time, and both counts. A stopped phase-one status that still claims a
  pairing is refused by the schema. A phase-two identity pairing is kept.
- A stop, forget, parent loss, logoff, or shutdown has one explicit reason. A
  lost or closed session never restarts the engine.
- The app-side client and the service session share one frame contract in an
  in-memory loopback test. The test opens no pipe.
- The app-side `EngineServiceBroker` maps a real service status into the app
  dialect, and `EngineSession` and `EngineBoundary` drive status, start, and
  stop over a framed in-memory channel to a real `EngineServiceSession`.
  - A start ack is not an On claim. A fresh status confirms it.
  - An unpaired, stale, cleanup-blocked, or deferred status sends no start
    frame and keeps the service's fixed code.
  - A dropped start or stop reply is an ambiguous outcome. A status read
    confirms an applied start, and the request is not replayed.
  - A restarted service instance is `engine_restarted`.
  - An unknown connection count is shown as unknown, never zero.
  - The ping line uses the active ICMP relay state, not the requested setting.
  - A TTL audit failure is shown beside a running tunnel.
  - The service stop words keep their exact sentences.
  - The old broker status still parses with a known count, a clean cleanup
    gate, no source check time, and no audit failures.
- The four new status fields are optional. A status without them keeps the
  version 1 meaning, so the old broker path is unchanged.
- The engine source guard `require_token_destination_proof` is present and still
  returns `ErrorKind::Unsupported`.

These are local checks on macOS with the .NET 8 SDK. They are not a Windows
build, a service install, an app service connection, a named pipe, an
impersonation call, or a tunnel.

## What is not implemented

- No Windows service installation, `CreateService`, `StartService`, service
  configuration change, or uninstaller. The separate Service project now has
  an SCM service main, dispatcher, and status adapter, but no install path and
  no Windows host run.
- No named-pipe server or client in this foundation.
  `IEngineServiceChannel` has only a fake. A separate unapproved
  `ServiceHost` transport foundation is not wired, installed, or tested on
  Windows.
- No caller impersonation, token query, server process id proof, pipe owner
  proof, or SCM binary path proof. The policy inputs are supplied by a future
  host. No `ImpersonateNamedPipeClient`, `OpenThreadToken`, or `RevertToSelf`
  call exists here. The failed-revert rule is a policy result only.
- No protected `%ProgramData%` directory, parent reparse check, write path,
  flush, or atomic replace. `EngineServiceStateRecord` only models the data
  and the gates. The Service project adds a bounded read-only file store, not
  the protected directory or a writer.
- No engine launcher, launch gate, final frame, or automatic stop monitor. The
  authenticated control client, status source, and one-stop seam exist, but
  the default channel factory is unavailable. The Service project therefore
  reports `engine_unavailable` and refuses every start. No engine-side
  `ControlHandler` is wired.
- No app wiring. The app does not reference the service types, and the
  AppContainer cannot open the reviewed pipe or load the `net8.0-windows`
  ServiceHost assembly. The app uses the full-trust broker and its UAC
  elevated starter instead (README.md).
- No service install, so the pipe does not exist and the new app-side bridge
  has no endpoint in this tree. The bridge is tested only against a framed
  in-memory channel to a real service session.
- No production enablement and no real tunnel from the app.

## Exact blockers to production enablement

1. **The service design is UNAPPROVED.** G1 and G2 have not passed. The open
   decisions include the app host (O1), service account (O2), data-plane
   privilege (O2b), start mode (O4), credential at rest (O5), engine transport
   (O3), installer technology (O16), runtime (O15), controlling session (O25),
   and same-user risk acceptance (O18). No code may be enabled against the
   design until those decisions and the review gates are recorded.
2. **The engine refuses Windows source proxy token use.** The Windows route
   verifier returns `ErrorKind::Unsupported` from
   `require_token_destination_proof`. It says that physical adapter and gateway
   identity cannot be verified safely. This foundation does not enable, bypass,
   or weaken that guard. A real Windows tunnel start therefore remains
   impossible from any app in this tree.
3. **No Windows host.** No named pipe was created, no token was impersonated, no
   SCM service was installed, and no Windows shell ran this code. The policy
   constants are based on documented Windows behavior, not a host result.
4. **No installer or signing.** There is no per-machine MSI, no service
   security descriptor applied to a live service, no protected ProgramData
   directory, and no signed package or publisher pinning. The install and
   uninstall contract is not testable here.
5. **No full-trust app host.** The UWP app cannot hold the engine or use
   loopback without an exemption. The reviewed design recommends a WinUI 2
   desktop host, and that host spike has not passed. The UWP app uses the
   packaged full-trust broker instead of this service.
6. **No named-pipe transport.** The exact access mask, server identity proof,
   caller impersonation, one-session policy, and bounded pipe I/O are policy and
   test seams only. They are not a working boundary.
7. **No engine launcher or launch gate.** The service can speak the
   authenticated control transport, read a status, and send one stop when a
   session exists. It cannot create the private channels, start the engine,
   receive an adapter identity, install routes, or receive a final frame.
   `EngineServiceStateRecord` models the ordering but does not perform it. The
   Rust `desktop_control` handler for `Status`, `Start`, and `Stop` is also not
   wired.
8. **The .NET 8 service target is not chosen.** The existing broker targets
   .NET 8, whose support ends on 2026-11-10. The design recommends .NET 10 LTS
   (O15). New service code must not pin .NET 8.
9. **Same-user control is allowed, not blocked.** Any process of the installing
   account can pass the account check, control the tunnel, and hold the single
   session. Holding the session can deny the app a connection. It cannot read
   the bearer, the source credential, or the identity key through the service
   protocol. Remote clients are rejected by `PIPE_REJECT_REMOTE_CLIENTS`, and
   other accounts are denied by the DACL and the caller policy. The boundary
   protects other accounts and remote clients, not one process of the account
   from another. It is not an isolation boundary between two processes of the
   same account.
10. **Failed hello handling needs an integrated transport test.** The core
    binds a session only after a successful hello and refuses other requests
    until then. The separate `ServiceHost` listener currently continues
    reading after a failed hello reply when the transport handshake succeeded,
    so a client can retry. Keep this retry behavior in the proposed host and
    verify it across both layers before integration. Closing the connection
    would invoke parent-loss cleanup on a transient status failure. A future
    backend should treat a stop before any launch as a clean no-op once it can
    prove that no engine was launched. The current backend reports cleanup
    unknown without that proof. This is not evidence of a bypass of caller
    authentication.
11. **No app-side host can reach the pipe.** The UWP app is an AppContainer. It
    cannot open a pipe under the reviewed DACL, which names SYSTEM,
    Administrators, and the installing person, and it cannot load the
    `net8.0-windows` ServiceHost assembly. A full-trust app-side host with an
    approved Windows authorization story is still missing. The new
    `EngineServiceBroker` is the transport-free seam that host will use; it
    does not supply the host, the pipe, or the service.

## What a future implementation must add, in order

1. Record the G1 and G2 decisions and pass the named tier V and tier R evidence.
2. Install and prove the service on a disposable Windows x64 VM: the
   installer, protected state directory, exact service and pipe descriptors,
   SCM dispatch, status transitions, stop path, and uninstall path. The
   unapproved Service project now supplies the SCM service main and a
   read-only state store, but no installer, protected directory, writer, or
   host run.
3. Implement the named-pipe transport with an exact mask open, one unparsed
   frame, impersonation, `OpenThreadToken` with `OpenAsSelf`, `RevertToSelf` on
   every path, and the SCM and pipe owner proofs. Create the pipe with
   `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS` at one
   instance. A failed `RevertToSelf` closes the connection, parses no frame,
   sends no reply, and runs the stop from a thread that never impersonated. The
   client must fail closed on any inconclusive check.
4. Implement the launcher and launch gate around the existing control client.
   The launcher creates the private control, key, and parent-liveness channels,
   writes the key, starts the installed engine image, and returns the service
   ends. No adapter, network call, or route may happen before `go`. The final
   frame and the 2 second drain must distinguish a normal stop from a crash.
   Wire the Rust `desktop_control` handler for `Status`, `Start`, and `Stop`.
5. Remove the Windows token guard only after the reviewed physical adapter and
   gateway proof exists, or keep source proxy mode unavailable on Windows. Do
   not bypass the guard to make a demo work.
6. Add the full-trust app host and its sign-in and session lifetime rules. The
   host builds `WindowsEngineServiceChannel` and passes it to
   `EngineServiceBroker` and `EngineBoundary`. The app UI then reads real
   status instead of `DemoSession`.
7. Sign the installer and package, add publisher pinning where approved, and
   run the live source device and hotspot tests with owner approval.

## Security review request

An independent reviewer should answer these questions before any service code
is enabled:

- Is the exact `0x00120183` mask a subset of the user ACE with no
  create-instance, delete, DACL, or owner right?
- Does every client open use that exact mask and fail closed on access denied?
- Does the server creation policy require `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`, and exactly one instance?
- Does the user ACE refuse Everyone, Authenticated Users, Users,
  Administrators, SYSTEM, service SIDs, and authority-only SIDs?
- Does the host require `SidTypeUser` for a custom account-form SID?
- Does the Win32 impersonation value map exactly, and is an unknown value
  denied?
- Does every server path impersonate only after one bounded unparsed read, query
  only token fields, and call `RevertToSelf` on every path?
- Does a failed `RevertToSelf` close the connection, parse no frame, send no
  reply, and run one stop from a thread that never impersonated?
- Is the server identity proof limited to SCM process id, pipe owner, and
  installed binary path, and does it fail closed when any step is inconclusive?
- Is the state record written before the process, and does a missing,
  unreadable, damaged, or version-mismatched record block a start?
- Does a session built without a readable durable state refuse every start?
- Is a failed process that was already launched `cleanup_unknown`, never clean?
- Is a missing final frame always `cleanup_unknown`, never `cleanup=failed` and
  never clean?
- Does the stopped status leave both counts unknown instead of inventing zero?
- Does a status from another service instance fail closed, and does source
  freshness use `checked_at` rather than the read time?
- Does a phase-one stop clear `paired` and `paired_scope`, and does a phase-two
  identity pairing survive?
- Does a second stop trigger avoid a second backend stop and keep the first
  reason?
- Does the same-user section say allowed, not blocked, and name the remote
  client rule?
- Does the SCM adapter register the control handler before any status report,
  and does every `SERVICE_STATUS` record use a documented transition?
- Does a stop that wins before Running avoid a backwards StartPending or
  Running record, and is exactly one Stopped record sent with the fixed
  service-specific exit code?
- Does a stop, shutdown, interrogate, pause, or custom control leave the live
  session untouched except for the documented stop and interrogate cases?
- Does the service executable avoid every install, service-start, route,
  adapter, socket, and engine-launch call?
- Does the configuration accept no secret and no caller-named pipe or
  endpoint?
- Is the engine guard still present and unmodified?
- Does the control client use the exact `HSDC` header, HMAC labels, key
  descriptor format, and command bytes from `rust/src/desktop_control.rs`?
- Does every request use one increasing id, and does a write or read failure
  close the session with no replay and no second reply read?
- Does `Dispose` close the parent-liveness channel before the control channels?
- Does the status source refuse engine-supplied `v`, `instance`, and `cleanup`,
  force `cleanup=unknown` for a running status, and keep a missing durable
  record `cleanup_unknown`?
- Does a stop remain `cleanup_unknown` until exit and cleanup are proven, and
  does every start remain behind the source-proxy guard?

## Repaired review findings

This revision is a policy and test repair. It does not enable the service and
does not create a pipe, process, route, or tunnel.

- The server pipe policy now names `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`, and exactly one instance. A missing flag or a
  second instance is refused.
- SID validation now separates syntax from the ACE form rule. The user ACE
  form check refuses Everyone, well-known groups, service SIDs, SYSTEM, and
  authority-only values. The form check is not an account-type proof; the host
  must add `LookupAccountSid` and require `SidTypeUser`.
- The impersonation enum uses the Win32 values 0 to 3. An unknown value becomes
  `Unreadable` and is denied.
- A failed `RevertToSelf` has one rule: close, parse nothing, reply nothing, and
  run the stop from a thread that never impersonated.
- The session serializes requests, observes cancellation while a request waits,
  and runs exactly one backend stop. The first stop reason wins.
- A missing, unreadable, damaged, or version-mismatched durable record blocks a
  start. A session with no state gate refuses every start.
- A failed process that was already launched is `cleanup_unknown`. Only a
  launch that the launcher proves did not create a process is clean. A
  `Launching` record without that proof is also `cleanup_unknown`.
- A status from another instance is `engine_restarted`. Source freshness uses
  `checked_at` and the sample time, whichever is older.
- A phase-one stop clears the pairing claim. A phase-two identity pairing is
  kept.
- The same-user text says the boundary does not block a same-user process and
  names `PIPE_REJECT_REMOTE_CLIENTS` for remote clients.

These repairs are hermetic checks on macOS. They are not a Windows host result,
a pipe create, an impersonation call, a service install, or a tunnel. An
independent reviewer must re-check them before any service enablement.

## Run the checks

From the repository root on a host with the .NET 8 SDK:

```text
dotnet run --project windows/tests/HotspotShade.WinUI2.Core.Tests/HotspotShade.WinUI2.Core.Tests.csproj -c Release
dotnet build windows/src/HotspotShade.WinUI2.Core/HotspotShade.WinUI2.Core.csproj -c Release
sh windows/tools/check_static_contract.sh
```

Expected: the test runner prints `ALL WINUI2 PROTOTYPE CHECKS PASSED` with 237
checks, the core build has no warnings, and the static check prints
`STATIC CONTRACT CHECK PASSED`. These are local hermetic results. They do not
change the Windows platform status.
