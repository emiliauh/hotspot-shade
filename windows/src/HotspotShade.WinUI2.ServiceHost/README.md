# Windows engine service host transport foundation

Status: **UNAPPROVED FOUNDATION. NOT WIRED. NOT INSTALLED. NOT ENABLED.
NOT PRODUCTION READY. NO TUNNEL IS CLAIMED.**

This directory holds new, isolated code for the Windows named-pipe transport
and the service-host foundation described by
`experiments/windows-service-design/WINDOWS_SERVICE_ARCHITECTURE.md` and
`windows/SERVICE_BOUNDARY.md`.

It does not edit the existing foundation in
`windows/src/HotspotShade.WinUI2.Core/Engine/Service/`. It does not edit the
solution, the installer, the app package, the CI workflow, or any Rust code.
No existing project references it. It is not loaded by the UWP app. It has
no install command or automatic start path.

## SCM adapter and executable

A separate project at `windows/src/HotspotShade.WinUI2.Service/` now connects
this foundation to a runnable Windows Service Control Manager process. It
supplies `StartServiceCtrlDispatcherW`, one
`RegisterServiceCtrlHandlerExW` handler, and `SetServiceStatus` reporting. It
builds the real installed-account, durable-state, caller-policy, pipe, session,
and guarded-backend seams and runs one host generation.

That project is also unapproved, not installed, not in the solution, and not
wired to the app. Its hermetic tests run in Windows CI. It has never run as a
service on Windows. It does not install or start
a service, create a route or adapter, or launch an engine. Its README lists the
retained gates, the fixed service-specific exit codes, and the remaining
blockers. The foundation below remains the transport and policy owner.

The review findings folded in:

1. The named pipe is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`,
   `PIPE_REJECT_REMOTE_CLIENTS`, and a maximum of one instance.
2. Session calls are serialized by one gate. The gate closes before a parent
   loss or service stop waits, refuses new calls, and marks the backend so a
   start cannot pass the parent-loss boundary.
3. A missing, unreadable, or invalid durable state record is
   `cleanup_unknown`, never a clean record.
4. Win32 `SECURITY_IMPERSONATION_LEVEL` values are mapped explicitly. They are
   not cast to the managed enum, whose values differ.
5. The configured account and the token user must pass a numeric SID prefilter
   and a `LookupAccountSid` account-type check that requires a user account.
   Everyone, Authenticator Users, SYSTEM, service accounts, builtin groups, and
   labels are refused.
6. `RevertToSelf` is checked on the same new thread that impersonated. The
   thread then exits, so it never returns to the thread pool with a token. A
   handshake deadline with a running probe, or a failed checked revert, records
   one event and calls the fatal boundary on the clean caller thread. A normal
   service stop during impersonation is not a failed revert: the clean caller
   waits for that thread's checked revert and then reports the stop. It never
   calls the fatal boundary for a normal stop. When the fatal boundary only
   disables the process, a fatal unverified probe still owns the pipe; the
   handshake keeps the pipe open until the probe thread exits, then disposes
   it. The listener does not close the pipe under a running probe. A
   clean-thread runner that throws after the probe start request, without
   returning a completion task, is treated as a possibly running probe: the
   handshake fails closed, records one unverified event, and keeps the pipe
   open for the life of the process.
7. Status is accepted only when its instance id matches the service instance,
   its read time is recent, and its observed time is not in the future.
   Running and cleanup coherence is checked again.
8. The source-proxy engine start guard stays closed. The guarded backend
   refuses every start and never launches a process or changes a route.
9. The host reports Running only after the listener proves its first pipe
   instance exists, and it rechecks listener completion immediately before the
   status report. A listener that ends or times out before readiness never
   reports Running. That final recheck is not atomic with the status call, so
   the narrow window described under "What is not implemented" remains. There
   is no claim that a listener which finishes in that window can never be
   reported Running once.
10. A stop claimed after a timeout is not dropped. A clean continuation keeps
    waiting for the in-flight request and then runs the one stop with the first
    actual reason. Disposing the session gate after a stop is claimed does not
    dispose the gate under that stop: the gate stays alive until the one stop
    settles. A later trigger shares that stop result.
11. A requested stop during connect or the first-frame handshake is a service
    stop. It is not reported as a parent loss, a pipe failure, or an engine
    failure. A connect failure without a requested stop is a parent loss with
    `engine_unavailable`.
12. Only an accepted shutdown, or one whose stop the session already claimed,
    stops the service. A forbidden or unconnected shutdown is answered with a
    failure and leaves the live session alone.
13. A request read has two phases. At a frame boundary it waits until the
    remaining absolute monotonic idle deadline, 60 seconds after the last
    completed validated request by default. It consumes one byte, then starts
    one fixed 5 second frame deadline for the remaining prefix and body.
    Further bytes cannot extend that deadline. There is no five second boundary
    cancellation and no idle retry loop. A hidden poll taking more than five seconds can
    still arrive within the idle deadline. The handshake has its own fixed
    5 second deadline, including the first byte; it does not use the idle
    budget or restart on its first byte. Reply writes retain RequestTimeout.
    Neither forward nor backward wall-clock steps affect server read budgets.

    A complete decoded and validated request earns one fresh boundary interval
    after its backend processing and successful reply write. That interval is
    the completed request's liveness credit. A valid failure reply also counts.
    A reply alone, malformed or unvalidated input, a failed write, and observed
    cancellation earn no credit. No credit is granted while backend work is in
    progress. The next read can therefore consume a queued poll even after a
    request took longer than the idle budget. No credit exists before hello.
    Hello earns credit after authentication, validation, processing and a
    successful write, within its original fixed handshake deadline. Policy,
    processing, write and process-id checks cannot renew that deadline.

    Backend execution remains unbounded: the loop awaits it without an enforced
    request execution deadline. The idle policy cannot interrupt that work.
    The reserved start timeout does not bound a backend request today. A silent
    parent after the response gets one boundary interval. Time already spent
    processing that request cannot cause an immediate idle stop.

    Every failed read closes the session, even a proven zero-byte Idle result.
    There is no replay or partial-frame recovery. Expiry and transfer evidence
    are separate. `boundary_read_timeout` names the exhausted boundary budget;
    it does not prove a silent peer or zero transfer. A frame deadline records
    `frame_timeout`. Unknown or Partial also records `pipe_read_failed`.
    Successful native completion can prove a count. Failed completion has an
    unknown count, including after cancellation. Completion proof still allows
    memory release; absent proof retains the context in quarantine. A handshake
    expiry with an unknown or partial transfer records both `frame_timeout`
    and `frame_invalid`, with no impersonation or reply. Either the linked
    handshake timer or the monotonic deadline supplies timeout evidence.
    Observed service cancellation reports closed without timeout diagnostics;
    a running probe still must finish its checked revert. Failed or unproven
    revert keeps the existing fatal and deferred-disposal behavior.

    Server read acceptance uses completion observation time. Both synchronous
    and pending completions are checked after collection. A completion observed
    at or after its deadline is refused even if its count is known. This does
    not prove when the bytes arrived or whether bytes existed before expiry.
    Scheduling or completion-collection delay can reject a healthy peer. These
    checks are not atomic with a concurrent stop or the next clock read; an
    observed stop still wins at the stop claim and before another dispatch.

    With no backend request in progress, silent boundary detection needs at
    most the remaining idle budget plus the bounded native completion-proof
    wait (5 seconds). A first byte just before the idle horizon can add the
    fixed frame budget, for up to about 70 seconds from the last completed
    validated request with defaults, before the stop wait. These are design
    budgets, not measured real-Windows guarantees. A native call that never
    returns can exceed them. Stop completion adds its own wait. A requested stop
    wins at the one claim; a stop after the claim keeps the first reason. The stop runs
    before pipe disposal. No path restarts the session or engine automatically.
14. The host readiness and stop budgets use a monotonic clock. Each wait
    rechecks completion at the budget boundary before it reports a timeout. A
    readiness proof or stop completion in that final window is accepted.
15. The app-side client has per-operation budgets. A start waits thirty five
    seconds and a stop twenty five, so the client no longer aborts a start that
    the service is still completing. The same table is carried through the
    app-side `EngineSession`; a single short budget never cuts a start or a
    stop. The client pipe seam reports the frame-read outcome, and a request
    that reached the pipe without a validated reply is an ambiguous outcome
    that the app must confirm with a status read. A partial or unproven reply
    read closes the pipe and is never a clean refusal, an idle read, or a
    replayed request. A failed request write keeps its delivery evidence: a
    write that never started a kernel call is a clean refusal, a write that
    provably delivered zero bytes is also a clean refusal, and every other
    failed write is ambiguous and closes the pipe. A cancellation or a budget
    expiry that lands inside a write is therefore never reported as a clean
    refusal. The app session preserves that ambiguity as
    `EngineReply.OutcomeUnknown` and `EngineCommandResult.OutcomeUnknown`, and
    a start, stop, or forget with an unknown outcome stays pending until a
    status read confirms it. A validated `timeout` failure reply is ambiguous
    too, because the service uses that code for a canceled start or stop whose
    work may still have run.
16. The service start and stop budgets stay reserved, not enforced. Server
    boundary, frame, and handshake read deadlines are separate. Hermetic checks
    exercise their pacing; real Windows timing remains unverified.

## What is in this directory

| File | Purpose |
|---|---|
| `EngineServiceTransportContracts.cs` | Seams, limits, options, platform gate, fixed event codes, and the request-write delivery evidence. |
| `EngineServiceBoundedFrameReader.cs` | One 4-byte big-endian length and one bounded payload, read from a source. No allocation above 65536 bytes. Reports Idle only for a proven zero-byte transfer, and Partial or Unknown for a failed read that may have consumed bytes. |
| `EngineServiceSidPolicy.cs` | Non-user SID prefilter, account-type requirement, caller policy wrapper, and explicit Win32 impersonation mapping. |
| `EngineServicePipeServerHandshake.cs` | One unparsed frame, impersonation and token open on a dedicated clean thread, checked revert, clean-thread fatal boundary, caller policy, then parse. |
| `EngineServicePipeServerSession.cs` | Serialized, cancellable session gate that closes before parent loss, runs exactly one stop, keeps the first reason, claims a pipe break as a service stop when a stop is already requested, and resumes a claimed stop after a timeout. |
| `EngineServicePipeListener.cs` | One pipe, one session, readiness proof, bounded reads and writes, a claim-time stop reason, no auto-restart. |
| `EngineServiceIdleGuard.cs` | One monotonic idle deadline credited only after a validated request completes processing and a successful reply, without an observed stop. Each read receives the same remaining absolute boundary deadline. |
| `EngineServiceReadDeadline.cs` | Absolute monotonic boundary deadline, one first-byte frame budget, separate fixed handshake budget, and expiry cause independent of transfer evidence. |
| `EngineServiceCleanThreadDispatcher.cs` | New-thread runner for the impersonation phase and the clean stop seam. The thread pool is never used for impersonation. |
| `EngineServiceServerProof.cs` | App-side SCM process id, pipe owner, and installed binary path proof. |
| `WindowsEngineServiceChannel.cs` | Client channel that proves the server before the first frame and after each exchange, applies the caller's per-operation budget, and reports the reply-read evidence and an ambiguous outcome without replay. |
| `EngineServiceDurableStateGate.cs` | Missing or unreadable record is `cleanup_unknown`; no clean default. |
| `EngineServiceStatusGate.cs` | Instance, freshness, and cleanup coherence for a status read. |
| `EngineControlProtocol.cs` | Client half of the Rust `desktop_control` transport: `HSDC` frame codec, session key descriptor reader, HMAC handshake, monotonic request ids, fixed error mapping, and no replay. |
| `EngineControlSession.cs` | One authenticated session over the launcher-supplied channels, parent-liveness close order, and the service status source that composes the engine answer with the service instance and durable cleanup gate. |
| `GuardedEngineServiceBackend.cs` | Start gate with the source-proxy guard closed, plus one authenticated stop when a control session exists. |
| `EngineServiceHost.cs` | Service-host lifecycle, start and stop states, checkpoints, one generation, no restart. |
| `EngineServiceEventBuffer.cs` | Bounded fixed event codes. No SID, path, process id, or token. |
| `WindowsPipeNativeMethods.cs` | Documented Win32 P/Invoke declarations. |
| `WindowsNamedPipeSecurity.cs` | SDDL to descriptor, token read, account type lookup, and checked revert. |
| `WindowsNamedPipeIo.cs` | Overlapped server reads with monotonic deadlines; legacy client/connect/write wall and monotonic caps, pre-cancel refusal, documented transfer counts, write delivery evidence, and quarantine on unproven completion. |
| `WindowsNamedPipeServer.cs` | First-instance server pipe creation with the exact SDDL and one instance. |
| `WindowsNamedPipeClient.cs` | Exact-mask client open with a per-call frame budget, the reply-read outcome, server process id, pipe owner, and SCM queries. |

The tests are in
`windows/tests/HotspotShade.WinUI2.ServiceHost.Tests/`. They use fakes. They
open no pipe, service, process, route, or network endpoint. They run on a
non-Windows host.

## What the hermetic tests prove

- The frame reader reads exactly one frame, accepts a maximum 65536 byte frame,
  and refuses a zero or oversized length, a short read, an EOF in the middle,
  and a refused source result. It reports Idle only for a proven zero-byte read
  before the first byte of a frame. A partial header, a complete header with no
  body, and a partial body each report Partial. A failed read that cannot prove
  a zero-byte transfer before the first byte reports Unknown.
- A pre-canceled connect, read, or write starts no kernel call. An atomic
  Begin and Dispose race either starts the operation and quarantines the
  context or refuses the begin, and never releases a started operation. A pipe
  wait uses a monotonic cap, so a backward wall clock cannot extend it.
- A successful completion keeps its reported count. A failed completion has
  an unknown count even if the out value is zero. Completion proof still
  releases the native records. The fake native seam covers failed reads and
  writes with zero, positive, and undefined counts, and pre-canceled writes. The
  frame layer reports `unknown` for a refused read whose transfer count is not
  proven zero, so it cannot fall through as a clean refusal.
- The server reads one unparsed frame before impersonation. The token is opened
  with `OpenAsSelf` on a new dedicated thread. Revert is attempted on every
  path after an impersonation attempt. The impersonation thread exits and never
  returns to the thread pool. A failed revert or a handshake deadline with a
  running probe sends no reply, parses nothing, runs no event or stop fallback
  on that thread, records one event on the clean caller thread, and calls the
  fatal boundary once. A normal stop during impersonation waits for the
  checked revert and does not call the fatal boundary. A fatal unverified probe
  keeps the pipe open until the probe thread exits. A clean-thread runner that
  throws after the probe start request, without returning a completion task, is
  treated as a possibly running probe: the handshake fails closed, records one
  unverified event, and keeps the pipe open.
- A handshake read diagnostic follows the read outcome. A proven zero-byte idle
  first-frame read records `frame_timeout`. A partial or unknown read records
  `frame_invalid` even when the transport code is `timeout`, because a consumed
  or unproven byte is a framing problem, not an idle peer. Every one of those
  cases still sends no reply, parses nothing, and starts no impersonation.
- A caller from another account, a low impersonation level, a bad session, a
  non-user SID, a group, Everyone, or SYSTEM is denied. A user SID with a
  positive account type is allowed.
- Win32 impersonation value 0 maps to anonymous, 1 to identification, 2 to
  impersonation, and 3 to delegation. Any other value is refused.
- The server proof fails closed when the service is not running, the process id
  is zero or differs, the owner is not SYSTEM, the binary path differs, or a
  recheck after the connection fails. No frame is sent after a failed proof.
- A missing or unreadable durable record is `cleanup_unknown`. A cleanup
  failure, unknown cleanup, pending routes, or an image mismatch blocks a
  start.
- A status with another instance, a stale read, a future observe time, a
  running status with clean cleanup, or a stopped status with invalid stop
  fields is refused.
- A start after parent loss returns `closed`. A parent loss, cancellation, and
  a service stop run exactly one stop. A session call is serialized. The first
  stop reason wins across a cancellation, shutdown, or parent-loss race.
- A claimed stop that waits past the stop budget is not dropped. The first
  caller reports `engine_stop_timeout`, a clean continuation keeps waiting for
  the in-flight request, and the one stop then runs with the first reason.
  Disposing the session gate after the claim keeps the gate alive until that
  stop settles; a later trigger shares the result.
- A requested stop during connect or the handshake read is a clean service
  stop. It does not report a parent loss, a pipe failure, or an engine failure.
  A connect failure without a requested stop is a parent loss with
  `engine_unavailable`.
- The fake native API drives the production overlapped wait, frame source,
  frame reader, handshake and listener. A healthy six second boundary wait
  completes without cancellation. A first byte just before the idle horizon
  can finish under the fixed frame budget. Partial prefix, header-only, body,
  and trickle cases expire without restarting that budget. A silent pending
  read is canceled once at the absolute boundary and never replayed.
- Fake forward and backward wall-clock jumps do not change boundary expiry;
  server reads never consult UTC. Cancellation races with failed, proven zero,
  and positive transfers preserve the frame outcome. Incomplete completion or
  a missing completion event quarantines live storage. Healthy hidden polls
  followed by silence run one stop before one pipe disposal. A stop at that
  boundary wins over the expiry reason, including when storage is quarantined.
- The handshake read uses its own fixed deadline even when its first byte is
  late. Partial or unknown handshake expiry keeps the framing diagnostic. An
  early proven Idle from a broken seam closes immediately without spinning.
  Delayed validated hello earns credit only after a successful reply within
  its fixed deadline. Expired policy, reply or process-id checks, invalid input,
  denied authentication, failed writes and cancellation earn no credit. A linked
  timeout with unknown transfer preserves both timeout and framing diagnostics.
- A backend request longer than the idle budget can finish and then read a
  queued poll. Both success and valid failure replies earn one interval. Silence
  after the final response expires at that response's new boundary. Invalid
  input, failed replies, stop during backend work, stop during the write and
  stop after a frame all close with the expected request counts, stop reason,
  single stop and stop-before-dispose order. Synchronous and pending completion
  collection crossing boundary or frame expiry is refused with transfer
  evidence retained and no quarantine when completion was proved.
- A shutdown with a mismatched session is answered `forbidden` and runs no
  stop. Only an accepted shutdown, or one whose stop the session already
  claimed, stops the service.
- The service host reports StartPending, Running, StopPending, and Stopped, and
  reports Running only after the listener proves its first pipe instance
  exists and after an immediate listener completion recheck. A listener that
  ends or times out before readiness never reports Running. The recheck is not
  atomic with the status call, so the narrow window below remains. A pipe name
  already in use stops the host. A second run is refused. A stop timeout is a
  failed stop. A fatal revert result disables the host and refuses a later run.
  Nothing restarts automatically.
- The separate SCM adapter registers the control handler before any status
  report, maps the host states to `SERVICE_STATUS`, converts a stop that wins
  before Running to StopPending, keeps the longest pending wait hint, sends
  one stopped record with a fixed service-specific exit code, accepts
  interrogate, and refuses pause, continue, and custom controls. The
  configuration is read from the process command line, not the SCM service
  main vector. The executable is not in the solution or app and has no
  install, launch, route, or network call. These are fake-backed checks.
- The host readiness and stop budgets use the monotonic clock seam.
  Readiness or stop completion at the final budget check is accepted instead of
  being reported as a timeout.
- The guarded backend returns `unsupported` for every start, records
  `source_proxy_guard_closed`, and never launches.
- The per-operation client budgets are pinned. A start waits thirty five
  seconds, a stop twenty five, and every other operation five. Both long
  budgets exceed the matching service budget plus one short budget, and a test
  fails if either table drifts. The reserved start and stop service budgets are
  pinned false.
- The channel passes the caller's budget to the client pipe unchanged, so a
  start reply is not cut at the five second short budget. The base channel form
  supplies no delivery evidence. A zero budget, a busy gate, and a caller that stopped
  before the gate start no pipe call and are transient, not ambiguous.
- A partial reply read is an ambiguous outcome and closes the pipe with no
  replay and no second read. An unproven read and a refused read report
  `unproven`. A proven zero-byte reply read reports `missing` and is still
  ambiguous after a delivered request. A partial request write is ambiguous. A
  failed write that started no kernel call is a transient clean refusal and
  keeps the pipe. A failed native write has an unknown count and closes the
  pipe. A write with a positive or undefined count
  is ambiguous, including a cancellation that lands inside the write. A
  failed server proof after the reply is ambiguous. A valid failure reply
  keeps the pipe, so a failed hello can be retried on the same connection.
- The core client turns an ambiguous answer into `EngineReply.OutcomeUnknown`
  with a fixed code, and a later successful exchange is not ambiguous. A
  channel without outcome evidence keeps the old fixed timeout and claims no
  ambiguity. An exchange channel that throws after the frame was handed to it
  is an unknown outcome, never a clean refusal.
- The Rust guard `require_token_destination_proof` remains present and returns
  `ErrorKind::Unsupported`.

## Engine control seam

`EngineControlProtocol.cs` and `EngineControlSession.cs` implement the service
half of the transport in `rust/src/desktop_control.rs`. The engine is the
server. The service is the shell.

- The launcher supplies one duplex control channel, one parent-liveness
  channel, and a 32-byte session key. The service keeps its ends for the life
  of the generation.
- The engine sends a 32-byte challenge. The service answers with
  HMAC-SHA256 over the fixed hello label, the server nonce, and a fresh client
  nonce. The engine answers with its own proof over the fixed ready label. A
  wrong key or a wrong proof is refused before any request.
- Each request has one 16-byte header and one bounded payload. The request id
  starts at 1 and increases. A zero, repeated, or lower id is a protocol
  fault. A write or read failure closes the session. The client never resends
  a request and never reads a second reply.
- A validated failure reply keeps the session open. Every transport,
  handshake, or framing failure closes it.
- `Dispose` closes the parent-liveness channel first, then the control output,
  then the control input, before waiting for the session lock. Fake-pipe tests
  cover blocked handshake and request reads. Native stream cancellation and
  bounded close are not yet proven, so a future launcher must provide bounded
  I/O. This object starts no process and creates no pipe.
- The engine status answer is one flat JSON object with the engine fields in
  `EngineControlStatusSource`. Values use the service field words: `0` or `1`
  for booleans, unix seconds for times, and the fixed engine, mode, scope,
  stop, and cleanup words. The service adds `v=1`, its own instance id, and
  a conservative cleanup word. The engine cannot override those three values.
  A running status and an apparently clean durable record both carry
  `cleanup=unknown` until process exit and cleanup are proven.
- If the status source or gate rejects a sample, the backend passes its fixed
  error code to the service session. For example, pending or failed cleanup
  stays distinguishable from an unavailable engine. The sample is still
  refused and the start guard remains closed.
- `GuardedEngineServiceBackend` sends one authenticated stop when a control
  session exists. An acknowledgement alone cannot prove cleanup, so the
  result remains `cleanup_unknown`; it is not retried. A missing session also
  leaves cleanup unknown. Every start remains
  refused by the source-proxy guard. The session also refuses start without
  sending a frame, so a caller cannot bypass the backend guard.

`IEngineControlChannelFactory` is the launcher seam. The default factory is
`UnavailableEngineControlChannelFactory`, so this build still has no engine
session and reports `engine_unavailable`. The hermetic tests inject a fake
engine peer over in-memory streams and exercise the real frame codec,
handshake, request ids, replay refusal, status mapping, stop path, and dispose
order. No pipe, process, service, route, adapter, or endpoint is created.

The client applies no deadline, matching the Rust contract. The service host's
backend call is still unbounded. A launcher that enables the session must add
a bounded readiness check, or the service must add a watchdog that closes the
parent-liveness channel and the control channel on expiry. Until then, a dead
or silent engine can hold a status request open and delay the service stop
path.

## What is not implemented

- No service installation, `CreateService`, `StartService`, `sc.exe`, or
  service security descriptor applied to a live service. The separate
  `windows/src/HotspotShade.WinUI2.Service/` project now holds an SCM service
  main, dispatcher, and status adapter. It is unapproved, not installed, not
  in the solution or CI, and has never run on Windows.
- No installer, protected `%ProgramData%` directory, parent reparse check,
  write path, flush, or atomic replace. `EngineServiceDurableStateGate` reads
  an injected store and refuses when the store is missing or unreadable. The
  separate Service project supplies a bounded, read-only file store, but not
  the protected directory or a writer.
- No launcher, launch gate, process handle, final frame, or adapter identity.
  The authenticated control client and status source exist, but the default
  channel factory is unavailable. A reviewed launcher must create the private
  control pipes, the key pipe, and the parent-liveness pipe, write the 64 hex
  key bytes and newline, start the installed engine image with the child
  handles, and return the service ends. The guarded backend still refuses
  every start because the Windows source-proxy guard is closed.
- No Rust engine-side `ControlHandler`. The client implements the transport
  and the status field contract. The engine must map
  `ControlCommand::Status`, `ControlCommand::Start`, and
  `ControlCommand::Stop` to its stored pairing and service state before the
  seam can report a real tunnel.
- No durable state writer. A successful authenticated stop is a session success,
  but the service does not yet write the stopped phase, cleanup result, and
  process identity to the durable record. A later start therefore still fails
  closed. Do not treat the stop ack as a recorded cleanup result until the
  writer and its review exist.
- No app wiring, package capability, app service extension, full-trust host, or
  executable entry point.
- No live Windows host result. There is no Windows host run in this tree. The
  P/Invoke code was compiled on a non-Windows host, not run on Windows.
- No proof that `GetSecurityInfo` on a pipe handle returns the owner through
  `SE_KERNEL_OBJECT`. The app fails closed if it does not. This is a design
  hypothesis, not a verified result.
- No proof that a synchronous `LookupAccountSid` for a domain SID returns inside
  the account-type budget on a disconnected host. A timeout is a denial.
- No package-family check. The optional package family field is empty. The
  account and SID checks do not depend on it.
- No `StartService` on a person start action. The app-side proof requires the
  service to be already running and fails closed otherwise. This is deliberate
  because the existing tree forbids a service start path before review.
- No automatic restart, keep-running behavior, or reconnect grace. One
  listener serves one session and then returns.
- The process-termination path is not exercised. `EngineServiceProcessTerminator`
  calls `Environment.FailFast`, and a test cannot run it without ending the
  test process. The hermetic tests use a fake fatal boundary. A future SCM host
  must supply either that terminator or an explicit disablement boundary that
  refuses every later start. The host also sets `Disabled` and refuses a later
  run, but that is a host-instance state, not a process-wide guarantee. No SCM
  adapter exists to make the process-wide guarantee.
- A fatal unverified probe whose thread never exits, and a probe start request
  whose runner throws before returning a completion task, keep the pipe handle
  open for the life of the process. That leak is deliberate: closing the pipe
  under a thread that may still use it is worse. The process terminator path
  ends the process instead. A disable-only boundary leaves the handle and the
  thread until process exit.
- A normal stop waits for the probe's checked revert. A probe thread that never
  returns therefore keeps the listener alive until the host stop budget
  expires. The host then reports a stop timeout and must terminate the process.
  No fail-fast and no pipe close happen on that path. No test can force a
  kernel call to hang forever.
- The host checks listener completion before and immediately before the
  Running report. That is not atomic with the status call, so a listener that
  finishes in the last narrow window can still be reported Running once. A
  future SCM adapter must treat the listener result as authoritative and move
  directly to StopPending.
- If the stop continuation cannot be scheduled at all, the stop result is
  reported as `internal` and the gate is kept open. No test can force
  `Task.Run` to fail without patching the runtime.
- No test changes the real system clock or proves a Windows clock step. The
  pipe monotonic cap and the host readiness and stop budgets are checked with
  source contracts and fake-clock tests. The Begin/Dispose check is a bounded
  race stress test, not a proof of every interleaving.
- The read policy is fake-native and fake-clock tested. No test proves actual
  Windows pipe pacing, cancellation behavior, or driver latency. Silent
  boundary expiry uses the remaining idle budget plus completion proof. A late
  first byte can add the fixed frame budget. Backend request execution is not
  bounded by this policy, so there is no end-to-end idle stop bound while a
  request runs. No test changes the host clock. Native cancellation with an
  unknown transfer closes the session even if the peer was healthy. The repair
  removes the five second boundary collision; it does not make cancellation
  idle-safe. A driver that never signals leaves storage in quarantine until
  process exit. Capacity is bounded and later operations fail when it is full.
- The one stop claim is made with the cancellation state read in the same
  critical section, so a stop that lands between the listener's last check and
  the claim is a service stop. A cancellation that lands after the claim keeps
  the parent-loss reason because the pipe break was observed first. That
  ordering is decided at claim time, not by a later status read, and it is not
  atomic with anything outside the gate.
- The app request budget is per operation and is separate from the service
  budgets. `EngineServiceCallBudgets` gives hello, status, forget, shutdown,
  and the unsupported operations the five second short budget, a start thirty
  five seconds, and a stop twenty five seconds. Both long budgets exceed the
  matching service budget plus one short budget for the connect, the server
  proof, and the reply write. A service host check pins that relation. A caller
  can still pass one uniform budget for diagnostics.
- The service start and stop budgets in `EngineServiceTransportLimits` are
  reserved, not enforced. `StartTimeoutEnforced` and `StopTimeoutEnforced` are
  false and a test pins both. There is no reviewed engine launch seam to bound,
  and the guarded backend refuses every start. The stop path is bounded by the
  session gate stop wait and the host stop budget. The remaining integration
  blocker is an approved launch seam with a cancellable wait plus a
  process-identity proof for an exited engine.
- A client that abandons a start does not cancel the service. The service keeps
  working on the request and fails to write the reply, which is a parent-loss
  stop with the fixed events. The client reports an ambiguous outcome and the
  app must re-read status. There is no request cancel frame in this version.
- Server boundary and frame deadlines are repaired only in this unwired
  ServiceHost foundation. Legacy BrokerRuntime polling, timeout and
  cancellation behavior is unchanged. No real Windows service or app path is
  enabled by these changes. Live Windows measurements remain open.

## Scope and safety rules

- The source-proxy engine guard is closed. Do not enable a real start to make a
  demo work.
- Do not install or run a service, create a pipe on a shared host, change a
  route, create a TUN device, load Wintun, or use a token from a command line.
- Do not wire this project into the solution, installer, app package, or CI
  until the independent review below is complete and the design gates G1 and
  G2 are recorded.
- The same-user limit is unchanged. Any process running as the installing
  account can pass the account check. It cannot read a bearer, a source
  credential, or an identity key. The boundary protects other accounts and
  remote clients, not one process of the account from another.

## Independent security review request

A reviewer should answer these questions before any enablement:

1. Is `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, and a
   maximum of one instance present on every server pipe creation path?
2. Is the exact user mask `0x00120183` still the only client mask, with no
   create-instance, delete, DACL, or owner right?
3. Does every server path read one bounded frame before impersonation, open the
   token with `OpenAsSelf` on a thread that never returns to the pool, and call
   and check `RevertToSelf` on every path, including an impersonation failure?
   Does a normal stop during impersonation wait for the checked revert without
   failing fast, while a failed revert or a deadline with a running probe
   records nothing and runs no stop on that thread, then fails closed through
   the fatal boundary? Is the pipe kept open until an unverified probe thread
   exits?
4. Does the caller policy reject well-known non-user SIDs and require a
   `LookupAccountSid` user type, and does it still compare the exact token user
   SID to the installed user SID?
5. Is the Win32 impersonation mapping explicit and fail-closed for an unknown
   value?
6. Does the app-side proof require the SCM process id, the SYSTEM pipe owner,
   and the installed binary path, and does it fail closed when any step is
   inconclusive? Does it send no frame after a failure?
7. Is a missing or unreadable durable record always `cleanup_unknown`, never a
   clean record?
8. Are session calls serialized, is a start refused after parent loss, and is
   exactly one stop run for a parent loss or service stop? Does the first stop
   reason survive a cancellation or shutdown race, and does a stop claimed
   after a timeout still run when the in-flight request leaves? Does gate
   disposal defer to that claimed stop instead of dropping it?
9. Are status instance, read freshness, future observe time, running cleanup,
   and stopped cleanup rules enforced?
10. Is the engine source-proxy guard still closed and is every start path
    unable to launch?
11. Are the event records fixed tokens with no SID, path, process id, address,
    or token?
12. Does a requested stop during connect or the handshake read report a
    service stop rather than a parent loss or engine failure?
13. Does a forbidden shutdown leave the live session and engine alone, and
    only an accepted shutdown stop the service?
14. Does the host avoid reporting Running after the listener has finished, apart
    from the documented narrow window between the final completion recheck and
    the status call?
15. Does a boundary read use the remaining monotonic idle deadline without
    polling cancellation at five seconds? Does the first consumed byte start
    one fixed frame deadline? Is the handshake deadline separate and fixed?
    Do all failed reads close without replay, and do diagnostics distinguish
    deadline expiry from zero-transfer evidence? Do forward and backward wall
    clock changes leave the boundary unchanged? Does a validated request earn
    one fresh boundary interval only after processing and a successful reply,
    including hello within its fixed deadline? Do failed writes, malformed
    input and observed cancellation earn none? Is backend execution explicitly
    unbounded, and are late completion observations refused without inferring
    when the bytes arrived?
16. Do the readiness and stop budgets use the monotonic clock and recheck
    completion at the budget boundary?
17. Does a clean-thread runner failure after the probe start request fail closed
    and keep the pipe open when no completion task proves the probe exited?
18. Does the README avoid claiming a Windows host result, a service install, a
    live pipe, or a tunnel, and does it state the idle decision bound as a
    design bound with no hard real-Windows guarantee?
19. Is a stop that lands between the listener's last check and the one claim a
    service stop, and is a stop that lands after the claim kept as the first
    parent-loss reason? Is the stop run before the pipe is disposed?
20. Does the app-side client use per-operation budgets, with a start and a stop
    that outlive the matching service budget, and does the channel apply the
    caller's budget to its own reply read? Does the app-side `EngineSession`
    keep that table and preserve the ambiguous outcome through its second wire
    validation, leaving a start, stop, or forget pending until a status read
    confirms it? Is a request that reached the pipe and produced no validated
    reply reported as an ambiguous outcome rather than a clean refusal? Does a
    partial or unproven reply read close the pipe with no replay, and is a
    proven zero-byte reply read kept distinct from a partial one? Does a failed
    request write keep its delivery evidence, so only a write that never
    started a kernel call or provably delivered zero bytes is a clean refusal?
21. Are the service start and stop budgets still reserved and not enforced,
    and are real Windows read timing and service integration still unverified?
22. Does the control client use the exact `HSDC` header, version, HMAC labels,
    key descriptor format, and command bytes from `rust/src/desktop_control.rs`?
23. Does every request allocate one increasing id, and does a write or read
    failure close the session with no replay and no second reply read?
24. Does `Dispose` close the parent-liveness channel before the control
    channels, and does the launcher create each channel with no access for an
    unrelated process?
25. Does the status source refuse engine-supplied `v`, `instance`, and
    `cleanup`, and preserve `cleanup=unknown` when a clean exit is unproven?
26. Does every stop remain `cleanup_unknown` until cleanup is proven, and does
    every start remain behind the source-proxy guard?
27. Does the launcher or service add a bounded readiness check before the
    unbounded control client can hold the backend call open? Does a timeout
    close the parent-liveness channel and the control channel?

## Build and test on a non-Windows host

These commands run the pure and fake-backed checks. They do not create a pipe
or run a service.

```text
dotnet build windows/src/HotspotShade.WinUI2.ServiceHost/HotspotShade.WinUI2.ServiceHost.csproj -c Release
dotnet build windows/src/HotspotShade.WinUI2.Service/HotspotShade.WinUI2.Service.csproj -c Release
dotnet run --project windows/tests/HotspotShade.WinUI2.ServiceHost.Tests/HotspotShade.WinUI2.ServiceHost.Tests.csproj -c Release
```

Expected: both builds have no warnings, and the test runner prints
`ALL WINDOWS SERVICE HOST FOUNDATION CHECKS PASSED`. A pass is not a Windows
host result, a named pipe, an impersonation call, a service install, an SCM
dispatch, or a tunnel.
