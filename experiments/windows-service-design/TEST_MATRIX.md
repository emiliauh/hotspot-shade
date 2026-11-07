# Windows service design test matrix

Status: **UNAPPROVED**. Revision 4. Test plan only. No test in this file has
been written or run. No service was installed, no pipe was created, no process
was started, no route was read, and no Windows host was used for this plan. No
production enablement is approved. Section 9 is the traceable adversarial
matrix for the fourth review, id `c0b94fca-d9ea-4d4f-8aa8-87de7c508503`, B1 to
B5 and H1 to H4. The task record for that id was not reachable; the supplied
content is treated as complete. Section 10 is the matrix for the fifth review,
id `e1b9ed6a-3041-4221-873f-3a406392400b`, E1 to E11, on the same terms.

Architecture: `WINDOWS_SERVICE_ARCHITECTURE.md`.
Review answer: `REVIEW_RESPONSE.md`.
Decisions and gates: `OPEN_DECISIONS_AND_REVIEW_GATES.md`.

## 0. Tiers

| Tier | Where | Needs | Uses | Never does |
|---|---|---|---|---|
| H | Any OS | A supported .NET runtime, recommended .NET 10 LTS | Pure state, source contracts, fakes | Create a pipe, process, service, socket, adapter, or route |
| V | Windows VM, unprivileged | A supported .NET runtime, Windows | Real named pipe, real processes, fake engine, console service host | Install a service, create an adapter, change a route, load Wintun |
| R | Windows VM, administrator, disposable | Administrator, owner approval | SCM install and uninstall | Create an adapter, change a route, load Wintun |
| R, Wintun exception | Disposable Windows VM, administrator | Owner approval per run | R20 and R23 only: load Wintun and create and remove a test adapter | Change a route, carry traffic, or leave an adapter behind |
| T | Any OS, plus Windows CI for the platform parts | Rust toolchain | Control pipe framing, error contract, handle hygiene | Create a real tunnel or a route |
| L | Real device with a real hotspot | Owner approval, source device, admin | The real tunnel | Nothing here is approved or run |

Tier V deliberately does not use `CreateService`. It runs the service core as a
console host (`--test-host`) with the same pipe, DACL, identity, lifecycle, and
handle code. That keeps the design testable without an install during review.
Tier R covers the SCM contract separately.

.NET 8 support ends on 2026-11-10. Tier H and tier V do not pin .NET 8. They run
on the supported runtime chosen by O15. The existing broker project still targets
`net8.0-windows10.0.19041.0`; S26 records that it must be retargeted before any
implementation starts.

Every row has an ID, a setup, an action, an assertion, and what it does not
prove.

## 1. Harness and mocks

| Mock | What it is | It can do | It cannot do |
|---|---|---|---|
| `fake_engine` | A test executable that speaks the control pipe and the event pipe | Ready, final, hang, crash, exit early, refuse the bearer, return each error code, report a chosen connection count | Prove that the real engine behaves the same |
| `fake_service_host` | The service core as a console app, no SCM | Own the pipe with the first-instance flag, enforce identity, launch `fake_engine`, run the lifecycle, write the state record | Prove SCM start, stop, or security descriptor behavior |
| `fake_caller` | A process started with a chosen user SID, a chosen integrity level, or an AppContainer token | Connect as the configured account, as a second account, or as an elevated process of the same account | Change its own token after start |
| `squatter_pipe` | A process that creates the pipe name before or after the service | Accept a connection and record every byte | Pass the SCM PID and owner checks |
| `squatter_tcp` | A process that binds a chosen loopback port | Accept and record requests | Receive a usable bearer if the design is correct |
| `handle_auditor` | A child process that reports `NtQueryInformationProcess` handle counts and `GetHandleInformation` flags for a known list | Show the inheritable set and the grandchild set | Prove kernel level leakage |
| `secret_scanner` | A helper that reads a command line, a file, a pipe replay, and a state record and searches for a fixed 64 character test value | Prove a fixed vector is absent | Prove that no copy exists anywhere in memory |
| `fake_route_table` | A fixed `RouteObservation` for the pure layer of `rust/src/windows_route_verify.rs` | Present owned routes, foreign routes, an empty table, and an API error | Prove the live Windows table |
| `mock_clock` | A manual clock | Advance freshness, deadlines, and stop timestamps | Prove wall clock behavior |
| `crash_child` | A process that runs only the fake engine | Be killed to test liveness | Prove route cleanup |
| `crash_injector` | A debug helper in the test host that stops the host at a named point | Stop between the intent write and `CreateProcess`, or between `CreateProcess` and the PID write | Prove the real service crash path |
| `precreated_dir` | A standard-user-created directory at the `ProgramData` path | Show that the installer refuses it | Prove the real ACL on a real disk |
| `fake_app_service` | A fake UWP app service bridge with a chosen caller package family and a peer count | Accept one peer, reject a second, and reject the wrong family | Prove a real package identity or app service |
| `fake_install_root` | A fake install root with a reparse point or an engine path outside it | Show that the launch path refuses before `CreateProcess` | Prove a real NTFS junction or ACL |
| `same_image_process` | A process started from the installed engine image path but not by the service | Show that the service observes and blocks, and never adopts it | Prove that a real orphan cannot be spoofed |
| `create_instance_probe` | A same-user process that calls `CreateNamedPipeW` on the live service pipe name with `FILE_CREATE_PIPE_INSTANCE` | Show that the DACL denies the create | Prove the exact real DACL |
| `restricted_engine` | A fake engine launched under a restricted token with access to a fake adapter | Show that it can relay and cannot change a route | Prove a real Wintun adapter and token |
| `link_identity_fixture` | A fake interface table with LUID, GUID, type, and gateway | Exercise same-IP and changed-identity cases | Prove a real Windows interface table |

`crash_child` is not a tunnel. A `TerminateProcess` on it is allowed. Do not
terminate a real engine that may own routes.

## 2. Tier H: hermetic contract tests

Runner: the existing dependency free runner,
`dotnet run --project windows/tests/HotspotShade.WinUI2.Core.Tests/HotspotShade.WinUI2.Core.Tests.csproj --configuration Release`.
The new checks belong in a new class registered from `Program.cs`, in the same
style as `BrokerBoundaryTests.Run(runner)`.

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| S01 | Source read of the service install script and manifest | Inspect start mode, account, arguments, recovery actions, startup task | Demand start, `LocalSystem`, no arguments, `SC_ACTION_NONE`, no startup task, no `Automatic` | That the SCM accepts the configuration |
| S02 | `EngineLaunchPlan.TryCreateTrusted` | Build a plan with a known secret | The argument list contains only the fixed switches and handle numbers. `DisclosesSecret` is false for a secret that is not in the path | That `CreateProcess` receives exactly that list |
| S03 | Plan builder | Relative path, path outside the install root, quoted path, invalid port, equal handle pair | Each returns the fixed failure and builds no plan | That an NTFS ACL protects the path |
| S04 | `EngineBrokerFields.TryConvert` | 25 fields, a 33 character key, a 513 character value, a duplicate key, a non-string value, a credential key | Each is refused with the fixed code. A credential key is `forbidden` | That the pipe frame parser has the same limits |
| S05 | Source read of `Package.appxmanifest` | Inspect extensions and capabilities | The UWP package still declares no app service extension and no capability | That a future package will not |
| S06 | `EngineBrokerService` fake | `status` before `hello`, then `hello` with session A, then `hello` with session B | `not_connected`, then ok, then `forbidden`. The bound session does not change | That the pipe accepts a second connection |
| S07 | Lifecycle state machine fake | Start during `Stopping`, stop during `Starting`, retry during `Launching` | Each returns `busy` and changes no state | That the real gate is held across a process wait |
| S08 | Generation fake | Complete generation 1 after generation 2 started | The generation 1 result is discarded and its handles are closed | That a real late `CreateProcess` is handled |
| S09 | Generation fake | Retry from idle, from failed, from connected, twice within 2 seconds | Allowed, allowed, `already_running`, `busy`. A retry has a new plan and a new secret | That the old secret is gone from the heap |
| S10 | Mapping table | Engine code `cleanup_blocked` | Wire code `cleanup_blocked`, Start disabled, the fixed text | That the engine emits the code |
| S11 | Mapping table | Engine code `admin_required` | Wire code `admin_required`, Start disabled | That the engine token is actually checked |
| S12 | Mapping table | `wintun_missing`, `route_setup`, `tunnel_setup`, `service_start` | Each maps to its own code, not to `not_ready` | The real failure causes |
| S13 | Mapping table | `manual_phone`, `phone_auth` | `manual_phone`, `not_paired`. Neither is retried | That the token was rejected for that reason |
| S14 | Mapping table | Bearer rejection | `boundary_auth_failed`, fatal, no retry with the same bearer | That the engine returns 401 |
| S15 | Mapping table | An unknown code, a 404, a 415, `protocol_mismatch`, `launch_timeout`, `engine_stop_timeout`, `boundary_busy`, `busy`, `forbidden` | Each has a fixed wire code and text. The human message is never parsed | That no future code is missed |
| S16 | Mapping table | Timeout | `timeout`, running unknown, never `running=0` as a confirmed off | That the deadline fires |
| S17 | Mapping table | Engine process exit, pending cleanup, a missing final frame, `source_device_gone` | `engine_lost`, `cleanup_pending`, `cleanup_unknown`, `source_device_gone`. None relaunches | That the wait fires |
| S18 | Status builder with a hostile fake status | A status containing `logs`, `error`, `iface`, `stats`, `platform.default_iface`, an address, and a port | None appears in the wire fields. Only the fixed schema is emitted | That the engine never emits them |
| S19 | Consistency rules | Every rule in the architecture section 11.5, one case each | Each violation is `bad_response`. `phone.connections_known=0` with `running=1` is accepted. `phone.connections_known=1` without a fresh phase 2 authenticated status is rejected. A phase 1 manual session with a known source count is rejected. A target gauge value in `phone.connections` is rejected | That the app displays the two counts correctly |
| S20 | Source read of the boundary client and the service secret holder | Search for `Encoding.ASCII.GetString`, string concatenation with the secret, and an unpinned buffer | No match. One sealed buffer, cleared on every exit path | That a copy does not exist in the CLR heap |
| S21 | Source read | Search the privileged layer for a single-instance mutex, for exit code 0 on acquisition failure, and for `TerminateProcess` | No mutex. No silent success. No forced termination | That the SCM enforces one instance |
| S22 | `EngineTiming` fake clock | Ages 0, 2.9 s, 3 s, 9.9 s, 10 s, and a future timestamp | Fresh, fresh, stale, stale, unavailable, unavailable | That the app polls at the stated rate |
| S23 | Status cache | Change the service instance id between two samples | The cached sample is discarded and the state is `checking` | That the service restarts cleanly |
| S24 | Threat table source check | Read the table and the caller identity rules | Every same-user row says allowed for control and denied for the secret. No row claims a block that the design does not provide. An elevated same-account caller is allowed. A second non-administrator account is denied | That a real caller behaves the same |
| S25 | Frame and status schema | Inspect the constants and the status builder | Length is 4 byte big-endian. The cap is 65536. `ttl_bad` is always present and non-negative. `ipv6_dropped` and `fragments_dropped` are present. `phone.connections` and `relay.tcp_flows_active` are separate fields with separate known flags | That the peer honors the cap |
| S26 | Runtime target | Read every changed project and the CI matrix | No new project targets .NET 8. The service targets a supported runtime. The broker retarget is recorded as a prerequisite | That the runner image provides the runtime |
| S27 | Installer SID resolution | Fake interactive token and fake elevated token with different user SIDs | The pipe DACL and the service configuration use the interactive SID. An explicit `--user-sid` overrides it. No silent fallback to the elevated SID | That a real UAC split-token logon behaves the same |
| S28 | Service control source read | Inspect the handler list and the wait hint | `STOP`, `SHUTDOWN`, `PRESHUTDOWN`, and `SESSIONCHANGE` share one bounded path. The code does not call 20 seconds "below the default" | That the SCM grants the wait hint |
| S29 | UWP app service bridge source read | Inspect the caller check and the accept path | `AppServiceTriggerDetails.CallerPackageFamilyName` must equal the app's own family name. One broker peer is accepted. A second peer is refused. No other app is relayed | That a real app service connection reports the family name |
| S30 | Install and registration source read | Inspect the installer and the launch path | Real mode is a per-machine MSI under `%ProgramFiles%`. Developer registration and an unpackaged loose-file layout are preview-only and are refused by the service install. The engine path is opened with reparse checks and must resolve under the install root | That a real installer writes the expected layout |
| S31 | Broker preview source read | Inspect `windows/src/HotspotShade.WinUI2.Broker/app.manifest` and `Win32EngineHost.IsElevated` | The manifest is `asInvoker` and the launch path returns `AdminRequired`. No preview code path claims elevation | That the preview cannot start a tunnel on a real host |
| S32 | Source read of the recovery path | Search for image-path adoption, process-handle adoption, and any frame sent to an `orphan_candidate` | No adoption by image path. No frame is sent. The nonce proof is absent or gated behind an unapproved decision | That a real process cannot match the path |
| S33 | Service rights source read | Inspect the installer contract, the service descriptor, and the app open call | The person has `SERVICE_QUERY_STATUS`, `SERVICE_QUERY_CONFIG`, `SERVICE_START`, `SERVICE_STOP`, `SERVICE_INTERROGATE`, and `SC_MANAGER_CONNECT`. The app fails closed on access denied | That the SCM accepts the descriptor |
| S34 | Stopped status builder | Build a stopped status with a cached nonzero gauge and a fresh live zero gauge | The stopped status has both counts empty and both known flags 0. The live zero is accepted with `running=1` and `known=1`. A stopped zero is `bad_response` | That the app label matches |
| S35 | Threat table source read for review H3 | Read the `LocalSystem` data-plane rows and the ownership claims | The table says a data-plane defect can compromise the host. No row claims least privilege. The split is labeled unproven | That a real defect behaves as described |
| S36 | Session and SCM precedence source read | Inspect the stop handlers and the timeout table | One stop path wins. A pipe break during an SCM stop does not run a second stop. No timeout starts a process | That the SCM timing matches a real host |
| S37 | Pipe mask source read | Inspect the server SDDL constant and every client open path, including any framework pipe constructor | The user ACE is `0x00120183`. The client requests exactly `0x00120183`. No path requests `GENERIC_WRITE`, `GENERIC_ALL`, or `0x4`. The two constants are in one reviewed place on each side. | That Windows grants and denies as the mask table says. V97 and R19 test that. |
| S38 | Status builder and app text, `observation_unavailable` | Build statuses for the stop in phase 1 and phase 2, and render the app text | `running=0`, `source=0`, `trusted=0`. Phase 2 keeps `paired`. No text says hotspot lost, source device gone, rejected, or not paired. A later positive answer does not restart. | That the 300 s value is right. That is O23. |
| S39 | Guard handling source read | Inspect where gateway MAC, SSID, and BSSID are read, stored, compared, and cleared | Memory only. Not in status, diagnostics, failures, the state record, or the event log. Unknown blocks nothing. A known change clears the credential. No text calls a match identity. | That the values are readable on a real host. R22. |
| S40 | SCM control source read | Inspect the accepted controls, the installer preshutdown setting, and the checkpoint loop | `SERVICE_ACCEPT_PRESHUTDOWN` and `SERVICE_ACCEPT_SESSIONCHANGE` are accepted. `dwPreshutdownTimeout = 20000` is set by the installer. Checkpoints advance only inside bounded steps. The shutdown fallback never waits for the engine. | Host behavior. R24. |
| S41 | Final-frame classification, pure | Feed the classifier: frame ok, frame failed, no frame with exit code 0, no frame with a crash code | Only a received `cleanup=failed` sets the latch. No frame is `cleanup=unknown` whatever the exit code. | A real pipe race. V106. |
| S42 | Caller authentication source read | Inspect the accept path | A bounded unparsed first-frame read comes first. Then `ImpersonateNamedPipeClient`, `OpenThreadToken` with `OpenAsSelf = TRUE`, `TokenUser` and `TokenSessionId`, and `RevertToSelf` on every path. No frame is parsed before the token check. `GetNamedPipeClientProcessId` feeds no decision. | Real Windows impersonation behavior. V107, V108, R25. |
| S43 | Launch gate source read, engine side | Inspect the engine command before `go` | Before `go` there is no Wintun load or call, no outer socket, no probe, and no route or address call. The gate waits at most 10 s. | Runtime behavior. V101. |
| S44 | Orphan rule, pure | Feed process lists: recorded PID and creation time; `SYSTEM` token inside the launch window; `SYSTEM` outside it; user token; unreadable token | Only the first blocks while it lives. The second blocks for at most 12 s. The rest are recorded and never block. None is adopted or sent a frame. | A real token read. V103. |
| S45 | Citation check | Compare the architecture, the response, and this matrix with the working tree `rust/src/gui.rs` and `rust/src/main.rs` | Every citation of the GUI `LinkWatch` change says uncommitted and unverified. No document uses it as evidence or as the service model. | That the GUI change works. T3.21 and a later review. |
| S46 | Probe helper exposure source read | Inspect the threat table, the O2b record, and the helper launch plan | The helper is listed as a privileged parser of hotspot-side input. It runs restricted only after R21 passes, or the O2b acceptance names it. | That the restricted helper works. R21. |

Tier H creates no pipe, process, socket, adapter, or route. It cannot prove any
Windows API behavior.

## 3. Tier T: engine contract tests

Commands:

- `cargo test --locked --manifest-path rust/Cargo.toml`
- `cargo test --target x86_64-pc-windows-msvc --locked --manifest-path rust/Cargo.toml`
  compiles the Windows tests. It does not run them on a Windows host.
- On a Windows VM: `cargo test --locked --manifest-path rust/Cargo.toml`.

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T3.01 | Loopback pipe pair | Round trip every control frame | Version, 4 byte big-endian length, 65536 byte cap, one request in flight | That a real service pipe behaves the same |
| T3.02 | Engine service layer | Force each error cause | Every error reply carries a fixed `code`, including `cleanup_blocked`. No reply relies on the human text | That the client maps the code |
| T3.03 | Engine status | Build a status with hostile fields | Only the whitelist crosses the control pipe | The service redaction |
| T3.04 | Bearer check | Correct, short, long, and wrong bearer | Constant time comparison, no early return, no secret in the error | That the comparison is timing safe at the CPU level |
| T3.05 | Engine handle read | A file handle, a console handle, and a pipe handle for the bearer, the parent, and each control handle | File and console are refused. The pipe is accepted. `HANDLE_FLAG_INHERIT` is cleared | That the service created the right handle |
| T3.06 | Windows VM | Start a child that reports its handle table | The child sees no control handle | Kernel level leakage |
| T3.07 | Fallback only | Start the engine with `--port 0` | The ready frame arrives after the bind and contains the bound port and instance id | That the port is exclusive |
| T3.08 | Engine exit paths | Normal stop, start failure, parent loss, panic in a worker | A final cleanup frame is written on every non-crash path | A hard crash |
| T3.09 | Engine with a forced cleanup failure | Stop the tunnel | The final frame says `cleanup=failed`, not `ok` | That the route table is dirty |
| T3.10 | Fallback only, Windows VM | Bind the engine port from a second socket after the engine bound | The second bind fails | That a squatter cannot win the first bind |
| T3.11 | Fallback only | Compare the status instance id and the ready frame instance id | They match for one engine process and differ after a restart | That a fake engine cannot lie |
| T3.12 | Engine in service mode | Enumerate listening sockets for the process | No loopback listener exists | That no other socket exists |
| T3.13 | Engine with a held credential | Start with no token in the request | The engine uses the held credential and does not return `manual_phone` | That the credential is the right one |
| T3.14 | Loopback relay | Open 3 TCP flows, close 1, open 2 more | `relay.tcp_flows_active` equals the live target-side socket count at each step. It is not written to `phone.connections` | A half-closed or reset flow on a real network |
| T3.15 | Engine with a parent pipe | Close the parent write end | The engine stops and exits within the cleanup budget | The real route cleanup |
| T3.16 | Extracted source silence monitor, fake clock | Simulated `Up`, `Down`, and `Unknown` link, simulated probe silence, then a good probe | On a platform with an observer, 20 seconds of `Down` stops with `hotspot_lost`. On Windows, only `Unknown` is available and it never produces `hotspot_lost`. 90 seconds of probe silence stops with `source_device_gone` under `Up` and under `Unknown`. A good probe resets the timer. A probe that cannot run clears the interval | A real source device and a real Windows link |
| T3.17 | Loopback relay | Half-close one flow, reset another, then open a new one | The live `relay.tcp_flows_active` gauge tracks the open count, not a subtraction of cumulative counters | A real network |
| T3.18 | Fake engine and state record writer | Normal stop, automatic stop, cleanup failure, crash | The final frame and the state record agree for normal, automatic, and failed stops. A crash leaves `cleanup=unknown`. An automatic stop is not `engine_lost` | A real service crash |
| T3.19 | Diagnostics and failures operations | Build both records with hostile input | Only bounded numeric counters and fixed failure codes cross. `ttl_bad` is present and exact. `relay.tcp_flows_active` is separate from `phone.connections`. No address, host, token, key, or interface name crosses | The service redaction layer |
| T3.20 | CLI-shaped source monitor, fake clock | Link closure returns `Some(true)`, probe returns `Silent` for 90 s | The monitor stops with `source_device_gone`. This records the current CLI shape, not a GUI result | A real Windows CLI tunnel |
| T3.21 | GUI-shaped source monitor, fake clock, run against both the committed `auto_stop_sample` and the uncommitted working-tree `auto_stop_sample_watch(LinkWatch::Unobservable, ...)` | `observe_link` returns `None`, probe data is fresh silence for 90 s; then stale or missing probes for 300 s | Committed baseline: the policy resets and does not stop. Working tree: fresh silence stops at 90 s with `source_device_gone`, and stale or missing probes reset without a bound. Both results are labeled as observed behavior of an unverified change, not as the service contract. Revision 4 updates this row for E11. | A real GUI session |
| T3.22 | Service-shaped source monitor, fake clock | Link is `Unknown`, probe returns `Silent` for 90 s, then `Unavailable`, then `Silent` again | The first interval stops at 90 s. `Unavailable` clears the interval. A later silence starts a new 90 s interval. `Unknown` never produces `hotspot_lost` | A real service monitor |
| T3.23 | Service-shaped source monitor, fake clock | Link `Unknown` throughout. Sequences: all `Unavailable` for 300 s; `Silent` and `Unavailable` alternating for 300 s; `Rejected` then `Unavailable`; one `Accepted` at 299 s, then `Unavailable` for 300 s | The first three stop at 300 s with `observation_unavailable`, never `source_device_gone` and never `hotspot_lost`. The fourth resets at 299 s and stops 300 s later. `Unknown` link never starts or resets the clock. Pure `Silent` still stops at 90 s with `source_device_gone`. | Real probe timing, sleep behavior, and the right value. V98 and O23. |
| T3.24 | Engine final-frame write, fake event pipe | Close the read end before the engine writes; make the write block past 1 s; make it succeed | Cleanup completes in every case before the write. A failed or timed-out write changes neither the exit path nor the exit code and is not logged as a cleanup failure. | A real anonymous pipe on Windows. V106. |

## 4. Tier V: Windows VM, unprivileged

Proposed location, not created: `windows/tests/HotspotShade.WinUI2.Service.Tests/`
and a `--test-host` mode in the service project. The service core must be
constructible without the SCM.

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| V01 | `fake_service_host`, `squatter_pipe` | Create the pipe name first, then start the host | The host fails on `FILE_FLAG_FIRST_PIPE_INSTANCE`, records `pipe_name_in_use`, and serves nothing. The app reports `engine_unavailable` | That the real SCM path fails the same way |
| V01b | `fake_service_host`, `squatter_pipe` | Let the service create the first instance, then create a later instance. Connect the app with an injected owner-SID seam that reports `SYSTEM` for the service PID and the test user for the squatter | The app compares `GetNamedPipeServerProcessId` to the SCM PID and refuses the squatter. It sends no frame. The owner check fails closed when the seam reports a non-`SYSTEM` owner | That the SCM PID is authoritative on a real install, and that `GetSecurityInfo` returns the owner on a pipe handle. R12 tests the real API |
| V02 | `fake_service_host`, `fake_engine` | `hello`, `credential.set`, `status`, `start`, `stop` | Every reply is well formed. The client process holds no bearer and no stored credential. The typed token buffer is cleared after `credential.set`. A UI framework text copy is out of scope | That the real engine starts |
| V03 | `fake_caller` as the same user | Connect, `status`, `start`, `stop` | Allowed. The same-user process controls the tunnel and cannot read the bearer or the credential. The event log records the caller | That the real app behaves the same. R13 and R14 cover the other accounts and elevation |
| V04 | Pipe DACL | Open by name as a non-configured SID | `ERROR_ACCESS_DENIED` | That the install time SDDL is correct |
| V05 | Two clients | Connect the second while the first is live | Refused at accept. The first session is unaffected | That the SCM enforces one service |
| V06 | Hostile client | Send a 0 byte frame, a 1 byte frame, a 64 KiB frame, and a frame that claims 1 MiB | Fixed error or close. No allocation above the cap | A memory exhaustion attack |
| V07 | Hostile client | Unknown key, duplicate key, non-string value | `bad_request`, session kept | That the app cannot send them |
| V08 | Hostile client | A field named `token` | `forbidden`, session kept, no echo | That no other field leaks a secret |
| V09 | Slow client | Send half a frame and stop | Closed at the deadline. The gate is not held | A network partition |
| V10 | Fallback only, `squatter_tcp` | Squat the port, then start | The service sends no usable bearer and reports `boundary_auth_failed`. A sent bearer is dead | The pipe design, where this cannot happen |
| V11 | `squatter_pipe` | Squat the pipe name, then start the app | `engine_unavailable`, no secret sent | That the SCM path fails the same way |
| V12 | Fallback only | Stop the engine, then bind the old port | No request reaches the new listener | A port that is reused by an administrator process |
| V20 | `fake_engine` | `TerminateProcess` the fake engine while idle and while running | `engine_lost` within 250 ms. No relaunch in 30 seconds | That a real engine crash is detected the same way |
| V21 | `fake_engine` that sleeps | Exit after 5 s | The wait fires within 250 ms of the exit | Scheduler behavior under load |
| V22 | `fake_engine` | Fail a launch, retry, then complete the old generation late | New handles and a new secret. The old secret is cleared. The late result is ignored | Heap inspection |
| V23 | `fake_engine` that fails the first launch | Retry | The retry launches, the state leaves `Failed`, and no `Closed` is returned | The real engine start path |
| V24 | `fake_engine` that never signals ready | Start | `launch_timeout`. Every handle created for the attempt is closed | A hung `CreateProcess` |
| V30 | WinUI 2 XAML Islands desktop host, real window | Close the window while a session is live | The pipe session stays and status keeps updating | UWP behavior, which is out of scope, and a real packaged host |
| V30b | WinUI 2 XAML Islands desktop host | Minimize the window | The session and tunnel stay live | A suspended UWP app |
| V31 | Desktop host client | Kill the app process | `parent_lost`, the tunnel stops, no relaunch | A real tunnel stop |
| V40 | `fake_engine` that accepts and never replies | `status` | Ends within the deadline plus 250 ms. The gate is released. The next request is served | WinHTTP specifics |
| V41 | `fake_engine` that drips one byte per second | `status` | Ends at the absolute deadline, not at a multiple of per-read timeouts | A slow TLS peer, which does not exist here |
| V42 | Fallback only, no listener | `status` | One attempt, no SYN retry storm, within the deadline | The WinHTTP connect retry option value |
| V43 | `fake_engine` per code | Each error code | The exact wire code and the exact app text. No human message is displayed | The real engine's codes |
| V44 | `fake_engine` returns 302 | One request | `protocol_mismatch`, fatal, no second request, no bearer on the second hop | The pipe design |
| V45 | `fake_engine` with a phase 1 manual credential, then a phase 2 paired status, and a live target gauge | `status` while running in each mode | Phase 1: `phone.connections` is empty with `phone.connections_known=0`. Phase 2: the fake authenticated status count is shown. `relay.tcp_flows_active` is shown separately with its own known flag and is never copied into `phone.connections`. Start and Stop stay enabled | The real source device status and the real relay gauge |
| V46 | `CryptProtectMemory` wrapper | Seal, unseal, clear | The 64 bytes round trip. The buffer is zero after clear | A memory dump |
| V47 | `fake_engine` | Start a tunnel | The command line of the engine and of every child contains no 64 character hex value | A debugger that reads memory |
| V48 | Event pipe and state record replay | Full lifecycle | Neither contains the bearer or the source credential. No credential file exists after phase 1 | A crash dump |
| V50 | `handle_auditor` | Launch the fake engine | The engine's inheritable set is exactly the five control handles | Kernel handles |
| V51 | `fake_engine` starts `handle_auditor` as its child | Child reports | Zero control handles | A driver or service child |
| V52 | Forced launch failure | After the failure | The service host has zero inheritable handles | A leak in a later generation |
| V53 | `fake_engine` that hangs 20 s on cleanup | Stop, then start | `engine_stop_timeout`, start refused, exactly one engine process exists | Real route cleanup |
| V54 | `fake_service_host` restarted with a live fake engine | Start the host again | The PID and creation time match, the host observes the engine and refuses a start. It does not adopt it by image path. After the engine exits, a start stays refused until `recheck` is clean, then succeeds | The SCM restart path |
| V55 | State record DACL | Read as a non-SYSTEM user | Denied | A backup operator |
| V56 | Fallback only | Emit ready before the bind | Test fails. The ready frame must come after the bind | The real bind order |
| V57 | `fake_engine` final frame | `cleanup=ok`, `cleanup=failed`, and no frame | `ok`, latched `failed`, `unknown`. A start is refused for `failed`, `pending`, and `unknown` | The real cleanup result |
| V58 | `recheck` with a clean and an inconclusive table | `recheck` | Clean clears the latch. Inconclusive keeps it and says so | The live table |
| V59 | `fake_route_table` | Owned route present, foreign route present, empty table, API error | The absence proof passes only for the empty table and fails closed on the error | The real Windows table |
| V60 | Idle service host | No app and no engine | The host exits. The tunnel is not kept | The SCM self-stop path |
| V62 | `diagnostics` and `failures` replay | Hostile fake records | Only fixed numeric fields and codes cross. `ttl_bad` is exact. `relay.tcp_flows_active` is separate from `phone.connections`. No address, host, token, key, or interface name crosses | The real engine record |
| V63 | Fresh install, no credential | Query status and inspect the filesystem | `paired=0`, `paired_scope=none`, and no credential file exists | A real install |
| V64 | Phase 1 credential lifecycle | Stop, kill the app, kill the engine, stop the service, then reconnect | The in-memory credential is gone in every case. `source_device_gone` is used, never `hotspot_lost` | A real tunnel |
| V65 | Fake physical route table | Change the recorded gateway, then run a probe | The engine clears the credential and stops with `gateway_changed`. No probe is sent | The live Windows route table |
| V66 | `precreated_dir` owned by a standard user | Run the installer contract against it | The installer refuses the directory and tells the person to remove it. It does not adopt or repair it | A real installer |
| V67 | `crash_injector` between the intent write and `CreateProcess` | Restart the host | The record says `launching` with no PID, the exact adapter name, `guid_planned`, and `routes_may_exist=0`. The host searches for a matching image process but does not adopt it. If none exists it records `cleanup=unknown` and refuses a start until `recheck` is clean. The route scope can be clean because no route was installed | A real service crash |
| V68 | `crash_injector` between `CreateProcess` and the PID write | Restart the host | Revision 4: the gated engine never received `go` and exits on parent loss. The host treats a `SYSTEM`-token image process created inside the launch window as a candidate, waits up to 12 s for it, sends no frame, and does not adopt it. After it exits, the planned name and `guid_planned` read decides `Clean` or `Present`. A candidate alive after the wait is `cleanup_pending`. Revision 3 asserted an indefinite block; E7 replaces it | A real service crash |
| V69 | `PeekNamedPipe` reader | Send half a frame, then stop | The read returns `timeout` at the absolute deadline and does not block. A later complete frame is still read in a fresh request | A malicious kernel driver |
| V70 | Blocked pipe write | Fill the pipe buffer and stop reading | The writer thread waits until the deadline, then `CancelSynchronousIo` returns and the handle closes with `timeout` | A real service crash |
| V71 | State record writer | Truncate the record, corrupt the version, and corrupt the sequence | Each is `cleanup=unknown`, never `cleanup=ok`. A start is refused | A disk that loses a flush |
| V72 | `fake_service_host` with a stopped engine | Send `STOP`, `SHUTDOWN`, `PRESHUTDOWN`, and `SESSIONCHANGE` | Each runs the same bounded stop path, writes the state record, and returns within the wait hint | The real SCM |
| V73 | `fake_service_host` with a recorded engine | Simulate sleep and resume by suspending and resuming the host | The process handle and record remain valid. Status is `unknown` until a fresh status and `recheck`. Nothing restarts | A real sleep transition |
| V74 | `fake_service_host`, fake source device, `probe` | Run `probe` with no tunnel and with a running tunnel | With no tunnel, the helper starts with no bearer, reports one fixed result, updates `source`, `trusted`, `checked_at`, and, in phase 2, `phone.connections`, and exits with `ttl_bad=0`. It creates no adapter or route. With a tunnel, the request is delegated to the engine monitor and no helper starts. The helper exits on parent loss | A real source device and a real Wintun adapter |
| V75 | `fake_service_host`, fake UWP app service bridge | Connect with the expected package family, then with a different family, then with a second peer | The expected family is accepted. The different family is refused with no frame. The second peer is refused and the first session is unaffected | A real package identity and a real app service |
| V76 | Fake install root with a junction or reparse point, and an engine path outside the root | Start the launch path | The launcher refuses before `CreateProcess`. It records a fixed failure and creates no process | A real NTFS junction on a real disk |
| V77 | UWP preview host, real window | Minimize or suspend the window during a live session | The app service session closes and the tunnel stops. The app reports the stop. Nothing relaunches | A real UWP suspension policy and a real tunnel |
| V80 | `fake_service_host`, fake engine, state record writer | Inspect the record after the launch intent and before the adapter identity frame | The record has the exact planned adapter name, `routes_may_exist=0`, and `identity_source=planned`. No route exists. No `install_routes` acknowledgement was sent | A real engine and a real adapter |
| V81 | Crash injection before the adapter identity frame | Restart the host and run `recheck` | The record has no LUID or GUID and `routes_may_exist=0`. No adapter with the exact name exists. The route scope is `Clean`; the result does not claim a general route check. A start is allowed only after the rest of the proof is clean | A real crash and a real adapter table |
| V82 | Crash injection after the identity write and before route install | Restart the host | The record has the LUID and GUID and `routes_may_exist=1`. The absence proof runs normally. A start is refused until it is clean | A real crash |
| V83 | Crash injection after route install | Restart the host | The record has the identity and `routes_may_exist=1`. A live route or adapter is `Present` and keeps the latch. The manual recovery path is the only override | A real route table |
| V84 | `same_image_process` | Start a process from the installed engine image, then start the service | The service never adopts the process and sends it nothing. Revision 4: a user-token process is recorded as `foreign_engine_image` and does not block a start (V103). Revision 3 asserted a refused start; E7 replaces it | That a real spoof cannot influence the latch |
| V85 | Nonce challenge, conditional on O21 | Present a wrong nonce and a right nonce to the orphan channel | The wrong nonce is refused. The right nonce still requires the exact image path, creation time, and a recorded launch. No adoption happens in revision 3 | A real service-only channel |
| V86 | `fake_service_host` with a stopped engine and a stale nonzero gauge | Read status after stop | Both counts are empty and both known flags are 0. A stopped `relay.tcp_flows_active=0` is rejected as `bad_response`. A live fresh zero with `running=1` is accepted | The app label |
| V87 | `link_identity_fixture` | Same gateway IP, changed LUID or GUID | The credential is cleared with `link_changed`. No probe is sent | A real Windows interface table |
| V88 | `link_identity_fixture` | Same gateway IP and same LUID or GUID, different source device | Phase 1 cannot distinguish them. The test records the limitation and does not assert a detection. The token stays memory-only | A real hotspot swap |
| V89 | `create_instance_probe` as the configured user | Try to create a later instance of the service pipe | `ERROR_ACCESS_DENIED`. The first session is unaffected. An administrator later instance is rejected by the SCM PID check | The real DACL |
| V90 | `restricted_engine` and a fake service-owned adapter | Start the engine under a restricted token and open the adapter | The engine relays a loopback frame and cannot change a route. The service closes the adapter after the engine exits | A real Wintun adapter and a real token |
| V91 | `LocalSystem` fallback | Start the engine with the prototype token | The status and threat table say the engine is not least-privilege. G2 cannot pass without a written owner acceptance | A real deployment |
| V92 | `fake_engine` automatic stop | Write a final frame with `cleanup=ok` and `stop=source_device_gone`, then exit | The service records a normal stop, keeps the session, keeps Start enabled, and does not set the latch. It does not report `engine_lost` | A real automatic stop |
| V93 | `fake_engine` crash | Exit with no final frame | After the 2 second drain the service reports `engine_lost`, `cleanup=unknown`, and disables Start until `recheck`. It does not call `TerminateProcess` | A real crash |
| V94 | `fake_service_host` with a live app session | Send SCM stop while the app pipe is live | One stop path runs. The record says `service_stop`, not `parent_lost`. No second stop and no relaunch | A real SCM stop |
| V95 | `fake_service_host` with a hung engine | Send SCM stop | The service returns within the wait hint, records `cleanup=pending`, and leaves the engine alive. A later start is refused | The real SCM timeout |
| V96 | Windows VM, unknown link, fake or real source probe | Run the service monitor with no link observer | Unknown link does not produce `hotspot_lost`. A silent probe stops at 90 s with `source_device_gone`. An unavailable probe clears the interval | A real hotspot and a real source device |
| V97 | Console host with the exact SDDL, interactive user | Open the pipe with `0x00120183`; with `GENERIC_READ \| GENERIC_WRITE`; with the chosen framework constructor; then call `CreateNamedPipeW` for a second instance as the user | The exact mask opens. The generic request is denied with `ERROR_ACCESS_DENIED`. The framework path opens only if it passes the exact mask. The second instance is denied. | An installed service. R19. |
| V98 | Console host and fake engine monitor, fake probe on loopback | Make the identity unreadable for 300 s; alternate silent and unavailable; sleep and resume the VM during an interval | `observation_unavailable` at 300 s; no loss reason; status follows S38. Record whether the monotonic clock counted the sleep. | A real hotspot. L06. |
| V99 | Windows VM, fake neighbor and WLAN readers | Record guard values, then change the gateway MAC; make the WLAN read fail; restore | A change clears the credential with `link_changed`. A failed read is `unknown` and blocks nothing. No guard value appears in any output. | Real WLAN reads and location policy. R22. |
| V100 | Fake Wintun API that records the requested GUID | Run two intents and crash each before the identity report | Each intent has a fresh `guid_planned`. A live adapter with the planned GUID is `Present`, never `Clean`. No adapter and `routes_may_exist=0` is `Clean` for the route scope only. | Real Wintun behavior and profile count. R23. |
| V101 | Fake engine with call tracing | Start the engine, withhold `go` | No Wintun, socket, probe, or route call is traced before `go`. The engine exits after 10 s with no final frame. | The real engine. A later engine test. |
| V102 | Console host and fake engine | Kill the console host after `CreateProcess` and before the PID write, and again after the PID write | The gated engine exits on parent loss in both cases. The next host start applies the `launching` and `launched` recovery rows. | An installed service crash. |
| V103 | Console host as `SYSTEM` through a test harness, user-token copy of the engine image | Leave a `launching` record, run a copy of the image as the interactive user, then start | The copy is recorded as `foreign_engine_image`, receives no frame, and does not block the start after the clean check. | An administrator-created `SYSTEM` copy. Out of scope. |
| V104 | Console host with the SCM control handler driven by a test harness | Send stop with a hung fake engine; send preshutdown; send shutdown after preshutdown | Checkpoints advance once per second inside bounded steps. Total stays within 20 s. The record says `pending` for the hung engine. Shutdown does not wait. | The real SCM. R24. |
| V105 | Console host, two sessions simulated through the harness | Deliver logoff for another session, lock, disconnect, then logoff for the controlling session, with and without a pipe break first | Only the controlling logoff or the pipe break stops. Exactly one stop runs. The reason is the first event. | Real session notifications. R24. |
| V106 | Console host and fake engine | Break the event pipe before the final frame; delay the frame past the drain | `cleanup=unknown`, never `failed`, and no latch. A clean `recheck` clears it without the override. | A real crash. |
| V107 | Console host, real pipe | Connect as the interactive user, send a first frame, then let the host impersonate | Impersonation before the first read fails with `ERROR_CANNOT_IMPERSONATE`, or the order is documented otherwise. After the read, `OpenThreadToken` with `OpenAsSelf` succeeds at identification level and `TokenUser` and `TokenSessionId` are correct. `RevertToSelf` runs on every path. | An installed `LocalSystem` service. R25. |
| V108 | Console host, real pipe | Connect, exit the client, start an unrelated process to reuse the PID if possible, then let the host check | The decision uses the connection token. A reused PID does not change it. | That PID reuse occurs on demand. |

## 5. Tier R: SCM and install, administrator, disposable VM

Requires the device owner's approval. Not run for this design.

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| R01 | Disposable Windows VM | Install | Demand start, `LocalSystem`, no arguments, `SC_ACTION_NONE`, a security descriptor that grants the person start and stop | A real user profile |
| R02 | Standard user | Start, query, stop | Allowed. Create and delete are refused | Domain policy |
| R03 | Uninstall | Remove | Service deleted. The credential file is removed only after the service is stopped | An installer rollback |
| R04 | Running engine | SCM stop | `SERVICE_STOP_PENDING`, then `SERVICE_STOPPED` after the engine exits. The wait hint is accepted by the host | A hung engine on a real host |
| R05 | Kill the service process | Wait | The SCM does not restart it. The engine sees the parent pipe close | A configured recovery policy on a managed machine |
| R06 | Reboot after install | Log in | The service is not running. No tunnel starts | Fast startup behavior |
| R07 | Phase 2 credential file | Inspect ACL and backup attribute | `SYSTEM` only, no backup | An offline disk attack |
| R08 | Pre-created `ProgramData` directory | Run the real installer | The installer refuses the user-owned directory and does not write into it | A redirected junction on a real disk |
| R09 | Installed `ProgramData` directory | Inspect owner, DACL, and reparse state | Owner `SYSTEM` or `Administrators`, protected DACL, no non-administrator write or create-child, no reparse point | A backup operator |
| R10 | Real SCM shutdown and preshutdown | Shut down the VM | The service writes the state record and returns within the wait hint | Every OEM power path |
| R11 | Standard user elevates with administrator credentials | Install | The installing person SID is the interactive user, not the administrator. The service starts and stops for the interactive user | Domain policy and credential provider variation |
| R12 | Installed service | Run the app server checks | First-instance flag, SCM PID, pipe owner from the real `GetSecurityInfo` call, and installed path all pass. No service token is opened | A compromised service binary |
| R13 | A second non-administrator local account, created by the VM owner | Connect to the pipe | Denied, closed, no reply. The service records a fixed event | Domain policy and a real managed desktop |
| R14 | An elevated process of the configured account | Connect and control the tunnel | Allowed. The event log records `elevated_caller`. No authorization decision depends on elevation | A real UAC split-token logon |
| R15 | Installed layout | Inspect the engine, probe helper, and service paths | All three are under `%ProgramFiles%\HotspotShade`, not a developer registration folder, and no path component is a reparse point. A loose-file or developer registration layout is refused for real mode | Every installer and every Windows version |
| R16 | Installed service as the interactive user | Run the app server proof, including `QueryServiceConfig` | The service descriptor grants `SERVICE_QUERY_CONFIG`, `SERVICE_QUERY_STATUS`, `SERVICE_START`, `SERVICE_STOP`, and `SERVICE_INTERROGATE`. The path read succeeds. Removing the query-config right makes the app fail closed | A different domain policy |
| R17 | Installed pipe DACL | Attempt a later pipe instance as the interactive user, then as an administrator | The user create is denied. The administrator create succeeds at the kernel but the app's SCM PID check rejects it. No frame is sent | An administrator who replaces the service |
| R18 | Real SCM stop and shutdown | Measure the wait hint and the stop path | The service returns within the host's stop timeout with a record. If the host timeout is shorter than 12 seconds, the design is recorded as not viable | Every OEM power path |
| R19 | Installed service with the exact pipe DACL | Repeat V97 against the installed service, as the interactive user and as an administrator | The user opens with the exact mask only, and cannot create an instance. The administrator create succeeds at the kernel and fails the app server check. | A live tunnel. |
| R20 | Disposable VM, administrator, Wintun from the official source, owner approval. Wintun exception: an adapter may be created. No route is ever created. | Service-shaped harness creates an adapter. A restricted-token child tries `WintunOpenAdapter` and `WintunStartSession`. Separately, measure a service-side frame pump to a restricted child. | Records whether option A is possible, and the pump's added latency and throughput cost for option B. Removes the adapter and verifies its absence. | A live tunnel or carrier traffic. |
| R21 | Disposable VM, administrator, owner approval. No adapter. | A restricted-token child created as in architecture section 4.6.2 opens outer sockets, sets `IP_TTL` 65, `IP_UNICAST_IF`, and `IPV6_UNICAST_IF`, and reads the TTL back to a loopback or VM-local peer | Records each result. `ttl_bad == 0` if all succeed. Any failure blocks options A and B and the restricted probe helper. | A hotspot path. |
| R22 | Windows host with a Wi-Fi adapter joined to a test access point, owner approval. No tunnel. | Read SSID, BSSID, and the gateway neighbor entry from a `LocalSystem` service with location on and off | Records which values are readable and what a refusal looks like. | Spoof resistance. There is none. |
| R23 | Disposable VM, administrator, owner approval. Wintun exception: an adapter may be created. No route. | Create adapters with two requested GUIDs in turn and remove them. Count network profiles before and after. | Records whether Wintun honors the requested GUID and how many profiles remain. Removes every adapter it created. | Behavior across Windows versions not tested. |
| R24 | Installed service on a disposable VM, owner approval | Stop, restart the VM, shut it down, and log off the controlling and another session, with a hung fake engine in one run | Records the preshutdown timeout honored, the checkpoint handling, and the logoff filter. The record is written in every run. | A real engine cleanup. |
| R25 | Installed service | Repeat V107 against the `LocalSystem` service | Same assertions as V107 with the real service token. | A live tunnel. |

## 6. Tier L: live, not approved

These are listed so nobody confuses a VM pass with a tunnel result. None may run
without the device owner's approval, a real hotspot, and an administrator
session. They are not designed here.

| ID | What it would show | Why it is not in this plan |
|---|---|---|
| L01 | A real tunnel start and stop with `ttl_bad == 0` | Needs a real source device and a hotspot |
| L02 | Hotspot link loss alone does not stop the Windows tunnel, and the app makes no hotspot-loss claim | Needs a real link change. This row records the absence of a claim, not a stop feature |
| L03 | Source device silence stops the tunnel with `source_device_gone` | Needs a real source device |
| L04 | An engine crash leaves routes and `recheck` finds them | Needs a real crash and a real route table |
| L05 | Reboot after a crash leaves no owned routes | Needs a real reboot |
| L06 | A real run with a long unreadable identity stops with `observation_unavailable` and no loss or pairing claim | Needs a real hotspot and a real identity fault. O23 must be decided first. |
| L07 | Hotspot BSSID or gateway MAC behavior across hotspot restarts on real iOS and Android source devices | Needs real source devices. It measures how often the guard forces a re-entry. It cannot show identity. |

A VM pass, a fake engine, a console service host, or a demo mode does not prove
any part of tier L.

## 7. CI proposal

| Job | Runner | Runs | Does not run | Gate |
|---|---|---|---|---|
| `windows-service-contract` | `windows-2025` with the supported .NET runtime | Tier H through the existing test runner | Tier V, R, L | Required after approval |
| `windows-service-vm` | `windows-2025` | Tier V, unprivileged, with the console service host | SCM install, routes, Wintun, live tunnel | Required after approval |
| `windows-service-scm` | Disposable Windows VM or a self hosted runner | Tier R | Routes, Wintun, live tunnel | Owner approval per run |
| `rust-windows` | `windows-latest` | Tier T compile and the hermetic parts | A real pipe, process, or route | Existing job, extended |

The existing `winui-demo` job keeps running the current tests. It must not be
changed to install a service. A failed job blocks only its own tier.

S26 adds a check that no new project targets .NET 8 and that the CI image
provides the chosen runtime. The broker's existing `net8.0` target is recorded
as a prerequisite, not silently accepted.

## 8. What this matrix does not prove

- No test here proves a Windows tunnel.
- No test here proves carrier, source device, or hotspot behavior.
- No test here proves that the SCM accepts the install configuration.
- No test here proves that the route absence proof matches the live table.
- No test here proves that the live `relay.tcp_flows_active` gauge is exact for
  a half-closed or reset flow; T3.14 and T3.17 test the pure and loopback cases.
- No test here proves that the source device connection count is accurate or
  fresh on a real source device. V45 uses a fake source status.
- No test here proves that a pipe name cannot be taken before the service. It
  proves the service fails closed and the app refuses it. It does not prove the
  later-instance DACL until V89 and R17.
- No test here proves that a post-exit port takeover receives no usable bearer.
  V12 and a Windows host are needed.
- No test here proves that the UWP app service bridge checks the caller package
  family and accepts one peer. S29 and V75 use fakes.
- No test here proves that developer registration and a reparse-point install
  path are refused. S30, V76, and R15 are needed.
- No test here proves that no secret copy exists in memory. It proves the
  project's own paths hold one and clear it.
- No test here proves or disproves the UWP suspension hypothesis. That needs a
  UWP host build and a Windows check.
- No test here proves that the WinUI 2 XAML Islands host builds or that it
  survives suspension.
- No test here proves that a standard user cannot pre-create the `ProgramData`
  directory on every Windows version. R08 and R09 test the install contract on a
  disposable VM.
- No test here proves hypothesis H1, whether the Wintun adapter survives a
  crash. L04 and a disposable VM crash test are needed.
- No test here proves hypothesis H2, sleep and resume on a real host. V73 is a
  simulation.
- No test here proves hypothesis H3, the physical gateway check on a live route
  table. V65 uses a fake table.
- No test here proves the Windows hotspot link observer exists. It does not.
- No test here proves that the Windows CLI and GUI source-silence paths behave
  the same. They do not today. T3.20 and T3.21 record both shapes.
- No test here proves B2's route-scope `Clean` on a real adapter table. V80 to
  V83 use fakes.
- No test here proves B3's no-adoption rule against a real same-image process.
  S32 and V84 are the first check.
- No test here proves B4's real service descriptor. R16 is needed.
- No test here proves B5's stopped status on a real app. V86 uses a fake host.
- No test here proves review H1's same-IP limitation on a real hotspot swap. V88
  records the limitation, not a detector.
- No test here proves review H2's exact DACL. R17 is needed.
- No test here proves review H3's restricted engine. V90 uses a fake adapter.
- No test here proves review H4's classification on a real service crash. V92
  and V93 use a fake engine.
- No test here proves that the exact pipe mask works with an installed service
  until R19 runs.
- No test here proves the O23 value. T3.23 and V98 prove the rule, not the
  number.
- No test here proves that a restricted token can use Wintun or the socket
  options. R20 and R21 are spikes that need owner approval.
- No test here proves that a guard value identifies a hotspot. It cannot.
- No test here proves the launch gate in the real engine. V101 uses a fake
  engine.
- No test here proves session logoff behavior on a real desktop until R24.
- No test here proves impersonation with the real `LocalSystem` token until R25.

## 9. Traceable adversarial matrix (fourth review)

Each row names the review finding, the adversarial or failure scenario, the
design control, the residual risk, the first test that can check it, and the gate
that cannot pass without it. A test id is a plan, not a result. No row is closed.

| Finding | Scenario | Design control | Residual risk | Test | Gate |
|---|---|---|---|---|---|
| B1 | Windows service monitor sees an unknown link while the source device is silent | Three-state link evidence. `Unknown` never becomes `hotspot_lost` and never clears the source-silence interval. An unrun probe is `Unavailable` and clears it. | The GUI gap remains; there is no link-loss stop. | T3.20, T3.21, T3.22, V96 | G4 |
| B2 | Service crashes before the adapter LUID and GUID are recorded | Planned exact name, `routes_may_exist=0`, identity handshake before routes, exact-name identity read, service-owned adapter as the preferred direction | A present adapter with unreadable identity is inconclusive; the split is unproven. | V80 to V83, V90 | G4 |
| B3 | Same-user process runs the installed engine image to match an orphan search | No image-path adoption. An `orphan_candidate` blocks a start and receives no frame. Adoption needs a nonce proof and is unapproved. | A same-image process can deny service. | S32, V84, V85 | G4 |
| B4 | App calls `QueryServiceConfig` without `SERVICE_QUERY_CONFIG` | The service descriptor and the app open rights grant query configuration. Access denied is `boundary_auth_failed`. | Descriptor drift; the app fails closed. | S33, R16 | G2 |
| B5 | A stopped tunnel still has a stale nonzero relay gauge | No live engine means both counts empty and both known flags 0. Zero requires `running=1`, a fresh status, and `known=1`. | A stale cached sample is bounded by freshness and generation checks. | S34, V86 | G3 |
| Review H1 | A different hotspot reuses the same gateway IP and the same interface identity | Phase 1 binds to LUID or GUID plus gateway and states that same-IP same-identity cannot be told apart. Phase 2 identity is the only binding. | The phase 1 token can reach the wrong source device after a person action. Memory-only bounds it. | V87, V88 | G2 |
| Review H2 | Same-user process tries to create a later pipe instance | DACL omits `FILE_CREATE_PIPE_INSTANCE`. The SCM PID check remains defense in depth. | An administrator can create one; administrators are out of scope. | V89, R17 | G2 |
| Review H3 | Malicious inner packet reaches the engine parser | The design records the `LocalSystem` exposure, recommends a split control and data plane, and blocks real mode until the split is proven or the owner accepts the risk. | A data-plane defect can still compromise the process. | S35, V90, V91 | G2 |
| Review H4 | A normal automatic stop exits the engine, and a crash does the same without a frame | Final frame with stop reason, 2 second event drain, `cleanup=unknown` when no frame. A normal stop does not set the latch. | A torn or lost frame is unknown and can require `recheck`. | V92, V93, T3.18 | G4 |
| Session and SCM | App loss, timeout, and SCM stop overlap | One stop path wins. SCM stop beats a pipe break. 12 second cleanup, 2 second drain, 20 second hint. No timeout starts anything. | A host with a shorter SCM timeout is not viable; G1 must measure it. | V94, V95, R18 | G4 |

Revision 4 note: the B3 control above is superseded by E7 in section 10. An
image-path match no longer blocks by itself. The row is kept as history.

A finding moves from open to closed only when its test exists, passes on the
named tier, and a reviewer records the result. A design row is not evidence.

## 10. Traceable adversarial matrix (fifth review)

Review id `e1b9ed6a-3041-4221-873f-3a406392400b`. Same rules as section 9. A
test id is a plan, not a result. No row is closed. Owner decisions are marked.

| Finding | Scenario | Design control | Residual risk | Test | Gate |
|---|---|---|---|---|---|
| E1 | A same-user client asks for `GENERIC_WRITE`, which carries `FILE_CREATE_PIPE_INSTANCE`, or a developer widens the ACE to make a framework open work | Exact SDDL with the user mask `0x00120183`; the app requests exactly that mask; a denied open is `boundary_auth_failed` | A future edit widens one constant. Both live in one reviewed place. | S37, V97, R19 | G2 |
| E2 | The identity stays unreadable, or silent and unavailable samples alternate, so the silence timer never completes | Unsupervised interval of 300 s since the last `Accepted` answer, reason `observation_unavailable`; Windows `Unknown` link ignored; no loss or pairing claim | The value trades availability against invariant 13. Owner decision O23. Not implemented. | T3.23, V98, S38, L06 | G3, G4 |
| E3 | A crafted packet or a crafted gateway reply reaches the engine or the probe helper while they run as `LocalSystem` | Options A, B, C in O2b; the restricted probe helper after R21; a written owner acceptance for anything that stays privileged | If R20 and R21 fail, the exposure stays, under the owner's signature. | S35, S46, V90, V91, R20, R21 | G2 |
| E4 | A different hotspot reuses the gateway address and interface, and copies or hides the SSID, BSSID, and gateway MAC | Guard values compared when readable; a change clears the credential; a match is never identity; phase 2 is the only identity | A spoofer passes phase 1. Guard values may be unreadable. | S39, V99, R22, L07 | G2 |
| E5 | A crash leaves an adapter that an earlier intent also could have created | Fresh `guid_planned` per intent as the requested Wintun GUID; a match is `Present` or `Inconclusive`, never `Clean` | Network profiles may accumulate. O19 sub-decision. | V100, R23 | G4 |
| E6 | The service crashes between `CreateProcess` and the PID record | Launch gate: no effect before `go`; `go` only after the durable PID record; the engine exits on parent loss | A gate defect in the engine. V101 checks it. | S43, V101, V102 | G4 |
| E7 | A same-user process runs a copy of the engine image to block every start | Orphan rule: block only on the recorded PID and creation time, or on a `SYSTEM`-token candidate inside the launch window for at most 12 s | A process whose token cannot be read is recorded and does not block. An administrator can still interfere, out of scope. | S44, V103 | G4 |
| E8 | Shutdown, a slow stop, or a logoff ends the service before the record is written, or another account's logoff stops this tunnel | Preshutdown with an explicit 20 s timeout, checkpoints inside bounded steps, a non-waiting shutdown fallback, logoff filter on `TokenSessionId` | Shutdown can be delayed up to 20 s. Fast user switching leaves machine-wide routes in place. Owner decision O25. | S40, V104, V105, R24 | G4 |
| E9 | The engine cannot write its final frame because the service is gone | Cleanup before the write; a 1 s best-effort write; a missing frame is `cleanup=unknown`, not `failed` | A clean stop without a frame needs `recheck`. | T3.24, V106, S41 | G4 |
| E10 | A client exits after connecting and its PID is reused by another process | Caller identity from the connection token by impersonation after one unparsed read; `RevertToSelf` on every path; PID diagnostics only | One unauthenticated bounded read per connection, limited to processes that pass the DACL. | S42, V107, V108, R25 | G2 |
| E11 | A document cites the GUI auto-stop as fixed or as the service model | Every citation says uncommitted and unverified; the service monitor has its own contract | The GUI change may land differently. Citations must be rechecked at G3. | S45, T3.21, V96 | G3 |
