# Windows privileged engine service architecture

Status: **UNAPPROVED**. Revision 4. Design only. This file describes a design
that has not been approved by an independent reviewer, has not been implemented,
and has not run on a Windows host. Revision 4 answers the fifth independent
review, id `e1b9ed6a-3041-4221-873f-3a406392400b`. The task record for that id
was not reachable; the review content was supplied with the revision task. It
also keeps the revision 3 answers to the fourth review, id
`c0b94fca-d9ea-4d4f-8aa8-87de7c508503`, and the revision 2 answers to the
earlier reviews. Every document in this directory stays UNAPPROVED. Real mode
stays behind G1 to G6. No implementation is approved.

Windows 10 and Windows 11 are the target family. This design does not claim a
minimum build, an architecture list, or a live tunnel. The WinUI 2 host spike
and a Windows host must record those before any real-mode claim.

Related: `README.md` (scope and reading rules), `REVIEW_RESPONSE.md` (finding by
finding answer), `TEST_MATRIX.md` (test plan), `OPEN_DECISIONS_AND_REVIEW_GATES.md`
(decisions and gates).

## 0. One page summary

The Windows target device needs three processes, not two.

1. The **app** (`HotspotShade.exe`), a WinUI 2 desktop app with a full-trust
   desktop host, per user. It shows state and takes person actions. It holds no
   long-lived secret, no bearer, and no stored credential. In phase 1 manual
   entry it holds the typed token in memory only until `credential.set`
   completes.
2. The **engine service** (`HotspotShadeEngineSvc.exe`), a Win32 service. It is
   installed once with administrator consent. It runs as `LocalSystem` by
   default. It holds the engine bearer secret and, while a session runs, the
   source device credential in memory. It is the only process that may start
   the engine.
3. The **engine** (`hotspotshade.exe`), a child of the service. It owns the
   Wintun adapter, the routes, the relay, the inner TCP stack, and the source
   silence monitor. It is started once per explicit person action and never
   restarted by the service.

The app talks to the service over one authenticated named pipe. The service
talks to the engine over inherited handles, not a TCP port. The bearer secret
travels on an inherited pipe, never on a command line. The engine binds no
loopback port in service mode. That removes the port squatting class instead of
mitigating it.

The pipe is a boundary between *accounts and remote clients*, not between
processes of one account. Any process running as the signed-in person can pass
the pipe DACL and the caller identity check. It can start and stop the tunnel,
set or forget the in-memory credential, and hold the single session. It cannot
read the bearer, the credential, or the identity key. This is the honest
same-user threat. `REVIEW_RESPONSE.md` and the threat table record it. A design
that claimed to block same-user processes would be false.

The service is demand started, stops itself when the app is gone and the engine
has exited, and has no recovery actions. A lost app session or a lost engine
stops the tunnel. Windows has no enabled hotspot link observer. On Windows, a
hotspot link loss must not be claimed as a stop. The source-silence path needs
care, because the CLI and GUI have different evidence contracts:

- The Windows CLI `tun` branch in `rust/src/main.rs` passes `|| Some(true)` as
  the link closure, so its source-silence monitor can run and stop after 90
  seconds of silence when a physical hotspot interface resolves. If the
  interface is missing or invalid, the CLI warns and auto-stop is off.
- A GUI fix is now in progress in the working tree. It adds a platform link
  capability, treats an unobservable Windows link as `Unknown` rather than
  `Up`, and lets a fresh silent source probe stop after 90 seconds without
  claiming hotspot loss. The change is uncommitted and unverified. It does not
  implement the bounded unavailable interval in O23. This design records the
  change as in progress and does not use it as evidence.
- The service engine monitor must use its own explicit three-state contract:
  an unknown link is not link loss, but it must not erase the source-silence
  interval. A probe that cannot run is no evidence and clears the silence
  interval. This design does not claim that the monitor is implemented.
- Continuous unknown or unavailable evidence is not proof of loss. It cannot
  run forever either. Revision 4 proposes a bounded stop after 300 seconds with
  no usable link or source evidence, reason `observation_unavailable`. It is
  proposed, not implemented, and is decision O23. It preserves invariant 13 by
  refusing a persistent proxy with no supervision. It must not be described as
  `hotspot_lost` or `source_device_gone`.

No source device credential is stored at rest before phase 2 pairing. Phase 1
manual entry is memory only and is cleared on stop, app loss, engine loss,
gateway or link-identity change, and service stop. A DPAPI file is not part of
phase 1.

No remote relay, VPS, or VPN is added. The source device NAT remains the
terminator. The engine runs source device proxy mode only. The engine and the
probe helper parse untrusted input while the prototype runs them as
`LocalSystem`; that exposure is recorded in section 14 and is a real-mode gate
item, not a solved problem. The split in section 4.6 is feasible only if the
real Wintun privilege spike passes. Otherwise G2 needs a written owner
acceptance.

## 1. Claim labels

- **Verified in this tree**: read from a named file and function in this
  checkout at the time of revision 2. Line numbers move, so functions are named.
- **Standard**: documented Windows or Win32 behavior. Not a project claim.
- **Hypothesis**: needs a build, test, or Windows host. Every one has a test id.
- **Open**: an undecided item. See `OPEN_DECISIONS_AND_REVIEW_GATES.md`.

A design answer closes a design question. It does not close an implementation
test.

Review ids and hypothesis ids can collide. The fourth review uses B1 to B5 and
H1 to H4. The fifth review is referenced as E1 to E11 in this document. The
architecture already used hypothesis H1 for adapter survival, H2 for sleep, and
H3 for the physical gateway check. When the distinction matters, this file
writes "review H1" or "hypothesis H1". A bare H1 in section 8.5 is the
hypothesis. A bare H1 in section 14 is the review item.

## 2. What exists today

The broker in `windows/src/HotspotShade.WinUI2.Broker/` is dormant. The UWP app
does not reference it, the package declares no extension, and CI compiles it
without running it. That is accurate and it does not change here.

Verified facts that shape the design:

| Fact | Evidence |
|---|---|
| The broker manifest is `asInvoker`, so the broker running as the signed-in person cannot elevate. | `windows/src/HotspotShade.WinUI2.Broker/app.manifest`, `requestedExecutionLevel level="asInvoker"`. |
| The broker opens the app service with its own package family. | `windows/src/HotspotShade.WinUI2.Broker/AppServiceBrokerTransport.cs`, `Package.Current.Id.FamilyName`. |
| The UWP package declares no app service extension and no capability. | `windows/src/HotspotShade.WinUI2/Package.appxmanifest`; S05. The broker fragment is not merged. |
| There is no production bundle. The broker is in the solution but the preview app does not reference it. | `Package.broker.fragment.xml` is inactive and says so. |
| The launch path refuses a non elevated process. | `Win32EngineHost.cs`, `IsElevated` and the `AdminRequired` result. |
| The broker assumes the secret holder is the elevated parent. | `BrokerRuntime.cs` comment and the same-process launch model. |
| The loopback port is chosen before the engine runs, with no retry. | `EngineBrokerService.cs`, one value in 49152-65535. |
| The engine binds loopback with a plain `TcpListener::bind`. | `rust/src/gui.rs`, `run_gui` bind path. No exclusive-address option. |
| The endpoint check is only "a process handle exists". | `Win32EngineHost.cs`, `TryGetEndpoint`. |
| Nothing waits on the engine process. | No process wait except inside the close path, `Win32EngineHost.cs`. |
| A failed launch closes the host permanently. | `Win32EngineHost.cs` `closed = true`; `EngineStartup.cs` closes the host on every failed launch; `RetryAsync` then returns `Closed`. |
| The close path gives up after 8 seconds and closes the handle. | `Win32EngineHost.cs`, close path. |
| The engine's HTTP error body carries no machine code. | `rust/src/gui.rs`, `error()` emits `{"ok":false,"error":...}` only. |
| Some start errors already have fixed codes. | `rust/src/gui_backend_windows.rs`, `start_error`; `rust/src/gui.rs`, `phone_token_rejected`. |
| `cleanup_blocked` is returned as a generic `service_start`. | `rust/src/service.rs`, `start_socks` uses `io::Error::other("route cleanup failed...")`, which `start_error` maps to `service_start`. |
| The Windows engine reports no `paired` field and a null source device connection count. | `rust/src/gui_backend_windows.rs`, status path. |
| A running status with an unknown count becomes `BadResponse`. | `windows/src/HotspotShade.WinUI2.Core/Engine/EngineLocal.cs`. |
| A stopped status has no live engine sample, so a target-side flow gauge cannot be a confirmed zero. | `rust/src/relay.rs` exposes a live atomic gauge; it is meaningful only while the engine runs. A stopped status must publish unknown, not `0`. This is the B5 correction. |
| The Windows service security descriptor described in revision 2 did not grant `SERVICE_QUERY_CONFIG`, although the app proof calls `QueryServiceConfig`. | Revision 2 section 5.4 step 5 and section 4.5 step 6. The right is added in revision 3; the existing preview does not exercise it. |
| The GUI auto-stop code is being revised in the working tree. It adds `LinkWatch`, treats an unobservable Windows link as `Unknown`, and can stop after 90 seconds of fresh silent source probes. | `rust/src/gui.rs`, `auto_stop_sample_watch`, `LinkWatch::Unobservable`; uncommitted at revision 4. It does not implement a bounded unavailable interval. This is in progress, not evidence. |
| A named pipe's `GENERIC_WRITE` mapping includes the `0x4` bit, which is `FILE_CREATE_PIPE_INSTANCE` on a pipe. | Windows access-mask mapping. `GRGW` in SDDL and `GENERIC_READ \| GENERIC_WRITE` on `CreateFileW` therefore request the create-instance right. The exact masks in section 5.2 avoid both. This is standard behavior, to be proven at R19. |
| The readiness signal on Windows is a stdout line and a port file that Windows does not support. | `rust/src/main.rs`, `write_gui_port` returns `Unsupported`. |
| The Windows presence loop sends the cleartext SOCKS token to the stored target every 2 seconds while it runs. | `rust/src/gui_backend_windows.rs`, `start_presence`, `PROBE_INTERVAL`. |
| On Windows the GUI link observation is unknown, not up. | `rust/src/autostop.rs`, `link_observation` returns `Unsupported` on Windows; `observe_link` turns that into `None`. |
| The old GUI auto-stop policy reset on an unknown link. | `rust/src/gui.rs`, old `auto_stop_sample`, `None => { policy.reset(); return None; }`. A GUI fix is now in progress that adds `LinkWatch::Unobservable` and stops after 90 seconds of fresh silent probes. The fix is uncommitted and unverified; it is not a service monitor and not a bounded unavailable stop. |
| The Windows CLI `tun` path supplies a positive link closure, so its source-silence timer can run. | `rust/src/main.rs`, Windows `tun` branch, `auto_stop_wait(..., || Some(true), ...)`. It runs a probe and can stop with `source_device_gone`. It does not prove hotspot loss. |
| The engine's automatic stop policy is 20 seconds of link loss or 90 seconds of source device silence. | `rust/src/autostop.rs`, `LINK_DOWN_LIMIT`, `SOURCE_DEVICE_GONE_LIMIT`. |
| The Windows backend has no enabled hotspot link observer. | `rust/src/autostop.rs` Windows `link_observation` returns an unsupported error; the name is retained but no observer is enabled. It must not be described as a hotspot-loss feature. |
| The Windows CLI and GUI auto-stop paths are converging, but the service monitor is still a separate contract. | `rust/src/main.rs` Windows `tun` branch versus the in-progress `rust/src/gui.rs` `LinkWatch` change. The service monitor must not copy either path without the O20 and O23 review. |
| A continuous missing or stale probe can leave a running tunnel with no usable supervision. | The in-progress GUI resets on a stale, missing, or `no_hotspot` probe. Source silence needs fresh silent probes. Revision 4 proposes O23 as the bounded fix. It is not implemented. |
| `read_gui_token` and `watch_parent_handle` now check `GetFileType == FILE_TYPE_PIPE` and clear `HANDLE_FLAG_INHERIT`. | `rust/src/main.rs`, `seal_windows_control_handle`, used by both readers. This does not yet cover the new control and event handles. |
| A live target-side TCP gauge already exists, but is not exported. | `rust/src/relay.rs`, `tcp_flows_active` at the atomic counters and the flow close sites. It is not the source device connection count. |
| `privileged.rs` framing is a 4 byte big-endian length and a 256 KiB cap, and the module is Unix only. | `rust/src/privileged.rs`, `receive`, `send`, `MAX_MESSAGE`, `#![cfg(unix)]`. |
| The Windows engine status already carries `ttl_bad`, `ipv6_dropped`, and `fragments_dropped`. | `rust/src/service.rs`, `tunnel_relay_stats`. |
| The broker targets `net8.0-windows10.0.19041.0`. .NET 8 support ends on 2026-11-10. | `windows/src/HotspotShade.WinUI2.Broker/HotspotShade.WinUI2.Broker.csproj`; Microsoft .NET support policy. |

Those facts produce the four blockers from the first review, the additional
blockers from the second review, and the 82046682 conditions. This design
answers them in sections 2.1 and 4 through 12.

### 2.1 The 82046682 review

An independent review of the existing Windows broker (task 82046682) found the
preview path unreachable and listed the remaining conditions before any
production enablement. Revision 2 incorporates them as follows. None of them is
closed. Each needs the named evidence.

| Finding | Design consequence | Evidence |
|---|---|---|
| The current broker is `asInvoker` and `Win32EngineHost` returns `AdminRequired`, so the preview path cannot start a tunnel. | The preview is not a capability. Real mode moves to the installed service. The app host decision is O1. | S31, V02 |
| A loopback endpoint can be owned by a squatter, and the port can be taken over after the engine exits. | The primary design removes the port. The fallback requires `--port 0`, exclusive bind, a PID proof, an instance id, and a fresh endpoint proof for every generation. A cached endpoint is never reused after an engine exit. | V10, V12, V56 |
| The UWP app service must validate `AppServiceTriggerDetails.CallerPackageFamilyName` and allow one peer. | The primary design replaces the app service with the pipe. A UWP bridge, if ever used, must check the caller package family and accept one broker peer. A second peer is refused. | S29, V75 |
| Loose-file developer registration can place the broker and engine outside a trusted install root. | Real mode is a per-machine MSI install under `%ProgramFiles%`. Developer registration and an unpackaged layout are preview-only. The engine path is opened with reparse checks and must resolve under the install root. | S30, V76, R15 |
| The broker must detect process exit and a stop timeout, and it must prevent a second engine. | The state record, launch intent, process wait, 12 second cleanup wait, latch, and image-path observation without adoption are the controls. No `TerminateProcess`. | V20 to V24, V53, V54, V67, V68, V84 |
| UWP suspension can stop the real-mode session. | The primary host is a full-trust WinUI 2 desktop app. The UWP app stays the labeled preview. A bridge inherits the suspension stop for the app session. | V30, V30b, V77 |
| The current status schema and source token provisioning are not the new contract. | Section 11 defines a fixed schema, `ttl_bad`, separate source and relay counts, fresh-only source counts, manual phase 1 credential provisioning, and phase 2 pairing. | S18, S19, S25, V43, V45, V62, V63, V64 |
| Retry behavior is implicit and can leave a dead host. | Section 9 defines generations, one launch per 2 seconds, late-result discard, and explicit retry only from a person action. | S07 to S09, V22, V23 |
| There is no Windows runtime evidence. | The design claims no Windows host result. Tier V and R must run on a Windows VM before production enablement. | Tier V, tier R |

### 2.2 The fourth review (B1 to B5, H1 to H4)

Review id `c0b94fca-d9ea-4d4f-8aa8-87de7c508503`. The task record was not
reachable; the content supplied with the revision task is treated as the
complete review. It is a static read. Revision 3 answers each finding on paper.
No finding is closed. Revision 3 changes these areas:

| Finding | Revision 3 answer | Evidence still needed |
|---|---|---|
| B1: the Windows source-silence stop was described incorrectly. | The CLI and GUI paths are separated in section 0 and section 6.1. The service monitor gets an explicit link-evidence contract. Unknown link does not clear source silence; an unrun probe does. The design claims no general Windows auto-stop. | T3.20 for the CLI shape, T3.21 for the GUI gap, T3.22 for the service monitor, V96 for a Windows VM probe |
| B2: a crash record can lack the adapter LUID and GUID, so recovery is inconclusive. | Section 8.3 records the planned adapter name and a `routes_may_exist` gate. The preferred direction is service-owned adapter identity (section 4.6); the fallback is an engine identity handshake before the first route. | V80 to V83, V90, and a real crash on a disposable VM |
| B3: image-path orphan adoption can be spoofed. | Section 8.3 and section 8.7 stop adopting by image path. A matching process is observed and blocks. Adoption requires a per-launch nonce proof and is not approved. | S32, V84, V85 |
| B4: `SERVICE_QUERY_CONFIG` was missing from the service rights. | Section 4.5 step 6 and section 5.4 grant it and fail closed when it is absent. | S33, R16 |
| B5: a stopped status required a zero target-side gauge. | Section 11.1 and section 11.5 make both counts unknown when no live engine status exists. Zero is not invented. | S34, V86 |
| Review H1: the same gateway IP cannot identify a different hotspot. | Section 11.4 binds phase 1 to the interface LUID or GUID plus the gateway, and states that two hotspots that reuse both are indistinguishable before phase 2. | V87, V88 |
| Review H2: a later pipe instance needs `FILE_CREATE_PIPE_INSTANCE`. | Section 5.2 does not grant that right to the interactive user. A later user instance is denied; the SCM PID check remains defense in depth. | V89, R17 |
| Review H3: the engine parses untrusted traffic as `LocalSystem`. | Section 4.6 and section 14 record the data-plane exposure, recommend a split control and data plane, and block real-mode approval until the split is proven or the owner accepts the risk. | S35, V90, V91 |
| Review H4: a normal automatic stop and a crash were not distinguished. | Section 8.8 and section 8.10 require a final frame with a stop reason, a bounded drain, and `cleanup=unknown` when the frame is missing. | V92, V93 |

The session and SCM timeout precedence is in section 8.10 and section 12. The
traceable adversarial matrix is in `TEST_MATRIX.md` section 9.

### 2.3 The fifth review (E1 to E11)

Review id `e1b9ed6a-3041-4221-873f-3a406392400b`. The task record was not
reachable; the content supplied with the revision task is treated as the
complete review. It is a static read. Revision 4 answers each finding on paper.
No finding is closed. No code was written.

| Finding | Revision 4 answer | Evidence still needed |
|---|---|---|
| E1: the pipe SDDL and client desired access were not exact. | Section 5.2 gives one exact SDDL string with a numeric user ACE, `0x120183`, and a bit-by-bit table. Section 5.4 opens the pipe with that same exact mask, not `GENERIC_READ \| GENERIC_WRITE`. The mask omits `0x4`, which is `FILE_CREATE_PIPE_INSTANCE` on a pipe. A client that asks for `GENERIC_WRITE` is denied by design, including a framework default constructor. | S37, V97, R19 |
| E2: continuous unknown or unavailable evidence had no bound. | Section 6.1 and O23 propose a 300 second bound on the time since the last positive source device answer, reason `observation_unavailable`. The constant Windows `Unknown` link never starts or resets it. An unreadable identity is never silence and never `source_device_gone`. Section 11 keeps the stop separate from pairing and loss claims. It is proposed, not implemented. | T3.23, V98, S38, and the O23 owner decision |
| E3: the restricted-token split was not shown feasible, and the probe helper was missing from the threat model. | Section 4.6 states why a Wintun session cannot move between processes, lists the three split options, and names the spikes R20 and R21. The probe helper is a second privileged parser of hotspot-side input, is in the threat table, and has its own restricted-token path that does not depend on Wintun. If a spike fails, G2 needs the written owner acceptance in O2b. | S35, S46, V90, V91, R20, R21 |
| E4: same-interface, same-gateway hotspots are common, and SSID/BSSID were dismissed too quickly. | Section 11.4 separates target-side link identity, hotspot-side guard values (gateway MAC, SSID, BSSID), and source device answers. Guard values are spoofable and a match is not identity. A change clears the credential. A phase 1 token acceptance is not identity either. Only a phase 2 authenticated answer identifies the source device. | S39, V99, R22 |
| E5: the pre-route adapter identity used an ambiguous planned GUID. | Section 8.3 uses a fresh random `guid_planned` per intent, passed to Wintun as the requested GUID and recorded before the adapter exists. It is an intent marker, not ownership proof. A planned GUID match is `Present` or `Inconclusive`, never `Clean`. The network profile cost of a fresh GUID is recorded in O19. | V100, R23 |
| E6: the suspended launch and PID phase was unresolved. | Section 8.3 compares `CREATE_SUSPENDED` with a launch gate and chooses the gate. The engine may not open Wintun, an outer socket, or a route API until the service has written the PID and creation time and sent `go`. A service crash at the gate leaves a process that exits by itself and holds no route. PID is not identity; the handle and creation time are. | S43, V101, V102 |
| E7: a same-user image-path orphan could deny service. | Section 8.7 blocks a start only for a recorded PID with a matching creation time, or for a `LocalSystem` process of the installed image created inside the recorded launch window, and the second case only for a bounded wait. A process of the installed image that runs under a user token is recorded and never blocks. | S44, V103 |
| E8: SCM preshutdown, checkpoints, and per-session logoff were too thin. | Section 8.6 adds `SERVICE_ACCEPT_PRESHUTDOWN`, an explicit 20 second `SERVICE_CONFIG_PRESHUTDOWN_INFO`, start and stop checkpoints, and a session logoff filter keyed to the session id read from the client token. Only the controlling session's logoff stops the tunnel, with `stop=session_logoff`. | S40, V104, V105, R24 |
| E9: a failed final frame on parent loss could look like a cleanup failure. | Sections 8.8 and 8.9 make the final-frame write bounded, best effort, and nonfatal. The engine finishes cleanup before it tries the write. A missing frame is `cleanup=unknown`, never `cleanup=failed`. | T3.24, V106, S41 |
| E10: caller authentication by PID has a reuse race. | Section 5.3 reads the first frame unparsed, then uses `ImpersonateNamedPipeClient`, `OpenThreadToken` with `OpenAsSelf`, `TokenUser` and `TokenSessionId`, then `RevertToSelf` before it parses anything. `GetNamedPipeClientProcessId` is diagnostics only. | S42, V107, V108, R25 |
| E11: the model, matrix, and status citations were behind the GUI fix. | Sections 0, 2, 6.1, 10, and 12 and the test matrix record the GUI fix as in progress and unverified. The service monitor keeps its own contract, and the O23 bound is not part of the GUI fix. | S45, T3.21, V96 |

Production enablement is not approved. The design is UNAPPROVED. The preview
path is unreachable, and no production path exists yet.

## 3. Goals and non-goals

Goals:

- One privileged owner for the engine, and one holder of the bearer secret.
- An app boundary that authorizes the caller by account identity and states
  plainly what a same-user process can do.
- An engine endpoint that a local squatter cannot impersonate and cannot
  receive the bearer.
- Descriptor handles with a bounded inheritance window and no inherited copies
  in grandchildren.
- Observed process liveness, a bounded stop, and no start that can overlap a
  previous cleanup, including after a service crash.
- Retry that is explicit, bounded, and safe. No automatic restart.
- A status and pairing contract where every displayed value is real or is
  clearly unknown, including TTL audit counters and recent failures.
- No source device credential at rest before authenticated pairing.

Non-goals:

- Windows direct mode. Windows stays source device proxy mode only.
- Live Windows tunnel verification.
- A signed package, installer UI, update path, or crash reporting.
- IPv6 policy changes. Source device proxy mode still forwards IPv6.
- Any change to the browser GUI, the relay, the inner TCP stack, or the
  normalization helpers.
- Any change to the macOS or Linux helper model.
- A Windows hotspot link observer.
- A remote relay, VPS, VPN hop, or cloud endpoint. The source device NAT is the
  terminator.
- A claim that phase 1 can identify a different hotspot that reuses the same
  gateway IP and interface identity.
- A claim that SSID, BSSID, or gateway MAC identifies a source device. They are
  an optional spoofable guard, not authentication.

## 4. Process model and privilege

### 4.1 Components

| Component | Identity | Lifetime | Holds |
|---|---|---|---|
| App | Signed-in person, medium integrity | Person opens it | No long-lived secret, no bearer, no stored credential, no engine handle, no route. In phase 1 it holds the typed token until `credential.set` completes. |
| Engine service | `LocalSystem` by default | Demand started, self stops when idle | Engine bearer, in-memory source device credential, engine process handle, cleanup latch, state record, and in the preferred split also the Wintun adapter and route ownership |
| Probe helper | `hotspotshade-probe.exe`. Prototype: service token (`LocalSystem`). Preferred: the restricted engine token in section 4.6, which does not depend on the Wintun spike. Neither is proven. | One short run per explicit `probe` | One typed source credential copy, no adapter, no route, no bearer |
| Engine | Service token (`LocalSystem`) in the prototype. A restricted service SID is the preferred target and is not proven. | One per explicit start | Prototype: Wintun adapter, routes, relay, in-memory credential use, source silence monitor. Target split: relay and source silence monitor only, over an adapter opened from the service. |

The prototype keeps the engine at `LocalSystem` because the Windows route and
adapter path needs an administrator token. That is the review H3 exposure, not a
least-privilege claim. Section 4.6 records the preferred split.

### 4.2 Why a service and not the broker

The first review's first blocker is that the broker cannot elevate and must not
be given the secret at medium integrity. A service solves both:

- Installation requires administrator consent once, at install time.
- The service token can create the Wintun adapter and change routes.
- The secret lives in a process that a medium integrity process cannot open.
- The SCM guarantees one instance of the service, which removes the need for
  a squattable single-instance mutex at the privileged layer.

The broker is not adapted. It is replaced. The transport free contract in
`windows/src/HotspotShade.WinUI2.Core/Engine/` is reused where it is still true:
`EngineProtocol`, `EngineWire`, `EngineStatus`, `EngineRules`, `EngineLaunch`.
The host and transport classes are replaced.

Runtime: the broker project targets .NET 8. .NET 8 support ends on 2026-11-10.
New service code must target a supported runtime. The recommended choice is
.NET 10 LTS, which is supported through November 2028. The existing broker
project stays as it is until implementation. Retargeting it is decision O15 and
a prerequisite for G1. A WinUI 2 XAML Islands host has its own framework
constraint; the host team must record the supported combination before code.


### 4.3 Service account

Default: `NT AUTHORITY\LocalSystem`.

Reason: the engine must create an adapter and change the IPv4 and IPv6 route
tables. Those operations need an administrator token. `LocalSystem` provides
that without a stored password and without a second account to manage.

Residual risk: the engine process then runs with full system rights, and its
control surface is the highest value target on the machine. The design reduces
that surface to one authenticated pipe with a fixed operation set and a fixed
redacted status schema. It does not eliminate the risk.

Alternatives and why they are not the default:

| Option | Why not the default |
|---|---|
| A virtual service account in `Administrators` | Grants a service identity permanent administrative group membership. This is broader than `LocalSystem` and adds a group to manage. |
| A dedicated local administrator account | Needs a stored password or a managed account. More moving parts than the prototype needs. |
| Delegate the interactive person's elevated token to the service | The person must pass UAC first. It narrows what the engine can touch, but it needs token duplication across the boundary and a UAC prompt that the product does not currently have. This is the strongest long term option and it is an open decision. |

`OPEN_DECISIONS_AND_REVIEW_GATES.md` records the decision as O2.

### 4.4 App host

The primary app host is a full-trust desktop app built with WinUI 2 controls in
a XAML Islands host. The current UWP app stays the labeled preview.

AGENTS.md says to use WinUI 2 for the Windows UI and to evaluate a UWP host and a
desktop host with legacy XAML Islands. Revision 1 offered "WinUI 3 or Win32" and
that conflicts with AGENTS.md. Revision 2 does not offer WinUI 3. A WinUI 3 host
would require an AGENTS.md change by the maintainer and is not part of this
design.

Reason the host must be full trust, and this is decisive rather than stylistic:

- The review found that an in-process app service connection closes when the
  UWP app is suspended, for example when the window is minimized. The broker's
  reaction is verified: `AppServiceBrokerTransport.cs` sets the stop signal, and
  the broker then stops the engine. The suspension trigger itself is a
  hypothesis that needs a Windows host check. If it holds, the tunnel stops on
  minimize.
- UWP has no tray icon and no reliable long lived background execution. An
  `ExtendedExecutionSession` with reason `Unspecified` can be denied, so there
  is no guarantee.
- The macOS target app keeps a live tunnel while its window is closed. Linux
  keeps one while the tray item exists. A Windows app that stops the tunnel when
  the window is minimized is not the same product.

So the privileged boundary is designed so that it does not depend on the app
host. The boundary is a named pipe with caller account identity checks. A
full-trust WinUI 2 desktop app speaks it directly. If the product ever needs the
UWP host, a packaged full-trust broker can bridge the app service to the same
pipe. That bridge is compatibility work, not the primary design. It inherits the
suspension stop for the app session, and therefore for the tunnel, because a lost
session is a stop by design.

A UWP bridge must check `AppServiceTriggerDetails.CallerPackageFamilyName`
against its own package family name before it accepts a request. It accepts one
broker peer and refuses a second. It never relays another app's connection. The
current broker already does the client side; the app side is not enabled. If the
UWP app is suspended, the bridge loses its session and the service runs the stop
sequence with `parent_lost`. Nothing relaunches. That is the exact UWP
suspension lifecycle the review asked about, and it is why the primary host is a
desktop app.

This is open decision O1 and it is a review gate. It is a product decision
because it replaces the current UWP real-mode base. It is not an approval of
WinUI 3.

### 4.5 Install and uninstall contract

Install, run once with administrator consent:

1. Create the install directory under `%ProgramFiles%\HotspotShade\` with an
   ACL that allows the person read and execute and allows administrators write.
   The person must not be able to replace the service, the engine, or the probe
   helper binary. If the directory already exists, accept it only when its owner
   is `SYSTEM` or `Administrators`, the DACL is protected, no non-administrator
   has write access, and no path component is a reparse point. Otherwise stop.
2. Create `%ProgramData%\HotspotShade\` before the service starts. The installer
   creates it with a protected DACL, owner `SYSTEM`, full control for `SYSTEM`
   and `Administrators`, and no write or create-child right for `Users` or
   `Authenticated Users`. The default `ProgramData` ACL lets users create
   subfolders, so an existing folder is not trusted by default.
3. If `%ProgramData%\HotspotShade` already exists, check its owner and DACL. It
   is accepted only when the owner is `SYSTEM` or `Administrators`, the DACL is
   protected, and no non-administrator has write or create-child access. If it
   fails, the installer stops and tells the person to remove it with
   administrator help. The installer never adopts a user-owned folder and never
   repairs it silently.
4. Write an initial state record with `phase=never_launched`, `cleanup=ok`,
   `routes_may_exist=0`, `adapter.identity_source=missing`, and `v=1`. This is
   the only state that permits a start without a route check. A missing or
   unreadable record is `cleanup=unknown`, not `ok`.
5. Create `HotspotShadeEngineSvc` with `CreateService`:
   - `SERVICE_WIN32_OWN_PROCESS`
   - `SERVICE_DEMAND_START`
   - account `LocalSystem`
   - no dependencies
   - no arguments
6. Set the service security descriptor so the installing person may query
   status, query configuration, start, stop, and interrogate. Nobody else may,
   except `Administrators` and `SYSTEM`. The person's rights are exactly
   `SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START |
   SERVICE_STOP | SERVICE_INTERROGATE`, plus `SC_MANAGER_CONNECT` on the SCM
   handle. `SERVICE_QUERY_CONFIG` is required because the app's server proof
   reads `lpBinaryPathName` with `QueryServiceConfig` (section 5.4 step 5). If
   the right is absent, the app fails closed and does not connect. This is the
   B4 correction.
7. Set `SERVICE_CONFIG_FAILURE_ACTIONS` to `SC_ACTION_NONE` explicitly. Do not
   assume the default. This is the no-auto-restart rule at the SCM level.
8. Resolve the installing person's SID from the interactive logon token or the
   shell owner, not from the elevated administrator token. When a standard user
   elevates with an administrator's credentials, the elevated token's user SID
   is the administrator, not the person. Store the interactive user SID in the
   service configuration and the pipe DACL. If it cannot be resolved, the
   installer asks the person to pass `--user-sid` explicitly or stops.
9. Do not create a startup task. Do not create an `Automatic` service.
10. Do not write a source device credential at install time. Phase 1 keeps no
    credential at rest. Phase 2 writes one only after authenticated pairing.
11. Do not bundle `wintun.dll`. The engine loads it from the install directory by
    absolute path, as it does today.

Installer technology: a per-machine MSI built with WiX, or an equivalent
elevated installer, is assumed. MSIX is not chosen. The install needs explicit
SCM calls, a protected `ProgramData` DACL, and a service security descriptor
that a normal MSI custom action can perform. Packaged-service support varies by
Windows version. If the maintainer requires MSIX, the service install contract
must be re-reviewed and this assumption changes. The installer toolchain and a
code-signing certificate are external prerequisites.

Developer registration and an unpackaged loose-file layout are preview-only.
Real mode does not run from a developer registration folder, a `bin` output
directory, or a user-writable path. The service refuses to start an engine whose
image does not resolve under `%ProgramFiles%\HotspotShade`. Before every launch,
it opens the engine image with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects a reparse
point, and compares the final path to the install root. The install directory
ACL prevents a standard user from replacing the image between the check and
`CreateProcess`. The launch plan is fixed; the app cannot name the path.

Uninstall removes the service with `DeleteService`, stops it first through the
SCM, and does not delete the state record or a phase 2 credential while a tunnel
may run. The state record is removed after the service is confirmed stopped and
the engine process is gone. A phase 2 credential file is removed on explicit
forget or on uninstall after the service is stopped. The normal stop path removes
the objects the service recorded. If the service cannot prove ownership,
uninstall leaves the route or adapter in place and tells the person what to
inspect. It never deletes a foreign object.

### 4.6 Data-plane privilege split (review H3 and E3, recommended, unproven)

The prototype design starts the engine as `LocalSystem` because the Wintun
adapter and the route tables need an administrator token. The engine then parses
untrusted input with system rights. The account boundary in section 5 does not
mitigate that. The design records the exposure and does not claim the engine is
least-privilege.

Untrusted input reaches two privileged parsers, not one:

| Parser | Input | Source of the input |
|---|---|---|
| Engine data plane | Inner IPv4 and IPv6 packets, the inner TCP stack, relayed reply bytes, SOCKS replies, ICMP echo frames | Every local process of every account (the routes are machine-wide), the source device, and remote hosts whose replies the relay carries |
| Probe helper | The SOCKS reply to the token check; in phase 2 the pairing status frames and their AEAD decryption | Whatever answers at the hotspot gateway address. Before phase 2 that peer is not authenticated. |

The engine uses memory-safe Rust and bounded parsers. That lowers the defect
rate. It is not a privilege boundary.

#### 4.6.1 Why a simple handoff does not work

Standard (Wintun API, to be confirmed at R20): `WintunCreateAdapter` and
`WintunOpenAdapter` return an adapter handle in the calling process.
`WintunStartSession` allocates the send and receive rings in the calling
process and registers them with the driver. The API has no call that moves a
session to another process. So the service cannot open a session and hand it to
a restricted engine as an inherited handle. Whether a non-administrator token
may open the adapter or start a session at all depends on the Wintun device
object security and on how `wintun.dll` opens it. The design assumes it may not
until R20 shows otherwise.

#### 4.6.2 Options

| Option | What runs as `LocalSystem` | Feasibility | Cost |
|---|---|---|---|
| A. Restricted engine opens the adapter | The service: adapter create, route install and removal | Only if R20 shows that a restricted token can open the adapter and start a session on an adapter the service created. Expected to fail. | Smallest change to the engine |
| B. Service-side packet pump | The service: adapter, routes, and one Wintun session. It copies whole frames, with a length check only, to the restricted engine over a shared memory ring or an anonymous pipe, and back. It never parses a packet. | Needs R20 for the pump throughput and latency, and R21 for the engine's outer sockets under the restricted token | One extra copy and a context switch per packet in each direction. A new privileged component, small but on the hot path. |
| C. Keep `LocalSystem` | The engine and the probe helper | Feasible today on paper | The H3 exposure stays. G2 needs a written owner acceptance. |

The restricted engine token in A and B is built by the service with
`CreateRestrictedToken` from its own token: every privilege removed, the
`SYSTEM` and `Administrators` SIDs and the user SID set deny-only, a restricting
SID list of the service SID and a per-launch logon SID, and the integrity level
lowered. The service starts the engine with `CreateProcessAsUserW` and the same
explicit handle list as section 7. Hypotheses, all for R21: the token can create
outer sockets, set `IP_TTL` to 65, set `IP_UNICAST_IF` and `IPV6_UNICAST_IF`,
read the TTL back, and resolve nothing through the system resolver. If any of
them fails, the normalized socket helpers cannot run under that token and option
A or B is not viable as written.

The probe helper needs no adapter and no route. It needs only the normalized
socket helpers. Its restricted token therefore depends on R21 only, not on R20.
The recommendation is to run the probe helper under the restricted token from
its first real-mode build if R21 passes, even if the engine stays at
`LocalSystem`.

#### 4.6.3 Owner risk acceptance

If R20 or R21 fails, or the maintainer does not accept the cost of option B, the
prototype stays at option C for the failed component. G2 then requires a written
owner acceptance (O2b) that names:

- each component that stays at `LocalSystem`: the engine, the probe helper, or
  both
- the untrusted inputs in the table above, including remote reply data and an
  unauthenticated gateway peer before phase 2
- the scope: which builds and which hosts, for example disposable test hosts only
- the compensating controls: bounded parsers, the fixed operation set, no
  network listener, and any fuzzing the owner requires
- the re-review trigger: a passing R20 or R21, a parser change, or a fixed date

A G2 approval does not imply the acceptance. A missing acceptance blocks G2. The
design does not choose option C silently.

#### 4.6.4 Ownership in the split

In options A and B:

1. The service creates the Wintun adapter with the planned name and GUID
   (section 8.3), records the observed LUID and GUID, installs the routes, and
   holds the adapter handle for the session.
2. The engine runs under the restricted token. It does not call a route API and
   does not create an adapter.
3. The service removes the routes and closes the adapter on every stop path,
   including an engine crash, after the engine process exits. It may do so only
   while the recorded identity matches the live object and no foreign owner is
   proven. It does not delete a route while the engine may still be using it.
4. The engine keeps the bearer check, the fixed protocol, and the bounded
   parsers. A defect is still serious, but it no longer starts with
   `LocalSystem`.

Tests V90 and V91 are the first hermetic and VM checks. R20 and R21 are the
administrator spikes on a disposable Windows VM. Open decision O2b records the
choice. It blocks G2. It does not block design review of the rest of this file.

## 5. The authenticated app boundary

### 5.1 Transport

One named pipe: `\\.\pipe\HotspotShade.Engine.v1`.

- Byte mode, so the service controls the framing and the size bound.
- `PIPE_REJECT_REMOTE_CLIENTS`.
- One instance. A second connection attempt is refused, not queued.
- `FILE_FLAG_OVERLAPPED`, so a read has one absolute deadline and can be
  cancelled with `CancelIoEx`.
- `FILE_FLAG_FIRST_PIPE_INSTANCE` on `CreateNamedPipeW`. If the name already
  exists, the service does not fall back, does not use a second name, and does
  not serve. It records `pipe_name_in_use`, reports a service-specific error,
  and stops. This closes the case where a standard user creates the pipe before
  the service starts.
- An explicit security descriptor. Do not rely on the default DACL.
- No `FILE_CREATE_PIPE_INSTANCE` right for the interactive user. The DACL
  grants read and write data access, not the right to create another instance.
  This is the review H2 correction and it changes the threat result: a same-user
  process cannot create a later instance of the service pipe. `Administrators`
  still can, because they can already debug or replace the service, and the SCM
  PID check in section 5.4 stays as defense in depth.
- No network listener. The service opens no socket.

The service creates the pipe and listens before it reports `SERVICE_RUNNING`.
The pipe exists for the life of one app session.

`FILE_FLAG_FIRST_PIPE_INSTANCE` is necessary and not sufficient by itself. A
same-user process cannot create the first instance while the service holds the
name, and it cannot create a later instance because the DACL omits
`FILE_CREATE_PIPE_INSTANCE`. An administrator can create a later instance or
replace the service; that is out of scope, and the app's SCM PID check in
section 5.4 rejects a later instance anyway. If a future DACL is changed to
grant the create-instance right, the SCM PID check remains the control that
prevents trust.

### 5.2 DACL

The pipe security descriptor grants access to exactly these identities:

- `SYSTEM` (the service itself)
- `Administrators`
- the configured interactive user SID

The exact SDDL string, for review at G2:

```
O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120183;;;<user SID>)
```

`<user SID>` is the numeric SID that the installer recorded (section 4.5 step 8).
`P` means the DACL is protected from inheritance. No `Everyone`, no
`Authenticated Users`, no `INTERACTIVE`, no `ANONYMOUS`. A second local account
that is not an administrator cannot open the pipe. A remote client is rejected
by `PIPE_REJECT_REMOTE_CLIENTS`. `GA` for `SYSTEM` and `Administrators` maps to
`FILE_ALL_ACCESS` on a pipe and includes the create-instance right; that is
accepted because both can already replace the service. A reviewer may write
`FA` instead; the meaning is the same.

The user ACE is a numeric mask, not `GRGW`. Bit by bit:

| Bit | Name on a pipe | Granted | Why |
|---|---|---|---|
| `0x00000001` | `FILE_READ_DATA` | yes | Read replies |
| `0x00000002` | `FILE_WRITE_DATA` | yes | Write requests |
| `0x00000004` | `FILE_CREATE_PIPE_INSTANCE` | **no** | This is the right to create another server instance. It is the same bit as `FILE_APPEND_DATA`, and `GENERIC_WRITE` maps to it. |
| `0x00000008` | `FILE_READ_EA` | no | Not needed |
| `0x00000010` | `FILE_WRITE_EA` | no | Not needed |
| `0x00000080` | `FILE_READ_ATTRIBUTES` | yes | `GetNamedPipeInfo` and handle queries |
| `0x00000100` | `FILE_WRITE_ATTRIBUTES` | yes | `SetNamedPipeHandleState` on the client's own handle. A framework may call it after the open. It changes only the client handle mode. |
| `0x00010000` | `DELETE` | no | Not needed |
| `0x00020000` | `READ_CONTROL` | yes | Section 5.4 step 4 reads the pipe owner with `GetSecurityInfo` |
| `0x00040000` | `WRITE_DAC` | no | The user must not change the pipe DACL |
| `0x00080000` | `WRITE_OWNER` | no | The user must not take ownership |
| `0x00100000` | `SYNCHRONIZE` | yes | Wait on the handle |

Sum: `0x00120183`. Standard behavior, to be proven at S37, V97, and R19:
`GENERIC_READ` on a pipe maps to `0x00120089` and `GENERIC_WRITE` maps to
`0x00120116`, which contains `0x4`. So `GRGW` in SDDL would grant the
create-instance right, and a client that asks for `GENERIC_WRITE` asks for it.

The matching client request is in section 5.4 step 2. The app opens the pipe
with exactly `0x00120183`, so the requested mask is a subset of the user ACE and
contains no bit the ACE omits. A client that asks for `GENERIC_READ |
GENERIC_WRITE` is denied with `ERROR_ACCESS_DENIED`. That is the intended
result, not a bug to work around by widening the ACE. A .NET client must not use
a `NamedPipeClientStream` constructor that requests `GENERIC_WRITE` by default;
it must pass the explicit rights, or the app must call `CreateFileW` directly.
Which constructor does that on the chosen runtime is a hypothesis for S37 and
V97. Changing either mask needs a G2 re-review, and the two constants live in one
reviewed place in each code base.

The DACL does not distinguish one process of the configured account from
another. Any process running as that user passes. This is deliberate: the app
must be controllable by the person, and a same-user process already has the
person's authority. The boundary protects the privileged engine from other
accounts and from remote clients. It does not protect the tunnel from the
person's own processes. The threat table says so in plain words.

If the app is packaged, the package identity can be added as defense in depth,
but a full-trust packaged app has no AppContainer token. The design does not
require an AppContainer SID. The package identity check is optional and does not
change the same-user result.

### 5.3 Caller authentication

The caller is authenticated from the connection's own token, not from a PID. A
PID can be reused after the client exits, so a PID lookup can name a different
process. Revision 4 replaces the revision 3 PID lookup. This is E10.

On every accepted connection:

1. `ConnectNamedPipe` completes. Start the 5 second `hello` deadline.
2. Read exactly one frame into a bounded buffer: a 4 byte length and at most
   65536 bytes, under the same deadline. Do not parse it, act on it, or log its
   content. Standard: `ImpersonateNamedPipeClient` fails with
   `ERROR_CANNOT_IMPERSONATE` until data has been read from the pipe, so the
   read must come first. This is proven at R25.
3. Call `ImpersonateNamedPipeClient`. Failure closes the connection with no
   reply.
4. Call `OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, OpenAsSelf = TRUE)`.
   `OpenAsSelf` is required: the app limits the server to
   `SecurityIdentification` (section 5.4 step 2), and an identification-level
   token cannot pass the access check to open itself.
5. Read `TokenUser`, `TokenSessionId`, `TokenImpersonationLevel`, and, for the
   event log only, `TokenElevationType`. If a package identity is configured,
   read it from the same token.
6. Call `RevertToSelf` on every path, success or failure, before step 7. If
   `RevertToSelf` fails, the worker thread runs no other operation. The service
   closes the connection, records `revert_failed`, and runs the normal stop path
   from a thread that never impersonated.
7. Close the token handle. Require `TokenUser` to equal the configured
   interactive user SID, the impersonation level to be at least
   `SecurityIdentification`, and, if configured, the package identity to match.
   Do not require an AppContainer token and do not reject a full-trust process.
8. On any mismatch: close the pipe, record a fixed event code, send no reply.
   The buffered frame is discarded unparsed. The app sees a broken pipe and
   reports `boundary_auth_failed`.
9. Only now parse the buffered frame. It must be `hello`. Record
   `TokenSessionId` as the controlling session for the logoff filter in section
   8.6.

`GetNamedPipeClientProcessId` may be called for the event log. It is
diagnostics only and never an authorization input. The token in steps 3 to 7
belongs to the connection, so PID reuse cannot change the result.

The impersonation window is steps 3 to 6. In that window the thread does only
token queries. The token is identification level, so the thread cannot open an
object as the client even by mistake. One impersonation runs per connection.
The single pipe instance serves one client per connection, so the identity
cannot change during a session.

The unauthenticated read in step 2 is bounded by the frame cap and the `hello`
deadline. It can delay the real app by at most 5 seconds per connection
attempt, and only a process that passes the DACL can make it.

The service does not reject an elevated caller. An elevated process of the same
account is still the same principal, and rejecting it locks out accounts with
UAC turned off. The DACL already grants `Administrators`. The honest trust set
is the account, elevated or not. The service records `elevated_caller` in its
event log for visibility, but it does not make an authorization decision from
it.

What a same-user process can do after it passes this check:

- start and stop the tunnel with the current in-memory credential
- set or forget the credential for this session
- hold the single session and deny the real app a connection
- read the redacted status and diagnostics
- run `recheck`, `probe`, and `shutdown`

What it cannot do:

- read the bearer, the credential, or the identity key
- create another instance of the service pipe while the DACL omits
  `FILE_CREATE_PIPE_INSTANCE`
- name an engine path, port, or handle
- point the engine at a host other than the current default IPv4 gateway and
  the recorded interface identity
- make the service delete a route the service did not record, or name one
- read raw engine JSON, addresses, interface names, or logs

A same-user process can also inject into the app at the same integrity level.
That is outside this boundary and is recorded as residual risk.

### 5.4 Server authentication, performed by the app

A medium integrity process can create the pipe name before the service starts.
The first-instance flag makes the service fail closed in that case, but a
squatter can also create a later instance. The app must not trust the pipe name
alone.

The app does this before the first request:

1. Open the SCM with `SC_MANAGER_CONNECT` and query
   `HotspotShadeEngineSvc` with `SERVICE_QUERY_STATUS`. Read
   `SERVICE_STATUS_PROCESS.dwProcessId` and `dwCurrentState`. If the service is
   not `SERVICE_RUNNING`, there is no engine. For a status read, report
   `engine_unavailable` and stop. Do not connect to the pipe. For a person start
   action, call `StartService` with `SERVICE_START`, then repeat this step with a
   10 second bound. Do not start the service for a status read. A start timeout
   is `engine_unavailable`, not a kill.
2. Connect to the pipe with `CreateFileW`, desired access exactly
   `0x00120183` (section 5.2), share mode 0, `OPEN_EXISTING`, and flags
   `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`. Do not request
   `GENERIC_READ | GENERIC_WRITE`; that asks for `0x4` and the DACL denies it.
   The identification flag lets the server identify the client in section 5.3
   but not act as the client. The open shares the request deadline in section
   12; a pipe connect that does not complete inside it reports
   `engine_unavailable`. An `ERROR_ACCESS_DENIED` on this open is
   `boundary_auth_failed`, not a reason to retry with a wider mask.
3. Call `GetNamedPipeServerProcessId`. Require it to equal the SCM PID from
   step 1.
4. Call `GetSecurityInfo` on the pipe handle with `SE_KERNEL_OBJECT` and
   `OWNER_SECURITY_INFORMATION`. Require the owner SID to be `SYSTEM`. The pipe
   handle must carry `READ_CONTROL`, which the step 2 mask includes. This step
   is a hypothesis until a Windows host confirms that a pipe handle returns the
   owner through `SE_KERNEL_OBJECT`. If it fails, the app fails closed. It does
   not fall back to trusting the name.
5. Query `QueryServiceConfig` for `lpBinaryPathName`. Opening the service handle
   requires `SERVICE_QUERY_CONFIG`; the installer grants it to the interactive
   user in section 4.5 step 6. Compare the normalized path to the installed
   service path compiled into the app. A mismatch or an access-denied result
   fails closed with `boundary_auth_failed`. This is B4.
6. Re-query the SCM state after the connection. If the service stopped or the
   PID changed, close and report `engine_unavailable`.

The app does not open the service process token. A medium integrity process
cannot reliably open a `LocalSystem` process token, so a design that depends on
that step is not feasible. The SCM PID, the pipe owner, and the installed
service path are the feasible proof.

If the service is demand started and not running, the app may call `StartService`
because the service security descriptor grants start to the installing person.
It also grants query configuration, which step 5 needs; a missing right is a
deployment failure, not a reason to skip the check. If `StartService` fails, the
app reports `engine_unavailable`. It never falls back to a pipe that fails steps
1 through 6.

A squatter that created the pipe name first makes the service fail its first
instance creation. A non-administrator same-user process cannot create a later
instance because the DACL omits `FILE_CREATE_PIPE_INSTANCE` (section 5.2). An
administrator can, but is not the SCM PID, so step 3 fails. The app closes the
pipe and reports `boundary_auth_failed`, then may retry the connection a bounded
number of times to reach the real service. It sends no frame to a squatter.

### 5.5 One session

The service binds one session on the first `hello`. The app supplies a 32
character session id, as it does today (`EngineProtocol.SessionIdLength`).

- A second `hello` with a different session id is refused with `forbidden`.
- A second connection while a session is live is refused at accept time with
  `boundary_busy`.
- The session ends when the pipe breaks. A broken pipe is a stop reason:
  the service runs the full stop path with reason `parent_lost`.
- There is no reconnect grace. A grace would be a persistent proxy. The person
  starts the tunnel again after the app restarts.

A same-user process can take the single session before the app. That is a
denial of service, not a secret leak. The real app then reports
`boundary_busy`. The person can stop the offending process or stop the service
through the SCM.

Session lifecycle is bounded and has no grace:

- `hello` must arrive within 5 seconds of the connection. Otherwise the service
  closes the connection and accepts no frame from it.
- One request is in flight. A request that exceeds its deadline closes the
  connection; the session ends and the stop path runs if a tunnel is live.
- A pipe break is `parent_lost`. There is no reconnect grace and no resume of
  the previous session.
- If an SCM stop or shutdown arrives while a session is live, the SCM path wins.
  The service closes the session, runs one stop sequence, and records
  `stop=service_stop` or `stop=shutdown`. It does not run a second stop for the
  pipe break.
- If the app disconnects while a start request is in flight, the start is
  cancelled at the next deadline check. Any engine that was launched is closed
  through the parent pipe and observed under the 12 second cleanup wait. The
  service never leaves an unobserved child.
- A second connection attempt is refused even while the service is stopping.
  There is no queue and no takeover of the stopping session.

### 5.6 What the app may ask

The operation set is fixed and versioned:

| Operation | Purpose | Launches the engine |
|---|---|---|
| `hello` | Bind the session, return the service instance id | No |
| `status` | Read the redacted state, including TTL audit counters | No |
| `start` | Start the tunnel with the held credential | Yes, once |
| `stop` | Stop the tunnel, keep the service | No |
| `credential.set` | Set the in-memory source device credential | No |
| `credential.forget` | Forget the in-memory credential | No |
| `probe` | Run one source device presence probe now, rate limited. Phase 2 also reports the source connection count. | No tunnel launch. If no engine runs, starts one short-lived probe helper with no adapter and no routes. If an engine runs, delegates to its monitor. |
| `diagnostics` | Read the bounded timing and counter record | No |
| `failures` | Read the bounded recent failure record | No |
| `recheck` | Run the read-only route absence check and clear a latch only if clean | No |
| `shutdown` | Stop the tunnel and stop the service | No |
| `pair.begin`, `pair.status`, `pair.cancel` | Reserved for version 2 | No |

`hello` and `status` must not launch the engine. The current broker launches on
`hello` (`EngineBrokerService.cs`). That is a privilege cost paid on page load
and it makes a failed launch permanent. The service reports
`engine=unavailable` without an engine, and `paired` from the in-memory
credential store.

The app cannot:

- name an engine path, a port, a handle value, or an argument
- name a source device host other than the current default IPv4 gateway
- request direct mode, SOCKS5 mode, IPv4 pinning changes, or an IPv6 policy
- read the service's stored credential, the identity key, or the bearer. In
  phase 1 the app holds the token the person typed until `credential.set`
  completes, then clears it. It never receives the token back from the service.
- read raw engine JSON, logs, addresses, interface names, or paths
- read a route table snapshot that names a foreign adapter

`diagnostics` returns only bounded numeric counters and timing reservoirs. It
carries no address, host name, token, key, or interface name. `failures` returns
the same redacted record as `GET /api/failures`. That record stays in service
memory, is never written to disk, is never sent to the source device, and is
cleared when the tunnel starts or stops. `ttl_bad` is a number and is never
omitted, because invariant 1 requires the tunnel to keep the TTL audit visible.

### 5.7 Boundary failures

| Event | Service action | App result |
|---|---|---|
| Caller identity mismatch | Close, fixed event code, no reply | `boundary_auth_failed` |
| Frame exceeds 65536 bytes | Close, no reply | `bad_response` |
| Frame length zero or trailing bytes | Close, no reply | `bad_response` |
| Unknown key, duplicate key, non string value | Reply `bad_request`, keep session | `bad_request` |
| Credential key in a request | Reply `forbidden`, keep session | `forbidden` |
| Session mismatch | Reply `forbidden`, keep session | `forbidden` |
| Second connection | Refuse at accept | `boundary_busy` |
| Pipe name already exists at service start | Service fails closed, event `pipe_name_in_use` | `engine_unavailable` |
| Same-user process tries a later pipe instance | DACL omits `FILE_CREATE_PIPE_INSTANCE`; create denied | `engine_unavailable` |
| Administrator creates a later pipe instance | App server identity check fails | `boundary_auth_failed` |
| Client opens with `GENERIC_WRITE` or any bit outside `0x00120183` | `CreateFileW` is denied by the DACL; no connection reaches the service | `boundary_auth_failed` |
| No first frame within 5 s, so impersonation cannot run | Close, no reply | `timeout` |
| `ImpersonateNamedPipeClient` or `OpenThreadToken` fails | Revert, close, fixed event code, no reply | `boundary_auth_failed` |
| `RevertToSelf` fails | Close, `revert_failed`, stop path from a thread that never impersonated | `engine_unavailable` |

Framing is one 4 byte big-endian length, then exactly that many bytes of one
JSON object. A zero length, a length above 65536, a non-object JSON value, or
trailing bytes is a protocol failure. One request in flight per session. The
service never echoes a rejected frame.

The 65536 byte cap is a deliberate new Windows constant. It is not the Unix
`privileged.rs` `MAX_MESSAGE` value of 262144. The framing pattern is copied;
the code is not, because `privileged.rs` is Unix only and uses `UnixStream`.

## 6. The engine endpoint

### 6.1 Recommended design: a control pipe, no TCP port

In service mode the engine binds no loopback port. The service talks to it over
one inherited duplex channel made of two anonymous pipes:

- `control_in`: service writes, engine reads.
- `control_out`: engine writes, service reads.

`event` is a separate engine-to-service pipe for readiness and the final cleanup
frame.

Framing is one 4 byte big-endian length, then one JSON object, with a 65536 byte
cap. One request in flight. The length prefix is big-endian because
`rust/src/privileged.rs` uses `to_be_bytes`, and a Windows reader must not
reverse it. The cap is 65536 on every pipe in this design.

Why this is the recommendation:

- There is no port, so there is no port to squat, no port collision with Hyper-V,
  WSL, or Docker reserved ranges, and no `SO_EXCLUSIVEADDRUSE` dependency.
- There is no WinHTTP, so the whole request deadline is one bounded read, not
  five phase timeouts that can add up.
- There is no redirect, no `Host` check, and no bearer header to leak.
- The bearer is checked once at connect, from the pipe.
- The anonymous pipe has an explicit `SYSTEM`-only security descriptor. A
  medium integrity process cannot open it. A same-user process with a handle to
  the `LocalSystem` engine could duplicate it, but that needs
  `PROCESS_DUP_HANDLE` on a higher-integrity process, which Windows denies.

An anonymous pipe has no name. That is convenient, not the security argument.
The explicit security descriptor is the security argument.

The engine keeps its browser GUI server for `hotspotshade gui`. The two surfaces
share the same `GuiBackend` trait and the same service layer, so status and start
behavior cannot drift. The new `engine` command does not start the browser
server, the loopback listener, or the static assets.

Engine change required: a new hidden command, for example
`hotspotshade engine --bearer-fd H --parent-fd H --control-in H --control-out H
--event-fd H`. It is a new command, not a new flag on `gui`, so the existing
`gui` option validation stays strict. The command reads the bearer, clears
`HANDLE_FLAG_INHERIT` on every control handle, and never binds a socket.

The engine command must keep the automatic stop behavior that lives in
`GuiServer::run` today, with its own explicit evidence contract:

- `start_presence` and `auto_stop_loop` are extracted into a monitor owned by
  the engine command. The policy is not duplicated.
- The monitor samples the same `GuiBackend` status every 2 seconds.
- The source device probe runs only while a tunnel is running and the app
  session is live. It stops on stop, app loss, engine loss, or `shutdown`. It
  uses the token check in phase 1 and the authenticated pairing status in phase
  2. Phase 1 reports no source connection count.
- The monitor takes a three-state link observation: `Up`, `Down`, or `Unknown`.
  On Windows the observation is always `Unknown` because no observer is
  enabled. `Unknown` never produces `hotspot_lost`, never resets the source
  silence interval, and never starts or resets the unsupervised interval below.
  It is constant on Windows, so a clock driven by it would stop every Windows
  tunnel or none. `Down` is reachable only on a platform with an enabled
  observer. This is the B1 fix.

Each probe sample is one of these results:

| Result | Meaning | Silence interval | Unsupervised interval |
|---|---|---|---|
| `Accepted` | A fresh answer from the source device that accepted the credential. In phase 2 the answer is authenticated. | Cleared | Reset to 0 |
| `Rejected` | A fresh answer that refused the credential | Cleared | Not reset. The existing `phone_auth` path decides the stop. |
| `Silent` | The probe ran, the link identity was readable and matched, and no answer came inside the 4 second socket bound | Runs. 90 s stops with `source_device_gone`. | Not reset |
| `Unavailable` | The probe could not run: the identity was unreadable, the interface was missing, the socket failed, or the TTL audit could not be taken | Cleared. It is no evidence of silence. | Not reset |
| `Cancelled` | The probe was cancelled by a stop or a request deadline | No change | No change |

- The unsupervised interval is the time since the last `Accepted` result. It
  starts at the `running` transition. If it reaches 300 seconds, the engine
  stops the tunnel with reason `observation_unavailable`. Silence alone stops
  first at 90 seconds with the more specific reason. The 300 second bound
  catches the remaining cases: continuous `Unavailable`, and any mix of
  `Silent`, `Unavailable`, and `Rejected` that never yields an `Accepted`
  answer. Without it, alternating `Silent` and `Unavailable` samples would clear
  the silence interval forever.
- `observation_unavailable` is not `hotspot_lost` and not `source_device_gone`.
  It says that the tunnel ran for 300 seconds without one usable positive
  answer. It does not say that the hotspot or the source device is gone, and it
  does not say that pairing failed. Section 11 keeps it apart from pairing
  status. Its app text is "The tunnel stopped because it could not check the
  source device for 5 minutes. This does not mean the hotspot or the source
  device is gone."
- The bound preserves invariant 13: a tunnel with no supervision does not run
  forever. It is a proposal, decision O23. It is not implemented in the engine,
  the CLI, or the GUI. The 300 second value is a proposal for the owner. A
  shorter value stops more often during a long DHCP renewal or interface flap; a
  longer value keeps an unsupervised tunnel longer.
- The clock is monotonic. Whether it counts time while the host is asleep is
  measured at V98 on a Windows VM. If it does, a long sleep can cause an
  `observation_unavailable` stop at the first sample after resume. That is
  accepted behavior for a stale tunnel and is documented, not hidden.
- The Windows CLI `tun` path supplies `Some(true)` as its link closure, so it
  runs the probe and can stop on source silence when a physical interface
  resolves. The service monitor must produce the same silence stop with an
  explicit `Unknown` observation, not by pretending the link is up for every
  purpose. The CLI has no unsupervised bound.
- The command-line GUI is changing in the working tree. The uncommitted
  `LinkWatch::Unobservable` path in `rust/src/gui.rs`
  (`auto_stop_sample_watch`) treats a fresh `not_running` or `not_responding`
  probe as silence and can stop with `source_device_gone` after 90 seconds. A
  positive, stale, missing, or `no_hotspot` probe resets both timers, so the GUI
  still has no unsupervised bound. This design records that change as in
  progress and unverified. It does not use it as evidence, and the service
  monitor does not call `auto_stop_sample` or `auto_stop_sample_watch`
  unchanged. Whether the CLI and GUI adopt the O23 bound is part of O23.
- The monitor writes a final cleanup frame with the stop reason
  (`source_device_gone` or `observation_unavailable`) on the normal automatic
  stop path. The write is best effort (section 8.8). A hard crash cannot write
  one, and the service records `cleanup=unknown`.

Do not describe a Windows hotspot loss stop. It does not exist. The app and the
docs must not claim it. Do not describe the Windows CLI and GUI as behaving the
same. They do not.

This is open decision O3. It is the largest engine change in the design, and it
is the one that closes the first review's endpoint, timing, and redirect findings
by construction rather than by mitigation.

### 6.2 Bounded pipe I/O

Anonymous pipes created with `CreatePipe` are synchronous. A blocking `ReadFile`
has no timeout, so "one bounded read" needs a stated mechanism. Revision 2
specifies one:

- Every pipe is created with a 131072 byte buffer for both directions, so a
  65536 byte frame and its 4 byte length prefix fit without a short write. If
  the kernel provides a smaller buffer, the writer thread blocks and the
  deadline applies.
- The service reader uses `PeekNamedPipe` in a loop. It checks the absolute
  deadline every 25 ms, reads only bytes the kernel reports available, and
  returns `timeout` when the deadline expires. It never enters a blocking
  `ReadFile` without data.
- The engine reader uses the same loop for `control_in`. It also watches the
  parent pipe, so it stops when the parent is gone.
- A write goes through a dedicated writer thread. The caller waits on a bounded
  channel with the same absolute deadline. On timeout it calls
  `CancelSynchronousIo` on that thread and closes the handle. A synchronous pipe
  write can block when the peer is not reading; the buffer size and one-request
  rule make that rare, and the writer thread makes it bounded.
- The 65536 byte frame cap plus the 131072 byte buffer means one full frame
  fits. A second frame cannot be in flight because one request is in flight.
- `CancelSynchronousIo` is a documented way to cancel a synchronous pipe I/O.
  Its interaction with a pipe handle close is a hypothesis with tests V40 and
  V70.

This is more code than a blocking read. It is honest: a synchronous anonymous
pipe cannot be given a timeout any other way. A named overlapped pipe would be
the alternative. The design keeps anonymous pipes because the handles are
inherited and there is no name to squat.

### 6.3 Frame and operation set

Request: `{"v":1,"op":"status","sid":"<32 hex>"}`.

Reply: `{"v":1,"ok":true,"fields":{...}}` or
`{"v":1,"ok":false,"code":"<fixed code>"}`.

The code is a fixed token from `EngineProtocol.ErrorCodes`, plus the codes in
section 11.2. A reply never carries free text that a person did not already have
from the app. The engine's human message is dropped at the service.

Operations over the engine control pipe mirror the app operations that need the
engine: `status`, `start`, `stop`, `probe`, `diagnostics`, `failures`,
`credential.set` (sets the engine's in-memory copy for the start request), and
`recheck`. `hello` and `shutdown` are service operations. The service adds the
credential to `start`; the app never builds that request.

### 6.4 Fallback design: loopback HTTP with proof

If review rejects the control pipe, the HTTP path stays and must add all of the
following. Each is required, not optional.

1. The service passes `--port 0`. The engine binds, then reports the bound port
   and its instance id on the event pipe. `--port-file` stays unsupported on
   Windows; the event frame replaces it.
2. The engine sets the Winsock exclusive-address option (the inverse of
   `SO_REUSEADDR`) before `bind`. The current `TcpListener::bind` in
   `rust/src/gui.rs` does not.
3. Before the first request, the service reads
   `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER)` and requires the listener
   on that port to be owned by the engine PID from the process handle. A
   mismatch is `boundary_auth_failed` and stops the engine.
4. The engine reports its instance id in the readiness frame, and status replies
   carry the same instance id. The service refuses a status whose instance id
   differs. This catches a port that is reused after the engine dies. This
   instance id is consumed inside the service and is not forwarded to the app.
5. The service sends the bearer on the first request after steps 1 through 4.
   The engine returns its instance id in that reply. A squatter that won the
   bind before the engine can receive that first request and the bearer. The
   bearer is dead because the real engine never received it. The instance id
   check prevents the service from trusting the reply, not the send. Do not say
   the design prevents the bearer from being sent.

Residual risk in the fallback: the service must trust the TCP table read and the
process handle. A same-user process cannot bind while the engine holds an
exclusive bind, and cannot answer on the port after the engine dies without
failing the instance id check. It can still race the bind itself, which then
fails the engine bind and produces `engine_unavailable`, not a usable bearer.

Post-exit takeover is explicit. After the engine exits, a same-user process can
bind the old port. The service never reuses a cached endpoint. Every generation
re-runs steps 1 through 4 against the new engine, and the instance id must match
that generation. If the old port is taken, the new engine bind fails and the
start reports `engine_unavailable`. The service sends no frame and no bearer to
the squatter.

### 6.5 Which one is required for approval

The fallback is a valid design. It is more code paths to test and it keeps a
WinHTTP client whose timing rules must be written down. The control pipe is
smaller and removes a class of findings. The review gate G3 decides.

### 6.6 The source probe helper

The app can run a "Check now" probe before a tunnel starts. The service cannot
use the tunnel engine for that, because the engine is not running. It also must
not start a full tunnel just to probe. It starts a short-lived **probe helper**
instead.

While a tunnel runs, the engine monitor performs the same probe in-process
every 2 seconds. The service does not start the helper for each sample. An
explicit `probe` during a run is delegated to the engine monitor.

The helper is a separate small executable, `hotspotshade-probe.exe`, built from
the same Rust crate. It links the same `PhoneProxy` code and the same
authenticated status read as the tunnel. It is not the engine binary, so the
image-path observation cannot mistake it for a tunnel engine. The
service uses the installed absolute path, which the app cannot name. The
service starts it with the same inherited-handle discipline as the engine, but
with only:

- a token pipe carrying the target host, port, interface index, source
  credential, and the phase 1 or phase 2 mode
- a result pipe carrying one redacted status frame
- a parent pipe for liveness
- no bearer, no adapter, no routes, and no browser server

The helper runs the check that the held credential supports. In phase 1 manual
mode it runs the token check, which proves the source device accepts the token
but reports no connection count. In phase 2 it runs `pairing::status_at` and
reports the authenticated status fields, including `phone.connections`. It uses
the normalized socket helpers, so the outer socket sets TTL 65 and the TTL audit
applies. It reports only the fixed numeric fields and the fixed state token. It
zeroizes the credential, writes one result frame, and exits. The service waits
for it with the same deadline as the `probe` operation and records one presence
sample. On timeout, the service closes the parent pipe and records a failed
probe. It does not terminate the helper; the helper exits on parent loss. A
helper crash is a failed probe, not a tunnel event. It creates no device and
changes no route, so it needs no cleanup latch.

Before the helper sends anything, it checks the physical link identity: the
interface LUID or GUID, the gateway IPv4 address, and the interface type. It also
reads the hotspot-side guard values in section 11.4 when they are available. If
the identity cannot be read, it does not send and reports `Unavailable`; that is
no evidence, not silence. If the identity or a known guard value differs from
the stored value, it clears the credential and reports `gateway_changed` or
`link_changed`. It does not claim that the IP address, the interface, or a guard
match proves the hotspot. This is review H1 and E4.

The helper parses untrusted hotspot-side input: the SOCKS reply to the token
check, and in phase 2 the pairing status frames. Before phase 2 the peer at the
gateway address is not authenticated. In the prototype the helper runs as
`LocalSystem`, so it is a second privileged parser beside the engine. Section
4.6 records it in the exposure table. Its restricted token needs only R21, not
the Wintun spike R20, and it is recommended for the first real-mode build. If
R21 fails, the helper is named in the O2b owner acceptance. This is E3.

The helper is not a second source of truth. It is a short-lived child of the
service, and it never outlives the `probe` request. It relays no user traffic. A
restart of the service or the app does not leave it running. Test V74 checks
that it creates no adapter or route and that it exits on parent loss.

## 7. Descriptor handles

The project calls the inherited channel a descriptor. On Windows it is an
inherited handle. The handle number is not a secret and travels on the command
line. The secret travels only inside the pipe. That matches invariant 12.

### 7.1 Handle inventory per launch

| Channel | Direction | Service end | Engine end | Kind |
|---|---|---|---|---|
| `token` | service to engine | write | read | anonymous pipe |
| `parent` | service to engine, held open | write | read | anonymous pipe |
| `event` | engine to service | read | write | anonymous pipe |
| `control_in` | service to engine | write | read | anonymous pipe |
| `control_out` | engine to service | read | write | anonymous pipe |

All five are created with `CreatePipe` and an explicit `SECURITY_ATTRIBUTES`
whose descriptor grants full control to `SYSTEM` and `Administrators` only. The
default DACL is not used. Each pipe uses a 131072 byte buffer, so a maximum
frame and its length prefix fit. A medium integrity process cannot open it. A
handle duplication needs `PROCESS_DUP_HANDLE` on the engine, which Windows
denies to a lower-integrity process.

The handle number is passed on the command line. The command line never carries
the bearer, the credential, or the identity key.

The probe helper in section 6.6 uses the same creation and inheritance rules
with a credential pipe, a result pipe, and a parent pipe. It has no bearer
handle, no event pipe, and no control pipes.

### 7.2 Inheritance window

The first review found that the read ends are inheritable from broker start
until the launch, and that the engine's parent handle stays inheritable and may
reach `netsh`. The second review found that Rust `std::process::Command` always
calls `CreateProcessW` with inherit-handles on, so a `SystemRunner` based on
`Command` cannot meet a `bInheritHandles = FALSE` rule.

Design rules:

1. Create the pipes inside the launch critical section, immediately before
   `CreateProcess`. Do not create them at service start. There is no inheritable
   handle in the process while the service is idle.
2. Create each pipe with `bInheritHandle = TRUE`, then call
   `SetHandleInformation(serviceEnd, HANDLE_FLAG_INHERIT, 0)` immediately.
3. The engine ends stay inheritable only until `CreateProcess` returns. The
   service closes its copies of the engine ends immediately after the call, on
   every path, including failure.
4. `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` contains exactly the engine ends. Windows
   requires the handles in the list to be inheritable; that is why the engine
   ends are created inheritable and the service ends are not.
5. `bInheritHandles = TRUE` is required for the list to take effect. It does not
   widen inheritance beyond the list.
6. A service wide launch mutex serializes the critical section, so no other
   launch or child process can exist while inheritable handles are open.
7. `CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW`.
   No `STARTF_USESTDHANDLES`, so the engine has no console handles.
8. The launch plan resolves the engine image under the install root, rejects a
   reparse point, and is fixed by the service. The app cannot name a path,
   argument, or handle value.

For any child that the **service** starts outside the engine launch, use a
native `CreateProcessW` call with `bInheritHandles = FALSE`, not
`std::process::Command`. For the engine's `netsh` call, replace `SystemRunner`
on Windows with a native launcher that passes `bInheritHandles = FALSE` and no
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Until that change exists, rule 7.3.3 is not
met through `SystemRunner`. Rule 7.3.2, clearing the inherit flag on every
control handle, is the control that actually works today.

### 7.3 Engine side

The engine must, before it does any work and before it starts any child:

1. `GetFileType(handle) == FILE_TYPE_PIPE` for `token`, `parent`, `event`,
   `control_in`, and `control_out`. The tree now does this for `token` and
   `parent` through `seal_windows_control_handle` in `rust/src/main.rs`; the new
   command must use the same function for the other three.
2. `SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)` on every control
   handle, so the `netsh` child and any other child cannot inherit them. The
   same helper already clears the flag for `token` and `parent`.
3. Launch every child with `bInheritHandles = FALSE`. The engine's `netsh` call
   is the only child today. A test must prove that the child sees no control
   handles, using a child that reports its own handle table size.
4. Close `token` after reading the 65 bytes. Close `event` and the control
   handles only on the exit path, after the final frame.

### 7.4 Failure paths

Every launch failure closes every handle it created. A failed `CreateProcess`
must not leave an inheritable handle. A failed secret write must close the token
write end, the engine ends, and the parent write end, in that order, and then
wait a bounded time for the process it did create.

The current code closes the pending handles in most paths
(`Win32EngineHost.cs`) and closes the engine ends after a successful create. The
redesign moves creation into the critical section and wraps each handle in
`SafeHandle`, so the failure path is one `Dispose` and not a list of `if`
statements.

## 8. Process liveness and cleanup overlap

### 8.1 Who watches what

| Watcher | Watches | Action |
|---|---|---|
| Service | Engine process handle, with a blocking wait on a dedicated thread | Sets `engine_lost` only after the event pipe is drained and no final frame exists |
| Service | Event pipe frames | Records `ready`, `adapter_identity`, `final`, and the final cleanup result |
| Engine | Parent pipe end of file | Runs its own stop path and exits |
| Probe helper | Parent pipe end of file | Exits without a result; the service records a failed probe |
| App | Pipe, with one in flight request and a deadline | Shows `timeout` or `engine_unavailable` |
| Engine monitor | Source device probe silence, and the proposed unsupervised interval | Stops the tunnel with `source_device_gone` or `observation_unavailable`, tries a best-effort final frame, then exits |
| Service | `SESSIONCHANGE` for the controlling session, preshutdown, stop | Runs one bounded stop with checkpoints |

The service registers one wait on the process handle and one read on the event
pipe. The wait thread calls the same `HostLost()` transition that `EngineStartup`
already models (`EngineStartup.cs`). `HostLost` is called from a real event for
the first time. Process exit and the final event frame can race. The wait thread
does not classify the exit as a crash until it has read the event pipe to end of
file or hit a 2 second drain bound. A final frame with `cleanup=ok` and a stop
reason is a normal stop, including an automatic stop. No final frame is
`engine_lost` with `cleanup=unknown`. This is review H4.

A job object is deliberately not used with kill-on-close. Kill-on-close would
terminate the engine while it is removing routes. The parent pipe already gives
the engine a graceful stop signal when the service dies, because the operating
system closes the service handles. Removing routes is more important than
removing the process.

### 8.2 Stop sequence

The lifecycle gate is one semaphore held for the whole sequence, including the
process wait. Requests that arrive during it get `busy`, not a new transition.

1. Acquire the gate.
2. State `Stopping`. Stop accepting new starts. Write the state record with
   `phase=stopping` before closing the parent.
3. Close the parent write end. This is the only stop signal. Nothing is written.
4. Wait for the process handle, `T_cleanup = 12 s`, polling every 100 ms and
   reading event frames until end of file.
5. If the final frame says `cleanup=ok`, record `cleanup=ok`. If it says
   `cleanup=failed`, latch `cleanup_blocked`. If there is no final frame,
   record `cleanup=unknown`.
6. If the process exited: close the process handle, state `Stopped`, release.
7. If the process did not exit: do not close the process handle. Record
   `pending_cleanup` with the PID and process creation time. State
   `Stopping(waiting)`. Report `engine_stop_timeout`. A later start is refused.
   A background wait continues. Release the gate.
8. Never call `TerminateProcess`.

In the preferred split in section 4.6, the service also removes the routes it
recorded and closes the adapter after the engine exits. It does that only after
the recorded name, LUID, and GUID still match. In the prototype, the engine
removes its own routes. Both paths run after the parent close and before the
service reports `SERVICE_STOPPED` when the 12 second budget allows. A path that
cannot prove ownership leaves the latch set and reports `Present`; it does not
delete a foreign object.

Step 7 is the fix for the first review's second-engine finding. The current
close path waits 8 seconds and then closes the handle and exits
(`Win32EngineHost.cs`), which forgets that cleanup may still be running.

### 8.3 Cleanup timeout, the latch, and the state record

`cleanup_blocked` lives inside the engine process today and is lost when the
process exits (`rust/src/service.rs`, `cleanup_blocked`). The service must own
the latch across engine lifetimes, or a restart silently forgets a failed
cleanup.

The state record is `%ProgramData%\HotspotShade\engine-state.json`. It holds no
secret. It is owned by `SYSTEM`, has a protected DACL, and is written only after
the service verifies the directory owner, the absence of a reparse point, and
the final path (section 4.5).

Schema, version 1:

| Field | Meaning |
|---|---|
| `v` | Record version, 1 |
| `seq` | Monotonic record sequence, increments on every write |
| `phase` | `never_launched`, `launching`, `launched`, `adapter_ready`, `running`, `stopping`, `stopped`, `cleanup_failed`, `cleanup_unknown` |
| `intent_id` | Random id minted before the launch |
| `launch_nonce` | Random value written only to the child over a descriptor. It is never on a command line. It is reserved for an approved orphan proof and is not used for adoption. |
| `launch_started_100ns` | System time, in the `GetProcessTimes` unit, written just before `CreateProcess`. It opens the launch window in the recovery rule. |
| `engine.pid` | Engine PID, absent before `CreateProcess` returns |
| `engine.created_100ns` | `GetProcessTimes` creation time, absent before the process exists |
| `engine.image` | Installed engine path |
| `adapter.name` | Exact adapter name chosen before the launch. It is unique per intent. |
| `adapter.guid_planned` | A fresh random GUID minted per intent before the launch and passed to Wintun as the requested adapter GUID. It is an intent marker. It is not ownership proof. |
| `adapter.luid`, `adapter.guid` | Observed adapter identity, absent until the engine or service reports it |
| `adapter.identity_source` | `planned`, `observed`, or `missing` |
| `routes` | Exact managed prefixes: `0.0.0.0/1`, `128.0.0.0/1`, `2000::/3` |
| `routes_may_exist` | 0 or 1. It is set to 1 before the engine is allowed to install a route. It is the crash-recovery gate. |
| `cleanup` | `ok`, `failed`, `pending`, `unknown` |
| `updated_at` | Unix seconds |

#### 8.3.1 The planned GUID (E5)

`WintunCreateAdapter` takes a requested GUID. Standard per the Wintun API, to
be proven at R23: the adapter is created with that GUID, or the call fails. The
service mints a fresh random GUID for every intent and writes it as
`adapter.guid_planned` before `CreateProcess`.

Rules:

- A fresh GUID per intent makes a leftover adapter from an earlier intent
  distinguishable from this one. A fixed GUID per install would not: every
  intent would look the same after a crash.
- A live adapter whose GUID equals `guid_planned` proves only that some process
  created an adapter with the value this intent planned. It does not prove that
  this intent created it, and it does not prove which routes belong to it. The
  absence proof treats it as `Present` (the adapter exists) or `Inconclusive`
  (the read is incomplete). It is never `Clean`.
- No live adapter with `guid_planned` and no adapter with the exact planned
  name is the only planned-GUID result that can contribute to `Clean`, and only
  under the `routes_may_exist=0` rule in section 8.4.
- If Wintun returns an adapter with a different GUID, the service records the
  observed value, keeps `guid_planned`, and treats the mismatch as
  `Inconclusive` until `recheck`.

Cost: Windows network location awareness keys a network profile to the adapter
GUID. A fresh GUID per intent can add one network profile per tunnel start.
Whether profiles accumulate, and whether they need cleanup, is measured at R23.
The trade-off between unambiguous recovery and profile accumulation is part of
O19.

#### 8.3.2 Launch gate instead of a suspended launch (E6)

Two ways can record the PID before the engine can act:

| Way | What a service crash at the bad moment leaves | Verdict |
|---|---|---|
| `CREATE_SUSPENDED`, write PID and creation time, then `ResumeThread` | A suspended engine that never runs its parent-loss watcher. It holds its inherited handles and stays until reboot or until someone terminates it. If the crash came before the PID write, the new service can find it only by image path, which is the B3 problem. | Not chosen |
| Launch gate: the engine starts normally, reads its descriptors, and waits for `go` on `control_in` before it does anything with an effect | An engine that sees the parent pipe close and exits by itself. It never opened Wintun, an outer socket, or a route API. | Chosen |

Before `go`, the engine may only parse its fixed arguments, seal its handles,
read the bearer and the nonce, and wait. It must not load or call Wintun, open
an outer socket, send a probe, or call a route or address API. It waits for `go`
for at most 10 seconds. If `go` does not arrive, or the parent pipe closes, it
exits with no final frame and no effect. Test V101 checks that no Wintun, socket,
or route call happens before `go`. V102 checks the self-exit.

PID is not identity. The service holds the process handle from `CreateProcess`
and records the creation time from `GetProcessTimes` on that handle. A later
check opens the PID and compares the creation time. A different creation time is
PID reuse.

#### 8.3.3 Write ordering

Write ordering is the core of the crash fix. Every write flushes a temp file,
then replaces the record with `MoveFileExW` using `MOVEFILE_REPLACE_EXISTING |
MOVEFILE_WRITE_THROUGH` on the same volume. Do not rely on `ReplaceFileW`'s
write-through flag; it is not supported.

1. Choose a unique adapter name, a fresh `guid_planned`, a fresh `intent_id`, and
   a fresh `launch_nonce`. Write `phase=launching`, the name, `guid_planned`,
   the prefixes, `launch_started_100ns`, `routes_may_exist=0`,
   `adapter.identity_source=planned`, and no PID. Only then create the pipes and
   the process. The process is not suspended. The nonce travels over a
   descriptor, never on the command line.
2. Immediately after `CreateProcess` returns, write the PID and the
   `GetProcessTimes` creation time with `phase=launched`. `routes_may_exist`
   stays 0. If this write fails, the service does not send `go`. It closes the
   parent, waits up to 12 seconds for the gated engine to exit, and reports
   `launch_failed`. No adapter or route can exist for this intent.
3. Send `go`. The engine creates the adapter with the planned name and
   `guid_planned` and sends `adapter_identity` with the name, LUID, and GUID
   before it installs any route. The service writes `phase=adapter_ready`, the
   LUID and GUID, `identity_source=observed`, and `routes_may_exist=1`. It writes
   the record before it sends the `install_routes` acknowledgement. If the write
   fails, it does not send the acknowledgement. The engine must not install a
   route without it.
4. The engine installs the routes and reports `ready`. The service writes
   `phase=running`. The route gate is pessimistic: a crash after step 3 and
   before the routes exist is still treated as "routes may exist".
5. On the final frame, write `phase=stopped` and `cleanup=ok` or
   `cleanup=failed`, with the stop reason. With no final frame, write
   `cleanup=unknown` (section 8.8).
6. On a normal service stop with no engine, write `phase=stopped`.

So `go` permits the adapter and nothing else, and the `install_routes`
acknowledgement permits the routes. Each permission follows a durable record
that names what it may create.

The preferred split in section 4.6 moves the adapter and the routes to the
service. The service then creates the adapter with `guid_planned`, records the
observed identity, and installs the routes before it sends `go`, and `go` lets
the engine start its data plane only. The fallback handshake above stays so that
B2 and E5 are answered even if the split is rejected. Neither order is
implemented.

#### 8.3.4 Recovery on service start

- `phase=never_launched` and `cleanup=ok`: no engine has ever run. A start is
  allowed without a route check.
- `phase=launching` with no PID: the service may have crashed before
  `CreateProcess` or before the PID write. No `go` was sent, so a correct engine
  created nothing. The orphan rule in section 8.7 runs: a candidate is only a
  `LocalSystem` process of the installed image created inside the launch window.
  The service waits up to 12 seconds for each candidate to exit, because a gated
  engine exits on parent loss. Then it reads the adapter table for the exact
  planned name and `guid_planned`. No adapter and no live candidate is `Clean`
  for the route scope. A present adapter is `Present`. A candidate still alive
  after the wait is `cleanup_pending`; that is evidence of a gate defect, not of
  an attacker.
- `phase=launched` with a PID and creation time: no `go` was proven to reach the
  engine, but the service may have sent it just before the crash. Open the
  process, compare the creation time, and wait up to 12 seconds while it lives.
  Then read the adapter table for the planned name and `guid_planned`. No
  adapter is `Clean` for the route scope, because no `install_routes`
  acknowledgement was possible while `routes_may_exist=0`. A present adapter is
  `Present`.
- `phase=adapter_ready` with a PID and a complete LUID and GUID: the service
  opens the process, compares the creation time, waits while it lives, and
  requires `recheck` after it exits. The new service cannot read the old event
  pipe, so it does not assume the old cleanup result.
- `phase=running` with a PID and creation time: open the process with
  `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`, compare the creation time,
  and wait if it is the same process. While it waits, the service reports
  `cleanup_pending` and refuses a start. The old parent pipe is already closed,
  so the engine should run its own stop path. A different creation time is PID
  reuse; treat the old engine as gone and set `cleanup=unknown`.
- `phase=adapter_ready` or `phase=running` with a missing LUID or GUID is
  `Inconclusive` for the normal absence proof, but not automatically clean. The
  service may read the adapter by the exact recorded name and `guid_planned` and
  record the identity only when the name, the GUID, the adapter type, and the
  absence of a live engine agree. If it cannot, the latch stays and O7b is the
  recovery path.
- A missing, unreadable, or version-mismatched record is `cleanup=unknown`.
  Never default to `cleanup=ok` in code.
- A record that says `cleanup=failed`, `cleanup=pending`, or `cleanup=unknown`
  keeps the latch. A start is refused until `recheck`.

The engine tries to write one final event frame before exit: `final cleanup=ok`
or `final cleanup=failed reason=<fixed token>`. The write is best effort
(section 8.8). The service latches `failed` in memory and in the state record
only from a received `cleanup=failed` frame. A start while the latch is set
returns `cleanup_blocked`. A missing frame is `cleanup=unknown`, which also
refuses a start until `recheck`, with a different message. The app shows a
person actionable message and disables Start.

### 8.4 Recovery evidence and the latch

The latch clears only through `recheck`, which runs a read-only absence proof.
The existing `rust/src/windows_route_verify.rs` proves that expected routes are
present and owned. It does not prove absence. Revision 2 adds a new pure layer,
`verify_absence`, with a live observation layer.

`verify_absence` takes the recorded adapter name, LUID, GUID, route prefixes,
and `routes_may_exist`. It returns one of:

- `Clean`: no recorded prefix is bound to the recorded adapter LUID or GUID, and
  the recorded adapter is absent. When `routes_may_exist=0`, the route scope may
  be `Clean` if no adapter with the exact recorded name exists; no route was
  installed by this intent. The result says `routes=clean, adapter=absent` and
  does not claim a general route check.
- `Present`: at least one recorded route or the adapter is still present. The
  result names the prefix and the adapter GUID or exact name so the person can
  inspect it. No secret is included.
- `Inconclusive(reason)`: a table read failed, the IPv6 stack is absent, the
  record does not hold a complete adapter identity and every managed prefix,
  `routes_may_exist=1` without a LUID or GUID, or the evidence is not complete.
  The latch stays.

A `launching` or `launched` record always holds the planned adapter name,
`guid_planned`, and the managed prefixes. It has no observed LUID or GUID. With
`routes_may_exist=0`, that is enough to prove that this intent installed no
route, but it is not enough to prove a general route absence. The service reads
the adapter table for the exact name and for `guid_planned`. If neither exists,
the route scope is clean. If either exists, the result is `Present` and the latch
stays. If a read fails, the result is `Inconclusive`. A planned GUID match is
never `Clean`. This is the B2 and E5 rule.

Reads:

1. `GetIpForwardTable2(AF_INET)` and `GetIpForwardTable2(AF_INET6)`. For each
   recorded prefix, search for a row with the same prefix and the recorded
   `InterfaceLuid` or a matching `InterfaceIndex` whose LUID is also recorded.
   A matching row is `Present`.
2. `GetIfEntry2` by the recorded LUID. `ERROR_NOT_FOUND` is adapter absence.
   Any other error is `Inconclusive`.
3. `GetAdaptersAddresses` searches for the recorded GUID or name. A match is
   `Present`. A read error is `Inconclusive`.
4. On a host with no IPv6 stack, the IPv6 table read fails. That is
   `Inconclusive` for the IPv6 route, not `Clean`. `rust/src/windows_route_verify.rs`
   already warns that an API error must not become a success.
5. `recheck` never changes a route and never deletes an adapter.

A permanent latch is a lockout, so there is a designed manual recovery path:

- The app's Advanced panel shows the `recheck` reason and the recorded adapter
  GUID and prefixes. It offers `Copy evidence`.
- An elevated administrator can run `HotspotShade.ServiceRepair.exe --inspect`
  to print the same evidence and the live matching rows. It changes nothing.
- If the evidence is inconclusive and the person has independently inspected the
  table, the administrator can run
  `HotspotShade.ServiceRepair.exe --acknowledge-cleanup-unknown`. That writes
  the observed route and adapter snapshot to the state record, records the
  administrator account and a fixed acknowledgement string, and only then
  clears the latch. It never deletes a route. It is an explicit override, not
  an automatic recovery.
- The override is a product and security decision. It is open decision O7 and
  needs maintainer approval. Without it, an inconclusive check keeps the latch
  forever, and that is not an acceptable shipped behavior.

The repair tool is not part of this design's implementation. It is a named
requirement for the implementation phase and for G4.

### 8.5 Wintun adapter after an engine crash

Normal cleanup removes the routes first and closes the adapter second. A hard
crash runs neither path. Whether the Wintun adapter, and the device-bound routes
that belong to it, disappear when the engine process dies is not stated in the
tree. It is a hypothesis, H1.

If the adapter survives, no process holds its handle, and no path removes it.
`recheck` must then prove adapter presence by the exact recorded name and, when
known, GUID, and keep the latch. The manual recovery path above is the only way
out. A live Windows test must answer H1 before any claim that a crash leaves no
adapter. Do not assume `WintunCloseAdapter` semantics apply to a process that
never called it.

The preferred split in section 4.6 changes this answer. If the service owns the
adapter handle, the service can close it after the engine exits and after it
proves the recorded name, LUID, and GUID still match. That removes the
device-bound routes through the adapter close. The service must not close a
foreign adapter, and it must not claim that device-independent routes disappear.
This is still a hypothesis, not a capability. Test V90 is the first check.

### 8.6 Service stop, preshutdown, checkpoints, and logoff (E8)

#### 8.6.1 Controls the service accepts

The service reports `SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN |
SERVICE_ACCEPT_SESSIONCHANGE` once the pipe listens. It also accepts
`SERVICE_ACCEPT_SHUTDOWN` only as a fallback that writes the record without
waiting (section 8.6.4). It accepts no pause, no parameter change, and no power
event that changes behavior.

The installer sets `SERVICE_CONFIG_PRESHUTDOWN_INFO` with
`dwPreshutdownTimeout = 20000` milliseconds through `ChangeServiceConfig2`. Do
not rely on the default; it differs between Windows versions. The value bounds
how long this service can delay a system shutdown. Twenty seconds covers the 12
second cleanup wait, the 2 second drain, and a 2 second record margin. Whether
the host honors the value is measured at R24.

#### 8.6.2 Checkpoints

The SCM treats a pending service as hung when `dwCheckPoint` does not advance
inside `dwWaitHint`. The service never reports one long hint and then goes
silent.

- `SERVICE_START_PENDING`: report checkpoint 1 at entry with a 3000 ms hint.
  Advance the checkpoint after the state record read, after recovery, and after
  the pipe listens. Report `SERVICE_RUNNING` only when the pipe listens.
  Recovery that waits for an old engine reports `SERVICE_RUNNING` first and
  serves `cleanup_pending`; it does not hold the start pending for 12 seconds.
- `SERVICE_STOP_PENDING`: report a 3000 ms hint and advance the checkpoint once
  per second while a bounded step is in progress: session close, parent close,
  the 12 second process wait, the 2 second drain, the record write. The total
  stays inside 20 seconds. A checkpoint advances only while the service is
  inside a bounded step; it is never used to extend an unbounded wait.
- If the total budget expires, the service writes `cleanup=pending` and reports
  `SERVICE_STOPPED`. It never calls `TerminateProcess`.

#### 8.6.3 `SERVICE_CONTROL_STOP`

1. Report `SERVICE_STOP_PENDING` with checkpoints as above.
2. Close the app session. Record `stop=service_stop`. Do not run a second stop
   path when the pipe break arrives.
3. Run the stop sequence.
4. If the engine exited, `SERVICE_STOPPED`.
5. If it did not, the state record already holds `pending_cleanup`. At the end
   of the budget report `SERVICE_STOPPED` and leave the engine alive. A later
   service start reads the record, finds the engine by PID and creation time,
   and refuses to start a second engine until that process exits.

A start request that is in flight when the stop arrives is cancelled; the
service does not wait for the app's 25 second start budget. If the start already
launched an engine, that engine is closed through the parent pipe and observed
under the 12 second wait. A gated engine that has not received `go` exits at
once. The service never returns `SERVICE_STOPPED` while it still owns a control
handle it has not closed.

#### 8.6.4 Preshutdown and shutdown

`SERVICE_CONTROL_PRESHUTDOWN` runs the same stop path with
`stop=shutdown`, inside the 20 second preshutdown timeout. The handler returns at
once and the stop runs on a worker thread. The preshutdown checkpoints follow
section 8.6.2.

`SERVICE_CONTROL_SHUTDOWN` arrives only if preshutdown did not finish or did
not run. The handler does not wait for the engine. If the record does not
already say `stopped`, it writes `phase=stopping` and `cleanup=pending` and
returns. The engine sees its parent pipe close when the service process ends and
runs its own stop path if the system gives it time. The next boot reads the
record and requires `recheck`.

#### 8.6.5 Session logoff

The service handles `SERVICE_CONTROL_SESSIONCHANGE`. The handler returns at
once and acts on a worker thread.

- The controlling session id is `TokenSessionId` from the client token at
  `hello` (section 5.3 step 9). It is not taken from the app's claim.
- `WTS_SESSION_LOGOFF` whose `WTSSESSION_NOTIFICATION.dwSessionId` equals the
  controlling session id runs the stop path with `stop=session_logoff`.
- A logoff of any other session is ignored. Another person signing out does not
  stop this person's tunnel.
- `WTS_SESSION_LOCK`, `WTS_SESSION_UNLOCK`, `WTS_CONSOLE_DISCONNECT`,
  `WTS_REMOTE_DISCONNECT`, and the connect events do not stop the tunnel. A
  disconnected session still has a live app and a live pipe. See O25 for the
  fast user switching consequence.
- During logoff, Windows also ends the app, so the pipe breaks. The first of the
  two events starts the one stop and sets the reason. A later logoff
  notification for the same session is recorded as an event and does not
  change the reason or start a second stop. Test V105 accepts either reason and
  requires exactly one stop.
- Logoff does not stop the service process, so the stop is not bounded by a
  logoff timeout. It uses the normal bounded stop: 12 seconds of cleanup, 2
  seconds of drain, and the record write.

On resume from sleep, the process handle and the state record remain valid. The
adapter and routes may be stale. The service does not restart anything. The app
shows `unknown` until a fresh status and a successful `recheck`. This is
hypothesis H2 and needs a Windows sleep/resume test.

### 8.7 Second engine prevention

Four independent reasons a second engine cannot start:

1. The service is the only launcher, and the SCM runs one instance.
2. The service refuses `start` while the cleanup latch is set,
   `pending_cleanup` is set, or `cleanup=unknown`.
3. On service restart, the state record plus PID and creation time identify the
   previous engine and the service waits for it.
4. A `launching` record without a PID runs the orphan rule below before any new
   launch.

The orphan rule (E7). The service enumerates processes whose final image path
is the installed engine binary and sorts each one:

| Process | Treatment |
|---|---|
| Matches the recorded PID and creation time | The previous engine. Wait for it. Blocks a start while it lives. |
| Token user is `SYSTEM`, and creation time is inside the launch window (`launch_started_100ns` to the service start) | A candidate gated engine. Wait up to 12 seconds for it to exit. If it is still alive, report `cleanup_pending` and refuse a start. |
| Token user is anything else, including the interactive user | Recorded in the event log as `foreign_engine_image`. Receives no frame. Is never adopted. Never blocks a start. |
| `SYSTEM` token but created outside the launch window | Recorded. Never adopted. Does not block. It cannot be an engine of the recorded intent. |

Why this closes the denial of service: a standard user can run a copy of the
installed engine image, because the install directory grants read and execute.
That process runs with the user's token, not `SYSTEM`, and the service ignores
it for blocking. A same-user process cannot create a `SYSTEM` process. An
administrator can, and is out of scope. Reading the token user of another
process is a service capability (`OpenProcess` with
`PROCESS_QUERY_LIMITED_INFORMATION`, then `OpenProcessToken` with
`TOKEN_QUERY`). A process whose token cannot be read is recorded and treated
like the third row; S44 and V103 test both rows.

Adoption by image path is not used. Adoption needs the nonce proof and is not
approved (O21).

The engine also holds the Wintun adapter name. That is not used as a lock,
because `WintunOpenAdapter` can attach to an existing adapter, so it does not
prove exclusivity. In the preferred split the service holds the adapter handle
and the route ownership; the engine's handle is not a lock.

### 8.8 Engine crash and normal automatic stop

A normal automatic stop is not a crash. The engine monitor decides
`source_device_gone` or `observation_unavailable`, stops the relay and routes,
tries to write a final frame with `cleanup=ok` and the stop reason, and exits.
The service drains the event pipe, records `Stopped(<reason>)`, keeps the app
session, and keeps Start available after the credential rules in section 11.4.
It does not set the cleanup latch and does not report `engine_lost`.

The final-frame write is best effort and nonfatal (E9):

- The engine finishes every cleanup step before it tries the write. Cleanup
  never depends on the event pipe.
- The write has a 1 second bound through the writer thread in section 6.2.
- A failed write (`ERROR_NO_DATA`, `ERROR_BROKEN_PIPE`, a timeout, or any other
  error) is ignored. It does not change the exit path, it does not skip a step,
  it is not logged as a cleanup failure, and it does not change the process exit
  code.
- On parent loss the service may already be gone, so a failed write is the
  expected case. On a normal automatic stop the service is reading, so the write
  usually succeeds.

On the service side:

- A received `cleanup=ok` frame is a normal stop.
- A received `cleanup=failed` frame sets the latch. This is the only input that
  sets it.
- No frame after the 2 second drain is `cleanup=unknown`, never
  `cleanup=failed`. It refuses a start until `recheck`, and a clean `recheck`
  clears it without the administrator override.
- The process exit code is recorded for diagnostics only. It never turns
  `unknown` into `ok`.

Detection of a crash: the process wait fires and the event pipe reaches end of
file with no final frame, after the 2 second drain bound.

Actions:

1. `HostLost()`: state `Failed(engine_lost)`, session closed, ensure cache
   cleared.
2. No relaunch. The app shows "The engine stopped answering. The tunnel state is
   unknown." Start stays disabled until `recheck` proves the route table is
   clean, or proves that owned routes or the adapter remain and keeps the latch.
3. A crash can leave routes or an adapter behind, because cleanup did not run.
   This is why the absence proof and hypothesis H1 exist. The app must not claim
   "off" on an engine loss.
4. If a final frame says `cleanup=failed`, that is a normal stop with a failed
   cleanup, not a crash. The latch is set and the stop reason is preserved.
5. In the preferred split, the service still holds the adapter and the route
   record. After the engine exits it may remove the recorded objects and then
   run `recheck`. It does not assume the engine cleaned up. In the prototype the
   engine owned both, so `recheck` is the only path. Neither behavior is proven
   on a Windows host.

The distinction matters for review H4 and E9: a process exit alone is not proof
of a crash, a final frame alone is not proof that the process exited cleanly, a
missing frame is not a normal stop, and a missing frame is not a failed
cleanup. V92, V93, and V106 exercise the races on a fake engine. T3.24 checks the
engine side.

### 8.9 App session loss

The pipe breaks. The service runs the stop sequence with reason `parent_lost`,
then returns to idle. Once the engine has exited and no session is live, the
service reports `SERVICE_STOPPED` and exits. It does not relaunch. It does not
keep the tunnel. This is the invariant 13 rule and it matches the macOS helper
behavior. Phase 1 clears the in-memory credential when the session ends. A
restarted app must enter it again.

In this path the service is alive and reading the event pipe, so the engine's
final frame usually arrives. If the service itself was lost, the engine's write
fails and is ignored (section 8.8). The next service start then finds
`phase=running` and requires `recheck`; it does not read the missing frame as a
cleanup failure.

### 8.10 Session and SCM timeout precedence

The service has several timers that can overlap. One table fixes the order and
the owner of each decision. No timer starts a process or a tunnel.

| Event | Bound | Winner | Result |
|---|---|---|---|
| App connects and sends `hello` | 5 s from accept, covering the unparsed first-frame read and the impersonation check | Session | No `hello` closes the connection with no reply. No session is bound. |
| Request deadline | Per section 12 | Request | The request returns `timeout`; one in-flight request is closed. If a tunnel is live, the pipe break runs `parent_lost`. |
| Person start | 25 s | Start request | Engine launch is 20 s. If launch finishes late, the late result is discarded and the generation is failed. It is not adopted by a later request. |
| Engine launch | 20 s | Service | `launch_timeout`; every handle created for the attempt is closed; no engine is left unobserved. |
| Engine cleanup | 12 s | Service | `engine_stop_timeout`; the handle is kept; `pending_cleanup`; a start is refused. |
| Event drain after process exit | 2 s | Service | A final frame found in the drain sets the normal stop. No frame sets `engine_lost` and `cleanup=unknown`. |
| App loss | Immediate | Service | `parent_lost` stop. No reconnect grace. |
| SCM stop | 20 s total, 3 s hint, checkpoint every 1 s | SCM | Close the session, run one stop, write the record, return `SERVICE_STOPPED`. This wins over a pipe break. |
| SCM preshutdown | 20 s `dwPreshutdownTimeout`, set by the installer | SCM | Stop accepting, run the same stop with `stop=shutdown`, write the record. Do not wait forever for a hung engine. |
| SCM shutdown (fallback) | No wait | SCM | Write `cleanup=pending` if the record is not `stopped`. Return at once. |
| Controlling session logoff (`SESSIONCHANGE`, matching `TokenSessionId`) | Normal bounded stop | First of logoff or pipe break | One stop, `stop=session_logoff` or `parent_lost`. Do not restart. Other sessions and lock or disconnect events are ignored. |
| Launch gate | 10 s from engine start to `go` | Engine | No `go`: the engine exits with no effect and no final frame. |
| Unsupervised interval (proposed, O23) | 300 s since the last `Accepted` answer | Engine monitor | Stop with `observation_unavailable`, final frame best effort. |
| Final-frame write | 1 s | Engine | A failed write is ignored. The service records `cleanup=unknown` if no frame arrives. |
| Service restart with a live engine | 12 s observation window, then record | State record | `cleanup_pending`; no second engine; `recheck` after exit. |

Rules:

- The SCM path is one stop, not two. A pipe break that arrives during the SCM
  stop is folded into `stop=service_stop` or `stop=shutdown`.
- A stop that cannot finish inside the 20 second budget writes `cleanup=pending` and
  returns. It does not call `TerminateProcess`.
- A start that loses the race to a stop is cancelled. It never leaves a child
  behind and never writes a `running` state after the stop has begun.
- The app treats a broken pipe during a stop as `stopping`, not as `engine_lost`.
  It re-reads the service state with a bounded retry after the SCM stop.
- No timeout path starts, restarts, or retries anything. Only a person action
  can start a new generation.

## 9. Safe retries

A launch attempt is a generation.

- `g` increments on every explicit retry.
- Each generation creates new pipes, a new handle list, a new plan, and a new 64
  character bearer. Nothing is reused.
- Every asynchronous result carries `g`. A result from `g-1` is discarded and
  its handles are closed. That is the fix for the current "close the host and
  never launch again" behavior.
- A retry is accepted only from `Idle`, `Failed`, or after `pending_cleanup`
  resolves and `recheck` returns clean. It is refused with `busy` while a
  launch is in flight.
- A retry is refused with `cleanup_blocked` while the latch is set, and with
  `cleanup_unknown` while the record is unknown. A matching image-path process
  is observed, never adopted; the retry waits until it exits and `recheck`
  passes.
- At most one launch attempt per 2 seconds, measured at the service, so a click
  loop cannot create a process storm.
- A terminal success is cached for the generation. A terminal failure is cached
  for the generation so a poll does not relaunch. An explicit retry clears it.
- A host loss clears the cache and increments `g`. A status poll never launches.

The current `RetryAsync` is not reused. It ends in `Closed` because
`CloseHostAsync` sets `closed` permanently (`Win32EngineHost.cs`,
`EngineStartup.cs`).

## 10. No auto-restart

Explicit rules, each with a test:

1. No SCM recovery action. The installer sets `SC_ACTION_NONE`.
2. No timer retry. `RetryAsync` is only reachable from a person action.
3. No relaunch on `engine_lost`.
4. No relaunch on source device return.
5. No launch on `hello` or `status`.
6. No keep-running flag, no tray auto-start, no service auto-start.
7. The service exits when the app is gone and the engine has exited.

A tunnel that stops for `source_device_gone`, `observation_unavailable`,
`gateway_changed`, `link_changed`, or `session_logoff` stays stopped. A positive
answer that arrives after an `observation_unavailable` stop does not restart it.
The app may offer a Start button. It never starts on its own. Windows has no
`hotspot_lost` stop and the app must not show one. A normal automatic stop is a
stop, not a crash, and it never triggers a restart. The service monitor contract
in section 6.1 is the behavior model. The Windows CLI silence path and the
in-progress GUI `LinkWatch` change are inputs to it, not models, and neither has
the unsupervised bound.

## 11. Status and pairing coherence

### 11.1 Status schema

The service replies with a fixed schema. It is built from the engine status and
the service state. It is not a passthrough of the engine JSON. The current
`EngineStatus`, `EngineWire`, and `EngineLocal` shapes are inputs, not the wire
contract. The service maps known fields, drops unknown fields, and refuses a
shape that breaks the consistency rules.

| Field | Type | Meaning |
|---|---|---|
| `v` | int | Protocol version, 1 |
| `instance` | token | Service instance id, minted on every service start |
| `engine` | word | `unavailable`, `starting`, `ready`, `running` |
| `running` | 0/1 | A live tunnel confirmed by a fresh engine status |
| `mode` | word | `phone` or `none` |
| `paired` | 0/1 | The service holds an in-memory credential for this session |
| `paired_scope` | word | `none`, `session` (phase 1), `identity` (phase 2) |
| `source` | 0/1 | The last presence check succeeded and is fresh |
| `trusted` | 0/1 | The last fresh check was `Accepted`. In phase 1 this means only that the peer at the gateway address accepted the token; a different device can accept any token. In phase 2 the answer is authenticated. |
| `checked_at` | int or empty | Unix seconds of the last presence check |
| `ping` | 0/1 | Echo relay setting |
| `icmp_enabled` | 0/1 | The echo relay is on in phone mode |
| `phone.connections` | int or empty | The connection count reported in the source device's authenticated pairing status answer. Available only when that answer exists (phase 2). Empty in phase 1 manual mode and when no fresh answer exists. |
| `phone.connections_known` | 0/1 | False when `phone.connections` is empty. It says nothing about the target-side relay count. |
| `relay.tcp_flows_active` | int or empty | Target-side count of open TCP relay flows, from the live `tcp_flows_active` gauge. This is not a source device connection count. It is empty when no live engine status exists, not `0`. |
| `relay.tcp_flows_active_known` | 0/1 | False when the target-side gauge is unavailable or no live engine status exists |
| `ttl_bad` | int | Count of outer sockets whose TTL read-back was wrong |
| `ipv6_dropped` | int | Count of inner IPv6 packets dropped by policy |
| `fragments_dropped` | int | Count of fragments dropped |
| `stop` | word | `none`, `user`, `source_device_gone`, `observation_unavailable`, `gateway_changed`, `link_changed`, `engine_lost`, `start_failed`, `parent_lost`, `service_stop`, `shutdown`, `session_logoff`, `unknown`. `link_unknown` is a refusal code for `credential.set` and `start`, not a stop reason: an unreadable identity during a run is `Unavailable` evidence (section 6.1). |
| `stop_at` | int or empty | Unix seconds of the last stop |
| `cleanup` | word | `ok`, `failed`, `pending`, `unknown`; `ok` only after a final frame or `never_launched` |
| `admin` | 0/1 | The engine process token is elevated |

Dropped at the service, never sent to the app: `logs`, `error` free text,
`iface`, raw `stats`, `platform.default_iface`, `started_at`, addresses, ports,
paths, handle values, the bearer, the credential, the identity key.

`ttl_bad` is the number from the normalization audit. Invariant 1 requires the
tunnel to keep `ttl_bad == 0` visible. A status that omits it is not acceptable.
`ipv6_dropped` and `fragments_dropped` come from the same relay counters and are
numbers only.

`paired_scope=session` means the credential exists only in service memory and
dies with the session or service. `paired_scope=identity` is the phase 2 value
and means the credential is bound to a source device identity. The app must not
show "saved" for `session`.

The two counts are different and must never be substituted for each other.
`phone.connections` comes from the source device's authenticated pairing status
answer, as `Presence.connections` does in `rust/src/gui_backend.rs`. It is the
count the source device reported and is empty when that answer is unavailable or
the source is not paired. `relay.tcp_flows_active` is the target-side live relay
gauge from `rust/src/relay.rs`. A target-side relay is not a source device
connection. The app labels them separately: "source device connections" and
"local relay flows". If the source status is stale or missing, or the mode is
phase 1 manual, `phone.connections` stays empty and `phone.connections_known=0`.
Do not fill it with the target-side gauge.

When `running=0`, there is no live engine status. Both counts are empty and both
known flags are 0. Do not publish `relay.tcp_flows_active=0` as if a stopped
engine had confirmed zero flows. A stopped engine can have half-closed flows or
no engine at all; the honest value is unknown. The app shows "not running", not
"0 local relay flows". When a live engine reports zero open flows while
`running=1`, `relay.tcp_flows_active=0` and `relay.tcp_flows_active_known=1` are
correct. This is the B5 correction.

### 11.2 Engine to wire mapping

The engine must return a machine code on every error. Today it partly does:
`start_error` in `rust/src/gui_backend_windows.rs` returns fixed tokens, and
`phone_token_rejected` already goes out with a `code` in `rust/src/gui.rs`. The
gap is `cleanup_blocked`, which `rust/src/service.rs` returns as
`io::Error::other` and `start_error` maps to `service_start`, plus the generic
`error()` body, which has no `code`.

This is a required engine contract change, smaller than revision 1 described.
Add `code` beside the existing `error` text; do not remove the text until every
client maps the code. Add a typed `cleanup_blocked` error.

| Engine condition | Engine code | Wire code | App text | Start |
|---|---|---|---|---|
| Status ok | none | none | current state | - |
| Engine not running | none | `engine_unavailable` | "The engine is not running. Turn the tunnel on to start it." | yes |
| Engine starting | none | `starting` | "Starting the engine." | no |
| Start ok, tunnel live | none | none | "On" | - |
| Cleanup latch set | `cleanup_blocked` | `cleanup_blocked` | "An earlier tunnel did not clean up its routes. Open Advanced, check the routes, then try again." | no |
| Cleanup result unknown | `cleanup_unknown` | `cleanup_unknown` | "The last tunnel did not report a clean stop. Check the routes before you start again." | after recheck |
| Previous cleanup unfinished | none | `cleanup_pending` | "The last tunnel is still cleaning up. Wait, then check again." | no |
| Engine token not elevated | `admin_required` | `admin_required` | "The engine service is not running with administrator rights." | no |
| `wintun.dll` missing | `wintun_missing` | `wintun_missing` | fixed install text | no |
| No credential | `manual_phone` | `manual_phone` | "Enter the source device address and token." | after credential |
| Source device rejected the token | `phone_auth` | `not_paired` | "The source device changed its token. Pair again." | after credential |
| Route setup failed | `route_setup` | `route_setup` | "The tunnel could not configure its routes." | yes |
| Tunnel setup failed | `tunnel_setup` | `tunnel_setup` | "The tunnel could not create its virtual interface." | yes |
| Start refused by the service | `service_start` | `not_ready` | "The tunnel could not start." | yes |
| Direct mode requested | `windows_phone_only` | `unsupported` | "This Windows build runs source device proxy mode only." | no |
| Bearer rejected at connect | `unauthorized` | `boundary_auth_failed` | "The app and the engine service do not trust each other. Restart the service." | no |
| Pipe name already exists at service start | none | `engine_unavailable` | "Another process is using the engine service pipe. Restart the service." | no |
| Unknown operation or field | `bad_request` | `bad_request` | fixed | no |
| Frame malformed | `bad_response` | `bad_response` | "The engine sent a status that this app does not know. The tunnel state is unknown." | no |
| Protocol version or shape mismatch | `protocol_mismatch` | `protocol_mismatch` | fixed | no |
| Request deadline | none | `timeout` | "The engine did not answer in time. The tunnel state is unknown." | no |
| Engine launch timeout | none | `launch_timeout` | "The engine did not finish starting." | yes |
| Engine stop timeout | none | `engine_stop_timeout` | "The engine is still cleaning up." | no |
| Engine process gone | none | `engine_lost` | "The engine stopped answering." | after recheck |
| Source device probe silent 90 s | none | `source_device_gone` | "The source device stopped answering." | after credential (phase 1) |
| No `Accepted` answer for 300 s (proposed, O23) | none | `observation_unavailable` | "The tunnel stopped because it could not check the source device for 5 minutes. This does not mean the hotspot or the source device is gone." | after credential (phase 1) |
| Physical gateway changed | none | `gateway_changed` | "The hotspot changed. Enter the source device address and token again." | after credential |
| Interface LUID or GUID, or a known guard value, changed | none | `link_changed` | "The hotspot changed. Enter the source device address and token again." | after credential |
| Link identity unreadable at `credential.set` or `start` | none | `link_unknown` (refusal, not a stop) | "The hotspot could not be identified. Check the connection and try again." | after link is readable |
| SCM stop | none | `service_stop` | "The tunnel service stopped." | after service start |
| SCM preshutdown or shutdown | none | `shutdown` | "Windows is shutting down." | after restart |
| Controlling session logoff | none | `session_logoff` | "The tunnel stopped because you signed out." | after sign-in and credential |
| Service not running | none | `engine_unavailable` | fixed | yes |
| Pipe auth failure at the app | none | `boundary_auth_failed` | fixed | no |
| Busy with another request | none | `busy` | "Wait for the current action to finish." | no |
| Second connection | none | `boundary_busy` | "Another app is using the tunnel service." | no |
| Forbidden field or session | none | `forbidden` | fixed | no |

Rules:

- `pipe_name_in_use` is a service event and a service-specific SCM error, not a
  wire code. The service is not running when it fires, so the app sees
  `engine_unavailable`.
- A 401 equivalent is never retried with the same bearer. It means either the
  engine restarted with a new secret or something else answered. The service
  stops the engine and re-proves the endpoint before any new request.
- A timeout is never turned into "off". The app shows unknown.
- Start is refused while `cleanup` is `failed`, `pending`, or `unknown`. The
  latch clears only through `recheck` or the explicit administrator override.
  `ok` is allowed only after a final frame or `never_launched`.
- A missing source device count is `phone.connections_known=0` with
  `phone.connections` empty, not a bad response. This is the normal phase 1
  manual state. A missing target-side gauge is
  `relay.tcp_flows_active_known=0`. Neither is filled with the other value. The
  app shows "unknown" and keeps Start and Stop enabled. The current design turns
  a missing count into `BadResponse` (`EngineLocal.cs`), which hides a real
  tunnel.
- `running` requires a fresh status. A cached sample older than 3 seconds is
  stale; older than 10 seconds is unavailable. Those thresholds already exist in
  `EngineTiming`.
- Every code in this table appears in the app mapping and in the tests. An
  unknown code is `bad_response`, never a fallback to the HTTP status.

### 11.3 Connection counts

There are two different counts. Do not merge them.

1. `phone.connections` is the connection count reported in the source device's
   authenticated pairing status answer. The Unix backend already reads it into
   `Presence.connections` in `rust/src/gui_backend.rs` through
   `pairing::status_at`. That call needs a paired identity. Phase 1 manual token
   entry uses a token check and has no such answer, so `phone.connections` stays
   empty with `phone.connections_known=0` in phase 1. Phase 2 pairing supplies
   it. It is never filled from a target-side counter.
2. `relay.tcp_flows_active` is a new, explicitly named target-side gauge. It
   comes from the existing `tcp_flows_active` atomic in `rust/src/relay.rs`. It
   counts open TCP relay flows that the target device is carrying. It is not a
   source device connection count and the app must not label it as one. It is
   published with `relay.tcp_flows_active_known`, which is 0 when the gauge is
   unavailable.

Do not compute `tcp_flows - tcp_flows_closed`. The gauge tracks the live count
at the flow open and close sites, and subtraction is not exact for a half-closed
or reset flow. UDP relays are not counted today, so the label is "local relay
TCP flows", not "connections".

If the source status is stale, or the source is not paired, `phone.connections`
is empty. If the target gauge is unavailable, `relay.tcp_flows_active` is empty.
A display that shows one in the place of the other is a bug. When `running=0`,
both are empty and both known flags are 0; a stopped state is not a zero-flow
measurement. Test T3.14 and T3.17 check the gauge against a loopback relay.
Test V45 checks that a phase 1 manual session keeps the source count unknown
while the target gauge is still shown separately, and that a phase 2 status can
supply the source count. Test V86 checks the stopped-state contradiction.

### 11.4 Pairing

Phase 1, manual credential entry. This is the only implemented path today and it
is honest to keep it labeled manual.

- The app collects host, port, and token in memory.
- `credential.set` sends them once over the authenticated pipe.
- The service validates: the host equals the current physical default IPv4
  gateway, the gateway is private, the port is 1 to 65535, the token is 1 to 255
  printable bytes, and the link identity is known. The link identity is the
  interface LUID or GUID, the interface type, and the gateway IPv4 address.
- If the link identity cannot be read, the service refuses the credential with
  `link_unknown`. It does not store a credential it cannot bind to a link.
- The service keeps the credential in a `Zeroizing` buffer in service memory
  only. It does not write a file. It does not use DPAPI. It clears the buffer
  on every tunnel stop, whatever the reason, and on app loss, engine loss,
  gateway change, link identity change, guard value change,
  `credential.forget`, and service stop. So after any stop in phase 1,
  `paired=0` and `paired_scope=none`.
- A cleared credential is not a pairing verdict. `paired=0` after
  `source_device_gone`, `observation_unavailable`, `user`, `parent_lost`,
  `service_stop`, `shutdown`, or `session_logoff` means only that phase 1 keeps
  no credential across a stop. The app shows "Enter the token again to start"
  and the stop message from section 11.2. It must not say that the source device
  rejected, forgot, or no longer trusts the target device. Only a `Rejected`
  answer supports that text. This is the E2 paired-status rule.
- `status.paired` becomes 1 with `paired_scope=session`. `source` and `trusted`
  stay 0 until a presence check runs. `phone.connections` stays empty with
  `phone.connections_known=0` because manual mode has no authenticated pairing
  status answer.
- The presence probe runs only while a tunnel is running and the app session is
  live. It is not a background loop before start. The app may run one explicit
  `probe` before start, rate limited by the service. It sends the token only to
  the stored private gateway. While a tunnel runs, the engine monitor updates
  `source`, `trusted`, `checked_at`, and, in phase 2, `phone.connections` from
  the one authenticated answer. Before start, the probe helper does the same for
  the one explicit request. Phase 1 leaves `phone.connections` empty.
- Before every probe, the probe helper or the engine checks the physical link
  identity and the guard values below against the stored values. It reads the
  physical `0.0.0.0/0` route, not `GetBestRoute2`, because the tunnel `/1`
  routes win for the gateway address. If the gateway address changed, it clears
  the credential and stops with `gateway_changed`. If the interface LUID or GUID
  or a known guard value changed, it clears the credential and stops with
  `link_changed`. If the identity cannot be read, it does not send and records
  `Unavailable`. This is review H1, E4, and hypothesis H3.
- An unreadable gateway or identity is never silence and never
  `source_device_gone`. It clears the silence interval. It does not reset the
  unsupervised interval, so 300 seconds without an `Accepted` answer stops the
  tunnel with `observation_unavailable` (section 6.1, proposed in O23). The
  revision 3 text that sent this case to `source_device_gone` was wrong, because
  it turned missing evidence into a loss claim.

#### 11.4.1 Hotspot identity evidence and its limits (E4)

The service has three kinds of evidence about which hotspot it is on. None of
them is authentication before phase 2.

| Kind | Values | Read with | What a match means | What a change means | Limits |
|---|---|---|---|---|---|
| Target-side link identity | Interface LUID or GUID, interface type, gateway IPv4 | The physical default route and `GetIfEntry2` | The target device uses the same local interface and the same gateway address | A different link: clear and stop | iPhone hotspots commonly use `172.20.10.1`. Android often reuses one private range. One Wi-Fi adapter serves every hotspot. Two hotspots routinely match. |
| Hotspot-side guard | Gateway MAC from the neighbor table (`GetIpNetEntry2`); for Wi-Fi, SSID and BSSID from `WlanQueryInterface` current connection | Service-side reads, no packet sent | Nothing positive. Any nearby device can copy an SSID, a BSSID, or a MAC. | A different access point or gateway, or the same source device after it changed its address: clear and stop with `link_changed` | Spoofable. A source device may randomize its hotspot BSSID or MAC per hotspot session, so a change can be benign; the cost is a credential re-entry, never a false loss claim. USB and Bluetooth links have no SSID or BSSID. Wi-Fi values may need location permission (below). |
| Source device answer | Phase 1: the reply to the token check. Phase 2: the authenticated pairing status answer. | The probe | Phase 1: only that the peer at the gateway accepted the token. A rogue device can accept any token, and it has already received the token in cleartext. Phase 2: the paired source device identity key. | Phase 1 `Rejected`: the credential is wrong for this peer. Phase 2 failure: not the paired device. | Only phase 2 identifies the source device. |

Rules:

- The guard is recorded at `credential.set` when it is readable, and compared
  before every probe and at `start`.
- A guard value that is not readable is `unknown`. An unknown guard value blocks
  nothing and does not make the probe `Unavailable`. It is simply not compared.
  A value that was known at `credential.set` and is unreadable later is also
  `unknown`, not a change.
- A guard match is never shown as "verified hotspot" or "same source device". The
  app may show only that the hotspot details did not change.
- Guard values are location-identifying. The service keeps them in memory only,
  with the phase 1 credential, and clears them with it. They are not in the
  status, the diagnostics, the failure record, the state record, or the event
  log.
- Wi-Fi SSID and BSSID reads may require location permission on recent Windows
  11 builds. Whether that applies to a `LocalSystem` service, and what the
  service sees when location is off, is a hypothesis for R22. If the read is
  refused, the values are `unknown`. The service never asks the person to turn
  on location for this guard.
- The gateway MAC is read from the neighbor table only. The service sends no
  ARP or neighbor probe for it, and it does not treat an incomplete entry as a
  change.

The residual case stays: two hotspots that share the gateway address, use the
same target interface, and whose guard values are equal or unknown, cannot be
told apart in phase 1. The design does not claim that they can. The bounded
exposure is that the token is memory-only, is sent only after a person action,
and is cleared on every stop. Phase 2 source device identity is the only binding
that distinguishes them.

Source token provisioning is explicit. Phase 1 has one operation,
`credential.set`, which carries the person-entered host, port, and token over
the authenticated pipe. The service validates it, keeps it in memory, and clears
it as listed above. Phase 2 replaces manual entry with `pair.begin` and
`pair.status`; the engine runs the pairing protocol and returns the result. No
token is written to disk before phase 2 proves the source device identity.

Reason for memory only: every iPhone hotspot commonly uses `172.20.10.1`. A
credential bound only to host and port would match any iPhone hotspot. A DPAPI
file would extend that exposure across reboots and service restarts. The current
presence loop already sends the cleartext token every 2 seconds while it runs.
Phase 1 must not make that exposure permanent. Report the behavior honestly: the
token crosses the hotspot link in cleartext, and the source device app compares
it in constant time.

Phase 2, real pairing. Reserved. The engine runs `rust/src/pairing.rs` against
the discovered gateway. The service exposes `pair.begin` and `pair.status` and
holds only the result that the engine returns. The app polls `pair.status`. The
token and the identity key never cross the app-service boundary. Only after a
successful pairing that proves the source device identity may the service write
an at-rest credential. The file is `%ProgramData%\HotspotShade\source-device.dat`, sealed
with DPAPI machine scope, in the protected directory, and holds the source
device identity fingerprint, host, port, and token. The app never reads it. This
is the invariant 11 end state and it is open decision O9.

The DPAPI machine scope is defense in depth, not the main control. A file in the
protected directory already has a `SYSTEM`-only DACL, and machine-scope DPAPI
adds little against an administrator. The design says so rather than claiming
that DPAPI is what protects the credential. The file DACL and the identity
binding are the controls that matter.

The target identity key is `%ProgramData%\HotspotShade\identity.key`. It is
created only in phase 2, with the same protected directory checks, a
`SYSTEM`-only DACL, and the same-volume replace. The app never reads it. It is
not written in phase 1. The service loads it only for pairing and status.

The manual path is not removed when pairing lands. It stays as the fallback for
a source device that has no pairing responder, and it stays memory only.

### 11.5 Consistency rules

Reuse `EngineRules.IsConsistent` and add:

- `running` requires `paired`.
- `running` requires `stop=none`.
- `running` requires `phone.connections_known=1` or an explicit unknown marker;
  an unknown source device count is allowed and does not invalidate the status.
- `running` requires `relay.tcp_flows_active_known=1` or an explicit unknown
  marker; an unknown target gauge is allowed and does not invalidate the status.
- `!paired` requires `source=0` and `trusted=0`, and `paired_scope=none`.
- `paired_scope=session` requires `paired=1` and no at-rest claim.
- `!running` requires `phone.connections` empty and `relay.tcp_flows_active`
  empty. Both known flags are 0. A stopped status does not publish a confirmed
  zero for either count.
- `phone.connections_known=0` requires `phone.connections` empty.
- `relay.tcp_flows_active_known=0` requires `relay.tcp_flows_active` empty.
- `phone.connections_known=1` requires a fresh phase 2 authenticated status
  answer. It is never satisfied by `relay.tcp_flows_active` or by a phase 1
  manual token check.
- `relay.tcp_flows_active_known=1` requires a fresh live engine status. It is 0
  when the tunnel is stopped or the engine is unavailable.
- `cleanup != ok` requires `running=0`.
- `engine=unavailable` requires `running=0`, `phone.connections_known=0`, and
  `relay.tcp_flows_active_known=0`.
- `ttl_bad` is always present and is a non-negative integer.
- `stop=gateway_changed` or `stop=link_changed` requires `paired=0` and
  `source=0`. `link_unknown` is never a `stop` value.
- `stop=source_device_gone` and `stop=observation_unavailable` do not require
  `cleanup!=ok`; a normal automatic stop tries to write a final frame and may be
  `cleanup=ok`. A missing frame makes it `cleanup=unknown`, never `failed`.
- `stop=observation_unavailable` requires `running=0`, `source=0`, and
  `trusted=0`. In phase 1 it also has `paired=0`, because every stop clears the
  credential. In phase 2 it does not change `paired` or `paired_scope`. It never
  appears with a `Rejected` verdict, and the app never shows it as
  `source_device_gone`, `hotspot_lost`, or a pairing failure.
- `stop=session_logoff` requires `running=0` and, in phase 1, `paired=0`.
- `stop=engine_lost` requires `cleanup=unknown` unless a later `recheck`
  establishes a different recorded result. The app must not show "off".
- An `instance` change means every cached sample is discarded and the app shows
  "checking" until the next sample.

A status that breaks a rule is `bad_response`, and the app shows unknown. It
never shows "off" from an inconsistent status.

## 12. Timing budget

The table is a design target, not evidence that the current ServiceHost meets
it. The current core client defaults every call to 5 seconds, and the named
pipe connection separately bounds each read and write. The transport's
25-second start and 15-second stop settings are not wired through that client
path. A start or stop can therefore time out before the service has finished.
The listener also currently treats a request-read timeout as parent loss even
though a hidden app may poll only every 5 seconds. These gaps must be resolved
and tested together before enabling the service. A client timeout alone does
not prove that the engine operation stopped or cleaned up.

| Action | Bound | Notes |
|---|---|---|
| `hello` | 5 s | Service only, no engine |
| `status` | 5 s | Service plus one engine status read |
| `start` | 25 s | Credential check, engine launch, route setup, phone check |
| `stop` | 15 s | Engine stop and cleanup observation |
| `credential.set` | 5 s | No engine |
| `probe` | 5 s | One source device probe, 4 s socket timeout |
| `diagnostics` | 5 s | Bounded counters |
| `failures` | 5 s | Bounded in-memory record |
| `recheck` | 5 s | Read-only route table and adapter table |
| Pipe connect | 5 s | From `CreateFileW` to the first frame; a slower connect is `engine_unavailable` |
| SCM start observation | 10 s | Poll `SERVICE_STATUS_PROCESS`; a timeout is `engine_unavailable`, not a kill |
| Engine launch | 20 s | Matches `EngineLaunchTiming.Launch` |
| Engine cleanup wait | 12 s | From parent pipe close to process exit |
| Event drain after exit | 2 s | Before classifying `engine_lost` or a normal stop |
| Service stop budget | 20 s total, 3 s wait hint, checkpoint every 1 s | Section 8.6.2. Confirm the host behavior at R24. |
| Preshutdown timeout | 20 s | Set explicitly with `SERVICE_CONFIG_PRESHUTDOWN_INFO`; do not rely on a default |
| Launch gate | 10 s | From engine start to `go`. No `go`: the engine exits with no effect. |
| Final-frame write | 1 s | Best effort and nonfatal |
| Status freshness | 3 s fresh, 10 s unavailable | Matches `EngineTiming` |
| App poll | 1 s visible, 5 s hidden | Matches `EngineTiming` |
| Source probe interval | 2 s | Matches `PROBE_INTERVAL` |
| Source silence limit | 90 s | Matches `SOURCE_DEVICE_GONE_LIMIT` |
| Link down limit | 20 s | Unix only; Windows has no enabled link observer |
| Windows link evidence | `Unknown` | Never `Down`, never a reset of the source-silence interval, never a start or reset of the unsupervised interval |
| Unsupervised interval | 300 s since the last `Accepted` answer | Proposed, O23. Stop reason `observation_unavailable`. Not implemented anywhere. |
| GUI unobservable link | 90 s of fresh silent probes; a stale, missing, or `no_hotspot` probe resets | In-progress working-tree change, unverified. No unsupervised bound. Not a model for the service. |

One absolute deadline per request, computed before the first byte is sent. Every
blocking step checks the remaining budget. A pipe read uses `PeekNamedPipe` with
a 25 ms poll and the remaining budget as its deadline. A pipe write uses a
writer thread and `CancelSynchronousIo` at the deadline. A blocked read is never
left to a fresh per-read timeout.

### 12.1 If the HTTP fallback is chosen

These rules then apply to the WinHTTP client in place of a pipe read.

1. Compute `deadline` once. Before every WinHTTP call, compute `remaining`.
   If `remaining <= 0`, return `timeout` without a call.
2. Set `WinHttpSetTimeouts` from `remaining` before each phase. Do not use five
   independent fixed phase values as the client does today
   (`WindowsEngineLocalClient.cs`).
3. Set the WinHTTP connect retry count to zero, or the lowest allowed value, so
   a refused loopback connect does not spend one to two seconds per attempt.
   The exact option number must be checked against `winhttp.h` at
   implementation time. Do not guess it in code review.
4. Run one watchdog that closes the request handle at the deadline.
   `WinHttpCloseHandle` from another thread is the only reliable way to abort a
   blocking `WinHttpReceiveResponse`. The cancellation token must be observed by
   that watchdog, not passed only to `Task.Run`
   (`WindowsEngineLocalClient.cs`).
5. Cap each body read at 8 KiB, cap the total at 65536 bytes, and check the
   deadline after each read. Do not reset the receive timeout per read
   (`WindowsEngineLocalClient.cs`).
6. Remove the 2 second startup poll window
   (`WindowsEngineLocalClient.cs`). Readiness comes from the event frame.
   If a poll is kept as a fallback, it shares the one deadline and each attempt
   is capped at 250 ms.
7. A 3xx, a 401, or an unexpected status is fatal for the generation. Release
   the gate, stop the engine, and re-prove the endpoint. Do not retry with the
   same bearer.

## 13. Secret handling

The bearer secret exists in exactly one place per process.

Service:

- One 64 byte buffer allocated once per generation and sealed with
  `CryptProtectMemory` (`CRYPTPROTECTMEMORY_SAME_PROCESS`). Unsealed only to
  write the token pipe, then resealed.
- Cleared with a volatile write, then the pipe buffer, on every exit path.
- Never converted to a managed `string`. That is the fix for the first review's
  secret-copy finding. The current client does `Encoding.ASCII.GetString` and
  string concatenation (`WindowsEngineLocalClient.cs`), which leaves copies on
  the heap.
- Written to the token pipe as 64 hex characters plus one newline, matching
  `EngineLaunchRules` and `parse_gui_token`.

If the HTTP fallback is kept, the `Authorization` header is built in a pinned
`char[88]`, passed to `WinHttpAddRequestHeaders` with an explicit length, and
cleared immediately. No `string` for the secret, ever.

Engine:

- Reads 65 bytes from the pipe, validates 64 hex characters and the newline,
  zeroizes the read buffer, and keeps one `BearerSecret` copy.
- Compares the header in constant time, as it does today.
- Does not log, print, or include the secret in any error.

Credential:

- Phase 1: memory only. The app holds the typed token in a pinned byte buffer
  until `credential.set` completes, then clears it. The service holds a
  `Zeroizing` copy, cleared on every stop and session loss. The token is never
  on disk, never in the state record, and never in a crash report field the
  project controls. It is never persisted by the app. A UI framework copy of the
  typed text is outside the project's control; do not claim the app never holds
  the typed value.
- Probe helper: it receives the target and token on an inherited pipe, keeps one
  `Zeroizing` copy for the probe, writes one redacted result frame, and exits.
  It receives no bearer and creates no adapter or route.
- Phase 2: DPAPI machine scope file only after authenticated pairing binds the
  credential to a source device identity, in the protected `ProgramData`
  directory, `SYSTEM`-only, same-volume replace, no backup attribute. The app
  never opens it.

## 14. Threat model

| Attacker | Capability | Result |
|---|---|---|
| Same-user non-elevated local process | Open the pipe by name | DACL and caller identity allow it. It can control the tunnel, start, stop, set or forget the session credential, hold the single session, and read redacted status. It cannot read the bearer, the credential, or the identity key. |
| Same-user non-elevated local process | Guess the pipe after it exists | Same. The pipe is not a boundary between processes of one account. |
| Same-user non-elevated local process | Inject into the app | Possible at the same integrity level. It inherits the app's ability to control the tunnel. It still cannot read the secret. |
| Same-user non-elevated local process | Duplicate the engine handles | Needs `PROCESS_DUP_HANDLE` on a `LocalSystem` process. Denied. |
| Same-user non-elevated local process | Read the service memory | Denied by integrity level. |
| Elevated same-account process | Read the service memory or duplicate the engine handles | Possible with administrator debug rights. Out of scope. It is already an administrator. |
| Same-user local process | Bind the engine port (fallback only) | Exclusive bind and PID proof prevent a usable bearer. The instance id check prevents a trusted answer. The bearer may be sent to the squatter and is dead. |
| Same-user local process | Create the pipe name first | The service fails `FILE_FLAG_FIRST_PIPE_INSTANCE` and does not serve. The app reports `engine_unavailable`. |
| Same-user local process | Create a later pipe instance | The DACL omits `FILE_CREATE_PIPE_INSTANCE`, so the create is denied. If an administrator creates one, the app's SCM PID check rejects it. The app sends no frame. |
| Same-user local process | Run the installed engine image to spoof or block an orphan search | The process runs with the user token, so the orphan rule in section 8.7 records it and ignores it for blocking. It is never adopted and receives no frame. This is B3 and E7. |
| Same-user local process | Connect, then exit so its PID is reused | Caller identity comes from the connection token by impersonation, not from the PID. PID reuse cannot change the result. This is E10. |
| Same-user local process | Open the pipe without sending a frame, or send a large first frame | Bounded by the 5 second `hello` deadline and the 65536 byte cap. The frame is not parsed before the token check. |
| Same-user local process | Hold the single session | Allowed. It is a denial of service against the real app. It gains no secret. |
| Second non-administrator local account | Open the pipe | DACL denies. Connection fails. |
| Second local account in `Administrators` | Open the pipe | Allowed, like any administrator. Administrator actions are out of scope. |
| Remote client | Open the pipe | `PIPE_REJECT_REMOTE_CLIENTS` and the DACL deny. |
| Different hotspot with the same gateway IP and same interface identity | Receive the phase 1 credential | Phase 1 cannot distinguish the two. The token is memory-only and sent only after a person action. Phase 2 source identity is the only binding. This is review H1. |
| Malicious inner packet or data-plane defect | Reach the engine parser | The prototype engine runs as `LocalSystem`. A defect can become system compromise. The recommended split in section 4.6 is unproven; real mode needs it or a written owner acceptance. This is review H3. |
| Device at the hotspot gateway address, before phase 2 | Send a crafted SOCKS reply or pairing status frame to the probe helper or the engine monitor | The prototype probe helper runs as `LocalSystem`, so a parser defect is a second system-level exposure. Its restricted token needs only R21. Until then it is named in the O2b owner acceptance. This is E3. |
| Different hotspot that copies the SSID, BSSID, or gateway MAC | Pass the hotspot-side guard | The guard is spoofable and a match is not identity. Phase 1 cannot detect it. Phase 2 source identity is the only binding. This is E4. |
| Another signed-in account on a shared machine | Sign out, lock, or disconnect | Ignored unless it is the controlling session. The tunnel routes are machine-wide while they exist (O25). |
| Compromised app | Ask for start, stop, or shutdown | Allowed by design. It can only use the current gateway and the in-memory credential. |
| Compromised app | Read the token or the bearer | It can see the token the person types during phase 1 manual entry, until `credential.set` completes. It cannot read the service's stored credential or the bearer. |
| Compromised app | Change the engine path or arguments | The path is fixed by the service from the install root. Arguments are fixed. |
| Compromised app | Point the engine at another host | The host must equal the current default IPv4 gateway and be private. |
| Administrator | Anything | Out of scope. The repair override is an administrator action and is recorded. |
| Remote host | Anything | No network listener exists in service mode. The loopback GUI is not started. |

Not claimed: protection from a kernel level attacker, a malicious
administrator, isolation from a same-user process, or protection from a hardware
attacker. Not claimed: fail-closed behavior. More specific routes, local DNS,
and platform filters can still bypass the tunnel.

## 15. Failure mode matrix

| Scenario | Detected by | State | App shows | Route cleanup |
|---|---|---|---|---|
| Engine crashes while idle | Process wait plus event drain | `Failed(engine_lost)` | unknown | None needed |
| Engine crashes while running | Process wait plus event drain | `Failed(engine_lost)` | unknown | `recheck` required; adapter fate is hypothesis H1 |
| Engine auto-stops normally | Final frame `cleanup=ok` and `stop=source_device_gone` | `Stopped(source_device_gone)` | source silence message | Engine ran its own stop; no latch |
| Engine reports cleanup failure | Final frame `cleanup=failed` | `cleanup_blocked` | actionable | Failed, needs a person |
| Engine process exits with no final frame | Event drain bound | `engine_lost`, `cleanup=unknown` | unknown | `recheck` required |
| Engine hangs on stop | 12 s wait | `Stopping(waiting)` | "still cleaning up" | Not confirmed |
| Cleanup reports failure | Final frame | `cleanup_blocked` | actionable | Failed, needs a person |
| Cleanup frame missing | End of file | `cleanup=unknown` | unknown | Not confirmed |
| Service crashes before the PID write | State record says `launching`, no PID | `cleanup_unknown` | unknown | Gated engine exits on parent loss; orphan rule; adapter read by name and `guid_planned` |
| Service crashes after the PID write, before `go` | State record says `launched` | `cleanup_pending`, then the adapter read | "still cleaning up" | Engine exits at the gate; no route possible |
| Service crashes after launch record | State record says `running` | `cleanup_pending` | "still cleaning up" | Waits for the engine |
| App crashes | Pipe break | Stopped, `parent_lost` | next launch: off | Engine ran its own stop |
| Service crashes | SCM | Service stopped | `engine_unavailable` | Engine sees the parent pipe close |
| Service restarted with a live engine | State record | `cleanup_pending` | "still cleaning up" | Waits for exit, then `recheck` |
| Source device silent 90 s | Engine monitor | Stopped, `source_device_gone` | fixed message | Engine ran its own stop |
| No `Accepted` answer for 300 s (proposed) | Engine monitor | Stopped, `observation_unavailable` | "could not check" message, no loss claim | Engine ran its own stop |
| Identity unreadable during a run | Engine monitor | `Unavailable` samples, no send | unchanged until the 300 s bound | None |
| Final-frame write fails on parent loss | Event drain | `cleanup=unknown`, not `failed` | unknown | `recheck` required |
| Controlling session logs off | `SESSIONCHANGE` or pipe break, first wins | Stopped, `session_logoff` or `parent_lost` | next sign-in: off | Engine ran its own stop |
| Other session logs off, or any lock or disconnect | `SESSIONCHANGE` filter | no change | no change | None |
| System shutdown | Preshutdown | Stopped, `shutdown` | next boot: per the record | Bounded 20 s |
| User-token copy of the engine image running | Orphan rule | recorded, does not block | no change | None |
| Guard value changed (gateway MAC, SSID, BSSID) | Link identity check | credential cleared, `link_changed` | re-enter credential | Engine ran its own stop |
| Probe helper crash | Child wait | `probe` failed, tunnel unchanged | "The check did not finish." | None needed |
| Physical gateway changed | Engine monitor | Stopped, `gateway_changed` | re-enter credential | Engine ran its own stop |
| Hotspot lost | Not detected on Windows | no change | no claim | Not observed |
| Bearer rejected | 401 or pipe hello mismatch | `boundary_auth_failed` | restart the service | Engine stop sequence |
| Port squatted (fallback) | PID or instance check | `boundary_auth_failed` | restart the service | Engine stop sequence |
| Pipe name exists at service start | `FILE_FLAG_FIRST_PIPE_INSTANCE` | service stops | "service unavailable" | None |
| Pipe squatted after start | App server PID check | `boundary_auth_failed` | retry or restart | None |
| Second start while stopping | Lifecycle gate | `busy` | "wait" | Unchanged |
| Start after a failed start | Generation check | `Failed` then retry | retry offered | Unchanged |
| Inconclusive `recheck` | Absence proof | latch stays | "check the routes" | Manual repair path |
| Adapter survives a crash | Absence proof by name and identity | latch stays | "check the adapter" | Manual repair path |
| Same gateway IP, different interface | Link identity check | credential cleared, `link_changed` | re-enter credential | Engine ran its own stop |
| Same gateway IP, same interface | No phase 1 detector | no change | no claim | Phase 2 identity needed |
| Later pipe instance denied | DACL without create-instance right | no connect | `engine_unavailable` or `boundary_auth_failed` | None |
| Stopped status has no engine | Status builder | both counts unknown | "not running" | None |

## 16. What this design does not prove

- It does not prove that a Windows service can hold `LocalSystem` and start the
  engine with the inherited handle list. That needs a Windows host.
- It does not prove that the pipe first-instance flag, the SCM PID check, and
  the pipe owner check work together on a real service. That needs tier R.
- It does not prove that the UWP app service bridge checks the caller package
  family and accepts one peer. That needs S29 and V75.
- It does not prove that developer registration and a reparse-point install path
  are refused. That needs S30, V76, and R15.
- It does not prove that a post-exit port takeover cannot receive a usable
  bearer. That needs V12 and a Windows host.
- It does not prove that `GetSecurityInfo` with `SE_KERNEL_OBJECT` returns the
  owner of a pipe handle. That is a hypothesis.
- It does not prove that a same-user process is blocked. It is not blocked, by
  design, and the design says so.
- It does not prove that SCM start and stop of a demand service is fast enough
  for the UI. That needs a measurement.
- It does not prove that the control pipe carries the same semantics as the
  HTTP API. That needs an engine implementation and a parity test.
- It does not prove that `PeekNamedPipe` plus `CancelSynchronousIo` bounds every
  read and write on a real pipe. That needs V40 and V70.
- It does not prove that the target-side `tcp_flows_active` gauge equals the
  live relay socket count. That needs T3.17.
- It does not prove that the source device creates the connection count in
  `phone.connections` or that the count is fresh. That needs V45 and a real
  source device.
- It does not prove that the absence proof clears a latch safely. That needs a
  route table fixture, an adapter fixture, and a Windows read-only run.
- It does not prove that the source probe helper creates no adapter or route, or
  that it exits on parent loss. That needs V74.
- It does not prove that the Wintun adapter disappears on a crash. Hypothesis
  H1 needs a Windows host.
- It does not prove that an inconclusive check has an acceptable manual
  recovery. O7 needs maintainer approval.
- It does not prove that the Windows CLI source-silence stop and the GUI path
  behave the same. They do not today. B1 is a design correction, not a fix.
- It does not prove that the service monitor stops after 90 seconds of source
  silence on Windows. That needs V96.
- It does not prove that the state record always holds enough adapter identity
  for a conclusive `recheck`. The pre-route gate and the exact-name read are
  designed, not implemented. That is B2.
- It does not prove that an orphan cannot be spoofed. Adoption by image path is
  removed; a nonce proof is not approved. That is B3.
- It does not prove that `SERVICE_QUERY_CONFIG` is present in a real service
  security descriptor. That is B4 and R16.
- It does not prove that a stopped status never publishes a false zero gauge.
  That is B5 and V86.
- It does not prove that two hotspots with the same gateway IP and same
  interface identity are distinguished in phase 1. They are not. That is review
  H1.
- It does not prove that `FILE_CREATE_PIPE_INSTANCE` is absent from the real
  DACL. That is review H2 and R17.
- It does not prove that the engine can run under a restricted token. That is
  review H3; V90 and V91 are the first check.
- It does not prove that a normal automatic stop and a crash are always
  distinguished. V92 and V93 exercise the race on a fake engine.
- It does not prove that a real tunnel works on Windows. It does not.
- It does not prove that the WinUI 2 XAML Islands host builds, or that the app
  survives suspension. That needs a host build.
- It does not prove that a supported .NET runtime is available for the service
  and for the WinUI 2 XAML Islands host. That is decision O15 and a host spike.
- It does not prove that the chosen installer technology can create the service,
  the protected `ProgramData` directory, and the service security descriptor.
  That is decision O16 and tier R.
- It does not prove that the exact user mask `0x00120183` is enough for the app
  and denies `FILE_CREATE_PIPE_INSTANCE`, or that the chosen .NET constructor
  requests that exact mask. That is E1, S37, V97, and R19.
- It does not prove that a 300 second unsupervised bound is the right value, or
  that it avoids false stops on real hosts. It is proposed, not implemented, and
  needs the O23 owner decision, T3.23, and V98.
- It does not prove that a restricted token can open a Wintun session or run the
  normalized socket helpers. That is E3, R20, and R21. Without them, real mode
  needs the written O2b owner acceptance.
- It does not prove that SSID, BSSID, or gateway MAC are readable by the service,
  or that they identify anything. They do not identify. Readability is R22.
- It does not prove that Wintun honors the requested GUID, or how many network
  profiles a fresh GUID per intent leaves. That is E5 and R23.
- It does not prove that the launch gate holds, or that a gated engine exits on
  parent loss. That is E6, V101, and V102.
- It does not prove that the orphan rule can always read a process token. That
  is E7, S44, and V103.
- It does not prove that the host honors the preshutdown timeout, the
  checkpoints, or the session logoff filter. That is E8, V104, V105, and R24.
- It does not prove that `ImpersonateNamedPipeClient` needs a prior read, or
  that an identification-level token opens with `OpenAsSelf`. That is E10, V107,
  V108, and R25.
- It does not prove the in-progress GUI `LinkWatch` change. It is uncommitted
  and unverified. That is E11, S45, and T3.21.

## 17. Traceability

| Review item | Design section | Tests |
|---|---|---|
| 82046682 preview unreachable, endpoint takeover, app-service peer, loose-file install, UWP suspension, status and retry evidence | 2.1, 4.4, 4.5, 6.4, 8, 9, 11 | S01, S29, S30, S31, V02, V10, V12, V30, V30b, V56, V75, V76, V77, R15 |
| Same-user threat honesty | 0, 5.2, 5.3, 14 | V03, R13, R14, S24 |
| Pipe server authentication and first instance | 5.1, 5.4, 5.7 | V01, V01b, V11, R12 |
| Crash intent before launch | 8.3, 8.5, 8.7 | V54, V67, V68 |
| ProgramData ownership | 4.5, 8.3, 13 | V55, V66, R09 |
| No at-rest credential before pairing | 11.4, 13 | V48, V63, V64 |
| Source silence and no hotspot claim | 6.1, 8.1, 10, 15 | T3.16, V64, L02 |
| Bounded pipe I/O | 6.2, 12 | V40, V41, V69, V70 |
| Framing, status, TTL diagnostics | 5.7, 11.1, 11.2 | S10 to S17, S25, V43, V62 |
| Check now probe parity | 5.6, 6.6, 11.4 | V74 |
| Installer and WinUI 2 | 4.4, 4.5 | S01, S05, V30, R01 to R03 |
| .NET runtime support | 2, 4.2 | O15, S26 |
| Shutdown, preshutdown, sleep and resume | 8.6 | V72, V73, R10 |
| Elevated caller usability | 5.3 | R14, S24 |
| HTTP fallback bearer wording | 6.4 | V12, V56 |
| First review 1.1 privilege | 4.2, 4.3, 5 | S01, S02, V02 |
| First review 1.2 endpoint | 6 | V10, V11, V12 |
| First review 1.3 process watching | 8.1, 8.8, 9 | V20 to V23 |
| First review 1.4 app host | 4.4 | S05, V30 |
| First review 2.5 timing | 6.2, 12 | V40 to V42 |
| First review 2.6 status | 11.2 | S10 to S17, V43 |
| First review 2.7 redirects | 12.1 rule 7 | V44 |
| First review 2.8 contract gaps | 6.3, 11.3, 11.4 | S18, V45, T3.17 |
| First review 3.9 secret copies | 13 | S20, V46 |
| First review 3.10 handle inheritance | 7 | V50 to V52 |
| First review 3.11 mutex squat | 4.5, 9 | S21 |
| First review 3.12 second engine | 8.3, 8.7 | V53, V54 |
| Fourth review B1 CLI and GUI source silence | 0, 6.1, 10, 16 | T3.20, T3.21, T3.22, V96 |
| Fourth review B2 adapter identity in crash recovery | 4.6, 8.3, 8.4, 8.5 | V80 to V83, V90 |
| Fourth review B3 orphan spoofing | 8.3, 8.7, 14 | S32, V84, V85 |
| Fourth review B4 `SERVICE_QUERY_CONFIG` | 4.5, 5.4 | S33, R16 |
| Fourth review B5 stopped gauge | 11.1, 11.3, 11.5 | S34, V86 |
| Review H1 same gateway IP | 6.6, 11.4, 14 | V87, V88 |
| Review H2 pipe instance right | 5.1, 5.2, 14 | V89, R17 |
| Review H3 LocalSystem data plane | 4.1, 4.6, 14 | S35, V90, V91 |
| Review H4 normal stop versus crash | 8.1, 8.8, 15 | V92, V93 |
| Session and SCM timeout precedence | 5.5, 8.6, 8.10, 12 | V94, V95, R18 |
| Fifth review E1 exact pipe mask and client request | 5.2, 5.4, 5.7 | S37, V97, R19 |
| Fifth review E2 bounded unavailable evidence, no false stop or pairing claim | 6.1, 10, 11.1, 11.2, 11.4, 11.5, 12 | T3.23, V98, S38 |
| Fifth review E3 restricted-token feasibility, probe helper, owner acceptance | 4.1, 4.6, 6.6, 14 | S35, S46, V90, V91, R20, R21 |
| Fifth review E4 hotspot-side evidence and limits | 6.6, 11.4, 11.4.1, 14 | S39, V99, R22 |
| Fifth review E5 planned GUID | 8.3.1, 8.4 | V100, R23 |
| Fifth review E6 launch gate instead of a suspended launch | 8.3.2, 8.3.3, 8.3.4 | S43, V101, V102 |
| Fifth review E7 orphan denial of service | 8.3.4, 8.7, 14 | S44, V103 |
| Fifth review E8 preshutdown, checkpoints, logoff | 8.6, 8.10, 12 | S40, V104, V105, R24 |
| Fifth review E9 nonfatal final frame | 8.3.4, 8.8, 8.9 | T3.24, V106, S41 |
| Fifth review E10 impersonated client token | 5.3, 5.7, 14 | S42, V107, V108, R25 |
| Fifth review E11 GUI fix citations | 0, 2, 6.1, 10, 12 | S45, T3.21, V96 |
