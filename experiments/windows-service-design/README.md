# Windows privileged engine service design

Status: **UNAPPROVED**. Revision 4. Design only. No code was written, no project
was wired, no Windows host was used, and nothing was committed. No production
enablement is approved.

This directory holds a design and a test plan for the Windows target device
privilege boundary: a privileged engine service, an authenticated app boundary,
a trusted engine endpoint, descriptor handles, process liveness, cleanup
overlap, safe retries, no auto-restart, and a coherent pairing and status
contract. It keeps one product rule throughout: no remote relay, VPS, or VPN
hop is added. The source device NAT remains the terminator, and the optional
source device proxy stays a separate mode.

It answers five independent reviews of the dormant Windows broker in
`windows/src/HotspotShade.WinUI2.Broker/`. Nothing here is production code.
Nothing here changes `windows/`, `rust/`, the workflows, the GUI, or any
existing file. Windows 10 and Windows 11 are the target family, but this design
does not claim a minimum build, an architecture list, or a live tunnel. The
host spike must record those. Real mode stays behind G1 to G6 and the
UNAPPROVED gate.

## Files

| File | Purpose |
|---|---|
| `README.md` | This index, the reviews, and the reading rules. |
| `WINDOWS_SERVICE_ARCHITECTURE.md` | The design: processes, privilege, boundary, endpoint, handles, lifecycle, retries, status and pairing, timing, threats. |
| `REVIEW_RESPONSE.md` | Point by point answer to every finding in all five independent reviews, with residual risk and the evidence each finding still needs. |
| `TEST_MATRIX.md` | Hermetic and Windows VM test plan, including the traceable adversarial matrices for B1 to B5 and H1 to H4 (section 9) and E1 to E11 (section 10). Each row states what it does not prove. |
| `OPEN_DECISIONS_AND_REVIEW_GATES.md` | Unresolved decisions, the recommended option for each, and the independent review gates that must pass before code. |

## The reviews this design answers

### First review

Thread: "Review Windows broker security and lifecycle".
Thread id
`thread:delegated-task:command%3Amcp%3A03268a16-2f62-4147-8102-f7277104e15e%3Adelegate-task%3A62fb4e4e-7ce4-435f-8a95-583ca3b523c6`.
The thread was reachable. It holds 70 items. The final review is item position
68, about 9,300 characters, and it is the only substantial message. All other
items are short progress notes. The review was read in full.

The verdict: none of the broker code is reachable from the shipped app, and four
blockers must be solved by design before anyone wires it in.

1. Who holds the privilege and the secret.
2. Proof that the endpoint is the real engine.
3. Watching the engine process.
4. The app service host, and UWP suspension.

It also found WinHTTP timing and status mapping problems, and hygiene problems
in secret copies, handle inheritance, the single-instance mutex, and the second
engine during cleanup.

### Second review

Thread: "Review Windows service boundary design", final item.
Thread id
`thread:delegated-task:command%3Amcp%3A03268a16-2f62-4147-8102-f7277104e15e%3Adelegate-task%3A98a30f79-07a6-43c1-8ab8-61f0d80a8cf7`.
The thread was reachable. The review was read in full. It was a static read with
no Windows host run.

The verdict: not approvable. Service implementation cannot safely begin. It
found seven blockers in revision 1:

1. Same-user callers are not blocked, but the threat table said they were.
2. The app's check of the pipe server was not feasible as written, and the
   first-instance pipe flag was missing.
3. A crash could still produce a second engine, or a permanent lockout.
4. A standard user can pre-create the `ProgramData` directory.
5. A credential at rest before identity-bound pairing extends the exposure.
6. The automatic stop was at risk, and the summary made a Windows hotspot-loss
   claim.
7. Anonymous pipes cannot time out a blocking read without a stated mechanism.

It also found lower problems in framing, error codes, the stop reason, the
connection count, the operation set, the WinUI 2 boundary, handle inheritance,
the HTTP fallback wording, the installing-person SID, the installer technology,
shutdown and sleep handling, the 20 second wait, elevated-caller usability, and
the .NET 8 end of support.

### Third review

Review of the existing Windows broker, task 82046682. The preview path is
unreachable: the broker is `asInvoker` and `Win32EngineHost` returns
`AdminRequired`. The review listed the conditions before production enablement:

- loopback endpoint ownership and post-exit port takeover
- app-service caller package family validation and one peer
- loose-file developer registration, reparse checks, and a trusted engine
  directory
- process exit and stop timeout, and preventing a second engine
- the UWP suspension lifecycle
- the actual status schema and source token provisioning
- explicit retry semantics
- Windows runtime evidence

Revision 2 incorporates each condition in architecture section 2.1 and
`REVIEW_RESPONSE.md` section 4. No production enablement is approved.

### Fourth review

Review id `c0b94fca-d9ea-4d4f-8aa8-87de7c508503`. The task record for that id
was not reachable when revision 3 was written; the review content was supplied
with the revision task and is treated as the complete independent review. It is
a static read. It found five blockers and four higher findings:

1. **B1:** the Windows source-silence stop was described as working when one
   path does not work. The correction matters: the Windows CLI `tun` branch
   passes a link closure that reports `Some(true)`, so its source-silence timer
   runs when a physical hotspot interface resolves. The command-line GUI's
   `observe_link` returns `None` on Windows, and
   `auto_stop_sample` resets the policy on `None`, so the GUI path does not
   currently stop on source silence. Revision 3 separates the two paths and
   makes the service monitor use the CLI-equivalent policy without claiming
   link loss.
2. **B2:** a crash record can lack the adapter LUID and GUID, so the absence
   proof is inconclusive. Revision 3 records the planned adapter name and a
   route-installation gate before the engine installs any route. The preferred
   direction is service-owned adapter identity; the fallback is an engine
   identity handshake before the first route. Neither is implemented.
3. **B3:** an image-path orphan search can be spoofed by another process that
   runs the same installed image. Revision 3 stops adopting an orphan by image
   path. It observes and blocks; adoption requires a per-launch nonce proof and
   is not approved.
4. **B4:** the app's server proof calls `QueryServiceConfig` but the service
   security descriptor and the opened service handle did not grant
   `SERVICE_QUERY_CONFIG`. Revision 3 adds that right explicitly and fails
   closed if it is absent.
5. **B5:** stopped status rules required `relay.tcp_flows_active=0`, which
   contradicts an unavailable gauge and invents a zero. Revision 3 makes both
   counts unknown when no live engine status exists.

The higher findings:

- **H1:** the same gateway IP on a different hotspot cannot be identified by an
  IP comparison. Phase 1 now binds the credential to the interface LUID or GUID
  plus the gateway, and it states that two hotspots that reuse both are
  indistinguishable before phase 2 identity pairing.
- **H2:** a later pipe instance needs `FILE_CREATE_PIPE_INSTANCE`. Revision 3
  does not grant that right to the interactive user, so a later user instance
  is denied by the DACL; the SCM PID check stays as defense in depth.
- **H3:** the engine parses untrusted inner traffic while running as
  `LocalSystem`. Revision 3 records the data-plane exposure, recommends a split
  between a privileged control plane and a restricted engine, and blocks
  real-mode approval until that split is proven or the owner accepts the risk
  in writing. It does not claim the split works.
- **H4:** a normal automatic stop and an engine crash were not clearly
  distinguished. Revision 3 requires a final frame with a stop reason, a
  bounded drain after process exit, and `cleanup=unknown` when no final frame
  exists.

Revision 3 also adds the session and SCM timeout precedence that the review
asked for. It answers all nine findings on paper. It closes none of them. It
passes no gate.

Revision 2 answered all three earlier reviews. It did not close them. Only the
evidence named in `REVIEW_RESPONSE.md` closes a finding.

### Fifth review

Review id `e1b9ed6a-3041-4221-873f-3a406392400b`. The task record for that id
was not reachable when revision 4 was written; the review content was supplied
with the revision task and is treated as the complete independent review. It is
a static read. Revision 4 answers its eleven findings, E1 to E11, on paper:

1. **E1:** the pipe now has one exact SDDL string with the user mask
   `0x00120183`, and the app requests exactly that mask. The mask omits `0x4`,
   which is `FILE_CREATE_PIPE_INSTANCE` on a pipe and is part of
   `GENERIC_WRITE`.
2. **E2:** a proposed 300 second bound on the time since the last positive
   source device answer stops an unsupervised tunnel with
   `observation_unavailable`. It is not a loss claim and not a pairing verdict.
   An unreadable identity is no longer sent to `source_device_gone`. The value
   is owner decision O23. It is not implemented.
3. **E3:** a Wintun session cannot move between processes, so the split has
   three options: a restricted engine that opens Wintun itself, a service-side
   frame pump, or `LocalSystem` with a written owner acceptance. The probe
   helper is now in the threat model as a second privileged parser, with a
   restricted path that does not need the Wintun spike.
4. **E4:** SSID, BSSID, and gateway MAC are a spoofable guard. A change clears
   the credential. A match is not identity. A phase 1 token acceptance is not
   identity either. Phase 2 remains the only identity.
5. **E5:** a fresh `guid_planned` per intent is the requested Wintun GUID. A
   match is never `Clean`. The network profile cost is in O19.
6. **E6:** a launch gate replaces a suspended launch. The engine does nothing
   with an effect until the service has recorded its PID and sent `go`.
7. **E7:** a user-token copy of the engine image no longer blocks a start.
8. **E8:** preshutdown with an explicit timeout, checkpoints, and a logoff
   filter keyed to the controlling session.
9. **E9:** the final-frame write is best effort and nonfatal. A missing frame is
   `cleanup=unknown`, never `cleanup=failed`.
10. **E10:** caller identity comes from the connection token by impersonation
    after one unparsed read. The PID is diagnostics only.
11. **E11:** every citation of the in-progress GUI `LinkWatch` change says
    uncommitted and unverified.

Revision 4 closes no finding and passes no gate. Three items need the owner, not
a reviewer: the O2b acceptance if a privilege spike fails, the O23 value, and
O25, the controlling-session scope on a shared machine. Every Windows
feasibility item stays a hypothesis until the named tier V or tier R test runs.

All five reviews were static reads. The reviewers built nothing, ran nothing,
and made no Windows host run. That is also true of this design.

## Reading rules

The design uses four labels.

- **Verified in this tree**: checked by reading a file in this working tree. The
  function is named. Line numbers move, so they are not the citation.
- **Standard**: documented Windows, Win32, Winsock, WinHTTP, SCM, or installer
  behavior. It is not a claim that this project implements it. It needs a
  Windows host before it becomes a project claim.
- **Hypothesis**: a statement that needs a build, a test, or a Windows host
  before anyone may use it. Every hypothesis has a test id in
  `TEST_MATRIX.md`.
- **Open**: a decision that is not made. An open item is not a capability.

A design answer closes a design question. It does not close an implementation
test. `REVIEW_RESPONSE.md` keeps the difference for every finding.

## Hard limits of this work

- No implementation of a service, broker, pipe, client, or engine mode.
- No change to `windows/`, `rust/`, or any existing file.
- No Windows host run. No build was produced for Windows in this task.
- No service install, no `sc.exe`, no SCM call.
- No route, adapter, TUN device, Wintun DLL, or physical device.
- No root or administrator action.
- No Python.
- No commit and no push.
- No remote relay, VPS, or VPN was added or proposed.
- No production enablement. The preview is unreachable and no production path
  exists. Real mode stays behind G1 to G6.
- The parent `experiments/README.md` is not updated, by instruction. The index
  entry for this directory is owed when the design is approved.

## What the design does not claim

- It does not claim Windows tunnel support.
- It does not claim that the current WinUI preview can start a tunnel. The
  preview broker is `asInvoker` and the launch path returns `AdminRequired`.
- It does not claim that a privileged service boundary works.
- It does not claim that the app service pattern is viable for a tunnel.
- It does not claim that any test in `TEST_MATRIX.md` has run.
- It does not claim that a same-user process is blocked. It is not blocked,
  except that a later pipe instance is denied by the DACL when
  `FILE_CREATE_PIPE_INSTANCE` is absent. The account boundary does not isolate
  processes of the account.
- It does not claim a source device connection count in phase 1 manual mode.
  That count comes only from the phase 2 authenticated status. Phase 1 shows it
  as unknown and never fills it from the target-side relay gauge.
- It does not claim a general automatic stop on Windows. The Windows CLI `tun`
  path has a coded 90-second source-silence stop when a physical interface
  resolves. The committed command-line GUI path does not stop on source silence,
  because its unknown link observation resets the timer. An uncommitted,
  unverified working-tree change adds `LinkWatch::Unobservable`, which can stop
  after 90 seconds of fresh silent probes and still resets on a stale or missing
  probe. The service monitor has its own contract, and this design does not
  claim that code exists.
- It does not claim that the proposed `observation_unavailable` bound exists or
  that 300 seconds is the right value. It is proposed in O23.
- It does not claim that a restricted token can use Wintun or the normalized
  socket helpers. R20 and R21 must run first.
- It does not claim that SSID, BSSID, gateway MAC, or a phase 1 token acceptance
  identifies a hotspot or a source device.
- It does not claim that hotspot link loss stops the tunnel. Windows has no
  enabled hotspot link observer.
- It does not claim that phase 1 can tell two hotspots apart when both reuse
  the same gateway IP and the same interface identity. Only phase 2 source
  device identity can bind the credential.
- It does not claim that the engine is least-privilege. The data-plane exposure
  under `LocalSystem` is recorded, and a split is recommended but unproven.
- It does not describe the tunnel as fail-closed. It is not fail-closed.

## External prerequisites

These are not approvals. They are things this environment does not have.

- A Windows 10 or Windows 11 VM or a disposable Windows test host for tiers V
  and R. The exact minimum build and architecture list is not claimed.
- A supported .NET runtime image for the service build and the host spike.
- An installer toolchain, assumed to be WiX or an equivalent MSI builder.
- A code-signing certificate if O11 adds publisher pinning. The design does not
  require one for the prototype.
- Maintainer decisions for O1, O2, O2b, O5, O7b, O9, O10, O12, O15, O16, O17,
  O18, O19, O20, O21, O22, O23, O24, and O25. The O2b owner acceptance, the O23
  value, and O25 are owner decisions.
- Evidence for B1 to B5, H1 to H4, and E1 to E11, and owner approval for every
  tier R and tier L run.
- A Windows host with a Wi-Fi adapter and a test access point for R22, and a
  disposable VM where a test Wintun adapter may be created for R20 and R23. No
  route is created in either.
- Device owner approval for every tier R run and every tier L run.

## Related files in the tree

| File | Why it matters here |
|---|---|
| `AGENTS.md` | Invariants 6, 10, 11, 12, and 13 constrain this design directly. The WinUI 2 rule constrains O1. |
| `windows/src/HotspotShade.WinUI2.Broker/` | The dormant broker the first review and the 82046682 review examined. |
| `windows/src/HotspotShade.WinUI2.Broker/app.manifest` | The `asInvoker` manifest that makes the preview path unable to elevate. |
| `windows/src/HotspotShade.WinUI2.Broker/Package.broker.fragment.xml` | The inactive app-service and full-trust fragment. It is not merged into the preview package. |
| `windows/src/HotspotShade.WinUI2.Core/Engine/` | The transport free contract that survives the redesign. |
| `rust/src/gui.rs` | The loopback GUI server, the bearer check, the error mapping, and the auto-stop loops. |
| `rust/src/main.rs` | `--token-fd`, `--parent-fd`, `read_gui_token`, `watch_parent_handle`, and `seal_windows_control_handle`. |
| `rust/src/gui_backend_windows.rs` | The Windows status shape, the presence loop, and the phone start path. |
| `rust/src/service.rs` | The engine lifecycle, `cleanup_blocked`, and `status()`. |
| `rust/src/autostop.rs` | `LINK_DOWN_LIMIT` and `SOURCE_DEVICE_GONE_LIMIT`. |
| `rust/src/relay.rs` | `RelayStats` and the live target-side `tcp_flows_active` gauge. It is not the source device connection count. |
| `rust/src/windows_route_verify.rs` | The read-only route presence proof. The absence proof is a new derived requirement. |
| `linux/helper/src/main.rs` | The closest existing pattern: descriptor secret, liveness descriptor, no arguments. |
| `rust/src/privileged.rs` | The framed message pattern that the control pipe copies. It is Unix only. |
