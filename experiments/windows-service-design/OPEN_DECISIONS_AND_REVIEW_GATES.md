# Open decisions and independent review gates

Status: **UNAPPROVED**. Revision 4. Every decision in this file is open. No gate
is passed. No code may be written against this design until G1 and G2 pass. No
production enablement is approved. Real mode stays behind G1 to G6.

Architecture: `WINDOWS_SERVICE_ARCHITECTURE.md`.
Review answer: `REVIEW_RESPONSE.md`.
Test plan: `TEST_MATRIX.md`.

## 0. How to use this file

Each decision has options, a recommendation, the reason, and what it blocks.
A recommendation is not a decision. A person or an independent reviewer must
record the decision.

Each gate has an entry condition, the artifact under review, the exit condition,
and the evidence that must exist first. A design answer does not pass a gate. A
gate passes when the named evidence exists and a reviewer records approval.

Revision 3 adds the decisions that the fourth review, id
`c0b94fca-d9ea-4d4f-8aa8-87de7c508503`, found missing: data-plane
privilege (O2b), adapter identity before routes (O19), the source-silence monitor
policy (O20), the orphan proof (O21), and the session and SCM timeout budget
(O22). It also corrects O5, O10, O12, O14, and O18.

Revision 4 answers the fifth review, id `e1b9ed6a-3041-4221-873f-3a406392400b`
(E1 to E11). It adds the bounded unsupervised interval (O23), the hotspot-side
guard (O24), and the controlling-session scope (O25). It extends O2b with the
Wintun feasibility options and the exact owner acceptance, O19 with the planned
GUID, O21 with the orphan denial-of-service rule, and O22 with preshutdown,
checkpoints, and logoff. Three items are owner decisions, not reviewer
decisions: the O2b acceptance if a spike fails, the O23 value, and O25. No
Windows host has run any test, so every feasibility item stays a hypothesis.

## 1. Open decisions

### O1. App host: UWP preview or full-trust WinUI 2 desktop

| Option | Consequence |
|---|---|
| Keep UWP as the real-mode host | The app service likely closes on suspension (hypothesis, needs a host check). The tunnel stops when the window is minimized. No tray. No reliable background execution. |
| Full-trust desktop host with WinUI 2 controls in a XAML Islands host | The app talks to the service pipe directly. Window close does not stop the tunnel. Tray is possible. Requires replacing the current UI base. Keeps the AGENTS.md WinUI 2 rule. |
| Full-trust packaged broker bridging the UWP app service | Keeps UWP. Adds a third process and keeps the suspension stop for the app session. Does not fix the minimize behavior. The bridge must check `CallerPackageFamilyName` and accept one peer. Compatibility only. |

Recommendation: the full-trust WinUI 2 XAML Islands desktop host. The UWP app
stays the labeled preview.

Reason: the product behavior on macOS and Linux is a tunnel that survives the
main window. UWP cannot guarantee that, and the review already found the
suspension path. AGENTS.md requires WinUI 2 and asks for an evaluation of a UWP
host and a desktop host with legacy XAML Islands. This recommendation is the
result of that evaluation. WinUI 3 is not offered. It would need an AGENTS.md
change and is not part of this design.

This is a product decision, not only a technical one. The host spike must prove
that a supported WinUI 2 XAML Islands combination exists for the chosen runtime.
If it does not, the UWP preview stays and real mode waits.

Blocks: G1.
Evidence needed: a written product decision, the host spike result, V30 and
V30b for the desktop host, and V77 for the UWP bridge suspension behavior.

### O2. Service account

| Option | Consequence |
|---|---|
| `LocalSystem` | No stored password. Full system rights. Broadest engine token. |
| Dedicated virtual service account added to `Administrators` | Permanent administrative group membership. More to manage. Not narrower in practice. |
| Delegated interactive user administrator token | Narrows what the engine can touch. Needs token duplication across the boundary and a UAC prompt the product does not have. |

Recommendation: `LocalSystem` for the prototype. Record the delegated token
option as the stronger long-term direction. Do not claim the engine is
least-privilege.

Blocks: G1, G2.
Evidence needed: a threat model review that accepts the engine as a high-value
`LocalSystem` target, or a decision to take the delegated option.

### O2b. Data-plane privilege (review H3)

| Option | Consequence |
|---|---|
| C. Keep the engine and the probe helper `LocalSystem` | Smallest change. Two privileged parsers of untrusted input: the engine data plane and the probe helper. A parser defect is a host compromise. Needs the written owner acceptance below. |
| A. Service owns the adapter and routes; the restricted engine opens the adapter | Narrows the data-plane token. A Wintun session cannot move between processes, so the restricted engine must open the adapter and start the session itself. Feasible only if R20 shows that a restricted token may do that. Expected to fail. |
| B. Service owns the adapter, the routes, and the Wintun session, and pumps whole frames to the restricted engine | No packet parsing in `LocalSystem`. One extra copy and a context switch per packet each way. A new privileged copy loop on the hot path. Needs R20 for throughput and latency and R21 for the engine's outer sockets. |
| Probe helper under the restricted token, independent of the engine choice | Removes the second privileged parser. Needs only R21, because the helper uses no adapter and no route. |
| Drop the engine token after setup inside one process | The cleanup path also needs the privileged token. Re-acquiring it after a drop is not available. Not viable without a second process. |

Recommendation: the probe helper under the restricted token as soon as R21
passes. For the engine, option A if R20 passes, else option B if its measured
cost is acceptable to the maintainer, else option C with the acceptance. Do not
claim the engine or the helper is least-privilege until the matching spike
passes.

Owner acceptance, required for every component that stays at `LocalSystem`. It
is a written record, signed by the owner, that names:

- the component: the engine, the probe helper, or both
- the untrusted inputs: inner packets from every local account, relayed reply
  data from remote hosts, SOCKS and pairing replies from an unauthenticated
  gateway peer before phase 2
- the scope: which builds and which hosts
- the compensating controls the owner requires, for example parser fuzzing
- the re-review trigger: a passing spike, a parser change, or a date

A G2 approval does not imply the acceptance. A reviewer cannot give it.

Reason: the design already separates the app from the service. The next useful
boundary is between the control plane that changes routes and the parsers that
read untrusted input. The prototype may keep `LocalSystem`, but only with the
written owner acceptance at G2.

Blocks: G2. It does not block G1 design review.
Evidence needed: V90, V91, S35, S46, R20, and R21. R20 and R21 need a
disposable Windows VM with administrator rights and owner approval per run.

### O3. Engine transport

| Option | Consequence |
|---|---|
| Control pipe, no TCP | No port, no squat, no WinHTTP, one bounded read. Larger engine change. |
| Loopback HTTP with port 0, exclusive bind, PID proof, instance id | Smaller engine change. Keeps WinHTTP and the timing rules. More proof steps to get wrong. |

Recommendation: control pipe. It closes the endpoint, timing, and redirect
findings by construction.

Blocks: G3.
Evidence needed: an engine change estimate, and T3.01 to T3.19 for the chosen
transport. The fallback must keep every rule in architecture section 12.1.

### O4. Service start mode

| Option | Consequence |
|---|---|
| Manual, demand start | No privileged process at boot. Self-stops when idle. SCM start latency on the first action. |
| Automatic | Always present. Simpler UX. A privileged process is always running. |

Recommendation: manual. It does not violate invariant 13 either way, because
the tunnel is the thing that must not persist. Manual is the smaller surface.

Blocks: G1.
Evidence needed: a measured SCM start and stop time on a Windows VM.

### O5. Credential at rest

| Option | Consequence |
|---|---|
| Memory only in phase 1 | The person enters the token after every service stop. No credential at rest. No cross-hotspot exposure. |
| DPAPI file before identity-bound pairing | The person enters the token once. A token bound only to host and port would match any hotspot with the same gateway. The exposure lasts across reboots. |
| DPAPI file only after phase 2 identity-bound pairing | The person enters the token once per source device identity. The file is bound to a device identity, not only an address. |

Recommendation: memory only in phase 1, and an at-rest file only after phase 2
identity-bound pairing. Do not take a DPAPI file before phase 2. The old revision
recommended DPAPI without that condition. That recommendation is withdrawn.

Reason: every iPhone hotspot commonly uses `172.20.10.1`. A credential bound only
to host and port matches any of them. The Windows presence loop already sends
the cleartext token every 2 seconds while it runs. A file would make that
exposure permanent across reboots. Machine-scope DPAPI adds little beyond a
`SYSTEM`-only file DACL. The identity binding is the control that matters.

Review H1 adds a second limit. Even a memory-only phase 1 credential can be
bound only to the interface LUID or GUID and the gateway address. Two hotspots
that reuse both are indistinguishable before phase 2. The design says so and
does not claim otherwise. No SSID or BSSID is used, because the project does not
have that permission path.

Blocks: G2.
Evidence needed: V48, V63, V64, V55, V87, V88, and R07.

### O6. Connection count contract

| Option | Consequence |
|---|---|
| Engine computes `tcp_flows - tcp_flows_closed` | A real number when it is exact. Subtraction is not exact for a half-closed or reset flow. |
| Export the existing `tcp_flows_active` gauge as `phone.connections` | Wrong meaning. The gauge is target-side relay flows, not the source device count. |
| Export the gauge as a separate `relay.tcp_flows_active` field | Correct meaning. The app can show local relay load without claiming it is the source device count. |
| Phase 2 authenticated status supplies `phone.connections`, with `phone.connections_known` | Preserves the existing meaning. Phase 1 manual mode stays unknown because it has no authenticated status answer. |
| Wire carries both a source count and a separately named target gauge | The best behavior. Two small protocol additions. |

Recommendation: keep `phone.connections` as the count from the source device's
authenticated pairing status answer, with `phone.connections_known`. That answer
exists only after phase 2 pairing; phase 1 manual mode stays unknown. Add the
target gauge as `relay.tcp_flows_active` with
`relay.tcp_flows_active_known`. Never substitute one for the other. Label them
"source device connections" and "local relay TCP flows". UDP relays are not
counted by the target gauge. When no live engine status exists, both counts are
empty and both known flags are 0; a stopped tunnel is not a measured zero. This
is B5.

Blocks: G3.
Evidence needed: T3.14, T3.17, and V45.

### O7. Clearing the cleanup latch

| Option | Consequence |
|---|---|
| A person action only | Matches AGENTS invariant 6. The app needs an Advanced action. |
| Automatic on a clean absence proof | Fewer steps. Risks clearing while a route check is inconclusive. |
| A person action, plus a documented administrator override when the check is inconclusive | Avoids a permanent lockout. Adds an explicit privileged action and a record. |

Recommendation: a person presses `recheck`. The service runs the read-only
absence proof. A conclusive clean result clears the latch. An inconclusive
result keeps it and says so. The service may run the same read-only check
automatically to choose between "off" and "unknown" for display, but may never
clear the latch without the person action.

When the check is inconclusive and an administrator has independently inspected
the table, `HotspotShade.ServiceRepair.exe --acknowledge-cleanup-unknown` may
clear the latch. It records the route and adapter snapshot, the administrator
account, and a fixed acknowledgement string. It never deletes a route. This
override is a separate decision, O7b.

Blocks: G4.
Evidence needed: V58, V59, and the new absence proof in tier T.

### O7b. Manual recovery override for an inconclusive latch

| Option | Consequence |
|---|---|
| No override | A host with no IPv6 stack or a table read error keeps the latch forever. That is not acceptable shipped behavior. |
| An explicit administrator override with an audit record | A person can recover. The override is a privileged action and must be recorded. |
| A service-side automatic clear on a second inconclusive read | No person action. It can clear while a route remains. Not recommended. |

Recommendation: the explicit administrator override. It is a security decision
for the owner because it relaxes the latch.

Blocks: G4.
Evidence needed: maintainer approval, V58, and V71. The repair tool is a named
implementation requirement, not part of this design.

### O8. Engine token versus service token

| Option | Consequence |
|---|---|
| Same token as the service | Simple. The engine has full system rights. |
| A restricted token with only the needed rights | Route APIs need an administrator token, so a restricted non-admin token cannot do the work. The option is not viable for routes. |

Recommendation: same token. Document the consequence. Do not pretend the engine
is restricted.

Blocks: G2.
Evidence needed: a statement that the Windows route API path needs
administrator rights, with a test that a non-elevated engine start fails with
`admin_required`.

### O9. Pairing scope on Windows

| Option | Consequence |
|---|---|
| Phase 1 only, manual credential entry labeled as manual | Honest today. The app holds the token briefly in memory. No credential at rest. The source connection count stays unknown because there is no authenticated status answer. |
| Implement `pair.begin`, `pair.status`, `pair.cancel` now | Removes the token from the app. Larger engine and service change. Enables identity-bound at-rest storage and the source connection count. |

Recommendation: phase 1 now, memory only. Phase 2 before any claim of pairing
support or credential storage. The manual field stays as a fallback after phase
2 and stays memory only.

Blocks: G3.
Evidence needed: a parity test against the existing pairing vectors if phase 2
is taken, and V63 and V64 for phase 1.

### O10. Windows hotspot link observer and the source-silence gap

| Option | Consequence |
|---|---|
| Add an engine link observer now | Enables an honest `hotspot_lost` stop. AGENTS says Windows has no enabled observer today. More Windows API work. |
| Defer the observer and use the CLI-equivalent source-silence policy | No hotspot-loss claim. The service can still stop after 90 seconds of source silence. Needs the monitor change in O20. |
| Defer both | No automatic stop in the service. The GUI gap stays. Honest but weaker. |

Recommendation: defer the observer, and require the CLI-equivalent source
silence policy for the service monitor. This design does not add the observer.
It does not claim a general Windows automatic stop.

The current facts matter: the Windows CLI `tun` path supplies `|| Some(true)`,
so its 90 second source-silence stop can run when a physical interface
resolves. The command-line GUI returns `None` for an unknown link and resets the
policy, so its source-silence stop does not currently run. The service must not
copy that reset. This is B1.

Blocks: G6. It does not block G1, but it blocks any "automatic stop on Windows"
claim.
Evidence needed: T3.20, T3.21, T3.22, V96, L02, and a real link change on a
Windows host. L02 records that link loss alone does not stop the tunnel. It does
not justify a stop claim.

### O11. Pipe server authentication strength

| Option | Consequence |
|---|---|
| First-instance flag, SCM PID, pipe owner SID, installed image path | Feasible without opening the service token. A squatter cannot be the service PID. |
| Add Authenticode publisher pinning | More defense in depth. More install and signing assumptions. |

Recommendation: the first four. Add signature pinning only when the package is
signed. The pipe owner check is a hypothesis until V01b proves it. The app fails
closed if any check is inconclusive.

Blocks: G2.
Evidence needed: V01, V01b, V11, V30, and R12.

### O12. Who may control the tunnel on a shared machine

| Option | Consequence |
|---|---|
| The installing person's account | Matches the macOS root helper model at the account level. A second non-administrator account cannot control the tunnel. Any process of the installing account can. |
| Any interactive user | Surprising. A second user could stop another person's tunnel. |

Recommendation: the installing person's account. The pipe DACL and the caller
identity both encode that SID. The design states plainly that this authorizes
the account, not one process. Any same-user process can control the tunnel and
cannot read the secret. O18 records the acceptance of that residual risk.

Two rights are exact, not implied. The service descriptor must grant
`SERVICE_QUERY_CONFIG` for the path check (B4). The pipe DACL must omit
`FILE_CREATE_PIPE_INSTANCE` for the interactive user so a later instance is
denied (review H2). The SCM PID check remains as defense in depth.

Blocks: G1, G2.
Evidence needed: V03, V04, R13, R14, S33, R16, V89, and R17.

### O13. Reconnect grace on app session loss

| Option | Consequence |
|---|---|
| No grace | Invariant 13 is exact. An app crash stops the tunnel. |
| A short grace | Survives an app restart. It is a persistent proxy in disguise. |

Recommendation: no grace. The app must not hold a tunnel it did not ask for
after it restarts.

Blocks: G4.
Evidence needed: V31.

### O14. State record

| Option | Consequence |
|---|---|
| `%ProgramData%\HotspotShade\engine-state.json`, `SYSTEM` only, no secrets | Survives a service restart. Enables the second-engine check and the launch intent. |
| Memory only | Simple. A service restart forgets a live engine and can start a second one. |

Recommendation: the file. It holds only PID, process creation time, launch
intent, launch nonce, adapter name, observed LUID and GUID, identity source,
route prefixes, `routes_may_exist`, and the latch. No token, no bearer, no
identity key. The nonce is never on a command line. The directory is created by
the installer with a protected DACL. The service checks the owner and reparse
state before every write. The route gate is written before any route exists, so
a crash before the adapter identity is known does not force an inconclusive
check. This is B2.

Blocks: G2, G4.
Evidence needed: V54, V55, V66, V67, V68, V80 to V83, and R09.

### O15. Service runtime

| Option | Consequence |
|---|---|
| Keep .NET 8 | Support ends on 2026-11-10. Not acceptable for new work. |
| .NET 10 LTS | Supported through November 2028. Needs a runner image and a host check for the WinUI 2 combination. |
| .NET Framework 4.8 | In support as part of Windows, but a poor fit for the new service and the Rust interop. |

Recommendation: .NET 10 LTS for the service. The WinUI 2 XAML Islands host must
record its own supported combination. The existing broker's `net8.0` target is
existing code and must be retargeted before implementation.

Blocks: G1.
Evidence needed: S26, a CI image with the chosen runtime, and the host spike.

### O16. Installer technology

| Option | Consequence |
|---|---|
| Per-machine MSI built with WiX, or an equivalent elevated installer | Explicit SCM calls, a protected `ProgramData` DACL, and a service security descriptor are straightforward. Unsigned until a signing certificate exists. |
| MSIX packaged service | Packaged-service support varies by Windows version. The service install contract would need a new review. |
| A custom elevated executable | Full control. More code and more review surface. |
| Loose-file developer registration | Only for preview. It places the binary in a user-writable path and is not a real-mode install. Real mode refuses it. |

Recommendation: a per-machine MSI built with WiX or an equivalent elevated
installer. MSIX is not chosen. Developer registration is preview-only. The
installer toolchain and a code-signing certificate are external prerequisites.

Blocks: G1, G5.
Evidence needed: R01 to R03, R08, R09, R11, and R15 on a disposable VM.

### O17. Installing-person SID when the installer is elevated

| Option | Consequence |
|---|---|
| Read the interactive logon token or the shell owner | Works when a standard user elevates with an administrator's credentials. |
| Read the elevated token | Stores the administrator's SID, not the person's. The real person is locked out. |
| Require an explicit `--user-sid` | Always correct, but asks the person for a SID. |

Recommendation: read the interactive logon token or the shell owner. If that
fails, accept an explicit `--user-sid` or stop. Never fall back silently to the
elevated token.

Blocks: G1, G2.
Evidence needed: S27 and R11.

### O18. Same-user residual risk acceptance

| Option | Consequence |
|---|---|
| Accept same-user control | Any process of the installing account can control the tunnel. It cannot read the secret. The boundary protects other accounts and remote clients. |
| Claim a same-user block | False. The DACL grants the account. No pipe design can distinguish one process of an account from another. |
| Add a per-launch secret to the app | Any same-user process can read it. It does not create a boundary. |

Recommendation: accept same-user control and state it in the threat table. It is
not a secret leak, and the app must be controllable by the person. A same-user
process already has the person's authority. This is a security decision for the
owner, not a technical choice. The one process-level exception is that a later
pipe instance is denied by the DACL; that does not create an account boundary.

Blocks: G2.
Evidence needed: maintainer sign-off, V03, and S24.

### O19. Adapter identity before the first route (B2)

| Option | Consequence |
|---|---|
| Service creates and owns the Wintun adapter | The service knows the name, LUID, and GUID before launch. It records them in the intent. It can close the adapter after an engine crash. Needs cross-process Wintun open and a narrow adapter DACL. |
| Engine creates the adapter and reports identity before routes | Smaller change. The service records identity and sets `routes_may_exist=1` before it acknowledges route installation. A crash before the report cannot have installed a route. |
| Keep the revision 2 ordering and accept an inconclusive check | Rejected. It makes an ordinary crash depend on the administrator override. |

Recommendation: service-owned adapter if V90 proves it. Otherwise the engine
handshake. Do not keep the inconclusive ordering.

Planned GUID (E5), a sub-decision:

| Option | Consequence |
|---|---|
| Fresh random `guid_planned` per intent, passed to Wintun as the requested GUID | A leftover adapter from an earlier intent is distinguishable. A match is `Present` or `Inconclusive`, never `Clean`. Network location awareness may keep one profile per GUID, so profiles may accumulate. |
| One fixed GUID per install | No profile growth. A leftover adapter from any earlier intent looks the same as this one, so recovery is more often `Inconclusive`. |
| No requested GUID | Wintun or Windows picks one. Nothing is known before the adapter exists. Rejected. |

Recommendation: a fresh GUID per intent, with the profile count measured at
R23. If profiles accumulate, the maintainer decides between a cleanup step and
the fixed GUID.

Reason: recovery must not depend on a manual action for a crash that happened
before the adapter was observed. The route gate is the conservative part; the
ownership split is the stronger part.

Blocks: G4.
Evidence needed: V80 to V83, V90, V100, and R23.

### O20. Source-silence monitor policy (B1)

| Option | Consequence |
|---|---|
| Three-state link evidence, CLI-equivalent source timer | Unknown link never becomes link loss and never clears source silence. An unrun probe is no evidence. The service can stop after 90 seconds. |
| Keep the GUI `auto_stop_sample` behavior | Unknown link resets the timer. The service would not stop on source silence. This copies the known gap. |
| Add a hotspot link observer now | Enables a separate `hotspot_lost` stop. More Windows API work and a new claim. Not chosen. |

Recommendation: three-state evidence. Do not claim a hotspot-loss stop. Do not
describe the CLI and GUI as the same.

Revision 4 note (E11): the working tree now has an uncommitted GUI change,
`LinkWatch::Unobservable` in `rust/src/gui.rs`. It can stop after 90 seconds of
fresh silent probes on Windows, and it still resets on a stale, missing, or
`no_hotspot` probe. It is unverified and is not evidence for this decision. The
unsupervised bound is a separate decision, O23.

Blocks: G4 and G6.
Evidence needed: T3.20, T3.21, T3.22, and V96.

### O21. Orphan adoption proof (B3)

| Option | Consequence |
|---|---|
| No adoption; observe and block | A same-image process can deny service but cannot be trusted, cannot clear the latch, and receives no frame. Safe and simple. |
| Adopt by image path | Rejected. Any same-user process can run the installed image and match. |
| Adopt after a nonce challenge on a service-only channel | Stronger, but needs a new channel, a nonce on a descriptor, and a real test. Not designed or approved. |

Recommendation: no adoption in revision 3. A future nonce proof must pass V85
before O21 changes.

Revision 4 (E7): observing and blocking on any image-path match lets a same-user
copy of the installed image deny service. The recommended blocking rule is
narrower. A start is blocked only by the recorded PID with a matching creation
time, or, for a bounded 12 second wait, by a `SYSTEM`-token process of the
installed image created inside the recorded launch window. A process of the
image that runs under any other token is recorded and never blocks. This needs
the token read in architecture section 8.7 to work on a real host.

Blocks: G4.
Evidence needed: S32, S44, V84, V103, and V85 if the nonce path is taken.

### O22. Session and SCM timeout budget

| Option | Consequence |
|---|---|
| The table in architecture section 8.10 | One absolute request deadline, 12 second cleanup, 2 second drain, 20 second SCM hint, SCM stop wins over a pipe break. |
| Shorter SCM hint with no measured host value | A host can end the service before it writes the record. Rejected. |
| Longer cleanup with no bound | A hung engine keeps the service from stopping. Rejected. |

Recommendation: the table, plus a measured host SCM timeout at R18. If the host
timeout is shorter than 12 seconds, G1 records the design as not viable for that
host.

Revision 4 (E8) adds to the table: `SERVICE_ACCEPT_PRESHUTDOWN` with an explicit
20 second `SERVICE_CONFIG_PRESHUTDOWN_INFO`, start and stop checkpoints with a 3
second hint advanced once per second inside bounded steps only, a shutdown
fallback that writes the record without waiting, and a logoff filter keyed to
the controlling `TokenSessionId`. The 20 second preshutdown value can delay a
system shutdown by up to 20 seconds when an engine hangs. That cost is part of
this decision.

Blocks: G4.
Evidence needed: V94, V95, V104, V105, R18, and R24.

### O23. Bounded unsupervised interval (E2)

| Option | Consequence |
|---|---|
| Stop after 300 s without an `Accepted` answer, reason `observation_unavailable` | Bounds a tunnel with no usable supervision. A long DHCP renewal, an interface flap, or a sleep can cause a stop. The stop is not a loss claim and keeps pairing status honest. |
| A shorter bound, for example 120 s | Less time unsupervised. More stops during transient faults. |
| A longer bound, for example 900 s | Fewer stops. A stale tunnel runs longer, which is closer to the persistent proxy that invariant 13 forbids. |
| No bound | Rejected. Alternating silent and unavailable samples, or a permanently unreadable identity, keep the tunnel running forever. |

Rules that hold for every bounded option: the constant Windows `Unknown` link
never starts or resets the interval; only an `Accepted` answer resets it; an
unreadable identity is never `source_device_gone`; the stop never sets
`paired=0` by itself in phase 2 and never shows a pairing failure; a later
positive answer does not restart the tunnel.

Recommendation: 300 seconds for the service monitor. This is an owner decision,
because it trades availability against invariant 13. Whether the CLI and the GUI
adopt the same bound is part of this decision and is not assumed.

Blocks: G3 and G4.
Evidence needed: T3.23, V98, S38, and later a live run under G6.

### O24. Hotspot-side guard (E4)

| Option | Consequence |
|---|---|
| Guard on gateway MAC, SSID, and BSSID when readable; a change clears the credential; unknown blocks nothing | Catches a visible change of access point or gateway. A spoofer passes. A source device that randomizes its hotspot address forces a credential re-entry. |
| No guard | Simpler. Relies only on the target-side identity. Misses a visible change. |
| Treat a guard match as identity | Rejected. Every value is spoofable. |
| Require location permission so Wi-Fi values are always readable | Rejected. It asks for a privacy permission for a weak guard. |

Recommendation: the guard, memory only, never displayed or logged, and never
described as identity. Phase 2 remains the only identity.

Blocks: G2.
Evidence needed: S39, V99, and R22.

### O25. Controlling session scope on a shared machine (E8)

The service stops the tunnel only on logoff of the controlling session, the one
whose `TokenSessionId` opened the session. Lock, disconnect, and fast user
switching do not stop it. While the tunnel runs, its routes are machine-wide, so
traffic from every signed-in account uses the tunnel.

| Option | Consequence |
|---|---|
| Stop on controlling-session logoff only | Matches the macOS and Linux model of a live app. Another account's traffic uses the tunnel while the controlling account is switched away. |
| Also stop on disconnect of the controlling session | Fast user switching stops the tunnel. Another account must start its own. |
| Refuse to start while more than one session is signed in | Strongest separation. Blocks a common shared-machine case. |

Recommendation: logoff only, with the machine-wide route effect stated in the
app. This is an owner decision tied to O12.

Blocks: G1 and G4.
Evidence needed: V105 and R24.

## 2. Independent review gates

| Gate | Artifact | Entry condition | Exit condition | Owner |
|---|---|---|---|---|
| G1 Architecture and host | `WINDOWS_SERVICE_ARCHITECTURE.md` sections 4, 5, 10 | O1, O2, O4, O12, O15, O16, O17, O25 decided | A reviewer records approval of the process model, the host decision, and the runtime. No code before this. | Maintainer plus an independent reviewer |
| G2 Boundary and threat model | Sections 4.6, 5, 13, 14, and `REVIEW_RESPONSE.md` 1.1, 1.2, 1.4, 1.5, 9.4, 9.6, 9.7, 9.8 | O2b, O5, O8, O11, O12, O14, O18, O24 decided, and any O2b owner acceptance signed | A reviewer confirms the exact DACL mask and the matching client request, caller identity by impersonation, server identity, same-user residual risk, credential at rest, directory ownership, `SERVICE_QUERY_CONFIG`, no `FILE_CREATE_PIPE_INSTANCE`, the data-plane exposure, and the threat table. V01, V01b, V03, V04, V05, V11, V55, V66, V87, V89, V91, V97, V99, V107, and V108 pass in tier V, and R13, R14, R16, R17, R19, R20, R21, R22, and R25 pass in tier R. | Independent security reviewer |
| G3 Engine protocol and transport | Sections 6, 11, 12.1 | O3, O6, O9, O23 decided | The transport is chosen. The error code table, the status schema, the stopped-gauge rule, the `observation_unavailable` rules, and the TTL audit fields are approved. T3.01 to T3.24 pass for the chosen transport. | Engine owner plus reviewer |
| G4 Lifecycle and cleanup | Sections 8, 9, 10 | O7, O7b, O13, O14, O19, O20, O21, O22, O23, O25 decided | A reviewer confirms the launch intent, the adapter identity and route gate, the no-adoption rule, the stop sequence, the cleanup timeout, the latch, the manual override, the generation retry, the automatic-stop versus crash rule, the launch gate, the planned GUID, the orphan rule, preshutdown, checkpoints, the logoff filter, the nonfatal final frame, the session and SCM precedence, and that no path restarts anything. V20 to V24, V40, V41, V53, V54, V57 to V60, V67, V68, V71 to V73, V80 to V86, V92 to V96, V98, and V100 to V106 pass, and R23 and R24 pass in tier R. | Reviewer |
| G5 Test matrix | `TEST_MATRIX.md` | G1 to G4 approved | A reviewer confirms the tiers, that tier V needs no administrator, that tier R needs approval, that no row overclaims, and that no test pins an unsupported runtime. | Reviewer |
| G6 Live test | A live plan, not written | G1 to G5 approved, owner approval, a real hotspot and source device | The owner approves each run. Cleanup and rollback are written down and verified after the run. | Device owner |

### G1 exit checklist

- [ ] O1 decided: host, with the WinUI 2 XAML Islands spike result.
- [ ] O2 decided: service account.
- [ ] O4 decided: start mode.
- [ ] O12 decided: who may control the tunnel.
- [ ] O15 decided: runtime, with no .NET 8 target for new code.
- [ ] O16 decided: installer technology, with developer registration and a
      loose-file layout refused for real mode.
- [ ] O17 decided: installing-person SID.
- [ ] O25 decided: controlling session scope, with the machine-wide route
      effect stated in the app.
- [ ] The install layout is under `%ProgramFiles%` with no reparse path.
- [ ] No production enablement is claimed.
- [ ] A reviewer signs the one page summary in section 0 of the architecture.

### G2 exit checklist

- [ ] The pipe DACL is written as an exact SDDL string and reviewed. The user
      ACE is the numeric mask `0x00120183`, and each bit is justified.
- [ ] The app opens the pipe with exactly that mask, and no code path requests
      `GENERIC_WRITE`. S37, V97, and R19 pass.
- [ ] Caller identity comes from the connection token: an unparsed bounded first
      frame, `ImpersonateNamedPipeClient`, `OpenThreadToken` with `OpenAsSelf`,
      `RevertToSelf` on every path, then parse. The PID is diagnostics only.
      S42, V107, V108, and R25 pass.
- [ ] O24 decided: the hotspot-side guard is memory only and never described as
      identity. S39, V99, and R22 pass.
- [ ] The probe helper is in the threat table as a privileged parser of
      hotspot-side input, and it either runs restricted after R21 or is named
      in the owner acceptance.
- [ ] The caller identity steps are reviewed in order, including the failure path.
- [ ] The server identity steps are reviewed, including the SCM PID, the pipe
      owner check, the installed path, and `SERVICE_QUERY_CONFIG`.
- [ ] The pipe DACL omits `FILE_CREATE_PIPE_INSTANCE` for the interactive user.
- [ ] The same-user rows in the threat table say allowed, not blocked.
- [ ] Review H1 is stated: phase 1 cannot distinguish two hotspots with the same
      gateway IP and interface identity.
- [ ] Review H3 and E3 are decided: a proven split after R20 and R21, or a
      written owner acceptance with every field that O2b names, for each
      component that stays at `LocalSystem`.
- [ ] O5 decided: no credential at rest before phase 2.
- [ ] O11 decided: server authentication strength.
- [ ] O18 decided: same-user residual risk accepted.
- [ ] O2b decided: data-plane privilege.
- [ ] O14 decided: state record, with the protected directory.
- [ ] The threat table has no row that claims a protection the design does not provide.
- [ ] If the UWP bridge is chosen, `CallerPackageFamilyName` and one peer are
      checked, with S29 and V75.
- [ ] The install path refuses developer registration, a loose-file layout, and
      a reparse point, with S30, V76, and R15.
- [ ] V01, V01b, V03, V04, V05, V11, V55, V66, V87, V89, V91, V97, V99, V107,
      and V108 pass in tier V.
- [ ] R13, R14, R16, R17, R19, R20, R21, R22, and R25 pass in tier R, each with
      owner approval per run.
- [ ] S33, S35, S37, S39, S42, and S46 pass in tier H.

### G3 exit checklist

- [ ] O3 decided: pipe or HTTP fallback.
- [ ] Every engine error has a fixed code. The table in section 11.2 is approved.
- [ ] The status schema is closed. No free text, address, port, path, or log crosses.
- [ ] `ttl_bad` is always present and is the audited count.
- [ ] A stopped status publishes both counts as unknown, not as zero.
- [ ] O6 decided: source device count with `phone.connections_known`, and a
      separate `relay.tcp_flows_active` gauge.
- [ ] O9 decided: pairing scope.
- [ ] T3.01 to T3.24 pass for the chosen transport.
- [ ] O23 decided: the unsupervised bound, its value, and whether the CLI and
      GUI adopt it. `observation_unavailable` is never shown as a loss or a
      pairing failure. S38 passes.
- [ ] S34 passes in tier H.
- [ ] If the fallback is chosen, every rule in section 12.1 has a test.

### G4 exit checklist

- [ ] The launch intent record is written before `CreateProcess` and flushed.
- [ ] The adapter name is recorded before launch, and `routes_may_exist` is set
      before any route can exist.
- [ ] A matching image-path process is observed, never adopted.
- [ ] The stop sequence is reviewed step by step.
- [ ] The 12 second cleanup wait, the 2 second event drain, and the 20 second
      SCM wait hint are reviewed. The hint is not described as below a default.
- [ ] The latch is reviewed: who sets it, who clears it, and who may not.
- [ ] A normal automatic stop is not reported as a crash.
- [ ] O7 and O7b are decided: person `recheck` and the administrator override.
- [ ] O19, O20, O21, and O22 are decided.
- [ ] The generation retry is reviewed: new handles, new secret, late result discard.
- [ ] No path restarts the engine, the service, or the tunnel on its own.
- [ ] O13, O14 decided.
- [ ] V20 to V24, V40, V41, V53, V54, V57 to V60, V67, V68, V71 to V73, V80 to
      V86, and V92 to V96 pass.
- [ ] S36 passes in tier H.
- [ ] The launch gate is reviewed: no Wintun, socket, or route call before `go`,
      a 10 second gate, and self-exit on parent loss. S43, V101, and V102 pass.
- [ ] `guid_planned` is fresh per intent and never yields `Clean` on a match.
      V100 and R23 pass, and the profile count is recorded.
- [ ] The orphan rule blocks only a recorded engine or a bounded `SYSTEM`-token
      candidate. A user-token copy never blocks. S44 and V103 pass.
- [ ] Preshutdown, checkpoints, and the controlling-session logoff filter are
      reviewed. S40, V104, V105, and R24 pass. O25 decided.
- [ ] A missing final frame is `cleanup=unknown`, never `cleanup=failed`. T3.24,
      V106, and S41 pass.

### G5 exit checklist

- [ ] No tier H row creates a pipe, process, socket, adapter, or route.
- [ ] No tier V row needs an administrator, an install, or a route.
- [ ] Tier R is marked as needing owner approval per run.
- [ ] Tier L is marked as not approved and not designed.
- [ ] L02 records no Windows hotspot-loss claim.
- [ ] V88 records the same-IP same-identity limitation instead of a detector
      claim.
- [ ] S29, S30, S31, V75, V76, V77, and R15 exist for the 82046682 conditions.
- [ ] S32, S33, S34, S35, S36, V80 to V96, R16, R17, and R18 exist for the
      fourth review.
- [ ] S37 to S46, T3.23, T3.24, V97 to V108, and R19 to R25 exist for the fifth
      review.
- [ ] Every row has a "not proven" entry that is not empty.
- [ ] No row pins .NET 8.

### G6 exit checklist

- [ ] The device owner approves the run in writing.
- [ ] The run uses a real hotspot and a real source device.
- [ ] The route table is recorded before and after.
- [ ] Cleanup is verified with the read-only route check.
- [ ] The run is recorded as a live result, not as a design result.
- [ ] No result claims a Windows hotspot-loss stop.

## 3. Risk register

| Risk | Likelihood | Effect | Mitigation | Owner |
|---|---|---|---|---|
| The desktop host decision is rejected | Medium | The boundary must still work for UWP, and the suspension stop returns | Keep the pipe boundary host neutral, and record the UWP bridge as compatibility work | Product |
| The WinUI 2 XAML Islands host does not build on a supported runtime | Medium | The real-mode UI has no host | The host spike under O1, and the UWP preview stays until it passes | Product |
| A same-user process controls the tunnel | Certain by design | Start, stop, credential set, and session denial | State it plainly, accept it in O18, keep the secret out of reach, and record the caller | Security owner |
| The control pipe is rejected | Medium | The WinHTTP timing rules and the port proof become mandatory | Section 12.1 and V10, V12, V40 to V42 | Engine |
| The cleanup latch is cleared too early | Low | A start overlaps a live cleanup and two engines exist | Launch intent, absence proof, a person action, and V53, V54, V58, V59, V67, V68 | Service |
| The cleanup latch never clears | Medium | The person is locked out | The O7b administrator override with an audit record, and V58 | Service |
| The engine runs as `LocalSystem` and its API is exploited | Low to medium | Full system compromise | The fixed operation set, the redacted schema, the caller identity, and one pipe | Security |
| A connection count is shown with the wrong meaning | Medium | A source device count and a target relay gauge are confused | Keep `phone.connections` from the phase 2 authenticated status, add a separate `relay.tcp_flows_active`, publish unknown instead of a guess, and T3.14, T3.17, V45 | Engine |
| A standard user pre-creates the `ProgramData` directory | Medium | Link or junction redirection | Installer creates and checks the protected directory, and V66 and R09 | Installer |
| A loose-file or developer registration layout is used for real mode | Medium | The engine runs from a user-writable path | Real mode is a per-machine MSI under `%ProgramFiles%`, the service refuses an outside path, and S30, V76, and R15 test it | Installer |
| A post-exit port takeover receives a usable bearer | Low | A same-user process answers as the engine | Fresh endpoint proof every generation, no cached endpoint, and V10 and V12 | Engine |
| The UWP bridge accepts another app or a second peer | Low | The wrong app controls the session | `CallerPackageFamilyName` check, one peer, and S29 and V75 | Product |
| The unreachable preview is mistaken for a real path | High if the status line is ignored | Someone ships a non-working feature | The status line says preview, and G1 blocks code | Maintainer |
| A credential at rest leaks to another hotspot | Medium if O5 is taken early | A token is sent to the wrong source device | No at-rest credential before phase 2, and V63 and V64 | Security owner |
| A service crash leaves an engine and routes | Low | Routes remain after a crash | The launch intent, the parent pipe, the state record, and the read-only check | Service |
| The Windows GUI source-silence gap is copied into the service | Medium | The service never stops on source silence | Three-state link evidence, T3.20 to T3.22, and V96 | Engine |
| A crash leaves no adapter identity | Medium | The latch is inconclusive and a person is locked out | The exact name and route gate, V80 to V83, and V90 | Service |
| A same-image process spoofs an orphan | Medium | The service waits on the wrong process or clears a latch wrongly | No image-path adoption, S32, and V84 | Service |
| `SERVICE_QUERY_CONFIG` is missing from the install | Medium | The server proof cannot run | S33 and R16 | Installer |
| A stopped status publishes a false zero | Medium | The app shows a count it did not measure | Unknown-on-stop rule, S34, and V86 | Engine |
| A same-IP hotspot receives the phase 1 token | Medium | The token reaches the wrong source device | Link identity binding, memory-only credential, V87 and V88, and phase 2 identity | Security owner |
| A later pipe instance is possible | Low | A same-user process answers as the service | The DACL omits `FILE_CREATE_PIPE_INSTANCE`, V89 and R17, and the SCM PID check | Security owner |
| A data-plane defect becomes a system compromise | Low to medium | Full host compromise | The split in O2b, V90 and V91, or a written owner acceptance | Security owner |
| A normal auto-stop is reported as a crash | Medium | Start is disabled and the person sees a false failure | Final frame and drain rule, V92 and V93 | Service |
| The SCM stop timeout is shorter than cleanup | Medium | The record is not written before the process ends | Measure at R18, record at G1, and keep the 12 second cleanup | Service |
| .NET 8 support ends before implementation | High if ignored | No security updates | O15 targets .NET 10 LTS, and S26 fails a new .NET 8 target | Maintainer |
| The design is mistaken for approval | High if the status line is ignored | Someone implements an unapproved design | Every file starts with UNAPPROVED, and G1 blocks code | Maintainer |

## 4. Handoff

If another agent or person continues this work:

1. Read `README.md`, then `WINDOWS_SERVICE_ARCHITECTURE.md`, then this file.
2. Do not implement anything until G1 and G2 pass.
3. Do not treat a recommendation as a decision.
4. Do not run tier R or tier L without the device owner's approval.
5. Do not claim a Windows host result. There is none.
6. Do not claim a Windows hotspot loss stop. There is none.
7. Do not describe the Windows CLI and GUI source-silence paths as the same.
   They are not. The CLI path runs with a positive link closure. The GUI
   `LinkWatch` change is uncommitted and unverified, and it resets on a stale or
   missing probe. Neither has the O23 bound.
8. Do not claim the engine is least-privilege. It runs as `LocalSystem` in the
   prototype. O2b is open.
9. Do not adopt an orphan by image path. The design does not.
10. Do not enable production. The preview is unreachable and no production path
    exists.
11. When the design changes, add a new revision. Do not rewrite history in place.
12. Do not describe `observation_unavailable` as a hotspot loss, a source device
    loss, or a pairing failure. It is proposed and not implemented.
13. Do not treat SSID, BSSID, gateway MAC, or a phase 1 token acceptance as
    source device identity.
14. Do not sign or imply the O2b owner acceptance, the O23 value, or O25 on the
    owner's behalf.
    The existing `experiments/` work keeps superseded revisions.
