# Multiplatform production roadmap

This is the shared goal and task list for HotspotShade on macOS, iOS,
Android, Linux, and Windows. A checked task needs linked evidence from the
current implementation and the relevant platform. A demo, a compile, or a
mock test alone does not establish production support.

## Product outcome

A person can install the apps, connect a target device to a source device,
pair when the source app is needed, start and stop the connection, and see
what happened. All supported platforms provide the same user-facing features
and protocol behavior, with native controls and OS-specific presentation.
The apps must work together across OS boundaries. Direct mode remains usable
without a source app. Do not hide an unsupported OS capability or a leak risk
behind a parity label.

Phones provide connections: iOS and Android are source devices. Desktops use
the connection through a tunnel interface: macOS, Windows, and Linux are
target devices. The maintainer confirmed this role split. The two phone apps must
have source feature parity, and the three desktop apps must have target feature
parity. Every phone OS must interoperate with every desktop OS. Direct mode on
each desktop still works without a source app.

## Current evidence

| Platform and role | Current state | Production gap |
|---|---|---|
| macOS target | Rust tunnel and SwiftUI app exist. An earlier build was tested on a live hotspot. | Revalidate the current changes, releases, failure recovery, and every supported source pairing. |
| iOS source | Swift app, proxy, and pairing exist. Current changes build and pass logic tests. | Revalidate the current build on a device and in cross-platform live tests. Background operation is subject to iOS limits. |
| Android source | Compose UI wired to the real source proxy and pairing listener, with real Start and Stop, real state, real connection counts, real Forget one and Forget all, real token rotation, a notification permission flow, and a separate labeled preview mode. A source proxy foreground service, a pairing responder and listener (port 18090) on the shared protocol, in-tree X25519 and ChaCha20-Poly1305, Keystore token storage, and a saved proxy port exist. The source proxy serves TCP and UDP, IPv6 CONNECT and UDP destinations, and the private ICMP echo commands `0x81` and `0x82` through an unprivileged ICMP datagram socket. It applies the phase-aware session capacity from the iOS app, and the relay cap follows the open-file limit. On 2026-11-05 the real Rust target client completed two pairings, a 64 KiB TCP echo, an ICMP echo, and an IPv6 destination through the emulator loopback, the VM build and 217 JVM tests passed, lint reported 0 errors, and the APKs built. | No live hotspot test, no real phone or carrier test, and no background pairing. The pairing listener is foreground only. The IPv6 case used the emulator loopback; the emulator has no cellular IPv6 route. |
| Windows target | WinUI 2 simulated preview and a Rust source device proxy tunnel start path. The command-line `gui` and `tun` commands start the tunnel with a Wintun DLL supplied at run time, the Windows socket helpers, and the native route boundary. Hermetic start, stop, cleanup, and missing-DLL tests pass on a macOS host and type-check for x86_64 and i686 Windows. | No live Windows hotspot test. No WinUI engine connection or protected service boundary. Direct mode, pairing in the command-line GUI, and a signed installer are missing. |
| Linux target | Electron target app with a labeled demo backend, a protected engine boundary to the real Rust `gui` service, a separate Settings window, a tray item, desktop notifications, XDG launch at login, system light, dark, and high contrast themes, and an in-tree axe-style accessibility check. A packaged `.deb` holds the app, the engine, a pkexec helper, and a polkit action. A disposable VM passed the 127 Node tests, the sandboxed smoke test, the Settings window test, the accessibility check, the real engine demo smoke test, the real app entry point test, the helper test with a fake engine, the package build and install, and the packaged app in engine demo mode. The Rust direct-mode and source-proxy tunnel starts use a dedicated routing table. A disposable VM passed direct IPv4 flows with TTL 65, a verified IPv6 block, an explicit IPv6 forward start, source-proxy TCP and IPv6 flows, a 20-second link-loss stop, SIGTERM cleanup, and a SIGKILL run. The run left no link, rule, route, or TUN device. | No live hotspot test. No polkit prompt on a real desktop session. The tray item and notifications are untested on GNOME, KDE, and tiling window managers. Direct mode is not wired to the app. A crash still leaves policy rules. |

### End-to-end release matrix

Each cell requires a real phone and desktop, current build identities, the
tests in step 4, and a linked result. An empty cell is not a pass. Earlier
macOS and iOS hotspot evidence does not establish the current build.

| Source phone | macOS target | Windows target | Linux target |
|---|---|---|---|
| iOS | [ ] Current build verified | [ ] Current build verified | [ ] Current build verified |
| Android | [ ] Current build verified | [ ] Current build verified | [ ] Current build verified |
| Direct mode, no source app | [ ] Current build verified | [ ] Current build verified | [ ] Current build verified |

See [GOAL.md](../GOAL.md), [AGENTS.md](../AGENTS.md),
[PORTABILITY.md](../PORTABILITY.md), and [PHONE_PROXY.md](../PHONE_PROXY.md)
for current behavior and constraints. Source files and current test results
take precedence over an old status statement. Update these documents when
behavior changes.

## Decisions and approval

- Use the available iOS Simulator and Android Emulator for development tests,
  including mocked networks. They do not replace the live phone and carrier
  tests in the release matrix. Installing on a personal phone still needs
  approval.
- Ask the maintainer before installing, replacing, signing into, or removing a
  build on a phone or other personal device. Explain the exact build, device,
  effect on the existing app and saved trust, and how to revert. Do not send or
  request passwords or tokens in chat.
- Ask before a live hotspot, tunnel, routing, carrier, or device test. State
  whether it can interrupt the connection and how to clean up. Do not run it
  until the maintainer authorizes that test. An unrelated test approval does not
  authorize installation or a different disruptive test.
- Ask for product direction when an OS restriction,
  security tradeoff, feature difference, cost, or irreversible release choice
  has no agreed answer. Present concrete options and their consequences.
- Pairing and access approvals in the app must be explicit, bound to the
  displayed request, and understandable on the source device. Do not confuse
  these product prompts with permission to use a test device.
- The maintainer authorizes temporary Windows Developer Mode on the Windows test
  host for development. Record and restore the prior settings. Follow any tool
  policy requiring action-time confirmation.
- Perform reversible implementation, hermetic tests, mock reviews, and build
  preparation without stopping for unnecessary approval. Keep test artifacts
  separate from production credentials and personal traffic.

## Shared feature parity

For each supported role and OS, track implementation, automated evidence,
device evidence, and remaining differences. A feature is not complete when a
screen only simulates it.

| Feature | Production requirement |
|---|---|
| Setup and discovery | Find the eligible local hotspot and explain permission or network failures. No manual address, port, or token is needed for normal pairing. |
| Pairing and trust | Match protocol and test vectors across implementations. Show and bind approval to the exact request. Support cancel, denial, expiration, forget, and re-pair. Explain token rotation and revocation limits. |
| Start and stop | Offer equivalent controls and show the real state. Stop idempotently and remove owned resources. Never restart automatically after a loss or failure. |
| Direct and source-proxy modes | Preserve direct mode without a source app. Support source-proxy TCP and UDP, remote DNS, and the agreed ICMP behavior. Keep one inner flow per outer socket. |
| IP behavior and DNS | Audit TTL or hop limit 65 and physical-interface pinning. Keep DNS on normalized outer sockets. Preserve explicit IPv6 policies and document actual leak paths. |
| Status and recovery | Show stale, unavailable, source missing, hotspot lost, capacity, and actionable errors without claiming success from a demo or stale data. |
| Activity and diagnostics | Show real bounded counters, failure stages, and privacy-safe reports. Do not expose tokens, keys, or personal traffic in logs or reports. |
| Settings and access | Support equivalent settings, accessibility, keyboard or touch navigation, reduced motion, light and dark appearance, and OS-native notifications where permitted. |
| Lifecycle and security | Protect credentials and local control channels, enforce parent-loss shutdown, and explain OS background restrictions. |
| Delivery | Provide signed, updateable packages and documented install and rollback paths for each supported OS and architecture. |

## Linux target app parity

The Linux app matches the macOS target features where the Linux desktop
allows. The items below are implementation state and test evidence. They do not
replace the release matrix.

| Feature | Linux state | Evidence | Difference from macOS |
|---|---|---|---|
| Main window, Dashboard, Activity, pairing | Implemented. | Node model tests, sandboxed smoke test, engine demo smoke test. | None. |
| Settings window | Implemented as one second BrowserWindow with General, Pairing, and Advanced. | `test:settings-window`, accessibility check. | It is a normal window, not a macOS settings sheet. |
| Let ping work | Implemented in Settings and sent on Start. | Model, IPC, and engine demo tests. | None. |
| Launch at login | Implemented in a packaged app with one XDG autostart file. The toggle reads the real file. | Settings and autostart tests. | `SMAppService` on macOS, `.desktop` on Linux. |
| Notifications | Automatic stop reasons, pairing results, and engine loss. The setting controls them. | Policy, sink, and monitor tests. | The tray and notification service are not tested on a real GNOME or KDE session. |
| Tray or menu bar item | Start, Stop, Open, and Quit. | Menu and tray tests. | StatusNotifierItem when a host exists. A plain no-tray fallback otherwise. |
| Light, dark, high contrast | System, light, dark, and a high contrast token layer. | Accessibility check, CSS source test. | High contrast follows `prefers-contrast` and `forced-colors`. |
| Keyboard and screen reader | Skip link, landmarks, names, focus rings, tab and arrow keys, target size, live regions. | In-tree axe-style check over 9 states and 8 focus stops. | This is not a full axe-core or screen-reader run. |
| Engine boundary | Fixed loopback operations, secret on descriptor 3, liveness on 4, parent-loss stop. | Node boundary and process tests, real engine demo smoke test. | None. |
| Privileged start | Packaged app calls pkexec with the fixed helper and no other argument. The helper starts the fixed engine. | Fake helper transport test, real helper with a fake engine, package install. | The macOS helper protocol is different. The Linux helper runs the whole engine as root. |
| Package | One unsigned `.deb` with app, engine, helper, polkit action, desktop entry, and icon. | VM package build and install. | No signed package or update feed. |
| Live tunnel | Engine start path exists. The app uses source device proxy mode. | Rust VM tunnel tests. | No live hotspot or source device test. Direct mode is not in the app. |

## Work plan

### 1. Establish the contract

- [ ] Confirm supported versions and architectures, and first production
  release scope with the maintainer. Keep the confirmed phone-source and
  desktop-target role split.
- [ ] Maintain a feature matrix with owners, implementation state, automated
  tests, live evidence, and explicit OS differences. Compare every user-facing
  change against all five platforms.
- [ ] Define shared protocol versions, compatibility rules, discovery,
  lifecycle states, error vocabulary, privacy rules, and migration behavior.
- [ ] Resolve the six-digit pairing code search risk with a reviewed protocol
  and user experience. Keep current rate-limit and prompt-binding limits
  explicit until a stronger protocol is implemented and tested. Done so far:
  the Rust, iOS, and Android responders share per-address and global challenge budgets,
  approval bound to connection, prompt, code, and deadline, canonical peer
  keys, and a capped inactive deadline, with mirrored tests and an independent
  review. Still open: the known-key path is not rate limited, the iOS responder
  does not track AEAD nonce reuse, no live-device test exists, and a stronger
  protocol (longer code or a PAKE) is not designed.
- [ ] Specify safe resource ownership and cleanup on partial start, normal
  stop, parent loss, crash, reboot, and unexpected device removal. Do not
  delete resources whose ownership cannot be proven.

### 2. Complete platform engines and source apps

- [ ] Revalidate macOS target and iOS source behavior after the current
  interruption, session-capacity, pairing, and UI changes.
- [ ] Implement Android source discovery, hotspot-only listener, token
  protection, pairing, TCP and UDP proxy, lifecycle, foreground service,
  notifications, and a real UI. Test supported Android versions and ABIs.
  The source proxy foreground service wires the cellular selector, the hotspot
  finder, the resolver, the network echo sender, and `SourceSocksServer`, and
  stops on network or hotspot loss. The server serves TCP and UDP, IPv6
  CONNECT and UDP destinations, and the private ICMP echo commands with the
  phase-aware capacity from the iOS app. The app UI controls the real service
  and shows the real state, the real connection counts, the real trusted list,
  and the real token rotation. The pairing responder and listener pass the
  shared vectors and the Rust target client interop test. The Rust target client
  also completed a 64 KiB TCP echo, one ICMP echo, and one IPv6 destination
  through the server on the emulator loopback. It still needs a real
  `ConnectivityManager` test, a network whose capabilities arrive after
  `onAvailable`, a live cellular IPv6 and ICMP test, real background behavior,
  a live cellular-path test, a real phone hotspot test, a rendered real prompt
  on a hotspot, and a background pairing lifecycle.
- [ ] Implement Windows relay, physical-interface pinning and audit, Wintun
  device and address lifecycle, IPv4 and IPv6 policies, route ownership,
  service boundary, automatic stop, and cleanup. Verify native APIs on Windows.
  Done so far: the source device proxy start path opens an explicit Wintun DLL,
  runs the portable relay on raw IP frames, pins outer sockets with TTL 65,
  installs the two IPv4 `/1` routes and the IPv6 `2000::/3` route with LUID and
  GUID ownership proof, and removes them on every exit path. Hermetic tests use
  a fake device and a fake route controller. Open: a live Windows hotspot test,
  read-only route verification against live Windows APIs, full hotspot-loss
  auto-stop, direct mode, a protected service boundary for the WinUI app, and
  Windows device tests.
- [ ] Implement Linux relay integration, TUN and address lifecycle, interface
  binding and audit, DNS, owned routes, IPv6 block and forwarding, automatic
  stop, and cleanup. Done: direct mode and source device proxy mode start in the
  Rust engine. Both use table 700, rules 17000 and 17001, recorded ownership,
  and cleanup on every exit path. The start gate verifies the IPv4 `/1` routes
  and the selected IPv6 policy. Block mode proves the `2000::/3` blackhole from
  the table dump and one fake FIB lookup per probe. The worker stops after 20
  seconds without the physical link. A disposable VM passed direct IPv4 flows
  with TTL 65, the block and forward starts, source-proxy TCP and IPv6 flows,
  SIGTERM cleanup, and a SIGKILL run. The Electron app is wired to the real
  engine, starts a packaged engine through a pkexec helper, and has a tray,
  notifications, XDG launch at login, a separate Settings window, high contrast
  themes, a package script, and an in-tree accessibility check. Open: a live
  hotspot test, a polkit prompt on a real desktop, the tray and notification
  paths on GNOME, KDE, and tiling window managers, direct mode in the app, and a
  periodic route re-check after a privileged process changes table 700.
- [ ] Record genuine OS limits and obtain product direction for alternatives
  when a required source or target feature cannot be implemented as specified.
- [ ] Close shared-control gaps: authenticated private transport, bounded
  shutdown, parent loss, process exit, and observable cleanup failure. Do not
  wire a foundation that cannot meet its security contract.

### 3. Complete app and interaction parity

- [ ] Connect each native UI to the real engine through a protected boundary.
  Keep demos labeled and prevent demo data from appearing as real status.
- [ ] Translate the macOS target experience to WinUI 2 on Windows and Electron
  on Linux. Match features and behavior while using native controls and OS
  conventions. Resolve current layout defects at wide and narrow sizes.
- [ ] Complete the Android source UI against the real service. Match the iOS
  source experience and adapt interaction and motion to Android conventions.
  Done: the Dashboard Start and Stop control starts and stops the real
  foreground service, the real state and connection counts show, the real
  Forget one, Forget all, and token rotation actions change the stores, the
  notification permission flow is in place, and the preview mode is separate
  and labeled. Open: a real phone and hotspot run, and background pairing.
- [ ] Exercise all app states, errors, navigation, notifications, screen readers,
  keyboard and touch access, text scaling, theme, and reduced motion. Measure
  Electron memory and responsiveness on representative Linux desktops.

### 4. Verify end to end

- [ ] In CI, run shared protocol vectors, mocked source-device flows, local
  loopback tests, platform-specific unit tests, build, lint, and accessibility
  checks. Keep CI hermetic: no real routes, TUN devices, or credentials.
- [ ] Run a versioned interoperability matrix for iOS and Android sources
  against macOS, Windows, and Linux targets. Cover each supported source and
  target version, plus direct mode on each supported target.
- [ ] With prior maintainer approval, install test builds and exercise first pair,
  known pair, denied and expired requests, cancel, forget, token rotation,
  source and target restarts, upgrade, and rollback. Confirm saved trust and
  settings behave as documented.
- [ ] With prior approval, verify real TCP, UDP, DNS, IPv6, and ICMP flows;
  concurrent and long-lived traffic; idle, half-close, zero-window recovery;
  weak link, hotspot loss, source loss, sleep, background, and reconnect.
- [ ] Verify physical-interface pinning and TTL on the target, route and DNS
  selection, owned-resource cleanup, failed setup, process termination, and
  post-test network state. Record more-specific route and local DNS bypasses;
  do not claim fail-closed operation without proof.
- [ ] Measure latency, throughput, memory, CPU wakeups, battery, capacity, and
  recovery on representative hardware. Agree acceptance thresholds with the
  maintainer before declaring the performance work complete.
- [ ] Record platform, versions, build identity, date, test method, results,
  limitations, and cleanup evidence for each live run. Do not retain private
  traffic, credentials, or packet captures with personal data.

### 5. Production release gates

- [ ] Complete independent security and platform reviews. Resolve or explicitly
  accept each finding with the maintainer before release.
- [ ] Provide signing, installer, update, rollback, trust migration, and support
  documentation. Keep signing credentials out of the repository and CI artifacts.
- [ ] Confirm all required CI jobs pass on the release revision. Test signed
  artifacts on supported devices with explicit maintainer approval.
- [ ] Review the feature and interoperability matrices with the maintainer. Resolve
  every missing feature, unsupported combination, and material OS difference.
- [ ] Obtain the maintainer's production release decision for the exact artifacts.
  Do not equate a successful build or isolated demo with a production release.

## Evidence and completion

Keep task status next to the relevant feature and link to reproducible tests or
dated evidence. Reopen a task when the code or supported platform changes.
Production is complete only when all agreed roles and combinations work, the
parity and safety gates pass, the maintainer approves required device tests and the
release, and the documented behavior matches the tested artifacts.

### Emulator evidence (development only)

- 2026-11-04: the iOS source app (Debug simulator build, no signing) installed
  and launched on the iPhone 17 simulator (iOS 27.2). The Dashboard, Off
  state, waiting-for-target text, and tab bar rendered. The simulator has no
  Personal Hotspot interface, so the listener, pairing, and proxy paths were
  not exercised. This is not a release-matrix result.
- 2026-11-04: with `172.20.10.0/28` free,
  a mimicked hotspot interface (`bridge100`, `172.20.10.1/28`, created and then
  destroyed with `ifconfig`) let the real iOS app run its listeners in the
  simulator. The Rust pairing client (`rust/tests/ios_simulator_pairing.rs`,
  ignored, `HS_IOS_SIM=1`) paired with the Swift responder: both showed the same
  six-digit code, the prompt was approved in the simulator UI, and the client
  received credentials. A second run paired without a prompt (known device) and
  authenticated to the iOS proxy (`PROXY_AUTH_OK`, 2 outer sockets, 0 TTL audit
  failures). The simulator has no cellular path, so a destination CONNECT was
  not tested. The interface list matched the baseline after cleanup. The
  mimicked interface cannot be used while a real phone holds `172.20.10.0/28`.
  This is development evidence, not a release-matrix result.
- 2026-11-05: a disposable Linux VM
  ran `./gradlew testDebugUnitTest lintDebug assembleDebug
  assembleDebugAndroidTest`: 173 JVM tests passed, lint reported 0 errors and
  7 version warnings, and the debug and test APKs built. The Pixel 8 API 36
  emulator (`emulator-5554`) installed the APKs. The instrumented
  `PairingInteropTest` served the real Kotlin responder on the emulator
  loopback, and the real Rust target `pair_at` client
  (`rust/tests/android_pairing_interop.rs`, ignored, `HS_PAIRING_PORT`) completed
  two pairings. The first pairing was unknown and the test approved the prompt
  automatically. The second used the trusted key and needed no prompt. The
  audit counted 2 outer sockets and 0 TTL failures. The real app showed the
  pairing listener as off because the emulator has a Wi-Fi client interface and
  a cellular interface, not a hotspot; the real prompt was not rendered in the
  app. This is development evidence, not a release-matrix result.
- 2026-11-05: the Pixel 8 API 36 emulator showed the wired Android app. The
  real Dashboard showed Off, Waiting for the hotspot, and On. The On state came
  from the instrumented service test with the test-only hotspot address. The
  Settings page showed the real listener state, the real empty trusted list,
  and the real Advanced counts. Preview mode showed a banner, a PREVIEW badge,
  and simulated values. The notification permission dialog appeared on the
  first Start. The instrumented service test passed its assertions, and the
  Rust `android_emulator_interop` and `android_pairing_interop` tests passed.
  The instrumented runner crashed at teardown while another device session held
  UiAutomation; the test method result was a pass. The emulator has no hotspot
  or cellular bearer, so this is development evidence, not a release-matrix
  result.
- 2026-11-05: the Android source proxy gained the private ICMP echo commands,
  IPv6 CONNECT and UDP forwarding, and the phase-aware capacity policy. A
  disposable Linux VM ran `./gradlew testDebugUnitTest lintDebug
  assembleDebug assembleDebugAndroidTest`: 217 JVM tests passed, lint reported
  0 errors and 7 version warnings, and the debug and test APKs built. The Pixel
  8 API 36 emulator returned echo status `SUCCESS` with a 7 byte payload from
  the direct ICMP test. The Rust target client
  (`rust/tests/android_emulator_interop.rs`, ignored) passed the token check, a
  64 KiB TCP echo to `10.0.2.2`, the wrong-token rejection, the unreachable
  destination, one `0x81` echo to `10.0.2.2`, and one IPv6 CONNECT to an echo
  listener on the emulator loopback `::1`. The audit counted 5 outer sockets
  and 0 TTL failures. The open-file limit was 32768, so the relay limit was 256
  and the total session limit was 288. The 6 service test methods and the
  serving service test passed; a fresh install needed `adb shell pm grant` for
  the notification permission because the UiAutomation grant did not complete.
  The runner still crashed at teardown after the result. The emulator has no
  cellular IPv6 route, so the IPv6 case used the loopback. This is development
  evidence, not a release-matrix result.

### Windows host test (open limit)

The Windows source device proxy start path compiles for
`x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` (check and clippy). The
hermetic start, stop, cleanup, and missing-DLL tests pass on the macOS host.
They have not run on a Windows host. The current tree still needs a Windows host
run. A live Windows tunnel test still needs a decision about route changes on
that host, because a captured default route cuts the remote test link. Until
then, the commands in `scripts/windows_relay_test.md` are untested on Windows,
and no live Windows hotspot test exists.


## Linux routing review findings

An independent review of the Linux routing code found no lockout and no deletion
from the main table. The 2026-11-05 fix resolves the ownership and start items:

- Fixed: rule ownership compares every selector before a delete: family, prefix
  lengths, destination, source, TOS, table, priority, action, flags, input and
  output interface, goto target, protocol, mark, mark mask, flow, tunnel id,
  suppress values, l3mdev, uid range, IP protocol, port ranges, port masks,
  DSCP, DSCP mask, and flow label. An unknown selector blocks the delete.
- Fixed: route ownership compares metric, preferred source, flow, source, and
  TOS in addition to the prefix, table, protocol, type, and output interface.
- Fixed: the manager records each rule and route key before the add. On an ACK
  timeout it reads the object again and keeps the record only when the object
  matches, so rollback removes an applied add.
- Fixed: an inner IPv6 TCP flow test passes through the TUN to the mock source
  device with a clean TTL audit and one outer connection. The test host supplied
  the IPv6 source address. See `docs/LINUX_TEST_VM.md`.
- Fixed: the start path compares the outer interface index recorded before the
  source device check with the index from the outer pin proof. A mismatch
  refuses the start.

Open:

- Unbound DHCP or ND traffic is captured. Test on a live host before release.
- The IPv6 flow test needs a host with an IPv6 source address. Test a live
  dual-stack hotspot host.
- A privileged process can change table 700 after the start gate. Linux has no
  periodic route re-check yet.

Evidence: on 2026-11-05 a disposable Linux VM
passed `cargo test --locked` (733 library tests and every integration test), the
ignored `linux_tunnel_vm` suite (10 tests, serial), clippy, and formatting. The
tunnel suite covered a direct IPv4 flow with TTL 65 and a pinned outer socket, a
verified IPv6 block, an explicit IPv6 forward start, a 20-second link-loss stop,
source-proxy TCP and IPv6 flows, SIGTERM cleanup, and a SIGKILL run. The same VM
left no `hs-tun`, `hs-host0`, `hs-src0`, network namespace, policy rule at
priority 17000 or 17001, or route in table 700.

## Evidence log, 2026-11-05

- CI had not produced evidence for the branch under test.
- A Windows Server 2025 test host: `cargo test --locked --tests` passed 555 tests with 0 failures and 4 ignored. This includes the Windows identity store with its ancestor ACL check, the Winsock readiness tests, and the relay end-to-end test on loopback. WinUI 2 state model: 44 checks passed. A live Windows tunnel test needs a decision on route changes on the test host, because a captured default route cuts the remote test link.
- 2026-11-05: Windows source device proxy start path implemented. `service.rs` starts Wintun from an explicit `wintun.dll` path, runs the portable relay on raw IP frames, and installs the IPv4 `/1` routes and the IPv6 `2000::/3` route through `windows_native_routes.rs` with LUID and GUID ownership proof. `cargo check` and `clippy -D warnings` pass for `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` from a macOS host. A host `cargo test` passes 598 unit tests and the integration tests, including 7 hermetic Windows start tests with a fake device and a fake route controller. Native Windows tests and a live hotspot test are still open. The DLL is not bundled.
- Windows identity fix: the volume root keeps removal and permission checks but no longer rejects create-file and attribute rights, because the root cannot be removed, renamed, or redirected. Lower ancestors keep the strict set.
- Android: pairing responder, hotspot-only listener on port 18090, token storage, real Start and Stop, Forget, and Rotate. The source proxy serves TCP and UDP, IPv6 CONNECT and UDP destinations, the private ICMP echo commands, and the phase-aware capacity from the iOS app. 217 JVM tests pass. Rust interop with the real target client passed a 64 KiB TCP echo, an ICMP echo, and an IPv6 destination on the emulator. Not tested on a real phone or hotspot.
- 2026-11-05: Linux target app parity. A disposable VM (Ubuntu 24.04 x86_64, Node 26.13.0, Electron 45.2.3) ran `npm test` (127 tests, 0 failed), `xvfb-run -a npm run test:smoke`, `npm run test:settings-window`, and `npm run test:a11y` (9 states and 8 keyboard focus stops, 0 violations). The real engine demo smoke test passed 40 checks. The real app entry point test passed 10 checks and left no engine child or temporary directory. `ARCH=x64 npm run package:deb` wrote an unsigned `.deb`; `dpkg -i` installed it after the VM added `xdg-utils` and `pkexec`; the packaged app started its engine in demo mode. The packaged app default path called pkexec and showed the plain authorization error in the headless session. The real pkexec helper ran as root with the test account id against a fake engine at the packaged path, returned one port, served `GET /api/status` with HTTP 200 and the descriptor secret, refused one argument, and exited 0 when stdin closed. The VM measured 585.4 MiB RSS and 273.5 MiB PSS at idle, and 623.5 MiB RSS and 295.2 MiB PSS in the active demo state. The polkit prompt, tray item, notifications, and launch at login were not tested on a real desktop session. No route or TUN device changed.
- Linux direct mode: `service.rs` and `platform_linux.rs` now start direct mode with no source device. The start gate verifies the IPv4 `/1` routes and the IPv6 policy. Block mode installs and verifies the `2000::/3` blackhole in table 700. The worker stops after 20 seconds without the physical link. In a disposable Linux VM, `cargo test --locked` passed 733 library tests and all integration tests, the serial ignored suite passed 10 tunnel tests, and clippy and formatting passed. The new tests covered a direct IPv4 flow behind a veth/netns echo server, the block and forward starts, and the link-loss stop. Cleanup left no link, namespace, rule, route, or TUN device. A live hotspot test is still open.
- Windows tunnel start path (source device proxy mode) is implemented behind trait seams with a mock Wintun device and fake route controller. Windows keepalive (SIO_KEEPALIVE_VALS, fixed 10 probes) is in. Native Windows run at commit 94fbee1: library 551 passed, 0 failed, all other targets ok, 4 ignored. A native run found a real FFI bug (CreateWellKnownSid missing its size argument, access violation); fixed. No Wintun adapter or route has been created. A live Windows tunnel test still needs a decision on route changes on the test host.
- macOS unsigned app build (scripts/build_mac_app.sh) succeeded after these changes.
