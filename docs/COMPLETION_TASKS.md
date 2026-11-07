# Completion goal and task list

Owner thread: "Complete HotspotShade macOS and iOS apps" (Opus 5.5), started
2026-11-06. This file is the working task list. It is not evidence. Evidence
lives in the files and logs named next to each item.

## Goal

Complete HotspotShade as one finished product across every platform: the iOS
and Android source device apps and the macOS, Windows, and Linux target apps.
Each app is a release candidate a person can install and use without technical
setup: no demo or preview mode, every visible control real, unbuilt or
decision-blocked features hidden and listed. The apps find each other on the
hotspot, pair once, and the target turns the tunnel on and off with one
button, with real status on both sides. Target apps open, pair, and change
settings as the signed-in user and ask for administrator rights only to
install the protected helper or start the route-changing tunnel. Every
AGENTS.md invariant holds on every platform: TTL 65 on every outer socket,
interface pinning, DNS and IPv6 policy, cleanup on every exit path, no Python,
no external hop. Done means each supported source and target pair is verified
on real hardware, with honest records of what is untested.

Order of work: iPhone to Mac first, then Windows on the owner's PC, then
Linux and Android, with parallel hermetic work on all of them.

## Approval boundaries

- Authorized: build, sign with the local Apple Development identity, install
  and run the macOS app, helper, engine, and right on this Mac, with cleanup
  and a rollback path.
- Not authorized yet: a live hotspot or tunnel test, any route or utun change,
  any phone install. Ask first, with the exact build, effects, and rollback.
- Linux VM source-snapshot transfer gate is closed (see AGENTS.md).

## macOS target

- [x] M0. Confirm the cancelled cleanup subagent stopped (interrupted
  2026-11-06 22:04) and record its partial edits: TunnelCleanupState,
  TunnelSession, TunnelRoutingBackend, EngineLaunch, AppModel,
  HotspotShadeApp, EngineLaunchTests. Its race tests were not written.
- [x] M1. Lifecycle edits finished (2026-11-06): six findings verified, four extra races fixed, 14 new tests incl. real-wiring "opens with only the user engine"; swift test 627 passed, 0 failed, 4 skipped (3 runs); unsigned app builds. Independent lifecycle review running.
  Original scope: Review and finish those lifecycle edits. Add tests for: cleanup
  retry after a lost engine reply, retained elevated session token adoption and
  the `finish` shadowing bug, quit gate token fencing after Stay, stale cleanup
  generation updates, no unrelated-session proof, durable-block recovery text.
  Full Swift suite passes.
- [x] M2. (real run on the installed RC: user engine only, no helper, no prompt) Show that the app opens, pairs, and edits settings with no
  administrator prompt and no root process. Test done (testOpeningTheRealWiringUsesOnlyTheUserEngine); real run on this Mac pending the install.
- [x] M3. Independent Opus review (2026-11-06): no non-admin route change, no token leak to argv, env, logs, status. Blocker B1: new installer and uninstaller reject the installed timeout-0 right. Should-fix: S1 socks5 root start skips the grant; S2 no deadline for an unauthorized root engine; S3 credential and parent descriptors inherited by route and scutil children; S4 no app or engine version floor (deferred). Notes: helper accepts many connections; handoff tokens not zeroized; route delete by destination.
- [x] M4. Fixed S1 (helper root engine refuses non-grant modes), S2 (120 s deadline for an unauthorized root engine), S3 (close-on-exec control descriptors), handoff limits and zeroize; Rust 1368 passed, ProtectedHelper 222 passed (2026-11-06). B1 handled by procedure (old coordinator uninstall, then new first install). S4 version floor deferred. Re-review running.
- [x] M4b. (done 2026-11-06: 12 items, 7 new tests, swift test 639 passed, 0 failed, 4 skipped; app builds) macOS UI review fixes: stale forgetBlocked gating; visible admin-prompt hint under Turn on and on retry; Activity log error state; demo labels on Activity, Pairing tab, pairing overlay, menu bar, and no real notifications in demo; failures text when status is unavailable; unavailable connection card and stale link advice; VoiceOver demo and checked text; Pair-disabled reason; duplicate stale line; tunnel-error notification body; scalable pairing code font; plain-English recovery strings.
- [x] M4c. (done 2026-11-06: 6 tests that fail on the old code; swift test 645 passed twice, 0 failed; KitTests pairing 40/40) Lifecycle review should-fixes: restart the user engine monitor after Stay; keep start-in-flight across a model rebuild; pass cancellation into the process start; KitTests pairing flake; stop flight clears its active task. Deferred: quit marks that only a relaunch clears (safe side); lost-reply mark not tied to a session; blocking helper calls on the shared pool.
- [x] M4d. (done: liveness watch race, descriptor checks before bind, authorization-timeout text, demo text; Rust 1551 passed, Swift 663 passed, 0 failures) ( plus stale demo text in build_mac_app.sh, macos_release_readiness.sh, PHYSICAL_DEVICE_VALIDATION.md) S1-S3 re-review lows: helper liveness timer can be stopped for a new session (remove stopLivenessWatch on session removal, main.swift ~347-441); validate --parent-fd and --handoff-fd open and of the right kind before GuiServer::bind (main.rs ~146-176, ~1652-1740) and reject handoff == token/parent on macOS; surface the authorization_timeout reason instead of "helper lost".
- [x] M4e. (fixed + regression tests in Rust and the Swift real-engine test) BLOCKER found by L6: macOS RustGuiBackend did not route the pair_handoff trait method (cfg linux only), so POST /api/pairing/handoff returned handoff_unsupported and Turn on would fail. cfg widened to macos+linux; regression test requested from the M4d agent; tree currently fails to compile at rust/src/gui.rs:114 from another in-progress edit.
- [x] M5. Rust check, clippy -D warnings, fmt --check, cargo test (1362 passed, 0 failed, 8 ignored), release build, GUI smoke passed, bash -n on 17 scripts (2026-11-06 baseline; re-run after the Mac and Windows edits land).
- [x] M6. (done 2026-11-06: build/mac-rc-20261106, reviewed) Rebuild the signed preview: app, helper, engine, right as one set.
  Review the build. Older staged previews are obsolete.
- [x] M7. (done 2026-11-06: old set uninstalled by its coordinator, rollback set kept, new set installed, app opened as user; evidence build/mac-rc-20261106-delivery/INSTALL_EVIDENCE.md) Inspect the installed preview (zero-timeout right), active tunnels,
  journals, and cleanup blocks. Keep a rollback copy. Remove it with its own
  coordinator, install the new set, verify, and run the app as the user.

## iOS source

- [x] I1. Swift logic tests (34 suites, ALL SWIFT TESTS PASSED), simulator build, `scripts/ios_source_proxy_flow_test.sh` (IOS_SIM_SILENT_CLOSED, IOS_SIM_PROXY_OK audit=(7, 0)), 2026-11-06.
- [x] I2. Simulator UI check through the device tools on a dedicated Simulator (iOS 27.2): Start without a hotspot shows "Needs attention" with guidance; Settings shows real empty states. Notes: a switch exposes the accessibility label "1"; the floating tab bar covers the "Refresh address" row until scrolled. Simulator only, no hotspot.
- [x] I2b. iOS pairing responder brought to Rust/Kotlin parity (2026-11-06): credential validation and strict parsing, status host check, per-session nonce guard, 2056-byte read bound, typed frame errors; 7 new tests; ALL SWIFT TESTS PASSED, IOS_SIM_PROXY_OK audit=(7, 0), Simulator build OK. Existing 32-hex tokens stay valid.
- [x] I2d. iOS review fixes (2026-11-06): stale pairing-unavailable line cleared on hotspot loss; accurate start, ambiguous-link, and Forget texts; one confirmation dialog; Keychain load left on main (no safe change). All iOS checks pass.
- [ ] I2c. iOS real-test UX fixes in progress (review 2026-11-06): unsupported hotspot message, stale Manual connection address, visible pairing-unavailable and Keychain-conflict states, pairing prompt needs a ready listener, expired-pairing status, diagnostics state matches the screen. Test with a Release build; do not use Debug hotspot override keys on the phone.
- [x] I3. Owner-approved install of the signed Release RC 0.1.0 (1) on Em's iPhone (in-place upgrade from 1.0 (1)); launch verified; evidence build/ios-rc-20261106/EVIDENCE.md. Profile expires 2026-11-10: rebuild and reinstall before then.
- [x] I3b. Owner-approved update install of the iPhone RC with today's fixes (2026-11-06 evening); evidence build/ios-rc-20261107/EVIDENCE.md.
- [x] I4. Live test approved 2026-11-06 (full). Attempt 1 at 18:03: Turn on showed no administrator prompt; the root engine exited before authorization; the helper wrote a durable cleanup block ("launch stop was not clean"). Verified afterwards: no HotspotShade routes, no blackhole, default route normal, no root engine. Fix in progress (root cause, no durable block for a pre-grant exit, helper exit reason, reviewed clear command). Test paused. ROOT CAUSE (fixed, reviewed): helper placed the token pipe over the pairing socket (descriptor order in RootEngineLauncher); engine exited before its port. Helper now treats a pre-grant exit as a failed start with a reason; reviewed preview-clear-cleanup-block added. Rust 1555, Kit 682, Installer 350 pass. 0.1.2 installed 2026-11-06 evening after clearing the block with the reviewed command; evidence build/mac-rc-20261107-delivery/INSTALL_EVIDENCE.md. RETRY PASSED 2026-11-06 ~19:28: Turn on works, IPv4 and IPv6 through utun10, HTTPS 200, Mac shows On with 40 source connections, off/on cycle without error; evidence build/mac-rc-20261107-delivery/LIVE_TEST_2026-11-06.md. Final Turn off verified clean (no routes, no utun10, no root engine, no mark). Open: TTL audit readout and carrier-side TTL.

## Windows target (background)

- [x] W0. First Windows pass (2026-11-06): console TestLauncher (real engine, no demo), exclusive loopback listener, reviewed; Windows Rust cross-check and clippy pass; not built on Windows. Verdict: not ready (gates closed, no pairing, WinUI simulated).
- Owner decisions 2026-11-06: enable gated proxy token use (physical adapter + gateway check); owner builds on own PC; real WinUI app + Windows pairing, remove DemoSession.
- [x] W6. Windows engine (2026-11-06, reviewed): token gate = default gateway on a physical adapter, re-checked every 2 s, first refusal stops; pairing, cancel, forget, handoff with the macOS/Linux API; Rust 1551 passed; Windows x86_64/i686 check+clippy clean; not run on Windows.
- [x] W7. WinUI wired to the real engine via broker + NativeAOT elevated starter (one UAC prompt at Turn on), DemoSession removed, unsupported features listed (2026-11-06, reviewed; Core 244, ServiceHost 281 checks pass; static contract and delimiter checks pass; not built on Windows). GetNamedPipeInfo on the handoff write end confirmed correct by the FFI audit.
- [x] W8. (fixed 2026-11-06: Broker builds 0 warnings in both configs; Core 250, ServiceHost 281 checks pass; static contract passes; Windows-only I/O paths not run) Broker compile review (real .NET 8 SDK at ~/.dotnet8/dotnet builds it clean): HARD BREAK RendezvousPipe manual-reset event makes every Turn on fail; also close-timeout handle loss, OpenAsync not retried, IPv6-disabled listener check, shutdown race, manifest EntryPoint, reply size. Fix in progress.
- [x] W9. (fixed 2026-11-06, reviewed: starter proves install root by final path, owner and DACL, package path, fixed disk; publish fix; Activity, test-data, Turn off fixes; Core 266, ServiceHost 281; not run on Windows. Risk: strict rule may refuse a genuine install - collect owner/SDDL/icacls per BUILD_AND_TEST_ON_PC.md section 5 on first install) Elevate + Core review (2026-11-06): HIGH SECURITY text-only WindowsApps trust lets a standard user get a payload run elevated via the signed starter; HIGH BUILD stage_payload.ps1 global PublishAot breaks publish; Activity silent after Turn on; test-data status wedges Starting; Turn off unavailable when status unavailable. Fix in progress (Opus, reviewed).
- [x] W10. (fixed 2026-11-06; static contract and delimiter checks pass; not built on Windows) UWP review: compiles as written; fixed min-version mismatch (csproj 17763 vs manifest 19041), attention list rebuilt every second, Activity list reset every 2 s, binding refresh, disabled Turn on reason, CoreWindow guard, MaxVersionTested, assembly version.
- [x] W-READY. Windows is ready for the owner's first PC build and test (2026-11-06) with windows/BUILD_AND_TEST_ON_PC.md: engine gate and pairing, real WinUI app, broker, hardened elevated starter. First compile of the UWP app and package happens on the PC.
- [ ] W1. Readiness assessment from current code and the linked Windows host:
  what is real, what is simulated, what is blocked by a product decision.
- [ ] W2. Real app, service, and engine integration needed for a first test.
- [ ] W3. Build and hermetic tests on the Windows host. No adapter or route
  change without approval.
- [ ] W4. Independent review of privilege and network changes.
- [ ] W5. Test handoff: prerequisites, signing, unsupported features.

## Linux target (background)

- [x] L1. Assessment: the app backend had no non-demo real-engine coverage; pair, forget and probe contact the gateway and are not hermetic on a Mac.
- [x] L2. linux/test/real-engine-backend.test.mjs (5 cases) drives the real non-demo engine through the real client, backend and router, a labeled helper stand-in, liveness and parent loss; start refusals verified; network snapshot unchanged. macOS host only.
- [x] L3. `cd linux && npm test`: 283 tests, 281 pass, 0 fail, 2 skipped (2026-11-06, macOS). Not run: Xvfb settings-window and a11y (no xvfb here), Linux execution (VM gate closed), Linux cross-check (rustup lacks rustc).
- [ ] L4. Still open: real Rust helper with pkexec and polkit, TUN and route cleanup on a live hotspot, a Linux run of the new test.
- [x] L5. (done 2026-11-06, reviewed; npm test 317, 313 pass, 0 fail, 4 skipped; not run on Linux) Packaging fixes: prerm/postrm, build-host and Depends, helper EPIPE panic, opaque exit 1, README root-process claim.
- [x] L6. (done 2026-11-06, reviewed; npm test 341, 337 pass, 0 fail; not run on Linux; HS2 handoff via helper fd 2 because pkexec closes fds above 2; old root identity unused, pair once again; packaged app has no demo) Was: the packaged app runs pkexec at window open (violates invariant 14 and needs a polkit agent). Move the dashboard, pairing, and settings to an unprivileged user engine and ask only at tunnel start, as on macOS.
- [x] L7. (fixed 2026-11-06, reviewed; npm test 349/338 pass 0 fail; with engine 363/359 0 fail) Linux review (2026-11-06): HIGH helper exit 1 before spawn locks the session as an unconfirmed stop (same class as the Mac Turn-on bug); confirmed stop reported failed when the user engine is gone; recovery actions unreachable while cleanup pending; stale status poll; engine start reason discarded; HS2 untested. Fix in progress.

## Source app parity (from the 2026-11-06 review)

- [x] P-iOS1. (confirmed 2026-11-06: the iPhone app started the proxy on the real hotspot) On the first iPhone test, record the hotspot interface the app
  sees (it accepts only 172.20.10.1/28 on a bridge and fails closed).
- [ ] P-iOS2. First live test keeps the iPhone app in the foreground; the Mac
  stops the tunnel after 90 s of source silence.
- [ ] P-iOS3. Owner decision: GOAL says one button on the target, but both
  phone apps still need a Start tap on the phone.
- [x] P-iOS4. (trust list with per-device Forget and Forget all done 2026-11-06; token rotation still disabled pending review) iOS has Forget all only, no per-target list; token rotation is
  disabled, so there is no revocation path.
- [x] P-DOC. (done 2026-11-06) README claims stronger than code: ios/README.md:304 ("stays
  awake"), ios/README.md:298 toggle name, android/README.md:331 key storage,
  android/README.md:321,376 port range fallback, android/README.md missing the
  disabled background status consequence.
- [x] P-AND. (2026-11-06: background status enabled; token created at first Start; real Activity tab; Copy connection details; per-process trust reconfirmation kept by design and documented; 929 JVM tests pass; no real phone yet) Android: trust reconfirmed after each process start; background
  status host compiled off; no real port edit, activity log, copy connection
  details, or token before first pairing; unbounded UDP write path.

## Secret handling follow-ups (from the 2026-11-06 audit)

- [x] S-R1. (done: env var removed after read, env_remove on children, 5 tests) Unix CLI reads
  HOTSPOTSHADE_PHONE_TOKEN and leaves it in the environment; child route,
  scutil, ip commands inherit it (rust/src/main.rs ~1802, ~1870). Remove the
  variable after reading and env_remove on child commands, as Windows does.
- [x] S-R2. (done, 2 tests) manual Debug for gui.rs Request (prints Authorization and
  body) and pairing.rs PairView (prints the SAS code).
- [x] S-R3. (done: rust/src/redact.rs shared, 2 tests; Rust 1377 passed, 0 failed) one shared redactor for gui.rs and desktop_control.rs.
- [x] S-A1. Android: revealed token now has a non-secret TalkBack label and FLAG_SECURE while shown; 922 JVM tests pass, lint 0 errors (2026-11-06).
- [ ] S-I1. Owner decision: iOS keeps the migrated legacy token in plaintext
  UserDefaults (backup-eligible) by design while rotation is disabled.
- Note: ignored build/ holds provisioning profiles and signed artifacts; never
  upload or snapshot build/.

## CI readiness (from the 2026-11-06 check)

- [x] C1. (resolved: npm test 0 failures after L5) `cd linux && npm test` failed assets.test.mjs (regex flags
  RegExp.exec in engine-client.js); expected to be fixed by the Linux
  packaging task. Re-run before any push.
- [x] C2. (owner approved committing; checkpoint f7ade3e on branch completion-2026-11-06, noref/ excluded, not pushed) (2026-11-06 recount: 489 untracked + 27 uncommitted deletions; every job depends on them; commit with git add -A only on owner go-ahead) About 250 untracked files are required by CI jobs (Rust modules and
  tests, macOS helper/installer, iOS sources and tests, Android tests, Windows
  ServiceHost/Broker/Service, scripts and *.expected blocks, docs/CI_PIPELINE.md).
  Commit only with the owner's go-ahead; exclude noref/, experiments/ unless
  wanted, and never build/.
- [x] C3. android/.kotlin/ added to android/.gitignore.
- [x] C4. (fixed: CI compile step passes /p:HotspotShadeSkipPayloadCheck=true; PC build keeps the check; TestLauncher and ReleaseProbe built in CI; release audit 58 passed) winui-demo: csproj payload check needs stage_payload.ps1 output that CI never makes; TestLauncher and ReleaseProbe never compiled by CI (fix in progress).

## Release candidate rule (owner, 2026-11-06)

No demo mode and no preview mode in any app the owner tests. Every visible
control must be real. Unbuilt or decision-blocked features are hidden and
listed, not simulated. The engine `--demo` flag may remain only as a hidden CI
smoke-test seam that no app offers.

- [x] RC-mac. macOS demo mode removed (2026-11-06): app always runs the real engine; an engine answering with test data is an error; binary has no demo UI text; swift test 653, 0 failures (twice); installer 340, 0 failures; app builds.
- [x] RC-and. Android Preview mode removed (2026-11-06); Activity sheet and editable port removed (no real implementation); 899 JVM tests pass, lint 0 errors. Package id com.hotspotshade.demo kept to preserve installs.
- [x] RC-and-ui. Emulator check (Pixel 8 API 36, 2026-11-06): current debug APK shows Dashboard (Off, Start, waiting, background), real Activity empty state, Settings; no preview banner or badge. Emulator only.
- [x] RC-win. (W7 and W8 done; WinUI uses the real engine; not built on Windows) Windows app must be the real engine path, not the simulated
  preview (Windows agent).
- [ ] RC-lin. Packaged Linux app offers no engine demo option.
- [ ] RC-list. List hidden or unbuilt features for the owner.

## Docs pass (after RC-mac, Windows and Linux L6 land)

- [ ] D1. macos/README.md:3-6 says real pairing needs the signed helper; the
  user engine serves pairing, status, settings; only Turn on needs the helper.
- [x] D2. (done 2026-11-06) docs/MULTIPLATFORM_ROADMAP.md:32-41 root dashboard engine (stale);
  :48 right timeout is 30 s, not 10; :58 and :107-109 iOS Simulator run now
  done; :198 Linux Direct control exists (contradicts :61).
- [ ] D3. macos/README.md:395-397 auto-pair is one try plus one retry, then
  Pair or relaunch (not continuous 10 s retries).
- [x] D4. (done 2026-11-06) windows/README.md counts (391, 396, 757, 767-769, 820, 826-828),
  layout omits Service and TestLauncher, "no launcher" wording.
- [x] D5. (done) android/README.md:764 five instrumented test classes, not three.
- [x] D6. (done) AGENTS.md:237 echo limits: 30 s idle and 16 sessions are the iOS and
  Android source values, not rust/src/relay.rs (8 active, 8 s, 5 s, 300 s).
- [x] D7. (done) AGENTS.md:152 probe prints uid and root flag on macOS.
- [ ] D8. Earlier items in P-DOC.

## Invariant audit follow-ups (2026-11-06: no violations found)

- [x] V1. probe_listener now takes iface: u32; Windows x86_64/i686 check+clippy clean; 345 windows lib tests pass.
- [ ] V2. Linux pair_handoff write (gui_backend.rs ~1561) has no deadline; bound it like Windows HANDOFF_WRITE_LIMIT (after the Mac fix agent finishes gui_backend.rs).
- [ ] V3. Windows proxy start does not run windows_route_verify::verify_live on the installed /1 and 2000::/3 plan (known open; needs Windows host evidence).
- [x] V4. (all done incl. i686 check and clippy in rust-windows CI; release audit and pipeline tests pass) FFI audit (2026-11-06): all layouts and signatures correct for x64 and i686; GetNamedPipeInfo on a CreatePipe write end succeeds (W7 checkpoint resolved). Fixing: handoff claim test, zeroed IPv4 sockaddr, doc wording. Queued: add i686 check to the rust-windows CI job (after the CI WinUI fix).

## Linux evidence (needs owner approval)

- [~] LE1. (RUN 1 done on 417c6d43, Boat Ubuntu 24.04: helper 92 + container 26 pass, Xvfb settings + a11y pass, .deb build and install/remove/purge pass; 3 Linux-only failures fixed in dc2e281c (verified in local Linux containers); run 2 on dc2e281c: all steps pass except an intermittent opt-in helper integration test (real_engine_demo, 2 of 4 runs "engine exited before helper was frozen"; fix in progress); evidence docs/evidence/linux-boat-2026-11-06-run2/; evidence docs/evidence/linux-boat-2026-11-06/; sandbox deleted) docs/LINUX_EVIDENCE_PROPOSAL.md recommends a git archive of the
  committed branch, SHA-256 pinned, extracted with tar --no-same-owner as an
  unprivileged user on a disposable Boat Ubuntu 24.04 amd64 sandbox, for the
  Rust/helper tests, npm test, Xvfb checks, and a .deb build. Needs the owner's
  approval to send source to a sandbox. Live tunnel in a VM is separate.

## Android review follow-ups (2026-11-06)

- [x] A1. (fixed 2026-11-06: hold FLAG_SECURE until foreground with token hidden, port-owner fence, registry under lock, copy note when stopped; 940 tests, lint 0 errors) FLAG_SECURE cleared before the recents snapshot; background tick port
  race; host registry leak on failed start; copied saved port while stopped
  (fix in progress).
