# Physical device validation procedure

Status: procedure only, and physical tests are BLOCKED and UNAPPROVED. This
revision answers the independent review findings listed below, on top of review
`a41485ff`, review `a3a2fad8-29ab-4358-b5e9-737a4b16fb98`, and review
`ff0aeea4`. None of those reviews approved this text, and this revision has not
been reviewed. It was written from the current source and documentation by
reading files only. No network, phone, device, hotspot, carrier, route, install,
root action, TUN device, or test command was used. The source it describes is
the uncommitted working tree, which other writers are still editing, so any line
that describes Linux start order, claim recovery, the destination proof, or the
macOS lock protocol can drift. Earlier hotspot results do not establish behavior
for the current working tree. Treat every live result as evidence for one build,
one device, one hotspot, and one carrier path at a time.

The Linux IPv6 route parser and its later expiry and clone ownership changes
have received independent source review, but the selected build still needs
fresh disposable-VM evidence before this plan can be approved. A review found
that the earlier working-tree snapshot with
`platform_linux.rs` SHA-256
`ab0ba779030498daef36188edaacf87ec916112d5f6b4a62279c3528825d6c5c`
treated the normally emitted `RTA_CACHEINFO` attribute as unrecognized. On that
snapshot, real IPv6 route dumps would prevent the block-mode start check and
could leave cleanup unconfirmed. Later repairs address this finding, but their
hermetic tests are not live route evidence. Require the reviewed repair and fresh
disposable-VM block, forward, stop, and recovery evidence for the selected build.
The later parser treats nonzero IPv6 cache expiry and `RTM_F_CLONED` as negative
ownership evidence. A zero expiry, including one rounded to zero, or a missing
cache-info attribute does not prove ownership. Re-review the exact selected
revision and these residual limits; do not approve an older hash by implication.
Do not use a physical hotspot to investigate this failure.

The Linux VM transfer gate remains closed pending review of the current source
snapshot verifier and harness. Follow `docs/LINUX_TEST_VM.md`; do not upload an
archive until the verifier, harness, and exact archive are independently
reviewed and the transfer is authorized. Earlier VM results do not establish
that the current source bytes were tested.

The macOS engine now also writes an `engine-session` record for a direct start
and reports uncertain cleanup as an error. This guide has not been re-reviewed
against that change. In particular, do not remove a record on the assumption
that only the helper can create it. Recheck the engine, helper, and coordinator
together before using any macOS recovery procedure.

This correction addresses the latest review findings on this page. It removes
the helper README's conflicting instruction to delete `engine-session` or
`cleanup-blocked`; states that no reviewed Linux selector dump exists in this
tree, so a present claim blocks every start; corrects the macOS state-file link
and ACL description; separates the first all-or-nothing Linux recovery read
from later partial deletion; records the fifth-predecessor compaction proof and
its limits; replaces the outdated Android background status rationale; describes
the gated Windows direct lifecycle; and updates the source read record. It
approves no live action, no state deletion, and no recovery. The page remains
BLOCKED and UNAPPROVED.

Source inspected for this revision, with SHA-256 at the last read where pinned:

```text
# no hash pinned: rust/src/service.rs changed repeatedly during this correction
# no hash pinned: rust/src/platform_linux.rs changed repeatedly during this correction
6ddb354cb097b60926bf9bc57507bb9ac353888381757518ad160a5f281dc683  rust/src/gui.rs
17bb53c210c9fc2743b0f10b0683540533d37e1757e9e4896297ef07ccad2c9e  rust/src/autostop.rs
bee9ca3c7470e30ca3ccc64e98d6c95394e8f6b65049ff1b4c388ad1b6090f37  rust/src/main.rs
614719601c9ca477cc370c9222864d0a80c29ee0ec681b50aaf3199629d5584e  rust/src/gui_backend.rs
dcb2b41e7d2722e28cf8a6d692f67266fe1483d8bab0726c3e1c59fb6d3209bf  rust/src/gui_backend_windows.rs
b8db3679e54d76faffed8bf9725571f72880a2e536bb80ff16c0d0b3ee0b6541  rust/src/windows_route_verify.rs
26231d3c0b76814af9f20cdbf85a0ae486ac4d55bec4751c11e209c2df028648  rust/src/environment.rs
d9f8b4c100719d9ecfcf3b24600023905773c6f1477b87c81a36c6f85eec25f2  rust/src/macos_upgrade_lock.rs
94ea07f1549dc689879de80c450be90bfca4174cec78c12f70bcddd62072d7be  rust/src/privileged.rs
f396057d677c92a715b94681082fe8f67eeb34dcb98df45d953f6b70433fc74e  linux/helper/src/main.rs
5a6571dcd3a50aeeb6070065a6d8efeb1a0ada2fc1e6b00d3e5055968186fe8d  linux/src/backend/engine-client.js
e3ac1b55674ce49b292e7117fe680a063e6b490fa00e00ff6e48a4598d6acf15  macos/HotspotShadeKit/Sources/HotspotShadeHelper/main.swift
003b84286164fdbdb9cb4de02fb4d9aa9f7e3228a47c08deea22cd824e86b738  macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/RootEngineLauncher.swift
59a83b1aa0f129220360930b6b21a9bba8c006a2d26b6f77b6c56ea89fbea80e  macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperLifecycle.swift
23ba335c03355b284141f9bea531acbdd8bb699e11fc02188a0143dde160cdd6  macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperStartExclusion.swift
44556a3770e23bd10a2c45cb7a4c42dce976aa0037e5181ac3e0965fb177a8ee  macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperCleanupBlock.swift
4c7041823bf2e9bbf4330950e54207a793acb2505d9d882e470d528c794ddb21  macos/Installer/Sources/HotspotShadeInstallerCore/InstallLock.swift
e4aed37cb8d185ffae28c03ca54425f3d9e39ad85dc5ff6858f5a5a4e8ae3673  macos/Installer/Sources/HotspotShadeInstallerCore/StartJournal.swift
2f29babc8a8e053ce7b7644865cbe3f5a8e9e5f18563cf5f01dfeb1855e352f8  macos/Installer/Sources/HotspotShadeInstallerCore/Coordinator.swift
4f521693e961022d387387d0b51e4e84bba180c5eb018a15b628aa5276a8e510  ios/HotspotProxy/SecureTokenStore.swift
29f401993d94aec4caecac788e53cf4afa1cedac8e3062507c96230653fdc1d7  ios/HotspotProxy/TokenLifecycle.swift
0f26a954c1ed9dcbd3dd42386f66ab6afe941515a554271b7b4d4d08b7033e9f  ios/HotspotProxy/HotspotProxyApp.swift
dde3066b0d52697531e55cb7469bcb101548ee9d45cd67f71e44945b0b587d97  android/app/src/main/java/com/hotspotshade/source/TetheredInterfaceEvidence.kt
f3a009b5bc2214e129d8f065d6b06ed3ba782366a695f35eda136172034967fa  android/app/src/main/java/com/hotspotshade/source/HotspotWatch.kt
8aac641d93f672db97aa8cc78f4adf356116f302f0e2188153c9988f0b9e24bf  android/app/src/main/java/com/hotspotshade/source/SourceProxyController.kt
# no hash pinned: android/app/src/main/java/com/hotspotshade/source/TokenStore.kt changed during this correction
37a35898c772dd6e25500aeb0577fadcdb28228359f3499be77f11d32e013389  android/app/src/main/java/com/hotspotshade/source/SourceProxyService.kt
# no hash pinned: docs/LINUX_ROUTE_RECOVERY.md is another writer's scope and changed during this correction
```

The values above were re-read for this correction. The tree changed repeatedly
during the correction, including in `rust/src/platform_linux.rs`,
`rust/src/service.rs`, `rust/src/macos_upgrade_lock.rs`,
`ios/HotspotProxy/SecureTokenStore.swift`,
`ios/HotspotProxy/HotspotProxyApp.swift`, the Android `TokenStore.kt`, and the
helper comments. The values are last-read records. They are not review,
approval, build identity, or provenance. No hash is pinned for
`rust/src/platform_linux.rs`, `rust/src/service.rs`,
`android/app/src/main/java/com/hotspotshade/source/TokenStore.kt`, or
`docs/LINUX_ROUTE_RECOVERY.md`: those files changed repeatedly during this
correction. The Linux start order, claim recovery, and the macOS direct start
record were read from the working tree without review. A matching hash for any
file does not mean a statement was reviewed. `docs/LINUX_ROUTE_RECOVERY.md` is
another writer's scope and can change again. If any listed file changes, re-read
the affected section.

The macOS lock and journal files changed while this revision was being written.
An early read of `HelperStartExclusion.swift` used
`/var/db/hotspotshade/start-exclusion` and `start-journal`. The last read still
uses `start-exclusion` for the helper and engine, and the Rust engine uses the
same inode and validates the helper descriptor handoff. The helper refuses
`install-journal.json` and `service-journal.json`, and its durable start record
is the `engine-session` launch intent. The installer coordinator uses
`start.lock` as its primary name and holds `start.lock`, `start-exclusion`, and
`upgrade.lock` as a transition set for the whole transaction, so it contends
with the current helper and engine through `start-exclusion`. Old binaries take
no lock at all. The installer still reads `start-journal`, and its
`InstallLockLayout` still names `start-journal`. That is not one converged or
reviewed protocol. Do not assert that the helper, engine, and installer share
one approved lock, and do not approve an install from this tree.

The previous revision recorded these hashes for files that changed again. The
block is history, not a current pin:

```text
dc971d5e1ba965a5dd80f9568fd8391b1271cc9d30527993c8a1a074a3a0240c  rust/src/service.rs
84f77c3db1d18b47306f4edd3dbc8377ba3796e60f2b7a03c40cc5926282e6c4  rust/src/platform_linux.rs
4b56dae49e0029237cdb3bcb21d8673abe886dbb2476eb80a0858697dc8e086f  linux/helper/src/main.rs
2d5f008b8fa8f72e58020529d01f662ea33bff95808226807e3b8968a9899c11  macos/HotspotShadeKit/Sources/HotspotShadeHelper/main.swift
46eecdaf59d1603bc9262a561c5e76763da67ee4f8271a9e1e180e07e07a4dcf  macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperLifecycle.swift
```

Files that changed more than once during this revision include
`HelperStartExclusion.swift`, `HelperLifecycle.swift`, `rust/src/service.rs`,
and `rust/src/platform_linux.rs`. `rust/src/macos_upgrade_lock.rs`,
`HelperCleanupBlock.swift`, `InstallLock.swift`, `StartJournal.swift`, and
`Coordinator.swift` are new or rewritten working-tree files. The hashes above
were read at different moments while the tree changed, are last-read values, and
may not match at handoff. A matching hash is not approval, reviewed provenance,
a build identity, or a manifest. Treat any mismatch as drift, not as approval.
If a file changes again, re-read it and request a new review before using the
affected section.

If any inspected file changes before the next review, the statements tied to it
are drift, not an approved description. Re-read that file and request another
review before using the affected section. The guide stays unapproved even when
this page is internally consistent.

One platform change arrived during the review: the current Windows build now
refuses source device token use on both source-proxy paths. That change blocks
every Windows tunnel, X, and A cell. It also means the Windows link-silence
behavior is described for a future build, not as a current result.

Physical tests stay blocked until all of these are true:

- a reviewed build exists: a clean clone at a committed, independently reviewed
  revision, with a recorded digest, built after the Linux and helper repairs
  below;
- a second, independent review has closed its findings on this revision and
  has been repeated on the build's source, not on this working tree;
- the Linux crash recovery, route claim, and the Linux `tun --phone` destination
  proof are committed, independently reviewed, and named by the build's recorded
  source revision. A safe, reviewed, read-only selector dump must decode the
  version 3 current record and every predecessor and derive every selector that
  recovery can delete. No such dump exists in this tree, so a present claim
  blocks every start. The current working tree contains uncommitted changes, so
  it is not a test candidate;
- the linked Linux recovery, VM, and technical guides are revised so no manual
  delete command relies on a priority and table alone, or on a route prefix
  without its type. `LINUX_ROUTE_RECOVERY.md` is another writer's scope and is
  not made current or approved by this page;
- the Android pairing concurrency and token-persistence repairs and the macOS
  helper authorization and crash-recovery repairs are finished and independently
  reviewed for the build under test. Windows direct mode, its link observer, and
  its source-proxy token path remain unavailable until their separate evidence
  and review gates pass. The direct service lifecycle is gated and no shipped
  path can start it;
- the macOS real-mode installation is unblocked and approved: one reviewed lock
  and journal protocol is shared by the helper, the engine, and the installer
  coordinator, it covers `install-journal.json` and `service-journal.json`, and
  it includes a reviewed recovery for direct and helper engines that does not
  delete `cleanup-blocked` or `engine-session` by hand. An approved root package
  must install the Developer ID helper, its launch daemon, the start right, and
  the root-owned engine. The current `macos/Installer` package is build-only,
  its `preinstall` refuses, and the current helper, engine, and installer lock
  and journal files are still evolving working-tree text. Do not install or test
  real mode from this tree;
- the iOS token storage behavior is device-tested. A Keychain item can survive an
  uninstall, Forget does not revoke it, and rotation is disabled in the current
  build by `TokenRotationPolicy.reviewed = false`, so P-08 is Blocked. Do not
  treat uninstall, reinstall, or Forget as revocation, and do not expect an
  in-app rotation control to revoke a saved token. Trust entries are stored in
  UserDefaults; a power loss before a Forget is durable can restore an entry;
- the build can be traced from the artifact back to that source revision and to
  the build that produced it. For a local build, that means a clean clone at the
  reviewed revision and a digest recorded at build time. For CI, it means the
  workflow, job, and run id. Immediately before installation, hash the exact
  artifact to be installed and compare it with the recorded build digest. Stop
  on a mismatch or if the bytes cannot be identified. A string inside a binary
  is not provenance;
- the owner has approved the exact build, the exact action, and every read-only
  root read in section 5. Approval for a build or a device does not approve a
  later action.

At the time of this revision, the Linux crash recovery source, its Linux
`tun --phone` destination check, and their documentation are being edited
concurrently. Do not run a Linux physical test until those edits land, are
reviewed, and are present in the identified build. Independent reviews found that
route and rule dumps can omit entries without reporting interruption, so a
missing entry cannot by itself prove cleanup. They also found that large route
tables can prevent cleanup, and that an earlier source-device token check ran
before the physical-link proof. The current working tree captures physical outer
evidence before it touches the claim and rechecks the retained identity again
immediately before it uses the token and during route setup, but that order is
uncommitted and unreviewed. Do not describe it as settled. Repairs and a new
review are required before this procedure is used.
[LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md) contains read-only
inspection commands and does not approve a manual deletion procedure.

This revision makes these corrections from review `ff0aeea4`:

- it states that an empty or missing Linux claim with leftover objects can reach
  the token check, TUN creation, and the address install, and that a refused
  start can unlink the claim, instead of claiming a safe refusal;
- it corrects the Linux destination proof: a default route is required, and an
  on-link match on an `--iface` interface proves only the route, not the
  gateway;
- it separates early start errors that come before any claim read;
- it puts the boot check before the namespace check and lays out the claim
  states in start order;
- it splits the one-time Linux preflight from the per-start gate;
- it adds non-DNS UDP to the source proxy test and adds D-03U for direct mode;
- it records that the Electron app has a direct mode control that no test has
  shown to start a tunnel;
- it records the status-poll claim-lock race.

This revision makes these corrections from review `a41485ff`:

- it places the current Linux start order: a read-only physical outer capture
  before the claim, retained link evidence and a live outer pin proof after the
  claim, and rechecks of the retained identity before the token and during route
  setup;
- it records that a recovered claim record stays on disk when the later
  start-time read refuses, unlike an empty claim, which the manager removes on
  release;
- it separates the Linux CLI's raw text from the GUI's fixed error codes, and
  records that the GUI has no fixed text for `source_device_moved` or
  `outer_interface_changed`;
- it records that a CLI user stop cannot report `last_stop=user`; only a GUI or
  app path that records a user stop can show it;
- it records that `checking`, `unpaired`, and `not_trusted` are unverified
  plaintext answers, that a continuous run is bounded by the 120 second grace
  and then the 90 second silence limit, and that `pin_unknown` is local
  no-evidence;
- it records that a future Windows command-line GUI, with no link observer,
  still accumulates fresh source device silence; the current build cannot start
  that tunnel;
- it requires an explicit non-loopback `--dns-servers` list for Linux SOCKS5
  mode, and separates the SOCKS5 `socks5h` name test from the tunneled UDP:53
  test;
- it adds A-02 to the macOS cells and gives A-02 per-platform cleanup checks;
- it accounts for a root browser GUI direct-mode start, which is a separate
  path from the app and has no live test;
- it removes the outdated empty-marker comment claim and aligns the claim text
  with the current recovery handover;
- it records that Android source keepalive uses the system defaults, not the
  iOS 60/10/3 values;
- it adds MAC addresses and local interface IPv6 addresses to redaction;
- it notes that a Unix identity key or directory accepts any owner-only mode,
  not only `0700` and `0600`;
- it makes the expected-error and prerequisite table path-specific, and records
  which paths show a recovery line on stderr;
- it records the platform change that arrived during this review: the current
  Windows build refuses source device token use on both source-proxy start
  paths, so no Windows X or A cell can run.

This revision makes these corrections from the current independent review
findings:

- it records that the macOS real app and helper installation remains blocked and
  unapproved. The current package is build-only, `preinstall` refuses, and the
  helper, engine, and installer lock and journal files changed during this
  revision. The helper and engine last read use `start-exclusion` and the
  descriptor-5 handoff; the installer uses `start.lock` as its primary name and
  holds `start.lock`, `start-exclusion`, and `upgrade.lock` as a transition set.
  The helper no longer writes `start-journal`, but the installer still reads it.
  Do not assert a unified or approved lock;
- it records that the macOS helper cleanup block is durable at
  `/var/db/hotspotshade/cleanup-blocked`, that the launch intent at
  `engine-session` and the install and service journals also block a later
  start, and that a helper restart re-reads the marker. The Linux engine flag,
  the Linux claim lock, and the Windows flag are not durable in the same way;
- it records that an iOS Keychain token can survive an uninstall and that Forget
  does not revoke it. The current iOS build disables token rotation:
  `TokenRotationPolicy.reviewed` is false, the Rotate token control stays
  disabled, and P-08 is Blocked. The app also has no in-app conflict recovery.
  The fake-store tests do not establish real Keychain and UserDefaults crash
  durability, device restore safety, or external-writer safety;
- it records that X-03 in source device proxy mode cannot use `--dns-upstream`.
  Only direct mode D-03 may configure an upstream;
- it records that the Windows refusal test must use a fixed non-secret
  placeholder, never a real source token. The refusal happens before any
  adapter, route, or token send;
- it records source credential unreadable, conflict, damaged rotation intent,
  and unfinished rotation as stop conditions. Do not reinstall, clear data, or
  expect a rotation control to clear them;
- it requires the Linux route-claim preflight to reject a symlink, a non-regular
  file, and a file whose link count is not 1;
- it recorded an earlier Android 16 pending estimate of about 12 seconds. The
  latest revision corrects that: the first uncertain miss is about 8 seconds
  and a loss follows about 12 seconds, and a start wait is shorter;
- it corrects platform gating and safety assumptions: `--dns-upstream` and
  `--no-pin` and `--no-routes` are direct-mode options, source proxy mode
  requires IPv6 forwarding, `--experimental-icmp` requires source proxy mode,
  and no macOS real-mode install or helper start is approved.

This revision makes these corrections from the latest independent review
findings:

- it records the Linux claim format as version 3 with up to four predecessor
  records. A `stat` or the `route_claim` status cannot enumerate the current
  record or its predecessors, so a start that may recover requires a safe,
  reviewed, read-only selector dump and owner approval of every selector. This
  tree provides no such dump, so a present claim is Blocked. The safe clear
  removes only an empty file or a valid earlier-boot record and refuses a
  non-empty damaged file or a valid current-boot record;
- the Windows command-line GUI returns `source_proxy_unavailable` for a start
  or source check and shows "Source device proxy mode is unavailable in this
  Windows build." Neither Windows path opens `wintun.dll` before refusal;
- it adds `service-journal.json` to every macOS state, preflight, and recovery
  list. The helper refuses a start while it is present, and a direct engine also
  refuses it. The installer transition lock set still includes
  `start-exclusion`, and old binaries that take no lock remain a gap. No manual
  deletion of a cleanup marker, launch intent, or either journal is approved;
  the helper README recovery is not a direct-engine recovery;
- it states that a stop can fail. A failed cleanup can leave routes, rules,
  addresses, a device, or a durable start record, and it is reported as a failed
  stop, not a clean stop;
- it corrects the Android pending tethering timing: the pending backstop counts
  the fourth pending probe as the first uncertain miss at about 8 seconds, and a
  loss follows about 12 seconds after the watch starts. The background status
  gate stays off pending service-owner review and a real-device test;
- it records the target pairing result wait as 242 seconds, while a foreground
  source prompt usually expires at 60 seconds;
- it adds the macOS state directory and state file set-id and extended ACL
  checks.

This revision also matches the current iOS review gate. Token rotation is
disabled: `TokenRotationPolicy.reviewed` is false, the Rotate token control is
disabled, and P-08 is Blocked for this build. Earlier text that said rotation was
available with the proxy stopped is corrected in this page. Forget, uninstall,
and reinstall do not revoke a saved token, and the app has no in-app conflict
recovery. The fake-store tests do not establish real Keychain and UserDefaults
crash durability, device restore safety, or external-writer safety.

The earlier corrections still stand:

- it requires artifact provenance and explicit owner approval before preflight
  and every root read;
- it makes a claim, rule, and route inspection mandatory immediately before
  every Linux tunnel start, and states that recovery can remove exact recorded
  objects before authentication, and that an empty claim can be unlinked or an
  earlier-boot claim truncated in the same start;
- it separates the scoped `phone-udp-diag` command from tunneled inner UDP;
- it records X-08 timing as inconclusive without a separately approved lab
  capture;
- it states that stop tests must record startup warnings;
- it states the Windows CLI and GUI difference, the Linux package setuid
  sandbox, the polkit action, the persistent `/var/lib/hotspotshade` identity,
  and remove versus purge behavior;
- it adds DNS to redaction and adds a per-platform required-cell and
  expected-error matrix.

This page is for a person who has the owner's approval to test HotspotShade on
real hardware. It is a manual procedure. It installs nothing and changes no
route unless the person performs the step and the owner approved that step.

Read [GOAL.md](../GOAL.md), [AGENTS.md](../AGENTS.md), [README.md](../README.md),
[PHONE_PROXY.md](../PHONE_PROXY.md), and
[MULTIPLATFORM_ROADMAP.md](MULTIPLATFORM_ROADMAP.md) before you use this page.
It does not replace those documents. It turns their claims into test steps and
records what the steps do not prove.

## 1. Scope

This procedure covers:

- read-only preflight;
- install, backup, and rollback preparation;
- pairing and trust tests;
- source device proxy tests;
- direct mode tests;
- automatic stop and cleanup tests;
- failure and recovery tests;
- security and performance checks;
- per-platform gaps;
- a privacy section that stays a non-test until a mode exists.

It does not produce a release decision. A pass is one redacted record for one
build and one environment.

Recommended order:

1. Section 3: prerequisites, artifact provenance, and owner approval, including
   approval for the read-only root reads in section 5.
2. Section 5: read-only preflight.
3. Section 6: install and prepare rollback.
4. Section 7: pairing tests.
5. Section 8 or 9: source device proxy tests or direct mode tests.
6. Section 10: automatic stop and cleanup.
7. Section 11: failure and recovery.
8. Sections 12 and 13: security and performance.
9. Sections 14 to 16: gaps, privacy, and verdict.

## 2. What a pass can and cannot prove

### 2.1 Can prove

A pass can show that the tested build started the tested tunnel, carried the
tested flows, stopped on the tested condition, and removed the resources that
the process created. When the chosen path exposes the running audit, it can also
show that the target read back TTL 65 on its outer sockets and that `ttl_bad`
stayed 0 during the run. That is target-side evidence only.

### 2.2 Cannot prove

A pass cannot prove:

- that the carrier saw TTL 64. The project does not capture packets inside the
  carrier network.
- that the carrier treats the traffic as native source device traffic at every
  layer. The project changes the outer IP TTL and pins outer sockets. It does
  not hide TLS server names, TCP options, DNS behavior, flow size, timing, or
  traffic analysis.
- that the tunnel is fail-closed. More-specific routes, local DNS, DoH and DoT,
  network extensions, and IPv6 `inherit` can bypass it.
- that the target stayed on the hotspot network. The link check proves that an
  interface exists, is up, and has a usable IPv4 address. It does not prove
  which network that interface is on. A target that joins another known network
  can keep the interface up and send traffic through that network.
- that billing, throttling, metering, or carrier terms changed. No mode changes
  them.
- that the traffic evades deep packet inspection, TLS inspection, or tethering
  detection. The project makes no such claim.
- that destinations or server names are private. No destination privacy control
  is implemented today.
- that a compile, hermetic test, demo, emulator, simulator, mock, or VM run is a
  physical-device result. Those are development evidence. Say "development
  evidence, not a release-matrix result" and do not upgrade the label to a pass.
- that an unsigned build installs or launches on every machine. Signing,
  Gatekeeper, Developer Mode, provisioning profiles, application ids, and
  package trust differ per platform and per machine.
- that uninstalling an app, reinstalling it, or forgetting a target device
  revokes a saved source token. On iOS the Keychain item can survive an
  uninstall. The current build disables token rotation, so it has no working
  in-app revoke path.
- that one clean run proves every stop path. Cleanup can fail. A failed cleanup
  can leave a route, rule, address, tunnel device, adapter, or durable start
  record behind in a build that can start that path, and the stop is then an
  error, not a clean stop. Treat the observed cleanup evidence, not the stop
  message alone, as the result.

### 2.3 Current limits to state in every record

- The Windows WinUI app is a simulated preview. It has no engine connection, no
  tunnel, no routes, and no credentials. Do not use it as Windows tunnel
  evidence.
- Windows has a gated direct-mode lifecycle in the service, but no shipped path
  can start it. The service direct entry is refused by
  `require_windows_direct_evidence` before it loads Wintun or changes an adapter
  or route. The CLI `tun` path without `--phone` is rejected during option
  parsing and never reaches that service branch. Windows source device proxy
  mode is the only reachable tunnel start path, and the current build disables
  source device token use on it. It refuses a source-proxy start and a
  source-device probe until physical adapter and gateway identity can be
  checked safely. No Windows direct tunnel has run.
- Windows has two different command paths. The WinUI app is preview only. The
  Rust CLI `tun --phone` would need Administrator rights for a real start, but
  the current token gate runs before the elevation check, so it refuses source
  device token use without elevation and before any adapter or route change. It
  does not need `wintun.dll` to reach that refusal: the token gate runs before
  the DLL path is resolved or loaded, so an absent DLL does not change the
  result. The command-line GUI needs an authenticated launcher with `--token-fd`
  and `--parent-fd`. Its start and source-device check return
  `source_proxy_unavailable`, shown as "Source device proxy mode is unavailable
  in this Windows build." They send no token. Do not use one path's result for the other. Neither
  path is tunnel evidence today. A Windows refusal test types a fixed non-secret
  placeholder at the prompt, never a real source token.
- An unsigned or ad hoc macOS app opens the real dashboard and pairing with the
  bundled user engine, and its Turn on fails closed. A tunnel start needs a
  signed helper and engine. The macOS real app, helper, launch
  daemon, start right, and root engine installation remains blocked and
  unapproved: the current package is build-only, its `preinstall` refuses, and
  no signed helper install has run. Do not install or replace a root helper from
  this tree.
- The macOS lock and journal files are uncommitted working-tree text. At the last
  read, the helper and engine use `/var/db/hotspotshade/start-exclusion` and a
  descriptor-5 handoff. The installer coordinator uses `start.lock` as its
  primary name and holds `start.lock`, `start-exclusion`, and `upgrade.lock` as a
  transition set, so it contends with the current helper and engine through
  `start-exclusion`. Old binaries take no lock at all and remain a gap. The
  helper refuses a present `cleanup-blocked`, `engine-session`,
  `install-journal.json`, or `service-journal.json`. The engine also refuses
  `start-journal`. A direct CLI or GUI engine now writes `engine-session` itself
  and reports an uncertain cleanup as an error, so a failed direct stop can leave
  the same record. Treat the protocol as drifting and reviewed nowhere, not as
  converged or approved.
- The Linux package is unsigned and not in the release set. It installs a
  setuid-root `chrome-sandbox` when present, uses a per-launch polkit
  `auth_admin` action, and keeps a root-owned `/var/lib/hotspotshade` home that
  survives `apt remove` and `apt purge`. The packaged app has not been shown to
  start a real tunnel.
- The Android target tunnel is not implemented. The Android source app has
  emulator and VM evidence only.
- The Android tethering pending state has two bounds. If the finder keeps
  reporting a pending first reading, the fourth consecutive pending probe at
  2-second spacing is the first uncertain miss, about 8 seconds after the watch
  starts. Two more misses report a loss, about 12 seconds after the watch starts.
  The evidence's own pending timeout is 3 seconds, after which the ordinary name
  rules usually decide earlier. A start waits at most 3 seconds. Do not record a
  hotspot loss from the first pending window.
- The Android background status host stays off. `BACKGROUND_STATUS_ENABLED` is
  false. The current host uses a status-only responder and fences one run and
  one token epoch, but those rules are covered by JVM and loopback tests only.
  The service owner review and a real-device background test are still open.
  The earlier rationale that the host could return the captured token without a
  prompt or had no run or token epoch fence is no longer current. The gate stays
  off; do not enable it for a test.
- The current iOS build has no physical-device test in this tree. A Keychain
  token can survive an app uninstall, and forgetting a target device does not
  revoke the token. Token rotation is disabled in this build:
  `TokenRotationPolicy.reviewed` is false and the Rotate token control stays
  disabled, so P-08 is Blocked. Do not treat uninstall, reinstall, or Forget as
  revocation.
- A source token that is unreadable, invalid, in conflict with an old copy, or
  covered by a damaged or unfinished rotation record is a stop condition. The
  app keeps both copies and suspends pairing, and it offers no in-app conflict
  recovery: the store refuses both repair actions. Do not clear app data,
  uninstall, reinstall, or look for a rotation control to make it start.
- The direct-mode matrix cells are blocked for a physical pass in this build.
  The CLI `tun` path prints no running counters, and the macOS real path needs a
  signed helper. See section 9 and section 16.1.
- A Linux build from a source revision without the route claim or the Linux
  `tun --phone` destination proof, or from a dirty working tree, cannot be
  tested. The current working tree contains both but is uncommitted and
  unreviewed. The current claim format is version 3 and can carry up to four
  predecessor records. A `stat` or the `route_claim` status cannot enumerate the
  selectors that a recovery could delete. No reviewed selector dump exists in
  this tree, so a present claim blocks every start. A replacement that would
  need a fifth distinct predecessor keeps the previous current record and the
  newest three predecessors only after a completed two-absence recovery;
  without that proof it refuses. See section 3.3, section 5.3, and A-08.
- Do not treat the Linux `tun --phone` destination proof as settled behavior
  until the reviewed commit contains it. macOS `tun --phone`, `phone`,
  `phone-udp-diag`, and `phone-speed-diag` still send the token to the address
  you type and do not prove it is the current default gateway.
- Linux SOCKS5 mode has no per-interface system resolver. Without an explicit
  non-loopback `--dns-servers` list, the start fails closed with "the Linux
  system resolver list is not tied to one interface; pass an explicit DNS
  server". macOS can discover an unambiguous resolver for the pinned interface.
- `--ipv6 inherit`, `--no-pin`, and `--no-routes` are explicit leak or
  diagnostic paths. Never record a pass that needed one of them.
- Platform gating: `--dns-upstream`, `--no-pin`, `--no-routes`, and `--ipv6
  block` or `inherit` are direct-mode options. Source device proxy mode requires
  pinning, routes, IPv6 forwarding, and the source device DNS path, so it rejects
  those options. `--experimental-icmp` requires source device proxy mode.
  `phone`, `socks5`, and `phone-*` exist only on macOS and Linux. Windows has
  the source proxy CLI, the separate authenticated command-line GUI, and a gated
  direct service lifecycle that no shipped path can start. The two reachable
  paths refuse token use. The Linux `tun --phone` destination proof is
  Linux-only; macOS does not check the typed address. Do not move a command,
  option, or result from one platform or path to another.

## 3. Prerequisites

Do not start a live stage until every item in this section is true.

### 3.1 Owner approval

Get explicit approval from the device owner and the maintainer before each
action:

- running any preflight command, including `probe`, and especially any read that
  uses `sudo` or reads a root-owned path;
- installing, replacing, signing into, or removing an app on a phone or a
  personal computer;
- starting a tunnel that changes routes or creates a tunnel device;
- every Linux tunnel start after a claim, rule, or route inspection, because the
  start can clear a claim or delete the exact recorded objects of the current
  record and every predecessor before it checks the source device token. The
  approval must name the reviewed selector set, not only the claim file. No
  reviewed selector dump exists in this tree, so a present claim cannot be
  approved for recovery today and the start is Blocked;
- turning the hotspot off or on while a tunnel runs;
- disconnecting a network, disabling an interface, or changing Wi-Fi auto-join
  or the known-network list;
- forcing a source device app to quit, locking the phone, or changing its
  background state;
- running a bulk throughput or UDP test that uses cellular data;
- running a packet capture;
- removing a route, rule, address, or device that the test did not create;
- running a test that can interrupt a connection someone is using.

The approval must name the exact build, the artifact digest and provenance, the
device, the effect on the existing app and stored trust, the rollback path, and
the expected interruption. For a Linux start, it must also name the claim state,
the reviewed selector set for the current record and every predecessor, and the
possibility that recovery deletes those exact routes and rules before
authentication. An approval for one action does not approve another. An approval
for a build does not approve a preflight read or a tunnel start.

Emulator use for development tests is approved by the owner. A personal phone
or computer install still needs the device owner's approval for that device.

Do not start or stop a tunnel that someone is using. A running tunnel has the
source device app at its other end. A restart of either end cuts the connection.

### 3.2 Devices and roles

You need:

- one source device per source platform: iOS 17 or later, or Android 8.0 or
  later;
- one target device per target platform: macOS 14 or later on Apple silicon,
  Windows 10 or 11, or Linux;
- a hotspot that the source device provides and the target device can join;
- a carrier path that the owner permits you to use;
- physical access to both devices for the whole run;
- a way to stop the tunnel without `kill -9`, such as the app Stop control,
  Ctrl-C, or SIGTERM.

Use test devices, not a phone or computer that someone needs during the run. A
hotspot loss test cuts the target off the network. A source device loss test
cuts every flow through that source device.

### 3.3 Build identity and provenance

Do not run section 5, the `probe` command, or any `sudo` read until the artifact
provenance below is recorded and the owner approved those reads. A read-only
command is still an action on someone else's device.

Record before you install:

- the source revision used to build, from `git rev-parse HEAD` on the build
  machine;
- the build machine's `git status --porcelain` at build time, so a dirty tree is
  visible;
- the build command or the CI workflow, job, and run id;
- the artifact name and its SHA-256 digest;
- the app version and build number;
- the signing class: unsigned, ad hoc, development, Developer ID, debug APK, or
  release APK;
- the platform and architecture;
- the source of the artifact: local build, CI artifact, or release asset.

CI publishes only the macOS binary, the unsigned IPA, the macOS app bundle, and
the release bundle. The Linux engine, the Linux `.deb`, and the Android APK are
local builds. For a local build, use a fresh clone at the reviewed commit,
confirm that `git status --porcelain` is empty, and write down the SHA-256
digest immediately after the build. A local build has no CI attestation. Its
provenance is the tester's own log, so keep that log with the record. Do not
build from this working tree while the Linux recovery, route-proof, and macOS
lock changes are uncommitted. Do not treat the macOS app bundle as a real-mode
install: it does not install the root helper, launch daemon, start right, or
root-owned engine, and the installer package remains build-only with a refusing
`preinstall`.

Do not test a build you cannot identify. Do not mix artifacts from different
commits in one record. An artifact from a dirty tree, an unrecorded tree, or an
unknown CI run is blocked, not a test candidate.

Before installation, recompute the SHA-256 of the exact artifact selected for
installation and compare it with the recorded build digest. Use `shasum -a 256`
or `sha256sum` on macOS or Linux, or `Get-FileHash -Algorithm SHA256` on
Windows. Record the match. A mismatch or an unidentifiable installed artifact
blocks the test; the archive digest alone does not prove the installed bytes.

A string in a binary, a version banner, or a file name does not prove which
source produced the artifact. Prove a required change from the recorded source
revision. For example, before a Linux test, confirm that the revision contains
the route claim and the destination proof:

```sh
git show <recorded-commit>:rust/src/platform_linux.rs | grep -n 'ROUTE_CLAIM_PATH'
git show <recorded-commit>:rust/src/service.rs | grep -n 'verify_phone_destination'
git show <recorded-commit>:rust/src/platform_linux.rs | grep -n 'hotspotshade-route-claim 3'
git show <recorded-commit>:rust/src/platform_linux.rs | grep -n 'MAX_CLAIM_PRIORS'
```

If a command produces no match, the recorded source does not contain that
change. A match only shows that the symbol exists. It does not prove that the
start path calls the destination proof before the token, that the recovery order
is the one described here, that the build parses every predecessor record, or
that the code was reviewed. A version 2 build reads no predecessor lines, so it
cannot exercise a predecessor recovery. Check the artifact against that
revision, not against a local working tree. Do not treat a match from a working
tree, an unreviewed commit, or a string inside the binary as proof. The Linux
recovery line, the route claim, and the Linux `tun --phone` destination proof
are the specific changes that a Linux physical test needs; ask the maintainer
which reviewed commit contains them. Do not infer the answer from `HEAD` or from
a dirty tree. The current working tree has these symbols but is not a reviewed
candidate. A reviewed read-only selector dump is also required before a Linux
start that may recover. No such dump exists in this tree, so a present claim is
a hard block.

### 3.4 Network and cost

- Use a hotspot that the owner controls.
- Before a direct-mode test or a hotspot-loss test, disconnect or disable every
  other network on the target and turn off Wi-Fi auto-join. Remove a known
  network only with owner approval. Record the baseline interface list.
- Do not use a public hotspot for a real token or real traffic.
- Do not record the hotspot SSID, password, carrier account number, phone
  number, IMEI, ICCID, or plan name.
- Do not sign into a carrier or app store account unless the owner approved
  that sign-in.
- Set a byte cap and a time cap before any bulk test. Cellular data can cost
  money.

### 3.5 Tools

On the target device, use the current `hotspotshade` binary for the platform, or
the current target app. On the source device, use the current source app.

Optional tools:

- `curl` for a SOCKS5 or HTTP check;
- `ping` for an echo check;
- `lsof` on macOS or Linux to list listeners;
- `ip` on Linux to read routes and rules;
- PowerShell `Get-NetRoute` and `Get-NetAdapter` on Windows;
- a platform task manager for memory and CPU;
- `phone-udp-diag` and `phone-speed-diag` on macOS and Linux for scoped
  diagnostics. `phone-udp-diag` opens its own outer socket to the source proxy.
  It is not a test of inner UDP through the tunnel. Windows has no `phone` or
  `phone-*` command in this build.

Do not add a tool that captures personal traffic. If the owner approves a
capture, use a lab destination, keep the file private, and delete it after the
run. This procedure never needs a capture to prove a token or a TTL claim. X-08
timing is the one case that requires a separately approved lab capture; without
it, record the timing as inconclusive.

### 3.6 Timers

Do not shorten a documented timer to make a test faster.

| Stage | Minimum time |
|---|---|
| Preflight and demo review | 20 minutes |
| Install and backup | 20 to 40 minutes per device |
| Pairing tests | 20 minutes |
| Source device proxy tests | 30 minutes |
| Direct mode tests | 20 minutes |
| Automatic stop tests | 20 minutes |
| Failure and recovery tests | 30 minutes |
| Security checks | 15 minutes |
| Performance checks | 20 to 60 minutes, depending on caps |

A source device loss test waits 90 seconds. A test that holds an unverified
plaintext source state (`checking`, `unpaired`, or `not_trusted`) waits a 120
second grace and then 90 seconds. A hotspot loss test waits 20 seconds plus
cleanup. A pairing expiry test waits about 60 seconds with the source app in the
foreground; the target waits up to 242 seconds for a result. That covers the
240-second maximum source prompt window and 2 seconds for the result frame. A
foreground source prompt usually expires at 60 seconds, an inactive one can last
120 seconds, and the maximum is 240. Do not treat 60 seconds as the target's
limit. A clean stop can take up to about a minute on macOS; a failed cleanup can
take longer and is not a clean stop. If the Android finder keeps reporting a
pending tethering reading, the fourth consecutive pending probe at 2-second
spacing is the first uncertain miss, about 8 seconds after the watch starts, and
a loss follows about 12 seconds after the watch starts. The evidence's own
pending timeout is 3 seconds, and an Android start waits at most 3 seconds. Do
not shorten any of these windows.

### 3.7 Stop conditions

Stop the run and report to the owner if any of these happens:

- a token, password, identity key, pairing code, or private key appears in a
  status answer, log, report, screenshot, or chat;
- a target listener appears on a non-loopback address, or a source listener
  appears on an address other than its hotspot address;
- the tunnel restarts itself after a stop or a loss;
- a route, rule, address, or device remains after a clean stop and you cannot
  match it to the test record;
- a stop reports that cleanup did not finish, or a cleanup failure sets a
  cleanup block;
- on macOS, `/var/db/hotspotshade/cleanup-blocked`, `engine-session`,
  `install-journal.json`, `service-journal.json`, or `start-journal` is present
  or unreadable, or the state directory or a state file has a group or other
  bit, a set-id bit, an extended ACL, the wrong owner, or a non-regular type, or
  a state file has more than one link, the helper reports a cleanup block, or
  the helper and engine lock paths or identities disagree. A state directory
  with a subdirectory can have a link count above 1; do not fail it for that
  reason. A helper restart does not clear a durable marker;
- on Linux, `/run/hotspotshade` or the claim is a symlink, is not a regular file
  or real directory, or the claim link count is not 1, or the claim is version 1
  or an unknown header;
- the source app reports an unreadable or invalid token, an old-copy conflict, a
  damaged rotation intent, or an unfinished rotation. Pairing and the proxy stay
  off, and the app has no in-app repair for a conflict. Do not clear data,
  reinstall, or look for a rotation control to clear it;
- a Windows refusal test prompt receives a real source token instead of the
  fixed non-secret placeholder;
- a source device app shows a prompt that the person did not start;
- the target loses its normal network after the test and a clean stop does not
  restore it;
- the test needs `kill -9` or a forced power cycle to recover;
- the hotspot interface stays up but the target has joined another network, or
  you cannot tell which network the interface is on;
- a delete would match more than the object the record names;
- the artifact cannot be traced to a recorded source revision, or the recorded
  revision does not contain the change the test claims to exercise;
- a preflight read fails or its output is ambiguous. A `stat` reporting that
  `/run/hotspotshade` or its claim file does not exist is an expected absence;
  other errors are stop conditions. An unknown state is a stop condition, not a
  reason to continue;
- a startup warning says auto-stop or source-silence detection is off, and the
  test needs that stop path;
- a startup warning is recorded as a stop reason, or a stop happens with no
  matching `last_stop` reason while a warning is present;
- a claim, rule, or route read before a Linux start is ambiguous, changes
  between the inspection and the start, or would make the start clear an
  earlier-boot claim or delete recorded objects without explicit approval;
- DNS resolver addresses, search domains, or query names appear in a shared
  record, log, screenshot, or report;
- a MAC address, interface identifier, link-local IPv6 address, or another
  local interface IPv6 address appears in a shared record, log, screenshot, or
  report.

Do not continue past a stop condition to finish a matrix. A clean stop and a
private report are worth more than an incomplete pass.

## 4. Records and secrets

Keep one record per live stage in a private location. Do not commit it unless
it is redacted and the owner asks for it.

### 4.1 Record fields

- test id and date;
- owner approval reference;
- tester initials or a role, not a personal account name;
- build identity from section 3.3;
- the path used: target app, command-line GUI, or CLI, and the fixed error code
  when that path was unavailable;
- source device model and OS version;
- target device model and OS version;
- app version and install method;
- hotspot band, channel width, and security type, with no SSID;
- carrier and plan: "not recorded by policy";
- test steps by id;
- result: pass, fail, blocked, inconclusive, or development evidence;
- startup warnings, with any host name or resolver removed;
- the claim, rule, and table 700 inspection immediately before a Linux start,
  including file type and link count for the claim, the claim header version,
  and the claim state. A present claim is Blocked because no reviewed selector
  dump exists and no owner approval can name every selector. Record the start as
  Blocked instead of recording a selector set;
- whether the recorded revision contains the Linux destination proof;
- on macOS, the helper state files and lock and journal names that exist,
  including `service-journal.json`, with owner, mode, set-id bit, extended ACL
  state, type, and link count;
- on iOS and Android, the token storage state and any unreadable, conflict, or
  rotation-recovery state;
- on Android, whether a pending tethering observation was still in progress;
- observed messages and counters, with secrets and personal data removed;
- `ttl_bad` and the `probe` TTL value;
- stop reason and stop message, or a note that the CLI path has no `last_stop`
  view and cannot report `user`;
- cleanup evidence: routes, rules, addresses, devices, listeners, and
  processes;
- limitations and anything the test did not cover;
- redaction check result, including DNS.

### 4.2 Redact

Remove or replace before storage or sharing:

- source device token and any password;
- pairing code;
- target identity key and any private key;
- carrier account number, phone number, IMEI, ICCID, SIM identifier, and plan
  name;
- hotspot SSID and password;
- destination host names and IP addresses;
- MAC addresses, interface identifiers, and persistent or link-local IPv6
  addresses of the target, source device, or hotspot interface;
- neighbor, ARP, or ND entries that name a device or a local address;
- DNS query names and answers;
- resolver addresses, search domains, and the system DNS server list that
  `probe`, `scutil`, `resolvectl`, or `/etc/resolv.conf` prints;
- route and rule output that names a personal destination, resolver, or private
  address;
- `ifconfig`, `ip addr`, `ip -6 addr`, and `Get-NetIPAddress` output before it
  is redacted;
- packet captures and payload dumps;
- screenshots that show any item above;
- personal names, email addresses, and account names;
- full logs that contain any item above.

Use labels such as "public test endpoint A", "test destination 1", or
"resolver R". Keep unredacted detail in a private note that is not in the
repository and delete it after the run. When a command prints DNS servers, record
only that the list was read, not the addresses. When a command prints a MAC
address or a local IPv6 address, record only that the interface state was read.

### 4.3 Token and credential handling

- Never put a token on a command line, in an environment variable, in a shell
  history file, in a script, in a chat, in an issue, or in a test record.
- The CLI still accepts `HOTSPOTSHADE_PHONE_TOKEN`, and `tun` and `phone` read
  it before they prompt. That is a compatibility path. Do not use it, and do not
  set it for a test. The variable must be absent, not empty: an empty value is a
  token error, not a reason to show the prompt.
- `tun` runs under `sudo`, so check the root process environment. Run `sudo -v`
  first, so the check does not put a token into a password prompt:

  ```sh
  sudo -v
  sudo sh -c 'test -z "${HOTSPOTSHADE_PHONE_TOKEN+x}" && echo unset'
  ```

- `phone` runs as your own user in this procedure and reads your own shell
  environment. Check that shell too:

  ```sh
  test -z "${HOTSPOTSHADE_PHONE_TOKEN+x}" && echo unset
  ```

  Do not use `sudo` for this check. The two checks cover different processes.
  On Windows, in the console you will use,
  `Test-Path Env:HOTSPOTSHADE_PHONE_TOKEN` must print `False`. A variable that
  is set to an empty string still prints `True`. The current refusal test does
  not need an elevated console; a future real start does.
- Do not run `env`, `printenv`, `set -x`, or a shell trace while a token may be
  set. Do not paste a command transcript that contains one.
- Use the hidden prompt. Do not use `--secrets-fd` in this procedure. Under
  `sudo` a descriptor does not survive by default, and a private file plus a
  descriptor is easy to get wrong.
- On the target, the browser GUI and the desktop service keep paired
  credentials in process memory only. They are not written to disk. A service
  restart loses them; pair again. The GUI has a manual token field for its own
  start path, but this procedure does not use it when a CLI hidden prompt is
  available.
- On the source device, the token is shown only through Settings. Tap Show
  token, read it on screen, and type it at the hidden prompt. It hides again
  after 30 seconds; tap Show token again if needed.
- Do not use the Copy token button for this procedure. Do not use the
  clipboard, a note, a chat, or a screenshot. The Android app asks the system
  to clear its own copy on a timer, but the platform enforces no expiry and can
  skip the clear while the app is in the background. iOS sets a two-minute
  expiration. Do not rely on either.
- Never ask another person to send a token in chat.
- Never commit an identity key, a provisioning profile, a certificate, or a
  packet capture with personal traffic.
- Never edit a file under `probes/`. Those files are measurement records. Add a
  new file only if the owner asks.

The manual path for a build without GUI pairing is: open the source app
Settings, tap Show token, read the token on screen, and type it at the target
CLI prompt. This is the path on Windows, where GUI pairing is not supported, and
on macOS when the unsigned or ad hoc app cannot start real mode. On Windows the
current build still refuses source device token use after the prompt, so record
the Windows tunnel cells as Blocked and type a fixed non-secret placeholder,
such as `test-placeholder-not-a-token`, at the prompt. Never type a real source
token into the Windows refusal path. Do not treat the typed placeholder as
consent for a disabled path.

On iOS, a Keychain token can survive an app uninstall, and Forget does not
revoke it. The current build disables token rotation: the Rotate token control
stays disabled because `TokenRotationPolicy.reviewed` is false. Do not treat the
control, an uninstall, or a reinstall as a revoke path. Do not reinstall or
delete saved data to clear a token conflict, an unreadable item, a damaged
rotation intent, or an unfinished rotation. Those are stop conditions, and the
app has no in-app conflict recovery. The rotation and recovery code is exercised
with fakes only. That does not establish real Keychain and UserDefaults crash
durability, device restore safety, or external-writer safety.

A destination check is not proof that the token is safe. The Linux `tun
--phone` check in the current working tree rejects a destination that is not
the default gateway before the token leaves the process. macOS `tun --phone`,
`phone`, `phone-udp-diag`, and `phone-speed-diag` do not run that check. Type
only the current default gateway even when a build is expected to check it.

## 5. Read-only preflight

Do not run this section until section 3.3 provenance is recorded and the owner
approved every command below, including the `sudo` reads. A `sudo` read is a root
read. It needs its own approval, and the approval must name the commands. If you
cannot get that approval, stop before the first command.

Every step in 5.1 to 5.6 is read-only or demo only. It changes no route,
creates no tunnel device, and starts no real tunnel. Section 5.3.1 is a
pre-start gate, not a preflight step: it runs with a Linux tunnel start and can
accompany a host change. It does change what you know, so record the command and
its exit status. Do not run a command that this section does not list.

If any check is ambiguous, fails, or names an object you did not create, stop.
Do not "clean up" in preflight. Report the state to the owner.

### 5.1 All platforms

1. Confirm the build identity from section 3.3.
2. Confirm no HotspotShade engine or helper is already running.
3. Confirm no other tunnel, VPN, or network extension is active. A VPN or a
   filter driver can intercept flows before the tunnel.
4. Run the read-only probe with an absolute path:

   ```sh
   BIN=/absolute/path/to/hotspotshade
   test -x "$BIN"
   "$BIN" probe
   ```

   `probe` takes no options. On Windows, run `& $Bin probe` instead. It prints
   the account id or elevation state, the default interface, the system IPv4
   DNS servers, the TTL of one local UDP socket, the audit failure count, and a
   privilege line. It creates no adapter, route, or listener. On Windows it
   prints the elevation state in place of the account id and DNS servers.
   Record the TTL and audit count, not the account id. Do not record the DNS
   server addresses; they are in the section 4.2 redaction list.
5. Re-read the platform state in 5.2 to 5.4 and compare it with the baseline.
   `probe` must change nothing.

If `probe` fails, do not retry with guessed flags. It has no flags. Report the
error.

### 5.2 macOS target

```sh
route -n get default
netstat -rn -f inet
netstat -rn -f inet6
ifconfig
scutil --nc list
systemextensionsctl list
pgrep -fl hotspotshade
```

Record the default interface, the default gateway, any existing `utun`
interface, and whether any VPN or network extension is active.
`scutil --nc list` shows VPN services. It does not show every network
extension, so `systemextensionsctl list` is also required. A filter or
transparent proxy can intercept flows before the tunnel. A label such as
"default gateway G1" is enough. Do not record a personal address if the owner
considers it private.

Expected before a test:

- the default route is the physical hotspot interface, not a `utun`;
- no `0.0.0.0/1` or `128.0.0.0/1` route points at a `utun`;
- no `2000::/3` blackhole route from a previous run;
- no active network extension, content filter, or transparent proxy;
- no `hotspotshade` engine process.

A `2000::/3` blackhole that survives a crash is possible. A-08 covers the
ownership rule. Do not delete it in preflight.

Check the user identity key and its directory, if they exist:

```sh
stat -f '%Sp %Su %N' \
  "$HOME/Library/Application Support/hotspotshade" \
  "$HOME/Library/Application Support/hotspotshade/identity.key"
```

Expected: the engine creates the directory as `0700` and the file as `0600`,
and both are owned by the account that runs the engine. The check itself
accepts any directory or file mode with no group or other bit, including a
stricter mode such as `0500` or `0400`. Record the actual mode text. A group or
other bit, a different owner, or a non-regular file is a stop condition. The
engine checks the directory as well as the file. Do not print the key.

Real mode runs the root engine with `HOME=/var/lib/hotspotshade`, set by the
helper, so its key is under
`/var/lib/hotspotshade/Library/Application Support/hotspotshade/`. Do not infer
the root engine's home from `sudo`; the helper sets it explicitly. Inspect that
path only with owner approval.

Check the helper state directory only with owner approval. A missing directory
or any missing listed file is expected before the first helper run. A present
cleanup marker, launch intent, or install or service journal is a stop
condition, not a state to clear:

```sh
sudo stat -f '%Sp %Su %l %N' /var/db/hotspotshade
sudo stat -f '%Sp %Su %l %N' \
  /var/db/hotspotshade/cleanup-blocked \
  /var/db/hotspotshade/engine-session \
  /var/db/hotspotshade/install-journal.json \
  /var/db/hotspotshade/service-journal.json \
  /var/db/hotspotshade/start-journal \
  /var/db/hotspotshade/start-exclusion \
  /var/db/hotspotshade/start.lock \
  /var/db/hotspotshade/upgrade.lock
sudo ls -lde /var/db/hotspotshade
sudo test ! -L /var/db/hotspotshade
for name in cleanup-blocked engine-session install-journal.json \
  service-journal.json start-journal start-exclusion start.lock upgrade.lock; do
  if sudo test -e "/var/db/hotspotshade/$name"; then
    sudo ls -lde "/var/db/hotspotshade/$name"
  fi
done
```

The helper requires the state directory to be a real root-owned directory with
no group or other permission, no set-user-ID, set-group-ID, or sticky bit, and
no extended ACL. A state file
that the helper reads or removes must be a root-owned regular file with no group
or other permission, no set-user-ID, set-group-ID, or sticky bit, and no
extended ACL. The helper checks a
single link on `start-exclusion`; it does not check the link count of every
state file. The Rust engine checks the state directory ACL and the
`start-exclusion` owner, mode, special bits, link count, and ACL. In the
working-tree engine last read, a direct `engine-session` record is created
and removed as a single-link owner-only file, and its descriptor is checked for
an extended ACL before writing or removing it. This change remains under
independent review. The engine's `start-journal`,
`cleanup-blocked`, `install-journal.json`, and `service-journal.json` check is a
presence check only. This procedure treats a multi-link state file as a stop
condition even where the code would accept it. That is a conservative operator
rule, not a code requirement. `stat` shows the mode letters, including special bits,
but it does not show an ACL. `ls -lde` prints an ACL line when one exists. Run it
on each listed file that exists; a missing file is expected. Any ACL line, a
set-user-ID, set-group-ID, or sticky bit, a group or other bit, the wrong owner,
a non-regular type, or more
than one link on a state file is a stop condition. Do not use the link count of
`/var/db/hotspotshade` itself as a failure; a state directory with a subdirectory
can report a count above 1. An unreadable ACL state is unknown, not clean. Do not
delete or edit any listed state file by hand. There is no approved direct-engine
recovery.

The lock and journal names are changing in the working tree. The helper and
engine last read use `start-exclusion`, and the helper passes descriptor 5 to
the engine. The helper also uses `cleanup-blocked`, `engine-session`, and refuses
a present `install-journal.json` or `service-journal.json`. A direct CLI or GUI
engine writes the same `engine-session` record and refuses the same journals.
The installer coordinator uses `start.lock` and holds `start.lock`,
`start-exclusion`, and `upgrade.lock` as a transition set. The helper no longer
writes `start-journal`, but the installer still reads it. Old binaries take no
lock at all. Record every name that exists, its type, link count, set-id bit,
and ACL state. Do not infer a clean host from a missing lock or from one name
being absent.

Check listeners with root visibility when an engine may be root:

```sh
sudo lsof -nP -iTCP -sTCP:LISTEN
```

A non-root `lsof` can miss a socket that a root-owned process holds. Do not
report "no listener" from a non-root run. Before a tunnel, no tunnel listener
should exist. A GUI listener on `127.0.0.1` is allowed if the app is open.

Stop if any of these is true:

- the default route points at a `utun`;
- a `/1` route or a `2000::/3` blackhole exists and you cannot explain it;
- a VPN, network extension, content filter, or transparent proxy is active or
  you cannot tell;
- a `hotspotshade` process is running;
- `/var/db/hotspotshade/cleanup-blocked`, `engine-session`,
  `install-journal.json`, `service-journal.json`, or `start-journal` exists, is
  unreadable, or is not a regular root-owned file. This procedure also treats a
  multi-link state file as a stop condition;
- the state directory or a state file has group or other permission, a set-id
  bit, or an extended ACL, or the ACL state cannot be read;
- the helper and engine lock names or identities disagree, or the installer
  reports a start-journal lock mismatch;
- `route`, `netstat`, `stat`, `ls`, or `lsof` fails or its output is ambiguous.

### 5.3 Linux target

```sh
ip -4 rule show
ip -6 rule show
sudo ip -4 route show table 700
sudo ip -6 route show table 700
ip link show type tun
ip addr show
pgrep -a hotspotshade
sudo stat -c '%a %U %G %F %n' /run/hotspotshade
sudo stat -c '%a %U %G %h %F %s %n' /run/hotspotshade/route-claim
sudo test ! -L /run/hotspotshade
sudo test ! -L /run/hotspotshade/route-claim
```

Do not add `-L` to `stat`. The preflight must see a symlink at the path, not the
target it names.

Expected before a test:

- no rule at priority 17000 or 17001;
- no route in table 700;
- no `hs-tun0` or other `hs-tun*` device;
- no `hotspotshade` process;
- no `/run/hotspotshade/route-claim` file. A claim of any size is not a clean
  preflight result. Record its metadata and stop. Do not delete it.

The `/run/hotspotshade` directory can exist after a clean stop. The clean result
is an absent claim file, not an absent directory. A successful `stat` on the
directory is normal. When the directory or the claim exists, each must be a real
directory or regular file, not a symlink, and must be owned by the account that
runs the engine. The claim must have exactly one link. Each must grant no
permission to group or other. The check rejects any group or other bit (`mode &
0o077`). It does not require exactly `0700` and `0600`; a stricter mode is
accepted. Any group or other bit, a symlink, a non-regular file, or a claim link
count other than 1 is a stop condition. The engine opens the claim with
`O_NOFOLLOW` and requires a regular single-link file.

The current claim format is version 3: `hotspotshade-route-claim 3`. A version 2
record without predecessor lines is still read; version 1 is refused. The
current record names the boot id, network namespace, writer pid, tunnel name and
index, outer interface, and IPv6 policy. Up to four `prior` records each name
another tunnel name and index, outer interface, and IPv6 policy. The table,
priorities, protocol marker, prefixes, and route types are not stored; they come
from the build's constants. A claim can therefore describe more than one tunnel
identity, and recovery can match the current record and every predecessor. A
replacement that would need a fifth distinct predecessor refuses unless a
just-completed recovery proved every recorded selector absent on two complete
reads. Only then does it keep the previous current record and the newest three
predecessors, for four `prior` lines total, and drop the oldest. Without that
proof it refuses and the fifth can block every later start. The linked
[LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md) now describes the same
compaction rule and its limit: a kernel dump can omit a stable object on every
read, so a hidden object can survive after its selector is dropped. That note is
another writer's scope, is unreviewed, and does not approve a manual path.

`stat` and the `route_claim` status show file metadata and coarse state. They do
not enumerate the tunnel names, indexes, outer interfaces, IPv6 policies, or the
rules and routes that recovery can delete. No safe, reviewed, read-only selector
dump exists in this tree. `inspect_route_claim` reads record fields, but it does
not derive the selectors and is not a replacement for that dump. Do not derive a
delete set by hand from the claim text: a delete request with missing selectors
can match a foreign object. Until a reviewed dump is added, a present claim is a
hard block for every Linux start. Record the start Blocked and do not start. A
future dump must decode the header, the current `tun`, `outer`, and `ipv6` lines,
and every `prior` line, and derive every rule and route selector from the
build's constants. The owner must approve every selector. Approval of the file,
its size, or its `stat` output is not approval of the set.

Do not use a start as a read-only claim check. A start creates, locks, truncates,
or unlinks the claim file, and for a valid current-boot record it can delete the
exact routes and rules of the current record and every predecessor before it
checks the source device token. This is the order in the working-tree Linux
start. It is uncommitted source, so read the recorded revision before you rely
on it:

1. Early refusals that never read the claim: invalid options, a direct-mode
   `--no-pin`, `--no-routes`, or `--ipv6 inherit`, a source device proxy start
   without IPv6 forwarding, a process that is not root, a cleanup block from this
   process, a tunnel already running in this process, and an interface that
   cannot be resolved or is not a physical name. A frozen outer index that
   differs from the resolved one (`outer_interface_changed`) also refuses here.
   None of these touches the claim, so they say nothing about the claim state.
2. The start resolves the selected interface, checks the frozen index, and runs
   a read-only physical outer capture (`capture_physical_outer`). The capture
   retains open sysfs link and device descriptors and their canonical paths. It
   opens no TUN device and changes no route. It rejects loopback, tunnel, and
   VPN links. It runs before the claim, so a refusal here says nothing about the
   claim state.
3. The start rechecks the retained physical identity immediately before and
   after the claim step. It creates `/run/hotspotshade` and the claim file when
   they are missing, takes the exclusive lock, and proves that the locked file is
   the file at the path. A missing claim therefore becomes an empty, locked file.
4. The start reads the record under the lock. It checks the boot identity first.
   An earlier-boot record is truncated at once, whatever namespace it names. Only
   a current-boot record is then compared with the namespace.
5. A valid current-boot, current-namespace record with no live lock goes to
   recovery and can delete the exact recorded objects of the current record and
   every predecessor. After a successful recovery the recovered record stays in
   the claim file. The start then runs the ordinary table 700 and priority read
   for its own gate. It does not clear or replace the recovered record at this
   step. `install_verified` later repeats that read and writes its own record
   only when the second read is free. If either read refuses, the recovered
   record stays on disk and the next start adopts it again.
6. The start reads table 700 and both reserved rule priorities once and refuses
   with `route_setup` if any object is present. The read is a snapshot. A kernel
   dump can omit an entry without reporting interruption, and another process can
   add one afterward, so an object that is present on the host can pass this
   check.
7. The start proves the live outer pin (`verify_outer_pin`) and checks the frozen
   index again. In source device proxy mode it then proves the source device
   destination, rechecks the retained physical identity, and only then runs the
   token check. Direct mode has no destination proof and no token. The start then
   rechecks the retained identity, opens the TUN device, proves its identity,
   rechecks the retained identity again, adds the link address, and rechecks it
   again.
8. `install_verified` reads table 700 and the priorities again and refuses an
   object. It writes its own claim record only after that read passes, then adds
   the rules and routes. The start rechecks the retained physical identity
   around that route setup. At a late refusal the token has already been used and
   the TUN device and address existed.
9. A refusal at any step from 6 onward drops the route manager. With no route or
   rule recorded and no record written, the drop unlinks an empty claim file. A
   recovered record that the later read did not confirm stays in the file, and
   only the lock is released. Do not rely on a comment in the source. The
   current code and [LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md) agree on
   this handover.

The states differ:

- Empty claim file. The engine treats it as no record. A start does not clear
  an empty claim and does not need to. If table 700 or a reserved rule priority
  still holds an object, the start normally refuses with `route_setup` at step 6
  and then unlinks the empty claim. It does not promise that: if the read at
  step 6 omits or misses the object, the start can reach the token check, TUN
  creation, and the address install before step 8 refuses. If the host is
  otherwise clean, the start writes a new record. An empty claim is still a crash
  trace and is a stop condition for preflight. A missing claim with leftover
  objects, such as objects from a build that had no claim code, takes the same
  path: step 3 creates the claim and later steps behave as above.
- Claim from an earlier boot. The engine cannot adopt kernel objects across a
  reboot. A start truncates the claim file at step 4 and deletes no route or rule
  because of that record. The start then continues. If objects remain, step 6 or
  step 8 refuses and unlinks the now empty claim. This is a host write before the
  token check and can be quiet in an app launch. Do not start to clear it. The
  boot check comes before the namespace check, so an earlier-boot record from
  another namespace is also truncated.
- Claim from another network namespace, with a current-boot record. The start
  refuses at step 4 and leaves the claim in place.
- Damaged or unreadable claim. The start refuses. The safe clear
  (`clear_corrupt_route_claim` and `Service::clear_route_claim`) removes only an
  empty file or a valid earlier-boot record. It refuses a valid current-boot
  record even when its owner or mode is wrong, a current-boot record from
  another namespace, and a non-empty damaged or unparsable file. No CLI command,
  engine API route, browser GUI control, or Linux desktop app action calls it.
  It is an inaccessible foundation today. The linked
  [LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md) documents it, but that file
  is another writer's scope and is not approved by this page. Do not delete the
  claim file by hand.
- Valid current-boot record with no live lock. A start may adopt the record and
  every predecessor, and delete the exact recorded routes and rules without a
  prompt, before the token and gateway checks. The first complete recovery read
  is all or nothing: if it is inconclusive, no object is deleted and the start
  refuses with `route_setup`. Once deletion begins it is incremental. A later
  read or delete failure can leave part of the recorded set removed, and the
  claim stays as the record for the next start. The later install-time read is a
  separate check, so recovery may already have deleted objects before that check
  refuses. The owner must have approved a reviewed selector dump for every
  current and predecessor record before this start. No reviewed dump exists in
  this tree, so this start is Blocked. If the recovery succeeds but the step 6
  read refuses, the recovered record stays on disk and the next start adopts it
  again. That is not the same as an empty claim, which is removed on release.
- Valid current-boot record with a live lock. Another process holds it. The
  start refuses with `route_setup`. Do not delete the claim to force a start.
- A false live lock from a status poll. On Linux every status answer takes the
  same exclusive claim lock for a moment, in the process that serves the status,
  to report `route_claim.locked`. It releases the lock at once and changes
  nothing. A start in another process that reaches step 3 during that moment
  sees a held lock and refuses with `route_setup`, exactly as for a live owner.
  Nothing has changed, but the refusal is not evidence of a live tunnel. Before
  a CLI start, confirm that no engine, app, or root GUI process is running
  (5.1), so no process polls status. If a start refuses with `route_setup` and a
  poller may have been active, record the refusal as inconclusive, repeat the
  reads in 5.3.1, and retry only with owner approval. The refusal comes before
  the token check, so the failed try sent no token. While a
  tunnel runs, its own status answer reports `locked: true` for its own claim,
  because the status lock uses a separate open file description. That means the
  claim is in use, not that another process owns it.

If any of these states applies, do not start during preflight. Read A-08 and
[LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md) before you touch anything. A
later start from a build that contains the review-settled claim code takes the
lock and can adopt the record when every check in A-08 passes. That start is a
host change, not a preflight step. Do it only with owner approval of a reviewed
selector dump for the current and every predecessor record, and with the
before-and-after record from A-08. No reviewed dump exists in this tree, so a
present claim is Blocked. Neither procedure approves a manual delete command.

Check the identity key and its directory, if they exist. A user-run engine uses
`$HOME/Library/Application Support/hotspotshade/identity.key`. A packaged app
runs the root engine with `HOME=/var/lib/hotspotshade`, set by the helper, so
its key is under
`/var/lib/hotspotshade/Library/Application Support/hotspotshade/`. Inspect the
root path only with owner approval.

```sh
stat -c '%a %U %n' \
  "$HOME/Library/Application Support/hotspotshade" \
  "$HOME/Library/Application Support/hotspotshade/identity.key"
```

Expected: the engine creates the directory as `0700` and the file as `0600`,
and both are owned by the account that runs the engine. The check accepts any
owner-only mode, not only those two values; a mode with group or other access is
a stop condition. An absent directory or key before the first run is expected;
record its absence. Stop on any other read error. The engine checks both when
present. Do not print the key.

Check listeners with root visibility:

```sh
sudo lsof -nP -iTCP -sTCP:LISTEN
```

If `lsof` is not installed, use `sudo ss -ltnp`.

Expected: no tunnel listener before a test. The GUI and the SOCKS adapter bind
`127.0.0.1` only. A listener on `0.0.0.0` or a public address is a stop
condition.

An absent `/run/hotspotshade` directory or claim file is expected before a
first run or after cleanup. Stop on any other read error, if a rule, route,
claim file, or device remains, or if you cannot prove that the state belongs to
an earlier approved run. A zero-length claim, a claim from an earlier boot, and
a damaged claim are each a remaining claim file: record the state and stop
rather than starting a physical test.

#### 5.3.1 Immediately before every Linux tunnel start

The steps above, from the first command in 5.3 through the identity key and
listener checks, are the one-time preflight for the host. This gate is not part
of that layout. It is a short repeat that you run last, immediately before every
Linux tunnel start, including a retry, the packaged app, a root browser GUI, and
the CLI `tun` path. Use no other host change between the gate and the start.
A start can change the claim and run recovery before it checks the source device
token, so a stale preflight result is not enough.

1. Confirm that no `hotspotshade` engine or root GUI process is running
   (`pgrep -a hotspotshade`), so no status poll can hold the claim lock (see the
   false live lock bullet above). For an app start, the app starts the engine
   itself; confirm that no engine is already running before you authorize it.
2. Record `ip -4 rule show`, `ip -6 rule show`, `ip -4 route show table 700`,
   `ip -6 route show table 700`, `ip link show type tun`, and the claim `stat`
   with the commands above, including `%F` and `%h`. Read the claim header with
   the read-only commands in 5.3. Do not derive the current or predecessor
   selectors by hand. No reviewed selector dump exists in this tree. The `sudo`
   reads need the approval from section 5.
3. Confirm the claim state is absent. A present claim is Blocked in this tree
   because no reviewed selector dump exists and the owner cannot approve a
   selector set that no tool has decoded. Do not start. Only a future build with
   a reviewed dump could reach the next sentence. In that future build, if the
   claim is a valid current-boot record and the owner approved the dump for the
   current record and every predecessor, record that the start may delete those
   exact recorded objects before authentication, and that a later refusal can
   leave the recovered record in place for the next start. Approval must name
   every selector, not only the file. If the selector set is unreadable,
   unreviewed, or not approved, stop. If the claim is empty, from an earlier
   boot, from another namespace, damaged, or locked, stop and do not start. Also
   stop if the directory or claim is a symlink, the claim is not a regular file,
   or the claim link count is not 1.
4. Confirm no rule at priority 17000 or 17001, no route in table 700, and no
   `hs-tun*` device. In a future build with a reviewed dump, the only exception
   would be the exact recorded set that the dump names and the owner approved
   for recovery. No reviewed dump exists in this tree, so a present claim has
   already stopped step 3. One read cannot prove that a dump is complete. Read
   twice, apart, and stop if the two reads differ.
5. Start the tunnel. Record the exact start error if it refuses.
6. Immediately after the start attempt, repeat the same reads and compare. A
   failed start can still have changed the claim, removed recorded objects, or,
   at the late refusal in step 8 of the order above, created and removed a TUN
   device and address after the token was used. An empty claim that the start
   held can be gone. A recovered record can still be present. Compare the
   before and after state rather than assuming either result.

Do not use a start as a probe. Do not treat an expected `phone_auth` or
`source_device_moved` error as safe. Recovery may already have deleted objects
before either error was produced. An absent claim with leftover objects is not a
safe start either: the table 700 and priority reads are snapshots, and a start
can pass them and use the token before the install read refuses. This gate
describes the working-tree start. It is uncommitted. A reviewed build can differ;
read the recorded revision before you apply it.

### 5.4 Windows target

Run PowerShell as the signed-in user for the read-only baseline:

```powershell
$Bin = "C:\path\hotspotshade.exe"
Get-Process hotspotshade -ErrorAction SilentlyContinue
Get-NetAdapter
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix
Get-NetRoute -AddressFamily IPv6 | Sort-Object DestinationPrefix
Get-NetIPAddress
Get-NetTCPConnection -State Listen
```

Expected before a test:

- no `HotspotShade-Tunnel` or `HotspotShade-Tunnel-<unit>` adapter;
- no `/1` route to a `HotspotShade-Tunnel*` adapter;
- no `2000::/3` route to a `HotspotShade-Tunnel*` adapter;
- no `hotspotshade` process.

The adapter name has a unit suffix for units above zero. Match
`HotspotShade-Tunnel*`, not only the exact base name. A source device proxy run
installs two IPv4 `/1` routes and one IPv6 `2000::/3` route on that adapter. The
cleanup checks look for those exact objects. The mode always forwards IPv6, so
the `2000::/3` route forwards through the adapter; there is no IPv6 blackhole.

Check the identity key ACL, if it exists:

```powershell
$LocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
if ([string]::IsNullOrWhiteSpace($LocalAppData)) { throw 'Local AppData is unavailable' }
$IdentityKey = Join-Path $LocalAppData 'hotspotshade\identity.key'
icacls $IdentityKey
```

The engine uses the Windows Local AppData known folder, not the
`LOCALAPPDATA` environment variable. Confirm that the path above resolves to
the same known folder for the account that will run the engine. Stop if it
cannot be established. Windows has no pairing path in this build, so the key
may be absent. An absent key is not a failure. If it exists, the engine accepts the current user,
LocalSystem, Builtin Administrators, and TrustedInstaller. Every ancestor owner
must be one of those principals. The private directory and the file must be
owned by the current user and hold the private descriptor. Any other principal
with a hazardous allow entry fails closed, even one that looks administrative.
A broader allow entry is a stop condition. Do not print the key. The Windows key
is protected with DPAPI and is not portable to another account.

If an engine runs elevated, a user PowerShell may not list its listener. Use an
elevated window only with owner approval, and do not change anything there.

Windows has two different paths, and both refuse source device token use in this
build:

- The Rust CLI `tun --phone` would need Administrator rights for a real start.
  It refuses source device token use with the fixed text "Windows
  source device token use is disabled: physical adapter and gateway identity
  cannot be verified safely; use a supported target device". The token gate runs
  before the elevation check, so the refusal does not need elevation. It comes
  before any adapter or route change. It also comes before the DLL path is
  resolved or loaded, so it does not need `wintun.dll` and an absent DLL does not
  change the result. It is not a gateway proof and not a tunnel.
- The command-line GUI needs an authenticated launcher with `--token-fd` and
  `--parent-fd`. Its start and source-device check return
  `source_proxy_unavailable`, displayed as "Source device proxy mode is
  unavailable in this Windows build." They send no token and do not prove a
  gateway or source identity.
- The WinUI app is a simulated preview. It has no engine, no tunnel, no routes,
  and no credentials.

Preflight records both the CLI elevation state and the GUI launcher state
separately. A GUI result does not cover the CLI, and a CLI result does not cover
the GUI. Neither path can start a tunnel in this build, so record the source
proxy and automatic-stop cells as Blocked, not as a pass or a fail. Do not type
a real source token at the CLI prompt to prove the refusal. Type a fixed
non-secret placeholder such as `test-placeholder-not-a-token`; the refusal comes
before any adapter, route, or token send.

The read-only `hotspotshade probe` command does not use a token and remains
read-only in the current source. A source-device probe, which would use the
token, is refused with the source-proxy refusal. Record which one you ran.

Stop if a `HotspotShade-Tunnel*` adapter, `/1` route, `2000::/3` route, or
`hotspotshade` process exists. Also stop if a VPN or filter driver is active or
you cannot identify an adapter.

### 5.5 Source devices

On iOS:

- confirm the current build and the bundle identifier `local.hotspotproxy.app`;
- confirm the app is signed with your own certificate;
- note the provisioning profile expiry;
- confirm the hotspot is on and the target is connected;
- confirm the app is in the foreground;
- record whether the app reports a token storage conflict, an unreadable item,
  a damaged rotation intent, or an unfinished rotation. Stop on any of them.
  Confirm that the Rotate token control is disabled and does not claim to be a
  revoke path. Do not try to make it available.

On Android:

- confirm the current build and the application id `com.hotspotshade.demo`;
- confirm the notification permission on Android 13 or later;
- confirm the hotspot is on and the target is connected;
- confirm the app is in the foreground;
- record whether the proxy stop reason or pairing state is `TOKEN_UNREADABLE`.
  Stop on it. Do not clear app data or reinstall to make it start.

Do not install or replace an app in this section. Installation belongs in
section 6 and needs approval.

### 5.6 Demo GUI review

```sh
BIN=/absolute/path/to/hotspotshade
"$BIN" gui --demo --no-open --port 8794
```

Open `http://127.0.0.1:8794/` in a browser on the same machine. Check:

- the page says the data is simulated;
- the layout at 1440x1000 and 1100x900;
- the light theme and the dark theme;
- the browser console for errors and failed requests;
- the network log for external asset requests. There must be none.

This is a UI check. It does not prove a tunnel, a pairing, or a carrier result.
Stop it with Ctrl-C.

## 6. Install, backup, and rollback

Every step in this section needs owner approval.

### 6.1 macOS target app

```sh
scripts/build_mac_app.sh build/HotspotShade-unsigned.zip
```

The bundle is ad hoc signed. Unzip it and move it to Applications.

Gatekeeper on macOS 14 and later has two paths:

- try to open the app once, then go to System Settings > Privacy & Security and
  choose Open Anyway;
- on macOS 14, Control-click the app and choose Open.

A managed Mac or a policy can still block the app. This is not a universal
install path.

Real mode installation remains BLOCKED and UNAPPROVED. Real mode needs a
root-owned, Developer ID, hardened-runtime helper and engine, a launch daemon,
and the `dev.hotspotshade.tunnel.start` right. The current tree has no approved
package that installs them. `macos/Installer` is a build-only foundation, its
generated `preinstall` refuses before it observes or changes anything, and a
signed helper install and live XPC launch have not run. An unsigned or ad hoc
app opens the real dashboard and pairing with the bundled user engine, and Turn
on fails closed with a plain message that the signed helper is needed. The app
has no demo mode. Do not
describe an unsigned build as protected.

The macOS lock and journal protocol is also unapproved and changing. At the
last read, the helper and engine use
`/var/db/hotspotshade/start-exclusion`, and the helper passes descriptor 5 to
the engine. The helper's durable records are `cleanup-blocked` and
`engine-session`; it refuses a start while `install-journal.json` or
`service-journal.json` is present. A direct CLI or GUI engine writes the same
`engine-session` record and refuses the same journals. The installer coordinator
uses `start.lock` as its primary name and holds `start.lock`, `start-exclusion`,
and `upgrade.lock` as a transition set, so it contends with the current helper
and engine through `start-exclusion`. Old binaries take no lock at all and
remain a gap. The helper no longer writes `start-journal`, but the installer
still reads it. Do not treat these names as one reviewed protocol. Re-read the
recorded revision before any install decision.

Before install:

- back up the existing app bundle if the owner wants a rollback;
- back up the identity key to a private encrypted location if the owner wants
  to keep the target identity. The key is secret;
- record the app version and the pairing state;
- record whether the helper is at
  `/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper` and the launch
  daemon at `/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist`;
- record `cleanup-blocked`, `engine-session`, `install-journal.json`,
  `service-journal.json`, `start-journal`, `start-exclusion`, `start.lock`, and
  `upgrade.lock` under `/var/db/hotspotshade`, with owner, mode, set-id bit,
  extended ACL state, type, and link count. A present marker or journal is not a
  clean host.

Do not install a root helper or the installer package from this tree. That
installation is blocked, not merely unapproved for one device. Do not remove
the durable cleanup marker, launch intent, `install-journal.json`,
`service-journal.json`, `start-journal`, or a lock file to make a start pass.
The recovery in `macos/Helper/README.md` is an inspection and containment
procedure for the helper engine path. It does not cover a direct CLI or GUI
engine, and it says a reviewed recovery for direct and helper engines is still
required. It does not approve deleting `cleanup-blocked` or `engine-session` by
hand. Do not delete either journal or any state file by hand. Stop and escalate.

### 6.2 Linux target app

Build on a Linux host:

```sh
cd linux
ARCH=x64 npm run package:deb
```

The package is `linux/build/hotspotshade_0.1.0_amd64.deb`. From the repository
root, install it with your own trust decision:

```sh
sudo apt install ./linux/build/hotspotshade_0.1.0_amd64.deb
```

The path is relative to the repository root. If you are in `linux/`, use
`./build/hotspotshade_0.1.0_amd64.deb`. The package is unsigned and is not in
the release set. A missing dependency, a different distribution, or a policy
that rejects unsigned packages can block the install.

The package is a privileged install, not an ordinary user app. When the build
contains `/opt/hotspotshade/chrome-sandbox`, the package sets that Electron
sandbox helper to mode `4755`, so it is setuid root. That is a second privileged
component outside the `pkexec` helper. Confirm the package digest and the exact
setuid path with the owner before install. Do not install it merely because the
window is convenient.

Before install:

- record the current package version, if any;
- record user settings and the autostart file at
  `${XDG_CONFIG_HOME:-$HOME/.config}/autostart/hotspotshade.desktop`;
- record whether `/var/lib/hotspotshade` exists and who owns it;
- record whether `/opt/hotspotshade/chrome-sandbox` exists and its mode;
- confirm polkit and a status notifier host if you will test the authorization
  prompt or the tray.

The packaged app starts the engine through `pkexec` and the fixed helper at
`/usr/lib/hotspotshade/hotspotshade-helper`. The helper accepts no argument. Do
not start the app as root. Start it as the signed-in desktop account.

The polkit action `local.hotspotshade.tunnel` uses `auth_admin` for every
session state, so each launch needs a fresh authorization. The helper checks
`PKEXEC_UID`, refuses arguments, and starts only the fixed engine path after an
ownership check. It cannot prove which desktop process called it.

The root engine runs with `HOME=/var/lib/hotspotshade`. The package creates that
directory as root, mode `0700`. The engine keeps the target identity key, the
helper lock, and the engine state file there. The app never reads or copies the
key. Every user who can authorize a launch shares that identity and trust, so a
tunnel identity can outlive the account that created it. Inspect the directory
only with owner approval, and do not print the key.

Keep the prior `.deb` for rollback. There is no automatic update and no rollback
tool. A rollback means installing the prior package with owner approval and
recording the version and digest. A downgrade can need an explicit package
manager option, and it can keep the newer root identity and trust. Record what
you observe.

### 6.3 Windows target

The WinUI app is a simulated preview. It has no engine connection, no tunnel,
no routes, and no credentials. Do not attach it to the Rust engine.

The Rust CLI has a source device proxy start path. A real start would need
Administrator rights. The current build refuses source device token use on this
path before it creates an adapter or changes a route, and before it resolves or
loads a DLL, so it cannot start a tunnel and does not need `wintun.dll`. The
refusal also comes before the elevation check. A future build that enables token
use will need a `wintun.dll` that you supply. The repository does not bundle or
commit it. Place it next to the executable or pass `--wintun PATH`. The file
name must be `wintun.dll`. The loader does not search `PATH` or the current
directory.

The command-line GUI is a different path. It needs an authenticated launcher
with `--token-fd` and `--parent-fd`. Its start and source check return
`source_proxy_unavailable`, shown as "Source device proxy mode is unavailable
in this Windows build." It is not the WinUI app and not the CLI.

Before install or run:

- record the Windows build and architecture;
- record whether Developer Mode is on and restore the prior setting afterward.
  Developer Mode is needed only if you deploy the WinUI preview, not for the
  Rust CLI;
- record the adapter list and route table;
- record the DLL path and digest only if the owner wants it for a future build
  that can use a tunnel. The current refusal does not need the DLL;
- record whether the command-line GUI is the intended path and its launcher
  state;
- confirm no VPN or filter driver is active.

Do not install a Windows service or signed package unless the owner approved
it. No Windows installer or release artifact exists.

### 6.4 iOS source app

The CI IPA is unsigned. Sign it with your own certificate and install it with
Xcode or your signing tool. A free Apple ID profile expires after seven days. A
new bundle identifier installs as a new app, loses stored trust, and cannot read
the old Keychain item. The old item can still exist on the device.

Before install:

- record the existing version and bundle identifier;
- record whether the app has stored trust and a token;
- record the provisioning profile expiry;
- confirm the owner approved the install and the developer certificate trust;
- confirm the rollback path: reinstall the older signed build with the same
  bundle identifier, or accept the loss of trust. The same bundle identifier can
  read the old Keychain token again, so an uninstall or reinstall is not
  revocation. The current build disables token rotation, so a reinstalled app
  still cannot revoke a saved token from the app.

### 6.5 Android source app

CI runs `testDebugUnitTest lintDebug assembleDebug assembleDebugAndroidTest`,
but it does not publish the APK. Build it locally:

```sh
cd android
./gradlew assembleDebug
```

The APK is `android/app/build/outputs/apk/debug/app-debug.apk`. It is signed
with the local Android debug key. A build from another machine or from CI can
use a different debug key. Android refuses an update signed with another key,
so you must uninstall first. An uninstall removes the Keystore token and the
SharedPreferences trust list. That is data loss, not a clean rollback.

The application id is `com.hotspotshade.demo`. There is no release signing
configuration and no release APK. Do not claim one.

Before install:

- record the existing version, application id, and signing certificate digest;
- record whether the app has stored trust and a token;
- confirm the owner approved the install and the debug signing key;
- confirm the rollback path and the uninstall data loss.

### 6.6 Backup and rollback rules

Back up only what the owner asks for. Keep every backup private.

| Item | Where it lives | Rule |
|---|---|---|
| Target identity key, macOS user run | `$HOME/Library/Application Support/hotspotshade/identity.key` | Secret. Private encrypted copy only. |
| Target identity key, macOS or Linux root engine | Under `/var/lib/hotspotshade` | Secret. Inspect or copy only with owner approval. |
| Target identity key, Windows | `hotspotshade\identity.key` under the engine account's Local AppData known folder | Secret and DPAPI-bound. A copy may not work under another account. |
| Source trust list | On the source device | Public keys only. It does not replace the source device's own list. |
| Source token, iOS | Device-only Keychain item | Secret. Do not export it. The item can survive an uninstall. Forget does not revoke it. Rotation is disabled in this build, so the app has no working revoke path. The rotation and recovery code uses fakes only; real Keychain and UserDefaults crash durability, device restore safety, and external-writer safety are unverified. |
| Source token, Android | Encrypted app storage protected by Android Keystore | Secret. An uninstall loses it. A `TOKEN_UNREADABLE` stop is not fixed by clearing data or rotating blindly. |
| User settings and autostart | Platform-specific | Back up if the owner wants them. |
| Linux package privileged files | `/opt/hotspotshade/chrome-sandbox` (setuid root when present), `/usr/lib/hotspotshade/hotspotshade-helper`, and the polkit action | Removed with the package files on `apt remove` or `apt purge`. The sandbox binary is setuid root. |
| Linux root engine home | `/var/lib/hotspotshade` | Secret identity, helper lock, and engine state. Shared by every user who can authorize a launch. Survives `apt remove` and `apt purge`. Inspect only with owner approval. |
| Pairing state on the target | Service process memory | Not on disk. A restart can require pairing again. |

A target identity backup keeps the target key. It does not keep the source
device's trust. If the source device forgets the target, the target must pair
again even with the same key.

Rollback and uninstall:

- macOS: removing the app does not remove a root helper, its launch daemon, the
  durable `/var/db/hotspotshade` cleanup marker, launch intent,
  `install-journal.json`, `service-journal.json`, or the identity key. Real-mode
  installation remains blocked; do not install or remove a root helper from this
  tree. Do not delete state by hand. There is no approved direct-engine recovery;
  stop and escalate.
- iOS: deleting the app removes its container, including stored trust. It does
  not reliably remove the Keychain token. A reinstall with the same bundle
  identifier can read the old token again. A new bundle identifier is a new app.
  Forget removes trust only. Rotation is disabled in this build, so no in-app
  revoke path exists, and uninstall or reinstall does not revoke the token.
- Android: an uninstall removes the Keystore token and the trust list. A lower
  `versionCode` needs an uninstall first.
- Linux: `sudo apt remove hotspotshade` removes the package files, including
  the setuid `chrome-sandbox` and the helper, but does not delete user settings,
  the autostart entry, or `/var/lib/hotspotshade`. `sudo apt purge hotspotshade`
  also leaves `/var/lib/hotspotshade` because this package has no `postrm`
  action that removes it. The root identity and pairing trust therefore survive
  both commands and are shared by every user who can authorize a launch. Do not
  delete that directory by hand. Inspect it with owner approval, do not print
  the key, and record the state before and after the package command.
- Windows: the WinUI preview has no engine state to roll back. Remove the CLI
  binary and the DLL only with owner approval.

No platform has an automatic update, an update feed, or a rollback tool.

## 7. Pairing tests (P)

Approval: required. Pairing starts a listener on the source device and writes
trust on both devices. Do not pair a device that someone is using.

Use the target app or the local GUI. Do not use the HTTP API with a token on a
command line.

Process note: the pairing and the tunnel must be owned by the same engine
process. The browser GUI (`hotspotshade gui`) does not start a real tunnel as a
non-root process: on macOS it returns `protected_helper_required`, and on Linux
it returns `admin_required`. The service never sends a paired token back to the
caller, so a CLI `tun --phone` cannot use credentials that a separate GUI
process paired. The signed macOS app through its helper, and the packaged Linux
app through its helper, keep pairing and the tunnel in one engine.

When the pairing is in a different process from the tunnel, record P-07, P-08
steps 5 to 8, P-09, the tunnel steps of P-10, and the app-close part of A-07 as
Blocked. P-08 is also Blocked for the current iOS build because rotation is
disabled. Do not record a false pass or a false fail. A GUI Forget cannot see a
CLI tunnel, so it is not a test of the documented refusal.

Windows note: the Windows GUI backend has no pairing and the Rust CLI has no
pair command. The current Windows build also refuses source device token use on
the source proxy path, so no Windows pairing or tunnel cell can run. Record P-01
to P-11 as Blocked on Windows and continue with the remaining platforms. Do not
treat the preview UI as a pairing result.

### P-01 First pair, unknown target

1. Start the hotspot and connect the target.
2. Open the source app and keep it in the foreground.
3. Start pairing on the target.
4. Confirm that the source device shows a six-digit code in two groups of
   three digits.
5. Confirm that the target shows the same code. Do not record the code.
6. Tap Allow on the source device.
7. Confirm that the target shows "Paired" or the documented paired state.

Expected: the target receives the proxy port and token. The token is held by
the service, not shown in the browser.

### P-02 Deny

1. Start pairing from an unpaired state, or use a second target.
2. Tap Deny on the source device.
3. Confirm the documented denied message on the target.
4. Confirm that the target has no new credentials and does not start a tunnel.

Expected: a denial does not pair. Existing credentials, if any, are kept.

### P-03 Cancel

1. Start pairing.
2. Cancel on the target before the source device answers.
3. Confirm the cancelled state.
4. Confirm the source prompt is gone or expires.

Expected: cancel stops that attempt. It does not forget an existing pair.

### P-04 Expiry

1. Start pairing.
2. Do not answer the source prompt.
3. Wait about 60 seconds with the app in the foreground. A foreground source
   prompt normally expires at 60 seconds. The target waits up to 242 seconds for
   the result: 240 seconds for the maximum source prompt window plus 2 seconds
   for the result frame. An inactive source prompt can last 120 seconds, and the
   maximum is 240. Do not treat 60 seconds as the target's hard limit.
4. Confirm the documented timeout.
5. Confirm the source prompt was removed.

Expected: an unanswered visible prompt expires. Do not shorten the wait. A
prompt that started while the source app was inactive can last longer than 60
seconds, so confirm the source state before calling the result early.

### P-05 Known target, no prompt

1. Pair a target once with P-01.
2. Stop the tunnel and keep the pair.
3. Start pairing again from the same target.
4. Confirm that the source device shows no new prompt.
5. Confirm that the target receives the port and token.

Expected: a known target pairs without a tap. It does not authenticate the
source device to the target.

### P-06 Forget

1. Stop the tunnel. Forget is refused while a tunnel runs.
2. Select Forget on the target.
3. Confirm the confirmed "Forgotten" state.
4. Confirm that the source device removed the target key.
5. Start pairing again.
6. Confirm the source prompt appears again.

Expected: Forget clears the target credentials and the source trust. If the
source is unreachable, the target clears its own credentials and reports
`not_delivered`. The source may still trust the key. Forget does not revoke a
saved source token. A target device that still holds the old token can
authenticate until the source device app changes the token. On iOS, token
rotation is disabled in this build, so there is no such in-app path, and an
uninstall or reinstall does not remove the Keychain token. The iOS trust list
uses UserDefaults. A power loss before a Forget write is durable, or a restore,
can bring back an entry. Record the observed trust state; a clean Forget result
does not prove revocation across power loss or restore. Those tests need their
own owner approval and are not part of this procedure.

### P-07 Forget while the tunnel runs

This test needs the pairing and the tunnel in the same engine process. A CLI
tunnel is invisible to the GUI service, so the GUI cannot know that a tunnel is
running. Record P-07 as Blocked in that setup. Do not treat the GUI result as an
engine result, and do not remove trust on the source device as a reaction.

1. Start a tunnel from the app or GUI that owns the pair.
2. Try Forget.
3. Confirm the action is refused with "Turn off the tunnel first."

Expected: the tunnel is not stopped by Forget. The target keeps its credentials.

### P-08 Token rotation

P-08 is Blocked for the current iOS build. The build sets
`TokenRotationPolicy.reviewed` to false, so `canRotate` is false in every state.
The Rotate token control stays disabled and says that rotation is unavailable
until the staged rotation protocol is reviewed. Do not record a pass from a
disabled control, and do not reinstall, clear app data, or change the review gate
to make it available.

The staged rotation record has fake-store tests only. Those tests do not
establish real Keychain and UserDefaults crash durability, device restore or
downgrade safety, or safety against another writer that changes the same item.
The app has no in-app conflict recovery: when a valid Keychain token and a
different old UserDefaults copy both exist, it keeps both and uses neither.

The Android app refuses rotation while the source proxy runs or a start is
pending, and the iOS app refuses it in every state because of the review gate.
The Android app still has a Rotate source token control, but a physical P-08 run
remains Blocked by the device and owner gates at the top of this page. Do not
use an Android result as iOS evidence, or the reverse.

The steps below are conditional. Run them only on a later reviewed build whose
recorded source revision enables rotation, and only after the owner approves the
build and the action. A CLI tunnel that uses a hand-typed token holds no paired
credential, so it tests the manual token path, not a rotation of a paired
credential. Steps 5 to 8 also need the paired credentials in the same engine
process as the tunnel. Record those steps Blocked in that setup, or record a
separate manual-token observation.

1. Stop the target tunnel.
2. Stop the source proxy.
3. On the source device, rotate the token. Confirm that trust is unchanged.
4. Start the source proxy.
5. Start the target tunnel without pairing again. Confirm the target still
   holds the old token.
6. Record the exact rejection: `phone_token_rejected` or the documented
   message. It must not contain the token.
7. Pair again. Confirm the known target pairs without a prompt and receives the
   new token.
8. Start the tunnel and confirm that the new token works.

Expected on that later build: rotation does not remove trust. Do not claim that a
running tunnel keeps working after a rotation; the apps refuse rotation in that
state.

### P-09 Source proxy port change

This test needs a source app with a real port control. The current iOS app has
one. The current Android app shows the saved port but does not expose a change
control, so record P-09 as blocked on Android.

It also needs the tunnel and the pair in the same engine process, because the
target learns about a port change from that service's status answer. The CLI
source device probe does not show the documented port-change message. Record
P-09 as Blocked for a CLI tunnel.

1. Start a tunnel with a known proxy port.
2. On iOS, stop the proxy if it is running, then change the proxy port.
3. Start the proxy again and confirm that the running target tunnel keeps the
   old port.
4. Confirm the target shows "The source device changed its port. Turn the
   tunnel off and on."
5. Stop and start the target tunnel.
6. Confirm that the target uses the new port.

Expected: the target learns a port only from an authenticated pairing or status
answer. A running tunnel does not switch ports.

### P-10 Pairing state after a restart

This test needs the app or GUI that owns the pair. A CLI tunnel has no pairing
state. The browser GUI and the desktop service keep credentials in process
memory only; the desktop apps follow their own documented behavior.

1. Pair a target.
2. Quit and reopen the target GUI or app.
3. Confirm the documented state.
4. Confirm that a service restart requires pairing again, because the
   credentials live in process memory.
5. Do not assume that a restart keeps the pair. Record what happened.

Expected: the browser GUI and desktop service hold credentials in process
memory only. The desktop apps follow their own documented behavior.

### P-11 Pairing limits and wrong code

Do not run a hostile pairing search. The six-digit code is not a complete
defense against an active attacker. The responders rate-limit challenges and
bind approval to the connection, prompt, code, and deadline. A live test cannot
prove those limits without hostile traffic.

Record this test as "not run" unless the owner approves a controlled test with
a second device that the owner controls. Do not claim that the code search risk
is resolved.

## 8. Source device proxy tests (X)

Approval: required. These tests start a tunnel and change routes on the target.
Use a test target. Do not run them on a device that someone is using.

Run them after a successful P-01 or P-05 pairing, or after the manual token
path in section 4.3 if the target cannot pair through the GUI.

On Windows, the current build refuses source device token use on both start
paths. Record X-01 to X-09 and X-03S as Blocked on Windows and do not attempt a
source-proxy tunnel. Only the read-only preflight applies.

### Start commands

Use the target app for the normal path. For the command line, use an absolute
binary path. `sudo` resets `PATH` on many systems, and a relative command can
run the wrong binary or fail to resolve.

The CLI starts its own engine. It cannot use credentials that a separate GUI
process paired. If pairing was done in a GUI that cannot start a real tunnel,
use the manual token path in section 4.3, and record the pairing tests as
Blocked under section 7. Do not use the CLI to finish a GUI pairing test.

On Linux, run the inspection in 5.3.1 immediately before every start, including
a retry after a failed start. A valid current-boot claim can make the start
delete the exact recorded routes and rules of the current record and every
predecessor before the token check, and an earlier-boot claim is still truncated
by the start without a kernel delete. Do not treat a failed start as a read-only
check.

macOS and Linux do not share one destination check. Read the recorded revision
before you rely on any check:

- Linux `tun --phone` in the current working tree verifies the destination before
  the token leaves the process. It runs after the early read-only physical outer
  capture and after the claim step, and before the token. The claim step alone
  does not prove the live outer pin; that proof runs immediately before the
  destination proof (section 5.3 order). The destination proof needs all of
  these:
  - a default route exists. Without one the start fails with
    `source_device_moved`, even when `--iface` names another interface;
  - the kernel route lookup for the destination returns one unicast route, with
    no multipath, dead, link-down, encapsulated, or `via` data. A local route, a
    failed lookup, or no observation fails with `source_device_moved`;
  - that route leaves through the selected interface. Another interface fails
    with `outer_interface_changed`;
  - that route either names the destination as its next hop, or is on-link (no
    gateway, and its prefix contains the destination). Anything else fails with
    `source_device_moved`;
  - when the selected interface is the default route's interface, the
    destination must also equal the default gateway. This is the strong case. It
    rejects a mistyped address inside the hotspot subnet.
  When `--iface` selects an interface that is not the default route, only the
  route lookup applies. An on-link match proves that the kernel would send the
  address out that interface. It does not prove that the address is the hotspot
  gateway or the source device, so a mistyped address inside the on-link subnet
  passes and the token goes to it. For `--iface`, record the result as "on-link,
  gateway not proven", and do not count it as a gateway check. Do not use
  `--iface` for a pass cell: this procedure keeps the hotspot as the default
  route interface and types its gateway. This change is uncommitted and
  unreviewed. Do not present it as settled Linux behavior until the reviewed
  commit contains it and the review names it.
- macOS `tun --phone` does not verify the typed address against the default
  gateway. It pins the outer socket to the selected interface and sends the token
  to the address you type.
- `phone-udp-diag` and `phone-speed-diag` require the source address to be on
  the hotspot interface subnet. `phone` only requires the interface. None of
  them proves the address is the default gateway. `phone` does not run the Linux
  `tun` destination check.
- Windows has two paths, and both refuse source device token use in this build.
  The Rust CLI `tun --phone` refuses with "Windows source device token use is
  disabled: physical adapter and gateway identity cannot be verified safely; use
  a supported target device". It does not need `wintun.dll` to reach that
  refusal. The command-line GUI needs `--token-fd` and `--parent-fd` and returns
  `source_proxy_unavailable`, shown as "Source device proxy mode is unavailable
  in this Windows build." The WinUI preview has no tunnel. Do not record a Windows
  source-proxy cell from either path.

For every path, read the current default gateway first and type only that
address:

```sh
# macOS
route -n get default
# Linux
ip -4 route show default
```

On macOS, read `gateway`. On Linux, read the `via` address. If the address you
intend to type differs, stop. If more than one default route appears, stop. Do
not continue because the connection works. If the recorded revision does not
contain the Linux destination proof, treat Linux like macOS: the typed address is
the only guard. The token crosses the hotspot link in cleartext (S-07).

macOS and Linux:

```sh
BIN=/absolute/path/to/hotspotshade
test -x "$BIN"
sudo -v
sudo "$BIN" tun --phone <hotspot-gateway>:<proxy-port>
```

Windows, in a console, only to confirm the current build refuses the start.
Elevation and `wintun.dll` are not needed for this refusal, because the token
gate runs before both:

```powershell
$Bin = "C:\path\hotspotshade.exe"
Test-Path Env:HOTSPOTSHADE_PHONE_TOKEN   # must print False
Get-NetRoute -DestinationPrefix 0.0.0.0/0
& $Bin tun --phone <gateway>:<port>
```

The Windows command must print the disabled-token message and exit non-zero. It
must create no `HotspotShade-Tunnel*` adapter, route, or listener. Do not pass
`--wintun` for this refusal test: the gate runs before the DLL path is resolved
or loaded, so the DLL is not needed and its absence must not change the result.
At the hidden prompt, type a fixed non-secret placeholder such as
`test-placeholder-not-a-token`. Do not type a real source token. The CLI reads
that placeholder before the service refuses; the refusal comes before any
adapter, route, or token send. Record the exact text and the before-and-after
adapter and route state. Do not treat a refusal as a gateway check, an
authentication result, or a tunnel result. The Windows command-line GUI is a
separate path, and its start shows the generic page message rather than
`windows_phone_only`.

Source device proxy mode does not accept `--dns-upstream`. The service validation
rejects it with the source device proxy mode message, and the relay also refuses
a phone configuration with an upstream. X-03 must use the original destination
or a server the client selects. Only direct mode D-03 may pass `--dns-upstream`.

The token comes from a hidden prompt. Do not put it on the command line, in the
environment, or in a file. On macOS and Linux, the engine prompt appears after
`sudo` starts and reads from the terminal. Type nothing until you see it. If you
see only a password prompt, stop and re-check the environment variable with
section 4.3. Add `--experimental-icmp` for the CLI echo path. The GUI and the
macOS target app turn the echo relay on by default.

The Windows CLI `tun --phone` refuses before it verifies a destination or sends
the token. It is not a live tunnel test. The Windows command-line GUI is a
separate path with the same token gate. A CLI result does not cover the GUI, and
a GUI result does not cover the CLI.

Expected start errors, in the order that the Linux start can produce them. The
names below are service codes. A CLI and a GUI do not show them the same way.

- A CLI `tun` prints `error: <text>` on stderr and exits with status 1. A fixed
  code appears as that word. Early validation and the read-only physical outer
  capture print their own plain text. The CLI has no separate error page.
- A GUI or the packaged engine maps only a known set of codes to fixed text.
  `phone_auth`, `route_setup`, `tunnel_setup`, `service_start`,
  `admin_required`, `protected_helper_required`, and the Windows codes have
  fixed text. `source_device_moved` and `outer_interface_changed` are not in the
  browser GUI map, so the page shows its generic "The service could not start.
  Check the settings." message. Record the displayed text and do not invent a
  code that the page did not show.
- The macOS app shows the helper's or engine's fixed text. The Windows CLI and
  the Windows command-line GUI also differ. Section 16.1.1 gives the path
  prerequisites and the expected results.

The order is:

- Early, before the claim and before the physical outer capture: invalid options,
  a source device proxy start without IPv6 forwarding, a direct start with
  `--no-pin`, `--no-routes`, or `--ipv6 inherit`, a cleanup block left by this
  process ("route cleanup failed; inspect routes before restarting"), a tunnel
  already running in this process, no resolvable physical interface, and
  `outer_interface_changed` for a frozen outer index that no longer matches.
  Treat none of these as a claim or table result.
- A read-only physical outer capture failure. It carries its own plain message,
  not a fixed code. It runs before the claim, so it says nothing about the claim
  state. A loopback, tunnel, or VPN interface fails here.
- `admin_required`: the process is not elevated on Linux, or a non-root Linux
  GUI tries to start a real tunnel. This comes before the claim.
- `protected_helper_required`: a non-root macOS GUI without the signed helper.
- `route_setup` at the claim step: the claim is locked, foreign, damaged, or the
  table 700 and priority read found an object. A retained-identity recheck
  immediately before or after the claim step also reports this code. This comes
  after the early physical capture and before the live outer pin proof, the
  destination proof, and the token.
- A live outer pin proof failure. It carries its own plain message, not a fixed
  code. It comes after the claim and before the destination proof and token.
- A retained-identity recheck that fails inside a wrapped step takes that step's
  code. Around the token it reports `service_start`, or `phone_auth` only for a
  rejected credential. Around the TUN device it reports `tunnel_setup`. Around
  route setup it reports `route_setup`. A bare recheck before the address or
  after the link install prints its own plain text. Record the stage as well as
  the word.
- `source_device_moved` or `outer_interface_changed`: Linux `tun --phone` in a
  build that contains the destination proof, when the destination, the default
  route, or the route to the destination does not satisfy the proof above. macOS
  does not produce these at start. They come after the claim and live outer pin
  proof, so recovery, an empty-claim unlink, or a kept recovered record may
  already have happened.
- `phone_auth`: the source device rejected the token. This comes after the
  destination proof and the physical outer capture and recheck, and before the
  TUN device. Any other source device connection check failure on Linux returns
  `service_start`. Do not read `service_start` as an authentication result.
- `route_setup` at the install step (Linux): the table 700 and priority read
  failed after the token was used and after the TUN device and address existed.
  The start removes them before it returns. On macOS a stale IPv6 blackhole can
  also fail the route add.
- `tunnel_setup`: the tunnel device or link configuration failed.
- Windows source device token use is disabled in this build. The CLI prints the
  fixed disabled-token text and exits non-zero. The command-line GUI returns
  `source_proxy_unavailable`, shown as "Source device proxy mode is unavailable
  in this Windows build." This comes
  before any adapter or route change and before the token is sent. Do not read
  it as an authentication result.
- `wintun_missing` and `windows_phone_only`: `windows_phone_only` is not the
  disabled-token refusal. The GUI currently returns `source_proxy_unavailable`.
  `wintun_missing` would belong to a missing DLL, but the token gate comes first
  and the DLL is not resolved or loaded, so the current build does not reach the
  DLL check on a source proxy start. The Windows GUI backend maps another start
  failure to `service_start`, so do not expect a raw code there either.
- A missing `--token-fd` or `--parent-fd` on the Windows command-line GUI is a
  launcher error, not a tunnel error. `--demo` starts the simulated UI without
  either.

For a local SOCKS adapter on macOS or Linux:

```sh
"$BIN" phone --phone <hotspot-gateway>:<proxy-port> --listen 127.0.0.1:1081
```

The adapter reads the token from a hidden prompt. It creates no route and no
tunnel device. Use `socks5h` so the adapter resolves names. The adapter also
sends the token to the `--phone` address you type and does not run the Linux
`tun` destination check, so apply the gateway check above. Windows has no
`phone` command in this build.

### Reading status

The CLI prints one line when the tunnel runs, and a fixed message only after an
automatic stop. It has no status page and no `last_stop` view. The GUI and the
target app show the status, counters, and `last_stop`. Record which one you
used. Do not claim that a CLI run showed a GUI status.

Record every startup warning before you wait for an automatic stop. The CLI
prints warnings on stderr for `--no-pin`, `--no-routes`, `--ipv6 inherit`, an
unknown hotspot interface, and a source-silence probe that cannot be built. The
GUI and app expose service warnings in their logs. A warning that auto-stop or
source-silence detection is off makes the related A test Blocked. A warning is
not a stop reason.

### X-01 TCP CONNECT

1. Start the source proxy.
2. Start the target tunnel in source device proxy mode.
3. Open a public test page in a browser, or use the SOCKS adapter with
   `socks5h`.
4. Confirm the page loads.
5. Confirm the running state. Use the GUI or app status, or the CLI running
   line.
6. Record the setup time and result. Do not record the page name or destination
   address.

Expected: one inner TCP flow uses one outer socket to the source device. The
source device opens the destination connection on its cellular path.

### X-02 Inner UDP through the tunnel

This is the tunneled UDP test. It is not the `phone-udp-diag` command.

1. Keep the tunnel running in source device proxy mode.
2. Send one non-DNS UDP flow through the tunnel: a client that sends UDP to a
   lab or public test destination on a port other than 53. A DNS query does not
   count for this step. The relay treats inner UDP port 53 as a separate DNS
   case with its own timing, so a DNS answer cannot stand in for general UDP.
   Do not send the flow directly to the source proxy.
3. Confirm the target relays it as one inner flow with one normalized outer
   socket to the source device.
4. Record the result and, when the build exposes it, the UDP counters and
   `ttl_bad`. Confirm `ttl_bad` is 0.
5. Do not use a local stub resolver or a direct diagnostic socket for this step.
6. Record the DNS case separately in X-03. A cell needs both. X-03S is the
   separate SOCKS5 adapter test and does not cover X-03.

Expected: inner non-DNS UDP uses the tunnel. A public STUN server can rate-limit
or ignore requests. One run is not a throughput result.

### X-02D Scoped phone-udp-diag (not tunneled)

`phone-udp-diag` is a separate scoped diagnostic. It opens its own outer socket
to the source proxy and sends the proxy's UDP-over-TCP command. It creates no
TUN route and does not test the inner UDP path through the tunnel. Do not use it
as evidence for X-02. State clearly that the tunnel is not carrying this flow.

1. Run:

   ```sh
   "$BIN" phone-udp-diag --phone <hotspot-gateway>:<proxy-port> \
     --iface <hotspot-interface> --target <public-test-address>:<port> \
     --rate 10 --seconds 10
   ```

   It reads the token from a hidden prompt. It changes no route and creates no
   listener. It requires the source address to be on the hotspot interface
   subnet. It does not prove the address is the default gateway, so apply the
   gateway check in the start commands. Windows has no such command; record the
   gap.
2. Record `sent`, `received`, `loss_percent`, `rtt_ms`, `outer_sockets`, and
   `ttl_bad`.
3. Confirm `ttl_bad` is 0.
4. Record this as source proxy diagnostic evidence, not as tunneled inner UDP
   evidence.

Expected: the UDP-over-TCP path works at a low rate. A public STUN server can
rate-limit or ignore requests. Loss can be server loss. One run is not a
throughput result.

### X-03 DNS through the tunnel

This is the tunneled DNS test. It uses the TUN path and inner UDP port 53. It is
not the SOCKS5 adapter test in X-03S. A `socks5h` result does not substitute for
this cell.

1. Keep the tunnel running in source device proxy mode.
2. Send one inner UDP port 53 query through the tunnel to the original
   destination. Source device proxy mode rejects `--dns-upstream`, so this cell
   cannot use a configured upstream. Use a client or query tool that sends the
   datagram into the TUN path, not a local stub resolver and not the source
   proxy diagnostic command.
3. Confirm that the query leaves through the source device and that the name
   resolves.
4. Do not use local resolution. A client that resolves a name locally leaks the
   name before the proxy sees it.
5. Record only "name resolved through the tunnel: yes/no" and whether the answer
   came through the TUN path.

Expected: inner UDP port 53 uses a normalized outer socket to the source device.
The target does not call `getaddrinfo()` on an egress path for a proxied name.
Source device proxy mode does not accept `--dns-upstream`; only direct mode D-03
may use it. DoH and DoT use their own paths. A DNS answer does not prove X-02,
and an X-03S adapter result does not prove X-03.

### X-03S SOCKS5 adapter remote DNS

This is a separate adapter test. It creates no route and no tunnel device, and it
does not test the running tunnel. Do not record it as X-03.

1. Start the `phone` adapter from the start commands, listening on
   `127.0.0.1`.
2. Send a request with `socks5h`, so the adapter resolves the name:
   `curl --proxy socks5h://127.0.0.1:1081 https://example.com/`.
3. Confirm that the adapter resolves the name through its own resolver on the
   pinned outer socket, not through the local OS resolver.
4. Record "adapter remote DNS: yes/no". Do not record the destination or the
   query name.
5. Do not use a plain `socks5` request. The client would resolve the name
   locally and leak it.

Expected: the adapter resolves names remotely and uses the normalized outer
socket. The local client must not resolve the name first. This result covers the
adapter only.

### X-04 IPv6

1. Keep the tunnel running in source device proxy mode. This mode always
   forwards IPv6.
2. Open an IPv6 test destination, or use a client that supports IPv6 through
   the proxy.
3. Record success or failure.
4. Do not claim a cellular IPv6 result from an emulator loopback test. The
   Android emulator has no cellular IPv6 route.

Expected: IPv6 TCP, UDP, DNS, and echo go through the source proxy.
More-specific IPv6 routes can bypass the tunnel. The mode rejects `--ipv6
block` and `--ipv6 inherit`.

### X-05 ICMP echo

1. Confirm that "Let ping work" is on in the macOS target app or GUI. This is a
   target-side setting, on by default in both. The source app always serves the
   echo commands while its proxy runs; it has no matching toggle.
2. If you started the CLI tunnel, confirm that it used `--experimental-icmp`.
3. Ping a public test address through the tunnel.
4. Record the reply count and round trip.
5. Record that the inner reply TTL is generated by the target relay. It does
   not measure the source device cellular path.

Expected: echo requests are relayed. ICMP errors, traceroute, and path MTU
discovery are not supported. The echo path has no TTL control.

### X-06 Concurrency and one flow per outer socket

1. Open several TCP flows at the same time.
2. Confirm the source connection count rises by the number of flows, not by one
   shared connection.
3. Confirm the target diagnostics show the expected `tcp.flows_peak` when the
   build exposes them. Otherwise record the gap.
4. Do not accept a result where unrelated inner flows share one outer
   connection.

Expected: one inner 4-tuple maps to one outer socket. Multiplexing unrelated
flows is a tunnel fingerprint and is not the design.

### X-07 Long-lived and half-closed flows

1. Open a TCP flow and keep it idle for 10 minutes.
2. Confirm it survives the source keepalive and the carrier NAT, or record the
   failure.
3. Open a TCP flow, send a request, and close the write side.
4. Confirm the response completes and the upload is not truncated.
5. Record whether the flow survived and which source platform produced the
   result. Do not claim reliability from one short run.

Expected: the target answers a keepalive probe with an ACK. An iOS source sets
keepalive at 60 seconds idle, 10 seconds interval, and 3 probes. An Android
source uses the platform system keepalive defaults; the app cannot set the iOS
values, so do not record 60/10/3 for Android. Record the Android value only if
the device exposes it, otherwise record "system default, not measured". A
carrier NAT can still drop an idle mapping. A source session with no application
traffic can close.

### X-08 Zero-window and paused reader

Advanced test. Run it only if the owner approved a paused-reader test on a test
destination. The app UI does not expose probe timing, so the timing part needs a
separately approved lab capture. Without that capture, record the timing as
inconclusive, not as a pass.

1. Open a TCP flow to a lab test destination and stop reading on one end.
2. Confirm from app behavior that the flow does not reset at once.
3. Record whether the flow later resets. Do not claim a probe interval or a
   probe count from the UI.
4. If, and only if, the owner separately approved a lab capture on that test
   destination, capture the zero-window probes and record whether they start at
   300 ms, back off, and reset after 12 unanswered probes. Keep the capture
   private, use no personal traffic, and delete it after the run.
5. Without the capture, write "probe timing inconclusive" in the record.

Expected: a peer that answers can hold a flow slot while its window stays
closed. The live paused-reader test is still open. Do not claim it passed
without this evidence, and do not derive timing from a normal flow.

### X-09 Capacity

This test is disruptive and resource-heavy. Run it only with owner approval and
only on a test source device.

1. Open flows until the source reaches its relay cap.
2. Confirm a new relay is refused when no safe slot is available.
3. Confirm the server does not evict a healthy open TCP relay only for silence.
4. Record the open-file limit and the computed cap.

Expected: the cap follows the open-file limit. When the limit permits, the
server allows 256 relays plus 32 setup sessions. A low limit gives fewer relays.
An unreadable or too low limit stops the start with `START_FAILED`.

## 9. Direct mode tests (D)

Approval: required for a tunnel start. Direct mode needs no source app. It does
change routes and create a tunnel device on the target.

The direct-mode cells are blocked for a physical pass in this build. The CLI
`tun` path prints no running counters, so it cannot produce the `ttl_bad`
evidence that D-02 requires. On macOS, a real direct start needs the signed,
installed helper and engine; an unsigned or ad hoc app fails closed. On Linux,
the Electron app has a direct mode control. Its engine client sends a `tun`
start with `ipv6: block` and names no interface, DNS server, host, or token. The
packaged app starts the engine through `pkexec` and the helper, and the status
and diagnostics path could show the audit. No test in this tree has shown that
control to start a real tunnel, and no polkit prompt or desktop session has been
tried. So the Linux app direct cells are also Blocked, for that reason and not
for a missing control. A development run that uses `--engine` starts the engine
directly and is development evidence only. Section 16.1 records the cells as
Blocked. A CLI flow test is useful development evidence, but it is not a pass.
A Linux app direct start is still a Linux start: the 5.3.1 gate and the claim
order apply, and the packaged app shows no recovery line.

A browser GUI started as root with `--token-fd` is a separate direct-mode path.
On Linux and macOS it can start direct mode through the same service, and its
diagnostics page can expose the running audit. No test in this tree has shown it.
It is not the signed macOS app and not the packaged Linux app. On Linux it is a
Linux start, so the 5.3.1 gate and the claim order apply. The page does not show
the `[route]` recovery line, but a terminal that launched the GUI can. Treat a
root GUI result as its own path; do not fill the macOS or Linux app cell from it
unless the owner approved that exact process and the cell allows that path.

Windows has a gated direct-mode lifecycle in the service, but no shipped path
can start it. The CLI `tun` path without `--phone` is rejected during option
parsing with "source device proxy mode requires --phone IPv4:PORT" before the
service. The service direct entry returns "Windows direct mode is disabled:
physical adapter pin and Wintun route evidence from a Windows VM and an
independent review are required" before it loads Wintun, creates an adapter, or
changes a route. A command-line GUI start refuses source device token use, and
the WinUI preview has no engine. Skip D-01 to D-06 on Windows and record the
gap. Do not use the WinUI preview or the gate refusal as direct-mode evidence.

On Linux, direct mode uses the same route claim and recovery path as source
device proxy mode. Run the inspection in 5.3.1 immediately before D-01, even
though direct mode has no token. An earlier-boot claim can be truncated and a
valid current-boot record can delete exact recorded objects before the TUN
device is created. The same owner approval and before-and-after record apply.

### D-01 Direct mode without a source app

1. Stop the source app. Keep the hotspot on.
2. Connect the target to the hotspot. Disable or disconnect every other
   network, and turn off Wi-Fi auto-join. If another network is active, stop:
   the run cannot show which network carried the traffic.
3. Start direct mode:

   ```sh
   BIN=/absolute/path/to/hotspotshade
   sudo "$BIN" tun
   ```

   Do not use `--no-pin` or `--no-routes` for a pass. They are diagnostic
   options.
4. Open a public test page.
5. Confirm the running direct tunnel. Use the GUI or app status, or the CLI
   running line.
6. Record the result.

Expected: direct mode works without a source app. The source device NAT is the
terminator.

### D-02 TTL audit

This test needs a running tunnel whose diagnostics are readable. The CLI `tun`
path prints one running line and no counters. A CLI `probe` before or after the
run measures a local UDP socket, not the running tunnel audit. Do not use it as
the `ttl_bad` value.

1. Start the direct tunnel from a path that exposes diagnostics: the signed
   macOS app through its helper, the packaged Linux app, or a root browser GUI
   with `--token-fd`. Record which one you used. The root browser GUI is its own
   path and has no live test; do not merge its result with an app cell.
2. While it runs, read the TTL audit counter in the app or GUI diagnostics.
3. Confirm `ttl_bad` is 0.
4. Record the TTL value and the mode and path that produced it.

If you only have the CLI, record D-02 as Blocked, not as pass. The non-root GUI
`socks5` start does expose diagnostics, but only for SOCKS outer sockets. It is
not direct-mode evidence.

Expected: every outer socket sets TTL 65 and reads it back. `ttl_bad` stays 0.
Do not claim the carrier saw 64. That is an expectation from one source NAT
decrement.

### D-03 DNS in direct mode

1. With the direct tunnel running, resolve a public test name.
2. Confirm the name resolves through the tunnel.
3. If the hotspot resolver blocks the query, retry with a documented
   `--dns-upstream` value. Record the change. This option belongs to direct mode
   only. Source device proxy mode rejects it, so X-03 must not use it.
4. Do not claim DoH or DoT is covered. They use their own paths.

Expected: inner UDP port 53 goes to the original destination or the configured
upstream over a normalized outer socket. The engine does not fall back to
`mDNSResponder`.

### D-03U Non-DNS UDP in direct mode

D-03 covers only inner UDP port 53. The relay handles other inner UDP as one
flow per inner 4-tuple with its own normalized outer socket to the original
destination, so it needs its own test. A DNS answer does not prove it.

1. With the direct tunnel running, send one UDP flow to a lab or public test
   destination on a port other than 53. Use a client that you control. Do not
   send it to the source proxy; direct mode has none.
2. Confirm that the reply arrives through the tunnel and from the destination
   that you sent to.
3. Send a second flow from a different local port and confirm that the target
   reports a second outer socket, not a shared one, when the build exposes the
   counters. Otherwise record the gap.
4. Read `ttl_bad` and confirm it is 0. If the build exposes no running audit,
   record D-03U as Blocked for the TTL part, as in D-02. A reply is not TTL
   evidence.
5. Record the result. Do not record the destination or the local ports.

Expected: inner UDP uses a normalized outer socket with TTL 65 and the pinned
interface. A public STUN server can rate-limit or ignore requests. One run is not
a throughput result. This test is separate from X-02D (`phone-udp-diag`), which
needs a source app and is not tunneled.

### D-04 IPv6 block, the default

A failed IPv6 connection proves nothing if the hotspot had no IPv6 path before
the tunnel. Record the baseline first.

1. Before the tunnel, confirm that the hotspot path carries IPv6. Use an IPv6
   connection to a public test destination, or check the selected route:
   - macOS: `route -n get -inet6 2606:4700:4700::1111` shows a real interface
     with `UP` and without `BLACKHOLE`;
   - Linux: `ip -6 route get 2606:4700:4700::1111` names the hotspot interface.

   If the baseline has no IPv6, record D-04 as inconclusive, not pass.
2. Start direct mode with the default policy. Do not pass `--ipv6 inherit`.
3. After the start, confirm the block:
   - macOS: the same `route -n get -inet6 2606:4700:4700::1111` shows the
     `BLACKHOLE` flag, has `UP`, and does not have `REJECT`. The engine rejects
     a `REJECT` route as a block. Also confirm that `netstat -rn -f inet6`
     shows no IPv6 default route that the run added;
   - Linux: `sudo ip -6 route show table 700` shows `blackhole 2000::/3 proto
     196`. The protocol id 196 is the project's route marker.
4. Compare the IPv6 table with the baseline.
5. Try one IPv6 test connection.
6. Confirm it fails or the documented block is in place.
7. Record the baseline, the route state, and the result.

Expected: direct mode blocks IPv6 by default. The blackhole is not fail-closed.
More-specific routes can bypass it. Loopback and link-local traffic is not
touched. Without the baseline, the result is inconclusive.

### D-05 IPv6 forward, explicit

1. Start direct mode with `--ipv6 forward` only if the owner approved the
   explicit forward policy.
2. Open an IPv6 test destination.
3. Record the result.
4. Stop the tunnel and restore the default policy.

Expected: `forward` is an explicit choice. It is not the default. Do not use
`--ipv6 inherit` for a pass. It is a documented leak path.

### D-06 SOCKS5 mode, no root

1. On macOS or Linux, start the local adapter with the same absolute path.

   On macOS, the adapter discovers the resolver for the selected interface. The
   discovery must be unambiguous, or the start fails:

   ```sh
   BIN=/absolute/path/to/hotspotshade
   "$BIN" socks5 --port 1080 --iface <hotspot-interface>
   ```

   On Linux, the system resolver file is one aggregate list and does not prove
   which link a server belongs to. The start fails closed unless you pass an
   explicit, numeric, non-loopback list:

   ```sh
   BIN=/absolute/path/to/hotspotshade
   "$BIN" socks5 --port 1080 --iface <hotspot-interface> \
     --dns-servers <non-loopback-ip>
   ```

   Without `--dns-servers`, the Linux start returns "the Linux system resolver
   list is not tied to one interface; pass an explicit DNS server". A loopback
   server is refused. Do not use a public resolver just because the start
   demands one; use a resolver the owner approved for that link. Windows has no
   `socks5` command in this build. Record the gap.

2. Use `socks5h` so the adapter resolves names:

   ```sh
   curl --proxy socks5h://127.0.0.1:1080 https://example.com/
   ```

3. Confirm the request works and that the adapter resolved the name remotely.
   Record the result separately from X-03S and X-03.
4. Stop the adapter with Ctrl-C.

Expected: SOCKS5 mode needs no root and creates no route. It binds
`127.0.0.1` only. A client that resolves names locally leaks DNS. The adapter's
resolver test is X-03S; it is not tunneled evidence and not X-03.

## 10. Automatic stops and cleanup (A)

Approval: required. These tests cut the connection. Do not run them on a device
that someone is using.

Before any automatic-stop test, record every startup warning from section 8.
The CLI prints warnings on stderr, and the GUI and app expose service warnings in
their logs. If a warning says the hotspot auto-stop is off, or that a silent
source device will not stop the tunnel, record the related A test as Blocked.
Do not start the stop test and do not record the warning as a stop reason.

On Linux, the start for any A test is still a start. Run the inspection in
5.3.1 immediately before it. The recovery path can delete exact recorded objects
before authentication.

On Windows, the current build refuses source device token use, so no Windows
source-proxy tunnel exists to stop. Record A-01 to A-09 as Blocked on Windows.
The A-02 note describes future link behavior only; it is not a current result.

### A-01 User stop

1. Start a tunnel. Record every startup warning and the path that owns the
   tunnel.
2. Stop it with the app Stop control, Ctrl-C, or SIGTERM. Do not use `kill -9`.
3. For a GUI or app start, record the `last_stop` reason and message if the path
   shows them. Do not assume the reason is `user`; record what it shows. For a
   CLI start, do not expect `last_stop=user`: the CLI has no status page, and the
   service records only automatic stop reasons. Confirm the process exits, no
   automatic-stop message appears, and the stop is not reported as
   `hotspot_lost` or `source_device_gone`.
4. Confirm the tunnel does not restart.
5. Run the cleanup checks in A-09.

Expected: a user stop is graceful and idempotent. It attempts to remove the
resources that the process created. A cleanup failure leaves state behind and
reports a failed stop, often with "Tunnel cleanup did not finish. Inspect routes,
devices, and the start record before restarting." A failed stop is not a pass.
Only a path that records a user stop can report `last_stop=user`; a manual CLI
stop cannot.

### A-02 Hotspot loss

1. Before the start, disable or disconnect every other network on the target
   and turn off Wi-Fi auto-join. Record the baseline network list.
2. Start a tunnel on a test target. Record every startup warning. If the warning
   says hotspot auto-stop is off, record A-02 as Blocked.
3. Turn off the hotspot, or move the target out of range.
4. Keep it down for the full 20 seconds. While it is down, confirm the target
   did not join another network. If it did, or you cannot tell, record A-02 as
   inconclusive: the link check can see an up interface, but not which network
   the interface is on.
5. Confirm the target stops the tunnel.
6. Confirm `last_stop.reason` is `hotspot_lost`. The GUI and app show "The
   hotspot turned off, so HotspotShade turned the tunnel off." The CLI prints
   "The hotspot turned off, so HotspotShade stopped the tunnel."
7. Wait 2 minutes and confirm the tunnel does not restart.
8. Run the platform cleanup checks in A-09. On macOS, check the `/1` routes, the
   `utun`, and the `2000::/3` blackhole. On Linux, check table 700, both rule
   priorities, the link address, the `hs-tun*` device, and the claim. Windows
   A-02 is Blocked, so it has no cleanup result.
9. Turn the hotspot back on and start the tunnel manually.

If the hotspot returns before 20 seconds, the timer resets and the tunnel stays
up. That is expected. It is not a failure and not a stop. Do not shorten the
window.

Expected on macOS, Linux, and the GUI: a link that is down for 20 continuous
seconds stops the tunnel. The stop uses the graceful path and tries to remove
routes, the IPv6 address, and the tunnel device. A cleanup failure can leave
them and reports a failed stop. Run A-09 for that platform; a stop message alone
is not cleanup evidence.

Windows note: the current build refuses source device token use, so it cannot
start a Windows source-proxy tunnel. A-02 is Blocked on Windows, and A-03 is
Blocked too because there is no running tunnel to observe. Do not claim a
Windows hotspot-loss or source-silence stop. The gated direct service lifecycle
has a retained-link observer, but no shipped path can start it, so it is not a
current stop result either. If a future build enables token use, the Windows
command-line GUI treats the link as unobservable and never reports hotspot loss,
but it still accumulates fresh source device silence and can stop after 90
seconds. That future behavior is not present in this build.

### A-03 Source device gone

1. Start a source device proxy tunnel. Record every startup warning. If the
   warning says a silent source device will not stop the tunnel, record A-03 as
   Blocked.
2. Force-quit or force-stop only the source app. Keep the hotspot on and the
   target connected. On Android, use Force stop in Settings, not the app Stop
   control: a clean stop answers `proxy_off`, which counts as an answer. On
   iOS, use the app switcher to force-quit.
3. Wait 90 seconds without a good sample. If the probe reports one of the
   unverified plaintext states (`checking`, `unpaired`, or `not_trusted`), the
   policy first waits a 120 second grace, then applies the 90 second silence
   limit, so keep the state continuous for about 210 seconds. Do not shorten
   either interval.
4. Confirm the target stops the tunnel.
5. Confirm `last_stop.reason` is `source_device_gone`. The GUI and app show "The
   source device stopped answering, so HotspotShade turned the tunnel off." The
   CLI prints "The source device stopped answering, so HotspotShade stopped the
   tunnel."
6. Wait 2 minutes and confirm the tunnel does not restart.
7. Restore the source app and start the tunnel manually.

Do not turn off the phone or move it out of range for this test. That also
removes the hotspot link and tests A-02 instead. Do not count a single silent
sample as a stop.

If the source app answers again before 90 seconds, the timer resets and the
tunnel stays up. That is expected.

Expected: `not_running` and `not_responding` count as silence. `proxy_off`,
`ready`, and `connected` count as an answer and reset the timer. `checking`,
`unpaired`, and `not_trusted` are unverified plaintext answers: they do not
reset an existing silence interval, and they start one only after the 120 second
grace. A continuous run of them can stop the tunnel after about 120 plus 90
seconds. `pin_unknown` is a local failure to pin the probe; it is not an answer
from the source device, it is not evidence of loss, and it resets both timers.
`no_hotspot` is link down on an observable link. On the Windows GUI, where the
link is unobservable, `no_hotspot` resets both timers. A stale or missing probe
breaks continuous silence. One good sample resets the timer. The stop uses the
graceful path.

The CLI probe has only answered, silent, and unavailable. A rejected token
counts as answered. The unverified states come from the GUI or engine probe, so
record which path produced the state. Do not apply a GUI-only state to a CLI
run.

### A-04 Source app in the background

1. Start a source device proxy tunnel.
2. Put the source app in the background, or lock the phone, in the way the
   platform allows.
3. Record what happens for 2 minutes.
4. Confirm whether the tunnel stays up or stops with the documented reason.
5. Do not claim sustained background relay.

Expected: the source app stops its proxy when the hotspot is gone. On iOS, the
documented wait is 20 seconds of observed absence. On Android, the documented
wait is three consecutive uncertain checks at 2 seconds, about 6 seconds, and a
bound address that belongs to a reported network interface stops the run at
once. On Android 16 or later, a pending tethering reading is not a loss. If the
finder keeps reporting pending, the fourth consecutive pending probe at
2-second spacing is the first uncertain miss, about 8 seconds after the watch
starts, and a loss follows about 12 seconds after the watch starts. The
evidence's own pending timeout is 3 seconds, so the ordinary rules usually
decide earlier. Do not record a loss before the applicable bound. The target may
report source silence after 90 seconds. Short background tests do not establish
reliability after screen lock or extended use.

In the current Android build, background authenticated status is disabled by
`SourceProxyServiceLifecycle.BACKGROUND_STATUS_ENABLED = false`. The host now
uses a status-only responder and fences one run and one token epoch, but those
rules are covered by JVM and loopback tests only. The service owner review and a
real-device background test are still open. The earlier rationale that the host
could return the captured token without a prompt or had no run or token epoch
fence is no longer current. The gate stays off; do not enable it for a test.
When the activity stops its foreground pairing listener, a target can report
the source as unavailable and stop after sustained silence even if the proxy
service is still running. Record the observed listener and tunnel states
separately; do not count this as proof of sustained background presence or
relay.

### A-05 Source hotspot address loss

1. While the proxy runs, turn off the hotspot, or change the interface so the
   bound hotspot address disappears.
2. Confirm the source app stops its proxy. On iOS, the documented wait is 20
   seconds. On Android, the documented wait is about 6 seconds, or at once when
   the bound address belongs to a reported network interface. On Android 16 or
   later, a pending tethering reading can hold the decision for about 8 seconds
   before the first uncertain miss and about 12 seconds before a loss. Do not
   shorten those windows.
3. Confirm the source app does not restart the proxy.
4. Restore the hotspot and start the proxy manually.

Expected: the source app reports the plain stop reason. It never starts itself
again. Do not apply the iOS 20-second value to Android.

### A-06 Pairing listener stop

1. Keep the source app open with the hotspot on and the proxy stopped.
2. Turn off the hotspot.
3. On iOS, confirm the pairing listener stops after 15 missed checks. The
   interval is 5 seconds while the proxy is stopped, so the documented wait is
   75 seconds.
4. On iOS, repeat with the proxy running. The interval is 2 seconds, so the
   documented wait is 30 seconds.
5. On Android, background the app or open another activity so the app is not
   visible. Confirm the listener stops on `onStop` and does not run in the
   background. Do not apply the iOS 75/30-second values to Android.
6. Restore the hotspot and the app. Confirm iOS re-arms the listener when it
   returns to the foreground. On Android, confirm the listener runs again while
   the activity is visible, or record what happened.

Expected: the pairing listener binds the hotspot address and port 18090 only. It
does not run in the background on Android. iOS can suspend it without an error.

### A-07 Target app or GUI close

This test needs the app or GUI process that owns the tunnel. A CLI tunnel has
no app to close. Record A-07 as Blocked for a CLI tunnel, and for an unsigned or
ad hoc macOS app that fails closed before real mode.

1. Start a tunnel.
2. Quit the target app, or stop the GUI process with Ctrl-C or its quit action.
   Closing a browser tab is not a quit. The service and the tunnel keep running
   if the process that owns them remains.
3. Confirm the engine stops and the tunnel turns off.
4. Confirm no privileged engine process remains. The app process may remain.
5. Run the cleanup checks in A-09.

Expected: the desktop app sends a stop and waits. The macOS app can take about a
minute. The Linux app waits up to 65 seconds for the helper; the helper sends
SIGTERM, waits 45 seconds, and never sends SIGKILL. A cleanup failure can leave
routes, rules, addresses, a device, or a start record, and the stop is reported
as failed. A forced stop can skip cleanup and is a stop condition for this
procedure.

If the Linux engine does not stop, the current helper reports a timeout and
stays alive holding its lock while it retries a graceful stop. That helper can
block a later start. Do not kill it or start another engine to clear the block;
stop the test and ask the maintainer to inspect the engine and routes.

On an unsigned or ad hoc macOS app, real mode is blocked before this test. Run
it only in demo mode for the UI, or use the CLI for the tunnel.

### A-08 Crash and cleanup block

Do not create a crash on purpose. If one happens:

1. Do not use `kill -9` to make it worse.
2. Inspect routes, rules, devices, the claim, and any durable marker before a
   new start.
3. Do not restart the app or engine as a way to clear a block. On Linux and
   Windows the in-process flag is not durable, so a new process starts with it
   false and hides the warning without checking the host. On macOS the helper
   writes a durable `cleanup-blocked` marker, and `engine-session`,
   `install-journal.json`, or `service-journal.json` can also refuse a start. A
   direct CLI or GUI engine writes the same `engine-session` record. A helper
   restart re-reads the marker and does not clear it.
4. If you cannot match an object to the test record, do not delete it. Report it
   to the owner.

Linux:

- The Linux claim, recovery, and `tun --phone` destination proof are
  working-tree changes. They are not committed, settled, or independently
  reviewed. Do not begin a physical test until this page is reconciled with the
  reviewed build and the recorded revision contains the exact change under test.
- A crash that closes the TUN descriptor removes the device, the address, and
  the device-bound routes. The four policy rules are not bound to the device and
  can survive. In block mode the `2000::/3` blackhole in table 700 can also
  survive.
- A build that contains the recovery change writes a private claim at
  `/run/hotspotshade/route-claim` before the first add and removes it after the
  last proven delete. The current format is version 3. The current record names
  the kernel boot, network namespace, writer pid, tunnel name and index, outer
  interface, and IPv6 policy. Up to four `prior` records each name another
  tunnel name and index, outer interface, and IPv6 policy. A version 2 record
  without predecessor lines is still read; version 1 is refused. The next start
  captures read-only physical outer evidence, then takes the claim's exclusive
  lock before it changes anything. It proves the live outer pin after the claim.
  A held lock is a live owner and the start refuses. A valid current-boot record
  with no live lock can be adopted, and the start can delete the exact recorded
  routes and rules for the current record and every predecessor without a
  prompt, before the source device token and gateway checks. The first complete
  recovery read is all or nothing: if it is inconclusive, no object is deleted
  and the start refuses with `route_setup`. Once deletion begins it is
  incremental. A later read or delete failure can leave part of the recorded set
  removed, and the claim stays as the record. This is a host change, not a
  status message.
- `stat` and the `route_claim` status cannot enumerate the current record, its
  predecessors, or the exact rules and routes that recovery can delete. No
  reviewed read-only selector dump exists in this tree, so a present claim is a
  hard block for every start. `inspect_route_claim` reads fields but does not
  derive selectors. A future dump must decode the current `tun`, `outer`, and
  `ipv6` lines and every `prior` line, and derive every selector from that
  build's constants. The owner must approve every selector. If the set is
  unreadable, unreviewed, or not approved, stop. Do not treat a `stat`, a file
  size, or a `route_claim` status as the set.
- The claim records the kernel boot identity and network namespace device and
  inode in the current record. An earlier-boot claim is truncated without
  deleting kernel routes or rules, but the start still truncates the claim file
  before authentication and can be quiet in an app launch. The boot check comes
  before the namespace check. A current-boot claim from another namespace is left
  in place and causes refusal. An empty or missing claim is treated as no
  record, and the start creates the file if it is missing. The start then reads
  table 700 and the reserved priorities and normally refuses with `route_setup`
  if an object remains, and a refused start unlinks the empty claim. That read is
  a snapshot, and a dump can omit an entry without reporting interruption. A
  start can therefore pass it, reach the token check, create the TUN device, and
  add the address, and only then refuse at the route install. Do not describe an
  empty or missing claim with leftover objects as a safe refusal. Do not use a
  start as a read-only check.
- After a successful recovery, the recovered record stays in the claim file. The
  start clears it or writes its own record only if the later table 700 and
  priority read shows those keys free. If that read refuses, the recovered record
  stays for the next start, which adopts it again. That is different from an
  empty claim, which the route manager removes on release. Do not describe the
  recovered record as cleared by recovery alone.
- The engine prints `[route]` lines to stderr for an earlier-boot discard and
  for a kept recovered claim. A CLI run in a terminal shows them. A root browser
  GUI started from a terminal can show them in that terminal's stderr, but the
  page does not. The packaged helper sends the engine's stderr to null, and the
  development Electron client reads and discards stderr. The read-only
  `route_claim` status is not a recovery-event record and does not prove what a
  start removed. A start from an app path with a claim present can therefore
  delete host objects silently. No reviewed selector dump exists in this tree,
  so a present claim is Blocked. Do not start. Record the four `ip` reads and the
  claim `stat` for the report, but do not treat them as the selector set.
- Recovery can run before the source device token and gateway checks. The start
  has already captured the early read-only physical outer evidence, but that
  capture changes nothing and says nothing about the claim. A start that later
  fails either check may already have deleted recorded routes and rules. Do not
  use an expected authentication failure as a safe recovery probe.
- If a live process holds the claim lock, the start fails. Do not delete the
  claim file to force a start. A damaged, foreign-namespace, or unreadable claim
  also refuses. `clear_corrupt_route_claim` and `Service::clear_route_claim`
  remove only an empty file or a valid earlier-boot record. They refuse a valid
  current-boot record even when its owner or mode is wrong, a current-boot
  record from another namespace, and a non-empty damaged or unparsable file.
  Neither is reachable from any shipped CLI command, engine API route, browser
  GUI control, or Linux desktop app action. The safe clear is an inaccessible
  foundation today. The linked
  [LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md) describes it but is another
  writer's scope and is not approved by this page. Do not delete the claim by
  hand.
- A build without the claim code keeps the older behavior: a start refuses while
  an object remains, and there is no automatic recovery from that build.
- Recovery is covered by hermetic tests in `rust/src/platform_linux.rs`. It has
  not been independently verified, and this procedure does not verify it on a
  live host.
- Do not claim that recovery guarantees cleanup. The claim is a record that this
  project wrote, not a kernel attestation. A privileged process can create the
  same file and the same objects, and a pre-claim build leaves objects with no
  claim. The cleanup check and the delete are not atomic. Do not describe the
  claim as ownership proof.
- Read [LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md) for context only.
  Inspect the claim and the recorded ownership first:

  ```sh
  sudo ip -4 rule show
  sudo ip -6 rule show
  sudo ip -4 route show table 700
  sudo ip -6 route show table 700
  sudo stat -c '%a %U %G %F %n' /run/hotspotshade
  sudo stat -c '%a %U %G %h %F %s %n' /run/hotspotshade/route-claim
  sudo test ! -L /run/hotspotshade
  sudo test ! -L /run/hotspotshade/route-claim
  ```

  A symlink, a non-regular claim, or a claim link count other than 1 is not a
  clean result. These commands do not show the claim header or the current and
  predecessor selectors. No reviewed selector dump exists in this tree. Do not
  substitute a hand read for the dump.

  Do not edit the claim. Do not flush table 700. This procedure has no approved
  Linux manual delete. A rule delete with missing selectors can match a foreign
  rule. A route delete can match a foreign route. Do not invent a command. If a
  stale object must be removed, stop and ask the maintainer for a command proven
  against this host and record. Linux gives a route or rule no creator identity.
  An absent claim file is the expected clean result. The `/run/hotspotshade`
  directory can remain after a clean stop, because only the file is removed. A
  successful `stat` on the directory is normal. A zero-length claim is an
  incomplete file from a crash between creation and write. The engine treats it
  as no record, but objects can still remain, so inspect them. An earlier-boot
  claim is also not a clean result for a physical test, even though a start
  discards it without a kernel change. An unreadable or damaged claim is not a
  clean result. If the claim is missing while objects remain, damaged,
  ambiguous, or names a live device, stop and ask the owner. A run from a build
  without the claim code has no claim for its objects. Do not paste route or
  rule output with personal destinations into a shared record.
- A status poll can make a start refuse. The Linux status answer takes the claim
  lock for a moment to fill `route_claim`. A start in another process that
  arrives at that moment sees a held lock and refuses with `route_setup`, as if a
  live owner held the claim. Do not read that refusal as proof of a live owner,
  and do not delete the claim. Repeat the reads in 5.3.1 with no poller running.

macOS:

- The two IPv4 `/1` routes point at the `utun` interface. Closing the device
  normally removes them. The IPv6 `2000::/3` blackhole uses gateway `::1` and is
  not device-bound, so it can survive a crash.
- A crash can leave that blackhole in place. It is not fail-safe: it can block
  IPv6 from unrelated processes until it is found and removed. macOS has no
  route claim and no automatic route recovery. The working-tree protected
  helper records a durable cleanup marker at
  `/var/db/hotspotshade/cleanup-blocked` and a launch intent at `engine-session`.
  A direct CLI or GUI engine writes the same `engine-session` record before it
  opens a utun and reports an uncertain cleanup as an error. The helper and the
  direct engine refuse a start while `install-journal.json` or
  `service-journal.json` is present. The marker survives a helper restart, and
  no helper path clears it. The current lock files are still changing: the
  helper and engine use `start-exclusion`, the installer uses `start.lock` and
  holds `start.lock`, `start-exclusion`, and `upgrade.lock` as a transition set,
  and the helper no longer writes `start-journal` while the installer still
  reads it. Old binaries take no lock at all. That marker is not proof of route
  ownership or cleanup, and the helper changes still need final review and a
  signed live test. A stale blackhole makes every later route add fail with
  `route_setup`, in both block and forward mode, because the route add returns
  "exists".
- Inspect it read-only before any delete:

  ```sh
  netstat -rn -f inet6
  route -n get -inet6 2000::
  ```

  Compare with the baseline from section 5.2. Use `netstat` to inspect the
  actual `2000::/3` prefix (destination `2000::`, mask `e000::`), its gateway
  `::1`, and its blackhole flag, shown as `B`. The `route get` command looks up
  the single destination `2000::`; it reports the longest matching route and
  does not prove that the `2000::/3` entry exists. It can show `BLACKHOLE` for
  the selected host lookup.
- This procedure has no approved manual macOS route delete. A route delete can
  match more than the route described by its gateway and flags, and a read and
  a delete are not atomic. Stop and ask the maintainer to inspect the recorded
  baseline, current routes, running engines, VPNs, and network extensions.
  Do not delete a `/1` or `2000::/3` route based on its prefix alone.
- A timed-out stop, a non-zero or signaled engine exit, an engine exit without a
  stop request, a failed journal clear, or a direct-engine cleanup that cannot
  prove route and device removal also sets the durable cleanup marker or leaves
  `engine-session`. Inspect the host and the state directory and files for the
  owner, mode, set-id bit, and extended ACL as in 5.2. Do not delete or edit
  `cleanup-blocked`, `engine-session`, `install-journal.json`,
  `service-journal.json`, or a lock file. The helper README recovery is an
  inspection and containment procedure for the helper engine path and does not
  approve a manual delete. It says a reviewed recovery for direct and helper
  engines is still required. Stop and escalate. Do not remove state to make a
  start pass.

Windows:

- A cleanup failure sets `cleanup_blocked`. The flag is in the running service
  process, so a new process does not remember it. No durable cleanup marker
  exists on Windows in this build.
- Inspect the adapter and route table before a new start. Match the adapter name
  `HotspotShade-Tunnel*`.
- Do not delete a route on an adapter you cannot prove. Report the failure and
  let the owner inspect it.

Expected: the cleanup code refuses a delete when its checks observe an
ambiguous object. The checks and delete are separate operations, and a dump can
omit an object; they cannot guarantee that another process's object is never
deleted. A failed or inconclusive cleanup can leave routes, rules, an address,
a device, or a durable start record behind, and the stop is reported as failed.
The process closes its own device so the operating system can remove
device-bound routes. Device cleanup does not remove device-independent routes.

### A-09 Cleanup checks

Run these after every stop, not only after A-01.

macOS:

```sh
route -n get default
netstat -rn -f inet
netstat -rn -f inet6
ifconfig
pgrep -fl hotspotshade
sudo lsof -nP -iTCP -sTCP:LISTEN
sudo stat -f '%Sp %Su %l %N' \
  /var/db/hotspotshade \
  /var/db/hotspotshade/cleanup-blocked \
  /var/db/hotspotshade/engine-session \
  /var/db/hotspotshade/install-journal.json \
  /var/db/hotspotshade/service-journal.json \
  /var/db/hotspotshade/start-journal \
  /var/db/hotspotshade/start-exclusion \
  /var/db/hotspotshade/start.lock \
  /var/db/hotspotshade/upgrade.lock
sudo ls -lde /var/db/hotspotshade
for name in cleanup-blocked engine-session install-journal.json \
  service-journal.json start-journal start-exclusion start.lock upgrade.lock; do
  if sudo test -e "/var/db/hotspotshade/$name"; then
    sudo ls -lde "/var/db/hotspotshade/$name"
  fi
done
```

Expected: the default route matches the baseline. No `/1` route points at a
HotspotShade tunnel. No new `utun` remains. No new `2000::/3` blackhole remains.
Compare the IPv6 route table with the baseline. No root engine process remains.
A GUI listener on `127.0.0.1` may remain while the app is open. A non-root
`lsof` does not prove that a root listener is absent. If cleanup failed,
`/var/db/hotspotshade/cleanup-blocked` or `engine-session` can remain, and
`install-journal.json` or `service-journal.json` can also be present. The state
directory, the refusal records, and the lock files must still pass the owner,
mode, set-id, and ACL checks in 5.2. Do not delete them; follow A-08 and stop.

Linux:

```sh
ip -4 rule show
ip -6 rule show
sudo ip -4 route show table 700
sudo ip -6 route show table 700
ip link show type tun
ip addr show
sudo stat -c '%a %U %G %F %n' /run/hotspotshade
sudo stat -c '%a %U %G %h %F %s %n' /run/hotspotshade/route-claim
sudo test ! -L /run/hotspotshade
sudo test ! -L /run/hotspotshade/route-claim
sudo lsof -nP -iTCP -sTCP:LISTEN
```

Expected: no rule at priority 17000 or 17001, no route in table 700, no
`hs-tun*` device, no `198.18.0.1` link address left by the test, and no
`/run/hotspotshade/route-claim` file. The
`/run/hotspotshade` directory can remain after a clean stop and is not by itself
a leftover. A successful `stat` on the directory is normal. If the directory or
the claim file exists, each must be a real directory or regular file, not a
symlink, and must be owned by the engine account. The claim must have exactly
one link, and neither object may grant permission to group or other. A
zero-length claim after a clean stop is unexpected; record it and inspect before
any new start. A present claim after a failed cleanup is the record for the next
start; `stat` does not enumerate its selectors, and this check does not approve a
recovery. A GUI listener on `127.0.0.1` may remain while the app is open.
Compare with the baseline. An absent directory or claim file is expected; stop
on any other `stat` error, a symlink, a non-regular object, or a claim link count
other than 1.

Windows:

```powershell
Get-NetAdapter | Where-Object Name -like 'HotspotShade-Tunnel*'
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix
Get-NetRoute -AddressFamily IPv6 | Sort-Object DestinationPrefix
Get-NetTCPConnection -State Listen
```

Expected: no `HotspotShade-Tunnel*` adapter, no `/1` route to it, no
`2000::/3` route to it, and no tunnel listener. A GUI listener on `127.0.0.1`
may remain while the app is open. Compare with the baseline.

Source device:

- the app shows Off, or the documented stopped state;
- the proxy notification is gone;
- the pairing listener is off when the hotspot is gone;
- the app did not restart the proxy.

## 11. Failure and recovery (F)

Approval: required for each live failure test. These tests can interrupt a
connection.

### F-01 Source device states

This sequence applies only to a supported path after its gates open. The
current Windows command-line GUI refuses the check with
`source_proxy_unavailable`; do not record `not_running` for that refusal.

Use the target's status-probe path for these observations. Pairing has a
separate state machine and is not a substitute for a probe result.

1. With the source app closed, run a status probe and record the state actually
   returned. A connection refusal maps to `not_running`; other connection
   errors map to `not_responding`. Closing the app does not guarantee either
   network result.
2. With the hotspot off, record `no_hotspot`.
3. With the app open but no pair, record `unpaired`.
4. With the source trust removed, record `not_trusted`.
5. With the proxy stopped, record `proxy_off`.
6. With the proxy running, record `ready` or `connected`.
7. With the app open but not answering, record `not_responding` or `checking`.
8. Record the exact fixed message for each state.

Expected: the state text is fixed and holds no credentials. A TCP connection
alone does not set `ready` or `connected`. A timeout is not proof that the app
is off. If the network cannot establish the condition needed for a state,
record that observation as inconclusive. The rotation token-rejection case belongs to P-08, which is Blocked for
the current iOS build.

### F-02 Identity key permissions

1. Inspect the directory and the file for the account that the engine runs as.
2. If the key is rejected, do not overwrite or delete it. On Unix, remove every
   group and other permission bit. The engine accepts any owner-only mode, not
   only `0700` and `0600`; a stricter mode is fine. On Windows, fix the ACL. A
   file with the wrong owner is not fixed by `chmod`: a root-owned file in a user
   path needs a `chown` as root, which needs owner approval.
3. Restart the target app and try pairing again.
4. If the key is lost, the source treats the target as unknown. Pair again and
   remove the old key on the source.

Expected: the service checks the directory and the file. It refuses a directory
that has a group or other bit, a file with the wrong length, another owner, a
non-regular file, or group or other permissions. It does not require exactly
`0700` and `0600`. It never logs the key.

### F-03 Cleanup block

1. If a cleanup failure sets a cleanup block, do not start a new tunnel.
2. Inspect routes, devices, the claim, listeners, and the macOS durable state
   files.
3. On Linux and Windows the in-process flag is not durable. Restarting the app
   or engine clears the flag, not the leftover objects. On macOS the helper
   writes `/var/db/hotspotshade/cleanup-blocked`, and `engine-session`,
   `install-journal.json`, or `service-journal.json` can also refuse a start. A
   direct CLI or GUI engine writes the same `engine-session` record. A helper
   restart re-reads the marker and refuses again. Do not restart to clear it.
4. Remove only objects that match the test record and the documented ownership
   rules. Follow A-08.
5. If the object is ambiguous, stop and ask the owner.
6. After the host is clean, restart the app or engine so a non-durable
   process-local block is gone. On macOS, do not delete `cleanup-blocked`,
   `engine-session`, `install-journal.json`, `service-journal.json`, or a lock
   file. The helper README recovery is written for the helper engine path and
   says a reviewed recovery for direct and helper engines is still required.
   Stop and escalate. On Linux, do not start while a claim record is present;
   follow A-08 first.

On Linux, do not use a start as a cleanup step. A start captures read-only
physical outer evidence, then takes the claim. A build with the claim code can
adopt a valid current-boot claim record, including every predecessor, and delete
the recorded routes and rules before authentication, but only when every A-08
condition holds and the owner approved a reviewed selector dump for all of them.
No reviewed selector dump exists in this tree, so a present claim is Blocked.
The first complete recovery read is all or nothing: if it is inconclusive, no
object is deleted and the start refuses with `route_setup`. Once deletion begins
it is incremental. A later read or delete failure can leave partial cleanup and
keeps the claim as the record. An earlier-boot claim is truncated by the start
without a kernel change, which is still a host write. An empty or missing claim
with leftover objects normally refuses with `route_setup` and then unlinks the
empty claim, but the refusing read is a snapshot, so a start can pass it, use the
token, and create the TUN device and address before the install read refuses. A
recovered record that the later read did not confirm stays in the claim file for
the next start. A damaged, foreign-namespace, or unreadable claim blocks every
start. The safe clear removes only an empty file or a valid earlier-boot record
and refuses the rest, and it is not reachable from any shipped interface. Only
start after the 5.3.1 inspection and the owner's approval. On macOS, a stale
blackhole makes the start fail with `route_setup`; stop and ask the maintainer
to inspect it as described in A-08. On Windows, inspect the adapter and the
route table before a new start.

Expected: a cleanup block refuses a new start. It does not delete an object
that may belong to another process. On Linux and Windows a restart clears only
the in-process flag, not the leftover objects. On macOS the durable marker
survives a helper restart and no helper path clears it. A Linux start with a
valid claim record can be a deletion, so it is not a safe way to clear a block.

### F-04 Target app restart

1. Start a tunnel.
2. Quit and reopen the target app.
3. Confirm the pairing state and the tunnel state.
4. Pair again if the credentials were in process memory only.
5. Confirm the tunnel does not restart by itself.

Expected: a restart is a new process. It does not restore a tunnel that the
person did not start. The service also loses paired credentials.

### F-05 Source app restart

1. Start a source device proxy tunnel.
2. Force-quit or force-stop and reopen the source app, as in A-03.
3. Confirm the target reports source silence or the documented state.
4. Confirm the tunnel stops after the documented silence window.
5. Start the tunnel manually.

Expected: nothing restarts the tunnel. The person starts it again.

### F-06 Weak link and recovery

1. Start a tunnel on a test target.
2. Move the target away from the source, or add a controlled weak-link condition
   that the owner approved.
3. Observe flows and diagnostics for 2 minutes.
4. Move back and confirm whether the flow recovers or the tunnel stops.
5. Record the observed result. Do not claim reliability from one run.

Expected: a slow connect does not use up the exchange budget. A busy hotspot
can delay a write without breaking the flow. A carrier NAT can drop an idle
mapping. The tunnel never restarts by itself.

### F-07 Hotspot subnet change

1. On iOS, record the observed hotspot interface name, type, IPv4 address,
   netmask, and flags. The current discovery policy requires one up, non-loopback
   bridge with `172.20.10.1/28`; it does not require a particular name.
2. Confirm the app binds the discovered address. If discovery or binding fails,
   record the observed values and the failure. Toggle Personal Hotspot off and
   on during the separately approved live test and record the listener state.
3. Do not use the Debug override on a physical device. It is for the Simulator
   and the host harness only.

These observations test a compatibility assumption. A bridge type and address
do not authenticate Personal Hotspot or prove interface continuity.

Expected: the iOS app fails closed when it cannot bind the expected hotspot
address. A different iOS version or hotspot configuration can change it. The app
does not support those configurations.

### F-08 Upgrade and rollback

1. Record the current version, stored trust, and token state.
2. Install the newer build with the same bundle identifier or application id.
3. Confirm whether trust and token survive.
4. If the owner wants a rollback, install the older build.
5. On Android, expect an uninstall if the signing key changed, and the loss of
   the Keystore token and trust list.
6. On iOS, expect the free profile expiry and a possible reinstall.
7. Record the result.

Expected: a same-identifier, same-key upgrade can keep stored trust and token. A
changed identifier or signing key is not a clean upgrade. No platform has an
automatic update or rollback tool.

## 12. Security checks (S)

Approval: required for a live tunnel. The read-only checks can run before a
tunnel.

### S-01 Listener binding

1. With the GUI and the tunnel running, list listeners with root visibility when
   the engine may be root:
   - macOS or Linux: `sudo lsof -nP -iTCP -sTCP:LISTEN`
   - Linux without `lsof`: `sudo ss -ltnp`
   - Windows: an elevated `Get-NetTCPConnection -State Listen` only with owner
     approval

   The command lists every listening socket that the account can see, not only
   HotspotShade sockets. Identify the process by name and user. A non-root run
   can miss a socket that a root-owned process holds.
2. Distinguish the cases:
   - direct mode: the target has no listener for the tunnel; only the GUI or a
     SOCKS adapter can listen, and only on `127.0.0.1`;
   - source device proxy mode: the target has no tunnel listener; it makes
     outbound connections to the source proxy;
   - SOCKS5 mode: the adapter listens on `127.0.0.1` only;
   - GUI: it listens on `127.0.0.1` only.
3. Confirm that no target listener appears on `0.0.0.0` or a public address.
4. Check the source device listener on the source device itself. It must bind
   its hotspot address only. The pairing listener uses TCP 18090 on that
   address. A target `lsof` cannot prove the source binding. Use an approved,
   supported source-device inspection method if one is available. If the iOS
   or Android device does not expose such evidence, record the source-binding
   check as Blocked; do not infer a pass from target-side sockets.

Expected: target listeners are loopback only. Source listeners are hotspot
only. A non-root `lsof` can miss a root-owned socket. Do not report "no
listener" from a non-root run.

### S-02 No token in status, diagnostics, or failures

1. Open the target app or the local page.
2. Use Copy diagnostics and open Recent failures.
3. Inspect the text locally for a token, password, pairing code, identity key,
   or private key.
4. Do not paste the text into a chat.
5. If a secret appears, stop and report privately to the owner.

Expected: status, diagnostics, and failure records hold no token and no key.
The failure record can hold example destination names and addresses. That is a
privacy issue, not a credential issue. Redact it before sharing.

### S-03 Browser never receives the token

1. Pair from the local page.
2. Confirm the page shows the paired state without the token.
3. Inspect the page's own network responses, if the browser tooling allows it,
   for a token field. Do not paste the response into a chat.
4. Confirm the manual token field is a fallback that sends a token typed by a
   person to the service, and the service never sends a token back.

Expected: the service pairs in `rust/src/pairing.rs` and holds credentials in
memory. The browser is the least trusted part of the target.

### S-04 Identity key handling

1. Confirm the key permissions and owner for the account that runs the engine.
2. Confirm the key is not in the repository or a shared folder.
3. Confirm no log, status answer, or report contains the key.
4. Do not print the key.

Expected: the key lives in the platform data directory with private
permissions. Tests use fixed public vectors or temporary directories.

### S-05 No external relay

Scope the listing to the engine process. Do not list every process: that
collects other people's connections and conflicts with section 4.2.

1. With a tunnel running, list the engine's internet sockets:
   - macOS or Linux: `sudo lsof -nP -a -c hotspotshade -i`. This includes TCP
     and UDP. If `-c` does not match the process, find the engine pid and use
     `sudo lsof -nP -a -p <pid> -i`.
   - Windows: in an elevated window only with approval,
     `Get-NetTCPConnection -OwningProcess <pid>` and
     `Get-NetUDPEndpoint -OwningProcess <pid>`.
2. Record only counts and endpoint classes, not names or addresses.
3. In source device proxy mode, inspect observed proxy-data endpoints against
   the hotspot gateway and proxy port. Pairing and status connections can also
   use the gateway on TCP 18090. Investigate any unexpected endpoint and stop
   the test if it cannot be explained.
4. In direct mode, the outer sockets go to the real destinations of the inner
   flows. That is the design, not a relay. Confirm that no endpoint is a
   third-party hop that you did not expect, and that the source device proxy
   port does not appear among the observed data sockets.
5. Record whether an unexpected VPS, cloud hop, or third-party relay appears
   in the available observations.

Expected: the source NAT is the terminator. There is no external relay, VPS, or
VPN protocol. A destination listing from direct mode is personal data and is
not recorded. A point-in-time listing can miss short-lived sockets, and the
Windows UDP endpoint listing does not show remote destinations. It cannot
prove that no relay was used or that an outer socket is bound to the hotspot
interface. Record the absence of pinning warnings, but do not claim positive
proof of interface binding from this check.

### S-06 No fail-closed claim

1. Record the bypass paths you can observe:
   - a more-specific route;
   - local DNS, DoH, or DoT;
   - a network extension or VPN;
   - IPv6 `inherit`, if someone selected it.
2. Do not describe the tunnel as fail-closed.
3. Do not claim all traffic is captured.

Expected: the project is a prototype and a research tool. It is not fail-closed.

### S-07 Token on the hotspot link

1. Read this from the source, not from a packet capture.
2. The proxy authentication sends the username and token as a SOCKS
   username/password exchange. It has no TLS. Pairing encrypts the delivery of
   the token with X25519 and ChaCha20-Poly1305, but the later proxy connection is
   not encrypted.
3. Use only a trusted hotspot for a real token.
4. Do not run a token test on a public hotspot.
5. Do not capture packets to "confirm" this. A capture would expose the token
   and personal traffic, and this procedure does not need one.

Expected: a device on the hotspot that can impersonate the source can capture
the token or traffic. This is a documented limit, not a fixed issue.

### S-08 Pairing code and rate limits

Do not run a hostile search. Record the documented limits:

- a six-digit code;
- a per-address challenge budget;
- a global challenge budget;
- a known-claim budget;
- an approval bound to the connection, prompt, code, and deadline;
- a per-address prompt-attempt budget and lockout.

Do not claim the six-digit code is a complete defense against an active
attacker. A live test without hostile traffic does not prove the limits.

## 13. Performance checks (PF)

Approval: required. These checks use cellular data and can cost money. Agree on
a byte cap and a time cap first. Do not declare a performance pass without a
threshold that the maintainer agreed to.

`phone-speed-diag` and `phone-udp-diag` send the token to the `--phone` address
you type. Both require the address to be on the hotspot interface subnet, but
neither proves it is the default gateway. Apply the gateway check in the start
commands before either one. `phone-udp-diag` is not a tunneled inner UDP test;
see X-02D.

### PF-01 Latency through the source proxy

1. On macOS or Linux, use `phone-speed-diag` with a test server whose operator
   permits the use. Windows has no such command; record the gap.
2. Use the hidden prompt for the token.
3. Set `--seconds`, `--repeat`, and `--max-mb` to small values first.
4. Record `connect_ms`, `ttfb_ms`, `phone_auth_ms`, and the probe success
   percent.
5. Record idle and loaded values separately.
6. Do not compare a direct hotspot result with a proxy result as if they were
   the same path.

Expected: the numbers describe the tested path at the tested time. A short
sample does not prove a speed improvement.

### PF-02 Throughput

1. With `phone-speed-diag` on macOS or Linux, run the download and upload
   phases with a byte cap. Windows has no such command; record the gap.
2. Record the steady rate after warmup, not the first interval.
3. Record the stream count, duration, and errors.
4. Record TCP retransmit and out-of-order counts.
5. Stop the run if the cap is reached.

Expected: the report contains no token and no payload. An upload counts bytes
that the socket accepted, minus bytes still in the send buffer.

### PF-03 UDP loss and round trip

1. On macOS or Linux, run `phone-udp-diag` at a low rate. Windows has no such
   command; record the gap.
2. Record `sent`, `received`, `loss_percent`, `rtt_ms`, `loss_runs`, and
   `interface_deltas`.
3. Do not call a public STUN server a bulk destination.
4. Do not use `--own-responder` unless you control the responder and the owner
   approved the rate.

Expected: a low-rate run is a loss and liveness result, not a throughput result.
A STUN server can rate-limit or ignore requests.

### PF-04 Memory and CPU

1. Measure the target app at idle and under load. On Windows, the current build
   cannot start a tunnel, so record PF-04 as Blocked. The WinUI preview is not
   engine evidence.
2. Use Activity Monitor on macOS, `ps` or `top` on Linux, and Task Manager on
   Windows.
3. Record RSS or the platform equivalent, and CPU use.
4. Measure source battery use qualitatively if the owner asks.
5. Do not claim a memory or battery pass without an agreed threshold.

An earlier VM record reported 585.4 MiB RSS and 273.5 MiB PSS at idle, and
623.5 MiB RSS and 295.2 MiB PSS in the active demo state. Its build identity is
not established for this tree. Those historical numbers are not a result for
the selected build, a live hotspot result, or a threshold.

### PF-05 Capacity and keepalive

1. Record the source open-file limit and the computed relay cap.
2. If a future Windows build enables source device token use, record its
   keepalive values: 60 seconds idle, 10 seconds interval, and a fixed 10 probes,
   so the dead-peer age is about 160 seconds. The current build cannot start that
   tunnel, so the Windows part of PF-05 is Blocked.
3. Record the macOS and Linux dead-peer age of about 90 seconds.
4. For an Android source, record the system keepalive defaults if the device
   exposes them. Do not record the iOS 60/10/3 values for Android.
5. Do not compare the Windows dead-peer age with the macOS or Linux value as if
   they were the same.

Expected: the relay cap follows the open-file limit. A low limit gives fewer
relays. The source does not evict a healthy open TCP relay only for silence.

## 14. Per-platform gaps

Update this table only when the platform status in `AGENTS.md` and `README.md`
changes. The table describes the intended procedure after applicable gates
open. Every physical test cell remains blocked today.

| Platform and role | Intended scope after gates open | What remains unverified |
|---|---|---|
| macOS 14+ arm64 target | Read-only `probe`, demo GUI, unsigned app bundle install, and the CLI source device proxy path. | Real app, helper, launch daemon, start right, and root engine installation is BLOCKED and UNAPPROVED. The installer is build-only, its `preinstall` refuses, and no signed helper install or XPC launch has run. The helper and engine use `start-exclusion`; the installer uses `start.lock` and holds `start.lock`, `start-exclusion`, and `upgrade.lock` as a transition set. Old binaries take no lock and remain a gap. The helper and direct engine refuse `install-journal.json` and `service-journal.json`. A direct engine writes `engine-session` and reports an uncertain cleanup as an error. The files changed during this revision and do not form one converged, approved protocol. The helper cleanup marker is durable across a helper restart, and no manual deletion or direct-engine recovery is approved. No direct-mode pass: the CLI does not expose the running audit. An unsigned or ad hoc app fails closed for real mode. The release app is arm64 only. The IPv6 blackhole can survive a crash and has no route claim. `tun --phone` does not check the typed destination against the default gateway. |
| Windows 10/11 target | Read-only `probe` and preflight. The CLI and command-line GUI refuse source device token use before any adapter or route change. | Source-proxy token use is disabled in this build, so no Windows tunnel, X, or A cell can run. A gated direct service lifecycle exists but no shipped path can start it; the production entry refuses before Wintun, an adapter, or a route. No GUI pairing. No `socks5`, `phone`, or `phone-*` command. The WinUI app is a simulated preview. The direct link observer is gated with the direct lifecycle; no source-proxy link observer is enabled. No installer or signed package. |
| Linux target | The CLI source device proxy path, table 700, the policy rules, IPv6 block and forward, the 20-second link-loss stop, and cleanup after A-08. | Physical tests are blocked until the recovery change, the `tun --phone` destination proof, and the linked Linux guides are revised, committed, reviewed, and present in the identified build. The claim format is version 3 and can name up to four predecessor records. A valid current-boot claim start can delete the exact selectors of the current record and every predecessor without a prompt before authentication, but only after a reviewed selector dump and approval of every selector. No reviewed selector dump exists in this tree, so a present claim is Blocked. `stat` and the `route_claim` status cannot enumerate that set. Once deletion begins, a later read or delete failure can leave partial cleanup; the first complete read is all or nothing. An earlier-boot claim is truncated by a start without a kernel delete. An empty or missing claim with leftover objects normally refuses, but the checks are snapshots and a start can use the token and create the TUN device and address first; a refused start unlinks the empty claim. A recovered record stays in the claim file when the later read refuses. A replacement that would need a fifth distinct predecessor keeps the previous current record and the newest three predecessors only after a completed two-absence recovery; without that proof it refuses and can block every start. A consistently omitted object can still survive after its selector is dropped. The linked `LINUX_ROUTE_RECOVERY.md` now records the compaction rule and that limit; it is another writer's scope and is unreviewed. A status poll can make a start refuse as if a live owner held the claim. On an `--iface` interface that is not the default route, the destination proof shows only on-link or next hop, not the gateway. A damaged or foreign claim blocks every start, and the safe clear refuses a non-empty damaged or valid current-boot claim and is not reachable from any shipped interface. No page or app status reports the recovery line; only a terminal can show it. Linux SOCKS5 needs an explicit non-loopback `--dns-servers` list. No live hotspot test. The package is unsigned, installs a setuid-root `chrome-sandbox` when present, uses a per-launch polkit `auth_admin` action, and leaves a root-owned `/var/lib/hotspotshade` identity and trust store after remove and purge. The packaged Electron app has not been shown to start a real tunnel. No real polkit prompt, tray, or notification test. Crash recovery is hermetic only and not independently verified. The Electron app has a direct mode control, but no test has shown it to start a real tunnel, so the Linux app direct cells stay Blocked. A root browser GUI direct start is a separate untested path. |
| iOS 17+ source | Pairing, proxy, trust removal, foreground behavior, and the documented permissions. | No device test of the current build. No cross-platform live test. Token rotation is disabled in this build, so P-08 is Blocked and there is no in-app revoke path. A Keychain token can survive an uninstall, and Forget does not revoke it. The rotation and recovery matrix uses fakes only; it does not establish real Keychain and UserDefaults crash durability, device restore safety, or external-writer safety. There is no in-app conflict recovery. Background operation is subject to iOS limits. A free profile expires after seven days. |
| Android 8.0+ source | Pairing responder, source proxy, real Start and Stop, trust list, token rotation, notification permission, IPv6 and ICMP paths on an emulator. | No real phone, hotspot, or carrier test. The pairing listener is foreground only. If the Android 16 finder keeps reporting a pending tethering reading, the fourth pending probe is the first uncertain miss at about 8 seconds and a loss follows about 12 seconds after the watch starts; the evidence's own pending timeout is 3 seconds. The background status host stays off. Its status-only responder and run and token epoch fences have JVM and loopback tests only; no real-device background test or service-owner review has run. A `TOKEN_UNREADABLE` stop is not fixed by clearing data or rotating blindly. The emulator has no hotspot interface and no cellular IPv6 route. The Android target tunnel is not implemented. CI builds but does not publish an APK. Hotspot discovery on a real vendor ROM is still open. |

Do not fill a release-matrix cell from a row above unless every required step for
that cell passed on the current build. An emulator or VM result stays
development evidence.

## 15. Privacy mode tests

There is no user-selectable privacy mode to test today. Do not test `shape`,
`hide`, `cover`, or `terminate` as if a mode runs. Do not claim destination
privacy, SNI hiding, ECH coverage, billing changes, throttling changes, or
detection evasion.

The tree has a capability report and a bounded TLS record reframing module.
Neither is a live privacy mode. The report says `off` is the only supported
mode, and every app row offers no control. The reframing module has hermetic
tests but no user control and no relay mode wiring.

| Item | Status | Test rule |
|---|---|---|
| `off`: TTL normalization, interface pinning, normalized outer sockets | Implemented | Test with sections 7 to 13. It does not hide destinations. |
| `shape`, TLS record reframing | Mechanism in `rust/src/tls_shape.rs` with hermetic tests. Not wired to a user control or a relay mode. The report marks it `unsupported`. | No live mode test. Run 15.1. |
| `hide`, ECH and encrypted DNS | No code path. The report marks ECH and SNI override `unsupported`. | No test. Do not treat a proposal as a feature. |
| `cover`, a TLS tunnel to an owner endpoint | Deferred. No code path. The project has no external relay or VPS. | No test. |
| `terminate`, source-side TLS termination | Out of scope. Not a shared engine mode. | No test. It would need a local CA and break certificate pinning. |
| Mode flags | A fixed report. `off` is `supported`; the other three and `sni_override` and `ech` are `unsupported`. | Run 15.1. |
| UI controls | The apps show capability rows. No row offers a control. | Check that every row is unavailable and no switch exists. |

### 15.1 Read-only capability check

1. Open the target app Settings or the local page.
2. Find the destination privacy row.
3. Confirm the current mode reads `Off` or `Default`.
4. Confirm every other mode reads `Unavailable` or `Out of scope`.
5. Confirm no switch or button can turn a mode on.
6. Read `GET /api/status` on a non-root GUI without a secret, or use Copy
   diagnostics. Do not put a bearer secret on a command line.
7. Confirm:
   - `platform.destination_privacy.mode` is `off`;
   - `default_mode` is `off`;
   - `modes.off` is `supported`;
   - `modes.shape`, `modes.hide`, and `modes.cover` are `unsupported`;
   - `sni_override` and `ech` are `unsupported`;
   - `background_relay` is `unsupported` on every platform.
8. Confirm the report holds no destination name, address, certificate, ECH
   config, token, or key.

Expected: the report states what the build can do. It does not state that a
mode runs. A row that offers a control, or a mode that reads as active, is a
stop condition.

Until a mode exists, the privacy-relevant checks are:

- credential redaction in records and reports (section 4);
- listener binding (S-01);
- the documented DNS leak paths (X-03 and D-03);
- the documented IPv6 leak path, `inherit` (D-04 and D-05);
- the documented bypass paths (S-06);
- the statement that destinations, TLS server names, DNS names, flow size, and
  timing stay visible to the carrier.

When a mode is implemented, add a test only after it has a documented contract,
a capability flag, hermetic tests, and a clear statement of what it does not
hide.

## 16. Evidence record and verdict

### 16.1 Combination matrix and required cells

Fill one cell per source and target combination. An empty cell is not a pass.

| Source phone | macOS target | Windows target | Linux target |
|---|---|---|---|
| iOS | [ ] P-01 or P-05, P-02, P-03, P-06; X-01, X-02, X-03, X-04, X-05, X-06, X-07; A-01, A-02, A-03, A-04, A-05, A-06, A-07; S-01 to S-07 | [ ] P, X, and A blocked: source device token use is disabled. Preflight only. | [ ] P-01 or P-05, P-02, P-03, P-06; X-01 to X-07; A-01, A-02, A-03, A-04, A-05, A-06, A-07, A-08; S-01 to S-07 |
| Android | [ ] P-01, P-02, P-03, P-05, P-06 (P-09 blocked); X-01 to X-07; A-01, A-02, A-03, A-04, A-05, A-06, A-07; S-01 to S-07 | [ ] P, X, and A blocked: source device token use is disabled. Preflight only. | [ ] P-01, P-02, P-03, P-05, P-06 (P-09 blocked); X-01 to X-07; A-01, A-02, A-03, A-04, A-05, A-06, A-07, A-08; S-01 to S-07 |
| Direct mode, no source app | [ ] D-01, D-03, D-03U, D-04, D-05, D-06; D-02 blocked, D-03U TTL part blocked; A-01, A-02, A-07; S-01 to S-07 | No reachable Windows direct start. The gated service lifecycle is refused before Wintun, an adapter, or a route. | [ ] D-01, D-03, D-03U, D-04, D-05, D-06; D-02 blocked, D-03U TTL part blocked; A-01, A-02, A-07 for the app path, A-08; S-01 to S-07 |

Every cell is Blocked today by the status at the top of this page. The
direct-mode cells are blocked even when a CLI flow works: the CLI cannot show
the running `ttl_bad`, the Windows direct path is gated and refused, the Linux
app has a direct-mode control that no test has shown to start a real tunnel, and
the macOS app needs a signed, installed helper. Do not fill a direct cell from a
CLI flow test or from a root browser GUI test unless the cell names that path.

X-03 is the tunneled DNS cell. X-03S is the separate SOCKS5 adapter test and does
not satisfy X-03. A root browser GUI direct run is a separate path from the
macOS signed app and the packaged Linux app. It is untested.

A cell passes only when:

- the build identity and provenance from section 3.3 are recorded, and the
  recorded source revision contains every change the cell needs;
- the owner approval is recorded for the exact build and each action;
- the required pairing tests pass for that source and target, or the cell
  records the manual token path and marks pairing Blocked;
- the required proxy or direct tests pass, including X-02 for tunneled non-DNS
  inner UDP and X-03 for the tunneled DNS case, or D-03 and D-03U in direct mode.
  X-02D alone is not a pass for X-02, a DNS answer is not a pass for non-DNS UDP,
  and X-03S is not a pass for X-03;
- the automatic stop and cleanup tests that the platform supports pass, and
  the startup warnings are recorded;
- the security checks pass;
- the record has no unredacted secret, personal data, or DNS data;
- the cleanup evidence matches the baseline.

The Windows CLI and command-line GUI cells are Blocked while source device token
use is disabled. Do not use the manual token path to work around that refusal.
The GUI is a separate path from the CLI when a future build enables token use; do
not merge the two.

### 16.1.1 Paths and expected errors

A GUI error is not a CLI result, and a CLI result is not a target app result.
Record the path and the exact fixed error.

| Path | Prerequisite | Expected result or error |
|---|---|---|
| macOS target app, real mode | Signed Developer ID helper and engine, hardened runtime, no `get-task-allow`, an approved root package, the launch daemon and start right, one reviewed lock and journal protocol, app started by the logged-in user | BLOCKED. The current package is build-only, its `preinstall` refuses, and no signed helper install or XPC launch has run. The helper and engine use `start-exclusion`; the installer uses `start.lock` and holds `start.lock`, `start-exclusion`, and `upgrade.lock` as a transition set. Old binaries take no lock and remain a gap. The helper and direct engine refuse `install-journal.json` and `service-journal.json`; a direct engine writes `engine-session`. The files are still evolving and are not one approved protocol. An unsigned or ad hoc app fails closed. A non-root browser GUI without the helper returns `protected_helper_required`. The app shows its own fixed text, not a CLI line. |
| macOS root browser GUI, phone or direct | Root, a 64-character secret on `--token-fd`, owner-approved root process | Starts the service directly and exposes diagnostics for direct mode. It is not the signed app. No live test has shown it. A direct result is a separate path, not a D-02 app cell. |
| macOS CLI `tun` | Root; a physical hotspot interface with a usable IPv4 address; the typed address is the current default gateway; no utun or VPN on the selected path | Starts the tunnel. A rejected token prints `error: phone_auth`. The typed destination is not checked against the gateway. The CLI prints its raw `error:` text. |
| macOS CLI `phone` | Non-root; a physical hotspot interface; the typed gateway; a token from the hidden prompt | Local adapter on `127.0.0.1`. No route. The typed destination is not checked. |
| macOS CLI `socks5` | Non-root; a physical interface; an unambiguous per-interface resolver, or an explicit server list | Local adapter. No route. A non-root GUI `socks5` start exposes diagnostics only for SOCKS outer sockets; it is not direct-mode evidence. |
| macOS CLI `phone-udp-diag` | Non-root; a physical hotspot interface; the typed source address on that interface's subnet; a permitted target; owner approval for the data use | Scoped diagnostic. It opens its own outer socket and is not tunneled evidence. |
| macOS CLI `phone-speed-diag` | Same as `phone-udp-diag`, plus a test server whose operator permits the use and agreed caps | Performance sample only. Not a tunnel, pairing, or carrier pass. |
| Linux packaged app | Non-root desktop account; polkit `auth_admin`; packaged helper and engine present; claim state absent. A present claim is Blocked because no reviewed selector dump exists; the 5.3.1 gate | Starts through `pkexec`. A non-root browser GUI without the helper returns `admin_required`. A real polkit prompt is untested. The app shows no recovery line. |
| Linux packaged app, direct mode | Same as the packaged app, plus owner approval for a direct start; the 5.3.1 gate; the claim order | The app sends a `tun` start with `ipv6: block`. No test has shown it to start a real tunnel. The app shows no recovery line. |
| Linux root browser GUI, phone or direct | Root; a 64-character secret on `--token-fd`; the 5.3.1 gate; owner approval for the root process; claim state absent. A present claim is Blocked because no reviewed selector dump exists | Starts the service directly. The page exposes diagnostics but no recovery line. It is a separate path from the packaged app and has no live test. |
| Linux CLI `tun`, phone mode | Root; a physical hotspot interface; the 5.3.1 gate; claim state absent. A present claim is Blocked because no reviewed selector dump exists; the claim path is a regular single-link file and not a symlink; the typed address is the current default gateway, or `--iface` is used with the on-link-only limit; owner approval | Starts the tunnel. A rejected token prints `error: phone_auth`; another source device connection failure prints `error: service_start`. A claim or early table refusal prints `error: route_setup`. A destination mismatch prints `error: source_device_moved`, or `error: outer_interface_changed` for another interface. A late install refusal prints `error: route_setup` after the token and TUN device. A symlink, non-regular claim, or multi-link claim is not a valid preflight state. `stat` cannot enumerate the recovery selectors, and no reviewed dump exists in this tree. |
| Linux CLI `tun`, direct mode | Root; the 5.3.1 gate; claim state absent. A present claim is Blocked because no reviewed selector dump exists; the claim path is a regular single-link file and not a symlink; owner approval for the start; default `--ipv6 block` unless forward was approved | `--no-pin`, `--no-routes`, and `--ipv6 inherit` are refused before the claim. A claim or table refusal prints `error: route_setup`. No token exists. A symlink, non-regular claim, or multi-link claim is not a valid preflight state. `stat` cannot enumerate the recovery selectors, and no reviewed dump exists in this tree. |
| Linux CLI `phone` | Non-root; a physical hotspot interface; the typed gateway; a token from the hidden prompt | Local adapter. No route. No destination proof. |
| Linux CLI `socks5` | Non-root; a physical hotspot interface; an explicit, numeric, non-loopback `--dns-servers` list | Local adapter on `127.0.0.1`; no route. Without the DNS list the start fails closed with "the Linux system resolver list is not tied to one interface; pass an explicit DNS server". This is the X-03S adapter test, not X-03. |
| Linux CLI `phone-udp-diag` | Non-root; a physical hotspot interface; the typed source address on that interface's subnet; a permitted target; owner approval for the data use | Returns "the source device address is not on the subnet of the hotspot interface" or "the hotspot interface does not exist" when the link is wrong. It is not tunneled evidence. |
| Linux CLI `phone-speed-diag` | Same as `phone-udp-diag`, plus a permitted test server and agreed caps | Performance sample only. Not a tunnel or carrier pass. |
| Windows CLI `tun` | `--phone`; a fixed non-secret placeholder at the prompt, never a real source token. Administrator and `wintun.dll` are not needed to reach the refusal, which comes before the elevation and DLL checks | Refuses source device token use with "Windows source device token use is disabled: physical adapter and gateway identity cannot be verified safely; use a supported target device". It creates no adapter or route and sends no token. Without `--phone` it prints "source device proxy mode requires --phone IPv4:PORT" and never reaches the gated direct service entry. Do not treat the refusal as a gateway or authentication result. |
| Windows service direct entry, no shipped CLI or GUI path | Windows; no `--phone`; production direct entry | Refuses with "Windows direct mode is disabled: physical adapter pin and Wintun route evidence from a Windows VM and an independent review are required" before Wintun, an adapter, or a route. It is a gate refusal, not a tunnel result. |
| Windows CLI `gui` | An authenticated launcher with `--token-fd` and `--parent-fd`. `wintun.dll` is not needed to reach the refusal | Starts the real GUI. Without the token it returns the authenticated-launcher message. Without the parent pipe it returns "The Windows GUI needs a launcher parent pipe. Pass --parent-fd N." Source-proxy starts and probes are gated by `source_proxy_unavailable`, with the fixed text "Source device proxy mode is unavailable in this Windows build." `--demo` works without either launcher descriptor. |
| Windows GUI backend, phone mode | A token and a source app | Refuses source device token use with `source_proxy_unavailable` and the fixed text "Source device proxy mode is unavailable in this Windows build." No source-device probe can run. This refusal is not evidence of gateway identity or source authentication. |
| Windows WinUI app | None | Simulated preview. No engine, tunnel, routes, or credentials. Never a result. |
| Windows `socks5`, `phone`, `phone-udp-diag`, `phone-speed-diag` | None | These commands are not implemented on Windows. Record the gap. |

On every CLI row, a fixed code appears after `error:` unless the row says the
path prints plain text. A GUI shows fixed text for a known code and its generic
start message for an unknown code, so record the displayed text and the path. A
GUI code is not a CLI result, and a CLI line is not a GUI result.

For a macOS or Linux source device proxy start, `--ipv6 block`, `--ipv6
inherit`, `--no-pin`, `--no-routes`, or `--dns-upstream` is refused with the
source device proxy mode validation message. Do not use one of them for a pass.
On Windows the source device token refusal comes first, so none of these options
reaches that validation in the current build.

The Linux destination proof is uncommitted at the time of this revision. A
result from the current working tree is development evidence, not a cell pass. If
the recorded build does not contain the proof, expect no `source_device_moved`
error and treat the typed address as the only guard. If the build does contain
it, still type only the current default gateway.

### 16.2 Verdict vocabulary

| Verdict | Meaning |
|---|---|
| Pass | Every required step ran on the recorded build and hardware, the expected result occurred, and cleanup matched the baseline. |
| Fail | A required step produced a wrong result, a secret exposure, a leftover resource, or a self-restart. |
| Blocked | A prerequisite was missing, for example a signed helper, a real phone, a carrier path, or owner approval. |
| Inconclusive | The step ran but the evidence cannot separate success from a confounder. |
| Development evidence | The result came from an emulator, simulator, mock, VM, or demo. It is not a release-matrix pass. |

### 16.3 Record template

```text
Test id:
Date:
Owner approval:
Tester:
Build: commit, tree state, build command or CI run, artifact digest, app version, signing class
Path: target app / command-line GUI / CLI; fixed error code when unavailable
Source device: model, OS, app version, install method
Target device: model, OS, app version, install method
Hotspot: band, channel width, security type, no SSID
Carrier and plan: not recorded by policy
Steps: P-01, X-01, A-01, ...
Startup warnings: recorded or "none"; no host name or resolver
Linux pre-start: claim state, header version, rule and table 700 reads, destination proof in revision; no reviewed selector dump exists, so a present claim is Blocked
Result: pass / fail / blocked / inconclusive / development evidence
Observed: fixed messages, counters, ttl_bad, stop reason
Cleanup: routes, rules, addresses, devices, listeners, processes
Limitations:
Redaction check: no token, password, code, key, destination name or IP,
resolver address or search domain, DNS query, account data, or capture
```

### 16.4 Evidence storage

- Keep the private record outside the repository.
- If the owner asks for a repository record, commit only the redacted summary.
- Do not commit a token, key, certificate, provisioning profile, packet
  capture, or personal traffic.
- Do not edit existing files under `probes/`.
- Delete temporary files and capture files after the run.

## 17. What remains unverified

Physical tests are blocked by the status at the top of this page. This revision
answers the earlier reviews and the latest independent findings, but it does not
close the blockers. They close only when an independent review repeats on the
reviewed build, the owner approves the exact build and action, the Linux recovery
and destination-proof changes are committed and reviewed, the linked Linux guides
are settled by their own writer and review, and a physical run produces the
evidence. Independent re-review is required before this page is used to approve
a test.

Record the gaps in 2.2 and 2.3, and the platform table in section 14, in every
result until evidence closes them. This includes the signed macOS helper, a live
Windows tunnel, a live Linux hotspot and desktop session, Linux crash recovery
on a real kernel, every physical source device test, sustained iOS background
relay, the paused-reader behavior, and the pairing rate limits under hostile
traffic. Earlier physical results do not establish those properties for the
current build. A pass here is not a release decision.

The following uncertainties stay open even after the document corrections:

- this revision has not been independently reviewed or approved. It answers
  the current independent review findings on top of review `a41485ff`, review
  `a3a2fad8-29ab-4358-b5e9-737a4b16fb98`, and review `ff0aeea4`. A new review
  must confirm the corrections and close the remaining findings before any
  physical test;
- macOS real app and helper installation is BLOCKED and UNAPPROVED. The installer
  is build-only, its `preinstall` refuses, and no signed helper install, start
  right write, or XPC launch has run. The helper and engine use
  `start-exclusion`; the installer uses `start.lock` and holds `start.lock`,
  `start-exclusion`, and `upgrade.lock` as a transition set. Old binaries take no
  lock and remain a gap. The helper and direct engine refuse
  `install-journal.json` and `service-journal.json`; a direct engine writes
  `engine-session`. There is no approved manual deletion or direct-engine
  recovery. Do not install or test real mode from this tree, and do not assert a
  converged or approved lock;
- the Linux source and linked guides are uncommitted working-tree text. Recheck
  the claim path, `ROUTE_CLAIM_PATH`, the version 3 header and up to four
  predecessor records, the permission check, the adoption conditions, the
  earlier-boot, empty-claim, and recovered-record behavior, the recovery
  reporting, the selector dump, the early physical capture and rechecks, and the
  `tun --phone` destination proof after the repairs land and are reviewed. No
  reviewed selector dump exists in this tree;
- `LINUX_ROUTE_RECOVERY.md` is another writer's scope. Its current text names
  the version 3 predecessors, the compaction rule and its limit, the early
  physical capture, and the retained identity rechecks. Confirm the text against
  the build's recorded revision. This page does not make the file current,
  complete, or approved. A `stat` or the `route_claim` status does not enumerate
  the recovery set, and the safe claim clear removes only an empty file or a
  valid earlier-boot record. It is not reachable from any shipped interface;
- the link check cannot tell the hotspot network from another network, so A-02
  and the direct tests depend on the operator disabling other networks;
- macOS has no route claim and no automatic recovery for a stale `2000::/3`
  blackhole. It has a start lock, a durable cleanup marker, a launch intent, an
  install journal, and a service journal, but they are not route ownership
  proof. Stop and ask the maintainer to inspect the host. This procedure does
  not approve a manual delete; the read and a delete would not be atomic;
- Linux recovery is a claim record, not kernel attestation. A start captures
  read-only physical outer evidence and retains it before it takes the claim,
  then can delete the exact recorded objects of the current record and every
  predecessor without a prompt only when every A-08 pre-deletion condition holds
  and the owner approved a reviewed selector dump. No reviewed dump exists in
  this tree, so a present claim is Blocked. The first complete recovery read is
  all or nothing; once deletion begins it is incremental. A later read or delete
  failure can leave partial cleanup. The check and the delete are not atomic. An
  earlier-boot claim is truncated by a start without a kernel change, and an
  empty or missing claim does not by itself make a start safe. A start can pass
  the table 700 and priority read, use the token, and create the TUN device and
  address before the install read refuses, then unlink an empty claim. A
  recovered record that the later read did not confirm stays in the file for the
  next start. A replacement that would need a fifth distinct predecessor keeps
  the previous current record and the newest three predecessors only after a
  completed two-read absence proof; without that proof it refuses and can block
  every later start. Do not describe recovery alone as clearing the record;
- a Linux recovered record and an empty claim behave differently on a later
  refusal. The empty file is removed when the manager is released; the recovered
  record is kept and adopted again. Do not read either result as proof that the
  start did not change the host;
- a Linux status poll takes the claim lock for a moment, and a start in another
  process that arrives then refuses with `route_setup` as if a live owner held
  it. The refusal is a false positive for a live tunnel;
- the Linux destination proof on an `--iface` interface that is not the default
  route proves only that the address is on-link or the next hop, not that it is
  the gateway;
- the Linux destination proof is uncommitted. macOS `tun --phone`, `phone`,
  `phone-udp-diag`, and `phone-speed-diag` do not check the typed address against
  the gateway, and every mode sends the token over the hotspot link in cleartext;
- Linux SOCKS5 mode has no per-interface system resolver. An explicit,
  non-loopback `--dns-servers` list is required, and a loopback server is
  refused. A missing list is a start failure, not a fallback to the system list;
- the claim directory can remain after a clean stop. The clean result is an
  absent claim file. The permission check rejects any group or other bit; it
  does not require exactly `0700` and `0600`. The current claim is version 3
  with up to four predecessor records. `stat` and the `route_claim` status do
  not enumerate the current or predecessor selectors. No reviewed selector dump
  exists in this tree, so a present record is Blocked; a future reviewed dump
  would need approval of every selector before a start that may recover;
- a stop can fail. A cleanup failure can leave routes, rules, addresses, a
  device, a Linux claim and its lock, or a macOS `engine-session` record behind.
  A Windows adapter can remain only in a build that can start a Windows tunnel,
  and none can today. The stop then reports an error, and the next start can
  refuse until a person inspects the host. Do not read a stop message as proof
  that cleanup finished; run A-09 and compare with the baseline;
- the Windows identity key may be absent because Windows has no pairing path,
  and the ACL check accepts LocalSystem, Builtin Administrators, and
  TrustedInstaller as well as the current user;
- the current Windows build disables source device token use. The CLI prints a
  fixed refusal, and the command-line GUI returns `source_proxy_unavailable`
  with its fixed unavailable message. Both come before an
  adapter or route change and before the DLL is resolved, so no Windows
  source-proxy, X, or A cell can run and an absent `wintun.dll` does not change
  the result. A gated direct service lifecycle exists, but the CLI without
  `--phone` is rejected during option parsing and the production direct entry
  returns "Windows direct mode is disabled: physical adapter pin and Wintun route
  evidence from a Windows VM and an independent review are required" before
  Wintun, an adapter, or a route. No Windows direct tunnel has run. A future
  build that enables token use must also solve physical adapter and gateway
  identity and must re-check them at each credential write. In that future GUI,
  the link stays unobservable, but a fresh silent source device probe still
  accumulates and can stop the tunnel after 90 seconds; an unknown interface
  reading alone does not reset that fresh silence. The Windows CLI and
  command-line GUI remain separate paths, and a result from one is not a result
  for the other;
- a root browser GUI direct start is a separate path from the signed macOS app
  and the packaged Linux app. It can expose diagnostics, but no test has shown
  it, and it must not fill an app cell;
- the Linux package setuid `chrome-sandbox`, the polkit `auth_admin` prompt, the
  persistent `/var/lib/hotspotshade` identity, and the remove versus purge
  behavior have not been tested on a real desktop. A root identity can survive
  the package and be shared by every user who can authorize a launch;
- startup warnings are not a stable, documented API. The operator must record
  the actual text and decide whether the related stop test is Blocked;
- X-08 probe timing is inconclusive without a separately approved lab capture;
- X-03 is the tunneled DNS cell, and X-03S is the separate SOCKS5 adapter test.
  Neither substitutes for the other;
- DNS redaction depends on the operator. `probe`, `scutil`, `resolvectl`,
  `/etc/resolv.conf`, route dumps, and logs can all carry resolver or destination
  data. `ifconfig`, `ip addr`, neighbor tables, and interface dumps can carry
  MAC addresses and local IPv6 addresses, which are also redaction items;
- the direct-mode cells cannot reach a pass without a readable running audit;
- the macOS state directory and the state files that the helper reads or removes
  require the expected owner, no group or other permission, no set-id bit, and
  no extended ACL. The helper checks a single link on `start-exclusion`, not on
  every state file. The Rust engine checks the state directory ACL and the lock
  and handoff; it creates the direct `engine-session` record as a single-link
  owner-only file and does not read an ACL on that record. This procedure treats
  a multi-link state file as a stop condition even where the code would accept
  it. `stat` does not show an ACL, so `ls -lde` is also required. No live host
  has run these checks in this revision, and an unreadable ACL state is unknown,
  not clean;
- the macOS helper cleanup marker at `/var/db/hotspotshade/cleanup-blocked`
  survives a helper restart. `engine-session`, `install-journal.json`, and
  `service-journal.json` can also refuse a start. A direct CLI or GUI engine
  writes `engine-session` and can leave it after an uncertain cleanup. No helper
  path clears the marker, and no manual deletion or direct-engine recovery is
  approved. Do not restart or remove state to clear it. Stop and escalate;
- the Linux route-claim preflight must see a real directory, a regular claim
  file, and exactly one link. A symlink, a non-regular object, or a multi-link
  claim is a stop condition. The engine opens the claim with `O_NOFOLLOW` and
  requires a single-link file. The file can hold version 3 with up to four
  predecessor records, and the recovery set cannot be read from `stat`;
- an iOS Keychain token can survive an uninstall, and a reinstall with the same
  bundle identifier can read it again. Forget removes trust only and does not
  revoke the token. Token rotation is disabled in the current build:
  `TokenRotationPolicy.reviewed` is false, the control stays disabled, and P-08
  is Blocked. Do not describe uninstall, reinstall, or Forget as revocation;
- the rotation and recovery code is exercised with fakes, not a physical device.
  That does not establish real Keychain and UserDefaults crash durability, device
  restore safety, or external-writer safety;
- an unreadable or invalid source token, an old-copy conflict, a damaged
  rotation intent, or an unfinished rotation is a stop condition. The app keeps
  both copies, suspends pairing, and offers no in-app conflict recovery: the
  store refuses both repair actions. Do not clear app data, reinstall, or expect
  a rotation control to clear it. Android reports `TOKEN_UNREADABLE` for the same
  class of failure;
- source device proxy mode rejects `--dns-upstream`. X-03 must use the original
  destination. Only direct mode D-03 may configure an upstream;
- the Windows refusal path must use a fixed non-secret placeholder at the
  prompt, never a real source token;
- an Android 16 pending tethering reading has two bounds. If it stays pending,
  the fourth consecutive pending probe at 2-second spacing is the first
  uncertain miss, about 8 seconds after the watch starts, and a loss follows
  about 12 seconds after the watch starts. The evidence's own pending timeout is
  3 seconds, after which the ordinary name rules usually decide earlier. Do not
  report a loss from the first pending window;
- the Android background status host stays off. The current host uses a
  status-only responder and fences one run and one token epoch, but those rules
  are covered by JVM and loopback tests only. The earlier rationale that the
  host could return the captured token without a prompt or had no run or token
  epoch fence is no longer current. The gate stays off pending service-owner
  review and a real-device background test. Do not enable it for a test;
- platform gating and safety assumptions: `--dns-upstream`, `--no-pin`,
  `--no-routes`, and `--ipv6 block` or `inherit` are direct-mode options; source
  proxy mode requires pinning, routes, and IPv6 forwarding; `--experimental-icmp`
  requires source proxy mode; `phone`, `socks5`, and `phone-*` are macOS and
  Linux only; Windows has no such commands; and no macOS real-mode install or
  helper start is approved;
- the source was read from the uncommitted working tree. The hashes at the top of
  this page identify the inspected files where pinned.
  `rust/src/platform_linux.rs`, `rust/src/service.rs`,
  `android/app/src/main/java/com/hotspotshade/source/TokenStore.kt`, and
  `docs/LINUX_ROUTE_RECOVERY.md` are not pinned because they changed during this
  correction. Any change to those files before the next review is drift, and the
  affected statements need a new review.

## 18. References

- [GOAL.md](../GOAL.md): product goal and non-goals.
- [AGENTS.md](../AGENTS.md): invariants, CI, tests, safety rules.
- [README.md](../README.md): setup, measured results, limits.
- [PHONE_PROXY.md](../PHONE_PROXY.md): source proxy, pairing, local API,
  diagnostics, automatic stop.
- [MULTIPLATFORM_ROADMAP.md](MULTIPLATFORM_ROADMAP.md): production plan, test
  matrix, evidence rules.
- [TECHNICAL_REFERENCE.md](TECHNICAL_REFERENCE.md): architecture, privileges,
  DNS, IPv6, cleanup, troubleshooting.
- [LINUX_ROUTE_RECOVERY.md](LINUX_ROUTE_RECOVERY.md): Linux crash claim and
  recovery, with its hermetic-test and live-test limits. It has no approved
  manual delete procedure.
- [LINUX_TEST_VM.md](LINUX_TEST_VM.md): disposable Linux VM tunnel procedure.
- [RELEASE_READINESS.md](RELEASE_READINESS.md): release gates and rollback
  limits.
- [SNI_HIDING_PLAN.md](SNI_HIDING_PLAN.md): privacy proposal and its
  unimplemented status.
- [macos/Helper/README.md](../macos/Helper/README.md): protected helper, start
  exclusion, the `engine-session` launch intent, both installer journal
  refusals, and the limits of the helper recovery. It does not approve a
  direct-engine recovery or a manual state delete.
- [macos/Installer/README.md](../macos/Installer/README.md): build-only installer
  foundation, its refusal gate, and the transition lock set.
- [macos/Installer/SERVICE_TRANSACTION.md](../macos/Installer/SERVICE_TRANSACTION.md):
  service journal phases, the reverse fences, and the two-journal gap.
- [ios/README.md](../ios/README.md): iOS Keychain token, uninstall and Forget
  limits, and the source app rotation review gate.
- [android/README.md](../android/README.md): Android source proxy, token store,
  tethering evidence, and emulator-only limits.
