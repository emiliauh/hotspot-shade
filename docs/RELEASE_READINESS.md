# Release readiness

This page records what the release path does today, what it proves, and what it
does not. It is a prototype release path. HotspotShade is not production ready,
and no artifact is signed for distribution. Read this page with
[CI_PIPELINE.md](CI_PIPELINE.md) and
[MULTIPLATFORM_ROADMAP.md](MULTIPLATFORM_ROADMAP.md).

## Scope

The audit covers CI and the release path only:

- `.github/workflows/ci.yml`: job graph, artifact uploads, release gating.
- `scripts/release_audit.sh`: release metadata, workflow policy, tree hygiene,
  and artifact policy.
- `scripts/release_manifest.sh`: `SHA256SUMS` and `PROVENANCE.txt`.
- `scripts/ci_graph_check.sh`: the `needs:` graph.
- `scripts/linux_vm_test.sh` and `scripts/tests/linux_vm_test_test.sh`: the
  disposable Linux VM evidence.
- `scripts/tests/release_pipeline_test.sh`: tests for the checks above.

The workflow policy scanner is under repair after independent review found
valid YAML inputs that bypassed its action, permission, secret, trigger, and
verification checks. Do not rely on it as a release gate until the revised
scanner and its fixtures pass independent review and CI on the release commit.
One review reproduced a job replacing `release-bundle` after artifact
verification. The subsequent digest-binding repair is also unapproved: a later
review reproduced a valid-YAML decoy job outside `jobs:` that makes the audit
and graph checker accept a different release job. A passing local audit does not
close either review gate.

The audit and its expected job blocks live in the same commit as the workflow.
They are review aids, not an independent security boundary. Branch and tag
rules, the protected release environment, action code, and cache provenance
must be checked separately; a tag build that consumes an untrusted build cache
can publish bytes that pass structural checks without proving their source.

The disposable-VM source archive helper is also under repair after an
independent review found unsafe file and archive handling. Do not use it to
transfer the working tree until the revised helper and its extraction path
have passed independent review. Earlier VM and emulator results apply only to
the snapshots named in their evidence records.

This audit work did not change platform application source, `README.md`,
`PHONE_PROXY.md`, or `docs/MULTIPLATFORM_ROADMAP.md`. `AGENTS.md` lists the
current CI jobs, including the three verify jobs and the integrity job.

## Gates in the working tree

These descriptions apply to the current working tree. They do not establish
that the changes ran in GitHub Actions or are present in a release commit.

| Gate | Where | What it proves | Limit |
|---|---|---|---|
| Release audit | `release-audit` job, every push | Intended to check release files, workflow policy, and tree hygiene. | Independent review found bypasses in the prior scanner. Repairs and review are in progress; a local pass does not prove the policy holds or the build is genuine. |
| Graph check | `release-audit` job | Every job has a stage tag, every `needs:` entry names a job, no cycle exists, and the release job reaches every job. | It reads the structure the workflow uses. Parse the YAML with a YAML parser as well. |
| Artifact verify | `verify-macos-binary`, `verify-ios-ipa`, `verify-macos-app` | The uploaded bytes, not the build directory, are the documented shape: a Mach-O arm64 binary, an unsigned IPA with no provisioning profile, and an ad hoc signed app bundle that passes `codesign --verify --deep --strict`. | It does not prove the artifact runs on a device. |
| Checksum manifest | `artifact-integrity` job | `SHA256SUMS` covers every published file, and `PROVENANCE.txt` names the commit, ref, run, runner, size, and digest of each artifact. | Integrity only. It is not a cryptographic attestation. |
| Tag match | `release` job | Checks the tag, source versions, artifact set, checksums, and readable artifact versions. | The strict tagged path currently refuses the standalone binary and, on Ubuntu without `plutil`, a binary IPA plist. See blocker 4. |
| Tag check | `release` job | `gh release create --verify-tag` publishes only to an existing tag and never creates one. | It does not prove the tag points at a reviewed commit. Tag protection rules handle that. |
| Environment | `release` job | The job names the `release` environment, so repository settings can require reviewers and a tag rule. | The gate exists only after someone configures it. See blocker 7. |
| Publication | `release` job | Intended to publish the binary, IPA, app zip, `SHA256SUMS`, and `PROVENANCE.txt` after all gates pass. | The strict audit currently blocks this path. No Developer ID signed or notarized artifact exists; the binary signature is not verified by this workflow. |

## Upgrade and rollback

No platform has an update feed, an automatic update, or a rollback tool. A
person upgrades by installing a newer build and rolls back by installing an
older one.

| Platform | Version today | Upgrade keeps | Rollback path | Open gap |
|---|---|---|---|---|
| iOS source app | `CFBundleShortVersionString` 0.1.0, bundle id `local.hotspotproxy.app` | Pairing trust is in the app container. The current token uses a device-only Keychain item and can survive app deletion. | Replace the app with an older build signed with the same bundle id, subject to storage compatibility. | The IPA is unsigned. A free Apple ID profile expires after seven days. Reinstall or Forget does not revoke an existing token. Rotation is disabled pending a reviewed recovery protocol; there is currently no in-app revocation path. Keychain migration and reinstall behavior need device tests. |
| Android source app | `versionCode` 1, `versionName` `0.1.0`, application id `com.hotspotshade.demo` | The Keystore token, the current file-based trust store, and legacy preferences, if the application id and signing key stay the same. A nonempty legacy trust list requires reset and re-pairing. | An older compatible APK may read the legacy preferences. Android rejects a lower `versionCode` without a separate downgrade procedure. | CI builds a debug APK only. No release signing config. No real phone test. The downgrade trust policy remains unresolved. |
| macOS target app | `MARKETING_VERSION` 0.1.0, arm64 only | The identity key at `$HOME/Library/Application Support/hotspotshade/identity.key` survives an app replacement. | Replace the app bundle with an older build. | Ad hoc signature only, no Developer ID, no notarization. Gatekeeper blocks a downloaded copy until the person allows it. The installer foundation deliberately refuses installation; there is no approved installer, DMG, or update feed. |
| Linux target app | `linux/package.json` 0.1.0 | `/var/lib/hotspotshade` holds the root engine identity key. User settings and the autostart file survive a package upgrade. | `dpkg -i` an older `.deb`. dpkg allows a downgrade with a warning. | The `.deb` is unsigned and is not in the release set. No repository or release key. No live desktop test of a polkit prompt. |
| Windows target app | appx `0.1.0.0` | Nothing. The WinUI app is a simulated preview and holds no engine state. | Nothing to roll back. | No installer, no release asset, no engine connection. |

The intended release set holds the macOS binary, unsigned iOS IPA, macOS app
zip, `SHA256SUMS`, and `PROVENANCE.txt`. The strict release gate currently
blocks publication. The Linux `.deb` and Android APK are not in the set.

## Release procedure

Run this only after the blockers below are closed or accepted.

1. Align the version in `rust/Cargo.toml`, `desktop/Cargo.toml`,
   `linux/package.json` and its lockfile, `macos/HotspotShade.xcodeproj`, and
   `ios/HotspotProxy/Info.plist`. Then run the strict audit locally:
   `sh scripts/release_audit.sh --require-aligned-versions`.
2. Confirm every required check passes on the release commit. The check names
   are listed in [CI_PIPELINE.md](CI_PIPELINE.md).
3. Confirm the `release` environment has required reviewers and a tag rule.
4. Create and push the `v*` tag.
5. Read the `release` job log. It must show the audit, the manifest write, and
   the manifest verify before the publish step.
6. Download the published artifacts and check the digests:
   `sh scripts/release_manifest.sh --verify <download-dir>`.
7. Record the run URL, the tag, the commit, and the digest of each artifact in
   the roadmap evidence log.

The release job uses `--require-aligned-versions`. It compares readable app
artifact versions with source metadata and refuses an unreadable version. The
standalone binary currently has no version the audit can verify, and Ubuntu's
IPA binary plist needs a reviewed portable reader. The tagged release cannot
pass until both blockers are resolved.

## Linux tunnel evidence

The current `--tunnel` harness is diagnostic only and always reports failure;
its root monitor has not been independently established as a trustworthy pass
signal. Source transfer also remains blocked pending the snapshot helper repair
and review. The fixture results below do not authorize a VM run or prove a
tunnel pass.

The ignored Linux tunnel suite holds eight tunnel scenarios and two
child-process helpers. The helpers return at once when a test runner starts
them directly, so a top-level run would report ten passes without exercising
ten scenarios.

`scripts/linux_vm_test.sh --tunnel` now:

- builds the test and the engine into a fresh per-run `CARGO_TARGET_DIR`, so a
  hashed binary from an older archive cannot be selected;
- requires exactly one `linux_tunnel_vm-*` binary in that directory and that it
  is inside it;
- skips `linux_vm_mock_source` and `linux_vm_direct_echo` at the top level and
  asserts eight passes and two filtered out;
- sets `HS_DISPOSABLE_LINUX_VM=1` on that one command only. The test binary
  refuses to change a namespace or a route without it. The variable is
  deliberate consent, not proof that the host is disposable.

`scripts/tests/linux_vm_test_test.sh` proves this with a fake cargo, a fake
sudo, a decoy binary in the shared target directory, and a fake test binary
that reports its arguments, its consent variable, and its pass count.

## Local evidence

These checks ran on macOS on 2026-11-05. They are local development evidence,
not a substitute for the CI run on the final release revision:

| Command | Result |
|---|---|
| `bash -n scripts/*.sh scripts/tests/*.sh` | No output, exit 0. |
| `sh scripts/release_audit.sh --require-aligned-versions` | Passed version and policy checks with 37 PASS lines. This checks source metadata, not the versions inside release artifacts. |
| `sh scripts/ci_graph_check.sh` | 16 jobs, no cycle, release reaches all. |
| `bash scripts/tests/release_pipeline_test.sh` | Passed. Covers graph and workflow-policy mutations, including quoted, spaced, flow-map, and explicit-key action references; quoted, spaced, flow-map, explicit, escaped, and `write-all` permission spellings; an additional workflow file; and comments that look like policy entries. Also covers missing or unlisted artifacts, malformed or duplicate manifest entries, path traversal, symlinks, a signed IPA, wrong Mach-O architecture and file type, and a tampered digest. |
| Repeat release-pipeline fixtures, 2026-11-05 20:29 UTC | Passed locally. The audit, graph, manifest, and fixture scripts had matching SHA-256 hashes before and after the run. The one-line log is `/tmp/hs-release-fixtures.log`, SHA-256 `f1544765a2082fd34d8fd1c130653b5c1fe29f9e10bfed457ae58d66cc743373`. This does not prove that other inputs stayed unchanged, close the scanner review findings, or establish a CI pass. |
| `cd linux && npm test` on macOS | 197 passed and 2 skipped. The real-engine contract needed `HOTSPOTSHADE_BIN`; the package-mode check needed `dpkg-deb`. Fake-process tests do not establish a real polkit session, route cleanup, or a live tunnel. |
| `bash scripts/tests/linux_vm_test_test.sh` | Passed. Lifecycle cases plus the tunnel harness cases. |
| `ruby -ryaml -e ...` on `ci.yml` | 16 jobs, `release` has 15 needs. |
| Release gate rehearsal on a fake artifact set | `release_manifest.sh` wrote the record, the audit passed 48 checks with the tag, and `release_manifest.sh --verify` verified 4 files. Re-ran after the policy scan change. |
| Artifact checks on files from CI run 42025303930, commit `1a37ed7` | The downloaded macOS arm64 binary and unsigned IPA passed their checks on macOS and Linux. The downloaded macOS app zip passed the archive and ad hoc signature checks on macOS. A locally assembled set passed the non-strict tagged audit and complete-set checksum verification. These artifacts predate the current working tree. |
| Windows portable model runner in a Linux .NET 8 SDK container | 98 checks passed on a 58-file source snapshot from the 2026-11-05 working tree. At 20:21 UTC the live non-ignored file list and hashes matched the snapshot; this does not prove later edits match. The [snapshot manifest](WINDOWS_MODEL_EVIDENCE_2026-11-05.sha256) SHA-256 is `f19617ef788891f3ae719c2d7d33cb4979ba0da683e7291456608b44f8d0e672`; the test log is `/tmp/hs-win-model.JHpDiliW/test.log`, SHA-256 `aee5deed3b524e4aa3f481dd133cc51c94cbd6e38840722edea71d4919ebf9ff`. Image digest: `sha256:6ba9644da07bb5b560a402acec9ca38711a0762969f1b61da261df5c9f6f85da`. The image was downloaded and package restore had network access. The compiler emitted an unused-field warning in `EngineTests.cs`. This does not build or run the WinUI app, exercise Windows APIs, or verify a tunnel. |

Not run: GitHub Actions for the new graph, because these changes have not been
pushed. No release tag, device, hotspot, carrier, or VM test was used for this
change. Version alignment alone does not establish that a tagged release or its
artifacts are ready to publish.

## Residual blockers

1. **No signing or notarization.** The IPA is unsigned. The macOS app is ad hoc
   signed and not notarized. There is no Developer ID, no Windows signing, no
   release-signed APK, and no signed Linux package or repository. A person must
   sign the IPA with their own certificate. This blocks a production claim.
2. **No cryptographic provenance.** `PROVENANCE.txt` and `SHA256SUMS` record
   the inputs and detect a changed file. They are not a SLSA attestation and
   they are not signed. GitHub artifact attestations
   (`actions/attest-build-provenance` with `id-token: write` and
   `attestations: write`) are not enabled.
3. **Action updates need review.** The audit requires a full 40-character
   commit pin for every `uses` reference and rejects a YAML spelling it cannot
   read. A commit pin keeps a reference immutable; it does not establish that
   the action code or its downloaded dependencies have been independently
   reviewed. Check upstream releases and update the pins deliberately.
4. **Strict artifact version verification blocks release.** Source metadata
   aligns at 0.1.0 (Windows uses a fourth numeric component). The artifact
   audit reads XML plists and uses `plutil` for binary plists when available;
   it refuses an unreadable version in strict mode. The standalone binary has
   no verifiable in-band version, and Ubuntu does not provide the binary-plist
   reader needed for the IPA. A reviewed portable reader and a verifiable
   binary version are needed before the tagged release can pass. These checks
   do not prove that an artifact runs or is signed by a release authority.
5. **No upgrade or rollback tooling.** There is no update feed, no automatic
   update, and no rollback command on any platform. Android rejects a lower
   `versionCode` without a separate downgrade procedure; a compatible older
   build may instead retain and read legacy preferences. Uninstalling removes
   app data, including its token and trust. The downgrade policy is unresolved.
   An iOS free profile expires after seven days.
6. **Two target apps cannot ship.** The Linux `.deb` is not in the release set
   and its packaged app has not been shown to start a tunnel. The Windows app
   is a simulated preview with no installer. The current Windows engine also
   refuses source-device token use. Adapter and gateway checks do not
   authenticate the source device: v1 sends a reusable token in cleartext.
   Source authentication and compatibility policy remain unresolved, as do
   the required Windows path checks. No Windows artifact is published.
7. **Required checks and environment protection are not configured.** Branch
   protection must require the fifteen job names in
   [CI_PIPELINE.md](CI_PIPELINE.md). The `release` environment must be
   configured with required reviewers and a tag rule. Neither is a repository
   file, so neither is in this change.
8. **Security repairs and integration evidence are incomplete.** Independent
   reviews found unresolved Android pairing concurrency and persistence issues,
   a macOS helper crash window, and Windows control-handle and route-proof
   gaps. A later macOS exclusion review found that an engine can exit zero
   after route cleanup fails, which can cause the helper to clear its durable
   intent; direct starts also lacked a durable start record. The working tree
   now reports uncertain cleanup and records direct starts, but those changes
   still need independent review and live cross-binary validation. A later
   installer service-transaction review found ambiguous bootstrap ownership,
   rollback and journal-ordering defects, and missing live trust and durability
   checks. Repairs are in progress; installation remains disabled. The Windows
   service-host review found unsafe overlapped I/O lifetime, failed-revert
   handling, premature Running status, and a dropped stop after timeout. The
   service host is unintegrated and must not be enabled on those test results.
   The Windows direct-mode route proof is not connected to a production start
   path, and the Windows link observer remains disabled pending validation.
   The Linux helper and route recovery also need final integration review.
   No signed macOS helper install, real polkit session, or live Windows tunnel
   has been verified. The release matrix has no verified cell for the current
   build. A later review found that Android trust-store writes can change the
   in-memory preferences even when disk commit fails, and that iOS migration
   and rotation rollback can alter a different concurrent Keychain writer's
   item. iOS rotation is now disabled pending a reviewed protocol; staged
   recovery tests do not prove crash durability or exclude external writers.
   Repairs are in progress and require independent review.
   An unsigned iOS 27.2 Simulator build showed a token storage problem and its
   Keychain marker read returned missing entitlement `-34018`. A separately
   identified Debug build with simulator signing enabled showed token controls
   enabled. That comparison supports a signing-related explanation but also
   changes the Keychain identity, so it does not isolate signing as the cause.
   The original installation was preserved and not retested with the signed
   build; credential recovery and physical-device validation remain open.
   An independent review of the iOS credential recovery snapshot found that a
   pending recovery marker could leave the app unable to load or repair even a
   valid token, and that an invalid Keychain item with a valid legacy copy had
   no implemented restore path despite user documentation saying otherwise.
   It also found unresolved cleanup, lifecycle concurrency, and external-writer
   windows. Repairs and a fresh review are required; passing host tests alone
   do not establish recoverability or Keychain crash and backup behavior.
9. **Pairing and credential recovery have unresolved trust limits.** Pairing
   v1 does not authenticate the source device to the target device, and its
   remote FORGET reply cannot prove trust was removed. A peer at the pairing
   endpoint can produce a protected status and advertise a proxy port. A
   local wait for FORGET or a pairing cancellation also cannot order a delayed
   request against a later trust change on the source device. A target-side forget
   clears local credentials; remove trust on the source device when verified
   removal is needed. On Android, a failed legacy-token deletion followed by a
   corrupt or missing newer token can reactivate an older token. Existing
   legacy-only files do not record whether they were superseded. The current
   save path writes a supersession marker before a later token replacement to
   prevent future fallback to a stale legacy copy. It cannot reconstruct old
   history, and target rename durability still has limits. The marker repair
   passed JVM tests and lint, but independent review found that a transient
   legacy read could strand the token and that an unsynced target rename could
   undo a rotation or lose the only copy after power loss. The current repair
   syncs the target directory and treats an uncertain replacement as requiring
   a reload. Follow-up reviews found dangling-symlink and alias cases. The
   current code checks paths from the app data directory, rejects symlinks and
   parent traversal in the checked paths, and has host JVM regression tests.
   These checks are not descriptor-relative and assume one process owns the
   app-private paths. The latest traversal fix still needs independent review.
   Android filesystem and power-loss validation remain open; see [the Android
   token notes](../android/README.md).
   The current Android trust-store revision blocks nonempty legacy lists until
   reset, and makes stored keys pending confirmation after each app process
   restart. Until a target is paired and approved again, status and remote
   forget are rejected as well. Reset discards the new store's trust, while an
   older build may still read the untouched legacy list. The selected upgrade
   policy requires reset and re-pairing for a nonempty legacy list; downgrade
   handling remains unresolved. An approved pairing whose response is
   lost can also remain trusted while the source process runs; restart
   confirmation does not resolve that delivery ambiguity. Review of the
   Android listener and Settings repairs also found a prompt ownership race
   during startup and a way to queue repeated trust mutations. Further repair
   and independent review are in progress. These behaviors need a protocol
   or product decision where applicable, and device validation.
10. **Outer-interface and DNS repairs need integration review.** Review found
    that IPv4-mapped addresses could bypass IPv4 validation or socket auditing,
    and that a renamed bridge or veth could pass Linux interface checks. The
    current changes normalize mapped egress and add shared Linux link evidence
    and identity checks. Review found that public normalization helpers still
    accept mapped addresses and a public SOCKS constructor permits a resolver
    on a different interface; repairs are in progress. Linux startup ordering,
    recovery interactions, cleanup failures, and compatibility with real
    hotspot interfaces still need complete integration evidence.

## What this page does not claim

- It does not claim that HotspotShade is production ready.
- It does not claim that any artifact is signed, notarized, or trusted by an
  operating system.
- It does not claim that a build, a hermetic test, or a VM run proves carrier,
  hotspot, or physical-device behavior.
- It does not claim that the CI graph ran on GitHub for this change. The
  evidence above is local.
