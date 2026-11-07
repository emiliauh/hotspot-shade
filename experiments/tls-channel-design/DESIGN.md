# Authenticated encrypted channel and first-pairing bootstrap

Status: UNAPPROVED. Revision 13. Design only.

This is a design draft, not a protocol requirement, and not a security result.

Revision 9 answers the independent review `d6f2ff01-4669-466c-bded-ce1012a3e470`,
which returned NOT APPROVED against revision 8 with two blockers, six medium
findings, and six low findings. The full review text was available for this
revision, so section 2.0 maps each finding from that text, labelled R8-B1 and
R8-B2, R8-M1 to R8-M6, and R8-L1 to R8-L6. The review did not confirm the
revision-8 mapping against `50f21843`, because it did not read that review, so
section 31 item 1 stays open. The revision-8 introduction follows unchanged as
the record of that revision.

The independent review with task id `50f21843-f0b1-4e95-b063-4f1c686bfcf7`
returned NOT APPROVED against revision 7. That review supplied the complete M8
and M9 text, which revision 7 did not have. This revision answers M8 and M9 and
keeps the revision-6 record for B1 to B6 and M1 to M7. The reviewer must confirm
that the mapping matches the review. The six revision-6 blockers are grouped
here as B1 to B6:

- B1. The bootstrap acknowledgement `HSACK1` was written to descriptor 4, which
  the launcher does not open for writing on macOS and Windows.
- B2. The Linux launcher created both secrets and returned one to the app over an
  extra inherited descriptor, and that descriptor was never verified.
- B3. The design cleared the app-wide API bearer and pairing capability on
  window close and screen lock, which breaks a tray session or a running tunnel.
- B4. Source local revocation was not atomic with session registration and
  assumed a TCP idle bound that does not exist for an open relay.
- B5. A valid attacker can occupy the single prompt and exhaust the source
  arming, and the text claimed the arming could not be exhausted.
- B6. The design did not list the token-only proxy and diagnostic paths that
  exist today on macOS, Linux, and Windows, so the cost of P2 was understated.

The review names nine medium findings, M1 to M9. M1 to M7 are the revision-6
record in section 2.1.1. M8 and M9 are answered in section 2.1, with the M9
parts labelled M9.1 to M9.12 so a test row can name the exact part it covers.
Section 2.1 lists each M8 and M9 item, the change in this revision, and what
remains open. The first revision-8 pass was interrupted before it was
consistent. Section 2.1.2 records the completion pass: eight places where the
first pass still contradicted itself, the repository, or the rustls source, and
the correction for each. Section 2.1.1 keeps the revision-6 record, section 2.2 the
revision-5 record, section 2.3 the revision-4 record, section 2.4 the
revision-3 record, section 2.5 the revision-2 record, and section 2.6 the
verified facts.

This revision answers the review on paper only. No production code and no
protocol code were written for it. No device, route, tunnel, network, or
emulator was used. No test was run. No Python was used.

Scope of this revision: `DESIGN.md` and `TEST_MATRIX.md` only. Other changes in a
shared working tree belong to other tasks and are not part of this revision.

Do not implement this design, do not ship it, and do not treat any statement
here as a security result. A new independent review must accept or reject this
revision before implementation. The explicit review gate is in `TEST_MATRIX.md`.

This revision does not claim a security proof. Where a platform behavior is
documented but untested, the text says so. Where a platform cannot provide a
required property, the text says which mode is not approved instead of defining
a weaker profile. Four live gates remain open: cross-stack exporter equality,
the Android vendor Keystore `DIGEST_NONE` path, the Android 16 KB runtime, and
the iOS lifecycle. They are not presented as measured.

Direct verification: where a claim could be checked against a primary source,
section 2.6 records the source and the result. A source reading is not a device
test. Section 2.6 separates verified facts from remaining unknowns. The test
matrix in `TEST_MATRIX.md` names the device rows that would turn an unknown into
evidence.


## Revision 13 review disposition

Independent review `f85c9263-fe81-425e-9a32-eb34bfbf3ed5` returned NOT
APPROVED against revision 12. This revision corrects selected local-removal
claims and historical matrix rows, and clarifies the release review reference.
It does not claim to dispose of every finding in that review. Its remaining
findings, the missing incarnation and recovery protocol, product choices, and
all feasibility gates remain open. A fresh independent review is required.

## Revision 12 review disposition

Independent review of revision 11 returned NOT APPROVED. The cross-device
incarnation protocol, local revocation durability, per-host crash recovery and
migration timer model remain incomplete. The separate [incarnation candidate review](INCARNATION_REVIEW_NOTES.md) is NOT APPROVED. It is a critique, not an accepted protocol or a product decision.
This revision corrects the trace and gates only. It grants no implementation
approval and makes no product decision. A fresh independent review is required.

Trace of revision 11 review findings: cross-device ordering requires an incarnation
protocol (W17-W19); uncertain local writes and revocation need per-host commit
and recovery (W20); v1/v2 status isolation needs a timer model (W21-W22);
store-key provisioning and loss need per-host review (W23). Historical success
procedures do not close these findings. The review identifier and full text are
not recorded here; do not infer a finding-by-finding mapping beyond this trace.

Candidate review and release are separate gates: a complete specification and
its feasibility must first pass independent review before protocol implementation
or device tests. Product choices and their timing, including coexistence and any
hard v1 cutover, are separate and remain undecided. Release additionally requires product decisions, implementation,
host and authorized device evidence, and the remaining release gates in the
matrix. Review acceptance alone is not a release decision.

Earlier numbered review dispositions below are historical records. Their assertions
of unconditional durable removal and pin-only success are superseded by the
revision 10 and 12 gates, including W17-W20.

## Revision 11 review disposition

The independent revision 10 review identified operational contradictions in the
release gate, historical procedures, durability outcomes, sweep scope, and v2
status tests. This revision corrects those locations. It does not approve a
protocol or make a product decision. Independent re-review is required.

A candidate design should issue a non-reused incarnation at the source and bind
it to both pins and the authenticated ceremony transcript. Each durable record,
commit, removal request and result must name it. Source commits and removals
must compare the expected incarnation under the source store lock; the target
must compare it under its own store lock before promotion or deletion. A durable
revocation marker must survive restart and prevent reuse. A future specification
must define issuance, message encoding and authentication, exact state machines,
concurrent ceremonies, conditional writes, tombstone retention and exhaustion,
rollback and anchor loss, and every crash and retry boundary. It must also prove
that each host can provide the required atomicity and persistence. These are
requirements for a candidate, not a completed protocol or proof of distributed
ordering. W17 to W20 test its eventual reviewable claims; W21 and W22 cover
migration status isolation.

## Revision 10 blocking corrections and precedence

The revision 9 review found that the wire protocol does not establish ordering
between devices. This is an **unsolved implementation gate**. Pin matching,
local store generations, local epochs, exporter binding, and request IDs do not
identify a particular pairing incarnation across devices. In particular, an old
FORGET can remove a new same-pin pairing, a delayed OK can remove the target's
new record, and an old PAIR_DONE can race revocation or re-pair. All wire
layouts, vectors, recovery tables, and claims of safe remote removal or
re-pair below are provisional, including sections 9, 13, 14, and 18. They
cannot authorize implementation or establish these properties. This gate takes
precedence over earlier dispositions and their claimed fixes.

A future revision must specify and review a source-issued, non-reused record
incarnation bound cryptographically to both pins, the ceremony, every commit,
FORGET request and result, and the target's durable record. It must define
persistent tombstones, anti-rollback and exhaustion, source commit checks against
concurrent deletion and re-pair, target conditional acceptance under its own
store lock, and lock ordering and failure atomicity on each device. It must
cover crashes before and after each durable write, delayed requests and replies,
restarts, retries, re-pair, tombstone retention and recovery when a store or
anchor is lost or uncertain. No local epoch or bounded in-memory tombstone is
that cross-device mechanism. Until a complete protocol and recovery model pass
independent review, remote FORGET, record replacement, re-pair and pairing
commit ordering are not approved for implementation. Tests W17 to W22 are
requirements for that future design, not evidence that it exists.

Migration is also gated. The timer state machine and expiry semantics remain
unspecified and require a reviewed design. Untrusted, stale, wrong-pin or v1
status must not start, reset, suppress or trigger v2 auto-stop, including at
expiry. A v2 target must exclude v1 discovery and status from
v2 presence, auto-stop timers, trust, and endpoint updates. Only an authenticated
v2 source proving the selected source pin on the current session may refresh
presence or propose a port; the target validates and atomically associates an
accepted port with that same record and incarnation. A forged v1 status or a
status from another pin changes nothing. Unknown, unauthenticated, stale, or
ambiguous updates fail without a fallback or silent downgrade. Legacy records
and v1-only peers require an explicit new pairing after a reviewed migration;
never interpret a v1 record as v2 trust. Coexistence and any source v1
mitigation remain product and implementation decisions, not approved work.

All existing product choices and platform/host gates remain open. The review
mapping below is historical; corrections in this section and the matrix govern
where an earlier disposition claims a change that was incomplete. No new product
decision is made. Independent review of both documents is required again.

## 1. Summary of the change

The channel now requires a TLS exporter channel binding on every pairing and
trust-change transcript. The binding is computed on the live session, so a
transcript computed on any other session does not verify. This removes the
previous "no channel binding" statement and the two-profile outcome it created.

The bootstrap now carries a mechanism discriminator and requires local arming on
both devices. A session cannot switch mechanism in either direction, so an
attacker cannot force a QR session to fall back to a short numeric code, and a
source cannot accept a pairing attempt that nobody armed. The target consumes its
arming when it sends `PAIR_HELLO` (TD1), so it can send only one hello per
ceremony. Consuming the arming does not end the target ceremony: the QR secret,
the session handle, and the SAS code that the hello leads to stay alive until a
ceremony-end event, TD2 to TD10 or the session outcomes TE1 and TE2. The source
does not consume arming on an unauthenticated hello. Section 4.2 lists the
complete sets, SD1 to SD10 for the source, TD1 for target arming consumption, and
TD2 to TD10 with TE1 and TE2 for the target ceremony end, and every other section
refers to those labels instead of repeating a shorter list. In short, the source
keeps the person's armed state until success, explicit cancel or back navigation,
expiry, app background, screen lock, a mechanism change, the end of the one QR
session that sent a proof, the third failed SAS attempt, a source app process
exit, or the pairing listener closing. A source person's Deny in SAS is one
failed attempt, not a cancel. A QR secret serves exactly one session that reaches
a proof, even when that proof fails. Section 4.2 defines the scan order, the
retry budget, and the prompt deadline inside the arming window.

The arming budget is not a guarantee. A peer that can open a well-formed SAS
session and reach a verified reveal can occupy the single prompt and spend one
of the three attempts. A hotspot peer cannot burn a scanned QR secret: the
source refuses, before `PAIR_READY` and without consuming arming, a hello whose
`pairing_id` or target certificate pin does not match the scanned payload. Only
a peer that proves the target's key can reach a QR proof. A peer that answers the
target's dial in place of the source can end the target's QR ceremony instead.
These are real denials of one ceremony attempt, bounded by the 120 second
window and the existing rate limits, and this revision states them instead of
claiming that the arming cannot be exhausted. Section 4.3 and section 24. A SAS
attacker who never reveals a verifiable nonce cannot spend an attempt, but can
still hold the prompt slot until its deadline. Whether SAS ships at all stays a
product choice, Q1 and P3.

Half-close is specified as an explicit framed data phase, because the platform
TLS APIs do not expose a portable one-way `close_notify`. A clean inner FIN is a
`FIN` frame. A TLS close without a prior `FIN` is truncation. The slow download
keeps flowing because the peer that sent `FIN` keeps reading until it receives
the other `FIN`, within the source session idle bound in section 15.2. The design
does not claim that an abort produces a TCP RST on every platform. The decisive
rule is that a close without a `FIN` frame is truncation at the receiver, and the
per-platform reset behaviour is a device row.

The pin store becomes a set of records with a store-wide generation and a
separate anchor, an explicit local replace action, and honest per-platform
integrity claims. The known path is check-only under one lock with a fresh
recheck immediately before credentials are issued. FORGET is reframed around
the authenticated server pin, request identity, and idempotent framing. A source
local removal is not vetoed by a live flow; durable success requires a reviewed
commit and recovery model. Local
removal and an accepted remote FORGET run one removal procedure. Registration and
removal each hold the store lock for their whole step, and registration rechecks
the store, but a pin-only check cannot distinguish a same-pin re-pair. A remote FORGET
checks for a live session of that pin under the session-table lock inside the
same store-lock hold, and returns `DENIED` with no write if one exists. A local
removal closes the matching sessions by force instead of waiting for an idle
timer. An open relay has no idle bound, so the design does not rely on one. The
source also keeps one revocation epoch per authenticated client pin and a
per-session index by that pin. While both steps hold the store lock, the epoch
is a redundant second check and adds no protection of its own. A removal of one
source never aborts a concurrent session for another source. Section 14.1 and
section 18.2.

Pairing display and consent move to a native target app actor. The **target app**
creates one per-launch API bearer and one per-launch **pairing capability** (PC),
separate from each other, and sends them to the engine through the privileged
helper on the existing app-to-helper request. A launcher with no helper, the
macOS demo launcher and the Linux development launcher, writes the frame itself.
The engine receives them on inherited descriptor 3, selected by the non-secret
argument `--bootstrap-fd 3`, in a fixed versioned binary frame that holds exactly
32 raw bytes per secret, and writes nothing back on any descriptor. Descriptor 3
is the read end of a pipe, or a socket whose write half the engine shuts down
before it reads; the kernel enforces the direction only for a pipe. Today every
launcher passes `--token-fd 3`; the design replaces that argument, it does not
reinterpret it. There is no bootstrap acknowledgement. Readiness
is observed from the existing process signals: the helper's fixed status lines on
Linux and the authenticated XPC reply on macOS. The PC is required for arm, code,
allow, deny, cancel, and QR create, read, and clear. The browser GUI holds no
credential and has no pairing surface: it shows status, diagnostics, and failures
only. QR and SAS are target-app-only. The engine renders no QR and returns no QR
payload to any page. Section 11.4 states the per-platform channel and the
authorization matrix. The Windows target and a headless target have no PC, so QR,
SAS, and new-device pairing are unavailable there unless a console actor is
designed. That is a gated product decision, P2 and P22.

The target keeps an in-memory credential map keyed by `(peer_role, pin)`. The
host, port, and token issued for one source are used only with that source's
pin. `PAIR_RESULT` host and port are the source listener's own bound settings,
never a value taken from the client or from an earlier record. The host field has
one canonical encoding, ASCII dotted-quad IPv4 with no leading zeros, and the
receiver compares it to the canonical rendering of the address it actually
connected to. A non-canonical value is a protocol error. Section 7.11.1 and
QV19.

Several paired sources may share one hotspot gateway address and one proxy port.
The target therefore builds a candidate set from that endpoint, verifies the
server certificate against the candidate pins, and only then associates the exact
record and token. It never sends one candidate's token to another candidate's
pin. A nonmatch is not proof that the source identity changed, even when the
candidate set has one entry: another paired source can sit at the same endpoint,
and a replaced source is indistinguishable from a different device. The target
shows one neutral message for every candidate count, names no record, offers no
forget action, and deletes nothing. Section 7.11.

The credential map is memory only, so a target restart loses every token. A
target that has a confirmed record but no token must run the known path before
its first proxy connection, and that needs the source device app open and in the
foreground on iOS and Android. The target start therefore fails with one fixed
message that names the source app, and it does not retry on a timer. Section
7.10.1.

Pairing becomes mandatory for proxy mode, so this revision lists every token-only
path that exists today, including the scoped diagnostics that change no route.
Section 23.1. A person who uses one of those paths today loses it unless a
protected target actor or a console actor exists. That is the true cost of P2,
and it is larger than the previous revision stated. The authorization matrix
also removes the unauthenticated browser control surface of a Unix GUI started
by hand as a non-root user: its routes accept no credential today, although its
tunnel start already fails for lack of root. Section 23.1 lists that loss as
well. The token sources differ by
command and platform. On macOS and Linux, `tun --phone` and `phone` read
`--secrets-fd N`, then `HOTSPOTSHADE_PHONE_TOKEN`, then a no-echo prompt on
`/dev/tty`; the two diagnostics read `--secrets-fd N` or the prompt and never the
environment. On Windows only `tun --phone` exists among these commands; it reads
`HOTSPOTSHADE_PHONE_TOKEN`, then a no-echo console prompt, and refuses
`--secrets-fd`. The environment form is a compatibility path on all three
platforms and is planned for removal.

Android keeps `minSdk 26`. Section 6.4 records why the platform `SSLSocket`
cannot carry this profile below API 31 and why the source app uses the bundled
Conscrypt provider instead. The Conscrypt provider is checked before the
handshake, not after it starts. No platform support is changed silently.

## 2. Review disposition

### 2.0 Revision-8 review

The independent review `d6f2ff01-4669-466c-bded-ce1012a3e470` returned NOT
APPROVED against revision 8. Its text was available for this revision, so each
row below names a finding as the review states it. The labels R8-B1, R8-B2,
R8-M1 to R8-M6, and R8-L1 to R8-L6 are this document's labels, in the review's
order. An open item is not a fix. Every change is on paper only.

| Finding | Change in this revision | Still open |
|---|---|---|
| R8-B1. TD1 contradicts the ceremony lifetime. Section 4.2 said the first `PAIR_HELLO` send disarms the target, and section 11.4.3 tied the SAS code and the QR secret to the armed ceremony, which ended at any of TD1 to TD10. Read literally, the hello destroyed the QR secret before `proof_source` could be checked, and the SAS code, computed after the hello, could never be shown. V6 asserted the broken behaviour. | Section 4.2 separates two states. **Target arming** is the permission to send one hello. TD1, the first hello send, consumes it, and nothing else does. The **target ceremony** is the session handle, the engine's QR secret, the SAS code, and the Allow prompt. It ends at TD2 to TD10, or at the session outcomes TE1 (completion) and TE2 (any failure after the hello: a Deny on either device, a protocol error, an exporter failure, a failed proof, a prompt timeout, or a transport close). TD1 does not end the ceremony. Section 11.4.3 ties the SAS code and the engine's QR secret to the ceremony, not to the arming. At TD1 the app stops displaying the QR payload and destroys its display copy, because the scan has already happened; the engine keeps the secret until the ceremony ends. Section 11.3, section 11.4.5, section 11.4.6, section 20, V6, and V22 follow. | W1 and W2. The UI wording for the state between Continue and the Allow prompt is part of P15 and P23. |
| R8-B2. Remote FORGET reopened B4. Section 14.1's epoch bump and sweep were written for local removal only. Section 18.2's remote path deleted the record, released the lock, and replied, with no epoch bump and no sweep. The live-flow refusal was "refuses" in one place and "may return `DENIED`" in another, and it was not said to run in the same store-lock section as the delete. | Section 14.1 now defines one removal procedure for both origins. A remote FORGET takes the store lock, runs the section 18.2 recheck, takes the session-table lock, and checks for a registered session with that client pin. If one exists, it releases both locks and replies `DENIED`, with no write, no generation change, and no epoch bump. Otherwise it deletes durably, bumps the generation and that pin's epoch, and runs the same sweep, all inside the one store-lock hold. Registration also holds the store lock for its whole step, so no session can register between the check and the delete, and a session that reaches registration later fails the store recheck. The remote sweep is therefore empty by construction; a non-empty remote sweep is a counted defect. `DENIED` is mandatory, never "may". Section 16, section 18, section 18.2, section 18.5, section 24, section 25, and P5 use the same rule. | W3 to W5, and F28 as corrected. |
| R8-M1. Section 11.3 still started the QR deadline when the QR is displayed, against section 4.2.1 and section 11.4.6. | The earlier disposition claimed section 11.3 was corrected; revision 10 corrects it to `qr_deadline = min(created_at + 120 s, arm_deadline)`. | W6. |
| R8-M2. The read-only descriptor claim is not true of the current code. The Linux helper builds descriptor 3 with `UnixStream::pair()` (`linux/helper/src/main.rs`), and the Linux development launcher uses Node `stdio: 'pipe'` (`linux/src/backend/engine-client.js`), which libuv creates as a socket pair. `fcntl(F_GETFL)` reports read-write for a socket, so L28 could not enforce the direction. | A reading of the code confirms the finding. The macOS launchers, `RootEngineLauncher.swift` and `BackendProcess.swift`, use `pipe()` and pass the read end, so `F_GETFL` reports `O_RDONLY` there. Section 11.4.1 rule 1 now accepts two descriptor types and refuses every other. A pipe read end must report `O_RDONLY`. A socket is accepted only after the engine calls `shutdown(fd, SHUT_WR)` on it, before any read; a failed shutdown is code `9`. A regular file, a terminal, a character device, a pipe write end, and a FIFO opened read-write are code `9`. The Linux helper must move to `pipe2(O_CLOEXEC)`; the Node development launcher keeps its socket. The text no longer says that the engine end is read-only on every launcher. The kernel enforces direction only for a pipe; on a socket the shutdown is a self-restriction of the engine, which is honest about what it proves. | W7 and L28 as corrected. |
| R8-M3. Launchers with no helper were missing. Section 11.4.1 named `BackendProcess.swift`, the macOS demo launcher with no helper, as a launcher to change, and neither it nor the Linux `--engine` development path said who writes the frame or whether demo mode gets a PC. | Section 11.4.1 and section 11.4.2 add the two launchers with no helper. The app is the creator and the writer: it creates the secrets, creates descriptor 3, writes the frame, and closes its end. macOS `BackendProcess.swift` starts the bundled engine as the signed-in user for demo mode; the Linux development launcher starts the engine named by `--engine` or `HOTSPOTSHADE_ENGINE`, with or without engine demo mode. A demo launch from the app gets a bearer and a PC, so the native pairing surface can be reviewed against the demo backend's simulated pairing. A demo PC authorizes only simulated routes, and the demo backend opens no pairing connection to a source. A `gui --demo` started by hand gets no frame, so its pairing routes return 401. The Linux development launcher is ignored by a packaged build, as today. | W8. Whether the shipped macOS app keeps a demo pairing surface is a product choice, P15. |
| R8-M4. The authorization matrix removed a working path that section 23.1 did not list: a non-root Unix GUI started by hand without `--token-fd` accepts start with no credential today (`rust/src/gui.rs`, `is_none_or`), and the matrix's "No credential: 401" removes that, including the direct-mode start. | Section 23.1 adds the row, read from the code. `gui_requires_token` in `rust/src/main.rs` requires a secret only on Windows or as root, so such a GUI has no bearer and every route passes the HTTP check. Its `POST /api/start` is accepted at the HTTP layer and then refused by the service for lack of privilege: `protected_helper_required` on macOS (`rust/src/gui_backend.rs`) and "tunnel requires administrator privileges" on Linux (`rust/src/service.rs`). So no tunnel, direct or proxy, starts from that path today. What it loses under the matrix is its unauthenticated browser control surface: v1 pairing, Forget, probe, stop, and the start request, which becomes 401 instead of a privilege error. Direct mode stays available through `sudo hotspotshade tun`, a root GUI with `--token-fd`, and the native target apps, so invariant 3 is not affected: the API bearer is a target-side launch secret, not a source device app. Section 11.4.4 states that an engine with no bearer has no state-changing route. P2 lists the loss. | W9. The reading of the code is not a run. |
| R8-M5. The claim that any peer can burn one QR attempt conflicted with the QR flow. Section 11.1 and section 11.2 have the source check `pairing_id` and the target certificate pin `pin_T` before any proof, and a wrong-payload hello does not consume arming, so only a peer holding the target's key could reach SD7. | The order is correct and the claim was wrong. Section 1, section 4.3, section 24, section 25, and P24 now say that a hotspot peer cannot burn a scanned QR secret. A hello whose `pairing_id` or target certificate pin does not match the scanned payload is refused before `PAIR_READY` and does not consume arming. Only a peer that presents the target certificate and proves its key with `CertificateVerify`, and sends the scanned `pairing_id`, reaches a QR proof: the real target, or a holder of the target identity key, which is the target-compromise bound. The remaining QR denial is on the target side: a peer that answers the target's dial in place of the source fails `proof_source` and ends the target ceremony (TE2), which costs a new QR and a new scan. Section 11.1 states that a pin mismatch does not consume source arming. | W10. |
| R8-M6. A source person's Deny was not mapped. It could be SD2, a full disarm, or a counted SD8 attempt, and the choice changes the three-attempt budget and rows C58 and U9. | Section 4.2 maps it to SD8: in SAS, a source person's Deny ends that session and counts as one failed attempt. The source stays armed for the rest of the window until the third failed attempt, which disarms it and starts the 30 second lockout. Cancel and back navigation stay SD2, a full disarm with no lockout. The reason: Deny judges one code, while Cancel withdraws consent. If Deny disarmed fully, one attacker session that shows a wrong code would cost the person a full re-arm, which is a cheaper denial than three attempts. A target person's Deny ends the target ceremony (TE2). In QR the source has no Allow prompt, so it has no source Deny; the scan is the source person's consent, and the target person's Allow or Deny decides. C58 and U9 follow. | W11. Whether the source UI should offer Deny and Cancel as two controls is part of P15. |
| R8-L1. Section 7.8 said section 20 bounds the store-lock hold, but section 20 had no row for it. Every proxy registration takes that lock inside the 5 second setup budget. | Section 20 adds a store-lock row: a proposed hold bound for a read-only step and for a step with a durable commit, and a wait bound for registration taken from the remaining setup budget. A registration that cannot take the lock in time aborts before its first application byte. A durable commit that overruns its bound is not interrupted; it is counted. All values are proposed and must be measured. | W12. |
| R8-L2. Exit codes `2` and `6` versus `10`. If the writer keeps the descriptor open, the parser could return `2` or `6` at the first wrong byte, or wait and return `10`, and the design did not say which. | Section 11.4.1 rule 3 now states that each step reads its full byte count or end of input and never decides early on a partial step. Codes `2`, `4`, and `5` depend only on bytes at fixed offsets and need no end of input. Success, code `3`, and code `6` with fewer than 7 trailing bytes need end of input. A writer that holds the descriptor open therefore produces `10` wherever a step needs more bytes or end of input. A fixture is the pair of its bytes and its close state, closed or held open, and has exactly one code. | W13, L29, and V13 as corrected. |
| R8-L3. V5 case 2 needs a custom server certificate setup. In rustls 0.23.46 `with_single_cert` runs `keys_match()`. | Verified in the local rustls 0.23.46 source: `ConfigBuilder::with_single_cert` builds the key with `CertifiedKey::from_der`, which calls `keys_match()` and returns an error for a known mismatch (`crypto/signer.rs`), while `CertifiedKey::new` does not check. V5 case 2 now builds a `CertifiedKey` with `CertifiedKey::new` and serves it from a test `ResolvesServerCert`. A source reading is not a test. | W14 and V5 as corrected. |
| R8-L4. E27 scope. Section 2.1 said "on each target", but E27 covers non-rustls stacks only, and every target stack is rustls, so E27 is empty today. | Section 7.11 and E27 now say so. Every target TLS client in this design is the Rust engine with rustls, which V5 covers. E27 has no case today and applies only if a non-rustls target client is added. The source stacks are TLS servers and do not send the client certificate. | E27 as corrected. |
| R8-L5. The per-pin epoch adds no protection today. Registration and removal each hold the store lock for their whole step, so safety comes from the lock and the store recheck, and section 7.8 overstated it. | Section 1, section 7.8, section 14.1, and section 20 now say that the store lock and the registration store recheck close the race, and that the epoch is a redundant second check while both steps hold the store lock. It is kept because it costs one map entry, it lets a session check its own pin at a message boundary, and it stays correct if a later change shortens the store-lock hold. It is not presented as the mechanism. | W15, and F35 and V7 as corrected. |
| R8-L6. "Proven on loopback" in section 16 sat beside "no test was run". | Section 16 now cites the evidence: the separate spike in `experiments/tls-transport-spike`, whose README records a passing `cargo test --locked` run of `tests/resumption.rs` on 2026-11-05 on macOS arm64 with rustls 0.23.46. This revision did not rerun it, and the spike uses its own configuration and ALPN, not this design's profile, so it is a host result for the spike only. | W16. |

The review's verified-correct list is kept as the reviewer's statement and is not
repeated here as a new claim. The open product and live gates the review lists
are unchanged: P2, P22, Q1, P3, P6, P15, P23, P17, P21, P19, Q18, Q28, the four
live gates, and the device rows E27 (if a non-rustls target client is added),
F38, L34 to L36, and U16.

### 2.1 Revision-7 review

The independent review `50f21843-f0b1-4e95-b063-4f1c686bfcf7` returned NOT
APPROVED against revision 7. It supplied M8 and M9 in full. M9 is one finding
with twelve separable parts, labelled M9.1 to M9.12 here so a test row can name
the exact part. An open item is not a fix.

| Finding | Change in this revision | Still open |
|---|---|---|
| M8. Any nonmatching candidate pin, even one, cannot prove that the source identity changed. Never advise forgetting a valid record. A shared gateway gets a neutral message. A rustls TLS 1.3 server rejection must prevent the client certificate, and the test must be mandatory and deterministic. | Section 7.11 replaces the two candidate-count messages with one neutral message for every nonmatch. A single nonmatch is not an identity change: another paired source can sit at the same endpoint, and a replaced source is indistinguishable from a different device. The target names no record, offers no forget action, and deletes nothing. Section 7.3 and section 14.4 use the same rule. Section 7.11 also states the TLS 1.3 order: the client verifies the server Certificate, CertificateVerify, and Finished before it emits its own Certificate, and a rustls server verifier error aborts before that emit. The client certificate resolver is called earlier, when CertificateRequest arrives, so a resolver call count is not evidence of disclosure. Evidence is a deterministic in-memory host test that counts what the server receives (`verify_client_cert` calls and a client Certificate message) and what the client key signs, and must observe zero of each on a rejected server. Section 2.1.2, fix 2. | The deterministic rustls test V5, and the stack-order row E27 on each target. A stack that cannot enforce the order records the client-certificate disclosure as a limitation and still sends no token. |
| M9.1. The summaries left out one failed QR proof, three failed SAS proofs, app background, screen lock, and a mechanism change. | Section 4.2 now holds the only complete disarm lists, labelled SD1 to SD10 for the source and TD1 to TD10 for the target. Section 1, section 4.2.1, section 8.2, section 11.4.3, section 20, and the test rows refer to those labels instead of repeating a shorter list. A QR secret is consumed by the first proof attempt even when that proof fails. Section 2.1.2, fix 3. | C5, C6, C52, C53, V6, and V22, one case per label. |
| M9.2. A global revocation epoch mismatch could abort an unrelated source session. | Section 14.1 replaces the global `revocation_epoch` with one epoch per authenticated client pin. A durable removal bumps only the removed pin's epoch. Registration reads and rechecks the epoch for its own pin, so removing source A cannot abort a concurrent registration for source B. Removed-pin entries are bounded tombstones and never re-admit a session, because the record is gone and registration rechecks the store. Section 18.2, section 20, section 24, section 31, and Q28 follow the per-pin rule. The section 20 budget row still described one global counter after the first pass; section 2.1.2, fix 4, corrects it. | F35 to F39, V7, and V23, including the two-pin race. |
| M9.3. The QV19 and U20 references, labels, and counts disagreed. | E29 now says seven rejected variants, matching U20 and QV19. QV19 is labelled the canonical-host vector and names U20 and E29 as its sources. The accepted length stays 7 to 15 bytes. | QV19, E29, U20, and V8. |
| M9.4. E26 and E31 contradicted each other and the candidate rule. | E26 and E31 now test the same neutral message for a shared gateway with no match, and E31 separately covers a single candidate with no match. Neither names an identity change and neither offers a forget action. U10 and V9 repeat the rule. | E26, E31, U10, and V9. |
| M9.5. The Windows `tun --phone` token path was written as `--secrets-fd`, which Windows refuses. | Section 23.1 now follows `rust/src/main.rs`. On macOS and Linux, `tun --phone` reads `--secrets-fd N` (a decimal inherited descriptor holding one JSON object `{"token":"..."}`), then `HOTSPOTSHADE_PHONE_TOKEN`, then a no-echo `/dev/tty` prompt. On Windows it reads `HOTSPOTSHADE_PHONE_TOKEN`, removes it from the process environment, then falls back to a no-echo console prompt, and refuses `--secrets-fd`. The first pass said the environment form was Windows only; it is not. The source token is never in argv. The environment form is a compatibility path on every platform and is scheduled for removal. Section 2.1.2, fix 6. | U11, V10, and V21. |
| M9.6. The diagnostics token source and the planned removal of the environment token were not stated. | Section 23.1 now follows the code: `phone-udp-diag` and `phone-speed-diag` exist on macOS and Linux only, read `--secrets-fd N` or a no-echo `/dev/tty` prompt, and never read the environment. On Windows both commands return the fixed "not implemented" error before any token source is read. The first pass gave Windows a diagnostics prompt and an environment token that do not exist. The `phone` command, a token-only local SOCKS forwarder on `127.0.0.1`, was missing from the inventory and is added. Section 2.1.2, fix 6. | U12, V11, and V21. |
| M9.7. The descriptor flags and numbers, and the difference between the binary frame and the hex request, were not defined. | Section 11.4.1 fixes the bootstrap descriptor at `3` (`HS_BOOTSTRAP_FD = 3`), selected only by the non-secret argument `--bootstrap-fd 3`, and states that descriptor 4 stays the parent liveness channel (`--parent-fd 4`). The bootstrap frame carries exactly 32 raw bytes per secret (`api_len = 32`, `pc_len` 0 or 32). The Linux `HS2` request carries 64 lowercase hex characters per secret, decoded before framing. The macOS XPC request carries raw 32-byte `Data`. The HTTP headers carry the 64 lowercase hex rendering. The legacy `--token-fd N` input is 64 lowercase hex characters and one newline, as the code reads it today; on Unix `N` is a descriptor number, on Windows an inherited handle value. `--secrets-fd` is not a `gui` option, so it cannot meet the frame. The first pass allowed `api_len` 32 to 64, which admitted a 64-byte ASCII hex bearer into the binary frame, had no selector argument, and described `--token-fd` as a 32 to 64 byte buffer. Section 2.1.2, fix 7. | L20, L24, L28, L32, QV20, V12, V19, and V20. |
| M9.8. The bootstrap exit codes did not distinguish the failure classes honestly. | Section 11.4.1 defines one parse order and one fixed engine exit code per class: `2` bad magic or a bare token, `3` truncated frame, `4` unsupported version, `5` invalid length, `6` trailing bytes, `7` a second frame, `8` `--bootstrap-fd` combined with `--token-fd`, `9` an unusable bootstrap descriptor, and `10` no end of input before the bootstrap deadline. The engine codes are not the helper's codes: the Linux helper already uses `7` for an abandoned request, so the helper reports any engine bootstrap failure as its existing engine-failed status and never forwards the engine number as its own. A launcher treats every non-zero code as a launch failure and never reads a reply byte. Section 2.1.2, fix 7. | L29, U3, U4, U18, QV20, V13, and V20. |
| M9.9. The PC and bearer matrix was not complete for every route family. | Section 11.4.4 states the rule for every row: a PC-only request to a start route is 401 with no change, a bearer-only request to a pairing route is 401 `pairing_requires_target_app` with no change, and neither credential is accepted from a query string, cookie, URL, page storage, or `Referer`. A credential from a previous launch, a short value, or a wrong value is 401 in constant time. Unknown routes are 404 and change nothing. | L37, U15, and V14. |
| M9.10. "The engine stops" did not distinguish a tunnel stop from an engine process exit. | Section 11.4.3 separates them. A tunnel stop ends routes and flows but keeps the launch, the bearer, the PC, and the target credential map. An engine process exit ends the launch and clears the bearer, the PC, and the credential map. App quit ends both. A crash is an engine exit. The next start in the same launch does not need the known path; the next launch does. | L34 to L36 and V15. |
| M9.11. The QR deadline was anchored to display time, so a late display could extend it. | Section 4.2.1 and section 11.4.6 anchor `qr_deadline` at secret creation: `qr_deadline = min(created_at + 120 s, arm_deadline)`. A late display does not extend it. The app shows the remaining time and refuses to display an expired payload. | C56 and V16. |
| M9.12. The store lock rule did not separate a network flush from a local durable flush. | Section 7.8 allows the store lock to cover the local durable commit in section 7.6 (`fsync`, `FlushFileBuffers`, `SecItemAdd`) because the read-modify-write and its commit are one bounded critical section. It forbids holding the lock across a network flush, a TLS write flush, a socket flush, or any call that waits on the peer. The session-table lock is never held across either kind of flush. | D33, R17, and V17. |

The review is answered on paper. It does not close the four live gates from
revision 5: cross-stack exporter equality, the vendor Keystore `DIGEST_NONE`
path, the Android 16 KB runtime, and the iOS lifecycle.

### 2.1.1 Revision-6 review

The sixth independent review returned NOT APPROVED. This table is the
revision-6 record and is kept unchanged except for the M8 and M9 row, which
revision 8 supersedes in section 2.1. An open item is not a fix. B1 to B6 are
the revision-6 blockers. M1 to M9 are the medium list as revision 7 recorded
it: six topics mapped to M1 to M6, an instruction to add adversarial rows
mapped to M7, and M8 and M9 whose text was supplied later.

| Finding | Change in this revision | Still open |
|---|---|---|
| B1. `HSACK1` wrote to descriptor 4, which the launcher does not open for writing on macOS and Windows. | The acknowledgement is removed, not patched. The bootstrap is one way: the engine reads a bounded frame from one inherited descriptor and never writes to any descriptor. Descriptor direction is part of the contract: the launcher holds the write end and closes it after the frame, and the engine holds a read-only end. Readiness comes from the signals that already exist, the helper's fixed `HS_READY` and `HS_PORT` lines on Linux and the authenticated XPC reply on macOS. A malformed frame makes the engine exit with a fixed status code, which the launcher sees as a process exit, not as a reply byte. Section 11.4.1. | The single-direction descriptor, the fixed exit codes, and the no-write rule need host rows L27 to L30. |
| B2. The Linux launcher created both secrets and returned one over an extra inherited descriptor that was never verified. | The **app** now creates both secrets on macOS and Linux. It sends them to the helper on the request channel that already exists: the authenticated XPC request on macOS, and the helper stdin request that already carries the launch secret on Linux, moving from the two-line `HS1` form to `HS2` with one line per secret. The helper forwards both to the engine on the bootstrap descriptor. The extra app secret pipe is removed. The XPC reply now carries the engine port, a launch id, and readiness only, because the app already holds both secrets. Section 11.4.2. | The request channel is not kernel-attested beyond the sender the operating system admitted: polkit for the Linux helper, and the audit-token check for the macOS helper. A same-user process that can write that request before `exec` is the same-user threat in M2, not a new channel. Rows L31 to L33. |
| B3. The design cleared the app-wide bearer and PC on window close and screen lock. | Credential lifetime is now separate from ceremony lifetime. The API bearer and the PC live for one launch and are cleared only when the app quits, the engine process exits, or the launch ends. Window close, tray hide, screen lock, and app background do not clear them, so a tray session and a running tunnel keep working. What ends on window hide, background, or screen lock is the **ceremony**: arming is cleared, the SAS code is hidden, and the QR secret is destroyed, because the person can no longer see them. Section 11.4.3. | The exact Linux tray and lock behavior, and the macOS lock behavior, need rows L34 to L36. |
| B4. Source local revocation was not atomic with session registration and assumed a TCP idle bound. | Section 14.1 adds one monotonic `revocation_epoch` per client pin and one session-table lock. Registration is one atomic step: store check, session-table lock, epoch recheck for that pin, insert. A removal bumps only the removed pin's epoch and sweeps the table under the same lock, so a session cannot register across the sweep for that pin, and another pin's session is not aborted. Live matching sessions are cancelled by force: the inner flow resets, the outer transport closes with no `FIN` frame, and the destination socket is closed abortively. The previous sentence that an orphan was bounded by its idle policy is removed, because an open TCP relay has no idle bound. Section 18.2. | Forced cancellation and the per-pin epoch require the rows F34 to F39 and V7. The wire result of the forced close is a device row, and the design does not depend on a RST. |
| B5. A valid attacker can occupy the prompt and exhaust the source arming, and the text claimed the arming could not be exhausted. | The claim is removed. Section 4.3 states the availability attack plainly: a peer that can open a well-formed session and reach a verified reveal can hold the one prompt slot and spend one of the three attempts, and only a peer proving the scanned target key and pairing id can reach a QR proof; a peer impersonating the source can instead end the target ceremony. The design bounds the damage with the 120 second window, one prompt, the rate limits, and the lockout, and it does not claim to prevent denial of one ceremony attempt. SAS stays a product choice, Q1 and P3, and this revision does not select it. | Whether SAS ships at all is Q1 and P3. The measured effect of the rate limits is a host and device row, C55 to C58. |
| B6. The design did not list the token-only proxy and diagnostic paths that exist today, so the cost of P2 was understated. | Section 23.1 inventories the current token-only paths on macOS, Linux, and Windows: the `tun --phone` proxy start, the GUI manual token field with `--token-fd`, and the two scoped diagnostics `phone-udp-diag` and `phone-speed-diag`, which change no route but do present the token. Under mandatory pairing each of them needs a paired record, so each becomes unavailable where no PC exists. The section states that plainly, keeps the demo path, and states that a headless target has no actor at all. | P2 must decide the scope: ship without those paths where no actor exists, or design the console actor first. Rows T5 to T7 and U11 to U14. |
| M1. There was no authorization matrix for the loopback API. | Section 11.4.4 adds one matrix over every route family and credential: none, API bearer, PC, and paired record. It states which combinations succeed, which return 401, and which change nothing. A pairing route never accepts the bearer alone and never accepts the token. | The matrix needs a host route test, L37 and U15. |
| M2. The same-user Linux attacker was not stated as a threat to the app-held secrets. | Section 24 states it: on Linux a process running as the signed-in user can read the Electron main process, so it can read the PC and the bearer, and `ptrace_scope` is a system setting this design does not control. On macOS the hardened app without `get-task-allow` resists a debugger attach, and a same-user process with the right entitlement can still read the engine's memory. On Windows a same-user process with `PROCESS_VM_READ` can read the app. The design claims the browser page boundary, not the same-user boundary. Section 25 repeats the limit. | A per-platform measurement of what the shipped app actually resists is a device row, U16. |
| M3. The `host` field had no canonical encoding and no vector. | Section 7.11.1 fixes it: ASCII dotted-quad IPv4, decimal, no leading zeros, no whitespace, no sign, no port, no brackets, no trailing dot. The receiver parses the value, rejects anything that is not the canonical rendering of the address it connected to, and stores bytes. An IPv6 hotspot listener is out of scope for this revision and a non-IPv4 value is refused. QV19 fixes the bytes. | The vector does not exist yet. It is host work, QV19 and E29. |
| M4. The target restart path did not say that the source app must be in the foreground. | Section 7.10.1 states the sequence after a target restart: record present, token absent, known path required, source app open and in the foreground on iOS and Android, one fixed message on failure, no timer retry. The source app being merely installed or backgrounded is not enough, and the target UI says so. | The messages and the failure state are rows E30 and U17. |
| M5. The legacy token descriptor and the bootstrap frame had no version rule and could be confused. | Section 11.4.1 defines one frame on one descriptor: `HSBOOT1`, version `0x01`, exact lengths, then end of input. The engine refuses an unknown version, a short or overlong frame, trailing bytes, and a frame that does not start with the magic. It never falls back to reading the same descriptor as a bare bearer. `--token-fd N` stays a separate legacy input for an API bearer only, is mutually exclusive with the bootstrap frame, and never supplies a PC. Section 11.4.1. | Host rows L29, L30, and U18. |
| M6. The arming TTL and the prompt TTL could disagree, so a prompt could outlive the arming. | Section 4.2.1 makes the prompt deadline subordinate: the ceremony ends at the earlier of the prompt deadline and the absolute arming deadline, and a prompt extension never moves the arming deadline. The QR display deadline is also capped by the arming deadline. A person who runs out mid-prompt re-arms; the design does not extend the window to keep a prompt alive. | The boundary rows are C55 to C57. |
| M7. Adversarial rows for the new blockers were missing. | `TEST_MATRIX.md` section U adds one or more adversarial rows for B1 to B6 and M1 to M6, plus the authorization matrix, the same-user reader, and the token-only paths. | The rows are proposed, not run. |
| M8, M9. Superseded by revision 8. | Revision 7 correctly did not invent these findings. Revision 8 answers the full text in section 2.1. The revision-6 record keeps the row so the history is not rewritten. | Section 2.1, rows V1 to V18, and the cross-references named there. |

The sixth review is answered on paper. It does not close the four live gates from
revision 5: cross-stack exporter equality, the vendor Keystore `DIGEST_NONE`
path, the Android 16 KB runtime, and the iOS lifecycle.

### 2.1.2 Completion pass for revision 8

The first revision-8 pass was interrupted. A reread against the repository and
the local rustls 0.23.46 source found the defects below. Each is corrected in
this revision, on paper only. None of them is a new review finding; each one is
a place where revision 8 did not yet do what section 2.1 said it did. The same
review must judge them.

| Fix | Defect in the first pass | Correction | Rows |
|---|---|---|---|
| 1. Pin mismatch text | Section 6.7 mapped every failed `CertificateVerify` to `not_trusted`, whose existing text is "The source device does not know this target device. Pair again." On the target that is a server that holds a pinned certificate but not its key, which is the same "no candidate proved its key" case as a pin nonmatch. Section 7.3 described replace as "remove the old record" without saying that the person must know the old source is gone. Row E28 said a nonmatch meant a "changed pin". | Section 6.7 rule 5 now splits by side: on the target a failed server `CertificateVerify` maps to the neutral nonmatch message, never to `not_trusted`. Section 14.4 states that `not_trusted` is used only after the server proved its pin and then refused the client certificate, and that it keeps the record and names no forget action. Section 7.3 states that a nonmatch, a failed `CertificateVerify`, a `not_trusted` alert, and a timeout are never evidence for step 1. E28 is reworded. | E15, E28, V1, V4, V9, V24 |
| 2. rustls order test | V5 required a counting `ResolvesClientCert` to observe zero calls. In rustls 0.23.46 `ExpectCertificateRequest::handle` calls `ClientAuthDetails::resolve` when CertificateRequest arrives, before `ExpectCertificateVerify::handle` calls `verify_server_cert` and `verify_tls13_signature`. The client Certificate is emitted later, in `ExpectFinished::handle`, after the server Finished is checked. A correct stack would therefore fail the first-pass test. | V5 now drives a rustls client and a rustls server over in-memory buffers with no socket. It asserts zero server `verify_client_cert` calls, no client Certificate message at the server, `peer_certificates()` absent at the server, and zero calls to the client key's `Signer::sign`. The resolver call count is recorded and is allowed to be one. A matching-pin control must show one of each. The test pins the rustls version in `Cargo.lock`, and an upgrade reruns it. A source reading is not a test; the test does not exist yet. Section 7.11 rule 3. | V5, E27 |
| 3. Disarm events | Section 1, section 4.2, section 11.4.3, and section 20 each listed a different subset. The section 4.2 table omitted back navigation, the bullet list omitted a mechanism change, and none listed a source app process exit, the pairing listener closing, a target window hide, or a target engine exit. | Section 4.2 holds the only complete lists, SD1 to SD10 and TD1 to TD10. Other sections refer to the labels. | C5, C6, C52, C53, V6, V22 |
| 4. Revocation epoch | Section 14.1 said each pin's epoch starts at 1 and that a pin with no entry has epoch 0. The section 20 budget row still described "one u64 ... incremented on every durable record removal", which is the global epoch that M9.2 removed. The tombstone budget was named but not sized. | A pin with no entry has epoch 0. The first removal of that pin creates the entry at 1. The section 20 row is a per-pin map with a fixed tombstone cap of 64 entries. No row and no sentence describes a shared counter. | F35 to F39, V7, V23 |
| 5. Matrix labels and references | Section 31 item 2 cited "U11 to U20" for the bootstrap, but U11 to U14 are the token-only paths and U19 and U20 are deadline and host rows. QV20 said all three vector suites produce it, but Kotlin has no bootstrap; the producers are Rust, the macOS Swift app, and the Linux Electron main process. L36 said "stopping the engine", which M9.10 separates into a tunnel stop and an engine process exit. L28 said a write-only descriptor "fails at open", but an inherited descriptor is not opened. | Section 31 cites the exact rows. QV20 names its producers. L36 says engine process exit. L28 checks the access mode with `fcntl(F_GETFL)` and exits with `9`. | L28, L36, QV20, V8 |
| 6. Token-only inventory | Section 23.1 said the environment token was Windows only and gave both diagnostics a Windows prompt and an environment token. `rust/src/main.rs` reads `HOTSPOTSHADE_PHONE_TOKEN` on macOS and Linux too, for `tun --phone` and `phone`. The diagnostics are `cfg(unix)`, read no environment variable, and on Windows return the fixed "not implemented" error. The `phone` command was missing. The GUI row did not say that only the browser page has a manual token field; the macOS and Linux native apps do not. | Section 23.1 is rewritten from the code, per command and per platform. | U11 to U14, V10, V11, V21 |
| 7. Bootstrap decoding | The frame allowed `api_len` 32 to 64, so a 64-byte ASCII hex bearer could enter a frame that is defined as binary. The engine had no way to know that descriptor 3 held a frame, while both launchers pass `--token-fd 3 --parent-fd 4` today. The legacy `--token-fd` was described as a 32 to 64 byte unwrapped buffer; the code reads exactly 64 lowercase hex characters and one newline. The HTTP header encoding of the bearer and the PC was not stated. The engine exit codes overlapped the Linux helper's own codes without a rule. | `api_len` is exactly 32. The non-secret argument `--bootstrap-fd 3` selects the frame. The legacy format is stated as the code reads it. Both headers carry 64 lowercase hex characters compared in constant time against the rendering of the raw value. Codes `9` and `10` are added, and the helper never forwards an engine code as its own. | L20, L28 to L30, QV20, V12, V13, V19, V20 |
| 8. Same-file contradictions | The section 1 summary and section 11.4.1 rule 8 still described the environment token as Windows only. | Both now match section 23.1. | V21 |

### 2.2 Revision-5 review

The fifth independent review returned NOT APPROVED. The review task is
`9f1414bc-feb0-4f69-8e48-d3b49b2a4616`; its text was also unavailable when
revision 6 was written, so revision 6 answered the blocker list supplied with that
task. This table is the revision-6 record and is kept unchanged. Its M1 to M7
labels are the revision-5 blockers. The revision-2 findings that also use M1 to
M7 are historical and remain in section 2.5.

| Blocker | Change in this revision | Still open |
|---|---|---|
| M1. The pairing capability was generated by the engine and sent backwards to the launcher, and the helper channel was not defined. | Section 11.4 now makes the **launcher** create both per-launch secrets. The launcher writes a fixed bootstrap frame to the engine on inherited descriptor 3 and the engine acknowledges on descriptor 4. The frame carries a magic, version, API bearer length, PC length, and the two secrets. A zero PC length means "no pairing". The engine zeroizes its copies on stop. On macOS the helper creates the PC, sends it to the engine, and returns it to the app only in the reply on the authenticated, single-connection XPC channel whose caller audit token was checked. On Linux the helper creates it and writes it to a dedicated app pipe, never to stdout or stderr. The app and helper contracts are in section 11.4. The secret type has a redacted `Debug`, is never formatted, and is never placed in argv, an environment variable, a file, a log, a panic message, a status, a diagnostics answer, or a failure record. | The descriptor protocol, XPC reply, and Linux pipe are design only and need host and device rows L19 to L26 and T1 to T4. |
| M2. Mandatory pairing made the Windows and headless proxy unavailable unless a console actor is designed. | Section 23 and P2 now state the consequence instead of assuming it away. If pairing is mandatory, a Windows target and a headless target have no PC and cannot pair a new source, so the proxy is unavailable there. The only approved alternatives are a designed console actor that reads the PC from a TTY without logging it, or removing those targets from the release. There is no token-only fallback, no unauthenticated local page, and no invented Windows helper. P2 is a gated product decision, not a technical selection. | The console actor is not designed. Windows and headless proxy support stay out of the release until P2 and P22 are decided. T5 to T7. |
| M3. A source local revocation could be blocked indefinitely by a live target, and the source had no per-session client pin. | Section 18.2 makes source local removal unconditional. It deletes the record durably and then closes every live proxy session whose authenticated client pin equals the removed pin. Section 7.11 and section 14 add a per-session client pin index, filled after the post-handshake pin recheck and before the first application byte. A target that keeps a flow open can no longer hold the source record. A remote FORGET may still receive `DENIED` while a flow is live; the person at the source is not blocked by it. The target sees the closed flow as truncation because no `FIN` frame crossed. | Whether the source resets or gracefully closes each orphaned flow, and how the target reports it, is a device row T8 to T11. P5 now covers only the remote-removal refusal; local removal is unconditional. |
| M4. Several paired sources can share one hotspot gateway, so a pin cannot be selected from the gateway address alone. | Section 7.11 replaces "select the record by gateway before the handshake" with a candidate set. The target collects confirmed proxy records whose host and port equal the dialed endpoint. It verifies the server certificate against the candidate pins before it sends its client certificate where the stack allows that order. Exactly one candidate must match. The target then binds that exact record, host, port, and token to the session. It never sends a token until the server pin has matched exactly one candidate, and it never falls back to another candidate's token. If no candidate matches, it shows the identity-changed message and sends no token. | The TLS 1.3 client-certificate ordering on each target stack, and the behaviour when two records have the same host, port, and pin, are host and device rows E25 to E28 and T12 to T15. |
| M5. QR arming and scan ordering were not defined. | Section 4.2 now defines the order. The target displays the QR and does not send `PAIR_HELLO`. The person scans on the source, which arms the source and binds `pairing_id` and `pin_T`. The person then confirms on the target with a local Continue action, which sends the hello. A hello before the source is armed is refused without consuming the source arming. SAS uses the same shape: both devices arm, then the person starts the session on the target. The target never auto-connects on arm. | The exact UI labels and the Continue affordance are product choices P15 and P23. The ordering is tested in T16 to T19. |
| M6. An attacker could exhaust a person's arming with unauthenticated attempts. | Section 4.2 separates the two arming states. The target consumes its arming when it sends `PAIR_HELLO`, because that is a local action. The source does not consume arming on a malformed, unauthenticated, or mechanism-mismatched hello. It consumes arming on success, explicit cancel, the 120 second expiry, or the third failed proof attempt. A QR secret is still consumed by the first proof attempt. The existing per-peer and global challenge budgets and the 30 second lockout still apply. This deliberately narrows R4-6: a single unauthenticated packet can no longer disarm the source, while the attempt budget stays bounded. | The three-attempt budget and the 120 second expiry are proposed bounds and need measurement. T20 to T24. |
| M7. The abort claims were not supported by the cited platform documentation. | Section 15.2 no longer claims that every abort produces a TCP RST. Apple documents `NWConnection.cancel()` as "cancels the connection and gracefully disconnects any established network protocols", so it is not a documented reset. Android's public `Socket.setSoLinger` documentation describes the option but does not state a reset. The design now relies on the receiver rule: any close without a prior `FIN` frame is truncation, whatever the transport does. An abort path sends no `FIN` frame, so the peer resets the inner flow even if the outer close is graceful. The reset behaviour of each API is recorded as a device row, not claimed. | The actual wire result of `SO_LINGER 0`, `NWConnection.cancel()`, and Android `setSoLinger(true, 0)` is a device row T25 to T28. The design no longer depends on it. |

The fifth review is answered on paper. It does not close the four live gates from
revision 5: cross-stack exporter equality, the vendor Keystore `DIGEST_NONE`
path, the Android 16 KB runtime, and the iOS lifecycle.

Revision 7 supersedes three statements in that record, and the record is kept as
written so the history is not rewritten:

- The M1 row's "launcher creates both per-launch secrets" and the "engine
  acknowledges on descriptor 4" are superseded. The target app creates the
  secrets, the acknowledgement is removed, and the helper receives them on its
  existing request channel. Section 11.4.1 and section 11.4.2.
- The M1 row's Linux "dedicated app pipe" is removed as well, under B2.
- The M3 row's description of the per-session index is superseded by the
  per-pin revocation epoch and the atomic registration in section 14.1 and
  section 18.2.

Revision 8 supersedes one more statement in the revision-5 record:

- The M4 row's "identity-changed message" is superseded. A nonmatching candidate
  pin cannot prove an identity change, so section 7.11 uses one neutral message
  for every candidate count and never advises forgetting a record. M8 and section
  2.1.

### 2.3 Revision-4 review

The fourth independent review returned NOT APPROVED. The right column names the
change in this revision. The last column names what is still open. An open item
is not a fix.

| Review finding | Change in this revision | Still open |
|---|---|---|
| R4-1 HIGH. The target engine is the TLS client and needs the QR secret, but the target apps reach the root engine only through local HTTP. The design claimed QR over app IPC and never over HTTP without defining a channel. | Revision 5 added the per-launch pairing capability (PC) and made pairing native target app only. Revision 6 supersedes the engine-created PC under M1: the launcher creates both secrets and sends them to the engine on one framed descriptor. macOS returns the PC on the authenticated XPC reply; Linux uses a dedicated app pipe. Windows has no channel, so QR and SAS are **unsupported**. The browser page holds no credential and has no pairing surface. | Superseded in part by M1, and in part by revision 7 under B2. The current rule is section 11.4.1 and section 11.4.2: the app creates both secrets, the helper receives them on its existing request, and there is no reverse path and no app pipe. |
| R4-2. The target arm, code, allow, deny, and cancel actions had no per-launch bearer, so a local API client could self-consent. | Section 11.4 requires the PC for arm, code, allow, deny, and cancel. The API bearer is not enough. The PC holder is the native target app acting as the target actor, and possession is treated as the person's consent. An engine with no PC refuses authenticated pairing with `pairing_requires_target_app` and shows no prompt. The unauthenticated browser GUI fails closed for pairing. | The product decision changes from a browser SAS surface to target-app-only pairing. See P17 and Q16. A process that steals the app's memory is out of scope, like a compromised app. |
| R4-3. The target did not key host, port, and token by `(peer_role, pin)`, did not bind the selected source identity to proxy authentication, took host and port from the wrong place, and did not gate a known re-pair on the source app being open. | Revision 5 added the per-record credential map. Revision 6 supersedes "select the record by pin before the handshake" with the candidate set in section 7.11, because several sources can share a gateway. `PAIR_RESULT` host and port come from the source listener's own bound settings. Section 12 requires the source app to be open for a known re-pair. | Superseded in part by M4. Cross-source tests are D38 to D42, E25 to E28, and T12 to T15. |
| R4-4. iOS peer authentication was not required explicitly, and anonymous clients were not tested. | Sections 4.1 and 6.3 require `sec_protocol_options_set_peer_authentication_required(options, true)` before the connection. The verify block decides trust only. J12 and K12 add an anonymous client on both listeners. | Device result. |
| R4-5. The design did not forbid data-phase frames before a successful SOCKS5 reply. | Section 15.1 starts the frame phase only after the sender has sent a success reply and the receiver has read it. A `DATA` or `FIN` frame before the reply or after a failure reply is a protocol error. The target sends no frame before it reads the success reply. | None. E24 and G28. |
| R4-6. Arming was not stated to be consumed by a failed or revealed attempt. | Revision 5 consumed the target arming on the hello and the source arming on acceptance. Revision 6 supersedes the source half under M6: the target stays one-shot, but the source keeps its arming through unauthenticated hellos and allows three failed SAS proof attempts. | Superseded by M6. The current rule is section 4.2 and T20 to T24. |
| R4-7. Local forget was refused while a tunnel ran but remote FORGET was accepted, and duplicate FORGET frames in one session were undefined. | Revision 5 used one live-flow rule for local and remote removal. Revision 6 supersedes it under M3: local removal is unconditional and closes matching sessions; a remote FORGET may still be `DENIED` while a flow is live. One `FORGET_REQUEST` per connection; the same request id returns the cached reply bytes; a different id closes with no reply. | Superseded by M3. The current rule is section 18.2 and P5. |
| R4-8. The 300 second source session idle was described as a 600 second idle, and the half-closed claim was too broad. | Section 15.2 distinguishes the target inner TCP idle (600 seconds) from the source proxy session idle (300 seconds for UDP and half-closed flows). A half-closed flow with no traffic for 300 seconds is closed by the source, and the target treats that as truncation unless both `FIN` frames crossed. G1 stays at 2.5, 30, and 120 seconds; G29 records 301 seconds. | Whether to raise the source half-closed idle to 600 seconds or accept the 300 second truncation is P21 and Q21. |
| R4-9. An abortive close could still call a TLS close that emits `close_notify`. | Section 15.2 forbids `close_notify`, `FIN`, `send_close_notify`, `.finalMessage`, and application data on an abort path. Revision 6 supersedes the reset claim under M7: `NWConnection.cancel()` is documented as graceful, and the receiver's no-`FIN` rule is decisive. | Superseded by M7. The abort wire result is a device row T25 to T28. |
| R4-10. The certificate extension set was described as a list of forbidden extensions, not an exact allowlist. | Sections 5.1 and 5.6 define the exact allowlist: `basicConstraints` critical `30 00` and `keyUsage` critical `03 02 07 80`. No other extension, no duplicate, and no unknown extension. | Platform acceptance of the template is B13. |
| R4-11. The rustls and rcgen dependency features were not pinned, so a default provider could enter the tree. | Section 22 pins `rustls` with `default-features = false` and features `ring`, `std`, `logging`, with no `tls12` and no `aws-lc-rs`; and `rcgen` with `default-features = false` and features `crypto`, `ring`. The host gate checks `cargo tree -i aws-lc-rs` is empty. | None. The exact feature list is rechecked against the pinned versions at implementation time. |
| R4-12. The `flags` mask was ambiguous between bit index and bit value. | Sections 9.2 and 9.5 define `HS_FLAG_QR_REQUIRED = 0x01`. Every other bit is zero and is rejected before a commitment is used. Tests C44, C45, QV4, and QV15 use the mask. | None. |
| R4-13. The Conscrypt provider check ran after the handshake started. | Section 6.4 checks `Conscrypt.isConscrypt(socket)` immediately after accept or socket creation and before any handshake byte. A mismatch closes the socket. | Device result in I6. |
| R4-14. The exporter context text claimed an empty context is never the no-context form, which is not accurate. | Section 6.2 states that RFC 8446 section 7.5 defines an absent context as the empty string, so `None` and `Some(b"")` in rustls, and the no-context and zero-length Apple calls, are the same input. Each peer records which API form it used. Equality is still a test. | Cross-stack equality remains open. A3, A4, and I8. |
| R4-15. The SAS code formula was ambiguous, and the iOS terminology was loose. | Section 10.2 gives the exact big-endian formula. Section 8 names the source device app and the TLS server role, and uses "verify block" only for trust. `TEST_MATRIX.md` QV16 and QV17 add byte-exact `PAIR_HELLO` and `PAIR_RESULT` vectors. | None. |
| R4-16. iOS background behavior was not gated. | Sections 4.1 and 8.2 state that iOS has no general background execution: pairing runs only while the app is in the foreground, arming is cleared on background, and the background proxy is not claimed. A live flow may be suspended or closed by the system. | The lifecycle result is a device row J13 and G23. |

The fourth review also repeated four live gates that this revision does not
close: cross-stack exporter byte equality, the vendor Keystore `DIGEST_NONE`
path, the Android 16 KB runtime, and the iOS lifecycle. They remain open and are
not counted as evidence.

### 2.4 Revision-3 review

The third independent review rejected revision 3 for the reasons below. The
right column names the change in this revision. The last column names what is
still open. An open item is not a fix.

| Review finding | Change in this revision | Still open |
|---|---|---|
| B1. The known path could switch to a prompt inside the same session, and the QR and known paths used zero commitments. | Section 9.5 makes `known` a separate mechanism. A known session never becomes a prompt. If either side lacks a complete record, the known session fails; a full ceremony is a new session with new nonces and new nonzero commitments. Section 9.3 requires a real `commit_T` and `commit_S` on every path, and rejects an all-zero commitment. Section 10 deletes `PAIR_NEED_PROMPT` and `mode_hint`. | The exact user flow for starting a new ceremony after a failed known attempt is a product choice. See P18. |
| B2. `SSLSocket.shutdownOutput()` sends a TCP FIN, not a TLS `close_notify`, so one-way close is not portable. | Section 15 specifies a framed data phase with explicit `DATA` and `FIN` frames on every peer. `FIN` is the half-close signal. A TLS close without a prior `FIN` is truncation. `shutdownOutput`, `.finalMessage`, and `send_close_notify` are not used as the half-close signal. | The framed data phase is new implementation work on all three peers. The frame tests are in `TEST_MATRIX.md` G and R. |
| B3. The iOS exporter was taken from metadata retained from the verify block, before the server Finished. | Section 6.3 uses `NWConnection.metadata(definition: NWProtocolTLS.definition)` after the connection is `.ready`, then `securityProtocolMetadata` and `sec_protocol_metadata_create_secret_with_context`. The verify-block metadata is not retained or used for the exporter. | Whether the post-ready server metadata returns a usable exporter is a device test. It is no longer a question about how to obtain a metadata handle. See Q7. |
| B4. The FORGET hash used `pin_peer` then `pin_self`, so the two sides computed different bytes, and the framing was not explicit. | Section 18.1 orders the pins by role, `pin_T` then `pin_S`, independent of who sends. It defines exact `FORGET_REQUEST` and `FORGET_RESULT` frames with length, type, version, role bytes, request id, status, and hash. The hash covers the role-ordered pins, the request id, and the status. | None in the wire definition. The frame tests are F17 to F22. |
| B5. The rollback model used a per-record counter, and the revocation limits were not precise. | Section 7 uses one store-wide `generation`, incremented on every store change, and one tag over the whole canonical store. Section 7.5 states that rollback can restore an entire prior trust set, including a record the person forgot. Section 18.5 states exactly what removal does and does not revoke. | A rollback of the store and its anchor together is not detectable. See Q14. |
| B6. A lost `PAIR_DONE` or `FORGET_RESULT` left the two sides in different states with no defined recovery. | Section 13.1 adds a staged target record and a confirmed target record. Section 13.2 defines every lost-message state and the next action. Section 18.4 defines FORGET loss and the local-forget recovery. Recovery is a person action or a new full ceremony; there is no automatic delete and no automatic re-pair. | The UI wording for each recovery state is a product choice; section 13.2 names the states and the next action. |
| B7. The browser QR endpoint could run without a bearer secret, and its idempotent repeat was not single use. | Section 11.4 removes QR from the browser GUI entirely. QR is displayed only by a target app UI surface. The Rust-served browser page has no QR endpoint and never receives the QR payload or secret. The page may show the six-digit SAS code during an armed pairing session; the code is not a stored secret, is not logged, and is not returned in a status, diagnostics, or failures response. | The target app QR surfaces and their clearing rules are device rows. The browser pairing surface is a product choice. See P17 and Q16. |
| B8. Store locks were held across network reads and writes. | Section 7.9 defines the lock scope. A lock covers only a bounded local read, verification, or write. It is never held across a TLS handshake, read, write, flush, connect, accept, or a blocking socket call. Each path copies the record, token, and generation under the lock, releases, and then uses the copy. | A concurrent removal after the copy can issue a credential or accept a connection that is immediately unusable. Section 7.9 states that bound. |
| B9. Conscrypt signs TLS `CertificateVerify` for a delegated EC key with `NONEwithECDSA`, which needs the Keystore key to authorize `DIGEST_NONE`. | Section 5.4.1 states that the Keystore key must authorize both `DIGEST_SHA256` for the certificate TBS and `DIGEST_NONE` for the Conscrypt handshake signature. A vendor keystore that refuses either blocks the Conscrypt path; there is no exportable-key fallback. | Real vendor acceptance is a device test. See Q18. |
| B10. The Conscrypt version was old, its maintenance status was not stated, and 16 KB page alignment was not checked. | Section 6.4 pins `org.conscrypt:conscrypt-android:2.9.0`, the current release at the time of writing. It records that upstream development moved internal, that the bundled provider does not receive Mainline updates, and that the app must track releases. It records the measured AAR size and the verified `0x4000` ELF alignment of the arm64-v8a and x86_64 libraries. Section 21 adds the Android 16 KB requirement. | A 16 KB device run and the long-term maintenance decision are open. See P19 and Q18. |
| B11. The design did not require `CertificateVerify` to be verified when a custom pin verifier is used. | Section 6.7 requires every peer to verify the peer's `CertificateVerify` over the handshake transcript. On rustls the custom verifier must call `rustls::crypto::verify_tls13_signature` and return its result; it must not return `HandshakeSignatureValid::assertion()` without a check. | The negative device test with a matching pin and a different private key is in K13 and R20. |
| B12. iOS cannot see the client's offered ALPN list, so the "reject no ALPN or more than one label" rule was not implementable there. | Section 4.1 requires the target to offer exactly one label and the source to check the negotiated label after `.ready`, before any application byte. On iOS the source cannot inspect the offered list; a nil or mismatched negotiated label is a hard failure. The rule is stated as a platform limitation, not a weaker profile. Section 6.3 uses `sec_protocol_metadata_get_negotiated_protocol` on iOS 17.0 to 18.4 and `sec_protocol_metadata_copy_negotiated_protocol` on iOS 18.5 and later, because the newer call is not available at the deployment target. | The exact Network.framework behavior for a client that offers no ALPN is a device test. See Q19. |
| B13. A QR session could be pushed toward a SAS confirmation. | Section 9.5 and section 11.5 state that a QR-armed target refuses every `mech` other than QR until the QR is consumed, expires, or is cleared. A source holding a scanned QR refuses SAS. A proof failure consumes the secret and ends the session; there is no in-session fallback. | None in the protocol. The UI must not offer an in-session switch. See C9, C10, and K18. |
| B14. There was no shared fixed-vector plan and no adversarial row for each blocker. | `TEST_MATRIX.md` Q defines the cross-language fixed-vector plan. `TEST_MATRIX.md` R has one or more adversarial rows for B1 to B14. | The vectors do not exist yet. They are host-only work in M. |

### 2.5 Previous review (revision 2)

The independent review rejected revision 2 for the reasons below. The right
column names the change in revision 3. The last column names what was still
open after revision 3. An open item is not a fix.

| Review finding | Change in revision 3 | Still open after revision 3 |
|---|---|---|
| H1. The exporter channel binding was declared unavailable, which created two security profiles. | Section 6 makes the RFC 9266 `tls-exporter` binding mandatory on every pairing and trust-change transcript. The value is computed after the handshake, covered by both commitments, and covered by the SAS code and the QR proofs. A peer that cannot produce it fails the session. There is no fallback profile. | The iOS source can only obtain `sec_protocol_metadata_t` in the verify block, which runs before a server sends its Finished. Whether `sec_protocol_metadata_create_secret_with_context` works on a retained metadata object after the handshake is untested. If it does not, iOS source mode is not approved. See Q13. |
| H2. The mechanism was not bound, and the source did not require a locally armed bootstrap. | Section 4.2 adds local arming with a TTL. Section 9.3 puts `mech` and `flags` in the transcript context and covers both in the commitments. Section 9.5 forbids any mechanism change in a session in either direction. A QR-to-SAS switch, an in-session "use the code instead" control, and an unarmed pairing attempt all fail closed. | Whether both mobile apps can present arming well enough to avoid a habitual tap is a product question. See P15. |
| H3. A fixed 2 second drain after a one-way `close_notify` truncates slow downloads. | Section 15 follows RFC 8446 section 6.1. A one-way `close_notify` closes only the sender's write side. The sender keeps reading and delivering until the peer closes its own write side, a fatal alert arrives, or the flow is aborted. The fixed drain is removed. A bounded timer remains only after both directions are closed. | Whether rustls, Network.framework, and Conscrypt can express one-way close is still untested. See Q5. |
| M1. Multiple source identities were undefined and a mismatch had no way forward. | Section 7.2 defines a record set with a cap and no silent eviction. Section 7.3 defines replace as a local, explicit, two-step action. No protocol message can overwrite a record. | The exact UI text and the record cap are product choices. See P16. |
| M2. One ALPN field per record contradicted pairing, proxy, and forget. | Section 4.1 makes the record hold a purpose set and a wire version. The ALPN label is derived from the purpose of the connection, not stored per record. | None in the record model. |
| M3. A FORGET reply could change storage without authenticating the source pin, and unknown-peer framing was inconsistent. | Section 18 defines a request id, a status bound into a reply hash, an authenticated server pin check under the store lock before any local deletion, and one idempotent reply shape. An unknown client on the proxy listener fails at the handshake. On the pairing listener it may complete a first-pairing handshake, but a `FORGET` from that pin fails the locked recheck and receives no distinct reply. | None in the protocol. The race window between the handshake check and the message is defined as a hard close. |
| M4. HMAC does not prevent rollback, and the known path could check and then issue credentials from stale state. | Section 7.5 adds a store-wide `generation` and a separate anchor, and states that rollback protection is best effort. Section 12 makes the known path check-only under one lock, with a fresh recheck immediately before the token is read. | Full rollback resistance needs a platform monotonic store that none of these platforms documents. See Q14. |
| M5. Desktop and iOS store claims overstated HMAC protection, and the Linux helper runs as root. | Section 7.4 replaces the claim table with a per-platform statement of what the store key protects against and what it does not. On iOS the keychain is the boundary and the tag is a corruption check. On Linux the boundary is the unprivileged user, not root and not a compromised helper. | The Linux helper still runs as root. That is a product property, not a fix in this document. |
| M6. Android resumption was unresolved, and the peer certificate was not rechecked after the handshake. | Section 6.4 selects the bundled Conscrypt provider and section 16 requires tickets off before the handshake on every accepted socket, plus a post-handshake pin recheck on every session before any application byte. | A public handshake-kind API is not available on Android, so the gate is a device trace, not a return value. See Q3. |
| M7. The QR secret must reach a display surface, so the "never reaches the browser" claim was false. | Revision 3 defined the display surfaces and an authenticated one-shot API for a browser-rendered QR. Revision 4 removes the browser QR endpoint entirely; section 11.4 is target-app-only for QR and SAS-only for the browser. Section 19 and section 24 repeat the corrected claim. | Which target app surface each target uses is a product choice. See P17. |

Revision 4 closes H3's half-close item with section 15's framed `DATA`/`FIN`
data phase. The historical row above records what revision 3 did, not what this
revision does. Q5 is now about accepting the frame, not about one-way
`close_notify`. Revision 4 also closes H1's retained-handle item: section 6.3
uses the post-ready metadata handle, never the verify-block handle, and Q7 is
the device gate for the server side.

Revision 5 removed the browser SAS surface that B7 and M7 describe. Revision 6
keeps it removed. Pairing, including the code and the QR, is native target app
only; section 11.4. The historical rows are kept as the revision-3 record.

Additional review items and their disposition:

| Item | Change in this revision |
|---|---|
| Complete `transcript_hash`. | Section 9.3 defines one canonical context that carries version, mechanism, flags, state, purpose, ALPN, TLS version marker, exporter value, both pins, both nonces, the pairing id, and both commitments. Section 9.4 defines a distinct state byte per message so a hash from one message cannot be replayed into another. |
| Nondeterministic certificate signatures. | Section 5.3 states that ECDSA signatures are not reproducible, that no test may compare full certificate bytes, and that the pin is over the key point, not the certificate. |
| Android generated certificate. | Section 5.4 states that the certificate generated by `KeyGenParameterSpec` is not the identity certificate. Android builds the shared template and signs it with the Keystore key. |
| `SecKeyCreateRandomKey`. | Section 8 uses `SecKeyCreateRandomKey` (iOS 10.0 and later) instead of `SecKeyGeneratePair`. |
| TLS version binding. | Section 6.6 states that the TLS 1.2 exporter and the TLS 1.3 exporter are different constructions, that the Apple call matches the TLS 1.3 construction only, and that the transcript carries an explicit version marker and requires the negotiated version to be TLS 1.3. |
| Short pin label must not be treated as authentication. | Section 5.7 states that the four-byte label is a display aid, that every trust decision uses the full 32-byte pin, and that a label collision is not a pass. |
| Certificate cap after parsing. | Section 5.6 caps the chain at one leaf and 4 KiB before parsing, and validates key type, curve, point length, and extension set after parsing. |
| Durable storage before ACK. | Section 13 defines the commit point per platform and forbids sending `PAIR_DONE` or `PAIR_DONE_ACK` before a durable commit. |
| Constant-time verification APIs. | Section 9.6 names the exact comparison used on each peer and forbids a short-circuit compare. |

### 2.6 Verified facts and remaining unknowns

These checks were made against primary source on 2026-11-05. A source reading is
not a device test and is not a security result. The design uses the verified
fact and marks the untested behavior as a device row.

| Claim | Verification | Result |
|---|---|---|
| Android `SSLSocket.shutdownOutput()` sends a TCP FIN, not a TLS `close_notify` | Conscrypt 2.9.0 `AbstractConscryptSocket.shutdownOutput()` delegates to `super.shutdownOutput()`, and `ConscryptEngineSocket` does not override it. The TLS `close_notify` is sent by `close()`, which closes both directions. | Verified in source. This is why section 15 uses a framed `FIN`, not `shutdownOutput`, as the half-close signal. |
| Conscrypt signs a delegated EC key with `NONEwithECDSA` | Conscrypt 2.9.0 `CryptoUpcalls.ecSignDigestWithPrivateKey()` calls `signDigestWithPrivateKey(javaKey, message, "NONEwithECDSA")`. | Verified in source. An AndroidKeyStore key is a delegated key, so the handshake signature path reaches this call unless the vendor provides its own OpenSSL key wrapper. The exact vendor path is a device test. |
| Android Keystore has a no-digest authorization | `KeyProperties.DIGEST_NONE` is API 23 and later, value `"NONE"`, "sign/authenticate the raw message". `KeyGenParameterSpec.Builder.setDigests` API 23 and later. | Verified in the platform reference. The key must authorize it for the Conscrypt handshake signature. |
| Conscrypt 2.9.0 is current, and its 64-bit libraries are 16 KB aligned | Maven Central metadata lists 2.9.0 as the latest release, last updated 2026-11-04 15:27 UTC. The AAR manifest declares `minSdkVersion 21`. The AAR is 5,003,083 bytes compressed and 11,105,510 bytes uncompressed. The four `libconscrypt_jni.so` files total 10,407,728 bytes: arm64-v8a 2,787,256, armeabi-v7a 1,793,508, x86 2,805,636, x86_64 3,021,328. Every PT_LOAD segment in the arm64-v8a and x86_64 libraries has `p_align = 0x4000`. | Verified from the published artifact. A 16 KB runtime test is still a device row. |
| Conscrypt returns null before the handshake | `Conscrypt.exportKeyingMaterial` documents and returns `null` if the handshake has not completed or the connection is closed. The context argument distinguishes `null` from an empty array. | Verified in the 2.9.0 source. The design passes an empty array, never `null`. |
| Conscrypt development moved internal, and the platform copy receives Mainline updates | The published Conscrypt README says primary development is now internal at Google, external pull requests are no longer accepted, and the platform version receives regular updates including security patches through Google Play system updates. | Verified in the published README. The bundled 2.9.0 AAR does not receive those Mainline updates, so the app must track releases. |
| iOS has a documented post-ready metadata handle | `NWConnection.metadata(definition:)` is iOS 12.0 and later, returns `NWProtocolMetadata?`, and "retrieves the connection-wide metadata for a specific protocol". `NWProtocolTLS.Metadata.securityProtocolMetadata` is non-optional and is "the result of the TLS handshake". | Verified in the platform reference. The optional is the `metadata(definition:)` result and the cast to `NWProtocolTLS.Metadata`, not `securityProtocolMetadata`. The exporter call on a server after `.ready` is still a device test. |
| iOS ALPN read needs an availability branch at deployment target 17.0 | `sec_protocol_metadata_get_negotiated_protocol` is iOS 12.0 and deprecated at iOS 18.5. `sec_protocol_metadata_copy_negotiated_protocol` is iOS 18.5 and later. The source app's deployment target is 17.0. | Verified in the platform reference. Section 6.3 uses `get` on 17.0 to 18.4 and `copy` on 18.5 and later. The earlier revision named only `copy`, which does not compile at 17.0. There is no public call that returns the client's offered list. |
| The exporter call has a documented signature and availability | `sec_protocol_metadata_create_secret_with_context(metadata, label_len, label, context_len, context, exporter_length)` is iOS 12.0 and later and returns `dispatch_data_t?`. | Verified in the platform reference. A nil result is a hard failure. |
| iOS signature and public-key encodings | Apple documents `SecKeyCreateSignature` with `kSecKeyAlgorithmECDSASignatureMessageX962SHA256` as an ECDSA signature in DER `ECDSA-Sig-Value` form, and `SecKeyCopyExternalRepresentation` for an EC public key as an X9.63 uncompressed point. | Documented. J1 and J2 check the identity and pin path on a device. |
| Android platform exporter and ticket APIs | `SSLSockets.exportKeyingMaterial` is API 31 and later. `SSLSockets.setUseSessionTickets` is API 29 and later. | Verified in the platform reference. This is why the platform `SSLSocket` cannot carry the profile below API 31. |
| Android 16 KB packaging floor | The Android 16 KB page-size guide says AGP 8.5.1 or higher and uncompressed shared libraries, and shows `PAGE_ALIGNMENT_16K` from `bundletool`. | Verified in the platform guide. The Play deadline is not treated as verified. |
| A rustls custom verifier can disable `CertificateVerify` by assertion | `rustls` 0.23 `ServerCertVerifier::verify_tls13_signature` must return `Ok(HandshakeSignatureValid)` only if the signature is valid. `HandshakeSignatureValid::assertion()` is public and constructs the marker without a check. `rustls::crypto::verify_tls13_signature` is the provider function that performs the check. | Verified in the rustls source. Section 6.7 requires the provider call. |
| rustls 0.23 emits the client Certificate only after the server checks | In the local crates.io copy of rustls 0.23.46, `src/client/tls13.rs`: `ExpectCertificateRequest::handle` calls `ClientAuthDetails::resolve` with the configured resolver; `ExpectCertificateVerify::handle` calls `verify_server_cert` and then `verify_tls13_signature`, and an error from either sends an alert and returns; `ExpectFinished::handle` checks the server `Finished` and only then calls `emit_certificate_tls13` and `emit_certverify_tls13`. | Verified in source on 2026-11-05. The resolver runs before the server checks; the wire Certificate and the client signature come after them. V5 tests the emitted messages and the signer, not the resolver. A source reading is not a test. |
| An absent exporter context equals a zero-length context | RFC 8446 section 7.5 says the context is included as a length-prefixed value, and an absent context is the empty string. | Verified in the RFC. The API mappings are still A19 tests, not a claim that every stack produces the same bytes. |
| iOS can require a peer certificate before the connection | `sec_protocol_options_set_peer_authentication_required(_:_:)` is a public Network.framework call. The verify block decides trust. | Verified in the platform reference. The handshake result is J12. |
| Apple documents `NWConnection.cancel()` as graceful | The official `cancel()` page says "Cancels the connection and gracefully disconnects any established network protocols." It does not promise a TCP RST. | Verified in the platform reference. The design no longer calls `cancel()` a reset. T25. |
| Android `Socket.setSoLinger` does not document a reset | The official page describes `SO_LINGER` and the linger time. It does not say that a zero linger sends RST. | Verified in the platform reference. The wire result is a device row T26. |
| Linux `SO_LINGER` does not document a reset on these pages | `socket(7)` describes the linger structure and close behaviour. `tcp(7)` says the option should not be used in portable code. Neither page states a guaranteed RST for a zero linger. | Verified in the Linux man pages. The design does not rely on a reset. T27. |
| Windows `LINGER` documents the close wait, not a guaranteed RST | The `LINGER` structure page describes whether the socket remains open after `closesocket` and for how long. It does not state a guaranteed reset for a zero linger. | Verified in the Windows reference. T28. |
| The exported value is equal across stacks | No primary source promises byte equality for Apple or Conscrypt on TLS 1.3. | Unknown. A3, A4, and I8 are the equality gates. |

Unknowns that remain after this revision:

- Whether `metadata(definition:)` on a Network.framework server after `.ready`
  returns a metadata whose exporter equals the rustls value. This is Q7.
- Whether a client that offers no ALPN completes the iOS handshake, and what
  the negotiated-protocol call returns in that case. This is Q19.
- Whether a given vendor Keystore accepts `DIGEST_NONE` for an EC key and
  whether Conscrypt's delegated-key path accepts that key. This is Q18.
- Whether Conscrypt 2.9.0 performs a full handshake, with no ticket, on each
  connection on a given OEM build. This is Q3.
- Whether rustls and Conscrypt permit an application write and read after a
  received TLS `close_notify`. The framed `FIN` removes this from the half-close
  path, but the final transport tidy step still needs a host test.
- Whether the framed data phase runs at acceptable cost on each peer. This is
  Q20.
- Whether `SO_LINGER 0`, `NWConnection.cancel()`, and Android `setSoLinger(true,
  0)` produce a TCP RST on each platform. The design no longer depends on the
  answer for correctness. This is Q26 and device rows T25 to T28.

## 3. What does not change

- Direct mode. It has no source device app and no channel. This design does not
  touch it.
- One inner 4-tuple maps to one outer socket. One inner flow is one TLS
  connection. Nothing is multiplexed.
- Every outer socket still comes from `normalization::tcp_start`, `tcp_connect`,
  or the platform wrapper. TTL 65, interface pinning, and the `ttl_bad == 0`
  audit are unchanged. TLS wraps the normalized socket; it does not replace it.
- The source listener still binds the hotspot address only. It never binds
  `0.0.0.0` and never a second interface.
- No external relay, VPS, or cloud hop. Pins are exchanged between the two
  devices only.
- The browser GUI never receives the source token, a private key, a full pin, the
  exporter value, the QR payload or secret, the API bearer, the pairing
  capability, or the SAS code. It has no pairing surface. Section 11.4 defines
  the surfaces.
- The native target app creates and holds the API bearer and the pairing
  capability, and the engine holds a copy for comparison. The browser page holds
  neither. Section 11.4.
- The target keeps host, port, and token per `(peer_role, pin)`. Section 7.10.
- Android `minSdk` stays 26. Section 6.4 changes the TLS provider, not the
  platform support floor.

## 4. Roles, listeners, purposes, and arming

The source device is the TLS server. The target device is the TLS client. The
TCP direction is unchanged: the target opens the connection to the hotspot
address, so the source device needs no route to the target and no inbound
reachability beyond the hotspot.

Each device has one long-term P-256 key pair. The source uses its key as the TLS
server identity on both listeners. The target uses its key as the TLS client
identity. The source never acts as a TLS client to the target, and the target
never acts as a TLS server.

### 4.1 Purposes and ALPN labels

Two listeners, two ALPN labels, and three purpose bits:

| Listener | Bind | ALPN | Client certificate | Record purpose required |
|---|---|---|---|---|
| Pairing | hotspot address, port 18090 | `hs-pair/1` | required | `PAIRING` |
| Proxy | hotspot address, port 20000-59999 | `hs-proxy/1` | required, must match a complete record | `PROXY` |

Both listeners require the peer certificate on every platform. On iOS the
source app calls `sec_protocol_options_set_peer_authentication_required(options,
true)` before it opens the connection. The verify block decides trust only; it
does not by itself require a client certificate. An anonymous client is a
handshake failure on both listeners. J12 and K12 test it.

The target's TLS client is also configured to require the server certificate.
It presents its own certificate only to a server whose pin matches, except
during a first pairing where it has no pin yet. Section 19 records that
disclosure.

The labels are ASCII and are not interchangeable. A proxy client that reaches
the pairing listener fails ALPN. A pairing client that reaches the proxy
listener fails ALPN; it never reaches the pin check or SOCKS5.

The pairing listener accepts a first pairing with no record. Once a record
exists, `PAIRING` is required for `known`. A first-message `FORGET_REQUEST` also
requires the `trust admin` purpose. Section 18.2.

ALPN rules:

1. The target offers exactly one label, the one for the listener it is opening.
2. The source requires the negotiated label to equal its listener's label
   exactly. A selected label that is absent or different is a hard failure
   before any pairing message, token byte, or SOCKS byte.
3. On a stack that exposes the client's offered list, the source also rejects a
   ClientHello that offers no ALPN or more than one label before the handshake
   completes. rustls and Conscrypt can apply this through their own ALPN
   configuration or selector.
4. Network.framework does not expose the client's offered list to the server.
   `sec_protocol_options_add_tls_application_protocol` adds a supported
   protocol, and the app can read only the negotiated result. On iOS 17.0 to
   18.4 it calls `sec_protocol_metadata_get_negotiated_protocol`; on iOS 18.5 and
   later it calls `sec_protocol_metadata_copy_negotiated_protocol`, because the
   newer call is not available at the deployment target and the older call is
   deprecated at 18.5. The iOS source cannot reject "no ALPN" or "two labels" at
   the ClientHello. It checks the negotiated label after `.ready`, before any
   application byte. A nil or mismatched result is a hard failure.
5. Rule 4 is a platform limitation, not a second profile. The security property
   is that the selected label must be exact and that the transcript binds the
   purpose and the label. The target's single-label rule is enforced on the
   target. A client that offers both labels can still select only one, and the
   selected one must match the listener. This is recorded in section 6.3 and
   tested in A17 and J10.

A pin record does not store an ALPN string. It stores a wire version and a
purpose bit set:

| Purpose bit | Meaning |
|---|---|
| `0x01` | pairing and known-state refresh |
| `0x02` | proxy |
| `0x04` | trust administration, which is FORGET |

A full pairing grants `0x07`. The listener's ALPN is derived from the purpose of
the connection, and the connection is rejected unless the record holds that
purpose bit. This removes the revision 2 contradiction where one stored ALPN
string had to authorize pairing, proxy use, and FORGET at the same time. FORGET
is an operation on the pairing listener, not a third listener, so it uses
`hs-pair/1` and needs no third label. It is refused on `hs-proxy/1`, because the
proxy listener's first bytes are SOCKS5 and a second protocol on that port would
be an ambiguous parser.

Every transcript and proof carries an explicit role byte:

| Role byte | Meaning |
|---|---|
| `0x01` | target device |
| `0x02` | source device |

A message that carries the wrong role byte is rejected. Role separation is not a
substitute for the pin check. It prevents a message from being replayed in the
other direction or under the other listener.

Both listeners keep the existing lifecycle rules: the pairing listener runs
while the app is open and the hotspot interface is present; it stops on the
existing hotspot watch; it never runs in the background on Android.

iOS has no general background execution. The source app runs the pairing
listener only while it is in the foreground. A backgrounded iOS app clears
arming. The proxy is not claimed to run continuously in the background; an
approved background mode is a separate product decision and test. The system
may suspend or close a live proxy flow. Pairing is foreground-only in this
revision. Section 8.2.

### 4.2 Local arming

A listener being open is not consent to pair. Both devices must be locally armed
for SAS or QR before a first-pairing session can authenticate. The `known` path
and a first-message `FORGET_REQUEST` need no arming, as the rules below say.

| Device | Armed when | Disarmed by |
|---|---|---|
| Target | the person opened the pairing screen in the native target app and chose a mechanism, which creates the local session handle and starts the target ceremony; for QR the payload is displayed | arming is consumed by TD1 below; the ceremony ends at any of TD2 to TD10, TE1, or TE2 below, and a ceremony end also ends an unconsumed arming |
| Source | the person opened the pairing screen and chose the same mechanism, and for QR has scanned the displayed payload into a local armed state | any event SD1 to SD10 below |

The target has two states, and revision 8 wrongly merged them:

- **Target arming** is the permission to send one `PAIR_HELLO`. TD1 consumes it.
  Nothing else consumes it, and a ceremony end also ends it.
- **Target ceremony** is the session handle, the engine's QR secret for QR, the
  SAS code once both commitments verify, and the Allow prompt. It lives from the
  arm action until TD2 to TD10, TE1, or TE2. TD1 does **not** end it, because the
  target still has to verify `proof_source`, compute `proof_target`, show the
  SAS code, and take the person's Allow after the hello.

These lists are the complete sets. Every other section, summary, and test row
refers to these labels. A section that lists fewer events is a summary, not a
narrower rule. Arming and ceremony state are memory only on both devices, so no
event here needs a durable write, and none writes a record.

Source disarm events:

| Label | Event | Notes |
|---|---|---|
| SD1 | a successful ceremony | the record write points in section 13 follow |
| SD2 | explicit cancel or back navigation off the pairing screen | a person action that withdraws consent; no lockout. A Deny at the SAS prompt is not SD2; it is counted under SD8 |
| SD3 | `arm_deadline` passes | monotonic clock, section 4.2.1 |
| SD4 | the source app leaves the foreground | iOS and Android background; section 8.2 |
| SD5 | screen lock | the person can no longer compare a code |
| SD6 | a mechanism change | the old QR payload is dropped; a new arm is required |
| SD7 | the end of the first QR session in which the source sent `proof_source`, whatever the outcome other than success | the scanned secret serves one session that reaches a proof. A failed `proof_target`, a target Deny, a timeout, or a close all count. A hello refused before `PAIR_READY` for a wrong `pairing_id` or a wrong target certificate pin does not reach a proof and does not count |
| SD8 | the third failed SAS attempt | an attempt counts only after `PAIR_READY` and a reveal whose commitment verifies, so a code was computed. It fails on a source person's Deny, a target Deny seen as a close without `PAIR_CONFIRM_T`, a prompt timeout, or a confirmation hash mismatch. The source stays armed after the first and second failure; the third disarms it and starts the 30 second lockout |
| SD9 | the source app process exits | crash, kill, or operating system termination; nothing is restored on restart |
| SD10 | the pairing listener closes | hotspot loss, a hotspot address change, or `onStop` on Android; a rebind on a new address does not keep the old arming |

In QR the source shows no Allow prompt and has no Deny. The scan is the source
person's consent, and the target person's Allow or Deny decides the session. A
source person who wants to stop uses Cancel, SD2.

Target arming consumption:

| Label | Event | Notes |
|---|---|---|
| TD1 | the first `PAIR_HELLO` send | the arming is consumed, so no second hello is sent in this ceremony. The ceremony continues: the session handle, the engine's QR secret, the SAS code, and the prompt stay alive. At TD1 the app stops displaying the QR payload and destroys its display copy, because the scan has already happened; the engine keeps the secret for the proofs |

Target ceremony-end events:

| Label | Event | Notes |
|---|---|---|
| TD2 | explicit cancel or back navigation off the pairing surface | a person action. A target Deny at the Allow prompt is TE2 |
| TD3 | `arm_deadline` passes, or `qr_deadline` passes for QR | section 4.2.1 |
| TD4 | window close, window hide, or tray hide | the pairing surface is not visible; section 11.4.3 |
| TD5 | app background or app deactivation | where the platform reports it |
| TD6 | screen lock | section 11.4.3 rule 4 |
| TD7 | a new mechanism choice | the old QR secret is destroyed |
| TD8 | an engine process exit | the PC dies with the launch; section 11.4.3 rule 6 |
| TD9 | app quit or launch end | section 11.4.3 rule 7 |
| TD10 | the PC request that armed the session is refused on a later step | for example a stale session handle; the session is ended, not repaired |
| TE1 | the session completes | the target promotes its record after a verified `PAIR_DONE_ACK`, section 13 |
| TE2 | the session fails after the hello | a target person's Deny at the Allow prompt, a source Deny seen as a close, a protocol error, an exporter failure, a failed `proof_source` or commitment check, a prompt timeout, a confirmation mismatch, or a transport close before TE1 |

Every ceremony-end event destroys the engine's QR secret, clears the SAS code
display, ends the prompt, and ends an unconsumed arming. TD1 alone does none of
these except end the arming and the app's QR display copy. None of TD1 to TD10,
TE1, or TE2 clears the API bearer or the PC except TD8 and TD9, which end the
launch. None of SD1 to SD10 changes a stored record or a token.

Ordering is explicit. The target never connects on arm:

1. QR. The target arms and displays the QR, and sends no `PAIR_HELLO`. The person
   scans it on the source. The source arms, binds the payload's `pairing_id` and
   `pin_T`, and sends no message. The person then taps Continue on the target.
   Only that local action opens TLS and sends `PAIR_HELLO`. A hello that arrives
   before the source scan is refused without consuming the source arming.
2. SAS. The person arms both devices. The person then taps Start on the target.
   Only that local action opens TLS and sends `PAIR_HELLO`. The source must
   already be armed. A hello before the source is armed is refused without
   consuming the source arming.

The Continue and Start actions are deliberate. They make the scan and arm order a
person action on both devices, and they stop the target from sending a hello
while the source is still unarmed. P15 and P23 name the UI choice.

Arming rules:

- Arming is a local UI state. It is never set by a network message and never by
  a pairing frame. On a target, it is created only through the pairing
  capability in section 11.4. The API bearer alone cannot arm.
- The armed mechanism is recorded locally. A session whose `mech` byte differs
  from the local armed value is refused before any prompt, with a fixed message.
- Arming expires at one absolute monotonic deadline, `arm_deadline = arm_time +
  120 seconds`. Revision 2 had no arming, so an idle foreground listener could
  present a prompt that nobody asked for. The deadline is absolute: a prompt, a
  retry, or a QR display never extends it. Section 4.2.1.
- The prompt deadline is subordinate to the arming deadline. A ceremony ends at
  the earlier of the two, and a prompt extension never moves `arm_deadline`.
  Section 4.2.1.
- The target consumes its arming when it sends `PAIR_HELLO` (TD1). That send is a
  local action, so it is a consent event. The ceremony continues after it until
  TE1, TE2, or one of TD2 to TD10. A Deny, timeout, protocol error, exporter
  failure, or failed proof is TE2 and ends the ceremony. A retry needs a new
  target arming action and a new ceremony.
- The source does not consume arming on an unauthenticated, malformed,
  mechanism-mismatched, or wrong-payload hello, and not on a hello whose target
  certificate pin differs from the scanned `pin_T`. The source disarms only on
  SD1 to SD10. Of those, only SD7 and SD8 can be caused by a peer. SD7 needs a
  peer that proved the target's key and sent the scanned `pairing_id`. SD8 counts
  only a session whose reveal verified. Malformed frames and unverified reveals
  do not count as attempts.
- A source that counts a failed SAS attempt, including its own person's Deny,
  stays armed for at most two more attempts inside the same 120 second window.
  The existing per-peer and global challenge budgets apply. After the third
  failure the source disarms and the 30 second lockout starts; the person arms
  again after the lockout. Cancel is SD2 and starts no lockout.
- This narrows R4-6 but does not remove the availability attack. A peer that can
  reach the listener and complete a well-formed session can hold the one prompt
  slot until its deadline and can spend the attempt budget. Section 4.3 states
  the residual and does not claim a guarantee.
- The source refuses a SAS or QR pairing session when it is not armed. The
  refusal is one fixed message and produces no prompt, no code, no QR, and no
  store access.
- The `known` mechanism is a credential refresh on an already pinned channel. It
  needs no arming on either side, but it cannot create a record and cannot grant
  a new purpose. It is refused while either side is armed for SAS or QR, so an
  armed first-pairing screen cannot silently become a `known` refresh. Section
  9.5.
- A first-message `FORGET_REQUEST` is a trust-admin operation on a confirmed
  record, not a first-pairing session. It needs no arming, but it is refused
  while the source is armed for SAS or QR, so a remote admin action cannot change
  trust during a first-pairing ceremony. Section 18.2.
- The presence probe does not use this listener, because an unarmed source would
  refuse a SAS or QR session. Section 14.3 moves the probe to the proxy channel.

Arming is exclusive per mechanism:

- A target armed for QR refuses every session whose `mech` is not QR until the
  QR is consumed, expires, or the person clears the session. It does not accept
  a SAS session while a QR is displayed.
- A source holding a scanned QR refuses SAS. The scanned payload is bound to
  `mech = QR` and its `pairing_id`; dropping it requires a new scan.
- A person who wants to change mechanism ends the armed session first. The old
  QR secret is destroyed and the new session gets new nonces and new nonzero
  commitments.
- A QR session that reached a proof and did not succeed consumes the secret and
  ends the source arming (SD7) and the target ceremony (TE2). The source does not
  then offer a code, and the target does not show one.
- A failed SAS session ends that session and the target ceremony (TE2). The
  target must re-arm to retry. The source may accept a new session with new
  nonces, a new `pairing_id`, and new nonzero commitments until its three-attempt
  budget or expiry is reached.
- An armed session is never reused. A new session has new nonces, a new
  `pairing_id`, and, for QR, a new secret.

This is the answer to "the source must accept only a locally armed QR or SAS"
and to "prevent a QR-to-SAS downgrade".

### 4.2.1 Deadlines inside the arming window

One absolute monotonic deadline owns the whole armed state. Every other deadline
is capped by it:

```
arm_deadline      = arm_time + 120 s          (both devices, per armed session)
qr_deadline       = min(created_at + 120 s, arm_deadline)
prompt_deadline   = min(prompt_start + 60 s, arm_deadline)
prompt_extension  = min(person_action_time + 120 s, arm_deadline)
```

Rules:

1. `arm_deadline` is set once, when the person arms. No event moves it forward.
   A retry, a new hello, a prompt extension, a QR redisplay, and a person reading
   the code slowly all consume the same window.
2. `qr_deadline` is anchored at secret creation and capped by `arm_deadline`. A
   late display does not reset it: a QR created near the end of the window
   expires with the window, and a QR created early expires 120 seconds after
   creation even if the person waits before displaying it.
3. The ceremony ends at the earlier of `prompt_deadline` and `arm_deadline`. An
   inactive prompt extension may not outlive the arming. A person who runs out
   mid-prompt gets the fixed timeout message, no record, and must arm again.
4. The source attempt budget lives inside the same window. Three failed proof
   attempts do not extend `arm_deadline`, and the 30 second lockout after the
   third failure starts at that moment.
5. Both devices evaluate the deadline on a monotonic clock. A wall-clock change,
   a timezone change, or a manual clock set does not extend or shorten a window.
6. A session that is mid-handshake when `arm_deadline` passes is refused at the
   next message boundary. The design does not try to interrupt a handshake in
   progress, and it does not accept a reveal that arrives after the deadline.
7. The prompt deadline is a bound on the person, not on the peer. A peer cannot
   extend it by sending bytes; only a local person action can extend an inactive
   prompt, and only up to `arm_deadline`.

The previous revision had a 120 second arming TTL and a separate 60 second active
and 120 second inactive prompt budget without stating which bound wins. A prompt
that outlived its arming would have let a session complete after the person's
armed state had expired. That is closed here by the `min` rules. C55 to C57 test
the boundaries.

### 4.3 The availability attack on arming

Arming is a local consent state, not an authentication state. Anyone who can
reach the pairing listener can take part in a session up to the point where
authentication is required. That gives an unauthenticated peer a limited denial
of service against one ceremony attempt, and this revision states it instead of
denying it:

| Action by a peer that can reach the listener | Effect | Bound |
|---|---|---|
| Opens a well-formed SAS session, lets the source send `PAIR_READY`, then withholds a reveal | Holds the single prompt slot for that session | `prompt_deadline`, one live prompt per source, and the existing connection caps |
| Opens a well-formed SAS session and sends a reveal that verifies its own commitment but does not match the person's code | Spends one of the three attempts | Three attempts, then disarm and a 30 second lockout |
| Repeats the second row three times inside the window | Forces the source to disarm | `arm_deadline` and the lockout; the person must arm again |
| Connects to the pairing listener while the source holds a scanned QR and sends a proof | Consumes the QR secret | One attempt by design; a new QR and a new scan are required |
| Sends malformed, truncated, or mechanism-mismatched frames | No attempt is counted and the arming survives | Fixed frame caps and the invalid-message budget |

What this means, stated plainly:

- The design does not prevent a denial of one ceremony attempt by a peer on the
  hotspot. It bounds it in time and in attempts, and it makes the person's
  recovery one local action.
- The lockout cuts both ways. While it is active, the person cannot complete a
  pairing either. The design accepts that trade because the alternative is an
  unbounded attempt budget.
- The single prompt slot is the resource an attacker competes for. Raising the
  slot count would not fix the attack; it would let one attacker hold several.
- An attacker cannot turn any of these actions into a record, a token, a QR
  payload, or a code. Every row above ends with no record on either side.
- A target device is not exposed to this attack in the same way, because its
  arming is created only through the PC and it is consumed by its own
  `PAIR_HELLO`. A local process that holds the PC is the app-compromise bound,
  not this attack.

Consequence for the product: SAS gives a person a code comparison that needs no
camera, and it gives a hotspot peer a bounded denial of one attempt. QR gives a
higher-entropy bootstrap and no code comparison, and it gives the same peer an
easy way to burn one scanned secret. Neither mechanism is a denial-free option.
Q1 and P3 decide whether SAS ships, and this revision does not select it. C55 to
C58 and U9 test the rows above.


## 5. Identities, certificates, and pins

The long-term key is P-256, used for TLS in both directions and for nothing
else. It is not the X25519 key in `rust/src/pairing.rs`. That key is a pairing v1
artifact and is not reused.

### 5.1 Certificate template

| Field | Value | Reason |
|---|---|---|
| Key | ECDSA P-256 | Supported by rustls, Network.framework, and Conscrypt on every target OS. One signature scheme to test. |
| Signature | ECDSA with SHA-256 | One algorithm on every builder. |
| Version | 3 | Required by every stack. |
| Subject, Issuer | empty sequence, self-signed | No name is used for the trust decision. A name would be a fingerprint. |
| Serial | 16 random bytes | Avoids a fixed value shared by every install. |
| Validity | 2000-01-01 to 2049-12-31 | Pins ignore validity, so a wrong clock must not break pairing. See section 18.6. |
| Extensions | exact allowlist: `basicConstraints` (2.5.29.19), critical, `30 00`; `keyUsage` (2.5.29.15), critical, `03 02 07 80` (digitalSignature only) | Minimal. No SAN, no EKU, no SKI, no AKI, no CT, no OCSP, no AIA. See section 5.6. |

No extension may cause a network fetch. AIA and OCSP would be a request to a
third party, which this project does not make. The pin is the whole trust
decision, so there is nothing to fetch.

The template is not proven on the platform stacks. An empty subject and issuer,
and the absence of an EKU, may be rejected by a platform TLS stack or by its
certificate parser. That is a device test, not a claim. If a platform requires
an EKU or a subject, the template changes on all peers together. The pin does
not change with the template, because the pin is over the key (section 5.5).

### 5.2 One builder per peer, one shared byte layout

| Peer | Builder | Signer |
|---|---|---|
| Rust target | `rcgen` with the shared field values | `ring` ECDSA P-256 with SHA-256 |
| iOS source | fixed TBS byte assembly, no general parser | `SecKeyCreateSignature(kSecKeyAlgorithmECDSASignatureMessageX962SHA256)`, which returns the DER `ECDSA-Sig-Value` that the `signatureValue` BIT STRING carries |
| Android source | fixed TBS byte assembly, no general parser | `Signature.getInstance("SHA256withECDSA")` with the Keystore private key |

All three builders emit the same TBS layout. Fixed vectors compare the TBS
bytes, the field set, and the SPKI key, not the signature.

### 5.3 Signatures are not reproducible

ECDSA with a random nonce produces a different signature for the same TBS on
every build, on every peer, and on every run. A deterministic nonce is not
required and must not be assumed. Consequences:

- No test compares full certificate DER across builders or across runs.
- A certificate is not an identity value. Two certificates that carry the same
  key pin the same, and a reissued certificate with the same key keeps the pin.
- Logs and diagnostics never contain a full certificate. Section 19.
- A signature length varies. Nothing may assume a fixed offset after the
  signature field.

### 5.4 The Android generated certificate is not the identity certificate

`KeyGenParameterSpec` with `PURPOSE_SIGN` produces a self-signed certificate with
a platform-chosen subject, a platform-chosen validity, and vendor-dependent
extensions. That certificate is not used as the identity certificate:

- The app builds the shared TBS and signs it with the Keystore key through
  `Signature`. The private key still never leaves the keystore.
- The app installs the resulting leaf with a custom `X509ExtendedKeyManager` that
  returns the Keystore private key and the built chain. It does not rely on
  `KeyStore.getCertificate` for the identity certificate.
- If a vendor keystore refuses to sign an externally built TBS, that is a device
  finding and a blocked row, not a reason to fall back to the generated
  certificate.

The reason is consistency of the wire identity, not trust. The pin is over the
key either way, but a vendor-chosen subject and validity would make the
cross-platform template test meaningless and would hide a template regression.

### 5.4.1 Keystore digest authorization for Conscrypt

Conscrypt signs the TLS 1.3 `CertificateVerify` for a delegated EC key through
`CryptoUpcalls.ecSignDigestWithPrivateKey()`, which calls
`Signature.getInstance("NONEwithECDSA")` on the Java key. An AndroidKeyStore key
is a delegated key. Android authorizes a Keystore key for a fixed digest set at
generation time, and `NONEwithECDSA` needs `KeyProperties.DIGEST_NONE`.

The identity key must therefore authorize two digests:

| Use | JCA algorithm | Keystore digest |
|---|---|---|
| Certificate TBS signature | `SHA256withECDSA` | `KeyProperties.DIGEST_SHA256` |
| TLS `CertificateVerify` through Conscrypt | `NONEwithECDSA` | `KeyProperties.DIGEST_NONE` |

Rules:

- `KeyGenParameterSpec.Builder.setDigests(KeyProperties.DIGEST_NONE,
  KeyProperties.DIGEST_SHA256)` is required. `DIGEST_NONE` is API 23 and later,
  so it is available at `minSdk 26`.
- An existing key cannot gain a digest authorization. A key created without
  `DIGEST_NONE` must be replaced by a new key, which changes the identity and
  requires a new pairing. The app must say so before it starts.
- If a vendor Keystore rejects `DIGEST_NONE` at generation, or rejects
  `NONEwithECDSA` for that key, the Conscrypt path is blocked on that device.
  There is no exportable-key fallback and no silent provider fallback. The
  shared Rust core with a Keystore `Signer` has the same vendor dependency and
  does not remove it.
- This is separate from the certificate TBS. The TBS is built by the app and
  signed with `SHA256withECDSA`; the handshake signature is made by Conscrypt
  over the handshake transcript.
- A failure maps to one fixed message, "The source device cannot use its
  protected identity key." It is not a pairing prompt and it writes no record.

The Conscrypt source path is verified in section 2.6. Vendor acceptance is a
device test in I15 and R18.

### 5.5 Canonical pin

`pin = SHA-256(0x04 || X || Y)`, where `X` and `Y` are the 32-byte big-endian
coordinates of the P-256 public key point and `0x04` is the uncompressed point
prefix. The value is 32 bytes.

The pin is over the key point, not over the certificate and not over the SPKI
encoding. This is a change from revision 2, which hashed the SPKI DER. The SPKI
is a container that three stacks can re-encode differently; the point is the
same 65 bytes everywhere. It also removes the revision 2 iOS path that built a
26-byte SPKI header by hand.

| Platform | Source of the 65-byte point | Validation |
|---|---|---|
| Rust | own key from `ring` (`EcdsaKeyPair::public_key()`, uncompressed); peer point from the peer leaf's SPKI with one fixed, bounded parse that accepts only `id-ecPublicKey` with `prime256v1` and a 65-byte BIT STRING | reject any other algorithm, curve, or length |
| Android | `ECPublicKey.getW()` from the peer leaf, and the Keystore key's public key for the local pin | `ECParameterSpec` must be P-256; X and Y must be exactly 32 bytes each; reject any other key |
| iOS | `SecCertificateCopyKey` then `SecKeyCopyExternalRepresentation`, which returns the X9.63 uncompressed point for a P-256 key | `kSecAttrKeyType` must be EC, `kSecAttrKeySizeInBits` must be 256; the export must be exactly 65 bytes with a `0x04` prefix |

The iOS key export works for a public key, including the public half of a Secure
Enclave key. A private key export is never attempted.

The Rust peer parse is the only parser added by this design. It is not a general
DER walker: it accepts one fixed shape, caps the input at 4 KiB, and fails closed
on anything else.

A pin is a public value. Comparing it with ordinary equality leaks nothing.
Secret comparisons use a constant-time comparison, as section 9.6 says.

### 5.6 Certificate parsing caps

The chain is capped before parsing and validated after parsing:

- Exactly one certificate in the chain. A second certificate fails the
  handshake.
- At most 4 KiB of DER. A larger input is rejected before any parse.
- After parsing: version 3, exactly two extensions and no others. The allowlist
  is exact:
  - `basicConstraints`, OID 2.5.29.19, critical `TRUE`, DER value `30 00`
    (`cA = FALSE`, no `pathLenConstraint`).
  - `keyUsage`, OID 2.5.29.15, critical `TRUE`, DER value `03 02 07 80`
    (`digitalSignature` only).
  Any other extension is rejected, including SAN, EKU, subject key identifier,
  authority key identifier, AIA, CRL distribution points, OCSP, name
  constraints, certificate policies, or an unknown OID. A duplicate extension is
  rejected, and a repeated OID is a duplicate even when the values match. A
  criticality bit that differs from this allowlist is rejected.
- The public key must be P-256 and the point must be 65 bytes.
- Validity is read but not enforced. Section 18.6.
- A parse failure is a handshake failure. No partial record and no partial pin.

### 5.7 The short label is not authentication

The four-byte label in the trust list is `SHA-256("hs-label-v4" || pin)[0..4]`,
printed as eight hex digits. It is deterministic, so both devices show the same
value for the same pin.

It is a display aid and nothing else:

- Every trust decision compares the full 32-byte pin in constant time.
- A label collision is not a match. Two different pins with the same label are
  two different devices, and the UI must not merge them.
- The SAS screen shows the code and the peer label. The code is the
  authentication. The label only helps a person notice a change.
- User text must not call the label a fingerprint check, a verification, or a
  proof. It may say "short name".

## 6. TLS profile and channel binding

### 6.1 Version policy

TLS 1.3 only. The rustls build has the `tls12` feature disabled. The platform
peers set the minimum and maximum version to 1.3. A TLS 1.2 client is rejected by
the version policy, not by an application check.

### 6.2 Exporter channel binding

Every pairing session and every trust-change exchange binds the live TLS
session with the RFC 9266 `tls-exporter` channel binding:

| Parameter | Value |
|---|---|
| Mechanism | RFC 9266 `tls-exporter` |
| Label | `EXPORTER-Channel-Binding`, 24 ASCII bytes, no terminating NUL |
| Context | empty string (zero length) |
| Length | 32 bytes |

```
cb = exporter(label = "EXPORTER-Channel-Binding", context = "", length = 32)
```

RFC 8446 section 7.5 defines an absent context as the empty string, so a call
with no context and a call with a zero-length context are the same input. On
rustls, `None` and `Some(b"")` are therefore the same input. On iOS, the
no-context call and `create_secret_with_context(..., 0, NULL, ...)` are the same
input. On Conscrypt, a `null` context and an empty `byte[0]` are the same
input. Whether each implementation maps its two API forms to the same bytes is
part of A19; the design does not assume it. The design passes an empty context
on every peer and records which API form that peer used. A peer that passes a
non-empty context does not match. Byte equality across the three stacks is still
a test, not a reading. A3, A4, and I8 are the gates. The revision-3 sentence
"never as no context" was inaccurate and is removed.

Rules:

1. `cb` is computed once per connection, after the handshake completes and
   before the first application message of the pairing or trust exchange.
2. A call before the handshake completes is a failure, not a retry.
3. A result that is not exactly 32 bytes is a failure.
4. `cb` is covered by `commit_T`, by `commit_S`, by the SAS code, by both QR
   proofs, and by the FORGET reply hash. It is not sent as a message field.
5. `cb` is never logged, never shown, and never stored.
6. A peer that cannot produce `cb` fails the session. There is no
   non-exporter profile, no version that omits it, and no setting that
   disables it.
7. `cb` is used once. It is not a key, and nothing is derived from it beyond
   the transcript hash.

Why this is in the transcript: the transcript already covers both pins, so it
fails against an attacker who terminates TLS with a certificate it holds. It
does not fail against a splice where an attacker relays messages between two
sessions that present the same pins and nonces. Covering `cb` makes any
transcript computed on a different TLS session produce a different code, a
different proof, and a different hash. That closes the splice, not the passive
relay. A passive TCP relay is not detected by channel binding and does not need
to be: it cannot decrypt, and it cannot impersonate on a later connection
without a private key.

The proxy data phase does not add an application-level binder. It has no
transcript; the client and server pin checks at the handshake are the binding,
and adding a round trip would add a failure mode without adding an
authentication property. This is a decision, not an omission.

### 6.3 Platform compatibility

| Peer | Call and timing | Documented availability | Verification status |
|---|---|---|---|
| Rust target (macOS 14, Windows, Linux) | `ConnectionCommon::export_keying_material(out, b"EXPORTER-Channel-Binding", Some(b""))` after the handshake completes, never the early exporter | rustls 0.23 | Documented. Proven on loopback for the exporter call, not for this transcript. |
| iOS source (deployment target 17.0) | Wait for `NWConnection` state `.ready`. Call `connection.metadata(definition: NWProtocolTLS.definition)`. If that is nil or the cast to `NWProtocolTLS.Metadata` fails, fail. Read `.securityProtocolMetadata`, which is non-optional, then call `sec_protocol_metadata_create_secret_with_context(metadata, 24, "EXPORTER-Channel-Binding", 0, NULL, 32)`. | `NWConnection.metadata(definition:)` is iOS 12.0 and later and returns an optional. `NWProtocolTLS.Metadata.securityProtocolMetadata` is non-optional and is the result of the TLS handshake. The exporter call is iOS 12.0 and later and returns an optional `dispatch_data_t`. | Documented. The verify block's metadata is **not** retained or used for the exporter. Whether a server-side post-ready metadata returns a usable value is a device test (J3). |
| Android source, bundled Conscrypt provider | `Conscrypt.exportKeyingMaterial(socket, "EXPORTER-Channel-Binding", new byte[0], 32)` after the handshake | Public in `org.conscrypt:conscrypt-android` 2.9.0, AAR `minSdkVersion 21` | Documented as RFC 5705. On TLS 1.3 it is expected to match RFC 8446 section 7.5 and must be proven by A3 and I8. Returns null if the handshake has not completed or the connection is closed. |
| Android source, platform `SSLSocket` | `android.net.ssl.SSLSockets.exportKeyingMaterial(socket, label, new byte[0], 32)` | Android API 31 and later only | Not available on API 26 to 30. See section 6.4. |

Rules for the iOS exporter:

1. Before the connection starts, the source app calls
   `sec_protocol_options_set_peer_authentication_required(options, true)`. The
   verify block decides trust only. It does not by itself require a client
   certificate, and an anonymous client must fail the handshake on both
   listeners. J12 and K12 test it.
2. The metadata used for the exporter is obtained after `.ready`. A handle
   captured in `sec_protocol_options_set_verify_block` is not stored and is not
   reused. The verify block decides trust; it does not produce a long-lived
   metadata object.
3. If `metadata(definition:)` returns nil, the cast to `NWProtocolTLS.Metadata`
   fails, or the exporter call returns nil or a value that is not exactly 32
   bytes, the session fails closed with the fixed exporter message.
   `securityProtocolMetadata` itself is non-optional and is not checked for nil.
4. The ALPN check uses the same post-ready metadata. On iOS 17.0 to 18.4 it
   calls `sec_protocol_metadata_get_negotiated_protocol`. On iOS 18.5 and later
   it calls `sec_protocol_metadata_copy_negotiated_protocol`. The newer call is
   not available at the deployment target. A nil result means no ALPN was
   negotiated and is a hard failure.
5. The post-handshake pin recheck and the ALPN check happen before the exporter
   is used and before any application byte. The order is: ready, metadata, ALPN,
   peer certificate recheck, exporter, transcript.
6. The metadata handle is released after the exporter is copied. The 32-byte
   value is kept only for the transcript and is zeroized when the session ends.
7. The iOS source cannot inspect the client's offered ALPN list. Section 4.1
   rule 4 records that limit. It does not change the exporter requirement.

Two honest caveats:

- Cross-stack byte equality is a test, not a reading. RFC 8446 section 7.5
  fixes the construction, and a public report compares Apple's function with
  `SSL_export_keying_material` on TLS 1.3 and finds the same output, but Apple's
  documentation does not state the construction. The known-answer test in
  `TEST_MATRIX.md` A3 is mandatory before any device row. A mismatch stops the
  design. It is not patched by hashing one side differently.
- Apple documents both a label-only exporter and a label-plus-context
  exporter. This design uses the label-plus-context call with an empty context.
  The TLS 1.2 result is reported to differ from RFC 5705. That is why section 6.6
  requires the negotiated version to be TLS 1.3 and carries an explicit version
  marker. It is also why the design never uses this value outside TLS 1.3.

### 6.4 Android TLS stack decision

The source app keeps `minSdk 26`. The platform `SSLSocket` cannot carry this
profile on API 26 to 30:

| Property | Platform `SSLSocket` floor | Source |
|---|---|---|
| TLS 1.3 | API 29 | `SSLSocket` protocol table |
| ALPN | API 29 | `SSLParameters.setApplicationProtocols`, `setHandshakeApplicationProtocolSelector` |
| Session tickets off | API 29 | `SSLSockets.setUseSessionTickets` |
| Exporter | API 31 | `SSLSockets.exportKeyingMaterial` |

With the platform stack, API 26 to 28 would have no TLS 1.3 and no ALPN, and
API 26 to 30 would have no exporter. The options and the decision:

| Option | Floor | One profile | Cost | Verdict |
|---|---|---|---|---|
| Platform `SSLSocket` only | 31 | yes | none | Rejected. It changes product support without saying so, or it defines a second profile. |
| Platform `SSLSocket` above 30, refuse below | 31 for the proxy, 26 for install | yes | The app installs on 26 to 30 and refuses to start the proxy with a fixed message. That is a visible support reduction. | Rejected unless the maintainer chooses it. See P14. |
| Bundled Conscrypt 2.9.0 | 21 in the AAR, so 26 in this app | yes | One native dependency. The 2.9.0 AAR is 11,105,510 bytes uncompressed: arm64-v8a 2,787,256, armeabi-v7a 1,793,508, x86 2,805,636, x86_64 3,021,328. A new supply chain and a vendor matrix remain. | Selected. See P13 and P19. |
| Shared Rust core on Android via JNI | 26 | yes | NDK build, JNI, a Keystore-backed rustls `Signer`, and a rewrite of the Kotlin relay path. The largest change. | Fallback if Conscrypt fails a gate. |
| Raise `minSdk` to 31 | 31 | yes | Drops Android 8 to 11 users. | Not taken in this revision. See P14. |

Selection rules for the Conscrypt path:

- The app installs the Conscrypt provider explicitly and creates its TLS
  contexts from it. It must not change the process-wide default provider.
- The version is pinned exactly to `org.conscrypt:conscrypt-android:2.9.0` in
  Gradle, with a committed checksum or dependency verification entry. A dynamic
  or ranged version is forbidden.
- Before any handshake byte, and immediately after `accept()` or socket
  creation, the app checks `Conscrypt.isConscrypt(socket)`. The check must run
  before `startHandshake()`. A socket from another provider is a hard failure
  with a fixed message; it is closed before any TLS byte, and there is no
  silent fallback to the platform stack.
- TLS 1.3, ALPN, ticket suppression, and the exporter all come from the
  Conscrypt helper calls, not from the platform `SSLParameters` methods, so no
  API-level branch remains in the TLS path.
- The identity key authorizes `DIGEST_NONE` and `DIGEST_SHA256` as section 5.4.1
  says. A key without `DIGEST_NONE` cannot complete the handshake signature.
- If the shared Rust core is chosen instead, the Android side gets the same
  rustls profile as the target, and the Keystore key is used through a rustls
  `Signer` that calls the Keystore. The two options must not be mixed.

Version, maintenance, and 16 KB alignment:

- Conscrypt 2.9.0 is the current published release at the time of writing
  (Maven Central last updated 2026-11-04). The AAR declares `minSdkVersion 21`.
- The 2.9.0 `arm64-v8a` and `x86_64` native libraries have PT_LOAD alignment
  `0x4000`, which is the 16 KB requirement. The check is recorded in section
  2.4. The app still needs a 16 KB emulator or device run, because ELF alignment
  is necessary and not sufficient.
- The app targets API 36. Google Play's 16 KB page-size requirement for apps
  that target recent Android versions is the reason the build uses AGP 8.5.1 or
  later and `zipalign -P 16`, and why a `PAGE_ALIGNMENT_16K` bundle is required.
  The exact Play deadline must be rechecked against the current policy before
  release; this document does not treat the date as verified.
- Conscrypt upstream has moved primary development inside Google and no longer
  accepts external pull requests. The README recommends the platform-provided
  Conscrypt. The platform version receives Mainline updates; the bundled 2.9.0
  does not. The app must therefore track Conscrypt releases and security
  notices and rebuild on a fixed schedule. If a security fix is not published
  for the bundled artifact, the fallback is the shared Rust core or the API 31
  platform floor, not a silent unmaintained dependency.
- The APK size and per-ABI native size are measured and recorded before release,
  with and without the dependency.

Either way, exactly one TLS implementation serves the pairing listener, the
proxy listener, and the pairing responder on that device.

### 6.5 Failure behaviour

- Exporter unavailable, wrong length, or computed before the handshake: the
  session fails closed with a fixed message. No prompt, no code, no QR proof, no
  store access.
- The post-ready `metadata(definition:)` is nil, or the cast to
  `NWProtocolTLS.Metadata` fails: the session fails closed with the same fixed
  exporter message. There is no retry with a retained verify-block handle.
  `securityProtocolMetadata` itself is non-optional.
- The negotiated ALPN is nil or not exactly the listener label: the session
  fails closed before any application byte. Section 4.1.
- The Keystore key does not authorize `DIGEST_NONE`, or the Conscrypt handshake
  signature is refused by the vendor: the session fails with the fixed protected
  key message. Section 5.4.1.
- Exporter mismatch between peers: the commitment reveals do not match, or the
  code does not match, or the QR proof does not verify. All three are hard
  failures.
- A platform that cannot provide the exporter is not approved as a source
  device. It does not get a weaker mode. It may still be a target device, where
  rustls provides the exporter.

### 6.6 TLS version binding is distinct from the exporter

The TLS 1.2 exporter is built from the master secret, which must be the extended
master secret for the RFC 9266 binding, and it uses the RFC 5705 label and
context encoding. The TLS 1.3 exporter is built from `exporter_master_secret`
and always carries a context (possibly empty). They are different
constructions, and a TLS 1.3 value cannot be compared with a TLS 1.2 value.
Consequences:

- The design is TLS 1.3 only, so only the TLS 1.3 construction is ever computed.
- The transcript carries `tls_version_marker = 0x04`, meaning TLS 1.3. A peer
  that negotiated anything else fails the version policy before this point.
- The exporter value is not a substitute for the version check. Both are
  required.
- Apple's function is reported to produce the TLS 1.3 construction even on a
  TLS 1.2 connection, and the TLS 1.2 value differs from RFC 5705. That is
  another reason the version check is mandatory and separate.

### 6.7 CertificateVerify is verified on every peer

The pin decides which key is trusted. It does not prove that the peer holds the
private key for that certificate. `CertificateVerify` does that, and every peer
must verify it over the handshake transcript before the handshake is accepted.

Rules:

1. A pin check is not a substitute for `CertificateVerify`. A certificate with
   the correct pin and a different private key must fail.
2. On rustls, the custom `ServerCertVerifier` and `ClientCertVerifier` do two
   separate jobs. `verify_server_cert` or `verify_client_cert` compares the pin
   under the store rules. `verify_tls13_signature` must call
   `rustls::crypto::verify_tls13_signature` with the peer certificate and the
   `DigitallySignedStruct`, using the provider's
   `WebPkiSupportedAlgorithms`, and return its result.
3. Do not return `HandshakeSignatureValid::assertion()` without that call.
   rustls makes the marker constructible so a verifier can assert a check it
   performed; it is not evidence that a check happened. A verifier that returns
   it directly disables `CertificateVerify`.
4. On Network.framework and Conscrypt, the TLS stack verifies
   `CertificateVerify`. The app's verify block or `X509TrustManager` decides
   trust only. It must not disable or replace the signature check, and it must
   not set an option that turns peer verification off.
5. A failed `CertificateVerify` is a handshake failure. It does not delete a
   record, does not prompt, and does not name a forget action. The mapping
   depends on the side:
   - On the target, a failed server `CertificateVerify` means that no candidate
     proved its key. It maps to the same neutral message as a pin nonmatch in
     section 7.11, never to `not_trusted`. The existing `not_trusted` text says
     the source does not know this target, which is a claim the target cannot
     make about a server that failed to prove its own key.
   - On the source, a failed client `CertificateVerify` closes the connection
     with no prompt and no store access. The source shows nothing to the person
     for it, because it was not a person action.
6. This is tested in K13 and R20 with a matching pin and a mismatched private
   key.

## 7. Pin store

### 7.1 Store and record

The store is one canonical object with one store-wide generation:

```
store = {
  format,          u8, 0x04
  generation,      u64be, starts at 1, increments on every store change
  record_count,    u16be, 0..16
  records[],       sorted by peer_role, then pin
}

record = {
  local_role,      u8
  peer_role,       u8
  pin,             32 bytes
  purposes,        u8 bit set: 0x01 pairing, 0x02 proxy, 0x04 trust admin
  wire_version,    u8, 0x04
  pairing_id,      16 bytes, from the ceremony
  paired_at,       u64 seconds, informational only
  label,           4 bytes, display only
  state,           u8, 0x01 staged, 0x02 confirmed
}

tag = HMAC-SHA256(
  K_store,
  "hs-store-v4" || u64be(generation) || canonical_store_bytes
)
```

`canonical_store_bytes` is the `format`, `generation`, `record_count`, and the
records in the fixed sort order, with fixed-width fields and no padding. One tag
covers the whole store, so a record cannot be removed, added, or reordered
without changing the tag.

`paired_at` is never used for a policy decision. `label` is never used for a
decision. Only `pin`, `purposes`, `wire_version`, `state`, and the store
`generation` gate anything.

The record does not contain the token. The source service holds the current
token in memory, and the store lock also guards the token copy on the known path.
Token rotation takes the same lock. A token is never written into a record and
never read from a peer message.

`state` is `staged` until the pairing is confirmed by the peer, and `confirmed`
after that. A staged record is a recovery marker, not a trust decision. It is
not used for `known`, not used for proxy traffic, and not shown as a trusted
device. It counts toward the record cap. The target UI lists it as incomplete
and offers a local forget, so a failed ceremony cannot fill the store with
entries that cannot be removed. Section 13.1 defines the transitions.

`K_store` is a random 32-byte key generated on first use and held in the
platform's protected storage. It is never derived from the TLS signing key. A
non-exportable signing key cannot produce an HMAC key, and a design that derives
one has to export the key or add a signing oracle that is not an HMAC.

### 7.2 Multiple identities

The store is a set of records, not one record:

- A target may hold several source devices. A source may hold several target
  devices. Records are keyed by `(peer_role, pin)`.
- A connection whose peer pin matches a confirmed record is `known`. A
  connection whose peer pin matches no record is `unknown`.
- Unknown is not a mismatch. An unknown pin on the pairing listener is a first
  pairing with a new device. An unknown pin on the proxy listener is refused.
- Cap: 8 records per role on a target, 16 on a source. A full store refuses a
  new pairing with a fixed message and names the action to remove a record.
  There is no silent eviction and no oldest-out rule.
- Two records with the same pin and role cannot exist. A duplicate is rejected,
  except for the same-pin re-confirmation in section 7.3.

This is the answer to "define multiple source identities".

### 7.3 Replace and same-pin re-confirmation

Historical and blocked: the following procedure is not an authorized recovery,
replacement or re-pair path. It requires the reviewed incarnation and recovery
models, including local revocation durability.

No protocol message can overwrite, replace, or merge a record. Replace is a
local two-step action:

1. The person removes the old record on the device they are holding. The action
   is named "Forget this device". It is a local removal and is not refused while
   a flow uses the record: the removing side closes its own flows for that pin.
   Section 18 defines the separate remote FORGET rule. The person takes this
   step from what they know, for example that the old source device was reset,
   sold, or lost. The design never supplies that knowledge: a pin nonmatch, a
   failed `CertificateVerify`, a `not_trusted` alert, a timeout, and a truncation
   are never presented as a reason for step 1, and no failure screen links to
   it.
2. The person runs a full new ceremony. The new pin is added as a new record.

When no candidate pin matches, the target cannot tell whether the source was
replaced, reset, or is a different paired source device at the same endpoint. It
does not claim that the identity changed and does not advise forgetting a valid
record. It shows one neutral message, "The hotspot is not answering as any paired
source device. Check that the intended source device is connected and try
again." There is no "continue" button, no automatic replacement, and no remote
replacement. The paired-device list still offers a deliberate local "Forget this
device" action, but the mismatch message does not point at it and names no
record. Section 7.11 and M8.

A mismatch is never a reason to re-prompt with the new identity. A prompt would
let one tap replace a known device. It is also never a reason to delete a record:
the record may still be the correct one for a source that is simply not on the
link.

Same-pin re-confirmation is a recovery path, not a remote replace:

- A full ceremony may create a record for a pin that is not present, or update
  the record for the same `(peer_role, pin)` if one is present. The update sets
  `pairing_id`, `purposes` to the set the ceremony grants, `wire_version`, and
  `state = confirmed`. A `staged` record for the same pin is promoted by this
  full ceremony only; the `known` path never promotes it.
- It cannot touch a record with a different pin and cannot merge two records.
- It is performed by the owner of the store after the ceremony authenticated
  both sides: a matching SAS code with both Allow actions, or a valid QR proof
  with the target Allow. It is not driven by a peer-supplied record identifier.
- It exists so a lost `PAIR_DONE` or a lost `FORGET_RESULT` has a way forward
  without a protocol message that overwrites trust. Section 13.2 and section
  18.4 define the states.
- The record cap still applies when the pin is new. A full store refuses the
  ceremony before any write.

### 7.4 Integrity: what each store actually protects

A substituted pin is a full compromise, so the store is integrity-protected
where the platform can hold a key the device account cannot read. It is not
protected everywhere, and the claim must match.

| Platform | Store key | Protected against | Not protected against |
|---|---|---|---|
| Android | `AndroidKeyStore` HMAC-SHA256 key, `PURPOSE_SIGN`, not user-authentication bound | Other apps, an offline edit of the store, and a restore onto another device | Code running in this app's UID, which can call the Keystore to compute a valid tag |
| iOS | Keychain item, `ThisDeviceOnly` | Other apps, an offline store edit, and a backup restored onto another device | Code running in this app's process with the keychain available; the keychain is the boundary and the tag is a corruption check |
| macOS target | Root-owned file in the engine directory, or a System Keychain item | The signed-in desktop user, who cannot read it | Root, the engine process, and any process that already has root |
| Windows target | DPAPI-protected file, bound to the user account | Other accounts, and a file copied to another machine or account | Any process in the same account |
| Linux target | Root-owned file under `/var/lib/hotspotshade`, mode 0600 | The unprivileged desktop user | Root, and any compromise of the root helper, which runs as root and reads the file |

The Linux row is not a detail. The helper runs as root, and root can read the
store key. A compromise of the helper is therefore a compromise of the store. The
design must not describe the Linux store as protected from a local root attacker,
and the helper must not gain new parsers. It stays argument-free.

On iOS the keychain item and the store key are in the same protection domain, so
the HMAC does not add an integrity boundary against an attacker who can read the
keychain. It is kept as a corruption check only, and the design must not claim
more.

If a platform cannot protect the store key, the design says the tag is a
corruption check. It must not claim HMAC integrity it does not have. A tag
mismatch fails closed with a fixed message. Do not delete the store and do not
re-pair automatically.

### 7.5 Generation, anchor, and rollback

HMAC detects modification and substitution. It does not detect rollback: an
attacker who restores an older, correctly tagged store restores an older trust
set. This revision makes the generation store-wide so a rollback of any part of
the store is a rollback of the whole store.

Rules:

- `generation` starts at 1 and increments by 1 on every successful store
  mutation: add, remove, same-pin re-confirmation, and staged-to-confirmed
  promotion. Only a definite pre-replacement failure leaves the named store
  generation unchanged. A possible replacement or failed flush leaves the
  durable generation uncertain and blocks trust use and dependent success.
- `anchor` is the highest generation this device has committed or accepted. It
  is stored in a second location that is separate from the store: an Android
  Keystore-bound preference, an iOS keychain item, a root-owned file for macOS
  and Linux, and a DPAPI-protected file for Windows.
- A store with `generation < anchor` fails closed. A store with
  `generation == anchor` is accepted. A store with `generation > anchor` is
  not automatically accepted: an explicit recovery model must distinguish a valid
  interrupted commit from rollback or other uncertainty (W20).
- Commit order is store first, anchor second. If the anchor write fails, the
  store and anchor require reviewed recovery; do not automatically repair the
  anchor. If the store write fails, the anchor is unchanged and the
  outcome may be uncertain after replacement; section 7.6 and W20 govern recovery.
- Registration, token delivery, and any other trust-dependent use require a
  validated store with `generation == anchor` under the applicable store lock.
  An absent, unreadable, uncertain, or unequal anchor or store blocks use pending
  reviewed recovery; equality alone does not solve joint rollback.
- A store with `generation == 0`, a count over the cap, a wrong format, a
  duplicate `(peer_role, pin)`, a `local_role` that does not match this device,
  or a `peer_role` that is not the other role fails closed.

Precise rollback limits:

- A rollback restores the whole store, not one record. It can resurrect a record
  the person removed with a local forget, including its purposes.
- It cannot introduce a key that was never in a correctly tagged store. It can
  only restore a key the person once approved.
- If only the target store is rolled back, the source's current store still
  decides. A resurrected target record cannot use the proxy if the source
  removed its matching record. It can still attempt a full ceremony, which the
  source refuses unless it is armed and the person approves.
- If only the source store is rolled back, a target that still holds its record
  can connect again after the source's rolled-back record returns. A target that
  has forgotten the source treats it as unknown and needs a ceremony.
- If both stores are rolled back to the same era, mutual trust returns,
  including for a device the person forgot after that era. That is the precise
  residual. No platform here documents a monotonic counter that survives a
  restore of both locations.
- Live flows are not changed by a rollback. New connections use the restored
  store. A store rollback is not a signal to tear down a live flow.
- Token rotation is separate. A rolled-back target record does not contain the
  token. The target can use the known path to obtain the current token only if
  the source still trusts it after the rollback. Rotation limits an attacker who
  holds only an old token; it does not revoke a restored identity.

This is a documented limit, not a fix. See Q14.

### 7.6 Durable commit

A store change is durable before any message that depends on it:

- Unix files: write a temporary file in the same directory, `fsync` it, `rename`
  it, then `fsync` the directory. A definite failure before replacement leaves
  the old named store. After rename, including a failed directory `fsync`, the
  visible or post-crash state is uncertain; do not assume the old store survived.
- Windows files: write the temporary file, `FlushFileBuffers`, then
  `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`.
  Windows has no documented directory flush; that limit is recorded.
- Android: a file in `noBackupFilesDir` with `FileOutputStream`,
  `getFD().sync()`, and an atomic rename. `SharedPreferences.apply()` is not
  used for a store. `commit()` alone is not treated as an fsync.
- iOS: `SecItemAdd` or `SecItemUpdate` returning success is treated as durable.
- The anchor is written after the store, never before.
- The new store carries `generation + 1`. A partially written store is not a
  store. A temporary partial file is not accepted as a store; it does not prove
  which named store survives an uncertain replacement.

Local revocation is not durably complete until both the removal and its anchor
are established by a reviewed per-host commit and recovery model. After an
uncertain write or restart, block registration, token delivery, trust mutations
and dependent success until that model establishes safe state. A memory-only
epoch can cancel current sessions but cannot persist a removal across restart or
prevent a previously valid record from returning. Do not report durable removal
or assume the old or new state.

Failures after a possible replacement, ambiguous OS errors, process death and
power loss require an explicit per-host recovery model. Until reviewed, block
trust mutations and dependent success messages; do not infer old or new state.
The model must specify validation of store and anchor, allowed recovered states,
credential consistency, retries and operator recovery, and prove platform
semantics rather than assuming equivalent flush guarantees. W20 covers each
boundary, including rename and directory flush failure. Section 13's write points
are historical until that model and the incarnation protocol are reviewed.

### 7.7 Corruption and deletion

- A corrupt store, a tag mismatch, a format mismatch, or a generation below the
  anchor fails closed with "The saved trust data is damaged. Pair again." The
  store is not deleted and not repaired.
- An unreadable store fails closed with "The saved trust data cannot be read."
- A deleted store forces a re-pair. That needs the full ceremony again, which is
  the correct failure direction.
- The store never re-pairs automatically and never offers a repair button.

### 7.8 Lock scope and no network under a lock

A store lock protects only a bounded local operation: read the store, verify its
tag and generation, compare a pin, copy a token, or write a new store. It is
never held across a TLS handshake, a TLS read or write, a network flush, a socket
flush, a connect, an accept, a DNS call, or any other call that can block on the
peer.

The store lock **may** cover the local durable commit in section 7.6: the
temporary-file write, `fsync` or `FlushFileBuffers` or `SecItemAdd`, the rename,
and the directory `fsync` on Unix. That is the one bounded critical section that
makes a read-modify-write atomic. Section 20 bounds it. The distinction is
deliberate: a network flush waits on a peer, while a durable flush waits on the
local filesystem. A design that holds the lock across the first is a deadlock
risk; a design that releases it in the middle of the second reopens the lost
update that the generation and anchor exist to prevent.

One second lock protects the proxy session table, and it has one order: the store
lock first, then the session-table lock. The table lock is never taken first and
is never held across a network call, a TLS call, a network flush, or a local
durable flush. Section 14.1 uses both locks to make registration and removal one
ordered step. A path that takes them in the other order is a defect, and F39
checks the order under load.

The pattern on every path is:

1. Acquire the lock.
2. Read and verify the local bytes. Copy the fields the decision needs: pin,
   purposes, wire version, state, generation, and, only on the known path, the
   token.
3. Release the lock.
4. Perform the network operation with the copied values.

Consequences:

- A removal that happens after the copy can allow a handshake or issue a
  credential that was authorized a moment earlier. The credential is immediately
  unusable if the source no longer has the record, because the next proxy
  connection fails the client pin check only while no same-pin re-pair intervenes.
  A registered session is detached and cancelled by the proposed sweep. The
  local epoch and locks alone cannot distinguish a new incarnation or close the
  same-pin race. Section 14.1 and W17 to W19.
- A `FORGET` deletion is a local durable write under the lock. The reply is
  framed after the lock is released. If the send fails, the deletion stands and
  section 18.4 applies.
- A store write that needs to read and replace the whole store is one bounded
  critical section. It does not perform I/O on the network. A slow filesystem
  can extend the hold time; the budget in section 20 bounds it and the design
  does not wait on a peer while holding it. The local durable flush is inside the
  section; the network flush is outside it.
- A test that blocks the network write and attempts a concurrent store mutation
  must not deadlock. It is R17. A lock held across the blocked write is a defect.

### 7.9 No lock across the handshake verifier

The TLS verifier callback follows section 7.8. It reads the record under the
lock, copies the pin, purposes, wire version, state, and generation, releases the
lock, and then returns allow or deny to the TLS stack. The post-handshake
recheck repeats the same pattern before the first application byte. The
verifier never holds the lock while the TLS stack continues the handshake.

### 7.10 Per-record credentials

The record itself never holds the token. The target keeps a separate in-memory
credential map, keyed by `(peer_role, pin)`:

```
credential = {
  host,               source listener hotspot address, from PAIR_RESULT
  port,               source proxy listener port, from PAIR_RESULT
  token,              1..64 bytes, from PAIR_RESULT
  pairing_id,         16 bytes from the ceremony that issued it
  issued_generation,  store generation at issue
}
```

Rules:

- One entry per confirmed record. A credential is not shared between records.
- The target selects a candidate set by the dialed host and port, then binds the
  exact record by the verified server pin. It never selects a token before the
  pin match. Section 7.11.
- The token sent in SOCKS5 authentication is the token for the pin that matched
  the server certificate exactly. The source cannot obtain another source's
  token, because it cannot present that source's pin without its private key.
- A failed or removed record removes only its own credential. Forgetting source
  A leaves source B's credential intact.
- `host` and `port` come from the source's own listener settings at pairing
  time: the bound hotspot address and the bound proxy port. They are never
  copied from `PAIR_HELLO`, from the client's socket, from an HTTP header, or
  from a previous record. If the source address or proxy port changes, the
  target learns the new values only through the known path on the pairing
  listener, which requires the source app to be open.
- A credential whose `issued_generation` is older than the record's current
  `generation` is stale. It may still be used for a live flow already open, but
  a new connection uses the record and the current token. Token rotation
  invalidates old tokens at the source; the target learns the new token only
  through `known` or a full ceremony.
- A confirmed record with no credential entry cannot open a proxy connection.
  The target runs the known path first, which needs the source app open. After a
  target restart, the record survives but the token does not, so a known
  refresh is required before the first proxy connection.
- The map is memory only. It is never written to the store, a log, a status, a
  diagnostics answer, or a failure record. It survives a tunnel stop and is
  cleared on engine process exit and record removal. A source token rotation
  invalidates old tokens at the source; the target learns the new token through
  the known path or a new ceremony. Section 11.4.3.

### 7.10.1 A target restart needs the source app in the foreground

The credential map does not survive a target restart. The record does, so the
target can still prove which source it trusts, but it has no token. The first
proxy connection after a restart therefore needs a `known` refresh, and the known
path runs on the pairing listener:

1. The target start action finds a confirmed record with no credential entry.
2. It dials the source's last known endpoint on `hs-pair/1` and runs the known
   path once.
3. On iOS and Android the pairing listener exists only while the source device
   app is open and in the foreground. An app that is installed, running in the
   background, or suspended is not enough.
4. If the dial or the known session fails, the target shows one fixed message:
   "Open the HotspotShade app on the source device and keep it in the
   foreground, then try again."
5. The target does not retry on a timer. It does not poll the pairing listener in
   the background. It does not start a proxy connection without a token. The
   person may retry, which is a new person action, and there is one attempt per
   action.
6. When the known session succeeds, the credential is written and the proxy
   connection proceeds in the same start action. The person does not pair again.

The consequence is visible and unwelcome: after every target restart, a person
who wants the tunnel must also bring the source device app to the foreground
once. Section 25 records it as a product consequence, P4 records the alternative
of persisting the token in the target store, and E30 and U17 test the flow. The
design does not claim that a target restart is transparent.

### 7.11 Candidate pins on a shared hotspot gateway

A hotspot gateway address is not a source identity. Two paired source devices can
present the same gateway address and the same proxy port, and the target cannot
tell which one is on the link until the server certificate arrives. The target
therefore separates **candidate selection** from **token association**.

Rules:

1. Candidate selection uses only the dialed endpoint. The target collects every
   confirmed record with the proxy purpose whose credential `host` and `port`
   equal the endpoint it is about to dial. The set is capped by the target record
   cap, so it is at most 8 entries. An empty set means the target has no
   credential for that endpoint and it does not dial.
2. The target opens one normalized outer socket and one TLS connection to that
   endpoint. The handshake may request its client certificate. The server pin is
   not known yet.
3. The target verifies the server certificate and computes the server pin before
   the client certificate flight. In TLS 1.3 the client processes the server
   `Certificate`, `CertificateVerify`, and `Finished` before it sends its own
   `Certificate`. The rustls `ServerCertVerifier` is the hook, and an error from
   `verify_server_cert` or `verify_tls13_signature` aborts the handshake before
   the client certificate is emitted. A reading of the rustls 0.23.46 source
   shows the order precisely: `ExpectCertificateRequest::handle` calls the
   client certificate resolver when CertificateRequest arrives, which is before
   the server checks; `ExpectCertificateVerify::handle` runs the two server
   checks; and only `ExpectFinished::handle`, after the server `Finished` is
   verified, emits the client `Certificate` and signs `CertificateVerify`. A
   resolver call therefore selects a key but puts nothing on the wire, and it is
   not evidence of disclosure. This is a protocol order and a source reading,
   not a claim that every stack exposes it. V5 is a mandatory deterministic
   host gate for rustls: it counts what the server receives and what the client
   key signs, and both must be zero on a rejected server. E27 records the actual
   order on each other stack. If a stack cannot enforce it, the target records
   the client-certificate disclosure as a limitation and still sends no token.
4. Exactly one candidate must match the server pin. If none matches, the target
   aborts and sends no application byte. It cannot conclude that the source
   identity changed, even when the candidate set has one entry: another paired
   source can share the endpoint, and a replaced source is indistinguishable from
   a different device. The message is the same for every candidate count: "The
   hotspot is not answering as any paired source device. Check that the intended
   source device is connected and try again." It names no record, offers no
   forget action, and deletes nothing. Zero candidates means the target does not
   dial at all and says it has no stored credential for this endpoint. If the
   same pin appears in two candidates, that is a duplicate record and the store
   rules reject it before dialing.
5. Only after the matching candidate is known does the target copy that exact
   record's token, host, port, and `pairing_id` into the session. It never copies
   a token from another candidate, and it never retries with another candidate's
   token.
6. A failed candidate match is not a reason to try the next candidate. The
   server at that endpoint is one device with one server certificate. Trying
   another candidate would only disclose the client certificate and the attempt
   to a server that already failed the pin check.
7. The source pin is recomputed after the handshake and compared again before the
   first SOCKS5 byte, as section 14 requires. A change between the two checks
   aborts.
8. The session records the exact `(peer_role, pin)` it bound. That value is the
   per-session client pin used by source revocation in section 18.2.

The target may hold two records that point at different endpoints. That is not a
candidate set. It selects the endpoint first, from the target's own route or from
the source's last known credential, and applies the candidate rule only within
that endpoint.

The candidate count is a diagnostic input and nothing else. It must not change
the protocol, the message, or the action offered, and it must not become a way to
try another candidate's token. A count of one or two does not authorize a
fallback and does not prove an identity change. U10 and V9 test that the neutral
message is shown for every candidate count, that no record is named, and that no
forget action appears.

### 7.11.1 Canonical host encoding

The credential entry is keyed by host and port, and the host is compared with the
address the target actually connected to. A textual field with no canonical form
would make two encodings of one address look like two endpoints. The field
therefore has exactly one encoding:

| Rule | Value |
|---|---|
| Form | ASCII decimal dotted-quad IPv4, for example `192.168.42.1` |
| Digits | decimal only, no leading zero, no `+`, no spaces, no tabs |
| Separators | exactly three `.` bytes, no trailing dot, no port, no brackets |
| Case | not applicable, because there are no letters |
| Zone or scope | not allowed; a `%` byte is a protocol error |
| Family | IPv4 only in this revision |
| Length | 7 to 15 bytes, which the existing `host_len` bound already allows |
| Comparison | byte equality with the canonical rendering of the connected peer address |

Rules:

- `PAIR_RESULT` carries a value the source rendered from its own bound listener
  address. It never copies an address from `PAIR_HELLO`, from the client socket,
  or from a header.
- The target parses the field as an IPv4 address. It rejects a value that is not
  the exact canonical rendering of the address it dialed, and it rejects a value
  whose canonical rendering differs by even one byte. It stores the canonical
  bytes, not the received string.
- A leading zero, a trailing dot, an embedded space, a port suffix, a bracket
  form, a `%` scope, an IPv6 literal, or an octet over 255 is a protocol error.
  The session ends before any credential write.
- An IPv6 hotspot listener is out of scope for this revision. The target tunnel
  and the source listener are IPv4 today, and the design does not define a second
  host family without a review note. A future IPv6 listener needs its own
  canonical form (RFC 5952 compressed lowercase, no brackets, no zone) and a new
  vector.
- QV19 fixes the bytes for the canonical form and for the seven rejected
  non-canonical forms listed in U20. E29 tests both on the host.

The reason for the strictness is not cosmetic. The host value decides which
credential entry is updated, and a value with two encodings would let a session
write a second entry for the same endpoint or fail to find the first.

## 8. iOS identity and locked key access

Terminology: this document calls the iOS app the source device app. It is the
TLS server role. "Verify block" means the block passed to
`sec_protocol_options_set_verify_block`; it decides trust and is not the source
of the exporter metadata. Network.framework calls the accepted endpoint a
connection; the design names the device the source device.

`SecIdentityCreateWithCertificate` is documented as macOS only. It must not be
used on iOS.

iOS has a documented public path. `kSecClassIdentity` is available on iOS 2.0
and later, and Apple documents that Keychain services represents the pair as an
identity when the certificate's `kSecAttrPublicKeyHash` matches the key's
`kSecAttrApplicationLabel`.

The iOS sequence is:

1. Generate a P-256 key with `SecKeyCreateRandomKey` (iOS 10.0 and later), not
   the older `SecKeyGeneratePair`. Use `kSecAttrTokenIDSecureEnclave` when
   available, `kSecAttrIsPermanent`, and a `kSecAttrAccessControl` with
   `kSecAccessControlPrivateKeyUsage` plus the chosen accessibility class. When
   a Secure Enclave key cannot be created, fall back to a keychain key and record
   which one the build used.
2. Build the minimal self-signed certificate DER from the fixed template and
   sign the `TBSCertificate` with
   `SecKeyCreateSignature(kSecKeyAlgorithmECDSASignatureMessageX962SHA256)`.
   That call returns a DER `ECDSA-Sig-Value`, which is exactly the
   `signatureValue` BIT STRING content, so no signature re-encoding is needed.
3. `SecItemAdd` the certificate with `kSecClassCertificate`. The keychain
   computes `kSecAttrPublicKeyHash` from it.
4. `SecItemCopyMatching` with `kSecClassIdentity` returns the `SecIdentity`
   because the hashes match.
5. `sec_identity_create` produces the `sec_identity_t` for
   `sec_protocol_options_set_local_identity`.

Step 2 needs about 80 lines of deterministic byte assembly and no dependency. It
has no parser, because it only ever emits a fixed layout. It needs fixed vectors,
including one produced by the Rust side, so all three platforms agree on the TBS
byte for byte. The signature itself is not reproducible, as section 5.3 says.

### 8.1 Locked key access

A keychain key with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` cannot sign
while the device is locked. A Secure Enclave key may also fail with
`errSecInteractionNotAllowed` when the device is locked or the passcode is
removed. The source app's foreground service can run while the screen is locked,
so this is a real behavior, not an edge case.

Rules:

- The app must not fall back to an exportable key, a software key, or a token
  when the protected key cannot be used.
- A failed key operation maps to one fixed message: "The source device is
  locked. Unlock it and try again." The message holds no token, key, pin, or
  certificate.
- A new TLS handshake fails while the key is unavailable. An established TLS
  flow can continue because TLS 1.3 key updates use traffic secrets, not the
  long-term signing key. That is a claim about TLS, not about the app's
  behavior; it needs a device test.
- The pairing listener must not show a prompt or write a pin if it cannot sign.
  It fails before the prompt.
- The accessibility class is a product decision. `AfterFirstUnlockThisDeviceOnly`
  matches the existing token store and keeps the foreground proxy usable while
  locked after the first unlock. `WhenUnlockedThisDeviceOnly` is stronger and
  stops new handshakes while locked. The app must state which class the build
  uses.
- Do not add `kSecAccessControlUserPresence` or a biometric requirement without
  a product decision. It would require a person for each new connection and
  break background use.
- If the exporter cannot be computed while locked, the session fails like any
  other exporter failure. There is no fallback.

### 8.2 iOS background gate

iOS does not provide a general foreground-service model. This design does not
claim one.

- The pairing listener runs only while the source app is in the foreground. A
  backgrounded app stops accepting pairing connections and clears arming (SD4 and
  SD10 in section 4.2).
- The proxy may run under an approved background mode, but the system can
  suspend or terminate it. A live flow that the system suspends is not a
  protocol failure and may end as a truncation on the target.
- The app must not present a notification-driven approval flow as a background
  feature. It may not approve a pairing from a notification.
- If the product needs continuous background service, that is a separate
  design with its own platform evidence. It is not part of this revision.
- J13 and G23 record the behavior. Until they run, iOS source mode is
  foreground-only and the background claim is not made.

## 9. Trust bootstrap: common rules

Three mechanisms: SAS and QR for a first pairing, and `known` for an existing
record. All end in the same state: each side stores one complete record for the
other, bound to one wire version and one purpose set.

The first pairing is unauthenticated. TLS proves that each side holds the
private key for the certificate it presents, but it does not prove that the
certificate belongs to the intended device. The code comparison or the QR
secret is the authentication. A person who approves without comparing is not
protected.

Common rules:

- The transcript is built from the certificates on this TLS connection. Pins
  are computed locally and are never accepted from an application message.
- Every transcript and proof is domain-separated by an ASCII label, a version
  byte, the mechanism, the flags, both role bytes, the purpose, the ALPN, the
  TLS version marker, the exporter value, both pins, both nonces, and the
  session `pairing_id`. The order is fixed by role name, not by who spoke first.
- Fixed-length fields are in the order shown. A variable-length field is
  prefixed with its two-byte big-endian length. This prevents ambiguity between
  concatenated values.
- Nonces are 32 random bytes from the platform random source. A random-source
  failure aborts the session before any message is sent.
- `pairing_id` is 16 random bytes chosen by the target for every session. On the
  SAS and known paths it is carried in `PAIR_HELLO`; on QR it is in the scanned
  payload and `PAIR_HELLO` must carry the same value. A zero value is invalid on
  every path.
- The target sends first in the transport, because it is the TLS client. That
  is a transport fact and does not decide the transcript order.
- A pairing session carries exactly one attempt. A retry is a new session with
  new nonces, a new `pairing_id`, new nonzero commitments, and, for QR, a new
  secret.
- No record is written before the write points in section 13.
- A pin that matches no record is unknown and may be added by a completed
  ceremony only. It is never accepted by a prompt and never replaces an existing
  record. The target does not claim that a nonmatch proves an identity change:
  another paired source can sit at the same endpoint, and a replaced source is
  indistinguishable from a different device. Section 7.11 and M8.
- The code and the QR secret are shown on a native target app surface only. They
  are never logged, never put in a diagnostics answer, and never in a status
  response. See section 11.4. Neither reaches the browser GUI.
- The pairing listener keeps the existing connection, frame, prompt, and rate
  limits. See section 20.
- Both devices must be armed for SAS and QR. The `known` path needs no arming,
  cannot create a record, and cannot grant a new purpose. It is refused while
  either side is armed for SAS or QR. Section 12.
- A session whose mechanism differs from the local armed value is refused. It
  never switches mechanism inside the session. Section 9.5.

### 9.1 Message framing

All pairing messages are inside TLS with ALPN `hs-pair/1`, with a two-byte
big-endian length, a one-byte message type, and a one-byte version. The length
field counts the body after itself and is at most 510, so the whole frame is at
most 512 bytes. A frame over that bound, or whose type is not defined for the
current state, closes the session. The parser never allocates by a declared
length before the bound check. The message type table is in section 18.1 and
covers both the pairing frames and the FORGET frames.

The frame body is `u8(type) || u8(version) || payload`. The payload layout is
fixed per type, so a parser never guesses a field length:

| Type | Payload |
|---|---|
| `PAIR_HELLO` | `u8 mech, u8 flags, pairing_id[16], commit_T[32]` |
| `PAIR_READY` | `commit_S[32]` |
| `PAIR_REVEAL_T` | `nonce_T[32]` |
| `PAIR_REVEAL_S` | `nonce_S[32]` on SAS and known; `nonce_S[32]` then `proof_source[32]` on QR |
| `PAIR_CONFIRM_S` | `th(0x02)[32]` |
| `PAIR_CONFIRM_T` | `th(0x03)[32]` |
| `PAIR_RESULT` | `u8 status, u16be port, u16be token_len, token[token_len], u16be host_len, host[host_len], th(0x04)[32]`, with `token_len` 1 to 64 and `host_len` 1 to 255 |
| `PAIR_DONE` | `th(0x05)[32]` |
| `PAIR_DONE_ACK` | `th(0x06)[32]` |
| `PAIR_KNOWN_OK` | `th(0x01)[32]` |
| `PAIR_PROOF_T` | `proof_target[32]` |
| `FORGET_REQUEST` | section 18.1 |
| `FORGET_RESULT` | section 18.1 |

A body that does not match the row for its type and mechanism, or that exceeds
the 510-byte body bound, is a protocol error before any field is used. The
`mech` byte in `PAIR_HELLO` decides which `PAIR_REVEAL_S` layout is valid; a
session cannot change `mech`. `PAIR_RESULT` accepts only `status = 0x00`; any
other status is a fixed protocol error and no record is written.

### 9.2 Transcript context

One canonical byte string, built identically on both sides:

```
ctx =
  "hs-pair-ctx-v4"                   ASCII, 14 bytes
  u8(WIRE_VER = 0x04)
  u8(mech)                           0x01 SAS, 0x02 QR, 0x03 known
  u8(flags)                          HS_FLAG_QR_REQUIRED = 0x01 (bit 0)
                                     every other bit must be zero
  u8(role_T = 0x01) || u8(role_S = 0x02)
  u8(purpose = 0x01)                 pairing
  u16be(len(alpn)) || alpn
  u8(tls_version_marker = 0x04)      TLS 1.3
  u16be(32) || cb                     exporter, section 6.2
  pin_T[32] || pin_S[32]
  nonce_T[32] || nonce_S[32]
  pairing_id[16]                     16 random bytes on every path
```

`pin_T` and `pin_S` are known before the first message, because both
certificates are already exchanged by TLS. `cb` is known before the first
message for the same reason.

`WIRE_VER = 0x04` is the wire version of this design. It is separate from
`tls_version_marker = 0x04`, which means TLS 1.3. The two fields happen to have
the same value and are never merged. The deployed pairing protocol is v1 and
uses no TLS. This design replaces it in one release; draft v2 and v3 were never
deployed. A record with `wire_version = 0x04` is not usable by a v1 listener,
and this design does not run a v1 listener.

`mech` and `flags` are covered by `ctx`; the state byte is covered by
`th(state)`. A peer that changes the mechanism or a flag mid-session produces a
different commitment, a different code, and a different hash.

`flags` is one byte with exactly one defined bit: `HS_FLAG_QR_REQUIRED = 0x01`.
The value is not a bit index. A frame with `flags & 0xfe != 0` is a protocol
error before either commitment is used. `PAIR_HELLO` and every commitment use
the same masking rule.

### 9.3 Commitments

Every path commits before either nonce is revealed:

```
commit_T = SHA-256(
  "hs-pair-commit-v4" ||
  u8(WIRE_VER) || u8(mech) || u8(flags) ||
  u8(role_T) || u8(role_S) || u8(purpose) ||
  u16be(len(alpn)) || alpn || u8(0x04) ||
  u16be(32) || cb ||
  pin_T || pin_S || nonce_T || pairing_id
)

commit_S = SHA-256(
  "hs-pair-commit-v4" ||
  u8(WIRE_VER) || u8(mech) || u8(flags) ||
  u8(role_T) || u8(role_S) || u8(purpose) ||
  u16be(len(alpn)) || alpn || u8(0x04) ||
  u16be(32) || cb ||
  pin_T || pin_S || nonce_S || pairing_id
)
```

The target chooses `nonce_T` before it sends `PAIR_HELLO`. The source chooses
`nonce_S` after it sees `commit_T` but before it sees `nonce_T`. The target
reveals `nonce_T` only after it sees `commit_S`, and the source reveals `nonce_S`
only after it sees `nonce_T`.

A malicious source cannot choose `nonce_S` after seeing `nonce_T`, and a
malicious target cannot choose `nonce_T` after seeing `nonce_S`. A peer that
reveals a nonce that does not match its commitment is rejected.

The commitments are real hashes on SAS, QR, and known. They are never zero, and
an all-zero `commit_T` or `commit_S` is invalid on every path. The QR and known
paths do not use a zero commitment, because a zero value carries no freshness and
would let a peer choose its nonce after seeing the other.

### 9.4 Confirmation context and transcript hash

```
confirm_ctx = ctx || commit_T[32] || commit_S[32]

th(state) = SHA-256("hs-pair-th-v4" || confirm_ctx || u8(state))
```

The state byte is distinct per message, so a hash captured from one message
cannot be replayed into another:

| State | Message |
|---|---|
| `0x01` | `PAIR_KNOWN_OK` |
| `0x02` | `PAIR_CONFIRM_S` |
| `0x03` | `PAIR_CONFIRM_T` |
| `0x04` | `PAIR_RESULT` |
| `0x05` | `PAIR_DONE` |
| `0x06` | `PAIR_DONE_ACK` |
| `0x07` | retired. `PAIR_NEED_PROMPT` is removed; a state byte is never reused. |
| `0x08` | `FORGET_RESULT` |

`FORGET_RESULT` uses `forget_hash` in section 18.1, which carries the same state
byte `0x08` under the separate `hs-forget-th-v4` label. It is not `th(0x08)`.
The state byte namespace is shared; the hash domain is not.

`th(state)` is what every confirmation message carries. A message whose
`th(state)` does not match the locally computed value closes the session with a
fixed protocol error. There is no partial acceptance and no "warn and continue".
A known session cannot move to a prompt. If the known check fails, the session
ends and a full ceremony is a new session with new nonces, a new `pairing_id`,
and new nonzero commitments.

### 9.5 Mechanism binding and no downgrade

Historical procedure: any commit or promotion described here is blocked and
non-executable until the incarnation and per-host recovery models pass review.
No success or durable state may be inferred from this sequence.


The mechanism is chosen by the target, recorded in `ctx`, covered by both
commitments, and fixed for the session.

Rules:

1. `mech` is set by the target in `PAIR_HELLO`. For SAS and QR it must equal the
   target's locally armed mechanism. For `known` the target must hold a
   confirmed record for the source pin, and neither side may be armed for SAS or
   QR.
2. The source refuses the session unless its own armed mechanism equals `mech`
   for SAS and QR, or, for `known`, it holds a confirmed record for the target
   pin and neither side is armed for SAS or QR. The refusal is before any
   prompt.
3. No message may change `mech`. A second `PAIR_HELLO` with a different `mech`,
   or a `mech` that differs from the commitment, closes the session.
4. There is no in-session fallback from QR to SAS and none from SAS to QR. The
   UI must not offer "use the code instead" or "show a QR instead" inside a
   session. To change mechanism, the person ends the session and arms the other
   one.
5. A target that requires QR by local policy sets `HS_FLAG_QR_REQUIRED`
   (`0x01`). A source that does not support QR refuses the session. It must
   never answer a QR-required target with SAS. A `PAIR_HELLO` with
   `HS_FLAG_QR_REQUIRED` set and `mech` other than QR is a protocol error, not a
   SAS session. Any bit outside `0x01` is also a protocol error.
6. A mechanism mismatch is a hard failure with one fixed message. It is not a
   prompt, not a warning, and not a reason to show a code.
7. `known` is a separate mechanism. A known session never becomes a prompt in
   the same session. If the target has no confirmed record, it must not choose
   `known`; if the source has no confirmed record, it refuses the known session
   before any prompt. The target then shows a fixed "pairing is incomplete"
   message and offers a new full ceremony. The new ceremony is a new session
   with new nonces, a new `pairing_id`, and new nonzero commitments. It is not a
   continuation.
8. A QR-armed target refuses every `mech` other than QR until the QR is
   consumed, expires, or is cleared. A source holding a scanned QR refuses SAS.
   A failed QR proof consumes the secret and ends the session. There is no
   SAS fallback after a QR failure.
9. A QR session never shows a SAS code. A SAS session never shows a QR. The UI
   has no in-session control that changes the mechanism.
10. A `known` failure does not write a record, does not delete a record, and
    does not change `mech`. It leaves the existing records as they were.
11. An armed SAS or QR session refuses `known` with the fixed mechanism-mismatch
    message. The known path runs only when neither side is armed for a
    first-pairing mechanism. A person who opened the pairing screen gets the
    mechanism they chose, not a silent refresh. This refusal is local and needs
    no wire change.

This is the answer to "prevent forced QR-to-SAS clickthrough" and to the
revision-3 finding that a known session could switch to a prompt.

### 9.6 Constant-time verification

| Peer | Call | Note |
|---|---|---|
| Rust | `subtle::ConstantTimeEq` on `[u8; 32]`, with `subtle` added as a direct dependency (it is already in the rustls tree), or `ring::constant_time::verify_slices_are_equal` | Do not use `==` on secrets. |
| iOS | `timingsafe_bcmp(a, b, 32) == 0` | Compare equal-length fixed buffers. Do not use `memcmp`, `==` on `Data`, or `elementsEqual`. |
| Android | `java.security.MessageDigest.isEqual(a, b)` | Documented as examining all bytes and taking time independent of content. Call it only with two 32-byte arrays so the length branch cannot differ. |

A compare that returns on the first differing byte is a defect. The unit tests
assert that the comparison does not short-circuit, and code review is the
evidence. A timing measurement is not proof.

## 10. Mechanism A: numeric comparison (SAS)

This keeps today's interaction: a six-digit code on both screens and an Allow
or Deny action on both devices. Both devices must be armed for SAS.

### 10.1 Messages

Historical procedure: any commit or promotion described here is blocked and
non-executable until the incarnation and per-host recovery models pass review.
No success or durable state may be inferred from this sequence.


Before step 1, both devices are armed for SAS. The person taps Start on the
target. Only that local action opens TLS and sends `PAIR_HELLO`. A hello before
the source is armed is refused without consuming the source arming; the person
can retry after the source is armed, until the target arming or the source
attempt budget expires.

1. Target to source: `PAIR_HELLO { version, mech = SAS, flags, pairing_id,
   commit_T }`. `pairing_id` is 16 fresh random bytes. `flags` uses the
   `HS_FLAG_QR_REQUIRED = 0x01` mask; every other bit is zero.
2. Source to target: `PAIR_READY { version, commit_S }`.
3. Target to source: `PAIR_REVEAL_T { nonce_T }`.
4. Source to target: `PAIR_REVEAL_S { nonce_S }`.
5. Both verify the peer commitment. A mismatch, an all-zero commitment, or a
   repeated nonce aborts the session.
6. Both compute the code and show it with the peer label. Both require an
   explicit local Allow or Deny. A target that already holds a confirmed record
   for the same pin is running a same-pin re-confirmation (section 7.3); it
   still shows the code and still requires Allow.
7. Source to target: `PAIR_CONFIRM_S { th(0x02) }`, sent only after the source
   user allowed.
8. Target to source: `PAIR_CONFIRM_T { th(0x03) }`, sent only after the target
   user allowed and the target verified `PAIR_CONFIRM_S`.
9. Source to target: `PAIR_RESULT { status, port, token_len, token, host_len,
   host, th(0x04) }`, sent only after the source verifies `th(0x03)`. The source
   does not write its record yet. It sends the current in-memory token; it does
   not read a token from the store on this path. `host` and `port` are the
   source listener's own bound hotspot address and proxy port, never a value
   from the client or from `PAIR_HELLO`.
10. Target validates every field and the hash. It checks that `host` equals the
    address it connected to, that `port` is usable and is not 18090, and that
    `token` is non-empty and within bounds. It writes a `staged` record durably
    and keeps the token in memory. It does not write a credential entry yet,
    because a staged record is not usable for proxy traffic. It then sends
    `PAIR_DONE { th(0x05) }`.
11. Source commits its own confirmed record durably, then sends
    `PAIR_DONE_ACK { th(0x06) }`.
12. Target promotes its `staged` record to `confirmed` durably and writes the
    credential entry for that `(peer_role, pin)`. The promotion is a local state
    change and is not a protocol message. A lost `PAIR_DONE_ACK` leaves the
    record `staged` and no credential; section 13.2 defines the recovery.

### 10.2 Code

```
v = SHA-256("hs-pair-sas-v4" || confirm_ctx)
code = (u32be(v[0..4])) mod 1_000_000
     = ((v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3]) mod 1_000_000
```

The code is printed as six decimal digits with leading zeros, in two groups of
three. Both sides use the same `mech` and `flags` bytes, so a session that
changed either produces a different code. A test vector fixes the 4-byte value
and the resulting integer (QV8). The reduction is a plain modulo; it is not
uniform over a 32-bit value, which is acceptable for a 20-bit display code.

### 10.3 Explicit confirmation

The prompt path requires a local Allow on both devices. The target's Allow is
not optional. The source's Allow is not optional. A denial, a timeout, or a
lost confirmation leaves no record on the side that did not complete. There is
no "the code changed, accept it" button.

The target shows:

- the six-digit code;
- the source's short label;
- Allow and Deny.

The source shows the same code and the target's short label. Neither screen
shows the full pin, a token, a certificate, or the exporter value.

### 10.4 Residual risk

A six-digit code is a 20-bit value. Commit-reveal removes the within-session
adaptive attack, but an attacker who can run many pairing sessions and choose
which two sessions to splice can search across sessions. The probability of a
match grows with the number of session pairs. The exporter binding removes the
splice that reuses one session's messages in another session, but not the
cross-session search over independent attempts.

The design bounds this with:

- local arming on both devices, with a 120 second TTL;
- one active prompt per source device;
- the existing per-peer and global challenge budgets;
- a lockout after repeated failures;
- no automatic retry.

It does not claim the SAS is safe against an unbounded, patient attacker. If the
new review treats this residual as a blocker, QR becomes the only approved
bootstrap and the SAS is removed. That is Q1, not a decision made here.

## 11. Mechanism B: high-entropy QR

Same protocol shape, different authentication. The target displays a QR that
holds `{ version, pairing_id[16], pin_T[32], secret[32], ttl_seconds }`. The
person scans it with the source device. The secret never crosses the wire.

### 11.1 Proofs

```
proof_source = HMAC-SHA256(
  secret,
  "hs-pair-qr-v4" || u8(0x02) || confirm_ctx
)

proof_target = HMAC-SHA256(
  secret,
  "hs-pair-qr-v4" || u8(0x01) || confirm_ctx
)
```

The role byte is inside the MAC input. The two proofs differ even when every
other input is the same. The source sends `proof_source` first. The target
verifies it in constant time before it sends `proof_target` or allows a write.
The source verifies `proof_target` in constant time before it sends the token. A
reflection of one proof into the other direction fails because the role byte
differs.

`confirm_ctx` includes `cb`, both pins, both nonces, the pairing id, the
mechanism, and the flags. A proof computed on a different TLS session, a
different mechanism, or a different QR does not verify.

The target checks that `pin_T` in the QR is its own key pin. The source checks
that the target certificate pin equals `pin_T` from the QR. Both compute `pin_S`
from the source certificate. A certificate that does not match the QR pin aborts
before any proof is sent.

### 11.2 Message order

Historical procedure: any commit or promotion described here is blocked and
non-executable until the incarnation and per-host recovery models pass review.
No success or durable state may be inferred from this sequence.


1. The target arms QR, creates the payload
   `{ version, pairing_id[16], pin_T[32], secret[32], ttl_seconds }`, and
   displays it. It keeps the secret in memory only. It sends no hello yet.
2. The person scans the payload on the source. The source arms for QR, binds the
   payload's `pairing_id` and `pin_T`, and sends nothing.
3. The person taps Continue on the target. Only this local action chooses
   `nonce_T` and `commit_T`, opens TLS with ALPN `hs-pair/1`, and sends
   `PAIR_HELLO { version, mech = QR, flags, pairing_id, commit_T }`.
4. The source, armed for QR and holding the scanned payload, checks that the
   hello `pairing_id` equals the payload and that the target certificate pin
   equals `pin_T`. It chooses `nonce_S` and `commit_S` and sends
   `PAIR_READY { version, commit_S }`.
5. The target sends `PAIR_REVEAL_T { nonce_T }`.
6. The source verifies `commit_T` against `nonce_T`, then sends
   `PAIR_REVEAL_S { nonce_S, proof_source }`. It computes `proof_source` over
   `confirm_ctx` with both nonces and the live exporter.
7. The target verifies `commit_S` against `nonce_S`, computes `confirm_ctx`, and
   verifies `proof_source` in constant time. A failure consumes the secret and
   ends both the session and the source arming. On success, the target requires
   an explicit local Allow.
8. The target sends `PAIR_PROOF_T { proof_target }`.
9. The source verifies `proof_target` in constant time before it sends
   `PAIR_RESULT`.
10. Source sends `PAIR_RESULT`. Target validates the same fields as the SAS path,
    writes a `staged` record durably, and sends `PAIR_DONE`. Source commits its
    confirmed record, sends `PAIR_DONE_ACK`. Target promotes its record to
    `confirmed`.

The QR path uses the same commit-reveal as SAS. It has no SAS code and no SAS
fallback. The target must not write a record before it receives and validates
`PAIR_RESULT`. The source must not send the token before `proof_target`
verifies. The source commits its confirmed record only after the target's staged
write, so a dropped `PAIR_RESULT` or `PAIR_DONE` leaves at least one side
without a complete record. The target promotes its staged record only after a
verified `PAIR_DONE_ACK`. Section 13.2 defines the recovery.

### 11.3 Single use and expiry

- The target creates one QR at a time and shows it only while the pairing screen
  is open and armed. Creating a new armed QR destroys the previous secret and
  invalidates the previous payload.
- `ttl_seconds` is short, proposed 120 seconds. The target starts a monotonic
  deadline at secret creation: `min(created_at + 120 s, arm_deadline)`. It does not use the wall clock for expiry,
  because a wrong clock must not extend a QR.
- The first proof attempt, valid or not, consumes the secret. The target
  destroys the secret on success, failure, expiry, backgrounding, screen lock,
  or a new QR. A retry needs a new QR and a new `pairing_id`.
- The source discards the scanned secret after one attempt. It does not cache it
  across sessions or write it to disk.
- `pairing_id` is random, is in the payload and in `ctx`, and is covered by both
  proofs. A captured proof from another QR does not verify.
- A photographed QR is out of scope. The person must protect the screen. The
  short TTL and single-use rule bound the window.

### 11.4 Pairing display, consent, and credential separation

Pairing is a native target app surface. The Rust engine has no pairing control
that a browser page can reach, and the page holds no credential. The browser GUI
served on `127.0.0.1` shows status, diagnostics, and failures only. It has no
arm, code, allow, deny, cancel, or QR control.

Two per-launch secrets exist, and neither reaches the page:

| Secret | Holder | Authorizes |
|---|---|---|
| API bearer | the native target app; the engine holds a copy for comparison | start, stop, and any other state-changing route; status, diagnostics, and failures when the engine requires a credential for them |
| Pairing capability (PC), a separate per-launch bearer | the native target app; the engine holds a copy for comparison | arm, SAS code read, allow, deny, cancel, QR create, QR read, QR clear |

Read-only routes may be served without a credential on loopback, as today. They
never contain a token, private key, full pin, exporter value, code, QR payload,
API bearer, or pairing capability. The browser page can therefore show status,
diagnostics, and failures, and nothing else. Every state-changing route requires
the API bearer, and every pairing route requires PC. The full matrix is section
11.4.4.

### 11.4.1 One-way bootstrap on one descriptor

The **native target app** creates both per-launch secrets with a platform CSPRNG.
The engine never generates either secret and never sends one back to the app or
the helper. This paragraph covers the API bearer and the PC, not the QR secret or
the long-term identity keys.

- The app gives both secrets to the privileged helper on the request channel that
  already exists between them. That channel has a different shape on each
  platform, and neither shape is new:
  - macOS: fields in the authenticated XPC request.
  - Linux: the helper stdin request, which today is the two-line form
    `HS1\n<hex secret>\n`. Revision 7 changes the tag and adds one line, so the
    request is `HS2\n<api bearer, 64 lowercase hex>\n<pc, 64 lowercase hex>\n`
    followed by end of input. `HS1` is refused, because it carries no PC and
    would silently launch a bearer-only engine. Any other tag, a short or
    non-hex line, a third line, or trailing bytes is refused. The helper never
    echoes a line.

The helper then writes one fixed bootstrap frame to the engine on inherited
descriptor `3`. The number is fixed, not negotiated: `HS_BOOTSTRAP_FD = 3`. The
helper clears close-on-exec on that descriptor, passes it to the engine, writes
the frame once, and closes its write end. Descriptor `4` remains the parent
liveness channel, passed as `--parent-fd 4` as it is today, and is never used for
the bootstrap.

The engine reads a frame only when its argument list contains `--bootstrap-fd 3`.
The argument names a descriptor number and carries no secret, so it is
compatible with invariant 12. The only accepted value is the decimal string `3`.
Today both the macOS launcher (`RootEngineLauncher.swift`, `BackendProcess.swift`)
and the Linux helper start the engine with `--token-fd 3 --parent-fd 4`, and the
engine reads descriptor 3 as one legacy token line. Under this design the
launchers replace `--token-fd 3` with `--bootstrap-fd 3`. Without
`--bootstrap-fd`, the engine never parses descriptor 3 as a frame, so the two
formats are selected by the argument, not guessed from the bytes. The frame is:

```
HSBOOT1              7 ASCII bytes
version              u8 = 0x01
api_len              u16be, must be 32
pc_len               u16be, must be 0 or 32
api_bearer           32 raw bytes
pairing_capability   32 raw bytes, absent when pc_len = 0
```

The length fields are kept so a later version can change a size under a new
version byte. In version `0x01` they have exactly the values above, so a frame is
either 44 or 76 bytes. Every value after the header is binary, not hex.

One value has exactly one encoding at each hop:

| Hop | API bearer | PC |
|---|---|---|
| app memory | 32 raw bytes from the platform CSPRNG | 32 raw bytes from the platform CSPRNG |
| macOS XPC request | 32-byte `Data` | 32-byte `Data` |
| Linux `HS2` stdin request | one line of 64 lowercase hex characters | one line of 64 lowercase hex characters |
| bootstrap frame on descriptor 3 | 32 raw bytes | 32 raw bytes |
| engine memory | 32 raw bytes in zeroizing memory | 32 raw bytes in zeroizing memory |
| loopback HTTP request | `Authorization: Bearer ` then 64 lowercase hex characters | `X-Pairing-Capability: ` then 64 lowercase hex characters |

The Linux helper decodes each `HS2` line to 32 bytes before it writes the frame.
It refuses a line that is not exactly 64 characters from `0-9a-f`; uppercase hex
is refused, not folded. The engine renders its raw value to 64 lowercase hex
characters once, at load, into zeroizing memory, and compares the header value byte by byte in constant
time over the full length, as `rust/src/gui.rs` does today for the bearer. The
scheme word `Bearer` stays case-insensitive as it is today; the hex is not. A
64-character hex string is a request or header encoding and never the frame
value: a sender that writes 64 ASCII characters into the frame produces a
length mismatch (`api_len` or `pc_len` of 64) and exits with code `5`.

Rules:

1. Descriptor 3 is inherited. The macOS helper and demo launcher pass a pipe
   read end; the proposed Linux helper uses `pipe2(O_CLOEXEC)`; the Linux
   development launcher passes a socket pair. `fstat` identifies the kind and
   `fcntl(F_GETFL)` checks access before any read. Accept a pipe read end only
   with `O_RDONLY`. Accept a socket only after successful `shutdown(fd, SHUT_WR)`
   before any read; `O_RDWR` alone does not prove direction. Reject a closed,
   write-only, regular file, terminal, character device, read-write FIFO, other
   descriptor, or failed shutdown with code `9`. Pipe direction is kernel
   enforced; socket shutdown is an engine self-restriction. The writer closes
   after the frame. One absolute 5 second deadline applies to the whole read.
2. The engine writes **nothing** back on this descriptor or on any other
   descriptor. There is no `HSACK1` and no reply frame. Revision 6 defined an
   acknowledgement on descriptor 4, and the helper does not open descriptor 4 for
   writing on macOS or on Windows. The acknowledgement carried no security value,
   so it is removed rather than patched. L27 to L29.
3. The engine rejects with a fixed process exit code and no log line that holds a
   secret. It checks in this order, and the first failing step decides the code,
   so each class is distinguishable and one input has one code:
   1. argument check, before any read: `--bootstrap-fd` together with
      `--token-fd` is code `8`, whatever value either names; `--bootstrap-fd`
      with any value other than `3` is code `9`;
   2. descriptor check, before any read: descriptor 3 fails rule 1 is code `9`;
   3. read until 7 bytes or end of input: fewer than 7 bytes at end of input is
      code `3`;
   4. the first 7 bytes must be `HSBOOT1`, or code `2`;
   5. read until 12 bytes: fewer at end of input is code `3`;
   6. the version byte must be `0x01`, or code `4`;
   7. `api_len` must be 32 and `pc_len` must be 0 or 32, or code `5`;
   8. read the declared payload: fewer bytes at end of input is code `3`;
   9. read until 7 more bytes or end of input, without deciding on a partial step. Zero bytes at EOF is
      success. If the next 7 bytes are exactly `HSBOOT1`, the code is `7`, a
      second frame, whatever follows them. Any other byte sequence, including a
      shorter prefix of `HSBOOT1`, is code `6`;
   10. if the deadline passes while a step awaits bytes or EOF, code `10` applies. A complete bad magic, version, length, or seven trailing bytes decides codes `2`, `4`, `5`, `6`, or `7` immediately even if the writer remains open; fewer trailing bytes require EOF for `6` or the deadline gives `10`.
4. The exit codes are fixed and carry no secret:

   | Code | Class | Detection |
   |---|---|---|
   | `2` | bad magic or a bare token | the first 7 bytes are not `HSBOOT1` |
   | `3` | truncated frame | end of input before 7 magic bytes, before 12 header bytes, or before `api_len + pc_len` payload bytes |
   | `4` | unsupported version | the version byte is not `0x01` |
   | `5` | invalid length | `api_len` other than 32, or `pc_len` other than 0 or 32 |
   | `6` | trailing bytes | one or more bytes after the declared payload that are not exactly `HSBOOT1` |
   | `7` | second frame | exactly `HSBOOT1` follows a complete first frame |
   | `8` | conflicting bearer input | `--bootstrap-fd` and `--token-fd` are both present |
   | `9` | unusable bootstrap descriptor | `--bootstrap-fd` names a value other than `3`, or descriptor 3 is closed or not readable |
   | `10` | bootstrap deadline | end of input not reached within 5 seconds of engine start |

   An empty descriptor is code `3`. A bare legacy token line of 64 hex
   characters and a newline is code `2`, because it is at least 7 bytes and does
   not start with `HSBOOT1`. A short bare value of fewer than 7 bytes is code `3`.

   These are the **engine** process exit codes. They are separate from the
   Linux helper's own exit codes, which already use `1`, `4`, `5`, `6`, and `7`
   (`7` is an abandoned request). The helper observes the engine exit, reports
   it with its existing engine-failed status, and never forwards the engine
   number as its own exit code. The macOS helper reports a fixed start failure
   in its XPC reply. The app learns only that the engine failed to start. The
   class is a host-test observable on the engine process, not a value the app
   parses. The engine's existing generic error exit is `1`, and none of `2` to
   `10` is used by it today.

   The app, or the helper that started the engine, treats every non-zero exit as
   a bootstrap failure. It has no reply byte to read and does not wait for one.
   The code names a class, not a secret, and the engine does not print the
   offending bytes.
5. There is no version negotiation. Version `0x01` is the only accepted value in
   this revision. An unknown version fails the launch; the engine does not try to
   parse an older or newer layout, and it does not fall back to any other shape.
6. A zero `pc_len` means "no pairing on this launch". A launch with no bootstrap
   descriptor at all has no PC. If it also has no API bearer, it cannot control a
   real tunnel. `--demo` is the only unauthenticated start.
7. With `--bootstrap-fd 3`, the byte string `HSBOOT1` is the only accepted
   framing. A descriptor whose first bytes are a bare secret is **not** accepted
   as a fallback; it exits with code `2`. Revision 6 left this open, which would
   have let a writer downgrade the engine to reading an unwrapped token. M5, L30,
   and U18.
8. The engine copies both values into zeroizing memory, keeps no copy on disk,
   and clears both on engine process exit. Neither per-launch secret is ever
   passed in `argv`, an environment variable, a file, a URL, a log, a status, a
   diagnostics answer, a failure record, a notification, or a renderer page
   context. The legacy source device token is a different credential and is
   covered by section 23.1. Its environment form, `HOTSPOTSHADE_PHONE_TOKEN`, is
   read today on macOS, Linux, and Windows by the commands section 23.1 names,
   and is a documented, planned-for-removal path there. It is never a carrier
   for either per-launch secret.

The legacy `--token-fd N` input is separate and is not part of this frame. This
is what the code reads today (`read_gui_token` and `parse_gui_token` in
`rust/src/main.rs`):

- On macOS and Linux, `N` is a decimal inherited descriptor number. On Windows,
  `N` is a decimal inherited handle value, `--parent-fd N` is also required for
  a real GUI, and the two values must not name the same pipe. Neither is a path
  or a name. A non-decimal value is refused before any read.
- The content is exactly 64 lowercase hex characters followed by one newline,
  65 bytes in total. Anything else is refused. On Windows the read has a
  5 second deadline and ends early when the parent pipe closes.
- It supplies an API bearer only. It never supplies a PC.
- The engine keeps that bearer as the 64 ASCII characters it read, because the
  HTTP header compares those characters today. This design does not change the
  legacy path to raw bytes; the header comparison is the same for both paths.
- The legacy path cannot be confused with the framed bootstrap, because the
  argument selects the parser: `--token-fd` reads one 65-byte line, and
  `--bootstrap-fd 3` reads one frame. A launch with both arguments exits with
  code `8` before either descriptor is read, so one launch cannot carry two
  bearers.
- `--secrets-fd` is not a `gui` option on any platform. It belongs to the CLI
  commands in section 23.1, which take no bootstrap frame, so the two never
  meet. On Windows `--secrets-fd` is refused everywhere.
- A launch that uses only `--token-fd` can control a tunnel but cannot pair a new
  source. Today that is the Windows command-line GUI behind an authenticated
  launcher, and any Unix GUI started by hand with `--token-fd`. It is the path
  that P2 would remove. The Windows `tun --phone` CLI has no API bearer at all;
  it is a token-only proxy start. Section 23.1.
- `--token-fd` is deprecated in this design. It is kept for the gated cases in
  P2 and is scheduled for removal when those cases are decided. Deprecating it
  does not relax invariant 12: the framed bootstrap is still a per-launch bearer
  secret passed on a descriptor, never on a command line.

Readiness is observed from signals that already exist, because the bootstrap is
one way:

| Target | How the app learns the engine is ready |
|---|---|
| macOS | the authenticated XPC reply carries the engine port, a launch id, and a readiness status; it carries no secret, because the app created both |
| Linux packaged | the helper prints the fixed `HS_READY` line after authorization and the fixed `HS_PORT` line after the engine reports its port, on stdout; neither line holds a secret |
| Windows and headless | no helper and no bootstrap; the legacy bearer path, if any, and no PC |

The app and helper contracts:

- The app generates both secrets with a platform CSPRNG. It must not derive
  either from a device key, a password, or a token.
- The app sends the secrets to the helper once, on the existing request channel.
  It accepts no secret from the helper and no secret on a command line.
- The helper forwards both values to the engine on the bootstrap descriptor and
  keeps a copy only for the lifetime of the launch.
- The helper's stdout and stderr carry only the fixed status lines. They never
  carry a secret. A debug or verbose mode must not add one.
- The secret type has a redacted `Debug` and no `Display`. A panic, an error
  string, and a structured log line must not format it.
- The engine compares the PC in constant time. A missing, short, or wrong PC is
  `401 pairing_requires_target_app` and changes nothing.

### 11.4.2 Per-platform delivery

The helper never creates a secret. That removes the reverse path that revision 6
needed on macOS and the extra descriptor it needed on Linux:

| Target | Secret creation | App to helper | Helper to engine | Pairing control | QR | SAS |
|---|---|---|---|---|---|---|
| macOS | the app | the authenticated single-connection XPC **request**, after the helper checks the caller audit token; raw `Data` fields | descriptor `3` | the app sends PC in `X-Pairing-Capability` on loopback HTTP | yes | yes |
| Linux packaged | the app | the helper **stdin** request that already carries the launch secret before `pkexec`; `HS2` with 64 lowercase hex per secret | descriptor `3`, decoded to raw bytes | the Electron main process sends PC in `X-Pairing-Capability` | yes | yes |
| Windows | none: no protected helper and no real target app | none | none | none | **unsupported** | **unsupported** |
| Browser GUI on `127.0.0.1` | none | none | none | none | no | no |
| Headless or console | none unless a console actor is designed | none | none | none | no | no |

Notes on the two delivered rows:

- The macOS XPC request is the existing control request from the app to the
  helper. It already carries the launch parameters and is already admitted only
  after the audit-token check. Adding two fields to that request does not add a
  channel, and the reply no longer carries a secret.
- The Linux helper stdin request already carries one launch secret today in the
  `HS1` two-line form. It moves to `HS2` with a second line for the PC. The extra
  app secret pipe from revision 6 is deleted. The helper still takes no argument,
  and the polkit action and its `auth_admin` setting are unchanged. A helper from
  an older build and an app from a newer build do not interoperate: the helper
  refuses `HS2` when it does not know it, and the app sees a non-zero exit. That
  is the correct direction for a launch-time credential change.
- The helper trusts the request because the operating system admitted its sender:
  polkit authorized the invoking user for the Linux helper, and the audit token
  matched the app for the macOS helper. It is not a kernel-attested channel
  beyond that. A same-user process that can write the request before `exec`, or
  read the app, is the same-user threat in section 24 and is not a new channel.
- The Windows and headless rows are product limits, not protocol profiles. The
  engine rejects every pairing control without PC on every platform, so a missing
  channel fails closed instead of falling back to an unauthenticated local page.
  A future console actor must read the PC from a TTY or a private descriptor,
  never from a command line, and must not echo it. That actor is not designed
  here.

### 11.4.3 Credential lifetime and ceremony lifetime

Revision 6 cleared the app-wide secrets on window close and screen lock. On
Linux the window can be hidden while the tray keeps the app and the tunnel
running, and on every platform a screen lock is not a launch boundary. Clearing
the bearer or the PC there would either break a live control path or force a
restart. The two lifetimes are therefore separate:

| Item | Lifetime | Cleared by |
|---|---|---|
| API bearer | one launch | app quit, engine process exit, or the launch ending. A tunnel stop does not clear it. |
| Pairing capability | one launch | the same events. A tunnel stop does not clear it. |
| Target credential map (host, port, token) | one engine process | engine process exit or removal of the record. A tunnel stop keeps it. |
| Target arming | permission to send one hello | TD1 consumes it; TD2 to TD10 also end it |
| Ceremony | visible and person-driven | target TD2 to TD10 or TE1/TE2; source SD1 to SD10. TD1 does not end it |
| SAS code display | the armed ceremony | any event that ends the ceremony, including window hide and screen lock |
| QR payload and secret | target display copy until TD1; engine secret through the ceremony | TD1 clears only the display copy; TD2 to TD10, TE1/TE2, expiry, or one proof ends the engine secret |

Rules:

1. Window close, tray hide, screen lock, and app background do **not** clear the
   API bearer or the PC. A tray session keeps working, and a running tunnel keeps
   its control path.
2. A hidden window or a locked screen ends the **ceremony**. The person can no
   longer see the code or the QR, so continuing would ask for a comparison nobody
   can make. Arming is cleared, the code display is cleared, and the QR secret is
   destroyed. The session on the wire ends at its next message boundary.
3. A tray app that hides its window on close keeps the engine and the tunnel
   running. Reopening the window shows the current state and requires a new arm
   for a new ceremony.
4. Screen lock is treated as a ceremony boundary, not as a credential boundary.
   This is a deliberate trade: a locked screen is a strong signal that the person
   is no longer watching, and a weak signal about whether the app is still alive.
5. A **tunnel stop** is the `POST /api/stop` action or the app Stop control. It
   ends routes and flows, not the launch. The engine stays alive, the bearer and
   PC stay valid, and the target credential map stays in memory. A start in the
   same launch does not need the known path.
6. An **engine process exit** ends the launch. A graceful stop that exits the
   engine, a crash, and a parent-channel close all count. The bearer and PC die
   with the process and the target credential map is gone. The app shows engine
   loss and does not silently restart. The next launch has new secrets, and a
   target that lost its token needs the known path.
7. App quit ends the launch and the engine. It clears both secrets and zeroizes
   the copies. A stale copy cannot authorize a second launch, because the next
   launch has new values.
8. The engine zeroizes its copies on engine process exit. The helper zeroizes its
   copy when the engine process exits. The app zeroizes its copy on quit and on a
   launch end. None of these events is triggered by a tunnel stop.

### 11.4.4 Authorization matrix

Every route family, and what each credential can do. "401" means
`pairing_requires_target_app` for a pairing route and `401 unauthorized` for a
state-changing route. "No change" means no store write, no generation bump, no
prompt, and no session state change.

| Route family | No credential | API bearer only | PC only | Bearer and PC | Paired record and client key |
|---|---|---|---|---|---|
| `GET /api/status`, `/api/diagnostics`, `/api/failures` | allowed on loopback when the engine serves read-only routes without a credential; the answer holds no secret | allowed; required when the engine requires a credential for read-only routes | allowed | allowed | not used |
| `POST /api/start`, `/api/stop` | 401, no change | allowed | 401, no change | allowed | not used |
| `POST /api/phone/probe` | 401, no change | allowed, one probe per 500 ms | 401, no change | allowed | not used |
| Pairing arm, code read, allow, deny, cancel | 401, no change | 401, no change | allowed, bound to the session handle | allowed | not used |
| QR create, read, clear | 401, no change | 401, no change | allowed | allowed | not used |
| Pairing state read | 401, no change | 401, no change | allowed, no code and no QR payload | allowed | not used |
| Local forget, local record list | 401, no change | 401, no change | allowed, local person action | allowed | not used |
| Remote FORGET send | 401, no change | 401, no change | allowed only for a confirmed record | allowed | required, with the trust-admin purpose |
| Source token show or rotate | 401, no change | 401, no change | allowed | allowed | not used |
| Proxy listener, `hs-proxy/1` | handshake fails | handshake fails | handshake fails | handshake fails | required, with the proxy purpose and a valid token |
| Pairing listener, `hs-pair/1`, first pairing | refused unless armed | refused unless armed | refused unless armed | refused unless armed | not required for a first pairing |
| Pairing listener, `hs-pair/1`, `known` | refused | refused | refused | refused | required, with the pairing purpose |
| `FORGET_REQUEST` on `hs-pair/1` | no reply | no reply | no reply | no reply | required, with the trust-admin purpose |

Rules that the matrix makes explicit:

1. The API bearer and the PC are different capabilities. Neither implies the
   other, and holding both is not a substitute for a record on a wire listener.
   A PC-only request to a start or stop route is 401 and changes nothing. A
   bearer-only request to a pairing route is 401 `pairing_requires_target_app`
   and changes nothing.
2. A credential is read from the `Authorization: Bearer` header and from
   `X-Pairing-Capability`. It is never accepted from a query string, a cookie, a
   URL, page storage, a `Referer`, or a request body. A value from a previous
   launch, a short value, or a wrong value is 401 in constant time.
3. An unknown route is 404 and changes nothing. It does not fall through to a
   route that accepts a weaker credential.
4. A loopback credential never authorizes a wire listener. The proxy and pairing
   listeners authenticate with certificates, and the pairing listener also needs
   arming for a first pairing.
5. No route accepts the proxy token as a bearer. The token is a SOCKS5
   credential and nothing else.
6. A read-only route that is allowed without a credential must still hold no
   secret, so a local reader learns only state. That is the page boundary.
7. The matrix is the authorization contract. A route that is not in it does not
   exist, and a new route needs a new row and a test.
8. One user-visible consequence: the browser page loses its Forget control and
   its pairing state. Forget is a local person action on the device being held,
   and the page is not that device's native surface. The page keeps status,
   diagnostics, and failures. If the product wants Forget on the page, that is a
   new decision with a page credential and a new review, and P17 currently says
   no.

L37, U15, and V14 test the matrix as a table, not route by route by hand.

### 11.4.5 Consent rules

1. The PC holder is the native target app acting for the target actor. A request
   that presents PC is treated as the person's action. A process that steals the
   app's memory is outside the claimed boundary, in the same way as a compromised
   app, and section 24 states the per-platform same-user case. On Linux the
   sandboxed renderer asks the main process over fixed IPC, and the main process
   holds PC. A compromised renderer can ask the main process to act; that is the
   app-compromise bound, not a page credential.
2. The API bearer alone cannot arm, read the code, allow, deny, or cancel. A
   request with the bearer and no PC returns 401 and changes nothing.
3. An engine that has no PC, or whose PC was not delivered, refuses every
   pairing control. The browser GUI therefore fails closed for authenticated
   pairing. It cannot self-consent.
4. `allow`, `deny`, and `cancel` are bound to the current session handle and
   mechanism. A stale handle, a handle from another mechanism, or a handle after
   expiry is refused with no state change.
5. One live prompt per target. A second arm request while a session is armed is
   refused; it does not replace the session.
6. The SAS code is returned only to a PC request, only while that session is
   armed, and only after both commitments are verified. It is cleared on
   completion, denial, failure, expiry, background, screen lock, and window hide.
   Clearing the code is a ceremony event and does not clear the PC. Section
   11.4.3.

### 11.4.6 QR display rules

1. The engine creates the QR secret and `pairing_id`, returns the payload only
   to a PC request, and keeps the secret in memory for verification.
2. The app renders the payload and destroys its copy on success, failure,
   expiry, background, screen lock, window hide, or a new QR. The engine
   destroys its copy on the same events. These are ceremony events and do not
   clear the PC. Section 11.4.3.
3. The payload is never written to disk, never logged, never sent to the source
   device, and never returned to a browser page.
4. The target sets one monotonic deadline when the QR secret is created:
   `qr_deadline = min(created_at + 120 s, arm_deadline)`. It does not start a
   fresh 120 seconds when the payload is displayed. A late display does not
   extend the deadline, the app shows the remaining time, and it refuses to
   display an expired payload. Section 4.2.1. It does not use the wall clock for
   expiry.
5. On Linux, the raw payload stays in the Electron main process. The renderer
   receives an image, not the payload bytes. A process that can read the
   renderer or the screen can decode the image; that is the same bound as a
   photographed QR, and the design does not claim more.
6. A photographed or screen-read QR is out of scope. The person must protect the
   screen. The short TTL and single-use rule bound the window.

The browser exposure is now empty for pairing: the page receives no code, no QR,
no token, and no credential. A local process that can read the page learns
nothing that can complete a pairing. A local process that can read the native
app's memory can act as the app; that is the documented app-compromise bound.

A target with no native app channel cannot run SAS or QR. It may still use the
`known` path for an existing record. That is a product property of a headless or
Windows target, and the UI must say so.

### 11.5 No QR-to-SAS downgrade

- A target that has an armed QR session, or has displayed a QR, refuses a
  session whose `mech` is SAS or known until the QR is consumed, expires, or is
  cleared.
- A source that holds a scanned QR refuses SAS and refuses `known`. It sends a
  fixed mechanism-mismatch error and no code.
- A failed `proof_source` or `proof_target`, an expired QR, or a consumed secret
  ends the session. The source does not then offer a code. The target does not
  show one.
- The only way to use SAS after a QR attempt is to end the session, destroy the
  QR, arm SAS on both devices, and start a new session with new nonces, a new
  `pairing_id`, and new nonzero commitments.
- The UI must not have a "use the code instead" or "show a QR instead" control
  inside a QR or SAS session.

## 12. Mechanism C: known path

Historical and blocked: the following known-path and recovery procedure cannot
authorize registration, token delivery, or a new ceremony until the complete
incarnation and per-host recovery models pass independent review.

The `known` shortcut is allowed only when all of these hold:

1. The target holds a confirmed record for the source key pin with the pairing
   purpose, and the presented server pin equals the record.
2. The source holds a confirmed record for the target key pin with the pairing
   purpose, and the presented client pin equals the record.
3. The record's `wire_version` equals this session's version.
4. The exporter binding verified, as section 6.2 requires.
5. Neither side is armed for SAS or QR. An armed first-pairing session refuses
   `known`; section 9.5 rule 11.
6. The source app is open and in the foreground on iOS and Android, because the
   pairing listener does not run in the background. A target that lost its token
   cannot refresh it while the source app is closed or backgrounded; the UI says
   so and offers a full ceremony when the app is open. Section 7.10.1.

A `staged` record is not a complete record. It cannot start or accept a `known`
session. It is a recovery marker only, as section 7.1 says.

The target's `known` claim is not trusted. The target independently checks its
own store. If the target has no record, it refuses `known` and does not show a
prompt in that session. A full ceremony is a new session with new nonces, a new
`pairing_id`, and new nonzero commitments, and it requires arming on both
devices. If the target has a record for a different pin, the presented pin is
unknown and section 7.3 applies.

The known message order is the SAS order with no code and no Allow:

1. Target to source: `PAIR_HELLO { version, mech = known, flags, pairing_id,
   commit_T }`.
2. Source to target: `PAIR_READY { version, commit_S }`.
3. Target to source: `PAIR_REVEAL_T { nonce_T }`.
4. Source to target: `PAIR_REVEAL_S { nonce_S }`.
5. Both verify the peer commitment. A mismatch or an all-zero commitment aborts.
6. Source performs the locked check, the locked recheck, and the token copy in
   the order below. It releases the lock, then sends `PAIR_KNOWN_OK { th(0x01) }`.
7. Target verifies `th(0x01)`. It sends no message and stores nothing yet.
8. Source sends `PAIR_RESULT { status, port, token_len, token, host_len,
   host, th(0x04) }`.
9. Target validates every field and `th(0x04)`, performs its own locked record
   check and recheck, and only then stores the token in the credential entry for
   that `(peer_role, pin)`. The target sends no `PAIR_DONE` and writes no record.
   There is no `PAIR_DONE_ACK`, no record write, and no `generation` bump on
   either side.

The known path is check-only and under one bounded lock hold:

1. Acquire the store lock.
2. Read the record, verify the tag, and require validated `generation == anchor`.
   Missing, unreadable, unequal or uncertain state blocks credential use.
3. Compare the 32-byte pin to the connection pin in constant time.
4. Confirm the purpose set, the `confirmed` state, and the wire version.
5. Immediately before the credential copy, re-read the record and repeat steps
   2 to 4. Any difference aborts the session. This second read is not optional
   and is not cached.
6. Only after the recheck, copy the token from the service's in-memory field and
   the host and port from the source listener's own bound settings. All three
   are read under the same lock. The record itself never contains the token or
   the host and port. The source never takes host or port from the client, from
   `PAIR_HELLO`, or from an earlier connection.
7. Release the lock.

Steps 1 to 7 are one bounded critical section: local reads and a copy only. Do
not write, do not bump `generation`, do not rename the file, and do not frame or
send while the lock is held. A write on this path is a defect. After step 7,
build and send `PAIR_KNOWN_OK`, then `PAIR_RESULT`.

The target performs the mirror check before it accepts and stores the token: it
verifies `th(0x04)`, rechecks its own record under its own lock, compares the
server pin to the connection, copies what it needs, releases the lock, and only
then stores the token. It writes the token, host, and port into the credential
entry for that `(peer_role, pin)`. A failure at any point stores nothing, sends
nothing, and leaves every other source's credential untouched. Section 7.10.

The known path can re-issue the token only for the record whose pin matched the
connection. It never refreshes a different source's entry, and a source that
presents another source's pin cannot obtain that source's token.

`PAIR_KNOWN_OK` is a protocol confirmation, not a user prompt. If the new review
requires a tap even on `known`, the same message can carry the result of that tap
without a wire change. See Q2. The target must not use a `known` failure to
switch to a prompt in the same session. Section 9.5.

The known path can re-issue the token because the source service holds the
current token in memory and the target may have lost its copy in a restart.
That is exactly why the source recheck and the target mirror check exist: a
credential is issued only from state that was rechecked in the same locked
critical section.

## 13. Write points and durability

The commit, promotion, re-pair and recovery procedures and success outcomes in
this section are historical and nonimplementable until a replacement incarnation
protocol and crash/recovery model pass independent review. See W17 to W20.

### 13.1 Record states and commit points

A record has two states, `staged` and `confirmed` (section 7.1). Only a
`confirmed` record is a complete record for a trust decision. A `staged` record
holds the token in memory and is a recovery marker only.

| Point | Writer | State written | Durable before | Notes |
|---|---|---|---|---|
| Target record | target | `staged` | sending `PAIR_DONE` | The target also stores the token in memory before this send |
| Source record | source | `confirmed` | sending `PAIR_DONE_ACK` | The source commits after the target's staged write and before the target promotion |
| Target promotion | target | `staged` to `confirmed` | showing success | After a verified `PAIR_DONE_ACK`; also writes the credential entry; no protocol message |
| Known path | nobody | no change | not applicable | Check-only, no write, no `generation` bump |
| FORGET on the source | source | record removed | sending `FORGET_RESULT` | Section 18.2 |
| FORGET on the target | target | record and token removed | after a verified `FORGET_RESULT` | Section 18.3 |
| Local removal on the source | source | historical proposal: record removed | before closing matching sessions | Blocked pending commit and recovery review; W20 |
| Local removal on the target | target | historical proposal: record and token removed | before closing its own flows | Blocked pending commit and recovery review; W20 |

These historical points cannot determine storage after an uncertain write.
Before replacement the old store may be guaranteed; after possible replacement
neither old nor new state is guaranteed (section 7.6, W20). A `staged` record is never used for proxy traffic and
never used for `known`.

### 13.2 Lost-message matrix and recovery

The historical next actions below are blocked. No retry, local forget, re-pair,
automatic deletion, or promotion is specified as safe recovery until the
incarnation and recovery model passes review (W17 to W20).

| Lost or failed event | Target state | Source state | Next action |
|---|---|---|---|
| `PAIR_HELLO`, `PAIR_READY`, `PAIR_REVEAL_T`, or `PAIR_REVEAL_S` | none | none | Session ends. Start a new full ceremony. New nonces and a new `pairing_id`. |
| `PAIR_CONFIRM_S` or `PAIR_CONFIRM_T` | none | none | Session ends. No record and no token. Start a new full ceremony. |
| `PAIR_RESULT` | none | none | Session ends. No record and no token. Start a new full ceremony. |
| Target `staged` write fails before `PAIR_DONE` | old or uncertain after possible replacement | none | No success. Block mutation on uncertain state pending reviewed recovery; W20. |
| `PAIR_DONE` lost | `staged` | none | Target shows "Pairing is incomplete. Pair again to finish." A new full ceremony promotes the same-pin staged record and creates the source record. A local forget is the other action. The staged record is not used for `known` or proxy. |
| Source `confirmed` write fails after receiving `PAIR_DONE` | `staged` | old or uncertain after possible replacement | No success. Block mutation on uncertain state pending reviewed recovery; W20. |
| `PAIR_DONE_ACK` lost | `staged` | `confirmed` | Target shows "Pairing is incomplete. Pair again to finish." A new full ceremony with the same pin promotes the target record; the source sees a same-pin re-confirmation and still requires arming and the code. No automatic promotion on the `known` path. |
| Target promotion fails after a verified `PAIR_DONE_ACK` | staged only if definitely before replacement; otherwise uncertain | `confirmed` | No success. Block mutation on uncertain state pending reviewed recovery; W20. |
| Process death or power loss | potentially uncertain | potentially uncertain | The historical table cannot resolve this. Block mutation pending the reviewed recovery model and W20. |

The target must not show a final success state before a verified
`PAIR_DONE_ACK` and a successful local promotion. The source must not send
`PAIR_DONE_ACK` before its own durable commit. The target must not treat a
`known` session as confirmation of a staged record.

A commit failure is reported as a fixed "could not save trust data" message and
no success state. An uncertain local commit cannot be equated to a lost
message. Block mutation pending the reviewed recovery model (W20).

## 14. The proxy channel

1. Target builds the candidate set for the endpoint from its confirmed proxy
   records, as section 7.11 says. It opens one normalized outer socket to that
   endpoint. TTL 65, interface pinned, audit unchanged. It never uses another
   endpoint's host, port, or token.
2. TLS 1.3 handshake with ALPN `hs-proxy/1`, one absolute handshake deadline,
   client certificate required.
3. The source verifies the client pin against the store, under the lock, and
   requires the proxy purpose. An unknown pin aborts the handshake before any
   application byte. The source's TLS handshake flight is already sent by then;
   section 19 treats the source certificate as public. The source never sends an
   application byte before the client pin check.
4. After the handshake, the source re-reads the client certificate and the store
   and repeats the pin comparison under the lock before the first application
   byte. This is the post-handshake recheck from finding M6. It then registers the
   session in the per-session table below. Registration is one atomic step with
   the store check, so a removal cannot miss a session that is registering and a
   session cannot register across a removal. Section 14.1.
5. The target verifies that the server pin matches exactly one candidate record.
   On a mismatch it aborts before any token byte and does not try another
   candidate's token. It re-reads the server certificate after the handshake and
   repeats the comparison.
6. SOCKS5 inside TLS, unchanged: greeting, username and password with the
   matched record's token, then CONNECT, the private UDP command `0x80`, or the
   private echo commands `0x81` and `0x82`. Reply codes and error mapping are
   unchanged. The token is never taken from another record and never from a
   global field.
7. The client may pipeline greeting, auth, and request in one write to save a
   round trip. Pipelining is allowed only after the pin check.
8. After the SOCKS5 success reply, the framed data phase in section 15 carries
   the inner bytes in both directions. The frame layer is a transport wrapper;
   the SOCKS5 control exchange is not framed. No frame is sent before the
   success reply is read.
9. A clean half-close is a `FIN` frame. A TLS close without a `FIN` is
   truncation. Section 15 defines both.

The source keeps a per-session table for accepted proxy sessions:

```
session = {
  session_id,        local opaque id, never on the wire
  client_pin,        32 bytes, from the authenticated client certificate
  peer_role,         0x01 target
  opened_at,         monotonic
  state,             handshaking, authenticating, relay
  epoch_at_register, u64, this pin's epoch read under the store lock
  cancel_requested,  bool, set by a removal sweep
}
```

The table is memory only, is bounded by the existing proxy session cap, and is
indexed by `client_pin` for local revocation. It holds no token and is never
written to a log, a status, a diagnostics answer, or a failure record.

The token stays a second factor. It authorizes proxy use; the certificate
authenticates the device. Rotating the token does not touch the records.

The local loopback SOCKS listener on `127.0.0.1:1081` is unchanged. It stays
plaintext to local apps. Only the hotspot link becomes TLS.

One inner flow is one TLS connection. A TLS record never carries a second flow.

### 14.1 Atomic registration and forced cancellation

Revision 6 filled the index after the post-handshake recheck and before the first
application byte, and then said an orphaned session was bounded by its idle and
stall policy. Both halves were wrong. A session could register after a removal
swept the table, and an open TCP relay has no idle bound at the source, so an
orphan could live for as long as the target kept it open. The fix has three
parts.

**One epoch per pin.** The source holds a monotonic `revocation_epoch` per
authenticated client pin. The map is `pin_epoch: [u8; 32] -> u64`. A pin with no
entry has epoch 0. The first durable removal of a pin creates its entry with
value 1, and each later removal of the same pin increments only that entry. Only
a removal creates an entry, and only a removal changes one. The map is memory
only and is reset on process start, because a process start already closes every
session. The map is capped at 64 entries. At the cap the oldest entry whose pin
has no record and no session in the table is dropped. Dropping such an entry
cannot re-admit a session, because the record is gone and registration rechecks
the store, and it cannot abort one, because no session for that pin is in the
table. An entry for a re-added pin or for a pin with a registered session is
never dropped. If every entry is protected, the removal still succeeds and the
entry is added above the cap; that overflow is bounded by the record cap plus the
session cap. The epoch is per pin so a removal of source A
cannot abort a concurrent registration for source B. Revision 7 used one global
epoch and called the unrelated abort safe; M9.2 rejects that, so the global epoch
is removed. A definitely pre-write failure leaves the record and sessions intact. A commit
with uncertain durability blocks mutation pending recovery; it cannot assume
either storage outcome.

**One lock order.** The store lock is taken first, then the session-table lock.
The table lock is never taken before the store lock, and neither lock is held
across a network call, a TLS call, a network flush, a close, or a connect. The
store lock may cover the local durable commit in section 7.6. Section 7.8 still
applies unchanged.

**One atomic registration.** Registration is:

```
acquire store lock
  read store, verify tag, require validated generation == anchor
  abort if store or anchor is missing, unreadable, unequal, or uncertain
  compare pin with the connection pin in constant time
  confirm confirmed state, purposes, wire version
  read pin_epoch[client_pin] or 0   -> e
  acquire session-table lock
    insert session with epoch_at_register = e, cancel_requested = false
  release session-table lock
release store lock
```

A removal does the mirror image under the **same two locks**:

```
acquire store lock
  delete the record durably, bump generation
  pin_epoch[removed_pin] += 1
  acquire session-table lock
    for each session with client_pin == removed pin:
      set cancel_requested = true
      detach it from the table
  release session-table lock
release store lock
cancel each detached session by force      (outside both locks)
```

Consequences:

1. A session that registers before the sweep is in the table when the sweep runs,
   so it is detached and cancelled. A session that registers after the sweep
   fails the locked record recheck and aborts before its first application
   byte only if no same-pin re-pair intervenes. A re-pair can create a new
   record that a pin-only recheck cannot distinguish (W17 to W19).
2. The store recheck and insertion occur in one store-lock hold. If removal
   wins, the record recheck fails; if registration wins, local removal detaches
   it or remote removal returns `DENIED`. Another pin is unaffected. A same-pin
   re-pair race requires the unresolved incarnation gate.
3. Forced cancellation closes the destination socket abortively and closes the
   outer transport with **no `FIN` frame**. The target therefore sees truncation
   by the section 15.2 rule, and the inner destination does not read a truncated
   upload as a complete one. The design does not require a TCP RST and does not
   claim one.
4. The cancellation does not wait for an idle timer, a stall timer, a keepalive
   probe, or a graceful close. The previous "bounded by its idle policy" sentence
   is deleted, because it was false for an open relay.
5. A cancellation that fails to close a socket leaves the record gone and the
   session detached from the index, so no later sweep needs to find it again. The
   failure is counted, and the socket handle is closed again on the next process
   shutdown path. The design does not claim that a stuck kernel close can be
   forced.
6. Each session keeps `epoch_at_register` for diagnosis only. A session may
   compare it with the current epoch for its own pin at any message boundary; if
   it differs, the session aborts. It never compares against another pin's
   epoch. That is a belt-and-braces check, not the primary mechanism.
7. The epoch is not sent on the wire and is not stored. A restarted source has a
   new epoch map and no sessions, so there is nothing to reconcile.
8. A local epoch cannot authorize a same-pin re-pair or distinguish an old
   session from the new incarnation. Acceptance remains blocked until a complete
   cross-device incarnation and recovery protocol passes independent review.

F34 to F39 test the order: registration before the sweep, registration racing the
sweep for the same pin and for another pin, a sweep with two pins, a sweep with a
session in the handshake state, a cancelled session with no `FIN`, and a target
that reconnects after the removal. V7 repeats the two-pin race.

### 14.2 Setup budget

One absolute deadline covers the TCP connect, the handshake, the SOCKS
greeting, the token check, and the destination request, as the current 5 second
`open_tcp` deadline already does. The handshake gets a sub-budget, so a peer that
drips bytes cannot consume the whole setup budget and still make progress. The
data phase keeps the existing per-operation socket bounds, the 30 second
write-stall allowance, the 250 ms UDP age limit, and the existing idle and
keepalive policy.

### 14.3 Presence probe

The probe no longer uses the pairing listener, because an unarmed source would
refuse a SAS or QR session under section 4.2. The probe opens a proxy connection,
completes the handshake, presents the client pin, and completes SOCKS5 username
and password authentication with the token. It sends no request and closes. A
completed TCP connection or a completed handshake alone never reports `ready` or
`connected`.

The probe closes after the authentication reply and before a request. The source
treats an authenticated connection that closes before a request as a successful
probe and creates no inner flow, no frame phase, and no record. It must not map
that close to an inner truncation, because no inner flow exists.

Only a successful authenticated v2 probe tied to the selected source pin and
current record and same current incarnation may refresh v2 presence or its
auto-stop timer. Any accepted port must be validated and atomically associated
with that same current record and incarnation. Legacy status, a wrong pin, a
stale incarnation, or an unauthenticated response cannot refresh presence or
update a port; see the revision 10 migration gate.

The probe costs a full handshake, because resumption is off. Measure it before
choosing the interval.

### 14.4 Failure mapping

Failure mapping keeps the existing fixed messages. A TLS alert that rejects the
client certificate maps to `not_trusted` only when the server first proved a
candidate pin, with a valid `CertificateVerify`. Its existing text, "The source
device does not know this target device. Pair again.", keeps the target record
and names no forget action; pairing again with the same source is the same-pin
re-confirmation in section 7.3, which does not delete a record. A handshake
timeout, a closed connection, or a local socket error maps to `not_responding`.
A certificate that does not match any candidate server pin, and a server
`CertificateVerify` that fails, both map to one neutral message, "The hotspot is
not answering as any paired source device. Check that the intended source device
is connected and try again." It does not claim an identity change, name a
record, or advise forgetting one. A truncation maps to a connection
error, not a clean close. None of these map to a state that deletes a record. A
fake alert from an attacker is cosmetic: it can make the target show a wrong
status, and it cannot change stored trust.

## 15. Framed data phase, half-close, and truncation

Revision 3 used a one-way TLS `close_notify` as the half-close signal. The
platform APIs do not expose that portably: Conscrypt's `shutdownOutput()` sends
a TCP FIN, and Network.framework's `.finalMessage` is not documented as a
one-way TLS close. This revision therefore uses one thin framed data phase on
every peer. The frame is the half-close signal. A TLS close without a `FIN`
frame is truncation. No platform gets a different profile.

### 15.1 Frame format

The framed data phase starts only after the SOCKS5 success reply. The SOCKS5
greeting, authentication, request, and reply are unchanged and are not framed;
SOCKS5 already delimits them. Pipelining the greeting, authentication, and
request in one write is still allowed after the pin check.

No frame is allowed before that reply. The target must not send a `DATA` or
`FIN` frame until it has read a success reply. The source must not send a frame
until it has sent a success reply. A frame that arrives before the reply, or
after a failure reply, is a protocol error: the connection closes and no inner
flow is created. E24 and G28 test both directions.

```
frame = u8(type) || u16be(length) || payload[length]
```

| Type | Value | Length | Meaning |
|---|---|---|---|
| `DATA` | `0x01` | 1 to 16384 | Inner bytes in this direction |
| `FIN` | `0x02` | 0 | Clean half-close of this direction |

Rules:

1. The header is 3 bytes. `length` counts the payload only.
2. The maximum payload is 16384 bytes. A frame may span TLS records; the parser
   is stream-based. A declared length over 16384 is a protocol error before any
   allocation.
3. The parser is stream-based. A frame may span TLS records, and several frames
   may share one TLS record. TLS record boundaries have no meaning to the frame
   parser.
4. A `DATA` frame with length 0, a `FIN` frame with length other than 0, an
   unknown type, or a second `FIN` from the same sender is a protocol error.
5. A protocol error closes the TLS connection and resets the inner flow. It is
   never delivered as a clean FIN.
6. One TLS connection carries one inner flow. A frame never carries bytes for a
   second flow. This is invariant 7.
7. The same framing applies to TCP `CONNECT`, UDP `0x80`, and echo `0x81` and
   `0x82` after their SOCKS5 reply. The UDP and echo payload keeps its existing
   internal format. The frame is a transport wrapper, not a new command.
8. The frame layer adds 3 bytes per write. A relay may coalesce consecutive
   inner writes into one `DATA` frame up to 16384 bytes. It must not delay a
   `FIN` behind data in the other direction, because there is only one direction
   per stream.

### 15.2 Half-close and truncation semantics

- A clean inner FIN is a `FIN` frame, sent after all `DATA` in that direction.
  A TLS `close_notify`, `shutdownOutput`, or `.finalMessage` is not the
  half-close signal.
- After sending `FIN`, the sender stops writing `DATA` in that direction. It
  keeps reading and delivering inbound `DATA` until it receives the peer's
  `FIN`.
- A received `FIN` is delivered to the inner flow as a clean half-close only
  after all preceding `DATA` is delivered. The local write direction stays open,
  and the local side sends its own `FIN` when it is done.
- After both sides have sent and received `FIN`, there is nothing left to
  exchange. The transport may be closed at once. A TLS `close_notify` or a
  platform graceful-close call is a tidy step after both `FIN` frames, never a
  substitute for one.
- A TLS `close_notify`, an EOF, a TCP FIN, a TCP reset, or a fatal alert that
  arrives before a `FIN` in that direction is a truncation. The receiver must
  not deliver a clean FIN. It resets the inner flow so a destination that reads
  to end of stream cannot take a truncated upload for a complete one.
- A `close_notify` that arrives before the peer's `FIN` is truncation, not a
  clean close. It closes the sender's write side without the required `FIN`.
- `DATA` after a received `FIN` in the same direction is a protocol error. It is
  not ignored, because the frame layer is application framing and a second
  write after `FIN` is a defect or an attack. Close the connection and reset the
  inner flow.
- An abortive inner close sends no `FIN` frame, no `close_notify`,
  `send_close_notify`, `.finalMessage`, or application data. The design does not
  claim that the outer transport always produces a TCP RST. The documented facts
  are narrower:
  - Apple documents `NWConnection.cancel()` as cancelling the connection and
    "gracefully disconnecting any established network protocols". It is not a
    documented reset.
  - Android documents `Socket.setSoLinger(boolean, int)` as setting `SO_LINGER`;
    the public page does not state that a zero linger produces a reset.
  - The Linux and Windows socket references document the linger option and its
    close behaviour, not a guaranteed RST on every path.
  The decisive rule is at the receiver: a close without a prior `FIN` frame is
  truncation, so an abort cannot look clean even when the transport close is
  graceful. A peer may set `SO_LINGER` with a zero timeout, or call the platform
  close API that best fits its local abort path, to make the local close prompt.
  The wire result is recorded by a device row and is not a design dependency.
  G9, R23, and T25 to T28 test the sender and the receiver.
- A peer that sends `FIN` and then stops reading is handled by the existing
  30 second write-stall bound, which applies to the direction that still has
  data.
- A peer that sends `FIN` and then goes silent is handled by the idle and
  keepalive policy, which is evaluated per direction. Do not reset a flow merely
  because one direction is closed.
- A frame parser error, a short read at TLS end, or a TLS error is a truncation.
  The inner flow is reset, not cleanly closed.

Idle bounds are not one number. The target's inner TCP endpoint uses its
existing 600 second idle policy. The source device proxy uses its existing 300
second session idle window for UDP and for a half-closed flow with no
application traffic. A half-closed flow that pauses for more than 300 seconds
at the source is closed by the source, and the target sees a truncation unless
both `FIN` frames already crossed. G1 uses 2.5, 30, and 120 seconds, all below
300. G29 records the 301 second case. Whether the source half-closed window
should be raised to 600 seconds is P21 and Q21. The design does not claim a
600 second source window.

### 15.3 Platform mapping

| Peer | DATA | FIN | Transport close after both FINs | Unknown |
|---|---|---|---|---|
| Rust target and engine | normal rustls write | normal rustls write of a `FIN` frame | `send_close_notify` or close | Whether rustls permits a write after receiving `close_notify`; the final tidy step still needs a host test. How the relay poll loop separates buffered plaintext from raw readability. |
| iOS source | `NWConnection.send` of a normal content context | `NWConnection.send` of a normal content context | `.finalMessage` or `cancel` after both FINs | Whether `.finalMessage` sends `close_notify`; it is not used as the half-close signal. |
| Android source | `SSLSocket` output stream write | `SSLSocket` output stream write | `shutdownOutput()` or `close()` after both FINs | Whether Conscrypt sends `close_notify` on `close()`; `shutdownOutput()` is not used as the half-close signal. |
| Windows and Linux target | same Rust engine path | same Rust engine path | same as Rust | Same as Rust, on each platform. |

The platform's own TLS close behavior is recorded by a device row, not assumed.
No peer may use `shutdownOutput`, `.finalMessage`, or `send_close_notify` as the
only half-close signal. A peer that cannot close the transport after both `FIN`
frames still has a correct half-close; the remaining connection is closed
abortively and the inner flow is already complete.

## 16. Resumption and the trust epoch

Session resumption, TLS 1.3 tickets, 0-RTT, and renegotiation are all off where
the platform permits. The platform status is not the same everywhere.

| Peer | Configuration | Status |
|---|---|---|
| Rust target | `send_tls13_tickets = 0` and `Resumption::disabled()`. Require `handshake_kind() == Full`. | Proven on loopback. rustls documents that peer certificates are available on a resumed handshake too, which is why the kind is checked and the presence of a certificate is not enough. |
| iOS source | `sec_protocol_options_set_tls_tickets_enabled(options, false)`. | Documented. Needs a device test that the verify block runs on every connection and that no Certificate message is skipped. |
| Android source, Conscrypt | `Conscrypt.setUseSessionTickets(socket, false)` before the handshake on every accepted socket. | Documented as enabling or disabling session tickets. The exact TLS 1.3 effect must be shown by a trace, not assumed. |
| Android source, platform `SSLSocket` | `SSLSockets.setUseSessionTickets(socket, false)`, API 29 and later. | Documented. Not used in the selected option. |

Consequence: the trust epoch is exactly one connection only where a full
handshake is proven on every connection. A resumed connection would skip the
certificate message and both pin checks, so a record removal or an identity
change would not apply until the ticket expires.

In TLS 1.3 resumption is client-initiated: the client offers a pre-shared key
derived from a ticket, and the server can only accept or decline it. The server
cannot "refuse resumption" in the abstract. Its only real control is whether it
issues a ticket in the first place, which is why the requirement is "do not
issue" and not "do not resume". A server that never issued a ticket has no PSK
to accept.

Two checks are required on every session, on every peer:

1. Tickets off before the handshake.
2. A post-handshake pin recheck: after the handshake completes and before the
   first application byte, read the peer certificate again, recompute the pin,
   and compare it to the store under the lock. Abort on any difference or if the
   certificate is unavailable.

The recheck alone is not sufficient. On a resumed TLS 1.3 session the peer
certificate can be the cached one, so the recheck can pass on a session that did
not authenticate the peer. That is why tickets off is a separate requirement and
why `handshake_kind() == Full` is required where the API exposes it.

Android has no public handshake-kind API. The gate is a device trace that shows
a full handshake with Certificate and CertificateVerify, and no
NewSessionTicket, on every connection. If a resumed session is observed once,
Android source mode is not approved.

The historical proposal intended to prevent new registrations and cancel
matching live sessions during source local removal. A live flow must not veto
the removal attempt, and an open relay has no idle bound. Neither immediate
revocation nor durable success is established: the incarnation, commit,
session-ordering, and recovery models remain blocked pending review. An
uncertain write blocks trust use and mutation; it is not reported as a durable
removal. See sections 14.1 and 18.2 and W17 to W20.

If resumption is wanted later for cost, it needs a `trust_epoch` counter bumped
on every record and token change, carried in the ticket and checked by the
server, plus a device test that the platform still runs the check. Until that
exists, resumption stays off.

## 17. Downgrade prevention

1. There is no non-TLS proxy path in the engine. The listener speaks TLS or
   nothing. Plaintext SOCKS to the proxy port fails the handshake and is closed.
2. There is no `--insecure`, `--no-tls`, or plaintext diagnostic switch. A
   diagnostic mode uses the same channel with a demo backend.
3. TLS 1.3 only. The rustls build has the `tls12` feature disabled; the platform
   peers set the minimum and maximum version to 1.3.
4. The record names the wire version and the purpose set. A record for a future
   version cannot be used with this one, and the target offers exactly one
   label.
5. The target never sends the token, a destination, or any inner byte before
   the server pin matches and the post-handshake recheck passes.
6. A pin mismatch is a hard, visible failure. It is never auto-repaired and
   never replaced without a fresh ceremony.
7. Pairing v1 and wire version 4 must not coexist on one device. A live v1
   proxy port would keep the plaintext proxy path reachable and give an attacker
   a way to force the older mode. This design replaces v1 in one release. Draft
   v2 and v3 were never deployed. See P6.
8. Where the stack exposes the client's offered list, a peer that offers no
   ALPN, the other listener's ALPN, or more than one label is rejected. On iOS,
   where the offered list is not visible, a nil or mismatched negotiated label
   after `.ready` is rejected. A server that selects no label is rejected. A
   client that offers TLS 1.2 is rejected by the version policy.
9. No mechanism change is possible in a session, and no unarmed session can
   authenticate. Section 9.5.

## 18. Forgetting, rotation, revocation, and recovery

Historical and blocked: the introduction and operation table below describe
proposed outcomes, not guaranteed or actionable procedures. Local removal
durability and remote ordering both require independently reviewed replacements.

The pin-only remote FORGET wire format, source and target procedures, and their
success and retry claims in sections 18.1 to 18.4 are historical and
nonimplementable until a replacement incarnation protocol and recovery model
pass independent review. Local locking alone does not order devices. See W17 to
W20. Local removal intent and other product choices remain unchanged.

One rule covers record deletion:

> No message on any channel may delete a record unless the sender is
> authenticated by a record that authorizes trust administration, on this
> connection, and the receiver rechecks that authorization under the store lock.

From that rule:

| Operation | Who may do it | Effect |
|---|---|---|
| Local forget on the target | the person, in the target UI | deletes the local record, the per-record credential, and the in-memory token, and closes the target's own live flows for that pin. It is never refused for a live flow. The source record is unchanged. |
| Remote forget | the pinned target, over a pin-matched `hs-pair/1` connection with the trust-admin purpose | Historical, blocked pending incarnation and recovery review. A live flow does not veto source local removal; durable success still requires reviewed commit and recovery. |
| Local removal on the source | the person, in the source trust list | Live flows do not veto removal. Matching sessions are cancelled; durable success and refusal of later connections depend on reviewed commit and recovery. An uncertain outcome blocks trust use and success. Same-pin re-pair remains gated. |
| Token rotation | the person, on the source | new token for new connections. Records unchanged. Existing authorized flows continue. |
| Identity reset | the person, on either device | the device generates a new key. The other side sees an unknown pin and requires a full ceremony. |

### 18.1 FORGET messages

The pairing frame in section 9.1 carries a one-byte message type. The assigned
types are:

| Type | Message |
|---|---|
| `0x01` | `PAIR_HELLO` |
| `0x02` | `PAIR_READY` |
| `0x03` | `PAIR_REVEAL_T` |
| `0x04` | `PAIR_REVEAL_S` |
| `0x05` | `PAIR_CONFIRM_S` |
| `0x06` | `PAIR_CONFIRM_T` |
| `0x07` | `PAIR_RESULT` |
| `0x08` | `PAIR_DONE` |
| `0x09` | `PAIR_DONE_ACK` |
| `0x0a` | `PAIR_KNOWN_OK` |
| `0x0b` | `PAIR_PROOF_T` |
| `0x10` | `FORGET_REQUEST` |
| `0x11` | `FORGET_RESULT` |

The state bytes in section 9.4 are a separate namespace. A message type is never
used as a state byte, and a state byte is never used as a message type.

```
FORGET_REQUEST {
  length      u16be, body length after this field
  type        u8 = 0x10
  version     u8 = WIRE_VER
  role_T      u8 = 0x01
  role_S      u8 = 0x02
  purpose_used u8, 0x01 pairing on this revision; 0x02 proxy is reserved and rejected
  request_id  [16]
}

FORGET_RESULT {
  length      u16be, body length after this field
  type        u8 = 0x11
  version     u8 = WIRE_VER
  role_T      u8 = 0x01
  role_S      u8 = 0x02
  purpose_used u8, 0x01 pairing on this revision; 0x02 proxy is reserved and rejected
  request_id  [16]
  status      u8, 0x00 OK or 0x01 DENIED
  hash        [32]
}
```

`request_id` is 16 random bytes from the target and is nonzero. A request with a
zero `request_id`, a wrong role byte, a wrong `purpose_used`, or a body length
that does not match the fields exactly is a protocol error.

```
forget_ctx =
  "hs-forget-v4" || u8(WIRE_VER) ||
  u8(role_T) || u8(role_S) || u8(purpose_used) ||
  u16be(len(alpn)) || alpn || u8(TLS13 = 0x04) ||
  u16be(32) || cb ||
  pin_T || pin_S ||
  request_id[16] || u8(status)

forget_hash = SHA-256("hs-forget-th-v4" || forget_ctx || u8(0x08))
```

The pins are ordered by role, `pin_T || pin_S`, independent of which device
sends the request or the reply. The reply hash binds the status, the request id,
both role-ordered pins, the purpose, the ALPN, and the exporter of this session.
A replayed reply from another request or another session does not verify.

### 18.2 Accepting a FORGET on the source

Two removal paths have two rules:

- A **local removal** is not vetoed by live flows. The proposed source action
  cancels matching sessions; the target action clears its credential and token
  and closes matching flows. Durable success requires the reviewed commit and
  recovery model. An uncertain write blocks trust use and success; do not assume
  that the record is gone.
- A **remote FORGET** is a request from another device. Its live-flow policy and
  recovery remain unapproved. A live flow must not veto a source local removal
  attempt, but it does not guarantee that removal is durably committed.

This historical proposal replaced the revision-4 live-flow rule. The current
draft does not establish authoritative durable revocation; W17 to W20 remain
blocking.

- Accepted on `hs-pair/1` only. No third listener and no second protocol on the
  proxy listener are added. A FORGET is accepted only from a confirmed record
  with the trust-admin purpose; the locked recheck enforces the pin match. A
  FORGET frame on `hs-proxy/1` is refused by the SOCKS5 parser; there is no
  FORGET parser on that port.
- The pairing listener must be open. On Android and iOS it does not run in the
  background, so a remote FORGET requires the source app to be open. The target
  UI must say so and must still offer a local forget. This is a product limit,
  not a wire fallback.
- The source refuses a first-message `FORGET_REQUEST` while it is armed for SAS
  or QR. The person's first-pairing screen is not changed by a remote admin
  action. The target retries after the armed session ends.
- The historical proposal refused a remote `FORGET_REQUEST` while a live flow
  used the record. A live flow must not veto an attempted source local removal.
  Durable removal and recovery remain blocked pending the reviewed model in
  section 14.1 and W17 to W20.
- On `hs-pair/1`, `FORGET` must be the first application message. A provisional
  pairing session with no confirmed record rejects it before any state change
  and before any prompt.
- The request has no target identifier field. The source uses the authenticated
  client certificate to choose the record. A request that tries to name another
  device's record is a protocol error.
- The source rechecks under the store lock: the client pin equals the record
  pin, validated `generation == anchor`, the record is `confirmed`, the record holds
  the `purpose_used` of this connection, and the record's wire version matches.
  Any failure closes the connection with no reply and no state change.
- For a remote `FORGET`, within one store-lock hold, recheck authorization,
  take the table lock and refuse `DENIED` if a matching session exists. Otherwise
  release the table lock, commit the durable removal and generation and epoch
  changes, reacquire the table lock and sweep before releasing the store lock.
  Registration holds the store lock throughout its recheck and insert, so the
  remote sweep must be empty. A nonempty sweep is a defect and its entries are
  detached and cancelled. No table lock is held over a durable flush. Frame and
  send the result only after releasing both locks. A failed or uncertain durable
  commit sends no OK, blocks further mutation pending recovery, and does not
  assume old or new storage won. These local rules do not solve the incarnation
  gate above.
- For a source local removal, a live flow must not veto the attempt. The
  proposed session cancellation, epoch changes, durable commit, and recovery
  are historical and blocked until the incarnation and per-host recovery
  models pass review. If a write may have replaced the store, do not report
  durable success or assume either stored state; block trust use and mutation
  pending reviewed recovery. See section 14.1 and W17 to W20.
- A local removal and a remote `FORGET` both bump `generation`. A pending
  ceremony that read an older generation before its final commit rechecks it
  under the lock and aborts if it changed. This local check alone does not prove
  cross-device ordering or safe re-pair; the incarnation gate remains open.
- Idempotence: one `FORGET_REQUEST` per connection. The source caches the reply
  bytes for that request id before it frames them. A second `FORGET_REQUEST` on
  the same connection with the same `request_id` returns the cached bytes and
  performs no second store write. A second `FORGET_REQUEST` on the same
  connection with a different `request_id` is a protocol error: close with no
  reply and no state change. A new `request_id` on a new pairing connection is
  rejected by the locked recheck if the record is gone, because the source has
  no confirmed record for that pin, and it receives no reply. The target sends at
  most one request per connection.
- If a delete fails or has uncertain durability, the source sends no result and
  closes. A definite pre-write failure leaves the record; an uncertain commit
  requires blocked mutation and recovery. The target treats the outcome as
  unknown; retry and re-pair remain gated by the incarnation protocol.
- On the pairing listener, an unknown client pin may complete the TLS handshake
  because a first pairing is allowed. A `FORGET_REQUEST` from that pin then
  fails the locked recheck and closes with no reply. It never receives a
  distinguishable answer and changes no state.
- A rejected `FORGET` must not be treated as success by the source. The source
  must not delete any record in that path.

### 18.3 Acting on a FORGET reply on the target

The following pin-only procedure is insufficient for a delayed reply and is
blocked by the incarnation gate. A future protocol must atomically compare the
request incarnation to the current durable target record before deleting. The
old provisional procedure was:

1. Checks the frame type, version, role bytes, `purpose_used`, and request id.
2. Verifies, under the store lock, that the connection's server pin matches the
   record for the source it is about to forget. A reply on a connection whose
   server pin does not match is ignored and changes no storage, because an
   attacker with a different key could otherwise force a re-pair.
3. Verifies `forget_hash` for this request id, purpose, and status.
4. Only then deletes its local record, its credential entry for that
   `(peer_role, pin)`, and its in-memory token, durably.
5. On a timeout, a protocol error, a hash mismatch, a pin mismatch, or an
   unreadable store, it keeps both and shows a fixed failure.

A `DENIED` reply leaves local storage unchanged. The source still holds the
record. The target may still offer a local forget as a person action, but that
only removes the target's trust; it does not revoke the source record. That is a
person action, not a protocol effect.

### 18.4 Lost FORGET messages and local-forget recovery

This table and its retry, re-pair and expected-state instructions are historical,
not an implementable recovery procedure. A definite failure before replacement
can leave the old store; after possible replacement or an uncertain flush the
source or target store may be old or new, including after restart. Send no OK
and block further mutation pending an explicitly specified and independently
reviewed recovery model (section 7.6, W20). Do not infer a safe retry or re-pair.

| Lost or failed event | Source state | Target state | Next action |
|---|---|---|---|
| `FORGET_REQUEST` or its reply is lost | unknown: record kept or removed | record and token kept | No inferred outcome, retry, re-pair, or local-forget recovery instruction; block pending a reviewed recovery model. |
| Source delete fails | old store only if definitely before replacement; otherwise uncertain | record and token kept | No result. Block mutation on uncertain state pending reviewed recovery; W20. |
| `FORGET_RESULT` with `OK` lost after the source delete | record gone in the historical scenario | record and token kept | No inference from a later handshake and no retry, re-pair, or local-forget recovery instruction pending reviewed recovery. |
| `FORGET_RESULT` with `DENIED` lost | record kept in the historical scenario | record and token kept | Outcome unknown to target; no recovery action specified pending review. |
| Target delete fails after a verified `OK` | source delete was acknowledged | old store only if definitely before replacement; otherwise uncertain | No inferred target state or retry. Block mutation pending reviewed recovery; W20. |
| Process death or power loss | potentially uncertain | potentially uncertain | Block mutation pending the reviewed recovery model; W20. |

A lost request and a lost reply are indistinguishable to the target. No retry,
local forget, or new ceremony is specified as a safe recovery from this state.
The replacement must define and review recovery before any such action.

### 18.5 What removal does and does not revoke

Historical and blocked: the following outcomes assume successful durable
removal and a valid incarnation. They are not guarantees after uncertain writes
or restart and cannot authorize implementation.

- Local removal on the source stops new proxy connections for that target and
  cancels every live proxy session whose authenticated `client_pin` equals the
  removed pin. Cancellation is immediate and forced, not an idle timeout. The
  target sees a truncation. It does not rotate the token and does not affect
  other records.
- Remote `FORGET` removes the source record and, after a verified `OK`, the
  target record and in-memory token. The source may refuse it while a flow is
  live. It does not rotate the token and does not affect other devices.
- Local removal on the target deletes the target record, credential, and token
  and closes the target's own flows for that pin. The source record remains
  until the source person removes it.
- A removed target may still hold the old token. The token alone cannot pass the
  client certificate check, so it is not a proxy credential without the removed
  private key.
- Token rotation is separate from removal. It invalidates the old token for new
  connections and leaves every record intact. It does not revoke an identity.
- Identity reset changes the key. The other side sees an unknown pin and needs a
  full ceremony. The old record remains until the person forgets it.
- Removal does not revoke a certificate, because there is no CA, no revocation
  list, no OCSP, and no transparency log. The record is the only trust state.
- A store rollback can resurrect a removed record, as section 7.5 states. That
  is a documented limit.

### 18.6 Validity is not checked

Pins ignore `notBefore` and `notAfter`. A device with a wrong clock must still
pair. The consequence is that an expired certificate still authenticates, which
is correct for a pin and would be wrong for a CA chain. This design has no CA
chain, no revocation list, and no OCSP, so it must never be described as one.

## 19. Privacy and certificate disclosure

- No SNI. The client passes the hotspot IP as the server name, so rustls sends
  no SNI extension. The pin is the trust decision.
- No DNS on the egress path. The channel carries a name only inside the SOCKS
  request, and the source resolves it on the cellular network. `getaddrinfo()`
  is never called on an egress path.
- TLS 1.3 encrypts the Certificate message. A passive observer on the hotspot
  does not see the certificates. It sees record sizes, timing, the flow count,
  and the ALPN label in the ClientHello.
- A passive observer no longer sees the token, the destination, or the proxy
  reply codes, which it does today.
- An active client can connect to the source's proxy or pairing listener and
  receive the source's certificate before it authenticates. That discloses a
  stable public pin. A hotspot attacker can use it to recognize the same source
  device across sessions and locations.
- During first pairing, a man in the middle can receive the target's client
  certificate, because the target has no server pin yet. After pairing, the
  target checks the server certificate against a candidate pin before the client
  certificate flight where the TLS stack exposes that order. The rustls server
  verifier is the intended hook, and the exact order is host row E27. If a stack
  cannot enforce that order, the disclosure is recorded as a limitation and no
  token is sent.
- A shared hotspot gateway does not identify a source. The target holds a
  candidate set for the endpoint and learns which source answered only from the
  server certificate. It sends no token until exactly one candidate matches.
- A stable pin is a linkable identifier. The certificate has no name, no SAN,
  and a random serial, so the key pin is the main stable value. Do not log it,
  show it in full, or put it in a diagnostics answer. The trust list shows only
  the four-byte label.
- ALPN is a fixed visible label and therefore a fingerprint. See P7.
- The pairing code and the QR payload are shown only on a native target app
  surface. Neither reaches the browser GUI. Neither is logged, stored, or put in
  a status, diagnostics, or failures response.
- The QR payload and secret are never sent to the source device. The source
  scans the code from the screen.
- The pairing capability and the API bearer never reach the browser page. The
  app creates both, sends them to the helper on the existing app-to-helper
  request, and the helper writes them to the engine on the bootstrap
  descriptor `3`. They never appear in argv, an environment variable, a file, a log,
  a panic, a crash report, a notification, or a diagnostics answer. Section
  11.4.1.
- The same-user local case is not hidden. On Linux a process running as the
  signed-in user can read the Electron main process and therefore the PC and the
  bearer. On Windows a same-user process with `PROCESS_VM_READ` can read the app.
  On macOS the hardened app without `get-task-allow` resists a debugger attach,
  but the engine is a separate process and the app holds the PC. Section 24.
- The exporter value is never logged and never shown.
- No padding, no cover traffic, no timing defence. Flow counts and byte counts
  remain visible.
- No certificate transparency, no AIA, no OCSP, because each would be an
  external request.

The server certificate disclosure is accepted in this draft. A separate design
could use a stable identity key with a short-lived presentation certificate, but
that adds a chain, a rotation rule, and a new pin model. It is Q6, not a change
made here.

## 20. Resource budgets

These are proposed bounds. They must be measured before release. A bound that is
not measured is not a claim.

| Resource | Proposed bound | Reason |
|---|---|---|
| Pairing connections | the existing platform limits: iOS 4; Android 8 sockets with at most 4 idle; 4 active sessions in the Rust responder | A silent client must not hold an unbounded slot. |
| Pairing handshake | 5 seconds absolute, inside the existing first-frame and prompt budgets | A drip cannot extend the handshake. |
| Pairing prompt | existing 60 seconds active and 120 seconds inactive extension, one live prompt, and always capped by the absolute arming deadline in section 4.2.1 | A person needs time; an attacker does not get an unbounded prompt, and a prompt cannot outlive the person's consent. |
| Arming | 120 seconds monotonic from the arm action, one armed session per device, one absolute deadline that no prompt, retry, or QR display moves. The target is one-shot on hello. The source allows at most three failed SAS proof attempts inside the window; a failed QR proof consumes the secret and the source arming. The complete disarm sets are SD1 to SD10 and TD1 to TD10 in section 4.2. | A stale armed screen must not accept a session later, and the window is a bound, not a guarantee against denial. Section 4.3. |
| Pairing frame | whole frame at most 512 bytes: 2-byte length plus a body of at most 510; length checks before allocation; 4-frame buffer | No new unbounded parser. |
| Pairing attempts | existing per-peer and global challenge budgets, 3 failures then 30 seconds lockout, 256 tracked peers; the source counts only a session that reached a verified reveal | Bounds SAS cross-session attempts, invalid frames, and arming exhaustion. |
| QR | 16-byte pairing id, 32-byte secret, 120-second monotonic TTL, one active QR, one use | High entropy, short window, no replay. |
| Records | 8 per role on a target, 16 on a source, no eviction | A bounded store with no silent replacement. |
| Candidate set | at most the target record cap, 8 entries; exact host and port match; exactly one pin match before a token is used | Bounds work on a shared gateway and prevents cross-record token use. |
| Per-session client pin index | at most the existing proxy session cap; one 32-byte pin, one epoch value, and one cancel flag per accepted session; no token; memory only | Enables source local revocation without an unbounded map. |
| Revocation epoch | Historical, blocked memory-only per-pin proposal. Its capacity and eviction rules are not approved. | A local epoch cannot distinguish incarnations or establish durable removal. A replacement must define capacity, registration ordering and recovery; W17 to W20. |
| Proxy setup | 5 seconds total; handshake sub-budget 4 seconds | Fits the current `open_tcp` deadline. |
| TLS record | 16 KiB plaintext record plus TLS overhead | Bounded buffer. |
| Certificate | one leaf, at most 4 KiB before parsing; one chain entry; post-parse validation as section 5.6 | A peer cannot send a large or unusual chain. |
| Exporter | 32 bytes, computed once per connection, not retained | Fixed size, no reuse. |
| Data-phase frame | 3-byte header, payload 1 to 16384 bytes, parser bounded before allocation; a frame may span TLS records and the parser is stream-based | No new unbounded parser and no second flow per record. |
| Per-connection buffers | 64 KiB plaintext each direction and a 64 KiB write queue, both measured; no unbounded queue | A slow peer must not grow memory without limit. |
| Pairing capability | app-generated 32 random bytes per launch, sent to the helper on the existing request, forwarded to the engine in one framed record on one pipe read end or self-restricted socket, never written to disk or a page, required for every pairing control; invalid after the launch ends | Separates the target actor from any page credential and has no reverse path. |
| API bearer | app-generated 32 random bytes per launch, same request and same descriptor, never on a command line or in a log; 64 lowercase hex characters only in the Linux `HS2` line and the HTTP header | One bootstrap path for both secrets. |
| Bootstrap frame | 12-byte header plus 32 or 64 secret bytes, so 44 or 76 bytes in total; `api_len` must be 32 and `pc_len` 0 or 32; bounded before allocation, read once within a 5 second deadline, then end of input required | No parser growth, no second frame, and no fallback shape. Section 11.4.1. |
| Half-closed flow | target 30 second write stall and 600 second inner idle; source 300 second session idle for UDP and half-closed flows; no close drain timer; a `FIN` frame is the only clean half-close | A half-closed flow must not be cut early, and must not live forever. The 300 second source limit is the P21 decision. |
| Proxy sessions | existing capacity formula from the open-file limit, 256 relays plus 32 setup when the limit permits | No new unbounded map. |
| Handshake CPU | measure 30 concurrent full handshakes on each target OS; cap concurrent handshakes per source and globally | ECDSA and ECDHE cost is real. |
| Handshake flood | per-source and global rate limits; listener stays responsive | Availability, not authentication. |
| Failure records | the existing bounded record in `rust/src/failures.rs` | No unbounded memory or disk. |
| Probe | the existing interval, measured with a full handshake on the proxy channel; back off if the cost is too high | Do not turn resumption on to fix probe cost. |

Memory, CPU, and battery numbers are not specified because none were measured.
The implementation must record them before a live test.

## 21. Android platform support

Android keeps `minSdk 26`, `compileSdk 36`, and `targetSdk 36`. Section 6.4
changes the TLS provider, not the floor. What this means for support, stated
plainly:

- The app still installs and runs its UI and settings on API 26 and later.
- The source proxy needs TLS 1.3, ALPN, the exporter, and ticket suppression.
  With the bundled Conscrypt provider those are library features, not platform
  features, so the profile is one profile from API 26 up.
- If the maintainer rejects the Conscrypt dependency and keeps the platform
  stack, the floor for the proxy becomes API 31. That is a support reduction,
  and it must appear in the app, the README, and the store listing, with a fixed
  message on API 26 to 30. It must not be silent.
- If the shared Rust core is chosen instead, the Android proxy floor stays at 26
  and the dependency cost moves to the NDK build.
- The AAR ships `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64` native libraries.
  The APK uses per-ABI splits or an App Bundle so a device downloads one.
  Measured sizes go in the release record.
- The app builds with AGP 8.5.1 or later, uses `zipalign -P 16`, and needs a
  `PAGE_ALIGNMENT_16K` bundle. The Conscrypt 2.9.0 64-bit libraries have
  `0x4000` PT_LOAD alignment; a 16 KB runtime test is still a device row. The
  exact Play deadline is not treated as verified in this document.
- The Android target tunnel still does not exist. This section is about the
  source app only.

API facts used above, read on 2026-11-05:

| Item | Fact |
|---|---|
| TLS 1.3 on platform `SSLSocket` | API 29 and later |
| ALPN on platform `SSLSocket` | API 29 and later |
| `SSLSockets.setUseSessionTickets` | API 29 and later |
| `SSLSockets.exportKeyingMaterial` | API 31 and later |
| `Conscrypt.exportKeyingMaterial`, `Conscrypt.setUseSessionTickets`, `Conscrypt.setApplicationProtocols` | public in `org.conscrypt:conscrypt-android` 2.9.0, AAR `minSdkVersion 21` |
| `KeyGenParameterSpec` with `PURPOSE_SIGN` | API 23 and later, self-signed certificate included; not used as the identity certificate, section 5.4 |
| `KeyProperties.DIGEST_NONE` and `KeyGenParameterSpec.Builder.setDigests` | API 23 and later |
| `MessageDigest.isEqual` | documented constant-time behaviour, all bytes examined |

## 22. Libraries and dependencies

| Peer | TLS | Certificate generation | New dependency |
|---|---|---|---|
| Rust target | `rustls` 0.23 with `default-features = false`, features `ring`, `std`, `logging`; no `tls12`, no `aws-lc-rs` | `rcgen` 0.13 with `default-features = false`, features `crypto`, `ring` | Yes: `rustls`, `rcgen`, and their tree |
| iOS source | Network.framework `NWProtocolTLS` plus `sec_protocol_options_*`, with peer authentication required | in-tree fixed DER builder plus `SecKeyCreateSignature` | No |
| Android source | bundled Conscrypt provider, `SSLContext`, `KeyManagerFactory`, `AndroidKeyStore`, custom `X509TrustManager`, `setNeedClientAuth(true)`, `Conscrypt.setApplicationProtocols`, `Conscrypt.setUseSessionTickets`, `Conscrypt.exportKeyingMaterial` | in-tree fixed DER builder plus `Signature` with the Keystore key | Yes: `org.conscrypt:conscrypt-android` and its native libraries |

The Rust feature set is deliberate. A default `rustls` build selects the
`aws-lc-rs` provider and enables `tls12`; both are excluded here. The host gate
runs `cargo tree -e features -i aws-lc-rs` and requires no output, and it checks
that `tls12` is absent. The exact feature names are rechecked against the pinned
versions when the dependency lands; the requirement is the provider and the
absent features, not a remembered default.

The engine dependency addition is significant for invariant 9 and needs an
explicit maintainer decision, with the stated reason: never invent crypto. The
alternative is to keep writing a record layer by hand, which is what the
rejected design did.

The Android dependency is the same kind of decision: the platform stack cannot
provide the profile below API 31, and the alternatives are a support reduction or
an NDK build. The reason is stated in section 6.4, and the measured APK size is
part of the record.

The engine must keep `--locked` and commit the new `Cargo.lock`. The Android
build must pin the Conscrypt version and must not use a dynamic or ranged
version. The added tree must be measured and recorded: build time, binary size,
and the per-connection handshake cost.

## 23. How this meets the token-auth invariant

Invariant 3 says the source device proxy must keep token authentication and bind
its listener to the hotspot only. Invariant 11 says pairing never sends the
token to the browser.

This design keeps both unchanged:

- The token stays a required factor on every proxy connection, checked with the
  existing constant-time comparison, now inside TLS instead of on the wire.
- The token is still delivered to the target by pairing, still held by the
  service, and still never sent to the browser.
- The API bearer and the pairing capability are both per-launch and are never
  sent to the browser. The browser page has no pairing surface.
- The target keeps the token per `(peer_role, pin)`, not as one global value.
- The listener still binds the hotspot address only.
- Token rotation and the "Show token" flow are unchanged.
- A `FORGET` request is authenticated by the record and the trust-admin purpose,
  not by the token. A client without a matching record cannot delete a record
  even if it holds a token.

No invariant change is requested. One user-visible behavior does change: proxy
mode needs one pairing before the first connection, because mutual authentication
needs a record. Typing a token alone is no longer sufficient. This is a gated
product decision, not an accepted one. If pairing is mandatory, a Windows target
and a headless target have no PC and cannot pair a new source, so their proxy is
unavailable. The options are a designed console actor that reads the PC from a
TTY without logging it, or removing those targets from the release. There is no
token-only fallback and no unauthenticated local page. See P2 and P22.

### 23.1 Token-only paths that exist today

Revision 6 said the Windows and headless proxy would be unavailable. It did not
say which working paths on macOS, Linux, and Windows would also stop working. The
cost of P2 is larger than a new install on an unsupported target, so the paths
are listed here. This is a reading of `rust/src/main.rs`, `rust/src/udp_diag.rs`,
`rust/src/gui.rs`, and `gui_assets/app.js` at the time of writing, not a device
test. The revision-8 first pass got the token sources wrong; section 2.1.2,
fix 6.

Token sources, in the order the code tries them:

| Command | macOS and Linux | Windows |
|---|---|---|
| `tun --phone <gateway>:<port>` | 1. `--secrets-fd N`; 2. `HOTSPOTSHADE_PHONE_TOKEN`; 3. no-echo prompt on `/dev/tty` | 1. `HOTSPOTSHADE_PHONE_TOKEN`, removed from the process environment after the read so children such as `netsh` do not inherit it; 2. no-echo console prompt, which also accepts redirected standard input. `--secrets-fd` is refused with a fixed error before any read. |
| `phone --phone <gateway>:<port>` | 1. `--secrets-fd N`; 2. `HOTSPOTSHADE_PHONE_TOKEN`; 3. no-echo prompt on `/dev/tty` | not available: the command returns the fixed "not implemented" error before any token source is read |
| `phone-udp-diag` | 1. `--secrets-fd N`; 2. no-echo prompt on `/dev/tty`. The environment is never read. | not available, as for `phone` |
| `phone-speed-diag` | 1. `--secrets-fd N`; 2. no-echo prompt on `/dev/tty`, only when the selected paths use the source device. The environment is never read. | not available, as for `phone` |

Common facts. `--secrets-fd N` is a decimal descriptor number. The engine accepts
a pipe, a socket, or a regular file owned by the effective user with mode 0600.
The content is one UTF-8 JSON object, `{"token":"..."}`, with no other key and at
most 4096 bytes. The prompt reads `/dev/tty`, so a run with no terminal fails
with "no terminal is available; use --secrets-fd". Every path accepts a token of
1 to 255 bytes; the descriptor and prompt paths also refuse control bytes. The
token never comes from `argv` on any platform.

| Path today | Platform | How it authenticates now | Route change | Under mandatory pairing |
|---|---|---|---|---|
| `hotspotshade tun --phone <gateway>:<port>` | macOS, Linux, Windows | source device token only, from the sources above | yes, it starts the tunnel | needs a paired record with the proxy purpose and a client certificate, so it needs a PC. Unavailable where no PC exists. |
| `hotspotshade phone --phone <gateway>:<port>` | macOS, Linux | source device token only, from the sources above. It runs a local SOCKS5 forwarder on `127.0.0.1` (default port 1081) to the source proxy, and `--check` runs one check | no | needs a paired record and a PC, like `tun --phone`. Unavailable where no PC exists. |
| `hotspotshade phone-udp-diag` | macOS, Linux | source device token only, from the sources above | no | the diagnostic now runs on the proxy channel, so it needs a paired record and a PC. Unavailable where no PC exists. |
| `hotspotshade phone-speed-diag` | macOS, Linux | source device token only, from the sources above, when a selected path uses the source device. The `direct` path presents no token | no | the source device paths need a paired record and a PC. The `direct` path is unchanged. |
| Non-root Unix GUI started by hand without a bearer | macOS, Linux | existing HTTP checks accept unauthenticated pairing, forget, probe, stop and start requests; start reaches the service but is refused for lack of privilege | no successful tunnel | proposed matrix denies unauthenticated state changes, including direct-mode start requests; W9. |
| Native target app pairing surfaces | macOS, Linux | current native Settings pairing and forget controls use the existing v1 service; no manual token field. Linux real desktop integration is incomplete | service-dependent | native actor and PC are proposed; UI changes and v1 migration are unapproved. |
| Browser GUI page with the manual token field | macOS, Linux, Windows | the `gui` engine's API bearer, if any (`--token-fd N`; required on Windows with `--parent-fd N` and on a root Unix engine), plus a source device token typed into the page and sent in the start request body. The macOS and Linux native target apps have no manual token field; they use pairing. | yes, the page can start and stop | the source device has no record and no certificate, so a token-only proxy start fails. The design removes the field, because the browser holds no credential and has no pairing surface. |
| `hotspotshade probe` | all | none; it is read-only and local | no | unchanged. It never used the source device. |
| `hotspotshade gui --demo` | all | none | no | unchanged. It is labelled as simulated and controls no tunnel. |
| Existing pairing v1 responder on port 18090 | iOS, Android source apps | X25519 pairing v1, then token | no | removed with v1 under P6. A device that still runs v1 cannot pair with this design, and this design does not run a v1 listener. |

Consequences that the product decision must include:

1. A macOS or Linux person who uses the typed-token proxy today, and who does not
   have a target app that can hold a PC, loses the proxy. They do not lose the
   direct mode, which has no source device app and no token.
2. The two scoped diagnostics and the `phone` forwarder are read-only on the
   route table, but they present the token. They cannot stay token-only while
   the proxy channel requires a certificate, unless they keep a separate
   token-only listener. That would be a second profile and is not proposed here.
   The diagnostics and `phone` exist on macOS and Linux only, so this loss is a
   macOS and Linux loss.
3. A Windows target has no PC and no real target app, so every Windows row above
   that needs a PC is unavailable there: the CLI `tun --phone` start and the
   browser page start. The diagnostics and `phone` are already unavailable on
   Windows today, so mandatory pairing removes nothing more there. T5 to T7 and
   U11 to U14.
4. A headless target has no actor at all. Without a console actor it can read
   status, but it cannot pair, cannot refresh a token after a restart, and
   therefore cannot start a proxy session on a fresh launch. A record it already
   holds is not usable without a token. Section 7.10.1.
5. Keeping pairing v1 alive for these paths is not a fallback this design
   accepts. A live v1 proxy port is a plaintext path and a downgrade route, P6.
6. The source token is never passed in `argv`. On macOS and Linux the code
   prefers the private inherited descriptor, `--secrets-fd N`, then the
   environment for `tun --phone` and `phone`, then the no-echo `/dev/tty` prompt.
   Windows has no `--secrets-fd`; it uses `HOTSPOTSHADE_PHONE_TOKEN`, then the
   no-echo console prompt.
7. The environment token is a compatibility path, not a protected channel, on
   every platform that reads it. A same-user process that can read the
   environment can read it. Windows removes it from the engine's own environment
   after the read; that does not erase copies held by the caller or the
   operating system. macOS and Linux do not remove it today. It is planned for
   removal on macOS and Linux, where `--secrets-fd` and the prompt already
   cover every use, and on Windows when a console actor or a Windows handle path
   exists. It is not a carrier for the per-launch API bearer or PC, which
   section 11.4.1 still forbids in an environment variable.

The honest summary is that mandatory pairing is not a UI change. It removes a
working capability from every desktop target that has no protected actor, and it
removes the token-only diagnostics everywhere. P2 must decide that with the whole
list in front of it.

## 24. Threat model

| Adversary or event | Result | Limit |
|---|---|---|
| Passive observer on the hotspot | Cannot read the token, destinations, reply codes, or payload. Sees record sizes, timing, flow count, ALPN, and no certificate because TLS 1.3 encrypts it. | No padding or cover traffic. Traffic analysis still works. |
| Passive TCP relay during first pairing | Sees ciphertext only. The exporter is computed end to end, so it cannot produce a valid splice. | It can drop or block. It cannot decrypt or impersonate later without a private key. |
| Active man in the middle, after pairing | Rejected. Both pins must match and `CertificateVerify` must verify. | A stolen private key defeats it. |
| Active man in the middle, during first pairing, SAS | The exporter binding, the commit-reveal exchange, and the pins make a splice produce a different code. | The 20-bit code is still open to cross-session search if the attacker can run many sessions. Arming, rate limits, and the target confirmation bound it. A person who taps Allow without comparing is not protected. See Q1. |
| Active man in the middle, during first pairing, QR | The attacker does not know the secret. Directional proofs, source-first order, and the exporter binding stop reflection and splicing. The target confirms. | A photographed QR, or a person who confirms without checking, is outside the protocol. |
| Forced QR-to-SAS downgrade | Refused. The mechanism is in the transcript and fixed for the session, and the source refuses a mechanism it did not arm. | A person who ends the session and re-arms SAS themselves has chosen it. |
| Unarmed pairing attempt | Refused before any prompt, code, QR, or store access. | A person who armed the device has consented to a pairing attempt. |
| Local process or browser page with the API bearer only | Can start and stop the tunnel if it has the bearer. It cannot arm, read a code, allow, deny, cancel, create a QR, or read a QR. Those routes return 401 `pairing_requires_target_app` and change nothing. The page holds no bearer at all. | A process that steals the native app's memory holds the PC and can act as the target actor. That is the app-compromise bound. |
| Local process with neither credential | Can read the browser page and call unauthenticated status routes if the engine allows them. It cannot pair and cannot read a QR or a code. | The engine fails closed for pairing without PC. |
| Browser page read by a local process | It sees status, diagnostics, and failures only. It has no code, QR, token, private key, full pin, exporter, bearer, or PC. | Section 11.4. |
| Target app QR read by a local process | That process can pair one device once, inside the TTL, because it can read the app's memory or screen. | Target-app-only surface, one use, 120-second monotonic TTL, no storage, section 11.4. The design does not claim protection from a process that can read the app. |
| One source selects another source's credential | The target builds a candidate set from the endpoint, verifies the server pin, and uses only the matching record's token, host, and port. A different source cannot present the pin without the private key. | A compromised target device sees every credential it holds. That is the target-compromise bound. |
| Several paired sources share one hotspot gateway | The target treats the gateway as an endpoint, not an identity. It matches the server certificate against the candidate pins and binds exactly one record. If none matches it sends no token, does not try another candidate's token, shows one neutral message, and does not claim an identity change or advise forgetting a record. | The target's client certificate can be disclosed before the pin check on a stack that cannot order the verifier first. The rustls order is tested deterministically; any other stack records the limitation and still sends no token. T12 to T15 and V5. |
| Attacker occupies the single SAS prompt | The attacker cannot produce a matching code, so no record is created. It can hold the one prompt slot until its deadline and can spend one of the three attempts with a reveal that verifies its own commitment. | Real denial of one ceremony attempt. Bounded by the prompt deadline, the absolute arming deadline, one prompt, and the invalid-message budget. The design does not claim to prevent it. Section 4.3, C55 to C58. |
| Attacker burns a scanned QR secret | One proof attempt consumes the secret by design, so only a peer proving the scanned target key and pairing id can reach that proof; a source impersonator can end the target ceremony and force a new QR and scan. | Real denial of one QR attempt. Bounded by the 120 second QR window, one QR at a time, and single use. The design does not claim to prevent it. Section 4.3. |
| Attacker exhausts the source arming through the attempt budget | Three verified-reveal failures inside the window disarm the source and start the 30 second lockout. | Bounded in time and attempts. The lockout also blocks the person, which the design accepts. T20 to T24, U9. |
| Malformed or unauthenticated pairing hellos | No attempt is counted, the arming survives, and no prompt, code, or QR is produced. | Frame caps and the invalid-message budget bound the work. T20. |
| Person removes a source record while the target holds a live flow | Live flows do not veto local removal; matching sessions are cancelled. Durable success requires reviewed commit and recovery, and uncertainty blocks trust use and success. | No idle timer is involved. Same-pin re-pair is gated. T8 to T11, F34 to F39 and W20. |
| Session registers across a removal | Store-lock serialization and a record recheck decide the race; a same-pin re-pair requires the unresolved incarnation gate. Another pin is unaffected. | Requires both locks on both paths. A lock-order mistake is a defect, F34 to F39 and V7. |
| Same-user process on a Linux target reads the app | It can read the Electron main process with `ptrace` when the kernel allows it, so it can read the PC and the API bearer and act as the target actor. | Same-user compromise. `ptrace_scope` is a system setting this design does not control. Section 25, U16. |
| Same-user process on a macOS or Windows target reads the app | On macOS the hardened app without `get-task-allow` resists a debugger attach, and a process with the right entitlement can still read it. On Windows a same-user process with `PROCESS_VM_READ` can read the app. | Same-user compromise. The design claims the browser page boundary, not the same-user boundary. U16. |
| Local process writes the bootstrap descriptor or the helper request | It can supply a bearer or a PC and control the launch, which is the same-user compromise above. It cannot make the engine read a bare secret from the framed descriptor, and it cannot make the engine accept two bearers. | No downgrade shape. Section 11.4.1, L30 and U18. |
| Launcher or helper leaks a per-launch secret | The secret crosses one inherited descriptor and an authenticated XPC request. Neither per-launch secret is ever in argv, an environment variable, a file, a log, a panic, a crash report, a notification, a status, or a page. The legacy source device token has its own Windows environment compatibility path in section 23.1, planned for removal. | A process that can read the app's or helper's memory can read the PC. That is the app-compromise bound. T1 to T4. |
| Half-closed flow paused over 300 seconds | The source closes the flow at its 300 second session idle; the target sees truncation unless both `FIN` frames crossed. | P21 and Q21. The design does not claim 600 seconds at the source. |
| Attacker replaying a captured record | Rejected. Fresh connection keys, no 0-RTT. | None beyond TLS. |
| Attacker replaying a pairing message into another session | Rejected. The exporter and the session nonces differ, so the transcript hash differs. | None. |
| Attacker with the token but not the key | Rejected at the client certificate check. | None. This is stronger than today. |
| Attacker deleting a record | Cannot, unless it holds the pinned private key or the person acts locally. A remote `FORGET` is accepted only on a pin-matched `hs-pair/1` connection with the trust-admin purpose, and only after a locked recheck. A local removal is not vetoed by a live flow; durable success requires reviewed commit and recovery. | Local file deletion forces a re-pair but does not substitute a record, because of the integrity tag. |
| Attacker sending a fake FORGET reply | The target verifies the server pin and the reply hash before any local deletion. | An attacker who holds the pinned server key is the source device. |
| Attacker substituting a record | Detected by the tag where the key is not readable by the device account, or refused by the confirmation requirement. | An attacker who can read the store key can forge the tag. An attacker who can read the signing key can impersonate. |
| Attacker rolling a record back | Detected only if the anchor was not rolled back too. Rollback restores an older approved pin, not an unapproved key. | No platform here documents a monotonic counter. See Q14. |
| Code in the Android app UID | Can read the store key through the Keystore and forge a tag. | Out of scope; the same code can already act as the app. |
| Root on a Linux target | Can read the store key and forge a record. Can read the signing key. | Out of scope. The helper runs as root, section 7.4. |
| Local attacker with the desktop user account | Can read the signing key on macOS, Windows, and Linux unless the file is root-owned and the attacker is not root. | Android and iOS with Secure Enclave are stronger. Desktops are not. |
| Downgrade to plaintext | No plaintext path exists. | None in the engine. |
| Downgrade to TLS 1.2 | Not built. | A future policy change needs its own tests. |
| Unknown client on the proxy port | Rejected at the handshake, before any application byte is sent. The TLS handshake flight is visible. | Handshake CPU is spent. Rate limits bound it. |
| Unknown client on the pairing port | Refused unless the source is armed and the mechanism matches. The target must confirm. | A person can still approve the wrong device. SAS cross-session search is bounded, not eliminated. |
| Slow handshake drip | Rejected at the total deadline. | The deadline covers the handshake only. |
| Truncation by a middlebox or attacker | Rejected as a truncation. A TLS close without a `FIN` frame resets the inner flow. An abort path sends no `FIN` frame and no application data; whether the outer close is a RST or a graceful TLS close is recorded by a device row. | The frame parser and both `FIN` directions are host tests before a device row. The design does not depend on a documented RST. |
| Slow download after a one-way close | Delivered in full within 300 seconds. The sender of `FIN` keeps reading until the peer's `FIN`. There is no close drain timer. | The flow's own idle and stall budgets still apply. A pause over the source's 300 second window is a truncation. |
| Malformed or reordered data-phase frame | Rejected by the frame parser or by TLS ordering. The inner flow resets. | A peer can always send garbage; it cannot deliver it as clean data. |
| Server certificate disclosure | An active hotspot client can learn the source's stable pin. | Linkability is accepted or needs a presentation-certificate design. See Q6. |
| Target client certificate disclosure during first pairing | A man in the middle can receive the target certificate before the target has a pin. | After pairing, the target checks the server certificate against the candidate pins before its client certificate. TLS 1.3 orders the server flight first; the rustls case is tested deterministically in V5, and a stack that cannot enforce the order records the disclosure as a limitation. The target sends no token on a mismatch. |
| iOS device locked | A new handshake fails with a fixed message. No fallback key. An established flow may continue because TLS 1.3 key updates do not use the long-term key. | Untested. The accessibility class is a product decision. See Q8. |
| Android resumption | Tickets are off before the handshake and the peer certificate is rechecked, so a resumed session is not expected and is caught by the trace gate. | Not proven. Android source mode is not approved until a full handshake is observed on every connection. See Q3. |
| Compromised source device | Attacker is the source device. | Out of scope. |
| Compromised target device | Attacker has the token and the client key. | Out of scope. |
| Quantum adversary | TLS 1.3 uses ECDHE, which is not post-quantum. A future quantum adversary that records traffic could derive past session keys. The static ECDSA key is also not post-quantum. | No post-quantum algorithm. Do not claim forward secrecy against a quantum adversary. |

### 24.1 Forward secrecy, precisely

TLS 1.3 uses ephemeral ECDHE for the session keys. Against a classical attacker
who records traffic and later obtains the static ECDSA private key, past session
keys are not recoverable. That is forward secrecy for session keys. The static
key can still impersonate future connections if it is stolen.

The store HMAC key and the proxy token are not forward secret. If the store key
is stolen, the attacker can forge records. If the token is stolen, the attacker
still needs the client private key to pass the certificate check.

The exporter value is derived from the session secrets and is not forward
secret against a compromise of those secrets during the session. It is not a
long-term secret.

A future quantum adversary that can break ECDHE is not covered. The design must
not say "session keys stay forward secret" without that limit.

## 25. Limitations

- No complete reviewed incarnation protocol or per-host crash and recovery
  model exists. Local revocation may be uncertain across restart; a memory-only
  epoch cannot make it durable. Migration coexistence and the auto-stop timer
  model are also unresolved. These block implementation and release.

- This is a design, not a proof. No code was written for it. No device, route,
  tunnel, or emulator was used.
- The platform rows are documented API availability, not tested behavior. Every
  one is a device test in `TEST_MATRIX.md`.
- The pairing ceremony is the entire trust decision. TLS cannot make a careless
  confirmation safe.
- A six-digit SAS has a residual cross-session search risk. The design bounds
  it; it does not eliminate it. QR avoids it.
- Exporter byte equality across rustls, Conscrypt, and Network.framework is
  documented for none of the three and must be measured. If it fails, the design
  does not ship.
- The iOS source may be unable to compute the exporter after its handshake.
  `metadata(definition:)` is documented, but whether a server-side post-ready
  metadata returns a usable exporter is untested. If it does not, iOS source
  mode is not approved.
- Rollback protection is best effort. It cannot stop an attacker who restores
  the record and the anchor together.
- No revocation list, no transparency, no expiry enforcement. A record is
  trusted until a person removes it.
- Non-exportable keys exist only on Android and iOS with the Secure Enclave.
  Desktop keys are files or DPAPI-protected files.
- The design does not make the product fail-closed. More-specific routes, local
  DNS, and network extensions can still bypass the tunnel, as documented today.
- Handshake cost per inner flow is unmeasured. A browser opening 30 connections
  does 30 full handshakes, each with two ECDSA operations on the source device.
- The framed data phase is new work on all three peers and adds 3 bytes per
  write. Its CPU and throughput cost is unmeasured.
- No audit has been done. `rustls`, `ring`, `rcgen`, Network.framework, and
  Conscrypt are trusted as established implementations.
- Memory zeroization beyond what the libraries do is not claimed.
- Android source mode depends on a bundled TLS provider. That is a supply-chain
  addition, not a platform guarantee.
- The certificate template with an empty subject and no EKU is untested on the
  platform stacks.
- A stable server pin is linkable by an active hotspot client.
- The browser GUI has no pairing surface. It cannot self-consent and never
  receives a code, QR, token, bearer, or pairing capability. Section 11.4.
- The target app QR payload is exposed to that surface's memory and screen. A
  process that can read either can pair one device once inside the TTL. The
  design does not claim to stop that process.
- The macOS XPC request, the Linux helper stdin request, and the one-way
  descriptor bootstrap protocol are design only. The bootstrap has no
  acknowledgement, so the app or the helper learns of a malformed frame only from
  the engine's exit code. Windows cannot pair at all until a protected helper and
  a real target app exist. A headless target cannot pair without a console actor.
  Section 11.4, P2, and P22.
- After a target restart the token is gone, so the first proxy connection needs
  the known path, which needs the source device app open and in the foreground on
  iOS and Android. The design does not make a restart transparent, and it does
  not retry on a timer. Section 7.10.1.
- The API bearer and the PC are protected from the browser page, not from the
  signed-in user. On Linux a same-user process can read the Electron main process
  and take both. The design claims the page boundary only. Section 24, U16.
- A peer on the hotspot can deny one ceremony attempt: it can hold the single SAS
  prompt to its deadline or spend the SAS attempt budget; a source impersonator can end the target QR ceremony.
  The design bounds the denial and does not prevent it. Section 4.3.
- The host field is IPv4 only in this revision, and the canonical form is fixed.
  An IPv6 hotspot listener needs a new canonical form and a new vector.
  Section 7.11.1.
- Pairing is mandatory for proxy mode. The Windows and headless proxy is
  therefore unavailable until a console actor is designed or those targets are
  removed from the release. There is no token-only fallback, and section 23.1
  lists the macOS, Linux, and Windows token-only proxy and diagnostic paths that
  this removes.
- A shared hotspot gateway can host several paired sources. The target learns
  which source answered only from the server certificate, and a stack that sends
  the client certificate before the server verifier discloses the client pin to a
  non-candidate server. Section 7.11.
- The historical removal proposal cancels matching live flows by force. Its
  cancellation and durable-revocation outcomes remain blocked pending the
  incarnation and recovery model; a live flow must not veto an attempted local
  removal. Sections 14.1 and 18.2, W17 to W20.
- The source half-closed idle is 300 seconds. A paused half-closed flow can be
  truncated by the source. P21 and Q21.
- An abort depends on the receiver's no-`FIN` rule, not on a documented TCP RST.
  Apple documents `NWConnection.cancel()` as graceful, and the Android public
  documentation does not promise a reset. The actual wire result is a device row
  T25 to T28. The design does not claim a reset it has not measured.

## 26. Implementation risks

1. **Readiness and buffering.** The engine's relay polls raw sockets for
   readiness. A TLS layer buffers plaintext, so raw readability is not plaintext
   readability. `phone.rs` already uses a blocking socket with `wait_socket`,
   which fits `rustls::StreamOwned`. `relay.rs` is poll-based and would need
   `wants_read` and `wants_write` handling. This is the largest engineering risk
   and it is not a protocol risk.
2. **Half-close.** The relay currently calls `shutdown(Shutdown::Write)` on an
   inner FIN. This design replaces that with a `FIN` frame and keeps reading in
   the other direction. The frame layer is new work on all three peers. The
   platform TLS close behavior after both `FIN` frames is recorded, not assumed.
3. **iOS exporter timing.** The metadata is obtained after `.ready`, not in the
   verify block. Whether a server-side post-ready metadata returns a usable
   exporter is untested. This is the second largest risk and it gates the iOS
   source mode.
4. **iOS ALPN availability.** The deployment target is iOS 17.0, but
   `sec_protocol_metadata_copy_negotiated_protocol` is iOS 18.5 and later. The
   app must use the deprecated `get` call on 17.0 to 18.4 and the `copy` call on
   18.5 and later. A build that uses only `copy` does not compile at 17.0.
5. **Cross-stack exporter equality.** Three implementations, one label, one
   empty context. A mismatch is a stop, not a workaround.
6. **iOS identity assembly.** The `kSecClassIdentity` match is documented but
   must be proven on a device, including with a Secure Enclave key.
7. **iOS locked key access.** A keychain key may be unavailable while the device
   is locked. The app must fail closed and must not keep an exportable fallback.
8. **Android TLS 1.3 server with a keystore key on API 26.** Documented as a
   library capability, not proven. Conscrypt behaviour varies by vendor, and the
   Keystore signer path must be shown to accept an externally built TBS.
9. **Android tickets and handshake kind.** No public kind API. The gate is a
   trace, and a single resumed session blocks the mode.
10. **Probe cost.** The probe now costs a full handshake on the proxy channel.
    Measure, then either back off or accept it. Do not turn resumption on to fix
    it.
11. **Certificate agreement.** Three independent builders must produce a
    certificate each stack accepts. Fixed cross-platform TBS vectors are required
    before any device test.
12. **Store key.** Each platform needs a separate protected store key. A
    non-exportable signing key cannot provide it. The provisioning and recovery
    path for that key needs a per-host design and independent review before
    implementation. Key loss, inaccessible keys, reset, partial restore and
    replacement must block trust until reviewed recovery establishes safe state;
    no automatic unkeyed fallback, re-pair or store deletion is authorized.
13. **Anchor write ordering.** A crash between the record commit and the anchor
    commit must not lose a record. The order is record first, anchor second.
14. **QR decoder.** Android has no QR decoder today. A camera and a decoder are
    a new dependency and a permission.
15. **Data-phase framing.** The 3-byte frame header, the 16 KiB payload cap, and
    the `FIN` rule are a new wire format. Both peers must implement the same
    parser and the same truncation rule. A frame bug is a data corruption bug,
    so the host rows in G are a release gate.
16. **Bootstrap delivery.** The app now creates both secrets and sends them to
    the helper on the existing request; the helper forwards them on one read-only
    descriptor. There is no acknowledgement, so the only failure signal is the
    engine's exit code. The macOS XPC request, the Linux helper stdin request, and
    the zeroization path are new plumbing. A missing or mis-scoped PC either
    blocks pairing or, worse, exposes it to the page. The fail-closed rule is that
    every pairing route without PC returns 401 and no channel is invented for
    Windows or headless. Host rows L27 to L33 and U11 are a release gate.
17. **Shared gateway candidate set.** The target must build candidates by
    endpoint, verify the server pin, and only then use a token. A bug that reads
    the token before the pin match, or that falls back to another candidate,
    crosses records. A second bug is a UI that claims an identity change or
    offers a forget action when the real condition is "none of the paired sources
    answered". The dialog must be one neutral message for every candidate count,
    name no record, and delete nothing. The host rows E25 to E31, V1 to V5, and
    T12 to T15 are a release gate.
18. **Revocation lock order.** Registration takes the store lock and then the
    table lock; a removal takes the same two in the same order. A reversed order,
    or a sweep that runs after the store lock is released, reopens the race that
    B4 names. A cancellation that closes the outer transport with a `FIN` frame
    also breaks the truncation rule. F34 to F39 and a lock-order audit are a
    release gate.
19. **Arming attempt budget.** The source keeps a SAS arming for up to three
    failed proof attempts. The counter must increment only after a verified
    reveal, not on malformed frames, or the original exhaustion bug returns. The
    prompt deadline must be derived from the arming deadline, not set
    independently. C55 to C58 test both.
20. **Credential lifetime versus ceremony lifetime.** The two are cleared on
    different events. A single "clear everything on window close" call would break
    a tray session, and a single "clear nothing" call would leave a code on screen
    after a lock. L34 to L36.
21. **Canonical host.** A textual host field is easy to compare two ways. The
    implementation must parse, re-render, and compare, or it will accept a
    non-canonical value that a later version reads differently. QV19 and E29.

## 27. Product decisions

These need the maintainer. They are not technical choices. Where this revision
already made the technical selection, the decision is the dependency, not the
design.

- **P1. Android TLS stack.** Bundle Conscrypt (selected here), move the Android
  TLS path to the shared Rust core, or reduce proxy support below API 31.
  Recommendation: bundle Conscrypt, keep `minSdk 26`, and measure the APK cost.
- **P2. Pairing becomes mandatory for proxy mode. This is a gated product
  decision, and its cost is listed in section 23.1.** A typed token alone no
  longer starts a proxy session, and the two token-only diagnostics stop working
  as well. On a target with a protected app actor this is a one-time setup. On a
  target without one it removes working paths:
  (a) design a console actor that reads the PC from a TTY and never logs it;
  (b) remove Windows and headless proxy, and say in the release notes that the
  CLI `tun --phone` path and both diagnostics also stop working there; or
  (c) do not make pairing mandatory, which would weaken the mutual-authentication
  goal and needs a new review. There is no token-only fallback and no
  unauthenticated local page. Recommendation: gate Windows and headless proxy out
  of the first release, keep the engine source-proxy path available only where a
  protected target actor exists, and design the console actor separately. State
  the diagnostic loss explicitly; it is easy to miss because those paths change
  no route.
- **P3. Primary bootstrap.** Numeric comparison, which needs no camera, or
  high-entropy QR, which avoids the SAS cross-session residual and needs a camera
  and an Android decoder. Recommendation: ship QR where a camera is available and
  keep SAS only if the new review accepts Q1. If it does not, SAS is removed.
- **P4. Persist records across restarts.** Today the GUI holds credentials in
  memory and asks the person to pair again after a restart. Records should
  persist. Recommendation: persist records, keep the token in memory as today,
  and use the known path to refresh it. The accepted consequence is that every
  target restart needs the source device app in the foreground once, section
  7.10.1; if that is unacceptable, the separate decision is to store the token in
  the target's protected store, which widens the store and needs its own review.
- **P5. Revocation and active flows.** Local removal on the source must not be
  vetoed by a live target. Matching sessions are cancelled. Durable success
  requires a reviewed commit and recovery model; uncertainty blocks trust use
  and success. A remote FORGET policy remains a product choice. No split is
  approved here.
- **P6. Remove pairing v1 and the plaintext proxy in one release.** Keeping them
  creates a downgrade path. Recommendation: remove, and require both apps to be
  updated and paired again.
- **P7. Accept the ALPN fingerprint.** A fixed label is visible in the
  ClientHello. Recommendation: accept, with a short non-branded label.
- **P8. Engine dependency.** Allow `rustls`, `ring`, and `rcgen` in `rust/`.
  Recommendation: allow, with the reason "never invent crypto", and record the
  measured cost.
- **P9. iOS key accessibility and Secure Enclave.** Choose
  `AfterFirstUnlockThisDeviceOnly` for background use or
  `WhenUnlockedThisDeviceOnly` for stronger protection. Recommendation: try
  Secure Enclave with `AfterFirstUnlockThisDeviceOnly`, fall back to a plain
  keychain key, and state which one the build used.
- **P10. Server certificate linkability.** Accept that an active hotspot client
  can learn the source pin, or design a stable identity with a short-lived
  presentation certificate. Recommendation: accept for the prototype, record the
  limitation, and do not log the pin.
- **P11. Android resumption proof.** Trace every handshake, or add a per
  connection `SSLContext` if the trace shows tickets. Recommendation: prove the
  Conscrypt ticket switch on the device matrix first; do not relax the recheck.
- **P12. Half-close mechanism.** The design selects a data-phase `FIN` frame on
  every peer. One-way `close_notify` is not used as the half-close signal because
  it is not portable. Recommendation: accept the 3-byte frame header and the
  `FIN` rule, and test them before any device row. Do not keep a per-platform
  half-close profile.
- **P13. Android dependency.** Allow `org.conscrypt:conscrypt-android` in the
  Android app. Recommendation: allow, with the reason in section 6.4, and record
  the per-ABI size.
- **P14. Android support floor.** Keep `minSdk 26` with Conscrypt (selected), or
  raise the proxy floor to API 31 and say so in the product. Recommendation: keep
  26. Do not raise it silently.
- **P15. Arming friction and order.** A person must arm both devices for SAS and
  QR, and for QR must scan before tapping Continue on the target. Recommendation:
  accept the two actions, use a clear single arm control, and make Continue and
  Start explicit rather than auto-connecting.
- **P16. Record cap and replace UX.** 8 records on a target and 16 on a source,
  with a two-step replace. Recommendation: accept, and put "Forget this device"
  on the row of the affected record.
- **P17. Pairing display surface and secret creation.** Native target app only.
  The app creates both the API bearer and the PC, and the Rust-served browser GUI
  has no pairing surface, no code, and no QR. The helper never creates a secret
  and never returns one. Recommendation: accept; do not add a browser pairing
  surface without a new review and a channel that the page cannot obtain.
- **P18. Known-path tap.** Require a user tap on the target even when both
  records match, or only a protocol `PAIR_KNOWN_OK`. Recommendation: no tap; the
  records already matched and the check is locked. Revisit if the new review
  requires one.
- **P19. Conscrypt maintenance and 16 KB.** Accept a bundled TLS provider with
  no Mainline updates, track its releases, and run a 16 KB device test, or move
  to the shared Rust core, or raise the proxy floor to API 31. Recommendation:
  accept the pinned 2.9.0 build with the release-tracking rule, and record the
  16 KB result. If a security fix is not published, move to the shared Rust core
  or the API 31 floor.
- **P20. Windows target pairing.** Windows has no protected helper and no real
  target app, so no target app creates a PC. Recommendation: keep QR and SAS
  disabled on Windows, keep the WinUI app a labelled preview, and do not ship the
  Windows target proxy until P2 and P22 are decided. Do not move the root engine
  behind an unauthenticated local page to make Windows pairing appear to work.
- **P21. Source half-closed idle.** Raise the source half-closed session idle to
  600 seconds to match the target, or accept a 300 second truncation for a
  half-closed flow with no traffic. Recommendation: raise it to 600 seconds and
  measure the held-slot cost. If that is not acceptable, state the 300 second
  limit in the UI and tests.
- **P22. Headless and console pairing actor.** Design a console actor that reads
  the PC from a TTY or a private descriptor, never logs it, and binds it to one
  launch; or declare headless proxy unsupported. Recommendation: declare it
  unsupported in the first release and design the console actor only if a real
  headless user exists. This decision gates the Windows and headless proxy.
- **P23. QR scan and target Continue.** Require the person to scan first and then
  tap Continue on the target, rather than auto-connecting on arm. Recommendation:
  accept; it removes the scan-order race and gives the target a local consent
  event before it sends `PAIR_HELLO`.
- **P24. Accept a bounded denial of one ceremony attempt.** Any peer that can
  reach the pairing listener can hold the single SAS prompt to its deadline, spend
  the SAS attempt budget, or end the target QR ceremony by impersonating the source. Recommendation remains open, with
  the bounds in section 4.3, and state it in the source app text. Do not claim the
  arming cannot be exhausted. If the maintainer will not accept it, SAS is
  removed and QR keeps its own single-use denial.
- **P25. Lock and window behavior.** Window close, tray hide, and screen lock end
  the ceremony but keep the API bearer, the PC, and a running tunnel.
  Recommendation: accept; a tray app that quits on window close would be a
  platform behavior change, and clearing the credentials on lock would break the
  tunnel control path.

## 28. Open questions

These are precise questions for the new independent review. They are not
resolved here.

- **Q1. SAS residual.** Is a six-digit SAS with commit-reveal, exporter binding,
  one live prompt, arming, and the existing rate limits acceptable against an
  attacker who can run many sessions? If not, is QR the only approved bootstrap?
- **Q2. Known path.** Must the target require a user tap on every `known`
  connection, or is a protocol `PAIR_KNOWN_OK` after a locked record check
  enough?
- **Q3. Android resumption.** Does `Conscrypt.setUseSessionTickets(socket, false)`
  suppress TLS 1.3 tickets on API 26 through 36? Is there a public handshake-kind
  signal? What is the per-connection cost?
- **Q4. Store key.** Where is the store key provisioned on each platform, and
  what happens when it is lost? If it is lost, is the correct behavior to refuse
  all records until re-pairing?
- **Q5. Half-close.** Is the 3-byte `DATA`/`FIN` frame approved on all peers?
  It is selected because one-way `close_notify` is not portable. The review
  should check the frame format, the 16 KiB cap, the truncation rule, and the
  cost. If it rejects the frame, the alternative is no half-close, not a
  per-platform profile.
- **Q6. Server certificate disclosure.** Is a stable server pin visible to any
  active hotspot client acceptable? If not, what is the presentation-certificate
  design and how does it interact with the pin?
- **Q7. Exporter.** Does `sec_protocol_metadata_create_secret_with_context` on a
  post-ready metadata handle produce the RFC 8446 value after the handshake on a
  TLS server? If not, is iOS source mode acceptable to drop?
- **Q8. iOS locked key.** Which accessibility class does the product require?
  Does the foreground proxy need to work while the device is locked after the
  first unlock? What happens to a new connection while locked?
- **Q9. Certificate template.** Do Network.framework and Conscrypt accept a
  self-signed P-256 certificate with an empty subject and issuer and no EKU? If
  not, which minimal fields are required?
- **Q10. Cross-session SAS and QR coexistence.** If both mechanisms ship, is the
  section 9.5 no-downgrade rule sufficient, or should QR be mandatory whenever
  the hardware supports it?
- **Q11. FORGET placement.** Is a pin-matched `FORGET` on `hs-pair/1` only
  acceptable, with the source app open, or should FORGET have its own label or a
  second protocol on the proxy listener? The design uses the pairing label only
  and refuses FORGET on `hs-proxy/1`, because the proxy listener starts with
  SOCKS5 and a second parser there would be ambiguous.
- **Q12. Probe cost.** What is the CPU and battery cost of a full handshake
  every 2 seconds, and what interval is acceptable without resumption?
- **Q13. iOS exporter on a server.** Same question as Q7, stated as a gate:
  which device result decides it, and what is the substitute if it fails?
- **Q14. Rollback.** Is a two-location anchor acceptable, or does the product
  accept a store that can be rolled back to a previously approved record?
- **Q15. Arming model.** Is a 120 second arming window acceptable, with a
  one-shot target and a source that allows three failed SAS proof attempts? Does
  the source need a per-mechanism confirmation every time?
- **Q16. Browser pairing.** The design removes browser pairing entirely: no QR,
  no code, no arm, no allow. Is target-app-only pairing acceptable, or does the
  product need a browser pairing surface with a channel the page cannot obtain?
  The current answer is no browser pairing.
- **Q17. Pairing capability delivery.** Is an app-created PC, sent to the helper
  on the existing request and forwarded on one pipe read end or self-restricted socket, sufficient to
  keep the secret out of the page, or is a separate app-signed control channel
  required? The design treats the app process as the target actor, and Q27 asks
  the narrower bootstrap question.
- **Q18. Android Keystore vendor path.** Does the target vendor accept a
  `DIGEST_NONE` EC key for Conscrypt's `NONEwithECDSA` handshake signature, and
  does the same key accept an externally built TBS with `SHA256withECDSA`? A
  refusal blocks the Conscrypt path on that device and has no exportable-key
  fallback.
- **Q19. iOS ALPN when the client offers none.** Does the iOS source complete a
  handshake with a client that offers no ALPN, and what does the negotiated
  protocol call return? A nil or mismatch is a hard failure. The app must branch
  between `get` on iOS 17.0 to 18.4 and `copy` on 18.5 and later.
- **Q20. Framed data-phase cost.** What is the CPU, memory, and throughput cost
  of the 3-byte frame header and the `FIN` state machine on each peer? A cost
  that breaks the existing budget is a design problem, not a reason to fall back
  to a per-platform close.
- **Q21. Source half-closed idle.** Raise the source half-closed window to 600
  seconds to match the target, or accept a 300 second truncation? If it is
  raised, what is the held-slot cost at the proxy session cap?
- **Q22. Headless and Windows actor.** Is there a real headless or Windows user
  for proxy mode? If so, what console actor reads the PC from a TTY or a private
  descriptor without logging it, and how is it bound to one launch? If not, the
  Windows and headless proxy stays out of the release.
- **Q23. Source local revocation.** The design closes matching live flows on a
  source local removal. Is that preferred to letting them finish with a hard
  upper bound? The requirement is that a remote target cannot block the removal.
- **Q24. Shared gateway candidates.** Is a candidate set keyed by the exact host
  and port sufficient, or must the target also handle a source whose proxy port
  changed without a known refresh? Is one neutral message for every nonmatch
  acceptable, given that a nonmatch cannot prove an identity change? Does every
  target stack run the server verifier before the client Certificate flight, and
  is the deterministic rustls counter test in V5 sufficient evidence for the
  rustls peer?
- **Q25. Source arming attempt budget.** Is three failed SAS proof attempts inside
  120 seconds the right trade between attack-driven arming exhaustion and SAS
  brute force? The QR secret remains single use.
- **Q26. Abort wire result.** The design does not require a TCP RST. Is the
  receiver's no-`FIN` rule sufficient, or must one platform force a reset? If a
  platform can only close gracefully, the peer still treats it as truncation.
- **Q27. One-way bootstrap.** Is an app-created secret, sent over the existing
  app-to-helper request, forwarded on descriptor `3` under rule 1, with no
  acknowledgement, a binary frame, 64-hex request lines, and the exit codes in
  section 11.4.1, sufficient? The alternative is a dedicated control socket or a
  helper-created secret, and revision 6 showed that the helper-created secret
  needs a reverse channel that does not exist.
- **Q28. Forced revocation.** Is immediate forced cancellation of matching proxy
  sessions, ordered by one revocation epoch per client pin and one lock,
  acceptable, given that an open relay has no idle bound? The alternative is a
  bounded drain, which would leave the removed identity working for the bound.
  The per-pin epoch exists so removing one source does not abort another source's
  registration.
- **Q29. Scope of the mandatory-pairing loss.** Section 23.1 lists the token-only
  proxy and diagnostic paths that stop working, including the Windows
  environment token path that is planned for removal. Is that list complete and
  is the loss acceptable, or must a protected actor exist on every desktop
  target before pairing becomes mandatory?
- **Q30. Host family.** Is IPv4-only acceptable for the `host` field in this
  revision, with one canonical form, or does the source listener need an IPv6
  form and a second vector before implementation?

## 29. Sources

Read on 2026-11-05.

- RFC 8446, TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
- RFC 8446, section 6.1, closure alerts and one-way close:
  https://www.rfc-editor.org/rfc/rfc8446#section-6.1
- RFC 8446, section 7.5, exporters:
  https://www.rfc-editor.org/rfc/rfc8446#section-7.5
- RFC 9266, channel bindings for TLS 1.3, `tls-exporter`:
  https://www.rfc-editor.org/rfc/rfc9266
- RFC 5705, keying material exporters: https://www.rfc-editor.org/rfc/rfc5705
- rustls 0.23.46 client TLS 1.3 state machine, `src/client/tls13.rs`, read from
  the local crates.io source copy, no network: `ExpectCertificateRequest`,
  `ExpectCertificateVerify`, `ExpectFinished`, `emit_certificate_tls13`.
- Repository files read for the token inventory and bootstrap, no network:
  `rust/src/main.rs` (`read_windows_token`, `read_gui_token`,
  `parse_gui_token`, the `tun`, `phone`, `phone-udp-diag`, `phone-speed-diag`,
  and `gui` arms), `rust/src/udp_diag.rs` (`read_secrets_fd`,
  `parse_secrets`, `prompt_secrets`), `rust/src/gui.rs` (bearer comparison and
  the manual token request body), `gui_assets/app.js`, `linux/helper/src/main.rs`
  (`HS1` request, `--token-fd 3 --parent-fd 4`, helper exit codes), and
  `macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/RootEngineLauncher.swift`.
- rustls `ConnectionCommon::export_keying_material`:
  https://docs.rs/rustls/0.23.46/rustls/struct.ConnectionCommon.html
- rustls `CommonState::handshake_kind` and `peer_certificates`:
  https://docs.rs/rustls/0.23.46/rustls/struct.CommonState.html
- Apple, `sec_protocol_metadata_create_secret`, iOS 12.0 and macOS 10.14:
  https://developer.apple.com/documentation/security/sec_protocol_metadata_create_secret(_:_:_:_:)
- Apple, `sec_protocol_metadata_create_secret_with_context`, iOS 12.0 and
  macOS 10.14:
  https://developer.apple.com/documentation/security/sec_protocol_metadata_create_secret_with_context(_:_:_:_:_:_:)
- Apple developer forums, comparison of `sec_protocol_metadata_create_secret`
  with `SSL_export_keying_material` on TLS 1.3 and TLS 1.2:
  https://developer.apple.com/forums/thread/128938
- Apple, `SecIdentityCreateWithCertificate`, macOS only:
  https://developer.apple.com/documentation/security/secidentitycreatewithcertificate(_:_:_:)
- Apple, "Creating an Identity", macOS scope:
  https://developer.apple.com/documentation/security/creating-an-identity
- Apple, `kSecClassIdentity`, iOS 2.0 and later:
  https://developer.apple.com/documentation/security/ksecclassidentity
- Apple, `SecKeyCreateRandomKey`, iOS 10.0 and macOS 10.12:
  https://developer.apple.com/documentation/security/seckeycreaterandomkey(_:_:)
- Apple, `SecCertificateCopyKey`, iOS 12.0 and macOS 10.14:
  https://developer.apple.com/documentation/security/seccertificatecopykey(_:)
- Apple, `NWConnection.metadata(definition:)`, iOS 12.0 and later:
  https://developer.apple.com/documentation/network/nwconnection/metadata(definition:)
- Apple, `NWProtocolTLS.Metadata.securityProtocolMetadata`, iOS 12.0 and later:
  https://developer.apple.com/documentation/network/nwprotocoltls/metadata/securityprotocolmetadata
- Apple, `sec_protocol_metadata_get_negotiated_protocol`, iOS 12.0 to 18.5:
  https://developer.apple.com/documentation/security/sec_protocol_metadata_get_negotiated_protocol(_:)
- Apple, `sec_protocol_metadata_copy_negotiated_protocol`, iOS 18.5 and later:
  https://developer.apple.com/documentation/security/sec_protocol_metadata_copy_negotiated_protocol(_:)
- Apple, `SecKeyCreateSignature`:
  https://developer.apple.com/documentation/security/seckeycreatesignature(_:_:_:_:)
- Apple, `sec_protocol_options_set_tls_tickets_enabled`, iOS 12.0 and later:
  https://developer.apple.com/documentation/security/sec_protocol_options_set_tls_tickets_enabled(_:_:)
- Apple, `sec_protocol_options_set_verify_block`:
  https://developer.apple.com/documentation/security/sec_protocol_options_set_verify_block(_:_:_:)
- Apple, `sec_protocol_options_set_peer_authentication_required`:
  https://developer.apple.com/documentation/security/sec_protocol_options_set_peer_authentication_required(_:_:)
- Apple, keychain accessibility constants:
  https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlockthisdeviceonly
  https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly
- Apple, `NWConnection.send` final message:
  https://developer.apple.com/documentation/network/nwconnection/send(content:contentcontext:iscomplete:completion:)
- Apple, `NWConnection.cancel()`, documented as a graceful disconnect:
  https://developer.apple.com/documentation/network/nwconnection/cancel()
- Android, `Socket.setSoLinger(boolean, int)`:
  https://developer.android.com/reference/java/net/Socket#setSoLinger(boolean,%20int)
- Linux man-pages, `socket(7)`, `SO_LINGER`:
  https://man7.org/linux/man-pages/man7/socket.7.html
- Linux man-pages, `tcp(7)`, `SO_LINGER` portability note:
  https://man7.org/linux/man-pages/man7/tcp.7.html
- Microsoft, `LINGER` structure:
  https://learn.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-linger
- Android, `android.net.ssl.SSLSockets`, added in API 29, with
  `setUseSessionTickets` in API 29 and `exportKeyingMaterial` in API 31:
  https://developer.android.com/reference/android/net/ssl/SSLSockets
- Android, `SSLSocket` protocol, cipher, and API-level tables:
  https://developer.android.com/reference/javax/net/ssl/SSLSocket
- Android, `SSLSessionContext.setSessionCacheSize`, zero means no size limit:
  https://developer.android.com/reference/javax/net/ssl/SSLSessionContext#setSessionCacheSize(int)
- Android, `SSLSessionContext.setSessionTimeout`, zero means no timeout limit:
  https://developer.android.com/reference/javax/net/ssl/SSLSessionContext#setSessionTimeout(int)
- Android, `MessageDigest.isEqual`, constant-time implementation note:
  https://developer.android.com/reference/java/security/MessageDigest#isEqual(byte[],%20byte[])
- Android, `Socket.shutdownOutput`:
  https://developer.android.com/reference/java/net/Socket#shutdownOutput()
- Android, `KeyProperties`, `DIGEST_NONE` API 23 and later:
  https://developer.android.com/reference/android/security/keystore/KeyProperties
- Android, `SSLParameters.setApplicationProtocols` and
  `setHandshakeApplicationProtocolSelector`, API 29 and later:
  https://developer.android.com/reference/javax/net/ssl/SSLParameters
- Android, `KeyGenParameterSpec.Builder`, self-signed certificate and
  certificate setters, API 23 and later:
  https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder
- Android, 16 KB page sizes, AGP 8.5.1 or higher, uncompressed libraries, and
  `PAGE_ALIGNMENT_16K`:
  https://developer.android.com/guide/practices/page-sizes
- Conscrypt capabilities, TLS 1.3 and cipher suites:
  https://github.com/google/conscrypt/blob/master/CAPABILITIES.md
- Conscrypt `Conscrypt` class, `exportKeyingMaterial`, `setUseSessionTickets`,
  `setApplicationProtocols`, and `setApplicationProtocolSelector`:
  https://github.com/google/conscrypt/blob/master/common/src/main/java/org/conscrypt/Conscrypt.java
- Conscrypt Android artifact `org.conscrypt:conscrypt-android:2.9.0`, AAR
  `minSdkVersion 21` and four native ABIs:
  https://repo1.maven.org/maven2/org/conscrypt/conscrypt-android/2.9.0/
- Conscrypt 2.9.0 sources, `CryptoUpcalls.ecSignDigestWithPrivateKey`,
  `AbstractConscryptSocket.shutdownOutput`, and `Conscrypt.exportKeyingMaterial`:
  https://repo1.maven.org/maven2/org/conscrypt/conscrypt-android/2.9.0/conscrypt-android-2.9.0-sources.jar
- Conscrypt README, development moved internal and platform Mainline updates:
  https://github.com/google/conscrypt/blob/master/README.md
- Maven Central metadata for `org.conscrypt:conscrypt-android`, latest 2.9.0,
  last updated 2026-11-04:
  https://repo1.maven.org/maven2/org/conscrypt/conscrypt-android/maven-metadata.xml

## 30. Change log

- 2026-11-05, revision 12 correction: Added the revision 11 finding trace,
  explicit blocked historical sequences, store-key loss gate, current-incarnation
  presence and port binding, exact anchor checks and uncertain-write outcomes.
  The separate candidate critique remains NOT APPROVED; no cutover is selected.

- 2026-11-05, revision 12: Recorded the revision 11 NOT APPROVED result;
  separated candidate review from release, marked historical procedures locally,
  corrected uncertain-write and revocation outcomes, and gated migration,
  per-host recovery, product choices and device evidence. No complete protocol
  or product decision is claimed. Fresh independent review is requested.

- 2026-11-05, revision 8 completion pass: The first revision-8 pass was
  interrupted. Mapped a failed server `CertificateVerify` to the neutral
  nonmatch message instead of `not_trusted`, and stated that no failure is a
  reason to forget a record. Replaced the rustls V5 resolver-count assertion,
  which a correct rustls 0.23.46 stack would fail, with server-side receipt and
  client signing counts. Added the complete disarm lists SD1 to SD10 and TD1 to
  TD10. Fixed the section 20 epoch row that still described a global counter,
  fixed the epoch start value, and sized the tombstone cap. Fixed the section 31
  row references and the QV20, L28, and L36 labels. Rewrote the section 23.1
  inventory from the code: the environment token is read on macOS and Linux
  too, the diagnostics and `phone` are macOS and Linux only, and the diagnostics
  read no environment. Fixed the bootstrap: `--bootstrap-fd 3` selects the
  frame, `api_len` is exactly 32, the per-hop encoding table, the legacy
  `--token-fd` format as the code reads it, engine codes `9` and `10`, and the
  separation from the helper's codes. Added rows V19 to V24. Design only. No
  code, test, device, route, tunnel, network, or Python. Status remains
  UNAPPROVED.
- 2026-11-05, revision 8: Revised after the independent review
  `50f21843-f0b1-4e95-b063-4f1c686bfcf7`, which returned NOT APPROVED against
  revision 7 and supplied the full M8 and M9 text. Replaced both
  candidate-count messages with one neutral nonmatch message, removed the
  identity-change claim and the forget advice, and added the deterministic
  rustls test that the client certificate is not sent after a rejected server
  certificate. Replaced the global revocation epoch with one epoch per client
  pin, so removing one source cannot abort another source's session. Completed
  the arming summary. Fixed the QV19, U20, E29, E26, and E31 counts and
  references. Corrected the Windows `tun --phone` token path to the environment
  or no-echo console, not `--secrets-fd`, and stated the diagnostics prompt and
  the planned environment-token removal. Defined bootstrap descriptor `3`, the
  decimal fd flags, binary frame versus hex request encoding, and the exit-code
  classes. Split tunnel stop from engine process exit. Anchored the QR deadline
  at secret creation. Separated network flush from local durable flush in the
  lock rule. Added rows V1 to V18 and fixed the section 2.3/2.4 and E26/E31
  cross-references. Status remains UNAPPROVED. The cross-stack exporter, vendor
  `DIGEST_NONE`, 16 KB runtime, and iOS lifecycle gates remain open.

- 2026-11-05, revision 7: Revised after the sixth independent review, which
  returned NOT APPROVED. The review task is
  `f5aa54fc-f04d-4ee0-93c0-69cb044850e2`; its text was not available when this
  revision was written, so the disposition maps the supplied blocker list B1 to
  B6 and the supplied medium topics M1 to M7. Removed the `HSACK1`
  acknowledgement and made the bootstrap one way on one pipe read end or self-restricted socket,
  because the launcher does not open descriptor 4 for writing on macOS or
  Windows. Moved secret creation to the target app and removed the Linux app
  secret pipe, so the PC travels on the existing app-to-helper request and is
  never returned. Split credential lifetime from ceremony lifetime, so window
  close and screen lock no longer clear the bearer or the PC. Added a revocation
  epoch, an atomic registration step, and forced cancellation, and deleted the
  idle-bound claim that an open relay does not satisfy. Replaced the
  "arming cannot be exhausted" claim with a stated bounded denial and left the
  SAS product choice open. Inventoried the token-only proxy and diagnostic paths
  that P2 removes. Added the authorization matrix, the same-user Linux and
  desktop threat, the canonical IPv4 host form, the target restart sequence, the
  legacy descriptor and version rules, the arming and prompt deadline ordering,
  and two distinct candidate-set failure messages (superseded in revision 8 by
  one neutral message). Added rows C55 to C58, E29 to
  E31, F34 to F39, L27 to L37, T5 to T7, U1 to U20, and QV19. Status remains
  UNAPPROVED. The cross-stack exporter, vendor `DIGEST_NONE`, 16 KB runtime, and
  iOS lifecycle gates remain open.

- 2026-11-05, revision 6: Revised after the fifth independent review, which
  returned NOT APPROVED. The review task is
  `9f1414bc-feb0-4f69-8e48-d3b49b2a4616`; its text was not available when this
  revision was written, so the disposition maps the task blocker list M1 to M7.
  Moved PC creation to the launcher and sent both secrets to the engine on one
  framed descriptor, with an authenticated XPC return on macOS and a dedicated
  app pipe on Linux. Made mandatory pairing a gated product decision and stated
  that Windows and headless proxy is unavailable without a console actor.
  Replaced the one live-flow removal rule with unconditional source local removal
  and a per-session client pin index. Added the shared-gateway candidate pin set
  and exact token association after server verification. Defined QR scan order
  and target Continue, and stopped unauthenticated hellos from consuming source
  arming. Replaced the abort reset claim with the documented Apple/Android/Linux
  and Windows behavior and the receiver no-`FIN` rule. Added T1 to T28 and
  Q22 to Q26. Status remains UNAPPROVED. The cross-stack exporter, vendor
  `DIGEST_NONE`, 16 KB runtime, and iOS lifecycle gates remain open.

- 2026-11-05, revision 5: Revised after the fourth independent review, which
  returned NOT APPROVED. Added the per-launch pairing capability and made
  pairing native target app only, so the browser page holds no credential and
  cannot self-consent; Windows target pairing is gated unsupported. Added the
  per-record credential map for host, port, and token. Required the target to
  select the source by pin and abort on mismatch. Required iOS peer
  authentication. Forbade data frames before the SOCKS5 success reply. Made
  arming one-shot. Resolved local and remote removal under one live-flow rule.
  Corrected the 300 second source idle. Required an underlying reset on abort.
  Pinned the certificate extension allowlist and the rustls and rcgen features.
  Defined the `flags` mask. Moved the Conscrypt check before the handshake.
  Corrected the exporter empty-context text. Fixed the SAS code formula and the
  iOS terminology. Gated iOS background behavior. Added `PAIR_HELLO` and
  `PAIR_RESULT` vectors and the revision-4 adversarial rows. Added P21 and Q21.
  Status remains UNAPPROVED. The cross-stack exporter, vendor `DIGEST_NONE`,
  16 KB runtime, and iOS lifecycle gates remain open.

- 2026-11-05, revision 4: Revised after the third independent review. Replaced
  one-way `close_notify` with a framed `DATA`/`FIN` data phase on every peer.
  Fixed the wire labels and record version to v4, added the message type table,
  and ordered the FORGET pins by role, `pin_T || pin_S`. Added the staged and
  confirmed record states, the lost-message recovery table, and the lost FORGET
  recovery table. Fixed the known path to use `generation`, require a confirmed
  record, and copy the token under the lock before framing. Removed the browser
  QR endpoint: QR is target-app-only and the browser page is SAS-only. Corrected the
  iOS ALPN availability branch for deployment target 17.0, the
  `securityProtocolMetadata` nullability, and the Conscrypt 2.9.0 source and
  artifact facts. Added the fixed pairing-message layout table, refused `known`
  while a first-pairing mechanism is armed, removed FORGET from the proxy
  listener (it runs on the pairing listener only), and corrected the validity
  cross-reference to section 18.6. Corrected the frame-size note: a 16 KiB
  payload can span TLS records and is not claimed to fit one record. Added P19,
  P20, Q17 to Q20, and the `TEST_MATRIX.md` Q and R sections. Status remains
  UNAPPROVED pending a new independent review.
- 2026-11-05, revision 3: Revised after the second independent review. Added the
  mandatory RFC 9266 exporter channel binding with per-platform availability and
  an explicit iOS gate. Added the mechanism discriminator, local arming, and the
  no-downgrade rule. Replaced the close-notify drain with the RFC 8446 one-way
  close rules. Added multiple identities and a local-only replace. Replaced the
  single ALPN field with a purpose set and a wire version. Rewrote FORGET around
  the authenticated server pin, a request id, and one idempotent reply. Added the
  store counter and anchor and corrected the rollback and per-platform integrity
  claims, including the root Linux helper. Made the known path check-only under
  one lock with a fresh recheck before the token. Selected bundled Conscrypt for
  Android to keep `minSdk 26` and recorded the alternative. Defined the complete
  transcript context and per-state hashes. Defined the QR display surfaces and
  the browser exposure rules, and corrected the "never reaches the browser"
  claim. Moved the pin from the SPKI hash to the key-point hash. Added the
  certificate parse caps, durable commit points, constant-time APIs, the
  non-reproducible signature rule, the Android certificate rule, and
  `SecKeyCreateRandomKey`. Status remains UNAPPROVED pending a new independent
  review.
- 2026-11-05, revision 2: Revised after the first independent review.

## 31. Blockers and limits for the next review

The next independent review must decide these before implementation. In
addition, it must assess a complete incarnation protocol, durable local
revocation and per-host recovery, and a migration and timer model. Product
coexistence and migration choices remain open; host and authorized device tests
are separate release gates. The separate candidate analysis is not presumed
accepted. They are not
resolved by this revision.

1. **Review mapping.** Confirm that B1 to B6 and M1 to M7 in section 2.1.1 and
   M8 and M9 in section 2.1 match the review
   `50f21843-f0b1-4e95-b063-4f1c686bfcf7`. If the review used different findings,
   this disposition is incomplete and its count cannot be trusted.
2. **Bootstrap shape.** The one-way descriptor `3` selected by
   `--bootstrap-fd 3`, the binary frame with exactly 32 raw bytes per secret, the
   64-hex Linux request and HTTP headers, the engine exit codes `2` to `10` and
   their separation from the helper's own codes, the app-created secrets, the
   existing app-to-helper request, and the legacy `--token-fd` rule as the code
   reads it today are design only. The review should accept them or name the
   missing app-helper contract. Rows L19 to L33, U1 to U8, U18, QV20, V12, V13,
   V19, and V20.
3. **Credential lifetime.** The design keeps the bearer and the PC for a launch,
   keeps the target credential map across a tunnel stop, and clears both on an
   engine process exit. The review should accept that split, or state which event
   ends a launch. Rows L34 to L36 and V15.
4. **Source local revocation.** The historical design proposes immediate forced cancellation,
   ordered by one revocation epoch per client pin, with no reliance on an idle
   bound. The review should accept it or require a bounded drain and say what
   happens to a removed identity that keeps working during the drain. The per-pin
   epoch must not abort a session for another pin. A memory-only epoch cannot
   persist removal; uncertain writes and restart require a reviewed durable
   recovery model before trust use. Rows F34 to F39, V7 and W20.
5. **Bounded denial.** Section 4.3 states that a peer can deny one ceremony
   attempt. The review should decide whether that is acceptable, and whether SAS
   ships at all. Rows C55 to C58 and U9.
6. **Mandatory pairing cost.** Section 23.1 lists the token-only proxy,
   forwarder, and diagnostic paths that stop working, per command and per
   platform, including the environment token that macOS, Linux, and Windows all
   read today and that is planned for removal. The review should confirm the
   list against the code and accept the loss, or require a protected actor on
   every desktop target first. Rows T5 to T7, U11 to U14, V10, V11, and V21.
7. **Shared-gateway candidates.** The review should accept the exact host and
   port candidate set, the canonical IPv4 host form, the no-fallback rule, the
   single neutral nonmatch message, the no-forget and no-identity-change rule,
   the mapping of a failed server `CertificateVerify` to that neutral message,
   and the client-certificate order limitation. Rows E25 to E29, E31, T12 to
   T15, V1 to V5, V9, and V24.
8. **Arming and prompt deadlines.** The absolute arming deadline, the subordinate
   prompt deadline, and the source three-attempt budget are proposed bounds.
   Rows C49 to C58 and T16 to T24.
9. **Abort rule.** The design does not claim a TCP RST. The review should accept
   the receiver no-`FIN` rule, or require a platform that can force a reset. Rows
   T25 to T28.
10. **Same-user boundary.** The design claims the browser page boundary, not the
    signed-in-user boundary. The review should confirm that this is acceptable
    for a desktop target, especially on Linux. Row U16.
11. **Live gates.** Cross-stack exporter equality, the vendor Keystore
    `DIGEST_NONE` path, the Android 16 KB runtime, and the iOS lifecycle remain
    open. No row here is evidence for them.
12. **M9 consistency items.** The review should confirm the per-pin epoch, the
    neutral nonmatch message, the Windows and diagnostics token sources, the
    binary frame and hex request encoding, the exit-code classes, the full
    authorization matrix, the stop-versus-exit lifetime split, the QR deadline
    anchor, and the network-versus-durable flush lock rule. Rows V1 to V18.
13. **Completion pass.** Section 2.1.2 lists eight corrections made after the
    first revision-8 pass was interrupted: the pin-mismatch and
    `CertificateVerify` mapping, the rustls order test that a correct stack
    would have failed, the complete disarm lists SD1 to SD10 and TD1 to TD10,
    the per-pin epoch budget row, the matrix references, the token-only
    inventory, and the bootstrap decoding. The review should check each against
    the cited code and rows. Rows V19 to V24.
14. **No implementation.** This revision wrote no production or protocol code,
    changed no route, created no TUN or utun device, ran no device or emulator,
    and used no Python. It is UNAPPROVED.
