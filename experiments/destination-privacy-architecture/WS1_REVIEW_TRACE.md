# WS1 review trace, revision 9

Status: UNAPPROVED. This file maps the independent review findings to the
revision 9 architecture. It is a trace, not evidence that a finding is fixed in
code. No production file was changed, no `AGENTS.md` invariant was changed, and
no product authorization was granted. No network, device, route, or TUN device
was used.

Revision 9: `WS1_TARGET_ECH_DOH_ARCHITECTURE.md`.
Revision 9 test plan: `WS1_TEST_MATRIX.md`.
Superseded revision 1: `WS1_REVISION_1_SUPERSEDED.md`.
Revisions 2 to 8 are not preserved as separate files in this checkout.
Their independent reviews are the input recorded below.

The revision 9 input is the independent revision 8 review (delegated review
task `ecb2b96c-d750-4156-9703-bcf9f5fc6052`), read in full for this revision.
It kept revision 8 UNAPPROVED. It named four blockers: the `session_generation`
rules made normal commits fail and could drop committed answers; waiter grants
could be settled twice and stop ignored outstanding grants; the DoH barrier
delayed route cleanup and an incomplete stop had no report path; and the B7
analysis misread the current invariant and code. It named four major issues:
three definitions of `snapshot_seq`, a stale runtime state through the probe
fallback, a TCP:53 `Close` that ended earlier queries, and two smaller gaps
(the retry row state and a cancelled config fetch with no wake). It named four
test rows that contradicted the design: T5.39, T5.46, T6.18, and T16.10.
Revision 9 answers every item and adds F87 to F95. The owner decisions and
host and device gates it listed stay open.

The revision 8 input is the independent revision 7 review (review thread
`00889a37-16c1-40c6-8fcb-45c725f3a6a0`). It did not approve revision 7. It
named seven blockers: B1 retry generation and cache commit ownership, B2 slot
and socket ownership until the pool returns, B3 adapter failure delivery and
reserved capacity, B4 cross-shard waiter FIFO, admission, cancel, and deadline,
B5 the actual `Relay::stop` and `Drop` ordering and an unknown stop budget, B6
the real status versus diagnostics paths and missing-key consistency, and B7
the third-party DNS product-owner decision and invariant amendment. The review
thread is no longer readable in this checkout. The blocker subjects are taken
from the task brief that names that review. Revision 8 answers every blocker
and adds F79 to F86, where F86 records the remaining contradictions.

The revision 7 input was the independent revision 6 review of this file, the
test matrix, and the trace (task `9afab1a0-b634-470c-9598-ff5e55e0a623`). It
did not approve revision 6. It named six blockers and must-fix items M1 to M5.
Revision 7 answers every blocker and adds F66 to F78.

Earlier inputs, retained for audit: revision 3 answered the review of revision 2
by delegated child `993f3dea-a391-40ce-9709-b79bbcd453e9`; revision 4 answered
`cf977de8-f512-4edf-9b7e-9e15ab932948`; revision 5 answered
`d0a77501-277d-4e77-906d-1c6f4b0c1b43`; revision 6 answered the review of
revision 5; revision 7 answered `9afab1a0-b634-470c-9598-ff5e55e0a623`. Those
reviews found the fallback conflict, the counter mismatch, the sharding
assumption, the delivery ordering, the lifecycle gaps, the capacity error, the
stop barrier, and the consumer incompatibility recorded in the trace table.

**Mapping of the revision 7 six blockers to M1 to M5.** These B numbers are the
revision 7 review's labels. They are not the revision 8 B1 to B7 subjects named
above; those are recorded in F79 to F86. The task brief records the six blocker
texts. The review expressed the same subjects again as M1 to M5 at must-fix
severity. This trace uses this mapping for the revision 7 rows; where the brief
and the review differ, the review wins:

| Blocker | Subject | M item |
|---|---|---|
| B1 | The relay is sharded 1 to 8 workers with no global ownership, barrier, or atomic limit | M1: sharded ownership and global limits |
| B2 | TCP:53 response bytes bypass the terminal job decision | M2: commit ordering and delivery |
| B3 | Connection, cache, and ECH state lack an owner and a slot lifecycle | M3: session, cache, and attempt lifecycle |
| B4 | 32 slots are exhausted by common per-query-port churn | M4: capacity and churn |
| B5 | Stop order admits while terminating | M5: stop barrier |
| B6 | Runtime coverage is in the static capability, and the `app_ech` parser and Linux renderer data path are incompatible | Consumer and capability compatibility (no separate M number) |

The plan was edited outside this task during revisions 5 and 6 and later by
task `85710a0e`. The plan's own revision note says that task applied P7 and P9
to P15. The trace treats that as a text claim to verify, not as approval and not
as evidence that each passage is correct. Revision 8 does not edit the plan.

Status vocabulary:

- **Design addressed**: the revised design answers the finding. The code and
  test are still missing.
- **Design addressed, open measurement**: the design answers it, but a build,
  a benchmark, or a live test is needed before a claim.
- **Open decision**: the design records a boundary. It does not claim the
  feature.
- **Corrected in revision 4**: an earlier revision's answer was wrong or
  incomplete, and revision 4 changes the design text. It does not change code.
- **Corrected in revision 5**: revision 4's answer was wrong or incomplete, and
  revision 5 changes the design text. It does not change code.
- **Corrected in revision 6**: revision 5's answer was wrong or incomplete, and
  revision 6 changes the design text. It does not change code.
- **Corrected in revision 7**: revision 6's answer was wrong or incomplete, and
  revision 7 changes the design text. It does not change code.
- **Corrected in revision 8**: revision 7's answer was wrong or incomplete, and
  revision 8 changes the design text. It does not change code.
- **Corrected in revision 9**: revision 8's answer was wrong or incomplete, and
  revision 9 changes the design text. It does not change code.
- **Open owner decision**: the design records a question that only the product
  owner can answer. The design does not answer it.

## 1. Trace table

| ID | Review finding | Status | Where addressed | Residual |
|---|---|---|---|---|
| F1 | The revision 1 definition of `hide` was DNS-only and did not meet the application ECH requirement | Design addressed | Sections 1.1 to 1.4, 2.2, 7.3, 12; section 10 items 1 and 2 | U1. `hide` stays unsupported. No application ECH path exists |
| F2 | DoH alone was being treated as `hide` | Design addressed | Sections 1.3, 2.2, 5.3.1, 7.3; section 10 item 5 | U20, U21. WS0 and WS5 must use the separate `encrypted_dns` capability. DoH alone cannot satisfy `hide` |
| F3 | macOS and Windows gateway DNS can bypass the tunnel | **Corrected in revision 4; refined in revision 6** | Sections 4.2, 4.3, 11.1 U4 and U5; T5.25 | U4, U5, U44. Revision 3 wrongly said the query enters under `/1`. The connected-subnet route wins. Gateway DNS is a bypass by route-specificity inference on macOS and Windows. The record names no OS and does not show the DNS case, so it is not live DNS evidence. Linux is a likely bypass on a default link-bound resolver. No detector is implemented and no host route is proposed |
| F4 | IPv6 link-local DNS bypasses the tunnel | Design addressed | Sections 4.2, 4.3, 6.3 | U6. No detector and no override |
| F5 | No safe resolver override and cleanup design | Design addressed, open decision | Section 4.4 | U7. Override is out of scope. The safe design is a requirement list, not code |
| F6 | The actual SOCKS CONNECT DNS path and invariant numbers were wrong or incomplete | Design addressed | Sections 6.1, 6.2, Appendix C | U9, U24. The `Setup` refactor is not done. The corrected invariant is design text. The SOCKS5 `socks5h` requirement is not enforced by the code. DoH does not cover SOCKS5 mode |
| F7 | A passive ClientHello count would count GREASE as ECH | Design addressed | Sections 5.4, 7.2; section 10 item 13 | U20. Do not add an application ECH counter |
| F8 | Per-query socket and handshake costs were not measured | Design addressed, open measurement | Sections 6.2, 6.5 | U10. No hotspot measurement exists |
| F9 | TCP:53 was not covered, and DNSSEC, DoT, DoQ, application DoH, and caches were not handled | Design addressed | Sections 4.7, 4.8, 4.9 | U8, U16, U17, U18 |
| F10 | Failure records can hold names | Design addressed | Section 7.1 | U19, U27. The existing name map needs a test and a mode-start clear. DoH uses a new constructor |
| F11 | The DoH design could block the relay worker | Design addressed | Sections 6.4, 6.6 | U9, U10. The pool is not implemented |
| F12 | The loopback TCP:53 adapter had no access control | Design addressed | Section 6.6 | U8. Cookie, caps, and crash tests are not implemented |
| F13 | HTTP parsing bounds were missing | Design addressed | Section 4.6 | The parser and fuzz tests are not written |
| F14 | Retries were allowed after a stall or timeout | Design addressed | Sections 4.8, 5.3, 5.3.1; section 10 item 12 | U20. The `ech_fallback` comment in `rust/src/diagnostics.rs` still says "or a stall" |
| F15 | The DoH bootstrap trust story was incomplete | Design addressed | Sections 4.5, 5.2 | U15. The rustls ECH API must be re-verified |
| F16 | Normalized sockets and the TTL audit were not applied to DoH | Design addressed | Sections 6.2, 6.3 | The implementation and TTL test are missing |
| F17 | Counters could leak names or merge different claims | Design addressed | Sections 2.3, 7.2 | U20. The schema additions belong to WS0 |
| F18 | The cross-target toolchain could regress or fail | Design addressed, open measurement | Section 8 | U14. `aws-lc-sys` and `ring` build results are unproven |
| F19 | The status could be read as support | Design addressed | Header, sections 2.2, 7.3, 12, Appendix D | U1. `hide` stays unsupported |
| F20 | Universal application ECH may be impossible under the constraints | **Corrected in revision 5** | Sections 1.2, 1.3, 3.1, 3.2; section 10 item 2 | U1. A transparent boundary does not exist, so `hide` is closed as unsupported under the plan's default. A product-owned client is a separate optional future proposal, not a blocking decision |
| F21 | The plan requires a post-failure non-ECH fallback that the architecture forbids | **Corrected in revision 4** | Sections 5.3.1, 5.3.2, 11.3 P1 and P2 | U25. Revision 3's own handoff offered an "opt-in retry" after a timeout, which repeated the contradiction. Revision 5's plan contains the corrected P1 and P2 text: no automatic non-ECH retry, and a separately selected non-ECH profile is not `hide` |
| F22 | Existing `doh_*` counter meanings change silently, and the `ech_*` handshake outcomes are undefined | **Corrected in revision 4** | Sections 2.3, 7.2.1 to 7.2.3 | U20. Revision 3's ledger did not add up. Revision 4 states both identities exactly, including retry precedence, `doh_other_error`, `doh_response_mismatch`, and the non-ECH bootstrap |
| F23 | The existing DNS failure constructor and direct-mode recorder cannot carry a DoH failure | **Corrected in revision 4** | Sections 6.6, 7.1 | U27. Add `FailureEvent::doh_query(destination, port, reason, code, phase)`, `record_doh_failure`, and the adapter preface that carries the inner destination. Test direct mode and TCP:53 |
| F24 | `encrypted_dns` could read as supported from a compile, and the default resolver path is unverified | **Corrected in revision 4** | Sections 2.2, 2.4, 4.2, 4.3, 7.3, 8 | U28. `encrypted_dns` and `resolver_ech` stay `unverified`. `ech` stays `unsupported`. Revision 3 still allowed `ech = supported` from a build, which revision 4 removes |
| F25 | The plan names SOCKS command `0x80` for DNS and uses stale status words | **Corrected in revision 5** | Section 11.3 P4, P5, P6, and P8 | U26. The plan now contains command 1, the numeric-address and gateway note, the four capability states, and capability reporting. P4, P5, P6, and P8 are applied |
| F26 | The test matrix lacked adversarial coverage and had ordering problems | Design addressed | `WS1_TEST_MATRIX.md` T4.06, T4.09, T4.10, T4.14, T4.20, T5.08, T7.15 to T7.21, T8.16, T9.17, T9.18, T12 | The tests are not written. T8.16 is a plan only |
| F27 | B1: the fallback rule contradicts itself, and WS6 was told to copy it | **Corrected in revision 5** | Sections 5.3.2, 11.3 P1 and P2; T5.05, T7.04, T9.18 | U25. The plan forbids an automatic non-ECH retry after a timeout, reset, or certificate failure and labels the separately selected profile |
| F28 | B2: the macOS and Windows gateway DNS claim is wrong, so the F3 correction did not hold | **Corrected in revision 5; refined in revision 6** | Sections 4.2, 4.3, 11.1 U4 and U5; T5.25 | U4, U5, U44. Gateway DNS is a bypass by route-specificity inference on macOS and Windows. The record is not a live DNS result and names no OS. Linux is likely on a default link-bound resolver. No row says "conditional" or "certain with live DNS evidence" |
| F29 | M1: `ech = supported` can come from a build, and the detail text has no field | Design addressed | Sections 2.2, 2.4, 7.3, 8; T4.21, T7.09, T7.19, T10.15, T10.16 | U28. `ech` stays `unsupported`; `resolver_ech` is separate and `unverified` |
| F30 | M2: the counter ledger does not add up and the causes are incomplete | **Corrected in revision 5; refined in revision 6** | Sections 7.2.1 to 7.2.3; T7.15, T7.18, T7.20, T7.23, T7.27 | U20, U37. Two exact identities. Seven DoH causes, including `doh_cancelled`. The identity is exact in a coherent snapshot and after the barrier seals. Revision 6 added the in-flight gauge terms and the per-job terminal owner; revision 7 makes the owner the admitting shard. GREASE and the non-ECH bootstrap are outside the ECH identity |
| F31 | M3 and the P1 to P11 gaps: the WS6 handoff is wrong and incomplete | **Corrected in revision 5; extended in revision 6** | Section 11.3; trace section 4; T12.01 to T12.21 | U30, U32. Architecture section 11.3 quotes the current passages and records the remaining work. The plan contains P1 to P6 and P8; P7 is partly applied; P9, P10, P11's open-question answer, and P12 to P15 remain. P10 records the boundary outcome, not an open owner decision, and separates the owner's DoH scope decision |
| F32 | M4: the adapter flood test cannot pass as designed | Design addressed | Section 6.6; T8.14, T8.16 | U31. No eviction. A bounded local denial of service is accepted |
| F33 | The lower-priority items: failed config fetch, `ech_*` while `mode = off`, TCP:53 destination and `phase`, `doh_lookups` narrowing, counter name, connection cap, source device cap, helper signature | Design addressed | Sections 5.2, 6.3, 6.5, 6.6, 7.1, 7.2.3; T5.24, T7.17, T8.02 | U20, U27. No code and no test |
| F34 | The RFC numbers and the plan's WS1 gate conflict | **Corrected in revision 5; refined in revision 6** | Section 11.1 U29 and U30; section 11.3 P10 | U29 still needs the RFC texts; every citation is now marked unverified. U30 is the required P10 text, not an applied plan edit. The plan body still needs P10 applied. No implementation |
| F35 | The gate contradicts P10, so the owner client decision blocks even encrypted DNS | **Corrected in revision 5; refined in revision 6** | Header, sections 1.3, 10 item 23, 11.3 P10; T12.14 | Application ECH is closed, not gated. The DoH forwarder has its own product owner scope acceptance. No owner client decision blocks closing `hide` or finishing this design. The owner acceptance and the review are separate |
| F36 | The tunnel-wide DoH forwarder is a scope expansion nobody approved | **Corrected in revision 5** | Sections 4.1.1, 10 item 6, 11.2, 11.3 P10 | The forwarder is a proposed independent scope with recorded tradeoffs and its own acceptance. It is not approved or implemented |
| F37 | "No plaintext by default" contradicts "DoH off by default" | **Corrected in revision 5; refined in revision 6** | Sections 2.6, 4.1, 12; matrix G2, T7.04, T14 | Acceptance and G2 say "with a DoH setting active." The default `off` profile adds no counter and no warning; the plaintext counter and UI need a separate acceptance |
| F38 | Exact counter identities fail in a live snapshot, and outcome ownership is ambiguous | **Corrected in revision 5; replaced in revision 6; superseded in revision 7** | Sections 6.4, 7.2, 7.2.2; T6.14, T7.23, T7.27 | `doh_in_flight` is a gauge. The admitting shard owns its jobs and every shard writes one global ledger; the pool and the TCP:53 adapter write no counter. The identity is exact in a coherent snapshot and after the barrier seals. Each accepted job has a job ID, one owning shard, and one terminal owner |
| F39 | The DoH cap assumes a source device free-slot report that does not exist | **Corrected in revision 5** | Section 6.5, U34; T5.22, T5.26 | Keep the proposed 32 cap. A capacity error is `doh_other_error` with reason `source_capacity`. A free-slot query is out of scope |
| F40 | Capability states conflict with the code, `supported` is unreachable, and `ech` duplicates application ECH | **Corrected in revision 5; replaced in revision 6** | Sections 2.2, 2.4, 2.5, 7.3, 8; T7.09, T7.13, T7.19, T7.22, T10.13 to T10.17, T13 | The four states have contract meanings; WS0 splits the comment and adds the reviewed build qualification constant. `supported` is reachable after live qualification and static per profile. The legacy `ech` keeps its meaning; the new keys carry the new claims. Every consumer is mapped |
| F41 | Linux gateway and default resolver behavior is likely a bypass, not merely "conditional" | **Corrected in revision 5; refined in revision 6** | Sections 4.2, 4.3, U4 and U5; T5.25 | Linux is a likely bypass on a default link-bound resolver. Gateway DNS on macOS and Windows is a route-specificity inference, not live DNS evidence. No record names the OS for the DNS case |
| F42 | The reason for rejecting a gateway host route is unverified | **Corrected in revision 5** | Section 4.2, U33 | A host route is an open option with pairing, probe, captive-portal, and platform-route risks. Do not claim interface pinning changes the path |
| F43 | The live record does not name the operating system | **Corrected in revision 5; refined in revision 6** | Sections 4.2, 4.3, U4 | The record reports a gateway route bypass, names no OS, and does not show the DNS case. It is not live DNS evidence |
| F44 | `doh_plaintext_fallbacks` contradicts its own definition and the default state is undefined | **Corrected in revision 5; refined in revision 6** | Sections 2.3, 2.6, 7.2, 7.2.3; T5.05, T7.04, T14 | The counter is `dns_plaintext_profile_queries`, it needs a separate acceptance, and it is absent or zero in the default `off` profile. It is never a fallback |
| F45 | Tethering detection is marked unchanged without measurement | **Corrected in revision 5** | Section 5.5 | Mark it not measured and name the DoH ClientHello and resolver IP |
| F46 | A rejected resolver ECH config can stay cached | **Corrected in revision 5** | Section 5.3; T4.22 | Retry configs replace the cached config, or the config is evicted when there is no supported retry config |
| F47 | Matrix row order and numbering | **Corrected in revision 5** | `WS1_TEST_MATRIX.md` | T7.19 to T7.23 follow T7.18 in order. No T7.23 gap remains |
| F48 | The section 12 "no non-ECH attempt" sentence contradicted the resolver ECH-disabled retry in section 5.3, T4.09, G5, and P11 | **Corrected in revision 6** | Sections 5.3, 5.3.2, 7.2.1, 10 item 13, 11.3 P11, 12; T4.09, T4.24, G5 | One retry table. Application flows never retry. The resolver connection retries once after an authenticated rejection, with retry configs or ECH disabled. Every summary uses that table |
| F49 | The TCP:53 adapter split frames and submitted jobs, so the "single worker writer" claim was false | **Corrected in revision 6; extended in revision 7** | Sections 4.8, 6.4, 6.6, 7.1, 7.2; T5.28, T5.29, T5.32 | The adapter sends an admission request with the owning shard. That shard owns the job, outcome, counter, cache commit, and failure record. The adapter writes no DoH counter and receives only committed deliveries |
| F50 | A dropped, cancelled, or timed-out completion had no ECH outcome, and late completions could count twice | **Corrected in revision 6; extended in revision 7** | Sections 6.4, 7.2.1, 7.2.2; T7.24, T7.25, T7.26 | Job IDs, reserved completion, event, and delivery slots, one terminal outcome, late-completion discard by ID and generation, and gauge terms for ECH attempts and config fetches |
| F51 | Separate atomics and queued work made instantaneous identities false | **Corrected in revision 6; extended in revision 7** | Sections 6.4, 7.2, 7.2.2; T7.27, T8.18 | One coherent ledger snapshot. Identities are exact in every snapshot and after the barrier seals, for 1 to 8 shards. A multi-shard stress test checks it |
| F52 | The capability migration would break the GUI, Linux page, and Windows report, and mixed runtime with static states | **Corrected in revision 6** | Sections 2.5, 2.6, 7.3; T13 | Every consumer is mapped. `ech` keeps its meaning. New keys are additive. Static capability and runtime coverage are separate. No default payload changes |
| F53 | The plan handoff was stale after orchestrator edits; P7 was partly applied and P10 missed passages | **Corrected in revision 6** | Section 11.3, 11.3.1; T12.06, T12.09, T12.10, T12.15 to T12.20 | P7 is partly applied. P10 lists every boundary-open passage and distinguishes the owner scope decision from the review. P12 to P15 add the stale code, DNS, Linux, and reader-facing corrections |
| F54 | Idle connection eviction contradicted one-flow-one-socket and could fail a live flow | **Corrected in revision 6; extended in revision 7** | Sections 6.4.6, 6.5; T8.02 | Hard session cap. No cross-session eviction. A slot frees only through its own session's release path. The bounded ECH retry is the only replacement |
| F55 | The adapter cap (64) exceeded the DoH connection cap (32) | **Corrected in revision 6; replaced in revision 7** | Sections 6.4.9, 6.5, 6.6; T8.05, T8.21 | The adapter cap is an independent local bound. The session cap governs DoH sessions. Neither is a reservation for the other |
| F56 | Deadlines could start after queue wait | **Corrected in revision 6; extended in revision 7** | Sections 4.6, 6.4.3; T8.11 | The deadline starts at arrival and includes the slot wait. A job that passes it is terminal without a socket |
| F57 | Worker panic detection and failure policy were incomplete | **Corrected in revision 6; extended in revision 7** | Section 6.7; T6.07, T6.08, T6.15, T6.20 | Pool, adapter, shard, and supervisor panics have separate policies. A shard panic does not publish a partial ledger as exact |
| F58 | Cancellation did not cover the whole source setup | **Corrected in revision 6** | Section 6.3; T6.02, T5.28 | The blocking source driver checks stop and deadline in every state and discards a late reply |
| F59 | A bounded completion queue could silently drop work | **Corrected in revision 6; replaced in revision 7** | Sections 6.4.3, 6.4.5; T8.04, T8.17 | Capacity is reserved at admission. No completion, event, or delivery drops. A post-commit write failure is `doh_adapter_errors` |
| F60 | Cargo features were described as mutually exclusive | **Corrected in revision 6** | Section 8; T10.17 | Features are additive. `ech` implies `doh`. Both may be enabled. One provider is selected |
| F61 | The gateway bypass was called live DNS evidence | **Corrected in revision 6** | Sections 4.2, 4.3, U4, U5; T5.25 | Gateway DNS is a route-specificity inference. The record names no OS and does not show the DNS case. No live DNS result exists |
| F62 | RFC citations were read from memory but labelled as read | **Corrected in revision 6** | Section 0, U29; T12.21 | All citations are unverified until a reviewer reads the text |
| F63 | A direct-mode DoH failure record is a new privacy scope | **Corrected in revision 6** | Section 7.1; T7.07, T7.16, T7.28 | Counters only by default. A record needs its own acceptance |
| F64 | The default plaintext counter and warning change default behavior | **Corrected in revision 6** | Sections 2.3, 2.6, 7.3; T14 | Separate telemetry and UI acceptance. The default `off` payload and UI do not change |
| F65 | Lower-priority items: T10.07 wrong key, a revision 4 label, a stale trace, the IPv6 qualifier, and the certificate fixture | **Corrected in revision 6** | Matrix T10.07, header, T4 header, T4.23, T5.09; Appendix G | The key is `resolver_ech`, the labels say revision 6, the trace is updated, the IPv6 row is qualified, and the fixture authenticates the origin name |
| F66 | B1/M1: the relay is sharded 1 to 8 workers, so "the relay worker" owned no global object, limit, or barrier | **Corrected in revision 7** | Sections 6.4.1 to 6.4.4, 6.4.9, 7.2; trace section 2; matrix T5.30, T5.31 | One supervisor, one compact shard owner, one global ledger. Global job, session, waiter, event, and delivery bounds are reserved under the ledger lock. A job belongs to one shard and never migrates. The pool and adapter write no counter |
| F67 | B2/M2: TCP:53 response bytes could reach the inner stream before the terminal decision | **Corrected in revision 7** | Sections 4.8, 6.4.5, 6.6, 7.2; matrix T5.32, T5.33, T7.29 | Two-phase commit. The owner records one outcome, then releases a delivery with job ID and generation. The adapter has no direct pool path. A post-commit write failure is `doh_adapter_errors`, not a second outcome |
| F68 | B3/M3: session, connection, config-cache, and ECH state had no owner or slot lifecycle | **Corrected in revision 7** | Sections 6.2, 6.4.2, 6.4.6, 6.4.7; matrix T5.34, T5.35, T5.36, T7.30 | One session owner, one reserved slot, one generation, named release paths, single-flight config cache with commit-only publication, and an `AttemptStarted`/`AttemptOutcome` pair |
| F69 | B4/M4: the fixed 32-slot cap is exhausted by common per-query-port churn | **Corrected in revision 7; open measurement** | Sections 6.5, 6.5.1, 6.8; matrix T8.19 to T8.23 | Session lifetime is separate from the relay flow lifetime: 250 ms quiet, 2 s hard idle, bounded FIFO slot wait, measured cap, declared envelope, explicit failure above it. Cross-source-port sharing is unapproved (U56) |
| F70 | B5/M5: stop recorded terminal outcomes before it stopped admission, and the barrier was single-worker | **Corrected in revision 7** | Sections 6.4.8, 6.7; matrix T6.16 to T6.20 | Phase is part of the ledger lock. Intake closes first, then the drain. Six phases, a bounded deadline, and a failed-stop result. An incomplete barrier never publishes an exact ledger |
| F71 | B6: runtime coverage lived in the static capability, the `app_ech` parser used the four-state vocabulary, and the Linux renderer had no payload path | **Corrected in revision 7; superseded in part by revision 8** | Sections 2.2, 2.4, 2.5, 2.5.1, 2.5.2, 7.3; matrix T13.06 to T13.11; F84 | Revision 7 separated the runtime object and gave `app_ech` its own kind. Revision 8 corrects the data path: capability and runtime are in status, counters are in diagnostics, and the Linux card reads both. The old "hs:diagnostics only" residual is withdrawn |
| F72 | The adapter cap, the session cap, and the DoH connection cap were treated as one budget | **Corrected in revision 7** | Sections 6.4.9, 6.5, 6.6; matrix T8.05, T8.21 | The adapter cap is an independent local bound. The session cap governs DoH sessions. Neither is a reservation for the other |
| F73 | Delivery capacity and delivery failure accounting were undefined | **Corrected in revision 7** | Sections 6.4.3, 6.4.5, 7.2; matrix T8.04, T7.32 | One delivery slot per accepted job, reserved at admission. A committed answer keeps its outcome if the inner write fails. `doh_adapter_errors` covers the transport event |
| F74 | The ECH attempt gauge was incremented at admission, before the pool knew whether ECH was offered | **Corrected in revision 7** | Sections 6.4.4, 6.4.7, 7.2.1; matrix T5.36, T7.25 | The pool sends `AttemptStarted` and `AttemptOutcome`. The owner records the gauge and the outcome. An open attempt at terminal records `ech_error` once |
| F75 | The DNS discovery claims were stale after the project guidance changed | **Corrected in revision 7** | Sections 4.2, 6.1; matrix T5.38, T12.22 | macOS uses an unambiguous scoped `scutil` block and rejects a VPN, split-DNS, mDNS, loopback, or link-local resolver. Linux `system_dns_for_interface` fails closed and needs an explicit `--dns-servers` list, bounded to 8, validated, deduplicated |
| F76 | A structural change could regress a protocol invariant without a check | **Corrected in revision 7** | Section 10 item 34; matrix T15 | No SOCKS, pairing, source device, ICMP echo, key schedule, TTL, route, IPv6 default, or one-outer-per-flow change. The adapter preface is local loopback framing. T15 checks it |
| F77 | New numbers were stated as facts rather than hypotheses | **Corrected in revision 7** | Section 6.8; U55; matrix section 12.3 | H1 to H12 name the measurement that closes each. The cap, pool size, quiet window, and barrier deadline are proposed until measured |
| F78 | Revision labels and cross-references were stale | **Corrected in revision 7** | Header, Appendix D, Appendix H; matrix header; trace header | The three files say revision 7 and cite the current section and test IDs |
| F79 | B1: one word, "generation", named the session counter, the cache counter, and the runtime snapshot; the retry config and cache publication had no single writer | **Corrected in revision 8; reopened by the revision 8 review and corrected in revision 9 (F87 to F95)** | Sections 5.3, 6.2, 6.4.7; decision 33; U59; matrix T5.39, T5.40, T7.35 | `session_generation`, `config_generation`, and `runtime.snapshot_seq` are separate. A retry is a second attempt of the same job, authorized by the owning shard. `commit_config`, `commit_retry_config`, and `mark_rejected` are compare-and-set commits; the pool never writes the cache; a stale rejection cannot evict a newer config |
| F80 | B2: the connection was owned by the pool and by the session at once, and a slot could be freed while the pool still held a socket | **Corrected in revision 8** | Sections 6.4.2, 6.4.5, 6.4.6, 6.4.10; decisions 30 and 34; matrix T5.41, T5.42, T6.22 | A move-only connection lease and a mandatory handback. The slot frees only after the handback for the attempt that held it. `JoinPool` drains never-started attempts. A late handback cannot free a newer slot |
| F81 | B3: the adapter had no shard-to-adapter terminal path, and "admission channel full" could drop an accepted frame | **Corrected in revision 8** | Sections 4.8, 6.4.9, 6.6, 7.2; decisions 17, 35; U59; matrix T5.43, T5.44, T8.24 | Four frame credits per authenticated connection, 128 total. One reserved answer or close disposition per accepted query. A failed query closes the inner connection immediately. The ingress cannot fill when credits are respected |
| F82 | B4: waiters were per-shard while the cap was global, so no cross-shard FIFO existed and a grant could be lost | **Corrected in revision 8; reopened by the revision 8 review and corrected in revision 9 (F87 to F95)** | Sections 6.4.3, 6.4.3.1, 7.2.2; decision 36; matrix T5.45, T5.46, T7.34, T8.25 | One global `DohWaitQueue`, one direct grant that keeps the slot counted, one global deadline reaper, and exactly one recorded outcome per waiter |
| F83 | B5: the barrier was not placed in the real `Relay::stop` order, `Drop` cannot report, and the total stop budget was unknown | **Corrected in revision 8; reopened by the revision 8 review and corrected in revision 9 (F87 to F95)** | Sections 6.4.8, 6.7, 6.8 H6 and H13; decisions 30 and 37; U58; matrix T6.22 to T6.24 | Verified that `Relay::stop` clears input, sets `running = false`, and joins without a timeout, and that `Drop` calls it. The DoH barrier starts before those steps and before the shard join. A Drop-only stop is `drop_only` and inexact. A stuck thread is detached and reported. The total stop time is measured, not assumed |
| F84 | B6: runtime coverage was placed with counters, but capability lives in status and counters live in diagnostics; missing-key rules contradicted each other | **Corrected in revision 8; reopened by the revision 8 review and corrected in revision 9 (F87 to F95)** | Sections 2.2, 2.4, 2.5, 2.5.1, 2.5.2, 7.2.3, 7.3; decision 38; matrix T7.36, T13.10, T13.11 | Capability and runtime are in status; counters and `ledger { exact, phase, snapshot_seq }` are in diagnostics. Cross-endpoint coherence is not claimed. Missing keys are hidden, never `unverified`; missing counters are not zero; missing `ledger.exact` is not true |
| F85 | B7: the forwarder substitutes a third-party resolver, a resolver substitution that `AGENTS.md` invariant 4 addresses, and no decision or amendment was recorded | **Corrected in revision 8; reopened by the revision 8 review and corrected in revision 9 (F87 to F95)** | Sections 4.1.1, 4.1.2, 11.1 U57, 11.2; decision 39; matrix T12.24, T16.10 | A product-owner decision and an explicit amendment to `AGENTS.md` invariant 4 are required before any DoH code; if the plan is read to require the network resolver, its scope text or invariant 4 needs the same amendment. No built-in, automatic, or fallback public resolver. The design does not assert scope approval or invariant compatibility |
| F86 | Other contradictions: the plan revision status was stale, the trace said the 2026-11-02 record names macOS, the adapter preface length was inconsistent, and missing keys were both "hidden" and "unverified" | **Corrected in revision 8** | Header, sections 4.2, 6.6, 7.1, 11.2, 11.3, 11.3.1, 12; matrix sections 13 and 17; trace F3 and F28 | The plan's revision note is a claim to verify, not approval. The record names no OS and does not show the DNS case. The preface is a fixed 32 bytes. Missing keys are hidden, with `modes.off` as the only runtime-mode exception |
| F87 | R9-B1: `session_generation` rose at connection install and retry authorization, so every successful retry and every queued job after the first commit failed with `generation_mismatch`, and the adapter could drop a committed answer as "not current" | **Corrected in revision 9** | Header R9-B1; sections 4.8, 6.2, 6.4.5, 6.4.6, 6.4.7, 6.4.10, 6.6, 7.2.2, 7.2.3; decisions 29, 30, 35; matrix T5.33, T5.39, T5.48, T7.35, G28 | `session_generation` is a session incarnation number, allocated once and never changed. A retry is `attempt_id` 2. `generation_mismatch` is removed. The adapter applies dispositions in `request_id` order; an unwritten committed answer counts once in `doh_adapter_errors` |
| F88 | R9-B2: revocation, `cancel_waiter`, and `admit_granted` could each settle the same waiter; `Draining` ignored outstanding grants; the release step ignored `wait_deadline` | **Corrected in revision 9** | Section 6.4.3.1, 6.4.8, 6.4.9; decision 38; matrix T5.46, T5.51, T5.52, T7.34, T16.04, G29 | One settlement transition, `settle_waiter`, removes the record and returns a granted slot in one critical section. A second call and a late `admit_granted` are `Stale`. `Stopping` settles queued waiters and grants. The release step grants only a waiter with both deadlines remaining |
| F89 | R9-B3: the tunnel worker runs `relay.stop()` before `routes.remove()`, so the DoH barrier lengthened the dead-route window; `Relay::stop` returns `()` and the fault slot could only report a route failure | **Corrected in revision 9; open measurement** | Sections 6.4.8, 6.7, 6.8 H15; decisions 32, 41; U61; matrix T6.18, T6.22, T6.25, T6.26, T6.27, T11.4j, G4, G30 | In a DoH run: nonblocking `begin_stop`, then routes and address removal, then the drain. `RelayStopReport` and a `doh_stop_incomplete` fault field. An incomplete DoH stop never sets `cleanup_blocked`. A DoH-profile start is refused while a detached thread lives. H15 must be measured per platform |
| F90 | R9-B4: the B7 analysis quoted an uncommitted invariant sentence as policy and said no build ships a built-in public resolver, while source device proxy mode redirects DNS to `1.1.1.1:53` and the docs suggest `1.1.1.1` and `8.8.8.8` | **Corrected in revision 9; open owner decision** | Header R9-B4 and gate item 3; sections 4.1.1, 4.1.2; decision 36; U57, U64; section 11.2; matrix T12.24, T16.10, G27 | Section 4.1.2 states the committed and uncommitted invariant texts, the existing redirect, and the explicit-server options. The no-built-in-endpoint rule is limited to the DoH profile. Owner questions Q1 to Q5 are open. The decision and amendment are still required. No invariant is changed |
| F91 | R9-M5: `snapshot_seq` had three definitions and `ledger.snapshot_seq` had no owner | **Corrected in revision 9** | Sections 2.2, 2.5.2, 6.4.2, 6.4.7, 7.2.3; decision 35; matrix T7.35, T13.11 | One per-run `ledger_seq`, written under the ledger lock on every mutation, never on a read. `runtime.snapshot_seq` and `ledger.snapshot_seq` report values of it |
| F92 | R9-M6: `platformInfo()` falls back to the probe's one-time copy of `status.platform`, so a runtime `active` state could outlive the run | **Corrected in revision 9** | Sections 2.5.1, 2.5.2; decision 39; matrix T7.36, T7.37, T16.09 | `runtime` is read only from the latest successful status response. The probe copy carries no `runtime` object. A failed poll hides the coverage row |
| F93 | R9-M7: a `Close` for one TCP:53 query closed the connection and turned an earlier in-flight query into `doh_cancelled` | **Corrected in revision 9; open owner option** | Sections 4.8, 6.4.5, 6.4.9, 6.6; decision 29; U63; matrix T5.47, T16.13, G31 | Ordered application and a graceful close: stop reading, apply earlier and already-admitted later dispositions, then FIN. Each query keeps its own cause. Local SERVFAIL is an owner option, not part of the design |
| F94 | R9-M8: the retry row said `Ready` while section 6.4.10 said `BetweenAttempts`; a cancelled config fetch sent no wake and elected no new fetcher | **Corrected in revision 9** | Sections 6.4.6, 6.4.7, 6.4.9; decision 40; matrix T5.49, T5.50, T16.14, G31 | Three retry rows: `BetweenAttempts`, `Attempting` with `attempt_id` 2, `Ready`. Every exit from `Fetching` wakes every shard. A cancelled fetch elects at most one new fetcher; a failed fetch sets `retry_after` |
| F95 | The review's product decisions and host and device gates | **Open owner decision; open measurement** | Sections 4.1.2, 6.7, 6.8, 11.1 U62 to U64, 11.2, 12; matrix sections 12 and 17 | Open: DoH scope acceptance; Q1 to Q5 and the amendment; tunnel up or down after a DoH-only stop, which touches invariant 13 (U62). Open: H1 to H15, live hotspot coverage per platform, real stuck-syscall stop timing, a Windows host, a real Linux desktop for T13.10. None of the matrix rows exist or have run |

## 2. Finding detail

### F1 and F2: the requirement and the DoH-only error

Revision 1 said that `hide` encrypts DNS and uses ECH only on the engine's DoH
connection. That is not the user's requirement. Revision 4 keeps the revision 2
answer:

- `hide` needs real ECH on application connections and DoH.
- DoH is necessary but not sufficient. DoH alone cannot satisfy `hide`.
- The engine's DoH ECH is real but covers one static resolver name.
- A build with DoH alone reports `encrypted_dns = unverified` and
  `hide = unsupported`.
- A build with DoH plus engine ECH reports `resolver_ech = unverified` and
  still `hide = unsupported`. `ech` stays `unsupported` because no field
  carries resolver scope and no application ECH path exists.

The old acceptance criterion "`hide` succeeds on a Cloudflare ECH origin" is
not enough. It tests the engine's connection, not an application's connection.
The revised criteria require an application ECH path and a wire test for the
flows it claims.

Residual: U1. There is no application ECH path today. A transparent one is
impossible. A product-owned one is a product decision.

### F3, F4, and F28: gateway and link-local DNS bypasses

The tunnel does not capture IPv4 DNS to the hotspot gateway on macOS or
Windows. The hotspot's connected-subnet route is more specific than the two
`/1` routes and wins. The start path adds no host route for the gateway
(`rust/src/platform.rs`, `rust/src/windows_native_routes.rs`). The repo's live
record says the same: `PHONE_PROXY.md` states that DNS addressed to the hotspot
gateway can use its existing local route, and that in the 2026-11-02 live test
"the hotspot gateway route bypassed the tunnel". The record names no operating
system and does not show the DNS case, so it supports the route-shape inference,
not a live DNS result. Windows is the same route shape, but no live record names
Windows.

Linux is different in principle and likely the same in practice on a default
desktop. Rule 17001 sends every output packet that is not bound to the physical
interface to table 700, and table 700 holds the `/1` routes. There is no
`suppress_prefixlength`. Rule 17000 sends a socket bound to the physical
interface to table main. A gateway query enters the tunnel only if the resolver
socket is not bound to the physical interface. A default `systemd-resolved`
per-link socket likely takes rule 17000 and table main. That is a hypothesis,
not a verified tree fact.

The tunnel also does not capture:

- IPv6 link-local `fe80::/10`;
- IPv6 ULA `fc00::/7`;
- multicast `ff00::/8`;
- NAT64 `64:ff9b::/96`;
- any other more-specific route on another interface;
- a macOS scoped resolver or `mDNSResponder` query bound to the physical link;
- a Windows NRPT rule, per-interface DNS, or smart multi-homed query;
- an application or OS DoH/DoT query;
- a cached answer.

The revised note has a split bypass table and requires the UI to say "tunneled
DNS queries". It does not claim universal DNS privacy and does not claim
gateway coverage on macOS or Windows.

Residual: U4, U5, U6, U28. A read-only detector can report a category. It
cannot prove which path an application used. No detector is implemented in WS1.
Revision 3 said the gateway query enters under `/1`; that was wrong and is
withdrawn. Revision 6 removes "conditional" for Linux and removes the false
"live DNS evidence" wording. Gateway DNS on macOS and Windows is a
route-specificity inference. The record names no OS and does not show the DNS
case.

### F5: resolver override and cleanup

The revised note decides against a host resolver override in WS1. The reasons
are host-global state, crash risk, other networks, privilege, captive portals,
and the no-persistent-proxy rule. It still records the safe design if the owner
asks later: per-interface scope, a write-ahead journal, restore on start if
stale, restore on stop and uninstall, a watchdog, and crash tests.

Residual: U7. The section is a requirement list, not an implementation.

### F6: actual SOCKS CONNECT DNS path and invariant numbers

The revision 1 text blurred the tun path and the SOCKS5 path. Revision 4 keeps
the separation:

- Tun plus `--phone`: numeric ATYP only; UDP:53 redirected to `1.1.1.1:53`;
  TCP:53 plaintext today.
- Direct tun: numeric; DNS to the original destination or `--dns-upstream`,
  IPv4 only.
- Direct SOCKS5: ATYP 1, 3, and 4 are accepted. ATYP 3 is resolved by
  `TinyResolver` over a normalized plaintext UDP socket pinned to the physical
  interface; that is the target-side local-resolution leak. ATYP 1 and 4 mean
  the client resolved locally, a separate leak. The plan says SOCKS5 mode
  requires `socks5h` or remote DNS; the code accepts ATYP 1 and 4, so that
  requirement is not enforced. This is a pre-existing gap, not fixed here.
- Phone CLI adapter: domains preserved for diagnostics, not the tun path.

The note lists the exact constants and their source locations. It corrects the
plan's invariant 4 wording. It states one flow to one egress socket, with the
loopback adapter as a local socket, not an egress.

Residual: U9. The `Setup` refactor is not done. The corrected invariant text
still lives only in this note; the plan is out of scope for this task.

### F7: GREASE and the false ECH counter

Revision 1 proposed a passive ClientHello parser that counted extension
`0xfe0d`. RFC 9849 section 6.2 defines GREASE ECH with the same extension and a
random payload. A passive parser cannot tell a real offer from GREASE, and it
cannot see acceptance. The revised note removes the application ECH counter
from product status. It keeps `ech_*` for engine-originated TLS only. If a
research count is ever wanted, it must be named
`client_hello_ech_extension_seen_unknown` and kept out of status.

Revision 4 also states the GREASE handshake rule: it counts in `ech_grease` and
never in `ech_attempts`.

Residual: U20. Do not add the counter during WS0 schema work.

### F8: per-query socket cost

The revised note states the cost: one TCP and TLS 1.3 handshake per inner DNS
flow, plus one SOCKS CONNECT RTT in proxy mode; reuse within the flow; no
resumption; no sharing to save fds. It proposes a 32-connection cache, a
4-thread pool, a 64-job queue, and a 5-second deadline. It requires a hotspot
measurement before fixing the numbers.

Residual: U10. No measurement exists. A loopback number is not a carrier
number.

### F9: TCP:53, DNSSEC, DoT, DoQ, application DoH, caches

- TCP:53 is covered by the adapter or the virtual outer. The note requires both
  to be considered; the adapter is the first implementation with access
  control.
- DNSSEC records and the AD bit pass through. The engine is not a validator and
  does not claim to be.
- DoT and DoQ bypass the forwarder. The note allows a "port 853" count, not a
  "DoT" count.
- Application DoH on 443 is indistinguishable. Do not count it.
- OS DoH/DoT is outside the policy. Report no capability and do not claim
  coverage.
- Preexisting caches make the mode non-retroactive. Do not auto-flush.

Residual: U8, U16, U17, U18.

### F10: names in failure records

The existing `failures.rs` map remembers A and AAAA names. Revision 1 did not
address it. Revision 4 keeps the revision 2 rules and adds the constructor,
the `phase` argument, the adapter preface, and the direct-mode path from F23:

- DoH never calls `remember_dns_response`.
- DoH never parses a forwarded QNAME for a name hint.
- DoH never attaches the endpoint name, the QNAME, or the ECH config to a
  failure record.
- Do not reuse `FailureEvent::dns`, which always records `1.1.1.1:53`.
- Add `FailureEvent::doh_query`.
- Add `record_doh_failure`, because `record_dns_failure` returns early in
  direct mode.
- Clear the map when a DoH mode starts, so old plaintext names do not appear.
- If the owner wants no addresses either, record only a counter.

Residual: U19, U27. The implementation and the output test are missing.

### F11: nonblocking bounded concurrency

Each relay shard is a poll loop (`rust/src/relay.rs`), and 1 to 8 shards run. A blocking TLS handshake
in that loop would stall every flow. Revision 4 keeps the bounded pool:

- at most 4 threads;
- a 64-job queue;
- one in-flight query per flow;
- a bounded completion channel and a wake signal;
- a 200 ms cancellation slice;
- at most 64 completions drained per loop;
- no `getaddrinfo`, no shell, no blocking trust call.

Residual: U9, U10. The pool and the completion path are not implemented.

### F12: loopback adapter access control

Revision 1 had a loopback listener with no access control. Revision 4 keeps the
revision 2 controls and fixes the flood case:

- binds `127.0.0.1:0` only;
- requires a per-start 128-bit cookie before any frame;
- after the cookie, a fixed 32-byte preface carries the inner numeric
  destination, port, shard index, and connection ID. The destination is for the
  failure record only;
- caps authenticated connections at 32 and unauthenticated at 8;
- never evicts an authenticated or unauthenticated connection; a full cap
  closes the new connection;
- bounds frames to 12..65535 bytes;
- has a 1-second cookie deadline and a 30-second idle bound;
- never recurses;
- never logs the port;
- closes on adapter failure and does not fall back to plaintext.

The threat model is local code execution. A local process can cause a bounded
denial of service, including denial of a new inner TCP:53 flow, but cannot
resolve through the adapter without the cookie and cannot evict the relay or an
authenticated flow. T8.16 records the outcome rather than requiring service. If
a future review rejects the local surface, the fallback is a virtual outer
stream.

Residual: U8.

### F13: HTTP parsing

Revision 4 keeps the revision 2 bounds: the status line, headers, body, chunks,
trailers, content type, content encoding, redirects, 1xx, and extra bytes. It
uses one absolute deadline and no per-read extension. It forbids pipelining and
HTTP/2. It requires ALPN `http/1.1`. The test matrix has a parser corpus and a
deterministic fuzz loop.

Residual: The parser and tests are not written.

### F14: retries

Revision 4 keeps the revision 2 rule and makes the plan conflict explicit:

- Exactly one retry after an authenticated ECH rejection.
- No retry on a timeout, reset, 5xx, parse error, certificate error, or
  SERVFAIL.
- No retry config in response to a connection that was itself a retry.
- No downgrade on a timeout or reset.
- The plan's "fresh non-ECH flow after a detectable failure" text is wrong.

The note also corrects the WS0 counter comment. The current
`rust/src/diagnostics.rs` says `ech_fallback` is "after a rejection or a
stall". A stall must not trigger a fallback.

Residual: U20, U25. The comment and the counter semantics belong to WS0. The
plan text belongs to WS6.

### F15: trusted bootstrap

Revision 4 keeps the revision 2 bootstrap:

- configured name, unicast IP, port, and path;
- `webpki-roots` on the egress path and no OS trust call;
- no redirects and no URI discovered outside the configuration;
- the first DoH connection is non-ECH by necessity; it is the bootstrap;
- ECH config only from the endpoint's own HTTPS RR over that authenticated
  connection, for the exact owner name, with no CNAME alias;
- reject a bad public name, an unsupported KEM, an empty list, an oversized
  list, a duplicate key, and an unknown mandatory extension.

Residual: U15. The rustls ECH API shape must be re-verified.

### F16: normalized sockets

Every egress DoH socket uses `normalization::tcp_connect_cancellable` in direct
mode, or `phone_tcp_start` plus `Setup::phone` in proxy mode. The loopback
adapter connection uses `normalization::tcp_start` with `iface = None`; it is
the one documented unpinned local socket and cannot leave the machine. The TTL
audit must end at `(n, 0)`. No raw egress socket and no new socket helper.

Residual: The implementation and the audit test are missing.

### F17: privacy-safe counters

Revision 4 keeps counters as integers. It forbids names, addresses,
certificates, ECH configs, and hosts. It separates engine ECH from application
ECH and from DoH. It adds plaintext fallback and TCP:53 counters because the UI
needs proof. It removes the false application ECH count. F22 adds the
non-overlapping outcome ledger.

Residual: U20. WS0 owns the schema.

### F18: cross-target toolchain

Revision 4 keeps the split `doh` and `ech` features. The base crate stays pure
Rust. The cross-target checks with features off keep working. Native jobs enable
supported features. A target that cannot build `ech` reports `ech =
unsupported` and still builds `doh`. No `continue-on-error`, no stub.

Residual: U14. The provider builds are unproven.

### F19: the status could be read as support

Revision 4 keeps the header, sections 2.2, 7.3, 12, and Appendix D. It adds the
`unverified` rule for `encrypted_dns`. `hide` stays `unsupported`.

Residual: U1, U28.

### F20: universal application ECH

Revision 6 closes the client boundary under the current constraints. A
transparent `hide` is impossible. The plan already states the default outcome:
if no acceptable boundary exists, `hide` is not built and no claim is made.
That is the outcome here, so no owner decision is needed to reach it. A
product-owned client is a separate optional future proposal, not a blocking
decision, and it must not terminate TLS or add an external relay. The DoH
forwarder is a separate product owner scope decision; closing `hide` does not
approve it.

Residual: U1. `hide` stays `unsupported`.

### F21 and F27: the plan fallback conflict

This was the first blocker in the revision 2 review. Revision 3's answer still
contradicted itself, which is revision 4 blocker B1.

- The plan's blockable bullet requires "a fresh non-ECH flow after a detectable
  failure".
- Its acceptance gate says `hide` on a network that blocks the ECH outer name
  "fails over to a fresh non-ECH flow within the connect deadline".
- Revision 3 forbade a retry on a timeout, then offered an "opt-in, labeled,
  per-profile non-ECH retry". On a blocking network, a timeout or reset is the
  only trigger, so that opt-in could only run as a timeout-triggered downgrade.
- A blocked outer name is exactly a timeout, a reset, or a failed public-name
  check. The plan's gate therefore requires the downgrade that this design
  forbids. An active attacker could force it.

Revision 4 removes the contradiction:

- A profile is either ECH or non-ECH before it connects. It never changes
  because of a failure.
- A person who wants a non-ECH flow selects the non-ECH profile before the next
  connection. That is a labeled state, not a retry.
- The resolver connection may retry once only after an authenticated ECH
  rejection. It never retries on a timeout, reset, certificate error, 5xx,
  parse error, or SERVFAIL.
- Plaintext DNS is a profile state chosen before start, not a per-query
  reaction.

Section 11.3 P1 and P2 quote the plan passages and give the replacement text.
The design does not change.

Residual: U25. The current plan contains the corrected P1 and P2 rule. This
task does not edit the plan; T12.01 checks that the text stays in place.

### F22, F30, and F33: counter semantics and the two ledgers

This was the second blocker in the revision 2 review. Revision 3's ledger still
did not add up, which is revision 4 must-fix M2.

- `rust/src/diagnostics.rs` defines `doh_lookups` as "HTTPS or SVCB lookups
  over DoH". `doh_ok` and `doh_failed` follow that meaning.
- Revision 2 said "Existing counters remain the contract" and then redefined
  `doh_lookups` as "Inner DNS queries sent to DoH". That was a silent meaning
  change.
- Revision 3 said every handshake has exactly one outcome. The non-ECH
  bootstrap has none, and GREASE is off by default. A retry handshake could
  overlap `ech_retry_exhausted`, `ech_error`, and
  `ech_rejection_unauthenticated`.
- The DoH causes did not cover a TLS error, a certificate error, a reset, a
  source device capacity error, or a pool panic. A queue-full query was counted
  in `doh_queries` but the cause list did not make that explicit.

Revision 4 fixes it with two exact identities:

```
ech_attempts = ech_ok + ech_rejected + ech_rejection_unauthenticated
             + ech_error + ech_retry_exhausted

doh_queries = doh_query_ok + doh_query_failed
doh_query_failed = doh_timeout + doh_http_error + doh_parse_error
                 + doh_response_mismatch + doh_queue_full + doh_other_error
```

Rules that make them exact:

- A retry attempt gets one outcome by precedence: accepted, authenticated
  rejection, unauthenticated rejection, then transport failure.
- `ech_grease` and `ech_fallback` are separate type counts, not outcomes.
- A non-ECH bootstrap moves no `ech_*` counter. Its result is in `doh_*`.
- A queue-full or connection-cap rejection is still a `doh_queries` attempt and
  a `doh_query_failed` with the `doh_queue_full` cause.
- `doh_response_mismatch` names the response that is dropped for a wrong ID or
  QR=0.
- `doh_other_error` takes every remaining DoH failure, so the cause sum is
  exact by construction.
- The plaintext-profile counter counts the plaintext profile, not a DoH
  failure, so it cannot double count. Revision 5 names it
  `dns_plaintext_profile_queries`.
- `doh_tcp53_queries` and `doh_tcp53_failed` are subsets, not addends.

Residual: U20. WS0 must implement the schema, record the `doh_lookups`
narrowing, and remove "or a stall" from the `ech_fallback` comment. T7.15,
T7.18, T7.20, T7.21, and T4.20 check both identities.

### F23: failure constructor and direct-mode recording

This is the first must-fix item in the revision 2 review.

- Section 7.1 said to reuse the existing `dns` protocol and the inner
  destination address, with no new field.
- `FailureEvent::dns` always records `1.1.1.1:53` (`rust/src/failures.rs`).
- `Relay::record_dns_failure` returns early when `config.phone.is_none()`
  (`rust/src/relay.rs`). It records nothing in direct mode.

Reusing the existing path would report a DoH failure as a failed plaintext
lookup to `1.1.1.1:53`. In direct mode it would record nothing, so a
direct-mode failure-record test could not pass.

Revision 4 fixes it:

- Add `FailureEvent::doh_query(destination, port, reason, code, phase)`. It
  takes the same `Option<Phase>` argument as every existing constructor
  (`rust/src/failures.rs`). It uses `proto = dns`, the inner destination, and
  no name.
- Add `record_doh_failure` that works in both direct and proxy mode.
- Do not change `record_dns_failure`; the plaintext phone path keeps it.
- The TCP:53 adapter gets the inner destination from a fixed 32-byte preface
  after the cookie. Without it the adapter knows only the loopback address.
- Test T7.07 in proxy mode, T7.16 in direct mode, and T5.24 for the adapter
  destination.

Residual: U27. The constructor, the recorder, and the preface are not
implemented.

### F24: `encrypted_dns` support and the default resolver path

This is the second must-fix item in the revision 2 review.

- Revision 2's trace and matrix reported `encrypted_dns = supported` for any
  build with DoH.
- The plan says never to report support from a compile alone.
- The code defines `unverified` as "code path exists, but no live evidence".
- In the bypass table, the main path said "Yes" with nothing to do, while the
  macOS scoped-resolver and Linux `systemd-resolved` rows said "Not
  guaranteed".
- On Linux, rule 17000 is `oif <physical> lookup main`
  (`rust/src/platform_linux.rs`). A resolver socket bound to the physical link
  skips the tunnel. `systemd-resolved` per-link servers and macOS
  `mDNSResponder` may bind that way. This is a hypothesis until a live run.

Revision 4 fixes it:

- `encrypted_dns` is `unverified` in every build until a live run on that
  platform shows tunneled queries carried by DoH. A compile and a hermetic test
  are not support.
- The gateway rows are split. Revision 6 treats gateway DNS on macOS and
  Windows as a bypass by route-specificity inference, not live DNS evidence,
  because the record names no OS and does not show the DNS case. Linux is a
  likely bypass on a default link-bound resolver, not "conditional".
- `ech` stays `unsupported` in every build. Revision 3 still allowed
  `ech = supported` from a build with an HPKE provider, which is revision 4
  must-fix M1. `resolver_ech` is the separate key and stays `unverified`.
- Section 2.4 defines the capability contract: four string values, no free
  text, and a missing key is not support.
- `hide` stays `unsupported` in every case.

Residual: U28. No live run exists.

### F25: plan DNS command and status words

This is a lower-priority item in the revision 2 review.

- Two plan passages, in a section marked "verified by inspection", say DNS
  travels over SOCKS command `0x80`. The code uses command 1 with DNS-over-TCP
  framing (`rust/src/relay.rs`). Command `0x80` is for other UDP.
- The plan uses `yes`, `no`, and `unknown`. The code and this note use
  `supported`, `unsupported`, `unavailable`, and `unverified`.

Revision 5 checks the current plan. P4, P5, P6, and P8 are present: both DNS
passages use command 1, the false "already resolved" claim is gone, the three
capability locations use the four state names, and the false "report no ECH or
SNI capability" sentence is gone. This task does not edit the plan.

Residual: U26. The exact capability key set still needs P9.

### F26: matrix adversarial coverage and ordering

This is the lower-priority test item in the revision 2 review.

Revision 4 fixes:

- T5.08 is labeled a synthetic injection. A real link-local packet does not
  enter the tunnel.
- T4.14 checks that no ECH-disabled retry follows a failed certificate check.
- T4.06 says whether a retry follows an unauthenticated rejection. T4.09 is
  the authenticated rejection with no retry config.
- T8.14 and T8.15 move after T8.13.
- T8.16 adds a continuous adapter flood test. It no longer requires the relay
  flow to be served: the adapter never evicts, and the threat model accepts a
  bounded local denial of service.
- T4.20, T7.15, T7.17, T7.18, T7.20, T7.21, and T7.23 check both counter
  ledgers and the in-flight gauge.
- T9.17 and T9.18 check that the future owned client fails closed on a timeout
  or reset and that a non-ECH profile is chosen before connecting, never after
  a failure.
- T10.14, T10.15, and T10.16 report `encrypted_dns = unverified`,
  `resolver_ech = unverified`, and `ech = unsupported`.
- T12 adds the P1 to P15 documentation checks.

Residual: None of these tests is written. T8.16 is a plan only.

### F27: B1, the fallback contradiction

Covered in section 2 under F21 and F27. The resolved rule is in architecture
section 5.3.2. A non-ECH flow is a profile state chosen before connecting. It
is not a retry, it never follows a failure, and no opt-in changes that. The
plan handoff is P1 and P2.

### F28: B2, the gateway DNS route claim

Covered in section 2 under F3, F4, and F28. Gateway DNS on macOS and Windows is
a bypass by route-specificity inference, not live DNS evidence. The record
names no OS and does not show the DNS case. Windows has no live record. Linux
is a likely bypass on a default link-bound resolver. Section 4.2, the split
bypass table, and T5.25 carry the correction. No host route is proposed.

### F29: M1, `ech = supported` from a build

- Revision 3 let `ech` report `supported` in a build with the DoH path and an
  HPKE provider, after a hermetic test. That conflicts with `CAP_UNVERIFIED`,
  the plan's "never report `yes` from a compile alone", and the matrix's own
  statement that rustls has no ECH server.
- The detail text "engine resolver connection only" has no field to live in.
  Capability values are bare strings (`rust/src/diagnostics.rs`).
- Revision 4 keeps `ech` at `unsupported` and adds `resolver_ech`, reported
  `unverified` in an `ech` build. Section 2.4 forbids free-text values and
  makes a missing key not support.

Residual: U20, U28. WS0 owns the schema.

### F30: M2, the counter ledger and failure causes

The two identities are in architecture section 7.2.1 and 7.2.2. Revision 6
replaces the revision 5 quiescence-only rule. Revision 7 supersedes this
paragraph with the sharded model; the points below are retained for audit:

- `doh_in_flight`, `doh_config_in_flight`, and `ech_attempts_in_flight` are
  gauges. Every accepted job increments the matching input counter and gauge,
  then records one outcome and decrements the gauge. A queue or connection-cap
  rejection records `doh_queries` and `doh_queue_full` without entering the
  gauge.
- Revision 6 answer, superseded: the relay worker was described as the single
  accounting owner. Revision 7 uses one admitting shard per job and one global
  ledger; the pool and the TCP:53 adapter still write nothing. A late
  completion is discarded by job ID and generation.
- The DoH identity is exact in a coherent snapshot and after stop and join. A
  live snapshot can show accepted work in the in-flight gauge, but it is part
  of the identity, not a lost outcome.
- `doh_cancelled` is a seventh cause. Stop, inner-flow expiry, and caller
  cancellation use it. A queued TCP:53 query behind a failed connection uses
  `doh_other_error` with reason `flow_closed`. A pool panic uses
  `doh_other_error` with reason `pool_unavailable`. Revision 7 removes the
  revision 6 `completion_queue_full` reason and uses a reserved delivery slot
  plus `doh_adapter_errors` for a post-commit write failure.
- `doh_other_error` remains the catch-all, so the cause sum is exact.
- A completion is never dropped. Capacity is reserved at admission.

Residual: U20, U37, U41. T6.14, T7.15, T7.18, T7.20, T7.21, T7.23, and T7.27
check this.

### F31: M3, the WS6 handoff

Revision 3 named the plan by line number and omitted P3, P5, P7, P8, P9, and
P10. Revision 6 quotes or names each current passage in architecture section
11.3 and trace section 4, and separates applied, partly applied, and remaining
items. Revision 8 supersedes the "P7 is partly applied" status: the plan's
revision note says P7 and P9 to P15 are applied, subject to verification. P10
lists every boundary-open passage. P12 to P15 cover the stale code and counter
claim, the DNS transport claim, the Linux bypass, and reader-facing terms.

At the 2026-11-05 checkpoint the plan's own revision note says task
`85710a0e` applied P7 and P9 to P15. This trace verifies that as text, not as
approval: read the quoted passage before accepting an item. No implementation
starts before the text is verified, the product owner accepts the DoH scope and
the third-party resolver decision, the invariant amendment lands, and a new
independent review passes.

### F32: M4, the adapter flood

Revision 3 evicted the oldest unauthenticated connection. The relay's own
connection is unauthenticated until it sends the cookie, so a continuous flood
could evict it, and T8.16 required service that the threat model did not
promise. Revision 4 never evicts a connection. A full cap closes the new
connection. A flood can cause a bounded local denial of service, which the
threat model accepts. T8.16 records the outcome and does not require service.

### F33: the lower-priority items

- A failed ECH config fetch loses L2, not L1. It does not change the profile
  and does not produce plaintext. Section 5.2.
- `ech_*` can be nonzero while `mode = off`. WS0 must state that for `doh_*`
  and `ech_*`. Section 2.4 and 7.2.3.
- The TCP:53 failure record gets the inner destination from the fixed 32-byte
  preface, and `FailureEvent::doh_query` keeps the `phase` argument. Section
  6.6 and 7.1.
- `doh_lookups` narrows to the endpoint's own ECH-config lookup, and the
  narrowing is recorded. An inner QTYPE 65 query counts only in `doh_queries`.
  Section 7.2 and 7.2.3.
- `doh_tcp53_lookups` is renamed `doh_tcp53_queries`. Section 7.2.
- The connection cap evicts an idle connection first, then fails. Section 6.5
  and T8.02.
- The source device relay cap follows the iOS and Android open-file-derived
  limits, not a fixed 256. Section 6.5.
- `tcp_connect_cancellable` takes a `Duration` timeout, not a deadline.
  Section 6.3.

### F34: RFC references and the plan WS1 gate

- RFC 9848 and RFC 9849 numbers and section references were read from memory,
  offline. Revision 6 marks every citation unverified until a reviewer reads
  the text. U29 and T12.21 cover it.
- The plan body is claimed to have the P10 corrections. The plan's revision
  note says task `85710a0e` applied them. This trace verifies the text. The
  architecture resolves the boundary under the plan's own default: no
  transparent boundary exists, so `hide` is not built and stays unsupported.
  Encrypted DNS is a separate proposed scope with its own product owner
  acceptance and the third-party resolver decision. The owner makes no decision
  to close `hide`.
- No implementation starts before the P1 to P15 text is verified, the product
  owner accepts the DoH scope and the resolver decision, the invariant
  amendment lands, and a new independent review passes.

### F35 to F47: the revision 5 findings

Revision 6 superseded the revision 5 answers that used a quiescence-only
identity, a single global writer, an immediate `ech` alias, a default
plaintext counter, or a live gateway DNS claim. Revision 7 supersedes the
single-worker and fixed-cap parts of the revision 6 answer. The F66 to F78
details carry the current answer.

**F35, the scope gate.** The revision 4 header and decision 21 made the owner's
client decision a precondition for all code, including encrypted DNS, while P10
offered a split. Revision 5 makes the gate scope-specific. Application ECH is
closed as unsupported under the plan's default. The DoH forwarder has its own
product owner scope acceptance and review. No owner client-boundary decision
blocks closing `hide` or preparing the independent DoH scope; the owner's
separate scope acceptance is still required before code. See the header,
sections 1.3, 10 item 23, and 11.3 P10.

**F36, the unapproved DoH scope.** The tunnel-wide forwarder is a new product
scope: it captures inner UDP:53 and TCP:53, adds a loopback adapter and a
bounded pool, edits `relay.rs`, and trusts a third-party resolver. Revision 5
adds section 4.1.1 with the tradeoffs and a separate review gate. The forwarder
is not approved, not requested by this task, and not implemented. The handoff
records the scope acceptance as a new product choice.

**F37, the plaintext default.** Revision 4 said both "no plaintext by default"
and "DoH is off by default". Revision 5 says acceptance and G2 apply "with a
DoH setting active". Revision 6 goes further: the default `off` profile adds no
counter and no warning. The plaintext counter and UI are a separate acceptance.
See sections 2.6, 4.1, and 12, and matrix G2, T7.04, and T14.

**F38, in-flight accounting and single ownership.** Revision 4 counted queries
when work started and outcomes later, and let either the pool or the worker
record a result. Revision 5 added the `doh_in_flight` gauge but kept a
quiescence-only identity and a single-writer claim that the adapter broke.
Revision 6 gave every accepted job a job ID and one terminal owner, but its
single-worker ownership claim was wrong. Revision 7 makes the admitting shard
the owner, writes one global ledger, discards late completions by ID and
generation, reserves event and delivery capacity at admission, and uses a
coherent snapshot so the identity is exact in every read. Stop, inner-flow expiry, queued TCP:53, source capacity,
pool panic, and a full response queue have named terminal causes. See sections
6.4, 7.2, and 7.2.2, and T6.14, T7.23, and T7.27.

**F39, unavailable source slots.** Revision 4 capped DoH connections at "the
smaller of 32 and the source device's free relay slots." No protocol field
reports free slots. Revision 5 keeps the proposed 32 cap, treats a capacity
error as `doh_other_error` with reason `source_capacity`, and records a
free-slot query as a protocol change in U34. See section 6.5 and T5.22 and
T5.26.

**F40, capability semantics and runtime scope.** Revision 4 said the states mean
"exactly what `diagnostics.rs` defines", but the code says `supported` means the
mechanism exists, and the modes comment allows `supported` from a hermetic test.
Revision 6 defines the four states in section 2.4, keeps `modes.off` at its
existing mechanism meaning, requires live evidence for the privacy keys, makes
`supported` reachable after live build qualification, and keeps the value static
per build and platform. Static capability is separate from
`encrypted_dns_coverage`. The legacy `ech` keeps its meaning; the new keys carry
the new claims. Every consumer is mapped in section 2.5. See sections 2.2,
2.4, 2.5, 7.3, and 8, and T7.09, T7.13, T7.19, T7.22, T10.13 to T10.17, and
T13.

**F41, Linux gateway and default resolver.** Revision 4 called Linux
"conditional". Revision 6 says a default link-bound resolver is a likely
bypass. Gateway DNS on macOS and Windows is a route-specificity inference, not
live DNS evidence. The record names no OS and does not show the DNS case.
Windows has no live record. See sections 4.2, 4.3, U4, U5, and T5.25.

**F42, the gateway host-route reason.** Revision 4 rejected a host route because
it "would change the path of the pinned proxy socket." Interface pinning may not
work that way. Revision 5 records a host route as an open option in U33 with the
real risks: the pairing port 18090, the presence probe, captive portals, and
platform route behavior.

**F43, the live record's OS.** Revision 4 said the live record "confirms the
macOS case" without naming the platform. The record names no OS, and it reports
a gateway route bypass, not a DNS query. Revision 6 stops citing it as live DNS
evidence for any target.

**F44, the plaintext counter.** Revision 4's `doh_plaintext_fallbacks`
contradicted its own "not a fallback" definition. Revision 6 names the counter
`dns_plaintext_profile_queries` only after a separate telemetry and UI
acceptance. It is a profile state, never a reaction to a failure, and it is
absent or zero in the default `off` profile. See sections 2.3, 2.6, 7.2, 7.2.3,
T5.05, T7.04, and T14.

**F45, tethering detection.** Revision 4 marked it "Unchanged" without a
measurement. Revision 5 marks it not measured and names the new DoH ClientHello
and resolver IP. See section 5.5.

**F46, cached resolver config after a rejection.** Revision 4 did not say what
happens when an authenticated rejection has no supported retry config. Revision
5 says the one ECH-disabled retry runs and the rejected config is evicted. A
later connection fetches a fresh config. See section 5.3 and T4.22.

**F47, matrix order and numbering.** Revision 5 moves T7.19 and T7.20 after
T7.18, keeps T7.21 and T7.22 in order, and closes the numbering gap with T7.23.
The matrix also adds T4.22, T5.26, T5.27, T6.14, T7.23, T12.11 to T12.14, and
the updated gate text.

### F48 to F65: the revision 6 findings

**F48, the retry contradiction.** Revision 5's section 12 acceptance criterion
said "a rejected or unauthenticated ECH attempt produces no non-ECH attempt,"
while section 5.3, T4.09, G5, and P11 allowed one ECH-disabled resolver retry.
Revision 6 states one table: application flows never retry; the resolver
connection retries once after an authenticated rejection, with retry configs or
with ECH disabled when none are supported. A timeout, reset, certificate
failure, 5xx, parse error, or SERVFAIL never retries. Section 12, G5, T4.24,
T12.20, and P11 all use the table.

**F49, the adapter ownership.** Revision 5 said the relay worker was the single
writer of every DoH counter, but the TCP:53 adapter split frames and submitted
jobs itself. Revision 6 makes the adapter send an admission request to the
worker. The worker assigns the job ID, reserves the completion slot, submits
the job, consumes the outcome, writes the counter, and writes any failure
record. The adapter writes no DoH counter. Adapter transport failures are
`doh_adapter_errors`, not queries. See sections 4.8, 6.4, and 6.6.

**F50, job IDs and terminal outcomes.** A cancelled, timed-out, dropped, or
panic-failed job could have no ECH outcome, and a late completion could be
counted twice. Revision 6 gives every accepted job a job ID and one terminal
owner. A completion for a terminal or unknown ID is discarded. An ECH attempt
with no completion records `ech_error`. A config fetch with no completion
records `doh_failed`. Gauges make the identity exact. See sections 6.4, 7.2.1,
and 7.2.2.

**F51, instantaneous identities.** Revision 5 used separate atomics and said
the identity held only at quiescence. Revision 6 uses one coherent ledger
snapshot. Every admission, outcome, and gauge change is one small critical
section with no I/O. A reader clones one snapshot. The identities hold in every
snapshot, and the final snapshot after join is exact. A multiworker stress test
reads snapshots concurrently. See sections 6.4 and 7.2.2.

**F52, capability migration.** Revision 5 would have changed `ech` into an
application ECH alias and added new keys without mapping the existing
consumers. The GUI parses `ech` against four states, the Linux page has a
hard-coded ECH card, and the Windows report uses its own availability model and
yes/no text. Revision 6 keeps `ech` as the legacy build-mechanism flag, adds the
new keys, maps every consumer in section 2.5, separates static capability from
runtime coverage, keeps `off` as a runtime mode, and forbids a default payload
change. See sections 2.5, 2.6, and 7.3, and matrix T13 and T14.

**F53, the stale plan handoff.** Revision 5 said P7, P9, P10, and P11 remained.
The plan has since partly applied P7, and P10 still misses several
boundary-open passages. Revision 6 records P7 as partly applied, lists every
P10 passage, and adds P12 to P15 for the stale code and counter claim, the
"DNS is UDP" claim, the missing Linux bypass, and reader-facing terms. See
section 11.3 and T12.06, T12.09, T12.10, and T12.15 to T12.20.

**F54, idle eviction.** Revision 5 evicted the oldest idle connection when the
cap was full. That can break a live flow's one-socket mapping. Revision 6 makes
the cap hard, never evicts another flow's connection, and frees a slot only
when its own flow closes or idles out. The bounded ECH retry is the only
replacement. See section 6.5 and T8.02.

**F55, the 32 versus 64 cap.** The adapter accepted 64 authenticated
connections while the DoH connection cap was 32. Revision 6 sets both to 32 and
states that an adapter slot is not a reservation. See sections 6.4 and 6.6.

**F56, the deadline origin.** Revision 5 did not say whether the absolute
deadline started at admission or at pool-thread start. Revision 6 starts it at
queue admission. See sections 4.6 and 6.4.

**F57, worker panic.** Revision 5 covered a pool panic but not a relay-worker
panic. Revision 6 gives pool, adapter, and relay-worker panics separate
policies, and a worker panic does not publish a partial ledger as exact. See
section 6.7 and T6.15.

**F58, source setup cancellation.** Revision 5's blocking source driver did not
cover every `Setup` state. Revision 6 checks the stop flag and deadline in each
state and discards a late reply by job ID. See section 6.3.

**F59, silent completion drop.** Revision 5 dropped a completion when the
channel was full and then recorded a timeout. Revision 6 reserves a completion
slot and a job-table entry at admission, never drops a completion, and fails a
job explicitly when its response-data queue is full. See section 6.4 and T8.17.

**F60, additive Cargo features.** Revision 5 said not to enable `doh` and `ech`
together, but Cargo features are additive. Revision 6 makes `ech` imply `doh`,
allows both, selects one provider, and tests all combinations. See section 8
and T10.17.

**F61, false live gateway evidence.** Revision 5 called macOS gateway DNS a
certain bypass with live evidence. The record reports a gateway route bypass,
names no OS, and does not show the DNS case. Revision 6 treats gateway DNS on
macOS and Windows as a route-specificity inference and requires a DNS-specific
live run for any stronger claim. See sections 4.2 and 4.3, U4, U5, and T5.25.

**F62, RFC citations.** Revision 5's reading guide said a Standard claim came
from an RFC text read for that revision, while U29 said the citations were from
memory. Revision 6 marks every citation unverified until a reviewer reads it.
See section 0, U29, and T12.21.

**F63, direct-mode failure records.** Revision 5 added a direct-mode DoH
failure record as a fix. That is a new privacy surface: it adds a numeric
destination and a reason to "Recent failures" in a mode that has no such record.
Revision 6 makes counters the default and puts the record behind its own
privacy scope acceptance. See section 7.1 and T7.28.

**F64, default plaintext counter and UI.** Revision 5 counted the default
no-DoH profile and showed "DNS is not private" by default. That changes default
behavior. Revision 6 puts the counter and warning behind a separate telemetry
and UI acceptance. The default `off` payload and UI do not change. See sections
2.3, 2.6, and 7.3, and T14.

**F65, the lower-priority items.** T10.07 now names `resolver_ech` and the
legacy `ech` separately. The labels say revision 6. The trace is updated. The
IPv6 path row says the DoH attempt happens only when the endpoint is reachable
for that family and IPv6 is forwarded, and block mode drops the packet before
an attempt. The ECH test certificate is for the origin name, not
`public_name`, because the client authenticates the origin. See matrix T10.07,
T4 header, T4.23, and T5.09, and Appendix G.

### F66 to F78: the revision 7 blockers

This subsection records the revision 7 answer. Revision 8 supersedes its
delivery, generation, slot-ownership, waiter, and stop-order terms. F79 to F86
carry the current answer; keep this subsection for audit.

**F66, B1/M1, the sharded relay.** `Relay::start` accepts 1 to 8 workers and
gives each its own `sync_channel(QUEUE)` and wake pair. `shard(key, workers)`
routes an inner flow to exactly one worker. Revision 6 said "the relay worker"
was the single accounting owner and the single stop barrier. That is false for
every run with more than one worker: there is no single worker, no global
admission point, and no global stop barrier.

Revision 7 defines:

- one `DohSupervisor` owned by the `Relay` facade;
- one `DohShard` per relay worker, owned by that worker;
- one global `DohLedger` and `DohLimits` object under one lock;
- one shared pool and one shared adapter;
- admission by the shard that receives the packet or the adapter request;
- no job migration, and no shard-private counter.

The global bounds are reserved in the same critical section that records the
input counter and the gauge, so two shards cannot over-admit. The admission send
cannot block because the pool ingress capacity equals the global job bound and
the job already holds a reservation. The adapter addresses a shard by the index
in its local preface, so a TCP:53 frame also lands on the owning shard.

Residual: U48. Matrix T5.30, T5.31, and T7.27. The ledger lock cost is H5 and is
not measured.

**F67, B2/M2, commit before delivery.** Revision 6 sent the response bytes to
the adapter's response slot and the outcome to the worker. Those are two paths
with no order between them. A cancelled, timed-out, duplicate, or stale job
could still write bytes, and a write could arrive after the job was terminal.

Revision 7 makes the terminal decision a commit:

1. The pool sends `Completion { job_id, result }` to the owning shard. It never
   sends bytes to the adapter.
2. The shard validates the job, deadline, phase, and generation.
3. On success, one ledger update records `doh_query_ok` and marks the reserved
   delivery slot committed.
4. Only then does the shard release `DohDelivery { job_id, generation, bytes }`
   to the consumer.

For UDP, the shard writes the datagram. For TCP:53, the adapter flow writes the
frame and checks the job ID and generation. A committed answer whose inner write
then fails keeps `doh_query_ok` and increments `doh_adapter_errors`; the DoH
exchange and the inner transport are separate claims. `doh_query_ok` is defined
that way in WS0 (section 7.2.3).

Residual: U49. Matrix T5.32, T5.33, T7.29, T7.32.

**F68, B3/M3, object ownership and slot lifecycle.** Revision 6 named a job
owner but left the session, the connection, the config cache, and the ECH
attempt without an owner or a release rule. A late event could attach to a
reused session, a rejected config could stay, and two sessions could fetch the
same config.

Revision 7 adds:

- a session keyed by the shard, inner 4-tuple, and generation, with one owner
  and one named release path;
- a reserved slot released exactly once, guarded by the generation;
- a connection owned by the executing pool job while it runs, with the session
  deciding replacement only after the job returns;
- a single-flight config cache with `Absent`, `Fetching`, `Fresh`, and
  `Rejected` states, published only by the fetch job's commit;
- an `AttemptStarted`/`AttemptOutcome` pair per handshake, with `ech_error` for
  an attempt that is open at terminal.

Residual: U50. Matrix T5.34, T5.35, T5.36, T7.30.

**F69, B4/M4, capacity under churn.** The revision 6 cap was 32 sessions and a
30 s idle window, but a direct-mode UDP relay entry lives up to `UDP_IDLE`
(120 s). A stub resolver that opens a new source port per query would hold
far more than 32 sessions at a trivial query rate, so the cap was a guaranteed
failure under common churn.

Revision 7 separates the DoH session lifetime from the relay flow lifetime:

- 250 ms quiet close for UDP, with a 2 s hard idle;
- a bounded FIFO slot wait (250 ms or a quarter of the remaining deadline);
- a measured cap, proposed 64 with a floor of 32;
- a declared envelope: `P / h` queries per second and about `qps × (h + q)`
  peak sessions, with `P = 8` and `h ≈ 0.3 s` as a hypothesis;
- an explicit `doh_queue_full` above the envelope, never a silent drop or a
  plaintext fallback;
- cross-source-port connection sharing recorded as U56, not implemented.

Residual: U51, U55, U56. Matrix T8.19 to T8.23. The rate, peak, and cap are H1 to
H4 and are not measured.

**F70, B5/M5, the stop barrier.** Revision 6 said "stop sets the flag and wakes
the relay worker. The worker records the terminal outcomes, then stops
admission." The order is wrong: it records outcomes before it closes intake, so
an admission can slip in during the drain. It is also single-worker.

Revision 7 puts the phase in the ledger state and changes the order:

- `Stopping`: close intake, reject queued adapter requests, wake every shard;
- `Draining`: mark every live job terminal, close attempts and sessions, ack;
- `JoinPool`, `JoinAdapter`: bounded joins, discard late completions;
- `Sealed`: verify every gauge and count is 0 and publish an exact snapshot;
- `Incomplete`: report a failed stop with the phase that timed out.

An admission either reserves before the transition (and is drained) or observes
`Stopping` (and is rejected with `doh_cancelled`). There is no third outcome.
The barrier is idempotent and `Drop` runs it.

Residual: U52. Matrix T6.16 to T6.20.

**F71, B6, runtime coverage and consumer compatibility.** Revision 6 put
`encrypted_dns_coverage` next to the capability values and told every consumer
to "parse all four states". That is wrong in three ways:

- `app_ech` has three values, and `app_dependent` is not a support state. A
  four-state validator either rejects it or misrenders it.
- Runtime coverage is not a build claim. A static build card cannot show it, and
  a capability string must not change because a connection failed.
- The Linux card is a static `PRIVACY_MODES`/`PRIVACY_FACTS` array fed only
  `{ demo, engine }`. It has no diagnostics payload, so "add a four-state row"
  was unimplementable as written. The Windows report is fixed text with its own
  availability enum.

Revision 7 adds:

- `capability_schema: 2`;
- a separate `runtime` object with `encrypted_dns_coverage`, `reason`,
  `generation`, and `shards`;
- a per-key parser table, with `app_ech` as an information kind;
- a missing key is hidden, not promoted to `unverified`;
- the Linux path `hs:diagnostics` -> preload `diagnostics()` -> `privacyView`,
  with the static card as the no-payload fallback;
- the Windows report stays static and says "Not reported by this build".

Residual: U53. Matrix T13.06 to T13.09.

**F72, the three caps.** The adapter's authenticated cap, the DoH session cap,
and the old "DoH connection cap" were treated as one budget. They are different
objects. The adapter cap is a local socket bound. The session cap is the number
of live DoH sessions. An adapter slot does not reserve a session. Revision 7
states both bounds and removes the equality claim. Matrix T8.05 and T8.21.

**F73, delivery capacity and failure.** Revision 6 reserved completion and
job-table capacity but not delivery capacity, and it had a
`completion_queue_full` product reason. Revision 7 reserves one delivery slot
per accepted job, removes `completion_queue_full` from the product reasons, and
accounts a post-commit write failure as `doh_adapter_errors`. Matrix T8.04 and
T7.32.

**F74, the ECH attempt gauge.** Revision 6 incremented `ech_attempts` at
admission, before the pool knew whether the handshake would offer ECH. Revision
7 records the attempt on `AttemptStarted` and the outcome on `AttemptOutcome`.
An open attempt at job terminal records `ech_error` once. The ledger stays exact
and the pool still writes no counter. Matrix T5.36 and T7.25.

**F75, the DNS discovery text.** The project guidance changed after revision 6.
macOS discovery now requires an unambiguous `scutil` block for the selected
interface and rejects a full VPN or split-DNS resolver, an mDNS resolver, a
loopback stub, and a link-local address. Linux `system_dns_for_interface` fails
closed because the resolver files are one aggregate list; the caller must pass
an explicit `--dns-servers` list, bounded to 8, validated, and deduplicated. The
old "up to 3 system DNS servers" text and the old macOS "numeric IPv4 only"
text are stale and are corrected in sections 4.2 and 6.1. Matrix T5.38 and
T12.22.

**F76, the protocol regression check.** A shard index, a session generation,
and an early close touch local code near the relay. Revision 7 states that SOCKS,
pairing, the source device proxy, the ICMP echo commands, the key schedule, the
TTL, the route rules, the IPv6 defaults, and one-outer-per-flow are unchanged,
and adds T15. The adapter preface is local loopback framing, not a source device
protocol.

**F77, hypotheses versus evidence.** Several numbers in revision 6 read as
facts. Revision 7 adds section 6.8 H1 to H12. Each has the measurement that would
close it. The cap, pool size, quiet window, barrier deadline, resolver binding
behavior, rustls API, provider behavior, and provider builds are hypotheses or
open standards checks, not evidence.

**F78, stale labels and references.** The three files now say revision 7. The
matrix and trace add the new rows and IDs. Appendix H records this review.

### F79 to F86: the revision 8 blockers

**F79, B1, retry generation and cache commit ownership.** The review found that
one word, "generation", named the session counter, the cache counter, and the
runtime coherence counter. It also found no single writer for a retry config or
a cache publication. Revision 8 separates:

- `session_generation`, owned by the shard, increments on connection install and
  on retry authorization;
- `config_generation`, owned by the shard through a commit, increments on
  `Fresh` or `Rejected`;
- `runtime.snapshot_seq`, owned by the supervisor, increments on status
  publication.

A retry is a second attempt of the same job, dispatched from the second work
item reserved at admission. The pool sends the authenticated rejection with no
connection and does not open the retry. The shard increments
`session_generation`, records `ech_rejected`, and dispatches the retry.
`commit_config`, `commit_retry_config`, and `mark_rejected` are compare-and-set
commits under the ledger lock. A stale rejection cannot evict a newer config,
and a retry config write against a newer generation publishes nothing. Sections
5.3 and 6.4.7; matrix T5.39, T5.40, T7.35.

**F80, B2, slot and socket ownership.** The review found that the connection was
owned by the pool and the session at the same time, and that a slot could be
freed while the pool still held the socket. Revision 8 defines a move-only
`ConnectionLease` and a mandatory handback. A slot stays `Attempting` until the
shard observes the handback for that attempt. A terminal decision alone does not
free it. `JoinPool` drains never-started attempts with `Handback::NotStarted`.
A late handback for an older attempt cannot free a newer slot. Sections 6.4.2,
6.4.5, 6.4.6, 6.4.10; matrix T5.41, T5.42.

**F81, B3, adapter failure delivery and reserved capacity.** The review found no
shard-to-adapter terminal path and an "admission channel full" path that could
drop an accepted frame. Revision 8 adds four frame credits per authenticated
connection, 128 total, and one reserved disposition per accepted query: `Answer`
or `Close`. A failed query gets a close immediately, not an idle timeout. The
adapter admission path cannot fill when credits are respected. Sections 4.8,
6.4.9, 6.6, 7.2; matrix T5.43, T5.44, T8.24.

**F82, B4, cross-shard waiters.** The review found per-shard FIFOs against a
global cap, so no cross-shard order existed and a grant could be lost. Revision
8 uses one global `DohWaitQueue`, a direct `SlotGrant` that keeps the slot
counted during handoff, `admit_granted` under the lock, a global deadline
reaper, and exactly one recorded outcome per waiter. Sections 6.4.3, 6.4.3.1;
matrix T5.45, T5.46, T7.34, T8.25.

**F83, B5, the real stop order and budget.** The review found the barrier was not
placed in the actual `Relay::stop` and `Drop` code and that the stop budget was
unknown. Revision 8 records the verified code: `Relay::stop` clears input, sets
`running = false`, and joins workers without a timeout, and `Drop` calls it. The
DoH barrier therefore starts before those steps and before the shard join.
`Drop` cannot report; a Drop-only stop is `drop_only` and inexact. A stuck pool
thread is detached and reported. The total stop budget is unknown because the
existing joins are unbounded. Sections 6.4.8, 6.7, 6.8 H6 and H13; matrix
T6.22 to T6.24.

**F84, B6, status versus diagnostics and missing keys.** The review found that
runtime coverage was placed with counters, but capability lives in `/api/status`
and `hs:status`, while counters live in `/api/diagnostics` and `hs:diagnostics`.
It also found contradictory missing-key rules. Revision 8 puts capability and
runtime in status, counters and `ledger { exact, phase, snapshot_seq }` in
diagnostics, and states that cross-endpoint coherence is not claimed. Missing
keys are hidden, never `unverified`; missing counters are not zero; missing
`ledger.exact` is not true. Sections 2.2, 2.4, 2.5, 2.5.1, 2.5.2, 7.2.3, 7.3;
matrix T7.36, T13.10, T13.11.

**F85, B7, third-party DNS.** The review found that the configured DoH endpoint
substitutes a third-party resolver for the resolver the network or the person
selected. `AGENTS.md` invariant 4 says "do not substitute a public resolver".
The plan's section 7.3 invariant 4 requires no `getaddrinfo` on an egress path
and documents bypasses; it does not authorise a resolver substitution. Revision
8 records that a product-owner decision and an explicit amendment to
`AGENTS.md` invariant 4 are required before any DoH code. If the plan is read to
require the network resolver, its scope text or invariant 4 needs the same
amendment. It does not assert that the scope is approved or that the invariant
is compatible. No built-in, automatic, or fallback public resolver exists.
Sections 4.1.1, 4.1.2, 11.1 U57, 11.2, 12 item 39; matrix T12.24, T16.10.

**F86, the remaining contradictions.** The plan's revision note says task
`85710a0e` applied P7 and P9 to P15; the architecture, matrix, and trace still
said those items remained. The trace said the 2026-11-02 record names macOS
only; the record names no operating system and does not show the DNS case. The
adapter preface was called 19 bytes but had to carry an IPv6 address. The
missing-key rule said both "hidden" and "unverified". Revision 8 corrects all
four and records the plan status as a claim to verify, not approval. Sections
4.2, 6.6, 7.1, 11.2, 11.3, 11.3.1, 12; matrix sections 13 and 17.

### F87 to F95: the revision 9 blockers and major issues

These findings come from the independent revision 8 review (delegated review
task `ecb2b96c-d750-4156-9703-bcf9f5fc6052`). The F79, F82, F83, F84, and F85
answers above were partly wrong; the rows below carry the current answer.

**F87, R9-B1, `session_generation`.** Revision 8 raised `session_generation`
when a connection was installed and when a retry was authorized, stored it in
each job at admission, and failed a completion whose stored value differed with
`doh_other_error`/`generation_mismatch`. The review showed that this fails every
successful retry (authorization raised the value after admission) and every
queued job after the first commit (the commit installed the connection and
raised the value), including the bootstrap user query behind the config fetch.
It also showed that the adapter, which dropped a disposition whose
`session_generation` was not current, could drop an earlier committed answer
when the next pipelined query committed first, so the answer was counted in
`doh_query_ok` but neither delivered nor counted as lost. T5.39 expected one
increment where the rule gave two. Revision 9 makes `session_generation` a
session incarnation number: allocated once at session reservation, never
changed while the session lives. A retry is `attempt_id` 2 of the same job;
matching uses `job_id` and `attempt_id`. A live job cannot disagree with its
session, because every release path terminalizes the session's jobs first; a
difference is an internal invariant violation, not a query outcome.
`generation_mismatch` is removed. The adapter applies dispositions per
connection in `request_id` order, never compares them with "the current" job,
and counts an unwritten committed answer once in `doh_adapter_errors`.
Sections 4.8, 6.2, 6.4.5 to 6.4.7, 6.4.10, 6.6, 7.2.2, 7.2.3; matrix T5.33,
T5.39, T5.48, T7.35.

**F88, R9-B2, waiter settlement and stop.** Revision 8 let revocation and
`cancel_waiter` each record an outcome and free a slot, and then let
`admit_granted` handle an "unknown or already cancelled" grant by returning the
slot and recording again. `Draining` cancelled queued waiters but not
outstanding grants, and the release step ignored `wait_deadline`. Revision 9
defines four waiter states (`Queued`, `Granted`, `Converted`, `Settled`) and one
settlement function, `settle_waiter`, which removes the record, returns a
granted slot, records the outcome, and emits the TCP:53 close in one critical
section. A second call, and a late `admit_granted`, are `Stale` and record
nothing. A granted-then-cancelled waiter records one waiter `doh_cancelled`; no
job exists. The release step settles waiters past either deadline and grants
only one with both remaining; `grant_deadline` is `min(now + T_grant, absolute
deadline)`. `Stopping` settles every queued waiter and every outstanding grant
in the phase transition. Section 6.4.3.1; matrix T5.46, T5.51, T5.52, T7.34,
T16.04.

**F89, R9-B3, route cleanup and incomplete stop reporting.** The review read
`rust/src/service.rs` and found that the tunnel worker runs `relay.stop()` and
only then `routes.remove()`, on every target, after its TUN read loop has
exited. A DoH barrier inside `Relay::stop` would therefore keep host traffic
routed into a dead device for up to the whole barrier. It also found that
`Relay::stop` returns `()`, that the fault slot holds only `(message,
cleanup_failed)`, and that T6.18 said the process still closes a detached
thread's sockets. Revision 9 splits a nonblocking `begin_stop` from the drain.
In a run with the DoH profile active, the worker calls `begin_stop`, removes
routes and the address, and then calls `relay.stop()`, so the drain does not
lengthen the dead-route window. The existing order is unchanged in other runs
(U61). The order depends on every DoH socket being pinned (H15), and the DoH
profile refuses `--no-pin`. `Relay::stop` returns a `RelayStopReport`; the fault
slot gains `doh_stop_incomplete`. An incomplete DoH stop has its own message,
never sets `cleanup_blocked`, and blocks only a later DoH-profile start while a
process-wide detached-thread count is above 0. T6.18 now says the stuck
thread's socket stays open until its call returns. Sections 6.4.8, 6.7, 6.8;
matrix T6.18, T6.22, T6.25 to T6.27, T11.4j.

**F90, R9-B4, the resolver substitution analysis.** Verified in this tree for
revision 9:

- The committed `AGENTS.md` invariant 4 (at `HEAD`) has no
  resolver-substitution sentence. The sentence "Resolver selection must be tied
  to the pinned interface; do not substitute a public resolver" exists only in
  the uncommitted working-tree change, in the interface-discovery paragraph,
  which also says "the person who names it accepts that choice" for explicit
  servers.
- `rust/src/relay.rs` `new_udp`, phone branch, sends every captured inner
  UDP:53 flow in source device proxy mode to `1.1.1.1:53` through the source
  device. This is committed code. The relay rejects `dns_upstream` in that
  mode.
- The committed `docs/TECHNICAL_REFERENCE.md` documents that redirect and
  suggests `--dns-upstream 1.1.1.1`. The working-tree `README.md` line 88
  suggests `--dns-servers 1.1.1.1,8.8.8.8`.

Revision 8 called the uncommitted sentence "the controlling text", said no
build may ship a built-in public resolver, and said even an explicit choice is
a substitution; T16.10 asserted that no built-in resolver exists. Those
statements were false for the current product. Revision 9 states the facts,
limits the no-built-in-endpoint rule to the DoH profile, and records that an
explicit DoH endpoint is the same trust class as an explicit `--dns-upstream`
with a different transport and a larger code surface. It lists owner questions
Q1 to Q5: whether the existing redirect conflicts with invariant 4; whether
explicit DoH differs from explicit `--dns-upstream`; what the amendment
permits; whether the uncommitted invariant change lands first; and how the plan
is read. The decision and the amendment are still required before any DoH code
and are still absent. This trace makes no product decision and changes no
invariant. Sections 4.1.1, 4.1.2; U57, U64; matrix T12.24, T16.10.

**F91, R9-M5, `snapshot_seq`.** Revision 8 described `runtime.snapshot_seq` as
the ledger sequence the supervisor used (section 2.2), as a counter the
supervisor increments per status publication (section 6.4.7), and as a field
separate from `ledger.snapshot_seq` (T13.11), which had no owner. Revision 9
defines one per-run `ledger_seq`, owned by the ledger, incremented under its
lock on every mutation and never on a read. Both reported fields are values of
it. Sections 2.2, 2.5.2, 6.4.7; matrix T7.35, T13.11.

**F92, R9-M6, the probe fallback.** `gui_assets/app.js` `platformInfo()` returns
`state.status.platform` or falls back to `state.probe.platform`, and the probe
handler in `rust/src/gui_backend.rs` copies `status["platform"]` once. A runtime
object inside `platform.destination_privacy` would therefore be copied into the
probe and could outlive its run. Revision 9 reads `runtime` only from the latest
successful status response, removes it from the probe copy, and hides the row
after a failed poll. Section 2.5.2; matrix T7.36, T7.37, T16.09.

**F93, R9-M7, pipelined TCP:53 close.** A `Close` for one query, for example an
admission rejection for a full queue, closed the inner connection before an
earlier in-flight query answered, and that query was recorded as
`doh_cancelled`, the wrong cause. Revision 9 applies dispositions in
`request_id` order and makes a close graceful: the adapter stops reading,
applies every earlier disposition and every already-admitted later one, then
sends FIN, bounded by the latest request deadline. An admission rejection does
not touch the session; a DoH transport failure gives the session's queued jobs
the true `flow_closed` cause. A local SERVFAIL answer stays out of scope as an
owner option (U63). Sections 4.8, 6.4.5, 6.6; matrix T5.47, T16.13.

**F94, R9-M8, the two smaller gaps.** The retry row in section 6.4.6 said
`Ready`; section 6.4.10 said `BetweenAttempts`. Revision 9 uses three rows:
`BetweenAttempts`, `Attempting` with `attempt_id` 2, and `Ready` on commit. A
config fetch that ended without a commit sent no wake and elected no new
fetcher, so waiting sessions ran to their deadlines. Revision 9 wakes every
shard on every exit from `Fetching`. A cancelled fetch lets at most one waiting
session claim a new fetch; a failed fetch sets `retry_after` (proposed 5 s) and
the waiters proceed without ECH. Sections 6.4.6, 6.4.7; matrix T5.49, T5.50,
T16.14.

**F95, the decisions and gates that stay open.** The review listed product
decisions (the DoH scope, the resolver substitution and amendment including the
existing redirect, and whether the tunnel may stay up with DNS dead after a
DoH-only stop, which touches invariant 13) and host and device gates (H1 to
H14, now H15, per-platform live hotspot coverage, real stuck-syscall stop
timing, a Windows host, and a real Linux desktop for T13.10). Revision 9 records
each as open. It does not answer an owner question, and none of the matrix rows
it names exist or have run.

## 3. What this revision does not do

- It does not implement DoH, ECH, the adapter, the pool, the parser, or a
  counter.
- It does not change `rust/`, `docs/`, `gui_assets/`, or any app.
- It does not edit `docs/SNI_HIDING_PLAN.md`. The plan was edited outside this
  task; the handoff reads the current text and records the exact remaining
  work.
- It does not add a dependency or a lockfile entry.
- It does not run a live network test, create a route, create a TUN device, or
  use root.
- It does not approve `hide`. The status stays UNAPPROVED.
- It does not make a carrier claim.
- It does not downgrade on a timeout or a reset.
- It does not accept DoH alone as `hide`.
- It does not claim the plan is fully corrected. The plan's own revision note
  says task `85710a0e` applied P7 and P9 to P15, but this trace treats that as a
  text observation to verify, not approval. WS6 checks each passage.
- It does not start implementation. The architecture header gate requires the
  verified plan text, the product owner's separate DoH scope acceptance, the
  third-party resolver decision and invariant amendment, and a new independent
  review first. Closing `hide` does not need an owner decision; the DoH
  forwarder and the resolver substitution do.
- It does not prove the ownership protocol. The shard model, the retry and cache
  commit, the connection lease and handback, the adapter credits and terminal
  close, the global waiter queue, the commit order, the session and cache
  lifecycle, the capacity envelope, the stop order, and the consumer paths are
  design and test rows only. Matrix T5.30 to T5.52, T6.16 to T6.27, T7.29 to
  T7.37, T8.19 to T8.25, T11.4j, T13.06 to T13.11, T15, and T16 are not written
  or run.
- It does not measure the capacity or stop numbers. H1 to H15 are open. The
  routes-first stop order in a DoH run depends on H15. The cap,
  pool size, quiet window, DoH barrier, and total stop time are hypotheses or
  unknown. The total stop budget is not bounded by the DoH barrier.
- It does not approve cross-source-port DoH sharing. U56 is a product option
  with its own review.
- It does not assert that the third-party resolver substitution is compatible
  with the committed or uncommitted `AGENTS.md` invariant 4 or the plan's
  invariant 4. It does not decide whether the existing source device proxy mode
  `1.1.1.1:53` redirect conflicts with invariant 4. U57 and U64 record the
  decision, owner questions Q1 to Q5, and the amendment as required and absent.
- It does not change an `AGENTS.md` invariant, commit or revert the uncommitted
  `AGENTS.md` change, or grant a product authorization. It does not decide U62
  (tunnel up or down after a DoH-only stop) or U63 (local SERVFAIL).
- It does not change a protocol invariant. T15 is a check, not evidence that a
  future change keeps the invariant.

## 4. Explicit handoff corrections

These are the corrections other workstreams must make. Architecture section
11.3 holds the current plan quote and the remaining replacement text for each
WS6 item; this trace records status and ownership. Where the two differ, the
architecture text wins.

### WS0

1. Add `capability_schema: 2`, `encrypted_dns`, `resolver_ech`, `app_ech`, and
   the separate `runtime` object under the capability contract and the migration
   in architecture section 2.5. Keep the legacy `ech` meaning and value. Define
   the reviewed build qualification constant that makes `supported` reachable.
   Define the per-key parser contract. `app_ech` is never a four-state value.
2. Keep `doh_lookups`, `doh_ok`, and `doh_failed` at the endpoint ECH-config
   meaning. Record the narrowing from "HTTPS or SVCB lookups over DoH". Do not
   reuse them for inner DNS queries.
3. Add `doh_queries`, `doh_in_flight`, `doh_config_in_flight`,
   `ech_attempts_in_flight`, `doh_query_ok`, `doh_query_failed`,
   `doh_timeout`, `doh_http_error`, `doh_parse_error`,
   `doh_response_mismatch`, `doh_queue_full`, `doh_cancelled`,
   `doh_other_error`, `doh_adapter_errors`, `doh_tcp53_queries`,
   `doh_tcp53_failed`, `ech_rejection_unauthenticated`, `ech_error`,
   `ech_retry_exhausted`, and `ech_config_unavailable`. State that the admitting
   shard is the accounting owner, that every shard writes one global ledger,
   that the pool and adapter write no counter, and that the gauges are not event
   counts. State that the fields are identical from any shard's snapshot.
4. Do not add `ech_config_fetch_ok` or `ech_config_fetch_failed`. They
   duplicate `doh_ok` and `doh_failed`.
5. Record the `ech_rejected` narrowing. The current comment says "server
   rejected". The new meaning is an authenticated rejection by the origin
   certificate. An unauthenticated rejection uses
   `ech_rejection_unauthenticated`.
6. Remove "or a stall" from the `ech_fallback` comment
   (`rust/src/diagnostics.rs`).
7. Do not add a DoH failure record by default. If the separate privacy scope is
   accepted, add `FailureEvent::doh_query(destination, port, reason, code,
   phase)` and the direct-mode `record_doh_failure` path.
8. Do not report `encrypted_dns` or `resolver_ech` as `supported` from a
   compile, a linked provider, or a hermetic test. Use `unverified`. Keep
   `ech` `unsupported`.
9. Do not add a passive application ECH counter.
10. State that `doh_*` and `ech_*` can be nonzero while `mode = off`, without
    adding a default counter or warning. The plaintext counter and warning need
    the section 2.6 acceptance.
11. Record the `doh_query_ok` definition: a committed, validated answer handed
    to the inner transport, not a client read. A post-commit write failure is
    `doh_adapter_errors`.
12. Do not add a `generation_mismatch` reason (revision 9 removes it). Remove
    `completion_queue_full` from the product reasons.
13. State that the runtime object is a separate object, is written only by the
    supervisor, is `unknown`/`not_running` when no tunnel runs, and never changes
    a capability string. Remove `runtime` from the `platform` copy in the probe
    response.
14. Define `ledger_seq` once and report it as `runtime.snapshot_seq` and
    `ledger.snapshot_seq`. Add the `doh_stop_incomplete` fault field and the
    `RelayStopReport` result (architecture section 6.4.8).

### WS5

1. Replace "Hide the destination" for DoH.
2. Add an app-dependent ECH row with its own three-value vocabulary, a
   `resolver_ech` row, and an `encrypted_dns` row. Do not use free-text
   capability values. `app_dependent` is information, not support.
3. Show `runtime.encrypted_dns_coverage` as runtime coverage, not as a
   capability value, and only when the runtime object is present.
4. Show the gateway, scoped, link-local, and OS encrypted resolver bypasses.
   Describe gateway DNS as route inference, not live DNS evidence.
5. Show `encrypted_dns = unverified` and `resolver_ech = unverified` until a
   live run.
6. Keep the legacy `ech` row labeled. Never say DoH alone satisfies `hide`.
   Never set `ech = supported`.
7. Update `gui_assets/app.js`, the Linux page, and the Windows report in the
   same change so no consumer silently changes meaning. Keep `off` a runtime
   mode. Do not add the default plaintext warning without section 2.6.
8. Read `runtime` in the browser only from the latest successful status
   response, never from `state.probe.platform`; hide the coverage row after a
   failed status poll.
9. Give the Linux card the `hs:diagnostics` payload path in architecture
   section 2.5.2. Keep the static array as the no-payload fallback. No new IPC
   channel is required.
10. Keep the Windows report static. A key the process did not receive says "Not
    reported by this build". It never prints a four-state value.
11. Use one parser specification with a per-key kind. A missing key is hidden,
    not promoted to `unverified`.
12. Update the Linux `hide` text to "closed as unsupported under the current
    constraints" rather than "blocked on an unresolved client boundary".

### WS6: plan handoff P1 to P15

Name each passage by its quoted text. The plan is untracked and its line
numbers move. Apply every item. The full replacement text is in architecture
section 11.3.

The plan's own revision note says task `85710a0e` applied P7 and P9 to P15. The
plan header also warns that some passages describe an older checkpoint. WS6
verifies each item against the quoted text. An applied status below is the
plan's claim to check, not this trace's approval.

| # | Plan claim to verify | Required check |
|---|---|---|
| P1 | Applied | The blockable bullet forbids an automatic non-ECH retry after a timeout, reset, or certificate failure and labels the separately selected profile |
| P2 | Applied | The acceptance gate forbids the automatic retry and labels the separate profile |
| P3 | Applied | GREASE is a separate opt-in, does not make destinations look alike, and is not `hide` |
| P4 | Applied | Both DNS passages use command 1 with DNS-over-TCP framing. `0x80` is only the other-UDP command |
| P5 | Applied | The plan sends a numeric IP and names the macOS and Windows gateway bypass. The "already resolved" claim is gone |
| P6 | Applied | The parity bullet, WS0 gate, and acceptance criterion use the four state names |
| P7 | Applied per the revision note | Invariant 4 names the `TinyResolver` plaintext local-resolution leak. The direct SOCKS5 passage names the separate ATYP 1 and 4 leak and the unenforced `socks5h` requirement. If it only says "local client resolution", it is not applied |
| P8 | Applied | The false "report no ECH or SNI capability" sentence is gone. The exact key statement belongs to P9 |
| P9 | Applied per the revision note | `encrypted_dns`, `resolver_ech`, and `app_ech` are in the parity key set and point to the capability contract |
| P10 | Applied per the revision note | Every boundary-open passage is replaced: header, status row, section 2.4, the `hide` section, the insertion table, the acceptance criterion, open question 1, the claim ledger, and reader-facing UI text. It records the boundary outcome and the separate DoH scope, and distinguishes the product owner's scope decision from the review |
| P11 | Applied per the revision note | "ECH config caching" is present and open question 6 answers the retry table: only an authenticated resolver rejection retries, once, with retry configs or ECH disabled; no timeout retry; application flows never retry |
| P12 | Applied per the revision note | The counter keys and zero values exist and the data path does not write them; no ECH client exists |
| P13 | Applied per the revision note | DNS uses UDP and TCP; the tunnel path is plaintext today; source proxy uses DNS-over-TCP framing on command 1; DoH is HTTPS over TCP |
| P14 | Applied per the revision note | The Linux default link-bound resolver bypass and the scoped, link-local, ULA, multicast, NAT64, and application or OS encrypted DNS bypasses are present. No live DNS result is claimed |
| P15 | Applied per the revision note | Reader-facing "unresolved" and "blocked on the client boundary" are replaced with "closed as unsupported under the current constraints". Encrypted DNS stays a separate proposed scope and DoH is never called `hide` |

P10 is a text correction, not an open owner decision. The DoH scope still needs
its own product owner acceptance, and the third-party resolver substitution
needs a separate decision and invariant amendment (F85, architecture section
4.1.2). The independent design review is separate from both. No implementation
starts before the plan text is verified, the scope is accepted, the amendment
lands, and the review passes.

### WS2

1. Sequence the `relay.rs` edits. WS1 touches the shard admission path, the UDP
   DNS path, the TCP SYN branch, the adapter, and the stop barrier. WS2 touches
   the TCP data path.
2. Keep one stop path. The shard drain and the relay worker exit must use the
   same barrier; do not add a second shutdown that skips the admission phase
   check.

### Owner

No owner decision blocks closing `hide` or finishing this design. If the owner
later wants a product-owned TLS client, that is a new optional proposal with its
own product decision and review. It must not terminate TLS or add a relay. The
DoH forwarder needs a separate product owner scope acceptance because it
captures DNS and trusts a third-party resolver. That acceptance is distinct from
the independent design review, and neither one substitutes for the other.

The third-party resolver substitution is a second owner decision. The
committed `AGENTS.md` invariant 4 has no resolver-substitution sentence; the
uncommitted working-tree change adds "do not substitute a public resolver" in
the interface-discovery paragraph. The product already redirects source device
proxy mode DNS to `1.1.1.1:53` and accepts explicit `--dns-upstream` and
`--dns-servers` values. A configured DoH endpoint is still a substitution for
all captured DNS. The owner must answer Q1 to Q5 in architecture section 4.1.2
and an amendment to `AGENTS.md` invariant 4, written against the committed text,
must land before any DoH code. If the plan is read to require the network
resolver, the plan's scope text or its invariant 4 needs the same amendment.
This trace does not assert that the amendment exists, that either invariant text
permits the forwarder, that the existing redirect conflicts or not, or that the
scope is approved (U57, U64, F90).

The owner also decides U62: after a second pool panic, whether the tunnel may
stay up with captured DNS unanswered and the `failed` coverage state visible,
or must stop. That touches `AGENTS.md` invariant 13. A local SERVFAIL answer
for a failed TCP:53 query (U63) is an optional owner choice, not part of the
design.

If the owner later wants DoH connection sharing across inner source ports to
raise the capacity envelope, that is a separate product decision (U56). It is
not part of the DoH scope acceptance and it needs its own review, because it
changes the one-inner-flow-to-one-outer-socket shape.

## 5. New independent review checklist

A reviewer should reject this note if any of these is false:

1. `hide` still requires application ECH plus DoH.
2. No path marks `hide` supported from DNS or engine ECH alone.
3. DoH alone cannot satisfy `hide`, and the note says so.
4. No timeout, reset, certificate failure, 5xx, parse error, or SERVFAIL causes
   a non-ECH downgrade. A non-ECH application flow is a profile state chosen
   before connecting, not a retry. The only non-ECH retry is the resolver
   ECH-disabled retry after an authenticated rejection.
5. The plan handoff covers P1 to P15 with the plan's own revision note as a
   claim to verify, not approval. P7 and P9 to P15 are applied according to that
   note. P10 covers every boundary-open passage. WS6 verifies the text.
6. The impossible-transparent-ECH argument is correct and complete.
7. App-native ECH coverage is not overstated.
8. The product-owned client is clearly a new client surface, not a proxy.
9. The bypass table splits macOS, Windows, and Linux. Gateway DNS on macOS and
   Windows is a route-specificity inference, not live DNS evidence. No record
   names the OS for the DNS case. Linux is a likely bypass on a default
   link-bound resolver. The main public-resolver path is unverified on default
   desktop resolvers.
10. The override is out of scope with a safe design recorded.
11. The SOCKS5 and tun DNS paths are stated correctly, including the
    `TinyResolver` leak and the unenforced `socks5h` requirement.
12. The GREASE counter is gone from product status and GREASE is optional, off
    by default.
13. The only retry is on the resolver connection, after an authenticated ECH
    rejection. It is at most one: retry configs, or ECH disabled when none are
    supported. No application flow retries.
14. `doh_lookups`, `doh_ok`, and `doh_failed` keep the endpoint ECH-config
    meaning and the narrowing is recorded. The forwarder counters are separate.
15. The ECH and DoH identities are exact in a coherent snapshot and after the
    stop barrier seals, for 1, 2, 4, and 8 shards. `doh_in_flight`,
    `doh_config_in_flight`, and `ech_attempts_in_flight` account for accepted
    work. Seven causes partition failures with a `doh_other_error` catch-all.
    `ech_grease` and `ech_fallback` are type counts.
16. Every accepted job has a job ID, one owning shard, one `session_generation`
    that is fixed for its session, one `attempt_id`, and one terminal owner.
    Every shard writes one global ledger. The pool and adapter write no DoH
    counter. A late completion is discarded by job ID and attempt ID, and a
    duplicate disposition by its applied job ID. A config fetch has its own
    terminal outcome. `config_generation` and `ledger_seq` are distinct from
    `session_generation`.
17. No shard blocks on I/O. Job, session, attempt work item, waiter, event,
    credit, and disposition capacity is reserved at admission. No completion,
    event, or disposition is silently dropped.
18. The adapter has access control, never evicts, sends admission requests with
    the owning shard under a credit rule, and accepts a bounded local denial of
    service. Its cap is independent of the session cap. Every accepted query
    gets one answer or one close, and a failed query closes the inner connection.
19. No name enters an output. A DoH failure record is off until its own privacy
    scope is accepted.
20. Every egress socket is normalized.
21. The build split is explicit and additive. `ech` implies `doh`; both may be
    enabled; one provider is selected. `encrypted_dns` and `resolver_ech` are
    `unverified` until live qualification. The legacy `ech` keeps its meaning.
22. The capability contract and the migration are followed: four state
    strings, three `app_ech` values with their own parser kind, no free text, a
    missing key is hidden and never `unverified`, the runtime object is
    separate, capability and runtime are in status, counters and `ledger` are in
    diagnostics, and every consumer is mapped with its data path.
23. The test matrix covers crashes, fuzz bounds, no plaintext DNS, the coherent
    counter ledger at 1 to 8 shards, job IDs and late completions, commit
    ordering, session and cache lifecycle, churn, the stop barrier, ECH config
    eviction, the failure-record scope, the bounded adapter flood, the gateway
    evidence, the capability consumers, the default `off` behavior, the
    protocol regression, the connection lease and handback, the retry and cache
    commits, the global waiter queue, adapter credits and close dispositions,
    the status/diagnostics split, and the T16 adversarial table.
24. The plan accounts for P1 to P15 as a claim to verify. The plan's revision
    note says task `85710a0e` applied P7 and P9 to P15. The fallback, GREASE,
    DNS command, DNS coverage claim, and status words must still be checked
    against the quoted text.
25. The implementation gate is scope-specific: the verified plan text, the
    product owner's DoH scope acceptance, the third-party resolver decision and
    the invariant amendment, and a new independent review precede any code. The
    owner acceptance and the review are separate.
26. The default `off` behavior is unchanged: no new DNS path, counter, warning,
    route, socket, dependency, or mode.
27. The capability consumer migration does not silently change `ech`, `off`, or
    any existing key, and a missing new key is never support.
28. The RFC citations are marked unverified from memory until a reviewer reads
    them.
29. The design does not assume one relay worker. The supervisor, shard, ledger,
    and limits are named, and a job is admitted once and never migrates.
30. The terminal decision precedes delivery. A cancelled, timed-out, duplicate,
    or stale-generation response cannot reach the inner client. A post-commit
    write failure is an adapter transport event, not a second outcome. Every
    accepted TCP:53 query ends with one answer or one close.
31. Every session, config-cache entry, and ECH attempt has one owner and a named
    release path. A connection is a move-only lease; a slot is freed only after
    the handback for the attempt that held it. A generation guard prevents an
    old event from attaching to or freeing a new object.
32. The capacity model states an envelope and an explicit failure above it. The
    cap and pool size are measured parameters. Cross-source-port sharing is
    unapproved and not a default. The slot wait is one global FIFO.
33. The stop barrier closes intake before the drain, runs before
    `Relay::stop` sets `running = false` and before the shard join, has a bounded
    DoH deadline, and reports a failed stop rather than an exact ledger when it
    misses. A Drop-only stop is `drop_only`. The total stop budget is measured,
    not assumed.
34. Runtime coverage is a separate object in status, `app_ech` has its own
    vocabulary and parser kind, the Linux card has status and diagnostics paths
    plus a static fallback, and the Windows report prints only what it received.
    Cross-endpoint coherence is not claimed.
35. No protocol invariant changed: SOCKS, pairing, source device, ICMP echo,
    key schedule, TTL, routes, IPv6 defaults, and one-outer-per-flow. The
    adapter preface is local framing.
36. The capacity, barrier, resolver-binding, rustls, provider, and build
    numbers are marked as hypotheses with a named measurement.
37. The DNS discovery text matches the current tree: macOS scoped `scutil` with
    the rejected cases, and Linux fail-closed with an explicit bounded server
    list.
38. The three files say revision 9 and cite the current sections and test IDs.
39. B1: the retry is a second attempt of the same job. The owning shard
    authorizes it without changing `session_generation`. The cache writes are
    compare-and-set; the pool never writes the cache; a stale rejection cannot
    evict a newer config.
40. B2: a slot is freed only after the handback for the attempt that held the
    connection lease. A terminal decision alone does not free it. A late
    handback cannot free a newer slot.
41. B3: adapter admission uses four credits per connection, not a dropping
    channel. Every accepted query has one answer or one close. A failed query
    closes the inner connection without waiting for the idle timer.
42. B4: slot waiters are one global FIFO with one direct grant, one global
    deadline reaper, and exactly one recorded outcome per waiter.
43. B5: the DoH barrier is placed in the real `Relay::stop` order, before
    `running = false` and before the shard join. A Drop-only stop is inexact. A
    stuck thread is detached and reported. The total stop budget is not the 5 s
    DoH bound.
44. B6: capability and runtime are in status; counters and `ledger` are in
    diagnostics. Cross-endpoint coherence is not claimed. A missing key is
    hidden, a missing counter is not zero, and a missing `ledger.exact` is not
    true.
45. B7: the third-party resolver substitution needs a product-owner decision and
    an explicit amendment to `AGENTS.md` invariant 4; if the plan is read to
    require the network resolver, its scope text or invariant 4 needs the same
    amendment. The design does not assert that the scope is approved or that the
    invariant is compatible. The DoH profile has no built-in, automatic, or
    fallback endpoint; the existing source device proxy mode `1.1.1.1:53`
    redirect and the explicit-server options are stated as existing behavior.
46. R9-B1: `session_generation` is allocated once per session and never
    changes. A successful retry and every queued job after the first commit
    complete normally. No `generation_mismatch` reason exists. No committed
    answer is dropped as "not current"; an unwritten one is counted once.
47. R9-B2: every waiter has one settlement transition. A second settlement and
    a late `admit_granted` are `Stale`. A granted-then-cancelled waiter records
    one waiter outcome, not a job outcome. The release step never grants a
    waiter past its wait window. `Stopping` settles queued waiters and grants.
48. R9-B3: in a DoH run the tunnel worker calls `begin_stop`, removes routes,
    then drains. `Relay::stop` returns a `RelayStopReport`. An incomplete DoH
    stop has its own message and never sets `cleanup_blocked`. No row claims
    that a stuck thread's socket is closed by the barrier. H15 is open.
49. R9-B4: section 4.1.2 states the committed and uncommitted invariant 4
    texts, the `1.1.1.1:53` redirect, and the explicit-server options
    correctly, limits the no-built-in-endpoint rule to the DoH profile, and
    lists Q1 to Q5 as open. No invariant is changed.
50. R9-M5: one `ledger_seq`, owned by the ledger; both `snapshot_seq` fields
    report it.
51. R9-M6: `runtime` is read only from status; the probe copy has none.
52. R9-M7: a TCP:53 close is graceful and ordered; no query is made
    `doh_cancelled` by another query's failure.
53. R9-M8: the retry rows are `BetweenAttempts`, `Attempting`, `Ready`. A
    config fetch that ends without a commit wakes every shard and elects at
    most one new fetcher.
54. T5.39, T5.46, T6.18, and T16.10 match the design they test.

## 6. What holds up from the prior reviews

The revision 2, 3, 4, 5, 6, 7, and 8 reviews confirmed these points. Revision 9
keeps them:

- The `hide` requirement is not reduced to DNS only. `hide` stays
  `unsupported` in the design and in the code (`rust/src/diagnostics.rs`).
- The ClientHello count, which GREASE would inflate, is removed from status.
  The only retry is the resolver connection after an authenticated rejection.
- The architecture describes the tun DNS path and the SOCKS5 `TinyResolver`
  path correctly, including the leak caveats.
- The failure name map is cleared at every service start
  (`rust/src/service.rs`).
- The loopback adapter's unpinned socket stays on loopback on all three
  platforms by reading. This is not tested.
- The normalizer helper, failure constructors, capability constants, and
  failure-map clearing facts are confirmed by reading the tree. The rate limit
  on the source device probe is separate.
- The relay is verifiably sharded 1 to 8 with deterministic flow routing
  (`Relay::start`, `shard`). Revision 7 no longer claims a single worker.
- macOS per-interface resolver discovery is verifiably scoped and fail-closed
  for the rejected cases; Linux `system_dns_for_interface` verifiably fails
  closed and the explicit server list is verifiably bounded to 8 and
  deduplicated (`rust/src/environment.rs`, `rust/src/dns.rs`).
- The Linux privacy card is verifiably static and both `hs:status` and
  `hs:diagnostics` exist. The Windows report is verifiably fixed text. Revision
  8 names the real split: capability in status, counters in diagnostics.
- The revision 8 review confirmed the B6 data paths:
  `status.platform.destination_privacy` comes from `destination_privacy_capability()`, diagnostics
  `destination_privacy` holds `{mode, counters}`, Linux `hs:status` and
  `hs:diagnostics` are passthroughs in `ipc.js`, and `privacyView` receives
  only `{demo, engine}`.
- The revision 8 review confirmed the B5 description of `Relay::stop`
  (`rust/src/relay.rs`), apart from the omitted `wake.clear()`, which does not
  matter, and that starting the barrier before `running = false` is correct.
- The revision 8 review confirmed that the three counter names are distinct and
  that the compare-and-set intent for the cache is sound.
- Revision 9 verified by reading: the tunnel worker runs `relay.stop()` before
  `routes.remove()` on macOS, Linux, and Windows; the fault slot is `(message,
  cleanup_failed)`; the probe handler copies `status["platform"]` once; and
  source device proxy mode redirects UDP:53 to `1.1.1.1:53`.

Not verified: the RFC section numbers (read from memory, offline; U29), the
rustls ECH API (U15), whether `systemd-resolved` and `mDNSResponder` bind their
queries to the physical link, the per-query-port churn and peak concurrency
(H1 and H2), the capacity envelope (H4), the ledger lock cost (H5), the DoH
barrier and the total stop time (H6 and H13), adapter credits (H14), pinned
DoH sockets after route removal (H15), the
provider builds and behavior (H9 to H11), and the real carrier result (H12).
