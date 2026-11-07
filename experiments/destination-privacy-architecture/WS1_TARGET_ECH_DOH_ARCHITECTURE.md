# WS1 destination privacy architecture, revision 9

Status: **UNAPPROVED**. Revision 9. This revision answers the independent
revision 8 review of this file, `WS1_TEST_MATRIX.md`, and `WS1_REVIEW_TRACE.md`
(delegated review task `ecb2b96c-d750-4156-9703-bcf9f5fc6052`, revision 8
UNAPPROVED). That review was read in full for this revision. Revision 9 has not
been independently re-reviewed. This note is research and design only. It
changes no production file, manifest, workflow, route, interface, GUI, test, or
`AGENTS.md` invariant. It grants no product authorization. No protocol code was
written and no protocol network test was run. No network, device, route, TUN
device, or phone was used.

Revision 9 revises revision 8. Revision 8 revises revision 7, revision 7
revises revision 6, revision 6 revises revision 5, revision 5 revises revision
4, revision 4 revises revision 3, revision 3 revises revision 2, and revision 2
revises revision 1. Revision 1 is preserved at `WS1_REVISION_1_SUPERSEDED.md`
for audit. Revisions 2 to 8 are not preserved as separate files in this
checkout; the independent reviews of them are recorded in
`WS1_REVIEW_TRACE.md`. The test plan is in `WS1_TEST_MATRIX.md`. Appendix E
lists the revision 4 corrections, Appendix F the revision 5 corrections,
Appendix G the revision 6 corrections, Appendix H the revision 7 corrections,
Appendix I the revision 8 corrections, and Appendix J the revision 9
corrections.

Revision 9 answers four blockers and four major issues from the revision 8
review. It does not change the product conclusion, the scope gate, any
protocol, or any project invariant:

1. **R9-B1 `session_generation` broke normal commits.** Revision 8 raised
   `session_generation` at connection install and at retry authorization, then
   failed any completion whose stored generation differed. That failed every
   successful retry and every queued job after the first commit, and the
   adapter could drop a committed answer. Revision 9 makes
   `session_generation` a session incarnation number: it is allocated once when
   the session is reserved and never changes while that session lives. A retry
   is identified by `attempt_id`. The `generation_mismatch` terminal reason is
   removed. The adapter never drops a committed answer for being "not
   current"; every committed answer is written or counted as undelivered
   (sections 6.2, 6.4.5, 6.4.7, 6.6).
2. **R9-B2 waiter grants could settle twice, and stop ignored grants.**
   Revision 9 gives every waiter one settlement transition under the ledger
   lock. Whoever settles a waiter removes its record and returns its granted
   slot in the same critical section. A later `admit_granted` for that grant is
   `Stale` and records nothing. The release step grants only a waiter whose
   wait window and absolute deadline both remain. `Stopping` settles every
   queued waiter and every outstanding grant (section 6.4.3.1).
3. **R9-B3 the DoH drain delayed route cleanup, and an incomplete stop had no
   report path.** The real tunnel worker calls `relay.stop()` before
   `routes.remove()`. Revision 9 splits a nonblocking `begin_stop` from the
   drain. In a run with the DoH profile active, the service closes DoH intake,
   removes routes and the address, and only then drains. `Relay::stop` returns
   a `RelayStopReport`. A DoH `Incomplete` result is reported with its own
   message and never sets `cleanup_blocked`. A later start with the DoH
   profile is refused while a detached pool thread from an earlier run is
   alive (sections 6.4.8, 6.7).
4. **R9-B4 the resolver substitution analysis misread the current tree.** The
   "do not substitute a public resolver" sentence exists only in the
   uncommitted `AGENTS.md` change. Source device proxy mode already redirects
   every captured UDP:53 query to `1.1.1.1:53`. The committed technical
   reference suggests `--dns-upstream 1.1.1.1`, and the working-tree
   `README.md` suggests `--dns-servers 1.1.1.1,8.8.8.8`. Revision 9 corrects
   section 4.1.2, limits the no-built-in-endpoint rule to the DoH profile, and
   lists the owner questions. The owner decision stays open (section 4.1.2).
5. **R9-M5 `snapshot_seq` had three definitions.** Revision 9 defines one
   per-run ledger sequence, `ledger_seq`, written under the ledger lock on
   every ledger mutation. `runtime.snapshot_seq` and `ledger.snapshot_seq`
   report values from that one sequence (sections 2.2, 2.5.2, 6.4.7).
6. **R9-M6 the probe path could show a stale runtime state.** The browser
   falls back to the probe's one-time copy of `status.platform`. Revision 9
   reads `runtime` only from the latest successful status response and requires
   the probe copy to carry no `runtime` object (section 2.5.2).
7. **R9-M7 a `Close` disposition ended earlier queries on the same TCP:53
   connection.** Revision 9 makes a close graceful and ordered: the adapter
   stops reading, writes every earlier disposition in request order, and then
   sends FIN. Each query keeps its own cause. No local answer is synthesized
   (sections 4.8, 6.6).
8. **R9-M8 smaller gaps.** The retry row now says `BetweenAttempts`. A config
   fetch that ends without a commit returns the cache to `Absent`, wakes every
   shard, and elects at most one new fetcher (sections 6.4.6, 6.4.7).

The revision 8 answers below remain in force where revision 9 does not replace
them. Revision 8 answered seven blockers. It did not change the product
conclusion, the scope gate, or any protocol:

1. **B1 retry generation and cache commit ownership.** Revision 7 used one word,
   "generation", for three different counters, and gave the retry config and
   cache publication no single writer. Revision 8 separates
   `session_generation`, `config_generation`, and `runtime.snapshot_seq`. A retry
   is a second attempt of the same query job. The owning shard, not the pool,
   authorizes it and writes the cache through a compare-and-set commit.
   (Revision 8 also incremented `session_generation` at retry authorization;
   R9-B1 removes that increment.)
2. **B2 slot and socket ownership until the pool returns.** Revision 7 said the
   session owned the connection after a job returned but also said the pool
   closed it, and a slot could be freed while the pool still held the socket.
   Revision 8 defines a move-only connection lease and a handback event. A slot
   is freed only after the shard observes a handback for the attempt that held
   it.
3. **B3 adapter failure delivery and reserved capacity.** Revision 7 had no
   shard-to-adapter terminal path, and its "admission channel full" path could
   drop a frame that the adapter had already accepted. Revision 8 adds
   per-connection admission credits, one reserved terminal disposition per
   accepted job, and a close disposition for every failed query.
4. **B4 cross-shard waiter FIFO, admission, cancel, and deadline.** Revision 7
   put waiters in per-shard FIFOs while the session cap was global, so no order
   existed across shards and a grant could be lost to another shard. Revision 8
   uses one global FIFO in the ledger, a direct slot grant that keeps the slot
   counted during handoff, and one global deadline reaper.
5. **B5 actual `Relay::stop` and `Drop` ordering and stop budget.** Revision 7
   named a barrier but did not place it in the real stop code. Revision 8
   records the verified stop code, puts the DoH barrier before the relay sets
   `running = false` and before it joins shards, and states that the total stop
   budget is unknown because the existing joins are unbounded.
6. **B6 real status versus diagnostics paths and missing-key consistency.**
   Revision 7 put runtime coverage in the same payload as counters, but the
   capability lives in `/api/status` and the counters live in
   `/api/diagnostics`. Revision 8 puts capability and runtime coverage in
   status, counters and ledger metadata in diagnostics, and states that
   cross-endpoint coherence is not claimed. Missing keys are hidden
   consistently, never promoted to `unverified`.
7. **B7 third-party resolver substitution.** The configured DoH endpoint is a
   third-party resolver. That is a resolver substitution in the meaning of
   `AGENTS.md` invariant 4. Revision 8 records that a product-owner decision and
   an explicit amendment to that invariant are required; if the plan is read to
   require the network resolver, its scope text or invariant 4 needs the same
   amendment. It does not assert that the scope is approved or that the current
   invariant is compatible. (R9-B4 corrects the revision 8 reading of the
   current invariant and code. The decision and amendment are still required
   and still absent.)

**Implementation gate.** No implementation starts while this file is
UNAPPROVED. The gate is scope-specific:

1. **Application ECH and `hide`: closed, not gated.** A transparent byte relay
   cannot inject ECH. Under the current constraints there is no transparent
   client boundary, so `hide` is not built and stays `unsupported`. This is the
   plan's own default outcome, not a question waiting for a new answer. A
   product-owned TLS client is a separate optional future proposal. It is not
   part of WS1, is not approved here, and must not terminate TLS or add an
   external relay.
2. **Tunnel-wide DoH forwarder: proposed independent scope, not approved.**
   This document designs a forwarder that captures inner UDP:53 and TCP:53.
   That is a new product scope with the tradeoffs in section 4.1.1. It is not an
   already approved user request and no part of it is implemented. It needs its
   own scope acceptance that records those tradeoffs, plus a separate design
   review, before any DoH client, adapter, pool, counter, or schema change. The
   scope acceptance is a **product owner decision**. It is not a technical
   review and it is not implied by the design review.
3. **Third-party resolver substitution needs its own decision and amendment.**
   The scope acceptance in item 2 must also decide whether the product may
   substitute a configured third-party resolver for the resolver selected by
   the network or the person. That decision requires an explicit amendment to
   `AGENTS.md` invariant 4. If the plan is read to require the network resolver,
   the plan's WS1 scope text or its invariant 4 needs the same amendment. The
   decision must also say how the DoH profile relates to the resolver choices
   the product already makes: the source device proxy mode redirect to
   `1.1.1.1:53` and the explicit `--dns-upstream` and `--dns-servers` options
   (section 4.1.2). This document does not assert that the amendment exists,
   that the invariant already permits the forwarder, that the existing redirect
   conflicts or does not conflict with the invariant, or that the scope is
   approved.
4. **The default `off` behavior does not change.** Revision 9 adds no default
   DNS path, no default counter, no default warning, no route, no socket, no
   dependency, and no mode. Every new capability is opt-in, behind a
   non-default cargo feature where applicable, and off by default. The plaintext
   profile counter and its UI wording are a separate acceptance item (section
   2.6). Do not add them as a side effect of the DoH forwarder.
5. **WS6 verifies the P1 to P15 handoff, it does not assume it.** The plan's own
   revision note says task `85710a0e` applied P7 and P9 to P15. That is a text
   observation by the plan, not an approval by this design, and not evidence
   that each passage is correct. WS6 verifies every item against the quoted
   text. This revision does not edit the plan.
6. **A new independent review approves this file, the test matrix, and the
   trace.** The independent review is separate from the product owner's
   acceptance of the DoH scope and from the invariant amendment. Neither
   substitutes for the other.

Revision 9 is a design answer to a review, not an approval of the design, the
DoH scope, the third-party resolver decision, or an implementation. A design
answer does not close an implementation test.

Until the applicable part of the gate holds, no DoH client, ECH client,
adapter, pool, counter, or schema change may be written. Encrypted DNS is not
exempt from its own scope gate.

`hide` is **not supported** and must not be advertised. Encrypted DNS is a
separate capability in a proposed scope. It is not `hide`. Do not mark `hide`
as supported because DoH works, and do not mark it supported because the
engine's own DoH connection uses ECH. No code is planned for `hide` under the
current constraints.

Scope: target devices only (macOS, Windows, Linux). The iOS and Android source
apps are out of scope. `cover` and `terminate` are out of scope. No dependency
was added. No default behavior changed.

## 0. Reading guide

This note uses four claim labels plus one work label:

- **Verified in this tree**: a statement checked by reading code in this
  working tree.
- **Standard reference**: a statement about an RFC that is cited from memory or
  from a secondary summary. The RFC text was not read for revision 9. Every
  such citation is unverified until a reviewer re-reads the cited section. The
  citation table in section 11.1 U29 records the open check. Do not treat a
  reference as a statement that this project implements the standard.
- **Hypothesis**: a statement that needs a build, a test, or a live network
  before it can be used in a claim.
- **Open**: a decision or measurement that is missing. An open item is not a
  capability.
- **Design invariant**: a rule the implementation must satisfy and a test can
  falsify hermetically. It is not evidence that the code exists.

Revision 7 adds a numbered hypothesis table in section 6.8. A hypothesis is
falsified by the named measurement. It is never promoted to evidence by
repetition in a later revision.

The prior review's findings are addressed by design, not by code. A design
answer does not close an implementation test. The trace file records the
difference. Revision 4 added a capability contract in section 2.4, a complete
counter and failure-cause ledger in section 7.2, and the WS6 handoff in section
11.3. Revision 5 made the gate scope-specific, resolved the client boundary
to the plan's default, separated the DoH forwarder into a proposed independent
scope, and added in-flight counter accounting. Revision 6 replaces the single
counter-writer assumption with a per-job owner and a coherent ledger, defines
the one retry policy for the resolver connection, maps every capability
consumer, removes the cross-flow connection eviction, extends the plan handoff
to P15, and withdraws the live-evidence wording for the gateway bypass.
Revision 7 replaced the single-worker assumption with a sharded ownership
model, made response delivery a commit after the terminal decision, defined
the session and config-cache lifecycle, removed the fixed 32-slot assumption,
added the multi-shard stop barrier, and separated runtime coverage from the
static capability in every consumer. Revision 8 separates the three generation
counters, adds the connection lease and handback rule, adds adapter credits and
a terminal close disposition, moves slot waiters to one global FIFO, places the
DoH barrier in the real `Relay::stop` order, and splits status from diagnostics
for capability and counters. It also records the third-party resolver decision
and the invariant amendment that decision needs. Revision 9 makes
`session_generation` a fixed session incarnation number, gives each slot waiter
one settlement transition, removes routes before the DoH drain in a DoH run,
returns a relay stop report, defines one ledger sequence, reads runtime coverage
only from status, makes the TCP:53 close graceful and ordered, re-elects a
config fetcher after a cancelled fetch, and corrects the resolver substitution
analysis against the current tree.

## 1. The requirement, and the hard conclusion

### 1.1 What the user asked for

The user's `hide` requirement has two parts:

1. application TLS connections must carry a real Encrypted Client Hello on the
   wire, so the destination server name is not in the plaintext ClientHello;
2. DNS used by those connections must be encrypted, so the query name is not
   visible on the carrier path.

Part 2 without part 1 is not `hide`. Part 1 on the engine's own resolver
connection without part 1 on application connections is not `hide` either.
Revision 1 made the first mistake. This revision does not repeat it.

### 1.2 Why the engine cannot add ECH to another process's handshake

ECH is built by the TLS client. The client obtains an `ECHConfig` for the
server, constructs a `ClientHelloInner`, encrypts it with HPKE to the server's
ECH public key, and sends a `ClientHelloOuter` whose SNI is the config's
`public_name` (RFC 9849 sections 3.2, 4, and 6.1). The server accepts or
rejects. The client must own the handshake transcript and the HPKE context.

The target engine is a byte relay for application flows. It copies inner TCP
payload to an outer socket. It does not hold the application's TLS keys, the
application's ECHConfig, or the application's inner ClientHello. It cannot
rewrite the ClientHello because the handshake transcript covers it
(RFC 8446 section 4.4.1), and it cannot splice in an ECH extension because it
has no HPKE context for the server. Adding a TLS library to the engine does not
change the ClientHello that another process builds.

The same limit applies to the SOCKS5 listener: it hands the application a byte
stream to a numeric address. The application still builds its own TLS.

### 1.3 The conclusion

Under the constraints in force (no local CA, no TLS termination, no external
relay or VPS, one inner flow to one outer socket, default off, no source device
app in the data path), **universal application ECH is not achievable**. No
transparent design can put ECH into every application's handshake. This is not
a missing library. It is a consequence of who owns the TLS client.

Two paths can produce real ECH on an application connection:

- **App-native ECH.** The application already implements ECH and obtains an
  ECHConfig through HTTPS/SVCB records. The engine can encrypt the DNS lookup
  that carries those records and can preserve the records. The engine cannot
  make an application support ECH, cannot make the operating system expose
  HTTPS records through `getaddrinfo`, and cannot stop an application from
  falling back. Coverage is app-dependent and is not a product capability.
- **A product-owned TLS client.** This is a separate optional future proposal,
  not part of WS1. The product would originate the TLS connection itself, for
  an application that deliberately delegates the connection to it, or for a
  product-owned fetch/browser surface. It would be a new client surface, not a
  transparent tunnel feature, and it is not approved by this document. It must
  not terminate TLS or add an external relay. It covers only the clients that
  adopt it.

Everything else is either termination (out of scope), a source device
terminator (out of scope), or a claim the product cannot keep.

The client-boundary question is **closed for this workstream under the current
constraints**, not left as a pending approval. A transparent byte relay cannot
inject ECH. The plan already states the default outcome: if no acceptable
boundary exists, `hide` is not built and no claim is made
(`docs/SNI_HIDING_PLAN.md`, section 2.4 and the WS1 acceptance gate). That is
the outcome here. `hide` is closed as unsupported. No owner decision is needed
to reach it. A product-owned client remains a separate optional future product
choice, not a decision this workstream waits on.

Therefore:

- `hide` is not implementable as a transparent mode.
- `hide` could only be a bundle: encrypted DNS plus real ECH on the flows the
  product owns, plus an honest `app-dependent` report for app-native ECH.
- Under the current constraints, the first part is unavailable, so `hide` stays
  `unsupported`. Encrypted DNS is reported separately.
- A product-owned TLS client remains a separate optional future proposal. It is
  not a decision this workstream waits on.

### 1.4 Coverage matrix

| Flow | DNS hidden by this work | ECH on the wire | Who must change | Honest label |
|---|---|---|---|---|
| Application uses the system stub resolver, and the query enters the tunnel | Yes, when DoH is on | Only if the application implements ECH and receives a usable HTTPS record | Application | `app-dependent` |
| Application uses its own DoH or DoT | No; the engine never sees the query | Only if that application implements ECH | Application and its resolver | `outside this mode` |
| Application uses the system stub resolver and the query bypasses the tunnel | No | Only if the application implements ECH anyway | Platform network configuration | `bypass` |
| Application uses the product-owned TLS client | Yes | Yes, for that client, where the origin publishes ECH | Product and the adopting application | `owned client only` |
| Ordinary application through the byte relay | Yes for its DNS if the query enters the tunnel | No | Application | `SNI visible` |
| Engine's DoH connection | Not applicable; it is the DNS transport | Yes, as a secondary property | Engine | `resolver_ech`, not a product claim |
| Source device app traffic | Out of scope | Out of scope | Source device app | `out of scope` |
| Engine control plane on loopback | No DNS | No TLS | None | `not affected` |

The matrix is the claim boundary. A UI that says "hide the destination" for
the third row is false. A UI that says "hide DNS names for tunneled queries"
for the first row is true but narrower than `hide`.

## 2. Vocabulary and claim ledger

### 2.1 Five traffic classes

| Class | Flow | TLS client | What the engine holds | What it may do |
|---|---|---|---|---|
| A | Engine-owned HTTPS: DoH transport, ECHConfig fetch | Engine | Handshake, keys, SNI, ALPN, certificate chain | ECH, TLS 1.3, no resumption, validation, total deadline |
| B | Relayed application TCP through the tunnel | Application | Opaque bytes | Copy bytes. Optionally re-frame (WS2 `shape`). Never rewrite TLS |
| C | Application through the local SOCKS5 listener | Application | Opaque bytes after name resolution | Same as B |
| D | Source device app: pairing, proxy, echo | Source device app | Nothing | Out of scope |
| E | Engine control plane on `127.0.0.1` | None (loopback HTTP) | Full | No TLS. Not affected |

Only class A can carry ECH under this workstream. A product-owned client would
be a new class, A-app, with its own security boundary. It is not class B.

### 2.2 Modes and capabilities

The engine schema has four mode names: `off`, `shape`, `hide`, and `cover`.
Do not add a fifth mode called `encrypted-dns`. A fifth mode would repeat the
revision 1 mistake in a different place.

Instead:

- `hide` means the bundle in section 1.3. It is closed as `unsupported` under
  the current constraints because no transparent application ECH path exists.
  It does not wait on a new owner decision.
- Encrypted DNS is a **capability**, not a mode, and the tunnel-wide forwarder
  is a **proposed independent scope**, not approved work. Suggested capability
  name: `encrypted_dns`, with states `supported`, `unsupported`, `unavailable`,
  `unverified`. WS0 owns the final schema.
- `encrypted_dns` is `unverified` in a build with the DoH code path until that
  build and platform have a recorded live run showing tunneled DNS queries
  carried by the DoH path. A compile, a hermetic test, or a mock is not live
  evidence. After that qualification, a build for that platform may report
  `supported`. The value is static per build and platform; it is not recomputed
  when a person changes network profile. A build without the DoH code path
  reports `unsupported`.
- `ech` is a **legacy key with its existing meaning**: "this build implements
  an ECH mechanism." It is not redefined as application ECH and it never carries
  resolver ECH. It stays `unsupported` and is never raised. The new keys carry
  the new claims. WS0 may remove `ech` only in a schema version that updates
  every consumer in section 2.5; it must not alias `ech` to `app_ech` while a
  consumer still reads `ech` as a mechanism flag. A silent alias is a semantic
  change.
- `resolver_ech` is a separate key for ECH on the engine's own DoH connection.
  It is `unverified` in a build with ECH until a live accepted ECH handshake is
  recorded, and `unsupported` in a build without ECH. After that live
  qualification it may report `supported` for that build and platform. The key
  name carries the scope. There is no free-text detail field in the capability
  row.
- `sni_override` stays `unsupported`. The engine overrides no application SNI.
- When WS0 adds the field, application ECH is reported as
  `app_ech = app_dependent`. It is never `supported` by the engine. If a
  separate product-owned client proposal is ever approved, report
  `owned_client` for that client only and scope it to that client.
- A build without the DoH code path reports `encrypted_dns = unsupported` and
  `hide = unsupported`. It never reports silence as support.
- Every mode is opt-in and off by default. There is no always-on ECH or DoH. A
  profile change never enables a mode silently. A capability value is a build
  and platform claim; profile-specific coverage is a separate UI state, not a
  different capability value.

The existing `destination_privacy_capability()` already has `modes.hide`,
`ech`, and `sni_override`. It does not have `encrypted_dns`, `resolver_ech`, or
an application ECH field. Adding any of them is a WS0 schema change. Until WS0
lands it, the capability must stay conservative: `hide = unsupported`,
`ech = unsupported`, `sni_override = unsupported`, and no `resolver_ech` or
`app_ech` claim. A missing key is not support.

The new keys are a **schema version 2** payload, not an unversioned addition.
WS0 adds `capability_schema: 2`. A consumer that does not know version 2
ignores every unknown key and renders the old rows. It must not read
`app_ech`, `encrypted_dns`, or `resolver_ech` as a four-state capability unless
it also reads the schema and the key's own value vocabulary (section 2.4).

Runtime coverage is **not** a capability value and is not a sibling of a
capability string. It is a separate object in the status payload, under
`platform.destination_privacy.runtime` (section 2.5.2):

```
destination_privacy.runtime = {
    encrypted_dns_coverage: "unknown" | "inactive" | "active"
                          | "bypass_detected" | "failed",
    reason: "not_running" | "no_profile" | "connecting" | "active"
          | "bypass" | "doh_failed" | "stopped" | "not_reported",
    snapshot_seq: <u64>,        // value of the run's ledger_seq that this
                                // state was derived from; not a time and not
                                // a session or config generation; absent when
                                // no tunnel runs
    shards: <u8>                // relay worker count, informational
}
```

Rules for the object:

- Only the DoH supervisor writes the coverage state. A shard never writes it.
  The coverage state is stored inside the ledger and changed under the ledger
  lock, so a coverage change is a ledger mutation. The service `status()` call
  reads it through the relay's shared status path with one ledger-lock read.
  The object never lives only in diagnostics.
- It is `unknown` with reason `not_running` when no tunnel runs. It never
  carries over from a previous run.
- It never changes a capability string in either direction. A `failed`
  coverage state does not make `encrypted_dns` `unavailable`; an `active`
  state does not make it `supported`.
- It holds no resolver name, address, QNAME, or host. `reason` is a fixed
  vocabulary.
- A consumer that does not receive the object shows no coverage row. It never
  infers `active` from a running tunnel or from `encrypted_dns`.
- `snapshot_seq` has one definition. Each relay run has one ledger sequence,
  `ledger_seq`, a `u64` that starts at 0 when the run's ledger is created and
  increments by one under the ledger lock on every ledger mutation: an
  admission, a waiter settlement, a terminal outcome, a cache commit, a phase
  change, and a coverage change. A read never increments it.
  `runtime.snapshot_seq` is the `ledger_seq` value at the lock read that
  produced the runtime object. `ledger.snapshot_seq` in diagnostics is the
  `ledger_seq` value at the lock read that produced the counter clone. Both
  fields report the same sequence; neither has its own counter, and the
  supervisor does not increment anything when status is read. Equal values in
  one run mean the two reads saw the same ledger state; that equality is a
  test aid, not a coherence claim for a UI. The sequence is not
  `session_generation` and not `config_generation` (section 6.4.7). It is
  scoped to one run and is absent when no tunnel runs. A status request and a
  later diagnostics request can carry different values; the design does not
  claim cross-endpoint coherence (section 2.5.2).

### 2.3 Counter semantics

Counters are event counts. They never hold a name, address, certificate, ECH
config, or host. Counters must not merge different claims:

- `ech_*` counts only engine-originated TLS. Today that is the DoH connection.
- Application ECH is not counted from passive parsing. Section 5.4 explains
  why a ClientHello extension count is false because of GREASE.
- Existing `doh_lookups`, `doh_ok`, and `doh_failed` keep their current
  scope. They currently count the endpoint's own HTTPS or SVCB lookup.
  Section 7.2 narrows that comment to the endpoint's ECH-config lookup and
  requires WS0 to record the narrowing. The inner DNS forwarder uses the new
  `doh_queries`, `doh_query_ok`, and `doh_query_failed` counters. Section 7.2
  defines both sets and the overlap rule.
- `dns_plaintext_profile_queries` counts queries sent over a plaintext DNS
  profile. It is absent or zero in the default `off` profile until the separate
  acceptance in section 2.6. When a DoH profile is active and a person selects
  the labeled plaintext profile, it counts from the first query. It is a
  profile state, never a reaction to a DoH failure.
- `doh_adapter_errors` counts TCP:53 adapter transport failures that never
  became an accepted query: a cookie failure, a preface failure, a frame
  failure, a write-bound failure, or an adapter connection-cap rejection. It
  also counts a delivery write that fails after a committed answer. It is not
  part of `doh_queries`.
- `doh_in_flight`, `doh_config_in_flight`, and `ech_attempts_in_flight` are
  gauges. They count accepted work with no terminal outcome. They exist so the
  reported identities can be exact in a coherent snapshot (section 7.2.2).
- No counter is called `hide_ok`, `sni_hidden`, or `app_ech_flows`.

### 2.4 Capability contract

A capability is a build and platform qualification claim. It is not a mode
name, not a runtime network-profile observation, and not a promise about an
application. The contract is:

| Key | Allowed values | `supported` requires | This revision |
|---|---|---|---|
| `modes.hide` | `supported`, `unsupported`, `unavailable`, `unverified` | An application ECH path exists for named flows, and a wire test shows the real name absent and ECH accepted on those flows | `unsupported`; closed under current constraints |
| `encrypted_dns` | same four | A live run on that build and platform shows a tunneled DNS query carried by the configured DoH path. The evidence may come from a named profile, but the value is not recomputed per profile | `unverified` in a `doh` build; `unsupported` without `doh` |
| `app_ech` | `app_dependent`, `owned_client`, `unsupported` | Not a support state. `owned_client` is scoped to a separately approved product-owned client and requires its own wire test | `app_dependent` |
| `resolver_ech` | same four | A live accepted ECH handshake on the engine's DoH connection, on that build and platform | `unverified` in an `ech` build; `unsupported` without `ech` |
| `ech` | same four | Legacy build-mechanism flag. It never means application ECH and never carries resolver ECH. WS0 keeps it at `unsupported` until a schema version removes it and every consumer in section 2.5 is updated | `unsupported` |
| `sni_override` | the four states | Never. The engine overrides no application SNI | `unsupported` |

Rules that bind the contract:

1. The four states have these meanings. `supported` means the mechanism exists
   **and** the build and platform have recorded live evidence for that claim.
   `unverified` means the mechanism exists but the live evidence is absent.
   `unsupported` means no such code path. `unavailable` means the platform or
   build configuration cannot provide it. The existing comment in
   `rust/src/diagnostics.rs` says `supported` means "this build implements the
   mechanism." That meaning stays true for `modes.off` only. WS0 must split the
   comment so a privacy key cannot become `supported` from a compile.
2. A compile, a hermetic test, a mock, a linked provider, or a build flag is not
   live evidence. No privacy key becomes `supported` from a build alone.
3. A capability value is one of the listed strings. There is no detail, note,
   or scope field in the row. Scope is carried by the key name (`resolver_ech`,
   `app_ech`) and by this document. WS0 must not put "engine resolver connection
   only" in a value string, because no field would carry it.
4. A missing key is not support and is not `unverified`. A UI that reads a
   missing key hides the row and says the build did not report it. It must never
   render `supported` or `unverified`, because `unverified` asserts that a
   mechanism exists. The one exception is `modes.off`, which keeps its existing
   runtime-mode meaning.
5. A capability value is static for a build and platform. It is not recomputed
   when a person changes network profile, so `supported` remains reachable once
   the build is qualified. WS0 must define how the build records that
   qualification, for example a reviewed compile-time constant per platform
   whose comment links the live record. It is not a runtime probe and not a
   network-profile observation. A build without the constant reports
   `unverified`. Profile-specific coverage, such as a gateway bypass or a DoH
   connection failure, is a separate runtime coverage state. It never lowers or
   raises the capability string at runtime.
6. Exactly one key carries application ECH. This design uses `app_ech`. The
   legacy `ech` key keeps its build-mechanism meaning and stays `unsupported`.
   It is removed only with a schema version that updates every consumer.
7. The `doh_*` and `ech_*` counters can be nonzero, and `encrypted_dns` and
   `resolver_ech` can be `unverified`, while `mode = off`, because both
   capabilities are separate from the mode. WS0 must state that condition
   instead of implying that `off` means all counters are zero. This is a
   capability statement, not a default behavior change: the default payload
   still has no DoH path and no new warning.
8. **Each key carries its own vocabulary.** `modes.*`, `encrypted_dns`,
   `resolver_ech`, `ech`, and `sni_override` use the four state strings.
   `app_ech` uses exactly `app_dependent`, `owned_client`, and `unsupported`.
   A parser takes a per-key specification. It must not run one four-state
   validator over every value. `app_dependent` and `owned_client` are
   information states, not support states: a UI must not render either as a
   green "supported" pill, and must not render `unsupported` as a failure of
   the app.
9. **A missing key is hidden, not promoted.** The row is omitted and the
   report says the build did not report it. The parser does not substitute
   `unverified`, because `unverified` asserts that a mechanism exists. This is
   the only missing-key rule in this document; section 2.5 and section 2.5.1
   use the same word. The one exception is `modes.off`, which keeps its
   existing runtime-mode meaning.
10. **Static and runtime are different objects.** A capability key is a build
    and platform claim. `runtime.encrypted_dns_coverage` is a per-run
    observation. A consumer reads them from different fields, renders them in
    different rows, and never derives one from the other. Section 2.5 names
    the exact consumer path.

### 2.5 Capability consumers and migration

The new keys are additive. No existing key changes meaning. Every consumer in
this table is part of the migration, and each one keeps working when the new
keys are absent.

| Consumer | What it reads today | Revision 9 mapping | Must not |
|---|---|---|---|
| `rust/src/diagnostics.rs` | `mode`, `default_mode`, `modes`, `sni_override`, `ech`, `background_relay`; fixed `supported` comment | Add `capability_schema: 2`, `encrypted_dns`, `resolver_ech`, `app_ech`, and the separate `runtime` object. Keep `ech` and its meaning. Split the `supported` comment into "mechanism exists" for `off` and "qualified by live evidence" for privacy keys | Redefine `ech`, raise it from a build, make `off` mean all counters are zero, or put runtime coverage in the capability map |
| `gui_assets/app.js` and `gui_assets/destination_privacy.test.mjs` | `privacy.ech` parsed with one four-state validator; `privacy.sni_override`; `privacy.modes[mode]`; ECH counters in diagnostics | Use a per-key parser specification. Read `capability_schema`; prefer `app_ech`, `resolver_ech`, and `encrypted_dns` when the schema is 2. Render `app_ech` with its own three-value vocabulary as an information row. Read runtime coverage only from `destination_privacy.runtime` in the latest successful `/api/status` response. `platformInfo()` may keep its probe fallback for static capability keys, but the runtime row never reads `state.probe.platform`. A missing key omits the row | Run one four-state validator over `app_ech`, infer coverage from `mode` or `encrypted_dns`, render `app_dependent` as support, treat a missing key as `unverified`, or show a runtime state from the probe copy or from an older status response after a failed poll |
| `linux/src/renderer/model.js`, `linux/src/renderer/app.js`, and `linux/test/privacy-capabilities.test.mjs` | A static `PRIVACY_MODES` and `PRIVACY_FACTS` array fed only `{ demo, engine }`; `hide` text says "blocked on an unresolved application TLS client boundary"; no diagnostics payload reaches `privacyView` | Make the card payload-driven: fetch `hs:status` for capability and runtime and `hs:diagnostics` for counters through the existing preload calls, pass `{ capability, runtime, counters, ledger }` into `privacyView`, and add `encrypted_dns`, `resolver_ech`, legacy `ech`, and `app_ech` (information) rows plus a separate runtime coverage row. Keep the static array only as the no-payload fallback. Change the `hide` text to closed as unsupported under the current constraints | Claim DoH or ECH from `engine: true`, show a static row as `unverified` or available, show `app_dependent` as support, take capability from diagnostics, or place runtime coverage in the capability list |
| `windows/src/HotspotShade.WinUI2.Core/WindowsPrivacyCapabilities.cs` and its tests | A static `WindowsPrivacyAvailability` enum and fixed "No. Not provided by this build" fact strings; the app is a simulated preview with no diagnostics payload | Keep the report static. New facts say "Not reported by this build" unless the build embeds a reviewed constant. Do not print a four-state value the process did not receive. If the app later reads the service, use the same per-key parser. `Off` stays a runtime mode with `NotRunning` | Map `NotRunning` to static `unavailable`, invent `unverified`, show `app_dependent` as support, or describe `off` as a privacy support claim |
| `macos/` target app | No destination-privacy capability row today | If a row is added, it uses the same contract and treats a missing key as hidden | Invent a capability or show a toggle before the backend exists |
| `ios/HotspotProxy/SourceDeviceCapabilities.swift` and the Android source app | A separate source-device capability model with its own state words (`On`, `Not available`, `Not guaranteed`, and others) | Leave it separate. It describes the source app, not the target engine payload. Do not force the four engine states into it or copy `encrypted_dns` into it. `hide` stays not available | Reuse an engine capability key with a different meaning, or imply that the source app adds `hide` |
| `rust/src/demo.rs` tests | Expect `ech = unsupported` and zero counters | Add the new keys with conservative values. Keep the `ech` assertion | Change the `off` demo behavior or add a default DoH path |
| README and technical reference | Say destinations are visible | Keep that text until an implementation and a live run exist | Soften it from this design |

Migration rules:

1. **No key changes meaning.** `ech` keeps its build-mechanism meaning and
   stays `unsupported`. The new keys carry the new claims.
2. **Additive and optional.** A missing new key is hidden, never `supported`
   and never `unverified`. `capability_schema` is a version, not a feature
   flag.
3. **Static and runtime are different fields.** `modes.hide`, `encrypted_dns`,
   `resolver_ech`, `app_ech`, and `ech` are static build and platform claims.
   `mode` is the runtime mode. `runtime.encrypted_dns_coverage` is a runtime
   coverage state (`active`, `inactive`, `bypass_detected`, `failed`, `unknown`)
   in its own object. A DoH connection failure at runtime sets coverage to
   `failed`; it does not change `encrypted_dns` from `unverified` to
   `unavailable`.
4. **`unavailable` is static.** It means the platform or build cannot provide
   the mechanism. It is not a transient network failure and not a person's
   choice.
5. **`off` stays `supported` as a runtime mode.** It means the tunnel can run
   with no destination-privacy mode. It is not a privacy claim and must not be
   read as one.
6. **No default behavior change.** The default payload is the current one plus
   absent or conservative new keys. No new default counter or warning appears
   until its own acceptance (section 2.6).

#### 2.5.1 Capability payload and per-key parser contract

WS0 publishes one schema. A consumer validates each value with the key's own
row, not with one global state list.

| Key | Kind | Allowed values | Missing key |
|---|---|---|---|
| `capability_schema` | version | `1`, `2` | Treat as version 1 |
| `modes.<name>` | static capability | `supported`, `unsupported`, `unavailable`, `unverified` | Omit the mode row |
| `encrypted_dns` | static capability | the four states | Omit the row; do not substitute `unverified` |
| `resolver_ech` | static capability | the four states | Omit the row |
| `ech` | static legacy mechanism flag | the four states | Omit the row |
| `sni_override` | static capability | the four states | Omit the row |
| `app_ech` | static information | `app_dependent`, `owned_client`, `unsupported` | Omit the row |
| `runtime.encrypted_dns_coverage` | runtime observation | `unknown`, `inactive`, `active`, `bypass_detected`, `failed` | Show no coverage row |
| `runtime.reason` | runtime observation | fixed vocabulary in section 2.2 | Show no reason |
| `runtime.snapshot_seq` | runtime observation | unsigned integer | Show no sequence |
| `destination_privacy.ledger.exact` | diagnostics metadata | `true`, `false` | Do not claim exactness |
| `destination_privacy.ledger.phase` | diagnostics metadata | `running`, `sealed`, `incomplete`, `drop_only` | Show no phase |
| a counter key | diagnostics event or gauge | non-negative integer | Show "not reported"; do not treat it as zero and do not assert the identity |

The parser rules:

1. A value outside the allowed set for that key is rendered as "not reported",
   never coerced to a support state.
2. `app_dependent` and `owned_client` are information, not support. The UI text
   says which flows the claim covers. It never says the app is protected.
3. `encrypted_dns` and `resolver_ech` are build and platform claims. A runtime
   `failed` or `bypass_detected` state is a separate row and never edits the
   claim.
4. A consumer that sees `capability_schema` 2 but not a key omits that row. It
   must not use `mode` or the presence of a `doh` build as a substitute.
5. A consumer that sees version 1 renders the existing rows and does not read
   the version 2 keys.

#### 2.5.2 Consumer data paths

Verified in this tree:

- `Service::status()` builds `platform.destination_privacy` from
  `diagnostics::destination_privacy_capability()` (`rust/src/service.rs`). That
  object holds `mode`, `default_mode`, `modes`, `sni_override`, `ech`, and
  `background_relay`. It holds no counters and no runtime object.
- `Service::diagnostics()` builds `destination_privacy` from
  `diagnostics::destination_privacy()` and merges the relay counters
  (`rust/src/service.rs` `merge_relay_diagnostics`, `rust/src/relay.rs`
  `Relay::diagnostics`). That object holds `mode` and `counters`. It holds no
  capability and no runtime object.
- The browser GUI serves those two objects at `GET /api/status` and
  `GET /api/diagnostics` (`rust/src/gui.rs`). `gui_assets/app.js`
  `destinationPrivacy()` reads `platformInfo()`, which returns
  `state.status.platform` and falls back to `state.probe.platform` when status
  has no `platform`. `diagnosticsReport()` reads `/api/diagnostics`.
- The probe response copies `status["platform"]` once, at probe time
  (`rust/src/gui_backend.rs`, the probe handler's `"platform":status["platform"]`
  field). The page keeps that copy in `state.probe` until the next probe. A
  runtime object placed in `platform.destination_privacy` would therefore be
  copied into the probe response and could outlive the run it described.
- The Linux app exposes both `hs:status` and `hs:diagnostics`
  (`linux/src/main/channels.js`) and its preload exposes both calls. The
  renderer passes only `{ demo, engine }` into `privacyView` today
  (`linux/src/renderer/model.js`, `linux/src/renderer/app.js`), so the card is
  static and reads no payload.
- The Windows app builds a fixed report
  (`windows/src/HotspotShade.WinUI2.Core/WindowsPrivacyCapabilities.cs`) and
  reads no engine payload. The macOS app has no destination-privacy row today.

Therefore capability and counters do not share a payload today, and the two
requests are separate instants. The required split is:

| Consumer | Capability and runtime | Counters and ledger | Failure behavior |
|---|---|---|---|
| Browser GUI | Static capability: `GET /api/status` `platform.destination_privacy`, or the probe copy when status has no `platform`. `runtime`: the latest successful `GET /api/status` response only, never the probe copy | `GET /api/diagnostics` `destination_privacy`: `mode`, `counters`, `ledger` | Missing capability key: hide the row. Missing `runtime`, or a failed or absent status response: show no coverage row. Missing counter: "not reported" and do not assert an identity. Missing `ledger.exact`: do not claim exactness |
| Linux target app | `hs:status` through the existing preload `status()`, passed as `capability` and `runtime` | `hs:diagnostics` through the existing preload `diagnostics()`, passed as `counters` and `ledger` | No payload or a failed call: keep the static card and say the build did not report the keys. Never print a four-state value or a coverage state it did not receive |
| Windows target app | Static report only. It prints "Not reported by this build" for a key it did not receive | None | No payload: static text only. It never prints `supported`, `unverified`, or `active` for a key it did not receive |
| macOS target app | No row today. If added, same split | Same split | Missing key: hide the row |
| Source device apps | A separate source-device capability model | None | Do not copy a target capability key |

Rules for the split:

- **Capability and runtime live in status.** WS0 adds the version 2 keys and
  the `runtime` object under `platform.destination_privacy` in the status
  payload, not under diagnostics. The DoH supervisor writes the coverage state
  into the ledger; `Service::status()` reads it through the relay's shared
  status path and emits `unknown`/`not_running` with no `snapshot_seq` when no
  tunnel runs.
- **The probe copy carries no runtime object.** WS0 removes
  `destination_privacy.runtime` from the `platform` value that the probe
  handler copies, or builds that copy from the static capability only. The
  browser runtime row reads `state.status` only. Both rules are required: the
  server rule keeps a stale object out of the probe response, and the page rule
  keeps an older engine or a cached probe from showing one. When a status poll
  fails, the page hides the coverage row instead of keeping the previous
  runtime state.
- **Counters and ledger metadata live in diagnostics.** The `destination_privacy`
  object in diagnostics gains a `ledger` object:
  `{ exact: bool, phase: "running"|"sealed"|"incomplete"|"drop_only",
  snapshot_seq: <u64> }`. `snapshot_seq` is the run's `ledger_seq` at the
  counter clone (section 2.2). The counters are the only fields the identities
  in section 7.2.2 apply to. Do not duplicate the capability there. If a later
  schema duplicates it, the copy must carry the same `snapshot_seq` and be
  documented as a copy, not as a second source of truth.
- **Cross-endpoint coherence is not claimed.** A status runtime state and a
  diagnostics counter set can come from different instants. The ledger identity
  is exact only within one diagnostics snapshot and after the barrier seals. A
  UI must not combine `runtime.encrypted_dns_coverage = active` from status with
  counters from a different diagnostics request and present them as one
  snapshot.
- **Missing keys are hidden, not promoted.** A missing capability key hides the
  row. A missing `runtime` object shows no coverage row. A missing counter shows
  "not reported" and the UI must not claim the ledger identity. A missing
  `ledger.exact` is not `true`.
- **No consumer infers a state from another field.** `mode`, a cargo feature,
  `engine: true`, or a DoH build never stand in for a missing capability or
  coverage key.

### 2.6 Plaintext counter and default UI: separate acceptance

`dns_plaintext_profile_queries` and a default "DNS is not private" state are a
**new telemetry and UI scope**, not a free part of the DoH forwarder. The
default `off` profile currently shows no such counter and no such warning.
Adding either changes what every default run reports.

Rules:

- The DoH scope acceptance in section 4.1.1 does not approve this counter or
  the default warning. They need a separate acceptance that names the default
  behavior change, the storage, and every consumer in section 2.5.
- Until that acceptance, `dns_plaintext_profile_queries` is absent or zero and
  the default UI is unchanged. A DoH-profile run may count plaintext queries
  only when a person selected the labeled plaintext profile, and that count is
  part of the DoH scope.
- The counter never implies a fallback. A DoH failure never increments it.
- A build with no DoH code path shows the current text. It does not gain a new
  warning.

## 3. The three viable client boundaries

### 3.1 App-native ECH through system DNS and HTTPS/SVCB

This is real ECH when all of the following hold:

1. The application implements ECH and the server publishes an `ech` SvcParam
   in an HTTPS or SVCB record (RFC 9848 section 3).
2. The application obtains that record. `getaddrinfo` does not return SVCB or
   HTTPS records on macOS, Windows, or Linux. The application must query type
   64 or 65 itself, or use an operating-system API that exposes the records.
   Examples are `DNSServiceQueryRecord` on macOS, `DnsQueryEx` on Windows, and
   `res_query` on Linux. Those queries go to the configured stub resolver, and
   the tunnel can forward them if they enter it. An application that uses only
   `getaddrinfo` cannot get a config this way.
3. The application treats the record as SVCB-reliant when every alternative
   endpoint publishes `ech` (RFC 9848 section 5.1). Otherwise it can fall back
   to a non-ECH endpoint.
4. The application does not use its own resolver in a way that bypasses the
   tunnel.

The engine's role is limited to:

- encrypting the DNS query that carries the HTTPS/SVCB record, if that query
  enters the tunnel;
- forwarding type 64 and 65 records byte for byte;
- not stripping the `ech` SvcParam, not rewriting the QNAME, and not filtering
  QTYPEs;
- not claiming that any of this made the application use ECH.

The limits are decisive:

- Many applications cannot see HTTPS records through the system resolver.
- ECH deployment is not universal. A site without an `ech` record cannot use
  ECH.
- An application that uses its own DoH gets its records from its own resolver.
  The engine neither helps nor hurts.
- An application that falls back to a non-ECH endpoint loses the benefit. The
  engine cannot enforce SVCB-reliant behavior.
- An observer can block HTTPS/SVCB resolution. RFC 9848 section 8 describes
  that downgrade. The engine cannot prove the application detected it.

Conclusion: app-native ECH is viable for some applications. It is not a
product capability and must not be counted as one. The honest status is
`app-dependent`.

### 3.2 An explicit product-owned TLS client

This is the only path that gives the product control over application ECH
without termination. It is a new client surface, not a tunnel feature.

Viable forms:

1. **A product-owned fetch or browser surface.** The product is the
   application. ECH is real; coverage is that surface only.
2. **An explicit local stream API or SDK.** An application deliberately hands
   the product a destination name, port, ALPN, and a byte stream, and receives
   plaintext bytes back. The product validates the origin certificate, builds
   the ClientHello, uses ECH, and carries the application bytes inside TLS.

What it must not be:

- Not a transparent SOCKS or HTTP `CONNECT` proxy. A SOCKS client expects a
  byte stream to the origin. If the product terminates TLS and hands plaintext
  through SOCKS, the application believes it is talking TLS when it is not.
  That is a semantic and security bug.
- Not a local CA. There is no certificate minting and no trust-store change.
- Not a TLS terminator for applications that did not ask for it. That is
  `terminate`, out of scope.
- Not a shared TLS connection for many application streams. One application
  stream maps to one TLS connection.

Security properties and costs:

- The product validates the origin certificate. There is no CA and no change to
  the system trust store.
- Application-level certificate pinning is not available unless the API adds a
  pin policy. The product's validation replaces the application's validation
  for that connection. This must be explicit in the API contract.
- Client certificates need a separate design. Do not copy an application's
  private key into the product.
- The TLS fingerprint becomes the product client's fingerprint for those
  flows. That is visible and must be disclosed.
- The local API carries plaintext. Bind it to `127.0.0.1`, authenticate every
  connection with a per-install token, cap connections and frame sizes, and
  never expose it to the network.
- The API must not resolve names through `getaddrinfo`. It uses DoH or a
  configured literal. The destination name is the TLS name and the ECH inner
  name.
- TLS 1.3 only. No resumption in the outer hello. No early data. No HTTP/2
  multiplexing across application streams.
- ECH policy: fail closed when a config exists and the server rejects ECH. A
  caller that wants a non-ECH flow selects a labeled non-ECH profile before
  connecting. The client never switches a live connection or a profile to
  non-ECH because of a failure. A silent retry would reveal the name and
  defeat the mode.

Integration tradeoffs:

- Applications must adopt the API or SDK. Browsers and existing applications
  will not use it without changes.
- The API is a new product surface with versioning, packaging, and support
  cost.
- Coverage is a list of adopting clients, not "all traffic".
- It changes the product shape. It is not a tunnel toggle.

Decision: this is the only complete path to product-controlled application
ECH. It is out of scope for WS1 and is not implemented. It is a separate
optional future proposal, not a pending decision that blocks this workstream.
`hide` stays `unsupported` under the current constraints whether or not that
proposal is ever made. A future proposal would need its own product decision and
review, and it must not terminate TLS or add an external relay.

### 3.3 Platform or operating-system TLS

Some platforms may add ECH to their TLS stack. If an application uses that
stack and the platform enables ECH, the application may get ECH without the
product. This is a hypothesis for the targets in scope:

- Windows Schannel ECH support varies by Windows version and is not verified in
  this tree.
- macOS and iOS platform TLS ECH support is not verified in this tree.
- Linux has no single platform TLS stack.

The product cannot configure, observe, or count this reliably. Report no
capability for it. Do not use `unverified` or `unknown` to imply that the
platform might provide it. Do not build a matrix row from a vendor blog post.
Verify headers, builds, and a live handshake before any claim.

### 3.4 Rejected designs

| Design | Verdict | Reason |
|---|---|---|
| Wrap the application stream in a second TLS session | Impossible | The origin expects a ClientHello, not TLS records. It is TLS-in-TLS to the same endpoint and fails. It adds the nested-handshake shape the plan avoids |
| Rewrite the SNI in the relay | Impossible | The ClientHello is covered by the transcript hash (RFC 8446 section 4.4.1). One changed byte breaks the server `Finished` |
| Splice an ECH extension into the application ClientHello | Impossible | ECH requires HPKE to the server's ECH key and a matching inner transcript. The relay has neither |
| Inject an `ech` SvcParam into DNS answers | Impossible and dishonest | The public key belongs to the origin's client-facing server. An injected config names a key the origin does not hold |
| Terminate application TLS with a local CA | Out of scope | No CA, breaks pinning, two TLS sessions, changes the client identity. This is `terminate` |
| Source device terminates TLS | Out of scope | Same CA and pinning costs, plus a phone-shaped fingerprint for desktop traffic |
| Relabel DoH as `hide` | Rejected | It does not meet the application ECH requirement. This is the revision 1 error |
| Count a ClientHello ECH extension as application ECH | Rejected | GREASE uses the same extension. Section 5.4 |
| Hook or interpose another process's TLS library to rewrite its ClientHello | Rejected | It is platform-specific, fragile, often blocked by code signing or system integrity protection, and behaves like a local man-in-the-middle. It is not a supported client boundary and cannot be a product claim |
| Set a system-wide ECH policy | No such general API | No verified target API. Do not invent one |

## 4. DNS architecture

### 4.1 Why DNS is a separate capability

DoH changes the transport of DNS queries that the tunnel carries. It does not
change any application TLS handshake. It is useful on its own, and it is a
prerequisite for app-native ECH. It is not `hide`.

The DoH resolver is a DNS destination, not a relay for user traffic. It adds no
hop to application flows. It does not violate the no-external-relay invariant.
It does shift DNS trust from every network on the path to the configured
resolver. The resolver sees the client's address and every QNAME it answers;
that is the trust cost. If the resolver and the destination are the same
provider, that provider can correlate the two. State this plainly. DoH does not
hide the query from the resolver, and it does not hide the destination IP or
ASN from the carrier.

DoH is opt-in and off by default. No start enables it automatically. A profile
is either DoH or plaintext before the tunnel starts. A profile with no
configured endpoint runs the plaintext DNS path. Its label, counter, and warning
are part of the separate acceptance in section 2.6; the default `off` profile
does not gain them here. A DoH failure never switches a query, a flow, or a
profile to plaintext. Do not infer consent from a previous session, from a
carrier name, or from a failed connection.

#### 4.1.1 Proposed scope and tradeoffs

The tunnel-wide forwarder in this section is a **proposed independent scope**.
It is not approved, not requested as part of the current goal, and not
implemented. It is separate from application ECH, which is closed.

Tradeoffs that the scope acceptance must record:

- It captures inner UDP:53 and TCP:53, adds a loopback adapter, a bounded
  thread pool, a completion path, and edits to `relay.rs`.
- It trusts a configured third-party resolver with the client's address and
  every QNAME it answers. A resolver that is also the destination provider can
  correlate the two. This is a resolver substitution. The product already makes
  two kinds of resolver substitution today (a built-in redirect in source
  device proxy mode and explicit person-set servers in direct mode); section
  4.1.2 records them, the product-owner decision, and the invariant amendment
  the DoH profile needs.
- On a default hotspot it may cover almost no system-resolver queries, because
  the gateway query and a link-bound resolver can bypass the tunnel. The
  coverage is measured per platform, not assumed.
- It adds a new TLS client and a new HTTP parser to the engine, plus two
  non-default cargo features. It does not add a relay hop for application
  traffic, and it does not change the no-external-relay invariant.

Its review gate is separate from application ECH: scope acceptance that records
those tradeoffs, this design review, the test matrix, and a live measurement.
If the scope is not accepted, none of the code is written and DNS stays on the
labeled plaintext path.

#### 4.1.2 Resolver substitution, the product-owner decision, and the invariant amendment

The configured DoH endpoint is a third-party resolver. It is not the hotspot's
DNS server, not the source device, and not a resolver the operating system chose
for the selected link. Sending tunneled queries to it changes who can read every
QNAME and which client address that party sees. That is a product decision about
DNS trust. It is not a technical default and it is not approved here.

**What the current tree says.** Revision 8 quoted invariant 4 as if the
resolver sentence were committed project policy, and it said no build ships a
built-in public resolver. Both statements were wrong for the current tree.
Verified in this tree:

| Source | State | Text or behavior |
|---|---|---|
| `AGENTS.md` invariant 4 at `HEAD` | Committed | Tun mode forwards inner UDP:53 "to the original destination or to `--dns-upstream` over a normalized socket". SOCKS5 mode uses `TinyResolver`. Never call `getaddrinfo()` on an egress path. It has no resolver-substitution sentence |
| `AGENTS.md` invariant 4 in the working tree | Uncommitted change | Adds "Resolver selection must be tied to the pinned interface; do not substitute a public resolver." The same paragraph then describes macOS `scutil` discovery and the Linux explicit `--dns-servers` list, and says "An explicit server can still be wrong for that link; the person who names it accepts that choice." Read in place, the sentence governs resolver discovery for the pinned interface. Whether it also governs every tun DNS path is not stated |
| `rust/src/relay.rs` `Relay::new_udp`, phone branch | Committed (at `HEAD` and in the working tree) | In source device proxy mode every captured inner UDP:53 flow is sent as DNS over TCP to `1.1.1.1:53` through the source device. The destination the client chose is ignored. The relay rejects `dns_upstream` in that mode. This is a built-in public resolver chosen automatically by a shipped mode |
| `docs/TECHNICAL_REFERENCE.md` and `PHONE_PROXY.md` | Committed | Document the `1.1.1.1:53` redirect. The technical reference troubleshooting row says "Try `--dns-upstream 1.1.1.1`" |
| `README.md` line 88 | Uncommitted change | Recommends `hotspotshade socks5 --dns-servers 1.1.1.1,8.8.8.8` and says Linux needs it |
| `--dns-upstream` in direct tun mode | Committed | A person-set numeric IPv4 resolver replaces the original destination of every inner UDP:53 query (`rust/src/relay.rs`, `rust/src/main.rs`) |

**Analysis.** This is analysis, not a decision.

1. The product already substitutes resolvers in two forms. Source device proxy
   mode substitutes a built-in public resolver with no person choice. Direct
   tun mode and SOCKS5 mode accept a resolver that a person names. Revision 8's
   statement that "no build may ship a built-in public resolver" was a
   description of a rule that the shipped code does not follow. It is withdrawn
   as a description of the product. Section 4.1.2 now states it only as a
   proposed rule for the DoH profile (item 5 below).
2. Whether the existing `1.1.1.1:53` redirect conflicts with invariant 4 is
   undetermined. The committed invariant does not address it. The uncommitted
   sentence would conflict with it if the sentence governs every tun DNS path,
   and would not if it governs only interface resolver discovery. The redirect
   predates the sentence. This design does not decide the question and does not
   change the redirect. It is owner question Q1.
3. On the trust axis, an explicit DoH endpoint is the same kind of choice as an
   explicit `--dns-upstream`: a person names a resolver, and that resolver sees
   every QNAME and the address that reaches it. In direct mode that address is
   the source device's carrier address after its NAT; in source device proxy
   mode it is the source device's cellular address, as for the `1.1.1.1`
   redirect. The differences are elsewhere: DoH hides QNAMEs from the hotspot
   link and the carrier, captures TCP:53 as well as UDP:53, needs an endpoint
   name for certificate checks plus a pinned bootstrap address (section 4.5),
   and adds a TLS client, an HTTP parser, and a loopback adapter. So the DoH
   profile does not introduce resolver substitution to the product. It
   introduces a new transport and a new code surface for it. Whether the owner
   wants a stricter rule for DoH than for `--dns-upstream` is owner question
   Q2.
4. A tunnel-wide DoH forwarder to a configured resolver is still a resolver
   substitution under either reading of the uncommitted sentence, so an
   explicit decision and amendment are still required before any DoH code.
   That conclusion from revision 8 stands. The reason given for it changes: it
   is required because the DoH profile is a new product scope that substitutes
   the resolver for all captured DNS, not because the product has never
   substituted one.

**Decision record required from the product owner.** None of these is
answered here.

- **Q1. The existing redirect.** Does the source device proxy mode redirect to
  `1.1.1.1:53` conflict with invariant 4 as the owner intends it? If yes, it
  is an existing gap to record and track outside WS1. WS1 does not fix it and
  must not describe it as fixed. If no, the amendment should say why a built-in
  redirect is allowed in that mode.
- **Q2. Explicit DoH versus explicit `--dns-upstream`.** Is an explicit DoH
  endpoint governed by the same rule as an explicit `--dns-upstream` or
  `--dns-servers` value, or by a stricter one? This design's position is that
  they are the same trust class with a different transport. The owner may
  still choose a stricter rule.
- **Q3. Amendment text.** What exactly does the amendment permit? At least:
  an opt-in DoH profile, off by default; an endpoint set explicitly by a person
  as a name plus a pinned bootstrap address; no built-in, automatic, or
  fallback DoH endpoint; whether the DoH profile in source device proxy mode
  replaces the `1.1.1.1:53` redirect for captured DNS while the profile is
  active (this design proposes that it does, section 6.2); the coverage limits
  in section 4.1.1; and the statement that the chosen resolver sees every
  QNAME and the address that reaches it.
- **Q4. Order of changes.** Is the uncommitted invariant 4 change committed,
  revised, or withdrawn before the DoH amendment? The amendment must be
  written against the committed text.
- **Q5. Plan reading.** If the plan is read to require the network resolver,
  the plan's WS1 scope text or its invariant 4 needs the same amendment. This
  document does not decide which reading is correct.

Rules this design keeps:

1. A product owner must decide, in writing, Q1 to Q5 and whether HotspotShade
   may forward captured DNS to a configured third-party DoH resolver, and must
   accept the trust cost in section 4.1.1.
2. An explicit amendment to `AGENTS.md` invariant 4 must land before any DoH
   code is written.
3. This design does not assert that the amendment is approved, that the current
   or uncommitted invariant already permits the forwarder, that the existing
   redirect is compatible or incompatible with it, or that the DoH scope is
   approved. None of those is established here.
4. This design does not change the source device proxy mode redirect, the
   `--dns-upstream` option, the `--dns-servers` option, or any project
   invariant. WS1 makes no invariant change.
5. **Proposed rule for the DoH profile only.** The DoH profile ships no
   built-in DoH endpoint, chooses none automatically, and never falls back to
   a public resolver, to the `1.1.1.1:53` redirect, or to plaintext when the
   configured endpoint fails. The endpoint is set explicitly by a person. This
   rule describes the proposed DoH profile. It is not a description of the
   existing modes and does not constrain them.
6. Until the decision and the amendment exist, the design remains a proposal.
   `encrypted_dns` stays `unverified` or `unsupported`; no query is forwarded
   by a DoH path.

This subsection is a record of a required decision. It is not a claim that the
decision was made, that the invariant is compatible, or that a review approved
the scope.

### 4.2 What the tunnel sees, and what bypasses it

Verified in this tree:

- macOS installs `0.0.0.0/1`, `128.0.0.0/1`, and, when IPv6 is forwarded,
  `2000::/3` (`rust/src/platform.rs`). The tunnel is not fail-closed. A
  more-specific route on another interface wins.
- Windows installs the same IPv4 `/1` routes and the IPv6 `2000::/3` route
  through Wintun (`rust/src/windows_native_routes.rs`). The route verifier
  explicitly says a more-specific route, a local DNS answer, link-local,
  multicast, and NAT64 are not covered
  (`rust/src/windows_route_verify.rs`).
- Linux installs two IPv4 `/1` routes in table 700, policy rules, and one IPv6
  route. Direct mode block is a reduction of the IPv6 path, not a complete
  block.
- Source device proxy mode forwards IPv6 through the source device. Direct mode
  defaults to block.
- The macOS per-interface resolver discovery runs `/usr/sbin/scutil --dns` and
  accepts only an unambiguous scoped block for the selected interface. It
  rejects a full VPN or split-DNS resolver, an mDNS resolver, a loopback stub,
  and a link-local address (`rust/src/environment.rs`
  `dns_for_interface_from_scutil`). That path is used by SOCKS5 mode, not by
  the tun DNS forwarder.
- Linux `system_dns_for_interface` fails closed. `/etc/resolv.conf` and the
  systemd-resolved upstream file are one aggregate list that does not prove
  which link a server belongs to, so the caller must pass an explicit
  `--dns-servers` list. The list is bounded to 8 numeric servers, validated,
  and deduplicated (`rust/src/dns.rs` `MAX_EXPLICIT_SERVERS`,
  `validate_servers`, `parse_server_list`). `system_dns()` remains a
  diagnostics-only aggregate and must not be used as an egress resolver. A
  loopback server is a local stub, so a production start rejects it; the
  loopback test seam is compiled only for unit tests.
- An explicit server can still be wrong for that link, and a resolver that
  binds its own socket to the physical interface can bypass the tunnel. The
  person who names the server accepts the first choice; the second is a
  documented bypass (section 4.3).
- Windows has no system DNS discovery in this tree; `environment::system_dns`
  and `system_dns_for_interface` return `Unsupported` there. The SOCKS5 start
  path is Unix-only, so this does not gate a Windows feature in this tree.

The DoH forwarder intercepts by inner destination port 53, not by the inner
resolver address. If a DNS packet enters the tunnel, the forwarder can send it
to DoH regardless of whether the inner destination was the gateway, a public
resolver, or another address. That is a strength. It does not cover packets
that never enter the tunnel.

The gateway case is platform-specific, and revision 3 got it wrong for macOS
and Windows. Do not repeat the claim that a gateway query enters under the `/1`
routes on those platforms.

- **macOS.** The hotspot's connected-subnet route is more specific than the two
  `/1` routes, so a packet addressed to the DHCP gateway follows the local
  route to the physical interface. The start path adds no host route for the
  gateway (`rust/src/platform.rs`). The route specificity makes gateway DNS a
  **bypass by inference**, not a measured DNS result. The repo's live record
  says that DNS addressed to the hotspot gateway can use its existing local
  route, and that in the 2026-11-02 live test "the hotspot gateway route
  bypassed the tunnel". That record does not identify the operating system and
  does not show a DNS query to the gateway. It is consistent with the
  inference, not proof of the DNS case. Do not call it live DNS evidence.
- **Windows.** The same connected-subnet specificity applies. The start path
  installs only the two IPv4 `/1` routes and the IPv6 `2000::/3` route
  (`rust/src/windows_native_routes.rs`); it adds no host route for the gateway.
  The route verifier says a more-specific route and a local DNS answer are not
  covered (`rust/src/windows_route_verify.rs`). Gateway DNS is a **bypass by
  route-shape inference** with no live record at all.
- **Linux.** Rule 17001 is `lookup TUNNEL_TABLE` with no
  `suppress_prefixlength`, and table 700 holds the `/1` routes. Rule 17000 is
  `oif <physical> lookup main` (`rust/src/platform_linux.rs`). A gateway query
  enters the tunnel under rule 17001 only if the resolver socket is not bound to
  the physical interface. On a default desktop, `systemd-resolved` per-link
  servers may bind to the link, which takes rule 17000 and table main. That is a
  hypothesis, not a verified tree fact. If it holds, gateway DNS on Linux is a
  bypass too. Treat the default system-resolver path as a likely bypass on all
  three desktops until a live DNS-specific run measures it.
- **Source device proxy mode.** On all three platforms the gateway is also the
  source device proxy address. A host route for that address would have to
  coexist with the pairing listener on TCP 18090, the presence probe, captive
  portals, and the pinned proxy socket. This design does not add one. The old
  claim that a host route "would change the path of the pinned proxy socket" is
  unverified: pinning uses interface binding, so macOS and Linux may not change
  that path. The real risks are the control-plane flows and platform route
  behavior. Record a gateway host route as an open option with those risks
  (U33), not as a rejected design.
- **IPv6 link-local.** A query to `fe80::` does not enter the tunnel on any
  platform. It is a plaintext bypass.

Effect: when the hotspot gateway is the DNS server, the common default-resolver
setup is a bypass **by route-specificity inference** on macOS and Windows and a
likely bypass on Linux when the default resolver binds per link. On a default
hotspot the forwarder likely covers almost no system-resolver queries, not
merely little.
No live DNS-specific result exists for any target. The 2026-11-02 record names
no operating system and does not show the DNS case. The capability therefore
stays `unverified` until a live DNS-specific run on that platform. A read-only
detector can report the gateway category. It cannot move the query, and this
workstream does not add a host route.

The default desktop resolver may also bind its query to the physical link,
which would skip the tunnel. This remains a hypothesis until a live run
measures it:

- `systemd-resolved` per-link servers and macOS `mDNSResponder` may bind that
  way. This is not verified in this tree.
- If the default resolver uses that path, the main DNS path is a likely bypass
  on that desktop, not only a Linux case. The capability must stay `unverified`
  until the live run, and the UI must show the coverage state.

### 4.3 DNS bypass table

"Covered" means the query is inside DoH **if the packet enters the tunnel**.
"Bypass" means the engine never sees it.

| Path | Enters the tunnel | Covered by DoH | What to do |
|---|---|---|---|
| IPv4 DNS to the DHCP gateway on macOS or Windows | **No.** The connected-subnet route is more specific than the `/1` routes. The macOS record reports a gateway route bypass but names no OS and does not show the DNS case; Windows has no live record | No, by route-specificity inference. This is not a measured DNS result | Report the gateway bypass category. Do not add a host route. Show a bypass coverage state; the capability value does not change per profile |
| IPv4 DNS to the DHCP gateway on Linux | Enters under rule 17001 and table 700 only if the resolver socket is not bound to the physical interface. A default `systemd-resolved` per-link socket likely takes rule 17000 and table main | Likely bypass on a default resolver; `unverified` until a live run | Measure the default resolver. Do not add `suppress_prefixlength` in this workstream |
| IPv4 DNS to a public resolver | Yes under the `/1` routes when the socket is not bound to the physical link. Likely bypass on a default desktop resolver that binds per link | `unverified` until a live run | Measure the default resolver on each desktop before any `supported` claim |
| DNS on a non-standard port (not 53) | The engine does not classify it as DNS | No | Document. Do not parse arbitrary UDP or TCP payloads to guess |
| TCP:53 before the DoH adapter exists | Yes, but plaintext today | No | Implement the TCP:53 adapter in section 4.8 |
| IPv4 DNS to `169.254.0.0/16` | Not guaranteed; a link-local route can be more specific | Not guaranteed | Detect the risk, report a boolean, do not override |
| IPv6 DNS to a global address in `2000::/3` | Yes only in forward mode, in source device proxy mode, or when a direct-mode diagnostic is explicit. In direct block mode the inner packet is dropped before any DoH attempt | Yes in forward/proxy and only when the DoH endpoint is IPv4 or IPv6 forwarding is active. No DoH attempt in block mode | Keep the policy explicit. An IPv6 DoH endpoint is rejected in direct block mode (section 6.3) |
| IPv6 DNS to `fe80::/10` (link-local) | No. The physical interface owns the link-local route | No | This is a plaintext bypass. Detect, document, do not claim universal DNS privacy |
| IPv6 ULA `fc00::/7`, multicast `ff00::/8`, NAT64 `64:ff9b::/96` | No | No | Same as link-local. Document |
| macOS scoped resolver or `mDNSResponder` path bound to the physical interface | Not guaranteed | Not guaranteed | Detect scoped resolvers read-only. Do not override in this workstream |
| Windows NRPT rule, per-interface DNS, or smart multi-homed name resolution | Not guaranteed | Not guaranteed | Detect the configuration. Do not override |
| Linux `systemd-resolved` stub on `127.0.0.53` | The stub is local; its upstream query may or may not follow the tunnel | Not guaranteed | Document. Do not claim the stub is covered |
| Application DoH or DoT | No | No; already encrypted outside this policy | Count TCP/UDP port 853 as "port 853", not "DoT". DoH on 443 is indistinguishable; do not count |
| Operating-system DoH or DoT | No | No; outside this policy | Report no capability. Do not claim |
| Cached answers in the OS, browser, resolver, or CDN, plus app connection reuse and TLS tickets | No query | No | Document that the mode is not retroactive. Do not flush automatically |
| Application resolves before the tunnel or uses a cached address | No | No | Documented leak. Do not describe it as fixed |
| Captive portal DNS | May be redirected before the tunnel | DoH likely fails | Return a clear failure. Do not switch to plaintext inside the query. A person may select the labeled plaintext profile before the next start |

The bypass rows are the reason the UI must say "tunneled DNS queries", not "all
DNS". The mode cannot be described as fail-closed.

### 4.4 Resolver override and cleanup

A host resolver override is the only way to move scoped, link-local, and
system-stub queries onto the tunnel. It is not in this workstream.

Why not now:

- It is host-global and persistent. A crash can leave the host unable to
  resolve names.
- It affects other networks and other users of the host.
- It needs privilege and a service or helper. The project has no Windows
  service and no verified macOS Network Extension.
- It can break captive portals, VPN split DNS, and corporate policy.
- It conflicts with the no-persistent-proxy rule and with route cleanup that
  must be safe on every exit path.
- It still does not cover applications with their own DoH, DoT, or DoQ.

Safe design, if the owner ever asks for it:

1. Use a platform mechanism that is scoped and reversible: a macOS Network
   Extension DNS proxy, a Windows NRPT rule managed by a service, or
   `systemd-resolved` per-link DNS. Do not use a global `networksetup` or
   `resolv.conf` edit as the primary mechanism.
2. Write a journal before the change. The journal holds the prior per-interface
   servers, the owner instance, and a timestamp.
3. On start, detect a stale journal and restore the prior state before applying
   a new one.
4. Restore on normal stop, on helper exit, and on uninstall.
5. Bound the override lifetime and require a person to re-enable it.
6. Test crash, reboot, network change, captive portal, and uninstall. A test
   that only stops cleanly is not enough.
7. Label the state while it is active. A direct query that bypasses the
   override must be reported as a bypass, not hidden.

Decision: no override in WS1. The bypass is documented and detected as a
boolean or category, never as a name. A future override is a separate
workstream with its own review.

### 4.5 DoH endpoint and trusted bootstrap

The endpoint is a configured four-tuple:

```
DohEndpoint {
    name: DnsName,      // TLS ServerName and ECH inner name; not an IP literal
    ip: IpAddr,         // numeric transport address; no getaddrinfo
    port: u16,          // default 443
    path: String,       // starts with '/', no CRLF, no redirect
}
```

Rules:

- `name` must be a valid DNS name. Reject an IP literal, an empty name, a name
  over 253 bytes, and a name with an empty label.
- `ip` must be a unicast address. Reject unspecified, multicast, and
  link-local. Reject loopback except in tests.
- `path` is configured, not discovered. A 3xx response is a failure. RFC 8484
  section 3 forbids using a different URI discovered outside the
  configuration.
- The IP literal removes the bootstrap loop and keeps `getaddrinfo` off the
  egress path. RFC 8484 section 10 lists an IP-based URI plus HTTPS
  authentication as a valid bootstrap strategy.
- TLS validates `name` against a compiled trust store (`webpki-roots`). The
  egress path never calls an OS trust API. A corporate or self-hosted resolver
  behind a private CA is out of scope. If it is added later, it must be an
  explicit SPKI pin for a configured endpoint, never a disable-verification
  switch, and it needs its own tests.
- The first connection is necessarily non-ECH. It is the trust bootstrap. It
  carries the DNS query inside TLS, and the resolver name is the configured
  static name. This is not a silent downgrade. RFC 9848 section 5.3 says an
  ECH-capable client must not send a ClientHello before SVCB resolution
  completes. That rule assumes a resolver is already available. For the DoH
  resolver's own name, the first connection is the bootstrap. Only the
  resolver's ECH is absent; the query payload is still encrypted.
- Fetch the endpoint's own HTTPS RR (QTYPE 65) over that authenticated
  connection. Accept an `ech` SvcParam only for the exact owner name. Do not
  follow a CNAME or alias for the ECH config. Do not accept a config from the
  system resolver, from a cache, or from any other response.
- Reject an `ech` config whose `public_name` is not a valid host name, whose
  KEM is unsupported, whose list is empty, whose list exceeds the bound, or
  whose mandatory extension is unknown.
- The configured endpoint is not a secret, but it must not be echoed by
  `/api/status`, diagnostics, probe output, logs, or failures. Report a boolean
  and counters only.
- DoH and the plaintext `--dns-upstream` option are mutually exclusive. Reject
  a start that sets both. Source device proxy mode already rejects
  `--dns-upstream`; it must accept the DoH option instead.
- A start in direct block mode with an IPv6 DoH endpoint is rejected. A start
  with `--no-routes` and DoH is allowed only as a diagnostic; the UI must say
  that tunneled DNS coverage is not guaranteed.

### 4.6 HTTP/1.1 client

RFC 8484 section 5.2 recommends HTTP/2 as the minimum recommended version. It
does not require it, and it says earlier HTTP versions can convey the
semantics. DoH servers must accept POST and GET and must use
`application/dns-message`.

Use HTTP/1.1 POST over TLS 1.3 with ALPN `http/1.1` required. Do not adopt
`hickory-resolver`, `h2`, or any HTTP client with its own TLS stack. The engine
has no async runtime and one POST per query does not justify an HTTP/2 stack.

Request rules:

- `POST` to the configured path.
- `Host` is the configured `name`. Do not use an IP-literal Host with a
  different TLS name.
- `Content-Type: application/dns-message`.
- `Accept: application/dns-message`.
- `Content-Length` is the exact DNS message length. No chunked request.
- No cookies, no authorization, no proxy, no `Expect`, no `Upgrade`, no
  compression.
- One request at a time per connection. No pipelining.

Response parser bounds:

| Item | Bound or rule |
|---|---|
| Status line | At most 256 bytes. HTTP/1.1 only. Accept 200 only |
| Header block | At most 8192 bytes |
| Header count | At most 64 |
| Header line | At most 4096 bytes |
| Line ending | CRLF only. No bare LF, no obs-fold, no NUL |
| `Content-Length` | One value, at most 65535 |
| `Transfer-Encoding` | `chunked` only, and never with `Content-Length` |
| `Content-Type` | Base type `application/dns-message`; parameters are ignored |
| `Content-Encoding` | Absent or `identity`. Anything else is a failure |
| `Connection` | `close` is handled. Keep-alive is the default |
| Body | At most 65535 bytes. Chunked total is bounded. Chunk count at most 1024. Chunk extension at most 256 bytes |
| Trailers | Reject. The parser does not need them |
| 1xx, 101, 204, 3xx | Failure. No retry, no redirect, no protocol upgrade |
| Extra bytes after the body | Failure. Close the connection |

The response body must be a DNS message of at least 12 bytes. The parser does
not need to understand the answer; it forwards the bytes. A malformed response
is a failure, not a partial answer.

Timeouts: one absolute deadline covers slot wait, queue wait, connect, TLS,
request, and response. The deadline starts when the owner first sees the work
item (the UDP packet in the shard, or the adapter admission request), not when a
pool thread starts it and not when a session slot is granted. The default is 5
seconds, with a maximum of 8 seconds to match the existing `DNS_TIMEOUT`
(`rust/src/relay.rs`). A per-read timeout must not extend the total. If a job
waits for a session slot or in the queue past its deadline, the owner records
`doh_timeout` and never opens a socket. The blocking driver checks the stop flag
and the absolute deadline every 200 milliseconds. On timeout, the query fails;
it does not retry and does not fall back to plaintext. The ECH-config fetch uses
the same admission-based deadline. A config fetch that misses its deadline is a
`doh_failed` for that fetch and loses L2 only; it never causes a plaintext
query.

### 4.7 DNS message handling

The engine is a forwarder, not a resolver.

- Forward the entire DNS message unchanged: ID, QNAME case, EDNS(0) OPT, DO
  bit, cookies, padding, and unknown options.
- Do not cache answers. The resolver may cache; the engine does not.
- Do not filter QTYPE. Type 64 (SVCB) and type 65 (HTTPS) must pass. This is the
  only way an app that queries them through the tunnel can learn an ECH config.
- Do not rewrite the transaction ID or the QNAME. DoH correlates the HTTP
  request and response; the DNS ID is not a privacy leak inside TLS. Record
  the deviation from the RFC 8484 "SHOULD use ID 0" guidance.
- Check that a response has QR=1 and the same transaction ID as the query
  before returning it to an inner UDP client, as the existing phone DNS path
  does. A mismatch is dropped and counted. The check reads the first four
  bytes; it does not parse the name. The TCP:53 adapter checks the same before
  framing a response.
- Do not validate DNSSEC. Pass the AD bit and every DNSSEC record through. Do
  not claim validation.
- Do not synthesize an answer for a failure, including SERVFAIL. On failure,
  drop the UDP query or close the TCP connection. The client times out or
  retries. The one allowed synthesis is a truncated response with TC set and
  the question section only; it is not an answer and it never contains a
  partial answer.

UDP response sizing:

- Read the inner query's EDNS UDP payload size. Default to 512 when OPT is
  absent.
- Cap the inner response at the smaller of that value and the inner datagram
  limit. The relay uses `MAX_DATAGRAM = 1472` (`rust/src/relay.rs`).
- If the answer does not fit, return a proper truncated response: the header
  with TC set and the question section only. Parse the question with a bounded
  parser. If the question cannot be parsed, drop.
- Never return a partial answer and never silently drop a large answer without
  TC. The client can then retry over TCP:53, and the TCP path is covered.

### 4.8 TCP:53 and DNSSEC

Today only UDP:53 is redirected in source device proxy mode. Direct mode
forwards UDP:53 in plaintext. TCP:53 goes through the normal TCP path to the
real resolver in plaintext in both modes (`rust/src/relay.rs`). Large answers,
DNSSEC, and TC retries therefore bypass DoH. A DoH claim without TCP:53 would
be false.

Use a loopback adapter for the first implementation, with access control in
section 6.6. The adapter speaks the 2-byte length framing of DNS over TCP, but
it is **not** the job owner and it never submits a job to the pool or writes a
counter. The relay knows which shard owns the inner TCP flow, because
`shard(key, workers)` in `rust/src/relay.rs` is deterministic. The relay writes
that shard index and a connection ID into the local 32-byte preface. The shard
assigns the session generation at admission; the adapter does not need it and
must not receive it. The adapter sends each complete frame as an
`AdapterAdmission { connection_id, request_id, preface, frame }` to that
shard's admission path under the credit rule in section 6.6. The shard admits
the query, assigns the job ID, reserves two attempt work items, a completion
slot, and one disposition slot, and submits the first attempt.

The adapter receives no raw pool completion. It receives exactly one
`AdapterDisposition` per accepted query, either `Answer { connection_id,
request_id, job_id, session_generation, bytes }` after the shard recorded a
successful terminal outcome, or `Close { connection_id, request_id, job_id,
cause }` after a failed one. The adapter applies dispositions per connection in
`request_id` order (section 6.6). It writes each answer in that order. A close
is graceful: the adapter stops reading new frames, writes every earlier
disposition, and then closes the inner connection. It never leaves a failed
query open until the idle timer. The adapter never drops an `Answer` because a
later job on the same session committed: `session_generation` names the session
incarnation and does not change while the session lives (section 6.2). A second
disposition for a `job_id` that already has one is impossible by reservation; a
test that injects one sees it dropped with a test-only diagnostic and no counter
change. A committed answer that is not written, because the inner client closed
or the stop flush deadline passed, counts once in `doh_adapter_errors`; it does
not retract the query outcome (section 6.4).

The owning shard is the accounting owner for the query. The adapter never
writes a DoH counter and never invents an answer. The inner TCP endpoint,
windowing, FIN, and abort logic are unchanged.

Rules:

- 2-byte big-endian length; message length 12 to 65535.
- Multiple queries on one connection are allowed. Process FIFO. A slow query
  delays only later queries on the same inner flow.
- Preserve response order. RFC 7766 allows out-of-order responses; serializing
  is allowed and simpler.
- A partial frame waits within the idle deadline. A half-close after a complete
  query is answered and then closed. A half-close in the middle of a frame
  fails.
- No answer synthesis. On DoH failure, close the inner connection after the
  earlier dispositions on it are written. The client sees a closed connection,
  not a fake answer. An earlier query on the same connection is not cancelled
  by a later query's failure. Answering a failed query locally with SERVFAIL
  would keep the connection open, but it is answer synthesis and is not part of
  this design. It is a product option that needs its own decision (U63).
- DNSSEC records, the DO bit, and the AD bit pass through. Large DNSSEC answers
  are not truncated on TCP. The engine is not a validator.

### 4.9 DoT, DoQ, application DoH, and caches

- An application that uses DoT (TCP 853) or DoQ (UDP 853) bypasses the
  forwarder. The query is already encrypted to the application's resolver. The
  carrier can see the resolver IP, the TLS SNI for DoT, and flow shape. The
  engine must not interfere. It may count port 853 as "port 853", not as
  "DoT".
- An application that uses its own DoH on 443 is indistinguishable from HTTPS
  without parsing SNI. Do not parse it. Do not count it. Do not claim it.
- An operating-system DoH or DoT setting is outside the tunnel policy. It may
  be more private or less. Report no capability and do not claim coverage.
- Preexisting caches defeat retroactive privacy. The OS resolver cache, browser
  cache, resolver cache, CDN, Alt-Svc, TLS session tickets, and application
  DNS pinning can all keep a name or address after the mode is enabled. Do not
  flush them automatically. Document that the mode applies to new tunneled
  queries.
- The engine does not cache answers. It may cache the DoH endpoint's ECH
  config, not user answers.

## 5. ECH architecture

### 5.1 Engine-owned DoH ECH

ECH on the DoH connection is real but secondary. The resolver name is static
and the resolver IP is already visible. ECH hides that name behind the
public_name, which often belongs to the same provider. On a blocking network,
the static IP or the public name is the tell.

Its value is:

- a real, standards-correct ECH code path with tests;
- no extra plaintext name from the engine's resolver traffic;
- a foundation for a future product-owned client.

It is not the privacy win. DoH is. Say so.

### 5.2 Config discovery and cache

- Source: the endpoint's own HTTPS RR, fetched through the authenticated DoH
  connection. Accept SvcParamKey 5 only (`ech`).
- Wire value: an `ECHConfigList` with its redundant length prefix
  (RFC 9848 section 3).
- Parse: DNS name decompression, RR type 65, SvcParams as `(u16 key, u16 len,
  bytes)` in strictly increasing key order. Reject duplicate keys, unknown
  mandatory extensions, unsupported KEM, empty list, and a list over 64 KiB.
- Cache: keyed by endpoint name, bounded, TTL from the RR, no persistence,
  cleared on stop. Never store a rejected list.
- An ECH-enabled client config is bound to the name that published the config.
  Never reuse it for another origin. For the DoH endpoint there is one name;
  for a future owned client, keep one config per origin name.
- A failed or timed-out config fetch is not a fallback and does not change the
  profile. Later connections to the fixed resolver simply offer no ECH for the
  resolver name. That loses L2, not L1: the query is still inside TLS to the
  configured resolver. State this explicitly. Do not let an attacker force a
  plaintext query by blocking the config fetch.
- `EchConfig::new` and `EchMode` are rustls API claims from the revision 1
  crate read. Re-verify them against the pinned version in an implementation
  spike. Do not build a plan on an unverified API shape.

### 5.3 Rejection and retry

RFC 9849 section 6.1.6 defines the only safe retry. The client authenticates the
connection against the **origin name it intended to reach** (the name whose
ECHConfig it used), not against `public_name`. `public_name` is the outer SNI.
If the origin certificate does not authenticate, the client fails; it does not
use retry configs and does not treat the failure as a signal to disable ECH.

The policy, stated once:

| Connection | Event | Action | Counter |
|---|---|---|---|
| Application flow (class B or C) | Any | The engine never offers ECH and never retries. A non-ECH flow is a profile chosen before the connection | None |
| Resolver connection | ECH accepted | Continue | `ech_ok` |
| Resolver connection | Server rejects ECH, origin certificate authenticates, supported `retry_configs` present | Close the old socket. Open exactly one new connection with the retry configs. Replace the cached config with the retry configs through the compare-and-set commit in section 6.4.7 | `ech_rejected`, then `ech_ok` or `ech_retry_exhausted` or `ech_error` |
| Resolver connection | Server rejects ECH, origin certificate authenticates, no supported retry config | Close the old socket. Open exactly one new connection with ECH disabled. Evict the rejected config. The query stays inside TLS (L1); the static resolver name becomes visible (L2) | `ech_rejected`, `ech_fallback`; the HTTP result is in `doh_*` |
| Resolver connection | ECH rejected but origin certificate does not authenticate | Fail. No retry | `ech_rejection_unauthenticated` |
| Resolver connection | Timeout, reset, transport error, TLS alert that is not ECH rejection, 5xx, parse error, SERVFAIL, or certificate error | Fail. No retry | `ech_error` if ECH was offered; otherwise the DoH cause only |
| Resolver connection retry with configs | ECH rejected again and origin certificate authenticates | Fail. No third attempt. Evict the config | `ech_retry_exhausted` |
| Resolver connection retry with configs | Origin certificate does not authenticate | Fail. No further attempt | `ech_rejection_unauthenticated` |
| Resolver connection retry with configs | Transport failure | Fail. No further attempt | `ech_error` |

Rules that bind the table:

- A retry is allowed only on the resolver connection and only after an
  authenticated ECH rejection. One retry per connection attempt. Never loop.
- The ECH-disabled retry is a resolver protocol fallback. It is not an
  application non-ECH flow, not a profile change, and not `hide`.
- The retry opens a new outer socket after the old one is closed. At most one
  live egress socket per inner flow at a time.
- Never retry to a different DoH server or a different IP discovered by a new
  DNS query.
- On an authenticated rejection with supported retry configs, the retry uses
  those configs and replaces the cached config for the endpoint. The old config
  is not used again. The cache write is a compare-and-set on the config
  generation that the handshake used; if another fetch has already published a
  newer config, the retry still uses its authenticated retry configs for this
  handshake and the older write publishes nothing (section 6.4.7).
- On an authenticated rejection with no supported retry config, the one
  ECH-disabled retry runs and the cached resolver ECH config is evicted. The
  eviction is a compare-and-set on the config generation that the handshake
  used, so a stale rejection cannot evict a newer config. A later connection
  starts with a fresh config fetch and must not keep offering a config the
  resolver rejected.
- If the one retry fails, do not keep the rejected config. Evict it.
- This table is the only place that authorises a non-ECH retry. Section 12, the
  test matrix G5, T4.09, T4.24, and P11 must use this table and must not say
  "no non-ECH attempt" without the resolver-connection exception.

The hidden object decides whether a fallback is safe:

| Layer | Hidden object | Fallback | Safe? |
|---|---|---|---|
| L1 | DNS QNAME and query payload | Plaintext DNS | No. This is the feature. It is a separate profile state chosen before start, never a reaction to a failure |
| L2 | DoH resolver SNI | TLS to the same configured endpoint without ECH | Yes for L1, because the query stays inside TLS and the resolver name is static. Only after an authenticated ECH rejection, and only on the resolver connection |
| L3 | Application SNI | None from the engine. The app or the owned client decides | Any non-ECH connection reveals the name. Fail closed by default. A non-ECH profile is chosen before connecting; it is not a retry |

#### 5.3.1 The plan's fallback text conflicts with this design

`docs/SNI_HIDING_PLAN.md` requires "a fresh non-ECH flow after a detectable
failure" and a `hide` acceptance gate that fails over to a fresh non-ECH flow
when a network blocks the ECH outer name. That text conflicts with this design.

- A blocked outer name shows up as a timeout, a reset, or a failed origin
  certificate check. This design forbids a retry in those cases. RFC 9849
  section 6.1.6 says a failure is not proof that ECH is disabled.
- The plan's gate would require the downgrade that this design forbids. An
  active attacker could force the timeout or reset and get a non-ECH flow.
- The design does not change. The plan text is wrong and must be corrected by
  WS6. The quoted passages and the exact replacement are in section 11.3.

No downgrade on a timeout, a reset, a certificate error, a 5xx, a parse error,
or a SERVFAIL. DoH alone cannot satisfy `hide`. That rule holds in this
revision and in every future revision.

#### 5.3.2 A non-ECH flow is a profile state, not a retry

Revision 3 left one contradiction: it described an "opt-in, labeled,
per-profile non-ECH retry" while forbidding a retry on a timeout. On a network
that blocks the outer name, a timeout or reset is the only trigger, so the
opt-in could only run as a timeout-triggered downgrade. Revision 4 removes the
contradiction:

1. A profile is either ECH or non-ECH before it connects. The choice is made by
   a person, stored per network profile, and shown in the UI.
2. The product never changes that state because of a failure. A timeout, a
   reset, a certificate error, a 5xx, a parse error, a SERVFAIL, or a failed
   origin certificate check ends the flow.
3. A person who wants a non-ECH flow selects the non-ECH profile before the
   next connection. That profile is labeled, counted, and not called `hide`.
   It is not an automatic retry and it never follows a failure in the same
   session.
4. The engine resolver's authenticated-rejection retry is different. It is a
   protocol step in RFC 9849 section 6.1.6, it happens only after the origin
   certificate authenticates and the server rejects ECH, and it is bounded to
   one. It is not a profile change and it is not available for an application
   flow from the relay. The resolver retry may use retry configs, or ECH
   disabled when no supported retry config exists.

The same rule applies to plaintext DNS. A profile either uses DoH or plaintext
before the tunnel starts. A DoH failure is a DNS failure. It never switches the
query, the flow, or the profile to plaintext. Section 4.1 and section 4.3 state
the UI labels for the plaintext profile; the default `off` label and counter are
gated by section 2.6.

### 5.4 GREASE and the false application ECH counter

Revision 1 suggested a passive ClientHello parser that would count extension
`0xfe0d`. That counter is false.

RFC 9849 section 6.2 defines GREASE ECH. A client without an ECHConfig sends a
GREASE `encrypted_client_hello` extension with a random config ID, a plausible
cipher suite, a random `enc` value, and a random payload. The server ignores
it. The wire extension is the same code point as real ECH. A passive parser
cannot distinguish a real ECH offer from GREASE ECH, and it cannot tell whether
the server accepted it. The outer ClientHello also carries the public_name in
SNI, so the presence of an inner name is not observable.

Therefore:

- Do not count application ECH from relayed traffic.
- Do not add `app_ech_flows`, `app_ech_ok`, or `ech_ok` for class B or C.
- Do not use a ClientHello extension count in a capability or UI claim.
- If research measurement is wanted, put it in a separate experiment with a
  name that says what it is: `client_hello_ech_extension_seen_unknown`. It may
  be GREASE. It is not a product counter and not status.
- The engine-owned client may count its own `ech_attempts`, `ech_ok`,
  `ech_grease`, `ech_rejected`, `ech_rejection_unauthenticated`, `ech_error`,
  `ech_fallback`, and `ech_retry_exhausted`. Those counts refer only to
  engine-originated TLS. Section 7.2 defines them as non-overlapping outcomes.
  A GREASE handshake counts in `ech_grease` and not in `ech_attempts`.

### 5.5 What ECH does and does not hide

| Object | With engine DoH ECH | With app-native ECH | With product-owned client ECH |
|---|---|---|---|
| DoH resolver SNI | Hidden behind public_name when accepted | Not applicable | Not applicable |
| DNS QNAME | Hidden inside TLS | Hidden if the query uses DoH | Hidden if the client uses DoH |
| Application SNI | Visible | Hidden when ECH is accepted | Hidden when ECH is accepted |
| Destination IP and ASN | Visible | Visible | Visible |
| Public name and ECH use | Visible | Visible | Visible |
| JA3/JA4, flow shape, timing | Visible | Visible | The product client's fingerprint |
| Certificate | Hidden only if TLS 1.3 is negotiated | Hidden only if TLS 1.3 is negotiated | Hidden only if TLS 1.3 is negotiated |
| Tethering detection | Not measured. DoH adds a rustls ClientHello to a well-known resolver IP. No claim | Not measured. The app's own ECH does not change it | Not measured. The product client's fingerprint is visible |

ECH is blockable. A network can block the public name, the DoH IP, or the
HTTPS/SVCB lookup. A non-ECH profile must be explicit, per-network, chosen
before connecting, and off by default. Record a counter, not a name.

The DoH connection carries the engine's TLS fingerprint, not a browser's. That
fingerprint and the DoH flow shape are visible to the carrier. Do not claim
that DoH makes the flow look like ordinary browsing. It does not change JA3,
JA4, timing, or volume.

## 6. Data path, invariants, and resource limits

### 6.1 Actual SOCKS CONNECT and DNS paths

Verified in this tree:

- **Tun plus `--phone`:** the inner flow key is a numeric address. `Setup::phone`
  serializes ATYP 1 or 4, never a domain name (`rust/src/relay.rs`). UDP:53 is
  redirected to `1.1.1.1:53` with SOCKS command 1, and the reply transaction ID
  is checked. TCP:53 is not redirected today. The source device never sees a
  CONNECT hostname on the tun path.
- **Direct tun:** the inner flow key is a numeric address. DNS goes to the
  original destination or to `--dns-upstream`, in plaintext. `--dns-upstream`
  is validated as a numeric IPv4 address; source device proxy mode rejects it
  (`rust/src/service.rs`).
- **Direct SOCKS5:** ATYP 1, 3, and 4 are accepted. ATYP 3 is resolved by
  `TinyResolver` (`rust/src/socks.rs`, `rust/src/dns.rs`). `TinyResolver` sends
  a plaintext A or AAAA query over a normalized UDP socket pinned to the
  physical interface. On Linux the server list must be explicit and is bounded
  to 8 numeric servers. macOS may discover an unambiguous per-interface scoped
  resolver instead. The SOCKS5 start path is Unix-only. It then dials the
  numeric address. This is a local-resolution leak in SOCKS5 mode: the name is
  visible on the physical link before the connection. It is not `getaddrinfo`,
  but it is not "DNS stays on the relayed path" either. The plan's section 7.3
  invariant 4 records the TinyResolver plaintext local-resolution leak in its
  current revision; WS6 verifies that text. The plan also says SOCKS5 mode
  requires `socks5h`
  or remote DNS. The code accepts ATYP 1 and 4 as well, so a client can resolve
  locally before the proxy; that is a separate leak and the requirement is not
  enforced. This is a pre-existing gap. It is out of scope to change here, and
  it must not be described as fixed. An explicit server can still be wrong for
  the selected link; the person who names it accepts that choice.
- **DoH scope:** The DoH forwarder in this note covers the tun DNS path. It
  does not change the SOCKS5 listener's `TinyResolver`. A later change could
  make `TinyResolver` use the DoH client, but that is a separate integration
  with its own tests. Do not imply that enabling DoH fixes SOCKS5 mode.
- **CLI `phone` adapter and `phone.rs`:** these preserve domains for
  diagnostics and tests. The tun path does not use them.

Exact numbers that matter:

| Constant | Value | Source |
|---|---|---|
| Flows per worker | 128 | `rust/src/relay.rs` `MAX_FLOWS_PER_WORKER` |
| Workers | 1 to 8 | `Relay::start` |
| Packet queue per worker | 4096 | `rust/src/relay.rs` `QUEUE` |
| Max inner UDP datagram | 1472 bytes (1452 for IPv6) | `MAX_DATAGRAM` |
| Max phone UDP outgoing buffer | 128 KiB | `MAX_UDP_OUTGOING` |
| Phone UDP buffer age | 250 ms | `MAX_UDP_OUTGOING_AGE` |
| Phone DNS timeout | 8 s | `DNS_TIMEOUT` |
| Connect timeout | 5 s | `CONNECT_TIMEOUT` |
| SOCKS clients | 128 | `rust/src/socks.rs` `LIMIT_CLIENTS` |
| SOCKS UDP flows per client | 128 | `LIMIT_UDP_FLOWS` |
| SOCKS UDP flows total | 512 | `LIMIT_TOTAL_UDP_FLOWS` |
| SOCKS idle | 300 s | `IDLE` |
| SOCKS I/O timeout | 10 s | `TIMEOUT` |
| TinyResolver servers | At most 8 explicit (`MAX_EXPLICIT_SERVERS`), or one macOS scoped interface block | `rust/src/dns.rs`, `rust/src/environment.rs` |
| TinyResolver total timeout | 4 s, a bounded per-server share with a 500 ms floor | `TinyResolver`, `MIN_SERVER_BUDGET` |
| TinyResolver cache | 512 entries, TTL cap 3600 s | `CACHE_MAX_ENTRIES`, `CACHE_MAX_TTL` |

The plan's invariant 4 says "No `getaddrinfo` on an egress path" and requires
documenting the DNS paths that bypass the tunnel. Older project text also said
DNS stays on the relayed path. The first sentence is true. The relayed-path
sentence is false for SOCKS5 mode. The corrected invariant is: no `getaddrinfo`
on an egress path; tun mode carries DNS inside the tunnel; SOCKS5 mode resolves
an ATYP 3 name at the target through `TinyResolver` over a normalized plaintext
socket, using an explicit bounded server list on Linux and Windows and an
unambiguous scoped resolver on macOS. That is a documented local-resolution leak
at the target, whether or not the client uses `socks5h`. A client that resolves
locally before the proxy has a separate leak. Do not describe either as fixed.

### 6.2 One inner flow, one outer socket

Define "outer socket" as an egress socket, not a local control socket.

| Inner flow | Local sockets | Egress sockets | Mapping |
|---|---|---|---|
| Inner UDP:53 flow | None in the shard | One DoH TLS connection per live DoH session | One session, one egress |
| Inner TCP:53 flow | One loopback adapter connection | One DoH TLS connection per live DoH session | One session, one egress |
| Inner TCP application flow | None | One outer TCP or one source device SOCKS stream | Existing relay rule |
| Inner UDP application flow | None | One outer UDP or one source device SOCKS stream | Existing relay rule |

A **DoH session** is the object that owns one DoH TLS connection for one inner
DNS flow. Its per-shard table is keyed by the inner protocol, the inner source
address and port, and the inner destination address and port. The owning shard
is derived from the inner flow key and is not part of the key. The session
carries a `session_generation`: a session incarnation number allocated from one
monotonic ledger counter when the session is reserved. It does not change while
that session lives: not when a connection is installed, not when a retry is
authorized, and not when a queued job starts. The value is never reused in a
relay run. Its only job is to tell this session apart from an earlier or later
session in the same table slot or on the same inner 4-tuple. A retry is told
apart by `attempt_id`, and a job by `job_id`. The session is not the relay's
UDP or TCP flow table entry:

- The relay flow entry may outlive the DoH session. In direct mode a UDP flow
  entry lives up to `UDP_IDLE` (120 s); the DoH session closes much earlier
  when it is quiet (section 6.5).
- A new query on the same inner 4-tuple after the session closed starts a new
  session with a new `session_generation` and a new handshake. That is a
  sequential replacement for the same inner flow, not a shared connection.
- The session key never ignores the inner source port. Two source ports are two
  inner flows. They never share a DoH session (section 6.5).
- `session_generation` is allocated only by the owning shard, under the ledger
  lock, at one point: when it reserves a new session. It is never mutated
  afterward. The pool never allocates or changes it. Every job on the session,
  including the config fetch, the queued user queries, and the retry attempt,
  carries the same value. It is not the ECH config `config_generation` and not
  the ledger sequence `ledger_seq` (section 6.4.7).
- Revision 8 also incremented it at connection install and at retry
  authorization, and failed a completion whose stored value differed. That
  failed every successful retry and every queued job after the first commit.
  Revision 9 removes both increments and the failure path.

Rules:

- One DoH TLS connection per live session. Do not share a session across
  unrelated inner flows. Do not multiplex with HTTP/2.
- Reuse the connection for later queries in the same session. Close it when
  the inner flow closes, the session is quiet (UDP), or the idle timer expires
  (TCP).
- Do not open a background connection to refresh the ECH config. Fetch or
  refresh on the session's own connection. If no session exists, do not
  refresh.
- An ECH rejection retry closes the old connection before opening the new one.
  It keeps the session's `session_generation` and uses `attempt_id` 2 of the
  same job. At most one live egress socket per session at a time. Invariant 3 forbids
  concurrent multiplexing of unrelated inner flows over one outer connection.
  It does not forbid a sequential replacement after the old connection is
  closed. The retry is the only replacement path, and it is bounded to one.
  The retry is a second attempt of the same query job, not a second admitted
  query (section 6.4.7).
- In source device proxy mode, one DoH session is one SOCKS CONNECT to the DoH
  IP and port. The source device opens one destination. No aggregation.
- The loopback adapter is a local socket, not an egress. It exists only between
  the relay and its own adapter. It never leaves the machine.

### 6.3 Normalized sockets and the TTL audit

Every egress socket goes through the normalized helpers.

- Direct DoH: `normalization::tcp_connect_cancellable(addr, iface, audit,
  timeout, stopped)` (`rust/src/normalization.rs`). The fourth argument is a
  `Duration` timeout from the call, not an absolute deadline. The DoH client
  computes the remaining time from its absolute deadline and passes it here.
  Do not describe the helper as deadline-based.
- Source proxy DoH: `phone_tcp_start(phone.address, iface, audit)` plus
  `Setup::phone` to the DoH IP. `phone_tcp_start` uses
  `normalization::tcp_start`, sets TTL 65, pins the interface, sets keepalive,
  and sets no-delay (`rust/src/relay.rs`).
- **Cancellation covers the whole source setup.** The blocking driver checks the
  stop flag and the absolute deadline before the connect, after the TCP
  connect, and in every `Setup` state while it waits for the source device
  reply. A cancellation closes the outer socket and returns a terminal
  `doh_cancelled`; it does not wait for the source device. A late source device
  reply after cancellation is discarded by job ID. If the existing helper has a
  state that cannot be interrupted, the driver bounds that state by the
  deadline and discards its late result. Do not add an uncancellable wait
  between queue admission and the terminal outcome.
- Loopback adapter connection: the platform's normalized start helper with no
  interface pin (`normalization::tcp_start` with `iface = None` on Unix, and the
  Windows equivalent with no interface index). It is the single documented
  unpinned local socket. It cannot leave the machine. The audit still counts
  it, and TTL 65 is set. `ttl_bad` must stay 0. The adapter connect also honours
  the job's stop flag and deadline.
- No new raw egress socket. No new socket helper. No `getaddrinfo`.

IPv6 policy:

- Prefer an IPv4 DoH endpoint. It avoids link-local scope and works in both
  direct and proxy modes.
- An IPv6 DoH endpoint is allowed only when the mode forwards IPv6. Reject it
  in direct block mode at start.
- Reject link-local, multicast, unspecified, and loopback endpoints (loopback
  only in tests). An inner link-local DNS query is not a reason to send DoH to
  a link-local address.

### 6.4 Sharded ownership, bounded concurrency, and one ledger

#### 6.4.1 Verified starting point

Verified in this tree:

- `Relay::start` accepts 1 to 8 workers (`rust/src/relay.rs`). It creates one
  `mpsc::sync_channel(QUEUE)` and one wake pair per worker, then spawns one
  `Worker` thread per shard.
- `shard(key, workers)` hashes the inner flow key, so every packet of one inner
  flow is handled by exactly one worker.
- Each worker holds at most `MAX_FLOWS_PER_WORKER` (128) flow entries.
- `Counters` and `Audit` are shared `Arc` values. Relay statistics are a plain
  struct snapshot merged into diagnostics by the service.

Therefore a design that says "the relay worker" owns a global object is wrong
for any run with more than one worker. Revision 6 made that claim. Revision 7
replaces it.

#### 6.4.2 Object model and owners

| Object | Count | Owner | Lifetime | Who mutates it | Who releases it |
|---|---|---|---|---|---|
| `DohSupervisor` | 1 | `Relay` facade | one relay run | the supervisor thread; phase changes under the ledger lock | `Relay::stop` or `Drop` through the stop barrier |
| `DohLedger` | 1 | supervisor | one relay run | any admission or terminal call, in one short critical section | sealed at the barrier; never reused |
| `DohLimits` | 1 | supervisor, same lock as the ledger | one relay run | admission and release | sealed at the barrier |
| `DohWaitQueue` | 1 | supervisor, inside the ledger lock | one relay run | admission, grant, and `settle_waiter` | every entry settled in the `Stopping` transition |
| `SlotGrant` | 0..1 per free slot | ledger, in the grant table | release step to conversion or settlement | the release step creates it; `admit_granted` converts it; `settle_waiter` removes it | exactly one of: conversion into a job by `admit_granted`, or `settle_waiter`, which returns the slot in the same critical section |
| `DohPool` | 8 threads, measured | supervisor | one relay run | each thread runs one attempt and sends events; it never mutates a shared object | joined at the barrier, or reported as detached |
| `DohShard` | 1 per relay worker | that worker | worker life | only its worker | worker exit, then barrier ack |
| `DohSession` | 0..S | the shard that owns the inner flow | reservation to release | only that shard; the pool never touches it | one named release path in 6.4.6 |
| `DohJob` | 0..G | the admitting shard | admission to commit, through at most two attempts | only that shard; the pool sends events and moves the lease | commit removes it |
| `ConnectionLease` | at most 1 per live session per attempt | the pool while an attempt executes, then the shard after the move | connect to close or handback | the holder only; transfer is a move | pool on failure, shard on commit or discard, supervisor on force-close |
| `EchConfigCache` | 1 | supervisor | one relay run | only through `commit_config`, `commit_retry_config`, and `mark_rejected`, called by the owning shard under the ledger lock | cleared at the barrier |
| `EchAttempt` | per handshake | the job that started it | `AttemptStarted` to `AttemptOutcome` | the owning shard | job commit or `ech_error` at job terminal |
| Adapter listener | 1 | supervisor | one relay run | supervisor | stop barrier |
| Adapter connection | 0..A | one adapter flow task | accept to close | that task | inner close, bound breach, or stop |
| Adapter admission credit | 4 per authenticated connection | the adapter flow task, then the shard | frame read to disposition | adapter decrements on read; shard returns on disposition | shard when it emits the disposition, or the adapter on connection close |
| Delivery / terminal disposition | 1 per accepted TCP:53 job | the admitting shard | reserved at admission | the shard | applied by the adapter in `request_id` order: written, or counted once as undelivered in `doh_adapter_errors` |
| Runtime coverage | 1, inside the ledger | supervisor | one relay run | supervisor only, under the ledger lock | reset to `unknown`/`not_running` at stop |
| `ledger_seq` | 1, inside the ledger | ledger | one relay run | every ledger mutation, under the ledger lock | discarded with the run's ledger |

Three rules follow from the table:

1. No object has two mutators. The pool sends events and moves the connection
   lease. It never writes the ledger, the session table, the cache, or the
   adapter stream.
2. No job migrates shards. A UDP query is admitted by the shard that received
   the packet. A TCP query is admitted by the shard named in the adapter
   preface. A config fetch is admitted by the shard that owns the session it
   runs on.
3. A connection has one holder at a time. A slot is freed only after the shard
   has observed the handback for the attempt that held it. The lease protocol is
   section 6.4.10.

#### 6.4.3 Admission

Every entry point calls one function, `DohSupervisor::admit(shard, request)`:

1. Take the ledger lock once.
2. If `phase != Running`, return `Rejected(doh_cancelled)` and record
   `doh_queries` plus `doh_query_failed` with cause `doh_cancelled` in the same
   critical section. The request never reaches the pool and never enters a
   gauge. For a TCP:53 request, emit one `AdapterDisposition::Close` and return
   the admission credit.
3. Check the global job bound `G`, the session bound `S` when a new session is
   needed, the per-session bound (`1` in flight plus `Q` queued), the global
   waiter bound `W`, and the per-job reservations. If a bound fails, record
   `doh_queries` plus `doh_query_failed` with cause `doh_queue_full` (or
   `doh_timeout` when the arrival deadline has already passed) and return. For a
   TCP:53 request, also emit one `AdapterDisposition::Close { cause }` and return
   that connection's admission credit. The close is a rejection disposition, not
   a second query outcome.
4. If only a session slot is missing, enqueue one global `SlotWaiter` (section
   6.4.3.1) and return `Waiting`. A waiter is not a job, holds no pool or event
   reservation, and does not enter `doh_queries` until its terminal transition.
5. Reserve, in one step:
   - one job-table entry;
   - one completion slot;
   - **two attempt work items** in the pool ingress, because one job may run at
     most two attempts;
   - five event slots (two ECH attempts at two events each plus one completion);
   - one delivery or terminal-disposition slot;
   - for a TCP:53 job, the adapter admission credit the adapter already holds
     stays held until the disposition returns it.
   Capacity is reserved here, so no later send can block or drop.
6. Record the kind-specific input counter and gauge, and insert the job record
   with its arrival deadline, destination (never logged), path, session
   generation, config generation used, attempt count 0, and ECH plan state. A
   `Query` job records `doh_queries` and `doh_in_flight`. A `ConfigFetch` job
   records `doh_lookups` and `doh_config_in_flight` and is never counted in
   `doh_queries`. Both use the same job table, attempt slots, and event
   reservation.
7. Send the first attempt to the pool's bounded ingress. That send cannot fail
   because the ingress bound includes the two reserved attempt items per
   admitted job. The retry attempt reuses the second reserved item.

#### 6.4.3.1 One global waiter queue

The session cap is global, so the waiter queue is global. A per-shard FIFO
cannot define an order across shards and cannot hand a released slot to the
oldest waiter. The queue is `DohWaitQueue` inside the ledger lock:

`Waiter { waiter_id, shard, seq, enqueue_at, wait_deadline, absolute_deadline,
session_key, job_request }`.

`SlotGrant { grant_id, waiter_id, slot_id, shard, grant_deadline }`.

A waiter is in exactly one of four states. Every transition runs under the
ledger lock:

| State | Where the record lives | Holds a slot | Next states |
|---|---|---|---|
| `Queued` | `DohWaitQueue` | no | `Granted` (release step) or `Settled` |
| `Granted` | grant table, keyed by `grant_id` and by `waiter_id` | yes, counted as used | `Converted` (`admit_granted`) or `Settled` |
| `Converted` | gone; the job record now exists | the job's session holds it | none. Later outcomes belong to the job |
| `Settled` | gone | no | none |

Rules:

- **One FIFO for all shards**, ordered by `seq`. There is no per-shard
  preference and no round robin. A shard with a burst can occupy the queue, but
  never more than `W` entries in total. The bound `W` counts `Queued` and
  `Granted` waiters together.
- **Bounded.** If `W` is full, the request is rejected immediately with
  `doh_queries` plus `doh_query_failed`/`doh_queue_full`. It does not displace
  another waiter. For a TCP:53 request, the rejection emits one
  `AdapterDisposition::Close` and returns the admission credit. This rejection
  never creates a waiter, so it is not a settlement.
- **Wait window.** `wait_deadline = min(enqueue_at + 250 ms, enqueue_at +
  remaining_deadline / 4)`. It is computed once and never extended. It bounds
  only the time a waiter spends `Queued`. Once a waiter is `Granted`, only its
  `grant_deadline` applies.
- **One settlement transition.** `settle_waiter(waiter_id, outcome)` is the
  only function that records a waiter outcome. In one critical section it:
  1. looks up the waiter in the queue and then in the grant table; if it is in
     neither, it returns `Stale`, records nothing, and changes no slot;
  2. removes the record;
  3. if the waiter was `Granted`, returns the grant's slot to the release step,
     which may grant it to the next eligible waiter in the same critical
     section;
  4. records `doh_queries` plus `doh_query_failed` with the outcome cause, once;
  5. for a TCP:53 waiter, emits one `Close` disposition and returns the
     admission credit.

  Revocation, cancellation, the deadline reaper, the stop transition, and a
  refused `admit_granted` all call `settle_waiter`. Because the first call
  removes the record, a second call for the same waiter returns `Stale`. A
  waiter can therefore be settled at most once, and a settled waiter can never
  be converted.
- **Direct grant.** When a session slot is released, the release step runs under
  the same lock. It first settles, in `seq` order, every `Queued` waiter whose
  `wait_deadline` or `absolute_deadline` has passed (`doh_timeout` when the
  absolute deadline passed, otherwise `doh_queue_full`). Deadlines are not
  monotonic in `seq`, so this is a scan of at most `W` entries, not a head
  check. It then pops the oldest waiter with `now < wait_deadline` and
  `now < absolute_deadline`, moves it to `Granted`, and creates a `SlotGrant`
  with `grant_deadline = min(now + T_grant, absolute_deadline)`
  (`T_grant` proposed 100 ms). The slot stays counted as used during the
  handoff, so no other shard can take it. The supervisor wakes the granted
  shard. The release step never grants a waiter whose wait window has already
  closed, so `admit_granted` never has to reject a grant for the wait window.
- **Revocation.** A grant that is not converted by its `grant_deadline` is
  revoked by any shard's reaper or the supervisor tick through
  `settle_waiter(waiter_id, doh_timeout)` when the absolute deadline passed, or
  `settle_waiter(waiter_id, doh_queue_full)` when only `T_grant` passed. The
  slot returns to the release step. A stalled shard cannot strand the cap.
- **Grant acceptance.** The shard calls `admit_granted(grant_id)` under the
  lock:
  - grant not in the table: return `Stale`. Record nothing, return no slot,
    emit no disposition. Whoever settled the grant already did all three;
  - grant present but the phase is not `Running`:
    `settle_waiter(waiter_id, doh_cancelled)`;
  - grant present but `now >= grant_deadline`: `settle_waiter` with
    `doh_timeout` if the absolute deadline passed, otherwise `doh_queue_full`;
  - grant present but the job bound `G` or the per-session bound no longer
    permits the job: `settle_waiter(waiter_id, doh_queue_full)`;
  - otherwise: convert.
- **Conversion.** The shard removes the grant record, converts the grant's slot
  into the session reservation, makes the job reservation from section 6.4.3
  step 5, records `doh_queries` and `doh_in_flight`, and dispatches the first
  attempt. A waiter that is converted is counted once, at this transition, not
  at enqueue and not at grant creation. From this point every outcome belongs
  to the job.
- **Deadline reaper.** Any shard loop tick or the supervisor's 100 ms tick calls
  `reap_waiters(now)` under the lock. It settles every `Queued` waiter past its
  wait window or absolute deadline and revokes every `Granted` waiter past its
  `grant_deadline`, across all shards, each through `settle_waiter`. A shard
  does not need its own timer per waiter, and an idle shard cannot keep an
  expired waiter alive.
- **Cancellation.** `cancel_waiter(waiter_id)` looks up the waiter. If it is
  `Queued` or `Granted`, it calls `settle_waiter(waiter_id, doh_cancelled)`,
  which records one `doh_cancelled` as a waiter outcome; no job exists, so none
  is recorded on a job. If the waiter was already `Converted`, the cancel is a
  job cancellation and records one terminal outcome on that job. If it was
  already `Settled`, the cancel is `Stale` and records nothing.
- **Stop.** The `Stopping` transition, in the same critical section that sets
  the phase, stops the release step from granting and settles every `Queued`
  waiter and every `Granted` waiter with `doh_cancelled` through
  `settle_waiter`. The slots that outstanding grants held return to the free
  pool and are not granted again. A shard that calls `admit_granted` after that
  transition gets `Stale`. `Draining` and `Sealed` therefore find no waiter and
  no grant. `Sealed` verifies that the queue, the grant table, and the session
  count are all 0. A waiter never blocks the barrier.
- **No shard blocks.** A shard processes grants and expiries at its loop
  boundary. A grant wake uses the existing per-shard wake socket. The wait never
  blocks packet processing and never opens a second session for the same flow.

#### 6.4.4 Execution

The pool performs one attempt of one job on one thread:

1. Check phase, cancellation, and the absolute deadline every 200 ms and before
   every blocking step. The normalized connect helper takes the remaining
   duration and the stop flag, so a stop interrupts a connect. If the phase is
   not `Running` or the job is already terminal when the thread dequeues the
   attempt, the thread sends a `Handback::NotStarted` for that attempt and opens
   no socket. It does not send a query outcome.
2. Connect through the normalized helper, perform TLS, send the HTTP request,
   read the response with the bounds in section 4.6.
3. When the handshake will offer real ECH, send
   `JobEvent::AttemptStarted { job_id, attempt_id, config_generation }` to the
   owning shard. On the handshake result, send
   `JobEvent::AttemptOutcome { job_id, attempt_id, outcome }`.
4. Send `JobEvent::Completion { job_id, attempt_id, result, connection }` to the
   owning shard. `connection` is the move-only lease from section 6.4.10. For a
   valid DNS response, `result` holds the bytes and `connection` holds the live
   TLS connection. For a failure, `result` holds the cause and `connection` is
   `None`, because the pool closed the socket before it sent the event.
5. Never write the ledger. Never write the session table. Never write the
   cache. Never send bytes to the adapter.
6. For an authenticated ECH rejection, the pool sends the attempt outcome with
   `connection = None` and no completion. The shard owns the retry decision
   (section 6.4.7). The pool does not open the retry socket on its own.

Event capacity is reserved at admission, so the pool never blocks on a full
event channel. A pool attempt that cannot send its handback because the shard is
gone (panic or process stop) is part of the barrier's failed-stop result, not a
silent drop. The connection lease is dropped with the event, which closes the
socket.

#### 6.4.5 Terminal decision and commit

The owning shard drains at most 64 events per loop iteration. Events are
applied in order:

1. `AttemptStarted` records `ech_attempts` and `ech_attempts_in_flight` in one
   update, if and only if the job is still live. If the job is already
   terminal, the event is discarded and the test-only discard diagnostic moves.
2. `AttemptOutcome` records exactly one ECH outcome and decrements the gauge.
   The outcome precedence is the table in section 7.2.1. An authenticated
   rejection is not the query outcome: it opens the one retry decision in
   section 6.4.7 and leaves the job in flight.
3. `Completion` is the terminal decision:
   - The event is matched by `job_id` and `attempt_id`. If the job is unknown,
     already terminal, or the attempt is not the job's current attempt, discard
     it, move the test-only `doh_late_completion_discarded` diagnostic, and take
     the connection lease if one was sent. Dropping the lease closes it. A
     `Completion` is the handback for its attempt, so free the slot at the end
     of this event only if the attempt is the session's current attempt.
   - A live job always belongs to a live session with the job's
     `session_generation`, because every session release path terminalizes the
     session's jobs first (section 6.4.6). The shard still compares the two. A
     difference is an internal invariant violation: a debug build asserts, and
     a release build treats the event as stale under the rule above. It is not
     a query outcome and it has no product cause. Revision 8's
     `generation_mismatch` reason is removed.
   - If the deadline passed or the phase is not `Running`, record
     `doh_timeout` or `doh_cancelled` respectively, close any open ECH attempt
     as `ech_error`, mark the job terminal, and drop the connection lease. This
     event is the handback, so free the slot if the attempt is still current.
   - Otherwise validate the response (QR, transaction ID, size, TC rule). A
     validation failure records its cause, marks the job terminal, and drops the
     connection lease.
   - On success, in **one** ledger update: record `doh_query_ok`, decrement
     `doh_in_flight`, install the connection lease into the session, and mark
     the reservation committed. Then push one `AdapterDisposition::Answer
     { connection_id, request_id, job_id, session_generation, bytes }` into the
     reserved disposition slot for a TCP:53 job. Only after this commit may
     bytes reach the inner client. The session keeps its `session_generation`;
     the next queued job on the session starts with the same value.
4. The consumer applies exactly one disposition. For UDP, the shard writes the
   datagram. For TCP:53, the adapter applies dispositions per connection in
   `request_id` order (section 6.6): it writes an answer, or performs the
   graceful close for a `Close`. A committed answer that is not written,
   because the inner client closed, the connection already closed after an
   earlier `Close`, or the stop flush deadline passed, is an adapter transport
   event counted once in `doh_adapter_errors`. It does not retract the
   committed query outcome. The outcome and the transport are separate claims.
   There is no other way for a committed answer to end: it is written or it is
   counted as undelivered.

A failed TCP:53 job also ends with one disposition: `AdapterDisposition::Close
{ connection_id, request_id, job_id, cause }`. The adapter performs a graceful,
ordered close (section 6.6): it stops reading new frames on that connection,
applies every disposition with a lower `request_id` first, applies the
dispositions of requests that were already admitted with a higher
`request_id`, and then sends FIN. An earlier or later admitted query on the
same connection keeps its own outcome; a failure of one query never turns
another into `doh_cancelled`. It does not leave a failed query open until the
idle timer. The close disposition is not an answer and never carries bytes. A
failed UDP job has no disposition; its shard sends no datagram.

When the failure is a DoH transport failure on the session's connection (a
connect, TLS, or HTTP failure with no retry), the session has no connection
left. The shard terminalizes the session's queued jobs with
`doh_other_error`/`flow_closed` and emits their `Close` dispositions. Their
cause is true: the session's outer connection closed. When the failure is an
admission rejection of one frame (`doh_queue_full` or `doh_timeout`), the
session and its connection are unaffected, and the already admitted jobs run
to their own outcomes.

`doh_query_ok` therefore means "the owner committed a validated DNS answer for
delivery to the inner transport". It does not mean the inner client read it.
WS0 must record that definition (section 7.2.3).

Commit order is simple per session because there is at most one in-flight job,
and jobs run in admission order. Write order is the adapter's job: a pipelined
connection can have one job committed and the next job committed before the
adapter writes the first answer. The adapter therefore keeps, per connection, a
small reorder buffer keyed by `request_id` (at most four entries, the credit
bound) and writes in `request_id` order. It never compares a disposition with
"the current" job or generation, so a later commit cannot make an earlier
answer stale. The adapter checks only that the connection ID is live and that
the `job_id` has not already been applied; a disposition for a closed
connection is an undelivered answer (counted) or a no-op close. The adapter has
no path that can write bytes from a pool completion directly.

#### 6.4.6 Session and slot lifecycle

A session is created when the first query for an inner DNS flow is admitted,
and released by exactly one of these paths:

| Event | Job outcome | Connection lease | Slot | Session state |
|---|---|---|---|---|
| First query admitted | `doh_in_flight` +1 | none yet | reserved | `Reserved` |
| First attempt dispatched | none | pool obtains a lease | held | `Connecting` |
| Connect and TLS ready, completion committed | none | pool moves the lease to the shard; shard installs it | held | `Ready` |
| Query committed | `doh_query_ok` | session holds it | held | `Ready`; arm quiet timer |
| Another query arrives before quiet | none | session holds it; next attempt takes a lease | held | `Ready`; cancel quiet timer |
| UDP quiet (250 ms, no job, no datagram) | none | session closes it | free | `Released` |
| TCP idle (30 s) or inner FIN | queued jobs terminal `doh_cancelled` | session closes it after the last handback | free | `Released` |
| Inner flow expiry mid-query | `doh_cancelled` | shard marks terminal; slot frees on handback | free after handback | `Released` |
| Connect/TLS/HTTP failure with no retry | one failure cause | pool closed it; `None` | free on handback | `Released` |
| Authenticated ECH rejection, retry authorized | one ECH outcome (`ech_rejected`); the job stays in flight | old lease closed by the pool before the outcome; `None` | held | `BetweenAttempts { job_id }`; `session_generation` unchanged |
| Retry dispatched | none | the pool obtains a new lease for `attempt_id` 2 | held | `Attempting { job_id, attempt_id: 2 }` |
| Retry committed | `doh_query_ok` | pool moves the new lease to the shard; shard installs it | held | `Ready`; `session_generation` unchanged |
| Stop | `doh_cancelled` for every live job | pool closes or hands back; shard drops | freed after `JoinPool` handbacks | `Draining`, then `Released` |
| Shard panic | supervisor cannot prove | force-closed | freed | `Incomplete`; ledger not published as exact |

The slot is released exactly once, and only after the shard has observed the
handback for the attempt that held it (section 6.4.10). The release is guarded
by `session_generation` and `attempt_id`, so a late event from an earlier
session incarnation cannot free a newer session's slot or attach to it, and a
late event from an earlier attempt cannot free the slot that the current
attempt holds. Every release path terminalizes the session's live and queued
jobs before it frees the slot, so no live job can outlive its session. There is
no eviction of another flow's
session. The only connection replacement within a session is the bounded ECH
retry, and it closes the old connection first. A quiet UDP close is a normal
close of that session, not an eviction of a different flow.

The two release triggers outside the session are explicit:

- **UDP flow expiry.** The shard owns both the relay flow entry and the DoH
  session for that flow, so its expiry path calls `doh.close_flow(key)` in the
  same thread. There is no cross-shard event and no lock order issue.
- **TCP:53 inner close.** The adapter sends
  `AdapterEvent::ConnectionClosed { connection_id, reason }` to the owning
  shard. The shard terminalizes any queued job with `doh_cancelled`, closes the
  connection when the lease is back, and releases the slot after the handback.
  The adapter never releases a slot itself.

#### 6.4.7 ECH config cache, retry authorization, and attempt lifecycle

Three sequences are distinct and must never be called "generation" without a
qualifier:

| Name | Scope | Owner | Changes |
|---|---|---|---|
| `session_generation` | one DoH session incarnation, allocated from one monotonic ledger counter | owning shard, under the ledger lock | allocated once, when the shard reserves the session; never changed while the session lives; never reused in a relay run. Not changed by connection install, retry authorization, or a queued job |
| `config_generation` | one cache entry | owning shard, under the ledger lock, through a commit | on every successful `Fresh` or `Rejected` publication |
| `ledger_seq` | one relay run's ledger | the ledger, under its lock | +1 on every ledger mutation. Read, never incremented, by a status or diagnostics read. Reported as `runtime.snapshot_seq` in status and `ledger.snapshot_seq` in diagnostics (section 2.2) |

A retry and a queued job are identified by `job_id` and `attempt_id`, not by a
sequence change.

The cache record lives inside `DohLedger`. The supervisor owns its lifecycle and
clears it at the barrier. Only the owning shard's commit functions mutate the
record, under the ledger lock. The cache has one entry for the configured
endpoint (plus test-only entries):

| State | Meaning | Allowed next states |
|---|---|---|
| `Absent { retry_after: Option<Instant> }` | no usable config; `retry_after` is set only after a failed fetch | `Fetching` when `retry_after` is `None` or has passed |
| `Fetching { job_id, fetch_ticket, attempt_seq }` | exactly one fetch is in flight | `Fresh`, `Rejected`, or `Absent` when the fetch job ends without a commit |
| `Fresh { config, ttl, config_generation }` | usable config | `Fetching` on refresh, `Rejected` on a compare-and-set rejection |
| `Rejected { config_generation }` | the resolver rejected this config | `Fetching` for one later attempt |

Rules:

- **Single flight.** The first session that needs a config becomes the fetcher
  and receives a `fetch_ticket`. Other sessions set a per-session
  `waiting_for_config` flag with their own deadline. They do not open a second
  config connection, do not open a background connection, and do not enter the
  slot waiter queue. Every cache transition out of `Fetching` broadcasts a
  config wake to every shard in the same critical section, whether the fetch
  committed or not. Each waiting session then re-checks the cache and its own
  deadline. The flag is bounded by `S`.
- **A fetch that ends without a commit.** The fetch job can end without a
  commit: it fails (connect, TLS, HTTP, parse, timeout), or it is cancelled
  (the fetcher's inner flow expires or closes, or the fetcher's session is
  released). In the same critical section as that terminal transition, the
  shard records `doh_failed` once, moves the cache from `Fetching` to
  `Absent`, and broadcasts the config wake. The two endings differ only in
  `retry_after`:
  - **Cancelled.** A cancellation says nothing about the endpoint, so
    `retry_after = None`. The first waiting session whose shard re-checks
    under the lock calls `claim_fetch` and becomes the new fetcher with a new
    `fetch_ticket`. `claim_fetch` succeeds only when the cache is `Absent`
    with no pending `retry_after`, the phase is `Running`, and the session's
    own deadline remains; every other session keeps waiting. At most one
    fetcher exists at a time, and a cancelled fetch elects at most one
    replacement per cancellation. If no session is waiting, the cache stays
    `Absent` until the next session needs a config.
  - **Failed.** A failure may mean the endpoint or its HTTPS record is broken,
    so `retry_after = now + 5 s` (proposed, unmeasured). No session claims a
    fetch before `retry_after`. The waiting sessions proceed without offering
    ECH (the "no config, no ECH" rule below). This bounds fetch attempts to one
    per 5 s while the endpoint fails, with no fetch storm across shards.
  The new fetcher runs the fetch on its own session connection, as the
  bootstrap rule below describes. A waiting session never waits for a fetcher
  that no longer exists: either it is woken and re-checks, or its own deadline
  ends the wait.
- **The bootstrap session has no config yet.** It connects without ECH, admits
  the config fetch as its own job, and carries any queued user query on the
  same connection after the fetch commits. That first query loses L2 only; L1
  is unaffected because the query is still inside TLS. Later sessions use the
  committed config. No session opens a second connection to upgrade a live
  query, and no session opens a second connection to fetch a config.
- **The fetch runs on the fetcher's session connection.** It is a `ConfigFetch`
  job owned by that shard. It is not a standalone connection. The connection
  lease moves back to the session between the fetch job and the queued user
  query job (section 6.4.10).
- **Publication is a compare-and-set commit.** `commit_config(job_id,
  fetch_ticket, config_generation_used, result)` runs on the fetch job's shard,
  under the ledger lock, and only when:
  - the cache is `Fetching` with exactly this `job_id` and `fetch_ticket`;
  - the job is still live and not cancelled;
  - the phase is `Running` or the commit is part of the drain.

  It then writes `Fresh` or `Rejected` with `config_generation + 1`, records
  `doh_lookups` plus `doh_ok`/`doh_failed`, and moves
  `ech_config_unavailable` when the record had no usable `ech` param, all in
  one update. A late, duplicate, cancelled, or mismatched fetch result
  publishes nothing and moves no `doh_ok` or `doh_failed`; a cancelled fetch
  records `doh_failed` once at its terminal transition, not at a later commit.
- **The retry decision belongs to the shard, not the pool.** On
  `AttemptOutcome::RejectedAuthenticated`, the shard:
  1. records `ech_rejected` for the first attempt;
  2. sets the session's slot state to `BetweenAttempts { job_id }`;
  3. authorizes exactly one retry by marking the job's second reserved attempt
     with `retry_authorized = true` and a `retry_ticket`;
  4. dispatches the second reserved attempt as `attempt_id` 2 with the retry
     configs, or with ECH disabled when no supported retry config exists, and
     sets the slot state to `Attempting { job_id, attempt_id: 2 }`.

  The job keeps one `doh_queries` increment, stays in `doh_in_flight`, and keeps
  the session's `session_generation`. The retry is not a second admitted query
  and is not a second terminal outcome. Its completion is matched by `job_id`
  and `attempt_id` 2 and commits through the normal success path. No sequence
  changes at retry authorization. The pool never dispatches a retry on its own.
- **Retry config publication is also a compare-and-set.**
  `commit_retry_config(job_id, retry_ticket, config_generation_used,
  retry_configs)` may run only for the live retry job. It writes `Fresh` with
  `config_generation + 1` only when the cache is still `Fresh` and its
  `config_generation` equals `config_generation_used`. If another fetch has
  published a newer config, the write publishes nothing; the retry still uses
  its authenticated retry configs for this handshake and does not overwrite the
  newer cache. It records no `doh_lookups`, because it is not a fetch. The call
  returns `Committed { retry_config_generation }` or `Stale`. Attempt 2 records
  the returned generation, or `None` when the commit was stale. On a second
  authenticated rejection, `mark_rejected` may run only when attempt 2's
  generation is `Some` and still current; a `None` or stale retry config evicts
  nothing and only records `ech_retry_exhausted`.
- **Eviction is a compare-and-set.** `mark_rejected(job_id,
  config_generation_used)` evicts only when the cache's current
  `config_generation` equals the generation the handshake used. A stale
  authenticated rejection from an older generation cannot evict a newer
  `Fresh` config. A rejected config is evicted, and a later session may fetch
  once. A second rejection is counted per attempt as `ech_retry_exhausted`, not
  as a permanent global ban.
- **No config, no ECH on that handshake.** A config waiter that reaches its
  deadline, or a session with an expired config and no fresh fetch, proceeds
  without offering ECH. L1 is unaffected because the query is still inside TLS.
  No `ech_*` attempt counter moves for that handshake.
- **The cache is memory only**, cleared at the barrier. It holds no QNAME and
  no user destination.
- **An ECH attempt** is the pair of `AttemptStarted` and `AttemptOutcome`
  events. It belongs to one job, one `attempt_id`, and one
  `config_generation`. A job may have at most two attempts: the first handshake
  and the one retry. If the job reaches its terminal state with an open attempt,
  the shard records `ech_error` for it once and discards a late
  `AttemptOutcome`. A cancelled retry that never started records no attempt and
  no `ech_*` outcome.
- **Stale-event rule.** An event whose `job_id` or `attempt_id` is not the
  current live attempt is discarded, including a completion, an attempt
  outcome, a handback, or a cache commit. It moves no counter except the
  test-only discard diagnostic. A handback for a stale attempt still returns
  its reserved work item, but never frees a slot that belongs to a newer
  attempt.

#### 6.4.8 Stop barrier and the real `Relay::stop` order

Verified starting point in this tree:

- `Relay::stop` sets `running = false`, clears the input sender vector, shuts
  every wake pair, then joins every worker handle. It has no timeout. A failed
  join increments `flow_errors`. It returns `()` (`rust/src/relay.rs`).
- `Relay` implements `Drop` by calling `stop`. A `Drop` cannot return a value,
  cannot report a reason, and cannot wait for a caller to read a result.
- The service `stop_locked` sets the tunnel stop flag, joins the tunnel worker
  with no timeout, then reads the auto-stop reason and the fault record
  (`rust/src/service.rs`). The tunnel worker calls `relay.stop()` on its own
  thread. The relay shards are separate threads.
- There is no stop budget anywhere in the current code. A join can block
  indefinitely. The 5 s below is a proposed DoH-only bound, not a total stop
  time and not a property of the current code.
- **The tunnel worker stops the relay before it removes routes.** On every
  target the tunnel worker's normal exit runs `relay.stop()` and then
  `routes.remove()` (macOS: `rust/src/service.rs` near the
  `v6_error`/`route_error` pair after `relay.stop()`; Linux: the worker exit
  that runs `relay.stop()`, `routes.remove()`, `link.remove()`, and then drops
  the TUN device; Windows: the worker exit and the shared Windows cleanup
  helper, both `relay.stop()` first). Most startup failure paths use the same
  order. The Linux path that fails to spawn the tunnel worker removes routes
  first. When the worker reaches `relay.stop()`, its TUN read loop has already
  exited, so packets that the host still routes into the TUN device are not
  read. Every millisecond `relay.stop()` takes is a window in which host
  traffic is routed into a dead device.
- **The fault slot has two fields.** The worker writes `(message,
  cleanup_failed)` into the shared fault slot. `stop_locked` copies the message
  into `inner.error` and ORs `cleanup_failed` into `inner.cleanup_blocked`.
  `cleanup_blocked` makes a later start refuse with a "Route cleanup failed.
  Inspect the routing table" message. `Relay::stop` returns `()`, so a relay
  stop result has no path into that slot today.

Stop is a phase machine owned by the supervisor. The phase is part of the
ledger state and is changed under the ledger lock, so an admission and the stop
transition cannot interleave: an admission either reserves before the
transition and becomes live work to drain, or observes `Stopping` and is
rejected with no reservation.

The stop has two parts. `begin_stop` is short and never waits. The drain waits
for acks and handbacks. The design keeps them apart so the drain can run after
route cleanup.

- **`Relay::begin_stop()`** takes the ledger lock once, sets `Stopping`, settles
  every slot waiter and outstanding grant (section 6.4.3.1), stops the release
  step from granting, wakes every shard and the pool, and closes the adapter
  accept path. It does not wait for an ack, a handback, or a join. It is
  idempotent. Its cost is one lock section plus wake writes; it is not bounded
  by any of the DoH phase deadlines.
- **`Relay::stop() -> RelayStopReport`** calls `begin_stop()` if no caller has,
  then runs the drain and the existing relay teardown. It is idempotent.

**Required order in the tunnel worker when the DoH profile is active for the
run:**

1. The worker loop exits, and the link monitor stops (existing code).
2. `relay.begin_stop()`. New DoH work is refused from this point.
3. `routes.remove()` and, on Linux, `link.remove()`, with the existing error
   checks. The routes no longer send host traffic into the TUN device.
4. `relay.stop()`, which runs the drain below and then the existing relay
   teardown, and returns a `RelayStopReport`.
5. Drop the TUN device (existing code).
6. Write the fault slot from both results (rules below).

The same order applies to the startup failure paths that hold a started relay
and installed routes. When the DoH profile is not active for the run, the
existing order is unchanged; WS1 does not change it. Whether to adopt
routes-first for every run is outside WS1 and is recorded as U61.

The dead-route window in a DoH run is therefore the existing worker exit plus
`begin_stop`, not the DoH drain. The drain then runs with no tunnel route in
place. That is safe only because every DoH outer socket is pinned to the
physical interface (section 6.3): `IP_BOUND_IF` on macOS, `SO_BINDTODEVICE` on
Linux, and `IP_UNICAST_IF`/`IPV6_UNICAST_IF` on Windows. A pinned socket does
not depend on the tunnel's `/1` routes or on the Linux policy rules at
priorities 17000 and 17001. This is a reading of the code, not a measurement.
H15 records the per-platform check that would close it. The DoH profile refuses
to start with `--no-pin`, so an unpinned DoH socket cannot exist; an unpinned
socket could loop into the TUN device while routes exist and would follow the
default route after removal.

Inside `Relay::stop`, the drain still runs **before** `running = false` and
before the shard join. A shard exits when `running` is false. If the relay
joins first, no shard can ack, terminalize its jobs, or accept a handback:

1. `begin_stop()` if it has not run.
2. Wait for the shard intake acks. `running` stays true so each shard can reach
   its loop boundary, ack, and keep servicing DoH events. If a shard does not
   ack within `T_ack`, record it and continue; the barrier is already
   `Incomplete`.
3. Run `Draining`, `JoinPool`, `JoinAdapter`, and `Sealed` as in the table.
4. Only after the DoH barrier returns, run the existing relay teardown:
   `running = false`, `input.clear()`, `wake.shutdown()`, then join the shard
   handles. The shards are idle after their drain ack, so this join is the
   existing one.
5. If the DoH barrier misses a phase deadline, abort it, mark `Incomplete`, and
   proceed to step 4 anyway. DoH must never make the existing stop hang longer
   than it already can.
6. Return `RelayStopReport { doh: DohStopOutcome, detached_pool_threads: u8,
   shard_join_failures: u8 }`, where `DohStopOutcome` is `NotActive`,
   `Sealed`, or `Incomplete { phase }`.

| Phase | Supervisor action | Shard action | Exit condition |
|---|---|---|---|
| `Running` | none | admit | `begin_stop` |
| `Stopping` | in one ledger-lock section: set the phase, settle every queued waiter and outstanding grant with `doh_cancelled`, stop granting; then wake every shard and the pool and close the adapter accept path | at the next loop boundary stop intake; reject queued adapter requests as `doh_cancelled`; a late `admit_granted` returns `Stale`; ack | every shard acks intake closed, or `T_ack` expires |
| `Draining` | wait for shard acks | mark every live job terminal with `doh_cancelled`; close attempts as `ech_error`; request cancellation and mark each session `Draining`; do not close a socket a pool attempt still holds; ack | every job is terminal, the waiter queue and grant table are empty, and no session accepts new work |
| `JoinPool` | close pool ingress; wake; wait for attempts to return | discard completions for terminal jobs; on each handback, take the connection lease, close it if not committed, and free the slot; drain queued, never-started attempts as `Handback::NotStarted` | every attempt has a handback and every session slot is freed, or `T_pool` expires |
| `JoinAdapter` | flush committed dispositions with a bounded deadline; stop the listener; close adapter connections | report any disposition that was committed but not written as a transport event; report every frame that never became an accepted job as an adapter error | adapter tasks exited, or `T_adapter` expires |
| `Sealed` | final snapshot; verify gauges, jobs, sessions, waiters, grants, credits, dispositions, and connections are 0 | none | published |
| `Incomplete` | record the phase that timed out in the `RelayStopReport` | none | the relay proceeds to the existing teardown and returns the report |

**How the service reports the result.** The fault slot gains a third field:
`(message, cleanup_failed, doh_stop_incomplete)`. After step 4 of the worker
order:

- A route or link cleanup failure is handled exactly as today: the route
  message, `cleanup_failed = true`, and `cleanup_blocked` after the stop. A DoH
  result never changes it.
- `RelayStopReport.doh = Incomplete { phase }` sets `doh_stop_incomplete =
  true`. It never sets `cleanup_failed` and never sets `cleanup_blocked`. The
  routes were removed and checked in step 3, so a DoH incomplete stop says
  nothing about the routing table, and the "inspect the routing table" message
  would mislead. When both happen, the route message is the primary
  `inner.error`; the DoH result is still recorded in its own field.
- When only the DoH stop is incomplete, `inner.error` is a fixed message:
  "Encrypted DNS did not stop cleanly. It stays unavailable until its stuck
  connection closes." The diagnostics ledger carries `exact: false` and
  `phase: "incomplete"`. The status runtime object resets to
  `unknown`/`not_running` as for any stop.
- `stop_locked` logs "Service stopped. Encrypted DNS did not stop cleanly."
  instead of "Service stopped." when only the DoH flag is set. It never logs
  "Route cleanup failed" for a DoH result.

**Restart after an incomplete DoH stop.** A detached pool thread can hold a
pinned outer socket until its blocked call returns. It belongs to the old run:
it holds an `Arc` of the old ledger, its event sender targets the old run's
dropped channel, and its send fails harmlessly. It cannot write the next run's
ledger. It is still a live thread with an open socket. The design therefore
keeps one process-wide atomic, `DOH_DETACHED_THREADS`. The barrier increments
it for each detached thread; the thread decrements it when its attempt returns
and drops its lease. A start that requests the DoH profile is refused with a
fixed `doh_stop_incomplete` error while the count is above 0. A start without
the DoH profile is not refused, because the tunnel does not depend on the old
DoH thread. The refusal is not `cleanup_blocked`; it clears by itself when the
thread exits, and the person can also restart the process. No component
restarts DoH automatically.

Rules:

- The DoH barrier has one bounded deadline (proposed 5 s, unmeasured). The
  proposed phase bounds are 250 ms for `Stopping` (the ack wait after
  `begin_stop`), 1 s for `Draining`, 2.5 s for `JoinPool`, 1 s for
  `JoinAdapter`, and 250 ms for `Sealed`. A phase that does not complete moves
  to `Incomplete`; the service reports an incomplete DoH stop, never a clean
  one.
- **The total stop budget is unknown.** It is `T_doh + T_relay_join +
  T_tunnel_worker_join + T_adapter_join`, and the last three are unbounded in the
  current code. Do not claim a 5 s stop. H6 and H13 record the measurement that
  would close the DoH part and the total part separately.
- **The DoH barrier does not extend the dead-route window in a DoH run.** The
  routes are removed after `begin_stop` and before the drain. T6.25 measures the
  time from the worker loop exit to the end of route removal with a drain held
  open, and asserts it does not include `T_ack`, `T_pool`, or `T_adapter`.
- A shard stays alive after its drain ack until `JoinPool` completes. It keeps
  discarding late events for terminal jobs and does not admit or deliver
  anything. This is how a completion that the pool sends during its unwind is
  discarded by job ID and attempt ID instead of blocking the pool.
- **The stop caller does not wait on a channel it must drain.** The supervisor
  sets the phase and reads an atomic ack or a per-shard ack slot; it does not
  require a shard to send on a channel that the supervisor itself must service.
  Each shard reaches its loop boundary, processes its own events, and acks. If a
  shard cannot reach its boundary because it is blocked in a pool send, the
  reserved event capacity means that send cannot block; a shard blocked
  elsewhere is a missed ack and an `Incomplete` result, not a deadlock.
- **`Drop` is not a clean-stop report.** `Drop` runs the same barrier with the
  same bounds, writes the `RelayStopReport` to a shared slot if one exists, and
  otherwise cannot report. `Drop` has no route context, so the routes-first
  order above applies only to an explicit stop by the tunnel worker. A stop
  that only ran from `Drop` publishes
  `ledger.exact = false` with phase `drop_only`, because no caller observed the
  barrier. `Drop` never claims a clean stop and never panics. It uses
  non-panicking operations and closes only objects it can prove it still owns.
  It does not run on the shard threads it is waiting for.
- **A stuck pool thread is reported, not hidden.** Rust cannot kill a thread.
  If a pool attempt does not return within `T_pool`, the barrier closes the
  sockets it can prove (a connection lease still in the ledger, a queued but
  unstarted attempt), marks `Incomplete`, increments `DOH_DETACHED_THREADS`,
  and detaches the thread. The socket that the stuck attempt holds is **not**
  closed by the barrier: the thread owns it and is blocked in a call that uses
  it. It closes when that call returns and the thread drops its lease, or when
  the process exits. Do not claim that every thread or socket is gone; say the
  thread was detached, its socket may still be open, and the DoH stop was
  incomplete.
- The adapter accept loop is nonblocking or wake-driven, so it cannot sit in a
  blocked `accept` past the bound.
- A completion that arrives after its job was marked terminal is discarded by
  job ID and attempt ID. It never creates an outcome. Its
  handback still returns the reserved work item and, if it carries a lease,
  closes the lease.
- A second stop is a no-op. A stop while `Incomplete` reports the same failure
  and does not start a new pool or adapter.
- The final snapshot is published only from `Sealed`. `Incomplete` publishes
  the counters with an explicit `exact: false` marker and the phase name; the
  UI must not present an inexact ledger as exact.
- An inner DNS packet that was still in the relay input queue when `input.clear`
  ran was never admitted. It is not a `doh_query`, moves no DoH counter, and is
  covered by the relay's existing drop accounting. Do not invent a DoH outcome
  for it.

#### 6.4.9 Bounded values

These are proposed values. Section 6.8 marks which are hypotheses. Measure
before fixing.

| Limit | Proposed value | Bound or reason |
|---|---|---|
| Relay shards | 1 to 8 | Existing `Relay::start`; every bound below is global, not per shard |
| DoH pool threads | 8, measured (section 6.5) | Bounds blocking TLS work; the envelope depends on it |
| Global job bound `G` | 64 | Bounds memory and latency across all shards |
| Global session bound `S` | 64, floor 32, measured (section 6.5) | Bounds fds and source device relay slots |
| Per-session in-flight | 1 | DNS is normally serial |
| Per-session queued | 4 | Bounds a stuck client |
| Slot waiters `W` | 64 | One global FIFO in the ledger, across all shards |
| Grant acceptance `T_grant` | 100 ms; `grant_deadline = min(grant time + T_grant, absolute deadline)` | A revoked grant is settled once through `settle_waiter`, which returns the slot |
| Config fetch `retry_after` after a failed fetch | 5 s, proposed, unmeasured | Bounds fetch attempts while the endpoint fails; a cancelled fetch sets none |
| Adapter reorder buffer per connection | 4 dispositions | Equals the frame credits; dispositions are written in `request_id` order |
| Graceful close drain per connection | the latest remaining request deadline (at most 8 s) plus the write bound | The adapter stops reading and writes the remaining dispositions, then FIN |
| Attempt work items per job | 2 | The first attempt and the one retry are reserved at admission |
| Event slots per job | 5 | Two attempts at two events plus one completion |
| Delivery / terminal dispositions | 1 per accepted TCP:53 job | Reserved at admission; exactly one answer or close |
| Completion drain per shard loop | 64 | Keeps packet processing fair |
| Adapter authenticated connections | 32 | An independent local bound; not a DoH session reservation |
| Adapter unauthenticated connections | 8 | Bounds pre-cookie sockets |
| Adapter frame credits per connection | 4 | The adapter stops reading that connection when its credits are spent |
| Adapter admission credits total | 128 | 32 connections times 4; the adapter admission path is sized to it, so a full channel is impossible |
| Pool attempt work items | 2 per job, 128 total | One first attempt and one retry per admitted job, reserved at admission |
| Adapter disposition slots | 64 | Equals `G`; one per accepted query across all connections |
| Adapter rejection dispositions | 128 | One `Close` per rejected or expired TCP waiter, bounded by the credit path |
| Adapter event slots | 32 | One per authenticated connection for close and write-failure events |
| Stop phases | 250 ms, 1 s, 2.5 s, 1 s, 250 ms | Proposed, unmeasured; the total stop time is not bounded by these alone |
| UDP quiet window | 250 ms | Keeps a stub's reuse while freeing a churned slot |
| UDP hard idle | 2 s | Upper bound even if the relay flow entry lives 120 s |
| TCP idle | 30 s | Matches the inner TCP:53 client expectation |
| Request deadline | 5 s default, 8 s max, from arrival | Includes slot wait and queue wait |
| ECH config cache entries | 4 | One configured endpoint plus tests |
| ECH config list size | 64 KiB | DNS RR bound |
| DoH barrier total | 5 s | DoH phases only; this is not the total process stop time (section 6.4.8) |

The source device transport is a special case. In `tun --phone` mode, the DoH
pool cannot drive the shard's nonblocking `Setup` state machine. Refactor
`Setup` into one reusable type with two drivers: the existing nonblocking
driver and a blocking completion helper that polls with a deadline and a stop
flag in every state. Do not duplicate the SOCKS wire format in a second module.
One implementation, two drivers. Cancellation covers the whole setup, as
section 6.3 requires. This refactor is unproven and is an open item.

#### 6.4.10 Connection lease, handback, and slot release

This subsection closes the gap between "the pool closes its own socket" and
"the session owns the connection". The rule is one holder at a time and a slot
that is not freed until the attempt that held it has returned.

The connection is a move-only `DohConnection` (the outer socket plus its TLS
session). It is held through one `ConnectionLease`:

| Holder | When | What it may do |
|---|---|---|
| `PoolAttempt { job_id, attempt_id }` | the pool dequeues a reserved attempt and connects | read, write, handshake, HTTP; close on failure; move the live connection in the completion |
| `Session { session_generation }` | the shard installs the connection after a committed response, or between the fetch job and the queued user query. The value is the session incarnation and does not change on install | keep it idle, hand it to the next attempt, close it on the session release path |
| `None` | before connect, after a failure, after a close | nothing |

Rules:

- **Transfer is a move in the event.** The pool sends
  `Completion { job_id, attempt_id, result, connection: Some(lease) }` for a
  valid response. Sending moves the lease. The pool must not touch it after the
  send. For a failure, a timeout, a cancellation, or an authenticated ECH
  rejection, the pool closes the socket and sends `connection: None`.
- **The shard decides.** Under the ledger lock it either installs the lease
  into the session (commit) or drops it (terminal, stale attempt, stop).
  Dropping the lease closes the socket. The pool never decides to keep a
  connection for a later job.
- **A slot is held for the whole live job, not only while a lease exists.** The
  session's `slot_state` is `Attempting { job_id, attempt_id }` from dispatch
  until the shard observes the handback for that attempt. On an authenticated
  rejection it becomes `BetweenAttempts { job_id }`: the attempt work item is
  back, no lease is held, and the session slot is still reserved for the retry.
  The retry dispatch moves it to `Attempting { job_id, attempt_id: 2 }`. It
  becomes `Ready` when a live lease is installed, and `Free` only when the
  job has no further attempt and the last handback carried `None` or a dropped
  lease. A terminal decision alone does not free the slot.
- **A handback is mandatory.** Every dispatched attempt produces exactly one of:
  - `Completion { connection: Some }` for a live connection;
  - `Completion { connection: None }` for a failed or cancelled attempt;
  - `AttemptOutcome { RejectedAuthenticated, connection: None }` for the retry
    decision;
  - `Handback::NotStarted` if the pool never dequeued the attempt;
  - `Handback::Abandoned` if the pool thread is being detached, which the
    supervisor treats as `Incomplete`.

  The reserved attempt work item is returned only by one of these. There is no
  path that reserves a job and then silently drops it without a handback or a
  recorded rejection.
- **Early terminal does not free the slot.** If the shard terminalizes a job
  for a deadline, stop, inner close, or cancellation while an attempt is
  outstanding, it sets `terminal = true` and keeps
  `slot_state = Attempting`. It also sets the job's stop flag so the pool
  returns promptly. The slot frees when the handback arrives.
- **Stop drains the queue.** `JoinPool` closes the ingress and the supervisor
  dequeues every never-started attempt with `Handback::NotStarted`. Only then
  does it free the corresponding session slots. A session with no outstanding
  attempt and no live lease is closed and freed at the end of `JoinPool`.
- **No slot is freed twice.** The handback carries `job_id` and `attempt_id`.
  A handback for an older attempt that is not the session's current attempt
  returns its work item but does not touch the current slot. The release path
  checks `session_generation` (the session incarnation) and the attempt ID.
- **The disposition slot is independent.** A committed answer lives in the
  reserved disposition slot, not in the connection lease. Freeing the session
  slot after the handback does not invalidate a committed disposition. The
  adapter writes it in `request_id` order or counts it once as undelivered
  (section 6.6). A later commit on the same session never makes it stale, and
  the adapter never drops it for that reason.
- **Panic.** A pool panic drops its lease during unwinding, which closes the
  socket. The supervisor records the attempt as `Handback::Abandoned` and does
  not publish the ledger as exact. A shard panic leaves the supervisor unable
  to prove the lease state; it force-closes every known session and reports
  `Incomplete` (section 6.7).

### 6.5 Per-query cost

A DoH query is not free.

- The first query on an inner DNS flow pays a TCP handshake, a TLS 1.3
  handshake (plus a possible HelloRetryRequest), and one HTTP request. On a
  hotspot with 30 to 100 ms RTT, that is roughly 2 to 3 RTT before the answer,
  or 60 to 300 ms. In source proxy mode, add one SOCKS CONNECT RTT through the
  source device.
- Later queries on the same inner flow reuse the connection. A stub resolver
  that keeps one UDP socket pays one handshake per stub socket, not per query.
  A resolver that opens a new source port per query pays a handshake per query.
- TCP:53 retries add a loopback connection and a DoH connection. A resolver
  that opens a new TCP:53 connection per query pays the full cost per query.
- No resumption is allowed in the outer hello. Every new flow pays a full
  handshake. This is a privacy choice, not an oversight.
- Memory: a TLS session with buffers is tens of KiB. 64 concurrent sessions
  can be a few MiB. Measure it.
- File descriptors: one per DoH TLS connection plus one per source device
  outer stream. The adapter adds one local fd per inner TCP:53 flow. Bound the
  cache; do not share to save fds.
- The session cap is a hard cap on **concurrently live DoH sessions**, across
  UDP:53 and TCP:53 and all shards. It is not a count of relay flow-table
  entries and not a cache of closed flows. When the cap is reached, a new
  session enters the bounded slot wait (section 6.4.3); if the wait expires,
  the query fails with `doh_queue_full`. The engine never evicts another
  session's connection. A session is closed only by its own named release path
  (section 6.4.6), and its own slot is freed. The only replacement of a live
  session's connection is the bounded ECH retry in section 5.3, and it closes
  that session's old connection first.
- The adapter's authenticated-connection cap is an independent local bound. It
  is not a DoH session reservation. It may be larger or smaller than the
  session cap; the session cap governs whether a query gets a DoH connection.
  Do not claim that an adapter slot is a session slot. Each authenticated
  adapter connection also has four frame credits; those credits bound the
  frames that can be outstanding, not the number of DoH sessions (section 6.6).
- **Per-query-port churn is the capacity case that revision 6 got wrong.** A
  stub resolver that opens a new UDP source port per query creates one inner
  flow and one DoH session per query. With a 30 s idle window, a trivial 2
  queries per second would hold about 60 sessions and exhaust a 32-slot cap.
  Revision 7 fixes this with three separate mechanisms:
  1. **The DoH session does not inherit the relay flow lifetime.** In direct
     mode the relay keeps a UDP flow entry for `UDP_IDLE` (120 s,
     `rust/src/relay.rs`). The DoH session closes after 250 ms of quiet and in
     no case later than 2 s after its last committed query. A relay flow entry
     can outlive its DoH session, and a later query on the same inner 4-tuple
     opens a new session with a new generation.
  2. **A bounded FIFO slot wait absorbs a burst.** A query that needs a new
     session while the cap is full waits up to 250 ms or one quarter of its
     remaining deadline, whichever is smaller. A released slot goes to the
     oldest waiter. The wait never blocks a shard and never opens a second
     session for the same flow.
  3. **The cap is sized from measured peak concurrency.** The proposed default
     is 64 sessions with a floor of 32. The cap is a measured parameter, not a
     constant copied from the previous revision.
- **The capacity envelope is stated, not assumed.** With `P` pool threads, a
  handshake and HTTP exchange of `h` seconds, and a quiet window `q`, the
  sustained per-query-port rate is about `P / h` queries per second, and peak
  sessions are about `qps × (h + q)`. At `h = 0.3 s` and `q = 0.25 s`:

  | Pool threads `P` | Sustained ceiling `P / h` | Peak sessions at that rate | Peak at 10 qps | Peak at 50 qps |
  |---|---|---|---|---|
  | 4 | about 13 qps | about 7 | about 6 | not reachable |
  | 8 (proposed) | about 26 qps | about 14 | about 6 | not reachable |
  | 16 (upper bound) | about 53 qps | about 29 | about 6 | about 28 |

  A one-off burst is the common desktop case, not a sustained high rate. A
  burst of 50 names with 8 threads takes about 1.9 s to drain and peaks near
  50 sessions, inside the proposed 64. These numbers are a hypothesis, not a
  measurement. Section 6.8 records the measurement that would close them.
- **Above the envelope, the failure is explicit.** A query that cannot get a
  session before its deadline fails with `doh_query_failed` and cause
  `doh_queue_full`. It never opens a second connection for the same flow,
  never shares a connection across source ports, and never sends plaintext.
  The UI coverage state becomes `failed` with reason `doh_failed`; the
  capability string does not change.
- **The relay flow table keeps its own bound.** Each shard still holds at most
  128 flow entries, and its existing idle-UDP eviction rule can reclaim an
  entry only when that entry has no pending work. That rule is not a DoH
  session eviction and does not close another session's connection. A DoH
  session can outlive its relay flow entry only until the shard's own expiry
  path calls `close_flow`.
- **Connection coalescing across source ports is an unapproved product
  option.** Sharing one DoH connection among queries from different inner
  source ports would raise the envelope and lower handshake cost. It would
  also fan in unrelated inner flows over one outer socket, weaken the
  one-inner-flow-to-one-outer-socket mapping, and change the flow shape the
  design treats as a fingerprint. It is **not** a default and not part of this
  design. It is recorded as U56 and needs its own product decision and review.
- **The cap must fit the fd and source device budgets.** In source device proxy
  mode each DoH session consumes one source device relay slot, and application
  flows share that budget. The iOS app allows 256 relays plus 32 setup sessions
  only when the open-file limit permits. The Android app derives its cap from
  the soft open-file limit as `min(288, (soft limit - 32) / 9)`, with a setup
  reserve of `ceil(total / 9)` capped at 32. A lower limit gives fewer relays.
  The DoH session cap is `min(proposed 64, target fd budget, source relay
  budget)`. The source device protocol reports no current free-slot count, so
  no cap may depend on one. A source device capacity error fails the query with
  `doh_query_failed` and cause `doh_other_error`, terminal reason
  `source_capacity`. It is not a reason to fall back to plaintext. Asking the
  source device for free slots would be a protocol change on both apps and is
  out of scope (U34).

Measure peak concurrent sessions, handshake time, and pool occupancy on a real
hotspot before choosing the cap and the pool size. A VM or loopback number is
not a carrier number.

#### 6.5.1 What the capacity model does not claim

- It does not claim that 64 sessions serve every workload. It claims a declared
  envelope and an explicit failure above it.
- It does not claim that a quiet close is free. A per-query-port client pays a
  handshake per query, as the cost list at the start of this section states.
- It does not claim that closing a UDP session closes the relay's inner flow
  entry. The two lifetimes are separate by design.
- It does not claim that a wait of 250 ms is enough for every burst. The wait
  is bounded by the query deadline, and a timeout is a failure, not a
  plaintext fallback.

### 6.6 Loopback TCP:53 adapter access control

The adapter is a local DNS-over-TCP endpoint. It must not become an open local
resolver.

Controls:

- Bind `127.0.0.1:0` only. Never `0.0.0.0`, never a LAN address. The port is
  ephemeral and is not written to status, logs, or diagnostics.
- One listener per relay start. Start it with the relay, stop it with the
  relay, and join it. A second start fails. The accept loop is nonblocking with
  a short poll timeout or a wake socket, so stop joins within a bounded time
  and never waits on a blocked `accept`.
- Require a 128-bit random cookie as the first bytes on every connection. The
  relay writes the cookie when it connects an inner TCP:53 flow. The adapter
  reads it with a 1-second deadline. A wrong or missing cookie closes the
  connection. The cookie is per relay start, held in memory, never logged.
- After the cookie, the relay writes a fixed **32-byte preface**:
  `version (1) | family (1) | address (16) | port (2, BE) | shard (1) |
  connection_id (8, BE) | reserved (3, zero)`. An IPv4 address is left-aligned
  in the 16 address bytes and the rest are zero. The adapter uses the
  destination only for a failure record on the matching flow and the shard
  index only to address the admission request. It never routes on the
  destination, never resolves it, and never logs it. The preface is local
  loopback framing, not a source device protocol. This is what lets a TCP:53
  failure name the inner destination that `FailureEvent::doh_query` needs.
  A bad version, family, address, port, shard index, or a non-zero reserved
  field closes the connection and counts `doh_adapter_errors`. A local process
  that holds the cookie can send any shard index, but it can only add load to a
  shard; it cannot choose a destination or bypass DoH.
- Cap authenticated connections at 32 and unauthenticated connections at 8.
  These are local socket bounds. They are not a DoH session reservation. A
  query can still fail with `doh_queue_full` when the global session cap is
  full. Never evict an authenticated connection and never evict an
  unauthenticated connection. When a cap is full, close the new connection
  immediately. An unauthenticated connection that does not present the cookie
  within 1 second is closed. Do not rely on eviction to make room for the relay:
  a flood can win that race, and the threat model accepts a local denial of
  service. The relay retries its adapter connection with a short bounded backoff
  up to the connect deadline. A failed retry fails that inner TCP:53 flow and is
  counted; it does not fall back to plaintext.
- **Admission credits, not a dropping channel.** Each authenticated adapter
  connection has four frame credits. The adapter reads a complete frame only
  when it holds a credit for that connection, then sends
  `AdapterAdmission { connection_id, request_id, preface, frame }` to the shard
  and decrements the credit. The shard returns the credit when it emits that
  job's disposition. The adapter admission path is sized to `32 × 4 = 128`, so a
  credit-respecting adapter can never find it full. There is no
  "admission channel full, close the connection" path. If a connection waits
  for a credit past its 30 s read deadline, the adapter closes that connection
  and reports `AdapterEvent::ConnectionClosed`.
- **One reserved disposition per accepted query.** At admission, a TCP:53 job
  reserves one `AdapterDisposition` in a shard-to-adapter path of `G` slots.
  Every accepted job ends with exactly one of:
  `Answer { connection_id, request_id, job_id, session_generation, bytes }` or
  `Close { connection_id, request_id, job_id, cause }`. The adapter writes the
  frame for an answer and performs the graceful close below for a close. It
  never leaves a failed query open until the idle timer. The disposition path
  cannot fill: each connection has at most four outstanding frames and the
  total accepted jobs are at most `G`.
- **Ordered application.** The adapter assigns `request_id` in read order per
  connection, starting at 0. It keeps a reorder buffer of at most four
  dispositions per connection, the credit bound, and applies dispositions
  strictly in `request_id` order. A disposition that arrives early waits in the
  buffer for the lower `request_id`s. This handles the pipelined case where the
  shard commits request `n + 1` before the adapter has written request `n`:
  both answers are written, in order. The adapter does not compare a
  disposition with "the current" job or session generation. The only checks
  are that the connection is live and that the `job_id` has not been applied.
- **Graceful close.** When the next disposition to apply is a `Close` for
  request `k`, the adapter has already written every request below `k`. It then
  stops reading new frames on the connection (credits are no longer used for
  reads), applies the dispositions of the requests above `k` that were already
  read and sent for admission, each as it arrives in order, and then sends FIN.
  The drain is bounded by the latest remaining request deadline (at most 8 s)
  plus the write bound. If the inner client closes first, the remaining
  answers are undelivered and counted. A failure of request `k` never turns an
  earlier or later admitted request into `doh_cancelled`; each keeps its own
  outcome. A `Close` that carries an admission rejection (`doh_queue_full`,
  `doh_timeout`) does not affect the session or its connection. A `Close` that
  carries a session transport failure arrives together with the `flow_closed`
  closes for the session's queued jobs (section 6.4.5).
- **Undelivered answers are counted.** A committed `Answer` that is not
  written, because the inner client closed, the write bound expired, or the
  stop flush deadline passed, increments `doh_adapter_errors` once and keeps
  its `doh_query_ok`. No committed answer leaves the adapter uncounted.
- The adapter never submits a job to the pool and never writes a DoH counter. It
  sends each complete frame as an admission request to the shard named in the
  preface. That shard owns the job, the completion slots, the counters, the
  config-cache commit, the failure record, and the disposition. The adapter
  never drops a query silently and never answers it from a local source.
- The adapter receives bytes only as a committed `AdapterDisposition::Answer`
  (section 6.4.5). It has no direct path from a pool completion to the inner
  stream. It applies dispositions under the ordered rule above. A second
  disposition for a `job_id` that was already applied cannot happen by
  reservation; a test that injects one sees it dropped with a test-only
  diagnostic and no counter change. A write failure after a commit is an
  adapter transport event in `doh_adapter_errors`; it does not retract the
  committed outcome. A close disposition caused by a query failure is not an
  adapter error: the query failure was already counted in `doh_queries`.
- **Failure delivery is explicit.** A failed query never waits for the idle
  timer. The owning shard emits `Close { cause }`; the adapter performs the
  graceful close above. If the adapter is gone before it can act, the shard
  records `doh_adapter_errors` once for each committed answer it could not
  hand over, keeps every query outcome, and releases the disposition slots.
- Bound the 2-byte frame length to 12..65535. Bound the idle time to 30 s.
  Bound the total connection lifetime to the inner flow lifetime.
- Use nonblocking or deadline-bound reads and writes in the adapter. A slow
  inner client must not block the accept loop or another adapter flow. Each
  adapter flow has its own bounded state or worker. A full write buffer fails
  that flow; it does not stall the service.
- Do not recurse. The adapter answers only through the DoH pool. It never
  queries the system resolver, the tunnel, or another local resolver.
- Do not store the QNAME. The adapter forwards the message bytes. The only
  parsing is the 2-byte framing and the minimal question parse needed for a TC
  response; that parse does not retain the name.
- On adapter failure, close the inner connections and count the failure. Do
  not fall back to plaintext.

Threat model: a local process without the cookie can connect and consume a
slot. It cannot resolve a name, and it cannot evict the relay or an
authenticated flow. A sustained flood can fill the unauthenticated cap and
cause a local denial of service, including denial of a new inner TCP:53 flow.
The design accepts that. A process that can read the relay's memory can read the
cookie, but it can also read the token and the traffic. The adapter does not
widen the trust boundary beyond local code execution. Do not write a test that
requires the relay flow to be served during a sustained flood; that would
contradict the accepted threat model.

If a future review rejects the adapter's local surface, the fallback is a
virtual outer stream: the inner TCP endpoint writes DNS-over-TCP bytes to a
bounded queue, and the DoH pool reads them. That removes the listener but
changes the inner TCP pump and flow control. It is a larger change. Do not do
both.

### 6.7 Cleanup and crash behavior

- DoH creates no route, address, or device. It owns threads, a loopback
  listener, sessions, and sockets only.
- **Normal stop** follows section 6.4.8. In a run with the DoH profile active,
  the tunnel worker calls `relay.begin_stop()`, then removes routes and the
  address, then calls `relay.stop()`. Inside `relay.stop()` the shards ack
  while they can still run, the pool drains through handbacks, the adapter
  flushes and closes, and the ledger seals. Only then does the existing relay
  teardown clear the input, close the wake pairs, and join the shards.
  `Drop` runs the same barrier, but a Drop-only stop is reported as
  `exact: false` with phase `drop_only`, because no caller observed the outcome.
  A second stop is a no-op. A barrier that misses a phase deadline returns
  `Incomplete` in the `RelayStopReport`; the service reports an incomplete DoH
  stop with its own message, never a clean one, never as a route failure, and
  the existing relay teardown still runs.
- **A stop does not admit new work.** The phase lives in the ledger lock, so a
  racing admission either reserved before the transition (and is drained) or
  observed `Stopping` and was rejected with `doh_cancelled`. There is no third
  outcome and no queued request that survives the barrier.
- **The total stop time is not bounded.** The DoH barrier has a proposed bound.
  The existing relay and tunnel-worker joins have none. A DoH phase that misses
  its bound is aborted so it does not add a new hang, but the total stop can
  still block in the existing joins. The service holds the lifecycle lock during
  stop, so a hung join also blocks a new start. Do not claim otherwise until a
  measurement exists.
- A process crash closes the sockets. Because there is no host resolver
  override and no persistent DNS state, there is nothing to restore on the
  host. DoH creates no route, but it changes when routes are removed: in a DoH
  run the routes are removed before the DoH drain, so the drain cannot lengthen
  the time that host traffic is routed into a dead TUN device (section 6.4.8,
  H15). Route ownership, route checks, and crash recovery of routes stay with
  the existing route code and are unchanged.
- **An incomplete DoH stop is not a route failure.** It never sets
  `cleanup_blocked`. It blocks only a later start that requests the DoH
  profile, and only while a detached DoH pool thread from an earlier run is
  alive (section 6.4.8).
- A DoH failure must not leave a half-open inner UDP flow or a half-open TCP
  connection. The shard's normal flow expiry handles the inner side; the
  adapter closes its side. A committed delivery whose inner client closed is an
  adapter transport event, not a stuck flow.
- The ECH config cache is memory only and is cleared at the barrier. No file,
  no keychain, no registry, no `~/.config` entry.
- **Pool job panic.** A pool attempt is wrapped. A panic in one attempt is a
  terminal outcome for that job: the owning shard records `doh_other_error` with
  reason `pool_unavailable` (or the job's own classified cause if it had one),
  closes the attempt as `ech_error`, drops the lease if unwinding has not
  already closed it, and frees the session after the `Handback::Abandoned`. A
  **second** panic in the same relay run marks the pool unavailable: the
  supervisor starts a DoH-only stop, records `pool_unavailable` for every
  accepted job with no outcome, and does not restart the pool. The tunnel stays
  up for non-DNS traffic. Runtime coverage becomes `failed` with reason
  `doh_failed`; the capability string does not change. Captured DNS then gets
  no answer and no plaintext fallback, so name resolution through the tunnel is
  dead while the tunnel stays up. Whether that is acceptable, or whether the
  tunnel must stop as well, touches `AGENTS.md` invariant 13 (a stale tunnel
  must not hide a dead path) and is a product-owner decision (U62). This design
  proposes keeping the tunnel up with the `failed` coverage state visible, and
  does not claim the owner agrees.
- **Shard panic.** The relay's existing worker-exit path stops the tunnel. The
  DoH supervisor sees the shard ack missing, moves the barrier to `Incomplete`,
  force-closes that shard's known sessions and sockets, and does not publish the
  ledger as exact. Other shards are drained and joined. Do not claim per-query
  accounting survives a shard panic. The service reports the failed stop, and
  the normal route cleanup runs.
- **Adapter panic.** The supervisor marks runtime coverage `failed`, closes the
  listener and open adapter connections, sends a `Close` disposition for every
  accepted job whose adapter connection is gone, and sends the terminal events
  it can for the adapter's flows to their owning shards. The pool may continue
  for UDP:53 only when the adapter reported a clean close, no disposition is
  outstanding, and every shard is healthy. Otherwise it runs a DoH-only stop.
  Do not restart the adapter silently.
- **Supervisor panic.** It is a process-level failure. The relay stop path and
  the service supervisor report a failed stop. No component restarts the DoH
  service.
- A panic must leave no listener and no connection that the process can still
  close. A test asserts the absence of the listener and of a stale exact ledger.
  A pool thread that cannot be joined after a stuck call is detached and
  reported, not claimed gone.

### 6.8 Hypotheses and the evidence that would close them

| ID | Hypothesis | Why it matters | Evidence that closes it | Status |
|---|---|---|---|---|
| H1 | Desktop stub resolvers open a new UDP source port per query at the rates assumed | It sets the session churn | A DNS-specific capture of inner 4-tuples per platform, no user payload | Open |
| H2 | Peak concurrent DNS queries on a normal desktop burst stay under the proposed envelope | It sizes `S` and the pool | A burst measurement (browser cold start, OS update) per platform | Open |
| H3 | 250 ms quiet and 2 s hard idle keep a stub's reuse while freeing churned slots | It is the main capacity fix | A mock and then a live run with a per-query-port client and a reusing client | Open |
| H4 | 8 pool threads and `S = 64` serve the measured envelope with headroom | It sets the blocking pool | The T8 load test plus a hotspot measurement | Open |
| H5 | The ledger lock is cheap enough at envelope rates | It serializes all admissions and commits | The T7 multi-shard stress test at 1, 2, 4, and 8 shards | Open |
| H6 | A 5 s DoH barrier with a 200 ms cancellation slice completes on every platform, and the existing relay and tunnel joins do not add an unbounded delay | It decides clean versus failed stop and the total stop time | T6.16 to T6.19 and the new T6.22 to T6.24 on each target, with each phase and each existing join timed separately | Open |
| H7 | The local preface can carry the shard index without breaking the adapter | It routes TCP:53 jobs | The adapter and relay tests; it is local framing, not a wire protocol | Design invariant |
| H8 | `systemd-resolved` and `mDNSResponder` bind some queries to the physical link | It changes the bypass table | A live DNS-specific run per platform | Open |
| H9 | rustls at the pinned version exposes the ECH client API assumed in section 5.2 | It gates the ECH build | A compile spike against the pinned crate | Open |
| H10 | Real DoH providers accept HTTP/1.1 POST | It gates the whole DoH client | Two independent providers | Open |
| H11 | `ring` and `aws-lc-sys` build on all shipping targets | It gates the feature matrix | A per-target build | Open |
| H12 | Closing a DoH session early does not change the carrier's flow classification in a way that matters | It is a shape claim | A carrier measurement, never a VM result | Open |
| H13 | The total stop budget is dominated by the existing `Relay::stop` and tunnel-worker joins, not by the DoH barrier | The service holds the lifecycle lock during stop, so a hung join blocks a new start | Time each join separately on each target; do not treat the 5 s DoH bound as the total | Open |
| H14 | Adapter credits keep the shard ingress from filling without dropping a frame | It replaces the old "channel full, close" path | T8.24 with a flood on all 32 authenticated connections | Open |
| H15 | A pinned DoH outer socket keeps working after the tunnel routes, the Linux policy rules, and the TUN address are removed, on macOS (`IP_BOUND_IF`), Linux (`SO_BINDTODEVICE`), and Windows (`IP_UNICAST_IF`/`IPV6_UNICAST_IF`), in direct and source device proxy mode | The routes-first stop order in section 6.4.8 depends on it | A per-platform host test that holds a pinned DoH connection open, removes the routes, then completes the query; plus T6.25 for the order. A VM result covers the platform stack, not a carrier | Open |

## 7. Privacy of records and outputs

### 7.1 Failure records and the existing name map

The in-memory failure recorder already maps A and AAAA answers to names
(`rust/src/failures.rs` `remember_dns_response`). The relay calls it on
plaintext phone DNS replies (`rust/src/relay.rs`). That map is a pre-existing
privacy surface. It is in target memory only and is never written to disk, but
it is shown in "Recent failures".

Rules for the DoH path:

- DoH must never call `remember_dns_response`.
- DoH must never parse a forwarded QNAME for a name hint.
- DoH must never attach the DoH endpoint name, the QNAME, the ECH public name,
  or the ECH config to a failure record.
- Do not reuse `FailureEvent::dns`. It always records `1.1.1.1:53`
  (`rust/src/failures.rs`). Reusing it would report an encrypted DNS failure as
  a failed plaintext lookup.
- **A DoH failure record is a new privacy scope.** It adds a numeric inner
  destination and a failure reason to "Recent failures" for a query that the
  user selected as encrypted DNS. Direct mode has no equivalent record today,
  so a direct-mode record is a new behavior, not a fix. It needs its own
  acceptance in the DoH scope (section 4.1.1), separate from this design
  review.
- **Default for the proposed scope: counters only, no DoH failure record in
  either mode.** This keeps the existing failure surface unchanged. A DoH
  failure is visible in `doh_query_failed` and its cause, not in "Recent
  failures".
- If the scope acceptance explicitly includes a record, add
  `FailureEvent::doh_query(destination, port, reason, code, phase)`. It takes
  the same `Option<Phase>` argument as the existing constructors
  (`rust/src/failures.rs`) and stores it. It sets `proto = Proto::Dns`, the
  inner destination address and port, and no name. Do not add an endpoint field.
  A constructor without `phase` would drop a field that every existing failure
  record carries.
- The UDP path knows the inner destination from the packet. The TCP:53 adapter
  gets it from the fixed 32-byte preface in section 6.6. A record raised for a
  TCP:53 job therefore names the inner destination, not the loopback listener. The
  worker writes the record from the job record; the adapter never writes one.
- Do not reuse `Relay::record_dns_failure`. It returns early when
  `config.phone.is_none()` (`rust/src/relay.rs`), so it records nothing in
  direct mode. A separate `record_doh_failure` path is required only if the
  scope includes records.
- Clear the name map when a mode that includes DoH starts, so names from an
  earlier plaintext session are not shown under the new mode. The recorder is
  already cleared on tunnel start and stop
  (`rust/src/service.rs`); verify it stays cleared on a mode change. This rule
  applies even when DoH failure records are off, because the map is shared.
- A record, if enabled, uses the inner destination address and the `dns`
  protocol. A numeric address is already part of the record; a name is not.
- If the scope wants no addresses either, record only a counter. That is a UI
  decision, not a reason to add names.
- If the plaintext profile is active, it may use the existing name map,
  because that path is plaintext and the UI says DNS is not private for as long
  as it is active. A DoH profile never feeds the map.

The endpoint name exists in process memory as configuration. It is the fixed
configured resolver, not a user destination. It must not appear in any output.

### 7.2 Counters

Existing counters remain the contract. Add only what is needed, and keep the
names literal. The ECH and DoH identities hold exactly in a **coherent
snapshot**, because every admission, outcome, and gauge change is one ledger
update and a reader clones one snapshot. Section 7.2.1 and section 7.2.2 state
them. A final snapshot after the stop barrier seals is also exact.

The **admitting shard is the accounting owner for the jobs it admits**. It is
not "the relay worker", because 1 to 8 workers exist. Every shard writes the
same `DohLedger` under one lock, and no job is owned by two shards. The pool
sends events and never writes a counter. The TCP:53 adapter sends admission
requests and delivery acknowledgements and never writes a counter. This
prevents a pool result, an adapter event, and a shard deadline from counting one
query twice. Object ownership is defined in section 6.4.2.

A shard's counter view is therefore not a separate ledger: every field lives in
one global object, so a snapshot from any shard is the same coherent snapshot.
Per-shard job tables hold ownership, not accounting.

| Counter | Meaning | Overlap rule |
|---|---|---|
| `doh_lookups` | The endpoint's own ECH-config HTTPS/SVCB lookup over DoH. Narrowed from the current comment "HTTPS or SVCB lookups over DoH"; WS0 must record the narrowing | An inner QTYPE 65 lookup counts only in `doh_queries`, never here |
| `doh_ok` | Those endpoint ECH-config lookups that succeeded | Not an inner DNS answer |
| `doh_failed` | Those endpoint ECH-config lookups that failed | Not an inner DNS failure |
| `doh_queries` | Inner DNS query jobs a shard admitted for a DoH attempt on either path, plus an admission rejection for the global job bound, the per-session bound, the global session bound after the slot wait, or a missing reservation. A global waiter records it once at its terminal transition: grant to a job, expiry, or cancel. Incremented only by the admitting shard | The forwarder total. Includes `doh_in_flight`. An adapter admission-channel failure with no accepted query is `doh_adapter_errors` |
| `doh_in_flight` | Gauge: admitted query jobs with no terminal outcome yet, across all shards | Part of `doh_queries`; 0 after a clean stop |
| `doh_query_ok` | The owner committed a validated DNS answer for delivery to the inner transport. It does not mean the inner client read it; a later write failure is `doh_adapter_errors` | One terminal outcome per `doh_queries` |
| `doh_query_failed` | DoH query failures, all causes | One terminal outcome per `doh_queries` |
| `doh_timeout` | The absolute deadline, measured from arrival and including any slot wait, expired | Cause inside `doh_query_failed` |
| `doh_http_error` | Non-200, redirect, bad content type, bad content encoding, or a 1xx, 101, 204, or 3xx status | Cause inside `doh_query_failed` |
| `doh_parse_error` | Malformed HTTP framing or a DNS body shorter than 12 bytes | Cause inside `doh_query_failed` |
| `doh_response_mismatch` | A DNS response with QR=0 or an ID that differs from the query, dropped instead of delivered | Cause inside `doh_query_failed` |
| `doh_queue_full` | A query rejected at admission or at the end of the bounded slot wait by the global job bound, the per-session bound, the global session bound, or a missing reservation, before a request was sent | Cause inside `doh_query_failed` |
| `doh_cancelled` | The owner cancelled a query with no protocol outcome: stop, shard teardown, inner flow expiry, or caller cancellation | Cause inside `doh_query_failed`. One per cancelled query |
| `doh_other_error` | TLS or certificate failure, connection reset, closed transport, source device capacity error, pool panic, a queued TCP:53 query on a failed connection, or any failure not classified above | Catch-all cause inside `doh_query_failed`. Terminal reasons include `flow_closed`, `source_capacity`, and `pool_unavailable`. Revision 9 removes `generation_mismatch` |
| `doh_adapter_errors` | TCP:53 adapter transport failures: cookie, preface, frame, write bound, adapter connection cap, a disposition that cannot be delivered because the adapter connection is gone, or a delivery write that fails after a committed answer | Not in `doh_queries` and not a DoH query outcome. A post-commit delivery failure does not retract `doh_query_ok`. A `Close` disposition caused by a query failure is not an adapter error; that failure is already in `doh_query_failed` |
| `doh_config_in_flight` | Gauge: config-fetch jobs with no terminal outcome | Part of `doh_lookups` |
| `dns_plaintext_profile_queries` | Queries sent over a plaintext DNS profile. Absent or zero in the default `off` profile until the separate acceptance in section 2.6 | Not in `doh_queries`. No DoH attempt precedes one. A profile state, never a fallback |
| `doh_tcp53_queries` | The TCP:53 subset of `doh_queries` | Sub-count. Do not sum with `doh_queries` |
| `doh_tcp53_failed` | The TCP:53 subset of `doh_query_failed` | Sub-count. Do not sum with `doh_query_failed` |
| `ech_attempts` | Handshakes that offered real ECH with a config, including a retry with retry configs. Recorded from `AttemptStarted` | Input count, not an outcome. Excludes GREASE and an ECH-disabled retry |
| `ech_attempts_in_flight` | Gauge: attempts with `AttemptStarted` and no `AttemptOutcome` | Part of `ech_attempts` |
| `ech_ok` | Outcome: the server accepted ECH | One per attempt |
| `ech_grease` | Type count: no config, GREASE sent, no real ECH offered | Not an attempt and not an outcome of one |
| `ech_rejected` | Outcome: ECH rejected on a first attempt and the origin certificate authenticated. The one retry follows | One per attempt |
| `ech_rejection_unauthenticated` | Outcome: ECH rejected but the origin certificate did not authenticate. Terminal, no retry | One per attempt. Takes precedence over `ech_rejected` and `ech_retry_exhausted` |
| `ech_error` | Outcome: an attempt ended without acceptance or authenticated rejection, such as a timeout, a reset, a cancellation, a shard teardown, or a transport error | One per attempt |
| `ech_fallback` | Type count: the one resolver retry ran with ECH disabled after an authenticated rejection | Not an attempt. No other `ech_*` counter moves for that handshake |
| `ech_retry_exhausted` | Outcome: a retry handshake with retry configs was rejected and the origin certificate authenticated, and the one-retry bound forbids another | One per retry attempt. Never used for a timeout, a transport failure, or a handshake that was not attempted |
| `ech_config_unavailable` | One HTTPS RR fetch returned a valid record with no usable `ech` param | Not a handshake outcome. May accompany `doh_ok` |

#### 7.2.1 ECH handshake ledger

The exact identity in a coherent snapshot is:

```
ech_attempts = ech_ok
             + ech_rejected
             + ech_rejection_unauthenticated
             + ech_error
             + ech_retry_exhausted
             + ech_attempts_in_flight
```

The owner records `ech_attempts` and `ech_attempts_in_flight` together when it
applies an `AttemptStarted` event from the pool. It records one outcome and
decrements the gauge when it applies the matching `AttemptOutcome`. A job that
reaches its terminal state with an open attempt (stop, cancellation, timeout,
shard teardown, pool panic) records `ech_error` once for that attempt and
discards any later `AttemptOutcome`. A late outcome for a terminal or unknown
attempt is discarded by job ID plus attempt ID and moves no counter. This is the
only ECH accounting path; the pool never writes a counter.

Precedence for a retry attempt, applied top to bottom:

1. The retry is accepted: `ech_ok`.
2. The retry is rejected and the origin certificate authenticates:
   `ech_retry_exhausted`.
3. The retry is rejected and the origin certificate does not authenticate:
   `ech_rejection_unauthenticated`.
4. The retry times out, resets, is cancelled, or fails at the transport layer:
   `ech_error`.

Rules that complete the ledger:

- Every `AttemptStarted` increments `ech_attempts` and exactly one of the five
  outcomes later applies. There is no sixth outcome and no overlap.
- A GREASE handshake increments only `ech_grease`. It does not increment
  `ech_attempts` and has no outcome in the identity.
- A handshake with no config and GREASE off, such as the trusted bootstrap
  connection, increments no `ech_*` counter. Its DoH result is counted in
  `doh_queries` and `doh_query_*`. The earlier claim "every engine-originated
  handshake has exactly one outcome" was false for this case and is withdrawn.
- An ECH-disabled resolver retry increments only `ech_fallback`, whatever its
  HTTP result. It does not increment `ech_attempts`. It is the exception in
  section 5.3, not an application flow.
- A retry with retry configs sends another `AttemptStarted` and increments
  `ech_attempts` again.
- A rejection whose origin certificate check fails increments
  `ech_rejection_unauthenticated` and not `ech_rejected`. The existing
  `ech_rejected` comment "server rejected" is narrowed to an authenticated
  rejection.
- `ech_attempts` is an input count. Do not add it to an outcome to get a total.
- If a shard panics, the ledger is not published as exact; the service stop path
  takes over (section 6.7).

#### 7.2.2 DoH query ledger and failure causes

The identities, exact in a coherent snapshot, are:

```
doh_queries = doh_query_ok + doh_query_failed + doh_in_flight

doh_query_failed = doh_timeout
                  + doh_http_error
                  + doh_parse_error
                  + doh_response_mismatch
                  + doh_queue_full
                  + doh_cancelled
                  + doh_other_error

doh_lookups = doh_ok + doh_failed + doh_config_in_flight
```

Rules that complete the ledger:

- The admitting shard records every `doh_queries` and every outcome for its own
  jobs, into the one global ledger. The pool and the adapter never write a
  counter. Each accepted job has exactly one owning shard and exactly one
  terminal outcome, regardless of how many relay shards run.
- Every query job a shard admits increments `doh_queries` and `doh_in_flight`,
  and later records exactly one of `doh_query_ok` or `doh_query_failed`, then
  decrements the gauge. A job rejected by the global job bound, the per-session
  bound, the global session bound after the bounded wait, or a missing
  reservation increments `doh_queries` and `doh_query_failed` with the
  `doh_queue_full` cause without entering the gauge. A waiter is not a job and
  is not in the gauge; it increments `doh_queries` exactly once at its terminal
  transition: grant (then it becomes a job), expiry (`doh_query_failed` with
  `doh_queue_full` or `doh_timeout`), or cancel (`doh_cancelled`).
- **One global wait queue, one accounting point.** A waiter can be granted,
  expire, be cancelled, or have an unaccepted grant revoked, but only one of
  those transitions records the query. A grant that is refused at
  `admit_granted` records exactly one outcome and returns the slot to the
  release loop. A revoked grant records once and returns the slot. A second
  record for the same waiter is a defect; the test T7.34 checks it.
- The snapshot is coherent: one reader clone returns every field from one
  ledger state, whichever shard or service path reads it. A live read can still
  show `doh_in_flight > 0`, and that is part of the identity, not a lost
  outcome. The stop barrier returns every gauge to 0 before it publishes the
  final snapshot. Coherence is claimed inside one diagnostics snapshot, not
  across a status request and a diagnostics request (section 2.5.2).
- Every `doh_query_failed` increments exactly one cause. The causes partition
  the failures; `doh_other_error` is the catch-all, so the sum is exact.
- A response with a wrong ID or QR=0 is a `doh_query_failed` with the
  `doh_response_mismatch` cause. It is never a delivered answer and never an
  `doh_query_ok`.
- An inner packet that the forwarder cannot classify as DNS, or that fails the
  minimum DNS parse before an attempt, is not a `doh_query`. The existing relay
  drop counter records it. An adapter transport failure with no accepted query
  is `doh_adapter_errors`.
- Stop, shard teardown, inner flow expiry, and caller cancellation record
  `doh_cancelled`, one per accepted query, and decrement the gauge. A pool
  panic records `doh_other_error` with terminal reason `pool_unavailable` for
  each accepted query with no outcome. There is no `generation_mismatch`
  reason: `session_generation` is fixed for the session's life, so a live job
  cannot disagree with its session (section 6.4.5). Revision 8's reason is
  removed.
- A queued TCP:53 query behind a failed connection records its own
  `doh_query_failed` with `doh_other_error`, terminal reason `flow_closed`. It is
  never silently dropped and never reuses the failed connection.
- A late completion, a duplicate disposition, or an outcome for a session
  incarnation that was already released is discarded by job ID and attempt ID
  (and, for a disposition, by the already-applied `job_id`). It is not a timeout, not a second outcome, and it moves no ECH
  counter. A test-only diagnostic counts the discard; it is not product status.
- A committed answer whose adapter write then fails keeps its `doh_query_ok`
  outcome and increments `doh_adapter_errors`. The same holds for a committed
  answer that is not written because the inner client closed, the connection
  closed, or the stop flush deadline passed. Every committed TCP:53 answer is
  written or counted once as undelivered. The two claims are separate: the
  DoH exchange succeeded, the inner transport did not receive the bytes. A
  `Close` disposition after a failed query is not an adapter error.
- **Every accepted TCP:53 job ends with one disposition.** `Answer` carries the
  bytes; `Close` carries the cause. The adapter performs one action. A
  disposition that cannot be handed over because the adapter connection is gone
  increments `doh_adapter_errors` once and does not change the query outcome.
  A frame that never became an accepted query increments only
  `doh_adapter_errors`.
- A config-fetch job increments `doh_lookups` and `doh_config_in_flight`, then
  publishes `Fresh` or `Rejected` and records one of `doh_ok` or `doh_failed`
  and decrements the gauge, all in one commit. A cancelled fetch is
  `doh_failed` once. A valid record with no `ech` param also moves
  `ech_config_unavailable`. It is never counted in `doh_queries`. A late,
  duplicate, or generation-mismatched fetch result publishes nothing. A
  `commit_retry_config` is not a fetch and moves no `doh_lookups`.
- A query sent over the plaintext profile increments
  `dns_plaintext_profile_queries` only when the separate acceptance in section
  2.6 is in force. It does not increment `doh_queries` and no DoH failure
  precedes it.
- `doh_tcp53_queries` and `doh_tcp53_failed` are subsets. The UI must not sum
  them with the totals.
- A final snapshot after the stop barrier seals is exact and carries
  `ledger.exact = true` and `ledger.phase = sealed`. A snapshot during a shard
  panic, a missed barrier deadline, or a Drop-only stop is not published as
  exact; it carries `exact = false` and the phase (section 6.7).

#### 7.2.3 Corrections required in WS0

- Keep `doh_lookups`, `doh_ok`, and `doh_failed` at the endpoint ECH-config
  meaning. Record the narrowing from "HTTPS or SVCB lookups over DoH" to "the
  endpoint's own ECH-config HTTPS/SVCB lookup over DoH". If WS0 prefers to keep
  the broad wording, an inner QTYPE 65 lookup must also count in
  `doh_lookups`; the design does not recommend that. Never silently repurpose
  the keys.
- Do not add `ech_config_fetch_ok` or `ech_config_fetch_failed`. They would
  duplicate `doh_ok` and `doh_failed`. The valid-record-but-no-param case uses
  `ech_config_unavailable`.
- Record the `ech_rejected` narrowing. The current comment says "server
  rejected". The new meaning is an authenticated rejection. An unauthenticated
  rejection uses `ech_rejection_unauthenticated`.
- The existing phone DNS counters (`dns_flows`, `dns_setup_ok`,
  `dns_setup_failed`, `dns_lookups`, `dns_ok`, `dns_failed`) describe the
  plaintext source device path. Do not reuse them for DoH. The `doh_*` counters
  are the only counters for the DoH path. The UI must not add them to `doh_*`
  and present the sum as "DNS queries".
- The `destination_privacy()` section is zero when `mode = off`. Both `doh_*`
  and `ech_*` can be nonzero while `mode = off`, because encrypted DNS and
  resolver ECH are separate capabilities. WS0 must decide whether they stay
  under `destination_privacy` or move to an `encrypted_dns` section. Do not
  silently change the meaning of the existing `off` row.
- Add `capability_schema: 2` and the separate `runtime` object in section 2.2.
  The runtime object is not a capability and not a sibling value. The capability
  keys stay build and platform claims. A consumer that reads version 1 ignores
  the runtime object.
- Do not add a `generation_mismatch` reason (revision 8 proposed one; revision
  9 removes it because `session_generation` is fixed per session). Remove
  `completion_queue_full` from the product reasons. Capacity is reserved
  at admission, so a full completion queue is not a product outcome. A
  post-commit delivery write failure is `doh_adapter_errors`.
- The current `ech_fallback` comment says "after a rejection or a stall"
  (`rust/src/diagnostics.rs`). A stall must not trigger a fallback. Remove "or
  a stall". This is a privacy fix, not a wording fix.
- Add the counters that the current schema lacks: `doh_queries`,
  `doh_in_flight`, `doh_query_ok`, `doh_query_failed`, `doh_timeout`,
  `doh_http_error`, `doh_parse_error`, `doh_response_mismatch`,
  `doh_queue_full`, `doh_cancelled`, `doh_other_error`, `doh_adapter_errors`,
  `doh_config_in_flight`, `ech_attempts_in_flight`,
  `dns_plaintext_profile_queries`, `doh_tcp53_queries`, `doh_tcp53_failed`,
  `ech_rejection_unauthenticated`, `ech_error`, `ech_retry_exhausted`, and
  `ech_config_unavailable`. Without them, the UI cannot prove that TCP:53 is
  covered or how a handshake or query ended.
- State that `doh_in_flight`, `doh_config_in_flight`, and
  `ech_attempts_in_flight` are gauges, not event counts. State that the reported
  identities are exact in a coherent snapshot and after the barrier seals. The
  admitting shard is the accounting owner for its jobs; every shard writes the
  same global ledger; the pool and adapter write no counter.
- State the definition of `doh_query_ok`: the owner committed a validated
  answer for delivery to the inner transport. A later inner write failure is
  `doh_adapter_errors`, not a failed query.
- State the terminal reasons in `doh_other_error` that the design names:
  `flow_closed`, `source_capacity`, and `pool_unavailable`. They are reasons on
  the catch-all cause, not additional counters.
- Rename `doh_plaintext_fallbacks` to `dns_plaintext_profile_queries` only when
  the separate acceptance in section 2.6 is in force. The old name implies a
  fallback, which the design forbids. In the default `off` profile, the counter
  is absent or zero. If WS0 keeps the old name, it must document that the
  counter is a profile state, not a fallback.
- Do not add an application ECH counter from passive parsing. If a research
  counter is needed, name it `client_hello_ech_extension_seen_unknown` and keep
  it out of product status.
- Do not name the TCP:53 counter `doh_tcp53_lookups`. It sounds like part of
  `doh_lookups`. Use `doh_tcp53_queries`.

- Add `destination_privacy.ledger = { exact, phase, snapshot_seq }` to the
  diagnostics payload. `phase` is `running`, `sealed`, `incomplete`, or
  `drop_only`. `snapshot_seq` is the run's `ledger_seq` at that clone. The
  counters and this object come from one ledger clone. Do not
  add the capability or the runtime coverage object to diagnostics; those live
  in status (section 2.5.2).
- Do not treat a missing counter key as zero and do not assert an identity from
  a partial payload. A missing capability key is hidden, not `unverified`. A
  missing `runtime` object shows no coverage row. A missing `ledger.exact` is
  not true.
- Keep `session_generation` (fixed per session), `config_generation`, and the
  ledger sequence (reported as `runtime.snapshot_seq` and
  `ledger.snapshot_seq`) distinct in comments, tests, and the schema. Do not use the bare word
  "generation" in a key or a field.
- The DoH resolver substitution in section 4.1.2 is not a counter or schema
  change. WS0 must not add a resolver setting or a default endpoint as part of
  the counter work.

A counter is an event count. It never carries a name, address, certificate,
ECH config, or host.

### 7.3 Status and UI wording

- `modes.hide`: `unsupported` because no transparent application ECH path
  exists under the current constraints. Do not set it to `supported` because
  DoH or the engine's ECH works. A future owned client proposal would report
  through `app_ech`, not by raising `hide` for the tunnel.
- `ech`: a legacy build-mechanism flag. It keeps its current meaning and stays
  `unsupported`. It is not application ECH and never carries resolver ECH. Do
  not set it to `supported` because the engine has an HPKE provider, because a
  build links one, or because the resolver connection uses ECH. Remove it only
  with a schema version that updates every consumer in section 2.5.
- `resolver_ech`: a separate key for the engine's DoH connection. It is
  `unverified` in an ECH build until a live accepted ECH handshake is recorded
  on that build and platform. After that qualification it may be `supported`.
  It never implies application coverage.
- `sni_override`: `unsupported`, always. The engine overrides no application
  SNI.
- `encrypted_dns`: a new capability, separate from `hide` and from the proposed
  scope decision. It is `unverified` in a `doh` build until a live run on that
  build and platform shows tunneled DNS queries carried by the configured DoH
  path. Compile and hermetic tests alone are not support. After that
  qualification a build for that platform may report `supported`; the value is
  static and does not change when the person changes network profile.
- `encrypted_dns_coverage`: **not a capability key.** It is
  `runtime.encrypted_dns_coverage`, with values `active`, `inactive`,
  `bypass_detected`, `failed`, and `unknown`. A profile switch or a DoH
  connection failure changes this state, never the capability string. State the
  bypasses in the UI as coverage: gateway DNS on macOS and Windows by route
  inference, likely gateway DNS on a default Linux resolver, scoped resolvers,
  link-local and IPv6 special addresses, application DoH/DoT/DoQ, and caches.
- `app_ech`: `app_dependent`. The capability contract (section 2.4) is the
  authority. It has its own three-value vocabulary and its own information row.
  It is never validated as one of the four capability states and never rendered
  as a support pill. There is no free-text detail field. If a separate
  product-owned client proposal is approved later, add `owned_client` for that
  client only, with its own scope and wire test.
- Capability values are the four strings in section 2.4. `app_ech` uses its own
  three strings. Do not add "engine resolver connection only" as a value; no
  field carries it. The key name and this document carry the scope.
- `off` is a runtime mode and stays `supported`. The UI must not present it as
  a privacy capability.
- The UI must not use "Hide the destination" for DoH. Prefer "Hide DNS names
  for tunneled queries". A future owned client proposal could use the `hide`
  title for that client only, with a coverage list.
- A distinct plaintext-profile state ("DNS is not private") is part of the
  separate acceptance in section 2.6. Do not add it to the default `off`
  profile as a side effect of DoH. When a DoH profile is active and a person
  selects the labeled plaintext profile, the state applies to that profile and
  is never a fallback.
- The UI must show a bypass state when the platform reports a scoped,
  link-local, gateway, or OS encrypted resolver: "Some DNS may use a path
  outside this mode." It must not name the resolver. This state is
  `runtime.encrypted_dns_coverage`, separate from the capability string, and
  does not change it. It is absent when the runtime object is absent.
- The Linux and Windows cards must obey section 2.5.2. The Linux card reads
  capability and runtime from `hs:status` and counters from `hs:diagnostics`,
  and is static only when neither payload is present. The Windows card is
  static and says "Not reported by this build" for a key it did not receive.
  Neither renders a runtime state from a build constant.
- A missing key is hidden. Do not substitute `unverified`, do not treat a
  missing counter as zero, and do not combine a runtime state from status with
  counters from a different diagnostics request as one snapshot.
- Every existing consumer in section 2.5 must be updated in the same change as
  the new keys, or it must keep working from the old keys. No consumer may
  interpret a missing new key as support.

## 8. Dependencies and cross-target build

Two non-default features, not one. Cargo features are additive:

| Feature | Crates | Purpose |
|---|---|---|
| `doh` | `rustls` with `ring`, `webpki-roots` | TLS 1.3 DoH without ECH |
| `ech` | `doh` plus `rustls` with `aws-lc-rs` for TLS and HPKE | ECH on the engine's DoH connection. `ech` implies `doh` |

`rustls` settings: `default-features = false`, `std`, TLS 1.3 only, no
`logging`, no `tls12`, no resumption, ALPN `http/1.1`. The exact feature names
must be checked against the pinned version. Pin exact crate versions in the
implementation spike and commit the lockfile; do not write a version into this
note without a build. `rcgen` is a dev-dependency only, for the mock server.

The `ech` build uses `aws-lc-rs` as its TLS provider so that one provider
covers TLS and HPKE. `ech = ["doh", ...]`, so `--features ech` never silently
omits the DoH code. Do not treat the features as mutually exclusive. Enabling
both is the same as enabling `ech`; the code selects exactly one
`CryptoProvider` at startup: `aws-lc-rs` when `ech` is on, `ring` otherwise. A
compile-time assertion or a single provider install call must make an ambiguous
selection impossible. If the pinned rustls version supports only one provider
feature at a time, the spike must split the provider crates and document the
exact combination. The implementation spike must settle the cargo feature graph
before any manifest changes.

`experiments/tls-transport-spike` is a useful pattern, not a dependency. It
proves TLS 1.3, no resumption, a total handshake deadline, one connection per
flow, and a byte-exact loopback relay with pinned test verifiers. It uses
`ring`, which has no HPKE, and it contains no ECH. Reuse the pattern and its
lessons; do not copy its IP-server-name trick to a public DoH hop. A public
server needs SNI to select a certificate.

Why two features:

- ECH needs an HPKE provider. `ring` has no HPKE. `aws-lc-rs` brings C and
  assembly builds, cmake, a C toolchain, and on Windows x86 likely NASM.
- DoH should not be blocked on every target because ECH's provider cannot
  build there.
- A build without `ech` reports `app_ech = app_dependent` (and legacy
  `ech = unsupported`), `resolver_ech = unsupported`, and `hide = unsupported`,
  but can still carry the `doh` path. It reports `encrypted_dns = unverified`
  until a live run on that build and platform succeeds, then may report
  `supported`.
- A build with `ech` reports `resolver_ech = unverified` until a live accepted
  handshake, then may report `supported` for that build and platform. The
  legacy `ech` key stays `unsupported` and keeps its build-mechanism meaning.
- A build without `doh` reports `encrypted_dns`, `resolver_ech`, and `hide` as
  `unsupported`, and `app_ech = app_dependent`.
- The `doh` and `ech` features are part of the proposed scope in section 4.1.1.
  No feature is added until that scope is accepted and this design is approved.
- The three build combinations are tested: features off, `doh` only, and
  `doh` plus `ech` (the `ech` build). A `--features ech` build that omits `doh`
  is a feature-graph bug, not a supported configuration.

Build rules:

- The base crate stays pure Rust. `cargo check --all-targets --locked` with
  features off must keep working on every host and cross-target.
- Do not add the features to the documented cross-target checks that run on a
  host without the target C toolchain. With `doh` or `ech` on, those checks
  will likely fail on macOS for an MSVC target. That is a workflow regression,
  not a cosmetic one.
- Native CI jobs for macOS, Windows x64, and Linux x64 add the supported
  features to check, test, and clippy. Release builds enable the supported
  features per target.
- A target that cannot build `ech` must still build and test `doh`. Do not add
  `continue-on-error`. Do not ship a hidden stub that claims ECH.
- Commit `Cargo.lock`. Build with `--locked`.
- iOS and Android engine builds are not in scope and are not tested. If they
  are added later, they need their own provider spike.

Unproven until a build runs:

- `ring` builds for every target that ships `doh`.
- `aws-lc-sys` builds for macOS arm64, Windows x64, and Linux x64 with the CI
  images.
- Windows x86 (`i686-pc-windows-msvc`) can build either feature. If not, it
  ships without them and reports `unsupported`.
- The cross-target checks still pass with features off.
- The mock server's test certificate and injected roots work on every target.

## 9. Test strategy

The detailed matrix is `WS1_TEST_MATRIX.md`. It includes:

- mock DoH server, mock tun, mock source device, and mock plaintext resolver;
- cleanup and crash tests with no route and no TUN;
- fuzz bounds for HTTP, DNS, ECH, and TCP framing;
- a no-plaintext-DNS assertion;
- a TTL audit assertion;
- a privacy-output assertion;
- cross-target build checks, including the additive feature combinations;
- a job-ID and late-completion test;
- a coherent-snapshot stress test at 1, 2, 4, and 8 relay shards;
- a multi-shard ownership test that every job ends exactly once;
- a TCP:53 commit-order test where a cancelled or timed-out job's bytes never
  reach the inner stream, and a duplicate or stale delivery is dropped;
- a stop-barrier test that races admission against `Stopping` and asserts no
  request is admitted after the transition;
- a session lifecycle and slot-release test, including a quiet UDP close and a
  generation mismatch;
- a connection lease and handback test where a slot is not freed until the
  attempt returns, and a late handback cannot free a newer slot;
- a retry-ownership test and a cache compare-and-set test;
- an adapter credit and terminal-close test;
- a global waiter FIFO, grant, cancel, and deadline test;
- a real `Relay::stop` and `Drop` order test, with a separate total stop budget
  measurement;
- a status versus diagnostics path test and a missing-key test;
- an adversarial table for races between retry, cache, slot reuse, credit
  return, preface input, and status publication;
- a per-query-port churn test at several rates, with the declared envelope;
- a config-cache single-flight, rejection, and late-publish test;
- a capability consumer migration test for the browser, Linux, and Windows
  paths, including the `app_ech` three-value parser;
- a default-`off` behavior test;
- a protocol regression test that checks SOCKS, pairing, source device, TTL,
  IPv6 defaults, and route behavior are unchanged;
- a separate table for what a runtime test proves and what only a carrier test
  can prove.

No test in that matrix has been written or run for revision 9. The matrix is a
plan, not evidence.

## 10. Decisions

1. `hide` requires real ECH on application connections plus DoH. DoH alone is
   not `hide`. The engine's DoH ECH alone is not `hide`.
2. Universal application ECH is impossible under the constraints. The engine
   cannot add ECH to another process's TLS handshake without termination.
3. App-native ECH is viable only for applications that implement ECH and can
   obtain HTTPS/SVCB records. The engine encrypts and preserves the DNS path.
   The status is `app-dependent`. It is not a product capability and is not
   counted from relayed traffic.
4. A product-owned TLS client is the only complete path to product-controlled
   application ECH. It is an explicit API or a product-owned surface, not a
   transparent proxy. It is a separate optional future proposal, out of WS1 and
   not implemented. It must not terminate TLS or add an external relay.
5. Encrypted DNS is a separate capability, not a mode and not a `hide` support
   claim. It is reported as `encrypted_dns`. It is `unverified` until a live run
   on the build and platform shows tunneled queries carried by DoH; after that
   qualification it may be `supported` for that build and platform. A compile
   and a hermetic test are not support. The tunnel-wide forwarder is a proposed
   independent scope, not approved work.
6. The DoH forwarder is a proposed scope with the tradeoffs in section 4.1.1.
   It is not approved by this document or by the WS6 handoff. No DoH code is
   written before its own scope acceptance, this design review, and the test
   matrix review.
7. DoH uses HTTP/1.1 POST over TLS 1.3, ALPN `http/1.1`, no HTTP/2, no async
   runtime, and no hickory.
8. The DoH endpoint is configured as name, unicast IP literal, port, and path.
   No `getaddrinfo`. No redirect. `webpki-roots` for public trust. No OS trust
   store on the egress path.
9. One DoH TLS connection per live DoH session. A session belongs to one inner
   DNS flow and is keyed by the inner 4-tuple plus a generation. No sharing, no
   multiplexing, no background refresh connection. The relay's inner flow entry
   may outlive the session. A quiet UDP session closes after 250 ms and in no
   case later than 2 s; a later query on the same tuple opens a new generation.
   The session cap is hard; the engine never evicts another session's
   connection. An ECH retry closes its own session's old connection first.
10. Forward DNS bytes unchanged. No answer cache, no answer synthesis, no QTYPE
    filter, no ID or case rewrite. A TC response is the only allowed
    truncation. Pass DNSSEC and EDNS through. Do not claim validation.
11. Honor the inner EDNS UDP size, cap at the inner datagram limit, and return
    a proper TC response. Cover TCP:53 so a TC retry cannot leak.
12. DoH failure is a DNS failure. Plaintext is a separate profile state chosen
    before start, off by default, and labeled while active. A query never
    switches to plaintext in reaction to a DoH failure, and there is no
    per-query fallback. The plaintext-profile counter is
    `dns_plaintext_profile_queries`, and it and its default UI are gated by a
    separate acceptance (section 2.6). The default `off` behavior does not
    change.
13. ECH uses rustls plus an HPKE provider. The config comes from the endpoint's
    own HTTPS RR over the authenticated DoH connection. The origin certificate,
    not `public_name`, is the authentication name. The resolver connection
    retries only after an authenticated ECH rejection, at most once, with retry
    configs, or with ECH disabled when no supported retry config exists. A
    rejected config is evicted. No application flow retries without ECH. A
    non-ECH application flow is a profile state chosen before connecting, not a
    retry. Never retry on a timeout, a reset, a certificate failure, a 5xx, a
    parse error, or a SERVFAIL. The plan's "fresh non-ECH flow after a
    detectable failure" text is wrong and must be replaced by WS6.
14. GREASE is optional, default off, and never a claim. Passive application ECH
    counting is removed because GREASE is indistinguishable.
15. A relay shard never blocks on TLS. DoH runs on one bounded pool shared by
    all shards, with bounded queues and pollable per-shard event channels. The
    source device SOCKS setup is one reusable type with two drivers, and
    cancellation covers every setup state.
16. The **admitting shard** is the accounting owner for its jobs, and every
    shard writes one global ledger under one lock. The pool and the TCP:53
    adapter write no counter. Each accepted job has a job ID, a session
    generation, an attempt ID, and exactly one terminal outcome. A late
    completion is discarded by job ID, attempt ID, and session generation.
    `doh_in_flight`, `doh_config_in_flight`, and `ech_attempts_in_flight` are
    gauges, and the reported identities are exact in a coherent snapshot and
    after the stop barrier seals. Stop, shard teardown, inner flow expiry,
    queued TCP:53 failure, source capacity, pool panic, and a session generation
    mismatch have named terminal causes. Response bytes are delivered only
    after commit.
17. The TCP:53 adapter binds loopback only, requires a per-start 128-bit
    cookie, caps authenticated connections at 32 as an independent local bound,
    carries the owning shard index and connection ID in its fixed 32-byte local
    preface, bounds frames, never recurses, never submits a pool job, and never
    writes a DoH counter. Each authenticated connection has four frame credits.
    Every accepted query has one reserved disposition: an answer or a close.
    The owning shard owns each query job, its counters, its config-cache
    commit, and its failure record. The adapter writes only a committed answer
    and closes the inner connection for every failed query.
18. No host resolver override in WS1. Scoped, link-local, OS DoH/DoT, and
    application DoH/DoT/DoQ bypasses are documented and detected as categories,
    not names. Gateway DNS is a bypass by route-specificity inference; no live
    DNS result exists. Linux SOCKS5 requires an explicit bounded `--dns-servers`
    list; macOS uses an unambiguous scoped interface resolver.
19. No QNAME, endpoint name, ECH config, SNI, or certificate enters a log,
    status, diagnostics, or failure record. DoH never feeds the failure name
    map. A DoH failure record is a separate privacy scope and is off by default
    (section 7.1).
20. Two non-default additive cargo features, `doh` and `ech`. `ech` implies
    `doh`; enabling both is valid and selects one provider. A target that cannot
    build one reports `unsupported` for it, never a stub.
21. Every egress socket goes through the normalized helpers and the TTL audit.
    The loopback adapter is the one documented unpinned local socket and cannot
    leave the machine.
22. Status stays UNAPPROVED until a new independent review.
23. The implementation gate is scope-specific. Application ECH is closed as
    unsupported under the current constraints; a product-owned client is a
    separate optional future proposal. The tunnel-wide DoH forwarder needs its
    own product scope acceptance and review. WS6 applies P1 to P15. A new
    independent review approves this file, the test matrix, and the trace. No
    scope starts before its gate.
24. The default `off` behavior does not change: no new DNS path, counter,
    warning, route, socket, dependency, or mode. Additive capability keys are
    conservative and a missing key is not support.
25. The capability migration in section 2.5 is mandatory. `ech` keeps its
    meaning; the new keys carry the new claims. Static capability and runtime
    coverage are different objects. `app_ech` has its own three-value parser.
26. A direct-mode DoH failure record, and the default plaintext counter or
    warning, are new privacy and UI scopes. They need their own acceptance and
    are not approved here.
27. RFC citations are unverified until a reviewer reads the cited text. A
    citation from memory is not a standard claim.
28. Every DoH admission and every terminal outcome is one ledger update under
    one lock. The phase is part of that state, so a stop transition and an
    admission cannot interleave into an admitted job after the transition.
29. Response bytes reach an inner client only after the owner commits one
    outcome. A disposition carries a connection ID, request ID, job ID, and
    session generation. The adapter applies dispositions per connection in
    `request_id` order and never drops a committed answer for being "not
    current"; a duplicate `job_id` cannot occur by reservation. A committed
    answer that is not written is counted once in `doh_adapter_errors`, not as
    a second query outcome. Every accepted TCP:53 query ends with exactly one
    answer or one close, and a close is graceful and ordered.
30. A session has exactly one owner and one reserved slot, released by one named
    path. A slot release is guarded by the session incarnation and the attempt
    ID and waits for the handback of the attempt that held the connection
    lease. A quiet UDP close is the normal
    release, not eviction of another flow. One fetch is in flight for the ECH
    config; the cache publishes only from that fetch's compare-and-set commit.
    A retry is a second attempt of the same job, authorized by the owning shard.
31. The session cap and pool size are measured parameters. The proposed values
    are 64 sessions and 8 pool threads, with a declared envelope and an explicit
    `doh_queue_full` above it. The slot wait is one global FIFO, not a per-shard
    queue. Sharing a DoH connection across inner source ports is an unapproved
    product option, not part of this design.
32. The stop barrier runs in the phases in section 6.4.8 with a bounded DoH
    deadline. It starts before `Relay::stop` sets `running = false` and before
    the shard join, because a joined shard cannot ack or hand back. In a DoH
    run the tunnel worker calls the nonblocking `begin_stop`, removes routes,
    and only then drains, so the drain does not lengthen the dead-route window.
    The total stop budget is unknown because the existing joins are unbounded.
    A barrier that misses its deadline is an incomplete DoH stop, reported
    through `RelayStopReport` with its own message, never a clean stop and
    never `cleanup_blocked`. The final ledger
    is published as exact only from `Sealed`; a Drop-only stop is `drop_only`
    and inexact.
33. The runtime coverage object is not a capability and is not read by a static
    build card. Capability and runtime coverage come from status; counters and
    ledger metadata come from diagnostics. The browser GUI, the Linux renderer,
    and the Windows report have the data paths in section 2.5.2. Cross-endpoint
    coherence is not claimed. No consumer renders `app_dependent` as support,
    infers a state from a missing key, or treats a missing counter as zero.
34. No protocol changes. SOCKS, pairing, the source device proxy, the ICMP echo
    commands, the key schedule, the TTL, the route rules, the IPv6 defaults, and
    the one-outer-per-flow rule are unchanged. The adapter preface is local
    loopback framing. A change to any of those needs its own review.
35. Three sequences are never interchanged: `session_generation` (owning
    shard, allocated once per session and never changed), `config_generation`
    (cache commit), and `ledger_seq` (every ledger mutation, reported as
    `runtime.snapshot_seq` and `ledger.snapshot_seq`). No field or key uses the
    bare word "generation".
36. The DoH endpoint is a third-party resolver. Substituting it for the resolver
    the network or the person selected is a product-owner decision and requires
    an explicit amendment to `AGENTS.md` invariant 4. If the plan is read to
    require the network resolver, the plan's WS1 scope text or its invariant 4
    needs the same amendment. The product already substitutes resolvers in
    source device proxy mode (`1.1.1.1:53`) and through explicit
    `--dns-upstream` and `--dns-servers` values; the decision must answer
    owner questions Q1 to Q5 in section 4.1.2. The no-built-in-endpoint rule is
    a proposed rule for the DoH profile only. This design records the
    requirement. It does not assert that the decision was made, that the scope
    is approved, or that the current or uncommitted invariant already permits
    the forwarder, and it changes no invariant.
37. A connection is held through one move-only lease. The pool holds it during
    an attempt; the shard holds it after the move. A slot is freed only after the
    handback for that attempt. A terminal decision alone does not free it.
38. A slot waiter has one settlement transition, `settle_waiter`, under the
    ledger lock. It removes the record and returns a granted slot in the same
    critical section. A second settlement or a late `admit_granted` is `Stale`
    and records nothing. The release step grants only a waiter whose wait
    window and absolute deadline both remain. `Stopping` settles every queued
    waiter and outstanding grant.
39. Runtime coverage is read only from the latest successful status response.
    The probe copy of `platform` carries no `runtime` object, and the browser
    never reads `runtime` from it.
40. A config fetch that ends without a commit returns the cache to `Absent`
    and wakes every shard in the same critical section. A cancelled fetch lets
    at most one waiting session claim a new fetch. A failed fetch sets a
    `retry_after` and the waiting sessions proceed without ECH.
41. An incomplete DoH stop is not a route cleanup failure. It never sets
    `cleanup_blocked`. A later start with the DoH profile is refused while a
    detached DoH pool thread from an earlier run is alive.

Decision numbering note: Appendix I cites decisions 33 to 39 for the revision 8
blockers. The revision 8 list ended at 37 and its numbers did not match those
subjects. Read Appendix I by subject; Appendix J uses the numbers above.

## 11. Unresolved issues, handoffs, and plan corrections

### 11.1 Unresolved issues

Each item is open or records where it closed. None is a capability.

| ID | Issue | Why it blocks a claim | Next step |
|---|---|---|---|
| U1 | Universal application ECH is impossible under the constraints | A transparent `hide` cannot be built | Closed: `hide = unsupported` under the plan's default. A product-owned client is a separate optional future proposal, not a blocking decision. No TLS termination and no relay |
| U2 | App-native ECH delivery through system DNS is not general | `getaddrinfo` is reported not to expose HTTPS/SVCB on the targets; this needs a per-OS check. Many apps therefore cannot get a config | Measure which apps query type 65 and whether the OS exposes it. No product claim |
| U3 | SVCB-reliant behavior is application-controlled | An app can fall back and lose ECH | Document as app-dependent. Do not try to enforce from the relay |
| U4 | macOS gateway DNS is a bypass by route-specificity inference, and scoped resolvers add another | The connected-subnet route is more specific than `/1`. The 2026-11-02 record reports a gateway route bypass but names no OS and does not show the DNS case | Read-only detection of the gateway and scoped resolvers. No host route and no override. Do not claim gateway DNS coverage or live DNS evidence |
| U5 | Windows gateway DNS is a route-shape bypass by inference, and NRPT, per-interface DNS, and smart multi-homed resolution add more | The start path adds no host route for the gateway and the connected route wins. No live record exists | Read-only detection. No host route and no override. Do not claim gateway DNS coverage |
| U6 | IPv6 link-local, ULA, multicast, and NAT64 DNS bypass | Plaintext DNS can leave the physical link | Detect and document; no override. Do not claim universal DNS privacy |
| U7 | Safe resolver override and crash cleanup | A host-global change can break the host | Separate design with journal, per-interface scope, restore, and crash tests. Not in WS1 |
| U8 | TCP:53 adapter access control and lifecycle | A local listener can be abused or leak | Implement cookie, caps, timeouts, and crash tests. Or choose the virtual outer |
| U9 | `Setup` refactor for a blocking DoH driver | Duplicating the SOCKS wire format would drift | One type, two drivers; test both against the mock source device |
| U10 | Per-query handshake cost on a real hotspot | The cost may be unacceptable | Measure cold and warm latency, battery, and fd use. Do not share connections to fix it |
| U11 | DoH HTTP/1.1 acceptance by real providers | Some providers may prefer HTTP/2 | Test two independent providers before committing. If H1.1 fails, the design changes |
| U12 | DoH endpoint reachability and blocking | A carrier may block the IP, port, or name | Live carrier test with owner approval. No claim before it |
| U13 | ECH acceptance across anycast and config rotation | A real provider may reject or rotate | Live test; retry configs; no loop |
| U14 | `aws-lc-sys` cross-target build | ECH may be unavailable on some targets | Build spike per target. Report `unsupported` where it fails |
| U15 | rustls ECH API shape at the pinned version | The revision 1 API claim was not re-verified | Check the crate source and compile a minimal client |
| U16 | DNSSEC validation | The forwarder is not a validator | Do not claim. Pass records and the AD bit. The resolver's policy is the resolver's |
| U17 | DoT, DoQ, application DoH, and OS DoH | They bypass the forwarder | Count only port 853 as a port. Report no capability claim for 443. Do not interfere |
| U18 | Preexisting caches and retroactivity | Old names and addresses remain | Document. Do not auto-flush |
| U19 | Failure record name map | Existing names can appear under a new mode | Clear on mode start; DoH never feeds it. Test the output |
| U20 | WS0 counter and capability changes | The current schema lacks `encrypted_dns`, `resolver_ech`, `app_ech`, the schema version, the runtime object, and the counters in section 7.2 | WS0 review against the capability contract in section 2.4 and the migration in section 2.5. Add `capability_schema: 2`, the `runtime` object, and the per-key parser contract. Correct the `ech_fallback` comment that mentions a stall. Add `doh_in_flight`, `doh_config_in_flight`, `ech_attempts_in_flight`, `doh_adapter_errors`, `doh_cancelled`, and the rest of the section 7.2 set. Record the `doh_query_ok` commit definition. Split the `supported` comment so `off` keeps its meaning and privacy keys require live evidence. Add the reviewed build qualification constant. Keep `ech` until the schema version and consumers are ready |
| U21 | UI wording and coverage | "Hide the destination" is false for DoH | WS5 review. Use "DNS names for tunneled queries", an app-dependent ECH row, a `resolver_ech` row, and a separate `runtime.encrypted_dns_coverage` row. Follow the per-key parser and the section 2.5.2 data paths |
| U22 | iOS and Android source paths | Out of scope; no claim | No work in WS1 |
| U23 | DoH endpoint IP rotation | The endpoint IP is configured to avoid `getaddrinfo`; a stale IP fails | Document manual update. A later version may accept an authenticated `ipv4hint` from the endpoint's HTTPS RR |
| U24 | SOCKS5 mode's `TinyResolver` remains plaintext | Enabling DoH does not fix the SOCKS5 listener's DNS leak | Separate integration that makes `TinyResolver` use the DoH client, with its own tests. Not in WS1 |
| U25 | The plan requires a post-failure non-ECH fallback that this design forbids | The plan's `hide` gate would force a downgrade on a timeout or reset, which is the attacker-controlled case | WS6 applies P1 and P2 in section 11.3. No downgrade on a timeout or reset. A non-ECH flow is a profile state chosen before connecting |
| U26 | The plan names SOCKS command `0x80` for DNS, carries a false "already resolved" claim, and uses stale status words | The plan is marked "verified by inspection" but contradicts the code, the DNS bypass record, and the capability vocabulary | WS6 applies P4, P5, P6, and P8 in section 11.3. Code uses command 1 with DNS-over-TCP framing. Use `supported`, `unsupported`, `unavailable`, `unverified` |
| U27 | The existing DNS failure constructor and direct-mode recorder cannot carry a DoH failure | `FailureEvent::dns` hard-codes `1.1.1.1:53`; `record_dns_failure` returns early in direct mode. A DoH failure record is also a new privacy surface | Counters only by default. If the privacy scope is accepted, add `FailureEvent::doh_query(destination, port, reason, code, phase)` and a `record_doh_failure` path. Carry the TCP:53 inner destination in the adapter preface. Test direct mode only after acceptance. Section 7.1 |
| U28 | `encrypted_dns` and `resolver_ech` could be read as supported from a compile | A compile, a linked provider, or a hermetic test does not prove a live path | `encrypted_dns` and `resolver_ech` are `unverified` until a live run on each build and platform. After qualification they may be `supported`. The legacy `ech` stays `unsupported`. Section 2.4 and 7.3 |
| U29 | RFC 9848, RFC 9849, RFC 8446, RFC 8484, and RFC 7766 numbers and section references were cited from memory or secondary text, offline | A wrong reference weakens the standards claim, and the reading guide must not call it read | Re-read every cited RFC text before approval and correct or remove each reference. This revision marks every citation unverified. T12.21 checks the table. This is a documentation check, not a code test |
| U30 | The plan's WS1 gate conflicts with building encrypted DNS and resolver ECH while the client boundary was open | The old plan says "No code before an agreed boundary"; the architecture proposes DoH and resolver ECH work separately | P10 is the required plan text. The plan's revision note says task `85710a0e` applied it. WS6 verifies the text. P10 separates the DoH scope and the third-party resolver decision, and it does not approve either. No implementation starts without the product owner's scope acceptance, the resolver decision and amendment, and review |
| U31 | The adapter flood test asserted a stronger property than the threat model | A continuous flood can deny a new inner TCP:53 flow; the threat model accepts a local denial of service | The design never evicts a connection. T8.16 asserts no authenticated eviction, no plaintext, and a bounded outcome, not guaranteed service |
| U32 | The plan's capability parity contract and accepted-failure gate are incomplete | It omits `encrypted_dns`, `resolver_ech`, `app_ech`, the TinyResolver leak, the GREASE policy, and the stale DNS, counter, Linux, and reader-facing claims, and open question 6 is stale | WS6 verifies P3, P7, P9, P11, and P12 to P15 in section 11.3 against the plan text. The plan's own revision note says task `85710a0e` applied P7 and P9 to P15. This design treats that as a text observation to verify, not as approval |
| U33 | A gateway host route as an alternative DNS capture | The old rejection reason was unverified. A host route would affect the pairing port 18090, the presence probe, captive portals, and platform route behavior, and may not affect the interface-pinned proxy socket | Record as an open option with those risks. Do not add a host route in this workstream |
| U34 | No source device free-slot report | The DoH session cap cannot be "the smaller of a constant and free slots" because no protocol field reports free slots | Use the measured cap from section 6.5. A capacity error is `doh_other_error` with reason `source_capacity`. A free-slot query needs a protocol change on both apps and is out of scope |
| U35 | The single-writer claim ignored the TCP:53 adapter and the relay shards | The adapter and the shards could each submit or record work, so "one worker owns every counter" was false | The adapter sends an admission request with the owning shard. The admitting shard owns the job, the outcome, the counter, the cache commit, and the failure record. All shards write one global ledger. The adapter writes no DoH counter (sections 4.8 and 6.4) |
| U36 | A dropped, cancelled, or timed-out completion had no ECH outcome | The pool could not report an ECH result after the owner had already classified the job | Every accepted job has a job ID and exactly one terminal outcome. A late completion is discarded by ID and generation. An ECH attempt with no completion records `ech_error`, not a second outcome. Config fetches use the same rule (section 6.4) |
| U37 | Separate atomics and queued work made instantaneous identities false | A reader could see some counters updated and others not | One coherent ledger snapshot covers every counter and gauge, for every shard count. Identities are exact in a snapshot and after the stop barrier seals. A 1, 2, 4, and 8 shard stress test reads snapshots concurrently (section 7.2.2) |
| U38 | The capability keys would break existing consumers | `gui_assets/app.js`, the Linux page, and the Windows report read `ech` and other old keys with their own meanings, and the Linux card has no payload path | Section 2.5 maps every consumer with its data path. `ech` keeps its meaning. New keys are additive and versioned. Static capability and the runtime object are separate. `app_ech` has its own parser. No default payload changes |
| U39 | The idle-eviction rule contradicted one-flow-one-socket | Evicting another flow's connection could fail a live query and break the mapping | The cap is hard. The engine never evicts another session's connection. A slot frees only through that session's own release path. Only the bounded ECH retry replaces a connection (sections 6.4 and 6.5) |
| U40 | The adapter cap and the DoH cap were treated as one budget | An adapter slot is a local socket, not a reserved DoH session | The adapter cap is an independent local bound (32). The session cap governs DoH connections. A query can still fail with `doh_queue_full` when the session cap is full (sections 6.4 and 6.6) |
| U41 | The deadline and completion rules could silently drop or mislabel work | A queued job's deadline started late, and a full completion channel dropped a result and reported a timeout | The deadline starts at arrival and includes the slot wait. Completion, event, and delivery capacity are reserved at admission. A committed answer is delivered after the outcome. A post-commit write failure is `doh_adapter_errors`. Nothing is dropped silently (section 6.4) |
| U42 | Panic and cancellation coverage was incomplete | The source setup could wait uncancelled, and a shard panic had no accounting policy | Cancellation covers every source setup state. Pool, adapter, and shard panics have separate policies. A shard panic is not published as an exact ledger (sections 6.3 and 6.7) |
| U43 | Cargo features were described as mutually exclusive | Cargo features are additive, so `--features ech` could omit `doh` or an ambiguous provider | `ech` implies `doh`; both may be enabled; one provider is selected. All three combinations are built and tested (section 8) |
| U44 | The gateway bypass was described as live DNS evidence | The 2026-11-02 record reports a gateway route bypass, not a DNS query, and names no OS | Gateway DNS is a route-specificity inference on macOS and Windows, and likely on a link-bound Linux resolver. No live DNS-specific result exists (section 4.2) |
| U45 | RFC citations were read from memory | A wrong number or section weakens the standards claim | The citation table records each check. No citation is a standard claim until a reviewer reads the text (section 11.1 U29) |
| U46 | A direct-mode DoH failure record is a new privacy surface | It would add a numeric destination and reason to "Recent failures" in a mode that has no such record | Counters only by default. A record needs its own acceptance in the DoH scope (section 7.1) |
| U47 | The default plaintext counter and warning change default behavior | The default `off` run would gain a new counter and a new warning | They need a separate telemetry and UI acceptance. The default payload and UI do not change (section 2.6) |
| U48 | The DoH ownership model assumed one relay worker | `Relay::start` runs 1 to 8 shards, each with its own flow table and wake. A global writer claim was false for every multi-shard run | One supervisor, one compact shard owner, one global ledger. A job belongs to the shard that receives the packet or the adapter request. No job migrates. Section 6.4 |
| U49 | TCP:53 response bytes could bypass the terminal decision | Revision 6 sent bytes to the adapter and the outcome to the worker, so a cancelled or timed-out job could still write | The owner commits exactly one outcome, then releases one disposition: `Answer` with bytes or `Close` with a cause. The adapter has no direct pool path. A post-commit write failure is an adapter transport event. Section 6.4.5 |
| U50 | Connection, cache, and ECH state had no owner or lifecycle | A session, a cached config, and an attempt could be mutated by more than one component, and no release path covered every exit | The session table, slot release paths, generation guard, single-flight config cache, and attempt event pair are defined. Section 6.2 and 6.4.6 to 6.4.7 |
| U51 | The 32-session cap cannot survive per-query-port churn | A relay UDP entry lives up to 120 s in direct mode, so a churning stub would hold far more than 32 sessions | The session lifetime is separate: 250 ms quiet, 2 s hard idle, bounded slot wait, measured cap. The envelope and the explicit failure above it are stated. Section 6.5 |
| U52 | Stop admitted work while terminating, and the barrier was single-worker | The old text set a flag and drained one worker; 1 to 8 shards could still admit | Phase is part of the ledger lock. Admission and the stop transition cannot interleave. Six barrier phases with a bounded deadline; a miss is a failed stop. Section 6.4.8 |
| U53 | Runtime coverage was inside the static capability, and two consumers cannot read the new shape | `app_ech` is not a four-state value; the Linux card is static with no payload; the Windows report is fixed text | A version 2 payload, a separate runtime object, a per-key parser, and explicit data paths for the browser, Linux, and Windows. Sections 2.2 to 2.5, 7.3 |
| U54 | A structural change could quietly regress a protocol invariant | The adapter preface, shard routing, and session generation touch local code near the relay | No SOCKS, pairing, source device, ICMP echo, key schedule, TTL, route, IPv6 default, or one-outer-per-flow change. The preface is local loopback framing. A protocol regression test is in T15. Section 10 item 34 |
| U55 | The capacity and barrier numbers are hypotheses | The cap, pool size, quiet window, DoH barrier, and total stop time are not measured on a target | Section 6.8 H1 to H15 names the evidence that closes each. No number becomes a claim before that evidence |
| U56 | Sharing a DoH connection across inner source ports would raise the envelope | It is a product option with a flow-shape and one-outer-per-flow tradeoff, not a design fix | Not approved and not implemented. A separate product decision and review. Section 6.5 |
| U57 | The DoH endpoint is a third-party resolver, which substitutes for the resolver the network or the person selected | The committed invariant 4 has no resolver-substitution sentence. The uncommitted working-tree change adds "do not substitute a public resolver" in the interface-discovery paragraph, which also says a person who names a server accepts that choice. The committed code already redirects source device proxy mode DNS to `1.1.1.1:53`, and the docs suggest `1.1.1.1` and `8.8.8.8` as explicit servers. Revision 8 misread all of this. A forwarder to a configured resolver still needs a decision and an amendment. If the plan is read to require the network resolver, its scope text or invariant 4 needs the same amendment | A product-owner decision on Q1 to Q5 (section 4.1.2) and an explicit amendment to `AGENTS.md` invariant 4, written against the committed text, before any DoH code. This design does not assert that the amendment exists, that either invariant text is compatible, that the existing redirect conflicts or not, or that the scope is approved. It changes no invariant. Section 4.1.2 |
| U58 | The total stop budget is unknown | The DoH barrier has a proposed bound, but `Relay::stop` and the tunnel-worker join are unbounded in the current code. The service holds the lifecycle lock during stop, so a hung join also blocks a start | Measure each join separately on each target. Do not call the 5 s DoH bound a total stop time. H6 and H13; T6.22 to T6.24 |
| U59 | The connection lease, handback, global waiter queue, and adapter credit flow are design invariants, not implemented behavior | The review found the previous ownership text contradictory. The new text is a rule, not evidence that the code exists | Implement and test T5.39 to T5.52, T7.34, T8.24, T8.25, and the T16 adversarial rows before any claim |
| U60 | The revision 9 rules (fixed `session_generation`, one waiter settlement, ordered adapter application with graceful close, fetch re-election, one ledger sequence, status-only runtime) are design invariants, not implemented behavior | The revision 8 review found that the revision 8 versions contradicted each other and their tests | Implement and test T5.33, T5.39, T5.46 to T5.52, T6.18, T6.25 to T6.27, T7.34 to T7.37, T13.11, and T16.04, T16.09, T16.10, T16.13, T16.14 before any claim |
| U61 | The routes-first stop order applies only to a run with the DoH profile active | Changing the order for every run would change existing non-DoH stop behavior, which WS1 does not own | Keep the existing order when the DoH profile is not active. A separate change may adopt routes-first for every run after its own review. H15 must hold before either |
| U62 | A second pool panic stops DoH but keeps the tunnel up with captured DNS unanswered | That touches `AGENTS.md` invariant 13, which forbids a stale tunnel that hides a dead path | Product-owner decision: keep the tunnel up with the `failed` coverage state visible (this design's proposal), or stop the tunnel with a fixed reason. No invariant change is made here (section 6.7) |
| U63 | A failed TCP:53 query closes its inner connection after an ordered drain; the client sees a close, not an answer | A local SERVFAIL answer would keep the connection open but is answer synthesis, which section 4.8 forbids | Product-owner option, not part of this design. If chosen, it needs its own review and its own counter |
| U64 | Owner questions Q1 to Q5 on resolver substitution are open | The existing `1.1.1.1:53` redirect and the explicit-server options shape the amendment text | Product-owner decision record (section 4.1.2). WS1 does not decide or change any of them |

### 11.2 Handoffs

| Owner | Work | Why |
|---|---|---|
| WS0 | Add `capability_schema: 2`, `encrypted_dns`, `resolver_ech`, `app_ech`, and the separate `runtime` object under the contract in section 2.4 and the migration in section 2.5. Put capability and `runtime` in the status payload; put counters and `ledger { exact, phase, snapshot_seq }` in diagnostics. Keep the legacy `ech` meaning; do not alias it while a consumer reads it as a mechanism flag. Split the `supported` comment so `modes.off` keeps "mechanism exists" and privacy keys require live evidence. Define the reviewed build qualification constant. Keep `doh_lookups`, `doh_ok`, and `doh_failed` at the endpoint ECH-config meaning and record the narrowing. Add the counters and causes in section 7.2, including `doh_in_flight`, `doh_config_in_flight`, `ech_attempts_in_flight`, `doh_adapter_errors`, `doh_cancelled`, `doh_other_error`, `doh_response_mismatch`, and `doh_tcp53_queries`. Record the `doh_query_ok` commit definition. Add `ech_rejection_unauthenticated`, `ech_error`, and `ech_retry_exhausted`, and narrow the `ech_rejected` comment. Remove "or a stall" from the `ech_fallback` comment. Do not add a `generation_mismatch` reason; remove `completion_queue_full` from the product reasons. Do not add a default DoH failure record or the default plaintext counter. State that `doh_*` and `ech_*` can be nonzero while `mode = off`, and that the ledger is one global object across 1 to 8 shards. Keep `session_generation` (fixed per session), `config_generation`, and the ledger sequence reported as `runtime.snapshot_seq` and `ledger.snapshot_seq` distinct. Remove `runtime` from the `platform` copy in the probe response. Add the `doh_stop_incomplete` fault field and the `RelayStopReport` result. Do not add a resolver setting or default endpoint | The current schema cannot report the design honestly, and an additive change must not break the consumers in section 2.5. The status/diagnostics split is required because the two payloads do not share a request |
| WS5 | Replace "Hide the destination" for DoH. Add an app-dependent ECH row with its own three-value vocabulary, a `resolver_ech` row, and an `encrypted_dns` row. Show `runtime.encrypted_dns_coverage` as runtime coverage from status, not as the capability value. Keep `off` as a runtime mode. Update `gui_assets/app.js` and its test, the Linux renderer and its test, and the Windows report and its test together. Give the Linux card both `hs:status` and `hs:diagnostics` paths in section 2.5.2 and keep the static fallback. Keep the Windows report static and label a missing key "Not reported by this build". Keep the legacy `ech` row labeled. Do not add the default plaintext warning without the section 2.6 acceptance | The UI must not exceed the claim boundary, and existing consumers must not silently change meaning, take capability from diagnostics, or infer a state from a missing key |
| WS6 | Verify the P1 to P15 handoff in section 11.3 against the plan text. The plan's revision note says task `85710a0e` applied P7 and P9 to P15; that is a text observation, not this design's approval. Verify each quoted passage and report any mismatch. This revision does not edit the plan. Keep README and the technical reference saying destinations are visible until an implementation lands. P10 records the resolved client boundary and the separate DoH scope in every old boundary-open passage, and distinguishes the product owner's scope decision from the technical review | The plan still hides the SOCKS5 local-resolution leak in the direct passage, omits the new capability keys, keeps several boundary-open passages, and carries stale DNS, counter, Linux, and reader-facing claims. A plan revision note is not evidence that each passage is correct |
| WS2 | Sequence the `relay.rs` edits. WS1 touches the shard admission path, the UDP DNS path, the TCP SYN branch, the adapter, and the stop barrier; WS2 touches the TCP data path. WS1 also touches the `rust/src/service.rs` tunnel worker stop order and the fault slot in a DoH run (section 6.4.8) | The plan's exclusive file scopes cannot be literal for `relay.rs`, and the stop barrier must be shared |
| Scope acceptance | Accept or decline the tunnel-wide DoH forwarder as an independent proposed scope, recording the tradeoffs in section 4.1.1 and the platform coverage limits. As part of that decision, decide whether the product may substitute a configured third-party resolver and approve an explicit amendment to `AGENTS.md` invariant 4; if the plan is read to require the network resolver, its scope text or invariant 4 needs the same amendment (section 4.1.2). Answer owner questions Q1 to Q5 in section 4.1.2, including how the DoH profile relates to the existing source device proxy mode `1.1.1.1:53` redirect and the explicit `--dns-upstream` and `--dns-servers` options, and whether the uncommitted invariant 4 change lands first. Decide U62 (tunnel up or down after a DoH-only stop) and, if wanted, U63 (local SERVFAIL) | It captures DNS, trusts a third-party resolver, substitutes for the resolver the network selected, and may cover little default system-resolver traffic. It is not approved by this document or by P10 |
| Owner | The DoH forwarder scope acceptance is a separate product owner decision, and the third-party resolver substitution needs its own decision and invariant amendment. The owner decisions open after revision 9 are Q1 to Q5 (U64), U62, and the optional U63. If the owner later wants a product-owned TLS client, that is a new optional proposal with its own product decision and review. It must not terminate TLS or add a relay | `hide` is closed as unsupported under the current constraints, so the old client-boundary decision is not a gate. The DoH scope and the resolver substitution are new product choices with the tradeoffs in sections 4.1.1 and 4.1.2 |

### 11.3 Explicit WS6 plan handoff P1 to P15

These are the only accepted corrections to `docs/SNI_HIDING_PLAN.md` from this
workstream. Name each passage by its quoted text, not by a line number: the
plan file is untracked and its lines move. Apply every remaining item. Do not
paraphrase P1 or P2 into a softer rule.

At the 2026-11-05 checkpoint, the plan's own revision note says task
`85710a0e` applied P7 and P9 to P15. The plan header also says a later reader
must re-read the quoted passage before trusting an older checkpoint statement.
This design treats the revision note as a text observation by the plan, not as
this design's approval and not as evidence that every passage is correct. WS6
verifies each item against the quoted text. This revision does not edit the
plan. Where an item below still says "Required correction", the plan's revision
note claims that correction is applied; read that sentence as the text to
verify, not as an instruction to edit the plan now.

No implementation starts until WS6 verifies the plan text, the DoH scope is
accepted by the product owner together with the third-party resolver decision
and the invariant amendment in section 4.1.2, and a new independent review
passes.

P10 records the resolved client boundary and the separate scope status of
encrypted DNS. Closing the boundary is not a new owner decision: the plan's own
default is that `hide` is not built when no acceptable boundary exists. The
**DoH forwarder scope acceptance is a new product owner decision** with the
tradeoffs in section 4.1.1. **The third-party resolver substitution is a second
decision** that needs an explicit invariant amendment (section 4.1.2). Both are
distinct from the independent technical review, and P10 does not approve
either.

**P1. The blockable bullet's fallback sentence. Status: applied.**

Current plan text:

> **It is blockable.** A static outer name and the encrypted-DNS dependency are
> visible. A network can block either. Do not automatically retry without ECH
> after a timeout, reset, or certificate failure. A separately selected non-ECH
> profile would not be `hide`. The future design needs independent approval.

The plan no longer requires a fresh non-ECH flow after a detectable failure. It
forbids the automatic retry and labels the separately selected profile. No
further plan edit is required for P1. T12.01 checks this text.

**P2. The `hide` acceptance gate. Status: applied.**

Current plan text:

> A blocked ECH outer name does not trigger an automatic non-ECH retry on a
> timeout, reset, or certificate failure. A separately selected non-ECH
> profile is labeled as such and is not `hide`.

The old "fails over to a fresh non-ECH flow" gate is gone. No further plan edit
is required for P2. T12.01 checks this text.

**P3. GREASE is described as the default and as the non-ECH fallback. Status:
applied.**

Current plan passages:

> ECH when a usable `ECHConfig` exists; GREASE, if implemented, is a separate
> opt-in and does not establish that destinations look alike;

> policy. GREASE alone is not `hide`.

GREASE is now opt-in and never a `hide` claim. The old "GREASE otherwise" and
"falls back to GREASE" text is gone. No further plan edit is required for P3.
T12.04 checks both passages.

**P4. SOCKS command `0x80` for DNS. Status: applied.**

Current plan passages:

> Intercepted UDP DNS port 53 is redirected to `1.1.1.1:53` using SOCKS
> command 1 with DNS-over-TCP framing. Other UDP uses command `0x80`.

> Intercepted UDP port 53
> is redirected to `1.1.1.1:53` over SOCKS command 1 with DNS-over-TCP framing.

The header also says command 1, not command `0x80`. Command `0x80` now appears
only as the other-UDP command. No further plan edit is required for P4. T12.02
checks both passages.

**P5. The false "already resolved through the relayed DNS path" claim. Status:
applied.**

Current plan text:

> **Target tun plus `--phone`:** the relay sends a numeric IP. `Setup::phone`
> serializes address type 1 or 4, never a domain. Some DNS can bypass the
> tunnel, including gateway DNS on macOS and Windows.

The old "already resolved" claim is gone. The plan keeps the numeric-address
fact and the gateway bypass warning. No further plan edit is required for P5.
T12.05 checks this text.

**P6. Status words `yes`, `no`, and `unknown`. Status: applied.**

Current plan passages:

> The current schema uses `supported`, `unsupported`, `unavailable`, and
> `unverified`. Future platform claims require evidence appropriate to their
> scope; a compile alone does not establish live support.

> Use the existing capability states and report unverified claims as
> `unverified`.

> `probe` on every platform prints the capability row for that build, using
> `unverified` where the claim is unverified.

The three plan locations use the four state names. No further plan edit is
required for P6. The stricter live-evidence rule remains section 2.4 of this
document, and the plan says a compile alone is not live support. T12.03 checks
the state names.

**P7. Invariant 4 and the SOCKS5 description hide `TinyResolver`'s plaintext
leak. Status: applied per the plan revision note; verify.**

Current plan passages:

> 4. No `getaddrinfo` on an egress path. Document DNS paths that bypass the
> tunnel, including local client resolution and scoped system resolvers. The
> SOCKS5 `TinyResolver` query is plaintext and pinned to the physical link. It
> is a target-side local-resolution leak. The `socks5h` requirement is not
> enforced by the code.

> **Direct SOCKS5:** the laptop resolves through the in-tree resolver over a
> normalized UDP socket and connects to an IP. The destination never sees a
> name.

The plan revision note says this item is applied. The invariant 4 quote above
includes the target-side plaintext leak and the unenforced `socks5h`
requirement. The direct SOCKS5 passage still says "resolves through the in-tree
resolver"; the invariant is the passage that carries the leak. Verify both
against the live plan text; do not treat the note as approval. T12.06 checks
both.

**P8. The capability status table says no ECH or SNI capability is reported.
Status: applied.**

Current plan text:

> Capability reporting exists and reports unsupported modes honestly. The
> proposed modes are not available.

The false "report no ECH or SNI capability" sentence is gone. The exact
`sni_override` key statement is folded into the P9 parity correction. No
further plan edit is required for P8. T12.07 checks this text.

**P9. The parity contract lacks `encrypted_dns`, `resolver_ech`, and
`app_ech`. Status: applied per the plan revision note; verify.**

Current plan passage:

> 2. **Capability flags, not silent absence.** The current schema uses
> `supported`, `unsupported`, `unavailable`, and `unverified`. Future
> platform claims require evidence appropriate to their scope; a compile
> alone does not establish live support.

Required correction: add `encrypted_dns`, `resolver_ech`, and `app_ech` to the
reported set. State that `encrypted_dns` and `resolver_ech` are separate
capabilities, that `app_ech` is `app_dependent` and not a support state, and
that the legacy `ech` keeps its build-mechanism meaning and value until a
schema version that updates every consumer. Point to architecture section 2.4
and the migration in section 2.5. The state names are fixed already;
the key set is not. T12.08 and T12.11 check this.

**P10. The WS1 gate treats the client boundary as open and blocks independent
encrypted-DNS work. Status: applied per the plan revision note; verify.**

The plan still has several boundary-open passages. Each one must change, not
only section 2.4. The current text is:

> The most important open question is not which library to use. It is **which
> client owns the TLS connection that would carry ECH**.

> Until that boundary is settled with evidence, `hide` is a hypothesis, not a
> promised feature.

> | `hide` mode | **Not implemented. Design blocked on the client boundary** |

> ### 2.4 The client boundary for `hide` is unresolved

> WS1 must answer "which connections does `hide` own?" with a concrete client
> boundary, a data path, and a test that shows an ECH `ClientHello` on the wire
> for those connections. If no acceptable boundary exists, `hide` is not built
> and no UI or documentation claim is made. This is a gate, not a research note.

> Correct status: not implemented, and blocked until WS1 names the client
> boundary.

> | Laptop TLS client for `hide` | Not present. ... | Blocked on section 2.4. |

> - WS1 records the client boundary and the exact flows `hide` can affect. If no
>   acceptable boundary exists, `hide` is not built and no claim is made.

> 1. **Client boundary for `hide`.** Which connections would the product own:
>    application-native ECH, an explicit client surface, or termination? This is
>    the WS1 gate and the largest blocker.

> - "`hide` is implemented in the Rust engine" changed to "not implemented and
>   blocked on the client boundary."

> | WS1 | Rust TLS core for `hide` | ... | **First deliverable is the client-boundary decision.** No code before an agreed boundary and a test that owns the wire. |

The Windows privacy report also says "The client boundary for this mode is
unresolved." That is reader-facing text and must change in the same migration.

Required correction: record the boundary outcome instead of waiting for a new
product decision. Replace every passage above with the outcome text below, and
keep the sections' surrounding facts:

> **First deliverable is the client-boundary outcome.** A transparent byte relay
> cannot inject ECH. Under the current no-termination and no-relay constraints,
> no transparent boundary exists, so `hide` is not built and stays unsupported.
> This is the plan's default outcome, not a new product choice. A product-owned
> TLS client is a separate optional future proposal with its own product
> decision and review; it must not terminate TLS or add a relay. Encrypted DNS
> and resolver ECH are a separate proposed scope with their own tradeoffs and
> review gate. This correction does not approve that scope, and no code starts
> until the product owner accepts the scope and an independent review passes.

The WS1 gate then applies only to application ECH, which is closed for lack of a
transparent boundary. The DoH forwarder is not approved by this correction, and
its scope acceptance is a separate new product owner decision. Do not present
either the boundary outcome or the scope split as approval of encrypted DNS.
Do not describe the independent design review as the scope acceptance. T12.09,
T12.14, and T12.18 check this.

**P11. "DoH caching" and the stale ECH failure-policy question. Status: applied
per the plan revision note; verify.**

Current plan passage:

> Test record reframing, ECH config handling, ECH config caching, and retry
> after rejection once in Rust, hermetically, with no routes and no root.

The caching correction is claimed applied. The plan's open question 6 is now
marked answered for the proposed design: the only detectable failure is an
authenticated ECH rejection on the resolver connection; there is no time-based
wait; a timeout, reset, certificate failure, 5xx, parse error, SERVFAIL, or
unauthenticated rejection never causes a non-ECH retry; a non-ECH application
flow is a profile chosen before connecting; the resolver connection retries at
most once only after an authenticated rejection, with retry configs, or with ECH
disabled when no supported retry config exists. Verify the text; the note is
not approval. T12.10 checks both the caching text and the open-question answer.

**P12. Stale code and counter claims. Status: applied per the plan revision note; verify.**

The plan contains both of these claims:

> The current tree has dormant TLS record-reframing code, tests, counters, and
> capability reporting; this does not make `shape` or `hide` available.

> | Counters | `relay::Counters` to `RelayStats` to diagnostics JSON to service status to app decode | Proposed, not implemented. Adding a field follows the same path. |

The tree has dormant `ech_*` and `doh_*` counter keys with zero values in
`rust/src/diagnostics.rs`, and it has capability reporting. It has no ECH
client. The two plan statements contradict each other and overstate what a
counter means.

Required correction: say that the counter **keys and zero values** exist and
that the data path does not write them; say that capability reporting exists
and reports conservative values; do not say "counters ... proposed, not
implemented" in a way that implies no keys exist. Do not imply that a counter
key is an ECH implementation. T12.17 checks this.

**P13. The DNS transport claim. Status: applied per the plan revision note; verify.**

The plan says:

> Its own outbound TLS surface is effectively absent: the local control page is
> loopback HTTP, pairing uses its own protocol, and DNS is UDP.

DNS is not only UDP. The source device proxy carries intercepted DNS over SOCKS
command 1 with DNS-over-TCP framing, and TCP:53 exists as a plaintext path. DoH
is HTTPS over TCP. The engine's tunnel DNS path is plaintext today, but the
transport claim is stale.

Required correction: "DNS uses UDP and TCP. The tunnel's DNS path is plaintext
today. In source device proxy mode, intercepted UDP:53 is carried to the source
device over SOCKS command 1 with DNS-over-TCP framing. TCP:53 is a separate
plaintext path. DoH would be HTTPS over TCP." T12.18 checks this.

**P14. The Linux and default-resolver bypass is missing. Status: applied per the plan revision note; verify.**

The plan header and section 7.1 name gateway DNS bypass on macOS and Windows.
They do not name Linux or the default link-bound resolver.

Required correction: add "On Linux, a default `systemd-resolved` per-link
resolver can take the physical-interface rule and table main; treat gateway DNS
as a likely bypass until a live DNS-specific measurement. Scoped resolvers,
link-local, ULA, multicast, NAT64, and application or OS encrypted DNS can also
bypass the tunnel. No live DNS-specific result exists for any target." T12.19
checks this.

**P15. Reader-facing terms. Status: applied per the plan revision note; verify.**

Several reader-facing passages still say `hide` is a hypothesis, blocked, or
waiting for a boundary. The Windows privacy report says "The client boundary
for this mode is unresolved."

Required correction: use "closed as unsupported under the current
constraints" for `hide`; keep "the boundary outcome is that no transparent
boundary exists"; say encrypted DNS is a separate proposed scope, not approved;
and remove "unresolved" and "blocked on the client boundary" from
reader-facing text. Do not say `hide` is implemented or that DoH is `hide`.
Update the Windows, macOS, Linux, and shared page text in the same change. T12.20
checks this.

#### 11.3.1 What closes P1 to P15

- P1 to P15 are present in the plan at the 2026-11-05 checkpoint, according to
  the plan's own revision note for task `85710a0e`. They remain closed only
  while the checked text stays in place and T12 passes. This design does not
  re-certify the plan and does not edit it.
- P7 remains the item to check most closely: the plan header says some older
  passages describe an older checkpoint, and the direct SOCKS5 passage must
  name the `TinyResolver` leak, the ATYP 1 and 4 leak, and the unenforced
  `socks5h` requirement, not only "local client resolution".
- P10 records the resolved client boundary and the separate DoH scope. Closing
  the boundary does not wait for a new owner decision. The DoH forwarder's own
  product scope acceptance is separate, and so is the third-party resolver
  decision and invariant amendment in section 4.1.2. Neither is closed by P10,
  by this design, or by the independent review.
- Every item is checked by T12.01 to T12.24. An "applied" status is a text
  observation, not evidence of code or live behavior.
- No implementation may cite this section as approval. It is a handoff.

## 12. Review gate and acceptance criteria

A new independent review must check at least:

1. The requirement was not redefined. `hide` still requires application ECH
   plus DoH.
2. No claim marks `hide` supported from DNS alone or from engine DoH ECH.
3. Universal application ECH is proven impossible under the constraints; the
   client boundary is closed to unsupported, not left waiting for an owner
   decision. A product-owned client is separated as an optional future proposal.
4. App-native ECH is described with its DNS/API limits and is not counted.
5. The DoH bypass table covers macOS, Windows, and Linux. macOS and Windows
   gateway DNS is a bypass by route-specificity inference, not live DNS
   evidence; Linux is a likely bypass on a default link-bound resolver. Scoped
   resolvers, link-local and IPv6 special addresses, OS DoH/DoT, application
   DoH/DoT/DoQ, and caches are covered. It does not claim gateway DNS coverage
   or a live DNS-specific result on any target.
6. The resolver override is either safely designed with crash cleanup or
   explicitly out of scope. It is out of scope here.
7. The actual SOCKS5 DNS path and the tun path are stated correctly, with the
   corrected invariant 4 text.
8. The GREASE false counter is removed and no application ECH counter is
   derived from relayed traffic.
9. The only retry is on the resolver connection, only after an authenticated
   ECH rejection. It is at most one retry: with retry configs, or with ECH
   disabled when no supported retry config exists. A non-ECH application flow
   is a profile state chosen before connecting, never a retry after a failure.
   Timeouts, resets, certificate failures, 5xx, parse errors, and SERVFAIL never
   cause a retry. The ECH-disabled resolver retry is explicit, not a loophole
   for application flows.
10. The bootstrap is trusted: configured name and IP, TLS validation,
    `webpki-roots`, no redirect, no config from the system resolver.
11. No relay shard blocks on I/O. Queues, threads, sessions, waiters, frames,
    event slots, delivery and close dispositions, job-table entries, attempt
    work items, adapter credits, and cache are bounded. A completion, event, or
    disposition is never dropped silently.
12. The TCP:53 adapter has access control and a crash test. It never submits a
    pool job or writes a DoH counter; the owning shard owns each query job. It
    receives bytes only as a committed answer disposition, and it closes the
    inner connection for every failed query. Every accepted query has exactly
    one answer or close. Or the virtual outer replaces it.
13. No QNAME, endpoint name, ECH config, SNI, or certificate enters a log,
    status, diagnostics, or failure record. A DoH failure record is a separate
    privacy scope and is off by default.
14. Every egress socket is normalized and the TTL audit stays at `ttl_bad == 0`.
15. The dependency split and cross-target behavior are explicit, with no stub.
    `doh` and `ech` are additive; `ech` implies `doh`; all three combinations
    are built.
16. The test matrix has mocks for cleanup and crashes, fuzz bounds, a
    no-plaintext-DNS assertion, a late-completion test, a 1 to 8 shard
    coherent-snapshot stress test, a commit-order test, a session lifecycle
    test, a churn test, a stop-barrier test, a capability consumer test, a
    default-`off` test, a protocol regression test, and a clear runtime versus
    carrier split.
17. The plan accounts for P1 to P15. The plan's revision note says task
    `85710a0e` applied P7 and P9 to P15. WS6 verifies the quoted passages; this
    design does not treat the note as approval. P10 covers every boundary-open
    passage and records the resolved boundary outcome plus the separate DoH
    scope. It distinguishes the product owner's scope decision and the
    third-party resolver decision from the independent review. No timeout or
    reset causes a downgrade.
18. Existing `doh_lookups`, `doh_ok`, and `doh_failed` keep their endpoint
    ECH-config meaning, the narrowing is recorded, and the new forwarder
    counters are separate.
19. The ECH and DoH identities are exact in a coherent snapshot and after the
    stop barrier seals. `doh_in_flight`, `doh_config_in_flight`, and
    `ech_attempts_in_flight` account for accepted work with no outcome.
    `doh_query_failed` is partitioned into exactly one of its seven causes,
    including `doh_cancelled`. Each accepted job has one job ID, one owning
    shard, one `session_generation`, one `attempt_id`, and one terminal owner; a
    late completion is discarded by job ID and attempt ID, and a duplicate
    disposition by its already-applied job ID. `session_generation` is fixed
    per session. The three sequences `session_generation`,
    `config_generation`, and `ledger_seq` are distinct. `ech_grease` and `ech_fallback` are
    type counts, not outcomes.
20. `encrypted_dns` and `resolver_ech` are `unverified` until a live run on
    each build and platform, then may be `supported`. No build reports either
    supported key from a compile, a linked provider, or a hermetic test. The
    legacy `ech` key keeps its meaning and value; it is not aliased to
    `app_ech` while a consumer reads it as a mechanism flag.
21. The capability contract and the migration in section 2.5 are followed: one
    of the four state strings for modes and capabilities, one of the three
    `app_ech` values with its own parser kind, no free-text detail, a missing
    key is hidden and never `unverified`, a capability value is not recomputed
    per profile, and static capability is a different object from runtime
    coverage. Capability and runtime come from status; counters and ledger
    metadata come from diagnostics. Cross-endpoint coherence is not claimed.
    Every consumer in section 2.5 is mapped with its data path.
22. The implementation gate is scope-specific. WS6 P1 to P15, the product
    owner's DoH scope acceptance, and a new independent review precede any
    implementation. Application ECH is closed. The DoH forwarder is not
    approved. The default `off` behavior does not change.
23. The retry policy is stated once and matches in section 5.3, section 12,
    matrix T4.09, T4.24, and G5, and plan P11. There is no blanket "no non-ECH
    attempt" sentence that contradicts the resolver ECH-disabled retry.
24. The counter ownership is per accepted job, held by the admitting shard,
    and covers the UDP query, the TCP query through the adapter, the config
    fetch, and the ECH attempt. Every shard writes one global ledger. The pool
    and adapter write no DoH counter.
25. The direct-mode DoH failure record and the default plaintext counter and
    warning are separate scopes. Neither is approved by this design review or
    by the DoH scope acceptance unless that scope names it.
26. The relay has 1 to 8 shards, and the design does not assume one. Every
    global bound is reservation-based under the ledger lock. A job is admitted
    by exactly one shard and never migrates. Slot waiters are in one global FIFO
    with a direct slot grant; there is no per-shard waiter order.
27. The terminal decision precedes delivery. A cancelled, timed-out, duplicate,
    or stale-attempt response never reaches the inner client. A disposition
    carries a connection ID, request ID, job ID, and session generation, and is
    applied in `request_id` order. A committed answer is written or counted
    once as undelivered; no later commit makes it stale.
28. A session has one owner, one reserved slot, one `session_generation`, and
    one named release path. A connection is held through one move-only lease;
    the slot frees only after the handback for the attempt that held it. A quiet
    UDP session is a normal close, not eviction. The config cache is
    single-flight and publishes only from a compare-and-set fetch or retry
    commit. An ECH attempt is an `AttemptStarted`/`AttemptOutcome` pair.
29. The capacity model states its envelope and its failure mode. The session
    cap and pool size are measured parameters. Per-query-port churn does not
    exhaust the default at the declared rate. Sharing across source ports is
    recorded as an unapproved option, not a default.
30. The stop barrier has explicit phases and a bounded DoH deadline, and it runs
    before `Relay::stop` sets `running = false` and before the shard join. An
    admission and the stop transition cannot interleave. A missed deadline is a
    failed stop, and an inexact ledger is never published as exact. The total
    stop budget is unknown because the existing joins are unbounded.
31. Runtime coverage is a separate object in status. `app_ech` has its own
    vocabulary and parser kind. `encrypted_dns_coverage` has its own parser
    kind. The Linux renderer has both status and diagnostics paths and a static
    fallback. The Windows static report does not print a value it did not
    receive. No consumer infers a state from a missing key or from `mode`.
32. No protocol regression: SOCKS, pairing, the source device proxy, the ICMP
    echo commands, the key schedule, the TTL, the route rules, the IPv6
    defaults, and one-outer-per-flow are unchanged. The adapter preface is local
    loopback framing.
33. B1: the retry is a second attempt of the same query job. The owning shard
    authorizes it and publishes a retry config only through a compare-and-set.
    No sequence changes at retry authorization (R9-B1). The pool never writes
    the cache, and a stale rejection cannot evict a newer config.
34. B2: a slot is freed only after the handback for the attempt that held it.
    A terminal decision alone does not free it, and a late handback cannot free
    a newer session's slot.
35. B3: adapter admission uses credits, not a dropping channel. Every accepted
    TCP:53 query gets one answer or one close disposition. A failed query closes
    the inner connection without waiting for the idle timer.
36. B4: one global waiter FIFO, one direct grant that keeps the slot counted,
    one global deadline reaper, and exactly one recorded outcome per waiter.
37. B5: the DoH barrier runs inside the real `Relay::stop` order. A Drop-only
    stop is `drop_only` and inexact. A stuck pool thread is detached and
    reported, not claimed gone. The total stop time is not bounded by the DoH
    barrier alone.
38. B6: capability and runtime coverage are read from status; counters and
    ledger metadata are read from diagnostics. Cross-endpoint coherence is not
    claimed. Missing keys are hidden, missing counters are not zero, and a
    missing `ledger.exact` is not true.
39. B7: the DoH endpoint is a third-party resolver. A product-owner decision and
    an explicit amendment to `AGENTS.md` invariant 4 are required; if the plan
    is read to require the network resolver, its scope text or invariant 4 needs
    the same amendment. This design does not assert that the scope is approved
    or that the invariant is compatible.
40. R9-B1: `session_generation` is allocated once per session and never
    changes. A successful retry and every queued job after the first commit
    complete normally. No `generation_mismatch` reason exists. The adapter
    applies dispositions in `request_id` order and never drops a committed
    answer for being "not current"; an unwritten committed answer is counted
    once.
41. R9-B2: every waiter has one settlement transition. Revocation,
    cancellation, the reaper, a refused `admit_granted`, and `Stopping` all go
    through it, and a second call is `Stale`. A granted-then-cancelled waiter
    records one waiter outcome, not a job outcome. The release step never
    grants a waiter past its wait window. `Stopping` settles queued waiters and
    outstanding grants.
42. R9-B3: in a DoH run the tunnel worker calls `begin_stop`, removes routes,
    and then drains. `Relay::stop` returns a `RelayStopReport`. An incomplete
    DoH stop has its own message and fault field, never sets
    `cleanup_blocked`, and blocks only a later DoH-profile start while a
    detached thread lives. No test claims that a stuck thread's socket is
    closed by the barrier.
43. R9-B4: section 4.1.2 states the committed and uncommitted invariant 4
    texts, the existing `1.1.1.1:53` redirect, and the existing explicit-server
    options correctly. The no-built-in-endpoint rule is limited to the DoH
    profile. Owner questions Q1 to Q5 are listed and open. No invariant is
    changed.
44. R9-M5: `snapshot_seq` has one definition, the per-run `ledger_seq`, and
    one owner, the ledger.
45. R9-M6: runtime coverage is read only from the latest successful status
    response. The probe copy carries no runtime object.
46. R9-M7: a TCP:53 close is graceful and ordered. One query's failure never
    makes another query on the same connection `doh_cancelled`.
47. R9-M8: the retry row says `BetweenAttempts`. A config fetch that ends
    without a commit wakes every shard and elects at most one new fetcher, or
    sets `retry_after` after a failure.

Acceptance criteria for a future implementation, none met today:

- No `hide` build is planned under the current constraints. If a future
  product-owned client proposal is approved, it must have an application ECH
  path tested on the wire for the flows it claims. The test shows the real name
  absent from the ClientHello and ECH accepted by a real provider for those
  flows. That proposal is not this workstream.
- With a DoH setting active, DoH covers UDP:53 and TCP:53 with no plaintext DNS
  for tunneled queries. A test with a capturing mock shows no egress packet to
  port 53 and no DNS payload. DoH is off by default; the default `off` behavior
  is unchanged.
- The TTL audit ends at `(n, 0)` for every DoH socket.
- A failure does not produce a plaintext query and does not produce a retry
  after a timeout, reset, certificate failure, 5xx, parse error, or SERVFAIL.
- An authenticated ECH rejection on the resolver connection produces exactly
  one retry and no loop: with retry configs, or with ECH disabled only when no
  supported retry config exists. It evicts the rejected config. A second
  failure ends the flow.
- An application flow never produces a non-ECH attempt. An unauthenticated
  rejection produces no retry. The resolver ECH-disabled retry is the only
  exception and is counted as `ech_fallback`.
- The default `off` profile adds no DoH counter, no plaintext warning, no DNS
  path, and no mode. A plaintext-profile counter and warning appear only after
  the separate acceptance in section 2.6.
- No DoH failure record appears in either mode until the privacy scope in
  section 7.1 is accepted. If accepted, a direct-mode record names the inner
  destination and no name, never `1.1.1.1:53`. The TCP:53 adapter path gets the
  destination from its preface, not from the loopback listener.
- The counter ledger in section 7.2 adds up exactly in a coherent snapshot and
  after the stop barrier seals, for 1, 2, 4, and 8 relay shards. The admitting
  shard is the owner of its jobs and every shard writes one global ledger.
  Every `doh_queries` has one outcome and one cause, with `doh_in_flight`
  accounting for accepted work with no outcome. Every attempt pair has one
  outcome or is in `ech_attempts_in_flight`. A GREASE handshake and a non-ECH
  bootstrap are outside that identity. A late completion or duplicate delivery
  is discarded.
- Every admitted job belongs to one shard and ends exactly once. No job migrates
  shards, and no shard has a private counter that a reader has to add.
- A response reaches the inner client only after the owner commits one outcome.
  A cancelled or timed-out job delivers no bytes. A duplicate disposition
  writes nothing. Dispositions are applied in `request_id` order, and a later
  commit never makes an earlier committed answer stale. A committed answer
  that is not written increments `doh_adapter_errors` once and does not create
  a second query outcome. Every accepted TCP:53 query ends with one answer or
  one graceful, ordered close, and no query is made `doh_cancelled` by another
  query's failure.
- A session, a config-cache entry, and an ECH attempt each have one owner and a
  named release path. A quiet UDP session frees its own slot. A slot is freed
  only after the handback for the attempt that held the connection lease. The
  cache is single-flight and publishes only from a compare-and-set fetch or
  retry commit. A late fetch result publishes nothing. A stale rejection does
  not evict a newer config.
- At the declared per-query-port rate the session cap does not exhaust. Above
  the envelope the query fails with `doh_queue_full`; it does not share a
  connection across source ports and does not send plaintext. The wait is one
  global FIFO and a grant cannot be lost to another shard.
- The DoH barrier completes within its DoH bound or reports a failed stop. It
  runs before `Relay::stop` sets `running = false` and before the shard join. In
  a DoH run the routes are removed after `begin_stop` and before the drain. An
  incomplete DoH stop is reported through `RelayStopReport` and never sets
  `cleanup_blocked`. No admission is recorded after the phase leaves `Running`. An inexact ledger is
  never published as exact. A Drop-only stop is `drop_only`. The total stop
  budget is measured, not assumed.
- The capability row uses the section 2.4 contract and the section 2.5
  migration. No value carries free text, a missing key is hidden and never
  `unverified`, `app_ech` uses its own three-value parser kind, a value is
  static per build and platform, and no build reports `supported` for any key
  from a compile alone. `runtime.encrypted_dns_coverage` is a separate object in
  status and is never read as a capability. Counters and ledger metadata are in
  diagnostics. Cross-endpoint coherence is not claimed. Runtime coverage is read only
  from the latest successful status response; the probe copy has no runtime
  object. `runtime.snapshot_seq` and `ledger.snapshot_seq` are values of one
  per-run `ledger_seq`.
- The Linux card reads capability and runtime from `hs:status` and counters from
  `hs:diagnostics` when they are present, and keeps a static fallback. The
  Windows static report prints "Not reported by this build" for a key it did not
  receive. Neither infers a state from `mode`, a build flag, or a missing key.
- No protocol changes. A static diff check and the behavior tests show SOCKS,
  pairing, the source device proxy, the ICMP echo commands, the key schedule,
  the TTL, the route rules, the IPv6 defaults, and one-outer-per-flow unchanged.
- No name appears in status, diagnostics, failures, probe, or logs.
- Stop, drop, panic, and crash tests leave no listener and no open connection
  that the process can still close. A pool thread that cannot be joined is
  detached and reported, not claimed gone, and its socket is not claimed
  closed. Stop records `doh_cancelled` and
  returns every gauge to 0. A shard panic or a missed barrier deadline does not
  publish a partial ledger as exact.
- The third-party resolver decision, answers to Q1 to Q5, and the invariant
  amendment in section 4.1.2 exist before any DoH code. Until they do, no DoH
  query is forwarded. The DoH profile has no built-in, automatic, or fallback
  endpoint. The existing source device proxy mode `1.1.1.1:53` redirect and the
  explicit-server options are existing behavior that this design does not
  change and does not describe as absent.
- A live carrier measurement shows what is reachable and what is blocked. A
  VM or loopback result is not a carrier result.
- `encrypted_dns` and `resolver_ech` are `supported` only after a live run on
  that build and platform shows the claimed path.
- `README.md`, `docs/TECHNICAL_REFERENCE.md`, the plan, and the UI match the
  behavior table. Until then, they say destinations are visible.

## 13. What would make this design wrong

- If no shipping target can build a TLS provider for `doh`, encrypted DNS is
  unavailable there. The capability must say so; it must not ship a stub.
- If real DoH providers reject HTTP/1.1 POST in practice, the design needs an
  HTTP/2 stack. That is a larger dependency and changes decision 6. Test two
  independent providers before committing.
- If no application on a target can obtain HTTPS/SVCB records through the
  system resolver, app-native ECH is not viable in practice. The only path is
  then a product-owned client, which is a separate optional future proposal.
- If the loopback adapter's local surface is unacceptable after review, the
  virtual outer must replace it. Do not keep both.
- If one connection per inner DNS flow is too expensive on a real hotspot, the
  tempting fix is a shared connection. That would violate invariant 3. The
  correct response is to reduce flows or accept the cost, not to multiplex.
- If a carrier blocks the DoH IP, port, or name, the feature fails on that
  network. A per-network profile is required; a silent plaintext switch is
  not.
- If an ECH rejection is treated as a network failure and retried without ECH,
  an active attacker can force a downgrade. The design would be wrong even if
  every test passed.
- If any component can write bytes to an inner client before the owner commits
  an outcome, the counter ledger and the client can disagree. The design would
  be wrong even if the bytes are usually correct.
- If the session cap, the pool size, or the quiet window cannot serve the
  measured per-query-port rate, the design needs a different capacity policy or
  the unapproved coalescing option. A silent drop or a plaintext fallback would
  be wrong.
- If the stop barrier cannot meet its bound on a target, stop must report a
  failed stop and the service must not claim a clean stop. An unbounded join is
  not an acceptable fix. A Drop-only stop must not be reported as clean.
- If a slot can be freed while the pool still holds the connection, or a
  handback for an old attempt can free a newer session's slot, the ownership
  model is wrong.
- If a retry writes the cache from the pool, or a stale rejection evicts a newer
  config, the cache ownership model is wrong.
- If a waiter can be granted by two shards, expire after it was granted, or be
  recorded twice, the global queue is wrong.
- If a failed TCP:53 query leaves the inner connection open until the idle
  timer, or a frame is dropped because the admission channel was full, the
  adapter capacity model is wrong.
- If a consumer reads capability from diagnostics, runtime from counters, or
  treats a missing key as `unverified`, the consumer contract is broken.
- If the design is described as compatible with `AGENTS.md` invariant 4 without
  the amendment in section 4.1.2, the scope record is false.
- If the Linux or Windows card prints a capability or runtime state it did not
  receive, the consumer contract is broken even when the engine payload is
  correct.

## Appendix A. Revision 1 errors corrected

| Revision 1 statement | Revision 2 correction |
|---|---|
| `hide` encrypts DNS and uses ECH only on the engine's DoH connection | Not sufficient. `hide` requires application ECH. DoH is a separate capability |
| `modes.hide` may become `supported` when DoH lands | It must not. It stays `unsupported` until an application ECH path exists |
| The plan's ECH acceptance criterion can be met on the DoH origin only | It cannot be used as the `hide` criterion. It is an engine ECH test, not an application ECH test |
| Optional passive ClientHello ECH count | Removed. GREASE makes it false |
| TCP:53 via a loopback adapter, with no access control | Adapter is retained only with a cookie, loopback bind, caps, and timeouts. A virtual outer is the fallback |
| DoH failure returns SERVFAIL | No synthesized answers. UDP drops and TCP closes. The client sees a failure |
| Retry after a rejection or a stall | Retry only after an authenticated ECH rejection. Never after a timeout |
| Direct SOCKS5 "DNS stays on the relayed path" | SOCKS5 resolves at the target over a normalized plaintext socket. It is a documented local-resolution leak |
| One feature `dns-privacy` for DoH and ECH | Two features, `doh` and `ech`, so DoH is not blocked by an HPKE provider |
| The existing failure record holds IP and DNS name hints | DoH never adds names. Clear the map on mode start. No endpoint name |

## Appendix B. Revision 3 review corrections

Revision 3 answered the independent review of revision 2. This table is kept for
audit. Revision 4 supersedes every row that conflicts with Appendix E. Revision
5 superseded the six-cause ledger with seven causes and the `doh_in_flight`
gauge. Revision 6 supersedes the single-writer and quiescence-only rules with
per-job ownership and a coherent snapshot. In particular, the revision 3 answer
"an opt-in labeled retry is a counted downgrade" is withdrawn: a non-ECH flow
is a profile state chosen before connecting, not a retry.

| Review item | Correction | Where |
|---|---|---|
| B1: The plan requires a post-failure non-ECH fallback that this design forbids | The plan is wrong. `hide` fails closed on a timeout or reset. Revision 4 replaces the opt-in retry with a non-ECH profile chosen before connecting. WS6 applies P1 and P2 by quoted passage | Section 5.3.2, section 11.3, and Appendix E |
| B2: Existing counter meanings change silently | `doh_lookups`, `doh_ok`, and `doh_failed` keep their endpoint ECH-config meaning. The forwarder uses new `doh_queries`, `doh_query_ok`, and `doh_query_failed`. Every handshake that offers real ECH has one outcome, and `ech_attempts` is an input count. Revision 4 adds the exact identity and the six failure causes | Section 2.3, section 7.2.1 to 7.2.3 |
| B2: GREASE and retry handshake counts are undefined | GREASE counts only in `ech_grease`. A retry with configs counts in `ech_attempts` again. A retry with ECH disabled counts in `ech_fallback` | Section 7.2 |
| B2: An unauthenticated rejection has no counter | Add `ech_rejection_unauthenticated`. It replaces `ech_rejected` for that handshake and never retries | Section 7.2 |
| S1: The failure record cannot work with the current code | Add `FailureEvent::doh_query` and a `record_doh_failure` path that records in direct mode. Do not reuse `FailureEvent::dns` or `record_dns_failure` | Section 7.1 |
| S2: `encrypted_dns` can read as supported from a compile | Report `unverified` until a live run on the platform. The main DNS path row is unverified on default desktop resolvers. Linux rule 17000 and `systemd-resolved` are named | Sections 2.2, 4.2, 4.3, 7.3, and 8 |
| Lower: The plan names SOCKS command `0x80` for DNS | The code uses command 1 with DNS-over-TCP framing. WS6 corrects the two quoted passages in P4 | Section 11.1 U26 |
| Lower: The plan uses stale status words | WS6 changes `yes`, `no`, `unknown` to `supported`, `unsupported`, `unavailable`, `unverified` | Section 11.1 U26 |
| Lower: Matrix gaps | Label T5.08 synthetic. Extend T4.14. Clarify T4.06 and T4.09. Reorder T8 rows. Add a continuous adapter flood test and the plan-check tests | `WS1_TEST_MATRIX.md` |

## Appendix C. Code references

Symbols are from this working tree. Line numbers will move; use the symbol
names, not a line number.

| Item | Location |
|---|---|
| Relay constants and config | `rust/src/relay.rs` `MAX_FLOWS_PER_WORKER`, `MAX_DATAGRAM`, `DNS_TIMEOUT`, `CONNECT_TIMEOUT`, `RelayConfig` |
| Relay shards and flow routing | `rust/src/relay.rs` `Relay::start` (1 to 8 workers), `shard(key, workers)`, per-worker `sync_channel(QUEUE)` |
| UDP flow idle and DNS idle | `rust/src/relay.rs` `UDP_IDLE` (120 s), `UDP_EVICT_IDLE` (30 s), `DNS_TIMEOUT` (8 s), the phone DNS idle branch |
| Phone DNS target and transaction check | `rust/src/relay.rs` `new_udp`, UDP reply path |
| TCP SYN branch and `Setup::phone` | `rust/src/relay.rs` `Setup`, `handle` |
| Phone outer socket | `rust/src/relay.rs` `phone_tcp_start` |
| UDP reply path and name hint | `rust/src/relay.rs`, `rust/src/failures.rs` `remember_dns_response` |
| Normalized sockets | `rust/src/normalization.rs` `tcp_start`, `tcp_connect_cancellable`, `udp_socket` |
| SOCKS5 name resolution and server list | `rust/src/socks.rs` `read_target`, `udp_target`; `rust/src/dns.rs` `TinyResolver`, `MAX_EXPLICIT_SERVERS`, `validate_servers`, `parse_server_list` |
| Tun options and validation | `rust/src/service.rs` `TunOptions`, `validate` |
| macOS DNS discovery | `rust/src/environment.rs` `dns_for_interface_from_scutil`, `system_dns_for_interface` |
| Linux DNS discovery | `rust/src/environment.rs` `system_dns_for_interface` (fails closed), `system_dns` (diagnostics aggregate) |
| macOS routes and IPv6 | `rust/src/platform.rs`, `rust/src/ipv6.rs` |
| Windows routes and verifier | `rust/src/windows_native_routes.rs`, `rust/src/windows_route_verify.rs` |
| Linux rules and table | `rust/src/platform_linux.rs` `OUTER_RULE_PRIORITY`, `TUNNEL_RULE_PRIORITY`, `TUNNEL_TABLE` |
| Capability and counters | `rust/src/diagnostics.rs` `destination_privacy_capability`, `zero_destination_privacy_counters`, `destination_privacy`, `CAP_UNVERIFIED` |
| Status versus diagnostics | `rust/src/service.rs` `status` (`platform.destination_privacy` capability), `diagnostics` (`destination_privacy` counters), `merge_relay_diagnostics`; `rust/src/gui.rs` `/api/status` and `/api/diagnostics` |
| Relay stop and drop | `rust/src/relay.rs` `Relay::stop` (sets `running = false`, clears input, joins with no timeout), `impl Drop for Relay`; `rust/src/service.rs` `stop_locked` |
| Diagnostics merge | `rust/src/service.rs` `diagnostics`, `merge_relay_diagnostics`; `rust/src/relay.rs` `RelayStats` |
| Browser capability parser | `gui_assets/app.js` `privacyState`, `destinationPrivacy`, `destinationPrivacyRow`, `diagnosticsReport`, copy diagnostics |
| Linux capability path | `linux/src/main/channels.js` `hs:status` and `hs:diagnostics`, `linux/src/main/preload.js` `status()` and `diagnostics()`, `linux/src/renderer/model.js` `privacyView`, `linux/src/renderer/app.js` call site |
| Windows static report | `windows/src/HotspotShade.WinUI2.Core/WindowsPrivacyCapabilities.cs` |
| Poll and wake | `rust/src/relay_poll.rs`, `rust/src/relay.rs` worker loop |
| Failure record | `rust/src/failures.rs` `FailureEvent::dns`, `remember_dns_response` |
| Direct-mode DNS failure guard | `rust/src/relay.rs` `record_dns_failure` |
| Live gateway bypass record | `PHONE_PROXY.md`, the 2026-11-02 live test paragraph |
| Tunnel worker stop order and fault slot | `rust/src/service.rs` tunnel worker exit on macOS, Linux, and Windows (`relay.stop()` before `routes.remove()`), the shared Windows cleanup helper, `stop_locked` (fault slot and `cleanup_blocked`) |
| Relay stop and drop | `rust/src/relay.rs` `Relay::stop` and `impl Drop for Relay` |
| Source device proxy mode DNS redirect | `rust/src/relay.rs` `new_udp`, phone branch (`1.1.1.1:53`, SOCKS command 1); `dns_upstream` rejected in that mode |
| Probe copy of status platform | `rust/src/gui_backend.rs` probe handler (`"platform":status["platform"]`); `gui_assets/app.js` `platformInfo()` |
| Invariant 4 text | `AGENTS.md` at `HEAD` (committed) and in the working tree (uncommitted change) |

## Appendix D. Status

UNAPPROVED. Revision 9 is a design response to the independent revision 8
review (delegated review task `ecb2b96c-d750-4156-9703-bcf9f5fc6052`, revision
8 UNAPPROVED). It has not been independently re-reviewed. It grants no product
authorization and changes no `AGENTS.md` invariant. It does not implement a
protocol, change a production file, or prove a carrier result. The
scope-specific gate in the header is closed for application ECH implementation
under the current constraints and open for the proposed DoH scope. The next step
is a new independent review of this file, `WS1_REVIEW_TRACE.md`, and
`WS1_TEST_MATRIX.md`, plus the product owner's separate DoH scope acceptance and
the third-party resolver decision (owner questions Q1 to Q5), the U62
decision, and the invariant amendment. Until that review passes, `hide` is
unsupported and no UI or documentation may claim it. No DoH starts before its own scope acceptance and the invariant amendment. No
revision 8 or revision 9 answer is evidence that the code, the
consumer migration, the ownership protocol, the stop order, or the capacity
numbers exist. None of the revision 9 matrix rows exist or have run.

## Appendix E. Revision 4 review corrections

Revision 4 answered the independent re-review of revision 3. This table maps each
blocking and must-fix item to its correction. No production file changed and no
test ran. Revision 5 supersedes the rows that say the owner decision stays open,
that the DoH cap uses free source slots, that Linux gateway DNS is merely
conditional, that the plan may record that WS1 waits, and that the DoH cause
partition has six causes. Revision 6 supersedes the rows that call the gateway
bypass live evidence, that evict an idle connection, or that state a single
global writer with a quiescence-only identity. See Appendix F and Appendix G.
The historical rows below are retained for audit; where they conflict with
revision 6, revision 6 wins.

| Review item | Correction | Where |
|---|---|---|
| B1: the fallback rule contradicts itself, and WS6 was told to copy it | A non-ECH flow is a profile state chosen before connecting, never a retry. A timeout, reset, certificate error, 5xx, parse error, or SERVFAIL ends the flow. The plan handoff P1 and P2 is rewritten and quoted | Sections 5.3.2, 5.3.1, 11.3; T5.05, T7.04, T9.18 |
| B2: the gateway DNS route claim is wrong for macOS and Windows | **Superseded by Appendix G.** Revision 4 said macOS and Windows gateway DNS is a certain bypass and cited the live record; revision 6 treats it as route-specificity inference because the record names no OS and does not show the DNS case | Sections 4.2, 4.3, 11.1 U4 and U5; trace F3; Appendix G |
| M1: `ech = supported` can come from a build | `ech` stays `unsupported`. Add `resolver_ech` as a separate `unverified` key. The capability contract forbids free-text scope | Sections 2.2, 2.4, 7.3, 8; T7.09, T7.13, T10.15 |
| M2: the counter ledger does not add up | Exact ECH and DoH identities, retry precedence, a catch-all `doh_other_error`, `doh_response_mismatch`, and a queue attempt counted in `doh_queries` | Section 7.2.1 to 7.2.3; T7.15, T7.18 |
| M2: the DoH failure causes are incomplete | Six causes partition every failure, including TLS, reset, source capacity, and pool panic in `doh_other_error` | Section 7.2.2 |
| M3 and P1 to P11: the WS6 handoff is wrong and incomplete | **Superseded by Appendix G.** Revision 4 added the eleven-item handoff; revision 6 extends it to P1 to P15, records P7 as partly applied, and replaces the open owner-decision wording with the closed boundary plus the separate DoH scope | Section 11.3; trace section 4; T12.01 to T12.21; Appendix G |
| M4: the adapter flood test contradicts the threat model | The adapter never evicts a connection. A flood can cause a bounded local denial of service. T8.16 asserts no authenticated eviction and no plaintext, not guaranteed service | Section 6.6; T8.14, T8.16 |
| Lower: a failed config fetch is a downgrade path | A failed config fetch loses L2, not L1. It does not change the profile or produce plaintext | Section 5.2 |
| Lower: `ech_*` can be nonzero while `mode = off` | WS0 must state that condition for `doh_*` and `ech_*` | Sections 2.4, 7.2.3 |
| Lower: the TCP:53 failure record lacks an inner destination and drops `phase` | Add a fixed adapter preface and the `phase` argument to `FailureEvent::doh_query` | Sections 6.6, 7.1; T7.07, T7.16 |
| Lower: `doh_lookups` narrows silently | Record the narrowing to the endpoint ECH-config lookup. An inner QTYPE 65 query counts only in `doh_queries` | Sections 7.2, 7.2.3 |
| Lower: `doh_tcp53_lookups` name | Rename to `doh_tcp53_queries` | Sections 7.2, 7.2.3 |
| Lower: connection cap behavior is inconsistent | Evict the oldest idle first; if none, fail. The test asserts the same order | Section 6.5; T8.02 |
| Lower: the source device relay cap is not 256 | Use the iOS limit and the Android open-file-derived limit. The DoH cap is the smaller of 32 and the free slots | Section 6.5. Revision 5 removes the free-slot term; see Appendix F |
| Lower: the helper signature is not deadline-based | `tcp_connect_cancellable` takes a `Duration` timeout; the caller computes the remainder | Section 6.3 |
| Lower: the RFC numbers are unchecked | Add U29. Re-read RFC 9848 and RFC 9849 before approval | Section 11.1 U29 |
| Lower: the plan's WS1 gate conflicts with encrypted DNS | **Superseded by Appendix G.** Add P10 and split encrypted DNS from application ECH. Revision 6 closes the boundary and requires the product owner's separate DoH scope acceptance | Section 11.3 P10; U30; Appendix G |
| Lower: the adapter test surface and GREASE policy are absent from the plan handoff | Add P3, P7, P9, P11 and T12.04 to T12.10 | Section 11.3 |

## Appendix F. Revision 5 review corrections

Revision 5 answered the independent re-review of revision 4. No production file
changed and no test ran. Revision 6 supersedes the rows that say the identity is
exact only at quiescence, that the worker is the sole global writer, that the
`ech` key is removed or aliased immediately, that the default plaintext profile
always counts, and that the gateway bypass is live evidence. See Appendix G.

| Review item | Correction | Where |
|---|---|---|
| Scope gate contradicts P10 and makes the client decision block everything | The gate is scope-specific. Application ECH is closed as unsupported under the plan's default. Owned client is a separate optional future proposal. The DoH forwarder is a proposed independent scope with its own acceptance and review | Header, sections 1.3, 3.2, 4.1.1, 10, 11.3 P10; T12.09, T12.14 |
| The DNS forwarder is an unapproved scope expansion | Section 4.1.1 records the tradeoffs and separate review gate. The document no longer presents it as approved work. No implementation | Sections 4.1.1, 10, 11.2, 11.3 P10; trace F36 |
| "No plaintext by default" contradicts "DoH off by default" | Acceptance and G2 now say "with a DoH setting active"; the default plaintext profile is labeled, not silent | Section 12; matrix G2, T7.04 |
| Exact counter identity fails during a live snapshot; outcome ownership is ambiguous | Add `doh_in_flight` gauge. The worker is the single outcome owner; the pool never writes a counter. Identity is exact only at quiescence | Sections 6.4, 7.2, 7.2.2; T7.23, T6.14 |
| Stop, inner-flow expiry, and queued TCP:53 behind a failure lack terminal causes | Add `doh_cancelled`; name `flow_closed`, `source_capacity`, and `pool_unavailable` under `doh_other_error` | Sections 6.4, 7.2, 7.2.2, 7.2.3; T5.27, T6.14, T7.20 |
| The design assumes source device free-slot reporting | Remove the free-slot term. Keep the 32 cap and treat capacity as `doh_other_error`. A protocol change is U34 | Section 6.5, U34; T5.22 |
| Capability states conflict with the code and can never reach `supported`; `ech` duplicates application ECH | Define the four states in the contract, require WS0 comment changes, add a reviewed build qualification constant that makes `supported` reachable after live qualification, keep the value static per build/platform, and remove or alias `ech` to `app_ech` | Sections 2.2, 2.4, 7.3, 8; T7.09, T7.19, T10.13 to T10.16 |
| Linux gateway and default resolver likely bypass, not "conditional" | **Superseded in part by Appendix G.** Linux is a likely bypass on a default link-bound resolver. The record names no OS for the DNS case, so no target has a live DNS-specific result | Sections 4.2, 4.3, 11.1 U4 and U5; T5.25; Appendix G |
| Gateway host-route rejection reason is unverified | Record it as an open option (U33) with pairing, probe, captive-portal, and platform-route risks. Do not claim the pinned socket path would change | Section 4.2, U33 |
| `doh_plaintext_fallbacks` contradicts its own definition | Rename to `dns_plaintext_profile_queries`; define the default no-DoH profile from its first query | Sections 2.3, 7.2, 7.2.3; T5.05, T7.04 |
| Table 5.5 says tethering detection is unchanged without measurement | Mark it not measured and name the new DoH fingerprint and resolver IP | Section 5.5 |
| A rejected resolver config stays cached | The authenticated-rejection path replaces the config with retry configs, or evicts it when the retry has no supported config | Section 5.3; T4.22 |
| Matrix row order | T7.19 and T7.20 now follow T7.18, before T7.21 | `WS1_TEST_MATRIX.md` |

## Appendix G. Revision 6 review corrections

Revision 6 answers the independent re-review of revision 5 (revision 5 NOT
APPROVED, six critical findings and the must-fix and lower-priority items). No
production file changed, no test was written or run, and no network, device,
route, or TUN device was used.

Revision 7 supersedes the revision 6 rows that assume one relay worker, a
single global accounting writer, a fixed 32-session cap, delivery before the
terminal decision, or runtime coverage inside the capability. Revision 8
supersedes the plan status in this appendix: the plan's revision note says task
`85710a0e` applied P7 and P9 to P15. The Appendix H rows carry the revision 7
answer and Appendix I the revision 8 answer. Keep the Appendix G rows for audit;
where they conflict with revision 8, revision 8 wins.

| Review item | Correction | Where |
|---|---|---|
| Critical 1: section 12 says no non-ECH retry, but section 5.3, T4.09, G5, and P11 allow an ECH-disabled resolver retry | One retry table. Application flows never retry. The resolver connection retries once only after an authenticated rejection: with retry configs, or with ECH disabled when no supported retry config exists. Section 12 and the acceptance criteria now say exactly that | Sections 5.3, 5.3.1, 5.3.2, 7.2.1, 10 item 13, 11.3 P11, 12; matrix T4.09, T4.24, G5 |
| Critical 2: the TCP:53 adapter, not the worker, split frames and submitted jobs, so "one worker owns every counter" was false | The adapter sends an admission request to the worker. The worker assigns the job ID, owns the outcome, writes the counter, and writes the failure record. The adapter writes no DoH counter and submits no pool job | Sections 4.8, 6.4, 6.6, 7.1, 7.2; U35 |
| Critical 3: a dropped, cancelled, or timed-out completion had no ECH outcome under the single-writer rule | Every accepted job has a job ID and one terminal owner. A late completion is discarded by ID. An ECH attempt with no completion records `ech_error`, not a second outcome. Config fetch uses the same rule. Gauges make the identity exact | Sections 6.4, 7.2.1, 7.2.2; U36 |
| Critical 4: separate atomics and queued work made instantaneous identities false | One coherent ledger snapshot covers every counter and gauge. Identities are exact in a snapshot and after stop and join. A multiworker stress test reads snapshots concurrently | Sections 6.4, 7.2, 7.2.2; U37; matrix T7.27, T8.18 |
| Critical 5: the capability migration breaks the existing GUI, Linux page, and Windows report | Section 2.5 maps every consumer. `ech` keeps its meaning. New keys are additive. Static capability and runtime coverage are separate. `off` stays a runtime mode. No default payload changes | Section 2.5, 2.6, 7.3; U38; matrix T13 |
| Critical 6: the plan handoff was stale after orchestrator edits | P7 is partly applied. P10 lists every boundary-open passage and distinguishes the product owner's scope decision from the review. P11 states the resolver retry. P12 to P15 add the stale code and counter, DNS transport, Linux bypass, and reader-facing corrections | Section 11.3, 11.3.1; U30, U32; matrix T12.06, T12.09, T12.10, T12.16 to T12.20 |
| Idle eviction contradicted one-flow-one-socket | The cap is hard. No cross-flow eviction. A slot frees only when its own flow closes or idles out. Only the bounded ECH retry replaces a connection | Section 6.5; U39; matrix T8.02 |
| The DoH cap (32) and adapter cap (64) disagreed | Both are 32. An adapter slot is not a reservation | Sections 6.4, 6.6; U40; matrix T8.05 |
| Deadlines did not start at queue admission | The absolute deadline starts when the job is admitted, not when a pool thread starts | Sections 4.6, 6.4; U41 |
| Worker panic detection and failure policy were incomplete | Pool, adapter, and relay-worker panics have separate policies. A worker panic does not publish a partial ledger as exact | Section 6.7; U42; matrix T6.15 |
| Cancellation did not cover the whole source setup | The blocking source driver checks stop and deadline in every state and discards a late reply | Section 6.3; matrix T6.02, T8.11, T5.28 |
| A bounded completion queue could silently drop a completion | Capacity is reserved at admission. A completion is never dropped. A full response queue fails the job explicitly | Section 6.4; U41; matrix T8.04, T8.17 |
| Cargo features were described as mutually exclusive | Features are additive. `ech` implies `doh`. Both may be enabled. One provider is selected. All combinations are tested | Section 8; U43; matrix T10.17 |
| The gateway bypass was called live DNS evidence | The record reports a gateway route bypass, names no OS, and does not show the DNS case. Gateway DNS is a route-specificity inference | Sections 4.2, 4.3, U4, U5; matrix T5.25 |
| RFCs were cited from memory | All citations are unverified until a reviewer reads the text. The reading guide and U29 say so | Section 0, U29; matrix T12.21 |
| A direct-mode DoH failure record is a new privacy scope | Counters only by default. A record needs its own acceptance | Section 7.1; U46; matrix T7.07, T7.16 conditional |
| The default plaintext counter and warning change default behavior | Separate telemetry and UI acceptance. The default `off` behavior and UI do not change | Sections 2.3, 2.6, 7.3; U47; matrix T14 |
| T10.07 named the wrong key | It now names `resolver_ech` and the legacy `ech` separately | Matrix T10.07 |
| A revision 4 label remained | The test strategy and status now say revision 6 | Sections 9, Appendix D; matrix header |
| The trace ledger was stale | The trace adds F48 to F65 and updates the handoff status | `WS1_REVIEW_TRACE.md` |
| The IPv6 path row lacked a qualifier | It now says the DoH attempt happens only when the endpoint is reachable for that family and IPv6 is forwarded, and block mode drops the packet before any attempt | Section 4.3 |
| The ECH certificate fixture was wrong | The client authenticates the origin name, not `public_name`. The mock certificate is for the origin. The public name is only the outer SNI | Sections 5.3, 7.2.1; matrix T4 header, T4.23 |

## Appendix H. Revision 7 review corrections

Revision 7 answers the independent revision 6 review (task
`9afab1a0-b634-470c-9598-ff5e55e0a623`, revision 6 NOT APPROVED). The review
named six blockers and must-fix items M1 to M5. Revision 8 supersedes this
appendix's plan status and ownership terms; Appendix I carries the current
answer. No production file changed, no test was written or run, and no network,
device, route, or TUN device was used. This appendix is a design record, not
evidence.

| Review item | Correction | Where |
|---|---|---|
| Blocker 1, M1: the relay is sharded 1 to 8 workers, so "the relay worker" owned nothing global | One supervisor, one compact shard owner, one global ledger, reservation-based global limits, and no job migration. The phase lives in the ledger lock | Sections 6.4.1 to 6.4.4, 7.2; U48; matrix T5.30, T5.31, T7.27 |
| Blocker 2, M2: TCP:53 response bytes bypassed the terminal decision | Two-phase commit. The owner records one outcome, then releases a delivery with job ID and generation. The adapter has no direct pool path. A post-commit write failure is an adapter transport event | Sections 4.8, 6.4.5, 6.6, 7.2; U49; matrix T5.32, T5.33, T7.29 |
| Blocker 3, M3: connection, cache, and ECH state had no owner or slot lifecycle | One session owner, one reserved slot, one generation, named release paths, single-flight config cache with commit-only publication, and an attempt event pair | Sections 6.2, 6.4.2, 6.4.6, 6.4.7; U50; matrix T5.34, T5.35, T7.30 |
| Blocker 4, M4: 32 slots exhausted by per-query-port churn | Session lifetime is separate from the relay flow lifetime. Quiet UDP close at 250 ms, 2 s hard idle, bounded FIFO slot wait, measured cap, declared envelope, explicit failure above it. Coalescing across source ports is an unapproved option | Sections 6.5, 6.5.1; U51, U56; matrix T8.19 to T8.23 |
| Blocker 5, M5: stop admitted work while terminating, and the barrier was single-worker | Phase in the ledger lock, six barrier phases, bounded deadline, failed-stop result, and no exact ledger from an incomplete barrier | Sections 6.4.8, 6.7; U52; matrix T6.16 to T6.19 |
| Blocker 6: runtime coverage lived in the static capability; the `app_ech` parser and the Linux renderer data path were incompatible | Version 2 payload, separate runtime object, per-key parser, `app_ech` three-value kind, Linux payload path with a static fallback, and a static Windows report that prints only what it received | Sections 2.2, 2.4, 2.5, 2.5.1, 2.5.2, 7.3; U53; matrix T13.06 to T13.09 |
| The stop rule was ambiguous: "records terminal outcomes, then stops admission" | The two steps are reversed in the model: intake closes first, then the drain records terminal outcomes. Nothing can be admitted between them | Section 6.4.8; matrix T6.16 |
| The connection cap, the adapter cap, and the DoH cap were the same number by accident | The adapter cap is an independent local bound. The session cap governs DoH sessions. Neither is a reservation for the other | Sections 6.4.9, 6.5, 6.6; matrix T8.05, T8.21 |
| Delivery capacity was reserved but the outcome was not ordered against it | Outcome commit and delivery release are one ordered step, and the delivery slot is per job | Section 6.4.5; matrix T5.32, T7.29 |
| The ECH attempt gauge was incremented at admission, before the pool knew whether ECH was offered | The pool sends `AttemptStarted` and `AttemptOutcome`; the owner records the gauge and the outcome. An open attempt at terminal records `ech_error` | Sections 6.4.4, 6.4.7, 7.2.1; matrix T7.25, T7.30 |
| The capacity numbers were stated as constants | The cap, pool size, quiet window, and barrier deadline are hypotheses with named measurements | Section 6.8; U55; matrix T11 |
| The Linux renderer was assumed to read the browser payload | The actual path is `hs:diagnostics` -> preload `diagnostics()` -> `privacyView`. The design names it and keeps a static fallback | Section 2.5.2; matrix T13.07 |
| `app_ech` was parsed as a four-state capability | It has three values and an information row kind. A parser that rejects it as a capability state is wrong | Sections 2.4, 2.5.1; matrix T7.14, T13.06 |
| A structural change could regress a protocol invariant | The design states no protocol change and adds a regression test. The adapter preface is local loopback framing | Section 10 item 34; matrix T15 |
| The DNS discovery claims were stale after the project guidance changed | macOS uses an unambiguous scoped `scutil` block; Linux fails closed and requires an explicit bounded `--dns-servers` list | Sections 4.2, 6.1; matrix T5.38, T12.22 |
| The revision labels were stale | The architecture, matrix, and trace say revision 7 | Header, Appendix D; matrix header; trace header |

## Appendix I. Revision 8 review corrections

Revision 9 supersedes the B1, B4, B5, and B7 rows below where they say that
retry authorization increments `session_generation`, that a revoked or
cancelled grant is settled outside one transition, that the barrier alone is
the stop order, or that no build ships a built-in public resolver. Appendix J
carries the current answer. This appendix also cites decisions 33 to 39 by
numbers that do not match the revision 8 list; read it by subject.

Revision 8 answers the independent revision 7 review (review thread
`00889a37-16c1-40c6-8fcb-45c725f3a6a0`, revision 7 NOT APPROVED). The review
thread is no longer readable in this checkout; the blocker subjects below are
taken from the task brief that names it. No production file changed, no test was
written or run, and no network, device, route, or TUN device was used. This
appendix is a design record, not evidence.

| Review item | Correction | Where |
|---|---|---|
| B1: retry generation and cache commit ownership | Three distinct counters: `session_generation`, `config_generation`, `runtime.snapshot_seq`. A retry is a second attempt of the same job, authorized by the owning shard, which increments `session_generation` and dispatches the second reserved attempt. `commit_config`, `commit_retry_config`, and `mark_rejected` are compare-and-set commits under the ledger lock; the pool never writes the cache. A stale rejection cannot evict a newer config | Sections 5.3, 6.2, 6.4.7; decision 33; U57 to U59; matrix T5.39, T5.40, T7.35 |
| B2: slot and socket ownership until the pool returns | A move-only connection lease and a mandatory handback. The pool holds the lease during an attempt; the shard holds it after the move. A slot is freed only after the handback for that attempt. A terminal decision alone does not free it. `JoinPool` drains never-started attempts with `Handback::NotStarted` | Sections 6.4.2, 6.4.5, 6.4.6, 6.4.10; decisions 30, 34; matrix T5.41, T5.42, T6.22 |
| B3: adapter failure delivery and reserved capacity | Four frame credits per authenticated connection, 128 total, so the ingress cannot fill. One reserved disposition per accepted query: `Answer` or `Close`. A failed query gets an explicit close; it never waits for the idle timer. The disposition path cannot fill | Sections 4.8, 6.4.9, 6.6, 7.2; decisions 17, 35; U59; matrix T5.43, T5.44, T8.24 |
| B4: cross-shard waiter FIFO, admission, cancel, deadline | One global `DohWaitQueue` in the ledger, ordered by sequence. A release grants the oldest waiter directly and keeps the slot counted during handoff. A grant is accepted or returned under the lock; an idle shard cannot strand an expired waiter because one global reaper removes them. Every waiter records exactly one outcome | Sections 6.4.3, 6.4.3.1, 7.2.2; decision 36; matrix T5.45, T5.46, T7.34, T8.25 |
| B5: actual `Relay::stop` and `Drop` ordering and stop budget | Verified that `Relay::stop` clears the queue, sets `running = false`, and joins workers without a timeout, and that `Drop` calls it. The DoH barrier starts before those steps and before the shard join, because a joined shard cannot ack or hand back. A Drop-only stop is `drop_only` and inexact. A stuck pool thread is detached and reported. The total stop budget is unknown | Sections 6.4.8, 6.7, 6.8 H6 and H13; decisions 30, 37; U58; matrix T6.22, T6.23, T6.24 |
| B6: real status versus diagnostics paths and missing-key consistency | Verified that capability is in `/api/status` and `hs:status`, counters are in `/api/diagnostics` and `hs:diagnostics`, the browser privacy row reads status, and Linux exposes both. Capability and `runtime` go in status; counters and `ledger { exact, phase, snapshot_seq }` go in diagnostics. Cross-endpoint coherence is not claimed. Missing keys are hidden, never `unverified`; missing counters are not zero; missing `ledger.exact` is not true | Sections 2.2, 2.4, 2.5, 2.5.1, 2.5.2, 7.2.3, 7.3; decision 38; matrix T7.36, T13.10, T13.11 |
| B7: third-party DNS | The configured endpoint is a third-party resolver. A product-owner decision and an explicit amendment to `AGENTS.md` invariant 4 are required before any DoH code; if the plan is read to require the network resolver, its scope text or invariant 4 needs the same amendment. This design does not assert that the scope is approved or that the current invariant is compatible. No built-in or default public resolver | Sections 4.1.1, 4.1.2, 11.1 U57, 11.2 Scope acceptance and Owner; decision 39; matrix T12.24, T16.10 |
| The plan revision status was stale in the architecture, matrix, and trace | The plan's revision note says task `85710a0e` applied P7 and P9 to P15. The design records that as a text observation to verify, not as approval, and does not edit the plan | Sections 11.2, 11.3, 11.3.1, 12 item 17; matrix section 13 and T12.19; trace section 4 |
| The trace said the 2026-11-02 record names macOS only | The record names no operating system and does not show the DNS case. It is a route-shape observation, not live DNS evidence | Section 4.2; trace F3 and F28 |
| The adapter preface length was inconsistent (19 bytes versus IPv6 addresses) | Fixed 32-byte local preface with a version, family, 16-byte address, port, shard, connection ID, and reserved zero bytes | Sections 4.8, 6.6, 7.1; Appendix E row |
| The missing-key rule said both "hidden" and "unverified" | One rule: hidden, never `unverified`, with `modes.off` as the only runtime-mode exception | Sections 2.4, 2.5, 2.5.1; matrix T7.19, T13.06 |

## Appendix J. Revision 9 review corrections

Revision 9 answers the independent revision 8 review (delegated review task
`ecb2b96c-d750-4156-9703-bcf9f5fc6052`, revision 8 UNAPPROVED). That review was
read in full. No production file changed, no `AGENTS.md` invariant changed, no
product authorization was granted, no test was written or run, and no network,
device, route, or TUN device was used. This appendix is a design record, not
evidence. Decision numbers refer to section 10 as revised.

| Review item | Correction | Where |
|---|---|---|
| Blocker 1: `session_generation` rose at install and at retry authorization, so every successful retry and every queued job after the first commit failed with `generation_mismatch`, and the adapter could drop a committed answer | `session_generation` is a session incarnation number, allocated once at session reservation and never changed. A retry is `attempt_id` 2 of the same job. `generation_mismatch` is removed. The adapter applies dispositions in `request_id` order and never drops an answer for being "not current"; an unwritten committed answer counts once in `doh_adapter_errors` | Header R9-B1; sections 4.8, 6.2, 6.4.5, 6.4.6, 6.4.7, 6.4.10, 6.6, 7.2.2, 7.2.3; decisions 29, 30, 35; matrix T5.33, T5.39, T5.47, T5.48, T7.35 |
| Blocker 1: T5.39 expected one increment at retry authorization while the rule gave two | No increment at all. T5.39 asserts `session_generation` is unchanged across the retry and the retry commits normally | Section 6.4.7; matrix T5.39 |
| Blocker 2: revocation and `cancel_waiter` each settled a waiter, and `admit_granted` could settle it again | One settlement transition, `settle_waiter`, removes the record and returns a granted slot in the same critical section. A second call and a late `admit_granted` are `Stale` and record nothing | Section 6.4.3.1; decision 38; matrix T5.46, T5.51, T16.04 |
| Blocker 2: T5.46 expected a granted-then-cancelled waiter to record `doh_cancelled` on a job | Before conversion no job exists. The cancel is a waiter settlement with one `doh_cancelled`. After conversion it is a job cancellation | Section 6.4.3.1; matrix T5.46, T7.34 |
| Blocker 2: `Draining` ignored outstanding grants | `Stopping` settles every queued waiter and outstanding grant in the same critical section that sets the phase. `Sealed` verifies the grant table is empty | Sections 6.4.3.1, 6.4.8; matrix T6.27 |
| Blocker 2: the release step ignored `wait_deadline` | The release step settles expired waiters and grants only a waiter with both its wait window and absolute deadline remaining. `grant_deadline = min(now + T_grant, absolute deadline)` | Section 6.4.3.1, 6.4.9; matrix T5.52 |
| Blocker 3: `relay.stop()` runs before `routes.remove()`, so the DoH barrier lengthened the dead-route window | Nonblocking `begin_stop`, then routes and address removal, then the drain, in a run with the DoH profile active. The existing order is unchanged otherwise (U61). The order depends on pinned DoH sockets (H15). `--no-pin` refuses the DoH profile | Sections 6.4.8, 6.7, 6.8 H15; decision 32; U61; matrix T6.22, T6.25 |
| Blocker 3: `Relay::stop` returns `()`, and the fault slot could only say "route cleanup failed" | `Relay::stop` returns `RelayStopReport`. The fault slot gains `doh_stop_incomplete`. An incomplete DoH stop has its own message and never sets `cleanup_blocked`. A later DoH-profile start is refused while `DOH_DETACHED_THREADS` is above 0 | Sections 6.4.8, 6.7; decision 41; matrix T6.18, T6.26 |
| Blocker 3: T6.18 said "the process still closes the sockets" | The barrier closes only sockets it can prove. A stuck thread's socket stays open until its call returns or the process exits, and the test says so | Section 6.4.8; matrix T6.18 |
| Blocker 4: the B7 analysis misread invariant 4 and the code | The resolver sentence exists only in the uncommitted `AGENTS.md` change. Source device proxy mode already redirects DNS to `1.1.1.1:53`. The docs suggest `1.1.1.1` and `8.8.8.8` as explicit servers. Section 4.1.2 states these facts, limits the no-built-in-endpoint rule to the DoH profile, and lists owner questions Q1 to Q5. The decision and amendment are still required and still absent. No invariant is changed | Header R9-B4 and gate item 3; sections 4.1.1, 4.1.2; decision 36; U57, U64; section 11.2; matrix T12.24, T16.10 |
| Blocker 4: T16.10 said no built-in endpoint exists | T16.10 checks the DoH profile only and records the existing redirect and explicit-server options as existing behavior outside its guard | Matrix T16.10 |
| Major 5: `snapshot_seq` had three definitions and `ledger.snapshot_seq` had no owner | One per-run `ledger_seq`, written under the ledger lock on every mutation. Both reported fields are values of it. No increment on a status read | Sections 2.2, 2.5.2, 6.4.2, 6.4.7, 7.2.3; decision 35; matrix T7.35, T13.11 |
| Major 6: the browser probe fallback could show a stale runtime state | `runtime` is read only from the latest successful status response. The probe copy carries no `runtime` object. A failed poll hides the coverage row | Sections 2.5.1, 2.5.2; decision 39; matrix T7.36, T7.37, T16.09 |
| Major 7: a `Close` ended every query on a TCP:53 connection and mislabeled an earlier one as `doh_cancelled` | The adapter applies dispositions in `request_id` order. A close is graceful: stop reading, apply earlier and already-admitted later dispositions, then FIN. Each query keeps its own cause. Local SERVFAIL stays out of scope as an owner option (U63) | Sections 4.8, 6.4.5, 6.4.9, 6.6; decision 29; U63; matrix T5.47, T16.13 |
| Major 8: the retry row said `Ready` while section 6.4.10 said `BetweenAttempts` | The table has three retry rows: `BetweenAttempts`, `Attempting` with `attempt_id` 2, then `Ready` on commit | Section 6.4.6 |
| Major 8: a cancelled config fetch sent no wake and elected no new fetcher | Every exit from `Fetching` wakes every shard. A cancelled fetch lets at most one waiting session claim a new fetch. A failed fetch sets `retry_after` (proposed 5 s) and waiters proceed without ECH | Sections 6.4.7, 6.4.9; decision 40; matrix T5.49, T5.50, T16.14 |
| Product decisions the review listed | Recorded as open, not decided: DoH scope acceptance; resolver substitution with Q1 to Q5 and the amendment (U64); tunnel up or down after a DoH-only stop, which touches invariant 13 (U62) | Sections 4.1.2, 6.7, 11.1, 11.2 |
| Host and device gates the review listed | Unchanged and open: H1 to H15, per-platform live hotspot coverage, real stuck-syscall stop timing, a Windows host, and a real Linux desktop for T13.10 | Sections 6.8, 12; matrix sections 12 and 17 |
