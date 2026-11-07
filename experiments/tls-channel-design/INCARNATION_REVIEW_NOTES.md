# Pairing incarnation candidate: open review obligations

Status: **UNAPPROVED.** These notes record an independent review of a candidate,
not a protocol specification or authorization to implement it. The design and
test matrix remain authoritative about their own status and release gates.

The candidate used a source-issued incarnation to scope pairing commits,
forget requests, acknowledgments, credentials, and sessions. The review found
that exact incarnation matching is useful, but is not enough without a complete
state machine, durable transitions, and authenticated messages carrying the
relevant fields.

Before a future proposal can be reviewed for implementation, it needs to define:

- A store schema that can represent an active pairing and a pending re-pair for
  the same peer, with one pending ceremony or an explicit supersession rule.
- Removal that invalidates eligible pending ceremonies, and session registration
  and removal scoped to the correct peer and incarnation.
- Target cancellation after a sent pairing commit that retains enough state to
  request conditional remote removal if the source may have committed.
- Canonical wire fields, transcript binding, state-based idempotence, and an
  authenticated reconciliation operation for lost responses and restarts.
- Credential clearing and active-flow behavior on local forget, including the
  fact that current v1 proxy access is token-based and lacks source identity.
- Per-platform transaction and recovery behavior for uncertain writes, storage
  capacity, partial restore, full rollback, identity reset, and downgrade.

The review recommends considering randomly generated, non-reused incarnation
identifiers with exact-match checks instead of relying on a global monotonic
counter. Randomness does not prevent restoration of an old store. A second
anchor may detect some partial restores, but it is not a general guarantee
against rolling back both copies. Platform feasibility and the required threat
model remain open.

Migration and coexistence with v1 require a product decision. Legacy v1 status
does not authenticate the source and must not be used as evidence of v2 trust or
presence. No automatic fallback or hard-cutover policy is approved by these
notes. The future specification must address delayed commits and forgets,
concurrent ceremonies, cancellation, crashes at every durable boundary, lost
replies, rollback, and source-authenticated proxy sessions in its test matrix.
