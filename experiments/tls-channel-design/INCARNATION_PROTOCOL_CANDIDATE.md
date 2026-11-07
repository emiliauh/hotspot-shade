# Pairing incarnation protocol candidate, revision 3

Status: **UNAPPROVED. Design for independent review only.** This document does
not authorize implementation, migration, device testing, release, or any change
to the existing v1 protocol. It is a candidate, not a security proof and not a
statement of existing behavior.

Revision 3 answers the topics in independent review revision 2. The exact review
text was not available to this thread. The labels R2-1 to R2-14 below come from
the review topics supplied with the task. They are this document's grouping, not
a verbatim finding-by-finding disposition. The reviewer must confirm the mapping.
Section 18 lists contradictions this revision found in its own revision 2 text
that are not in the R2-1 to R2-14 brief.

| Label | Review topic | Where this revision answers it |
|---|---|---|
| R2-1 | Zero-I response frames cannot be encoded | 3.2, 3.4, 8.5, 10 |
| R2-2 | Pre-offer CANCEL lacks the nonce and arm fields that lookup requires | 3.1, 8.5, 10 |
| R2-3 | Tombstone capacity behavior is contradictory | 8.5, 9.4, 9.5 |
| R2-4 | OFFER duplicate flags are undefined | 3.3, 7.1.1, 7.2 |
| R2-5 | The BEGIN and PAIR_DONE tables are not total | 7.1.1, 7.1.2 |
| R2-6 | Tombstones have no wire state | 3.1, 3.4, 9.4, 10 |
| R2-7 | A state-derived COMMITTED must match the full ceremony | 9.3.1, 13 |
| R2-8 | SESSION_OPEN retries are undefined | 5.7, 8.6, 13 |
| R2-9 | The target arm resend rule conflicts with arm clearing | 5.4, 8.2, 8.4 |
| R2-10 | The receipt schema lacks terminal request and denial matching | 6, 9.2, 9.3 |
| R2-11 | CANCEL and FORGET, and remote removal intent, are unclear | 8.7, 9.4 |
| R2-12 | The consent crash state is unclear | 5.5, 11.3 |
| R2-13 | PAIR_RESULT lacks the current source epoch | 3.1, 7.2, 9.3 |
| R2-14 | The pending zero-hash vector conflicts with the query rule | 10, companion vectors 3.16 and 3.21 |

No production code, protocol code, device, emulator, route, TUN device, or
network connection was used for this revision. No Python was used. The byte
vectors in `INCARNATION_CANDIDATE_VECTORS.md` were recomputed with SHA-256 and
HMAC arithmetic through `openssl` in a POSIX shell. They are test inputs, not an
implementation. The test requirements in
`INCARNATION_CANDIDATE_TEST_PLAN.md` were not run.

## 0. What changed from revision 2

The wire profile changed in three places. CANCEL and FORGET gain `begin_nonce`
and `target_arm_id`, so a pre-offer cancel can name the ceremony it cancels and
so the source can look it up. PAIR_RESULT gains `current_source_epoch`, so a
target can reject a result that names a superseded record. The wire state enum
gains `5 TOMBSTONE`, so a tombstone is visible on the wire. Offsets and lengths
were recomputed for those types.

The tag input was also corrected. Revision 2 stated that the tagged `frame`
starts at `version` and excludes the length prefix, but its vectors were
computed with the length prefix included twice. Revision 3 keeps the stated
definition and recomputes every tag. See section 18, item U1.

## 1. Scope and assumptions

The source device S and target device T each hold a durable identity key. A pin
is `SHA-256(DER SubjectPublicKeyInfo)` for that key. The pin is 32 raw bytes. No
name, serial, validity date, CA, revocation list, or SNI is part of the pin.

S and T establish a TLS 1.3 connection with mutual certificate authentication.
The connection proves possession of both identity keys and provides a TLS
exporter to both endpoints. A first pairing also requires a separate
out-of-band bootstrap in which a person confirms the same complete transcript on
both devices. TLS alone is not consent. The bootstrap display, the person's
comparison, the human channel's authenticity, TLS exporter equality across
stacks, secure key storage, and correct random generation are assumptions and
feasibility gates. They are not established here.

All operations address one ordered pair `(source_pin, target_pin)` in a new v2
namespace. This candidate's frame version is 2. It is not the `wire_version = 4`
of `DESIGN.md` and does not amend that document. One source may have many target
pins. One target may have many source pins. Each host serializes the checks and
mutations in this document under its own store lock. There is no distributed lock
and no atomic two-host transaction. No network write, TLS flush, socket flush, or
wait for a peer holds a store lock or a session-table lock.

The candidate has these fixed identifiers:

- `I[32]`: source-issued record incarnation. Fresh uniform random bytes for each
  reservation. Zero is a wire placeholder only where section 3.2 permits it; it
  is never a stored record identifier.
- `P[32]`: target-chosen pairing operation identifier. Fresh uniform random
  bytes for each ceremony. Zero is invalid.
- `operation_id[32]`: fresh uniform random identifier for one removal or
  cancellation attempt. Zero is invalid.
- `begin_nonce[16]`, `offer_nonce[16]`, `source_arm_id[16]`,
  `target_arm_id[16]`: fresh uniform random nonzero values for one ceremony.
- `query_id[32]`: fresh uniform random query identifier. It is not an operation
  receipt and never changes state.
- `session_nonce[32]`: fresh uniform random session request identifier.
- `source_instance_nonce[32]` and `target_instance_nonce[32]`: fresh uniform
  random values for one process or listener instance. They are independent. They
  are not durable.
- `namespace_id[16]`: fresh uniform random identifier for one identity
  namespace. An identity reset creates a new namespace.

A random-source failure aborts before any value is used or any frame is sent. A
collision with a retained identifier aborts and retries with new randomness.
Uniqueness against forgotten history is probabilistic, not proven. The two epochs
are ordering counters, not identities. A restore that includes the store and
anchor can restore them; section 11.4 states that limit. These identifiers are
not ordered clocks and not anti-rollback counters.

### 1.1 Threat boundary

This candidate addresses a network attacker on the hotspot, a stale or replayed
frame from another connection, a delayed or duplicated operation, a peer that
presents a different identity key, a concurrent ceremony, a peer that sends a
result for the wrong record, and a store that is partially rolled back or left
uncertain by a crash. It uses exact tuple matches, TLS pin authentication, an
exporter-bound tag, durable receipts, and a local block on uncertainty.

It does not protect against a compromised source or target operating system, a
same-user process that can read the store or process memory, a malicious peer
that has compromised a device key, a full store-and-anchor rollback, a
whole-device snapshot restore, traffic analysis, or physical coercion. It does
not make the tunnel fail-closed and does not claim to do so. It is a pairing-state
protocol, not a general secure channel design.

### 1.2 Epochs, sequence, and state names

The candidate uses two monotonic namespace counters as record epochs:

- `source_epoch u64`: durable on S, starts at 1. The source assigns the next
  value to each new source record at reservation, across the namespace. The
  value is immutable for that record. It never wraps. A value of
  `0xFFFFFFFFFFFFFFFF` blocks a new reservation and requires identity reset.
- `target_epoch u64`: durable on T, starts at 1. The target assigns the next
  value to each new target record at BEGIN persist, across the namespace. The
  value is immutable for that record. It never wraps. The same limit applies.

A record keeps its immutable `source_epoch` and `target_epoch`. A terminal
transition does not change either value. A new ceremony gets a new record and
new values.

`current_source_epoch` in a result is the `source_epoch` of the newest retained
source record for the pair, including a terminal record. It is not a separate
counter that changes on every transition. It is zero when no source record for
the pair is retained.

`state_seq` orders the transitions within one record. It is 0 at record
creation and increments by 1 on every durable mutation of that record. At
`0xFFFFFFFF` the record blocks further mutation and requires a new record or
identity reset. A tombstone has no `state_seq` and reports 0.

A source record state is one of PENDING, ACTIVE, TERMINAL. A tombstone is a
separate object and reports the wire state TOMBSTONE. UNKNOWN means no retained
record and no tombstone. Target record states are local and never appear on the
wire.

## 2. Notation and rejection rules

All integers are unsigned big-endian. `u8` is one byte. `u16` is two bytes.
`u32` is four bytes. `u64` is eight bytes. `[n]` is exactly `n` raw bytes.
Bit 0 is the least significant bit of a flags byte.

A frame is rejected before any state change if any of these is true:

- `frame_len` is not the exact value for its type in section 3.
- The total wire size is not `4 + frame_len + 32`, or exceeds 4096 bytes.
- The version is not 2.
- The type is not defined in section 3.
- Any reserved byte or reserved bit is nonzero.
- Any enum value is not defined in section 3.
- Any trailing byte exists after the tag, or the frame is truncated.
- A zero value appears in a field that section 3.2 or 3.4 requires to be
  nonzero.
- A nonzero value appears in a field that section 3.4 requires to be zero.
- A pin in the frame differs from the pin proved by TLS for that role.
- The tag does not verify in constant time before field parsing or state access.
- The `flags` value is not permitted for the type by section 3.3.
- A field has a value that the current state does not permit.

There are no optional fields, repeated fields, implicit defaults, text fields,
host names, ports, or JSON encodings in this frame profile. A parser never
allocates from a declared length before the bound check.

A receiver that rejects a frame sends no response frame for it. It closes the
connection after a fixed local delay. A rejection is not a result and writes no
receipt. This rule keeps a malformed frame from being answered as if it were a
valid request.

## 3. Frame profile

The frame layout is:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `frame_len` (bytes after this field, excluding the tag) |
| 4 | 1 | `version = 2` |
| 5 | 1 | `type` |
| 6 | 2 | `reserved = 0` |
| 8 | 32 | `source_pin` |
| 40 | 32 | `target_pin` |
| 72 | 32 | `I` |
| 104 | 32 | `P` |
| 136 | variable | type-specific suffix |
| `4 + frame_len` | 32 | `tag` |

`frame_len = 132 + suffix_len`. The total wire size is `4 + frame_len + 32`.
The tag is outside the length prefix. The tag input includes `frame_len`, so a
changed length invalidates the tag even if the field layout would otherwise
parse.

The type table is exact. Fields appear in the order shown with no padding.

| Type | Value | Sender | Suffix after `P` | Suffix bytes | `frame_len` | Total |
|---|---|---|---|---|---|---|
| BEGIN | 11 | T to S | `begin_nonce[16]`, `target_arm_id[16]`, `target_epoch u64`, `mode u8`, `flags u8`, `reserved u16` | 44 | 176 | 212 |
| OFFER | 1 | S to T | `begin_nonce[16]`, `target_arm_id[16]`, `offer_nonce[16]`, `source_arm_id[16]`, `source_epoch u64`, `target_epoch u64`, `mode u8`, `flags u8`, `reserved u16` | 84 | 216 | 252 |
| PAIR_DONE | 2 | T to S | `begin_nonce[16]`, `target_arm_id[16]`, `offer_nonce[16]`, `source_arm_id[16]`, `source_epoch u64`, `target_epoch u64`, `bootstrap_hash[32]`, `mode u8`, `flags u8`, `reserved u16` | 116 | 248 | 284 |
| PAIR_RESULT | 3 | S to T | `result u8`, `tuple_state u8`, `flags u8`, `reserved u8`, `source_epoch u64`, `target_epoch u64`, `state_seq u32`, `reserved u32`, `bootstrap_hash[32]`, `current_source_epoch u64` | 68 | 200 | 236 |
| CANCEL | 4 | T to S | `operation_id[32]`, `intent u8`, `flags u8`, `reserved u16`, `begin_nonce[16]`, `target_arm_id[16]`, `expected_source_epoch u64`, `expected_target_epoch u64` | 84 | 216 | 252 |
| FORGET | 5 | T to S | same as CANCEL | 84 | 216 | 252 |
| REMOVE_RESULT | 6 | S to T | `request_type u8`, `result u8`, `tuple_state u8`, `flags u8`, `operation_id[32]`, `source_epoch u64`, `target_epoch u64`, `state_seq u32`, `reserved u32`, `current_source_epoch u64` | 68 | 200 | 236 |
| QUERY | 7 | T to S | `query_id[32]` | 32 | 164 | 200 |
| QUERY_RESULT | 8 | S to T | `query_id[32]`, `state u8`, `flags u8`, `reserved u16`, `source_epoch u64`, `target_epoch u64`, `state_seq u32`, `reserved u32`, `bootstrap_hash[32]`, `current_source_epoch u64` | 100 | 232 | 268 |
| SESSION_OPEN | 9 | T to S | `session_nonce[32]`, `source_epoch u64`, `target_epoch u64`, `target_instance_nonce[32]`, `target_stop_seq u64`, `known u8`, `flags u8`, `reserved u16` | 92 | 224 | 260 |
| SESSION_RESULT | 10 | S to T | `session_nonce[32]`, `result u8`, `flags u8`, `reserved u16`, `source_epoch u64`, `target_epoch u64`, `state_seq u32`, `reserved u32`, `source_instance_nonce[32]`, `session_seq u64` | 100 | 232 | 268 |
| LOOKUP | 12 | T to S | `query_id[32]`, `begin_nonce[16]`, `target_arm_id[16]` | 64 | 196 | 232 |
| LOOKUP_RESULT | 13 | S to T | `query_id[32]`, `state u8`, `flags u8`, `reserved u16`, `source_epoch u64`, `target_epoch u64`, `state_seq u32`, `reserved u32`, `begin_nonce[16]`, `target_arm_id[16]`, `offer_nonce[16]`, `source_arm_id[16]`, `bootstrap_hash[32]`, `current_source_epoch u64` | 164 | 296 | 332 |
| REFUSED | 14 | S to T | `request_type u8`, `code u8`, `tuple_state u8`, `flags u8`, `operation_id[32]`, `source_epoch u64`, `target_epoch u64`, `state_seq u32`, `reserved u32`, `current_source_epoch u64` | 68 | 200 | 236 |

The suffix offsets are cumulative from 136. For example, in BEGIN the
`begin_nonce` is at bytes 136 to 151, `target_arm_id` at 152 to 167,
`target_epoch` at 168 to 175, `mode` at 176, `flags` at 177, and `reserved` at
178 to 179. The tag starts at 180. The same cumulative rule applies to every row
and is unambiguous because every field has a fixed size.

### 3.1 Type rules

`REFUSED.request_type` is 11 (BEGIN) or 2 (PAIR_DONE). No other value is valid.
`REMOVE_RESULT.request_type` is 4 (CANCEL) or 5 (FORGET). No other value is
valid. A response is valid only on the connection that carried its request, and
only after the request was accepted for processing. A response with no matching
in-flight request is a protocol error and is not a result.

BEGIN, LOOKUP, and CANCEL with `intent = 2` are the only requests that may carry
`I = 0`. A response may carry `I = 0` only where section 3.2 permits it.

Enums:

- `mode`: `1` SAS, `2` QR. No other value.
- `tuple_state` and `state`: `1` PENDING, `2` ACTIVE, `3` TERMINAL, `4` UNKNOWN,
  `5` TOMBSTONE.
- `PAIR_RESULT.result`: `1` COMMITTED, `2` ABORTED, `3` CONFLICT.
- `REMOVE_RESULT.result`: `1` REMOVED, `2` ALREADY_REMOVED, `3` DENIED,
  `4` CONFLICT, `5` RETRY_LATER.
- `REFUSED.code`: `1` BUSY, `2` NO_ARM, `3` MODE_MISMATCH, `4` CAPACITY,
  `5` CONFLICT, `6` BAD_STATE, `7` STALE_EPOCH, `8` RATE_LIMIT.
- `SESSION_RESULT.result`: `1` ACCEPTED, `2` NOT_ACTIVE, `3` STALE_EPOCH,
  `4` BUSY, `5` CAPACITY.
- `SESSION_OPEN.known`: `1` only. A first pairing cannot open a proxy session
  before both sides have promoted.
- `CANCEL.intent`: `1` EXACT, `2` PRE_OFFER.
- `terminal_reason` in a record: `1` CANCELLED, `2` FORGOTTEN_LOCAL, `3`
  FORGOTTEN_REMOTE, `4` SUPERSEDED, `5` ABANDONED, `6` IDENTITY_RESET, `7`
  PRE_OFFER_CANCEL, `8` QUARANTINED. It is not a wire field. It is reported only
  through state and the local UI.

### 3.2 The `I` field, per type

The common field cannot be one rule. Revision 2 said "every other frame uses a
nonzero `I`", which left no encoding for a response to a zero-I request. The
rule below is total.

| Type | `I` rule |
|---|---|
| BEGIN | 0 |
| LOOKUP | 0 |
| CANCEL, `intent = PRE_OFFER` | 0 |
| CANCEL, `intent = EXACT` | nonzero, equal to the named record's `I` |
| FORGET | nonzero, equal to the named record's `I` |
| OFFER | nonzero, equal to the named record's `I` |
| PAIR_DONE | nonzero, equal to the named record's `I` |
| PAIR_RESULT | the named record's `I`; nonzero |
| REMOVE_RESULT, `request_type = 5` | nonzero, the request's `I` |
| REMOVE_RESULT, `request_type = 4`, record matched | the matched record's `I`; nonzero |
| REMOVE_RESULT, `request_type = 4`, only a tombstone matched | 0 |
| QUERY | nonzero, equal to the named record's `I` |
| QUERY_RESULT | the request's `I`; nonzero |
| SESSION_OPEN | nonzero, equal to the named record's `I` |
| SESSION_RESULT | the request's `I`; nonzero |
| LOOKUP_RESULT, state PENDING, ACTIVE, or TERMINAL | the found record's `I`; nonzero |
| LOOKUP_RESULT, state TOMBSTONE or UNKNOWN | 0 |
| REFUSED, `request_type = 11` | 0 |
| REFUSED, `request_type = 2` | the request's `I`; nonzero |

A response whose `I` violates this table is a protocol error on receipt, not a
result. In particular, a REMOVE_RESULT with `request_type = 5` and `I = 0`, or a
REFUSED with `request_type = 11` and a nonzero `I`, is rejected and the
connection is closed.

### 3.3 The `flags` byte, per type

`DUPLICATE` and `STATE_DERIVED` are never set together. `TERMINAL_RECEIPT`
implies `DUPLICATE` and is never set with `STATE_DERIVED`. Bits 3 to 7 are zero
in every type.

| Type | Bit 0 `DUPLICATE` | Bit 1 `STATE_DERIVED` | Bit 2 `TERMINAL_RECEIPT` |
|---|---|---|---|
| BEGIN | 0 | 0 | 0 |
| OFFER | 0 or 1 | 0 | 0 |
| PAIR_DONE | 0 | 0 | 0 |
| PAIR_RESULT | 0 or 1 | 0 or 1 | 0 |
| CANCEL | 0 | 0 | 0 |
| FORGET | 0 | 0 | 0 |
| REMOVE_RESULT | 0 or 1 | 0 or 1 | 0 or 1 |
| QUERY | 0 | 0 | 0 |
| QUERY_RESULT | 0 | 0 | 0 |
| SESSION_OPEN | 0 | 0 | 0 |
| SESSION_RESULT | 0 | 0 | 0 |
| LOOKUP | 0 | 0 | 0 |
| LOOKUP_RESULT | 0 | 0 | 0 |
| REFUSED | 0 | 0 | 0 |

OFFER is a response to BEGIN even though it carries request values. An OFFER has
`DUPLICATE = 1` only when it replays the OFFER created by the reservation for
an exact duplicate BEGIN. The first OFFER for a reservation has `DUPLICATE = 0`.
An OFFER never carries a receipt flag because it writes no receipt.

A `REFUSED` frame never writes a receipt, so it never carries a receipt flag. A
`QUERY_RESULT` and a `LOOKUP_RESULT` are read-only, so they never carry a
receipt flag.

### 3.4 State-dependent field rules

These rules make a result frame self-checking. A result that violates them is a
protocol error, not a result.

| Wire state | `I` | `source_epoch` | `target_epoch` | `state_seq` | `bootstrap_hash` | record nonces |
|---|---|---|---|---|---|---|
| PENDING | nonzero | nonzero | nonzero | any, normally 0 or 1 | zero | all four nonzero |
| ACTIVE | nonzero | nonzero | nonzero | any, at least 1 | nonzero | all four nonzero |
| TERMINAL | nonzero | nonzero | nonzero | any, at least 1 | zero or nonzero | as stored |
| TOMBSTONE | 0 | 0 | nonzero | 0 | zero | begin and target arm set; offer and source arm zero |
| UNKNOWN | 0 in LOOKUP_RESULT; otherwise the request's `I` | 0 | 0 | 0 | zero | zero |

A field that the frame does not carry is not constrained by this table. The
`bootstrap_hash` column applies to PAIR_RESULT, QUERY_RESULT, and LOOKUP_RESULT.
The record nonce column applies only to LOOKUP_RESULT, which is the only result
frame that carries the four ceremony nonces.

A TERMINAL record may report a zero hash only when it was terminalized before a
PAIR_DONE supplied and the source verified a hash. Zero is never a match for a
computed hash and never authorizes promotion.

`current_source_epoch` is nonzero in every result that names an existing source
record, and it is zero only when no source record for the pair is retained. It
is never less than the named record's `source_epoch`. A result for an old record
may carry a larger value, and that is how a target sees that the record is
superseded.

`REFUSED` follows the state rules above for its `tuple_state`. It adds no field.

`REMOVE_RESULT` for a pre-offer cancel that matched only a tombstone reports
`I = 0`, `source_epoch = 0`, `target_epoch` from the tombstone, `state_seq = 0`,
and `tuple_state = TOMBSTONE`. `REMOVE_RESULT` for a pre-offer cancel that
terminalized a PENDING record reports that record's `I`, epochs, and
`state_seq`, with `tuple_state = TERMINAL`. Those two frames are distinguishable
and both are valid.

## 4. Frame key, tag, and channel binding

For the pairing channel:

```
E = TLS-Exporter("EXPORTER-HotspotShade-incarnation-v2", empty_context, 32)
```

For the proxy channel:

```
E = TLS-Exporter("EXPORTER-HotspotShade-session-v2", empty_context, 32)
```

The two labels are distinct. A value from one channel is never used on the
other. The exporter must return exactly 32 bytes. A missing exporter, a wrong
length, a call before the handshake completes, or a value that differs between
the peers is a fixed failure before any pairing frame is parsed.

The frame key is:

```
salt = "HotspotShade-v2-salt\0"
PRK  = HMAC-SHA256(salt, E)
K    = HMAC-SHA256(PRK, "HotspotShade-v2-frame-key\0" || 0x01)
```

`K` is 32 bytes. The `0x01` is the single HKDF-Expand block counter. The candidate
uses HKDF-SHA256-Expand with a 32-byte output, written here as one HMAC so there
is no ambiguity about an implementation's HKDF API.

The tag is:

```
tag = HMAC-SHA256(K,
  "HotspotShade-v2-frame\0" ||
  channel_u8 || direction_u8 ||
  u32be(frame_len) || frame)
```

`channel_u8` is `1` for pairing and `2` for proxy. `direction_u8` is `1` for S to
T and `2` for T to S. `frame` is exactly the bytes from `version` through the
last suffix byte. It does not include the 4-byte length prefix and does not
include the tag. The length appears once, in its own `u32be` field. A frame and
its length are therefore both covered, and no byte is covered twice.

The tag is verified in constant time after TLS peer validation and before the
type, length, or any field is used. A frame with a valid tag on one connection
has no meaning on another connection because `K` changes with the exporter. A
durable receipt is never a tag.

This binding proves that the frame was sent on this live mutually authenticated
connection by the peer that holds the key. It does not prove consent, durable
state, freshness across connections, or that the peer is the intended physical
device. Those come from the bootstrap, the state checks, and the record.

## 5. Bootstrap, transcript, and source authentication

### 5.1 TLS identity rule

The source is the TLS server and the target is the TLS client on both the pairing
and proxy listeners. Each side checks the peer certificate's SPKI pin against the
pin in its record and against the pin in the frame. The comparison is byte exact
and constant time. A difference rejects the connection before any application
byte. The source never takes a pin from a frame as proof of identity. The target
never accepts a source pin from a frame without the TLS server pin also matching.

The source proves possession of its identity key through the TLS
`CertificateVerify`. The target proves possession of its identity key in the same
way. A pin is a public value. An active hotspot client can connect and receive
the source certificate before it authenticates. That is linkability, not
authentication.

TLS 1.3 is required. TLS 1.2 and earlier are rejected before any exporter call.
No 0-RTT or early data is used. A resumed session is acceptable only if the
stack exposes the exporter and both pins are checked on the resumed connection.
If a stack cannot do that, it must use a full handshake. This is a feasibility
gate, not a claim about a particular stack.

### 5.2 Canonical bootstrap transcript B

The transcript is one byte string:

```
B =
  "HotspotShade-v2-bootstrap\0" ||
  source_pin[32] || target_pin[32] ||
  I[32] || P[32] ||
  source_epoch_u64 || target_epoch_u64 ||
  source_arm_id[16] || target_arm_id[16] ||
  begin_nonce[16] || offer_nonce[16] ||
  mode_u8 ||
  u32be(len(mechanism_data)) || mechanism_data
```

`len(mechanism_data)` is 0 for SAS and 212 for the QR payload in section 5.3.
The label is 26 bytes including the NUL. All integers are big-endian. There are
no optional fields and no separators beyond the fixed fields and the explicit
length. The source and target compute `bootstrap_hash = SHA-256(B)`.

`B` binds both pins, both epochs, both arming identifiers, both ceremony nonces,
the incarnation, the target-chosen operation, the mechanism, and the mechanism
data. A change to any of them changes `bootstrap_hash`. A hash from a different
`P`, `I`, pin pair, epoch, arm, nonce, mechanism, or ceremony does not verify.

The source does not know `bootstrap_hash` when it sends OFFER, because the
mechanism data is not complete until the human step. OFFER carries the fields,
not the hash. The source stores the pending record with the fields. On PAIR_DONE
it verifies the supplied hash against its own reconstruction and the stored
fields before any promotion.

The source may send OFFER before the human confirmation. OFFER is provisional.
The pending record is not usable and cannot be promoted until the source has
completed its own local confirmation of the same `B` and the presented hash
matches. A target that sends PAIR_DONE without a completed local confirmation is
rejected.

### 5.3 Mechanisms

SAS, `mode = 1`:

- `mechanism_data` is empty.
- Both devices compute
  `sas_digest = SHA-256("HotspotShade-v2-sas\0" || bootstrap_hash)`.
- The six-digit code is the first 20 bits of `sas_digest`, interpreted
  big-endian, modulo 1,000,000, rendered as exactly six ASCII digits with
  leading zeros. The modulo bias is small but nonzero; it is not a uniform
  1,000,000-way choice.
- Each person compares the code and performs a local confirm action. A code
  comparison without a local action is not consent.
- The code is never sent as a frame field. It is shown only on the device that
  computed it.

QR, `mode = 2`:

- The QR payload is exactly 212 bytes:

```
version_u8 = 2 || mode_u8 = 2 || reserved_u16 = 0 ||
source_pin[32] || target_pin[32] ||
I[32] || P[32] ||
source_epoch_u64 || target_epoch_u64 ||
source_arm_id[16] || target_arm_id[16] ||
begin_nonce[16] || offer_nonce[16]
```

- `mechanism_data` is those 212 bytes, not a text rendering and not a hash of
  them. A scanner must return the exact bytes. A text fallback is a product
  choice and is not defined here.
- The payload is single use. It expires at the earlier of the local arming
  deadline and 120 seconds after creation. The exact UI and timer behavior are
  product choices.
- The source scans and confirms the exact bytes. It must verify that every field
  in the scanned payload equals its own OFFER tuple, including both pins, `I`,
  `P`, both epochs, both arms, and both nonces. A mismatch rejects before any
  commit. The target confirms locally. The target may display the payload only
  after it has a durable OFFERED record with the same `I`, `P`, epochs, arms, and
  nonces. A payload displayed before that is not this protocol.
- A 212-byte binary payload needs a QR version and error-correction level that
  can carry it on the supported screen and camera. That is a feasibility gate,
  not a result. A text rendering is not defined here.

Which side displays the QR, whether SAS ships, and the exact local confirm
wording are unresolved product choices. This candidate specifies the bytes, not
the product surface.

### 5.4 Arming

Arming is local state. It is never set by a frame. There are two independent arm
machines.

Source arm:

```
S_ARM_NONE | S_ARM_LIVE
S_ARM_LIVE: source_arm_id[16], mode u8, start_monotonic,
            deadline_monotonic, reservation_used u8, attempts u8
```

Rules:

1. BEGIN requires `S_ARM_LIVE` with the same `mode` and a live deadline.
   Otherwise the source returns REFUSED `NO_ARM` or `MODE_MISMATCH` with no
   state change and no receipt.
2. A source arm permits exactly one reservation in the whole namespace. The
   first BEGIN that durably reserves sets `reservation_used = 1`. The arm stays
   live until a disarm event, so the matching PAIR_DONE can still be accepted. A
   BEGIN for a different pin pair, or for a different `P` on the same pair,
   while `reservation_used = 1` is `BUSY` unless it is the exact replay in rule
   3.
3. While `reservation_used = 1`, an exact BEGIN for the same `P`, `begin_nonce`,
   `target_arm_id`, and `mode` receives the stored OFFER with `DUPLICATE = 1`.
   Any other BEGIN is refused. A different `P` gets `BUSY`. The same `P` with a
   different nonce or arm gets `CONFLICT`.
4. `attempts` counts accepted BEGIN frames under the arm, including replays. It
   starts at 0 and increments for each handled BEGIN. At 7 the source returns
   REFUSED `RATE_LIMIT` and does not mutate. This bounds a replay loop without
   touching the record.
5. The source clears its arm on commit, local cancel, a remote CANCEL or FORGET
   that terminalizes the reserved record, deadline, app background or screen
   lock where the platform reports it, process exit, listener close, and local
   or remote removal for that peer. A failed proof may clear it too; that is a
   product choice. Arming is not durable.
6. A source restart does not restore an arm. A pending record may survive, but it
   cannot be promoted. The person must abandon or cancel it, which frees the
   pending slot, and then start a new ceremony with a new record and a new arm.
   The old pending record is `ABANDONED` by local policy or by cancellation.

Target arm:

```
T_ARM_NONE | T_ARM_ARMED | T_ARM_LIVE
T_ARM_ARMED: target_arm_id[16], mode u8, P[32], begin_nonce[16],
             target_epoch u64, start_monotonic, deadline_monotonic
T_ARM_LIVE:  the same fields, begin_resends_left u8, done_resends_left u8
```

Rules:

1. BEGIN requires `T_ARM_ARMED` or `T_ARM_LIVE`. The target writes its
   BEGIN_MAYBE_SENT record before sending. A target that has not persisted that
   record does not send.
2. On BEGIN send, after the durable write, the arm moves `T_ARM_ARMED` to
   `T_ARM_LIVE` with `begin_resends_left = 2` and `done_resends_left = 2`. It is
   not cleared. Revision 2 cleared the arm on send and then relied on it for an
   exact resend; that was a contradiction.
3. `T_ARM_LIVE` authorizes two things, and nothing else:
   - An exact resend of the same BEGIN with the same `P`, `begin_nonce`,
     `target_arm_id`, `target_epoch`, and `mode`, while `begin_resends_left > 0`.
     Each resend decrements that budget.
   - One PAIR_DONE for the same tuple, and exact resends of it while
     `done_resends_left > 0`. Each resend decrements that budget.
   No other `P` or nonce is permitted under that arm.
4. A matching OFFER sets `begin_resends_left = 0` and keeps the arm `T_ARM_LIVE`.
   The arm must stay live because PAIR_DONE still has to be sent. A REFUSED for
   that `P`, a pairing result that ends the ceremony, local cancel, local forget,
   the deadline, app background or screen lock where the platform reports it,
   process exit, and listener close all move the arm to `T_ARM_NONE`.
5. Arming is not durable. After a restart the arm is `T_ARM_NONE` and no BEGIN
   or PAIR_DONE is sent for the old record. The target reconciles by LOOKUP or
   QUERY and then cancels or abandons the record. It never reuses `P`.
6. PAIR_DONE must carry the current `source_arm_id`, the target's original
   `target_arm_id`, and the exact record epochs. If the source has restarted or
   disarmed, the arm identifier is gone and PAIR_DONE is REFUSED `NO_ARM` with no
   mutation. If the target has restarted, it cannot send PAIR_DONE; it may still
   promote from an authenticated ACTIVE query result, as section 7.2 states.
7. A local removal clears both arms for that peer and terminalizes the pending
   record. A delayed PAIR_DONE from the old arm cannot promote.
8. No arming state is claimed to survive process death. That is a deliberate
   fail-closed choice.

The target arm deadline covers the whole ceremony through the last PAIR_DONE
send. A person who confirms after the deadline has expired needs a new ceremony
with a new `P`. This candidate does not extend an arm; an extension would be a
second permission and needs its own reviewed rule.

Residual denial: a peer that can reach the armed source and complete mutual TLS
can consume the one reservation and cause an OFFER. It cannot promote without
the human bootstrap and a matching PAIR_DONE. This is a denial of one ceremony
attempt, bounded by the arm deadline and the rate limits. It is not a trust
grant. The source UI must show the pending state and the person can cancel it.

### 5.5 Consent state and crash behavior

Consent is a local durable fact, never a network claim. Each side records only
its own action.

Source consent:

- The source record has `consent_hash[32]` and `consent_present u8`.
- An explicit local source action computes `B` from the stored record and writes
  `consent_hash = SHA-256(B)` and `consent_present = 1` in one durable mutation.
  That mutation increments `state_seq`.
- PAIR_DONE is eligible only when `consent_present = 1`, the frame hash equals
  `consent_hash`, and the source's reconstruction of `B` from durable fields
  also equals both.
- A zero `consent_hash` with `consent_present = 0` is the only pre-consent
  value. A zero hash with `consent_present = 1` is a store defect and blocks
  promotion.

Target consent:

- The target writes `bootstrap_hash = SHA-256(B)` into the OFFERED record when
  the person confirms. That write is the target's consent record.
- DONE_MAYBE_SENT is written after the hash. PAIR_DONE is sent only after that.
- A zero target hash means no local confirmation.

Crash table:

| Crash point | Durable result | Permitted next action |
|---|---|---|
| Before the target writes BEGIN_MAYBE_SENT | No record, no frame | The person may start again |
| After BEGIN_MAYBE_SENT, before or after BEGIN send | BEGIN_MAYBE_SENT, no arm after restart | LOOKUP or CANCEL `PRE_OFFER`; never resend BEGIN |
| After the target writes OFFERED, before local confirm | OFFERED, hash zero | Cancel, or continue the ceremony in the same process only |
| After the target writes the hash, before DONE_MAYBE_SENT | OFFERED, hash set, no arm after restart | LOOKUP or CANCEL; no PAIR_DONE |
| After DONE_MAYBE_SENT, before or after PAIR_DONE send | DONE_MAYBE_SENT, no arm after restart | QUERY only; promote only from ACTIVE with a matching hash |
| After the source reservation, before local consent | PENDING, no consent | Cancel or abandon; PAIR_DONE gets `BAD_STATE` |
| After source consent, before the arm ends | PENDING, consent set, arm gone after restart | PAIR_DONE gets `NO_ARM`; a new ceremony is required |
| After the source commit, before PAIR_RESULT send | ACTIVE, receipt durable | QUERY returns ACTIVE; the target promotes |

A crash never turns a missing consent into a consent. A durable hash records a
completed local action. It is not proof that a person saw the same value after a
restore, and it does not replace the human bootstrap.

### 5.6 Source authentication for sessions

Pairing authentication alone does not authenticate a proxy session. The v2 proxy
channel uses mutual TLS with the same identity pins, ALPN `hs-proxy/2`, the
session exporter label, and channel `2`. The first application frame is
SESSION_OPEN. The source accepts it only after all of these hold:

1. The TLS client pin equals `target_pin` and the TLS server pin equals
   `source_pin`.
2. The record `(source_pin, target_pin, I, P)` is ACTIVE under the source store
   lock.
3. The `source_epoch` and `target_epoch` in the frame equal the record's stored
   values.
4. The session table can register the tuple before either lock is released.
5. The `target_instance_nonce` and `target_stop_seq` are opaque to the source.
   They are not used for source trust. The target keeps the pending request in
   memory keyed by `session_nonce`. It discards that request on every stop and
   on process restart. A SESSION_RESULT is accepted only if a pending request
   with the same nonce exists in the current instance and stop generation.

The source returns SESSION_RESULT only after registration. No inner flow byte is
accepted before SESSION_RESULT. The source proves itself to the target by the TLS
server certificate and `CertificateVerify`; the target checks the source pin
before sending SESSION_OPEN. A token is not source authentication and is not
required by this candidate. If a token is retained for another purpose, it must
be bound to the same tuple and never used as the only check. The credential wire
format remains open.

The target accepts a credential or SESSION_RESULT only from the proved source pin
on the current connection and only after checking the exact active `I`, `P`, and
epochs under its own store lock. A result for an older target instance or an
older stop sequence is discarded before any credential is created. A
`NOT_ACTIVE` or `STALE_EPOCH` result blocks use but does not authorize the target
to delete its record. Deletion is a local person action or the result of a
reviewed local transition.

This candidate does not define the inner proxy data frame format or the
credential wire format. The proxy data phase needs a separate reviewed design.
It must not accept any inner byte before SESSION_RESULT is accepted. It must not
fall back to a v1 token-only data path. A data frame is bound to the session by
the mutually authenticated TLS connection and the registered tuple; whether it
also carries a per-frame tag is a separate design choice.

### 5.7 SESSION_OPEN retry and idempotence

Revision 2 left a lost SESSION_OPEN undefined. The source could register a
session whose result the target never saw, and the target had no rule for a
second attempt.

Target side:

- One pending request entry exists per `session_nonce`. It records the nonce,
  the connection attempt, the target instance nonce, the stop sequence, and a
  local 15-second deadline.
- A retry uses the same `session_nonce` and a new mutually authenticated
  connection. It is allowed only while the pending entry exists and no result
  has been accepted.
- The target makes at most 3 attempts, with 1 second before the second attempt
  and 3 seconds before the third. At the deadline it discards the entry, retires
  the nonce forever, closes the connection, creates no credential, and reports
  failure. A later SESSION_RESULT has no pending entry and is discarded.
- The target never treats a retry as a second session. It must not open a second
  session for the same inner flow.

Source side. The source evaluates these checks in this order. The order is part
of the protocol so two hosts cannot differ.

1. TLS pins, tag, version, type, length, enums, and reserved bytes.
2. The record `(source_pin, target_pin, I, P)` is ACTIVE. Otherwise
   `NOT_ACTIVE`.
3. The frame epochs equal the record's. Otherwise `STALE_EPOCH`.
4. A live session is already registered under the session idempotence key. If
   so, `BUSY` with `session_seq = 0`. No second session is registered and the
   first is not disturbed.
5. The session table has room. Otherwise `CAPACITY` with `session_seq = 0`.
6. Register and return `ACCEPTED` with a fresh `session_seq`.

The session idempotence key is
`(source_pin, target_pin, I, P, source_epoch, target_epoch, session_nonce)`.

A retry after the first connection closed has no live session under the key, so
step 6 registers again and returns a new `session_seq`. That covers a lost
result and a dropped connection.

`session_seq` is a per-listener counter that starts at 1 and increments for
each accepted registration. It is not durable and resets when the listener
starts. It is 0 in any result that registered no session. The target uses it
for local ordering only and must not compare it across source instances.

A retry is never a substitute for a new ceremony. After `NOT_ACTIVE` the target
must block the tuple and require a new pairing.

## 6. Durable record schema

A host stores one canonical v2 store. The store is one integrity-protected unit.
The exact file encoding is a host design, but it must carry these fields with no
implicit defaults:

```
store:
  format u8 = 1
  namespace_id[16]
  identity_pin[32]
  store_seq u64             starts at 1, increments by 1 per commit
  previous_seq u64
  previous_digest[32]
  txid[16]
  records[]        ordered by (source_pin, target_pin, I)
  tombstones[]     ordered by (source_pin, target_pin, P, begin_nonce)
  next_source_epoch u64
  next_target_epoch u64
  anchor_meta      store_seq and store_digest expected by this store
  store_tag[32]
```

`records[]` holds zero or one record per `(source_pin, target_pin, I)`. For one
ordered pin pair there may be one ACTIVE record and one PENDING record at the
same time. There is at most one PENDING record per pair. A second pending
ceremony is refused `BUSY`, never silently superseded.

Receipt slot:

```
receipt_slot:
  used u8                 0 or 1
  request_type u8         4, 5, or 0 for a local action
  operation_id[32]
  request_fp[32]          zero only when request_type = 0
  result u8
  state_after u8          meaningful in last_request and terminal_request
  state_seq_after u32     meaningful in last_request and terminal_request
  flags u8
```

`request_type = 0` is a store-only value for a local removal. It is never valid
on the wire. A local removal has no remote request that could match it.

Source record:

```
source_record:
  source_pin[32], target_pin[32]
  I[32], P[32]
  begin_nonce[16], target_arm_id[16]
  offer_nonce[16], source_arm_id[16]
  mode u8
  state u8                  PENDING, ACTIVE, TERMINAL
  state_seq u32
  source_epoch u64          immutable record epoch, assigned at reservation
  target_epoch u64          immutable record epoch, from BEGIN
  bootstrap_hash[32]        zero before PAIR_DONE, then exact
  consent_hash[32]
  consent_present u8
  terminal_reason u8
  terminal_operation_id[32]
  terminal_result u8
  last_request receipt_slot
  terminal_request receipt_slot
  denial_receipts[4]        receipt_slot
```

Target record:

```
target_record:
  source_pin[32], target_pin[32]
  I[32]                     zero while BEGIN_MAYBE_SENT or pre-offer CANCEL_INTENT
  P[32]
  begin_nonce[16], target_arm_id[16]
  offer_nonce[16], source_arm_id[16]
  mode u8
  state u8                  BEGIN_MAYBE_SENT, OFFERED, DONE_MAYBE_SENT,
                            ACTIVE, CANCEL_INTENT, TERMINAL
  state_seq u32
  source_epoch u64          immutable record epoch, from OFFER; 0 before OFFER
  target_epoch u64          immutable record epoch, assigned at BEGIN
  bootstrap_hash[32]        zero before local confirmation
  terminal_reason u8
  terminal_operation_id[32]
  terminal_result u8
  remote_remove_pending u8
  remove_operation_id[32]
  remove_request_fp[32]
  remove_attempts u8
  last_request receipt_slot
  terminal_request receipt_slot
  denial_receipts[4]        receipt_slot
```

A target may hold one ACTIVE and one non-ACTIVE record for the same source pin.
The non-ACTIVE record is the pending re-pair. It never replaces the active
record until the promotion transaction commits.

A target BEGIN_MAYBE_SENT record and a pre-offer CANCEL_INTENT record have `I =
0` and `source_epoch = 0`. They are never usable for a session. A terminal record
created from that state keeps those zero values and its `P`, so a duplicate
cancel can still match it, but it is not a source record and never appears as
`I = 0` in a result that names a source record.

Tombstone for a pre-offer cancel with no source record:

```
tombstone:
  source_pin[32], target_pin[32]
  P[32], begin_nonce[16], target_arm_id[16]
  target_epoch u64
  operation_id[32]
  request_fp[32]
  created_store_seq u64
```

The tombstone is the durable receipt for the first pre-offer cancel that created
it. A duplicate with the same `operation_id` and `request_fp` is answered from
it. A pre-offer cancel with a different operation ID that matches the same
`(P, begin_nonce, target_arm_id)` is answered from the tombstone with
`STATE_DERIVED` and writes nothing.

The store is written with the transaction and recovery rules in section 11. A
record that is not the validated current store is not used for trust, sessions,
or credentials.

## 7. State machines

### 7.1 Source

The table describes one record. A pin pair may also retain older terminal
records and one ACTIVE record while a new PENDING record exists. The PENDING
slot is the only one that can be promoted.

| State | Meaning | Allowed next states |
|---|---|---|
| `NONE` | no record and no tombstone for the pair | PENDING on armed BEGIN |
| `TOMBSTONE` | one or more pre-offer cancellations for this pair | PENDING on armed BEGIN with a new P and new nonce; the same P is `CONFLICT` |
| `PENDING` | reservation with I and P, no promotion | ACTIVE on matching PAIR_DONE; TERMINAL on CANCEL, local removal, or policy abandonment |
| `ACTIVE` | committed record | TERMINAL on exact CANCEL, FORGET, local removal, or supersession by a promoted PENDING |
| `TERMINAL` | terminal record retained | none; a new BEGIN creates a new PENDING record with a new I and a new `source_epoch` |

An ACTIVE record does not block a new ceremony. It blocks a promote of a
different record only through the exact tuple checks. A new BEGIN while ACTIVE
exists and no PENDING exists reserves a second record and is the normal re-pair
path.

#### 7.1.1 BEGIN, total

The source evaluates these checks in this order. The first failure decides the
response. The order is part of the protocol so two hosts cannot differ.

1. Frame rejections in section 2. No response.
2. `I = 0`, nonzero `P`, nonzero `target_epoch`, and a defined `mode` and
   `flags`. Otherwise reject.
3. `S_ARM_LIVE` with the same mode and a live deadline. Otherwise REFUSED
   `NO_ARM` or `MODE_MISMATCH`. No mutation.
4. `attempts` below the cap. Otherwise REFUSED `RATE_LIMIT`. No mutation.
5. Exact replay. A PENDING record with the same `P`, `begin_nonce`,
   `target_arm_id`, and mode: replay the stored OFFER with `DUPLICATE = 1`. No
   mutation. This is allowed even though `reservation_used = 1`.
6. Collision with a retained record or tombstone for the pair. The cases are:
   - A PENDING record with the same `P` and a different nonce or arm: REFUSED
     `CONFLICT`. No mutation.
   - Any other retained record or tombstone with the same `P`, or any retained
     record or tombstone with the same `begin_nonce`: REFUSED `CONFLICT`. No
     mutation.
7. A consumed arm. `reservation_used = 1` and the frame is not the exact replay
   of step 5: REFUSED `BUSY`. No mutation. This covers a different `P` on the
   same pair and a first BEGIN from a different pin pair.
8. A PENDING record for the pair with a different `P`: REFUSED `BUSY`. No
   mutation. The pending record is never replaced. Step 7 normally covers this
   case; the explicit rule keeps the table total if an arm and a pending record
   are ever inconsistent.
9. Record capacity for the namespace. Otherwise REFUSED `CAPACITY`. No
   mutation.
10. Reserve. Assign a fresh `I` and `source_epoch`. Persist PENDING with the
    BEGIN fields, `source_arm_id`, `offer_nonce`, `state_seq = 0`, zero hashes,
    and `reservation_used = 1`. Then send OFFER with `DUPLICATE = 0`.

Every BEGIN that reaches step 10 for a pair with no retained `P` or
`begin_nonce` collision reserves a new record. That includes a pair with an
ACTIVE record, any number of TERMINAL records, and a TOMBSTONE for a different
`P`. The table is therefore total.

The line "A source arm permits at most one new PENDING reservation" is
implemented by `reservation_used`. It does not block a second record for a
different pin pair under a different arm.

#### 7.1.2 PAIR_DONE, total

The source evaluates these checks in this order.

1. Frame rejections. No response.
2. Nonzero `I`, `P`, both epochs, both arms, both nonces, and a defined mode and
   flags.
3. Receipt match for `(pins, I, P, operation_id = P)`. On an exact key and
   fingerprint match, return the recorded result with `DUPLICATE`. On a key
   match with a different fingerprint, return PAIR_RESULT `CONFLICT` with no
   mutation. This step is why a lost PAIR_RESULT is deterministic.
4. Record lookup by `(pins, I, P)`. If none: REFUSED `CONFLICT`, `tuple_state =
   UNKNOWN`, zero epochs, zero `state_seq`, and the newest retained source
   epoch. No mutation.
5. Epoch check. If either frame epoch differs from the record: REFUSED
   `STALE_EPOCH` with the record's state and epochs. No mutation.
6. Tuple check. `begin_nonce`, `target_arm_id`, `offer_nonce`, `source_arm_id`,
   and mode must equal the record. Otherwise PAIR_RESULT `CONFLICT` with the
   record's state, epochs, and hash. No mutation.
7. State:
   - PENDING: continue.
   - ACTIVE: PAIR_RESULT `COMMITTED` with `STATE_DERIVED` when the hash equals
     the stored nonzero hash; otherwise `CONFLICT`. No mutation.
   - TERMINAL: PAIR_RESULT `ABORTED` with `STATE_DERIVED` when the hash is zero
     in the record or equals the frame hash; otherwise `CONFLICT`. No mutation.
8. Source arm check. `S_ARM_LIVE`, the same mode, and a `source_arm_id` equal to
   the record. Otherwise REFUSED `NO_ARM` or `MODE_MISMATCH`. No mutation.
9. Consent check. `consent_present = 1`, and the frame hash equals both the
   stored `consent_hash` and the source's reconstruction of `B`. Otherwise
   REFUSED `BAD_STATE` or `CONFLICT`. A hash that differs from the stored
   `bootstrap_hash` of a record that already has one is `CONFLICT`. A missing
   consent is `BAD_STATE`. No mutation.
10. Commit. One durable transaction: terminalize the old ACTIVE record for the
    pair with reason `SUPERSEDED` if one exists, promote the PENDING record to
    ACTIVE, write `bootstrap_hash`, detach every session registered under the
    superseded record, and write the receipt. Send PAIR_RESULT `COMMITTED` only
    after the transaction is durable. The new ACTIVE record keeps its immutable
    `source_epoch` and `target_epoch`.

A PAIR_DONE for a PENDING record with a hash that the source has not confirmed
locally is never promoted. A PAIR_DONE for a TERMINAL record never recreates it.
A PAIR_DONE that arrives after a local or remote removal cannot revive the
record.

#### 7.1.3 CANCEL and FORGET, total

The source evaluates these checks in this order.

1. Frame rejections.
2. Field rules for the intent. `PRE_OFFER` requires `I = 0`, a nonzero
   `operation_id`, nonzero `begin_nonce` and `target_arm_id`, zero
   `expected_source_epoch`, and nonzero `expected_target_epoch`. `EXACT` requires
   nonzero `I`, `operation_id`, `begin_nonce`, `target_arm_id`,
   `expected_source_epoch`, and `expected_target_epoch`. FORGET requires
   `intent = 1`.
3. Receipt match. An exact key and fingerprint match returns the recorded result
   with `DUPLICATE`. A key match with a different fingerprint returns
   `CONFLICT` with no mutation.
4. For `PRE_OFFER`:
   - A PENDING record for the pair with the same `P`, `begin_nonce`, and
     `target_arm_id`: terminalize it with reason `PRE_OFFER_CANCEL`, detach its
     sessions, write the receipt, and return `REMOVED` with that record's `I`,
     epochs, `state_seq`, and `tuple_state = TERMINAL`.
   - An ACTIVE record for the pair: return `CONFLICT` with the current state.
     The source never removes an ACTIVE record from an `I = 0` request.
   - A TERMINAL record for the pair with the same `P`: return
     `ALREADY_REMOVED` with that record's fields.
   - A tombstone with the same `(P, begin_nonce, target_arm_id)`: return
     `REMOVED`, `tuple_state = TOMBSTONE`, `I = 0`, and the tombstone's
     `target_epoch`. A matching `operation_id` and `request_fp` gives
     `DUPLICATE`; otherwise `STATE_DERIVED`. No mutation.
   - A retained record or tombstone for the pair with the same `P` and a
     different nonce or arm: `CONFLICT`. No mutation.
   - A PENDING record for the pair with a different `P`: `CONFLICT`. No
     mutation. The request cannot name that record.
   - No retained object, tombstone capacity available: write the tombstone and
     return `REMOVED`, `tuple_state = TOMBSTONE`, `I = 0`, the request's target
     epoch, and `state_seq = 0`.
   - No retained object, tombstone capacity exhausted: return `RETRY_LATER` and
     write nothing.
   In every `PRE_OFFER` match, `expected_target_epoch` must equal the stored
   `target_epoch` of the record or tombstone. A mismatch is `CONFLICT` with no
   mutation. The target epoch is durable, so an honest target always matches it.
5. For `EXACT` and `FORGET`, look up `(pins, I, P)`. If none: `CONFLICT`,
   `tuple_state = UNKNOWN`. No mutation.
6. Epoch check. A mismatch gives `CONFLICT` with the record's state. No
   mutation. (`REMOVE_RESULT` has no stale-epoch result value; `CONFLICT` is the
   fixed answer.)
7. Tuple check. `begin_nonce`, `target_arm_id`, and mode must match the record.
   Otherwise `CONFLICT`. No mutation.
8. State:
   - PENDING: terminalize with reason `CANCELLED` or `FORGOTTEN_REMOTE`, write
     the `terminal_request` receipt, and return `REMOVED`.
   - ACTIVE and request is `CANCEL`: terminalize with reason `CANCELLED`, detach
     sessions, write the `terminal_request` receipt, and return `REMOVED`.
   - ACTIVE and request is `FORGET` with a registered session: `DENIED`, no
     mutation, and write a denial slot. If all four denial slots are used:
     `RETRY_LATER`, no mutation.
   - ACTIVE and request is `FORGET` with no registered session: terminalize the
     ACTIVE record with reason `FORGOTTEN_REMOTE`, terminalize any PENDING record
     for the pair with reason `SUPERSEDED`, detach sessions, write the
     `terminal_request` receipt on the ACTIVE record, and return `REMOVED`.
   - TERMINAL: `ALREADY_REMOVED` with `STATE_DERIVED` when `tuple_match` and
     `epoch_match` hold; otherwise `CONFLICT`. No mutation.
9. A local FORGET is not a wire request. It terminalizes the exact ACTIVE and
   PENDING records for the pair in one transaction, detaches sessions, clears
   the credential, clears the arm, and writes a `request_type = 0`
   `terminal_request` receipt. It never waits for the network and is never
   vetoed by a session.

An old CANCEL or FORGET for I1 cannot affect I2. The exact `I` and `P` check
fails and the result is `CONFLICT` with no mutation.

### 7.2 Target

The table describes one record. One ACTIVE record and one non-ACTIVE record for
the same source pin may coexist during a re-pair.

| State | Meaning | Allowed next states |
|---|---|---|
| `NONE` | no target record for the pair | BEGIN_MAYBE_SENT on local begin |
| `BEGIN_MAYBE_SENT` | P and nonces persisted, BEGIN may have been sent | OFFERED on matching OFFER; CANCEL_INTENT on cancel; TERMINAL on local forget |
| `OFFERED` | complete tuple persisted, bootstrap not confirmed | DONE_MAYBE_SENT before PAIR_DONE send; CANCEL_INTENT on cancel; TERMINAL on local forget |
| `DONE_MAYBE_SENT` | PAIR_DONE may have been sent | ACTIVE on COMMITTED or QUERY ACTIVE; CANCEL_INTENT on cancel; TERMINAL on local forget |
| `ACTIVE` | committed locally | TERMINAL on local forget; a new PENDING may coexist for re-pair |
| `CANCEL_INTENT` | durable cancel intent, use blocked | TERMINAL after local resolution or remote result; never ACTIVE |
| `TERMINAL` | terminal record retained | none; a new ceremony creates a new record |

The target writes BEGIN_MAYBE_SENT before sending BEGIN. It writes the complete
OFFERED tuple before it can display a bootstrap value or send PAIR_DONE. It
writes the local confirm hash before DONE_MAYBE_SENT. It writes
DONE_MAYBE_SENT before sending PAIR_DONE. A crash between a write and the send
is treated as possibly sent. That is intentional.

While a BEGIN_MAYBE_SENT, OFFERED, DONE_MAYBE_SENT, or CANCEL_INTENT record
occupies the pending slot, the target refuses a new begin for that source pin
with a local REFUSED `BUSY`. The person can cancel or forget the old record
first. The pending slot is not silently reused.

Incoming frame table. This table is total: every frame falls in exactly one row,
and a frame that does not match its expected state is ignored, never applied
partially.

| Frame | Target state | Action |
|---|---|---|
| OFFER, exact match | BEGIN_MAYBE_SENT | Persist the full tuple, move to OFFERED, set `begin_resends_left = 0`, keep the arm live for PAIR_DONE |
| OFFER, exact match | OFFERED, DONE_MAYBE_SENT | Ignore. No write, no new receipt |
| OFFER, any mismatch | BEGIN_MAYBE_SENT, OFFERED, DONE_MAYBE_SENT | No write. Send CANCEL `PRE_OFFER` with a fresh operation ID and a new durable intent |
| OFFER, any mismatch | ACTIVE, TERMINAL, CANCEL_INTENT | Ignore. It cannot affect the active record |
| PAIR_RESULT `COMMITTED` | DONE_MAYBE_SENT, or OFFERED with a nonzero stored hash | Promote only if the full tuple matches, `tuple_state = ACTIVE`, `current_source_epoch = source_epoch`, and the hash equals the stored hash |
| PAIR_RESULT `COMMITTED`, any mismatch | DONE_MAYBE_SENT, OFFERED | No promotion. Report a conflict. QUERY may resolve |
| PAIR_RESULT `COMMITTED` | ACTIVE, TERMINAL, CANCEL_INTENT | Ignore. No second promotion |
| PAIR_RESULT `ABORTED` | DONE_MAYBE_SENT, OFFERED | Terminalize locally with reason `ABANDONED`. No credential |
| PAIR_RESULT `ABORTED` | ACTIVE, TERMINAL, CANCEL_INTENT | Ignore |
| PAIR_RESULT `CONFLICT` | DONE_MAYBE_SENT, OFFERED | No mutation. QUERY may resolve |
| PAIR_RESULT `CONFLICT` | ACTIVE, TERMINAL, CANCEL_INTENT | Ignore |
| REMOVE_RESULT | CANCEL_INTENT or TERMINAL with a matching pending removal | Match `request_type`, `operation_id`, and the stored `remove_request_fp`. Apply the result as section 8.7 states |
| REMOVE_RESULT, no matching pending removal | any | Ignore. It creates no state change |
| QUERY_RESULT | DONE_MAYBE_SENT or OFFERED | Promote only from `ACTIVE` with a matching full tuple, nonzero equal hash, and `current_source_epoch = source_epoch`. `PENDING` permits a cancel. `TERMINAL` terminalizes locally. `UNKNOWN` blocks |
| QUERY_RESULT | any other state | Ignore |
| LOOKUP_RESULT `PENDING` | BEGIN_MAYBE_SENT with a live arm | Adopt `I` and the full tuple, move to OFFERED, set `begin_resends_left = 0` |
| LOOKUP_RESULT `PENDING` | BEGIN_MAYBE_SENT with no arm | Do not adopt. Report an orphan and cancel `PRE_OFFER` |
| LOOKUP_RESULT `ACTIVE` | BEGIN_MAYBE_SENT | Do not adopt. The target never confirmed this ceremony. Cancel `PRE_OFFER` and report an orphan |
| LOOKUP_RESULT `TOMBSTONE` | BEGIN_MAYBE_SENT or CANCEL_INTENT | Terminalize with reason `PRE_OFFER_CANCEL`. Keep the local P block |
| LOOKUP_RESULT `UNKNOWN` | BEGIN_MAYBE_SENT or CANCEL_INTENT | Block. After a local action, terminalize with reason `ABANDONED` and keep the local P block |
| LOOKUP_RESULT | any other state | Ignore |
| REFUSED | see the code table below | Apply the code. No promotion |
| any response | no matching in-flight request | Protocol error. Close the connection |

`REFUSED` handling for a target that is waiting on that request:

| Code | Target state | Action |
|---|---|---|
| `NO_ARM`, `MODE_MISMATCH` | BEGIN_MAYBE_SENT, OFFERED, DONE_MAYBE_SENT | Terminalize with reason `ABANDONED`. The source cannot complete this ceremony. No credential |
| `BUSY`, `CONFLICT`, `BAD_STATE`, `CAPACITY` | BEGIN_MAYBE_SENT, OFFERED, DONE_MAYBE_SENT | Terminalize with reason `ABANDONED`. The ceremony cannot complete. Report the code and keep the local P block |
| `STALE_EPOCH` | any | Block. Do not delete the record. QUERY may resolve |
| `RATE_LIMIT` | BEGIN_MAYBE_SENT | Retry only within the live begin resend budget. Otherwise terminalize |
| any code | ACTIVE, TERMINAL, CANCEL_INTENT | Ignore |

A `REFUSED` grants nothing. A target that terminalizes on a refusal must keep
its local P block so the P is never reused.

A matching PAIR_RESULT `COMMITTED` or an authenticated QUERY reporting ACTIVE can
promote only the exact OFFERED or DONE_MAYBE_SENT record if the tuple is still
eligible and no durable cancel intent exists. Promotion atomically terminalizes
the old local ACTIVE record, clears its credential and sessions, and writes the
new ACTIVE record. A result or query for another tuple never promotes, deletes,
or clears a different record.

Promotion by QUERY does not require a live arm, because the source has already
committed and the target already stored its own confirmed hash before the crash.
Sending PAIR_DONE does require a live arm. That distinction resolves the crash
case without letting a restart create a new consent.

The target does not become usable merely because the source committed. Until the
target has confirmed and durably promoted the same tuple, it does not open a
session for it.

### 7.3 Arming and removal fences in one table

| Fence | Value | Checked by | Reject effect |
|---|---|---|---|
| Source arming | `source_arm_id` and mode | BEGIN and PAIR_DONE | `NO_ARM` or `MODE_MISMATCH`; no mutation |
| Target arming | `target_arm_id`, mode, and the two resend budgets | BEGIN send, BEGIN resend, PAIR_DONE send and resend | local refusal; no send or no promotion |
| Source record | `I`, `P`, `source_epoch`, `target_epoch` | every source mutation and session | `CONFLICT` or `STALE_EPOCH`; no mutation |
| Target record | `I`, `P`, `source_epoch`, `target_epoch` | every target mutation and promotion | ignore or `STALE_EPOCH`; no promotion |
| Source removal | terminal state and record epochs | delayed DONE, CANCEL, FORGET, SESSION_OPEN | no effect on a new record |
| Target removal | terminal state, record epochs, and P block | delayed result, credential, session | no effect on a new record |

A local removal is a fence, not a hint. It writes the terminal state, clears the
arm, clears the credential, detaches sessions, and closes flows. The terminal
record keeps its epochs, so a duplicate for that exact record still resolves. A
new record gets new epochs, so a delayed frame with an older `I`, `P`, arm, or
epoch fails the exact checks.

## 8. Pairing operation order and cancellation

### 8.1 First pairing

1. The target arms locally and creates a fresh `P`, `begin_nonce`, and
   `target_arm_id`. It assigns the next `target_epoch`. It persists
   BEGIN_MAYBE_SENT with those values.
2. The target sends BEGIN with `I = 0` and that `target_epoch`.
3. The source checks its arm and mode. It creates a fresh `I`,
   `offer_nonce`, and `source_arm_id`. It assigns the next `source_epoch` and
   reserves PENDING with that immutable epoch. It persists the record, then
   sends OFFER with that `source_epoch`, the `target_epoch` from BEGIN, and the
   target arm and nonces.
4. The target verifies OFFER against its BEGIN. It persists the complete tuple as
   OFFERED and clears the arm. It computes `B` and obtains the human bootstrap
   confirmation.
5. The target persists the local confirm hash, then DONE_MAYBE_SENT, then sends
   PAIR_DONE with `bootstrap_hash`.
6. The source verifies the hash and consent, performs the commit transaction,
   and sends PAIR_RESULT `COMMITTED` after the commit is durable.
7. The target verifies the result, promotes the exact tuple, and clears the old
   active credential and sessions.

No person action is inferred from a network message. No record is written before
the step that requires it. No success is shown before the local durable state is
confirmed.

### 8.2 Lost OFFER

The target remains in BEGIN_MAYBE_SENT. It may resend the exact BEGIN with the
same `P`, `begin_nonce`, and `target_arm_id` while `T_ARM_LIVE` has a begin
resend budget and the deadline is live. The source returns the same OFFER with
`DUPLICATE = 1` for an exact duplicate. If the target has no resend budget or
has restarted, it must cancel the old P, or look it up, and start a new ceremony
with a new P. It must never reuse P.

### 8.3 Lost PAIR_RESULT

The target remains in DONE_MAYBE_SENT. It sends QUERY for the exact tuple. The
source returns the durable state:
- ACTIVE: the target may promote the exact tuple if it remains eligible, the
  hash matches, and it has no cancel intent.
- PENDING: the source did not commit. The target may resend PAIR_DONE only if a
  live arm still exists, or cancel.
- TERMINAL: the target terminalizes the local pending record and does not
  promote.
- UNKNOWN: unresolved. Block use and require a new ceremony or local forget. A
  timeout is not success.

### 8.4 Lost PAIR_DONE

The source stays PENDING. The target is DONE_MAYBE_SENT. The target may resend
the same PAIR_DONE with the same operation identity while a live arm exists. A
duplicate that the source already committed returns COMMITTED from the receipt
or the state-derived rule. A duplicate that arrives after the source terminalized
the record returns ABORTED. The target never creates a second commit by using a
new P.

If the target restarted, it has no arm. It must not resend PAIR_DONE. It sends
QUERY and applies section 7.2.

### 8.5 Pre-offer cancellation

This is the case where the target has sent BEGIN but has not received OFFER. It
may not know `I`. Cancellation must be durable before it is shown as a local
cancel.

1. The target persists CANCEL_INTENT with a fresh `operation_id`, `intent =
   PRE_OFFER`, its `P`, `begin_nonce`, `target_arm_id`, `target_epoch`,
   `expected_source_epoch = 0`, and the fingerprint of the exact request it will
   send. It clears its arm, blocks use, and detaches any session for this pending
   tuple. It keeps the record and the pending slot.
2. The target sends CANCEL with `I = 0`, the same `P`, `begin_nonce`,
   `target_arm_id`, `intent = PRE_OFFER`, `expected_source_epoch = 0`, and
   `expected_target_epoch` from BEGIN.
3. The source applies section 7.1.3. The cases are:
   - PENDING with the same P, nonce, and arm: terminalize with reason
     `PRE_OFFER_CANCEL`, write the receipt, return `REMOVED` with the record's
     `I`, epochs, and state.
   - ACTIVE for the pair: return `CONFLICT` with the current state. The source
     never removes an ACTIVE record from an `I = 0` request. The target does not
     need `I` to answer this: it already holds its own ACTIVE record for the
     pair, if any, and that is the only record it could name in a later exact
     request. If the source reports an ACTIVE record and the target has no
     local ACTIVE record, it cannot name it. It reports that the source holds a
     pairing this device does not have, blocks the tuple, and does not guess an
     `I`.
   - TERMINAL with the same P: return `ALREADY_REMOVED`.
   - A tombstone for the same P, nonce, and arm: return `REMOVED` with
     `tuple_state = TOMBSTONE` and `I = 0`.
   - A retained object with the same P and a different nonce or arm:
     `CONFLICT`. No mutation.
   - A PENDING record for the pair with a different P: `CONFLICT`. No mutation.
     The request cannot name that record.
   - No retained object and tombstone capacity available: write the tombstone
     and return `REMOVED` with `tuple_state = TOMBSTONE` and `I = 0`.
   - No retained object and tombstone capacity exhausted: return `RETRY_LATER`
     and write nothing.
   In every `PRE_OFFER` match, `expected_target_epoch` must equal the stored
   `target_epoch` of the record or tombstone. A mismatch is `CONFLICT` with no
   mutation.
4. A duplicate pre-offer CANCEL with the same `operation_id` and fingerprint
   returns the recorded result with `DUPLICATE`. A duplicate with a different
   operation ID but the same tombstone returns `REMOVED` with `STATE_DERIVED`
   and writes nothing. A later BEGIN that names the same `P`, with any
   `begin_nonce`, is `CONFLICT` and cannot create a reservation.
5. If the source is unreachable, the target remains in CANCEL_INTENT. It reports
   "remote removal is not confirmed" and never reports trust removal. A later
   authenticated connection retries the same operation ID and fingerprint. A
   matching OFFER or PAIR_RESULT received while in CANCEL_INTENT is ignored; it
   does not revive the ceremony or create a credential.
6. The target may resolve the local cancel after a local person action or a
   local policy deadline while retaining a durable local P block. That blocks
   any later promotion of that P. It does not prove the source removed its
   pending record. The source may retain a PENDING record until its own policy
   abandons or terminalizes it. That is a capacity denial, not a trust change.
7. A tombstone is retained across restart. It is never reused for a new
   ceremony. The tombstone table is bounded. Exhaustion refuses a new pre-offer
   cancel that would need a new tombstone with `RETRY_LATER`. It never refuses a
   BEGIN and never blocks local stop, local forget, or reading state.

### 8.6 Known, session, and stop generations

The candidate uses several different fences. They are deliberately not one
counter.

| Fence | Scope | Durable | Changes | What it rejects |
|---|---|---|---|---|
| `source_epoch` | one source record | yes | new source record at reservation | a different source record |
| `target_epoch` | one target record | yes | new target record at BEGIN persist | a different target record |
| `state_seq` | one record | yes | every record transition | a stale state report |
| `session_nonce` | one SESSION_OPEN and its retries | no | every request | a result applied to another request |
| `target_instance_nonce` | one target process | no | process start | a result from a previous process |
| `target_stop_seq` | one target process | no | every local stop | a result created before a stop |
| `source_instance_nonce` | one source listener | no | listener start | a target treating an old listener as current |
| `session_seq` | one source listener | no | every accepted registration | a result ordering mistake within one listener |

The known path is a SESSION_OPEN with `known = 1` against an ACTIVE record. It
requires the exact `I`, `P`, source and target epochs, current instance nonce, and
current stop sequence. It writes no pairing record and creates no new trust. It
registers one session under the active tuple. A local removal terminalizes the
record and detaches the session. A later known request fails `NOT_ACTIVE`.

A session is identified by
`(source_pin, target_pin, I, P, source_epoch, target_epoch, session_nonce)`. The
session table holds no token in the clear. A stop increments `target_stop_seq`,
clears the in-memory credential and session table, clears the pending request
map, and closes flows as one serialized local action. A result checks the pending
map and creates the credential under the same local lock. A late SESSION_RESULT
with an older stop sequence or instance nonce has no matching pending entry and
is discarded before it can create a credential. A process restart changes the
instance nonce, so all older results are stale by construction.

No durable stop counter is claimed. A crash discards all in-memory session and
credential state, which has the same effect as a stop for this protocol. If a
product requires a stop to survive a crash as a durable user-visible event, that
is a separate requirement and remains open.

### 8.7 Removal intents and what each side can confirm

Revision 2 mixed local removal, remote removal, and "trust removal" in one set of
words. This table separates them. No frame in this revision removes a record on
the target. A source-side removal is never claimed as confirmed on the target.

| Intent | Started by | First durable step | Wire request | Confirmed meaning | Never claimed |
|---|---|---|---|---|---|
| Pre-offer cancel | target | CANCEL_INTENT with request fingerprint | CANCEL `PRE_OFFER` | The source has no PENDING record for that P, or wrote a tombstone | That an ACTIVE record for the pair was removed |
| Exact cancel | target | CANCEL_INTENT with request fingerprint | CANCEL `EXACT` | The source terminalized that exact record | That a different record was affected |
| Forget | target | Local terminal, credential cleared, `remote_remove_pending = 1` | FORGET | The source terminalized or already had terminal state for that exact record | That the source removed its record when the result is `DENIED` |
| Local source forget | source | Terminal, sessions detached, arm cleared | none | Local only | That the target forgot the source |
| Local target forget | target | Terminal, credential cleared, sessions detached | optional FORGET | Local only | That the source forgot the target |
| Source-side removal seen by target | source action | none | none | Only a later `NOT_ACTIVE`, `TERMINAL`, or `UNKNOWN` result | That it was a person's removal rather than a lost record |

Rules:

1. A target local forget takes effect locally at once. It never waits for the
   source. The optional FORGET is a follow-up, not a precondition.
2. `remote_remove_pending` is cleared by any matching `REMOVED`,
   `ALREADY_REMOVED`, `DENIED`, or `CONFLICT` result, and by a local person
   action. It survives restart so the retry is possible.
3. A `DENIED` FORGET means the source kept its record because a session was
   registered. The target's local removal stands. The target reports that the
   source still holds the record. A new attempt needs a new `operation_id` and is
   allowed only after the flows are closed.
4. The target must show a record as "unverified" after a `NOT_ACTIVE`,
   `STALE_EPOCH`, or `UNKNOWN` result for its active tuple. It must not show
   "paired" from a stale local record alone.
5. A v2 forget cannot claim to revoke v1 token-only traffic. A v2 local forget
   does not delete the peer's record.

## 9. Receipts, duplicates, and current state

### 9.1 Operation identity

A mutation is identified by:

```
request_key =
  SHA-256("HotspotShade-v2-op-key\0" ||
          source_pin || target_pin || I || P || operation_id)
```

The request type is not in the key. It is in the fingerprint. Reusing an
operation ID for a different type or different fields therefore produces the
same key and a different fingerprint, which is `CONFLICT` when a receipt for
that key is retained. A source cannot prove that an operation ID was never used
if no receipt, record, or tombstone retains it. Honest targets never reuse an
ID. A reuse of a completely unrecorded ID is indistinguishable from a new
request; this is a documented limit, not a proof of uniqueness.

For PAIR_DONE the operation identity is `P`, so `operation_id` in the key is
`P`. For CANCEL and FORGET it is the explicit `operation_id`. BEGIN uses `P` and
`begin_nonce`; it is idempotent by the record, not by a separate receipt. BEGIN
never reads or writes a receipt slot.

The request fingerprint is:

```
request_fp =
  SHA-256("HotspotShade-v2-op-fp\0" || frame_without_tag)
```

The frame includes the length, type, pins, I, P, suffix, and reserved bytes. It
excludes the tag. The key and fingerprint are stored as 32 raw bytes.

### 9.2 Fixed receipt slots and matching

There is no unbounded receipt table. Each record carries three kinds of slot:

- One `last_request` slot: the last mutation receipt for the record.
- One `terminal_request` slot: the operation that terminalized the record.
- Four `denial_receipts`: one per completed `DENIED` result.

Revision 2 named `terminal_request` in the duplicate rules but omitted it from
the record schema. Revision 3 stores it.

Writing rules:

- A successful or state-changing mutation writes `last_request` in the same
  transaction. If it terminalizes the record because of a CANCEL, FORGET, or
  local removal, it also writes `terminal_request` with the same operation. Both
  slots then hold the same key and fingerprint.
- A record terminalized as a side effect of another operation, with reason
  `SUPERSEDED`, gets no `terminal_request`. Its own `last_request` is unchanged,
  so a duplicate of its original request resolves from that slot or by state.
- A `DENIED` result writes one denial slot in the same transaction. It writes no
  `last_request`, because no state changed.
- A `CONFLICT`, `RETRY_LATER`, `REFUSED`, `STATE_DERIVED`, or read-only result
  writes no slot.
- A local removal writes `terminal_request` with `request_type = 0`,
  `operation_id` from local randomness, `request_fp = 0`, and the terminal
  result. No wire request can match it.
- No slot is ever evicted to make room for a new ceremony. A new ceremony is a
  new record with fresh slots.

Matching rules:

1. Compute the request key and fingerprint.
2. Search `terminal_request`, then `last_request`, then the denial slots in
   index order. The terminalizing operation may appear in both `last_request`
   and `terminal_request` with the same fingerprint. No key may appear with two
   different fingerprints.
3. The first used slot with the same key decides. If the fingerprint matches,
   the result is a duplicate and the recorded result is returned. If it differs,
   the result is `CONFLICT` and `CONFLICT` is returned.
4. A slot whose `request_type = 0` is never matched by a wire request.
5. If no slot matches, the request is new and section 7 decides it.

A fifth denial is refused `RETRY_LATER` with no mutation. The person can still
use local removal. A record at the namespace record cap refuses a new ceremony
with `CAPACITY`. Slot exhaustion on an existing record never refuses a new
ceremony, because a new ceremony uses a new record.

The worst-case receipt storage is the record cap times six slots per record.
There is no global receipt map and no cache that can evict a trust record.

### 9.3 Duplicate rules

For every mutation response the `result` field is the outcome of the named
request. The `tuple_state` and `state_seq` fields are the current durable state
of the named record at response time. The `source_epoch` and `target_epoch`
fields are the named record's immutable epochs. `current_source_epoch` is the
newest retained source epoch for the pair. These may differ from the state after
the original request if a later operation changed the record. This is the
unambiguous current-state rule.

| Case | Response | Flags | Mutation |
|---|---|---|---|
| Exact request key and fingerprint match a slot | The recorded result, plus current state, epochs, and `state_seq` | `DUPLICATE`, plus `TERMINAL_RECEIPT` if the terminal slot matched | none |
| Same key, different fingerprint | `CONFLICT`, current state | none | none |
| No receipt, PAIR_DONE for the ACTIVE exact record with a full match | `COMMITTED`, current state | `STATE_DERIVED` | none |
| No receipt, PAIR_DONE for a TERMINAL exact record with a tuple match | `ABORTED`, current state | `STATE_DERIVED` | none |
| No receipt, CANCEL or FORGET for a TERMINAL exact record with a tuple match | `ALREADY_REMOVED`, current state | `STATE_DERIVED` | none |
| No receipt, CANCEL `PRE_OFFER` matching a tombstone with a different operation ID | `REMOVED`, tombstone state | `STATE_DERIVED` | none |
| No receipt, FORGET for ACTIVE with a session | `DENIED`, current state | none | none; write denial slot |
| No denial slot available for a new `DENIED` | `RETRY_LATER`, current state | none | none |
| Different I or P for the same pair | `CONFLICT`, current state of the named tuple or UNKNOWN | none | none |
| Frame epochs differ from the named record | `STALE_EPOCH` or `CONFLICT` per the type rules | none | none |

A `DENIED` result is never sent before its denial slot is durable. A
`RETRY_LATER` result is not a denial and does not consume a slot. A `CONFLICT`
does not consume a slot. A state-derived result does not write a new receipt;
the terminal or active record is the durable basis, and the result is
deterministic for that state. A read-only QUERY or LOOKUP does not consume a slot
and does not freeze state; each response reports its own locked read.

#### 9.3.1 What a state-derived result must match

Revision 2 allowed a state-derived `COMMITTED` for "the currently ACTIVE exact
I and P". That would let a frame with a wrong hash, wrong arms, wrong nonces, or
wrong epochs receive `COMMITTED` from the record alone. It would then be a
protocol-level success for a ceremony that never happened in full.

Revision 3 defines three predicates against a stored record:

- `tuple_match`: `source_pin`, `target_pin`, `I`, `P`, `begin_nonce`,
  `target_arm_id`, `offer_nonce`, `source_arm_id`, and `mode` all equal the
  record.
- `epoch_match`: `source_epoch` and `target_epoch` equal the record.
- `hash_match`: the frame `bootstrap_hash` equals the record's nonzero
  `bootstrap_hash`.

A state-derived result requires all three, with one exception. For a TERMINAL
record whose stored hash is zero, `hash_match` is replaced by "the frame hash is
any value", because the record was terminalized before any hash existed and the
answer grants nothing.

Therefore:

- `COMMITTED` from state requires a full ceremony match, including a nonzero
  equal hash. A wrong hash is `CONFLICT`, never `COMMITTED`.
- `ABORTED` from state requires `tuple_match` and `epoch_match`, and a hash that
  is zero in the record or equal to the frame hash.
- `ALREADY_REMOVED` from state requires `tuple_match` and `epoch_match`.
- A frame that fails any of these is `CONFLICT` with no mutation.

The receipt path is stronger still: the fingerprint covers every frame byte, so
an exact slot match is a byte-exact replay.

In a correct store the commit receipt is present, so a duplicate commit is
answered by the receipt path. The state-derived `COMMITTED` rule covers a record
that is ACTIVE while its commit slot is missing. Section 9.2 treats a missing
mandatory slot as a store defect and section 11.3 blocks on it, so the rule is a
defensive fallback, not a normal path. It is still exact, so a host that stores
fewer receipts can never get a permissive answer. The reachable state-derived
cases in this revision are the terminal ones: `ABORTED`, `ALREADY_REMOVED`, and
the tombstone `REMOVED`.

Example of the current-state rule. A first PAIR_DONE for I1 returns `COMMITTED`,
state ACTIVE. Later I2 is promoted and I1 is TERMINAL. A duplicate PAIR_DONE for
I1 returns the historical result `COMMITTED`, state TERMINAL, I1's epochs, I1's
current `state_seq`, I1's `current_source_epoch` (I2), and flags `DUPLICATE`. The
target must not treat the historical `COMMITTED` as current trust. It compares
`tuple_state`, `source_epoch`, and `current_source_epoch`, sees that I1 is
terminal or superseded, and does not open a session. This is why the result and
the current state are separate fields, and why PAIR_RESULT now carries
`current_source_epoch`.

### 9.4 Tombstones and their wire state

A pre-offer CANCEL can create a tombstone with no source record. Revision 2 had
no wire state for it, so a tombstone was reported as UNKNOWN, which section 10
also uses for "no evidence at all". A target could not tell a durable block from
a miss.

Revision 3 adds `tuple_state = 5 TOMBSTONE` and these rules:

- A tombstone reports `I = 0`, `source_epoch = 0`, the stored `target_epoch`,
  `state_seq = 0`, a zero hash, the stored `begin_nonce` and `target_arm_id`, and
  zero `offer_nonce` and `source_arm_id`.
- `REMOVE_RESULT`, `LOOKUP_RESULT`, and a REFUSED for BEGIN may report
  TOMBSTONE. `QUERY_RESULT` and `PAIR_RESULT` cannot, because QUERY and
  PAIR_DONE name a nonzero `I` and a tombstone has none.
- A tombstone is retained across restart and is never reused for a new ceremony.
- The tombstone table is capped at 32 per namespace. The cap is not per pair.
- No tombstone is evicted. A full table refuses a new pre-offer cancel that
  would need a new tombstone with `RETRY_LATER` and writes nothing.
- A full table never refuses BEGIN, never blocks local stop, local forget,
  local cancel, or a read, and never changes trust.
- If the table is full but the exact tombstone already exists, the normal
  duplicate or state-derived answer applies.
- A delayed BEGIN with an unknown P may then reserve when no tombstone exists.
  That is a capacity denial, not a trust change, because the target has a
  durable local cancel intent and will never promote that P.

### 9.5 Capacity and local safety

The proposed caps are 8 target records, 16 source records, and 32 source
tombstones per namespace. Each record reserves space for its terminal transition
and its six receipt slots before a ceremony starts. The store also reserves one
terminal in-place transition per existing record.

When capacity is exhausted:
- A new BEGIN is refused `CAPACITY` with no record. Only the record cap can do
  this.
- A pre-offer cancel that needs a new tombstone is refused `RETRY_LATER`. Only
  the tombstone cap can do this.
- A remote mutation that needs a new denial slot is refused `RETRY_LATER`.
- A remote mutation that can be resolved by state is still answered; it does
  not need a new slot.
- A local stop, local cancel, local forget, local identity reset, status read,
  diagnostics read, and session close always proceed without a new remote
  receipt. A local forget writes the terminal state in place, clears credentials,
  detaches sessions, and closes flows. It never waits for the network.
- If the local store write is uncertain, the UI shows an unresolved local
  action and blocks trust use. It does not claim durable success. It does not
  restore an old trust record to make the message go away.

Capacity exhaustion can deny new pairings and remote administration. It cannot
grant trust, keep a removed record usable, or veto a local removal. The exact
caps and the user recovery path are product choices.

## 10. Reconciliation and query

QUERY is read-only. It names one exact `I` and `P` and carries a fresh
`query_id`. `I` must be nonzero. The source reads the durable record under its
lock and returns:

- PENDING, ACTIVE, or TERMINAL with the exact tuple, epochs, state sequence,
  bootstrap hash, and current source epoch.
- A PENDING record reports a zero `bootstrap_hash` until PAIR_DONE has supplied
  and the source has verified the hash. Zero is not a match and must not be
  accepted as one. ACTIVE reports a nonzero hash. TERMINAL reports the stored
  hash, which may be zero if the record was terminalized before any hash.
- UNKNOWN with zero hash and zero epochs if no record is retained. UNKNOWN never
  means removed, committed, or never existed.

Revision 2's companion vector showed a PENDING LOOKUP_RESULT with a nonzero
placeholder hash. That contradicted this rule. Revision 3 uses a zero hash for
every PENDING result and adds a matching vector. A zero hash in a PENDING result
is not a hash match and never authorizes promotion.

The target compares the query ID, pins, tuple, hash, epochs, and its own intent
under its lock. ACTIVE can resolve a lost PAIR_RESULT only for an eligible
non-canceled pending tuple whose stored hash is nonzero and equal.
TERMINAL resolves a cancel or removal intent but does not prove who removed it.
PENDING permits a canceled target to retry CANCEL, or an eligible target with a
live arm to retry PAIR_DONE. UNKNOWN, a hash mismatch, an inaccessible store, or
a contradictory response is unresolved: block use and require a new ceremony or local forget.

LOOKUP is a read-only recovery for a lost OFFER. It carries `P`, `begin_nonce`,
and `target_arm_id` with `I = 0`. The source searches retained records and
tombstones for the authenticated pin pair. The match is exact on all three
fields. It returns:
- PENDING with the found record's `I`, complete tuple, zero hash, and state.
- ACTIVE or TERMINAL with the found record's `I` and stored hash. A target in
  BEGIN_MAYBE_SENT must not adopt either; it never confirmed the ceremony.
- TOMBSTONE with `I = 0` and the stored tombstone fields.
- UNKNOWN if no exact match exists, including a `P` match with a different
  nonce or arm.

LOOKUP does not create a record, consume a receipt, or require a new pairing
consent. It returns no hash for a PENDING record. LOOKUP authorization, rate
limits, and disclosure of retained history remain review gates. The candidate
bound is one LOOKUP per 500 ms per pin pair and 16 per connection. Excess
requests are answered with no frame and the connection is closed.

Neither a network timeout nor the absence of a response is success. A request
that may have reached the peer is resolved by an exact duplicate, QUERY, or a
local block, never by inferring the peer's state.

## 11. Store commit, crash recovery, and rollback

### 11.1 Single durable transaction

A host must demonstrate a single-writer lock across processes, atomic recovery
to a complete old or new transaction, integrity and confidentiality as needed,
and documented durable ordering for data and metadata. A local transaction has
one commit point: the atomic replacement of the validated store. Read-back is
not durability. A success response, promotion, or durable removal claim follows
only a confirmed durable commit.

The candidate transaction protocol is:

1. Take the store lock. Validate the current store and anchor with section 11.3.
   Reject or block on any mismatch.
2. Build the new store with `store_seq = old_seq + 1`, a fresh `txid`,
   `previous_seq = old_seq`, and `previous_digest = digest(old_store)`.
3. Write a temporary file in the same directory. Flush it with the host's
   documented file-flush operation. Atomically replace the named store. Flush
   the parent directory where the host documents a directory flush.
4. Update the anchor to the new `store_seq` and `store_digest`. Flush it.
5. Release the lock. Send the response only after steps 3 and 4 are confirmed or
   after the recovery rule accepts the store as the new committed state.

No network flush, TLS write, socket write, or peer wait is inside the lock. A
local durable flush may hold the store lock but never the session-table lock.

### 11.2 Anchor

The anchor is a second durable location, separate from the store, containing:

```
namespace_id[16], identity_pin[32], store_seq u64, store_digest[32]
```

`store_digest = SHA-256("HotspotShade-v2-store\0" ||
canonical_store_without_tag)`. The store tag is
`HMAC-SHA256(store_key, "HotspotShade-v2-store-tag\0" ||
u32be(len(canonical_store_without_tag)) || canonical_store_without_tag)`.
`store_key` is a static per-namespace key held in the host's protected key
store. It is not derived from the identity signing key, so a signing-key-only
fixture cannot produce a valid tag. The tag detects modification. It is not a
general anti-rollback device and not a replacement for the anchor. It cannot
detect a rollback that includes the anchor and the store together. It cannot
detect a whole-device snapshot restore. No platform API in this candidate is
assumed to provide a monotonic counter that survives such a restore.

The anchor update is a second resource. The recovery table makes an interrupted
anchor update safe on paper. It does not make the two writes atomic. A missing,
unreadable, or mismatched anchor blocks use.

### 11.3 Recovery table

| Observed state | Decision |
|---|---|
| Lock unavailable | BLOCKED. No trust use and no mutation. |
| Store and anchor both absent | First run. Create a new namespace only through an explicit local identity action. Do not infer trust. |
| Store absent, anchor present | BLOCKED. Do not create a replacement store and do not auto-repair. |
| Store present, anchor absent | BLOCKED. Do not recreate the anchor from the store; that would erase the rollback check. |
| Store tag invalid or format wrong | BLOCKED. |
| `namespace_id` or `identity_pin` differs from the anchor | BLOCKED. |
| `store_seq == anchor_seq` and digest matches | OK. Use the store. |
| `store_seq == anchor_seq + 1`, `previous_seq == anchor_seq`, store tag valid, and `previous_digest == anchor_digest` | The store was committed and the anchor update was interrupted. Rewrite the anchor to the store value and flush. If that write fails, BLOCKED. This is a candidate recovery rule, not a platform guarantee. |
| `store_seq < anchor_seq` | BLOCKED. A store rollback is possible. |
| `store_seq > anchor_seq + 1` | BLOCKED. An anchor rollback, a lost anchor write, or corruption is possible. |
| Digest mismatch at equal sequence | BLOCKED. |
| Any write, flush, rename, or anchor update returns an uncertain result | BLOCKED. Retain in-memory intent, stop affected flows, send no success, reopen and validate, then reconcile. Do not assume old or new. |
| Recovered store is old | Apply a still-authorized durable intent if one exists, or require the person to act. Do not invent a lost action. |
| Recovered store is new | Use the stored receipt and state. Do not reapply the mutation. |
| Corrupt, ambiguous, missing, locked, or inaccessible | BLOCKED. Report the fixed damage or unreadable message. Do not delete, repair, re-pair, or fall back to unkeyed state. |

A crash can lose an intent before its durable commit. The person is told that
the cancellation or removal was not confirmed. No remote cleanup is guaranteed
without another durable witness. Restart cannot infer an unrecorded user action.

A pending consent is not an intent to commit. A recovered PENDING record with
`consent_present = 1` still needs a live arm, and no arm survives a restart.
Section 5.5 is the consent table.

### 11.4 Partial and full rollback

Partial rollback means one record, one field, one store generation, or one
anchor is restored without the other. The store-wide tag and digest detect a
changed store if the attacker cannot recompute them. A `store_seq` below the
anchor is refused. A sequence above the anchor by more than one is refused. A
mismatched namespace or identity pin is refused. The affected peer stays blocked
until a person performs an explicit identity reset or re-pair. No automatic
winner is chosen.

Full rollback means the store, anchor, key, and identity are restored together
to an earlier valid era. This candidate does not detect it. A previously paired
source and target can appear current again, including a record the person
forgot after that era. Random `I`, HMAC tags, a second ordinary file, and local
counters do not detect this. A witness that is independently non-rollbackable is
not established on any supported host. Do not claim one.

An identity reset creates a new namespace and a new key. It invalidates the old
namespace credentials and sessions on the local host. It cannot retroactively
revoke an offline peer's copy. The peer sees a new pin and needs a new ceremony.
The old record remains until the peer removes it. The exact user experience and
platform cleanup are open.

## 12. Per-platform durability requirements

No property in this table is established. The table states what a host must
demonstrate before v2 can be approved there. API names do not prove crash
behavior. Each row needs fault injection at every boundary in section 11 and a
restart from the same durable state.

| Host | Candidate store and lock | Candidate key and anchor | Not assumed | Required evidence |
|---|---|---|---|---|
| macOS | Single file in a user or root-owned directory, temporary file, file flush, atomic rename, parent directory flush; `flock` or an equivalent single-writer lock | Identity and store key in Keychain; anchor in a separate root-owned or protected file | That APFS, a particular volume, or a directory flush has the claimed crash behavior; that Keychain and file updates are atomic together | Crash injection before and after each flush and rename, anchor interruption, two-process lock test, restore test |
| Linux | Single file, `fsync` on file and directory, atomic rename; `flock` or `fcntl` lock; root helper owns the private store | Identity and store key in a root-only file or protected key store; anchor in a separate root-owned file | That the filesystem, overlay, container, or power-loss behavior matches the API; that NFS or a shared volume is safe | Same injection, plus helper restart, ownership, and filesystem matrix |
| Windows | Single file, `FlushFileBuffers` on the temporary file, `MoveFileExW` with replace and write-through; named mutex or file lock | Identity and store key protected with DPAPI or an equivalent protected store; anchor in a separate protected file | That Windows has a documented directory flush; that antivirus, indexing, or a filter driver cannot change ordering | Same injection, plus filter-driver and reboot tests |
| iOS | One SQLite database in the app container with WAL and the strongest documented synchronous mode; one writer actor | Identity and store key in Keychain with a documented accessibility class; anchor in a separate Keychain item | That SQLite WAL and Keychain updates are atomic together; that app suspension, process death, or a locked Keychain preserves the required order | On-device crash and suspension matrix after separate authorization; no emulator result counts |
| Android | One SQLite database in the no-backup directory with WAL and the strongest documented synchronous mode; one writer | Identity and store key in Android Keystore; anchor in a separate protected preference or database | That OEM storage, Keystore availability, app standby, or process death preserves the required order; that `SharedPreferences.commit` is a durable transaction | On-device crash, Keystore, and OEM matrix after separate authorization; no emulator result counts |

Common requirements:

- One writer per store. If two processes can open the store, the host must show
  a working exclusive lock or the app must use one process.
- The identity key and store key are not updated in the same transaction as the
  record store. They are static for a namespace. A key loss blocks use; it never
  falls back to an unkeyed store.
- A failed or uncertain store write blocks trust use and mutation. It does not
  delete records.
- An anchor-free mode could be proposed, but this candidate does not approve it.
  Without an anchor, a store-only rollback to an older valid store is easier and
  is not detected. That mode needs a separate review and is not authorized here.
- A host that cannot demonstrate a single durable commit point is not approved
  for v2, regardless of API availability.

## 13. Adversarial orderings with deterministic outcomes

These outcomes are conditional on the durable transactions and assumptions
above. They are requirements for fault injection, not test results. Each row has
one expected outcome. A run that produces a second outcome is a defect in the
design or the implementation, not an acceptable variant.

| # | Ordering | Expected durable outcome | Observable trace |
|---|---|---|---|
| A1 | Old FORGET for I1 after source promotion of I2 | I2 and its pending record survive. Old request returns CONFLICT. | Exact I/P check; store before and after |
| A2 | Old CANCEL for I1 after target promotion of I2 | Target ignores the result for I1. I2 credential and sessions unchanged. | Target epoch, I/P, credential dump |
| A3 | PAIR_DONE for I1 after source local removal of I1 | Source stays TERMINAL. Result ABORTED with `STATE_DERIVED` if the tuple matches. No record is recreated. | Terminal record and no new ACTIVE |
| A4 | Local removal wins a race with PAIR_DONE | Source terminal. Delayed DONE gets ABORTED. If DONE wins first, the new ACTIVE is terminalized by the removal. | Store transaction order and both results |
| A5 | Target cancel wins a race with source commit | Source PENDING terminal. DONE gets ABORTED. If commit wins first, CANCEL terminalizes the new ACTIVE and detaches its sessions. | Source state and session table |
| A6 | Pre-offer CANCEL and a delayed BEGIN for the same P, either order, tombstone capacity available | If the CANCEL is handled first, a tombstone is written. If the BEGIN is handled first, the PENDING record is terminalized. In both orders the later BEGIN is CONFLICT and no reservation exists at the end. | Tombstone or terminal record; later BEGIN result |
| A7 | Pre-offer CANCEL handled before a delayed BEGIN, tombstone table full | `RETRY_LATER`, no mutation. A later BEGIN with the same P may reserve. The target's local P block still prevents promotion. | Tombstone count unchanged; later BEGIN result |
| A8 | Pre-offer CANCEL reaches a source with ACTIVE I2 for the same pair | `CONFLICT` with I2's state. I2 unchanged. The target resolves its local cancel and does not remove I2. | ACTIVE unchanged; result fields |
| A9 | Two ceremonies for the same pin pair | First durable reservation owns PENDING. Second BEGIN with a different P returns BUSY. | One PENDING record; two frame traces |
| A10 | Duplicate PAIR_DONE after restart | Receipt or state-derived COMMITTED with a full match. No second promotion, no second session detach. | State sequence unchanged; one receipt |
| A11 | Duplicate DENIED FORGET after sessions close | Returns DENIED from the denial slot. It does not become REMOVED under the same operation ID. A new operation ID is a new attempt. | Denial slot and result |
| A12 | Denial slots are full | New remote FORGET returns RETRY_LATER, no mutation. Local removal still works. | Slot count; local terminal record |
| A13 | Known session after removal | SESSION_OPEN returns NOT_ACTIVE. No credential is created. | Session table empty; store terminal |
| A14 | Session registration races removal | Both take store lock then session lock. If removal wins, registration fails. If registration wins, removal detaches it. No removed-pin session survives. | Lock order; session count |
| A15 | Late SESSION_RESULT after stop and restart | The target's pending request map is cleared on stop and on restart. The result has no matching nonce. It is discarded. No credential. | Pending map empty; credential map; instance nonce |
| A16 | Crash before BEGIN persist | No BEGIN is sent. If the person had acted, the UI says the action was not confirmed. No source record. | No durable target record; no source frame |
| A17 | Crash after BEGIN persist before send | Restart has no arm. The target sends CANCEL PRE_OFFER or marks the record ABANDONED. It never resends BEGIN. No duplicate P. | Same P retained; no second BEGIN |
| A18 | Crash after OFFERED before PAIR_DONE | Target reconciles by LOOKUP or cancels. Source PENDING. LOOKUP returns it. A restarted target does not send PAIR_DONE. | OFFERED record; LOOKUP result |
| A19 | Crash after source commit before PAIR_RESULT | Source ACTIVE. Target DONE_MAYBE_SENT. QUERY returns ACTIVE and the target promotes if its stored hash matches. No second commit. | Source ACTIVE; one target promotion |
| A20 | Crash after target promotion before UI success | Target ACTIVE. Source ACTIVE. No acknowledgement is required. The UI reconciles from local state and QUERY. | Both ACTIVE; no extra record |
| A21 | Store and anchor mismatch | BLOCKED. No trust use, no mutation, no auto-repair. | Fixed damage message; store unchanged |
| A22 | Full store, anchor, and key rollback | Undetected by this candidate. An old record can appear current. Do not claim detection. | Recorded as a documented limit |
| A23 | v1 status, token, or discovery message | No effect on v2 trust, presence, timers, credentials, or sessions. No fallback. | v2 store diff empty; no v2 timer change |
| A24 | Zero-I request and its response | A REFUSED for BEGIN carries I = 0. A REMOVE_RESULT for a pre-offer cancel that matched only a tombstone carries I = 0 and state TOMBSTONE. Each parses and applies. | Frame hex; field check |
| A25 | Duplicate BEGIN that produced an OFFER | The replay is byte-identical except `flags = 1 DUPLICATE`. No new epoch, no second reservation. | OFFER flags; store diff empty |
| A26 | SESSION_OPEN retry with the same nonce on a second connection | If the first session is live, `BUSY` with `session_seq = 0`. If the first connection is gone, `ACCEPTED` with a new `session_seq`. Never two sessions for one nonce. | Session table row count |
| A27 | State-derived COMMITTED with a wrong hash | `CONFLICT`, not `COMMITTED`. No promotion, no receipt. | Result and flags |
| A28 | PAIR_RESULT for a superseded record | `current_source_epoch` names the newer record. The target does not promote and does not clear the newer credential. | Field compare; credential map |
| A29 | Same operation key with a different fingerprint | `CONFLICT`, no mutation, the stored slot is unchanged. | Key and fingerprint; slot bytes |
| A30 | Target restart with DONE_MAYBE_SENT | No PAIR_DONE is sent. QUERY promotes only with ACTIVE, a full tuple match, and an equal nonzero hash. | Frame trace; one promotion |
| A31 | Source local forget, then a target session attempt | SESSION_OPEN returns NOT_ACTIVE. No credential. The target reports the pairing as unverified. | Session result; target UI state |
| A32 | Source consent present, then a restart | PAIR_DONE returns NO_ARM. No promotion. A new ceremony is required. | Result; store unchanged |
| A33 | BEGIN with a `begin_nonce` from a retained terminal record | CONFLICT even with a new P. No reservation. | Result; store diff empty |
| A34 | FORGET for an ACTIVE record whose session just closed | The source evaluates the session table under the store lock. Exactly one of DENIED with a denial slot, or REMOVED with a terminal receipt, is returned. Both slots are never written. | Store transaction; result |

## 14. Test requirements

`INCARNATION_CANDIDATE_VECTORS.md` gives concrete frames, tags, bootstrap
hashes, and operation keys. A parser and tag implementation must match every
vector byte for byte, including every `frame` and `tag` pair and every negative
vector. `INCARNATION_CANDIDATE_TEST_PLAN.md` gives host-only and device-gated
rows for state transitions, crash boundaries, receipts, fences, rollback, and
v1 isolation.

The test plan distinguishes:

- `H`: can run on a host with loopback and mocks. It changes no route and creates
  no TUN device.
- `D`: needs a real device and a real hotspot. It needs the device owner's
  approval. No row is run for this revision.

A host pass says nothing about a phone. An emulator pass says nothing about a
device. A byte-vector pass says nothing about TLS exporter equality or durable
storage.

## 15. v1 isolation and unresolved product choices

V1 records, tokens, discovery, status, endpoints, and sessions are separate from
this v2 namespace. A v1 message cannot create, refresh, delete, or prove v2
trust, presence, credentials, or sessions. A v1 status cannot start, reset,
suppress, or trigger a v2 auto-stop timer, including at expiry. A v1 token is not
source authentication for v2. A v1 record is not v2 trust.

The candidate does not select any of these product choices. They remain
unresolved and are not authorized by this document:

1. Whether v1 and v2 coexist at all, and for how long.
2. Whether a v1 listener or v1 proxy remains enabled during migration.
3. Whether v1 token-only sessions and diagnostics are stopped, warned, or left
   usable outside v2 guarantees.
4. Whether a failed v2 connection may fall back to v1. This candidate forbids
   silent fallback; a product decision is still required.
5. Whether v1 is removed in the same release or a later release.
6. The exact user warning for a legacy v1 record and the exact re-pair flow.
7. Whether SAS ships, whether QR ships, and which side displays the QR.
8. Whether a known session needs a local tap.
9. The record caps, tombstone cap, denial-slot cap, and the user recovery path
   when capacity is exhausted.
10. Whether a stop must be durable across a crash, or only clear in-memory
    state.
11. Whether an anchor is mandatory on every host, and what the user sees when
    it is missing.
12. The identity reset user experience and what happens to old peer records.
13. The ALPN labels, certificate template, and TLS stack choices, which are
    inherited from the main design and are not re-approved here.
14. The proxy credential format and whether a token is retained at all.
15. How a target presents "unverified" after a NOT_ACTIVE result, and when the
    person may forget the local record.
16. Whether a target forget sends the optional FORGET automatically or only on
    an explicit person action.

A v2 forget cannot claim to revoke v1 token-only traffic. A v2 record cannot be
created from a v1 pin. A v1 peer that presents an old pin is an unknown v2 peer
and needs a new ceremony.

## 16. Remaining blockers

This candidate is not ready for implementation or release. The following
blockers remain:

1. **Bootstrap proof.** The human channel, QR display surface, SAS code
   comparison, consent actions, deadlines, and anti-relay properties need a
   separate reviewed design. This document defines bytes, not proof.
2. **Exporter equality.** Rust, Swift Network.framework, and Android Conscrypt
   must produce the same 32-byte exporter on one session, and each stack must
   expose it after a resumed handshake or use a full handshake. No measurement
   is recorded here.
3. **Source authentication for the proxy.** The mutual TLS session frame is
   specified, but the credential format, the inner data frame, and the exact
   proxy handshake are not. A v1 token path cannot satisfy it.
4. **Durable store per host.** Every row in section 12 is unverified. Reading an
   API name is not evidence of crash behavior.
5. **Anchor and rollback.** The recovery table is a candidate rule. The anchor
   update is not atomic with the store. Full rollback is undetected. No platform
   guarantee is claimed.
6. **Arming and cancellation.** The source tombstone cap, the target's local
   cancel resolution, and the remote cleanup guarantee need product decisions
   and fault injection.
7. **Receipts and capacity.** The fixed slots and caps are proposed. The user
   recovery path for exhaustion needs review.
8. **Known and stop generations.** The in-memory instance and stop fences are
   sufficient only if the host proves that no older result can survive a
   restart. That proof is still needed.
9. **Timers and auto-stop.** The v2 timer state machine is not specified here.
   It must reject v1 and stale input and must not use a v2 message from another
   incarnation.
10. **v1 coexistence.** Every item in section 15 is unresolved.
11. **Independent review.** The mapping to review revision 2 must be confirmed,
    and a fresh review must accept or reject this revision before any protocol
    code.
12. **No authorization.** This document is UNAPPROVED. It does not authorize
    implementation, migration, device tests, or release.

## 17. Questions for the independent reviewer

1. Is the `I` policy in section 3.2 total for every request and every response,
   including a response to a zero-I request?
2. Does every result frame now carry enough state to make a tombstone, a
   terminal record, and a missing record distinguishable on the wire?
3. Are the BEGIN and PAIR_DONE decision orders total and free of a hidden case?
4. Does a state-derived result require the same fields as a live ceremony?
5. Does a restarted target ever create a new consent? If so, where?
6. Is a pre-offer cancel attributable to exactly one ceremony, including after
   a restart?
7. Is tombstone exhaustion kept separate from record capacity and denial-slot
   capacity in every section?
8. Does a lost SESSION_OPEN have exactly one deterministic outcome?
9. Is the removal intent table honest about what each side can and cannot
   confirm?
10. Are the receipt slots, their matching order, and their flags consistent
    between the schema, the duplicate table, and the vectors?
11. Are partial rollback, anchor interruption, and full rollback described
    without claiming a platform guarantee that is not demonstrated?
12. Is any sentence in this candidate an implementation authorization, a release
    claim, or a claim of measured behavior? If so, it is a defect.

## 18. Findings this revision could not map to the R2 brief

These contradictions were found in the revision 2 text. They were not in the
R2-1 to R2-14 topic list supplied with the task. They are listed so the reviewer
can confirm or reject the addition.

- **U1. The tag definition and the revision 2 vectors disagree.** Section 4 said
  the tagged `frame` starts at `version` and excludes the length prefix. The
  revision 2 vectors were computed with the length prefix included twice, once
  in the separate `u32be(frame_len)` and once inside `frame`. Every tag in the
  revision 2 companion file matched the second convention. Revision 3 keeps the
  stated definition and recomputes every tag. A test that copies a revision 2
  tag will fail, by design.
- **U2. `terminal_request` was used but not stored.** Section 9.3 matched
  against `terminal_request`, and section 3.3 defined `TERMINAL_RECEIPT`, but
  the record schema in section 6 had no such field. Section 6 now stores it.
- **U3. LOOKUP could not return the `I` it exists to recover.** Revision 2
  section 8.5 told the target to LOOKUP to learn `I`, but the `I` rule forbade a
  nonzero `I` in LOOKUP_RESULT and the result had no other field for it.
  Section 3.2 now sets the found record's `I` in LOOKUP_RESULT.
- **U4. A pre-offer cancel against an ACTIVE record pointed at a recovery that
  could not work.** The target cannot learn the ACTIVE record's `I` by looking
  up a different `P`. Section 8.5 now says the target already holds that record
  locally, or it does not name it at all.
- **U5. "Fixed slots exhausted" refused a new ceremony.** Section 9.2 said a
  new ceremony is refused when the fixed slots are exhausted, but a new ceremony
  uses a new record with empty slots. Only the record cap can refuse it. Section
  9.2 now separates record capacity from slot capacity.
- **U6. `session_seq` was on the wire with no definition.** Section 5.7 now
  defines its scope, its reset, and its zero value.
- **U7. The companion vectors used one value for both instance nonces.** That
  hides a swapped-field defect. The vectors now use independent values and the
  test plan adds a swap row.
- **U8. The PENDING LOOKUP_RESULT vector carried a nonzero placeholder hash.**
  That contradicted the zero-hash rule for a PENDING record. The rule already
  required zero; the vectors now comply. Both the QUERY_RESULT and LOOKUP_RESULT
  PENDING vectors carry an all-zero hash and are recomputed.
- **U9. `REFUSED` for BEGIN had no consistent `I`.** Revision 2's vector used a
  nonzero `I` while its own rule said BEGIN uses zero. Section 3.2 now fixes the
  response `I` per `request_type`, and the vector is recomputed with `I = 0`.
- **U10. `REMOVE_RESULT` could not report which request it answered.** The
  frame has `request_type`, but no rule said a pre-offer cancel that matched only
  a tombstone must use `I = 0`. Section 3.2 now states it.
