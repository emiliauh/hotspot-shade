# Pairing incarnation candidate: test plan

Status: **UNAPPROVED. Not run.** This plan is for independent review of
`INCARNATION_PROTOCOL_CANDIDATE.md` revision 3. It is a set of requirements, not
evidence. No row was executed. No device, emulator, route, TUN device, network
connection, or Python was used.

Rows marked `H` can run on a host with loopback, mocks, a fake device, and a
temporary store. They create no route and no TUN device. Rows marked `D` need a
real device and a real hotspot, and need the device owner's approval. A host pass
says nothing about a phone. An emulator pass says nothing about a device.

Revision 3 adds rows for the zero-I response encoding, the tombstone wire state,
the OFFER duplicate flag, the total BEGIN and PAIR_DONE decision orders, the
SESSION_OPEN retry and idempotence rule, the terminal and denial receipt slots,
the removal intent split, the consent crash states, and the PAIR_RESULT current
source epoch. It also adds deterministic traces in section L.

Every row names what to observe so a pass is evidence, not an opinion. Record
durable store bytes before and after, the exact frame hex, the result fields,
the lock order, the session table, and the UI state. Never record a private key,
a token, a full pin in a user-visible log, or a packet capture with personal
traffic.

Section L holds deterministic adversarial traces. Each trace lists every step
and the one expected outcome of each step. A run that produces a different
outcome is a defect. A trace is not satisfied by "no crash".

## A. Vectors, parser, and tag

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| V1 | Walk every `frame = ` and `tag   = ` pair in `INCARNATION_CANDIDATE_VECTORS.md` in order | 24 pairs. Each `frame` total equals `4 + frame_len + 32`. Each tag is the HMAC over the label, channel, direction, `u32be(frame_len)`, and the frame from `version` onward | Recomputed tag compare for all 24 | H |
| V2 | BEGIN fixed vector | Byte-exact frame and tag from section 3.1; `I = 0` | Full hex compare | H |
| V3 | OFFER first and duplicate vectors | Byte-exact; bit 0 of `flags` is 0 then 1 | Two comparisons; all other flag bits zero | H |
| V4 | PAIR_DONE fixed vector | Byte-exact | Full hex compare | H |
| V5 | PAIR_RESULT commit, duplicate, and state-derived ABORTED | Byte-exact; `current_source_epoch` is present and equals 1 | Three comparisons | H |
| V6 | CANCEL exact and pre-offer vectors | Byte-exact; exact has nonzero `I`; pre-offer has `I = 0`; both carry `begin_nonce` and `target_arm_id` | Two comparisons | H |
| V7 | FORGET vector | Byte-exact; `intent = 1`; nonzero `I` | Full hex compare | H |
| V8 | REMOVE_RESULT, REMOVE_RESULT tombstone, and REMOVE_RESULT pre-offer-pending | Byte-exact; the tombstone frame has `I = 0` and `tuple_state = 5`; the pending frame has nonzero `I` and `tuple_state = 3` | Three comparisons | H |
| V9 | QUERY and QUERY_RESULT ACTIVE and PENDING | Byte-exact; the PENDING frame has an all-zero hash and `state_seq = 0` | Three comparisons | H |
| V10 | SESSION_OPEN and both SESSION_RESULT vectors on channel 2 | Byte-exact; `source_instance_nonce` differs from `target_instance_nonce`; BUSY has `session_seq = 0` | Three comparisons; cross-channel rejection | H |
| V11 | LOOKUP and both LOOKUP_RESULT vectors | Byte-exact; LOOKUP `I = 0`; PENDING result carries the record's `I`; TOMBSTONE result carries `I = 0` | Three comparisons | H |
| V12 | REFUSED BEGIN and REFUSED PAIR_DONE vectors | Byte-exact; BEGIN refusal has `I = 0`, PAIR_DONE refusal has nonzero `I`, `operation_id = P`, epochs zero | Two comparisons | H |
| V13 | Every declared length off by one, with the correct tag recomputed over the changed length | Reject length before field use | Error code; memory flat | H |
| V14 | Every declared length off by one, with the original tag | Reject at tag verification | Error code | H |
| V15 | Every type with one trailing byte after the tag | Reject | Error code | H |
| V16 | Every type with a truncated tag | Reject | Error code | H |
| V17 | Unknown version, type, or enum | Reject after a valid tag | Error code; no state change | H |
| V18 | Nonzero reserved byte or bit | Reject after a valid tag | Error code | H |
| V19 | Undefined flag bit, or a flag the type forbids | Reject after a valid tag | Error code | H |
| V20 | `DUPLICATE` and `STATE_DERIVED` set together | Reject after a valid tag | Error code | H |
| V21 | Two frames in one TLS record | Parse both in order | Frame trace | H |
| V22 | One frame split across TLS records | Reassemble once | Byte-exact payload | H |
| V23 | Tag with wrong direction | Reject | Error code | H |
| V24 | Tag with wrong channel | Reject | Error code | H |
| V25 | Tag from another TLS connection | Reject | Error code | H |
| V26 | Pin in the frame differs from the TLS peer pin | Reject before state access | No store read; error code | H |
| V27 | Frame on the proxy channel with the pairing exporter | Reject | Error code | H |
| V28 | Exporter missing, short, or unavailable before the handshake | Fixed failure before any pairing frame | Error code; no prompt | H |
| V29 | Two peers compute the exporter | Equal 32 bytes on one loopback session | Byte compare inside the harness, never a log | H |
| V30 | Full handshake versus resumed handshake | Both expose the exporter and both pins are checked; if the stack cannot, it uses a full handshake or is not approved | Handshake kind, pin-check count | H |
| V31 | Distinct source and target epochs, arms, and instance nonces | Each field is parsed in its declared position. Swapped epochs give `STALE_EPOCH`; swapped arms or nonces give `CONFLICT`. Neither is accepted | Field values; result | H |
| V32 | A parser that receives a response with no matching in-flight request | Reject and close. No state change | Error code | H |

## B. Bootstrap, consent, and source authentication

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| B1 | SAS transcript fixed vector | `SHA-256(B)` equals the vector hash; code `100090` | Hash and code compare | H |
| B2 | QR transcript fixed vector | `SHA-256(B)` equals the vector hash; QR payload length 212; `B` length 451 | Hash and length compare | H |
| B3 | One field changed in `B` | Hash changes; PAIR_DONE with the old hash is `CONFLICT` | Hash compare; no promotion | H |
| B4 | Hash from another `P`, `I`, pin pair, epoch, arm, nonce, or mode | `CONFLICT`. No promotion | No promotion | H |
| B5 | Target confirms, source does not | No source consent. PAIR_DONE is `BAD_STATE`. No success | Both states; no active record | H |
| B6 | Source confirms a different code | No commit. Target remains pending. No success | Both states | H |
| B7 | QR payload changed by one byte | Rejected before PAIR_DONE. No record | Error; no promotion | H |
| B8 | QR payload replayed in a new ceremony | Rejected. New `P` and nonces required | Error; no record | H |
| B9 | QR displayed before the OFFERED record | Not this protocol. No payload is shown | UI trace | H |
| B10 | Expired local arm | BEGIN or PAIR_DONE refused. No record | Deadline and error | H |
| B11 | Target certificate pin differs from the scanned pin | Refused before proof | Error; no key use | H |
| B12 | Source server pin differs from the record | Target sends no session frame | No SESSION_OPEN; neutral message | H |
| B13 | Target client pin differs from the record | Source refuses before session registration | No session row; error | H |
| B14 | Mutual TLS with a substituted server certificate | Target rejects before SESSION_OPEN | No application byte | H |
| B15 | No SNI and no name check | Certificate has no SAN; client sends no SNI; pin is the only trust decision | Capture and certificate parse | H then D |
| B16 | Session source authentication | SESSION_OPEN accepted only with an exact active tuple and epochs under the source lock. SESSION_RESULT is returned only after registration. The target accepts it only with a matching pending nonce in the current instance and stop generation | Session row; result; target pending map | H |
| B17 | A token alone | Cannot authenticate a v2 session | No session accepted on token alone | H |
| B18 | Bootstrap transcript never in status, logs, or diagnostics | Grep of every output | No transcript, code, or full pin | H |
| B19 | Source consent durable, arm lost | Restart, then PAIR_DONE with the correct hash | REFUSED `NO_ARM`. No promotion. Consent remains in the store but cannot promote | Result; store unchanged | H |
| B20 | Source consent write uncertain | No result is sent. Recovery validates old or new. Consent is never assumed | Fault point; store | H |
| B21 | Target confirm hash written, then crash before DONE_MAYBE_SENT | Restart has OFFERED with a nonzero hash and no arm. No PAIR_DONE is sent. LOOKUP returns PENDING and the target cancels | Store; frame trace | H |
| B22 | Target crash after DONE_MAYBE_SENT | QUERY only. Promotion only from ACTIVE with a full match and an equal nonzero hash | Store; frame trace | H |

## C. Receipts, duplicates, and current state

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| R1 | First PAIR_DONE | `COMMITTED`, state ACTIVE, flags 0, `current_source_epoch = source_epoch`; exactly one promotion | Store diff; result | H |
| R2 | Exact duplicate PAIR_DONE after commit | `COMMITTED`, flags `DUPLICATE` only; no second promotion or session detach | Receipt slot; state sequence unchanged | H |
| R3 | Exact duplicate PAIR_DONE after a later removal | Historical result `COMMITTED`, current state TERMINAL, `current_source_epoch` names the newer record, flags `DUPLICATE`; no record change | Result fields; terminal record | H |
| R4 | Same PAIR_DONE key with a changed field | `CONFLICT`; no mutation; the stored slot is unchanged | Fingerprint compare | H |
| R5 | Duplicate FORGET with the same operation ID after `DENIED` | `DENIED` from the denial slot; no later removal under that ID | Denial slot; result | H |
| R6 | New FORGET operation ID after the session closes | Evaluated as a new request; may remove | New receipt; result | H |
| R7 | Duplicate CANCEL for a TERMINAL tuple with no retained receipt | `ALREADY_REMOVED`, `STATE_DERIVED`; no mutation | Current state; no mutation | H |
| R8 | Different `I` or `P` for the same pair | `CONFLICT`; the current state of the named tuple, or UNKNOWN when no such record exists | No mutation | H |
| R9 | Result frame reports an old record and a newer current source epoch | `source_epoch` is the old record; `current_source_epoch` is the newest record | Field compare | H |
| R10 | QUERY repeated with the same query ID | Both responses reflect their own locked read; no state freeze and no receipt | Query ID, state, sequence | H |
| R11 | QUERY for UNKNOWN | State UNKNOWN, zero hash, zero epochs. `current_source_epoch` is zero when no record is retained for the pair, and the newest epoch when another record exists. Not "removed" | Result fields | H |
| R12 | LOOKUP repeated | Read-only; same retained tuple, tombstone, or UNKNOWN; no receipt | Store diff empty | H |
| R13 | Denial slots full | New remote FORGET returns `RETRY_LATER`, no mutation; local removal still works | Slot count; local terminal record | H |
| R14 | Receipt write is uncertain | No result is sent; peer blocked; recovery validates old or new | Fault injection; no success | H |
| R15 | Record cap reached | New ceremony refused `CAPACITY`; existing trust unchanged; local actions work | Counters; store diff | H |
| R16 | Same operation ID reused for CANCEL and FORGET | Same key, different fingerprint; the second request is `CONFLICT`; no mutation | Key and fingerprint; result | H |
| R17 | `terminal_request` present after CANCEL and after FORGET | The terminal slot holds the exact operation. A duplicate sets `DUPLICATE` and `TERMINAL_RECEIPT` | Slot bytes; flags | H |
| R18 | `terminal_request` absent after supersession | Reason `SUPERSEDED`, no terminal slot. A duplicate for the old record is `ABORTED` with `STATE_DERIVED` | Slot bytes; result | H |
| R19 | Slot matching order | `terminal_request` is checked before `last_request`. When both hold the same terminalizing key, the result carries `DUPLICATE` and `TERMINAL_RECEIPT` | Slot assignment; flags | H |
| R20 | A local removal receipt | `request_type = 0`, zero fingerprint. No wire request can match it. A later CANCEL for that exact tuple is `ALREADY_REMOVED` with `STATE_DERIVED` | Slot bytes; result | H |
| R21 | A fifth denial | `RETRY_LATER`, no slot write. The four stored denials still answer their exact requests | Count; results | H |
| R22 | A state-derived result then the same frame again | First is `STATE_DERIVED` with no slot. The second is also `STATE_DERIVED`; state and bytes do not change | Store diff; flags | H |

## D. Arming, fences, and total decision tables

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| F1 | BEGIN while the source is unarmed | `REFUSED NO_ARM`, `I = 0`, no record | Result; store diff empty | H |
| F2 | BEGIN with the wrong mode | `REFUSED MODE_MISMATCH`; no record | Result | H |
| F3 | BEGIN while the target is unarmed | No frame is sent | No source frame; local UI | H |
| F4 | PAIR_DONE after the source arm expires | `REFUSED NO_ARM`; the PENDING record remains; no ACTIVE | Store; result | H |
| F5 | PAIR_DONE after a source process restart | `REFUSED NO_ARM`; no arm is restored | Store; result | H |
| F6 | PAIR_DONE with an old source arm ID | `REFUSED NO_ARM`; no promotion | Result | H |
| F7 | PAIR_DONE with an old target arm ID | `CONFLICT`; target does not promote | Both stores | H |
| F8 | Local source removal during a pending ceremony | Pending terminal; old DONE is `ABORTED`; a new BEGIN needs a new arm and new `P` | Store; result | H |
| F9 | Local target removal during a pending ceremony | Target terminal; old OFFER or result is ignored | Target store; no credential | H |
| F10 | Old FORGET for I1 after I2 is active | `CONFLICT`; I2 and its sessions unchanged | Store and session table | H |
| F11 | Old CANCEL for I1 after I2 is active | `CONFLICT`; I2 unchanged | Store | H |
| F12 | Old PAIR_RESULT for I1 after target promotion of I2 | Ignored; I2 credential unchanged. `current_source_epoch` also shows I1 is superseded | Target store and credential map | H |
| F13 | Removal closes only the matching tuple | Source A closes; source B stays byte-exact | Two session rows; one reset | H then D |
| F14 | Removal while a flow is live | Matching flow closes; no FIN claim; target sees truncation | Frame trace; inner reset | H then D |
| F15 | Removal with no session | Record terminal; the next session is refused | Store; session result | H |
| F16 | One source arm used for two different pin pairs | The first BEGIN reserves; the second pair's BEGIN gets `REFUSED BUSY` because the arm is consumed. No second PENDING | Two frame results; one PENDING record | H |
| F17 | Exact BEGIN retry with a resend budget | Same `P`, nonce, and arm returns the stored OFFER with `DUPLICATE = 1`; no new epoch | Two frame results; one reservation | H |
| F18 | Exact BEGIN retry with the resend budget at 0 | No BEGIN is sent. The target sends CANCEL `PRE_OFFER` on the next authenticated connection | Local refusal; frame trace | H |
| F19 | BEGIN with a new `P` while a PENDING record exists | `REFUSED BUSY`; the pending record is unchanged | Result; store | H |
| F20 | BEGIN with the same `P` and a different `begin_nonce` | `REFUSED CONFLICT` | Result; store | H |
| F21 | BEGIN with a new `P` and a `begin_nonce` from a terminal record | `REFUSED CONFLICT` | Result; store | H |
| F22 | BEGIN with a new `P` while an ACTIVE record exists and no PENDING exists | A new PENDING record is reserved; the ACTIVE record is unchanged | Two records; OFFER sent | H |
| F23 | BEGIN with a new `P` while only TERMINAL records exist | A new PENDING record is reserved | Store count; OFFER | H |
| F24 | BEGIN at the record cap | `REFUSED CAPACITY`; no record | Count; result | H |
| F25 | BEGIN at the arm `attempts` cap | `REFUSED RATE_LIMIT`; no mutation | Attempt count; result | H |
| F26 | BEGIN with a `begin_nonce` that collides with a tombstone for a different `P` | `REFUSED CONFLICT` | Result; tombstone unchanged | H |
| F27 | PAIR_DONE for an unknown `I` or `P` | `REFUSED CONFLICT`, `I` echoed, `operation_id = P`, epochs zero | Result | H |
| F28 | PAIR_DONE with an epoch that differs from the record | `REFUSED STALE_EPOCH`; no mutation | Result | H |
| F29 | PAIR_DONE for a PENDING record with a wrong `offer_nonce` | `CONFLICT`; no mutation | Result | H |
| F30 | PAIR_DONE for a TERMINAL record | `ABORTED`; no recreation | Result; store | H |
| F31 | Matching OFFER, then PAIR_DONE in the same process | The arm is still live after the OFFER. PAIR_DONE is sent once and accepted | Frame trace; arm state | H |
| F32 | PAIR_DONE resend while `done_resends_left > 0` | The source returns the recorded result with `DUPLICATE`. No second promotion | Result; store | H |
| F33 | PAIR_DONE resend with `done_resends_left = 0` | Local refusal. No frame is sent | Local refusal | H |
| F34 | PAIR_DONE after the source committed and the target is ACTIVE | Local refusal. The target does not send | Frame trace | H |

## E. Pre-offer cancellation and tombstones

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| C1 | Cancel after BEGIN, before OFFER | CANCEL_INTENT durable before any local cancel message; arm cleared; no session | Target store; frame trace | H |
| C2 | Pre-offer CANCEL reaches a source with PENDING | PENDING terminal; `REMOVED` with the record's `I`, epochs, and `state_seq`; `tuple_state = TERMINAL`; no promotion possible | Source store; result | H |
| C3 | Pre-offer CANCEL reaches a source with no record and tombstone capacity | Tombstone written; `REMOVED`, `I = 0`, `tuple_state = TOMBSTONE`; a later BEGIN with the same `P` is `CONFLICT` | Tombstone; later BEGIN result | H |
| C4 | Pre-offer CANCEL reaches a source with ACTIVE I2 | `CONFLICT`; I2 unchanged; no tombstone. The target resolves its local cancel and does not remove I2 | Store; result | H |
| C5 | Pre-offer CANCEL lost | Target remains CANCEL_INTENT; retries the same operation ID and fingerprint; no trust claim | Retry count; store | H |
| C6 | Source unreachable for the whole cancel | The target may complete the local cancel with a durable P block; reports remote removal unconfirmed; no promotion of `P` | UI text; target store | H |
| C7 | Tombstone table full, new `P` | `REMOVE_RESULT RETRY_LATER`; no tombstone write; local cancel still blocks promotion; a later BEGIN may reserve | Table count; target store; later BEGIN | H |
| C8 | Tombstone table full, exact tombstone exists | `REMOVED`; `DUPLICATE` for the same operation ID and fingerprint, `STATE_DERIVED` for a new operation ID. No write | Result; count | H |
| C9 | Delayed BEGIN with `P` after a tombstone | `CONFLICT`; no reservation | Source store | H |
| C10 | Delayed BEGIN with a different `P` after a cancel | Allowed only if the source is newly armed; it is a new ceremony, not a revival of `P` | Arm and store trace | H |
| C11 | Crash after CANCEL_INTENT persist before send | Restart retries the same operation ID; no duplicate `P` | Recovery; frame trace | H |
| C12 | Crash before CANCEL_INTENT persist | No local cancel is claimed; UI says not confirmed; the source may retain PENDING | No target intent; source store | H |
| C13 | LOOKUP after a lost OFFER, live arm | Returns the exact pending tuple and the record's `I`; no new record; zero hash. The target adopts the tuple and moves to OFFERED | LOOKUP result; target store | H |
| C14 | LOOKUP with a `P` match and a different nonce or arm | `UNKNOWN`; no record created. A later BEGIN with the same `P` is still `CONFLICT` | Result; later BEGIN | H |
| C15 | LOOKUP for a tombstone | `TOMBSTONE`, `I = 0`, stored `target_epoch`, zero offer and source arms, zero hash | Result; state rule | H |
| C16 | Second pre-offer CANCEL with a new operation ID | `REMOVED`, `STATE_DERIVED`; no second tombstone; the original `request_fp` is unchanged | Tombstone bytes | H |
| C17 | Pre-offer CANCEL with a zero `begin_nonce` or zero `target_arm_id` | Reject before state access | Error code | H |
| C18 | Pre-offer CANCEL with a nonzero `I` | Reject field rule | Error code | H |
| C19 | LOOKUP rate limit | The first LOOKUP in each 500 ms window is answered; excess is answered with no frame and the connection is closed | Frame count; error | H |
| C20 | LOOKUP after the record was terminalized | `TERMINAL` with the stored hash, which may be zero. The target does not revive it | Result; store | H |
| C21 | LOOKUP after a target restart, no arm | `PENDING` is returned, but the target does not adopt it. It cancels `PRE_OFFER` and reports an orphan. No credential | Target store; result | H |
| C22 | Pre-offer CANCEL with a wrong `expected_target_epoch` | `CONFLICT`, no mutation, even when the P, nonce, and arm match | Result; store | H |

## F. Sessions, retry, and stop generations

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| S1 | Known session with an ACTIVE record | `ACCEPTED`; one session under the exact tuple; no record write; `session_seq` starts at 1 | Session row; store diff empty | H |
| S2 | Known session with a PENDING record | `NOT_ACTIVE`; no session; `session_seq = 0` | Result | H |
| S3 | Known session after local removal | `NOT_ACTIVE`; no credential | Result; credential map | H |
| S4 | Known session with a wrong source or target epoch | `STALE_EPOCH`; no session | Result | H |
| S5 | Late SESSION_RESULT after a stop | Discarded by stop sequence; no credential | Stop sequence; credential map | H |
| S6 | Late SESSION_RESULT after process restart | Discarded by instance nonce; no credential | Instance nonce; map | H |
| S7 | Two concurrent SESSION_OPEN with the same nonce, first still live | The second returns `BUSY` with `session_seq = 0`; exactly one session | Session table | H |
| S8 | SESSION_OPEN retry with the same nonce after the first connection closed | `ACCEPTED` with a new `session_seq`; exactly one live session | Session table | H |
| S9 | Three failed attempts for one nonce | The target discards the entry, retires the nonce, creates no credential; a later result is discarded | Pending map; credential map | H |
| S10 | Session registration races removal | Store lock then session lock; no removed tuple survives; another tuple is unaffected | Lock trace; session count | H |
| S11 | Two pins, one removed | The removed pin's session closes; the other pin's bytes stay exact | Session table; payload | H then D |
| S12 | Stop during a live session | Session closes; no credential remains; a late result is discarded | Session table; stop sequence | H |
| S13 | Source listener restart | New source instance nonce; an old result is stale; `session_seq` resets | Instance nonce; result | H |
| S14 | Target restart with an ACTIVE record and no credential | Known path required; no proxy byte before SESSION_RESULT | Frame trace; store | H then D |
| S15 | SESSION_OPEN with `known = 0` | Reject. A first pairing cannot open a session | Error code | H |
| S16 | Session table full | `CAPACITY`, `session_seq = 0`; no existing session is evicted | Result; session count | H |
| S17 | Swapped target and source instance nonces in a result | The target discards it; no credential | Map; result | H |
| S18 | SESSION_OPEN for an ACTIVE record on the pairing channel | Reject at tag | Error code | H |

## G. Crash and durable recovery

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| D1 | Crash before BEGIN persist | No BEGIN sent; no source record; UI says the action was not confirmed | No frame; store | H |
| D2 | Crash after BEGIN persist before or after send | No arm after restart. The target cancels or abandons. It never resends BEGIN. No duplicate `P` | Store; frame trace | H |
| D3 | Crash after OFFERED persist | Restart has the exact tuple. LOOKUP recovers it. No new `P` | Store; LOOKUP | H |
| D4 | Crash after the confirm hash and after DONE_MAYBE_SENT | No PAIR_DONE is sent. QUERY promotes only from ACTIVE with a full match and an equal nonzero hash | Store; frame trace | H |
| D5 | Crash after source commit before PAIR_RESULT | Source ACTIVE; target DONE_MAYBE_SENT; QUERY resolves; one commit | Both stores | H |
| D6 | Crash after target promotion before UI success | Both ACTIVE; no extra record; UI reconciles | Both stores | H |
| D7 | Crash during source removal | Recovery validates old or new; no success on uncertainty; peer blocked until resolved | Store and anchor read; fault point | H |
| D8 | Crash during target removal | Same rule | Store and anchor read | H |
| D9 | Crash during receipt write | No result; recovery validates; no reapply | Receipt slot | H |
| D10 | Crash during the tombstone write | No result; recovery validates; either the tombstone exists with its `request_fp` or it does not | Tombstone bytes | H |
| D11 | Store replacement succeeds, anchor update fails | The recovery rule may complete the anchor only if `store_seq` is `anchor_seq + 1`, `previous_seq` is `anchor_seq`, and `previous_digest` matches. Otherwise BLOCKED. Record which happened | Store and anchor | H |
| D12 | Store replacement uncertain | BLOCKED; no old or new success claim | Fault point; UI | H |
| D13 | Store missing, anchor present | BLOCKED; no replacement store; no re-pair | Fixed message | H |
| D14 | Store tag invalid | BLOCKED; no delete, repair, or fallback | Fixed message | H |
| D15 | Store and anchor namespace differ | BLOCKED | Fixed message | H |
| D16 | Store identity pin differs from anchor | BLOCKED | Fixed message | H |
| D17 | Two writers | Exclusive lock or one-process design; the loser blocks without mutation | Lock trace | H |
| D18 | Network write blocked while a local flush holds the store lock | No session-table lock held; no deadlock | Lock trace; timeout | H |
| D19 | Local removal with a full receipt table | Proceeds; terminal write in place; no remote receipt needed | Store; UI | H |
| D20 | Local removal with an uncertain store write | No durable success claim; unresolved UI; trust blocked | Fault point; UI | H |
| D21 | Crash with `remote_remove_pending = 1` | The flag survives. The next authenticated connection retries the same operation ID and fingerprint | Store; frame trace | H |
| D22 | macOS or Linux file and directory flush matrix | Record actual crash behavior at each boundary. Do not assume a documented API guarantees it | Fault injection; restart | H then D |
| D23 | Windows replacement and flush matrix | Record actual crash behavior. Windows has no documented directory flush in this candidate. Do not assume one | Fault injection; reboot | H then D |
| D24 | iOS SQLite and Keychain matrix | Record actual crash, suspension, and locked-key behavior. If the required order is not demonstrated, v2 is not approved on iOS | On-device fault injection | D |
| D25 | Android SQLite and Keystore matrix | Record actual OEM crash, standby, and Keystore behavior. If the required order is not demonstrated, v2 is not approved on Android | On-device fault injection | D |
| D26 | Store present, anchor absent | BLOCKED; do not recreate the anchor from the store | Fixed message; store unchanged | H |

## H. Rollback

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| RB1 | Store rolled back one generation, anchor intact | BLOCKED | Store and anchor; fixed message | H |
| RB2 | Store rolled back several generations, anchor intact | BLOCKED | Same | H |
| RB3 | Anchor rolled back one generation, store intact | BLOCKED, unless the exact `store_seq == anchor_seq + 1` and previous digest rule applies; record which | Store and anchor | H |
| RB4 | Anchor rolled back several generations, store intact | BLOCKED | Same | H |
| RB5 | Store replaced with an older valid store and old tag | BLOCKED by sequence; if the sequence is forged, tag or anchor fails | Store bytes | H |
| RB6 | One record removed from the store | Store tag or digest mismatch; BLOCKED | Store bytes | H |
| RB7 | One record reordered or duplicated | Store tag or digest mismatch; BLOCKED | Store bytes | H |
| RB8 | One tombstone removed from the store | Store tag or digest mismatch; BLOCKED | Store bytes | H |
| RB9 | Store and anchor restored together | Not detected. Record the old record that appears; no claim of detection | Store, anchor, UI | H |
| RB10 | Whole device snapshot restored | Not detected. Record the old trust state; no claim of detection | Snapshot and UI | H then D |
| RB11 | Identity key restored with an older store | BLOCKED if the namespace or pin mismatches; otherwise the old record may appear. Do not infer trust | Key and store | H then D |
| RB12 | Identity reset | New namespace and key; old local records terminal; peer sees a new pin; no automatic trust | Store; peer result | H |
| RB13 | Old peer after local identity reset | Cannot use the old record; needs a new ceremony | Session result | H |
| RB14 | Store tag with only the identity signing key | No valid tag is produced; store is blocked | Fixed damage message | H |

## I. Capacity and local safety

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| L1 | Record cap reached on the target | New ceremony refused; no eviction; existing records usable | Count; result | H |
| L2 | Record cap reached on the source | New BEGIN refused `CAPACITY`; no eviction | Count; result | H |
| L3 | Tombstone cap reached | New pre-offer cancel gets `RETRY_LATER`; the target's local block remains; BEGIN is not affected | Count; target store; BEGIN result | H |
| L4 | Denial slots full | New remote FORGET gets `RETRY_LATER`; local removal works | Count; store | H |
| L5 | Local stop while the network is unreachable | Stop succeeds locally; no remote success claim; sessions close | Session table; UI | H |
| L6 | Local forget while the source is unreachable | Target record terminal; no remote claim; the old credential is unusable locally | Store; credential map | H |
| L7 | Local forget while a flow is live | Matching flow closes; no FIN claim; another pin is unaffected | Session table; payload | H then D |
| L8 | Status and diagnostics read at capacity | Read succeeds; no mutation; no secret in output | Response; grep | H |
| L9 | New pairing starts at the record cap | Refused before any durable reservation | Store diff empty | H |
| L10 | Capacity after local removal | The terminal record is retained; no eviction; a new pairing is still refused at the cap unless the cap has room | Store count; result | H |
| L11 | Slot exhaustion on one record, new ceremony for another pair | Allowed. A new ceremony uses a new record and is not refused by another record's slots | Store diff; result | H |
| L12 | Read and local action at every cap | Status, stop, cancel, forget, and identity reset all succeed. No remote receipt is needed | UI; store | H |
| L13 | Tombstone cap boundary at 31, 32, and 33 | 31 and 32 write; 33 returns `RETRY_LATER`; no eviction | Count; results | H |
| L14 | Record cap boundary at 15, 16, and 17 on the source | 15 and 16 reserve; 17 returns `CAPACITY` | Count; results | H |

## J. v1 isolation

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| I1 | v1 status before a v2 start | No v2 trust, presence, timer, or endpoint change | v2 store diff empty | H |
| I2 | v1 status during a v2 tunnel | No timer reset, suppression, or stop | Timer state; store | H |
| I3 | v1 status at v2 timer expiry | No effect | Timer transition | H |
| I4 | v1 token presented to v2 | Rejected; no session; no v2 record | Result; session table | H |
| I5 | v1 record present, no v2 record | Not v2 trust; no fallback | Result | H |
| I6 | v2 forget with a v1 peer connected | v1 traffic unchanged; v2 forget makes no v1 revocation claim | v1 flow; UI text | H then D |
| I7 | Failed v2 connection | No silent v1 fallback; fixed failure | Frame trace; UI | H |
| I8 | Discovery from a v1 peer | Does not name or create a v2 record | Store diff empty | H |

## K. Removal intent

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| X1 | Target local forget, source unreachable | Local terminal at once; credential cleared; `remote_remove_pending = 1`; UI says remote removal is not confirmed | Store; UI | H |
| X2 | Target local forget, source reachable, source record ACTIVE, no session | Follow-up FORGET returns `REMOVED`; the flag clears. If the source record was already terminal, the same request returns `ALREADY_REMOVED` and also clears the flag | Result; store | H |
| X3 | Target local forget, source has a registered session | FORGET returns `DENIED`; the flag clears; the local record stays terminal; the UI says the source still holds a record | Result; store | H |
| X4 | Retry after `DENIED` with the same operation ID | `DENIED` from the denial slot; no removal | Result; slot | H |
| X5 | Retry after `DENIED` with a new operation ID once flows are closed | May remove; a new receipt is written | Result; store | H |
| X6 | Source local forget, then a target session attempt | SESSION_OPEN returns `NOT_ACTIVE`; no credential; the target shows the pairing as unverified | Session result; UI | H |
| X7 | Source local forget, then a target QUERY | `TERMINAL`; the target does not infer who removed it. `UNKNOWN` is the answer only when the source retains no record at all | Result; UI | H |
| X8 | A source-side removal with no target request | The target never reports confirmed remote removal. It only reports an unverified tuple | UI; store | H |
| X9 | A v2 local forget with a v1 peer connected | No v1 revocation claim | v1 flow; UI | H then D |
| X10 | Removal of one source pin | Only the matching tuple closes. Another source pin is byte-exact | Session table; payload | H then D |

## L. Deterministic adversarial traces

Each trace is a fixed sequence. The expected column is the only acceptable
outcome for that step. The durable state column is checked after the last step
unless a step says otherwise. All traces are `H`. No trace changes a route or
creates a TUN device. No trace uses a real hotspot, a real phone, or a real
carrier.

### T1. Re-pair, then a delayed old result

| Step | Action | Expected |
|---|---|---|
| 1 | I1 pairs and commits | PAIR_RESULT `COMMITTED`, state ACTIVE, `current_source_epoch = 1` |
| 2 | I2 BEGIN, OFFER, PAIR_DONE, commit | PAIR_RESULT `COMMITTED`, state ACTIVE, `current_source_epoch = 2`; I1 is TERMINAL with reason `SUPERSEDED` |
| 3 | Replay PAIR_DONE for I1 | PAIR_RESULT `COMMITTED`, `tuple_state = 3`, `source_epoch = 1`, `current_source_epoch = 2`, flags `DUPLICATE` |
| 4 | Target applies step 3 | No promotion, no credential change, no session detach for I2 |
| 5 | FORGET for I1 | `CONFLICT`, `tuple_state = 3`; I2 unchanged |

Durable state: I1 TERMINAL, I2 ACTIVE, one credential, sessions for I2 only.

### T2. Pre-offer cancel, both arrival orders

Run A: the BEGIN is handled first.

| Step | Action | Expected |
|---|---|---|
| 1 | BEGIN for P1 reaches the source | PENDING reserved with I1 |
| 2 | CANCEL `PRE_OFFER` for P1 | Terminalizes I1; `REMOVED`, `tuple_state = 3`, `I = I1`, `state_seq = 1` |
| 3 | A delayed BEGIN for P1 | `REFUSED CONFLICT`; no reservation |

Run B: the CANCEL is handled first.

| Step | Action | Expected |
|---|---|---|
| 4 | CANCEL `PRE_OFFER` for P1 reaches a source with no record | Tombstone written; `REMOVED`, `tuple_state = 5`, `I = 0`, `state_seq = 0` |
| 5 | The delayed BEGIN for P1 | `REFUSED CONFLICT`; no reservation |

Durable state: run A ends with one terminal record. Run B ends with one
tombstone. Never both for the same `(P, begin_nonce, target_arm_id)`.

### T3. Tombstone capacity, then a delayed BEGIN

| Step | Action | Expected |
|---|---|---|
| 1 | Fill the tombstone table to 32 | Count is 32; no eviction |
| 2 | New pre-offer cancel for a new `P` | `RETRY_LATER`, `tuple_state = 4`, no write |
| 3 | Delayed BEGIN for that `P` with a live arm and record capacity | The source reserves PENDING. This is a capacity denial, not a trust grant |
| 4 | Target applies its local cancel | No credential. The target keeps a local `P` block. A session is never opened for that `P` |

Durable state: tombstone count 32, one PENDING record for the new `P` if step 3
ran, zero credentials.

### T4. Lost PAIR_RESULT

| Step | Action | Expected |
|---|---|---|
| 1 | PAIR_DONE commits at the source | Source ACTIVE, receipt written, PAIR_RESULT lost |
| 2 | Target sends QUERY | `QUERY_RESULT` ACTIVE, full tuple, nonzero hash equal to the target's stored hash, `current_source_epoch = source_epoch` |
| 3 | Target applies the query | Promotes. One credential. No second record |
| 4 | Target sends the same QUERY again | Same answer from a new locked read. No state change |

Durable state: one ACTIVE source record, one ACTIVE target record, one
credential.

### T5. Target restart with DONE_MAYBE_SENT

Common first steps:

| Step | Action | Expected |
|---|---|---|
| 1 | Target writes DONE_MAYBE_SENT, sends PAIR_DONE, then restarts before any result | Target has DONE_MAYBE_SENT, no arm |
| 2 | Target attempts to send PAIR_DONE | Local refusal. No frame is sent |

Run A, the source committed:

| Step | Action | Expected |
|---|---|---|
| 3 | Target sends QUERY | `ACTIVE`, full tuple, nonzero hash equal to the target's stored hash, `current_source_epoch = source_epoch` |
| 4 | Target applies the result | Promotes. One credential |

Run B, the source did not commit:

| Step | Action | Expected |
|---|---|---|
| 5 | Target sends QUERY | `PENDING`, zero hash |
| 6 | Target applies the result | Terminalizes locally and cancels. No credential. A new ceremony is required |

Durable state: run A ends with one target ACTIVE record. Run B ends with one
target TERMINAL record. Neither run creates a second source commit.

### T6. Lost SESSION_OPEN, retried while live, then after close

| Step | Action | Expected |
|---|---|---|
| 1 | Target sends SESSION_OPEN with nonce N on connection A | Source registers and replies `ACCEPTED`, `session_seq = 1` |
| 2 | Connection A stays open; target retries with N on connection B | `BUSY`, `session_seq = 0`. Exactly one session |
| 3 | Connection A closes; target retries with N on connection C | `ACCEPTED`, `session_seq = 2`. Exactly one live session |
| 4 | Target retries with N a fourth time after accepting a result | Local refusal. The nonce is retired. No third registration |

Durable state: no pairing record change. Session table holds one row at each
step, never two for N.

### T7. Denial slots full, then local removal

| Step | Action | Expected |
|---|---|---|
| 1 | Four FORGET requests with different operation IDs while a session is registered | Four `DENIED` results, four denial slots written |
| 2 | Fifth FORGET with a new operation ID | `RETRY_LATER`; no slot write; the four slots are unchanged |
| 3 | Local target forget | Succeeds at once. Terminal state written. Credential cleared. `remote_remove_pending = 1` |
| 4 | Duplicate of the first FORGET | `DENIED` from the slot; not `REMOVED` |

Durable state: target TERMINAL, four denial slots, no fifth slot.

### T8. A wrong hash or nonce never gets a commit result

| Step | Action | Expected |
|---|---|---|
| 1 | I1 commits with hash H | Record ACTIVE, commit slot holds the exact request |
| 2 | PAIR_DONE for I1 with hash H2 and every other field exact | The key matches, the fingerprint differs: `CONFLICT`. Not `COMMITTED`. No promotion, no receipt write |
| 3 | PAIR_DONE for I1 with `offer_nonce` B2 and hash H | The key matches, the fingerprint differs: `CONFLICT`. No mutation |
| 4 | Local source removal of I1 | I1 TERMINAL with a local `request_type = 0` receipt, so no wire key matches it |
| 5 | Replay the exact original PAIR_DONE for I1 | No receipt match. State-derived `ABORTED`, not `COMMITTED` |
| 6 | PAIR_DONE for I1 with a wrong `offer_nonce` after step 4 | `CONFLICT`. `tuple_match` fails, so the state-derived rule does not apply |

Durable state: I1 ACTIVE after step 1, TERMINAL after step 4. No step returns
`COMMITTED` for a frame that is not the exact original commit.

### T9. Consent present, source restarted

| Step | Action | Expected |
|---|---|---|
| 1 | Source reserves PENDING and the person confirms locally | `consent_hash` set, `consent_present = 1`, `state_seq` incremented |
| 2 | Source restarts | PENDING remains. No arm |
| 3 | PAIR_DONE with the correct hash arrives | `REFUSED NO_ARM`. No promotion |
| 4 | The person abandons the old record locally, then starts a new ceremony | The old record is TERMINAL with reason `ABANDONED`, which frees the pending slot. The new ceremony gets a new `I`, new arm, and new `source_epoch` |

Durable state: after step 3 the old record is PENDING with a stored consent hash
and no ACTIVE record. After step 4 it is TERMINAL with reason `ABANDONED`.

### T10. Zero-I responses

| Step | Action | Expected |
|---|---|---|
| 1 | BEGIN with `I = 0` reaches an unarmed source | REFUSED with `request_type = 11`, `I = 0`, `operation_id = P`, epochs zero |
| 2 | A target parser reads step 1 | Accepts the frame as a result. Applies `NO_ARM`. No state change |
| 3 | A pre-offer cancel reaches a source with no record | REMOVE_RESULT with `request_type = 4`, `I = 0`, `tuple_state = 5`, `state_seq = 0` |
| 4 | A target parser reads step 3 | Accepts the frame. Records the tombstone. No credential |

Durable state: no source record in step 1; one tombstone in step 3.

### T11. Operation key collision

| Step | Action | Expected |
|---|---|---|
| 1 | CANCEL with operation ID O | Processes. Receipt written with key K and fingerprint F1 |
| 2 | FORGET with the same operation ID O and the same pins, `I`, and `P` | Same key K, different fingerprint F2. `CONFLICT`. No mutation. The slot still holds F1 |
| 3 | CANCEL with operation ID O repeated | `DUPLICATE` from the slot with F1 |
| 4 | New FORGET with a new operation ID | New key. Evaluated normally |

Durable state: one receipt slot with F1, no FORGET receipt, record state
unchanged by step 2.

### T12. Duplicate BEGIN and OFFER replay

| Step | Action | Expected |
|---|---|---|
| 1 | Target sends BEGIN for P1, nonce B1, arm A1 | Source reserves PENDING, sends OFFER, flags 0 |
| 2 | Target resends the exact BEGIN | Source sends the same OFFER with flags `DUPLICATE = 1`. No new epoch, no new record |
| 3 | Target sends BEGIN with P1 and a new nonce B2 | `REFUSED CONFLICT`; no mutation |
| 4 | Target sends BEGIN with a new P2 and nonce B1 | `REFUSED CONFLICT`; no mutation |
| 5 | Target sends BEGIN with a new P2, new nonce B2, while the PENDING record exists | `REFUSED BUSY`; the PENDING record is unchanged |

Durable state: one PENDING record with P1 and B1, one `source_epoch`.

## M. Trace fields every row must record

For each row, record:

- The exact frame bytes for every request and result, or a hash of them if the
  trace is stored. Never store a token or private key.
- The `result`, `tuple_state`, `flags`, `source_epoch`, `target_epoch`,
  `state_seq`, and `current_source_epoch` from every result.
- The source and target durable state before and after: record key, state,
  `state_seq`, terminal reason, consent hash presence, receipt slot contents,
  tombstone contents, credential presence, session count.
- The store and anchor sequence and digest status, without the store key.
- The lock order: store lock, then session-table lock. No network write inside
  either lock.
- The UI state: success, unresolved, or failure. An uncertain write is never
  shown as success.
- The reset or close reason for every flow.

## N. What a pass does not prove

- A host pass does not prove a device, hotspot, or carrier behavior.
- A byte-vector pass does not prove exporter equality across stacks.
- A mock pass does not prove durable storage or power-loss behavior.
- A device pass on one OS does not prove another OS.
- A rollback test does not prove anti-rollback against a whole-device snapshot.
- A tombstone capacity test does not prove a real lease or a real disk bound.
- A v2 pass does not approve v1 coexistence, migration, or release.
- No row in this plan authorizes implementation or a device test.
