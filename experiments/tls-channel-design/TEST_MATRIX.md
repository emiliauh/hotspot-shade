# Interop and adversarial test matrix

Status: UNAPPROVED. Revision 13. This is a proposed test plan for
`DESIGN.md` revision 13. Revision 12 received NOT APPROVED in independent review
`f85c9263-fe81-425e-9a32-eb34bfbf3ed5`. This revision addresses selected
findings only; the other findings remain open. Nothing here was run. It is not a
claim of proof. Revision 13 has not had a fresh independent review. Do not run the device rows, do not
install an app on a phone, and do not start a live tunnel until that review
accepts the design and the device owner approves the work. No device, route,
tunnel, network, emulator, or Python was used for this revision.

Rows marked H can run on a host with loopback and mocks. Rows marked D need a
real device and a real hotspot, and need the device owner's approval. A host pass
says nothing about a device. An emulator pass says nothing about a phone.

"Observe" names the thing to record, so a pass is evidence and not an opinion.

This revision answers M8 and M9 in `DESIGN.md` section 2.1 and adds section V,
rows V1 to V18, so every M8 and M9 part has a traceable adversarial row. Section
V covers the neutral nonmatch message and the no-forget rule (V1 to V4, V9), the
deterministic rustls client-certificate order (V5), the per-pin revocation epoch
(V7), the complete arming disarm set (V6), the QV19 and U20 counts (V8), the
Windows and diagnostic token sources (V10 and V11), the descriptor and encoding
rules (V12), the bootstrap exit codes (V13), the PC and bearer matrix (V14),
tunnel stop versus engine exit (V15), the QR deadline anchor (V16), and the
network versus durable flush lock rule (V17). Section U keeps the revision-6
rows; its introduction is corrected to say that M8 and M9 were supplied later.

The first revision-8 pass was interrupted; its historical completion claims are superseded by revision 10 where corrected below. The completion pass in `DESIGN.md`
section 2.1.2 corrects eight defects and changes these rows: V5 now counts what
the server receives and what the client key signs, not resolver calls, because
rustls calls the resolver before it checks the server; V6 and the new V22 cover
every disarm label SD1 to SD10 and TD1 to TD10; L20, L28 to L30, QV20, V12, V13,
and the new V19 and V20 follow the `--bootstrap-fd 3` selector, the exact
32-byte frame fields, and engine codes `2` to `10`; U11, U12, V10, V11, and the
new V21 follow the token sources in the code; E27, E28, and the new V24 follow
the neutral mismatch rule; L36 separates an engine process exit from a tunnel
stop; and the new V23 checks the per-pin epoch values and tombstone cap.

The earlier rows for the one-way bootstrap (L27 to L30 and U1 to U4),
app-created secrets (L31 to L33 and U5 to U8), credential lifetime (L34 to L36),
per-pin revocation and forced cancellation (F34 to F39), the authorization
matrix (L37 and U15), the same-user reader (U16), the canonical IPv4 host form
(E29 and QV19), the target restart sequence (E30 and U17), the legacy descriptor
rules (L30, U18, and V13), the arming and prompt deadline ordering (C55 to C57),
the bounded denial of one ceremony attempt (C58 and U9), the candidate nonmatch
message (E26, E31, U10, and V9), and the token-only paths that P2 removes (U11
to U14 and V10 to V11) remain.

The earlier rows for the pairing capability (L14 to L26 and S1 to S4), source
local revocation (F29 to F33 and T8 to T11), shared-gateway candidate pins
(E25 to E28 and T12 to T15), QR scan order (T16 to T19), arming exhaustion
(C49 to C54 and T20 to T24), and the abort documentation check (T25 to T28)
remain. Some are narrowed by revision 8; sections U and V name the current rule.

Section letters are independent of the H and D markers in the last column.

The cross-device incarnation and migration gates in DESIGN revision 10 remain
unsolved. Earlier wire vectors and expected success outcomes are provisional and
do not authorize implementation; W17 to W22 describe required future tests.
Revision 11 review trace: W17-W19 cover incarnation ordering; W20 covers
durability and recovery; W21-W22 cover status and timer isolation; W23 covers
per-host key provisioning and loss. The review ID and full text are not recorded
here. [Candidate critique](INCARNATION_REVIEW_NOTES.md) is NOT APPROVED.
No rows were run.

## A. TLS profile and exporter channel binding

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| A1 | Exporter available on every peer | Every peer returns exactly 32 bytes for `EXPORTER-Channel-Binding` with an empty context | Length and hex of the value in the harness, never in a log | H |
| A2 | Exporter differs per connection | Two connections between the same two keys produce different values | Two 32-byte values, not equal | H |
| A3 | rustls and Conscrypt agree | Both peers compute the same 32 bytes on one loopback session | Byte compare of both values inside the test | H |
| A4 | rustls and Network.framework agree | The real Swift proxy harness and the Rust client compute the same 32 bytes | Byte compare on the host harness, then on a device | H then D |
| A5 | Exporter missing | Session fails closed before any pairing message | Fixed exporter failure; no prompt; no record | H |
| A6 | Exporter of the wrong length | Session fails closed | Fixed failure; no transcript computed | H |
| A7 | Exporter called before the handshake completes | Fails; no retry with a partial secret | Error returned by the call; session aborted | H |
| A8 | Exporter changed in the commitment | `commit_T` or `commit_S` does not verify | Fixed protocol error before a code is shown | H |
| A9 | TLS 1.2 client | Rejected by the version policy before any exporter call | `protocol_version` alert; no exporter value | H |
| A10 | Transcript version marker | A transcript built with a marker other than `0x04` does not verify | Fixed protocol error | H |
| A11 | Exporter not retained | No exporter value in status, diagnostics, failures, or logs | Grep of every response and log | H |
| A12 | One-sided exporter profile | A peer that requires the exporter while the other omits it is rejected | Fixed protocol error; no fallback | H |
| A13 | Exporter in the SAS code | Two sessions with the same pins and nonces but different session keys produce different codes | Two different codes; deny on both | H |
| A14 | Exporter in the QR proof | A proof computed on another session does not verify | Fixed failure; no record; no token | H |
| A15 | Exporter in the FORGET reply | A reply computed on another session does not verify | Fixed failure; no local deletion | H |
| A16 | Proxy data phase has no binder | No extra round trip and no binder field; after the SOCKS5 reply, only `DATA` and `FIN` frames appear | Frame trace; SOCKS5 control bytes are not framed | H |
| A17 | iOS ALPN read availability branch | On iOS 17.0 to 18.4 the code uses `sec_protocol_metadata_get_negotiated_protocol`; on 18.5 and later it uses `sec_protocol_metadata_copy_negotiated_protocol` | Build for both deployment branches; code inspection; a 17.0 build that uses only `copy` fails to compile | H |
| A18 | Exporter not in the data phase | No exporter value or binder field appears after the handshake | Frame trace and payload grep | H |
| A19 | Exporter context form | Each peer records whether it passed `None`/empty array or a zero-length context. RFC 8446 section 7.5 makes them the same input, so the 32-byte values match | API form recorded per peer; byte equality on one loopback session | H |
| A20 | iOS peer authentication is required | Before the connection, the source calls `sec_protocol_options_set_peer_authentication_required(options, true)`; an anonymous client fails on both listeners | Code inspection; handshake result | H then D |

## B. Certificate and pin

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| B1 | TBS byte equality | All three builders produce the same TBS bytes for the same key and template | Byte compare of the TBS from Rust, Swift, and Kotlin | H |
| B2 | Signature is not reproducible | Two builds of the same TBS produce different signature bytes, and both certificates are accepted | Two DER signature values, not equal; two successful handshakes | H |
| B3 | No full-DER comparison | The suite has no test that compares full certificate DER across builders | Code inspection of the test suite | H |
| B4 | Pin equality across platforms | All three platforms compute the same 32-byte pin for the same key | Fixed vector, byte compared in all three suites | H |
| B5 | Pin independent of the certificate | A new serial, validity, or signature with the same key keeps the pin | Two different certificates, one pin | H |
| B6 | Pin changes with the key | A new key produces a different pin and requires a ceremony | Different pin; the old record does not match | H |
| B7 | iOS pin path rejects a non-P-256 key | No pin is produced; the handshake fails closed | Fixed failure; no 65-byte export | H |
| B8 | Android identity certificate | The presented certificate is the built TBS, not the `KeyGenParameterSpec` certificate | DER subject is empty; the Keystore-generated certificate is absent | D |
| B9 | Post-parse caps: chain length | Two certificates in the chain are rejected | Handshake failure before any pin | H |
| B10 | Post-parse caps: size | A certificate over 4 KiB is rejected before parsing | Fixed failure; no partial parse | H |
| B11 | Post-parse caps: key type and curve | RSA, P-384, and Ed25519 are rejected | No accepted signature scheme; no pin | H |
| B12 | Post-parse caps: exact extension allowlist | Only `basicConstraints` critical `30 00` and `keyUsage` critical `03 02 07 80` are accepted. Any other extension, a duplicate, a different criticality, or an unknown OID is rejected | Fixed failure after parse | H |
| B13 | Empty subject and no EKU | Each platform stack accepts or rejects the template, and the result is recorded | Parse and handshake result per stack | D |
| B14 | Short label is identical on both sides | Both devices show the same eight hex digits for the same pin | Two screens photographed | H then D |
| B15 | Short label is not authentication | Two different pins with the same four-byte label are not merged and do not authenticate | Unit test with a stubbed label function; two records | H |
| B16 | Validity is not enforced | An expired certificate still pins | Record matches; no validity error | H |
| B17 | A pin is never taken from a message | A `PAIR_RESULT` or a `PAIR_HELLO` that carries a pin value is rejected or ignored | Fixed protocol error | H |
| B18 | Full pin never displayed | The UI, logs, status, and diagnostics show the label only | Grep of output and screenshots | H then D |
| B19 | No name is used | The certificate has no SAN and the client sends no SNI | Capture shows no SNI; certificate has no SAN | H |
| B20 | No extension is ignored | An unknown or unlisted extension is a hard failure, not skipped | Fixed failure; no pin | H |

## C. Bootstrap, arming, and mechanism

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| C1 | SAS, both devices armed | Code matches; both Allow; one complete record each; proxy starts | Two screens; both trust lists show the same label; no record before both Allow actions | D |
| C2 | Target not armed | The target refuses to start a session; no TLS connection is opened | No connection in the source trace | H |
| C3 | Source not armed | The source refuses before any prompt, code, QR, or store access | Fixed message; no prompt; no record | H |
| C4 | Arming expires after 120 seconds | A session started after the deadline is refused | Fixed message; monotonic timer, not the wall clock | H |
| C5 | Arming cleared by background or lock | A session after background or screen lock is refused | No prompt; no record | D |
| C6 | Mechanism mismatch at arming | The target is armed for QR and the source for SAS; the source refuses | Fixed mismatch message; no code, no QR | H |
| C7 | Mechanism changed in a second `PAIR_HELLO` | Session closes | Fixed protocol error; no state change | H |
| C8 | Mechanism changed after the commitment | The commitment does not verify | Fixed protocol error before a code | H |
| C9 | Forced QR to SAS | A SAS-shaped `PAIR_READY` in a QR session is rejected and no code is shown | Fixed error; no code on either screen | H |
| C10 | No in-session switch control | The UI has no "use the code instead" or "show a QR instead" action inside a session | Screenshot and code inspection | H then D |
| C11 | QR required by the target, source without QR | Refused; never answered with SAS | Fixed error; no code | H |
| C12 | `known` failure does not switch to a prompt in the same session | The session ends; a new full ceremony requires a new session, new nonces, and arming | No code shown in the known session; no record write; the next session is new | H |
| C13 | `known` with no confirmed record | Refused before any prompt; no in-session prompt | Fixed "pairing is incomplete" message; no record | H |
| C14 | Commitment mismatch | A revealed nonce that does not match its commitment is rejected | Fixed protocol error; no code | H |
| C15 | Reveal without a commitment | Rejected | Fixed protocol error | H |
| C16 | Codes differ | Both users deny, or one denies; no record | Two different codes; no record | H |
| C17 | Target denies | No record on either side | Fixed deny message | H |
| C18 | Source denies | No record on either side | Fixed deny message | H |
| C19 | Prompt timeout | Session ends; no record | Fixed timeout message on both | H |
| C20 | QR happy path | Proof order source then target; target Allow; record on both | Trace order; no code shown | H then D |
| C21 | QR reflection | A proof reflected to the sender fails | Fixed error; no record; no token | H |
| C22 | QR wrong role byte | Rejected even when the rest matches | Fixed error | H |
| C23 | QR wrong pairing id | Rejected | Fixed error | H |
| C24 | QR pin does not match the certificate | Abort before any proof | Fixed error; no proof sent | H |
| C25 | QR expiry | A proof after the monotonic TTL is rejected | Fixed expiry message; no record | H then D |
| C26 | QR single use | A second attempt with the same secret is rejected | Fixed error; a new QR is required | H |
| C27 | QR failed proof consumes the secret | The next attempt with the same secret fails and needs a new QR | Fixed error; new QR only | H |
| C28 | `th(state)` replay | A hash from `PAIR_CONFIRM_S` replayed as `PAIR_DONE` is rejected | Fixed protocol error | H |
| C29 | `PAIR_RESULT` field checks | Wrong host, port 18090, empty token, oversized token, and a short token are rejected; `host` and `port` are the source's own bound listener values, never a value from `PAIR_HELLO` or the client socket | Fixed protocol error; no record; credential map unchanged | H |
| C30 | Unknown record on the pairing listener | Treated as a new identity, allowed only through a full ceremony, never a replacement | Record count increases by one; no existing record changes | H |
| C31 | `known` hint from a source with no record | The target refuses `known`; it does not show a prompt in that session | Fixed "pairing is incomplete" message; a new full ceremony is a new session | H |
| C32 | Target claims `known`, source has no record | The source refuses rather than prompting, because the claim is inconsistent | Fixed error | H |
| C33 | Target claims `known`, source record lacks the pairing purpose | Refused | Fixed error | H |
| C34 | Target claims `known`, wire version differs | Refused; full ceremony required | Fixed error; no credential issued | H |
| C35 | Staged target record and `known` | The target refuses to start `known` from a staged record | Fixed "pairing is incomplete" message; no token | H |
| C36 | Known path issues a token without a record write | No store write and no `generation` bump; the token is copied under the lock and framed after release | Store trace shows no write; record bytes unchanged | H |
| C37 | Known path recheck | A record change between the first check and the recheck aborts the session | Fixed error; no token | H |
| C38 | Same-pin re-confirmation after a lost `PAIR_DONE_ACK` | A new full ceremony promotes the staged record and the source requires arming and the code | Staged to confirmed; new token; no automatic promotion | H |
| C39 | `PAIR_KNOWN_OK` replay | A `th(0x01)` value replayed into `PAIR_RESULT` is rejected | Fixed protocol error | H |
| C40 | Message type and state byte namespaces | A `PAIR_DONE` type byte is not accepted as a `th` state byte | Fixed protocol error | H |
| C41 | Known path message order | The source sends `PAIR_KNOWN_OK` only after the locked check, recheck, and token copy; the target stores the token only after `PAIR_RESULT` and its own locked recheck | Trace order; no token before `PAIR_KNOWN_OK`; no store write | H |
| C42 | Same-pin re-confirmation never promotes a staged record from `known` | A full ceremony with new nonces and arming promotes it; `known` does not | Staged remains staged after `known`; promotion only after a full ceremony | H |
| C43 | Armed first-pairing session refuses `known` | A target or source armed for SAS or QR refuses a `known` session; the person gets the armed mechanism or a new session | Fixed refusal; no silent refresh; no record write | H |
| C44 | QR-required flag with a SAS hello | A `PAIR_HELLO` with `HS_FLAG_QR_REQUIRED` (`0x01`) set and `mech = SAS` is a protocol error; no code | Fixed error; no record | H |
| C45 | Unknown mechanism or flag bit | Any `mech` outside `0x01` to `0x03`, or `flags & 0xfe != 0`, is rejected before a commitment is used | Fixed error; no code; no record | H |
| C46 | Source arming survives an unauthenticated attempt | A malformed, unauthenticated, or mechanism-mismatched hello does not consume the source arming; a retry while still armed is accepted if it is well formed | Two attempts; first refused with no state change; second reaches the ceremony | H |
| C47 | Target arming is one-shot on hello | The target is disarmed as soon as it sends `PAIR_HELLO`; a second hello in the same target arming window is refused | One hello accepted; second refused; no record | H |
| C48 | Known re-pair while the source app is closed | The pairing listener is absent on iOS and Android; the target shows a fixed message and cannot refresh the token | Connection failure; no token change; source record unchanged | D |
| C49 | QR scan order | The target displays the QR and sends no hello; the source arms on scan and sends nothing; the target sends `PAIR_HELLO` only after the local Continue action | Trace shows no target connection before Continue; source arming exists before the hello | H |
| C50 | QR hello before the source scan | A hello that arrives before the scan is refused without consuming the source arming; after the scan and Continue a new hello succeeds | First refused; source still armed; one record after the second | H |
| C51 | SAS start order | Both devices arm; the target sends no hello until the local Start action; a hello before the source arms is refused without consuming source arming | No connection before Start; first refused; second accepted | H |
| C52 | Source SAS attempt budget | Three failed proof attempts are accepted inside 120 seconds; the fourth needs a new arm; malformed frames do not increment the counter | Counter values; fourth refused; malformed frames leave the counter unchanged | H |
| C53 | Failed QR proof consumes the source arming | One failed proof destroys the QR secret and ends the source arming; a retry needs a new scan and a new QR | Fixed error; source unarmed; new payload required | H |
| C54 | Target Continue is required after a scan | No auto-connect on arm; the target opens TLS only after the Continue action | No target socket before Continue; one after | H then D |
| C55 | Prompt deadline inside the arming deadline | A prompt that is extended while inactive ends at `arm_deadline`, not 120 seconds after its own start. The ceremony ends with the fixed timeout message | Two deadlines recorded; one session end; no record | H |
| C56 | QR created near the end of the arming window | `qr_deadline = min(created_at + 120 s, arm_deadline)`, so a QR created at 110 seconds expires at 120 seconds even if it is displayed later. A proof after that is refused | Created, displayed, and deadline values; refusal; no record | H |
| C57 | Monotonic clock, not the wall clock | Setting the wall clock forward or back changes neither the arming deadline nor the prompt deadline; a device reboot loses the armed state entirely | Clock change; deadline values; session result | H then D |
| C58 | SAS denial and source Deny | Withholding an unverified reveal occupies the prompt until its deadline but spends no attempt. After a verified reveal, timeout or source Deny spends one; third such failure disarms and starts lockout. Cancel disarms without lockout. QR source has no Deny | Counters and deadlines for both branches; W10, W11, U9 | H then D |

## D. Identities, store integrity, rollback, and durability

Pairing commit, promotion, re-pair and recovery expected-success outcomes in
this section, including D31, are historical and nonimplementable until the
replacement protocol and recovery model are independently reviewed. W17 to W20
must replace any conflicting expected state; uncertain writes do not guarantee
the old store.

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| D1 | Two source devices on one target | Both records exist, both connect, the UI lists both by label | Two rows; two successful proxy connections | H then D |
| D2 | Two targets on one source | Both records exist and both connect | Two rows; two successful proxy connections | D |
| D3 | Record cap on a target | The ninth record is refused with a fixed message and names the removal action | Eight rows; fixed message; no eviction | H |
| D4 | Record cap on a source | The seventeenth record is refused | Sixteen rows; fixed message | H |
| D5 | Duplicate pin and role | Rejected; no second record | One row; fixed error | H |
| D6 | Unknown pin on the proxy | Refused at the handshake | No application byte | H |
| D7 | Expected device presents a new key | One neutral message, no identity-change claim, no prompt, no automatic replace, and no forget action. The old record is unchanged and still usable if the real source returns | Fixed neutral message; no record named; record unchanged; no deletion | H then D |
| D8 | Replace is local and two-step | After a local forget and a full ceremony, the new record exists and the old is gone | Two screens; old row gone; new row present | H then D |
| D9 | No protocol message replaces a record | Every pairing message is checked; none can overwrite a record | Code inspection plus D7 | H |
| D10 | Tag mismatch | Refused, not repaired, not deleted | Fixed "damaged" message | H |
| D11 | `generation` below the anchor | Refused | Fixed "damaged" message | H |
| D12 | Store rollback with the anchor intact | Refused | Fixed "damaged" message | H |
| D13 | Store and anchor rolled back together | Not detected; documented limit | The older approved record is used; no new key is accepted | H |
| D14 | Anchor written after the record | A crash between the two leaves a store at or above the anchor | Fault injection at each step | H |
| D15 | Store key missing | Fail closed; no unkeyed tag | Fixed message; no record use | H |
| D16 | Store key not derived from the signing key | A signing-key-only fixture cannot produce a valid tag | Fixed vectors; no derivation path | H |
| D17 | Record deleted | Forces a full ceremony; no substitution | Fixed message; pairing required | H |
| D18 | Store unreadable | Fail closed | Fixed "cannot be read" message | H |
| D19 | Historical target staged write | BLOCKED, non-executable. A possible replacement or interrupted flush leaves durable state uncertain; no staged-state or success claim | Future reviewed recovery model and fault injection at every boundary; W20 | H |
| D20 | Historical source confirmed write | BLOCKED, non-executable. A possible replacement or interrupted flush leaves durable state uncertain; no confirmed-state or success claim | Future reviewed recovery model and fault injection at every boundary; W20 | H |
| D21 | Write failure before `PAIR_DONE` | No success; a definite pre-replacement failure preserves only the affected old store, while a possible replacement leaves that store uncertain. Peer state depends on prior commits | Inject each boundary on both peers; block trust use and mutation pending reviewed recovery | H |
| D22 | Android UID attacker forges a record | Possible; documented limit | The forged record verifies; recorded as a limit, not a pass | D |
| D23 | Linux root forges a record | Possible; the helper runs as root; documented limit | Recorded as a limit | D |
| D24 | iOS integrity claim | The keychain is the boundary; the tag is a corruption check only | Code inspection and text audit | H |
| D25 | macOS and Windows store boundary | The unprivileged user cannot read or forge; root and the same account can | Permission and DPAPI checks | D |
| D26 | Partial record | A truncated file is invalid; a partial temporary file does not establish which named store survives an uncertain replacement | Inject before and after replacement and restart; reject invalid state and block use pending reviewed recovery | H |
| D27 | Store-wide `generation` | Successful mutations increment once. Only definite pre-replacement failure preserves the old named generation; possible replacement or failed flush leaves it uncertain and blocks trust use and dependent success pending reviewed recovery | Inject pre-replacement, rename and flush failures; record both store and anchor across restart; W20 | H |
| D28 | One tag over the whole store | A record cannot be added, removed, or reordered without changing the tag | Fixed store bytes; tag mismatch | H |
| D29 | Staged record is not a trust decision | A staged record cannot start `known` or proxy traffic | Fixed "pairing is incomplete" message; no token | H |
| D30 | Target promotion after `PAIR_DONE_ACK` | The promotion is durable before success is shown | Abort at each step; staged or confirmed, never half | H |
| D31 | Promotion failure after `PAIR_DONE_ACK` | No success; target is staged only on a definite pre-replacement failure, otherwise its durable state is uncertain. Source state follows its own durable commit | Inject promotion and anchor boundaries; block trust use pending reviewed recovery; no prescribed re-pair | H |
| D32 | Concurrent removal after a copy | The credential or handshake may be authorized a moment earlier; the next connection fails | Record the bound; no lock held across the network | H |
| D33 | Store lock during a blocked network flush | No deadlock; the store lock is not held across the network write or flush. A blocked local durable flush may hold the store lock but never the table lock (V17) | Timeout and lock trace | H |
| D34 | Record state byte | Only `0x01 staged` and `0x02 confirmed` parse; any other value fails closed | Fixed "damaged" message | H |
| D35 | Record format and wire version | `format = 0x04` and `wire_version = 0x04`; a v3 record is not used and needs a new ceremony | Fixed "damaged" or version error; no credential | H |
| D36 | Staged record counts toward the cap and can be removed | A staged record is listed as incomplete, counts toward the cap, and a local forget removes it; it is never shown as trusted | Cap count; local forget; no proxy or `known` use | H |
| D37 | Record role bytes | A `local_role` that does not match the device, or a `peer_role` that is not the other role, fails closed | Fixed "damaged" message; no credential | H |
| D38 | Two sources, two credentials | The target holds one host, port, and token per `(peer_role, pin)`; a pairing with source B does not overwrite source A's entry | Two entries; two proxy connections; byte-exact per source | H then D |
| D39 | Wrong-source token | The target connects to source B and presents source A's token; the source refuses with `denied` | No CONNECT; A's record unchanged | H |
| D40 | Forgetting one source | Removing source A deletes only A's record and credential; source B still connects | One row; B still works | H then D |
| D41 | Host and port source | `PAIR_RESULT` carries the source's own bound hotspot address and proxy port, not a value from `PAIR_HELLO` or the client socket | Field values compared with the listener settings | H |
| D42 | Known refresh for one record | A known refresh updates only the matching pin's credential; every other entry is byte-identical | Credential dump before and after | H |

## E. Proxy channel

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| E1 | Pin match with the proxy purpose | Handshake completes; CONNECT succeeds; byte-exact echo | `ttl_bad == 0`; one outer socket per flow | H then D |
| E2 | Record without the proxy purpose | Refused at the handshake | No application byte | H |
| E3 | IPv6 literal | Same as E1 over IPv6 | Reply code 0; byte-exact | D |
| E4 | Domain name | The name travels inside TLS; the source resolves it | No `getaddrinfo()` on the target egress path | D |
| E5 | UDP over `0x80` | Datagrams round trip; the 250 ms age limit holds | `udp_dropped` unchanged | D |
| E6 | Echo `0x81` and `0x82` | Replies arrive; the Android path uses an unprivileged ICMP socket | Existing echo tests pass | D |
| E7 | Eight concurrent flows | Eight outer sockets, eight full handshakes, no cross-flow bytes | Distinct peer ports; byte-exact payloads | H then D |
| E8 | Post-handshake pin recheck | A peer certificate swapped between the handshake and the first byte is refused | Harness abort before any SOCKS byte | H |
| E9 | Token required | No token, a wrong token, and an old token are refused with `denied` | No CONNECT reached | H |
| E10 | Pipelining before the pin check | Not possible; a pipelined write is sent only after the pin check | Frame order in the trace | H |
| E11 | Token rotation | New connections need the new token; records unchanged; live flows continue | Old token denied; new token accepted | D |
| E12 | Port change | The target learns the new port only over the pairing channel | Old port fails; new port after a pairing refresh | D |
| E13 | Presence probe on the proxy channel | An authenticated SOCKS auth reply is required; a TCP connect or a handshake alone is not `ready` | Probe result; no probe on the pairing listener | H then D |
| E14 | Presence probe while the source is unarmed | The probe still works, because it does not use the pairing listener | Probe succeeds; the pairing listener would have refused | H |
| E15 | Failure mapping | `not_trusted`, `not_responding`, candidate nonmatch, failed server `CertificateVerify`, and truncation map to fixed messages. A failed server `CertificateVerify` uses the neutral nonmatch message, not `not_trusted`. The nonmatch message is neutral and never claims an identity change | No failure deletes a record; no forget action on the nonmatch | H |
| E16 | Certificate linkability | The source certificate is visible to an unauthenticated client | Same pin in two captures; no name or SAN | H then D |
| E17 | Framed data phase starts after the SOCKS5 reply | The reply is unframed; the first post-reply byte is a `DATA` or `FIN` frame header | Frame trace; no frame around the greeting or request | H |
| E18 | One inner flow, one TLS connection | Two inner flows never share a TLS connection or a frame | Two outer sockets; distinct TLS sessions; no cross-flow payload | H then D |
| E19 | Frame overhead | A 1-byte write costs a 3-byte header plus TLS overhead, not a second round trip | Byte counts; latency | H |
| E20 | UDP and echo inside `DATA` frames | The existing `0x80`, `0x81`, and `0x82` payloads keep their internal format inside `DATA` frames | Byte-exact UDP and echo replies | H then D |
| E21 | Candidate selection by endpoint | The target builds the candidate set from the dialed host and port, not from the gateway address alone. It selects exactly one record only after the server pin matches | Candidate count; one selected record; no token before the match | H |
| E22 | Server pin mismatch on the proxy | The target aborts before any token byte; it does not try another candidate's token and shows the neutral nonmatch message | No SOCKS auth; neutral message; no forget action | H |
| E23 | Source address or port change | The target uses the old entry until a known refresh or a full ceremony updates it; no value is taken from the connection | Old connection fails; new entry after refresh | H then D |
| E24 | Frame before the SOCKS5 reply | A `DATA` or `FIN` frame before a success reply, or after a failure reply, is a protocol error; no inner flow | Fixed error; connection closed; no inner flow | H |
| E25 | Two sources share one gateway and port | Candidate set has two entries; exactly one server pin matches; the target uses only that record's token | One handshake; one token; the other credential unchanged | H |
| E26 | Shared gateway, no candidate matches | The target sends no token and shows one neutral "not answering as any paired source device" message. It does not claim an identity change, name a record, offer a forget action, or try the next candidate | No SOCKS auth; neutral message; no forget action; no second connection with another token | H |
| E27 | Shared gateway, client certificate order | No cases today: all target TLS clients use rustls. If a non-rustls target client is added, record whether a server whose pin matches no candidate, or whose `CertificateVerify` fails, is rejected before the client `Certificate` is emitted. rustls is covered by the deterministic V5 gate; this row is the per-stack record | Server-side receipt of a client `Certificate` (yes or no); client key signing count; or a recorded limitation | H then D |
| E28 | Candidate set where the source now presents a pin that matches no record | The target cannot tell a reset source from a different device. It sends no token, shows the neutral nonmatch message, names no record, offers no forget action, and deletes nothing. The record stays usable when the matching source returns. Only a person who knows the old source is gone removes it, from the paired-device list, and no failure screen links there | Neutral message; no forget action; no credential write; record intact; later success with the matching source | H |
| E29 | Canonical host encoding | `PAIR_RESULT` host is ASCII dotted-quad IPv4 with no leading zero, no space, no trailing dot, no port, no brackets, and no `%`. The target parses it, re-renders it, and compares bytes with the connected peer address. A non-canonical value is a protocol error | Accepted canonical value; seven rejected variants; no credential write on a rejection | H |
| E30 | Target restart with a record and no token | The first proxy connection needs the known path, which needs the source app open and in the foreground. On failure the target shows one fixed message and does not retry on a timer. On success the same start action proceeds | No proxy connection without a token; one dial; fixed message; success after the app is in the foreground | H then D |
| E31 | One candidate and no pin match | The target sends no token and shows the same neutral "not answering as any paired source device" message as the multi-candidate case. It does not claim an identity change and offers no forget action | Neutral message; no token; no forget action; record intact | H |

## F. FORGET and trust changes

The pin-only FORGET success, retry, deletion and recovery outcomes in these rows
are historical and nonimplementable until a replacement is reviewed. In
particular F2, F22 to F24, F28 and F30 cannot establish safe remote removal or
re-pair. W17 to W20 are required. F34 to F39's pin-only recheck and survivor
claims apply only when no same-pin re-pair intervenes; W17 to W19 cover that gap.

FORGET is accepted only on `hs-pair/1`, as the first application message. The
proxy listener has no FORGET parser. A remote FORGET needs the source app open,
because the pairing listener does not run in the background on Android.

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| F1 | FORGET on the proxy channel | Refused by the SOCKS5 parser; there is no FORGET parser on the proxy port | Fixed protocol error; no SOCKS5 reply; no `FORGET_RESULT`; no state change | H |
| F2 | FORGET on the pairing channel as the first message | HISTORICAL, BLOCKED AND NON-EXECUTABLE. Historical first-message acceptance and success are not established. | Future reviewed incarnation and recovery model; W17 to W20 | H |
| F3 | FORGET as a later pairing message | Refused | Fixed protocol error; no state change | H |
| F4 | FORGET on an unpaired pairing session | Refused before any state change and before any prompt | Fixed rejection; trust lists unchanged | H |
| F5 | FORGET from an unknown client | The pairing listener may complete the handshake for a first pairing, but the FORGET locked recheck fails; no distinct reply exists | Handshake result; no `FORGET_RESULT` byte; no state change | H |
| F6 | Record removed between the handshake and the message | Hard close; no reply; no store write | Connection closed; no partial reply | H |
| F7 | Duplicate request id in one session | The first frame is processed; a second frame with the same request id returns the cached reply bytes; no second store write | Identical bytes; one write in the store trace | H |
| F8 | Different request id in the same session | Protocol error; close with no reply and no state change | Connection closed; no second reply | H |
| F9 | Fake reply from a server with a different key | The target ignores it and deletes nothing | Record intact; fixed failure | H |
| F10 | Replayed reply from another session | The reply hash does not verify | Fixed failure; no deletion | H |
| F11 | Tampered status in a reply | The reply hash does not verify | Fixed failure; no deletion | H |
| F12 | `DENIED` reply | The target keeps its record and token; the source still holds the record; a local forget is offered only as a person action | Storage unchanged; UI copy; source record still present | H |
| F13 | FORGET naming another device | Refused; there is no target identifier field | Fixed protocol error | H |
| F14 | Local forget on the target while a flow uses the record | Close matching local flows; report durable removal only after reviewed durable commit. Uncertain write blocks trust use and mutation pending recovery | Fault injection and restart; no unconditional success or assumed store state | H then D |
| F15 | Local removal on the source while a target holds a live flow | Cancel matching sessions; durable removal is established only by the reviewed commit and recovery model. An uncertain write blocks trust use and mutation across restart | Fault injection, cancellation and restart; no unconditional success or assumed store state | H then D |
| F16 | Record removal applies to the next connection | The next connection is refused at the handshake | No application byte; fixed message | H |
| F17 | `FORGET_REQUEST` frame | The frame has the length, type `0x10`, version `0x04`, both role bytes, `purpose_used`, and a nonzero 16-byte request id | Byte-exact frame against a fixed vector | H |
| F18 | `FORGET_RESULT` frame | The frame has type `0x11`, both role bytes, `purpose_used`, request id, status, and a 32-byte hash | Byte-exact frame against a fixed vector | H |
| F19 | FORGET pin order | Both sides compute the pins in the order `pin_T` then `pin_S`, independent of sender | A hash built with `pin_peer` then `pin_self` does not verify | H |
| F20 | FORGET hash covers request id and status | A changed request id or a changed status fails the hash | Fixed failure; no deletion | H |
| F21 | FORGET purpose mismatch | A request with `purpose_used` that does not match the connection is refused | Fixed protocol error; no deletion | H |
| F22 | FORGET idempotence across a new connection | HISTORICAL, BLOCKED AND NON-EXECUTABLE. Historical retry rejection is not established. | Future reviewed incarnation and recovery model; W17 to W20 | H |
| F23 | `FORGET_REQUEST` or its reply is lost | HISTORICAL, BLOCKED AND NON-EXECUTABLE. Lost request or reply leaves outcome unknown; no retry, recovery or re-pair is specified. | Future reviewed incarnation and recovery model; W17 to W20 | H |
| F24 | `FORGET_RESULT` with `OK` lost | HISTORICAL, BLOCKED AND NON-EXECUTABLE. A lost OK leaves both remote outcome and safe local action uncertain. | Future reviewed incarnation and recovery model; W17 to W20 | H |
| F25 | Source delete failure | No result is sent. A definite pre-write failure leaves the record; uncertain durability blocks further mutation until recovery determines the state | Fault injection, recovery, no partial reply; W5, W20 | H |
| F26 | Remote FORGET while the source app is not open | The pairing listener is absent, so the target cannot connect; it shows a fixed message and offers a local forget; no record changes | Connection failure; local forget still available; source record unchanged | D |
| F27 | Remote FORGET while the source is armed for SAS or QR | The source refuses the FORGET; the armed first-pairing session is not changed | Fixed refusal; no record change; target retries after the armed session | H |
| F28 | Remote FORGET while the source serves a flow for the record | HISTORICAL, BLOCKED AND NON-EXECUTABLE. Historical remote DENIED and retry behavior is not approved; live flows do not veto local removal, whose durable success requires reviewed recovery. | Future reviewed incarnation and recovery model; W17 to W20 | H |
| F29 | Source per-session client pin index | Each accepted proxy session records the authenticated client pin after the post-handshake recheck and before the first application byte; no session is indexed from a pre-handshake value | Index entry per session; no entry for a failed handshake | H |
| F30 | A remote target cannot veto source local removal | A live flow cannot veto a local removal attempt; matching sessions close. Durable success requires the reviewed commit and recovery model; uncertain writes block trust use and mutation | Race and fault injection through restart; no assumed deletion or success | H then D |
| F31 | Removal closes only matching sessions | Source A and source B both have live flows; removing A closes only A's sessions and leaves B's bytes intact | One flow reset; one byte-exact flow | H then D |
| F32 | Index holds no token | A dump of the per-session table contains no token, host, or destination | Table dump; grep | H |
| F33 | Source removal races a pending ceremony | A changed local generation aborts that local commit; this alone cannot prove cross-device ordering or prevent same-pin resurrection. Full acceptance is blocked on W19 | Generation and commit trace; W19 | H |
| F34 | Registration before the sweep | A session registers, then the person removes the record: the sweep finds it in the table, detaches it, and cancels it. The target sees truncation with no `FIN` on that flow | Index entry; detached; socket closed; no `FIN` frame; reset | H |
| F35 | Registration races removal | Both take the store lock before the table lock. If removal wins, registration fails its record recheck; if registration wins, remote FORGET returns DENIED, while local removal detaches it. No epoch mismatch is possible within one lock hold. Another pin is unaffected. Incarnation ordering remains gated | Lock trace, record checks, 1000 interleavings; W3 to W5, W15, W17 | H |
| F36 | Sweep with two pins | Removing source A leaves source B's session registered and byte-exact. One epoch bump for A only, one detach, one cancel; B's epoch is unchanged | One reset; one intact flow; epoch and table trace | H |
| F37 | Unregistered handshake races removal | A handshake not yet registered must recheck the record under the store lock before insert. Removed record fails that check, without relying on epoch mismatch; an unrelated record proceeds. Same-pin re-pair remains gated | Store recheck and lock trace; no application byte; W17 to W20 | H |
| F38 | Cancelled session sends no `FIN` | The forced close writes no `FIN` frame and no application data, and closes the destination socket abortively. The target resets its inner flow rather than delivering a clean EOF | Frame trace; no `FIN`; inner reset; destination socket closed | H then D |
| F39 | Lock order under load | Registration takes the store lock then the table lock; the sweep takes the same two in the same order. Under 100 concurrent registrations for two pins and 100 removals of one pin with no intervening same-pin re-pair there is no deadlock, no inverted lock trace, no removed-pin survivor, and no abort for the other pin | Lock-order trace; no timeout; survivor and abort counts per pin | H |

## G. Framed data phase, half-close, truncation, and lifecycle

The frame layer starts after the SOCKS5 reply. A clean half-close is a `FIN`
frame. A TLS close, EOF, TCP FIN, TCP reset, or fatal alert before a `FIN` is
truncation. A `FIN` is never inferred from a transport close.

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| G1 | Upload `FIN`, then a slow download | The download completes with no truncation at 2.5, 30, and 120 seconds, all below the 300 second source session idle | Byte-exact download; no reset; one `FIN`; no close drain timer | H then D |
| G2 | `DATA` before `FIN` | Every `DATA` payload is delivered before the `FIN` is delivered as a clean half-close | Byte order; one clean half-close | H |
| G3 | Both directions closed | After both `FIN` frames the transport closes; an optional `close_notify` follows both frames only | Frame trace shows `DATA`, `FIN`, `FIN`, then transport close | H |
| G4 | Received `FIN`, local write still open | The local side can still send `DATA` and its own `FIN`; no premature close | Bytes after the peer `FIN` arrive; local `FIN` delivered | H then D |
| G5 | `DATA` after a received `FIN` in that direction | Protocol error; the connection closes and the inner flow resets | No delivered byte; inner RST | H |
| G6 | EOF, TCP FIN, or `close_notify` before a `FIN` | Truncation; inner RST; no clean FIN delivered | Inner RST observed; no clean EOF | H |
| G7 | TCP reset | Truncation; inner RST | RST observed | H |
| G8 | Fatal TLS alert | Truncation; inner RST | Alert recorded; RST | H |
| G9 | Abortive inner close | The sender sends no `FIN` frame and no application data. `NWConnection.cancel()` is documented as graceful, and a zero `SO_LINGER` is not documented as a guaranteed RST on every platform. The peer must treat a close without a `FIN` as truncation. Record the actual wire result | No `FIN`; inner reset; wire result (RST or graceful close) recorded | H then D |
| G10 | Write stall on a half-closed flow | Bounded by the 30 second stall allowance | Timer value; reset | H |
| G11 | Keepalive probe during a half-closed flow | The ACK is still sent | Probe answered | H |
| G12 | Zero-window plus half-close | Zero-window probes continue; the flow is not dropped for silence while the peer answers | Probe counters | H |
| G13 | Frame split across TLS records | A frame whose header and payload span records is reassembled and delivered once | Byte-exact payload; one delivery | H |
| G14 | Several frames in one TLS record | Every frame is parsed in order; none is dropped or merged | Byte-exact sequence | H |
| G15 | Invalid frame header | `DATA` length 0, `FIN` length other than 0, unknown type, or length over 16384 is a protocol error before allocation | Fixed error; inner RST; memory flat | H |
| G16 | Short read at TLS EOF before a full frame | Truncation; inner RST; no partial payload delivered | Inner RST; no partial byte | H |
| G17 | Second `FIN` from the same sender | Protocol error; connection closes; inner RST | Fixed error; RST | H |
| G18 | Coalescing and `FIN` order | Consecutive writes may coalesce up to 16384 bytes; `FIN` is not delayed behind data in the other direction | Byte-exact sequence; one `FIN` per direction | H |
| G19 | Eight concurrent half-closed flows | All complete; no cross-flow bytes | Byte-exact payloads; distinct sockets | H |
| G20 | Engine stop during a half-closed flow | Routes and device removed; inner flows reset | Cleanup check | H then D |
| G21 | Hotspot loss during a half-closed flow | `hotspot_lost`; routes removed | `last_stop` reason; cleanup check | D |
| G22 | Source device gone during a half-closed flow | `source_device_gone`; routes removed | `last_stop` reason | D |
| G23 | Source app backgrounded during a half-closed flow | Recorded behavior; no claim before it is measured | Flow continues or fails; the observation is recorded | D |
| G24 | Screen lock during a QR session | Arming cleared; the secret destroyed; the session ends | No prompt on unlock; no record | D |
| G25 | Hotspot loss during a ceremony | Listener stops; no record on either side | Both trust lists unchanged | D |
| G26 | Pairing while a tunnel runs | Allowed; live flows are not disturbed | Flow counters unchanged; new record present | D |
| G27 | Local forget while a tunnel runs | HISTORICAL, BLOCKED AND NON-EXECUTABLE. A live flow must not veto a local removal attempt. Durable success and session outcomes require the reviewed incarnation and recovery model. | Future fault injection and session ordering; W17 to W20 | H |
| G28 | Frame before the SOCKS5 success reply | Protocol error; no inner flow; connection closed | Fixed error; no inner flow | H |
| G29 | Half-closed flow paused for 301 seconds | Record the source behavior. If the source 300 second idle applies, the flow is closed and the target resets unless both `FIN` frames crossed | Timer value; reset or delivery; P21 decision | H then D |

## H. Resumption and the trust epoch

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| H1 | Rust target handshake kind | `HandshakeKind::Full` on every connection | Kind recorded for 100 connections | H |
| H2 | Rust target with a ticket from a previous connection | No resumption; both pin checks run | Both checks in the log; kind `Full` | H |
| H3 | Android tickets suppressed | No `NewSessionTicket` and a full handshake on every connection | Trace of `Certificate` and `CertificateVerify` on each connection | D |
| H4 | Android resumed session | Refused or absent; if observed once, Android source mode is not approved | Trace evidence | D |
| H5 | iOS tickets disabled | The verify block runs on every connection; no Certificate message is skipped | Counter and trace | D |
| H6 | Post-handshake recheck runs every session | The recheck counter equals the connection count | Counter comparison | H then D |
| H7 | Recheck alone is not accepted | A resumed session is refused even when the recheck would pass on cached certificates | Test with a forced ticket if the platform allows it | D |
| H8 | 0-RTT early data | Not offered and not accepted | No early data in the ClientHello | H |
| H9 | Renegotiation | Not possible in TLS 1.3 | Connection error | H |
| H10 | Record removal versus the trust epoch | The next connection is refused; live flows follow P5 | Connection result; flow result | H then D |

## I. Android platform

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| I1 | TLS 1.3 server on API 26 with Conscrypt | Handshake completes with client authentication and a Keystore key | Version, cipher, and provider in the handshake record | D |
| I2 | TLS 1.3 server on API 28 | Same as I1 | Same | D |
| I3 | TLS 1.3 server on API 29 and 30 | Same as I1 | Same | D |
| I4 | TLS 1.3 server on API 31 and later | Same as I1 | Same | D |
| I5 | At least one OEM build | Same as I1, or a recorded failure that blocks the mode | Vendor, model, API, and result | D |
| I6 | Conscrypt socket check before the handshake | `Conscrypt.isConscrypt(socket)` runs immediately after accept or socket creation and before `startHandshake()`; a socket from another provider is a hard failure with no fallback | Code inspection; fixed message; no TLS byte | H then D |
| I7 | ALPN selection | The selected label equals the listener label exactly; none or two labels are refused | Selected label in the trace | H then D |
| I8 | Exporter equality with rustls | 32 bytes, identical on both peers | Byte compare | H then D |
| I9 | No session tickets | Conscrypt ticket switch applied before the handshake on every accepted socket | Trace per connection | D |
| I10 | Keystore signs an externally built TBS | The built certificate is presented and accepted | Certificate subject empty; signature verifies | D |
| I11 | Constant-time compare | `MessageDigest.isEqual` on 32-byte arrays; no early return | Unit test and code inspection | H |
| I12 | Framed half-close on Conscrypt | A `FIN` frame is written as an ordinary `SSLSocket` output write; `shutdownOutput()` is not used as the half-close signal. Record whether `close()` sends `close_notify` after both FINs | Byte-exact half-close; trace; transport close result | D |
| I13 | APK size | Per-ABI native size measured with and without Conscrypt | Numbers in the release record | D |
| I14 | Platform stack on API 31 as a baseline | The same profile works there; this is a comparison, not the selected path | Handshake and exporter result | D |
| I15 | Vendor Keystore accepts `DIGEST_NONE` | The identity key authorizes `DIGEST_NONE` and `DIGEST_SHA256`; a vendor refusal blocks the Conscrypt path with a fixed message and no exportable fallback | Key authorization list; handshake result | D |
| I16 | 16 KB page-size runtime | The app runs with 16 KB pages; the Conscrypt native libraries load | Device or emulator page size; crash log; load result | D |

## J. iOS platform

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| J1 | Identity assembly with `kSecClassIdentity` | The identity is returned and used | Identity reference; handshake succeeds | D |
| J2 | Secure Enclave key | The key is created or the fallback is recorded | Which key type the build used | D |
| J3 | Exporter on a post-ready metadata handle | After `.ready`, `metadata(definition:)` returns a `NWProtocolTLS.Metadata`; the exporter is 32 bytes. The verify-block handle is not used | Value present and 32 bytes; no verify-block reuse | D |
| J4 | Exporter unavailable after `.ready` | Session fails with a fixed message; no fallback profile | Fixed message; no pairing | D |
| J5 | Post-ready metadata across iOS 17.0 to 18.4 and 18.5+ | The metadata and exporter behave the same on both branches; ALPN uses `get` on 17.0 to 18.4 and `copy` on 18.5+ | Build and run each branch; code inspection | H then D |
| J6 | Locked key, before first unlock | Handshake fails with the fixed locked message | Message; no record | D |
| J7 | Locked key, after first unlock while locked | Behavior per the chosen accessibility class, recorded | Message or success; class recorded | D |
| J8 | Locked key during an established flow | The flow may continue; recorded, not assumed | Bytes still flow or the flow fails | D |
| J9 | Framed half-close with Network.framework | A `FIN` frame is an ordinary `NWConnection.send`; `.finalMessage` is not used as the half-close signal. Record whether `.finalMessage` sends `close_notify` after both FINs | Trace and byte result | D |
| J10 | ALPN and tickets | Exact label; verify block on every connection | Trace | D |
| J11 | ALPN when the client offers none | The handshake result and the negotiated-protocol call are recorded; a nil or mismatched result is a hard failure | Handshake and negotiated label | D |
| J12 | Anonymous client on both listeners | The source calls `sec_protocol_options_set_peer_authentication_required(options, true)` before the connection; a client with no certificate fails the handshake on the pairing and proxy listeners | Handshake abort; no application byte | D |
| J13 | Background and foreground lifecycle | Pairing runs only while the app is foreground; background clears arming; a live flow may be suspended or closed by the system. Record the exact result | State at each transition; flow result | D |

## K. Adversarial

Each row names the attacker position. "Fail" means the connection is refused
and no application byte is exchanged.

| # | Attack | Expected | Observe | H/D |
|---|---|---|---|---|
| K1 | Passive capture of a proxy session | No token, destination, reply code, certificate, or payload readable | TLS records only; ALPN visible | H |
| K2 | MITM after pairing | Fail at the pin check before `CertificateVerify` | Client aborts before sending its certificate | H |
| K3 | MITM during first pairing, SAS | Codes differ; commitments and exporter cannot be changed; no record | Two codes; commitment or code mismatch | H |
| K4 | MITM during first pairing, QR | HMAC mismatch; directional proofs and exporter stop reflection and splicing | Fixed error; no record; no token | H |
| K5 | Splice of two sessions | The exporter differs, so the commitments and code differ | Session fails even when pins and nonces match | H |
| K6 | Message replay into another session | Rejected by the exporter and the `th(state)` binding | Fixed protocol error | H |
| K7 | Stolen token, no private key | Fail at the certificate check | No SOCKS greeting | H |
| K8 | Stolen private key | Impersonation succeeds | Documented limit; no test can pass it | D |
| K9 | Plaintext SOCKS to the proxy port | Fail; connection closed | No reply byte | H |
| K10 | TLS 1.2 client | Fail | `protocol_version` alert | H |
| K11 | No ALPN, wrong ALPN, both labels | Fail on both listeners where the stack exposes the offered list; on iOS a nil or mismatched negotiated label fails after `.ready` | Close or `no_application_protocol` | H then D |
| K12 | Anonymous client | Fail on the proxy listener and on the pairing listener; iOS sets peer authentication required before the connection | Handshake aborted; no application byte | H then D |
| K13 | Certificate with a matching pin and a different private key | Fail at `CertificateVerify` | Signature failure | H |
| K14 | RSA, Ed25519, or P-384 identity | Fail | No accepted scheme; no pin | H |
| K15 | Certificate outside its validity window | Accepted; pins ignore validity | Record still matches | H |
| K16 | Oversized or malformed certificate | Fail closed; no panic; no unbounded allocation | Parser error; memory flat | H |
| K17 | Truncated stream without a `FIN` frame | Truncation; inner RST | RST observed | H |
| K18 | Forced mechanism downgrade | Refused; no code shown | Fixed error | H |
| K19 | Unarmed drive-by prompt | Refused before the prompt | No prompt; no store access | H |
| K20 | FORGET spoof with a different server key | The target ignores it; nothing is deleted | Record intact | H |
| K21 | Record rollback | Detected unless the anchor is rolled back too | Fixed "damaged" message or a documented limit | H |
| K22 | Record substitution | Detected by the tag where the key is not readable by the account | Refused | H |
| K23 | Server certificate linkability | The same source is recognizable across sessions | Same pin in two captures | D |
| K24 | Client certificate disclosure during first pairing | Disclosed before the target has a record; the code or QR still fails | Certificate observed; no record; no token | H |
| K25 | Handshake flood | Bounded; the listener stays responsive | CPU and connection counts | D |
| K26 | Slow-drip handshake | Fail at the total deadline | Timed out with progress | H |
| K27 | Silent server | Fail at the total deadline | Timed out | H |
| K28 | Target app QR read by a local process | The process can pair once inside the TTL; the browser page has no pairing surface | Payload readable only in the native app surface or its memory; single use; no storage | H then D |
| K29 | Photographed QR after the TTL | Rejected; the secret is consumed and expired | Fixed expiry message | D |
| K30 | `close_notify` or TLS alert flood | Bounded by the deadline, the frame parser, and the idle policy; no unbounded wait | Timers; memory | H |
| K31 | Probe for a browser QR or pairing endpoint | No QR or pairing endpoint exists; any such request returns 404 or 401 and no payload | HTTP status; no QR or code bytes | H |
| K32 | Maximum-size `DATA` frame flood | The 16 KiB frame cap and the 64 KiB per-connection buffers bound memory; no unbounded queue | Memory and queue depth | H |
| K33 | Page credential tries to self-consent | A request with only the API bearer, or with no credential, cannot arm, read a code, allow, deny, or cancel; 401 and no state change | HTTP status; store trace; no prompt | H |
| K34 | Page tries to create or read a QR | 401 `pairing_requires_target_app`; no QR payload in the response, DOM, storage, or log | HTTP status; grep | H |
| K35 | Pairing capability from a previous launch | A capability from an earlier engine process is rejected; there is no reuse across launches | 401; no state change | H |
| K36 | Renderer compromise on Linux | The renderer holds only the QR image, not the raw payload; a process that reads it can scan it, the same as the screen | Renderer memory dump contains no payload bytes; the image is present | H then D |

## L. GUI and browser exposure

The browser GUI is the Rust-served page on `127.0.0.1`. It is not the Linux
target app's own Electron renderer. It has no pairing surface: no arm, no code,
no allow, no deny, no cancel, and no QR. It holds no API bearer and no pairing
capability.

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| L1 | Browser pairing routes are absent or unauthorized | Every arm, code, allow, deny, cancel, and QR route returns 404 or 401 `pairing_requires_target_app`; no payload and no state change | HTTP responses; store trace | H |
| L2 | Browser page never receives a QR payload | `/api/status`, `/api/diagnostics`, `/api/failures`, and every other response contain no QR payload or secret | Grep of all responses and logs | H |
| L3 | Browser page never receives a secret | No token, private key, full pin, exporter value, QR secret, API bearer, or pairing capability in any response, DOM, storage, log, or notification | Grep and storage dump | H |
| L4 | Browser page has no code | The page shows no six-digit code, no arm control, and no allow or deny control | DOM and screenshot | H |
| L5 | No pairing state in the page | Absent from `localStorage`, `sessionStorage`, `window.name`, the URL, `document.title`, a persistent DOM `data-` attribute, logs, notifications, and status | Storage, history, and DOM dump | H |
| L6 | Response headers | `Cache-Control: no-store`, `Pragma: no-cache`, `nosniff`, and a restrictive CSP on every page and API response | Header dump | H |
| L7 | No external request | No remote font, image, script, or analytics | Network log | H |
| L8 | User text | The page says pairing needs the target app and does not claim a browser QR or code | Text audit | H |
| L9 | Linux target app QR path | The Electron main process holds the pairing capability and receives the QR payload; the renderer receives only an image | IPC trace; HTTP log shows no page request with PC; renderer dump has no payload bytes | H then D |
| L10 | Headless target | No QR and no SAS surface; the UI says a new device cannot be paired and offers the known path only | Screenshot and text | D |
| L11 | Theme and size | The status and failure panels render in light and dark at 1440x1000 and 1100x900 | Screenshots; contrast check | H |
| L12 | Loopback binding | The GUI listens only on `127.0.0.1`; no non-loopback socket is open | Socket listing | H |
| L13 | Bearer separation | The API bearer changes tunnel control only; it does not authorize any pairing route | Route matrix with bearer and without PC | H |
| L14 | Page credential cannot pair | A client with no credential, and a client with the API bearer but no PC, cannot arm, read a code, allow, deny, cancel, or create a QR | 401 on every pairing route; no state change | H |
| L15 | Missing PC fails closed | An engine started without a pairing capability refuses every pairing route and shows no prompt | 401; no pairing state | H |
| L16 | PC is per launch | A PC from a previous launch is rejected; a second launch has a different PC | Two launches; old PC 401; new PC accepted | H |
| L17 | macOS XPC caller check and reply | A client without the app's audit token is rejected; a second XPC connection is rejected; both secrets travel in the authenticated request, and the reply carries the port, a launch id, and readiness only | XPC trace; fixed error; no secret in the reply, on stdout, or in stderr | D |
| L18 | Windows target pairing gate | QR and SAS are disabled; the UI labels the app as a preview; no fallback to the browser page; no target proxy is claimed | Screenshot; route matrix | D |
| L19 | App creates both secrets | The app, not the helper and not the engine, generates the API bearer and the PC; the engine starts with a valid frame and never emits a secret | Descriptor trace; engine has no generation path; byte compare at the app | H |
| L20 | Bootstrap frame format | With `--bootstrap-fd 3`: `HSBOOT1`, version `0x01`, `api_len` exactly 32, `pc_len` 0 or 32, 32 raw bytes per secret, so 44 or 76 bytes, then end of input. The engine writes no reply; a malformed frame exits with the fixed code from `DESIGN.md` section 11.4.1 | Byte-exact frame; no reply bytes; `api_len` 31, 33, and 64 each exit `5`; exit codes | H |
| L21 | Zero PC means no pairing | A zero `pc_len` starts the engine with no pairing capability; every pairing route returns 401 and the tunnel control still works with the API bearer | Route matrix; no prompt | H |
| L22 | No secret in argv, environment, file, or log | A process listing, the environment, the working tree, stdout, stderr, a panic, a notification, status, diagnostics, and failures contain neither secret | Grep of every surface; process listing | H |
| L23 | Secret redaction | The secret type has no `Display`; `Debug` is redacted; an error path that formats it is a test failure | Compile check and log audit | H |
| L24 | Linux helper secret handling | The app sends `HS2` on helper stdin with both secrets as 64 lowercase hex characters per line; the helper decodes them and forwards raw bytes on descriptor `3`; stdout carries only `HS_READY` and `HS_PORT`; the renderer never sees a secret; there is no app secret pipe | Stdin, descriptor, and stdout trace; renderer memory; no pipe | H then D |
| L25 | Zeroization | The app, helper, and engine clear their copies on quit, on engine process exit, and at a launch end. A tunnel stop, a window close, or a screen lock does not clear them (section 11.4.3). A stale copy cannot authorize a second launch | Memory check; second launch 401; hidden window still authorized; tunnel stop keeps the copy | H then D |
| L26 | Headless and console gate | A headless start has no PC and cannot pair a new source; if a console actor exists, it reads the PC from a TTY or private descriptor and never echoes it | Route matrix; terminal capture | H |
| L27 | No bootstrap acknowledgement | The engine writes nothing to descriptor `3` and nothing to any other descriptor. The helper's reply is a process exit code only. A test that expects a reply byte finds none | Write trace on every descriptor; exit code | H |
| L28 | Bootstrap descriptor kind and direction | Pipe read end with `O_RDONLY` accepted; socket requires successful `shutdown(SHUT_WR)` before read despite `O_RDWR`; closed, write-only, read-write FIFO, regular file, terminal, character device, other kind, and failed shutdown exit `9`. macOS launchers and proposed Linux helper use pipes; Linux development launcher uses socket. No reply | Kind, `F_GETFL`, shutdown result, pre-read trace, code; W7 | H |
| L29 | Bootstrap failure is an exit code | Bad magic or a bare token exits `2`; a truncated frame exits `3`; an unsupported version exits `4`; an invalid length exits `5`; trailing bytes exits `6`; exactly `HSBOOT1` after a complete frame exits `7`; `--bootstrap-fd` with `--token-fd` exits `8`; an unusable descriptor or a selector other than `3` exits `9`; no end of input within 5 seconds exits `10`. The check order is the one in `DESIGN.md` section 11.4.1, and each fixture has exactly one code. No secret appears in the process output | Exit code per class; stderr and stdout grep; no reply byte | H |
| L30 | No bare-secret fallback on the framed descriptor | With `--bootstrap-fd 3`, a descriptor that holds a legacy token line (64 hex characters and a newline) exits `2`, and a bare value shorter than 7 bytes exits `3`. The engine never reads either as a bearer. `--bootstrap-fd 3` together with `--token-fd N` exits `8` for every `N`, including `3`, before either descriptor is read | Exit codes; no read on `8`; no tunnel control with the bare value | H |
| L31 | App creates both secrets | The app, not the helper and not the engine, generates the API bearer and the PC. The helper has no generation path and no secret in its reply | Code inspection; XPC and stdin trace; no engine-generated secret | H |
| L32 | Secrets travel on the existing request | macOS: both secrets are fields in the XPC request and are absent from the reply. Linux: the stdin request is the `HS2` three-line form with both secrets, an `HS1` request is refused, and no extra descriptor or app pipe exists | Request and reply trace; descriptor list; no pipe; `HS1` refusal | H |
| L33 | Helper forwards and keeps no copy | The helper writes the frame once, closes its write end, and holds a copy only for the launch. A second launch has different values | Frame trace; helper memory check after engine exit | H then D |
| L34 | Window close keeps the bearer and the PC | With a tray present, closing the window hides it, the app and tunnel keep running, and a control request still succeeds with the same bearer and PC | Window state; control request; secret unchanged | H then D |
| L35 | Screen lock ends the ceremony, not the credentials | On lock, arming is cleared, the code display is cleared, and the QR secret is destroyed. The tunnel keeps running and a control request still succeeds | State and secret before and after lock; tunnel status | D |
| L36 | Quit and engine process exit clear both secrets | Quitting the app, an engine process exit (graceful exit, crash, or parent-channel close), and a launch end zeroize the copies. A tunnel stop does not (V15). A stale copy cannot authorize the next launch | Memory check; next launch 401 with the old value; tunnel stop keeps the copy | H |
| L37 | Authorization matrix as a table | Every row of section 11.4.4 of the design is a test case: route family times credential. Bearer-only on a pairing route is 401 with no change, PC-only on a start route is 401 with no change, and no credential on a read-only route returns no secret | Table-driven results; store trace; response grep | H |


## M. Host-only work that must land before any device test

Historical work list, blocked until a complete candidate passes independent
review. Its pin-only procedures and expected outcomes do not authorize code.

1. Extend the spike with a server-role certificate from a fixed key and a second
   client identity, so B1 to B7 have real cross-builder vectors.
2. Add the exporter to the loopback harness and run A1 to A20, including the
   `th(state)` and commitment coverage and the empty-context forms.
3. Add a TLS-framed SOCKS5 adapter and run E1, E7, E8, E13, E17 to E28, and G1
   to G19 on loopback, including the shared-gateway candidate set.
4. Add the two-sided pairing state machine with the transcript context, arming
   and its subordinate deadlines, the mechanism rule, the scan order, the source
   attempt budget, both confirmations, the known path, the staged and confirmed
   states, and the QR proofs. Run C1 to C58, F1 to F32, and K3 to K6.
5. Add the store with the store-wide `generation`, the anchor, the purpose set,
   the staged state, the multi-record model, the per-record credential map, the
   revocation epoch, and the per-session client pin index. Run D1 to D42 and F29
   to F39.
6. Add the bootstrap with the one-way framed descriptor, the fixed exit codes, the
   redacted secret type, the zeroization path, and the bearer separation. Run L1
   to L37 and K33 to K35 on the host. A missing, malformed, or versioned frame
   must fail closed, and the engine must write nothing back.
7. Add negative tests that a plaintext client, a TLS 1.2 client, a client with
   no ALPN, a client with the other label, a client with two labels, and an
   anonymous client are refused on both listeners.
8. Add a framed half-close harness. Delay the peer `FIN` for 2.5, 30, and 120
   seconds while the download continues. Run the split-frame, coalesced-frame,
   invalid-header, truncation, pre-reply, and abort rows G1 to G18, G28, and G29.
9. Add a fault-injection harness for the record commit order, D14, D19, D20,
   D30, and D31.
10. Add the resource-budget tests and record memory, CPU, and connection counts.
11. Add the constant-time comparison tests for all three peers.
12. Add GUI tests that no pairing route exists for the page, no QR payload or
    code appears in any response or storage, the headers are `no-store`, and the
    listener is loopback only.
13. Audit the security claims in the design and in user text. The audit must
    confirm that the text does not claim a proof, post-quantum forward secrecy,
    fail-closed behaviour, Android resumption being disabled, a browser QR or
    code, a target-app channel that does not exist, or a secret in the browser
    or a status response.
14. Run the cross-stack exporter equality test in the host Swift proxy harness
    before any iOS device row, so J3 is not the first time the value is
    compared.
15. Add the QV fixed vectors, including QV16 and QV17, and run them in the Rust,
    Swift, and Kotlin suites.
16. Fuzz the frame parser with short reads, split headers, invalid lengths, and
    unknown types. A panic or an unbounded allocation is a failure.
17. Add the Rust dependency gate: `cargo tree -e features -i aws-lc-rs` is
    empty, `tls12` is absent, and `rustls` and `rcgen` build with
    `default-features = false` and the selected features.
18. Add the certificate allowlist vectors: exactly two extensions, exact
    criticality, and one negative case per forbidden extension family.
19. Add the launcher descriptor test: a fixed frame on descriptor `3` selected by
    `--bootstrap-fd 3`, a short frame, an `api_len` of 31, 33, and 64, a zero PC,
    a second bootstrap, a closed and a write-only descriptor, a selector other
    than `3`, a writer that never closes, a trailing byte, an unknown version, a
    bare legacy token line, `--bootstrap-fd` plus `--token-fd`, a read-only
    descriptor with no reply channel, and the Linux helper's mapping of each
    engine code to its own engine-failed status. Run L19 to L30, U1 to U4, U18,
    V12, V13, V19, and V20.
20. Add the shared-gateway candidate harness: two records with one host and port,
    one candidate, several candidates, a matching pin, a non-matching pin, a
    matching pin with a mismatched server key, and a duplicate pin. Add the
    in-memory rustls client and server pair for V5, with a counting server
    `ClientCertVerifier` and a counting client signer; the client resolver count
    is recorded but is not the pass criterion. Run E25 to E29, E31, T12 to T15,
    V1 to V5, V9, and V24.
21. Add the source revocation harness: a live flow, a local removal, a
    per-session pin index, the per-pin revocation epoch, an atomic registration,
    a registration that races the sweep for the same pin and for another pin, a
    forced close with no `FIN`, a remote retry, and the epoch map values and
    tombstone cap. Run F29 to F39, T8 to T11, V7, and V23.
22. Add the arming harness: malformed hellos, mechanism mismatch, a verified
    reveal, one case for each disarm label SD1 to SD10 and TD1 to TD10 in
    `DESIGN.md` section 4.2, the QR single-use rule, the subordinate prompt
    deadline, and a QR created near the end of the window. Run C49 to C58, T20
    to T24, V6, V16, V18, and V22.
23. Add the abort API observation harness. It records whether the outer close is
    a RST or a graceful TLS close; it does not assert a reset. Run T25 to T28.
24. Add the credential-lifetime harness: a hidden window, a tray session, a
    screen lock, a tunnel stop, an engine process exit, and a quit, each with the
    bearer and PC still usable or cleared as section 11.4.3 says. Run L34 to L36,
    V15, and V18.
25. Add the authorization matrix as a table-driven test over section 11.4.4,
    including the query, cookie, URL, page-storage, `Referer`, previous-launch,
    short, and unknown-route variants. Run L37, U15, and V14.
26. Add the canonical host vector and the seven near-canonical rejections. Run
    E29, U20, QV19, and V8.
27. Add the restart sequence test with the source app closed, backgrounded, and
    in the foreground. Run E30 and U17.
28. Add the token-only path inventory test: each path in `DESIGN.md` section 23.1
    fails closed with a fixed message when no PC exists, and the Windows token
    source is the environment or prompt, never `--secrets-fd`. Run U11 to U14,
    V10, and V11.
29. Add the lock-scope test: a blocked network flush and a blocked durable flush
    with a concurrent store mutation and session registration. Run D33, R17, and
    V17.

## N. Device work

Blocked until candidate review, product coexistence and migration choices,
per-host recovery feasibility, and host prerequisites are resolved. Device
evidence remains a separate release gate.

Run on the iOS Simulator and the Android emulator first, then on a real phone
with a real hotspot, with the device owner's approval. Emulator and simulator
results do not prove carrier, hotspot, or physical-device behavior.

1. iOS identity assembly with `kSecClassIdentity`, plain key, then Secure
   Enclave key.
2. iOS exporter on a post-ready metadata handle after `.ready`. This is the gate
   for iOS source mode. Record the value or the NULL result.
3. iOS ALPN on 17.0 to 18.4 and 18.5 and later, including a client that offers
   no ALPN.
4. iOS locked key access: before first unlock, after first unlock while locked,
   and while an established flow runs. Record the accessibility class.
5. iOS framed half-close, abort wire result, tickets, and background/foreground
   lifecycle. Record the exact suspension and close behavior.
6. iOS anonymous client on both listeners with peer authentication required.
7. Android TLS 1.3 server with the Conscrypt provider and a Keystore key on API
   26, 28, 29, 30, 31, and one OEM build.
8. Android vendor Keystore digest authorization: `DIGEST_NONE` and
   `DIGEST_SHA256` on the identity key.
9. Android ticket trace and post-handshake recheck on every connection.
10. Android framed half-close, abort wire result, and exporter equality with the
    Rust client.
11. Android APK size per ABI with and without the Conscrypt library, and a 16 KB
    page-size run.
12. Certificate template acceptance on both platform stacks, including the exact
    extension allowlist.
13. QR camera and decoder on Android: arm, scan once, expire, and require a new
    QR after one use.
14. Background suspension behavior for the listener and for an armed session.
15. Probe cost and battery effect at the chosen interval, now on the proxy
    channel.
16. Live latency and throughput against today's plaintext SOCKS.
17. Active hotspot client fetches the source certificate and records the pin.
18. A local process reads a native target app QR and pairs once. The browser
    page has no QR to read.
19. macOS XPC pairing capability: the app-only caller, a rejected second
    connection, a rejected caller without the audit token, both secrets arriving
    in the authenticated request, and a reply that carries only the port, a
    launch id, and readiness.
20. Linux packaging: the app creates both secrets, sends `HS2` on helper stdin
    with 64 lowercase hex per secret, the helper forwards raw bytes on descriptor
    `3`, stdout carries only `HS_READY` and `HS_PORT`, the Electron main process
    holds the PC, the renderer receives an image, there is no app secret pipe,
    and the browser page receives no code or QR.
21. Windows target: QR and SAS are disabled, the app is labelled a preview, and
    no target proxy is claimed without a console actor.
22. Two sources on one target: separate credentials, separate tokens, a
    single-source forget that leaves the other working, a shared gateway
    candidate match, one candidate with a nonmatch, several candidates with no
    match, and the same neutral message with no forget action.
23. Half-closed flow paused 301 seconds: record the source idle result.
24. Source local removal while a target holds a live flow: the removal completes,
    the matching session closes, and an unrelated source session survives and
    continues byte-exact.
25. Source per-session client pin index on a real flow: one entry per accepted
    session, no token, no entry for a failed handshake.
26. Abort wire result on each peer: record whether the close is a RST or a
    graceful TLS close. Do not fail a row because it is graceful; the peer rule
    is the gate.
27. Arming exhaustion on a device: send 20 malformed hellos, then complete a
    ceremony; the source arming must survive the malformed traffic. Then hold the
    prompt to its deadline and record that the denial is bounded, not prevented.
28. QR scan order on two devices: the target sends no hello before the scan and
    Continue, and the source refuses an early hello without disarming.
29. One-way bootstrap on a device: the engine starts with descriptor `3` meeting L28 pipe or socket rules and no
    reply channel; malformed variants use the fixed codes `2` to `10`.
30. Credential lifetime on a device: a tray window close and a screen lock keep
    the tunnel and the control path, and end the ceremony. A tunnel stop keeps
    the launch credentials and credential map; an engine process exit clears
    them.
31. Target restart with the source app closed, backgrounded, and in the
    foreground: the fixed message, no timer retry, and success on the third case.
32. Forced revocation on a device: a live relay is cancelled with no `FIN`, the
    target resets, and an unrelated source session for another pin survives.
33. Same-user reader on each desktop target: record what the shipped app
    actually resists. A graceful result here is a recorded limit, not a pass.
34. Windows `tun --phone` token on a real Windows host: the environment or
    no-echo prompt path, the `--secrets-fd` refusal, and no token in the process
    listing.
35. Diagnostic token prompt on each host: no echo, no `argv`, and the Windows
    environment form marked for removal.
36. QR deadline on a device: create the QR, wait before displaying it, and
    confirm the deadline is unchanged and the late proof is refused.
37. Bootstrap descriptor `3` on a device: read-only engine end, no reply byte,
    and the exit-code matrix for the malformed variants.
38. Lock scope under a blocked local flush and a blocked network flush: no
    deadlock, and a concurrent store mutation and session registration complete.

## O. Candidate review and release gates

### Candidate review gate

Before any protocol implementation or device test, an independent review must
accept a complete incarnation protocol, durable local revocation and per-host
crash/recovery model, per-host store-key provisioning and loss recovery, and
migration/status isolation including a specified timer state machine. Each
credential and trust recheck requires validated `generation == anchor`. Missing,
unreadable, unequal or uncertain state blocks use. The separately documented
candidate critique is NOT APPROVED and does not satisfy this gate. Until then
protocol implementation and device tests are blocked.

### Product choices and timing

Coexistence, migration, any hard v1 cutover, and when to decide them remain
product choices. This document selects none. A technical candidate review does
not make these decisions. Choices needed for the candidate must be made before
its acceptance; remaining applicable choices must be made before release.

### Release gate

After the candidate gate and applicable product decisions, release additionally
requires implementation and the host and authorized device evidence below. A
review acceptance alone is not release approval.

The design and this matrix are UNAPPROVED. The following are release
requirements, not prerequisites that must all pass before implementation.
Protocol implementation requires the candidate gate above. Live work requires
separate authorization and applicable safety rules:

1. Confirm independent technical acceptance of a future complete candidate
   revision, including the applicable technical questions in `DESIGN.md`.
   Product owners separately decide product questions at the candidate or
   release stage as applicable. The candidate review must confirm the B1 to B6 and M1 to M7 mapping
   in section 2.1.1 and the M8 and M9 mapping in section 2.1 against
   `50f21843-f0b1-4e95-b063-4f1c686bfcf7`, and check the eight completion-pass
   corrections in section 2.1.2 against the cited code and rows.
2. The review accepts or rejects the SAS residual and the bounded denial in Q1,
   Q25, and P24. If it rejects SAS, the matrix loses the SAS rows and QR becomes
   mandatory, and QR keeps its own single-use denial.
3. The review accepts the exporter binding and the iOS gates in Q7 and Q13, or
   iOS source mode is removed from the release.
4. Cross-stack exporter equality passes on every peer, including the empty
   context forms. A mismatch blocks the release; it is not worked around.
5. The review accepts the Android stack decision in P1, P13, and P14, the
   vendor Keystore path in Q18, and the ticket evidence in Q3, or Android source
   mode is removed from the release.
6. The review accepts the framed `DATA`/`FIN` half-close in Q5 and P12. The
   design already uses it; there is no per-platform close profile.
7. The review accepts the rollback limit in Q14 and the target-app-only pairing
   surface in P17 and Q16. The browser page has no pairing surface at all.
8. The review accepts the known path in Q2, the restart sequence in Q4 and
   section 7.10.1, and a reviewed replacement for the historical section 13
   commit and recovery procedures, or the design changes before implementation.
9. The review accepts the Conscrypt maintenance and 16 KB plan in P19 and Q18.
10. The review accepts the app-created secrets, the one-way bootstrap on
    descriptor `3` selected by `--bootstrap-fd 3`, the binary frame with exactly
    32 raw bytes per secret, the 64-hex request and headers, and engine exit
    codes `2` to `10` in
    Q17 and Q27, the credential lifetime split in P25 and Q28, the Windows and
    headless gate in P20 and P22, and the mandatory-pairing cost in P2 and Q29,
    or the affected target is removed from the release. There is no token-only
    fallback, and section 23.1 lists the paths that stop working per command
    and platform, including the environment token that macOS, Linux, and
    Windows read today and that is planned for removal.
11. The review accepts the source 300 second idle or the P21 change, the forced
    source revocation in Q23 and Q28, the per-pin revocation epoch in section
    14.1, the shared-gateway candidates and the single neutral nonmatch message
    in Q24 and Q30, the arming budget in Q25, the complete disarm lists SD1 to
    SD10 and TD1 to TD10, and the abort rule in Q26. The
    claim in the UI and the tests must match each decision.
12. The host-only rows in M pass, including the QV vectors, the R rows, the S
    rows, the T rows, the U rows, and the V rows. A host pass is not a device
    pass.
13. The device rows in N are run with the device owner's approval on a real
    phone and a real hotspot. An emulator pass is not a device pass.
14. Independent review accepts a complete record-incarnation protocol, per-host
    crash and recovery model, and v1/v2 migration and status isolation design.
    The historical pin-only procedures and outcomes cannot satisfy this gate.
    W17 to W22 must pass against the reviewed replacement, including host
    feasibility and fault boundaries; a host pass is not a device pass.
15. The measured CPU, memory, battery, APK size, 16 KB result, and handshake
    costs are recorded. The cross-stack exporter, vendor `DIGEST_NONE`, 16 KB,
    iOS lifecycle, bootstrap, credential lifetime, shared-gateway candidate,
    per-pin revocation, arming, canonical host, QR deadline, Windows token
    source, and abort wire-result gates stay open until their device rows pass.

## P. What this matrix does not prove

- It is not a proof of security. It is a list of things to observe.
- It does not cover traffic analysis, DPI resistance, or fingerprinting beyond
  the rows named here.
- It does not cover post-quantum resistance.
- It does not cover a compromised device on either side.
- It does not cover a passive TCP relay that forwards ciphertext. Channel
  binding does not detect it, and it does not need to.
- It does not cover carrier behavior. The channel ends at the source device.
- A pass on the host says nothing about a device. A pass on an emulator says
  nothing about a phone.
- It does not make the product fail-closed. More-specific routes, local DNS, and
  network extensions can still bypass the tunnel.
- It does not prove that a person who approves a pairing without comparing the
  code or scanning the intended QR is protected. Pairing is target-app-only and
  requires the pairing capability, but a careless action is still possible.
- It does not resolve the SAS cross-session residual, the iOS exporter gate,
  Android resumption, iOS locked key access, store rollback, the vendor
  Keystore `DIGEST_NONE` path, the 16 KB runtime, the iOS lifecycle, the
  source 300 second idle, the bootstrap, the credential lifetime, the
  shared-gateway candidate order, the per-pin epoch behavior under real load,
  the forced revocation close behaviour, the arming attempt budget, the bounded
  denial of one ceremony attempt, the canonical host family, the QR deadline,
  the Windows token source, the abort wire result, or the cost of the framed
  data phase. Those are open questions, device gates, or unmeasured costs, not
  test results.
- It does not prove that a pin nonmatch means the source identity changed. No
  row may turn a nonmatch into an automatic forget, and V1 to V4 and V9 are the
  guard against that regression.
- It does not prove that a Windows or headless target can pair. Under mandatory
  pairing it cannot, unless a console actor is designed.
- It does not preserve the token-only paths. Section 23.1 of the design lists the
  proxy and diagnostic paths that stop working on a target without a protected
  actor, and no row here makes them work again.
- It does not protect the app-held secrets from a process running as the same
  user. Row U16 records what each platform resists; that is a limit, not a pass.

## Q. Cross-language fixed-vector plan

The three implementations must agree on bytes before any device row. Each vector
is a small public fixture. The plan names a future
`experiments/tls-transport-spike/vectors/` directory; it does not create it.
A vector uses fixed test keys, fixed nonces, and fixed certificates. It never
uses a real device key, token, or pin.

Each vector is one JSON object:

```
{
  "name": "string",
  "inputs": { "field": "hex" },
  "outputs": { "field": "hex" }
}
```

The Rust, Swift, and Kotlin suites load the same file and assert exact bytes. A
vector that cannot be produced by all three suites is a design ambiguity, not a
test skip. A vector that only one suite can produce does not count as coverage.
One exception is named, not implied: QV20 is a target-side launch vector. Its
producers are the Rust engine and Linux helper, the macOS Swift app, and the
Linux Electron main process. The Android source app has no bootstrap, so the
Kotlin suite does not load QV20.

| # | Vector | Inputs | Outputs |
|---|---|---|---|
| QV1 | Certificate TBS template | fixed P-256 key, fixed serial, fixed validity, empty subject and issuer, exact `basicConstraints` `30 00` critical and `keyUsage` `03 02 07 80` critical | exact TBS DER, with no third extension |
| QV2 | Canonical pin | fixed 65-byte uncompressed P-256 point | SHA-256 over the `0x04` prefix and X and Y |
| QV3 | Short label | fixed pin | SHA-256 over the `hs-label-v4` label and the pin, first 4 bytes |
| QV4 | Transcript context | fixed wire version, `mech`, `flags` with only `0x01` allowed, roles, purpose, pins, nonces, `pairing_id`, ALPN, TLS marker, `cb` | exact `ctx` bytes |
| QV5 | Target commitment | QV4 inputs plus `nonce_T` | exact `commit_T` |
| QV6 | Source commitment | QV4 inputs plus `nonce_S` | exact `commit_S` |
| QV7 | Confirmation hashes | `confirm_ctx` and state bytes `0x01` to `0x06` | exact `th(state)`; `0x07` is retired and rejected; `0x08` is a `FORGET_RESULT` hash under the separate forget label, not `th(0x08)` |
| QV8 | SAS code | fixed `confirm_ctx` | the first 4 bytes as a big-endian integer, the integer modulo 1_000_000, and the six-digit string |
| QV9 | QR proofs | fixed secret and `confirm_ctx` | exact `proof_source` and `proof_target` |
| QV10 | FORGET request frame | fixed roles, purpose, request id | exact frame bytes |
| QV11 | FORGET result frame and hash | fixed roles, purpose, request id, status, `cb`, pins | exact frame bytes and `forget_hash` |
| QV12 | Canonical store bytes | fixed generation, fixed records, fixed order | exact canonical bytes |
| QV13 | Store tag | fixed `K_store`, QV12 bytes | exact HMAC-SHA256 tag |
| QV14 | Data-phase frames | fixed payloads and sequences | exact `DATA` and `FIN` bytes |
| QV15 | Negative vectors | wrong role, wrong version, all-zero commitment, wrong length, unknown type, `flags & 0xfe != 0` | each rejected before allocation or store access |
| QV16 | `PAIR_HELLO` frame | fixed `mech = SAS`, `flags`, `pairing_id`, `commit_T`, version `0x04` | exact 2-byte length, type `0x01`, version, and body bytes |
| QV17 | `PAIR_RESULT` frame | fixed status, port, token, host, `th(0x04)` | exact length, type `0x07`, version, and body bytes, including both length prefixes |
| QV18 | `PAIR_READY` and reveal frames | fixed `commit_S`, `nonce_T`, `nonce_S`, and QR `proof_source` | exact bytes for types `0x02`, `0x03`, and `0x04` |
| QV19 | Canonical host (M3, M9.3; sources E29 and U20) | fixed IPv4 address and its canonical rendering, plus the seven near-canonical variants listed in U20: `010.0.0.1`, `10.0.0.1.`, `10.0.0.1:20000`, `[10.0.0.1]`, `10.0.0.1%en0`, ` 10.0.0.1`, and `fe80::1` | the accepted 7 to 15 byte value and one rejection result per variant, seven rejections in total |
| QV20 | Bootstrap frame and helper request (M9.7, M9.8) | fixed API bearer, fixed PC, `api_len` 32, `pc_len` 32; Linux request tag `HS2` with two 64-lowercase-hex lines, decoded to 32 raw bytes each; macOS XPC fields as raw 32-byte `Data`; bootstrap descriptor `3` selected by `--bootstrap-fd 3`; HTTP header renderings of both secrets. Producers: the Rust engine and Linux helper, the macOS Swift app, and the Linux Electron main process. The Kotlin suite has no bootstrap and does not produce this vector; that is not a coverage gap | exact 76-byte and 44-byte frames; exact `HS2` request bytes; exact `Authorization` and `X-Pairing-Capability` header values; the engine exit code for each class (`2` magic, `3` truncation, `4` version, `5` length, `6` trailing, `7` second frame, `8` conflict, `9` descriptor, `10` deadline) and the helper refusal of `HS1`, uppercase hex, and a 63- or 65-character line |

QV1 to QV13 and QV16 to QV20 run before any device row. QV14 and QV15 run in
the host frame harness. A change to a transcript field or a frame field requires
a new vector and a new independent review note; it is not a silent test update.

## R. Revision-3 blocker adversarial rows

Each row is an adversarial test for one blocking finding in `DESIGN.md` section
2.4. "Fail" means the session ends with a fixed error and no record, token, or
trust change is written. R15 to R20 are extra adversarial rows that the blocker
fixes depend on.

| # | Attack or scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| R1 | Known session tries to fall back to a prompt (B1) | The session ends; no prompt, code, record, or token in that session | Fixed "pairing is incomplete" message; a new session is required | H |
| R2 | Peer uses `shutdownOutput`, `.finalMessage`, or a TLS close as the half-close (B2) | Treated as truncation; inner RST; no clean FIN | No `FIN` frame; RST observed | H then D |
| R3 | iOS exporter is taken from a retained verify-block handle (B3) | The build does not use the verify-block handle; only the post-ready metadata path exists | Code inspection; a retained-handle test fails or is absent | H |
| R4 | FORGET hash uses `pin_peer` then `pin_self` (B4) | The hash does not verify; the frame is rejected | Fixed failure; no deletion | H |
| R5 | Store uses a per-record counter or a lower generation (B5) | The store fails the anchor check; a per-record fixture is rejected | Fixed "damaged" message | H |
| R6 | Final message lost after `PAIR_DONE`, `PAIR_DONE_ACK`, or `FORGET_RESULT` (B6) | Staged or confirmed state matches section 13.2 and section 18.4; no automatic promotion or delete | Abort at each send; state table matches | H |
| R7 | Browser is asked for a QR payload or any pairing control (B7) | No pairing route for the page; 401 `pairing_requires_target_app` or 404; no QR bytes, code, or state change | HTTP status; grep; DOM dump | H |
| R8 | A store lock is held across a TLS read or write (B8) | No deadlock; the lock is not held across the network call | Lock trace; timeout test | H |
| R9 | A Keystore key without `DIGEST_NONE` reaches the Conscrypt handshake (B9) | The handshake fails with the fixed protected-key message; no exportable fallback | Key authorization list; handshake abort | D |
| R10 | An older or unverified Conscrypt artifact is used (B10) | The build rejects it; only the pinned 2.9.0 artifact with the recorded alignment is accepted | Dependency verification result | H |
| R11 | Matching pin with a different private key (B11) | `CertificateVerify` fails; no application byte | Signature failure | H |
| R12 | iOS cannot see the client's offered ALPN list (B12) | The negotiated label is checked after `.ready`; nil or mismatch is a hard failure | Handshake and negotiated label | D |
| R13 | QR-armed target is offered SAS or `known` (B13) | Refused; no code; a failed proof consumes the secret | Fixed error; no record | H |
| R14 | A transcript or frame vector is missing or differs by language (B14) | The QV gate fails; no device row starts | Vector results in all three suites | H |
| R15 | A staged record is used for `known` or proxy traffic | Refused with a fixed message; no token | Fixed "pairing is incomplete" message | H |
| R16 | Frame parser receives an invalid header | `DATA` 0, `FIN` nonzero, unknown type, or length over 16384 fails before allocation; inner RST | Memory flat; fixed error; RST | H |
| R17 | A blocked network write and a concurrent store mutation (B8) | No deadlock; the mutation completes; the network write is not under the store lock. A local durable flush follows section 7.8 and V17 | Timeout and lock trace | H |
| R18 | A vendor Keystore refuses `DIGEST_NONE` or `NONEwithECDSA` (B9) | The Conscrypt path is blocked on that device with the fixed message; no exportable key and no silent provider fallback | Vendor, model, API, and result | D |
| R19 | Every response and log is searched for secrets (B7, B11) | No token, private key, full pin, exporter, QR secret, API bearer, pairing capability, or code | Grep of responses, logs, notifications, and storage | H |
| R20 | `CertificateVerify` bypass on each peer (B11) | rustls does not return `HandshakeSignatureValid::assertion()` without the provider check; iOS and Conscrypt reject the mismatch | Per-peer signature failure; no application byte | H then D |
| R21 | Page or local client self-consents with the API bearer | Every arm, code, allow, deny, cancel, and QR route returns 401 without PC; no prompt and no state change | Route matrix; store trace | H |
| R22 | Page obtains a QR payload | No route returns a payload with the page credential; the page has no PC and no channel | HTTP, DOM, storage, and log grep | H |
| R23 | Abort path emits `close_notify` or a clean close | The sender sends no `FIN` frame and no application data. A graceful outer close is still truncation at the peer. A platform that emits `close_notify` fails the no-`FIN` rule. Record the wire result | Trace; no `FIN`; inner reset; wire result recorded | H then D |

## S. Revision-4 blocker adversarial rows

Each row names the finding in `DESIGN.md` section 2.3 that it tests. "Fail"
means no record, token, credential, or trust change is written.

| # | Attack or scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| S1 | Page with the API bearer tries to arm, read the code, allow, deny, cancel, or fetch a QR (R4-1, R4-2) | 401 `pairing_requires_target_app` on every pairing route; no prompt; no state change | Route matrix; store trace; no code in the response | H |
| S2 | A local process reads the browser page and tries to pair (R4-1, R4-2) | The page has no PC, no code, no QR, and no pairing control | DOM, storage, and network dump; route matrix | H |
| S3 | Missing or old pairing capability (R4-1, R4-2) | An engine without PC, and a PC from a previous launch, refuse pairing; a fresh PC succeeds | 401; state unchanged; new launch works | H |
| S4 | Windows target tries to pair (R4-1, R4-2) | QR and SAS are unsupported; the UI says so; no fallback to a local page | Screenshot; route matrix | D |
| S5 | Two sources, one token each (R4-3) | The target uses only the selected record's host, port, and token; a mismatch aborts | Two connections; no cross-token use | H |
| S6 | Source B presents source A's pin (R4-3) | The handshake fails; B never receives A's token | No SOCKS auth; A's credential unchanged | H |
| S7 | `PAIR_RESULT` carries a host or port from the client or a hello (R4-3) | Rejected; the source uses its own bound listener settings | Fixed error; no credential write | H |
| S8 | Known re-pair while the source app is closed (R4-3) | No pairing listener; fixed message; no token change | Connection failure; source record unchanged | D |
| S9 | iOS anonymous client on either listener (R4-4) | Peer authentication required; handshake aborts | No application byte | D |
| S10 | `DATA` or `FIN` before the SOCKS5 success reply (R4-5) | Protocol error; no inner flow; connection closed | Fixed error; no inner flow | H |
| S11 | Failed attempt leaves the device armed (R4-6, superseded by M6) | The target is disarmed after its hello. The source stays armed through malformed and unauthenticated hellos, counts a failed SAS proof only after a verified reveal, and allows three failures. A failed QR proof consumes the source arming | Target unarmed; source counter; fourth SAS attempt refused; QR requires a new scan | H |
| S12 | Remote FORGET while a flow uses the record (R4-7, superseded by M3) | HISTORICAL, BLOCKED AND NON-EXECUTABLE. A live flow must not veto an attempted source local removal; durable success and session outcomes are not established. | Future reviewed protocol and recovery model; W17 to W20 | H then D |
| S13 | Duplicate or different request id in one session (R4-7) | Same id returns cached bytes; a different id closes with no reply | Identical bytes or close; one write | H |
| S14 | Half-closed flow paused 301 seconds (R4-8) | Record the source idle result; no claim of a 600 second source window | Timer; reset or delivery | H then D |
| S15 | Abortive close (R4-9, superseded by M7) | No `FIN` frame and no application data. The outer close may be a RST or a graceful TLS close; the peer treats a close without a `FIN` as truncation. Record the wire result | No `FIN`; inner reset; wire result recorded | H then D |
| S16 | Certificate with a third extension, duplicate extension, or wrong criticality (R4-10) | Rejected after parse; no pin | Fixed failure | H |
| S17 | Rust build pulls `aws-lc-rs` or `tls12` (R4-11) | The dependency gate fails; the build is rejected | `cargo tree` output | H |
| S18 | `flags` bit outside `0x01` (R4-12) | Rejected before a commitment | Fixed error; no code | H |
| S19 | Conscrypt check after the handshake starts (R4-13) | The build or test fails the order rule; the check runs before `startHandshake()` | Code inspection; no TLS byte on a non-Conscrypt socket | H |
| S20 | Exporter context forms differ (R4-14) | `None`, empty array, and zero-length context produce the same 32 bytes; a non-empty context does not match | Byte compare per form | H |
| S21 | SAS code formula differs by language (R4-15) | QV8 and QV16/QV17 match byte for byte; the integer and six-digit string agree | Three suite results | H |
| S22 | iOS app backgrounds during an armed session or a live flow (R4-16) | Arming is cleared; pairing stops; the live flow result is recorded, not assumed | State and flow result | D |

## T. Revision-5 blocker adversarial rows

Each row names the blocker in `DESIGN.md` section 2.2 that it tests. "Fail"
means no record, token, credential, or trust change is written. These rows were
the revision-6 gate; revision 8 keeps them, section U keeps the revision-6 rows,
and section V adds the revision-7 M8 and M9 rows. The earlier S rows remain for
the revision-4 findings. The M1 to M7 labels here are the revision-5 blockers;
the revision-2 findings with the same letters are historical.

| # | Attack or scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| T1 | Engine is asked to generate the pairing capability (M1, narrowed by B1 and B2) | The engine has no PC or API-bearer generation path. The app creates both, the helper forwards one framed record on one pipe read end or self-restricted socket, and the engine writes nothing back. A malformed frame is a fixed exit code, not a reply | Descriptor write trace; no engine-generated secret; no reply bytes; exit code | H |
| T2 | Secret is placed in argv, environment, a file, a log, a panic, a status, or a failure record (M1) | Every such path is absent or redacted. The secret type has no `Display` and a redacted `Debug` | Process listing; environment; filesystem; log and response grep; compile check | H |
| T3 | macOS caller without the app audit token, or a second XPC connection (M1, narrowed by B2) | Rejected. Both secrets travel in the authenticated request; the reply carries the port, a launch id, and readiness only, never on stdout or stderr | XPC trace; fixed error; reply and stdout dump | D |
| T4 | Linux helper writes the PC to stdout, or the renderer reads it (M1, narrowed by B2) | The helper receives both secrets on the `HS2` stdin request, forwards them on the bootstrap descriptor, and stdout has only fixed status lines. The renderer receives an image, not the PC. There is no app secret pipe | Stdin, descriptor, and stdout trace; renderer memory; HTTP log | H then D |
| T5 | Windows target under mandatory pairing (M2) | No PC exists; QR, SAS, and new-device pairing are unavailable; the target proxy is not claimed; there is no token-only or browser fallback | Route matrix; UI text; no handshake to a new source | D |
| T6 | Headless target under mandatory pairing (M2) | No PC exists; the known path only; a new device cannot be paired; there is no unauthenticated local page | Route matrix; UI text; no new record | H then D |
| T7 | A console actor is proposed for headless pairing (M2) | It reads the PC from a TTY or a private descriptor, never from argv, and never echoes it. Without that actor, headless proxy is unsupported | Terminal capture; process listing; design gate | H then D |
| T8 | Source local removal while the target holds a live flow (M3) | The removal succeeds. The record is deleted durably and the matching sessions close by authenticated `client_pin`; the target sees truncation | Record gone; matching flow reset; no removal refusal | H then D |
| T9 | Per-session client pin is taken before the post-handshake recheck (M3) | Rejected by the order test. The index is filled only after the recheck and before the first application byte | Code inspection; trace order; no index entry for a failed handshake | H |
| T10 | A remote target keeps a flow open to block removal (M3) | HISTORICAL, BLOCKED AND NON-EXECUTABLE. A live flow must not veto an attempted source local removal; durable success and session outcomes are not established. | Future reviewed commit and recovery, including uncertain writes; W17 to W20 | H then D |
| T11 | Removal of source A closes source B's session (M3) | Only A's sessions close. B's bytes are byte-exact | One reset; one intact flow | H then D |
| T12 | Two paired sources share one host and port (M4) | The target builds two candidates, verifies the server pin, and binds exactly one record and token | Candidate count; one match; one token | H |
| T13 | Shared gateway with no candidate pin match (M4, superseded by M8) | The target sends no token, does not retry another candidate's token, and shows the neutral nonmatch message with no forget action | No SOCKS auth; neutral message; no forget action | H |
| T14 | A target stack sends the client certificate before the server verifier (M4) | The target still sends no token. The client-pin disclosure is recorded as a limitation, not denied | Trace order; no token; recorded result | H then D |
| T15 | Two candidates with the same pin and endpoint (M4) | Rejected before dialing by the duplicate record rule | Store error; no connection | H |
| T16 | Target auto-connects on QR arm before the scan (M5) | No connection and no `PAIR_HELLO` until the local Continue action | No socket before Continue; source still unarmed | H |
| T17 | Source receives a QR hello before the scan (M5) | Refused without consuming the source arming or showing a prompt | Fixed refusal; no prompt; source arming intact | H |
| T18 | Scan, then a late Continue (M5) | The source arms on scan; the target sends the hello only on Continue; a new session has new nonces and a new `pairing_id` | Trace order; one record | H then D |
| T19 | SAS target sends before the source arms (M5) | Refused without consuming the source arming; the target Start action is the only send | No prompt; source arming intact; second attempt after arming works | H |
| T20 | Attacker floods malformed hellos to exhaust arming (M6) | Each malformed or unauthenticated hello is refused; the source arming survives; no prompt is shown | 20 attempts; source still armed; no prompt | H |
| T21 | Attacker sends a mechanism-mismatched hello (M6) | Refused without consuming the source arming | Fixed mismatch; source still armed | H |
| T22 | Three failed SAS proof attempts (M6) | Only sessions that reach a verified reveal count. The fourth attempt is refused until the person arms again; malformed frames do not increment the counter | Counter values; fourth refused; malformed frame leaves the counter | H |
| T23 | Failed QR proof (M6) | The QR secret is destroyed and the source arming ends. A retry needs a new QR and a new scan | Source unarmed; new payload required | H |
| T24 | Target sends two hellos in one arming window (M6) | The target is one-shot: the second hello is refused | One hello; second refused; no record | H |
| T25 | iOS `NWConnection.cancel()` abort (M7) | The call is documented as a graceful disconnect. The app sends no `FIN` frame; the peer treats the close as truncation. The wire result is recorded, not asserted as a RST | Trace; no `FIN`; wire result recorded | D |
| T26 | Android `setSoLinger(true, 0)` abort (M7) | The app sends no `FIN` frame; the peer treats the close as truncation. The public Android page does not promise a RST, so the wire result is recorded | Trace; no `FIN`; wire result recorded | D |
| T27 | Linux `SO_LINGER 0` abort (M7) | The app sends no `FIN` frame; the peer treats the close as truncation. The man pages do not promise a RST, so the wire result is recorded | Trace; no `FIN`; wire result recorded | H then D |
| T28 | Windows `LINGER` abort (M7) | The app sends no `FIN` frame; the peer treats the close as truncation. The Windows reference does not promise a RST, so the wire result is recorded | Trace; no `FIN`; wire result recorded | H then D |

## U. Revision-6 blocker and medium adversarial rows

Each row names the finding in `DESIGN.md` section 2.1.1 that it tests. "Fail"
means no record, token, credential, or trust change is written. B1 to B6 are the
revision-6 blockers. M1 to M7 are the medium findings revision 7 mapped from the
supplied topics. M8 and M9 were supplied in full with the revision-7 review;
their rows are V1 to V18 in section V, and the older U rows that touch the same
rule name the M8 or M9 part they now test.

| # | Attack or scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| U1 | Launcher expects `HSACK1` on descriptor 4 (B1) | The engine writes nothing back. The launcher's readiness comes from the process exit code and, on Linux, the fixed `HS_READY` and `HS_PORT` lines, and on macOS the authenticated XPC reply. A test that blocks on a reply byte times out by test design, not by product behavior | Descriptor write trace; readiness source | H |
| U2 | Bootstrap descriptor opened read-only and no other descriptor passed (B1) | The engine starts and reads the frame. It does not require a second descriptor | Start result; descriptor list | H |
| U3 | Bootstrap frame with trailing bytes or a second frame (B1, M5, M9.8) | Exit code `6` for trailing bytes and `7` for a second frame. Neither value is used | Exit codes; no secret in output; no tunnel control | H |
| U4 | Bootstrap frame with an unknown version (M5, M9.8) | Exit code `4`. The engine does not negotiate, does not parse an older layout, and does not fall back | Exit code; parser trace | H |
| U5 | Engine is asked to create the PC (B2) | No generation path in the engine. The app is the only creator, and the helper forwards | Code inspection; request trace | H |
| U6 | Linux helper is asked to return the PC on stdout, or an app secret pipe is opened (B2) | Neither exists. stdout carries only the fixed status lines and the request already carried both secrets | stdout dump; descriptor and pipe list | H then D |
| U7 | macOS XPC reply carries a secret (B2) | The reply carries the port, a launch id, and readiness only. A test that asserts a secret field fails | XPC reply bytes; grep | H then D |
| U8 | Same-user process writes the helper request before `exec` (B2, M2) | It can supply its own bearer and PC, which is the same-user compromise and not a new channel. Record the result per platform; do not claim the design prevents it | Trace; platform note | H then D |
| U9 | Attacker holds SAS prompt | Withheld or invalid reveal holds the slot to deadline without spending an attempt. A verified reveal followed by timeout or source Deny spends one; three failed attempts disarm and lock out. No record; denial remains possible | Reveal verification, attempt count, deadline and lockout; C58, W11 | H then D |
| U10 | One or several candidates and no pin match (M8) | The same neutral "not answering as any paired source device" message is shown for every candidate count, with no forget action, no record named, and no token. A nonmatch is not treated as an identity change | One message for both counts; no token; no forget action; record intact | H |
| U11 | `tun --phone` under mandatory pairing on Windows, macOS, and Linux (B6) | It needs a paired record and a PC. With no PC it fails closed with a fixed message. It does not reach the source with a token only, from any token source in `DESIGN.md` section 23.1 | Fixed message; no handshake with a client certificate; source record unchanged | H then D |
| U12 | `phone`, `phone-udp-diag`, and `phone-speed-diag` under mandatory pairing on macOS and Linux (B6) | Each needs a paired record and a PC for any source device path, so each is unavailable where no PC exists. They do not keep a token-only listener. The `direct` path of `phone-speed-diag` presents no token and is unchanged. On Windows the three commands are already unavailable | Fixed message; no token-only connection; no route change | H then D |
| U13 | GUI manual token field with `--token-fd` (B6) | The bearer controls the tunnel, and the typed source token alone cannot start a proxy session. The failure names the target app | Fixed message; no source handshake; no record | H |
| U14 | Headless target on a fresh launch (B6, M2) | No PC, no actor, and no token after a restart, so it cannot start a proxy session. Status and diagnostics that need no record still work | Route matrix; fixed message | H then D |
| U15 | Authorization matrix bypass (M1) | A route that accepts the bearer where the matrix says PC is a defect. A pairing route that accepts a record-less client is a defect. The table test covers every row | Table results; store trace | H |
| U16 | Same-user process reads the app (M2) | Linux: the PC and bearer are readable with `ptrace` where the kernel allows it. Windows: a process with `PROCESS_VM_READ` can read them. macOS: the hardened app resists a plain attach; record the result. No platform claim beyond what is measured | Per-platform result; recorded as a limit, not a pass | D |
| U17 | Target restart with the source app closed or backgrounded (M4) | The known path cannot run. The target shows the fixed "open the source app and keep it in the foreground" message, sends no token, and does not retry on a timer | No pairing connection; fixed message; no timer retry; success after foreground | D |
| U18 | Framed descriptor carries a bare 32-byte token (M5, M9.7) | Refused with exit code `2`. The engine does not fall back to reading it as a bearer. `--token-fd` plus a bootstrap frame is refused with `8` | Exit codes; no tunnel control | H |
| U19 | Prompt extension tries to outlive the arming (M6) | The ceremony ends at `arm_deadline`. The prompt is not extended past it, and the person must re-arm | Deadline values; one session end; no record | H |
| U20 | Canonical host value is near-canonical (M3, M9.3) | `010.0.0.1`, `10.0.0.1.`, `10.0.0.1:20000`, `[10.0.0.1]`, `10.0.0.1%en0`, ` 10.0.0.1`, and `fe80::1` are each refused. Only the exact canonical rendering is accepted. These are the same seven variants QV19 fixes | Seven refusals; no credential write; QV19 and E29 counts agree | H |

## V. Revision-7 medium adversarial rows (M8 and M9)

Each row names the M8 or M9 part in `DESIGN.md` section 2.1. "Fail" means no
record, token, credential, or trust change is written. V1 to V4 and V9 cover the
neutral nonmatch rule and the no-forget rule. V5 is the mandatory deterministic
client-certificate order test. V7 is the per-pin epoch isolation test. V10 to V17
cover the operational and consistency items that M9 names. V19 to V24 cover the
completion-pass corrections in `DESIGN.md` section 2.1.2, and each names its fix
number there.

| # | Attack or scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| V1 | One candidate, nonmatching server pin (M8) | The target sends no token, shows one neutral "not answering as any paired source device" message, claims no identity change, names no record, and offers no forget action. The old record remains and works when the correct source returns | Message text; store bytes; no token; successful retry with the correct source | H then D |
| V2 | Several candidates, none match (M8) | The same neutral message as V1. No candidate's token is tried, no record is named, and nothing is deleted | Token trace; message text; store dump | H |
| V3 | Several candidates, exactly one matches (M8) | Exactly one record is bound and only that record's token is sent. Other records and credentials are byte-identical. No neutral message is shown | One handshake; one token; credential dump before and after | H |
| V4 | A valid record survives a nonmatch (M8) | The record, credential, and `generation` are unchanged after the failed attempt. There is no automatic delete, no replacement, and no forget action | Store bytes; generation; credential dump; UI text | H |
| V5 | rustls TLS 1.3 rejects the server before the client Certificate (M8) | One process, no socket: a rustls client and a rustls server exchange bytes through in-memory buffers with `read_tls` and `write_tls`. The server requires a client certificate and uses a counting `ClientCertVerifier`. The client uses the pin-checking `ServerCertVerifier` and a client key whose `Signer::sign` is counted. Case 1: the server pin is not a candidate. Case 2: the pin matches but the server key does not, so `verify_tls13_signature` fails. Construct `CertifiedKey::new` with mismatched key and certificate and a custom `ResolvesServerCert`; `with_single_cert` rejects the fixture before handshake. Case 3, the control: the pin matches. In cases 1 and 2 the handshake fails at the client, the server sees zero `verify_client_cert` calls and no client Certificate message, `peer_certificates()` at the server is absent, the client signing count is zero, and no application byte or token is written. The client resolver count is recorded and may be one, because rustls resolves on CertificateRequest; it is not the pass criterion. In case 3 each count is exactly one. The rustls version is the one in `Cargo.lock`; an upgrade reruns the row. Part of the host gate | Server verifier count; server peer certificates; client signer count; resolver count recorded; handshake error; no token bytes | H |
| V6 | Every arming and ceremony event | SD1 to SD10 end source arming. TD1 consumes target arming and clears the display copy only; the engine QR secret and ceremony survive for proof. TD2 to TD10 and TE1/TE2 end the target ceremony and clear its secret. Success may commit only under the unresolved ordering gate | State, secret, and record per event; V22, W1 and W2 | H then D |
| V7 | Removing source A while source B registers | Registration and removal serialize on the store lock; A fails its record recheck if removal wins, or is detached if already registered. B proceeds. No epoch mismatch within the same lock hold; no cross-device ordering claim | Lock and store trace; B bytes; 1000 interleavings; W15 | H |
| V8 | QV19 and U20 labels and counts (M9.3) | The vector, E29, and U20 agree on one canonical value and exactly seven rejected variants. No file says six, and no label points at the wrong finding | Vector file; three suite results; text audit | H |
| V9 | Single and multiple candidate nonmatch messages (M8, M9.4) | Both counts produce the same neutral message, no record name, and no forget action. E26 and E31 no longer describe two different messages | Message text for both counts; DOM or text dump; store diff | H |
| V10 | `tun --phone` token sources (M9.5) | macOS and Linux: `--secrets-fd N`, then `HOTSPOTSHADE_PHONE_TOKEN`, then a no-echo `/dev/tty` prompt, in that order. Windows: `HOTSPOTSHADE_PHONE_TOKEN`, removed from the process environment after the read, then a no-echo console prompt; `--secrets-fd` is refused before any read. No token appears in `argv`, the process listing, an error, or a child environment on Windows. The environment form is marked for removal on every platform | Source used per fixture; process listing; command line; prompt capture; child environment; refusal message | H then D |
| V11 | Diagnostic token sources (M9.6) | `phone-udp-diag` and `phone-speed-diag` on macOS and Linux read `--secrets-fd N` or a no-echo `/dev/tty` prompt and never read `HOTSPOTSHADE_PHONE_TOKEN`: a run with only the environment set and no terminal fails with "no terminal is available; use --secrets-fd". On Windows both return the fixed "not implemented" error before reading any token source. No token appears in `argv` | Environment-only run result; prompt capture; Windows error; process listing | H |
| V12 | Descriptor selection and encoding per hop (M9.7) | The frame is read only with `--bootstrap-fd 3`. `--token-fd N` reads exactly 64 lowercase hex characters and one newline; on Windows `N` is an inherited handle and `--parent-fd` is required. `--secrets-fd` is not a `gui` option. A 64-lowercase-hex `HS2` line decodes to 32 raw bytes. The frame carries raw bytes. Both HTTP headers carry 64 lowercase hex characters, compared in constant time; uppercase hex is refused. A sender that puts 64 ASCII bytes into the frame exits `5` | Argument trace; frame bytes; request bytes; header compare result; exit code | H |
| V13 | Bootstrap exit-code matrix (M9.8) | Bad magic or bare token exits `2`; truncation `3`; version `4`; invalid length `5`; trailing bytes `6`; exactly `HSBOOT1` after the payload `7`; `--bootstrap-fd` plus `--token-fd` `8`; unusable descriptor or selector `9`; no end of input within 5 seconds `10`. Each fixture yields exactly one code. The Linux helper reports every engine failure with its own engine-failed status and never exits with the engine number. The launcher treats every non-zero as failure and reads no reply | Engine exit code per fixture; helper exit code; no reply bytes; no secret in output | H |
| V14 | PC and bearer matrix (M9.9) | A bearer-only pairing route is 401 with no change. A PC-only start route is 401 with no change. Neither credential is accepted from a query string, cookie, URL, page storage, or `Referer`. A previous-launch or short credential is 401. An unknown route is 404 | Table-driven status and state diff; request variants | H |
| V15 | Tunnel stop versus engine process exit (M9.10) | A tunnel stop ends routes and flows but keeps the bearer, PC, and target credential map. A start in the same launch succeeds without the known path. An engine process exit clears the bearer, PC, and credential map; the next launch needs the known path | Secret presence; credential map; start result; known-path count | H then D |
| V16 | QR deadline anchored at secret creation (M9.11) | `qr_deadline = min(created_at + 120 s, arm_deadline)`. A delayed display does not extend it. A proof after the deadline is refused. A QR created at 119 seconds expires at 120 seconds | Created, displayed, and deadline values; refusal; no record | H then D |
| V17 | Network flush versus durable flush lock scope (M9.12) | A blocked network flush holds neither the store lock nor the table lock. A blocked durable flush may hold the store lock but never the table lock. No deadlock; a concurrent mutation completes | Lock-order trace; timeout; mutation result | H |
| V18 | Ceremony clearing does not clear launch credentials (M9.1, M9.10) | Background and screen lock clear arming, the code display, and the QR secret but keep the bearer, PC, tunnel, and credential map. A tunnel stop keeps the launch credentials. An engine exit clears them. No state leaves a code visible or a running tunnel uncontrollable | State matrix before and after each event; secret presence; control request | H then D |
| V19 | Bootstrap length fields admit only raw 32-byte secrets (M9.7, fix 7) | `api_len` 64 with 64 ASCII hex bytes, `api_len` 31, `api_len` 33, and `pc_len` 64 each exit `5` before the payload is read. `api_len` 32 with `pc_len` 0 starts with no PC. `api_len` 32 with `pc_len` 32 starts with both | Exit code per fixture; payload bytes read before refusal; route matrix for the two accepted frames | H |
| V20 | Selector argument and helper code separation (M9.7, M9.8, fix 7) | Without `--bootstrap-fd`, descriptor 3 is never parsed as a frame. A launcher that still passes the old `--token-fd 3` with a frame on descriptor 3 fails the legacy line parse, because a frame is not 64 hex characters and a newline. `--bootstrap-fd 4` exits `9`. The Linux helper exits with its existing engine-failed status for every engine bootstrap code, so engine code `7` is never confused with the helper's abandoned-request code `7` | Argument list; engine exit code; helper exit code; app-visible result | H |
| V21 | Token-only inventory matches the code (M9.5, M9.6, fix 6) | For each command and platform in `DESIGN.md` section 23.1, the token source order observed in a host run equals the table: `tun --phone` and `phone` on macOS and Linux read the environment when `--secrets-fd` is absent; the diagnostics do not; Windows reads the environment for `tun --phone` and refuses `--secrets-fd`; `phone` and both diagnostics return "not implemented" on Windows. Any difference is a design defect, not a test update | Source used per command and platform; error text; one result per table cell | H |
| V22 | Disarm event table, one case per label (M9.1, fix 3) | SD1 success: disarmed, record written by section 13 only. SD2 cancel or back: disarmed. SD3 deadline: disarmed at `arm_deadline` on the monotonic clock. SD4 background: disarmed and listener closed. SD5 lock: disarmed. SD6 mechanism change: old QR payload dropped. SD7 one failed QR proof: secret consumed. SD8 third verified-reveal failure: disarmed and 30 second lockout. SD9 process exit: nothing restored after restart. SD10 listener close, including a rebind on a new address: disarmed. TD1 hello sent: arming consumed and display copy cleared; engine QR secret and ceremony remain through proof. TD2 cancel or back. TD3 deadline or QR deadline. TD4 window close or hide, tray hide. TD5 background or deactivation. TD6 lock. TD7 new mechanism: QR secret destroyed. TD8 engine exit: PC gone. TD9 quit or launch end. TD10 refused step on a stale handle: session ended. Only TD8 and TD9 clear the bearer or PC. SD1 and TE1 may commit only under the unresolved incarnation gate; other labels do not change a record or token | One result per label; arming state; bearer and PC presence; record and token diff | H then D |
| V23 | Epoch map values and tombstone cap (M9.2, fix 4) | A pin with no entry reads 0. The first removal sets 1 and changes no other entry. Removing 70 distinct unused pins keeps 64 entries and drops the oldest unprotected one. An entry for a re-added pin, or for a pin with a registered session, is never dropped; when every entry is protected the removal still succeeds above the cap. No session for another pin aborts during any step | Epoch map dump; entry count; abort count for other pins | H |
| V24 | Failed server `CertificateVerify` and `not_trusted` wording (M8, fix 1) | A server with a matching pin and a mismatched key produces the neutral nonmatch message, not the `not_trusted` text. A server that proves its pin and then rejects the client certificate produces the `not_trusted` text, which keeps the record and shows no forget action. Neither path deletes, replaces, or links to the removal action | Message text per case; store bytes; UI action list | H |

## W. Revision 9 review corrections and open gates

These are proposed tests, not results. W1 to W16 complete the references in
DESIGN section 2.0. W17 to W22 are blocked on reviewed incarnation, recovery and migration designs. W21 and W22 require a timer model that is not yet specified; they do not define its transitions.
Device rows need separate authorization. No test changes routes or creates TUN.

| # | Scenario | Expected | Observe | H/D |
|---|---|---|---|---|
| W1 | TD1 after QR scan | Arming consumed, display copy cleared, engine secret retained through proof | State at TD1 and proof | H |
| W2 | End each target ceremony | TD2 to TD10 and TE1/TE2 clear ceremony secret; TD1 alone does not | Per-event state, V6 and V22 | H then D |
| W3 | Remote forget with live matching flow | Mandatory DENIED in the same store-lock hold as recheck and table check; no mutation | Locks, record, result | H |
| W4 | Remote forget with no matching flow | Store lock spans recheck, durable commit and empty sweep; table lock is released for flush; send outside both | Lock and write trace | H |
| W5 | Failure or unexpected entry at sweep | Uncertain commit sends no OK and blocks mutation pending recovery; unexpected entries detach and cancel, counted as defect | Failure injection, lock and cancellation trace | H |
| W6 | Delayed QR display | Deadline starts at creation and is capped by arming deadline | Monotonic timestamps | H |
| W7 | Descriptor types per launcher | L28 pipe and socket rules, including failed shutdown and unsupported kinds | Descriptor and pre-read trace | H |
| W8 | Helperless launchers | App creates and writes both secrets; demo PC authorizes simulation only; hand-start demo has no PC | Launcher trace and routes | H |
| W9 | Non-root Unix GUI inventory | Current HTTP start passes auth then fails privilege; proposed matrix denies unauthenticated mutation, including existing pairing, forget, probe and stop | Route table and response | H |
| W10 | QR attacker and target impersonation | Wrong pairing id or target pin refused before READY without source consumption; proof requires target key; fake source can end target ceremony | Pin proof, secrets, state | H |
| W11 | SAS source Deny and Cancel | Verified reveal plus Deny counts one; third locks out. Unverified timeout counts zero; Cancel disarms without lockout. No source QR Deny | Counter and state | H |
| W12 | Store lock budget | Registration times out before application bytes; long durable commit counted, not interrupted; no table lock over flush | Timing and lock trace | H |
| W13 | Held writer and parser precedence | Complete magic/version/length or seven trailing bytes decides its code even while open; incomplete required step times out 10; EOF distinguishes 3 or short trailing 6 | Every closed/open fixture and code | H |
| W14 | Invalid server key proof | Custom `CertifiedKey::new` and resolver serve matching certificate with wrong signer; reject before client certificate/signature, no token | V5 counters and handshake trace | H |
| W15 | Locked registration and removal | Store recheck serializes the operations; epoch is redundant and cannot mismatch within the lock hold; unrelated pin unaffected | Lock trace and outcomes | H |
| W16 | Spike evidence scope | Spike's recorded resumption result is not a test of this design or of a device | Evidence attribution | H |
| W17 | Old FORGET delayed across same-pin re-pair | Future design rejects old incarnation without deleting new source record | Durable stores and request binding across restart | H |
| W18 | Old OK delayed across target re-pair | Future target conditionally rejects old incarnation result without deleting new record or token | Target lock, durable and in-memory state | H |
| W19 | Delayed PAIR_DONE versus local/remote removal and re-pair | Future source rejects stale commit; no revoked incarnation resurrects | All commit interleavings and restart states | H |
| W20 | Crash, lost result, tombstones and rollback | Future per-host model defines each durable boundary, uncertain local removal, retry, tombstone retention, anchor loss and recovery; no inferred success. Registration and token delivery require validated generation == anchor; memory-only epoch cannot persist revocation | Fault injection on both stores, anchors and persistent snapshots across restart | H then D |
| W21 | Forged or stale v1 status and port | Cannot start, reset, suppress or trigger v2 auto-stop; cannot modify presence, trust or endpoint; no fallback | Inject each status before and during each timer state, including expiry; timer transitions, presence, endpoint and store diffs | H |
| W22 | Wrong-pin or stale authenticated status and port update | Cannot start, reset, suppress or trigger v2 auto-stop; cannot modify presence, trust or endpoint. A valid update binds the accepted port atomically to the same current record and incarnation | Inject wrong-pin and old-incarnation status before and during each timer state, including expiry; pin proof, timer transitions, presence, endpoint and store diffs under races | H |
| W23 | Store-key provisioning and loss per host | Future reviewed model defines protected provisioning, inaccessible or lost key, identity reset, partial restore and recovery. No unkeyed fallback, automatic deletion, re-pair or trust use | Per-host key and store fault injection, restart and recovery traces | H then D |
