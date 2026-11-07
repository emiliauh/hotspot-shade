# WS1 test matrix, revision 9

Status: UNAPPROVED. This is a test plan. No test in this file has been written
or run for revision 9 or any earlier revision. It grants no product
authorization and changes no `AGENTS.md` invariant.

Revision 9 answers the independent revision 8 review (delegated review task
`ecb2b96c-d750-4156-9703-bcf9f5fc6052`). That review found four rows that
contradicted the design: T5.39 (one `session_generation` increment at retry
authorization), T5.46 (a granted-then-cancelled waiter recorded on a job),
T6.18 (the process "still closes the sockets" of a detached thread), and T16.10
("none exists" for a built-in resolver). Revision 9 rewrites those rows and
T5.33, T6.22, T7.34 to T7.36, T12.24, T13.11, T16.01, T16.04, and T16.09 to
match the revised design. It adds T5.47 to T5.52 (pipelined TCP:53 close and
commit order, config fetch cancel and failure, stop with a grant, wait-window
release), T6.25 to T6.27 (dead-route window, incomplete DoH stop reporting,
`--no-pin`), T7.37 (stale probe fallback), T16.13 and T16.14 (ordering and
fetch races), and gates G28 to G31. No route, TUN device, interface, root
privilege, phone, or carrier was used.

Revision 8 adds the tests that the independent revision 7 review requires
(review thread `00889a37-16c1-40c6-8fcb-45c725f3a6a0`): the retry and cache commit
ownership, the connection lease and slot handback, the adapter credit and
terminal close path, the global waiter queue, the real `Relay::stop` order and
stop budget, the status/diagnostics split, the third-party resolver decision,
and a dedicated adversarial table. It also records the plan's own revision note
for task `85710a0e` and does not treat it as approval.

Revision 7 added the tests that the independent revision 6 review requires: the
sharded ownership model, the TCP:53 commit ordering, the session and config-cache
lifecycle, per-query-port churn, the stop barrier, the capability consumer data
paths, and a protocol regression check. It also updated the DNS discovery rows
for the current macOS scoped resolver and the Linux explicit-server rule.

Architecture: `WS1_TARGET_ECH_DOH_ARCHITECTURE.md`.
Review trace: `WS1_REVIEW_TRACE.md`.
Superseded revision 1: `WS1_REVISION_1_SUPERSEDED.md`.

Revision 8 adds T5.39 to T5.46, T6.22 to T6.24, T7.34 to T7.36, T8.24 to T8.25,
T12.23 to T12.24, T13.10 to T13.11, and section 19 (T16 adversarial). It updates
the plan status in section 13 and the gate in section 17.

Revision 7 added T5.30 to T5.38, T6.16 to T6.21, T7.29 to T7.33, T8.19 to T8.23,
section 12.3, T12.22, T13.06 to T13.09, and T15. Section 17 records the gates
and the plan status.

## 0. How to read this matrix

Each row has:

- **ID**: stable test name.
- **Setup**: the mock or harness.
- **Action**: what the test does.
- **Assertion**: what must be true.
- **Not proven**: what the test cannot establish.

A hermetic pass is a code result. It is not a carrier result. A carrier result
needs a real hotspot, a real source device where applicable, and the owner's
approval. The last section separates the two.

All tests are hermetic by default: loopback, mocks, fixed vectors, temporary
directories, no route, no TUN device, no interface, no root, no phone.

## 1. Harness and mocks

| Mock | What it is | What it can do | What it cannot do |
|---|---|---|---|
| `mock_doh` | Loopback rustls server with a test certificate for `doh.test` and an injected root | HTTP/1.1 responses: 200, 400, 500, 302, chunked, gzip, drip, close, wrong content type, oversized body, malformed headers | Accept real ECH. rustls has no ECH server |
| `mock_ech_capture` | TLS server that records the ClientHello bytes | Show extension `0xfe0d`, the outer SNI, and the absence of the real name | Prove server acceptance of ECH |
| `mock_phone` | The existing source device proxy mock in the relay tests | Record every CONNECT target, delay, refuse, close, drop | Prove a real phone or carrier behavior |
| `mock_tun` | The existing mock tunnel device | Feed inner IPv4 and IPv6 packets, read inner replies | Prove a real TUN device or route |
| `mock_plain_dns` | A loopback UDP and TCP sink on a high port, wired through a test-only DNS target map | Record any plaintext DNS packet | Prove the real port 53 path or a real resolver |
| `mock_audit` | The existing `normalization::Audit` plus a test-only outer-connect recorder | Record TTL checks, TTL failures, and connect addresses | Record a carrier capture |
| `mock_clock` | The existing manual clock pattern in `rust/src/dns.rs` tests | Advance TTL, idle, and deadline | Prove wall-clock behavior |
| `crash_child` | A child process that runs only the DoH service and a loopback listener | Be killed to test fd and listener cleanup | Prove a tunnel or route cleanup |
| `shard_harness` | The real relay with 1, 2, 4, and 8 workers and a mock tun device | Drive flows whose keys land on different shards and inspect the shared ledger | Prove a real kernel schedule or a carrier |
| `capability_payload` | Fixed JSON fixtures for schema 1, schema 2, the runtime object, and each consumer | Feed the browser, Linux, and Windows parsers the same status and diagnostics fixtures | Prove a real desktop or app |
| `fuzz_corpus` | Fixed byte vectors plus a deterministic pseudo-random generator | Exercise parser bounds with fixed seeds | Substitute for a coverage-guided fuzzer |

The `mock_plain_dns` sink must not bind port 53. Use a high port and a test-only
mapping from the inner DNS target to the sink. Binding port 53 would need root
and would violate the no-root rule.

The `crash_child` is not a tunnel. It creates no route and no TUN device. A
`kill -9` equivalent on this child is allowed for the crash test. Do not use
`kill -9` on a real tunnel.

## 2. T1: DoH client unit tests

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T1.01 | `mock_doh`, injected root | One POST to the configured path | Request method, path, `Host`, `Content-Type`, `Accept`, and `Content-Length` are exact | A real provider's header policy |
| T1.02 | `mock_doh` | Send a query with ID `0x1234`, mixed-case QNAME, EDNS OPT, DO bit, cookie, padding, and an unknown option | The body is byte-identical to the query | A real resolver's answer |
| T1.03 | `mock_doh` | Send QTYPE 64, 65, and an unknown type | All are forwarded, not rejected or filtered | That the answer contains a usable ECH config |
| T1.04 | `mock_doh` | Two queries on one inner flow | One TLS connection and one outer socket are used | A real keep-alive server |
| T1.05 | `mock_doh` | Two inner flows | Two TLS connections and two server connections are used | Proxy mode's second socket |
| T1.06 | `mock_doh` chunked mode | Return a chunked body | The body is decoded exactly and the total is bounded | A real chunked response |
| T1.07 | `mock_doh` oversized mode | Return a body above 65535 bytes | The query fails without unbounded allocation | A real server's maximum |
| T1.08 | `mock_doh` 400 and 500 modes | Return a non-200 status | The query fails and is counted. No retry to another server | A real provider's error body |
| T1.09 | `mock_doh` 302 mode | Return a redirect | The redirect is refused, not followed | A real redirect chain |
| T1.10 | `mock_doh` wrong content type | Return `text/plain` | The query fails | A real provider's content type |
| T1.11 | `mock_doh` gzip mode | Return `Content-Encoding: gzip` | The query fails because compression was not requested | A real compressed response |
| T1.12 | `mock_doh` drip mode | Send one header byte every 100 ms | The total deadline fails the query, not a per-read timeout | A real slow server |
| T1.13 | `mock_doh` stall mode | Send headers then no body | The total deadline fails the query | A real network stall |
| T1.14 | `mock_doh` extra-bytes mode | Send a valid body then extra bytes | The query fails and the connection closes | A real keep-alive server |
| T1.15 | `mock_doh` close mode | Close after the request | The query fails cleanly, no panic | A real reset |
| T1.16 | `mock_audit` | Complete a DoH query | The audit snapshot ends at `(n, 0)` and the connect address is the configured IP:port | A carrier TTL observation |
| T1.17 | `mock_doh` TLS 1.2 only | Offer only TLS 1.2 | The handshake fails. The client does not downgrade | A real server's TLS policy |
| T1.18 | `mock_doh` ALPN mismatch | Select `h2` when the client offered only `http/1.1` | The handshake fails | A real provider's ALPN |
| T1.19 | `mock_doh` | Check the outbound request bytes | No user-controlled string is in a header except the configured name and path. No CRLF injection | A real proxy or middlebox |

## 3. T2: HTTP parser bounds and fuzzing

The parser is a client-side response parser. It is still untrusted input.

| ID | Input | Bound or expected result |
|---|---|---|
| T2.01 | Header block | 8192 bytes maximum. One byte more fails |
| T2.02 | Header line | 4096 bytes maximum. One byte more fails |
| T2.03 | Header count | 64 maximum. One more fails |
| T2.04 | Status line | 256 bytes maximum. HTTP/0.9, HTTP/2 preface, and HTTP/1.0 fail |
| T2.05 | Bare LF, NUL, obs-fold | All fail |
| T2.06 | `Content-Length` twice | Fails |
| T2.07 | `Content-Length` and `Transfer-Encoding` together | Fails |
| T2.08 | `Transfer-Encoding` other than `chunked` | Fails |
| T2.09 | Chunk size overflow, negative, or non-hex | Fails |
| T2.10 | Chunk count | 1024 maximum. One more fails |
| T2.11 | Chunk extension | 256 bytes maximum. One more fails |
| T2.12 | Trailer section | Fails |
| T2.13 | 1xx, 101, 204, 3xx | Fails. No upgrade and no redirect |
| T2.14 | Body shorter than `Content-Length` | Fails at the deadline or on close |
| T2.15 | Body longer than `Content-Length` | Fails and closes |
| T2.16 | DNS body shorter than 12 bytes | Fails |
| T2.17 | Fixed corpus of 200 malformed responses | No panic, no out-of-bounds read, a bounded error |
| T2.18 | Deterministic fuzz: 10,000 inputs, 4 seeds, at most 65535 bytes each | No panic. Each input completes within 50 ms. Every allocation is bounded by the declared length and the configured cap |
| T2.19 | Status line with a huge reason phrase | Fails at 256 bytes |
| T2.20 | Header value with a NUL or a CTL byte | Fails |

The fuzz loop is deterministic and needs no new dependency. A coverage-guided
fuzzer is optional and is not part of CI. If the parser uses a test-only
counting allocator, assert that the peak allocation per input is at most
`input_len + 16 KiB`. Otherwise assert the parser never grows a buffer beyond
its configured cap by construction and by a code review.

## 4. T3: DNS message handling

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T3.01 | `mock_doh` | Query with EDNS UDP size 512, answer 800 bytes | A TC response with the header and question only is returned | A real client's retry |
| T3.02 | `mock_doh` | Query without OPT | The default limit is 512 | A real resolver's default |
| T3.03 | `mock_doh` | Answer exactly at the limit | The full answer is returned, no TC | A real MTU |
| T3.04 | `mock_doh` | Answer one byte over the limit | TC is set, no partial answer | A real middlebox |
| T3.05 | `mock_doh` | Malformed question that cannot be copied | The query is dropped, no partial answer | A real malformed query |
| T3.06 | `mock_doh` | DNSSEC response with RRSIG and AD=1 | Bytes pass through and AD is unchanged | DNSSEC validation |
| T3.07 | `mock_doh` | Response with `Content-Length` 65535 | Accepted within the bound | A real maximum response |
| T3.08 | `mock_clock` | Answer cache check | No answer is cached by the engine | A resolver cache |
| T3.09 | `mock_doh` | QNAME case and ID | Both are unchanged | A real 0x20-encoding client |
| T3.10 | `mock_doh` | Cookie and padding options | Both pass unchanged | A real resolver's cookie policy |
| T3.11 | `mock_doh` | Return a response with a different ID or QR=0 | The response is dropped and counted; no wrong answer reaches the inner client | A real resolver bug |
| T3.12 | Adapter `mock_doh` | Return a TCP response with a different ID | The adapter closes the connection; it does not frame the wrong answer | A real resolver bug |

## 5. T4: ECH

The rejection and retry tests need a mock server certificate valid for the
**origin name** the client intended, not for the ECH config's `public_name`.
The client authenticates the origin certificate. `public_name` is only the outer
SNI, so a certificate for `ech-public.test` is the wrong fixture. Use a fixed
test config for the DoH endpoint `doh.test` with `public_name = ech-public.test`
and a server certificate for `doh.test`. The server selects that certificate
from the `public_name` SNI and the client checks it against `doh.test`. A
certificate for `public_name` would make the authenticated-rejection path test
the wrong name and would let a real defect pass.

rustls has no ECH server, so a full handshake that sends authenticated
`retry_configs` is not hermetic. T4.07, T4.08, T4.09, T4.20, T4.23, and T4.24
test the retry policy behind a test seam with a recorded authenticated
rejection. The real authenticated rejection and retry path needs a live provider
in T11. Do not describe the seam test as a hermetic ECH acceptance test.

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T4.01 | Fixed vectors | Parse a valid ECHConfigList | The config is accepted and cached | A real provider's config |
| T4.02 | Fixed vectors | Empty list, duplicate mandatory extension, unknown KEM, oversized list, bad public name | All are rejected and not cached | A real malformed config |
| T4.03 | `mock_clock` | Advance past the RR TTL | The config is not used after expiry | A real DNS TTL |
| T4.04 | `mock_clock` | Fill the cache | The bound holds and the oldest entry is evicted | A real rotation |
| T4.05 | `mock_ech_capture` | Connect with a config | Extension `0xfe0d` is present; the outer SNI is `public_name`; the real name does not appear in the ClientHello | Server acceptance |
| T4.06 | `mock_doh` plain rustls | Offer ECH to a server that ignores it | The client aborts with the ECH rejection error, sends `ech_required`, and sends no HTTP request. If the origin certificate authenticates, this is the T4.09 case and one resolver retry may follow. If it does not authenticate, no retry follows | A real rejection |
| T4.07 | `mock_doh` retry-config mode | Reject and send retry configs | Exactly one new connection is opened with the retry config; the old one is closed | A real retry config |
| T4.08 | `mock_doh` second rejection | Reject the retry | The query fails. No loop. `ech_retry_exhausted` moves | A real misconfiguration |
| T4.09 | `mock_doh` no retry config | Authenticated rejection with no usable config | Exactly one retry with ECH disabled is allowed **for the resolver connection only**. `ech_fallback` moves. No application flow and no profile change follows | A real server |
| T4.10 | `mock_doh` GREASE | No config, GREASE on | Extension is present, the real name is absent, `ech_grease` moves, `ech_attempts` and `ech_ok` do not | Server acceptance |
| T4.11 | `mock_doh` timeout | Time out the connection after ECH was offered | No retry. `doh_timeout` moves. `ech_error` moves. `ech_fallback` does not move. The profile does not change | A real timeout |
| T4.12 | `mock_doh` 500 | Return 500 | No retry. `doh_http_error` moves | A real error |
| T4.13 | `mock_doh` reset | Reset the connection | No retry. The query fails. `doh_other_error` moves. `ech_error` moves if ECH was offered. `ech_fallback` does not move. The profile does not change | A real reset |
| T4.14 | `mock_doh` bad origin certificate | Present a certificate that does not authenticate `doh.test` | The handshake fails. No retry configs are used. No ECH-disabled retry follows. `ech_rejection_unauthenticated` moves if the server also rejected ECH | A real misissuance |
| T4.15 | `mock_doh` retry-of-retry | Send retry configs in response to a retry connection | The client does not accept them and does not loop | A real bad server |
| T4.16 | `mock_ech_capture` | Check the ECH config source | The config came from the endpoint's own HTTPS RR over the authenticated DoH connection, not the system resolver | A real DNS path |
| T4.17 | `mock_doh` | Check outputs | The ECH config and public name do not appear in status, diagnostics, failures, or logs | A real log sink |
| T4.18 | `mock_doh` no HTTPS RR | Query the endpoint's HTTPS RR and get no `ech` param | DoH still works; no ECH is offered; `ech_config_unavailable` moves and `doh_failed` does not; the query does not fail | A real resolver |
| T4.19 | `mock_doh` alias mode | Return an HTTPS alias instead of an `ech` param | The alias is not followed for the ECH config; no config is cached | A real CNAME or alias chain |
| T4.20 | `mock_doh` retry-config success | Authenticated rejection, then accept the retry | `ech_attempts` moves twice, `ech_ok` moves once for the retry, `ech_rejected` moves once for the first handshake. `ech_attempts = ech_ok + ech_rejected + ech_rejection_unauthenticated + ech_error + ech_retry_exhausted + ech_attempts_in_flight` holds exactly | A real anycast retry |
| T4.21 | Capability JSON in an `ech` build before qualification | Read `app_ech`, `ech`, and `resolver_ech` | `app_ech` is `app_dependent`, the legacy `ech` is `unsupported`, `resolver_ech` is `unverified`, and no value contains free text. A hermetic test does not raise either capability | A live provider |
| T4.22 | `mock_doh` no retry config, then a later connection | Authenticated rejection with no supported retry config, then open a new connection | The one ECH-disabled retry runs and `ech_fallback` moves. The rejected resolver ECH config is evicted. The later connection fetches a fresh config and does not offer the rejected one. A second rejection does not keep the config | A real resolver rotation |
| T4.23 | `mock_doh` certificate fixture | Present a certificate for `doh.test` while the outer SNI is `ech-public.test`; repeat with a certificate for `ech-public.test` | The first authenticates the origin and reaches the retry policy. The second fails origin authentication and produces `ech_rejection_unauthenticated` with no retry. This checks the fixture, not a real provider | A real certificate chain |
| T4.24 | Retry policy matrix | Drive each row of architecture section 5.3 through the seam: accepted, authenticated rejection with retry configs, authenticated rejection with no config, unauthenticated rejection, timeout, reset, 5xx, parse error, SERVFAIL, second rejection, and a cancelled retry | Only the two authenticated-rejection rows retry. The value is ECH-disabled only in the no-config row. Every other row fails with no second attempt. `ech_fallback` moves only for the ECH-disabled row. Application flows never retry | A real provider and carrier |

No hermetic test can complete an ECH-accepted handshake. rustls has no ECH
server. The emission test proves the name is absent from the ClientHello. The
acceptance path needs a live provider and is in T11. Put that limit in the test
file header.

## 6. T5: Relay integration

### 6.1 UDP:53

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T5.01 | `mock_tun`, `mock_phone`, `mock_doh` | Inner UDP:53 query in source proxy mode | The phone sees a CONNECT to the configured DoH IP:443, never `1.1.1.1:53`. The inner client gets the exact answer | A real phone |
| T5.02 | `mock_tun`, `mock_doh`, `mock_audit` | Inner UDP:53 query in direct mode | The normalized outer socket reaches the mock DoH server. TTL audit ends at `(n, 0)` | A real hotspot |
| T5.03 | `mock_tun`, `mock_doh` | Large answer | TC=1 with the question only; the client's TCP:53 retry is answered | A real client |
| T5.04 | `mock_tun`, `mock_phone`, refusing DoH | DoH failure | No plaintext answer. The failure counter moves. The plain sink is empty | A real resolver failure |
| T5.05 | `mock_tun`, `mock_phone`, plaintext profile selected before start, section 2.6 accepted | Send a query, then force a DoH failure in a separate DoH-profile run | The plaintext-profile query goes to the configured plaintext path from the first query and the status says DNS is not private. The DoH-profile failure does not switch to plaintext, and `dns_plaintext_profile_queries` does not move in that run. The default `off` profile adds no counter | A real person's profile choice |
| T5.06 | `mock_tun`, `mock_phone` | Two inner DNS flows | Two DoH connections, no sharing | A real stub resolver |
| T5.07 | `mock_tun`, `mock_phone` | One inner flow with two queries | One DoH connection, reused | A real keep-alive |
| T5.08 | `mock_tun`, `mock_phone` | Synthetic injection: an inner IPv6 DNS packet to `fe80::1` in proxy mode | The phone sees a DoH CONNECT, not a link-local CONNECT. This is a synthetic injection; a real link-local packet does not enter the tunnel | The OS bypass outside the tunnel |
| T5.09 | `mock_tun`, direct block mode | Inner IPv6 DNS to a global address | No plaintext query and no DoH attempt. The packet is dropped by policy before any connect. An IPv6 DoH endpoint is rejected at start in block mode | A real OS resolver |
| T5.28 | Adapter admission ownership | Send a complete TCP:53 frame | The adapter sends an admission request to the owning shard and submits no pool job. That shard assigns the job ID, reads the outcome, writes the counter, and writes any failure record. The adapter has no counter writer and no direct pool path | A real scheduler |
| T5.29 | Adapter admission credit | Exhaust the four credits on one adapter flow while a frame waits, then release a credit | The adapter stops reading that connection instead of dropping the frame. When the credit returns, it reads and admits the frame. If the wait passes 30 s, it closes the connection with one adapter event. The shard records `doh_adapter_errors` only for the transport event, not for a full channel | A real local attacker |
| T5.38 | SOCKS5 resolver discovery | Run the SOCKS5 start on macOS with an unambiguous scoped resolver, on macOS with an ambiguous or VPN resolver, and on Linux with and without `--dns-servers` | macOS uses only the scoped interface block and rejects the ambiguous case. Linux fails closed without an explicit list and accepts a numeric, deduplicated list of at most 8. Every query socket is pinned to the interface. No `getaddrinfo` appears | A real OS resolver or a carrier |


### 6.2 TCP:53

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T5.10 | `mock_tun`, `mock_doh`, adapter | One 2-byte framed query | The adapter answers through DoH; the inner stream closes with FIN | A real resolver |
| T5.11 | `mock_tun`, `mock_doh`, adapter | Two queries on one TCP:53 connection | FIFO responses, one DoH connection | A real pipelined client |
| T5.12 | `mock_tun`, adapter | Partial frame then close | The adapter closes, no panic | A real half-close |
| T5.13 | `mock_tun`, adapter | Complete frame then half-close | The answer is written and the connection closes | A real client |
| T5.14 | `mock_tun`, adapter | DoH failure | The adapter closes the inner connection; no fake SERVFAIL | A real failure |
| T5.15 | `mock_tun`, adapter | Frame length 0, 11, 65536 | All fail within bounds | A real malformed client |
| T5.16 | `mock_tun`, adapter | Idle connection | Closed at 30 s | A real idle resolver |
| T5.17 | `mock_tun`, `mock_phone` | TCP:53 in proxy mode | The phone sees a DoH CONNECT, never a TCP:53 CONNECT | A real phone |

### 6.3 One flow, one socket

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T5.18 | `mock_tun`, `mock_doh` | Two inner DNS flows with the same DoH endpoint | Two separate TLS connections. The server accepts two | A real endpoint |
| T5.19 | `mock_tun`, `mock_doh` | ECH rejection retry | The old connection is closed before the new one is opened. At most one live egress per flow | A real anycast retry |
| T5.20 | `mock_tun`, `mock_doh` | Idle flow | The connection closes at the idle bound; no background refresh connection appears | A real provider |
| T5.21 | `mock_phone` | Proxy DoH | One SOCKS CONNECT per DoH session. No aggregation | A real source device |
| T5.22 | `mock_phone` at capacity | Refuse a new relay | The DoH query fails as `doh_query_failed` with `doh_other_error`, terminal reason `source_capacity`. No plaintext query and no profile change. The DoH cap does not depend on a free-slot report, which the protocol does not provide | A real phone capacity limit |
| T5.23 | Adapter, slow inner client | Stop reading the inner TCP:53 response | The adapter's write bound fails that flow. The accept loop and other flows continue | A real stuck client |
| T5.24 | Adapter, DoH failure, failure-record scope accepted | Fail one TCP:53 query after a valid cookie and preface | The failure record uses the preface destination, not the loopback listener, and carries the inner port and a `phase`. No name appears. Skip this row while the DoH failure-record privacy scope is not accepted | A real UI |
| T5.25 | Documentation and route table | Read the gateway rows for macOS, Windows, and Linux | macOS and Windows name a gateway bypass by route-specificity inference. The record is not described as a live DNS result, because it names no OS and does not show the DNS case. Linux says a default link-bound resolver is likely a bypass, and rule 17001 admits the query only when the socket is not bound. No row claims gateway DNS coverage | A real OS route lookup and a DNS-specific capture |
| T5.26 | Source device capacity | Read the DoH connection-cap code and contract | The cap is the proposed 32 and does not depend on a source-device free-slot report. A capacity error is `doh_other_error` with reason `source_capacity`. No protocol change is assumed | A real source device |
| T5.27 | Adapter queued TCP:53 behind a failed connection | Fail the active DoH connection while two TCP:53 queries are queued on the same inner flow | Each queued query records its own `doh_query_failed` with `doh_other_error`, reason `flow_closed`. Neither is silently dropped. The failed connection is not reused | A real resolver |

### 6.4 Sharded ownership and delivery

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T5.30 | `shard_harness` with 2, 4, and 8 workers | Drive UDP:53 queries and TCP:53 frames whose flow keys land on different shards | Every job has exactly one owning shard. The shared ledger records every admission and outcome once. No shard has a private DoH counter. The identity holds in a snapshot from any shard | A real kernel scheduler |
| T5.31 | `shard_harness` with 2 shards, global job bound `G` | Admit `G` jobs alternately through both shards, then one more through each | The bound holds globally. The extra admission from either shard is rejected with `doh_queue_full`. No shard over-admits because it counted only its own jobs | A real load |
| T5.32 | Adapter, `mock_doh` drip mode, one shard | Send a TCP:53 frame, then cancel or time the job out before the response commit | The owner records one terminal cause. The adapter receives no delivery and writes no bytes. The inner connection closes. No fake answer and no partial frame | A real stall |
| T5.33 | Adapter, session incarnation replacement | Release a session, admit a new session for the same inner 4-tuple (new `session_generation` N+1), then deliver a completion and a handback from the old session's attempt (N). Separately, inject a second disposition for a `job_id` that the adapter already applied | The old completion is discarded by `job_id` and `attempt_id` before delivery; it does not attach to session N+1 or free its slot. The injected duplicate disposition is dropped by the already-applied `job_id` without writing. The test-only discard diagnostic moves. No counter moves twice and no inner byte is written. No disposition is dropped because a later job on the same session committed | A real scheduler |
| T5.34 | `mock_doh`, one UDP flow with a per-query source port | Send one query, wait for the quiet window, then send another on a new source port | The first session closes and frees its slot before the second is admitted. The second uses a new session and `session_generation`. The relay flow entry is irrelevant. The slot count returns to the expected value | A real stub resolver |
| T5.35 | `mock_doh`, two shards, one endpoint | Have a session on each shard need the ECH config at the same time, then deliver a late fetch result after the first commit | Exactly one fetch runs. The other session waits within its deadline. The late result publishes nothing and moves no `doh_ok`. The cache holds the committed `config_generation` | A real resolver rotation |
| T5.36 | `mock_doh` with ECH config, a job on shard 2 | Run a handshake that offers ECH, then a stop before `AttemptOutcome` | `AttemptStarted` records one attempt on shard 2's owning ledger path, the gauge returns to 0 with `ech_error`, and the ECH identity holds. The stop barrier is not blocked by the open attempt | A real provider |
| T5.37 | UDP flow expiry and TCP:53 inner close | Let a UDP relay flow entry expire while its DoH session is already quiet, and close an inner TCP:53 connection with a queued job | The UDP path calls `close_flow` in the owning shard and frees the session if one remains. The adapter sends `ConnectionClosed`; the shard records one `doh_cancelled` for the queued job, closes, and frees the slot. No slot is freed twice and no second outcome appears | A real OS flow table and client close |
| T5.39 | `mock_doh`, ECH authenticated rejection, one shard | Reject the first ECH attempt with retry configs, then accept the retry; repeat on TCP:53 with two queued queries behind it | One `doh_queries` increment for the whole job and one final outcome, `doh_query_ok`. `session_generation` is the same before the rejection, during `BetweenAttempts`, and after the retry commit; no sequence changes at retry authorization. The retry completion is matched by `attempt_id` 2 and commits normally; no `generation_mismatch` or other failure appears. The shard dispatches the second reserved attempt; the pool does not dispatch it. `ech_attempts` moves twice and the retry outcome is `ech_ok`. The two queued TCP:53 queries then commit on the installed connection and both answers are written. No second admission and no second `doh_in_flight` entry | A real provider |
| T5.40 | `mock_doh`, two shards, cache race | Publish a fresh config from a fetch on shard 1 while a retry on shard 2 tries `commit_retry_config`, then deliver a stale authenticated rejection from the old generation | The retry commit is a no-op against the newer `config_generation`; the retry still uses its authenticated retry configs. The stale rejection cannot evict the newer `Fresh` config. `doh_lookups` moves only for the fetch. No `session_generation` moves from the stale event | A real resolver rotation |
| T5.41 | `shard_harness`, pool seam | Return a live connection to the shard, then fail or delay the completion; in a second run, terminalize the job before the pool returns | The slot stays `Attempting` until the handback. A terminal job does not free the slot. The live lease is installed only on commit; otherwise it is dropped and closed. The slot count never goes negative and no second job uses the same slot | A real scheduler |
| T5.42 | `shard_harness`, stop seam | Stop while a pool attempt holds a lease and the shard has marked the job terminal | `JoinPool` waits for the handback, closes the lease if it was not committed, then frees the slot. No slot is freed before the handback. A late handback for an older attempt does not free a newer attempt's slot | A real scheduler |
| T5.43 | Adapter, four credits per connection | Send five frames on one authenticated connection while the first four are in flight | The adapter reads the fifth frame only after a credit returns. It never drops a frame for a full admission channel and never closes the connection for that reason. A wait past 30 s closes the connection with one adapter event | A real local client |
| T5.44 | Adapter, `mock_doh` failure | Fail one accepted TCP:53 query with a timeout and one with a transport error | Each job gets one `Close` disposition and the adapter closes that inner connection without waiting for the idle timer. `doh_query_failed` moves once per job and `doh_adapter_errors` does not move for the close itself. No fake answer and no partial frame | A real resolver |
| T5.45 | `shard_harness` with 4 shards, session cap `S` | Fill `S`, queue waiters on all four shards, then release one slot at a time | The grant order is one global FIFO by sequence, not four per-shard orders. A granted slot stays counted during handoff, so no other shard can take it. Each waiter is granted, expires, or is cancelled exactly once | A real scheduler |
| T5.46 | `shard_harness`, waiter settlement | (a) Grant a waiter, cancel it before `admit_granted`, then let its shard call `admit_granted`. (b) Grant and convert a waiter, then cancel it. (c) Expire a queued waiter on an idle shard. (d) Cancel a queued waiter on another shard. (e) Stall a granted shard past `grant_deadline`, then let it call `admit_granted`. (f) Call `settle_waiter` twice for one waiter | (a) The cancel records one `doh_cancelled` as a waiter settlement and returns the slot in the same critical section; no job exists and none is created. The later `admit_granted` returns `Stale`, records nothing, and returns no slot. (b) The cancel is a job cancellation with one terminal outcome on the job and no waiter outcome. (c) The reaper settles it once although its shard is idle. (d) One settlement. (e) The revocation settles it once with `doh_queue_full` (or `doh_timeout` past the absolute deadline) and the next waiter is granted; the late `admit_granted` is `Stale`. (f) The second call is `Stale`. Every waiter has exactly one settlement or one conversion. The queue, the grant table, and the used-slot count return to their expected values | A real scheduler |
| T5.47 | Adapter, pipelined success and failure on one connection | On one TCP:53 connection send query A (held in flight), query B (rejected at admission because `G` is full), and query C (admitted behind A). Repeat with B failing on a DoH transport error after A commits | Run 1: A's answer is written, then C's answer, in `request_id` order, then FIN. B records one `doh_queue_full`. A and C record `doh_query_ok`. No query records `doh_cancelled`. The adapter stops reading after it applies B's close. `doh_adapter_errors` does not move. Run 2: A's answer is written; B records its transport cause; C records `doh_other_error`/`flow_closed`; then FIN. No fake answer and no partial frame | A real resolver or client |
| T5.48 | Adapter, commit before write | On one connection, commit query A and then commit query B on the same session before the adapter has written A (hold the adapter's writer in a seam). Then let the inner client close before B is written in a second run | Run 1: both answers are written, A then B. Neither is dropped as stale. `session_generation` is the same in both dispositions. Run 2: A is written; B counts once in `doh_adapter_errors` and keeps its `doh_query_ok`. Every committed answer is written or counted, never neither | A real client close |
| T5.49 | `mock_doh`, config fetch cancelled with waiters on other shards | Start a config fetch on shard 1, put sessions on shards 2 and 3 in `waiting_for_config`, then expire the fetcher's inner flow | In one critical section the fetch records `doh_failed` once, the cache moves to `Absent` with no `retry_after`, and every shard is woken. Exactly one of the waiting sessions claims a new fetch with a new `fetch_ticket`; the other keeps waiting and then uses the committed config. No session waits until its deadline because of the cancelled fetch. No `doh_ok` moves for the cancelled fetch | A real resolver |
| T5.50 | `mock_doh`, config fetch failure backoff | Fail a config fetch with a 5xx while two sessions wait, then advance the mock clock past `retry_after` and add a new session | The failure records `doh_failed` once and sets `Absent { retry_after }`. No session claims a fetch before `retry_after`; the waiting sessions proceed without offering ECH and no `ech_*` attempt counter moves for them. After `retry_after` exactly one fetch runs. There is no fetch storm across shards | A real resolver outage |
| T5.51 | `shard_harness`, stop with an outstanding grant | Grant a waiter, then call `begin_stop` before the granted shard calls `admit_granted` | The `Stopping` transition settles the grant with `doh_cancelled` and returns its slot without granting it again. The later `admit_granted` is `Stale`. `Draining` finds no waiter and no grant, and `Sealed` verifies the grant table is empty | A real scheduler |
| T5.52 | `shard_harness`, release skips expired wait windows | Queue waiter X whose wait window has passed while its absolute deadline remains, and waiter Y behind it with both deadlines remaining, then release one slot | The release step settles X once with `doh_queue_full` and grants Y. It never creates a grant for X, so `admit_granted` never rejects a grant for the wait window. Y's `grant_deadline` is `min(grant time + T_grant, absolute deadline)` | A real scheduler |

## 7. T6: Cleanup, crashes, and lifecycle

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T6.01 | DoH service, mock server | Stop with an idle connection | The listener closes, the pool joins, the port is free | A real process supervisor |
| T6.02 | DoH service, mock source setup, slow response | Stop with an in-flight query in every source setup state: before connect, during connect, during SOCKS handshake, during TLS, and during HTTP | The stop flag is seen in each state, the socket closes, the job ends as `doh_cancelled`, and a late source reply is discarded by job ID. The worker is not blocked | A real source device stall |
| T6.03 | DoH service, ECH retry | Stop during a retry | Both connections close; no retry after stop | A real anycast |
| T6.04 | DoH service | Stop twice | The second stop is a no-op | A real helper |
| T6.05 | DoH service | Drop without stop | The same cleanup runs | A real crash |
| T6.06 | Adapter | Drop with open adapter connections | Connections close; the listener port is free | A real process |
| T6.07 | DoH pool | Panic one pool job and then a pool thread | The first job fails once with `doh_other_error`/`pool_unavailable` or its own job panic outcome. A second panic marks the pool unavailable, fails all accepted jobs with no outcome, and does not restart. The tunnel stays up for non-DNS traffic | A real panic policy |
| T6.08 | Adapter | Panic the adapter thread | Inner TCP:53 connections close. No plaintext query is sent and the profile does not change. The owning shards record the accepted jobs that remain and `doh_adapter_errors` for transport events | A real panic |
| T6.09 | Parent descriptor | Close the parent descriptor | The service shuts down and cleans up | A real desktop parent |
| T6.10 | `crash_child` | Kill the child with SIGKILL or the platform equivalent | The OS closes the sockets; the listener port can be bound again; no file or registry state remains | A real tunnel crash |
| T6.11 | DoH service, mode change | Start with a populated failure name map, then start DoH | The name map is cleared and no DoH name enters it | A real UI |
| T6.12 | DoH service | Count live connections, threads, and jobs after stop | All are zero | A real fd table |
| T6.13 | DoH service | Assert no route, address, or device is created | The test's route and device lists are unchanged | A real host |
| T6.14 | DoH service, two in-flight queries | Stop the service | Each owning shard records `doh_cancelled` once for each accepted query with no outcome, every gauge returns to 0, and the sealed snapshot publishes no partial identity as exact. `doh_queries = doh_query_ok + doh_query_failed + doh_in_flight` holds in the final snapshot | A real process supervisor |
| T6.15 | Relay worker panic | Force a panic in the mock relay worker while DoH jobs are live | The DoH supervisor stops the adapter and pool, closes every job socket, and does not publish the ledger as exact. The tunnel stop path runs. No listener, thread, or connection remains. A test-only hook records the panic path | A real process supervisor |
| T6.16 | Stop barrier admission race, 8 shards | Request stop while both shards are admitting a steady stream | Once the phase leaves `Running`, no new admission is recorded and no job reaches the pool. An admission that reserved before the transition is drained. The final `doh_queries` equals the jobs that were admitted before the transition | A real process supervisor |
| T6.17 | Stop barrier drain, 8 shards, 2 live jobs | Stop with one UDP job and one TCP job in flight | Intake closes first. Each owning shard records `doh_cancelled` once, marks its session draining, and acks. The pool closes its own sockets during `JoinPool`. The adapter delivers no bytes. Every gauge and session slot is 0 in the `Sealed` snapshot | A real scheduler |
| T6.18 | Stop barrier timeout with a stuck pool thread | Hold one pool attempt in a test seam past `T_pool` while it holds an open mock socket, then stop | The barrier moves to `Incomplete` and the `RelayStopReport` names the phase. The barrier closes every socket it can prove (ledger-held leases, never-started attempts). It does not close the stuck attempt's socket: the test asserts that socket is still open until the seam releases the thread, then closed by the thread. `DOH_DETACHED_THREADS` is 1 until the thread exits, then 0. The fault slot has `doh_stop_incomplete = true` and `cleanup_failed = false`; `cleanup_blocked` stays false; the log says "Encrypted DNS did not stop cleanly", not "Route cleanup failed". The diagnostics ledger is `exact: false`, phase `incomplete` | A real stuck syscall |
| T6.19 | Drop with 8 shards | Drop the relay with open sessions and waiters | The same barrier runs. Every shard acks, the listener and threads are gone, and a second drop is a no-op | A real process |
| T6.20 | Shard panic | Panic one shard while the other shards own live jobs | The barrier misses that shard's ack and moves to `Incomplete`. Its known sessions are force-closed, the other shards drain, and the ledger is not published as exact. The relay stop path runs | A real process supervisor |
| T6.21 | Adapter delivery failure after commit | Commit a TCP:53 answer, then close the inner client before the adapter writes it | `doh_query_ok` stays counted once, `doh_adapter_errors` moves once, and no second query outcome appears. The slot is released | A real client close |
| T6.22 | Stop order in a DoH run, 8 shards | Run the tunnel worker stop with a fake route controller, live DoH jobs, a queued TCP:53 frame, a queued waiter, and an outstanding grant. The test hook records each step | The recorded order is: worker loop exit, `begin_stop` (`Stopping` set, the waiter and the grant settled `doh_cancelled`), `routes.remove()` and `link.remove()`, then inside `relay.stop()` the shard acks while `running` is still true, `Draining`, `JoinPool` handbacks, `JoinAdapter`, `Sealed`, and only then `running = false`, `input.clear()`, and the shard join, then the TUN drop. Every slot frees after its handback. In a run without the DoH profile the recorded order is the existing one, `relay.stop()` before `routes.remove()` | A real scheduler or a real route table |
| T6.23 | Drop-only stop | Drop a relay with live DoH jobs without an explicit `stop` | The barrier runs with the same bounds, but the published ledger is `exact: false` with phase `drop_only`. It is never reported as a clean stop. A second drop is a no-op | A real process |
| T6.24 | Stuck pool thread and total stop budget | Hold one pool attempt in a test seam past `T_pool`, then stop; time `Relay::stop` and the tunnel-worker join separately | The DoH barrier moves to `Incomplete`, detaches and reports the stuck thread instead of claiming it gone, and does not add a new hang. The total stop time is recorded. The test does not claim the total is 5 s | A real stuck syscall and a real supervisor |
| T6.25 | Dead-route window in a DoH run | With a fake route controller that timestamps `remove()`, hold the DoH drain open (a pool attempt in a seam until `T_pool`), then stop the tunnel worker | The time from the worker loop exit to the end of route removal does not include `T_ack`, `T_pool`, or `T_adapter`; it is the `begin_stop` lock section plus wake writes. Route removal completes while the drain is still running. A run without the DoH profile shows the existing order | A real route table, a real OS, or H15 |
| T6.26 | Incomplete DoH stop and the next start | After T6.18 leaves one detached thread, request a start with the DoH profile, then a start without it, then release the thread and request the DoH start again | The first DoH start is refused with the fixed `doh_stop_incomplete` error, not a route error, and `cleanup_blocked` is false. The start without DoH proceeds. After the thread exits and `DOH_DETACHED_THREADS` is 0, the DoH start proceeds. When a route failure and a DoH incomplete stop happen together, the route message is the primary error, `cleanup_blocked` is true, and `doh_stop_incomplete` is still recorded | A real stuck syscall |
| T6.27 | `--no-pin` refuses the DoH profile | Request a tunnel start with the DoH profile and `--no-pin` | The start is refused before any DoH socket, adapter, or pool exists. A start with `--no-pin` and no DoH profile behaves as today | A real OS |

## 8. T7: Privacy and no plaintext DNS

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T7.01 | `mock_tun`, `mock_phone`, `mock_plain_dns` | Query `secret.example` through DoH | The plain sink receives zero packets. The phone target list has only the DoH IP:443 | A real carrier capture |
| T7.02 | Direct mode, `mock_plain_dns` | Same query | The plain sink receives zero packets. The only outer connect is the DoH IP:443 | A real hotspot |
| T7.03 | DoH failure | Same query | The plain sink receives zero packets | A real network failure |
| T7.04 | Plaintext profile selected before start, section 2.6 accepted | Same query, then force a DoH failure in a DoH-profile run | The plain sink receives the plaintext-profile query, the status flag is true, and `dns_plaintext_profile_queries` moves for the selected profile. The DoH-profile failure sends nothing to the plain sink and does not change the profile. The default `off` profile adds no counter and no warning | A real person's profile choice |
| T7.05 | TCP:53 | Same query | The phone target list has only the DoH IP:443, never port 53 | A real phone |
| T7.06 | Status, diagnostics, failures, probe | Run a query | The JSON contains no `secret.example`, no DoH endpoint name, no ECH config, no SNI | A real log sink |
| T7.07 | Failure record, privacy scope accepted | Force a DoH failure in source proxy mode | The record has no name. It uses `FailureEvent::doh_query`, the inner numeric destination, and `proto = dns`. It does not report `1.1.1.1:53`. Skip this row while the DoH failure-record privacy scope is not accepted; the default is counters only | A real UI |
| T7.08 | Counter JSON | Read every counter | Every value is an integer. No string, address, or name | A real API client |
| T7.09 | Capability JSON | Read `hide`, `ech`, `resolver_ech`, `sni_override`, `encrypted_dns`, `app_ech`, and the separate `runtime` object | `hide` is `unsupported`; `ech` is `unsupported` and keeps its legacy meaning; `resolver_ech` is `unverified` in an ECH build before qualification; `sni_override` is `unsupported`; `encrypted_dns` is `unverified` in a `doh` build before qualification; `app_ech` is `app_dependent`; `runtime.encrypted_dns_coverage` is a runtime state in its own object, not a capability value. No value contains free text | A real build matrix |
| T7.10 | Name map | Call `remember_dns_response` from a DoH path | It is not called. A code review and a test hook confirm the call graph | A real future refactor |
| T7.11 | Static check | Search the DoH module for `getaddrinfo`, `ToSocketAddrs`, and hostname APIs | None are present. All connect addresses are `SocketAddr` | A real platform resolver call from a dependency |
| T7.12 | Static check | Search the DoH module for `log`, `println`, and status field writes | No name, endpoint, or config is written | A real log sink |
| T7.13 | Capability JSON | Read `encrypted_dns` and `resolver_ech` | Both are separate from `hide`; both are `unverified` until a live qualification on that build and platform, then may be `supported`; neither is raised by a compile, a linked provider, or a hermetic test; `hide` stays `unsupported`; neither value carries free text | A real build matrix |
| T7.14 | Capability JSON | Read the application ECH state | It is `app_dependent`, never `supported`; no counter implies application coverage | A real app |
| T7.15 | Counter ledger | Run one successful DoH query, one timeout, one HTTP error, one parser error, one response mismatch, one queue rejection, one TLS failure, and one cancellation | `doh_queries` moves 8. `doh_query_ok` moves 1. `doh_query_failed` moves 7. The seven cause counters move 1 each and sum to 7. No counter is double counted | A real resolver mix |
| T7.16 | Failure record, direct mode, privacy scope accepted | Force a DoH failure with no source device | The record is written. It uses the inner numeric destination and `proto = dns`. It is not dropped by the `config.phone.is_none()` guard. Skip this row while the DoH failure-record privacy scope is not accepted | A real direct-mode UI |
| T7.17 | Counter names and narrowing | Read the schema and the code comment | `doh_lookups`, `doh_ok`, and `doh_failed` mean the endpoint's own ECH-config HTTPS/SVCB lookup, and the narrowing from "HTTPS or SVCB lookups over DoH" is recorded. `doh_queries`, `doh_query_ok`, and `doh_query_failed` mean the forwarder. An inner QTYPE 65 query moves only `doh_queries`. No key is reused for both | A real API client |
| T7.18 | ECH outcome ledger | Run a GREASE handshake, an authenticated rejection with a successful retry, an unauthenticated rejection, and a timeout after a config | `ech_grease` moves 1 and `ech_attempts` does not. `ech_attempts` moves 4. `ech_rejected` moves 1. `ech_ok` moves 1. `ech_rejection_unauthenticated` moves 1. `ech_error` moves 1. `ech_attempts = ech_ok + ech_rejected + ech_rejection_unauthenticated + ech_error + ech_retry_exhausted + ech_attempts_in_flight` holds exactly. `ech_fallback` does not move | A real provider |
| T7.19 | Capability contract | Read every capability value | Each mode and capability is one of `supported`, `unsupported`, `unavailable`, or `unverified`. `app_ech` is one of `app_dependent`, `owned_client`, or `unsupported`. No value contains a note or a scope sentence. A missing key is hidden, never `unverified` and never `supported`. `modes.off` is the only runtime-mode exception | A real UI |
| T7.20 | Cause partition | Force a TLS error, a certificate error, a reset, a source device capacity error, and a pool panic | Each increments `doh_query_failed` once and `doh_other_error` once. No failure is uncounted and no failure increments a second cause | A real panic policy |
| T7.21 | ECH type counts | Run one ECH-disabled retry after an authenticated rejection, and one non-ECH bootstrap | `ech_fallback` moves 1 and no other `ech_*` counter moves for that handshake. The bootstrap moves no `ech_*` counter and its result moves `doh_queries` and one `doh_query_*` outcome | A real provider |
| T7.22 | Capability scope stability | Read `encrypted_dns` before and after a network-profile switch | The value is the same static build and platform qualification. The profile-specific bypass is a separate coverage state and does not change the capability string | A real UI |
| T7.23 | Coherent snapshot and per-job owner | Start one slow query, read the counters during it, then let it finish | During the query `doh_in_flight` is 1 and `doh_queries = doh_query_ok + doh_query_failed + doh_in_flight`. The pool and adapter write no counter. After completion the gauge is 0 and the identity holds. A late completion is discarded, not counted as a timeout | A real scheduler |
| T7.24 | Late completion discard | Cancel or time out a job, then deliver its pool completion | The job has one terminal outcome. The late completion is discarded by job ID. No counter moves twice and no ECH outcome is recorded from it. The test-only discard count moves | A real scheduler |
| T7.25 | ECH in-flight outcome | Admit an ECH attempt, then cancel or time out before the pool returns | `ech_attempts` moves 1, `ech_attempts_in_flight` returns to 0, and `ech_error` moves 1. `ech_ok`, `ech_rejected`, and `ech_retry_exhausted` do not move. The ECH identity holds | A real provider |
| T7.26 | Config-fetch terminal outcome | Cancel, time out, and fail a config-fetch job | `doh_lookups` moves 3, `doh_config_in_flight` returns to 0, and `doh_failed` moves 3 once each. The fetch is not in `doh_queries`. A late completion is discarded | A real resolver |
| T7.27 | Multiworker snapshot stress | Run 4 and 8 pool threads with 1, 2, 4, and 8 relay shards, many concurrent UDP and TCP jobs, out-of-order completions, cancellations, and late completions; read snapshots concurrently | Every snapshot satisfies the section 7.2.2 identities. No counter is torn, no outcome is counted twice, and every job ends exactly once. The final snapshot after the barrier seals is exact | A real scheduler |
| T7.28 | Direct-mode failure privacy default | Run a DoH failure in direct mode before the privacy scope is accepted | No DoH failure record is written. Only counters move. The existing failure surface is unchanged | A real UI |
| T7.29 | Commit before delivery | Run one successful UDP query and one successful TCP:53 query | The ledger records the outcome before the delivery is observable to the inner client. A hook that pauses between the two shows no bytes before the commit. On a failure path, no bytes appear at all | A real scheduler |
| T7.30 | Attempt ledger across shards | Run attempts on two different shards with one accepted, one rejected, and one cancelled before `AttemptOutcome` | `ech_attempts`, the five outcomes, and `ech_attempts_in_flight` satisfy the identity exactly. The cancelled attempt records `ech_error`. No shard has a private tally | A real provider |
| T7.31 | Slot waiter accounting | Fill the session cap, queue a waiter, then let the waiter expire and, in a second run, let it be granted | An expired waiter records exactly one `doh_queries` plus `doh_query_failed`/`doh_queue_full` and never enters `doh_in_flight`. A granted waiter records one admission and one later outcome. The waiter count returns to 0 | A real load |
| T7.32 | Adapter delivery error accounting | Commit a TCP:53 answer and fail the inner write, then repeat with an adapter transport failure before admission | The first moves `doh_query_ok` once and `doh_adapter_errors` once, with no second query outcome. The second moves only `doh_adapter_errors`. `doh_queries` counts only the accepted query | A real client |
| T7.33 | Inexact snapshot marker | Force an `Incomplete` barrier and read diagnostics | The payload carries `exact: false` and the phase name. The UI does not render the ledger as exact. A `Sealed` run carries `exact: true` | A real supervisor |
| T7.34 | Waiter accounting identity | Fill the session cap, queue `W` waiters, then convert some, expire some in the queue, revoke some grants, cancel some queued waiters, cancel some granted-but-unconverted waiters, and stop with the rest queued or granted, across shards | Each waiter contributes exactly one of: one admitted query (conversion), one `doh_query_failed`/`doh_queue_full` (wait window or revoked grant), one `doh_timeout` (absolute deadline), or one `doh_cancelled` (cancel or stop), recorded by `settle_waiter`. A granted-then-cancelled waiter contributes one waiter `doh_cancelled` and no job outcome. No waiter contributes twice and none contributes zero. The final identity holds and the grant table is empty | A real scheduler |
| T7.35 | Three sequences | Run one ECH retry, one pipelined TCP:53 session with three queries, one config fetch and retry commit, two status reads with no ledger change between them, and one diagnostics read | `session_generation` is allocated once per session and never changes, including across the retry and the queued queries. `config_generation` moves only for cache commits. `ledger_seq` moves on every ledger mutation and not on a read: the two status reads report the same `runtime.snapshot_seq`, and a diagnostics read with no mutation in between reports the same value as `ledger.snapshot_seq`. No field uses the bare word "generation". A stale event from one namespace cannot change another | A real provider |
| T7.36 | Status versus diagnostics split | Read `/api/status`, the probe response, `/api/diagnostics`, `hs:status`, and `hs:diagnostics` | Static capability is in status, and the probe response may carry a copy of it. `runtime` is in status only; the probe response has no `runtime` object. Counters and `ledger { exact, phase, snapshot_seq }` are in diagnostics only. The browser privacy row reads capability from status or the probe copy and reads `runtime` from status only; the diagnostics report reads diagnostics. No test combines status and diagnostics into one exact claim. A missing key hides the row; a missing counter is not zero; a missing `ledger.exact` is not true | A real desktop |
| T7.37 | Stale probe fallback | Load the browser page with a probe captured while `runtime.encrypted_dns_coverage = active`, then stop the tunnel; separately, make a status poll fail after an `active` state | The probe response holds no `runtime` object. The runtime row never reads `state.probe.platform`. After the stop the row shows `unknown`/`not_running` from the next status response, never `active`. After a failed poll the coverage row is hidden, not left at the previous state. Static capability rows may still use the probe copy | A real browser session |

## 9. T8: Resource bounds and fuzzing

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T8.01 | Job queue | Submit 65 jobs | The 65th is rejected with `doh_queue_full`; no unbounded growth | A real load |
| T8.02 | Session cap | Fill `S` concurrent sessions, then open one more | The extra query enters the bounded slot wait and then fails with `doh_queue_full` if no slot is released. No live session's connection is evicted and no extra fd is opened. Close one session; its own slot frees and the waiter is granted | A real fd limit |
| T8.03 | Per-session queue | Submit 5 queries on one session | The 5th is rejected with `doh_queue_full`; the bound holds | A real resolver |
| T8.04 | Disposition slot | Fill the admitted-job bound, then complete jobs out of order while a consumer is slow | Every admitted TCP:53 job has a reserved answer or close disposition, so no committed answer is lost and no failed query stays open. A slow consumer does not block the shard or turn into a timeout. A post-commit write failure is counted as an adapter error | A real scheduler |
| T8.05 | Adapter authenticated cap | Open 33 authenticated connections | The 33rd is rejected. The adapter never evicts an authenticated connection. The cookie check still runs first. The adapter cap is an independent local bound and is not a DoH session reservation | A real local attacker |
| T8.06 | Adapter cookie | Connect with no cookie, a wrong cookie, and a correct cookie | The first two close within 1 s; the third is served | A real local attacker |
| T8.07 | Frame parser | Send 12..65535 byte frames and malformed lengths | All are bounded. No panic | A real client |
| T8.08 | ECH parser | Send 64 KiB plus one byte | Rejected at the bound | A real config |
| T8.09 | DNS question parser | Send a compression loop and a 255-label name | Bounded error, no hang | A real malformed query |
| T8.10 | Pool threads | Submit 8 long jobs and a 9th | The 9th waits in the queue, bounded | A real CPU |
| T8.11 | Cancellation | Set stop while a job waits | The job returns within 200 ms plus the poll slice | A real scheduler |
| T8.12 | Memory | Run 10,000 fuzz inputs | Peak RSS stays under a fixed test ceiling. The exact ceiling is recorded in the test | A real process |
| T8.13 | Fd count | Run a flow churn loop | The fd count returns to the baseline | A real OS |
| T8.14 | Adapter unauthenticated cap | Open 9 connections with no cookie, then a relay connection with a cookie | The 9th unauthenticated connection is closed. No connection is evicted. The relay connection is served if a slot is free and fails with a counted flow error if the cap is full. The listener stays up | A real local attacker |
| T8.15 | Adapter recursion | Send a query through the adapter, then inspect the plain sink and the system resolver | The adapter uses only the DoH pool. No system resolver and no plaintext query is used | A real host resolver |
| T8.16 | Adapter continuous flood | Hold the unauthenticated cap open and keep reconnecting for 60 s while one relay flow starts | No authenticated connection is evicted and no plaintext query leaves. The listener stays up. The relay flow is either served within its connect deadline or fails with a counted flow error. The test records which outcome occurred and does not require service: the threat model accepts a bounded local denial of service | A real local attacker and a real CPU |
| T8.17 | Completion reservation | Admit the maximum number of jobs, then complete them out of order while the completion channel is full | Every admitted job has a reserved outcome slot, so no outcome is lost. The maximum admitted count never exceeds the job-table and completion bounds. A full response-data channel fails only that job | A real scheduler |
| T8.18 | Atomic snapshot under load | Run the T7.27 stress test with a reader sampling at high frequency | Every snapshot is internally consistent. The reader never sees a half-updated gauge or a cause sum that differs from `doh_query_failed`. The final snapshot is exact | A real CPU |
| T8.19 | Per-query-port churn at the low rate | A mock client opens a new UDP source port per query at 10 qps for 60 s | No query fails with `doh_queue_full`. Peak sessions stay under the measured cap. Peak sessions and fd use are recorded. After the run the fd count returns to baseline | A real stub resolver and carrier |
| T8.20 | Per-query-port churn at and above the envelope | Repeat at 50 qps and at a rate above `P / h` | Within the declared envelope no session is evicted and no query is silently dropped. Above it, queries fail with `doh_queue_full` and the failure is counted once. No connection is shared across source ports and no plaintext query is sent | A real load |
| T8.21 | Global session cap across shards | Use 4 shards and a churn that would exhaust `S` on any one shard | The global count never exceeds `S`. A slot released by one shard can be granted to a waiter on another. No shard holds a private allowance | A real scheduler |
| T8.22 | Slot wait fairness and deadline | Queue many waiters across shards, then release one slot at a time | Grants are FIFO. A waiter past its deadline is rejected once and removed. The wait never blocks a shard loop past the poll slice | A real scheduler |
| T8.23 | Pool-size envelope | Run the churn test with 4 and 8 pool threads | Throughput and peak sessions match the declared formula within the test tolerance. The test records both numbers. A number outside the declared envelope fails the test | A real CPU |
| T8.24 | Adapter credits under flood | Hold all 32 authenticated connections at four outstanding frames each, then send one more on each | No frame is dropped for a full adapter admission path, because the credit count keeps it at or below 128. The 129th frame waits for a credit. A connection that waits past 30 s closes with one adapter event. The listener and other connections stay up | A real local attacker and a real CPU |
| T8.25 | Global waiter bound and fairness | Queue `W` waiters across 8 shards, then try one more | The extra waiter is rejected with `doh_queue_full` once, not silently. The queue never exceeds `W`. A release grants the oldest global waiter, not the oldest in the releasing shard. No shard holds a private allowance | A real scheduler |

## 10. T9: Application ECH

### 10.1 App-native

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T9.01 | `mock_doh` | Query type 65 for a name with an `ech` SvcParam | The record passes through unchanged, including the `ech` value | A real app |
| T9.02 | `mock_doh` | Query type 64 | Passes through unchanged | A real app |
| T9.03 | `mock_doh` | Query type 65 with a CNAME alias | The bytes pass through; the engine does not follow the alias for its own config | A real resolver |
| T9.04 | `mock_doh` | Check the QNAME and ID | Unchanged | A real 0x20 client |
| T9.05 | A test app with an ECH client and `mock_ech_capture` | The app gets the config through the DoH path and connects | The ClientHello carries ECH and the app's name is absent | A real app on macOS, Windows, or Linux |
| T9.06 | OS API probe | Check whether `getaddrinfo` and the named OS query APIs expose type 65 | The probe records the result per OS. It does not assume the result before the run | All applications |
| T9.07 | SVCB fallback | Remove the `ech` param from one alternative endpoint | The app may fall back; the engine does not prevent it | A real app policy |

T9.05 is a model, not a real application. It proves the engine does not break
an ECH-capable client. It does not prove that a browser or mail client uses the
engine's DNS path.

### 10.2 Product-owned client (future, not built)

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T9.10 | Local API | Connect without a token | Rejected | A real local attacker |
| T9.11 | Local API | Connect with a token | One application stream maps to one TLS connection | A real application |
| T9.12 | Local API | Two streams | Two TLS connections. No multiplexing | A real server |
| T9.13 | Local API | Wrong certificate | Rejected | A real misissuance |
| T9.14 | Local API | ECH rejection | Fails closed by default. A non-ECH profile is chosen before connecting, not after the rejection | A real provider |
| T9.15 | Local API | Client certificate request | The API contract is explicit; no silent key copy | A real client cert |
| T9.16 | Local API | Pin policy | The API supports an explicit pin or states that it does not | A real application |
| T9.17 | Local API | Time out or reset the connection to the ECH public name | No non-ECH attempt follows. The caller sees a failure. A retry only follows an authenticated ECH rejection, never a timeout or reset | A real blocked network |
| T9.18 | Local API | Select the labeled non-ECH profile before connecting, then time out | No automatic non-ECH retry runs after the timeout. The caller sees a failure. The non-ECH profile is counted and the status does not call it `hide` | A real caller policy |

These tests are not in WS1 scope. They are listed so a future review cannot
mistake the tunnel for a client.

## 11. T10: Cross-target build

| ID | Command or setup | Assertion | Not proven |
|---|---|---|---|
| T10.01 | `cargo check --all-targets --locked` with features off | Passes on every host and cross-target | A feature build |
| T10.02 | `cargo test --features doh` on macOS | Passes | Windows and Linux |
| T10.03 | `cargo test --features doh` on Windows x64 | Passes | A live tunnel |
| T10.04 | `cargo test --features doh` on Linux x64 | Passes | A live tunnel |
| T10.05 | `cargo test --features ech` on macOS arm64 | Passes | ECH acceptance |
| T10.06 | `cargo test --features ech` on Linux x64 | Passes | ECH acceptance |
| T10.07 | The Windows x64 release build | Uses `doh` and, if the provider builds, `ech`. If `ech` cannot build, the build uses `doh` only and reports `resolver_ech = unsupported` and legacy `ech = unsupported`. No stub | A shipping Windows build |
| T10.08 | `cargo check --target i686-pc-windows-msvc` with features off | Passes | A feature build on x86 |
| T10.09 | `cargo check --target x86_64-pc-windows-msvc` on macOS with features off | Passes. Do not enable the C provider on a host without the target toolchain | A feature build |
| T10.10 | `cargo clippy --all-targets --locked -- -D warnings` with supported features | Passes | Other targets |
| T10.11 | `cargo fmt --check` | Passes | Nothing |
| T10.12 | `cargo tree` / lockfile review | Only the reviewed crates are added. `Cargo.lock` is committed | Runtime cost |
| T10.13 | A build without `doh` | Reports `encrypted_dns = unsupported`, `app_ech = app_dependent`, legacy `ech = unsupported`, `resolver_ech = unsupported`, and `hide = unsupported` | A feature build |
| T10.14 | A build with `doh` but without `ech` | Reports `encrypted_dns = unverified`, `app_ech = app_dependent`, legacy `ech = unsupported`, `resolver_ech = unsupported`, `hide = unsupported`. `supported` requires a live run | ECH |
| T10.15 | A build with `doh` and `ech` after a native hermetic test | Still reports `encrypted_dns = unverified`, `app_ech = app_dependent`, legacy `ech = unsupported`, `resolver_ech = unverified`, `hide = unsupported`. A compile, a linked provider, and a hermetic test are not live evidence. A recorded live qualification may then set `encrypted_dns` or `resolver_ech` to `supported` | A live run |
| T10.16 | Read every capability value from every build | Each mode and capability is one of the four strings. `app_ech` is one of `app_dependent`, `owned_client`, or `unsupported`. `runtime.encrypted_dns_coverage` is a separate object, not a capability value. No value carries free text. No build reports `supported` for any key from a compile, a linked provider, or a hermetic test. A build with the reviewed qualification constant may report `supported`; a build without it reports `unverified`. The legacy `ech` keeps its meaning and value | A live run |
| T10.17 | Additive feature matrix: build features off, `doh` only, `ech` only, and `doh` plus `ech` | `ech` implies `doh`, so an `ech`-only build still contains the DoH code. `doh` plus `ech` selects one provider and does not link two TLS providers. Every combination compiles and runs the base tests. A combination that omits `doh` is a feature-graph bug | A shipping provider build |

## 12. T11: Runtime versus carrier verification

This table is the most important one. A hermetic test is not a carrier test.

| Claim | What a hermetic test proves | What a runtime test on a real target proves | What only a carrier test proves |
|---|---|---|---|
| DoH code path | The client speaks the configured HTTP/1.1 and TLS shape to a mock | The target can reach a public DoH resolver and get an answer | The carrier permits the IP, port, and name, and at what latency |
| No plaintext DNS | A mock sink receives nothing on the test path | A local capture on the target shows no plaintext query for the tested app | The carrier path carries no plaintext query for all apps |
| TTL audit | Every test outer socket sets TTL 65 and the audit ends at `(n, 0)` | The target's sockets pass the same audit on a real interface | The carrier observes the expected TTL after the source device NAT |
| ECH emission | The ClientHello contains `0xfe0d` and not the real name | The target offers ECH to a public provider | The provider accepts it and the carrier does not block the public name |
| ECH rejection retry | A mock server rejects and the client retries once | A real provider rejects or accepts | The retry works across anycast nodes and config rotation |
| App-native ECH | A model app gets a config and emits ECH | A real app on the target emits ECH | The carrier sees the public name, not the inner name |
| DNS bypass | The policy table and detector unit tests. A hermetic test cannot prove which OS route wins | The target's gateway, scoped, and link-local configuration is read correctly, and a macOS or Windows gateway query is observed outside the tunnel | Whether a specific app actually used a bypass |
| Caches | The engine caches no answers | The target's OS and browser caches are present | Whether a specific name was already cached at the carrier |
| Cleanup | Stop, drop, panic, and child kill leave no listener or thread | The target's fd and thread state is clean after a real run | A carrier is unaffected by a target crash |
| Cost | Loopback latency and memory | Hotspot latency, battery, and fd use | The carrier's RTT, throttling, and flow model |

### 12.1 Runtime test prerequisites

- Owner approval.
- A real hotspot and a source device where proxy mode is tested.
- A known public DoH resolver and a known ECH-capable origin for the engine
  connection.
- A local packet capture on the target, limited to the test flows, with no
  personal traffic.
- No change to routes beyond the tunnel's own start path. Remove every route,
  address, and device after the test.
- A clean stop with SIGINT or SIGTERM. Never `kill -9` a live tunnel.
- A written record of the OS, resolver, carrier, and app versions.

### 12.2 Carrier test prerequisites

- Owner approval and a plan for the carrier terms.
- A source device under the owner's control.
- A capture at the carrier-facing socket, not at the target's hotspot link.
- A test origin the owner controls for the ECH acceptance path, or a public
  provider with a documented ECH deployment.
- A rollback and cleanup plan.
- No claim from a VM, an emulator, a loopback, or a mock.

No carrier, hotspot, route, or interface test was run for this revision.

### 12.3 T11.4: hypothesis measurements

The architecture section 6.8 lists H1 to H15. Each one needs evidence before it
becomes a claim. A hermetic test can close H5, H7, H14, and part of H6. The rest
need a real target or a real provider.

| ID | Hypothesis | Measurement | Closes |
|---|---|---|---|
| T11.4a | H1 and H2: per-query-port churn and peak concurrency | A DNS-specific capture of inner 4-tuples and burst sizes on each target, with no user payload | The capacity envelope |
| T11.4b | H3: the quiet window keeps reuse and frees churn | A mock run plus a live run with a reusing client and a per-query-port client | The UDP session policy |
| T11.4c | H4: 8 threads and 64 sessions serve the envelope | T8.19 to T8.23 plus a hotspot measurement | The cap and pool size |
| T11.4d | H5: the ledger lock is cheap at envelope rates | T7.27 at 1, 2, 4, and 8 shards, with lock wait time recorded | The admission design |
| T11.4e | H6 and H13: the DoH barrier completes within its phase bounds and the total stop time is measured | T6.16 to T6.24 on each target, with the DoH phases, the relay join, and the tunnel-worker join timed separately | The DoH barrier deadline and the total stop budget |
| T11.4f | H7: the local preface carries the shard index | The adapter and relay tests. It is local framing | The routing design |
| T11.4g | H8: a default resolver binds some queries to the link | A live DNS-specific run on macOS, Windows, and Linux | The bypass table |
| T11.4h | H9, H10, H11: rustls ECH API, provider HTTP/1.1, and provider builds | A compile spike, two real providers, and one build per target | The ECH and DoH builds |
| T11.4i | H12: an early session close does not change carrier classification | A carrier measurement with owner approval | The shape claim |
| T11.4j | H15: a pinned DoH socket keeps working after the tunnel routes, the Linux policy rules, and the TUN address are removed | A per-platform host test on macOS, Linux, and Windows that holds a pinned DoH connection, removes the routes, and completes the query, in direct and source device proxy mode where the platform supports them. It needs a host with route changes allowed and owner approval; it is not a hermetic CI test | The routes-first stop order in a DoH run |

## 13. T12: Documentation and handoff checks

These are hermetic text checks. They do not prove a runtime behavior. They stop
a stale plan or a stale capability label from passing review.

At the 2026-11-05 checkpoint, the plan's own revision note says task
`85710a0e` applied P7 and P9 to P15. That is a text claim to verify, not this
matrix's approval, and this matrix does not edit the plan. Re-read the plan
before relying on any item.

| ID | Check | Assertion |
|---|---|---|
| T12.01 | Plan fallback text (P1 and P2) | The blockable bullet and the `hide` acceptance gate forbid an automatic non-ECH retry after a timeout, reset, or certificate failure and label a separately selected non-ECH profile as not `hide`. They do not require a fresh non-ECH flow after a detectable failure |
| T12.02 | Plan DNS command (P4) | Both DNS-path passages say command 1 with DNS-over-TCP framing. Command `0x80` appears only for other UDP |
| T12.03 | Plan status words (P6) | The plan uses `supported`, `unsupported`, `unavailable`, and `unverified` at the parity bullet, the WS0 gate, and the acceptance criterion. It does not use `yes`, `no`, or `unknown` as capability states |
| T12.04 | Plan GREASE policy (P3) | The plan says GREASE, if implemented, is a separate opt-in and does not make destinations look alike. It says GREASE alone is not `hide`. It does not say "GREASE otherwise" or "falls back to GREASE" |
| T12.05 | Plan DNS coverage claim (P5) | The plan says the tun path sends a numeric IP and that gateway DNS on macOS and Windows can bypass the tunnel. It does not say the name was already resolved through the relayed DNS path |
| T12.06 | Plan SOCKS leak (P7) | Plan invariant 4 keeps "No `getaddrinfo` on an egress path" and adds the plaintext `TinyResolver` local-resolution leak. The direct SOCKS5 passage names `TinyResolver`'s plaintext leak, the separate ATYP 1 and 4 client leak, and the unenforced `socks5h` requirement. A partial correction that only says "local client resolution" does not pass |
| T12.07 | Plan capability table (P8) | The plan says capability reporting exists and reports unsupported modes honestly. It does not say `probe`, status, diagnostics, and app settings report no ECH or SNI capability |
| T12.08 | Plan parity contract (P9) | The plan adds `encrypted_dns`, `resolver_ech`, and `app_ech` to the reported set and points to the capability contract |
| T12.09 | Plan boundary outcome and DoH scope (P10) | Every boundary-open passage is replaced: the header, the status row, section 2.4, the `hide` section, the insertion table, the acceptance criterion, open question 1, the claim ledger, and the reader-facing UI text. The plan records that a transparent byte relay cannot inject ECH, so `hide` is not built and stays unsupported. It distinguishes the closed boundary from the product owner's separate DoH scope decision. A product-owned client is a separate optional future proposal with no TLS termination or relay. Encrypted DNS is a separate proposed scope and is not presented as approved |
| T12.10 | Plan caching and failure policy (P11) | The plan says "ECH config caching" and open question 6 is marked answered by the retry table: only an authenticated resolver rejection retries, once, with retry configs or ECH disabled; no timeout retry; application flows never retry |
| T12.11 | Capability honesty | Every capability document says `hide = unsupported`; no document says DoH alone satisfies `hide`. The legacy `ech` keeps its meaning. No document aliases it to `app_ech` while a consumer reads it as a mechanism flag |
| T12.12 | `encrypted_dns` and `resolver_ech` honesty | No document reports either as `supported` from a compile, a linked provider, or a hermetic test. `supported` requires recorded live qualification |
| T12.13 | Counter honesty | No document reuses `doh_lookups` for inner queries or adds `doh_lookups` to `doh_queries`. The narrowing is recorded. The plaintext counter is not called a fallback and is absent in the default `off` profile |
| T12.14 | Scope gate | The header and matrix gate do not make an owner client-boundary decision block encrypted DNS. Application ECH is closed, and the DoH forwarder has its own product scope acceptance. The independent review is separate. No implementation is implied |
| T12.15 | Plan stale code and counter claim (P12) | The plan says the counter keys and zero values exist and the data path does not write them. It does not say "counters ... proposed, not implemented" while the keys exist. It does not imply that a counter key is an ECH client |
| T12.16 | Plan DNS transport (P13) | The plan says DNS uses UDP and TCP, the tunnel path is plaintext today, source proxy uses DNS-over-TCP framing on command 1, and DoH would be HTTPS over TCP. It does not say "DNS is UDP" |
| T12.17 | Plan Linux bypass (P14) | The plan names Linux default link-bound resolver as a likely bypass and lists scoped, link-local, ULA, multicast, NAT64, and application or OS encrypted DNS. It does not claim a live DNS-specific result |
| T12.18 | Plan reader-facing terms (P15) | Reader-facing text says `hide` is closed as unsupported under the current constraints, not "unresolved" or "blocked on the client boundary". It says encrypted DNS is a separate proposed scope, not approved. It does not say `hide` is implemented or that DoH is `hide` |
| T12.19 | Plan handoff completeness | P1 to P15 are each present with the required text, verified against the quoted passage. The plan's revision note for task `85710a0e` is a claim to check, not evidence. Any remaining item is marked remaining, and no item is cited as approval |
| T12.20 | Plan retry consistency | No plan passage says "no non-ECH attempt" without the resolver-connection exception, and no passage authorises a non-ECH retry for an application flow |
| T12.21 | RFC citation check | Every RFC number and section used in the architecture and matrix has been checked against the text, or is marked unverified from memory. No citation is presented as read when it was not |
| T12.22 | DNS discovery text | The architecture says macOS uses an unambiguous scoped `scutil` block and rejects a VPN, split-DNS, mDNS, loopback, or link-local resolver. It says Linux `system_dns_for_interface` fails closed and needs an explicit `--dns-servers` list, bounded to 8 numeric servers, validated and deduplicated. It does not describe the old "up to 3 system servers" behavior or a Linux aggregate as an egress resolver |
| T12.23 | Plan revision status | The architecture, matrix, and trace agree with the plan's revision note: task `85710a0e` applied P7 and P9 to P15 according to the plan. None of the three treats the note as approval. None edits the plan |
| T12.24 | Third-party resolver decision and invariant amendment | The architecture records: that the DoH endpoint is a third-party resolver; that the committed `AGENTS.md` invariant 4 has no resolver-substitution sentence and the working-tree change adds one; that source device proxy mode already redirects captured UDP:53 to `1.1.1.1:53` (`rust/src/relay.rs`); that the docs suggest `1.1.1.1` and `8.8.8.8` as explicit servers; that the no-built-in-endpoint rule applies to the DoH profile only; and that owner questions Q1 to Q5, the decision, and the amendment are open. It does not assert that the decision exists, that the scope is approved, that either invariant text is compatible, or that the existing redirect conflicts or does not. It changes no invariant. The plan text is not changed by this matrix |

## 14. T13: Capability consumer migration

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T13.01 | `gui_assets/app.js` and `destination_privacy.test.mjs` | Load a payload with the new keys and one without them | The page prefers `app_ech`, `resolver_ech`, and `encrypted_dns` when present. Without them it keeps the legacy `ech` row labeled and shows no false support. `runtime.encrypted_dns_coverage` is shown as coverage. A mode row that is unsupported is described as not available, not as a failed privacy report | A real browser |
| T13.02 | Linux `model.js` and its test | Load the default and a `doh` build payload | The ECH card stays a legacy build statement. The encrypted DNS and resolver ECH rows use the four states. No build-only support appears | A real Linux desktop |
| T13.03 | Windows `WindowsPrivacyCapabilities` and its tests | Load the default and a `doh` build payload | The fact rows use the four states. "Off" is a runtime mode, not a privacy claim. `encrypted_dns` and `resolver_ech` appear as separate facts. No "Yes" for `unverified`. Runtime "not running" does not set `unavailable` | A real Windows app |
| T13.04 | `rust/src/demo.rs` tests | Read the demo capability and counters | The legacy `ech` assertion is unchanged, the new keys are present with conservative values, and no default DoH path or counter is added | A real build |
| T13.05 | Cross-consumer semantic check | Compare each consumer's old and new output for the same payload | No key changes meaning. The `ech` value and meaning are unchanged. A missing new key is hidden. `off` is still `supported` as a runtime mode | A real release |
| T13.06 | `app_ech` parser kind | Feed `app_dependent`, `owned_client`, `unsupported`, a four-state value, and a missing key to the browser parser and the Linux parser | The three allowed values render as information rows. A four-state value is rejected as "not reported", not accepted. A missing key omits the row. `app_dependent` is never rendered as support. `owned_client` appears only in a future build | A real app |
| T13.07 | Linux payload path | Run the Linux app with a version 2 status payload and a diagnostics payload, then with each alone, then with no payload, then with a failed IPC call | With both, `privacyView` receives capability and runtime from `hs:status` and counters from `hs:diagnostics`, shows `encrypted_dns`, `resolver_ech`, legacy `ech`, `app_ech`, and a separate runtime coverage row. With only one, it shows only the rows that payload supports. With none or a failed call, the static card stays and says the build did not report the keys. No row infers a state from `engine: true` | A real Linux desktop |
| T13.08 | Windows static report | Build the Windows report with and without a version 2 payload | The static report prints "Not reported by this build" for a key it did not receive. It never prints `supported`, `unverified`, or `active`. `Off` stays a runtime mode. If a payload path is added later, it uses the same parser | A real Windows app |
| T13.09 | Schema 1 compatibility | Feed every consumer a schema 1 payload and a schema 2 payload with unknown extra keys | The schema 1 consumers render the old rows unchanged. The schema 2 consumers ignore unknown keys. No consumer fails on an unknown key or coerces it to support | A real release |
| T13.10 | Linux status and diagnostics split | Run the Linux app with `hs:status` only, `hs:diagnostics` only, both, and neither | With both, `privacyView` receives capability and runtime from status and counters from diagnostics. With neither, the static card stays and says the build did not report the keys. With only one, it shows only the rows that payload supports and never invents the other. No row infers a state from `engine: true` or `mode` | A real Linux desktop |
| T13.11 | Cross-endpoint honesty | Read a status runtime state and a diagnostics counter set from different instants, then from the same instant with no ledger mutation between | The UI does not present the two as one exact snapshot in either case. `runtime.snapshot_seq` and `ledger.snapshot_seq` are two fields that report values of the one per-run `ledger_seq`; neither has its own counter. Different values show different ledger states; equal values in one run show the same ledger state, and the test may use that, but the UI still makes no coherence claim. A stale runtime state cannot change a counter and a stale counter cannot change a capability | A real desktop |

## 15. T14: Default `off` behavior

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T14.01 | Features off, default start | Start, stop, and read status, diagnostics, failures, and probe | The default DNS path, routes, sockets, counters, warnings, and UI are unchanged. No DoH connection and no new counter appear. `hide` is `unsupported` | A real host |
| T14.02 | A `doh` build, no DoH profile | Start and read status | `encrypted_dns` is `unverified`, `runtime.encrypted_dns_coverage` is `inactive`, no DoH connection is opened, and no plaintext warning appears unless section 2.6 is accepted | A real host |
| T14.03 | A `doh` build, DoH profile, then failure | Start with DoH and fail the connection | The query fails as a DNS failure. No plaintext query is sent and no plaintext warning is added by the failure. `runtime.encrypted_dns_coverage` is `failed`, not a changed capability | A real network |
| T14.04 | Default capability payload | Compare with the current release payload | The old keys and values are unchanged. New keys are additive and conservative. No consumer needs to change to keep working | A real release |

## 16. T15: Protocol regression

These tests protect the invariants that the DoH work must not change. They are
hermetic. They do not prove a carrier result.

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T15.01 | Source tree and a static symbol diff | Compare the SOCKS command constants, pairing labels and vectors, source device status codes, ICMP echo commands, and the key schedule before and after a DoH change | None changed. The adapter preface is local loopback framing and is not on the source device wire | A hidden runtime change |
| T15.02 | `mock_tun`, `mock_phone` | Run an application TCP flow and an application UDP flow with DoH enabled | Each inner flow still uses exactly one outer socket. No DoH session carries two inner flows. The ECH retry closes its own old connection first | A real hotspot |
| T15.03 | `mock_audit` | Run UDP:53, TCP:53, and an application flow | Every egress socket goes through the normalized helper, sets TTL 65, and the audit ends at `(n, 0)` | A carrier TTL observation |
| T15.04 | Start paths | Start direct mode with the default IPv6 policy, and source proxy mode | Direct defaults to `block`; source proxy forwards IPv6. `--ipv6 inherit` is still explicit. No DoH path changes a default | A real OS route |
| T15.05 | Failure and stop paths | Force a DoH failure, then stop the tunnel | No plaintext fallback, no route change, and no persistent state. The route cleanup path is the existing one. DoH adds no route or device | A real host |
| T15.06 | Adapter preface | Inspect the preface bytes and the source device mock | The preface carries the shard index and connection ID only on loopback. The source device sees the DoH IP and port, not the preface | A real source device |

## 17. Gates

A future implementation is not accepted until all of these pass:

- **G1 Requirement**: `hide` still requires an application ECH path and a DoH
  path. Under the current constraints `hide` is closed as unsupported, so no
  build passes it. DoH alone does not pass.
- **G2 No plaintext**: With a DoH setting active, no plaintext DNS leaves the
  target for a tunneled query. The mock sink and, later, a target capture agree.
  DoH is off by default; the default plaintext profile is labeled, not silent.
- **G3 TTL**: Every egress DoH socket sets TTL 65 and the audit ends at
  `(n, 0)`.
- **G4 Cleanup**: Stop, drop, panic, and child kill leave no listener, thread,
  fd, route, address, or device, with one reported exception: after an
  incomplete DoH stop, a detached pool thread and the socket it holds may live
  until its blocked call returns or the process exits (T6.18, T6.26). Double
  stop is a no-op. Stop runs the barrier, records `doh_cancelled`, and returns
  every gauge to 0. A missed barrier deadline or a shard panic reports an
  incomplete stop, never sets `cleanup_blocked` for a DoH-only cause, and never
  publishes a partial ledger as exact.
- **G5 ECH**: The ClientHello carries ECH and not the real name. The resolver
  connection retries once, only after an authenticated rejection: with retry
  configs, or with ECH disabled when no supported retry config exists. A timeout,
  reset, certificate failure, 5xx, parse error, or SERVFAIL never retries. A
  rejected config is evicted. A non-ECH application flow is a profile chosen
  before connecting, not a retry, and it never follows a failure. The
  ECH-disabled resolver retry is explicit and counted as `ech_fallback`.
- **G6 Privacy**: No QNAME, endpoint name, ECH config, SNI, certificate, or
  token appears in status, diagnostics, failures, probe, or logs. A DoH failure
  record is off until its own privacy scope is accepted.
- **G7 Bounds**: Every queue, session, waiter, frame, cache, parser, event slot,
  disposition slot, attempt work item, adapter credit, job-table entry, and
  adapter admission rule has a bound and a fuzz test. The adapter never evicts a
  connection and never submits a pool job. The event, attempt, and disposition
  capacities are reserved at admission.
- **G8 Build**: Features off and on build as designed. No stub. No
  `continue-on-error`. `doh` and `ech` are additive; `ech` implies `doh`; both
  may be enabled; one provider is selected. A build with DoH reports
  `encrypted_dns = unverified` until live qualification, then may report
  `supported`. A build with ECH reports `resolver_ech = unverified` until
  qualification. The legacy `ech` keeps its meaning and never becomes a privacy
  support claim.
- **G9 Carrier**: A live measurement exists for reachability, blocking, ECH
  acceptance, a DNS-specific gateway observation, other bypasses, and cost. A
  mock does not count. The 2026-11-02 route record is not a DNS result and does
  not stand in for Windows or Linux.
- **G10 Plan**: P1 to P15 are accounted for by the current plan text and verified
  by T12. The plan's revision note says task `85710a0e` applied P7 and P9 to P15;
  that is a claim to check, not approval. No stale plan text can force a
  downgrade, claim gateway DNS coverage, overstate support, or say "blocked on
  the client boundary". P10 records the closed boundary and the separate DoH
  scope in every old passage, and distinguishes the product owner's scope
  decision, the third-party resolver decision, and the review.
- **G11 Ledger**: The ECH and DoH identities in architecture section 7.2 are
  exact in a coherent diagnostics snapshot and after the barrier seals, for 1,
  2, 4, and 8 shards. `doh_queries = doh_query_ok + doh_query_failed +
  doh_in_flight`, with one of seven causes per failure and gauge terms for
  config fetches and ECH attempts. Each accepted job has one job ID, one owning
  shard, one `session_generation` that is fixed for its session, one
  `attempt_id`, and one terminal owner; a late completion is discarded by job
  ID and attempt ID, and a duplicate disposition by its applied job ID.
  `config_generation` and the ledger sequence (reported as
  `runtime.snapshot_seq` and `ledger.snapshot_seq`) are separate and never
  substituted.
- **G12 Capability**: The section 2.4 contract and the section 2.5 migration are
  followed. No free-text value. A missing key is hidden and never `unverified`.
  A value is static per build and platform and is not recomputed per network
  profile. Static capability and the `runtime` object are separate, and
  `app_ech` uses its own three-value parser kind. Capability and runtime come
  from status; counters and ledger metadata come from diagnostics.
- **G13 Gate**: No implementation starts until WS6 verifies P1 to P15, the
  product owner accepts the DoH scope and decides the third-party resolver
  substitution, the invariant amendment lands, and a new independent review
  approves. Application ECH is closed. The independent review is not the scope
  acceptance.
- **G14 Default**: The default `off` behavior is unchanged. No new default DNS
  path, counter, warning, route, socket, dependency, or mode. The plaintext
  counter and warning need the section 2.6 acceptance.
- **G15 Retry consistency**: The retry policy in architecture section 5.3,
  acceptance section 12, T4.09, T4.24, G5, and plan P11 is the same. No sentence
  forbids the resolver ECH-disabled retry and no sentence allows an application
  flow to retry.
- **G16 Sharded ownership**: 1 to 8 shards run without a private counter or a
  private global bound. Every job is admitted by one shard and ends exactly once.
  No job migrates. The shared ledger is identical from any shard's snapshot.
  Slot waiters are one global FIFO, not four per-shard orders.
- **G17 Commit ordering**: No inner client receives bytes before the owner
  commits one outcome. A cancelled, timed-out, duplicate, or stale-attempt
  response writes nothing. Dispositions are applied in `request_id` order. A
  committed answer is written or counted once in `doh_adapter_errors`, never a
  second query outcome and never dropped as "not current". Every accepted
  TCP:53 query ends with one answer or one graceful, ordered close.
- **G18 Lifecycle**: Every session, config-cache entry, and ECH attempt has one
  owner and a named release path. A connection is a move-only lease; a slot is
  freed only after the handback for the attempt that held it. The session
  incarnation and attempt ID prevent a late event from attaching to or freeing
  a newer object. A config fetch that ends without a commit wakes every shard
  and elects at most one new fetcher. The config
  cache is single-flight and publishes only from a compare-and-set fetch or
  retry commit. A stale rejection cannot evict a newer config.
- **G19 Capacity**: The measured per-query-port envelope holds with the declared
  cap and pool size. Below it, no query fails with `doh_queue_full`. Above it,
  the failure is explicit and counted once. No connection is shared across source
  ports and no plaintext query is sent. Adapter credits keep the ingress from
  filling.
- **G20 Stop barrier**: The DoH phase starts before `Relay::stop` clears the
  queue or sets `running = false`, and before the shard join. In a DoH run
  the tunnel worker calls `begin_stop`, removes routes, and then drains. Intake closes
  before the drain. No admission is recorded after `Stopping`. Every live job
  gets one terminal cause, every waiter is removed once, and every slot is freed
  only after a handback. The DoH barrier is bounded, and a miss is an
  incomplete DoH stop with an inexact ledger, its own message, and no
  `cleanup_blocked`. The total stop time is measured, not assumed.
- **G21 Consumers**: The browser, Linux, and Windows consumers obey their data
  paths. No consumer renders `app_dependent` as support, a runtime state as a
  capability, takes capability from diagnostics, or prints a value it did not
  receive. A schema 1 payload keeps working. Cross-endpoint coherence is not
  claimed.
- **G22 Protocol**: T15 shows no SOCKS, pairing, source device, ICMP echo, key
  schedule, TTL, route, IPv6 default, or one-outer-per-flow change. The adapter
  preface is local loopback framing.
- **G23 Retry and cache ownership**: A retry is the same job's second attempt.
  The owning shard dispatches the reserved attempt as `attempt_id` 2 without
  changing `session_generation`, and publishes the retry config only through a
  compare-and-set. The
  pool never writes the cache. A stale rejection publishes and evicts nothing.
- **G24 Lease and handback**: A live connection has one holder. A slot is freed
  only after the handback for the attempt that held it. A late handback cannot
  free a newer slot.
- **G25 Adapter failure delivery**: Every accepted TCP:53 query has one reserved
  answer or close. No frame is dropped for a full admission channel. A failed
  query closes the inner connection without waiting for the idle timer.
- **G26 Status and diagnostics**: Capability and runtime are in status. Counters
  and `ledger` are in diagnostics. `runtime` is read only from the latest
  successful status response, and the probe copy has none. A missing key is
  hidden, a missing counter is not zero, and a missing `ledger.exact` is not
  true.
- **G27 Resolver decision**: The third-party resolver decision, answers to owner
  questions Q1 to Q5, and the explicit invariant amendment exist before any DoH
  code. The DoH profile has no built-in, automatic, or fallback endpoint, and no
  query is forwarded by a DoH path without the decision. The existing source
  device proxy mode `1.1.1.1:53` redirect and the explicit-server options are
  recorded as existing behavior, not denied. The design does not assert
  compatibility with the committed or uncommitted invariant 4 and changes no
  invariant.
- **G28 Session incarnation**: T5.33, T5.39, and T5.48 pass. A successful retry
  and every queued job after the first commit complete normally. No
  `generation_mismatch` reason exists.
- **G29 Waiter settlement**: T5.46, T5.51, T5.52, T7.34, and T16.04 pass. Every
  waiter has exactly one settlement or one conversion, and a late
  `admit_granted` is `Stale`.
- **G30 Stop order and report**: T6.18, T6.22, T6.25, T6.26, and T6.27 pass on
  every target with a fake route controller. H15 is measured on each platform
  before the routes-first order is claimed safe. An incomplete DoH stop never
  sets `cleanup_blocked`.
- **G31 Graceful TCP:53 close and fetch election**: T5.47, T5.49, T5.50,
  T16.13, and T16.14 pass. No query is made `doh_cancelled` by another query's
  failure. A cancelled fetch never leaves waiters stranded until their
  deadlines.

## 18. Test status

| Area | Written | Run | Notes |
|---|---|---|---|
| T1 DoH client | No | No | Mock server design only |
| T2 HTTP parser | No | No | Bounds are proposed |
| T3 DNS handling | No | No | TC and DNSSEC pass-through proposed |
| T4 ECH | No | No | No ECH server exists hermetically. The retry ledger is tested behind a seam |
| T5 Relay integration | No | No | Reuses the existing mock tun and mock phone pattern |
| T6 Cleanup and crashes | No | No | Child kill is hermetic, no route |
| T7 Privacy and no plaintext | No | No | Requires the test-only sink, the output scan, the counter ledger, and the late-completion seam |
| T8 Bounds and fuzzing | No | No | Deterministic, no new dependency |
| T9 Application ECH | No | No | T9.05 is a model, not a real app |
| T10 Cross-target | No | No | Provider builds unproven |
| T11 Runtime and carrier | No | No | Needs owner approval |
| T12 Documentation | No | No | Text checks only |
| T13 Capability migration | No | No | Reads the consumer outputs, not a real OS. Includes the Linux payload path and the Windows static report |
| T14 Default `off` | No | No | Compares the default payload with the current release |
| T15 Protocol regression | No | No | Static symbol diff plus behavior tests. It does not prove a carrier |
| T16 Adversarial and race | No | No | Uses the pool, adapter, cache, waiter, and status seams. It is not a carrier test |

No test in this file has been run. Do not cite this file as evidence.

## 19. T16: Adversarial and race tests

These tests target the defects the revision 7 review named. They are hermetic
and use the seams in `shard_harness`, the pool, the adapter, and the status
publisher. They are not carrier tests.

| ID | Setup | Action | Assertion | Not proven |
|---|---|---|---|---|
| T16.01 | `shard_harness`, two attempts | Deliver a duplicate completion with the same job ID but an older attempt ID, then a duplicate disposition to the adapter | The older completion is discarded by job ID and attempt ID. The duplicate disposition is dropped by its already-applied `job_id`, not by a "current generation" comparison. No counter moves twice and no byte is written | A real scheduler |
| T16.02 | `shard_harness`, slot reuse | Free a slot, admit a new session in it, then deliver a handback from the old attempt | The old handback returns only its reserved work item. It does not free the new session's slot and does not change its generation. The slot count stays correct | A real scheduler |
| T16.03 | Cache race, two shards | Publish a newer config, then deliver a stale authenticated rejection from the older generation, then a stale retry config commit | The stale rejection does not evict the newer config. The stale retry commit publishes nothing. The live retry still runs with its authenticated configs. `doh_lookups` does not move for the retry | A real resolver rotation |
| T16.04 | Waiter race | Grant a waiter, then cancel it before `admit_granted`, then release another slot, then let the first shard call `admit_granted` | The cancel settles the waiter once with `doh_cancelled` and returns its slot in the same critical section; the release step may grant that slot to the next waiter. The later `admit_granted` returns `Stale` and records nothing. No waiter is granted twice, settled twice, or both settled and converted, and no slot is stranded or counted twice | A real scheduler |
| T16.05 | Adapter credit race | Return a credit twice for one disposition, and send a disposition for a connection that closed | The double return does not exceed four credits. The closed connection's disposition increments `doh_adapter_errors` once. No frame is read on a connection without a credit | A real local attacker |
| T16.06 | Retry storm | Send repeated authenticated rejections on the same job and on a second session | At most one retry per job. A second rejection ends the job with `ech_retry_exhausted` or `ech_error`. No third attempt, no cache loop, and `config_generation` does not churn | A real provider |
| T16.07 | Stop versus retry dispatch | Request stop between the authenticated rejection and the retry dispatch, and again while the retry is queued | No retry is dispatched after `Stopping`. The job records one `doh_cancelled`, the attempt gauge returns to 0, and the reserved retry work item is returned. No socket is opened | A real scheduler |
| T16.08 | Adapter preface attack | Send a preface with a bad version, an IPv6 address in a family-4 field, an unknown shard index, a non-zero reserved field, and a valid preface | The bad prefaces close the connection and count `doh_adapter_errors`. The valid one is accepted. No destination is used for routing and no answer is synthesized | A real local attacker |
| T16.09 | Status, probe, and diagnostics skew | Publish a runtime `active` state, take a probe, stop the supervisor, then read status, the probe copy, and diagnostics with a stale counter set | Status shows `unknown`/`not_running` with no `snapshot_seq`. The probe copy has no runtime object, so it cannot show `active`. The diagnostics ledger is inexact or from the sealed run. The UI does not present the old `active` state with new counters as one snapshot. A missing key is hidden | A real desktop |
| T16.10 | Resolver substitution guard for the DoH profile | Read the DoH profile's code and configuration surface for a built-in DoH endpoint, an automatic choice, or a fallback when the configured endpoint fails | The DoH profile has no built-in endpoint, no automatic choice, and no fallback to a public resolver, to the `1.1.1.1:53` redirect, or to plaintext. The endpoint requires an explicit person-set value. The existing source device proxy mode `1.1.1.1:53` redirect and the explicit `--dns-upstream` and `--dns-servers` options are recorded as existing behavior outside this guard; the test asserts that the DoH profile does not use, widen, or fall back to them, and does not assert that they are absent. The design still records Q1 to Q5, the product-owner decision, and the invariant amendment as absent until they exist | A real release |
| T16.11 | Late ECH outcome | Deliver `AttemptOutcome` after the job was terminal and after the session slot was reused | The late outcome is discarded by job ID and attempt ID. It does not move `ech_ok`, `ech_rejected`, or the gauge. The new session's attempt is unaffected | A real provider |
| T16.12 | Queue-full versus cancel | Fill `G`, then cancel a queued TCP:53 frame at the same time as a worker releases a slot | Exactly one terminal outcome is recorded for that query: either the grant becomes a job and later one outcome, or the cancel records `doh_cancelled`. The query is never both rejected and admitted | A real scheduler |
| T16.13 | Adapter ordering race | Deliver dispositions for requests 2, 0, 1 on one connection in that arrival order, with request 1 a `Close`, while the inner client is slow to read | The adapter writes 0, then applies 1's close: it stops reading, writes 2, then sends FIN. It never writes 2 before 0. The reorder buffer never exceeds four entries. Each query keeps its own outcome | A real local client |
| T16.14 | Config fetch cancel versus commit race | Deliver the fetch completion and the fetcher's inner flow expiry in the same shard loop, in both orders | Exactly one of: the commit publishes `Fresh` (and the later expiry finds the job terminal), or the cancel moves the cache to `Absent` and wakes the shards (and the late completion publishes nothing). `doh_ok` plus `doh_failed` moves exactly once for the fetch. At most one new fetcher is elected | A real resolver |
