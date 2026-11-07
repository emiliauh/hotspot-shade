> Superseded. This is revision 1, kept for audit. Its DNS-only definition of
> `hide` was rejected by review and is not the current design. See
> `WS1_TARGET_ECH_DOH_ARCHITECTURE.md` (revision 2) and
> `WS1_REVIEW_TRACE.md`.

# WS1 research: target-side ECH and encrypted DNS without terminating application TLS

Status: UNAPPROVED research note for WS1 of `docs/SNI_HIDING_PLAN.md`. An
independent review found that its proposed DNS-only definition of `hide` does
not meet the requested application ECH requirement. Do not implement it as
`hide` or advertise that mode as supported. The review also found DNS bypass,
resource exhaustion, parser, retry, and privacy-record gaps. The proposals and
claims below remain historical research until a revised design is reviewed.
This note changes no production file, manifest, workflow, route, or interface.

Scope: target devices only (macOS, Windows, Linux). The source device app is
out of scope. `cover` and `terminate` are out of scope. No dependency was
added. No network test was run.

## 1. The question, restated precisely

The plan calls mode `hide` "Encrypted Client Hello and encrypted DNS in the
target engine". That phrasing hides two different claims:

1. The carrier cannot read DNS names.
2. The carrier cannot read TLS server names (SNI).

Claim 1 is a property of the transport that carries DNS. The engine can own
that transport. Claim 2 is a property of the TLS client that originates each
application connection. For relayed application traffic the engine is not that
client. It never holds the key schedule, so it cannot put ECH in an
application's ClientHello. No amount of wrapping, buffering, or re-framing
changes that: ECH encrypts a ClientHello under the server's ECH public key
inside the client that builds the ClientHello.

So the architecture question is not "how do we add ECH to the relay". It is:

- which TLS connections does the engine originate, and
- what can it do for the ones it does not originate?

This note answers both and fixes the vocabulary so the UI and docs cannot drift
back into the over-claim.

## 2. Who is the TLS client: five classes of traffic

| Class | Flow | Who originates TLS | What the engine holds | What it may do |
|---|---|---|---|---|
| A | Engine-owned HTTPS: DoH query transport, ECHConfig fetch | Engine (rustls) | Full handshake, keys, SNI, ALPN, cert chain | ECH, SNI policy, TLS 1.3 pin, no resumption, cert validation, total deadline |
| B | Relayed application TCP through the tunnel (`tun` mode) | The application | Opaque byte stream | Copy bytes. Optionally re-frame (WS2 `shape`). Optionally observe "ECH extension present" as a boolean. Never rewrite |
| C | Application through the local SOCKS5 listener | The application | Opaque byte stream after name resolution | Same as B. The engine may resolve an ATYP 3 name, then dials a numeric address |
| D | Source device app: pairing, proxy, echo | Source device app | Nothing | Out of WS1 |
| E | Engine control plane: GUI HTTP on 127.0.0.1 | None (plain HTTP on loopback) | Full | No TLS. Not affected by this work |

Only class A can carry ECH. Classes B and C cannot, and the engine must not
pretend otherwise in code, counters, or UI text.

The same split applies to destination identity:

- Class A destination: a validated origin name. The configured DoH name is
  checked against the server certificate by rustls-webpki. The address is a
  configured literal, never a `getaddrinfo` result. The name is the ECH inner
  name. This is the only place where a name is trusted.
- Classes B and C destination: a numeric IP. A relayed ClientHello may contain
  an SNI string, but the engine cannot validate it, cannot bind it to the IP,
  and must not use it for policy, ECH selection, counters with names, logs,
  status, or diagnostics. CDN IPs are shared, CNAME chains vary per resolver,
  and the app may have used its own resolver. The IP to name map in
  `failures.rs` is a failure hint, not an identity, and must not be promoted
  into one.

This distinction has to be visible in the type system, not just in comments.
The DoH module takes `DohEndpoint { name: DnsName, ip: IpAddr, port, path }`.
The relay passes only `IpAddr` and never the SNI. There is no function that
takes both.

## 3. Why wrapping the existing byte stream does not work

Four candidate designs were examined.

| Candidate | Verdict | Reason |
|---|---|---|
| Wrap the app's TCP stream in a second TLS session | Impossible | The origin server expects a ClientHello, not TLS records. This is TLS-in-TLS to the same endpoint and the handshake fails. It also adds the nested-handshake fingerprint the plan wants to avoid |
| Rewrite the ClientHello SNI in the relay | Impossible | The ClientHello is covered by the transcript hash (RFC 8446 section 4.4.1). One changed byte breaks the server `Finished`, independent of certificates. The plan already states this. The plan cites section 4.4.4, which is `Finished`; the transcript hash is 4.4.1 |
| Splice an ECH extension into the app's ClientHello | Impossible | ECH requires HPKE to the server's ECH public key using a key schedule the client owns, plus a matching inner transcript. A relay has neither |
| Terminate the app's TLS, then re-originate with ECH | Excluded by scope | Needs a target-trusted CA, breaks certificate pinning, changes the TLS client identity, and is the `terminate` mode this task rules out |

Wrapping does work in one place: class A. There, rustls owns the handshake,
and `StreamOwned` can wrap the byte stream from `normalization::tcp_start` or
`normalization::tcp_connect` without replacing the normalized socket. That is
exactly the pattern `experiments/tls-transport-spike` already proves on
loopback: TLS 1.3 only, no resumption, one connection per flow, total
handshake deadline, byte-exact relay. The spike's provider is `ring`, which
cannot do ECH, and its no-SNI trick (`src/transport.rs`, IP server name) is for
a pinned private hop. That trick must not be copied to the public DoH hop: a
public server needs SNI to select a certificate.

Consequence: "wrap the stream" is the right mechanism for the engine's own
HTTPS, and the wrong mechanism for every other flow.

## 4. What `hide` means after this analysis

Keep the mode name for schema parity. Define it as:

> `hide` encrypts the DNS transport for every tunneled query and uses ECH on
> the engine's own encrypted-DNS connection where the resolver publishes an ECH
> configuration. It does not change the TLS server name of any application
> connection.

WS0 has already landed the shared schema, so use it rather than inventing a
second vocabulary:

- `diagnostics::DESTINATION_PRIVACY_MODES` is `["off", "shape", "hide",
  "cover"]`. Do not add a fifth engine mode for "encrypted DNS only". That is
  what `hide` means now.
- `destination_privacy_capability()` reports `modes.hide`, `ech`, and
  `sni_override`. When this work lands, `modes.hide` becomes `supported` only
  if the code path and its hermetic tests exist. `ech` becomes `supported` only
  in a build with an HPKE provider, and its detail text must say "for the
  engine's encrypted-DNS connection". `sni_override` stays `unsupported`: the
  engine still overrides no application SNI, and that is the honest part of the
  whole design.
- `zero_destination_privacy_counters()` already names the counters an
  implementation is expected to fill: `flows`, `shaped_flows`,
  `shaped_errors`, `ech_attempts`, `ech_ok`, `ech_grease`, `ech_rejected`,
  `ech_fallback`, `doh_lookups`, `doh_ok`, `doh_failed`, `cover_flows`,
  `cover_errors`. WS1 fills only the `ech_*` and `doh_*` keys. It must not
  reuse `ech_attempts` for observed application handshakes; that would merge
  two different claims into one number.

What `hide` then actually delivers:

| Object | Before | With `hide` |
|---|---|---|
| DNS QNAME and query payload on the carrier path | visible in plaintext DNS to 1.1.1.1:53 (source proxy) or to the original resolver (direct) | inside TLS to the configured DoH resolver |
| DoH resolver name (SNI) | n/a | visible, or hidden behind the ECH public name when ECH is accepted |
| Application SNI | visible | visible. Unchanged |
| Destination IP and ASN | visible | visible |
| JA3/JA4, flow shape, timing | visible | visible |
| Whether an app used ECH | visible | visible. Optionally counted as a boolean |

The headline that follows is "DNS names hidden from the carrier", not "SNI
hidden". The second is only true for the engine's own resolver connection, and
that name is a static resolver name.

The plan's acceptance criterion "`hide` succeeds on a Cloudflare ECH origin,
falls back to GREASE on a non-ECH origin" cannot be met for application
traffic. It can be met for the engine's DoH origin only. The criterion needs
rewording in WS6; otherwise it will be "verified" by testing the engine's DoH
connection and then read as a claim about browsing.

## 5. DoH design

### 5.1 Endpoint configuration and bootstrap

The endpoint is a four-tuple: name, IP literal, port, path. Example:
`cloudflare-dns.com`, `1.1.1.1`, `443`, `/dns-query`.

- The name is the TLS ServerName and the ECH inner name. It must be a valid
  DNS name, not an IP literal, because ECH rejects IP public names and webpki
  needs a DNS reference identity.
- The IP is the transport address. Configuring it removes the resolver
  bootstrap loop and keeps `getaddrinfo` off the egress path (invariant 4).
  RFC 8484 section 10 explicitly lists an IP-based URI plus HTTPS
  authentication as a valid bootstrap strategy.
- The path comes from the configuration. RFC 8484 section 3 forbids using a
  different URI discovered outside the configuration, so redirects are not
  followed and a 3xx is a failure.
- The DoH resolver's own HTTPS RR may later refresh the IP from `ipv4hint`.
  That is an optimization, not part of the first implementation.

This also answers the trust question: DoH moves trust from "every network on
the path" to "the configured resolver". A hostile resolver already sees every
query. The design must say that plainly.

Trust anchors: use `webpki-roots` so the egress path never calls an OS trust
API. That excludes a corporate or self-hosted resolver behind a private CA.
Support for that case is out of scope for the first version. If it is added
later, it must be an explicit SPKI pin for a configured endpoint, never a
"disable verification" switch, and the pin path needs its own tests.

The configured endpoint is not a secret, but it must not be echoed by
`/api/status`, diagnostics, or logs. Report a boolean and counters only.

### 5.2 HTTP version: HTTP/1.1, not HTTP/2

RFC 8484 section 5.2 says HTTP/2 is "the minimum RECOMMENDED version", not a
requirement, and notes that earlier HTTP versions can convey the semantics.
DoH servers must implement POST and GET and must accept and produce
`application/dns-message`.

The engine has no async runtime. It is a thread-per-flow, poll-driven design.
Adopting `hickory-resolver` would bring an async resolver built on `tokio`,
`futures-util`, `moka`, `parking_lot`, `hickory-net`, `hickory-proto`, and, for
DoH, an HTTP/2 stack (its own feature list pairs `https-ring` or
`https-aws-lc-rs` with HTTP/2). That is a large tree and a second concurrency
model for one POST per query. `h2` alone is a large protocol implementation.
Recommendation: a minimal HTTP/1.1 client over rustls, with ALPN
`http/1.1` required so a server cannot silently select a protocol we cannot
speak.

The client must handle: a bounded header block, `Content-Length`, chunked
transfer encoding, `Connection: close`, a bounded body (65535 plus framing),
and `Content-Type` checking. It must reject any `Content-Encoding` other than
identity, reject a redirect, and reject a non-2xx status without retrying
another server.

Cache friendliness: RFC 8484 says a client SHOULD use DNS ID 0 so equivalent
queries are cacheable. The engine is a forwarder, not a resolver, and the inner
client may check that its transaction ID and QNAME case are echoed. Rewriting
the ID would be safe (the engine could renumber and restore), but rewriting or
re-casing the question is not. Recommendation: forward the query bytes
unchanged. DoH over HTTP correlates request and response anyway, and the ID is
not a privacy leak inside TLS. Record the deviation from the SHOULD.

### 5.3 One inner flow, one outer socket

The invariant is not negotiable, and DoH can satisfy it exactly:

- One inner DNS 4-tuple (client IP, client port, resolver IP, 53) is one inner
  flow. Today that flow already maps to one source device SOCKS stream. Keep
  it: one DoH TLS connection per inner DNS flow.
- A stub resolver normally uses one UDP socket per process, so this is a
  handful of connections per session, each long lived and reused for every
  query on that socket.
- Pipelining multiple queries on one HTTP/1.1 connection is possible but
  responses are ordered. Process queries FIFO on that connection. A slow query
  delays the next one on the same inner flow only. That is acceptable and
  bounded.
- A shared DoH connection for all inner DNS flows would aggregate unrelated
  flows into one outer connection. That is the many-to-one shape invariant 3
  forbids. Do not do it "for performance".

Cost: one TLS handshake per inner DNS flow. In source proxy mode that is also
one SOCKS CONNECT through the source device. Measure it; do not assume it is
free.

### 5.4 DNS message handling

The engine is a forwarder, not a resolver. It must not parse, re-encode, or
cache answers. In particular:

- Forward the entire DNS message, including EDNS(0) OPT, the DO bit, cookies,
  padding, and unknown options. Do not strip or synthesize.
- Do not filter by QTYPE. Type 65 (HTTPS) and type 64 (SVCB) must pass. This is
  the only way an app that uses the system resolver can learn an ECH
  configuration. A DoH path that only answers A and AAAA would quietly break
  app-level ECH.
- Do not rewrite the QNAME, its case (0x20 encoding), or the transaction ID.
- Return the response bytes unchanged. The engine is not a DNSSEC validator
  and must not claim to be. Pass the AD bit and any DNSSEC records through.

Response size is the one place the forwarder must act:

- Read the inner query's EDNS UDP payload size. Default to 512 when absent.
- Cap the inner response at the smaller of that value and the inner datagram
  limit. The relay currently caps UDP at `MAX_DATAGRAM` 1472 and drops larger
  answers (`relay.rs:3187`).
- If the answer does not fit, return a proper truncated response: the header
  with TC set and the question section only. Never return a partial answer and
  never silently drop.
- The client then retries over TCP:53. That retry must not leak.

### 5.5 TCP:53 must be covered

Today only UDP:53 is redirected (`relay.rs:2502-2509`); TCP:53 goes through the
normal TCP path to the real resolver in plaintext. Large answers, DNSSEC, and
any TC retry therefore bypass DoH. Claiming "DNS names are private" while
TCP:53 is plaintext would be false.

Two ways to cover it:

1. A new outer variant. Add a `TcpOuter` enum to `TcpEntry` and feed the inner
   TCP endpoint from the DoH service. Clean conceptually, but it touches the
   inner TCP pump, the FIN/abort paths, and the close records.
2. A loopback adapter. For an inner SYN to port 53 with DoH enabled, connect
   `entry.stream` to a loopback listener owned by the DoH module. The adapter
   speaks the 2-byte length framing of DNS over TCP and answers each message
   through DoH. The inner TCP endpoint, windowing, FIN, and abort logic are
   unchanged.

Recommendation: option 2 for the first implementation. It is small, it reuses
all the proven inner TCP behavior, and it is testable with a loopback listener.
The adapter socket is the only unpinned outer socket in the data path and must
be documented as such: it connects to `127.0.0.1`, so it cannot leave the
machine. It still goes through `normalization::tcp_start` with
`iface = None`, so the TTL audit still counts it and `ttl_bad` stays 0. State
this exception in `AGENTS.md` when the feature lands, rather than letting a
reader infer that pinning was dropped.

### 5.6 Failure, fallback, and the hidden object

Define the hidden object per layer. A fallback is safe if and only if it does
not expose the object that was hidden.

| Layer | Hidden object | Fallback to | Safe? |
|---|---|---|---|
| L1 | DNS QNAME and payload | plaintext DNS to any resolver | No. This is the whole feature. Must be explicit and off by default |
| L2 | DoH resolver name (SNI) | TLS without ECH to the same DoH endpoint | Yes. The name is static and already implied by the IP. The query payload stays encrypted |
| L3 | Application SNI | none exists | Not provided, so no fallback question |

Therefore:

- DoH transport failure is a DNS failure by default. The inner client gets no
  answer or a SERVFAIL consistent with the resolver's own failure, and a
  counter records it. The UI says "Secured DNS is unavailable on this
  network."
- A per-network-profile option may allow plaintext DNS. When it is active the
  UI must say "DNS is not private" for as long as it is active. No silent
  fallback, ever.
- ECH rejection is handled inside L2. RFC 9849 section 6.1.6: authenticate for
  the public name, abort before any application data with `ech_required`, and
  retry on a new transport connection, using `retry_configs` if the server sent
  them, otherwise with ECH disabled. rustls implements exactly this: the
  handshake fails with `ServerRejectedEncryptedClientHello(retry_configs)` and
  the client sends the alert. A retry always opens a new outer socket, so the
  one-flow-one-socket rule still holds and there is no in-connection downgrade.
- Never accept an ECH configuration from anywhere except the DoH response
  (the trust anchor) or authenticated `retry_configs`.

## 6. ECH design

### 6.1 What rustls 0.23.46 provides (verified in the crate source and docs)

- `rustls::client::EchConfig::new(EchConfigListBytes, &[&'static dyn Hpke])`
  selects a compatible config from the list in the HTTPS RR `ech` parameter.
- `EchMode::{Enable(EchConfig), Grease(EchGreaseConfig)}` and
  `ConfigBuilder::with_ech(...)` at `ClientConfig` build time. The docs warn
  that such a config must only be shared by connections to the name that
  published that config.
- `EchStatus::{NotOffered, Grease, Offered, Accepted, Rejected}`.
- Rejection path: the client authenticates for `public_name`, sends the
  `ech_required` alert, and returns
  `PeerIncompatible::ServerRejectedEncryptedClientHello(retry_configs)`.
- GREASE uses a placeholder HPKE key and a random-looking payload of the right
  size; it is ignored by servers and negotiates nothing.
- ECH needs an HPKE provider. `EchConfig::new` takes `&dyn Hpke`; the trait
  lives in `rustls::crypto::hpke`. The `ring` provider has no HPKE, so ECH
  cannot be constructed with it. This matches the plan.

### 6.2 Where the ECHConfig comes from

RFC 9848 defines SvcParamKey 5, `ech`, in the HTTPS or SVCB RR. Its wire value
is an ECHConfigList with the redundant length prefix. RFC 9848 section 5.1 also
requires that an ECH-capable SVCB-optional client becomes SVCB-reliant when all
alternative endpoints publish `ech`, because falling back to a non-ECH endpoint
would negate the privacy benefit.

Implementation: after the first successful plain DoH exchange to the endpoint,
query the endpoint's own HTTPS RR (QTYPE 65) through that same connection. Parse
the answer for SvcParam 5 and cache the raw ECHConfigList with the RR TTL. The
first connection is necessarily non-ECH; that is the bootstrap, not a
downgrade, because the query payload is already encrypted.

Parsing needs: DNS name decompression (already present in `failures.rs`), RR
type 65, and SvcParams as `(u16 key, u16 len, bytes)` in strictly increasing
key order. Base64 is only needed for presentation format; the wire value is
raw. Do not add a base64 crate for that; a 40-line decoder with RFC 4648 vectors
is enough if a presentation format is ever needed for a CLI. Reject: unknown
mandatory extension, duplicate extension, unsupported KEM, empty list, list
larger than a bound. `EchConfig::new` already rejects most of these; the cache
must not store a rejected list.

### 6.3 GREASE

The plan asks for GREASE when no config exists so ECH-capable and non-capable
destinations look alike. That rationale is about destinations in general and it
does not hold here: the engine has exactly one engine-originated destination,
the DoH resolver. GREASE there hides nothing and only adds bytes.

Recommendation: keep `EchMode::Grease` available behind a sub-option, default
off, and never use its presence as a claim. If a future version of this feature
originates more connections, revisit.

### 6.4 What ECH on the DoH connection is worth

Little, on its own. The DoH resolver's name is static and its IP is already
visible; ECH only hides that one name behind a public name that usually belongs
to the same provider, and on a blocking network the static IP or the public
name is the tell. Its value is:

- it is a real, standards-correct ECH code path with tests, so the project can
  say "ECH is implemented and used for the engine's own resolver connection"
  without qualification;
- it keeps the engine's resolver traffic from carrying an extra plaintext name
  once the network starts treating static resolver names as a signal.

It is not the privacy win. DoH is. Say so.

## 7. Application ECH: what is possible, and what is a false claim

The engine cannot add ECH to an application's handshake. What it can do:

1. **Encrypt the DNS path** so the resolver name and the query are not visible.
   This is independent of ECH and helps every app that uses the system
   resolver.
2. **Preserve the records an ECH-capable app needs.** HTTPS and SVCB RRs must
   pass unchanged through the DoH forwarder. This is a "do not break it"
   requirement, not a feature.
3. **Report honestly.** `probe` and status must distinguish:
   - the `hide` mode row: `supported` only when the DoH path exists in this
     build
   - `ech`: `supported` only when the build has an HPKE provider, with detail
     text that scopes it to the engine's resolver connection
   - `sni_override`: `unsupported`, always, because application SNI is never
     overridden
   - application ECH: `app-dependent`. If a field is added, it must be named
     for what it measures (observed in relayed traffic), never as a capability
     the engine provides

4. **Optionally measure ECH in relayed traffic.** A bounded, passive
   ClientHello parser on relayed TCP:443 flows can set one boolean per flow:
   did the first ClientHello carry extension 0xfe0d. It must never record the
   SNI or any name, must not delay forwarding, and must give up after a fixed
   byte budget and report "unknown". This turns "ECH in use" from a marketing
   claim into a counter. It is optional and belongs in phase 2.

What is impossible or dishonest, and must not be built:

- **Injecting an `ech` SvcParam into DNS answers.** The ECH private key belongs
  to the origin's client-facing server. A config injected by the engine would
  name a public key the origin does not hold, so the handshake fails. It is not
  a policy choice; it cannot work.
- **Claiming per-site ECH coverage.** Whether a site uses ECH is a decision by
  the app and the origin. The project can measure, not provide.
- **Reusing the engine's ECH for app flows.** There is no interface by which an
  application can borrow another process's TLS session.
- **Client-side local resolution under the label of privacy.** Resolving before
  the tunnel is still a documented leak. DoH does not fix it.

One more honest limit: a browser that uses its own DoH (Firefox with DoH,
Chrome with secure DNS) does not use the engine's DoH at all. Such a browser
may already do ECH on its own, with its own resolver and its own policy. The
engine neither helps nor hurts. State that in the UI scope text instead of
implying the toggle covers every app.

## 8. Concrete seams

Line numbers are from the current tree and will move.

| Work | Where | Note |
|---|---|---|
| DoH client, HTTP/1.1 framing, DNS passthrough | new `rust/src/doh.rs` | Blocking, own thread, bounded queue |
| rustls client construction, `StreamOwned`, deadline | new `rust/src/tls_client.rs` | TLS 1.3 only, ALPN `http/1.1`, no resumption, injected roots for tests |
| HTTPS RR `ech` parser, ECH cache, retry policy | new `rust/src/ech.rs` | Cache keyed by name, TTL bounded, no names in output |
| Relay-facing service: per-inner-flow sessions, pending query table, counters | new `rust/src/dns_privacy.rs` or inside `doh.rs` | Must not block the worker |
| UDP:53 interception | `relay.rs` `new_udp` (`:2495`), DNS target at `:2502-2509`, send at `:2313-2325`, reply read at `:3160-3210` | Replace the `1.1.1.1:53` source-device target when DoH is on |
| TCP:53 interception | `relay.rs` `handle` SYN branch (`:2147-2200`) | Loopback adapter or a new outer variant |
| Outer socket creation | `normalization.rs` `tcp_start` (`:184`), `tcp_connect_cancellable` (`:207`) | No new socket helper; DoH calls these |
| Source device transport | `relay.rs` `Setup::phone` (`:1202`), `phone_tcp_start` (`:121`) | The DoH path needs a blocking variant of the SOCKS setup for its own thread |
| Config | `service.rs` `TunOptions` (`:106`) and validation (`:139`); `relay.rs` `RelayConfig` (`:144`) | Phone mode currently rejects `dns_upstream` (`:152-165`); add the DoH field and its own validation |
| CLI | `main.rs` `tun` option list (`:1137`) | Add `--doh`, `--ech`, `--allow-plaintext-dns` |
| GUI/service schema | `gui_backend.rs` start parse (`:2115`), `service.rs` status (`:1973`) | WS0 owns the shape; WS1 only fills it |
| Counters | `relay.rs` `Counters` (`:318`), `RelayStats` (`:178`), `diagnostics.rs` `empty()` | Same seven-step path as every other field |
| Docs and claims | `README.md` destination privacy, `docs/TECHNICAL_REFERENCE.md` | Both already say `hide` is engine-originated only; keep that wording |

Conflict to manage: WS2 also edits `relay.rs` (the ClientHello shaping in the
TCP data path). WS1 edits the UDP DNS path, the SYN branch, and `new_udp`. The
plan's "exclusive file scopes" cannot be literal for `relay.rs`. Sequence WS1
first, or land WS1 as one self-contained `DnsPrivacy` field plus three small
call sites, so WS2 rebases cleanly.

A second conflict: the source proxy transport for the DoH connection. In
`tun --phone` mode the DoH outer socket must be dialed through the source
device, because the target has no other path. `Setup` is a nonblocking state
machine driven by the worker poll loop. The DoH thread cannot drive it without
either duplicating the handshake or refactoring `Setup` into a reusable type
with a blocking completion helper. Prefer the refactor: one implementation of
the SOCKS request and reply parsing, two drivers. Duplicating the SOCKS wire
format in a second module is how the two copies drift.

## 9. Dependencies and build constraints

Proposed additions, all optional behind one feature:

| Crate | Why | Notes |
|---|---|---|
| `rustls` 0.23.46 | TLS 1.3 client, ECH | `default-features = false`, features `std` and `aws_lc_rs`. `tls12` stays off. No `logging` |
| `aws-lc-rs` (through rustls) | HPKE for ECH | C and assembly build. Needs a C toolchain; cmake; on Windows x86_64, NASM. Must be proven per target in native CI |
| `webpki-roots` | Public trust anchors for the DoH server | Data-only crate. No OS trust store call on the egress path |
| `rcgen` | Dev-dependency only, mock DoH server | Test-only |

Explicitly not adopted: `hickory-resolver` (async, tokio, HTTP/2, large tree),
`h2` (protocol implementation we do not need for one POST per query), and any
HTTP client crate with its own TLS stack.

Build constraint that must be settled before touching manifests: any rustls
provider builds C or assembly for the target. The documented macOS developer
commands cross-check Windows targets:

```
cargo check --target x86_64-pc-windows-msvc --all-targets --locked
cargo check --target i686-pc-windows-msvc --all-targets --locked
```

Those will very likely fail on macOS once the provider is a hard dependency,
because there is no MSVC C compiler for the target. That is a real regression
in the documented workflow, not a cosmetic one.

Recommendation: put the whole feature behind a non-default `dns-privacy`
feature. The base crate stays pure Rust, so the cross-target checks keep
working. Native CI jobs (macOS, Windows, Linux) add
`--features dns-privacy` to check, test, and clippy, and the release builds
enable it. Then add a documented rule: a build without the feature reports
`ech = unsupported` and `modes.hide = unsupported`, never silence.

This must be validated, not assumed. The following are unproven until a build
runs:

- `aws-lc-sys` builds for macOS arm64, Windows x64 and x86, and Linux x64 with
  the CI images as configured.
- The cross-target checks still pass with the feature off.
- `cargo check --features dns-privacy` still passes on iOS and Android
  cross-compiles, if the engine is ever built there. It is not today, but the
  workspace is checked with `--all-targets` on hosts only.

If `aws-lc-rs` cannot build on a shipping target, the fallback plan is: ship
DoH with a provider that builds, and report `ech = no` on the affected
platforms. Do not ship a hidden stub that claims ECH.

## 10. Invariant compliance

| Invariant | How this design keeps it |
|---|---|
| 1. Every outer socket through the normalized helpers | DoH calls `normalization::tcp_start` or `tcp_connect_cancellable`. The loopback adapter is the single documented unpinned exception and cannot leave the machine. `ttl_bad` stays 0 |
| 2. No external relay or VPS | The DoH resolver terminates the DNS connection. No new hop and no relay |
| 3. One inner 4-tuple, one outer socket | One DoH TLS connection per inner DNS flow. No shared DoH connection across flows |
| 4. No `getaddrinfo` on an egress path | The endpoint IP is configured. The ECH config is fetched through DoH. No name lookup anywhere in the DoH path |
| 5. Small dependencies | Three reviewed additions behind one feature, with a stated reason and a committed lockfile |
| 6. IPv6 policy explicit | DoH to an IPv4 endpoint works in both modes. DoH to an IPv6 endpoint is allowed only when the mode forwards IPv6. No policy change |
| 7. Route cleanup on every exit | DoH threads are owned by the relay and joined on stop and drop. Sessions close their outer sockets. No route or device is created by this feature |
| 8. Platform boundary | The DoH module is portable. Only socket helpers and the existing platform gates remain platform-specific |
| 9. Privacy of logs and status | No QNAME, DoH name, ECH config, or SNI enters a log, counter label, status, diagnostics, or failure record. Only counts |
| 10. Everything opt-in and labeled | `hide` is a per-profile opt-in. Capability flags are always printed. The plaintext fallback, if enabled at all, is labeled while active |

A subtle invariant interaction to record: the DoH connection is itself an outer
flow that the carrier can see. In direct mode it is pinned to the hotspot
interface and carries TTL 65 like every other outer socket, so it gets the same
one-decrement treatment. In source proxy mode it is a normal SOCKS CONNECT
through the source device, so it uses the source device's TCP stack and TTL
policy like any other relayed destination. No special case is needed, and none
should be added.

## 11. Hermetic test plan

All tests use loopback, fixed vectors, a mock tun device, and a mock source
device. No route, no TUN device, no interface, no root, no phone.

### 11.1 DoH client against a mock server

A loopback rustls server with a test certificate for `doh.test`, an injected
root store, and an HTTP/1.1 responder that decodes `application/dns-message`.

| Test | Claim |
|---|---|
| Basic exchange | The request is a POST to the configured path with the right media types and length, and the response bytes are returned unchanged |
| Query bytes | The DNS message is byte-identical: ID, QNAME case, EDNS OPT, DO bit, unknown options |
| QTYPE passthrough | Type 65 and type 64 are forwarded; an unknown type is forwarded, not rejected |
| Keep-alive | Two queries on one inner flow use one TLS connection and one outer socket |
| Two flows | Two inner flows produce two outer connections and two connections at the server |
| Chunked response | A chunked body is decoded correctly and bounded |
| Oversized body | A body above the bound is rejected without unbounded allocation |
| Non-2xx | A 400 or 500 fails the query and is counted, with no retry to another server |
| Redirect | A 302 is refused, not followed |
| Wrong content type | A 200 with a non-DNS media type fails the query |
| Content-Encoding | A gzip response is refused because it was not requested |
| Drip and stall | A slow header or body fails at the total deadline, not at a per-read timeout |
| TTL audit | Every outer socket reports TTL 65 and the audit snapshot ends at `(n, 0)` |

### 11.2 End-to-end through the relay

Use the existing mock tun device and `mock_phone` helper (`relay.rs` tests).

| Test | Claim |
|---|---|
| Inner UDP:53 to DoH, source proxy mode | The mock source device receives a CONNECT to the configured DoH IP:443, never to `1.1.1.1:53`, and the inner client receives the exact answer |
| Inner UDP:53 to DoH, direct mode | The normalized outer socket reaches the loopback mock server with TTL 65 |
| Truncation | A large answer produces TC=1 with the question only, and the client's TCP:53 retry is answered by the adapter |
| TCP:53 | A 2-byte length framed query is answered through DoH, the inner stream closes with FIN, and one outer DoH connection is used |
| DoH failure | With the mock server refusing, the inner query gets no plaintext answer and the failure counter moves. Assert that no packet reaches the old plaintext path |
| Explicit plaintext fallback | With the option on, the query goes to the plaintext path and a status flag reports that DNS is not private |
| Stop and drop | Stopping the relay closes DoH sessions and joins their threads; a second stop is a no-op |
| No secrets in output | The full status, diagnostics, failures, and probe JSON do not contain the DoH name, path, QNAMEs, or ECH bytes |

### 11.3 ECH

| Test | Claim |
|---|---|
| Config parse | Fixed ECHConfigList vectors parse; malformed, duplicated mandatory extension, unknown KEM, and empty list are rejected and not cached |
| Cache | TTL expiry, bound, replacement on retry |
| Emission | The first ClientHello contains extension 0xfe0d; the outer SNI equals the config `public_name`; the real name does not appear anywhere in the ClientHello bytes |
| Rejection | Against a plain rustls server that ignores ECH, the client aborts with the ECH error, sends no application data, and the mock server sees no HTTP request |
| Retry | A rejection produces a second outer connection and a successful exchange without ECH |
| Retry configs | The retry policy accepts authenticated retry configs, uses them for exactly one retried connection, and does not loop |
| GREASE | With GREASE on, the extension is present, the real name is absent, and the server completes normally |
| Second rejection | A rejected retry does not loop and does not silently downgrade inside the same connection |

Limit: no hermetic test can complete an ECH-accepted handshake. rustls does not
implement the server side of ECH, and a mock would have to implement ECH server
processing and drive TLS from a decrypted inner ClientHello. So "the server
accepted ECH" is not provable on the host. The emission test proves the privacy
property that matters (the real name is not on the wire); the acceptance path
needs a live test against a real ECH provider. Say that in the test file header.

### 11.4 What these tests do not prove

- That a real DoH provider accepts HTTP/1.1 POST with the exact header set.
- That a real provider publishes `ech` for the configured name, or accepts the
  ECH offer.
- That the carrier does not block the DoH IP, port, or name.
- That an app's own ECH works with the engine's DNS path.
- That the per-flow handshake cost is acceptable on a phone-tethered link.
- Anything about iOS or Android source devices.

## 12. Proven, hypothesized, needs a live network

### Proven by code or standards read

- The engine has no TLS client today. Every application TLS flow is a byte
  relay (`normalization.rs`, `relay.rs`, `socks.rs`, `phone.rs`).
- Source proxy TCP setup carries a numeric IP only (`Setup::phone` takes
  `IpAddr`; `relay.rs:1202`).
- Source proxy DNS is plaintext to `1.1.1.1:53` on a per-flow source device
  stream with a transaction ID check (`relay.rs:2502-2509`, `:3160-3210`).
- Direct mode sends inner UDP:53 to the original destination or
  `--dns-upstream` in plaintext (`TECHNICAL_REFERENCE.md`, DNS behavior).
- TCP:53 is not redirected today. A DoH claim without it would be false.
- rustls 0.23.46 has the client ECH API, `EchStatus`, the `ech_required`
  rejection path with retry configs, and GREASE (crate source read). ECH needs
  an HPKE provider; `ring` has none.
- RFC 8484 allows HTTP/1.1 (HTTP/2 is recommended, not required), requires POST
  and GET, forbids using an unconfigured URI, and defines the media type.
- RFC 9848 defines SvcParamKey 5 `ech` and the SVCB-reliant rule.
- RFC 9849 section 6.1.6 defines the rejection and retry behavior, including
  the safe "retry with ECH disabled" case after the server securely disables
  ECH.
- The in-tree TLS spike proves the rustls wrapping pattern, the total deadline,
  TLS 1.3-only, no-resumption, and byte-exact loopback relay.
- The repo already has hermetic mock tun, mock source device, and loopback
  relay tests, so a full DoH end-to-end test is achievable.

### Hypothesized, needs a build or a test to confirm

- `aws-lc-sys` builds on every shipping target and CI image, and the
  cross-target Windows checks still pass with the feature off.
- Real DoH providers accept the same HTTP/1.1 request shape, including chunked
  responses and keep-alive.
- One TLS connection per inner DNS flow is affordable in latency and battery.
- A loopback TCP:53 adapter does not disturb the inner TCP close and abort
  paths in practice, not just in the unit tests.
- webpki-roots contains the needed anchors for the chosen resolver for the
  supported lifetime of each release.

### Needs a carrier and a real device

- Whether DoH to the configured IP and port is reachable on a given carrier.
- Whether the ECH public name or the DoH IP is blocked, and how the failure
  looks to the person.
- Whether a real ECH provider accepts the engine's offer and whether the retry
  path works across real resolver nodes (config rotation, multiple anycast
  nodes with different configs).
- Whether common browsers on the target actually use the engine's DoH or their
  own, and whether their ECH works end to end.
- The real latency of a handshake per DNS flow on a hotspot link, and the
  effect on page load.
- Whether the carrier treats a static DoH connection as a signal. Measure flow
  counts and sizes; do not infer.

No carrier, hotspot, route, or interface test was run for this note.

## 13. Decisions resolved

1. `hide` is scoped to engine-originated TLS. The engine cannot add ECH to
   application TLS, and this note treats every design that needs it as out of
   scope.
2. The primary deliverable is DoH for all tunneled DNS, UDP:53 and TCP:53, not
   ECH. ECH is a secondary, honest capability on the DoH connection.
3. DoH uses HTTP/1.1 POST over TLS 1.3 on 443. No HTTP/2 dependency, no async
   runtime, no hickory.
4. The DoH endpoint is configured as name, IP literal, port, and path. No
   resolver bootstrap, no `getaddrinfo`.
5. One DoH TLS connection per inner DNS flow. No shared connection across
   flows, even for performance.
6. The DNS message is forwarded byte for byte. No answer caching, no record
   synthesis, no QTYPE filtering, no ID or case rewriting.
7. Response sizing honors the inner EDNS UDP size, caps at the inner datagram
   limit, and returns a proper TC response. TCP:53 is covered so truncation
   cannot leak.
8. DoH failure is a DNS failure by default. Plaintext fallback is explicit,
   per profile, off by default, and labeled while active.
9. ECH uses rustls plus aws-lc-rs HPKE, ECHConfig from the HTTPS RR `ech`
   parameter fetched through the same DoH endpoint, cached by TTL. On rejection
   it aborts with `ech_required` and retries once on a new outer socket, with
   retry configs if present, otherwise without ECH. That fallback is safe for
   L2 and never used for L1.
10. GREASE is optional, default off, and never used as a claim.
11. Application ECH is not provided. The engine encrypts DNS, preserves HTTPS
    and SVCB records, reports application ECH as app-dependent, and may count
    ECH extension presence per relayed flow as a boolean with no names.
12. The whole feature sits behind one non-default `dns-privacy` cargo feature
    so the documented cross-target checks keep working; native CI and release
    builds enable it; a build without it reports `hide = unsupported` and
    `ech = unsupported`.
13. The relay worker never blocks on TLS. DoH runs on its own thread with a
    bounded queue and a pollable reply path. The source device SOCKS setup is
    refactored into one reusable type with two drivers, not duplicated.

## 14. Open items for other workstreams

- WS0 owns the diagnostics and status shape. The landed keys are listed in
  section 4. WS1 fills `doh_lookups`, `doh_ok`, `doh_failed`, `ech_attempts`,
  `ech_ok`, `ech_grease`, `ech_rejected`, and `ech_fallback`, and moves `flows`
  for DNS flows only if WS0 defines that meaning. Two gaps remain for WS0:
  - no counter for a plaintext DNS fallback. Without one, the UI cannot prove
    that it is showing "not private" because the fallback really ran.
  - no counter for TCP:53 coverage and no counter for observed application
    ECH. If the optional ClientHello observation is built, it needs its own
    key, for example `app_ech_flows` and `app_ech_unknown`, so it can never be
    read as engine-originated ECH.

  Capability wording: `modes.hide` may become `supported`; `ech` may become
  `supported`; `sni_override` must stay `unsupported`. If a build has no HPKE
  provider, `ech` is `unsupported` even though DoH works, and the detail text
  must say the mode still encrypts DNS.
- WS5 owns the UI. The scope text must say DNS names, not "destinations", and
  must say apps decide their own ECH. The existing `TargetPrivacyFact` rows
  already separate `encryptedClientHello` from `serverNameOverride`; keep that
  split and put the "engine resolver connection only" scope in the ECH detail.
  The mode title "Hide the destination name" is now too broad for what `hide`
  does. Prefer "Hide DNS names from the carrier" or keep the title and make the
  detail say the TLS server name of applications is unchanged.
- WS6 owns the claim audit. `README.md` and `TECHNICAL_REFERENCE.md` already
  describe `hide` as engine-originated only; the plan text and the acceptance
  criteria are the parts that still over-claim.
- The plan's acceptance criterion "`hide` succeeds on a Cloudflare ECH origin"
  needs to become "the engine's DoH connection offers ECH when the resolver
  publishes a config, and the ECH test proves the real name is absent from the
  ClientHello".

## 15. What would make this design wrong

- If a shipping target cannot build an HPKE-capable TLS provider, ECH is
  unavailable there. The design still works with DoH; the capability must say
  so.
- If public DoH providers reject HTTP/1.1 in practice, the HTTP layer must grow
  to HTTP/2. That is a much larger dependency and would change decision 3. Test
  this against two independent providers before committing to H1.1.
- If one connection per inner DNS flow is too expensive on a real phone link,
  the tempting fix is a shared DoH connection. That would violate invariant 3.
  The correct fix is to keep per-flow connections and accept the cost, or to
  reduce the number of flows, not to multiplex.
- If TCP:53 interception proves too invasive, the honest move is to ship UDP
  only and label the feature "DNS over UDP:53 only, large answers may fall back
  to plaintext". Shipping it silently would be the false claim this work is
  meant to remove.
