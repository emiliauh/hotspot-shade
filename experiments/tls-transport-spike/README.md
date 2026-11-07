# TLS 1.3 transport spike

This directory is an isolated, test-only experiment. It asks one question: can
an established TLS implementation give the source device proxy authenticated,
encrypted transport with pinned identities, one connection per inner flow, and
no external relay?

It is not a product protocol. It is not wired into the engine, the GUI, or any
app. It has not had an independent cryptographic review. Do not present its
result as production security, and do not ship it without review.

The experiment uses rustls for TLS 1.3, rcgen to generate ephemeral test
certificates, and SHA-256 for pins. The crate has its own `Cargo.toml` and
`Cargo.lock`. Nothing in `rust/`, `gui_assets/`, or the platform apps depends on
it.

Pairing, pin distribution, pin storage, rotation, and recovery are out of scope.
This spike assumes each side already holds the correct pin. It does not design a
pairing protocol and it does not change the product's existing one.

## What the tests demonstrate

The suite has 44 tests. All run on loopback. They create no route, no tunnel
device, no phone connection, and no external socket. Each handshake has a 10
second total budget, and each socket read or write has a 10 second bound, so a
broken test fails instead of hanging.

| Test file | Tests | Claim |
|---|---|---|
| `tests/pinned_mtls.rs` | 4 | A Rust client accepts a pinned server key, presents a client certificate, and completes a byte-exact exchange over TLS 1.3. Both ends negotiate the spike ALPN. A whole-certificate pin also works. Two connections are independent full handshakes. The verifiers advertise only the tested signature policy. |
| `tests/rejection.rs` | 10 | Wrong server identity, wrong client identity, an anonymous client, cleartext to a TLS listener, a plaintext server, and a replayed application record are rejected. A certificate without the matching private key is rejected both by the configuration builder and, through a custom resolver, by CertificateVerify in each direction. |
| `tests/relay.rs` | 3 | A 256 KiB transfer and a 1 MiB chunked exchange are byte-exact. Eight simulated flows run at once, each on its own TCP connection, with no cross-flow mixing. These are not proxy relay tests: a handler echoes one TLS stream. |
| `tests/pins.rs` | 5 | rustls's certificate parser returns the same SPKI that the key pair produced. An SPKI pin survives certificate reissue. A certificate pin does not. Malformed length and truncated inputs produce no SPKI and do not panic. |
| `tests/resumption.rs` | 4 | The default config sends no tickets and never resumes. A deliberately resumable pair resumes on the second connection and skips both pin checks. Two crossed cases show that one side alone cannot resume: a ticket-sending server with a non-resuming client, and a ticket-accepting client with a non-ticket server, both stay full. |
| `tests/alpn.rs` | 6 | The library, not the test harness, enforces ALPN. A client with no ALPN extension and a client with only a different label are rejected before the server builds a connection. A server that selects no label is rejected by the client and by the server library. A server connection built directly still rejects the missing label after the handshake. The direct path also shows rustls's own `no_application_protocol` rejection for a non-overlapping list. |
| `tests/signature_policy.rs` | 4 | A signature scheme outside ECDSA P-256 with SHA-256 is rejected in each direction before the provider checks the signature. The pin check runs first. A real P-384 server key cannot negotiate under the P-256-only advertisement, and a real P-384 client identity cannot authenticate. |
| `tests/handshake_deadline.rs` | 4 | A silent client, a client that drips a ClientHello one byte at a time, and a silent server all fail at the total deadline, not at the per-read timeout. A normal loopback handshake finishes well inside the default budget. |
| `tests/crypto_policy.rs` | 4 | The ring provider enables exactly the three TLS 1.3 cipher suites, the three named key exchange groups, and a wider signature algorithm list than the spike policy. A loopback handshake selects TLS 1.3, AES-256-GCM, X25519, and the spike ALPN. |

Run them from this directory:

```sh
CARGO_TARGET_DIR=target cargo test --locked
```

Run clippy and the formatter check the same way:

```sh
CARGO_TARGET_DIR=target cargo clippy --locked --all-targets -- -D warnings
CARGO_TARGET_DIR=target cargo fmt --all --check
```

`cargo fmt` does not read the lockfile and takes no `--locked` flag. `target/`
is gitignored by the repository and is disposable. The committed tree holds
only source, tests, `Cargo.toml`, `Cargo.lock`, and this documentation.

## Observed result

On 2026-11-05, on macOS arm64 with rustc 1.99.1, `cargo test --locked` passed
all 44 tests in about 0.6 seconds of test time. The longest test file is the
handshake deadline test, at about 0.45 seconds. The run is a host test only. It
says nothing about iOS, Android, a real hotspot, or a carrier.

## Configuration

- TLS 1.3 only. The rustls `tls12` feature is disabled, and both configs are
  built with `version::TLS13`.
- The ring crypto provider. No custom cipher, key schedule, or record layer.
- ECDSA P-256 leaf certificates, self-signed for each test run.
- ALPN label `proxy`. It deliberately does not carry the product name or a
  version, but it is still a fixed, visible label and therefore a fingerprint.
  A production design must decide whether ALPN metadata is worth that. See
  "ALPN policy" below for where the label is enforced.
- The client passes `127.0.0.1` as its server name. rustls treats that as an IP
  address and sends no SNI extension. A product-specific host name would be
  another fingerprint, and the pin is the trust decision.
- Client authentication is mandatory. A client without a certificate fails.
- The verifiers advertise only `ECDSA_NISTP256_SHA256`, and they reject any
  other signature scheme before calling the provider's signature check. The ring
  provider supports more algorithms; this spike's policy does not.
- Session resumption is disabled by default on both ends, and the server sends
  no TLS 1.3 tickets. A resumed session can skip the certificate message and
  both pin checks. This spike authenticates every connection.

### Cipher suite and key exchange policy

The spike does not hand-pick a cipher suite or a key exchange group. Both ends
use the ring provider's default lists, so those lists are the policy. The
committed lockfile fixes the provider version the tests ran against. On that
version the enabled lists are:

| Kind | Enabled values | Notes |
|---|---|---|
| Cipher suites | `TLS13_AES_256_GCM_SHA384`, `TLS13_AES_128_GCM_SHA256`, `TLS13_CHACHA20_POLY1305_SHA256` | All three are TLS 1.3. No TLS 1.2 suite is compiled in. |
| Key exchange groups | `X25519`, `secp256r1`, `secp384r1` | All are elliptic-curve Diffie-Hellman groups. No post-quantum group is enabled. |
| Handshake signature schemes | `ECDSA_NISTP256_SHA256` only | This is the spike policy. The provider itself supports ECDSA over P-256 and P-384, Ed25519, and RSA PSS and PKCS#1. |

Negotiation is not pinned to one suite or one group. The client offers all
three cipher suites and its preferred group first. A loopback handshake selects
`TLS13_AES_256_GCM_SHA384` and `X25519` on the tested provider. A production
policy would need to decide whether to narrow the suite and group lists, and
would need a test for each allowed value. This spike does not claim that one
suite or group is required.

Certificate signature algorithms are not checked by the pin verifiers. A pin
compares public key bytes and the handshake signature, not a certificate chain,
so the provider's certificate signature list is not part of the trust decision.
See "What a pin verifies, exactly".

### ALPN policy

The test harness no longer owns this policy. It lives in `src/transport.rs`:

- `accept_server` reads the ClientHello with the rustls `Acceptor` and requires
  the `proxy` label in the offered list before it builds a server connection. A
  client that sends no ALPN extension, or only other labels, is refused at this
  point.
- `handshake_server` and `handshake_client` then require the negotiated label
  to be exactly `proxy`. This catches a server that selects nothing, and it
  stays in force for a caller that builds a `ServerConnection` directly and
  skips `accept_server`.
- On the client side, rustls already rejects a server that selects a label the
  client did not offer, with an `illegal_parameter` alert. It accepts a server
  that selects nothing; the spike's post-handshake check rejects that case.

rustls's own behavior is narrower than "reject a mismatch":

- A client ALPN list that does not overlap the server list is rejected by
  rustls with a fatal `no_application_protocol` alert. The direct-path test
  shows this.
- A client that sends no ALPN extension is accepted by rustls, even when the
  server has ALPN configured. The spike's presence check is what rejects it.
- A server that selects no label is accepted by the rustls client. The spike's
  post-handshake check is what rejects it.

A missing label is refused by closing the connection; the spike does not build
a `no_application_protocol` alert itself for that case. A non-overlapping list
that reaches rustls gets the rustls alert.

### Handshake deadline

`IO_TIMEOUT` bounds one socket read or write. That is not enough: a peer that
drips one byte every few seconds keeps resetting the kernel timer, so
`complete_io` makes a little progress forever. `HandshakeDeadline` is one
absolute budget measured from the moment the deadline is created. Each loop
pass sets the socket timeout to the remaining budget and checks it again. When
the budget is gone, the handshake returns `io::ErrorKind::TimedOut` even if the
last read made progress.

`tests/handshake_deadline.rs` uses a 400 millisecond budget to show three
negative cases: a client that sends nothing, a client that sends the ClientHello
header and then one byte every 20 milliseconds, and a server that sends nothing.
Each fails at the total deadline. The slow-drip client is the case that a
per-read timeout cannot catch. A normal handshake uses the default 10 second
budget.

The slow-drip test drives the server's ClientHello read path. Both handshake
helpers then share one loop that checks the remaining budget after every read or
write, so a drip after the ClientHello is subject to the same rule. The stalled
server test covers that shared loop on the client side. A crafted drip of a
server flight into the client is not built here.

The budget belongs to the caller. The test harness creates one
`HandshakeDeadline` per connection and passes the same value to `accept_server`
and `handshake_server`, so the ClientHello read and the rest of the handshake
share one budget. A caller that creates a new deadline for each helper call
gets one budget per call.

The deadline covers the handshake only. Post-handshake reads and writes return
to the 10 second socket bound. This spike has no idle timeout, keepalive,
half-close, or data-phase deadline.

## What a pin verifies, exactly

Two pin kinds are implemented.

**SPKI pin.** SHA-256 over the DER-encoded `SubjectPublicKeyInfo` of the leaf
certificate, including the SPKI tag and length. A new certificate for the same
key keeps this pin.

**Certificate pin.** SHA-256 over the full DER leaf certificate. Any reissue,
even with the same key, changes this pin.

The SPKI comes from rustls's `ParsedCertificate`, the same parser rustls uses in
the handshake. This experiment has no hand-written DER walker. A hand-written
length calculation can overflow on a 32-bit target or panic on malformed input;
the parser removes that code from the trust path.

In both pin kinds the check runs inside the TLS handshake, not after it:

1. rustls parses the peer certificate.
2. The custom verifier hashes the pin field and compares it with the expected
   value. A mismatch aborts the handshake with an alert.
3. rustls verifies the peer's `CertificateVerify` signature with the public key
   in that certificate. A certificate without the private key fails even when
   its public bytes match the pin.

The tests cover step 3 independently of the configuration builder. rustls
normally rejects a certificate and an unrelated private key when the config is
built. `tests/rejection.rs` also supplies the pair through a custom certificate
resolver, which bypasses that early check. The server then rejects a client
`CertificateVerify` signature from the wrong key, and the client rejects a
server `CertificateVerify` signature from the wrong key. In both cases the pin
check runs first and the signature check is what fails.

The client aborts before it sends its own certificate to a server that fails
the pin check. `wrong_server_identity_is_rejected_before_the_client_certificate`
asserts that the server's client-certificate verifier was never called.

A pin does **not** verify any of the following:

- the host name, subject alternative names, or that the server is authorized
  for a name;
- the certificate validity period, key usage, or extended key usage;
- a chain to a CA, name constraints, or certificate policies;
- revocation through OCSP or CRL;
- certificate transparency;
- that the pin itself came from the right source device.

The last point is the important one. Pinning moves trust to the distribution of
the pin. If an attacker can replace the pin on the target device, the pin
proves nothing. This spike does not design or test pin distribution, pairing,
storage, rotation, or recovery. That gap is separate from TLS and is not solved
by any test here.

The pin comparison uses ordinary equality. A pin is a hash of public key
material, not a secret, so comparison timing does not reveal a secret. The
private keys never leave the test process and are never written to disk. The
`Drop` implementation clears the one PKCS#8 buffer this type owns with
`fill(0)` as a best effort. That is not a zeroization guarantee: copies can
exist in rcgen, rustls, ring, and the allocator, and a compiler or allocator may
reuse freed memory. The spike makes no memory-zeroization claim.

## Signature policy details

The policy is enforced twice:

- The verifiers return only `ECDSA_NISTP256_SHA256` from
  `supported_verify_schemes`. rustls puts that list in the ClientHello
  `signature_algorithms` extension and in the server's CertificateRequest. A
  conforming peer cannot choose another scheme.
- Each verifier also rejects a `CertificateVerify` scheme outside the policy
  before it calls the provider. This covers a peer that ignores the advertised
  list.

A conforming rustls peer will not send a disallowed scheme when the
advertisement is honest, so `tests/signature_policy.rs` uses a test-only signer
that reports a P-384 scheme and ignores the peer's list. The signature body is a
placeholder because the scheme check runs before any signature verification.
The test asserts the policy error and that the pin check ran first. It does not
assert a cryptographic signature failure.

The same file also uses real P-384 identities. A P-384 server key cannot produce
a scheme that a P-256-only client accepts, so the server handshake fails. A
P-384 client key cannot answer a P-256-only CertificateRequest, so the server
sees no certificate. These are real key and certificate values, but they still
run on loopback with rustls on both ends.

This spike does not test RSA, Ed25519, certificate chains, or algorithm
migration. The ring provider supports more algorithms than the policy, as
`tests/crypto_policy.rs` records, but the spike does not exercise them.

## Why resumption is off

TLS 1.3 resumption does not let an arbitrary client skip authentication. A
resumed session uses a ticket derived from an earlier full handshake that did
authenticate the peer. The problem for a pinned design is trust change. The
certificate message and both verifiers do not run on a resumed connection. If a
pin is rotated or revoked after a ticket is issued, the resumed session keeps
using the old authentication until the ticket or session store expires. The
spike wants every connection to run the pin check, so it sends no tickets
(`send_tls13_tickets = 0`) and disables the client session store.

`tests/resumption.rs` uses the rustls `HandshakeKind` value to show both sides.
With the default config, two connections sharing one client config are both
`Full` and both pin checks run. With a deliberately resumable pair, the second
connection is `Resumed` and neither pin check runs.

Two crossed tests show that one side alone cannot create a resumed session:

- a ticket-sending server with a client that has resumption disabled stays
  full, and both pin checks run on both connections;
- a ticket-accepting client with a server that sends no tickets stays full, and
  both pin checks run on both connections.

This is test evidence for the policy, not a recommendation to enable
resumption.

## Threat model for the tests

| Case | Observed result | Limit |
|---|---|---|
| Passive observer on the hotspot | Cannot read or modify application bytes inside the TLS connection. | Addresses, ports, byte counts, ALPN, and timing stay visible. An IP server name removes SNI, not the rest. This does not defeat traffic analysis or deep packet inspection. |
| Active man in the middle | Rejected when it does not hold the pinned key. | No protection before the pin is trusted. A stolen private key defeats the pin. |
| Wrong client | Rejected. The server pins one client SPKI. | A stolen client key authenticates. There is no revocation. |
| Replayed application record | Rejected on a fresh connection with fresh keys. | This is not a test of 0-RTT. The spike does not enable early data. |
| Cleartext bytes | Rejected by the TLS listener. | None beyond TLS itself. |
| Downgrade | Not possible through these configs; TLS 1.2 is not built. | A future policy change would need its own tests. |
| Missing or wrong ALPN | Rejected by the library. A missing label is a close; a non-overlapping list that reaches rustls gets a `no_application_protocol` alert. | The library must be used; a direct `ServerConnection` still gets the post-handshake check, but the pre-handshake close is skipped. |
| Slow handshake drip | Rejected at the total handshake deadline. | The deadline covers the handshake only. Post-handshake data has only per-operation socket bounds. |
| Signature scheme outside the policy | Rejected before the provider checks the signature. | A conforming peer cannot reach this path when the advertisement is honest. The test uses a test-only signer. |

A failure in any of these tests aborts the handshake. The server side also
reports an error in each rejection test. Some rejections arrive at the client
on the first read rather than during `connect`, because a TLS 1.3 client sends
its `Finished` before the server has processed its certificate. The tests
accept either timing and always require the server to fail.

## One flow, one connection

`each_flow_gets_its_own_tls_connection` opens eight clients at once. Each gets
its own TCP connection, its own TLS handshake, and its own server worker. The
test records the server-side peer port for each flow and asserts that all eight
are distinct. No stream is multiplexed over another flow's connection.

This matches the engine invariant that one inner 4-tuple maps to one outer
socket. The spike does not add a framing layer that could multiplex flows. It
does not implement the engine's normalized outer socket either: the sockets here
are ordinary loopback `std::net::TcpStream` values, not the `tcp_start`,
`tcp_connect`, or `udp_socket` helpers that set TTL 65 and pin the interface.

## What the "relay" tests do not show

The tests in `tests/relay.rs` are connection tests, not a proxy. There is no
inner socket and no forwarding loop. A handler reads from one TLS stream and
writes back to the same stream. The tests show byte-exact data and independent
connections. They do not show:

- half-close behavior or an abortive close;
- backpressure between an inner socket and an outer socket;
- an idle timeout, keepalive, or dead-peer policy;
- MTU or fragmentation policy;
- throughput, memory use, or latency under load.

A production relay needs its own write, close, and idle policy inside the TLS
stream.

## No external relay

Every socket in this spike is a TCP connection to `127.0.0.1` on an ephemeral
port. No test resolves a name, opens a socket to a non-loopback address, or
contacts a server. The server identity is ephemeral and local. The experiment
does not change the product's direct mode, does not require a source device
app, and does not introduce a VPS, tunnel server, or cloud hop.

## Trust bootstrap

The pin is the whole trust decision, and this spike receives it as an argument.
It does not answer how a real deployment gets that value to the other device.
The limits are:

- The first pin exchange needs authentication. If an attacker can replace a pin
  before the first connection, the pin proves nothing. TLS cannot fix this.
- This spike does not design or test a pin delivery channel. It does not change
  pairing version 1, which uses X25519 key agreement and a bearer token. Whether
  that protocol can carry a pin with the required authentication is an open
  design question with its own parity vectors and review.
- There is no pin storage, rotation, revocation, recovery, or "forget"
  operation here. A compromised or replaced key needs a path that this spike
  does not provide.
- There is no identity continuity requirement. A pin binds to one public value,
  not to a device identity or a user account.

Do not read the passing tests as evidence that the trust bootstrap is solved.

## Experiment-only limits

- This is a host-only spike. It is not wired into the product, not reviewed
  independently, and not fail-closed.
- Certificates and keys are generated in memory for one test run. There is no
  platform key store, no non-exportable key, and no certificate lifecycle.
- Everything runs on loopback with rustls on both ends. Platform TLS stacks,
  emulators, real phones, hotspots, and carriers are not tested. See
  `INTEROP.md`.
- The tests do not measure traffic analysis resistance. ALPN, certificate
  shapes, record sizes, and timing remain observable. Deep packet inspection
  and fingerprinting are out of scope.
- The tests do not exercise loss, reordering, NAT rebinding, radio sleep, or
  background suspension.
- `rcgen` and `rustls` are trusted as established implementations. This spike
  does not audit them, and it makes no claim about their future versions beyond
  the committed lockfile.
- Memory zeroization, side channels beyond pin comparison, and denial of
  service are not evaluated.

## Files

- `src/identity.rs`: ephemeral key and certificate generation, rustls SPKI
  extraction, pin types, and pin stability checks.
- `src/transport.rs`: pinned verifiers, TLS 1.3 configs, ALPN policy, signature
  policy, the total handshake deadline, blocking handshake and stream helpers,
  and TLS record capture for the replay test.
- `tests/support/mod.rs`: bounded loopback listener, per-session worker, raw
  connect, and deterministic payload. The TLS and ALPN policy come from the
  library.
- `tests/pinned_mtls.rs`: happy path, SNI absence, policy advertisement.
- `tests/rejection.rs`: rejection cases for identities, keys, cleartext, and
  replay.
- `tests/relay.rs`: byte-exact data and independent flows.
- `tests/pins.rs`: SPKI extraction and pin semantics.
- `tests/resumption.rs`: default no-resumption policy, the resumable
  comparison, and two crossed cases.
- `tests/alpn.rs`: library ALPN enforcement, missing and wrong selections from
  each side, and the rustls non-overlap behavior on the direct path.
- `tests/signature_policy.rs`: disallowed scheme rejection and real P-384
  identities under the P-256 policy.
- `tests/handshake_deadline.rs`: silent and slow-drip peer tests for the total
  handshake budget.
- `tests/crypto_policy.rs`: the provider's actual cipher, key exchange, and
  signature lists, plus the values a loopback handshake selects.
- `INTEROP.md`: iOS Network.framework and Android assessment.

## Limitations

- Blocking `std::net` sockets. The engine runs a different relay and event
  model. This spike does not measure throughput, memory, or latency.
- No production write policy. The helpers flush in 16 KiB pieces because rustls
  holds a bounded plaintext buffer, and a blocked write is bounded only by the
  socket timeout.
- No idle timeout, keepalive, half-close, MTU handling, or data-phase deadline.
- No certificate rotation, pin update, revocation, or recovery path.
- No pin bootstrap. The first pin must arrive over an authenticated channel.
  This spike assumes the pin is already correct and does not design that
  channel.
- No review of the pin comparison against side channels beyond the fact that
  pins are public values.
- Cipher suites and key exchange groups are the provider defaults, not a
  narrowed policy. Only ECDSA P-256 certificates and the P-256 SHA-256
  handshake signature were tested. Algorithm agility, RSA, Ed25519,
  post-quantum key exchange, and certificate chains are out of scope.
- The tests are loopback only. They do not exercise loss, reordering, NAT
  rebinding, radio sleep, or background suspension.
- The ALPN label is fixed. A missing label is enforced by a close. A
  non-overlapping list gets the rustls `no_application_protocol` alert.
- `rcgen` and `rustls` are trusted as established implementations. This spike
  does not audit them.
