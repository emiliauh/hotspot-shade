# Interop assessment: iOS Network.framework and Android server TLS

This document is an assessment, not a test result. The spike in this directory
runs on the host with Rust on both ends. No iOS or Android code was built, run,
or installed for this experiment. Emulators were not used.

Every platform claim below is documented API availability, read from the sources
at the end. A documented API is not a tested behavior. Availability may differ
by OS version, vendor build, device configuration, and app entitlement. Treat
each row as a question to answer with a device test, not as support.

The product shape would put the phone in the TLS server role and the target
device in the TLS client role. The spike's Rust server exists only to test the
Rust client against a known peer.

This is an experiment-only assessment. It does not change the product, does not
choose a TLS design, and does not design a pairing or pin delivery protocol.

Sources are official primary documentation, read on 2026-11-05. They are listed
at the end.

## What the spike fixes on the wire

Any platform peer would need to agree on all of these:

- TLS 1.3 only, no TLS 1.2 fallback.
- A server certificate with an ECDSA P-256 key (the only key type the spike
  generates).
- Mutual authentication: the server requires a client certificate.
- SPKI or certificate SHA-256 pinning on both ends.
- A fixed ALPN label `proxy`. The Rust server library rejects a client that
  does not offer the label, and both sides require the selected label. The
  label is generic, but it is still visible metadata and a fingerprint. A
  platform peer must enforce the same policy in its own stack; ALPN
  configuration alone is not proof that a missing label is rejected.
- No SNI. The client uses an IP address as the server name, so rustls sends no
  SNI extension.
- No 0-RTT early data.
- No session resumption, so every connection carries a certificate and runs
  the pin check.
- One TLS connection per inner flow.
- A total handshake budget. The Rust helpers give one connection 10 seconds
  for the whole handshake. A platform peer needs its own handshake timeout;
  this assessment does not test any platform timeout.

The spike also fixes the signature policy to ECDSA P-256 with SHA-256. Its
verifiers advertise only that scheme and reject any other handshake signature
scheme. The ring provider supports more; the policy does not claim them. The
cipher suite and key exchange group are the provider defaults, not a narrowed
list: three TLS 1.3 suites and X25519, secp256r1, and secp384r1. A platform
design that needs one suite or one group must add that restriction and test it.

## Three separate gaps

These must not be collapsed into one problem.

1. **Unauthenticated bootstrap.** A pin is only as good as the channel that
   delivered it. The first pin exchange needs authentication, or an attacker can
   replace the pin before the first connection. TLS does not solve this. This
   assessment does not design a pin delivery channel and does not add a custom
   pairing protocol. The existing pairing version 1 uses X25519 key agreement
   and a bearer token. Whether that protocol can carry a pin with the required
   authentication is an open design question with its own parity vectors and
   review. Do not assume it is solved here.
2. **Android API 26 through 28 have no platform TLS 1.3.** TLS 1.3 server and
   client support starts at API 29, and the ALPN application protocol methods
   are API 29 and later. A TLS 1.3-only policy cannot run on API 26 through 28.
   This is separate from the bootstrap problem. The options are to raise the
   minimum API, allow TLS 1.2 with its own policy review, or bundle a TLS
   provider, which adds native code and a dependency the project does not have.
3. **Platform key and socket requirements.** A production peer must keep the
   private key in the platform key store where possible, and every outer socket
   must still be one of the engine's normalized sockets. Both requirements need
   platform tests and are described below.

## Platform key requirements

The pin protects a public key, but the private key must stay usable by the TLS
stack. The platform tests need to answer these questions:

- Can the TLS stack sign with a key that the app cannot export? On iOS this
  means a keychain `SecIdentity`; on Android it means an `AndroidKeyStore` key.
  If the TLS API insists on a PKCS #12 blob or an exported key, a
  non-exportable key may not be usable.
- Does the TLS stack expose the certificate chain and the SPKI the pin needs, or
  does the app need its own certificate parsing?
- Does the platform TLS stack run the peer verification hook on every
  connection, or can a resumed session skip it?
- What happens when the key is rotated or the device key store refuses an
  operation while the screen is locked?

None of these are answered by this host-only spike.

## Normalized socket requirements

The spike uses ordinary loopback `std::net::TcpStream` values. A production
transport would run inside the engine's outer socket path:

- Every outer socket must go through `tcp_start`, `tcp_connect`, or
  `udp_socket` in `rust/src/normalization.rs`, or the platform wrapper around
  them.
- The outer socket must set TTL 65 and pin the physical hotspot interface.
- The TTL read-back audit must keep `ttl_bad == 0`.
- One inner 4-tuple must map to one outer socket. The TLS connection is that
  outer socket, not a multiplexed stream shared by several flows.
- A TLS record cannot be allowed to hide a second flow inside one connection.

The spike does not test any of that. It proves the TLS shape on loopback, not
the normalized egress path.

## iOS and Network.framework

### Documented support

| Item | Documented availability | Source |
|---|---|---|
| `NWProtocolTLS` and TLS options | iOS 12.0 and later | NWProtocolTLS |
| `tls_protocol_version_TLSv13` and `sec_protocol_options_set_min_tls_protocol_version` | iOS 13.0 and later | tls_protocol_version_t, set_min_tls_protocol_version |
| `sec_protocol_options_set_local_identity` | iOS 12.0 and later | set_local_identity |
| `sec_protocol_options_set_peer_authentication_required` | iOS 12.0 and later | set_peer_authentication_required |
| `sec_protocol_options_set_verify_block` | iOS 12.0 and later | set_verify_block |
| ALPN through `sec_protocol_options_add_tls_application_protocol` | iOS 12.0 and later | add_tls_application_protocol |
| `SecPKCS12Import` for an identity and its key | iOS 2.0 and later | SecPKCS12Import |

The peer authentication function documents that clients default to requiring
peer authentication, while servers default to not requiring it. A server must
turn this on explicitly. The local identity function takes a `sec_identity_t`
that carries the private key and certificate. The verify block is the documented
hook for custom trust decisions, including self-signed certificates and
pinning.

### How the spike would map

- The phone would create an `NWListener` with `NWProtocolTLS.Options`, set its
  local identity to a server certificate, and set peer authentication required.
- A verify block would compare the client certificate against the pinned SPKI
  or certificate. Apple documents the verify block as receiving a
  `sec_trust_t`. A custom check converts it to `SecTrust` and inspects the
  certificate chain.
- The Rust client would pin the server leaf. The phone would pin the target
  client leaf. Both sides need the other side's pin before the first
  connection.
- ALPN would carry the same label on both ends.

### Where iOS support remains unproven

1. **Server identity provisioning.** iOS has no public API to create and sign an
   arbitrary X.509 certificate at runtime. `SecCertificateCreateWithData` only
   creates a certificate from DER that already exists, and there is no API to
   sign a new certificate with a keychain key. `SecPKCS12Import` imports an
   existing PKCS #12 blob into the keychain, so the app would need a provisioned
   identity or a build-time blob. Shipping one shared private key in the app
   bundle is unacceptable. A per-install identity needs an issuance or pairing
   step that does not exist today. This is the largest gap.
2. **Server-side TLS with mutual authentication.** The APIs exist, but this
   spike did not build an `NWListener` TLS server. The combination of a
   listener, a local identity, required peer authentication, a verify block,
   ALPN enforcement, and a handshake timeout needs a real test on the host and
   then on a device. Documented availability is not evidence that the
   combination works.
3. **SPKI extraction.** `SecTrust` exposes certificates. A certificate pin is a
   straight SHA-256 of the DER. For an SPKI pin, `SecCertificateCopyKey` gives a
   `SecKey`, and `SecKeyCopyExternalRepresentation` gives the raw public key
   bytes, not the DER `SubjectPublicKeyInfo`. The app would need to build the
   SPKI wrapper itself, or use a whole-certificate pin. That choice changes
   rotation behavior and needs a decision.
4. **Resumption.** A resumed TLS 1.3 session can skip the certificate message
   and the verify block. It does not let an arbitrary client skip
   authentication: the ticket is tied to an earlier full handshake that did
   authenticate the peer. The problem is trust change. If a pin is rotated or
   revoked after the ticket is issued, the resumed session keeps using the old
   authentication until the ticket or cache expires. The design must disable
   resumption or prove that the verify block still runs on every connection.
   This spike disables resumption for that reason. Whether Network.framework
   runs the verify block on a resumed session is untested here.
5. **Background operation.** A long-lived TLS listener competes with iOS
   background suspension. The current source device listener already stops
   when the app is not in the foreground. A TLS mode inherits the same limit,
   and background service behavior is not proven.
6. **Key storage.** Whether a keychain identity can be used by the TLS stack
   without exporting the private key, and how it behaves with a
   non-exportable key, needs a device test. The local identity API takes a
   `sec_identity_t`; whether every keychain identity can produce one is
   unproven.

## Android API 26 and later

### Documented support

The `SSLSocket` reference gives the platform protocol table.

| Protocol | Client supported | Client enabled by default | Server supported | Server enabled by default |
|---|---|---|---|---|
| TLSv1.2 | API 16+ | API 20+ | API 16+ | API 16+ |
| TLSv1.3 | API 29+ | API 29+ | API 29+ | API 29+ |

The same page lists the TLS 1.3 cipher suites as API 29 and later. Android 10
documentation says TLS 1.3 is enabled by default there, TLS 1.3 cipher suites
cannot be disabled individually, and 0-RTT is not supported.

`SSLSocket` also documents `setNeedClientAuth` for server sockets, and
`setUseClientMode` to select the role. A server socket is created from
`SSLServerSocket`, which comes from an `SSLContext` initialized with a key
manager. A custom `X509TrustManager` can implement the pin check on either
side.

### How the spike would map

- The phone would build an `SSLContext` with a `KeyManagerFactory` over an
  in-memory `KeyStore` that holds the server key and certificate chain.
- The accepted server socket would call `setNeedClientAuth(true)`.
- A custom `X509TrustManager` would compare the client leaf against the pinned
  SPKI or certificate. The client side would use the same approach for the
  server leaf.
- TLS 1.3 would be required with `setEnabledProtocols(new String[]{"TLSv1.3"})`.
- ALPN would use the API 29 application protocol selector.
- A blocking `SSLSocket` fits the existing thread-per-session proxy better than
  a non-blocking `SSLEngine`.

### Where Android support remains unproven

1. **minSdk 26 does not have TLS 1.3.** API 26 through 28 support TLS 1.2 only.
   A TLS 1.3-only design cannot run there, and the ALPN application protocol
   methods are API 29 and later. This is separate from the unauthenticated pin
   bootstrap problem described above. The options are:
   - raise the app's minimum to API 29;
   - allow TLS 1.2 with an explicit policy decision and its own review;
   - bundle a TLS provider that backports TLS 1.3, which adds native code and a
     dependency the project currently does not have.

   This is a product decision, not a test result.
2. **Server certificate provisioning.** Android can generate a key pair in the
   `AndroidKeyStore`. For a key pair with the sign purpose and no attestation
   challenge, the platform creates a self-signed X.509 certificate, which
   `KeyStore.getCertificate` returns. The `KeyGenParameterSpec` certificate
   setters (API 23 and later) can set the subject, serial number, not-before,
   and not-after. So "Android cannot make a certificate" is false. The limits
   are different: the key entry has only that platform-generated self-signed
   certificate, and replacing it with a CA-issued chain requires an exportable
   private key. Whether Conscrypt can use a non-exportable AndroidKeyStore key
   for TLS 1.3 server signing on every API level and vendor build is unproven.
   The Android 10 notes mention RSA-PSS with opaque keystore keys, which is not
   the same as a tested ECDSA TLS 1.3 server identity.
3. **Device variation.** Conscrypt behavior can differ by API level and vendor.
   The documented table is the platform contract, but a real phone test is
   still required.
4. **Resumption and pinning.** The platform can resume TLS sessions. A resumed
   session does not carry a new certificate, so the trust manager and pin check
   do not run again. As on iOS, this is a trust-change problem, not an
   arbitrary bypass: the ticket comes from an earlier authenticated handshake.
   A pin rotation or revocation may not apply until the ticket expires. The
   design must disable resumption or prove that the check still runs. This
   needs a test on API 29 and later.
5. **Background and Doze.** The existing source proxy runs in a foreground
   service. A TLS listener adds handshakes and keepalive behavior. Battery and
   network restrictions on a real phone are unproven.
6. **ALPN on API 26 through 28.** The application protocol methods are API 29
   and later. If TLS 1.2 is allowed on older versions, the ALPN binding needs
   another mechanism or an explicit omission.

## Interop matrix

Status values are "documented APIs exist" or "blocked". None are tested here.

| Peer pair | TLS 1.3 | Mutual auth | Pin | Status |
|---|---|---|---|---|
| Rust client (this spike) to iOS Network.framework server | Yes, iOS 13+ | Yes, if the server sets peer authentication required and a verify block | Verify block can inspect the client certificate | Documented APIs exist. Identity provisioning, server TLS, and background are unproven. |
| Rust client (this spike) to Android 10+ `SSLSocket` server | Yes, API 29+ | Yes, `setNeedClientAuth(true)` plus a trust manager | Custom `X509TrustManager` | Documented APIs exist. Certificate provisioning and a real device test are unproven. |
| Rust client to Android 8 or 9 server | No platform TLS 1.3 | TLS 1.2 mutual auth is documented | Trust manager API exists | Blocked for a TLS 1.3-only policy at minSdk 26. |
| iOS client to this Rust server | Yes, iOS 13+ | Client identity through a local identity | Verify block | Not the product shape. The APIs exist but are untested. |
| Android client to this Rust server | Yes, API 29+ | Client key manager plus a trust manager | Custom `X509TrustManager` | Not the product shape. The APIs exist but are untested. |
| iOS peer to Android peer | Standard TLS 1.3 on both | Both can request and present certificates | Pinning APIs exist on both | No cross-platform test. Certificate key and signature algorithm choices need a matrix. |

## Signing identity and lifecycle gaps

The current product does not use X.509. Pairing v1 uses X25519 key agreement
and a bearer token. A TLS mode needs a certificate and pin lifecycle that the
project does not have.

Open questions that block a production design:

- **Who issues the server certificate?** On Android the platform can create a
  self-signed certificate with an `AndroidKeyStore` key, but that certificate
  is not issued by a CA and needs a delivery and rotation story. On iOS a
  per-install identity needs an identity import, because the public APIs do not
  sign a new X.509 certificate at runtime. A provisioned identity needs a
  delivery path and a revocation story. This is unresolved.
- **How does the pin reach the other device?** The pin must arrive over an
  authenticated channel. If the first exchange is unauthenticated, an attacker
  can substitute a pin before TLS ever runs. The existing pairing protocol could
  carry a pin, but that requires a versioned protocol change and new parity
  vectors on all three implementations. This assessment does not design that
  change and does not propose a custom pairing protocol.
- **What does rotation look like?** An SPKI pin survives a certificate reissue
  only if the key stays the same. Replacing a compromised key needs a new pin
  and a recovery path. A lost or replaced phone must not strand the target
  device.
- **What replaces "Forget"?** Today the trust list removes a target public key
  and the token rotates. A TLS pin store needs the same operations with clear
  failure states.
- **What is the algorithm policy?** ECDSA P-256 worked in the spike. A
  production policy needs to state accepted keys, signature algorithms, and
  whether post-quantum key exchange is required later.
- **Can the private key stay non-exportable?** iOS keychain and Android
  keystore may hold keys that the app cannot read. The TLS stack must be able to
  use them. This needs device tests on each supported OS version.

## Replay and cleartext in platform peers

TLS 1.3 record protection and per-connection keys are the same on all three
stacks. A replayed application record from another connection must fail. The
spike proves the Rust side. The platform sides need the same test, or a
documented reliance on the platform implementation.

Cleartext bytes sent to a TLS listener must fail the handshake on every
platform. The spike proves the Rust side.

0-RTT is the exception to watch. Android documents that its platform TLS does
not support 0-RTT. This spike does not enable it. If a future design enables
early data on any peer, replay becomes possible by definition and needs a
separate anti-replay design. Do not enable it by default.

## What would close the gaps

These steps were not run for this task:

1. Extend the host harness to run a real Swift Network.framework TLS server and
   the Rust client from this spike. This can run on a Mac with no route change.
   It still does not prove the iOS device stack.
2. Add an Android instrumented test with an `SSLSocket` TLS 1.3 server and the
   same Rust client. Run it on the API 36 emulator first, then a phone.
3. Add a device test for identity provisioning, pin storage, resumption
   behavior, and background suspension on iOS and Android.
4. Get an independent cryptographic and protocol review before treating any of
   this as a security boundary.
5. Decide the TLS 1.2 policy for Android API 26 through 28, or raise the
   minimum API.

## Trust bootstrap

The pin, certificate, and token all arrive through a channel this assessment
does not design. The limits are:

- The first pin exchange needs authentication. If an attacker can replace the
  pin before the first connection, the pin proves nothing. TLS cannot fix this.
- This assessment does not design or change a pairing protocol. It records only
  that the existing pairing version 1 uses X25519 key agreement and a bearer
  token, and that carrying a pin over it would need a versioned change and new
  parity vectors.
- There is no pin store, rotation, revocation, recovery, or "forget" design
  here. A compromised or replaced key needs a path this assessment does not
  provide.
- There is no identity continuity requirement. A pin binds to one public value,
  not to a device identity or a user account.

A passing host test does not show that any of this is solved.

## Experiment-only limits

- This document is an assessment. It is not a test result, not a design, and
  not a product plan.
- No iOS or Android code was built, run, or installed. No emulator was used.
  Every platform row is documented API availability, which is not evidence of
  behavior.
- The host spike uses rustls on both ends. It does not exercise Network.framework,
  Conscrypt, a real phone, a hotspot, a carrier, or a platform key store.
- The spike does not test traffic analysis resistance, fingerprinting, loss,
  reordering, NAT rebinding, radio sleep, or background suspension.
- The spike has not had an independent cryptographic or protocol review.
- The cipher suite, key exchange group, and signature algorithm claims apply to
  the committed Rust lockfile. A platform stack has its own lists and its own
  version differences.

## Sources

All read on 2026-11-05.

- Apple, `NWProtocolTLS`: https://developer.apple.com/documentation/network/nwprotocoltls
- Apple, `NWProtocolTLS.Options`: https://developer.apple.com/documentation/network/nwprotocoltls/options
- Apple, `tls_protocol_version_t`: https://developer.apple.com/documentation/security/tls_protocol_version_t
- Apple, `sec_protocol_options_set_min_tls_protocol_version`: https://developer.apple.com/documentation/security/sec_protocol_options_set_min_tls_protocol_version(_:_:)
- Apple, `sec_protocol_options_set_local_identity`: https://developer.apple.com/documentation/security/sec_protocol_options_set_local_identity(_:_:)
- Apple, `sec_protocol_options_set_peer_authentication_required`: https://developer.apple.com/documentation/security/sec_protocol_options_set_peer_authentication_required(_:_:)
- Apple, `sec_protocol_options_set_verify_block`: https://developer.apple.com/documentation/security/sec_protocol_options_set_verify_block(_:_:_:)
- Apple, `sec_protocol_options_add_tls_application_protocol`: https://developer.apple.com/documentation/security/sec_protocol_options_add_tls_application_protocol(_:_:)
- Apple, `SecPKCS12Import`: https://developer.apple.com/documentation/security/secpkcs12import(_:_:_:)
- Apple, `SecCertificateCreateWithData`: https://developer.apple.com/documentation/security/seccertificatecreatewithdata(_:_:)
- Apple, `SecCertificateCopyKey`: https://developer.apple.com/documentation/security/seccertificatecopykey(_:)
- Apple, `SecKeyCopyExternalRepresentation`: https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:)
- Android, `SSLSocket` protocol and cipher tables: https://developer.android.com/reference/javax/net/ssl/SSLSocket
- Android, `KeyGenParameterSpec`: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec
- Android, `KeyGenParameterSpec.Builder` certificate setters: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setCertificateSubject(javax.security.auth.x500.X500Principal)
- Android, `KeyStore`: https://developer.android.com/reference/java/security/KeyStore
- Android 10 features, TLS 1.3 support: https://developer.android.com/about/versions/10/features
- Android 10 behavior changes for all apps, TLS 1.3 details: https://developer.android.com/about/versions/10/behavior-changes-all
