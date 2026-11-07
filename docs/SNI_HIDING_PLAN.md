# SNI hiding and DPI resistance - proposal and status

Status: proposal. **No proposed mode is implemented.** Last evidence check:
2026-11-05, working tree based on commit `1a37ed7`. Owner: HotspotShade thread.

Revision note: this text applies the P7 and P9 to P15 corrections from the WS1
revision 6 handoff. It does not approve the design. The WS1 trace and
architecture still list those items as remaining until an independent review
accepts the plan text.

**Status of older passages:** Some passages below describe an older checkpoint.
The tree has dormant TLS record-reframing code: the Rust module
`rust/src/tls_shape.rs` with tests, and matching source-app ports that are off
by default with no visible control. It also has dormant `ech_*` and `doh_*`
counter keys with zero values in `rust/src/diagnostics.rs`. No product path
enables reframing: `SocksServer::start` and `PhoneServer::start` pass no shape
policy, the shaped Rust entry points are test-only, and the source-app shaper
has no caller outside tests. The data path never writes the `ech_*` or `doh_*`
privacy counters. There is no ECH client. Capability reporting exists and
reports `off` supported and `shape`, `hide`, `cover`, `ech`, `sni_override`,
and `background_relay` unsupported. None of this makes `shape` or `hide`
available.

In source device proxy mode, intercepted UDP DNS uses SOCKS command 1 with
DNS-over-TCP framing, not command `0x80`. DNS sent to a hotspot gateway can
bypass the tunnel. On macOS and Windows that is a route-specificity inference,
not a live DNS measurement. On Linux a default `systemd-resolved` per-link
resolver likely takes the physical-interface rule and table main; treat it as a
likely bypass until a live DNS-specific run. That is the OS resolver path. For
SOCKS5 discovery, Linux `system_dns_for_interface` fails closed because the
resolver files are one aggregate list; the caller must pass an explicit
`--dns-servers`, and that explicit server can still be wrong for the link.
Scoped resolvers, link-local, ULA, multicast, NAT64, and application or OS
encrypted DNS can also bypass the tunnel. No live DNS-specific result exists
for any target.

An automatic non-ECH retry after a blocked outer name is not an approved safety
policy. The retry rule below applies only to a future resolver connection after
an authenticated ECH rejection; application flows never retry, and an
unauthenticated rejection never retries. The ECH and DoH architecture remains
unapproved. Do not implement it based on this plan, and do not treat DoH alone
as `hide`.

Bottom line: HotspotShade today normalizes IP TTL and pins outer sockets. It does
not hide destinations, server names, or DNS. This document describes possible
future work and its limits. It is not a description of shipped behavior.

The decisive question is not which library to use. It is **which client owns
the TLS connection that would carry ECH**. Ordinary applications originate
their own TLS. The target engine relays bytes. A Rust TLS wrapper cannot
retroactively make another process's `ClientHello` use ECH. Under the current
no-termination and no-relay constraints, no transparent client boundary exists,
so `hide` is closed as unsupported. This is the plan's own default outcome, not
a new product choice. A product-owned TLS client is a separate optional future
proposal with its own product decision and review; it must not terminate TLS or
add an external relay. A tunnel-wide DoH forwarder with encrypted DNS and
resolver ECH is a separate proposed scope that no part of this document
approves. It is not implemented, and it needs its own product owner acceptance
and independent review.

Purpose and framing of the proposal:

- Add defensive privacy engineering on the user's own device, account, and
  network subscription.
- Keep every feature opt-in, labeled, and off by default.
- Keep the current TTL and IP scope intact. Do not weaken direct mode.
- State what each feature does and does not conceal, with the same honesty the
  project already applies to TTL.
- Leave carrier terms and local law to the owner. This document is not legal
  advice.

## 0. Implementation status

| Item | Status | Evidence in this tree |
|---|---|---|
| Current `off` behavior: TTL normalization, interface pinning, normalized outer sockets | Implemented | `rust/src/normalization.rs`, `rust/src/normalization_windows.rs`, relay and service paths |
| `shape` mode | **Not available** | Dormant TLS record-reframing code and tests exist in the engine and the source apps, and the `flows`, `shaped_flows`, and `shaped_errors` counters are dormant. The mode has no enabled product path. |
| `hide` mode | **Closed as unsupported under the current constraints. Not implemented.** | No transparent client boundary exists: a byte relay cannot add ECH to another application's `ClientHello`. No `rustls`, `aws-lc-rs`, `hickory-resolver`, ECH, or SNI code in `rust/src`. No TLS client dependency in `rust/Cargo.toml`. A product-owned TLS client is a separate optional future proposal, not approved here. |
| `cover` mode | **Deferred. Not implemented** | No endpoint, no tunnel, no schema entry. The project still has no external relay or VPS. |
| `terminate` mode | **Out of scope. Not implemented** | No TLS termination, no local CA, no certificate signing. |
| Mode names, config schema, capability flags | **Partial** | Capability reporting exists and reports `off` supported and `shape`, `hide`, `cover`, `ech`, and `sni_override` unsupported. `encrypted_dns`, `resolver_ech`, and `app_ech` are a proposed key set, not present and not accepted. The proposed modes are not available. |
| UI toggles on macOS, Windows, Linux, iOS, Android, and the local page | **Not implemented** | No mode control exists in any app. |
| Hermetic parity tests and acceptance gates | **Not met** | Reframing tests exist, but do not establish cross-platform parity, ECH, or DoH support. |
| `experiments/tls-transport-spike` | Test-only spike, not product code | Separate crate and lockfile. Uses the `ring` provider, which has no HPKE. Contains no ECH. Nothing in `rust/` depends on it. |
| Platform ECH and SNI API claims | **Not verified in this tree** | Rows in section 3 come from vendor documentation and published reports. No SDK header check, build, or device test was run for this checkpoint. |

What this checkpoint did verify by code inspection:

- The target engine relays TCP payload bytes. It does not parse or terminate
  TLS. In `rust/src/relay.rs`, inner pending bytes are written to the outer
  stream and outer reads are passed back as inner payload.
- In tun plus `--phone` mode, the source device receives a numeric IP in the
  SOCKS request. `Setup::phone` serializes address type 1 or 4, never a domain
  name. Intercepted UDP DNS port 53 is redirected to `1.1.1.1:53` using SOCKS
  command 1 with DNS-over-TCP framing. Other UDP uses command `0x80`.
- Direct SOCKS5 resolves an ATYP 3 name through `TinyResolver` over a
  normalized plaintext UDP socket pinned to the physical interface, not through
  an arbitrary egress `getaddrinfo` call. That query is a target-side
  local-resolution leak. ATYP 1 and 4 are also accepted, and the code does not
  enforce `socks5h`.
- No file under `rust/src`, `ios/`, `android/`, `macos/`, `windows/`, `linux/`,
  or `gui_assets/` enables an ECH, SNI override, `shape`, `hide`, `cover`, or
  `terminate` mode. Dormant shaping code exists, but no product start path
  reaches it.
- The iOS source app sets `isIdleTimerDisabled` while the proxy is starting or
  listening. It has a location-based "keep running in the background" option,
  but no Network Extension. Sustained background relay is not guaranteed.

What this checkpoint did not verify:

- Any vendor ECH deployment statistic.
- Any platform API availability claim, including Android API 37 and the iOS SDK
  behavior described in section 3.
- That any proposed mode survives a real carrier, a real hotspot, or a real
  endpoint.
- That record reframing changes what a carrier's parser sees in practice.
- That the iOS app relays reliably after screen lock or extended background
  time.
- Any live DNS-specific result on any target. The gateway bypass statement on
  macOS and Windows is a route-specificity inference. The Linux link-bound
  resolver case is a likely bypass, not a measurement.

Do not turn a proposal row into a support claim. Do not soften the current
README, technical reference, or GUI threat text until a feature is implemented
and measured. Today those documents correctly say that SNI and destinations are
visible.

## 1. Settled decisions

These decisions come from the owner for this workstream. They are scope
decisions, not evidence that the features work.

1. **Order.** `shape` is the only mode with a possible near-term pathway,
   subject to its own evidence gate. `hide` is closed as unsupported under the
   current constraints because no transparent client boundary exists. A
   product-owned TLS client is a separate optional future proposal, not part of
   this plan. Neither `shape` nor any future mode is promised until its gate
   passes.
2. **`cover` is deferred.** It is not built without an endpoint the owner
   controls. The name may stay reserved in a future schema, but no code, UI, or
   default may depend on it. It must never become a default and must never add
   an external relay or VPS to the current product.
3. **`terminate` is out of scope.** TLS interception with a locally trusted CA
   is not part of the product direction. The earlier Android ECH argument does
   not reopen it without a new owner decision.
4. **The iOS source relay is foreground-limited in current practice.** The app
   keeps the screen awake while listening and offers a background keep-awake
   option, but it has no Network Extension entitlement. Short background tests
   do not establish reliable background relay. No plan here assumes sustained
   iOS background operation.
5. **Every feature is opt-in and labeled.** It is off by default. The UI must
   name the mode and state what it does not hide. No silent activation, no
   automatic switch to a privacy mode, and no claim that a default protects
   everyone.
6. **The owner is responsible for carrier terms and local law.** The product
   documents the requirement and does not decide it for the owner.
7. **Destination privacy is distinct from billing and detection.** No mode
   changes what the plan bills. No mode presents traffic as another service
   class. No mode claims to defeat tethering detection, DPI, TLS inspection, or
   traffic analysis. A separately approved product-owned client, if ever built,
   is a destination-name feature, not a billing feature and not a
   detection-evasion feature.

## 2. The architectural facts that define the design

### 2.1 The source proxy is a byte relay

In source device proxy mode, the target device hands the source device a host
and port, the source device opens a socket on the cellular path, and both ends
copy bytes. The source device does not parse TLS. The application's
`ClientHello` reaches the carrier as the application wrote it.

The target engine has the same shape. It runs a userspace TCP endpoint inside
the tunnel, then copies payload bytes to a normalized outer socket. The engine
sees TLS as opaque payload.

### 2.2 What a byte relay can do to a TLS connection

A byte relay can:

1. change where the bytes go (destination);
2. change how the plaintext TLS record stream is split into records, only
   before encryption keys exist (the `ClientHello`), without changing the
   handshake bytes; encrypted records cannot be re-framed because their record
   headers are authenticated as associated data;
3. change TCP segmentation and pacing on the socket it owns;
4. delay, drop, or close the flow;
5. terminate TLS and re-originate it, which needs a certificate the client
   trusts and is the `terminate` mode now out of scope.

### 2.3 What a byte relay cannot do

- **It cannot edit the SNI in place.** Any changed `ClientHello` byte changes
  the handshake transcript. The server's `Finished` check then fails,
  independently of certificate validation. This is an RFC 8446 transcript
  property, not a policy choice.
- **It cannot force TLS 1.3.** It can observe the negotiated version in the
  plaintext `ServerHello` and it can drop a non-1.3 flow, but dropping is not
  forcing. A relay that drops TLS 1.2 breaks peers. Certificate concealment
  therefore follows what the two endpoints negotiate, not what the relay
  wants. Do not write "pin TLS 1.3" as a property of `shape`.
- **It cannot add useful padding to the client handshake.** Inserted bytes
  corrupt the handshake. TLS 1.3 padding has to be added by the TLS client that
  builds the message, not by a relay.
- **It cannot make another process's TLS client support ECH.** This is the
  central problem for `hide`; see section 2.4.

### 2.4 The client boundary for `hide` is closed under the current constraints

A Rust TLS client with ECH can only change the `ClientHello` that the Rust
client itself builds. Adding `rustls` to the engine would not reach into a
browser, a mail client, or any other process and rewrite its handshake.

Today the engine does not originate user destination TLS at all. It relays
application bytes. Its own outbound TLS surface is effectively absent: the
local control page is loopback HTTP and pairing uses its own protocol. DNS
uses UDP and TCP. The tunnel's DNS path is plaintext today. In source device
proxy mode, intercepted UDP:53 is carried to the source device over SOCKS
command 1 with DNS-over-TCP framing. TCP:53 is a separate plaintext path. DoH
would be HTTPS over TCP. Wrapping `normalization::tcp_connect` in a TLS client
would create a TLS connection that the engine originates. It would not wrap an
application's existing TLS session. The earlier draft's insertion point was
wrong on this point.

There are only a few possible answers. Under the current constraints the plan
closes `hide` as unsupported:

1. **Applications use their own ECH-capable client.** Then the engine has
   nothing to implement for those flows. The carrier sees ECH only where the
   application and the destination support it. HotspotShade cannot claim the
   win.
2. **The engine terminates application TLS and re-originates it.** This needs a
   local CA trusted by every application, breaks certificate pinning, creates
   two TLS sessions, and is the `terminate` mode now out of scope. It also
   changes the endpoint's view of the client.
3. **The product adds an explicit client surface that owns the TLS session.**
   For example, a built-in fetch or a proxy that applications deliberately use.
   That is a product-direction change, not a transparent tunnel feature. It
   also still needs a trusted certificate path for HTTPS.
4. **The source device terminates TLS.** Same CA and pinning costs, plus a
   phone-shaped fingerprint for desktop traffic. Out of scope with `terminate`.

The client-boundary question is **closed for this workstream under the current
constraints**, not left as a pending approval. A transparent byte relay cannot
inject ECH. The plan's default outcome applies: if no acceptable boundary
exists, `hide` is not built and no claim is made. `hide` is therefore closed as
unsupported. A product-owned TLS client remains a separate optional future
proposal with its own product decision and review; it must not terminate TLS or
add an external relay. A tunnel-wide DoH forwarder with encrypted DNS and
resolver ECH is a separate proposed scope with its own tradeoffs and review
gate. This correction does not approve that scope, and no part of it is
implemented.

### 2.5 Which hop sees the shaping

TLS record framing is payload. If a relay re-frames the first records, those
record boundaries survive a byte relay to the destination. That part can be
done at the target relay.

TCP segmentation and pacing are different. They apply to the socket the process
owns. In source device proxy mode, the carrier sees the source device's
destination socket, not the target's socket to the source device. Pacing on the
hotspot link does not control the source device's TCP stack. Any TCP-level
`shape` claim must be measured at the carrier-facing socket, which means the
source device for proxy mode or the target's outer socket in direct mode.

### 2.6 The DNS boundary

The engine can encrypt DNS that it forwards. It cannot force an application to
use that path. A browser with its own DoH resolver, a system resolver, or a
local network resolver can still expose names outside the relay. ECH and DoH
only help when the same client owns both the name lookup and the TLS
connection. That is another reason a transparent client boundary does not
exist.

## 3. Platform capability matrix

These rows are planning inputs from vendor documentation and published reports.
**They are not verified support claims.** No SDK header check, build, or device
test was run in this checkpoint. Treat every platform API cell as reported and
unverified.

| Platform | Role | SNI override | ECH | Current relay evidence | Notes |
|---|---|---|---|---|---|
| macOS arm64 | target | Reported possible in a Rust TLS client | Reported possible with rustls and aws-lc-rs | CLI engine verified on a live hotspot; signed app helper path untested; no SNI mode exists | Only for connections the Rust client owns. Does not cover third-party apps. |
| Windows 10/11 | target | Reported possible | Reported possible | Source proxy start path implemented; live tunnel not verified | Same client-boundary limit as macOS. |
| Linux | target | Reported possible | Reported possible | Engine start paths VM-tested; live hotspot not verified | Same client-boundary limit. |
| Android 8+ | source | JSSE name override exists, but only if the phone is the TLS client | Only as a TLS terminator; reported API 37 surface | Emulator-tested; real phone and carrier not verified | A relay is not a TLS client. Terminator ECH is out of scope. |
| iOS 17+ | source | C shim only; the name must match a certificate the phone can present | Reported unavailable to third-party apps | **Foreground-limited in practice**; device test and background reliability not verified | The app uses the idle timer plus an optional background keep-awake. No Network Extension. |

Hard constraints to keep in the product docs:

- iOS apps have no general ECH surface through the platform TLS stack, as
  reported for the SDKs reviewed. Verify against the SDK actually used before
  building anything.
- Sustained iOS background relaying would need a Network Extension entitlement.
  The current app does not have one. Treat the relay as foreground-oriented and
  do not claim background reliability.
- Android platform ECH only matters if the phone is the TLS client. It does
  nothing in relay mode.
- ECH deployment is not universal. Published figures cited by the earlier draft
  are vendor and measurement claims, not measurements made here. Never claim
  "SNI hidden" as a universal property.

## 4. Modes

### Mode `off` (current, implemented)

TTL normalization, interface pinning, and normalized outer sockets only. The
docs correctly say destinations are visible. This is the only mode that exists.

### Mode `shape` (proposed, not implemented)

Relay-side, byte-preserving, and key-less in intent:

- split the plaintext `ClientHello` into more TLS records while preserving the
  handshake bytes;
- optionally apply small writes and pacing on the carrier-facing socket;
- observe and report, but do not claim control of, the TLS version.

Honest scope:

- It may break a parser that assumes the first TCP segment or the first TLS
  record contains the whole `ClientHello`. That is a narrow, unproven benefit.
- It does not hide SNI. SNI stays in the plaintext `ClientHello`.
- It does not hide the destination IP or ASN.
- It does not change JA3/JA4, DNS names, flow size, or timing.
- It cannot force TLS 1.3, so it cannot guarantee that the destination
  certificate is encrypted.
- It cannot pad the handshake.
- It can make the flow look unusual. That is a signal of its own.
- Very small records may be rejected by a server or a middlebox. Measure that
  before choosing a record size.
- It is hygiene at best, not privacy.

Before implementation, measure whether the intended parser is affected at all,
and measure the carrier-facing hop. Do not implement TCP shaping at the target
and claim it reaches the carrier in proxy mode.

### Mode `hide` (closed as unsupported under the current constraints; not implemented)

A potential no-server privacy win, but only for a TLS client the product owns.
It cannot be a transparent property of the current relay, and no transparent
client boundary exists under the current constraints.

If a separate product-owned TLS client were ever approved, the candidate design
is:

- a Rust TLS 1.3 client with an HPKE-capable provider;
- ECH when a usable `ECHConfig` exists; GREASE, if implemented, is a separate
  opt-in and does not establish that destinations look alike;
- `ECHConfig` from the HTTPS/SVCB record over DoH, cached per origin, with a
  retry after a rejection that authenticates the public name;
- TLS 1.3 only for connections the client owns;
- no PSK resumption in the outer hello;
- DoH for DNS that the same client forwards.

What `hide` must not claim:

- **It is not universal.** Valid ECH is a small share of real traffic in the
  published reports cited by the earlier draft. Cloudflare is effectively the
  only large provider. Safari and iOS do not ship ECH in the reports reviewed.
- **It is blockable.** A static outer name and the encrypted-DNS dependency are
  visible. A network can block either. Do not automatically retry without ECH
  after a timeout, reset, or certificate failure. An unauthenticated ECH
  rejection also does not retry. A separately selected non-ECH profile would
  not be `hide`. This candidate design is not approved; it needs its own
  product decision and independent review.
- **The outer ECH name can itself be a flag.** `hide` must be selectable per
  network profile, not always-on.
- **JA3/JA4, IP/ASN, flow shape, and timing survive.** `hide` moves the
  carrier's question from "which domain?" to "which CDN and what behavior?"
  and nothing more.
- **It does not cover application traffic unless the application or an
  explicit proxy uses the same client.** DoH alone is not SNI hiding. A relay
  that encrypts DNS but forwards an app's plaintext `ClientHello` still exposes
  SNI.
- **It does not change billing or defeat tethering detection.** Those are
  separate problems.

The earlier draft called `hide` "the only no-server privacy win" and placed it
"in the Rust engine" as if it applied to relayed traffic. That was an
overclaim. Correct status: not implemented and closed as unsupported under the
current constraints. A tunnel-wide DoH forwarder with encrypted DNS is a
separate proposed scope and is not approved by this document.

### Mode `cover` (deferred; needs an endpoint the owner controls)

The only way to literally exit through a chosen SNI is a TLS tunnel to an
endpoint that legitimately serves that name and that the owner controls. The
carrier would see one SNI, one destination, and one flow shape for all traffic.

Constraints:

- Domain fronting through other tenants' CDNs is not available. Cloudflare,
  Google, AWS CloudFront, Azure Front Door, and Fastly have enforced SNI and
  Host agreement at various times. Do not borrow another party's name.
- An SNI and IP/ASN mismatch is the fundamental tell of a self-hosted cover.
- TLS-in-TLS is detectable. `cover` reintroduces a nested-handshake signal that
  the byte relay avoids.
- Many-to-one aggregation is a standard proxy heuristic.
- Presenting a carrier-whitelisted or zero-rated service's name is a pricing
  misrepresentation. It is excluded from scope.
- It adds the extra hop the original goal tried to avoid.

Because the owner has no endpoint for this work, `cover` is deferred. No code,
no schema behavior, and no default may depend on it. Keep the name reserved only
in prose.

### Mode `terminate` (out of scope)

The phone or target terminates TLS with a locally minted CA, then re-originates
it. This would let a platform TLS stack use its own ECH or SNI controls.

Costs: a CA installed and trusted on the client, per-host signing, broken
certificate pinning, two TLS sessions, CPU and battery cost, and a
phone-shaped JA4 for desktop traffic. It is a different product with a
different threat model. It is out of scope. Do not build it as a side effect of
`hide`.

## 5. What each mode would defeat, if built

Only the `off` column describes current behavior. Every other column is a
proposal. `hide` is closed as unsupported under the current constraints; its
column describes only what a separately approved product-owned client could do,
not a product capability.

| Signal | `off` (current) | `shape` (proposed) | `hide` (closed; only for a separately approved owned client) | `cover` (deferred) |
|---|---|---|---|---|
| SNI | Visible | Visible | Hidden only on ECH origins and only for flows the chosen client owns | One chosen SNI, if an owned endpoint exists |
| Destination certificate | Visible unless the endpoints negotiate TLS 1.3; the relay does not control this | Same; the relay cannot force TLS 1.3 | Hidden only if the owned client uses TLS 1.3 | Depends on the tunnel's TLS version |
| Destination IP / ASN | Visible | Visible | Visible | One endpoint |
| JA3/JA4 | Visible | Visible | Visible, or the owned client's fingerprint for its own flows | One fingerprint |
| DNS names | Visible, subject to the app's own resolver | Visible | Hidden only for DNS the same client forwards over DoH | Hidden only inside the tunnel |
| Flow size and timing | Visible | Visible | Visible | One profile |
| ECH usage itself | Not applicable | Not applicable | Visible as a rare outer name where used | Not applicable |
| TLS-in-TLS | None | None | None; the relay is not a TLS tunnel | Present |
| TCP/OS fingerprint | Target stack in direct mode; source device stack in proxy mode | Unchanged unless measured at the carrier-facing hop | Unchanged | Unchanged |
| Concurrency and fan-out | Visible | Visible | Visible | Many-to-one |
| Tethering detection signals | Visible and unchanged | Unchanged | Unchanged | Unchanged |
| Billing and service class | Unchanged | Unchanged | Unchanged | Unchanged; no borrowed or zero-rated name |

Two points this table makes explicit:

1. **Tethering detection is multi-signal.** Public vendor material for carrier
   equipment combines TTL with TCP and OS fingerprints, DNS behavior,
   connectivity probes, and volume or flow models. TTL alone was already
   insufficient. No mode here fixes the OS or TCP fingerprint or volume
   heuristics.
2. **Destination privacy is not tethering evasion.** A separately approved
   product-owned client, if ever built, would move the carrier's question from a
   domain name to a CDN and a behavior pattern. It does not change what the plan
   bills, what the account is entitled to, or whether the carrier can infer
   tethering from other signals.

## 6. Cross-platform parity contract (future work)

None of this is implemented. When a mode is built and measured, these are the
parity rules:

1. **One schema and one set of mode names** (`off`, `shape`, `hide`, `cover`)
   in the engine, the desktop apps, the phone apps, and the local page. Do not
   ship a mode name that the build cannot honor.
2. **Capability flags, not silent absence.** The current schema uses
   `supported`, `unsupported`, `unavailable`, and `unverified`. It reports
   `modes.off`, `modes.shape`, `modes.hide`, `modes.cover`, `ech`,
   `sni_override`, and `background_relay` today. A future schema would add
   `encrypted_dns`, `resolver_ech`, and `app_ech`, and would keep the legacy
   `ech` key and its build-mechanism meaning until a schema version updates
   every consumer. `encrypted_dns` and `resolver_ech` are separate
   capabilities; `app_ech` is `app_dependent` and is never a support state.
   This key set is a proposal, not an accepted schema and not implemented. It
   needs the capability contract and consumer migration in
   `experiments/destination-privacy-architecture/WS1_TARGET_ECH_DOH_ARCHITECTURE.md`,
   sections 2.4 and 2.5, before any code. Every current consumer must keep
   working when a new key is absent: `rust/src/diagnostics.rs`, the local page
   (`gui_assets/app.js`), the Linux renderer, the Windows privacy report, and
   the demo tests. A missing key is not support, and a counter key is not an
   implementation. Future platform claims require evidence appropriate to their
   scope; a compile alone does not establish live support.
3. **Shared test vectors.** Test record reframing, ECH config handling, ECH
   config caching, and the proposed resolver-only retry after an authenticated
   rejection once in Rust, hermetically, with no routes and no root. Application
   flows never retry, and an unauthenticated rejection never retries. Phone apps
   test only their transport adapter against recorded fixtures.
4. **Every UI gets the toggle only when the backend exists.** The toggle is
   opt-in, off by default, and labeled with what it does not hide. Do not add a
   disabled or fake toggle to suggest capability.
5. **Documentation follows evidence.** Update `README.md`,
   `docs/TECHNICAL_REFERENCE.md`, `PHONE_PROXY.md`, and the app text only after
   a mode is implemented and measured. The earlier instruction to soften
   README once `hide` exists is withdrawn until that evidence exists. The
   current statement that destinations are visible remains correct.

## 7. Concrete seams

### 7.1 Where the bytes actually flow (code inspection and inference)

- **Target tun plus `--phone`:** the relay sends a numeric IP. `Setup::phone`
  serializes address type 1 or 4, never a domain. Some DNS can bypass the
  tunnel. On macOS and Windows, DNS to the hotspot gateway follows the
  connected-subnet route, a bypass by route-specificity inference, not a live
  DNS measurement. On Linux, a default `systemd-resolved` per-link resolver can
  take the physical-interface rule and table main; treat gateway DNS as a
  likely bypass until a live DNS-specific run. That is the OS resolver path,
  not the `TinyResolver` query. Scoped resolvers, link-local, ULA, multicast,
  NAT64, and application or OS encrypted DNS can also bypass the tunnel. No
  live DNS-specific result exists for any target. Intercepted UDP port 53 is
  redirected to `1.1.1.1:53` over SOCKS command 1 with DNS-over-TCP framing. The
  source device sees the DNS query payload, which carries names in plaintext
  unless the application uses its own encrypted DNS, but it never sees a
  CONNECT hostname.
- **Direct SOCKS5:** tun mode carries DNS through the tunnel as plaintext.
  SOCKS5 mode resolves an ATYP 3 name at the target through `TinyResolver` over
  a normalized plaintext UDP socket pinned to the physical interface. The name
  is visible on the physical link before the connection. This is a documented
  local-resolution leak, not a relayed encrypted path. A client that resolves
  locally before the proxy, including ATYP 1 or 4, has a separate leak. The
  `socks5h` requirement is not enforced by the code. On Linux, interface-scoped
  discovery fails closed because the resolver files are one aggregate list; the
  caller must pass an explicit `--dns-servers`. On macOS, discovery requires an
  unambiguous `scutil` block for the selected interface and rejects a full VPN
  or split-DNS resolver, an mDNS resolver, a loopback stub, and a link-local
  address. An explicit server can still be wrong for the link. The query still
  uses a normalized socket pinned to the physical interface. The outbound
  connection uses a numeric destination, but names can still appear in
  application traffic such as TLS SNI or HTTP.
- **CLI `phone` adapter and `phone.rs`:** these preserve domains, but the tun
  path does not use them. They are used by diagnostics and integration tests.
- **Source device:** iOS uses `NWConnection` and copies bytes. Android uses
  `Socket` and `CellularFlow` and copies bytes. Neither parses TLS.
- **Target engine:** inner pending bytes are written to the outer stream, and
  outer reads become inner payload. There is no TLS object in the data path.

### 7.2 Insertion points

| What | Where | Status and note |
|---|---|---|
| TLS record reframing for `shape` | Target relay first flight; source device destination socket if the source device also reframes | Dormant implementations and tests exist. Product start paths pass no shape policy, so the mode is unavailable. Only plaintext handshake records can be reframed, preserving handshake bytes. |
| TCP segmentation and pacing for `shape` | Carrier-facing socket only: source device destination socket in proxy mode, target outer socket in direct mode | Proposed, not implemented. Target-to-source pacing is not carrier-visible. |
| Laptop TLS client for `hide` | Not present. `normalization::tcp_start` and `tcp_connect` return byte streams, not a TLS client. | Closed as unsupported under the current constraints. A wrapper here would only own connections the engine originates. A product-owned client is a separate optional future proposal. |
| Phone as TLS terminator | iOS accept loop; Android accept loop; per-flow connection | `terminate`, out of scope. |
| Counters | `relay::Counters` to `RelayStats` to diagnostics JSON to service status to app decode | The `ech_*`, `doh_*`, `flows`, and `shaped_*` keys and their zero values exist in `rust/src/diagnostics.rs`. The relay exposes matching `privacy_*` counters, but the data path never increments them. Future counters are proposals. Adding a field follows the same path. A counter key is not an ECH implementation. |
| UI toggle | Engine API, desktop settings, phone settings, local page | Proposed, not implemented. No fake controls. |

### 7.3 Invariants the feature must obey

1. Every outer socket goes through `normalization.rs` or
   `normalization_windows.rs`. Wrap it; never bypass it. Keep `ttl_bad == 0`.
2. No external relay or VPS. `cover` stays deferred until the owner provides an
   endpoint, and it must never be a default.
3. One inner 4-tuple maps to one outer socket. No TLS multiplexing.
4. No `getaddrinfo` on an egress path. Document DNS paths that bypass the
   tunnel, including local client resolution and scoped system resolvers. The
   SOCKS5 `TinyResolver` query is plaintext and pinned to the physical link. It
   is a target-side local-resolution leak. The `socks5h` requirement is not
   enforced by the code.
5. Dependencies stay small. Adding a TLS stack is a reviewed dependency change
   with a stated reason and a committed lockfile.
6. No SNI, host, address, key, or certificate enters a log, status, or
   diagnostics report. The in-memory failure record already holds IP and DNS
   name hints; adding SNI there would expand the privacy surface and needs an
   explicit decision.
7. Tests stay hermetic: loopback, no route, no TUN, no phone, no root. An
   emulator or a VM result is not live evidence.
8. The product must not claim what it cannot do or what it cannot prove.

### 7.4 Reusable TLS work already in the tree

`experiments/tls-transport-spike` provides a test-only TLS 1.3 transport with
pinned mTLS verifiers, ALPN enforcement, a total handshake deadline, no
resumption, one connection per flow, and a hermetic test suite. It uses the
`ring` provider. `ring` has no HPKE, so this spike cannot do ECH as it stands.
It is not product code, it is not a workspace member, and nothing in `rust/`
depends on it. Its IP server name trick is a model for an outer hop, not a way
to hide an inner destination.

## 8. Workstreams

The table is a scope map, not a claim that a workstream or its gates are done.

| # | Workstream | Scope | Gate |
|---|---|---|---|
| WS0 | Measurement and probe | `probe`, diagnostics, status JSON, local page capability output. No behavior change. | Use the existing capability states and report unverified claims as `unverified`. |
| WS1 | Destination-privacy design | Analysis of the client boundary, a possible TLS client, ECH config cache, and DoH resolver; any dependency change needs a reason. | **First deliverable is the client-boundary outcome.** A transparent byte relay cannot inject ECH, so no transparent boundary exists under the current constraints and `hide` is not built. Encrypted DNS and resolver ECH are a separate proposed scope that needs its own product owner acceptance and independent review. No code is authorized by this plan. |
| WS2 | Relay shaping for `shape` | Record reframing and carrier-facing pacing; property tests that handshake bytes survive. | Measure at the carrier-facing hop. Do not claim target pacing reaches the carrier. |
| WS3 | Android source app | Capability row and `shape` control. JSSE and API 37 ECH only if the product later reopens termination. | Termination is out of scope. Do not add terminator code now. |
| WS4 | iOS source app | Capability text and `shape` adapter. No ECH claim. | Foreground-limited. No Network Extension assumption. |
| WS5 | Desktop target apps | Settings and capability rows. Refuse a mode the build cannot honor. | No toggle before the backend exists. |
| WS6 | Docs, tests, CI | Documentation, hermetic tests, and CI gates. | This correction edits only `docs/SNI_HIDING_PLAN.md`. App text, the Windows privacy report, code, tests, CI, and schemas remain untouched. No README, script, CI, app, or engine edit. |

Doc-only note: the Windows privacy report still says the client boundary for the
mode is unresolved. The macOS settings text, the Linux page, and the shared page
also need the reader-facing wording change from P15. None of those files is
updated by this plan correction. They remain a follow-up, and this document does
not claim otherwise.

## 9. Acceptance criteria (future; none met)

These are gates for a future implementation. None is satisfied today.

- WS1 records the client-boundary outcome. A transparent byte relay cannot
  inject ECH, so no transparent boundary exists under the current constraints
  and `hide` is not built. A product-owned client is a separate optional future
  proposal with its own product decision and review; it is not approved here.
- `shape` output reassembles to the original TLS handshake bytes on every test
  vector, and a handshake succeeds against a real server on each claimed
  platform.
- A measurement at the carrier-facing socket shows a change that the target
  parser actually cares about. If the measurement fails, drop the claim.
- Only if a separate product-owned client is ever approved: for flows that
  client owns, `hide` succeeds on an ECH origin and handles a stale config only
  under the independently reviewed authenticated-rejection policy. GREASE alone
  is not `hide`.
- A blocked ECH outer name does not trigger an automatic non-ECH retry on a
  timeout, reset, or certificate failure. A separately selected non-ECH
  profile is labeled as such and is not `hide`.
- `probe` on every platform prints the capability row for that build, using
  `unverified` where the claim is unverified.
- No mode logs host names, SNI values, or ECH configs.
- The README and the technical reference match the behavior table in section 5.
  Until then, the current "destinations are visible" text stays.
- `hide` is never described as defeating tethering detection, and the threat
  model lists OS/TCP fingerprinting and volume heuristics as not addressed.

## 10. Legal and compliance framing (not legal advice)

The legal picture splits cleanly, and the product must keep the split:

- **(A) Keeping destination names private from your own carrier.** ECH, DoH,
  VPNs, and proxies can fall here. In many jurisdictions this is ordinary
  privacy and security behavior. A carrier's terms may still govern VPNs,
  tethering, or plan use. That is a contract question for the owner, settled by
  choosing the plan and reading the terms.
- **(B) Presenting traffic as a different, cheaper service class.** Naming a
  zero-rated service while connecting elsewhere is a pricing
  misrepresentation. It has no privacy benefit. No feature in this plan builds
  it.

The line is deception about pricing, not encryption. A separately approved
product-owned client would be (A). `cover` keeps (B) out of reach because it
connects only to an endpoint the owner controls. `terminate` is out of scope. No
mode changes what the plan bills or claims a service class.

Every feature is opt-in and labeled. The owner is responsible for carrier terms
and local law. This document is not legal advice.

## 11. Open questions

1. **Client boundary for `hide`.** Closed under the current constraints. A
   transparent byte relay cannot inject ECH, so `hide` is not built and stays
   unsupported. App-native ECH is application-dependent and is not a product
   capability. A product-owned TLS client is a separate optional future
   proposal with its own product decision and review; it must not terminate TLS
   or add an external relay. A tunnel-wide DoH forwarder with encrypted DNS and
   resolver ECH is a separate proposed scope that is not approved here and is
   not implemented.
2. **Carrier-facing shape measurement.** Does record reframing or pacing change
   what a real parser sees on the source device's socket? No claim without a
   measurement.
3. **Platform API verification.** Which ECH and SNI APIs exist in the SDKs and
   OS versions actually targeted? Check headers and builds before any matrix
   row becomes a support claim.
4. **iOS background.** The current relay is foreground-limited in practice.
   Pursuing a Network Extension is not planned here. Any change is a new owner
   decision.
5. **Whether an explicit client surface is in product scope.** A built-in
   client would make `hide` meaningful but changes the product shape and the
   privacy story. This is a separate optional future product proposal, not
   approved by this plan and not a blocker for closing `hide`.
6. **ECH failure policy (answered for the proposed design only).** This answer
   is not implemented and authorizes no code. The only detectable failure is an
   authenticated ECH rejection on a future resolver connection. There is no
   time-based wait. A timeout, reset, certificate failure, 5xx, parse error,
   SERVFAIL, or unauthenticated rejection never causes a non-ECH retry.
   Application flows never retry. The resolver connection retries at most once,
   only after an authenticated rejection, with retry configs, or with ECH
   disabled when no supported retry config exists. A non-ECH application flow
   is a profile chosen before connecting, not a retry.

## 12. Claim ledger for this checkpoint

Changed from the earlier draft:

- "`hide` is implemented in the Rust engine" changed to "not implemented and
  closed as unsupported under the current constraints."
- "Wrap the normalized stream" changed to "a byte stream wrapper is not an
  application TLS client."
- "`shape` pins TLS 1.3" removed. A byte relay cannot force TLS 1.3.
- "TCP segmentation and pacing on the relay socket" changed to "measure at the
  carrier-facing socket; target pacing does not control the source device
  stack."
- "`cover` is a research path" changed to "deferred without an owner endpoint."
- "`terminate` is not recommended" changed to "out of scope."
- "Every UI gets the toggle" changed to "only when the backend exists."
- The instruction to soften README's DPI text is withdrawn until evidence
  exists.
- "Counters are proposed, not implemented" corrected to "the `ech_*` and
  `doh_*` counter keys and zero values exist and are dormant; the data path does
  not write them."
- "DNS is UDP" corrected to "DNS uses UDP and TCP; the tunnel DNS path is
  plaintext today."
- Gateway DNS bypass wording corrected to a route-specificity inference on
  macOS and Windows, a likely bypass on a Linux link-bound resolver, with no
  live DNS-specific result.

Unchanged and still true today:

- HotspotShade does not hide SNI, DNS names, destinations, TLS fingerprints, or
  destination IP and ASN.
- TTL normalization does not defeat DPI, TLS inspection, tethering detection,
  or traffic analysis.
- Direct mode defaults IPv6 to block. Source device proxy mode forwards IPv6.
- There is no external relay, VPS, cloud hop, or VPN protocol.

Verified in this tree:

- The target relay copies bytes and has no TLS parser.
- The tun plus `--phone` path sends numeric IPs, not domain names.
- No enabled ECH, SNI override, or mode implementation exists.
- No TLS client dependency exists in the engine.
- Dormant `ech_*` and `doh_*` counter keys and zero values exist in
  `rust/src/diagnostics.rs`; the data path does not write them.
- Dormant `tls_shape` code exists, and the product start paths pass no shape
  policy.
- The iOS app uses the idle timer and an optional background keep-awake, not a
  Network Extension.

Unverified:

- All platform ECH and SNI API availability claims.
- All ECH deployment percentages and vendor statistics.
- The domain-fronting enforcement history in section 4 and the general
  detectability of TLS-in-TLS.
- The behavior of any carrier parser against reframed records.
- The reliability of iOS background relay after screen lock or long use.
- The exact `rustls`, `aws-lc-rs`, or resolver versions and their HPKE support.
- Any performance, battery, or memory effect.
- Any claim that `hide` can cover ordinary application traffic.
- Any live DNS-specific result on any target. The Linux link-bound resolver
  bypass is a hypothesis.
- The RFC text itself was not re-read in this checkpoint.
