# Product goal

HotspotShade is a prototype normalizer for hotspot traffic. It runs on the target device, the machine that needs internet. It re-originates each tethered IPv4 flow with TTL 65 and pins every outer socket to the physical hotspot interface. If the source device NAT decrements the TTL once, the carrier is expected to see 64, which is the native source device value. The direct mode needs no app on the source device. An optional source device app for iOS and Android serves carriers that throttle the hotspot bearer. There is no external relay, VPS, or VPN protocol.

## Goal

Make HotspotShade a finished product that a person can install on a source device and a target device and use without technical setup. The apps find each other on the hotspot, pair once, stay connected, and make tethered traffic match native source device traffic at the IP and TTL layer. The person does not compare ports, copy tokens, or read debug text.

Phones are source devices. Desktops are target devices. Each phone app must match the source feature set. Each desktop app must match the target feature set. Verify every supported phone and desktop combination end to end before claiming support. The production task list and evidence requirements are in [docs/MULTIPLATFORM_ROADMAP.md](docs/MULTIPLATFORM_ROADMAP.md).

## What a person does

1. Install the app on the source device and the app on the target device.
2. Open both apps. They find each other on the hotspot and pair by a code.
3. Press one button on the target device to turn the tunnel on. Press it again to turn it off.
4. Read the status on the target device to see what works or what to fix.

## Success criteria

- Pairing works without manual addresses, ports, or tokens. The source device picks a random proxy port and tells the target device. Cancel and Forget behave as documented.
- The source device app stays alive in the background by default and explains its status in plain text.
- The target apps show real service state. They do not claim success from stale data, a demo, or a simulated preview.
- Opening a target app and using its ordinary interface must not require administrator privileges. Ask for them only when an operation actually needs them, such as installing the protected helper or starting the tunnel and changing routes. Pairing, settings, and viewing status must remain usable without an administrator prompt.
- The tunnel turns itself off when the hotspot link or the source device is gone. Nothing restarts it by itself.
- Ping works in source device proxy mode, and the apps say whether it is on or off.
- Failures and stalls are inspectable on the target device without exposing tokens, keys, addresses, or personal traffic.
- Hermetic tests, CI, and Rust and Swift parity tests protect the work.
- Each supported platform is verified on real hardware before support is claimed.

## Non-goals

- No external relay, VPS, cloud hop, or VPN protocol. The source device NAT is the terminator.
- No fail-closed guarantee. More-specific routes, local DNS, and network extensions can bypass the tunnel.
- No claim to defeat deep packet inspection, TLS inspection, or traffic analysis.
- No Python code, scripts, or dependency.
- No persistent proxy and no automatic restart after a loss.
- No source device app requirement for direct mode. The optional source proxy must not replace or weaken direct mode.
- No credential disclosure by the service. The service never sends the source
  device token to the browser, a log, a status report, or a diagnostics report.
  The manual fallback accepts a token typed by the person into the browser and
  sends it to the service; it does not return the stored token.
- No support claim from a compile, a demo, an emulator, or a VM test alone.

## Destination privacy proposal (not available)

The current goal normalizes IP and TTL. It does not hide destinations. A
separate proposal, [docs/SNI_HIDING_PLAN.md](docs/SNI_HIDING_PLAN.md), studies
destination-name privacy. Experimental ClientHello reframing code exists but
is disabled and unavailable as a product control. It does not hide names.

Settled scope for that proposal:

- Application-wide `hide` is unsupported: the byte relay cannot add ECH to
  another application's TLS handshake. Encrypted DNS is a separate,
  unapproved proposal and would not add ECH to application traffic.
- `shape` is experimental and unavailable. Reframing does not hide the server
  name, destination address, DNS, flow size, or timing.
- `cover` is deferred. Do not build it without an endpoint the owner controls,
  and it must not add a third-party relay or VPS.
- `terminate`, TLS interception with a locally trusted CA, is out of scope.
- The iOS source relay is foreground-limited in current practice. Do not claim
  sustained background relay.
- Every feature, if built, is opt-in and labeled. The owner is responsible for
  carrier terms and local law.
- Destination privacy is separate from billing and tethering detection. No
  proposal changes what the plan bills or claims to defeat DPI, TLS inspection,
  or traffic analysis.

Ordinary applications originate their own TLS. The engine cannot make an
existing ClientHello use ECH, and a byte relay cannot force TLS 1.3. A separate
product-owned TLS client would need its own proposal and review; it would not
protect other applications' connections. The non-goals above remain true.

## Constraints

- Follow every invariant in [AGENTS.md](AGENTS.md).
- Ask the maintainer before a live test or a device install.
- Do not commit secrets, identity keys, `wintun.dll`, or personal traffic.
