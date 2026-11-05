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
- No credential exposure. The source device token never goes to the browser, a log, a status report, or a diagnostics report.
- No support claim from a compile, a demo, an emulator, or a VM test alone.

## Constraints

- Follow every invariant in [AGENTS.md](AGENTS.md).
- Ask the maintainer before a live test or a device install.
- Do not commit secrets, identity keys, `wintun.dll`, or personal traffic.
