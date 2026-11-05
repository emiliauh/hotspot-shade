# Contributor guide

HotspotShade is a prototype normalizer for hotspot traffic. It runs on the target device, the machine that needs internet. It re-originates each tethered IPv4 flow with TTL 65 and pins every outer socket to the physical hotspot interface. If the source device NAT decrements the TTL once, the carrier is expected to see 64, which is the native source device value. The direct mode needs no app on the source device. An optional source device app for iOS and Android serves carriers that throttle the hotspot bearer. The project has no external relay, VPS, or VPN protocol.

The goal in one sentence: make tethered traffic match native source device traffic at the IP and TTL layer, on every supported platform, without an external hop.

This guide is for anyone who changes code, tests, or documentation. Read `GOAL.md` for the product goal and non-goals. Read `README.md` for setup and measured results, `docs/TECHNICAL_REFERENCE.md` for the architecture and threat model, `PHONE_PROXY.md` for the source device proxy, and `docs/MULTIPLATFORM_ROADMAP.md` for the production plan.

The project is a prototype and a research tool. It is not fail-closed. More-specific routes, local DNS, and macOS network extensions can bypass the tunnel. Do not describe it as fail-closed.

## Writing style

Write plain, direct English. Use short sentences and active voice. Use "outer socket", "inner flow", and "hotspot" in code comments and developer documentation. Use "source device" and "target device" in text that a person reads, including UI text and user documentation. Keep code identifiers and wire labels unchanged, including `laptop` in the key schedule. Avoid marketing words, emojis, and em dashes. Use straight quotes and ASCII hyphens.

## Repository layout

- `rust/` holds the engine and the command line tool. The platform code is behind `cfg` gates. The browser GUI server is `rust/src/gui.rs`.
- `ios/` holds the iOS source device app, HotspotShade, in Swift. The internal target name stays `HotspotProxy`.
- `android/` holds the Android source device app in Kotlin, with a Compose UI, a source proxy foreground service, and a pairing responder.
- `macos/` holds the macOS target app in SwiftUI. It contains the Rust engine in its `.app` bundle.
- `windows/` holds the WinUI 2 target app work. The current app is a simulated preview and does not connect to the engine.
- `linux/` holds the Electron target app. It starts the packaged engine through a pkexec helper.
- `gui_assets/` holds the HTML, CSS, and JavaScript for the local control page. The Rust binary embeds them.
- `desktop/` holds the shared desktop demo. It uses simulated data and does not control the real service.
- `assets/logo/` holds the logo sources and generated app icons. The GUI embeds the favicon from this directory.
- `scripts/` holds POSIX shell tooling. `docs/` holds the technical reference, roadmap, and Linux test procedure.
- **The project has no Python.** Do not add Python code, scripts, or a dependency anywhere. The earlier Python implementation is in git history at commit `f5cfd68`. Use it as a design reference only.

## Platform status

| Platform | Status |
|---|---|
| macOS 14+ arm64 target | Implemented and verified on a live hotspot. The release app is arm64 only. |
| macOS target app | Implemented. It has one main window, a Settings window, a native menu bar, notifications, and a demo mode. CI builds the unsigned `.app` bundle. |
| Windows 10/11 target | **Source device proxy start path implemented. Live tunnel not verified.** The CLI and the command-line GUI start the tunnel in source device proxy mode. The path loads Wintun from an explicit absolute path, uses the Windows normalized socket helpers, installs the two IPv4 `/1` routes and the IPv6 `2000::/3` route with ownership proof, and removes them on every exit path. Direct mode, pairing in the Windows GUI, the WinUI service boundary, and a live Windows test are still open. Commands that Windows does not provide return `The tunnel is not implemented on Windows.` The WinUI app is a simulated preview and does not connect to the engine. |
| Linux target | **Direct mode and source device proxy mode start paths implemented and VM-tested. The Electron app starts the packaged engine through a pkexec helper and provides the macOS target features.** A disposable VM test passed direct IPv4 flows with a clean TTL audit, a verified IPv6 block, an explicit IPv6 forward start, source device proxy TCP and IPv6 flows, a SIGTERM stop, a SIGKILL run, and automatic stop after the hotspot link went down. The tests restored the routing state and left no link, rule, route, or TUN device. The app has a tray item, notifications, XDG launch at login, a separate Settings window, light, dark, and high contrast themes, and an in-tree accessibility check. A live hotspot test, direct mode in the app, and a polkit prompt on a real desktop are still needed. |
| iOS source device app | Implemented. CI builds an unsigned IPA. The current build still needs a device test and cross-platform live tests. Background operation is subject to iOS limits. |
| Android source device app | **Source proxy, pairing responder, and wired app UI implemented and VM/emulator-tested.** The app UI starts and stops the real foreground service, shows the real state and connection counts, and changes the real trust list and token. A disposable VM built and tested the app. The real Rust target client paired with the Android responder on the Pixel 8 API 36 emulator, with a prompt for the first pairing and no prompt for the known key. The source proxy serves the private ICMP echo commands with an unprivileged ICMP datagram socket, forwards IPv6 CONNECT and UDP destinations through the selected cellular network, and applies the phase-aware session capacity from the iOS app. The Rust target client completed a 64 KiB TCP echo, an ICMP echo, and an IPv6 destination through the source server on the emulator. The Android target tunnel is not implemented. A real phone, carrier, and hotspot test is still needed. |
| Shared browser GUI | Implemented in `rust/src/gui.rs` and `gui_assets/`. It has demo mode, pairing, status, diagnostics, and failures. It binds to `127.0.0.1` only. |

## Architecture invariants

Do not break these rules. They are the reason the design works.

1. **Every outer socket goes through the normalized helpers.** Use `tcp_start`, `tcp_connect`, and `udp_socket` in `rust/src/normalization.rs`, or the code that wraps them. Every outer socket sets TTL 65. Interface pinning is on by default. `--no-pin` is diagnostic only. Do not create a raw egress socket in a data path. The TTL read-back audit must keep `ttl_bad == 0` during tests. This is the core of the design: one decrement from the source device NAT gives the native value.

2. **No external relay or VPS.** The source device NAT is the terminator. Do not add a remote endpoint, a tunnel server, or a cloud hop. The direct mode depends on the source device's own source NAT and single TTL decrement. An external hop changes the traffic shape and adds a failure point.

3. **The direct mode has no source device app.** Do not add an iOS or Android app to the direct path. The optional source device proxy in `ios/` and `android/` is a separate mode. It must not replace, weaken, or bypass the direct mode. It must keep token authentication and must bind its listener to the local hotspot only. The pairing listener on TCP port 18090 follows the same rule. It runs while the source device app is open and the hotspot interface is present. This keeps direct mode usable for people who do not install a phone app.

4. **DNS must not leak through mDNSResponder.** Tun mode forwards inner UDP:53 to the original destination or to `--dns-upstream` over a normalized socket. SOCKS5 mode uses `TinyResolver` and requires `socks5h` or remote DNS from the client. Never call `getaddrinfo()` on an egress path. Client-side local resolution is a documented leak. Do not describe it as fixed. The reason is that a name resolved before the tunnel leaves the target device outside the normalized path.

5. **The IPv6 policy stays explicit.** In direct mode `--ipv6 block` is the default. Keep it. `--ipv6 forward` is explicit in direct mode. In source device proxy mode IPv6 is always forwarded through the source device. This is a deliberate product choice: IPv6 must work in that mode. The mode rejects `block` and `inherit`. Every IPv6 flow still uses a normalized outer socket, and the TTL audit applies unchanged. `--ipv6 inherit` is an explicit leak path and must not become the default. Do not route `2000::/3` outside the tunnel unless someone asks for `inherit`. The reason is to avoid silent bypasses and to make the policy visible.

6. **Route cleanup runs on every exit path.** Use guards that clean up on drop. Keep stop idempotent. Remove every route, address, and device that the process created. Handle SIGINT and SIGTERM. Do not add an exit path that skips cleanup. A failed or inconclusive route check must not leave owned routes behind. If a cleanup ownership check is inconclusive, do not delete a route that might belong to another process. Report the failure and close the owned device so the operating system can remove its device-bound routes. Do not assume that device cleanup removes device-independent routes. The reason is that a failed or crashed tunnel must not break the host network.

7. **One inner 4-tuple maps to one outer socket.** Do not multiplex unrelated inner flows over one outer connection. That shape is a tunnel fingerprint, and it breaks the one-flow-one-socket model that the design depends on.

8. **Keep the platform boundary.** macOS uses `utun` and the AF header. Windows uses Wintun and raw IP frames. Linux uses `/dev/net/tun` and raw IP frames. Gate platform code with `cfg`. A change for one platform must not break the CI job of another. The reason is that the packet framing and the privilege model differ on each platform.

9. **Keep dependencies small.** The Rust dependencies are `libc`, `serde`, `serde_json`, `signal-hook`, `hmac`, `sha2`, `hkdf`, `chacha20poly1305`, `x25519-dalek`, and `zeroize`. The pairing code uses X25519 key agreement and clears temporary secrets with `zeroize`. The separate `desktop/` demo uses Tauri for its window, embedded assets, and demo IPC. It has its own lockfile and a larger dependency tree. Native Windows and Linux desktop apps can use the platform dependencies they need. State the reason and measure runtime cost. Add a dependency only with a stated reason. Commit each `Cargo.lock`. CI builds with `--locked`. The reason is to keep the trusted surface small and the build reproducible.

10. **The GUI uses the service.** Do not shell out to the CLI from the GUI. Use the service backend. The service may start its own binary as the privileged helper, and nothing else. Keep the listener on `127.0.0.1`. The reason is one control path, one privilege boundary, and no command injection surface.

11. **Pairing never sends the source device token to the browser.** The service pairs with the source device in `rust/src/pairing.rs` and holds the credentials in memory. The manual token field is a fallback that sends a token typed by a person to the service. The service never sends a token back. No status, log, error text, or Debug output holds the token or the identity key. `/api/status` reports pairing and source device presence without credentials. The pairing target is the discovered gateway, never a host from the browser. The reason is that the browser is the least trusted part of the target device.

12. **Protect the desktop engine API.** Pass a per-launch bearer secret on a descriptor, never on a command line. The engine must shut down gracefully when its parent descriptor closes. The reason is that a local process must not be able to take over the engine or keep it alive after the app exits.

13. **No persistent proxy.** The tunnel turns itself off when the hotspot link is gone or the source device is gone. Do not add a keep-running or auto-restart behavior. The reason is that a stale tunnel sends traffic into a dead path and hides the failure from the person using the device.

## Continuous integration

CI is `.github/workflows/ci.yml` on GitHub Actions. It is a second, independent check of your local result. Use it that way.

| Job | Runner | What it does |
|---|---|---|
| `rust-macos` | `macos-latest` | `cargo check --all-targets --locked`, `cargo test --locked`, release build, GUI smoke test. Uploads the macOS binary as `hotspotshade-macos-arm64`. Required. |
| `macos-app` | `macos-latest` | Builds the demo engine, runs the Swift package tests, builds the unsigned app bundle. Uploads `HotspotShade-macos-unsigned`. |
| `ios` | `macos-latest` | iOS logic tests, simulator build, unsigned IPA. Uploads `HotspotShade-iOS-unsigned-ipa`, which holds `HotspotShade-iOS-unsigned.ipa`. Required. |
| `rust-windows` | `windows-latest` | Type check, tests, and clippy for Windows code, including the hermetic Windows tunnel start tests. It creates no adapter or route and does not prove live tunnel support. Required. |
| `rust-linux` | `ubuntu-latest` | Type check, full hermetic test suite, clippy, mock VM cleanup, and Linux Electron Node tests and sandboxed webview smoke test. Required. It does not create a TUN device or prove live tunnel support. The Settings window and accessibility checks run in a VM, not in this job. |
| `desktop-demo` | `macos-latest` | Rust bridge and asset tests, JavaScript shim, page model and browser failure-report tests, hidden-webview smoke test, clippy, and formatting. Required. |
| `desktop-windows` | `windows-latest` | Build and test the shared desktop demo. It does not test a Windows tunnel. Required. |
| `winui-demo` | `windows-2025` | Test the WinUI demo state model and source contracts, and build the unsigned UWP app. It does not deploy or run the app. Required. |
| `android-demo` | `ubuntu-latest` | Run the Android JVM tests, lint, and a debug build. It does not run an emulator or test networking. Required. |
| `lint` | `macos-latest` | `cargo clippy --all-targets --locked -- -D warnings` and `cargo fmt --check`. Required. |
| `release` | `ubuntu-latest` | On a `v*` tag, attaches the unsigned IPA, the macOS binary, and the unsigned target device app to a GitHub Release. It needs `rust-macos`, `rust-windows`, `rust-linux`, `desktop-demo`, `desktop-windows`, `winui-demo`, `android-demo`, `ios`, `macos-app`, and `lint`. The IPA asset is `HotspotShade-iOS-unsigned.ipa`. |

Rules for CI:

- After you push, read the result. Run `gh run watch` and then `gh run view --log-failed`. Fix the failure. Do not disable a job, delete a test, or add `continue-on-error` to make CI pass.
- Keep every job hermetic. A job must not change routes, create a tunnel device, or need a source device.
- Do not trust a local pass over a CI failure. Find the cause of the difference. Runner OS and Xcode versions can differ from a local machine.
- Keep the Windows CI status separate from live tunnel support. Update the platform status here and in `README.md` when that support changes.
- Never put a certificate, a provisioning profile, a token, or a secret in the workflow or in an artifact. The IPA is **unsigned**. You sign it with your own certificate.

## Test commands and expected results

Run these commands from the repository root.

| Command | Expected result |
|---|---|
| `cargo check --all-targets --locked --manifest-path rust/Cargo.toml` | No errors. |
| `cargo check --target x86_64-pc-windows-msvc --all-targets --locked --manifest-path rust/Cargo.toml` | No errors. It type-checks the Windows target and does not build a tunnel. Run `rustup target add x86_64-pc-windows-msvc` first. |
| `cargo clippy --target x86_64-pc-windows-msvc --all-targets --locked --manifest-path rust/Cargo.toml -- -D warnings` | No findings. It compiles the Windows tests but does not run them. |
| `cargo check --target i686-pc-windows-msvc --all-targets --locked --manifest-path rust/Cargo.toml` | No errors. The Windows socket layouts support x86. |
| `cargo test --locked --manifest-path rust/Cargo.toml` | All tests pass: the unit tests plus the `relay_e2e`, `speed_diag_cli`, `udp_diag_cli`, `gui_lifetime`, and `windows_unsupported` integration tests. On macOS this also runs the hermetic Windows tunnel start tests with a fake device and a fake route controller. |
| `cargo build --release --locked --manifest-path rust/Cargo.toml` | Builds `rust/target/release/hotspotshade`. |
| `scripts/gui_smoke.sh rust/target/release/hotspotshade` | Prints `GUI smoke test passed`. |
| `cargo test --locked --manifest-path desktop/Cargo.toml --features webview-smoke --test webview_smoke` | Checks the demo in a hidden macOS webview. Needs a graphical session. |
| `swift test --package-path macos/HotspotShadeKit` | Runs the target app Swift package tests. |
| `scripts/build_mac_app.sh build/HotspotShade-unsigned.zip` | Builds the unsigned target app bundle. |
| `scripts/swift_tests.sh` | Prints `ALL SWIFT TESTS PASSED`. Needs macOS and Xcode. |
| `cargo test --locked --manifest-path rust/Cargo.toml pairing` | Runs the pairing parity vectors and the mock source device tests. |
| `scripts/build_ipa.sh build/HotspotShade-iOS-unsigned.ipa` | Writes an unsigned IPA. Needs macOS and Xcode. |
| `rust/target/release/hotspotshade probe` | Prints the numeric account id, the default interface, the system IPv4 DNS servers, the TTL of one UDP socket, and the count of audit failures, then a privilege line. It detects no transparent proxy. On Windows it prints the elevation state in place of the account id and DNS servers. |
| `bash -n scripts/*.sh` | No output. Exit code 0. |
| `cd linux && npm test` | 127 Node tests pass. |
| `cd linux && xvfb-run -a npm run test:settings-window` | Checks the separate Settings window. |
| `cd linux && xvfb-run -a npm run test:a11y` | Prints `"ok": true` with 0 rule violations for 9 page states and 8 keyboard focus stops. |
| `cd linux && ARCH=x64 npm run package:deb` | Writes one unsigned `linux/build/hotspotshade_0.1.0_amd64.deb` on a Linux host with `dpkg-deb`. |
| `cd android && ./gradlew testDebugUnitTest lintDebug assembleDebug` | 217 JVM tests pass. Lint has 0 errors and 7 warnings. Builds `android/app/build/outputs/apk/debug/app-debug.apk`. |

`cargo clippy --all-targets --locked -- -D warnings` and `cargo fmt --check` pass today. The `lint` job is required. Do not add new findings.

## Safety rules

- **Use the emulators for development tests.** Use the available iOS Simulator and Android Emulator for UI, pairing flow, lifecycle, and mocked-network tests. An emulator or a mocked network does not prove carrier, hotspot, or physical-device behavior. Say so in every result. Installing on a personal phone still needs the device owner's approval.
- **Do not change routes or create a utun in tests.** The tests and the smoke test must stay hermetic. Use the mock tunnel device, loopback servers, and the demo backend.
- **Do not start or stop a tunnel that someone is using without being asked.** If a tunnel is running, the source device app is its other end. A restart of either one cuts the connection that may be in use.
- **Ask before a live test.** The scoped diagnostics (`phone-udp-diag`, `phone-speed-diag`) change no route, but they need the source device token. Take the token from a private prompt or a private descriptor. Never from a command line.
- **Ask before a phone install.** Explain the build, the device, the effect on the existing app and stored trust, and the rollback. Wait for the device owner's approval before installing or replacing a build on a phone. See `docs/MULTIPLATFORM_ROADMAP.md` for the broader device and live-test rules.
- **Remove what you create.** If you add a route, address, utun, TUN device, or child process during a manual test, remove it before you finish. Check `route -n get`, `netstat -rn -f inet`, and `ifconfig` after cleanup.
- **Never commit secrets.** Do not commit tokens, passwords, private keys, certificates, provisioning profiles, carrier account data, or full packet captures with personal traffic. Test vectors must be fixed public values, not real secrets.
- **Never commit an identity key.** The target device pairing key lives at `$HOME/Library/Application Support/hotspotshade/identity.key`. Tests use fixed public vectors or temporary directories.
- **Never commit `wintun.dll`.** The project does not bundle it.
- **Do not edit probe evidence.** Files under `probes/` are measurement records. Add a new file if you need new evidence.
- **Do not use `kill -9` on the tunnel.** Send SIGINT or SIGTERM so the cleanup path can remove routes and close the device.
- **Do not expose the GUI or SOCKS5 listener.** Both bind to `127.0.0.1`. The GUI can require a bearer secret.
- **Windows changes need a Windows host.** The `rust-windows` CI job is a compile and test signal. It is not proof that the tunnel works.
- **Windows Developer Mode:** The maintainer authorizes temporary Developer Mode on the Windows test host for development and testing. Record the prior settings and restore them after the work. Follow any tool policy that requires confirmation at action time.

## Platform notes

### macOS

- There is no `/dev/utun`. Use the AF_SYSTEM and SYSPROTO_CONTROL path in `rust/src/platform.rs`.
- The data frame is `[4-byte big-endian address family][IP packet]`. `AF_INET` is 2. `AF_INET6` is 30. The header is not a length. A write without the prefix is silently not delivered.
- The interface name comes from `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`. Do not read it from the packet fd.
- Creating a utun needs root. TTL normalization and `socks5` mode do not.
- `IP_TTL` above 64 is allowed without root on macOS. Do not assume a Linux privilege requirement for this socket option. Verify it on the target kernel.
- Use the two `/1` routes. Do not replace the default route.
- A transparent TCP proxy can intercept flows before the utun. `probe` does not detect one. Check for VPN clients when the flow counters stay at zero.

### Windows

- The Windows source device proxy start path is implemented in `rust/src/service.rs` and `rust/src/platform_windows.rs`. The CLI command is `hotspotshade tun --phone <gateway>:<port>`. The `gui` command uses the same mode with the manual source device fields. The WinUI app is still a simulated preview and does not connect to the engine. Direct mode and pairing in the Windows command-line GUI are not implemented. A live Windows hotspot test is still needed. The `rust-windows` job compiles and tests the code only.
- Do not bundle or commit `wintun.dll`. The loader takes an explicit absolute path. The default is `wintun.dll` next to the executable. `--wintun PATH` selects another path. The file name must be `wintun.dll`. A missing file is a plain not-found error that names the path. The loader uses `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR` and `LOAD_LIBRARY_SEARCH_SYSTEM32`. It does not search `PATH` or the current directory. Treat the install directory as trusted.
- The tunnel needs Administrator rights. There is no Windows privileged helper yet. The CLI and the command-line GUI run the engine in the elevated process. Keep the protected service boundary open for the WinUI app.
- The start path opens the Wintun adapter, sets the IPv4 address and MTU with `netsh`, and installs two IPv4 `/1` routes and the IPv6 `2000::/3` route with `CreateIpForwardEntry2` in `rust/src/windows_native_routes.rs`. Before every create and delete, the route boundary proves the retained adapter LUID and GUID. A mismatch fails closed and keeps the route record. Do not delete a route on an adapter that the process cannot prove. A read-only route check against the live Windows routing table is still open.
- Every outer socket uses `rust/src/normalization_windows.rs`. It sets TTL 65, pins with `IP_UNICAST_IF` (index in network byte order) or `IPV6_UNICAST_IF` (index in host byte order), and reads the TTL back. `ttl_bad` must stay 0.
- TCP keepalive uses `SIO_KEEPALIVE_VALS` with whole milliseconds. Windows fixes the probe count at 10 and cannot read the time values back. The helper reads back `SO_KEEPALIVE`. The source device values are 60 seconds idle and 10 seconds interval, so the Windows dead-peer age is about 160 seconds. This differs from the 90-second macOS and Linux value. Document it.
- The relay is portable. The worker reads and writes raw IP frames through the Wintun session and uses the portable relay and `WSAPoll` readiness code.
- Cleanup removes the routes first and closes the adapter second. Drop guards, idempotent stop, and a console control handler cover normal stop, Ctrl-C, console close, logoff, and shutdown. Do not use `kill -9` equivalents.
- A failed route install removes the routes that the call created. A cleanup failure sets `cleanup_blocked`, and a later start refuses until a person inspects the routing table.
- Windows has no hotspot link observer yet. The CLI source device probe stops the tunnel after continuous silence. Hotspot loss alone does not stop the Windows CLI tunnel. Do not claim full automatic stop on Windows.
- `hotspotshade probe` is read-only on Windows. It reports the elevation state, the default interface, one UDP TTL, and the audit count. It creates no adapter and changes no route.

### Linux

- The Linux start path is in `rust/src/service.rs` and `rust/src/platform_linux.rs`. The CLI command is `sudo hotspotshade tun [--iface NAME] [--ipv6 block|forward]`. Direct mode has no source device. Source device proxy mode uses `sudo hotspotshade tun --phone <gateway>:<port>`.
- The tunnel uses `/dev/net/tun` with `TUNSETIFF` and `IFF_TUN | IFF_NO_PI`. The kernel returns raw IP packets. There is no address-family prefix.
- The start path installs two IPv4 `/1` routes in table 700, two policy rules for each family at priorities 17000 and 17001, and one IPv6 route in table 700. Rule 17000 sends a socket that is bound to the physical interface to table main. Rule 17001 sends every other output packet to table 700.
- Every outer socket sets `SO_BINDTODEVICE` and TTL 65 in `rust/src/normalization.rs`. `ttl_bad` must stay 0.
- Direct mode accepts IPv6 block and forward. Block is the default. The start gate reads table 700, proves the recorded `2000::/3` blackhole, and requires every default probe to select a non-unicast FIB entry. The kernel reports a blackhole FIB entry as `EINVAL`. Direct mode rejects inherit, `--no-pin`, and `--no-routes`. Source device proxy mode always forwards IPv6.
- The worker checks the physical link every 2 seconds with `platform_linux::link_ready`. After 20 seconds without the link, it stops, removes the routes, rules, address, and TUN device, and records the reason `hotspot_lost` in the service status.
- A cleanup failure sets `cleanup_blocked`. A later start refuses until a person inspects the routing table. Route and rule ownership is recorded and checked, but Linux gives an object no creator identity. Do not describe the ownership proof as complete.
- The `rust-linux` CI job compiles and runs hermetic tests. It creates no TUN device and changes no route. A live Linux hotspot test is still open.
- The Electron app in `linux/` is the Linux target app. It starts the packaged engine through `pkexec` and keeps the window, renderer, and engine client unprivileged. The helper is `/usr/lib/hotspotshade/hotspotshade-helper`. The engine is `/opt/hotspotshade/resources/engine/hotspotshade`. The app calls `pkexec` with the helper path and no other argument. A packaged launch asks for authorization before the engine starts. The secret goes on helper stdin, and the helper starts the engine with the secret on descriptor 3 and the liveness channel on descriptor 4. The helper accepts no argument. The polkit action is `local.hotspotshade.tunnel` with `auth_admin_keep`. The helper sets `HOME` to `/var/lib/hotspotshade`, so the root engine keeps its identity key there. The app never reads that key.
- The app refuses to start as root. Start it as the signed-in desktop account.
- A packaged build needs no `--engine` setting. A development build uses `--engine` or `HOTSPOTSHADE_ENGINE` and starts the engine directly. Engine demo mode (`--engine-demo` or `HOTSPOTSHADE_ENGINE_DEMO=1`) is unprivileged and needs no helper.
- The app has a tray item with Start, Stop, Open, and Quit. Electron uses StatusNotifierItem when the desktop provides a status notifier host. When the tray is absent, the app continues without it and a window close quits. When the tray is present, a window close hides the window and the tray keeps the app alive.
- Desktop notifications cover automatic stop reasons, pairing results, and engine loss. The app setting controls them. Each kind is limited to one message in 60 seconds. A person stopping the tunnel sends no message. Demo data sends no message. A notification click opens the main window.
- Launch at login in a packaged build writes one file at `${XDG_CONFIG_HOME:-$HOME/.config}/autostart/hotspotshade.desktop`. The write uses a temporary file and a rename. The remove path is one unlink. The setting reads the real file state. `HS_AUTOSTART_DIR` is a test override.
- The Settings window is a second BrowserWindow with the same sandbox and the same fixed IPC. It loads the same page with `--hs-window-kind=settings`. The page hides the sidebar and shows General, Pairing, and Advanced.
- The page follows the system light and dark preference. It also follows `prefers-contrast: more` and `forced-colors: active` through a high contrast token layer. Do not hard-code component colors.
- `cd linux && npm test` runs 127 Node tests. `xvfb-run -a npm run test:settings-window` checks the second window. `xvfb-run -a npm run test:a11y` runs the in-tree axe-style rules over 9 page states and 8 keyboard focus stops. It is not axe-core.
- `linux/scripts/package-deb.sh` builds one unsigned `.deb`. It uses the committed Rust and npm lockfiles and `@electron/packager`. The package holds the app, the engine, the helper, the polkit action, the desktop entry, and the icon. The package is unsigned. The remove path keeps user settings and the autostart file.
- A live hotspot test and a polkit prompt on a real GNOME, KDE, or tiling desktop are still open. The VM had no polkit daemon, DBus session bus, or status notifier host. A demo engine, a fake helper, or an Xvfb run does not prove tunnel or desktop integration support.

### Android source app

- The app is Kotlin in `android/`, with a Compose UI, a source proxy foreground service, and a pairing responder. The Android target tunnel is not implemented.
- The app UI controls the real source proxy. The Start control starts `SourceProxyService` and asks for the notification permission on Android 13 or later. The Stop control stops the service. The Dashboard shows the real controller state, and the usage card shows the real `SourceSocksServer` connection counts. The state report holds no token, address, or host.
- `SourceSocksServer` serves TCP CONNECT, the UDP-over-TCP command `0x80`, and the private echo commands `0x81` and `0x82`. It accepts IPv4 and IPv6 destinations and resolves a name through `NetworkResolver` on the selected network only. The echo path uses an unprivileged ICMP datagram socket bound to that network. The wire format, status codes, target rules, 5 second request bound, 30 second echo idle window, 300 second echo lifetime, and 16 persistent echo sessions match `ios/HotspotProxy/CellularICMPEcho.swift` and `rust/src/relay.rs`. A device that refuses the ICMP socket returns status 4.
- The server applies the phase rule in `SourceSocksCapacity`: a 30 second handshake, an 8 second connect, a 2 second relay grant, a 300 second idle window for UDP and half-closed flows, and no bound for an open TCP relay. The relay cap follows the open-file limit: `min(288, (soft limit - 32) / 9)` total, with a setup reserve of `ceil(total / 9)` capped at 32. A low limit gives fewer relays. An unreadable or too low limit stops the start with `START_FAILED`. A capacity decision closes only a stale session. It never closes a healthy open TCP relay for silence.
- The echo path has no TTL control. The kernel default applies to the echo request. The target device builds its inner reply with TTL 64. The client and destination TCP sockets set no-delay and keepalive. Android applies its system keepalive values; the app cannot set the iOS 60/10/3 values.
- The app has a separate preview mode. It shows simulated values for layout and motion comparison. A banner and a PREVIEW badge label it. Preview mode does not change the real proxy, the trust list, or the token. Keep the labels correct when you change the screen.
- `android/app/src/main/java/com/hotspotshade/source/pairing/` implements the source side of pairing protocol v1. Its wire format, labels, budgets, and fixed vectors match `rust/src/source_pairing.rs` and `ios/HotspotProxy/Pairing.swift`.
- Android API 26 has no X25519 key agreement and no ChaCha20-Poly1305 cipher. `X25519.kt` is a Kotlin port of the public-domain TweetNaCl scalar multiplication. `ChaCha20Poly1305.kt` is a Kotlin port of RFC 8439. `Hkdf.kt` uses the platform HMAC-SHA256. The app adds no dependency.
- `PairingServer` binds the hotspot address and TCP port 18090 only. It accepts at most 8 sockets and at most 4 idle sockets, closes a socket that sends no complete frame within 10 seconds, and evicts the oldest idle socket when a new connection arrives. The listener runs while the activity is visible, stops on `onStop`, and rebinds when the hotspot address changes. It does not run in the background. A request that arrives while the activity is paused but the listener is open posts a notification. The notification holds no code or key. The app never approves a request from a notification.
- The invalid-message budget map stays bounded at 256 peers. A full map evicts the record that expires first. The map does not drop the new peer's record.
- `HotspotAddressFinder` accepts only a confirmed tethering interface. A strong name (`swlan*`, `ap*`, `softap*`, `rndis*`, `bt-pan*`) confirms itself. A `wlan*` name needs the `ConnectivityManager` client interface list. The finder fails closed with null for `eth*`, `usb*`, `wg*`, and every unconfirmed name.
- The JVM tests hold the RFC 7748, RFC 8439, and RFC 5869 vectors and the parity vectors. Run `cd android && ./gradlew testDebugUnitTest`. The suite has 217 tests.
- A successful pairing writes the proxy token with `TokenWriter` into `AndroidKeystoreTokenStore`. If no token exists, the app generates a random token for the first pairing. A later proxy start then finds the token. The token file saves with a temporary file and one atomic rename.
- The real Settings page lists the trusted target devices. Each label is a short SHA-256 digest of the stored public key. Each row has a Forget action. "Forget all target devices" removes every key. "Rotate source token" writes a new random token and reloads the listener. Rotation is refused while the proxy runs and does not remove trust.
- `ProxyPortPolicy` saves a proxy port from 20000 to 59999 and never chooses 18090. The pairing result names it. A bind failure clears the saved value.
- Target public keys are stored in SharedPreferences. They are not secret. The token is not in SharedPreferences. One process-wide lock makes each load, change, and save one operation across the listener and the settings page. A read or write failure throws and writes nothing.
- The pairing UI has a real Allow or Deny prompt and a separate simulated preview dialog. Keep both labels correct when you change the screen.
- The emulator interop test binds the emulator loopback. It uses `TestOnlyHotspotFinder` in `androidTest`, which cannot compile into a release build. It does not prove hotspot-only binding, carrier behavior, or physical-device behavior. The emulator has no hotspot interface, so the real app shows "Waiting for the hotspot" unless an instrumented test installs the test-only hotspot address.

### Source device app

- The iOS app is Swift. Build it with Xcode, or take the unsigned IPA from CI. The IPA has no signature. Sign it with your own certificate. See `ios/README.md`.
- The app is named HotspotShade. Keep the internal identifiers `HotspotProxy` (Xcode target and scheme, folder, executable name, app bundle name) and `local.hotspotproxy.app` (bundle identifier). The display name comes from `Info.plist`. A new bundle identifier installs as a new app and loses the stored pairing trust and token.
- The app must bind its listener to the hotspot address only and must keep token authentication.
- The pairing listener uses TCP port 18090 (`PairingProtocol.port`, Rust `pairing::PAIRING_PORT`). It binds to the hotspot address only.
- `ios/HotspotProxy/Pairing.swift` and `rust/src/pairing.rs` implement one protocol. Their tests hold the same parity vectors. Change both sides and both test suites together.
- The proxy derives its session limit from the open-file limit. When the limit permits, it allows 256 relays plus 32 setup sessions. It refuses a new relay when no safe slot is available. It does not evict an open TCP relay solely for silence. The pairing listener and its presence check use a separate listener. Each proxy session owns one serial queue under one shared concurrent parent.
- A `.waiting` destination connect keeps the same connection for 1.5 seconds. Network framework can make it ready when the path returns. After a sustained wait, retry once on the same cellular path, inside the 4 second deadline. Do not report a wait as unreachable.
- The source device sets TCP keepalive on its listener and destination sockets: 60 seconds idle, 10 seconds interval, 3 probes. A carrier NAT can drop an idle mapping. Keepalive does not extend the 300 second application idle timeout. A source device session with no application traffic can still close.
- The deadline reply is code 5 for a refused destination and code 1 (general failure) in every other case. Code 4 is only for a real unreachable failure. A deadline does not prove that the destination is unreachable. A final failure uses code 4 for an unreachable network or host, code 5 for a refusal, and code 1 for every other error.

### Inner TCP stack

- The target device runs a userspace TCP endpoint in `rust/src/tcp.rs`. It answers a keepalive probe with an ACK. A remote desktop or terminal client resets an idle connection when the probe gets no answer.
- After 600 seconds of silence, the endpoint sends up to three idle probes at 60-second intervals. It resets the flow if those probes get no answer. It also resets the flow when a FIN retransmit limit is reached. A zero-window flow with data or a FIN waiting uses separate probes, starting at 300 ms and backing off to 60 seconds. It resets after 12 unanswered probes. A peer that answers can hold a flow slot while its window remains closed. Verify this behavior with a live paused reader before release.
- The target device maps source device reply codes with `phone::reply_error`. Code 1 is a general failure, code 3 is network unreachable, code 4 is host unreachable, code 5 is refused, and code 6 reports an expired TTL. Code 6 does not prove that a connection timed out.

### GUI

- Start with `hotspotshade gui`. The default port is 8787.
- Use `--demo` to review the UI without root or real traffic.
- Pair with `POST /api/phone/pair`. Read the state with `GET /api/phone/pair`. Cancel with `POST /api/phone/pair/cancel`. Forget with `POST /api/phone/forget`. Forget is refused with HTTP 409 while the tunnel runs. The demo backend simulates the pairing.
- `POST /api/phone/probe` runs one source device presence probe now. The engine allows at most one probe per 500 ms.
- The page has a "Let ping work" checkbox. It stores the value under the local storage key `hs-ping`. The target device app has the same setting in UserDefaults `letPingWork`, on by default. In phone mode both send `options.experimental_icmp` on `POST /api/start`. A wrong type gives HTTP 400 with the code `invalid_ping_option`. The `gui` command still accepts `--experimental-icmp` and `--experimental-icmp-persistent`, but the GUI phone start is on by default and the flags do not change it.
- `GET /api/status` has top-level `icmp_enabled`. It is true only when the tunnel runs in phone mode and the echo relay is on. It also has `iface`, `forget` (`state` and `attempts`), `last_stop` (`reason` and `at`), and `last_stop_message`. `phone` has `checked_at` and `trusted_by_source`.
- `GET /api/diagnostics` returns the counters from `rust/src/diagnostics.rs`. The timing metrics keep the last 512 samples. The answer holds no address, host, token, or key. The page uses it for Copy diagnostics.
- The page shows the automatic stop message from `last_stop_message`. It has Check now, Forget, and Copy diagnostics.
- `GET /api/failures` returns the bounded record from `rust/src/failures.rs`. The record stays in target device memory. It is never written to disk, never sent to the source device, and cleared when the tunnel starts or stops. The page shows it in "Recent failures". The target device app shows it in Settings, Advanced, "Recent failures". The privileged helper has a `failures` action for the same record.
- The server binds to `127.0.0.1` only. The UI has no external assets and no build step.

## UI quality rules

The macOS target app uses SwiftUI. Translate its layout, states, and interactions to native Windows controls, including native window controls and menus. Use WinUI 2 for the Windows UI. Evaluate a UWP host and a desktop host with legacy XAML Islands against the engine, privilege, packaging, and lifecycle requirements before you choose the Windows host. The current Tauri demo is not the finished Windows app.

The Linux target app uses Electron. Keep its layout and behavior consistent with the macOS and Windows apps while respecting Linux desktop conventions. Measure idle and active memory use and reduce unnecessary processes and assets. Keep dependencies locked and the UI local. No platform may expose credentials or bypass the protected engine API.

For every user-visible target app change, account for macOS, Windows, and Linux. Implement equivalent behavior on each available app, or record the missing platform work and its reason. Check error, loading, empty, accessibility, light, and dark states on each platform. A native translation can use different controls. It must retain the same user-facing meaning and capabilities.

Account for the Android preview when a shared mobile interaction changes. Keep its layout, states, motion, and accessibility aligned with the iOS app where the platform permits. Label simulated behavior. Do not claim a feature works until the real implementation is tested.

The browser GUI is `rust/src/gui.rs` plus `gui_assets/index.html`, `styles.css`, and `app.js`. These rules apply to that GUI and to web-based desktop UIs.

- Use the existing CSS variables. `gui_assets/styles.css` defines the browser GUI tokens. A separate desktop UI can define its own semantic tokens. Do not hard-code new colors in components.
- Use the 4/8 px spacing scale: 4, 8, 12, 16, 24, 32, and 48 px. Do not add arbitrary margins.
- Reuse the existing type sizes in `styles.css`. Do not add a new size for one label.
- Use one accent color. `--primary` is the action color. Use `--success`, `--warning`, and `--danger` only for status, never for decoration.
- Use `--radius` for cards, 8 px for controls, and 6 px for small marks. Use a 1 px `hsl(var(--border))` border.
- Do not add gradients unless the gradient already exists in the design system. Do not add glow effects, glass effects, or decorative blobs.
- Do not use emojis, stock illustrations, or generated hero images. Use the existing inline SVG icon set or a text label.
- Show real service data. If data is unavailable, show an empty state. In demo mode, label the data as simulated. Do not add fake users, fake charts, or fake uptime.
- Show real empty, loading, and error states. Every panel needs a meaningful state when it has no data or when the API fails.
- Keep focus visible. Every interactive element needs a visible `:focus-visible` ring. Do not remove outlines without a replacement.
- Use 150 ms transitions. Keep motion short and functional.
- Support light and dark themes. Test both themes. Do not use a color that works in only one theme.
- Keep the UI local. No remote fonts, images, scripts, or analytics. The Content Security Policy must stay restrictive. The server binds to `127.0.0.1`.

Before you call a UI change done:

1. Build the binary and run `scripts/gui_smoke.sh rust/target/release/hotspotshade`.
2. Run the GUI in demo mode: `rust/target/release/hotspotshade gui --demo --no-open --port 8794`.
3. Check the layout at **1440x1000** and **1100x900**.
4. Check the light theme and the dark theme.
5. Check the browser console for errors and failed requests.
6. Confirm that no external asset request appears in the network log.

## Change checklist

Before you finish a change:

1. Read the invariant list in this file.
2. Confirm that the change does not bypass the normalized socket helpers or the TTL audit.
3. Confirm that DNS still avoids `getaddrinfo()` on egress paths.
4. Confirm that direct mode still defaults IPv6 to `block` and that source device proxy mode still forwards IPv6.
5. Confirm that every new exit path removes routes and devices.
6. Run `cargo check`, `cargo test`, and `scripts/gui_smoke.sh`.
7. Run `scripts/swift_tests.sh` if you touched `ios/`.
8. Run `cd linux && npm test`, `xvfb-run -a npm run test:settings-window`, and `xvfb-run -a npm run test:a11y` if you touched `linux/`.
9. Run `bash -n scripts/*.sh` if you touched a script.
10. Push, then read the CI result with `gh run watch` and `gh run view --log-failed`.
11. Update `README.md`, `PHONE_PROXY.md`, this file, or the roadmap when behavior changes.
