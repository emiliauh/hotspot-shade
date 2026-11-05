# HotspotShade desktop demo

This directory holds the shared Rust desktop demo. It is a Tauri v2 shell with
its own page under `desktop/ui/`. The page follows the macOS target app: one
Dashboard, Activity, and Settings surface, one primary action, plain status
text, and a persistent demo label.

## Scope

This increment is a **labeled demo only**.

- It has no tunnel and no route change.
- It does not start the real engine and does not need root.
- It opens no network listener and makes no external request.
- All counters, logs, pairing steps, failures, and start and stop results are
  simulated by `DemoBackend` in `rust/src/demo.rs`.
- The page models the source device proxy flow. It has no direct SOCKS5 or
  transparent tun settings page.
- It does not claim Windows or Linux tunnel support. The macOS arm64 tunnel
  remains the only verified tunnel.

## Layout

The page has these parts:

- A native window frame and a native menu bar.
- A left sidebar with Dashboard and Activity, and Settings at the bottom.
- A persistent demo banner above every page: "Demo mode. All data is
  simulated. No tunnel, routes, or network traffic."
- A `Demo` badge in the sidebar brand on the wide layout. The banner remains at
  every width.
- A Dashboard with one status header, one primary action, a source device card,
  a connection card, and an attention list.
- A pairing panel with steps, a code, a copy action, and cancel.
- An Activity page with time, message, a Details toggle, and refresh.
- A Settings page with General, Pairing, and Advanced tabs.
- General holds the ping setting and the System, Light, and Dark appearance
  choice.
- Pairing holds Pair, Cancel, Forget, and Turn off and forget.
- Advanced holds recent failures, the diagnostics copy action, app details, and
  the demo limitations. The failure table shows the setup stage. A missing
  stage shows "Not reported". An unknown stage shows "Unknown stage".
- Light and dark themes use the local token set in `ui/styles.css`.
- Keyboard access uses native menu accelerators, ordinary tab order, visible
  focus rings, arrow keys in the sidebar and the Settings tabs, and a skip link.

The page uses no external font, image, script, style, or analytics.

This demo uses one window and a Settings section. It does not have the separate
Settings window, the macOS menu bar extra, notifications, or launch at login
that the macOS target app has. Those features need a plugin or a second window
and a live platform check. They are outside this increment.

## Architecture

1. The page assets are committed under `desktop/ui/`: `index.html`,
   `styles.css`, `app.js`, `model.js`, `boot.js`, and `favicon.svg`. The build
   script no longer copies `gui_assets/`. `ui/favicon.svg` is a copy of
   `assets/logo/favicon.svg`; the source stays unchanged. The local web GUI and
   this desktop page stay separate.
2. Tauri embeds `desktop/ui` with its `custom-protocol` feature and serves it
   from the built-in asset origin. The app has no loopback HTTP server.
3. `src/fetch_shim.js` is an initialization script. It sends only same-origin
   `/api/` fetch calls to one Tauri command. It sends every other URL string to
   the original fetch function, which serves embedded assets. The shim accepts a
   URL string or a URL object. It rejects a `Request` object with a fixed error
   because it does not read a request body, method, or signal from that object.
   It honors `AbortSignal` for an API call. An abort rejects the page promise,
   but it cannot cancel a demo command that is already running. The shim bounds
   the query to 4096 bytes.
4. `src/commands.rs` holds the one production command, `demo_api`. The demo
   binary has no constructor for a real service backend.
5. `src/bridge.rs` maps the allowed method and path pairs to one concrete
   `DemoBackend`. It publishes the fixed `ALLOWED_PATHS` list. It returns the
   same shapes that the page expects.
6. `src/menu.rs` builds the native menu. It has fixed item identifiers and
   fixed page calls. It cannot pass user text to a script.
7. `src/navigation.rs` allows only the asset origin for the current platform
   and `about:blank`. macOS and Linux use `tauri://localhost`. Windows uses
   `http://tauri.localhost`. The window denies every new window where the Tauri
   API supports that hook. Every other URL is denied.
8. `src/window.rs` sets the native title, the native frame, a 960 by 700 default
   size, and a 780 by 560 minimum size. The window keeps the platform title bar
   and window controls.

## Native menu and window controls

The menu needs no plugin and no capability. The Tauri menu API builds it in
Rust.

| Menu | Items |
|---|---|
| macOS application menu | About, Settings, Services, Hide, Hide Others, Show All, Quit |
| File on Windows and Linux | Settings, Quit |
| Edit | Undo and Redo on macOS, Cut, Copy, Paste, Select All |
| View | Dashboard, Activity, Refresh Status, Check Source Device Now, Toggle Appearance |
| Window | Minimize, Zoom, Close Window |
| Help | Demo Limitations |

Accelerators are Control 1, Control 2, Control comma, Control R, Control Shift
K, Control Shift L, Control M, and Control W. macOS uses Command in place of
Control. The window uses the native decorated frame. A menu action calls one
fixed page function or one Tauri window method. The page function names only a
fixed action such as `dashboard` or `theme`.

## Security boundary

- The window can call one production command: `demo_api`. The command accepts a
  method, a path, a query, and a JSON body. A body can contain a manual token,
  host, or port. The demo does not use those fields to contact a device. The
  command does not accept a destination URL or a command name.
- `src/bridge.rs` holds a fixed allowlist. An unknown path gets HTTP 404. A
  known path with a wrong method gets HTTP 405. A path with a percent escape, a
  parent segment, a backslash, or a doubled slash gets HTTP 404.
- The bridge limits the query to 4096 bytes and the body to 1 MiB. A larger
  query gets HTTP 414. A larger body gets HTTP 413.
- The bridge returns no credential. It redacts any field named like a token,
  password, authorization value, or secret.
- The demo backend has no credential and no privileged operation. It cannot
  start the real service.
- The Content Security Policy is:
  `default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ipc: http://ipc.localhost; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
- There is no Tauri plugin. There is no shell, process, filesystem, HTTP,
  opener, dialog, notification, tray, or updater permission.
- The app has no capabilities file because it registers no plugin command and
  no core permission.
- The native menu calls `window.eval` with a fixed string. It never includes a
  URL, token, host, path, or other input from the page or the user.
- The page sends no credential. A manual token field is not part of this page.

The test binary adds three test-only commands: `smoke_report`, `smoke_resize`,
and `smoke_menu`. The production binary registers `demo_api` alone.

## Limitation: no protected real-service bridge

This prototype does not connect the real engine. It does not use the engine
bearer secret and it does not use the parent-liveness descriptor. The demo
bridge is not a network API. Only the embedded page can call it through Tauri
IPC. It has no secret because the demo holds no credential and no privileged
operation.

Do not attach the real service to this shell as it stands. A later increment
must pass a per-launch secret on a descriptor, keep the secret out of the
webview, and release the parent-liveness handle on quit. That work needs a
separate design and test. This prototype makes the limitation explicit instead
of exposing the real engine through an unprotected API.

## Dependencies

| Dependency | Reason | Cost |
|---|---|---|
| `tauri` 2 | Window, menu, asset protocol, IPC, system webview | Large transitive tree: `wry`, `tao`, `muda`, WebKit or WebView2 bindings, and platform crates. |
| `tauri-build` 2 | Build-time config and platform metadata | Build dependency only. |
| `serde`, `serde_json` | Command arguments and the existing API shapes | Already used by the engine. |
| `hotspotshade` by path | `DemoBackend` and the status shapes | No extra package. The dependency compiles the whole engine library for the host platform. The demo uses only the demo and GUI items. |

There are no Tauri plugins. A later tray, notification, or updater increment
adds one plugin per feature, plus permission and capability entries, plus a
live check on each target system. The updater also adds signing and network
work. Do not add one without a stated reason.

The native menu uses the Tauri menu API that is already part of the `tauri`
dependency. It adds no package.

`desktop/Cargo.lock` is committed. It holds 430 locked packages. The resolver
selected `tauri` 2.12.5, `tauri-build` 2.7.4, `wry` 0.57.1, and `tao` 0.37.2.
Offline Cargo metadata for the macOS arm64 dependency graph lists 262 packages.
The two local packages have no license expression in their manifests. All
other packages in that graph declare one. This is not a license compatibility
review, and it does not cover the Windows or Linux dependency graphs.
The release build produced a 14 MB unsigned binary. The release build directory
was 920 MB. The full `desktop/target` directory was 3.0 GB after the debug and
release builds. Remove `desktop/target` to reclaim the space.

## Build and test

Run these commands from the repository root.

| Command | Expected result |
|---|---|
| `cargo check --locked --manifest-path desktop/Cargo.toml` | No errors. |
| `cargo test --locked --manifest-path desktop/Cargo.toml` | The bridge, menu, and navigation tests pass. The UI asset contract tests pass. |
| `node --test desktop/tests/fetch_shim.test.mjs` | The fetch shim tests pass. Node is needed for this test only. |
| `node --test desktop/tests/ui_model.test.mjs` | The pure page state tests pass. Node is needed for this test only. |
| `cargo test --locked --manifest-path desktop/Cargo.toml --features webview-smoke --test webview_smoke` | Opens one hidden webview, checks the page, the demo API, the native menu handler, both themes, three window sizes, pairing, start, stop, and forget, then prints `WEBVIEW SMOKE PASS`. Needs a graphical session and a system webview. |
| `cargo build --locked --manifest-path desktop/Cargo.toml` | Builds `desktop/target/debug/hotspotshade-desktop`. |
| `cargo run --locked --manifest-path desktop/Cargo.toml` | Opens the demo window. |
| `cargo build --release --locked --manifest-path desktop/Cargo.toml` | Builds `desktop/target/release/hotspotshade-desktop`. |
| `cargo clippy --locked --manifest-path desktop/Cargo.toml --features webview-smoke --all-targets -- -D warnings` | No findings. |
| `cargo fmt --manifest-path desktop/Cargo.toml -- --check` | No output. Exit code 0. |

No npm install and no Tauri CLI are needed.

The build does not create a bundle. `bundle.active` is false. The Windows
build uses `icons/icon.ico` even with bundling off. A later bundle needs a
signing decision and verified icon formats for each platform.

## Webview smoke test

`tests/webview_smoke.rs` is a separate test target behind the `webview-smoke`
feature. The feature adds no production command and no production code.

The test does this:

1. It creates one hidden Tauri window with the same builder as the desktop
   binary. The builder loads the embedded `index.html`, installs `fetch_shim.js`,
   and applies the navigation rule.
2. The test builds the production native menu and sets it on the test app. This
   catches a menu construction error on the host.
3. A test-only script waits for the page to show the status from the demo
   backend. It checks the asset origin, the fetch shim, the demo badge, the
   persistent demo banner, the source device card, and the fixed primary
   action.
4. It measures the layout at 1440 by 1000, 1100 by 900, and 780 by 560. It
   checks the sidebar width, the bounded content width, the two cards, and the
   absence of horizontal overflow.
5. It checks the pure model at runtime, the sidebar arrow keys, the Settings
   tab arrow keys, the Activity Details toggle, and the theme toggle.
6. It calls the production native menu handler with fixed identifiers for
   Settings and Dashboard. This proves that the menu script reaches the page.
7. It clicks Pair, reads the simulated code, waits for Pairing to complete,
   clicks Turn on, checks the running state and the ping line, clicks Turn off,
   then clicks Forget. This proves the main state transitions and actions.
8. It reads `/api/status` through the production shim. It checks HTTP 200, the
   demo flag, the stopped and unpaired state, and the absence of a credential.
9. The script prints bounded progress lines, then sends one final report to the
   test binary. A watchdog fails the test after 90 seconds when no final report
   arrives.

The hidden test window disables background timer throttling. Without that, a
hidden WebKit view can suspend the timers that the bounded action sequence
needs. The production window is visible and keeps the default policy.

The test opens no listener, makes no external request, starts no tunnel, and
changes no route or device. It uses the in-memory demo backend only.

A pass proves these points:

- The system webview loads the embedded page from the asset origin.
- The production fetch shim is installed and sends `/api/status` to the
  production `demo_api` command.
- The demo backend reports `demo: true`, `running: false`, and `paired: false`
  after the test forget action.
- The page shows the persistent demo banner and, at the default size, the
  `Demo` badge.
- The main container does not overflow at the three measured sizes.
- The native menu construction succeeds and the production menu handler
  reaches the page.
- Pairing, Turn on, Turn off, and Forget work through the page controls.
- The loaded document has no external `src` or `href` asset.
- No page error or rejected promise appears during the run.

A pass does not prove:

- A person inspected the rendered window. The test measures layout bounds and
  computed theme changes. It does not replace a visual review.
- A real click on the operating system menu bar. The test calls the same
  production handler with fixed identifiers.
- The Windows or Linux menu, window, webview, or tunnel. The test target runs on
  macOS only and fails with exit code 3 on another host.
- A real service, a tunnel, a route, or a device.
- The CI runtime by itself. The test needs a graphical session and a system
  webview. Read the CI log for the `WEBVIEW SMOKE PASS` line. A timeout or a
  start error is a failure, not a pass.

## Platform status

| Platform | Status |
|---|---|
| macOS arm64 | The demo build, Rust tests, Node tests, hidden-webview smoke test, clippy, and fmt pass on the development host. The hidden-webview test measured the layout at three sizes and exercised the native menu handler. No person inspected the rendered window. Treat the visual UI as measured but not reviewed by eye. |
| Windows 10/11 | CI builds the demo and runs its Rust tests. A local type check also passes. It does not open the webview, test a menu, or test a tunnel. Tauri needs the WebView2 runtime and the MSVC toolchain. The asset origin is `http://tauri.localhost`. The native menu uses a File, Edit, View, Window, and Help layout. |
| Linux | Not built and not tested. Tauri needs WebKitGTK 4.1 and GTK development packages. The asset origin is `tauri://localhost`. This is not proof. |

A successful compile does not prove a real tunnel. This app has no tunnel in
any case. The demo backend is the same on every platform. A successful compile
also does not prove the UI. The hermetic tests cover the bridge, the menu
mapping, the navigation rule, the shim, the pure page model, and one hidden
webview load.

## Verification in this increment

These are local results. They are not a claim of a real service or live
platform support.

- `cargo check --locked --manifest-path desktop/Cargo.toml`: pass.
- `cargo test --locked --manifest-path desktop/Cargo.toml`: 15 library tests and
  6 UI asset tests pass.
- `node --test desktop/tests/fetch_shim.test.mjs`: 14 tests pass.
- `node --test desktop/tests/ui_model.test.mjs`: 16 tests pass.
- `cargo clippy --locked --manifest-path desktop/Cargo.toml --features webview-smoke --all-targets -- -D warnings`:
  pass.
- `cargo fmt --manifest-path desktop/Cargo.toml -- --check`: pass.
- `cargo build --locked --manifest-path desktop/Cargo.toml`: pass.
- `cargo test --locked --manifest-path desktop/Cargo.toml --features webview-smoke --test webview_smoke`:
  pass on the development host in a graphical session. The hidden webview
  reported `WEBVIEW SMOKE PASS` with no failures.
- The hidden webview loaded `tauri://localhost`, measured 1440 by 1000, 1100 by
  900, and 780 by 560, and completed the demo action sequence. No person
  inspected the rendered window.
- A Windows type check with the `x86_64-pc-windows-msvc` target, a rustup
  toolchain, and `llvm-rc`: pass. This is a type check only. It does not open
  WebView2, test a menu, or test a tunnel.
- A Linux type check did not complete on this host. The host has no GTK
  sysroot, so `glib-sys` stops at `pkg-config` during cross-compilation. This
  is a host limit, not a product result.

The tests are hermetic. They use the in-memory demo backend, a fixed set of
paths, a fake Tauri invoke function, and one hidden webview window. They do not
create a route, a tunnel device, or a network connection.
