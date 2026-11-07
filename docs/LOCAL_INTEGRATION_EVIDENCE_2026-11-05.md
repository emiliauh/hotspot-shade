# Local integration evidence, 2026-11-05

This is development evidence from a shared, uncommitted working tree based on
`1a37ed738519af849bc0880755b3ba92bd9f92e1`. Other work was in progress. The
file hashes below were collected after the runs, not at both ends of each run;
they are pointers for drift detection, not proof of an immutable build input.
No physical device, carrier, hotspot, host route, or TUN device was tested.

## Later Linux Electron and demo-engine check

A Linux arm64 container ran the Electron engine-demo smoke test with a Rust
engine built offline from a copied source snapshot. All 39 reported checks
passed. The container had networking disabled and all capabilities dropped;
its seccomp policy was relaxed to allow Chromium's sandbox namespaces. This
was a demo-only run, not a real tunnel or desktop authorization test. The
snapshot, binary, image IDs, and limits are recorded in
`build/linux-electron-check.hxMa2o1n/EVIDENCE.md`, an ignored local artifact.
The same snapshot also passed 10 checks through the real Electron main entry,
including demo engine child and temporary-directory cleanup on normal quit.

After the desktop stop-confirmation and HTTP-deadline changes, `npm test` in
the current Linux desktop checkout ran on macOS: 209 passed, 2 skipped, and
none failed. It uses Node fixtures and loopback; it is not a Linux desktop or
real helper run. The following hashes were recorded after that run, not at
both ends, and therefore do not establish immutable build inputs:

```text
530ff3a602021a1f17b4a7eb9d04819dcf4dce26eb41c9f0dee238c24f7e79d9  linux/src/main/lifecycle.js
41247102b44fb2d362837b675224cf5f0dc1abed61f1eb8df6e1e2c43deb5c65  linux/src/backend/engine-backend.js
1a6709403d93e312b50118dea526d0c30674b3612d33d982c2bd85fc25dfa46f  linux/src/backend/engine-client.js
44a2307f04ac9c9ec12727b46027e790605c1bd80c472f6fd3f3a03ece646754  linux/test/lifecycle.test.mjs
86d9171fdf726fd62f42828eec3943fad66ecd7cea935327913ed773175dc633  linux/test/engine-client.test.mjs
```

## Later Electron and demo-engine smoke check

On macOS, `npm run test:engine-smoke` in `linux/` passed 39 checks with the
existing release engine in demo mode. The test drove the Electron page through
pairing, simulated start and stop, diagnostics, and an engine-crash display.
It deliberately sent SIGKILL to its own demo engine to exercise crash handling;
it did not start a real tunnel. The engine process was gone and its temporary
engine directory was removed after the run. The first attempt failed because
the shell inherited `ELECTRON_RUN_AS_NODE=1`; the passing run removed that
environment setting. This is macOS demo integration evidence, not a Linux
desktop, route cleanup, or physical hotspot result.

The following hashes were collected after the run. The checkout was shared,
and these are not proof that the binary was built from the current sources:

```text
be639b56ff0f0d582ee20a4e1f1fad48b3f2e7f04e781e04ce77ac0360c647e3  rust/target/release/hotspotshade
4418831cd667cdaa7081472db76b8fcf331fb5f05e446cfc14985b8cfcdb90aa  linux/test/engine-smoke-main.js
```

## Later iOS source and Rust client loopback check

Another `scripts/ios_source_proxy_flow_test.sh` run passed both tests on the
same date. The silent pairing socket closed after about 10.7 seconds, and the
paired TCP flow reported `audit=(5, 0)`. The harness used a fixed test token,
a fake hotspot selection, and loopback on this Mac. It did not run the iOS
Simulator app or establish carrier, hotspot, or physical-device behavior.

The following hashes were collected after this run, not before it. The checkout
was shared and uncommitted, so they identify later observed files, not an
immutable input set:

```text
f353a3ae772ab027d245d6261eed86fcc484d36f64b429e65b3bb9b809632692  ios/HotspotProxy/ProxyServer.swift
3b74f26cf2d8798afc15debc7b3037e24fa88292a6020897588fde39a54cab59  ios/HotspotProxy/Pairing.swift
38cb5d4c00ed2cd9a5add4f827d5812fd5b693f859e9f1edd5267eec01b37003  rust/tests/ios_simulator_proxy_flow.rs
8696fe7f25df60327bf8d8c94ef09e5c4611fd8dbc7cb10e6fd672fea7cf0414  scripts/ios_source_proxy_flow_test.sh
```

## Later Linux container checks

On the same date, `cargo test --offline --locked --lib` for the Rust engine
passed 1,144 tests in a `rust:1.99-slim-bookworm` container with networking
disabled, all capabilities dropped, and the checkout mounted read-only. The 68
route-recovery tests also passed in a separate run. For that focused run,
`rust/src/platform_linux.rs` had SHA-256
`1751c938da024133abf8e2422893866840d6f444e793a64f3ec8431129db05c7`
before and after the test. The full library run used the shared working tree;
its complete source was not hashed at both ends.

`bash linux/helper/tests/run-container.sh` then passed 24 opt-in helper
lifecycle checks and 2 real-engine demo checks in disposable, network-disabled
containers. The wrapper verified the hashes of its copied executables and
removed its containers and volume after success. It used a fixed test token,
fake engines or the demo engine, and local sockets; it did not run a tunnel or
change host routes. The helper source hash collected after the run was
`f396057d677c92a715b94681082fe8f67eeb34dcb98df45d953f6b70433fc74e`;
it was not hashed before the run. These results do not establish live routing,
physical hotspot behavior, or a frozen source-to-binary chain.

## Results

| Check | Result | Scope |
|---|---|---|
| `scripts/swift_tests.sh` | Passed | Local Swift logic and loopback server tests. |
| `scripts/ios_source_proxy_flow_test.sh` | 2 passed; `audit=(5, 0)` | Rust and Swift over loopback on macOS, not the iOS Simulator app. |
| `swift test --package-path macos/HotspotShadeKit --scratch-path <private>` | 457 tests, 3 skipped, 0 failures | Package tests; skips need a demo binary. |
| `swift test --package-path macos/Installer --scratch-path <private>` | 180 tests, 0 failures | Fixtures and injected runtimes; live installation is disabled. |
| iOS Simulator app Debug build, signing disabled | Build succeeded | Compilation only; Xcode reported a headermap warning. |
| macOS app Debug build, signing disabled | Build succeeded | Compilation only; Xcode reported a headermap warning. |
| `cd linux && npm test` | 205 passed, 2 skipped, 0 failed | Local Node fixtures on macOS; no real Linux desktop authorization. |
| Linux desktop engine HTTP contract, release binary in demo mode | 15 passed | Loopback on macOS, not a Linux tunnel. |

The last check used `HOTSPOTSHADE_BIN` set to the absolute path of the existing
`rust/target/release/hotspotshade`, then `node --test
test/engine-contract.test.mjs` from `linux/`. The engine ran in demo mode with
the fixed test secret on an inherited descriptor. Its binary was built before
these observations, so this is not evidence of a fresh release build from the
current working tree.

The macOS package and app logs remain in temporary directories on this host.
They are not a durable release artifact. Their SHA-256 values are:

```text
5b9163e91a1cd59fa982c858150556eb58b137605a0c98bee1a7030eacd77a28  macOS kit test log
5d5ebf067af090a0d327ba43cadbe529d73ecf526c44ebda1d02a4d5212a7e2d  macOS installer test log
6f10d2a207e6a5d7e13a26e2e37b4086bd9a439bf7a3fdbc6325dd1f2ab6836f  macOS app build log
d79064436459b2aca056c5a1333f0b16654f48f14ceccd44902a9f6c25bc00cc  iOS Simulator build log
```

Selected source hashes collected after the runs:

```text
a1d3ba2c14937cddd0e5fe6d62f0310ddb01d23be8f423bd97ce1a34e2ca3540  ios/HotspotProxy/ProxyServer.swift
72c4d271bcb9ae27530d086354603a8e135d9f7cb096d762f4c1447bbcc9431c  ios/HotspotProxy/HotspotProxyApp.swift
5d914cf930216829f161e72759d0e50430c65e6de238b3289984397870f3856b  ios/HotspotProxy/HotspotWatch.swift
5ff787241e8f498136f5bb820170ac11af9909d38330f14055601383781dfa0e  ios/HotspotProxy/TokenLifecycle.swift
bcb53e069243d0ecabfcd66a337916c07518bc5aaaffdb88b84cf5b5e9401738  rust/src/service.rs
0817d74346a53c4de0f7857fb7bcb6c00d8c603ab3b157f7c34422513c8a4b57  rust/src/macos_upgrade_lock.rs
bbf8048ea8a6d424e3bb16e9079e1051603d9da402beae34d774747f282eb5d1  macos/HotspotShade/HotspotShadeApp.swift
4548a020d388910b7d09e188249fc945853c24c077b6a878a7e8dbf9426a5180  linux/src/backend/engine-client.js
2a87a8266f1675c5103e8ae26094dca6568dfc708063b842337619ec3370c3d4  scripts/ios_source_proxy_flow_test.sh
```

These checks do not establish live route cleanup, signed helper installation,
Android Keystore durability, physical hotspot discovery, or carrier behavior.
The physical-device procedure and authenticated pairing candidate remain
unapproved. Do not infer release readiness from this page.

## Android local check after pairing invalidation change

On 2026-11-06 the offline Android Gradle command `testDebugUnitTest lintDebug
assembleDebug assembleDebugAndroidTest` succeeded with JDK 17. The retained
JVM results total 894 tests, zero failures and zero skipped. The focused
`PairingCoordinatorTest` has 41 passing tests. Lint reported zero errors and
seven dependency-version warnings. Gradle reused up-to-date outputs for some
tasks, and the instrumented APK was built but not run. These results do not
establish Android Keystore, emulator, device, or hotspot behavior.

The following hashes were recorded after the run in a changing working tree;
they are not a committed release snapshot:

```text
5f1f4c2ff1a82e2177f4b3110237b0fc2d181fcbfc7f6e5a6eac85ac136e9c24  android/app/src/main/java/com/hotspotshade/source/PairingCoordinator.kt
e2f81097ae4bbf56b3da87a2a5130b94486c05d951ea8fb45d103123e911e366  android/app/src/test/java/com/hotspotshade/source/PairingCoordinatorTest.kt
```

## iOS source proxy host flow, 2026-11-06

`scripts/ios_source_proxy_flow_test.sh` passed both ignored loopback tests
against the Swift source proxy harness and the Rust client. The silent pairing
socket closed and the proxy flow reported `audit=(5, 0)`. The harness disabled
cellular preflight probes. This is a host loopback test, not an iOS Simulator,
device, hotspot, carrier, or real cellular-path result. The source hashes below
were recorded after the run; the shared working tree was changing and was not
frozen during the test.

```text
f353a3ae772ab027d245d6261eed86fcc484d36f64b429e65b3bb9b809632692  ios/HotspotProxy/ProxyServer.swift
af3cd7ea7174fbd7c7be3a6486f0433911bdd75fab1d93313a0cecfac7215a89  ios/tests/ProxyFlowHarness.swift
38cb5d4c00ed2cd9a5add4f827d5812fd5b693f859e9f1edd5267eec01b37003  rust/tests/ios_simulator_proxy_flow.rs
4ab0ab254b9687a867d19c9cac40dfdd3ae22ab4a34a31e7472557a11f0893b1  /tmp/hs-ios-proxy-flow-current.log
```
