# iOS Simulator token-copy check, 2026-11-05

This is a UI observation, not a physical-device or carrier test. It does not
approve the token-copy implementation or the iOS app for release.

An unsigned Debug simulator build with bundle identifier
`local.hotspotproxy.app.validation20261105` was installed separately on the
iPhone 17 simulator running iOS 27.2. It launched to the Dashboard with the
proxy Off. Settings opened, and Advanced reported that the Keychain token could
not be read. Show token and Rotate token were disabled. The proxy was not
started. The other simulator app copies were not replaced.

Because no token was available, this run did not exercise Copy token, the
pasteboard expiration, switching apps after copying, or text selection. The
cause of the simulator Keychain error was not established in this run. An
unsigned simulator result does not establish the behavior of the signed iPhone
build. Those checks remain open for an appropriately isolated test setup.

## Ad-hoc-signed simulator build

A separate Debug build with an ad-hoc signature and bundle identifier
`local.hotspotproxy.app.signedsimulation20261105` was installed on the same
simulator. This build showed an enabled Show token control, unlike the unsigned
build. Show token exposed the Copy token control and the two-minute privacy
notice. Copy token and Hide token were invoked; the token was then hidden.
This shows that the signed simulator build reached those UI actions. The
pasteboard contents, switching apps and pasting, and actual item expiration
were not checked. This comparison does not establish the cause of the unsigned
Keychain failure or prove behavior on a physical iPhone.

## Cross-app receiver attempt

A separate simulator-only receiver was built to report whether a paste produced
a nonempty value without displaying it. After Copy token, the receiver was
installed and opened, but the device tool reported that it was not running.
The advised relaunch was attempted once and the same error recurred. The cause
was not established. The receiver did not report a paste result, so switching
apps and pasting remains unverified. No further device action was attempted
after the repeated error.

A subsequent read of the local receiver crash report showed a `SIGTRAP` with
the top frame in UIKit's scene-lifecycle adoption check. The disposable
receiver used the older application-delegate window setup and did not declare a
scene configuration. This points to the receiver fixture as a likely cause; it
does not establish a HotspotShade pasteboard failure. The fixture has not been
retested, and the cross-app check remains open.

The replacement source at `ios/tests/CopyReceiver/` declares a scene delegate.
Its plist passed `plutil -lint`, and its Swift source compiled for the arm64
iOS Simulator. It has not been installed or launched, so the fix and the
cross-app paste result remain unverified. The receiver records a SHA-256 digest
of its first nonempty paste and can compare a later paste without displaying or
logging either value. A match would show those two pastes agree, but would not
by itself prove the value equals the source token or that expiration works.

Run `sh ios/tests/CopyReceiver/build.sh` to build a fresh ad-hoc-signed
simulator receiver in a temporary directory. The script prints the app path and
does not install or launch it. It uses the same receiver bundle identifier as
the failed fixture, so a later installation on that simulator replaces that
fixture. Follow the active device-tool instructions before any later simulator
interaction.

The following SHA-256 values were recorded after the observation. They identify
the files present then; they are not proof of an immutable build input:

```text
74ea36aa47861001edc1016b67f540d8e26ed5d8e9b475a02308814fadecd186  ios/HotspotProxy/ActivityState.swift
0f26a954c1ed9dcbd3dd42386f66ab6afe941515a554271b7b4d4d08b7033e9f  ios/HotspotProxy/HotspotProxyApp.swift
7e55a52a01e36ac8a877c766f6debb46bfe562bb000ab2799f2f859c69fa2337  ios/tests/ActivityStateTests.swift
ebf69759c09bb9d83fc830265942fe98834a2a6c0f411cb79fb4c0ab0a283162  simulator HotspotProxy executable
```
