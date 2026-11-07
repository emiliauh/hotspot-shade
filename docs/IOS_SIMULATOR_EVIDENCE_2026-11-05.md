# iOS Simulator evidence, 2026-11-05

This is partial simulator evidence. It does not establish physical-device,
carrier, hotspot, or real Keychain recovery behavior.
The later working tree disables token rotation pending review; this earlier
snapshot was not used to validate that gate.

- Source: a 55-file snapshot of `ios/` from the dirty working tree at base
  commit `1a37ed7`. The snapshot included `.DS_Store` and Xcode `xcuserdata`,
  so it is not a clean source-only snapshot and must not be uploaded as-is.
  The local manifest SHA-256 was
  `f751a6ee91ce365eb4ca6168a660e42a4b73acad4b6c834f8c0d336c23bfdd75`.
- Build: Debug iOS Simulator, signing disabled, with bundle identifier
  `local.hotspotproxy.app.uitest`. The app binary SHA-256 was
  `9fcc7afc2f5d64940430272b15ee9d582a0a1a3a2374f4b6dd1d94930f94faa0`.
- Simulator: iPhone 17, iOS 27.2. The test app used a separate bundle
  identifier from the existing app and did not replace its data.
- Observed: the Dashboard showed the proxy as off, a Start proxy control,
  unpaired status, no connection attempts, and Dashboard and Settings tabs.
  The proxy was not started.
- Not observed: the Settings screen, token rotation or restore, recovery
  warnings, screenshots, appearance variants, or larger text sizes. Device
  tooling failed with `Remote daemon is unavailable` after a retry. The
  simulator and separate test app were left in place; the existing app was
  not uninstalled or modified.

The source snapshot, manifest, and build log were recorded in the local test
scratchpad. They are not release artifacts. A new run against a reviewed build
from a source-only snapshot that excludes machine-specific files is required,
and the device recovery gates remain open.

## Separate signed simulator comparison

A later iPhone 18 Pro, iOS 27.2 smoke test of an unsigned Debug build reported
`keychain_read_failed(-34018)` at the recovery-marker read and disabled token
controls. A separately identified Debug app built with simulator signing enabled
showed the controls enabled and no storage warning. The original installation and
its data were left in place; the signed comparison used a different identity.
The iOS app and project inputs were reported unchanged during that comparison.

This supports a signing-related explanation but does not isolate signing from
the changed Keychain identity, prove recovery or persistence, or establish the
original installation's state. See [the simulator build instructions](../ios/README.md).
Neither simulator run establishes physical-device, hotspot, or carrier behavior.
