#!/usr/bin/env bash
# Build and run the hermetic iOS logic tests on macOS. Each test is a
# standalone executable. Most tests are pure logic. PairingSuspensionTests and
# TokenLifecycleServerTests run the real server on the Debug loopback pair and
# bind TCP port 18090; they fail if that port is busy and never skip their
# resume checks.
# Usage: scripts/swift_tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=ios/HotspotProxy
TESTS=ios/tests
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

# test file : source files it covers
run() {
  local name="$1"; shift
  echo "== $name"
  xcrun swiftc -parse-as-library -o "$OUT/$name" "$TESTS/$name.swift" "$@"
  "$OUT/$name"
  echo "   ok"
}

run CellularICMPEchoTests "$SRC/CellularICMPEcho.swift"
run HotspotWatchTests "$SRC/HotspotWatch.swift"
# The same test with DEBUG covers the Simulator test override.
echo "== HotspotWatchTests (DEBUG)"
xcrun swiftc -DDEBUG -parse-as-library -o "$OUT/HotspotWatchTestsDebug" "$TESTS/HotspotWatchTests.swift" "$SRC/HotspotWatch.swift"
"$OUT/HotspotWatchTestsDebug"
echo "   ok"
run TransientNetworkErrorsTests "$SRC/TransientNetworkErrors.swift"
run ConnectWatchTests "$SRC/ConnectWatch.swift" "$SRC/ConnectSummary.swift"
run ConnectSummaryTests "$SRC/ConnectSummary.swift" "$SRC/ConnectWatch.swift"
run ActivityStateTests "$SRC/ActivityState.swift"
run LocationHealthTests "$SRC/ActivityState.swift"
run StopRecordTests "$SRC/ActivityState.swift"
run NotificationPolicyTests "$SRC/ActivityState.swift"
run PairingDisplayTests "$SRC/PairingDisplay.swift" "$SRC/ActivityState.swift"
run SourceStatePresentationTests "$SRC/PairingDisplay.swift" "$SRC/ActivityState.swift"

run PairingListenerPolicyTests "$SRC/PairingListenerPolicy.swift" "$SRC/HotspotWatch.swift"
run PairingTests "$SRC/Pairing.swift"
run ConnectRetryPolicyTests "$SRC/ConnectWatch.swift" "$SRC/ConnectSummary.swift" "$SRC/ConnectRetryPolicy.swift"
run SessionCapacityTests "$SRC/SessionCapacity.swift"
run DatagramQueueTests "$SRC/DatagramQueue.swift"
run RelayHalfCloseTests "$SRC/DatagramQueue.swift"
run DiagnosticsReportTests "$SRC/DiagnosticsReport.swift" "$SRC/ConnectWatch.swift" "$SRC/ConnectSummary.swift" "$SRC/ConnectRetryPolicy.swift" "$SRC/SessionCapacity.swift" "$SRC/ActivityState.swift"
# The source capability model and the diagnostics lines that report it.
run SourceDeviceCapabilityTests "$SRC/SourceDeviceCapabilities.swift" "$SRC/DiagnosticsReport.swift" "$SRC/ConnectWatch.swift" "$SRC/ConnectSummary.swift" "$SRC/ConnectRetryPolicy.swift" "$SRC/SessionCapacity.swift" "$SRC/ActivityState.swift"
run TrustActivityTests "$SRC/ActivityState.swift" "$SRC/TrustActivity.swift" "$SRC/Pairing.swift"
run TokenStorageSafetyTests "$SRC/TokenLifecycle.swift" "$SRC/SecureTokenStore.swift" "$SRC/ActivityState.swift" "$TESTS/TokenStoreFakes.swift"
echo "== TokenStorageSafetyTests (dormant failure paths)"
xcrun swiftc -DTOKEN_LIFECYCLE_TESTING -parse-as-library -o "$OUT/TokenStorageSafetyFailureTests" \
  "$TESTS/TokenStorageSafetyTests.swift" "$SRC/TokenLifecycle.swift" "$SRC/SecureTokenStore.swift" "$SRC/ActivityState.swift" "$TESTS/TokenStoreFakes.swift"
"$OUT/TokenStorageSafetyFailureTests"
echo "   ok"
run SecureTokenStoreTests "$SRC/SecureTokenStore.swift" "$TESTS/TokenStoreFakes.swift"
# The token lifecycle that ProxyModel runs: launch, rotation, retry, restore,
# and replacement against fake storage and a recording pairing sink.
run TokenLifecycleTests "$SRC/TokenLifecycle.swift" "$SRC/SecureTokenStore.swift" "$SRC/ActivityState.swift" "$TESTS/TokenStoreFakes.swift"
# The disabled staged rotation and restart matrix models selected crash points,
# external writers, downgrade copies, and damaged intents with fakes. It does
# not prove Keychain or UserDefaults crash durability on a device.
run TokenRotationRecoveryTests "$SRC/TokenLifecycle.swift" "$SRC/SecureTokenStore.swift" "$SRC/ActivityState.swift" "$TESTS/TokenStoreFakes.swift"
# ProxyModel needs UIKit and cannot run here. It must reach the token store and
# the pairing listener only through TokenLifecycle, so check the source. The
# simulator build in CI and in the change checklist type-checks the real wiring.
echo "== ProxyModel token wiring (source check)"
APP="$SRC/HotspotProxyApp.swift"
if grep -nE 'tokenStore|adoptToken|lastTokenError|server\.(suspendPairing|configurePairing)' "$APP"; then
  echo "FAIL: ProxyModel must use TokenLifecycle for token storage and pairing credentials"
  exit 1
fi
if grep -nE 'rotationReviewed[[:space:]]*:' "$APP"; then
  echo "FAIL: ProxyModel must not override the disabled rotation review gate"
  exit 1
fi
for needle in 'tokens.attach(host: self)' 'tokens.launch()' 'tokens.rotate()' 'tokens.replaceInvalid()' 'tokens.restoreLegacy()' 'tokens.retryLoadIfNeeded()' 'tokens.syncPairing()' 'tokens.beginStart()' 'tokens.endStart()' 'extension ProxyModel: TokenLifecycleHost' 'extension ProxyServer: PairingCredentialSink'; do
  grep -qF "$needle" "$APP" || { echo "FAIL: ProxyModel no longer calls $needle"; exit 1; }
done
# Text selection would expose an alternate system Copy path without the
# local-only expiration used by the app's Copy token button. This checks the
# current source shape; it does not replace a UIKit or pasteboard test.
if ! awk '
  /Text\(model\.token\)/ { in_token = 1; count++ }
  in_token && /\.textSelection[[:space:]]*\(/ { bad = 1 }
  in_token && /\.privacySensitive\(\)/ { private_text = 1 }
  in_token && /Button\("Copy token"\)/ { in_token = 0; copy_button = 1 }
  /private func hideToken\(\)/ { in_hide = 1; hide_count++ }
  in_hide && /[Pp]asteboard/ { bad = 1 }
  in_hide && /^    }/ { in_hide = 0 }
  /func sceneChanged\(_ phase: ScenePhase\)/ { in_scene = 1; scene_count++ }
  in_scene && /[Pp]asteboard/ { bad = 1 }
  in_scene && /^    }/ { in_scene = 0 }
  /func copyDiagnostics\(\)/ { in_diagnostics = 1; diagnostics_count++ }
  in_diagnostics && /UIPasteboard\.general\.string = diagnosticsText\(\)/ { diagnostic_write = NR }
  in_diagnostics && /tokenPasteboardOwnership\.forget\(\)/ { diagnostic_forget = NR }
  in_diagnostics && /^    }/ { in_diagnostics = 0 }
  /func copyToken\(\)/ { in_copy = 1; copy_count++ }
  in_copy && /guard tokenVisible, !token\.isEmpty/ { copy_guard = 1 }
  in_copy && /\.localOnly: true/ && /\.expirationDate:/ { copy_options = 1 }
  in_copy && /tokenPasteboardOwnership\.record\(before:/ { copy_record = 1 }
  in_copy && /^    }/ { in_copy = 0 }
  /func tokenStateDidChange\(\)/ { in_change = 1; change_count++ }
  in_change && /if token != tokens\.token/ { changed_token = NR }
  in_change && /clearOwnedTokenPasteboard\(\)/ { changed_clear = NR }
  in_change && /^    }/ { in_change = 0 }
  /clearOwnedTokenPasteboard\(\)/ { clear_count++ }
  END {
    exit !(count == 1 && private_text && copy_button && !bad && !in_token &&
      hide_count == 1 && !in_hide && scene_count == 1 && !in_scene &&
      diagnostics_count == 1 && diagnostic_write && diagnostic_forget > diagnostic_write &&
      copy_count == 1 && copy_guard && copy_options && copy_record &&
      change_count == 1 && changed_token && changed_clear > changed_token && clear_count == 2)
  }
' "$APP"; then
  echo "FAIL: token pasteboard wiring changed; review copy, hide, scene, diagnostics, and token-change behavior"
  exit 1
fi
echo "   ok"
run ProxyStartPolicyTests "$SRC/ProxyStartPolicy.swift"
run ManualConnectionTests "$SRC/ManualConnection.swift" "$SRC/ActivityState.swift"
# The source files for the proxy server and its constant-time token check.
PROXY_SOURCES=(
  "$SRC/ProxyServer.swift"
  "$SRC/ActivityState.swift"
  "$SRC/CellularICMPEcho.swift"
  "$SRC/ConnectRetryPolicy.swift"
  "$SRC/ConnectSummary.swift"
  "$SRC/ConnectWatch.swift"
  "$SRC/DatagramQueue.swift"
  "$SRC/DiagnosticsReport.swift"
  "$SRC/HotspotWatch.swift"
  "$SRC/Pairing.swift"
  "$SRC/PairingDisplay.swift"
  "$SRC/PairingListenerPolicy.swift"
  "$SRC/SessionCapacity.swift"
  "$SRC/TransientNetworkErrors.swift"
  "$SRC/TrustActivity.swift"
)
run SessionPresenceTests "${PROXY_SOURCES[@]}"
run ProxyTokenTests "${PROXY_SOURCES[@]}"
echo "== ProxyListenerLifecycleTests"
xcrun swiftc -DPROXY_LISTENER_LIFECYCLE_TESTING -parse-as-library \
  -o "$OUT/ProxyListenerLifecycleTests" "$TESTS/ProxyListenerLifecycleTests.swift" "${PROXY_SOURCES[@]}"
"$OUT/ProxyListenerLifecycleTests"
echo "   ok"
run ClientHelloShapeTests "${PROXY_SOURCES[@]}"
# The pairing listener must stay down while the app has no usable token, also
# across a scene change. The test runs the real server on the loopback test
# pair and binds port 18090 while the listener is up, so that port must be free.
echo "== PairingSuspensionTests (DEBUG)"
xcrun swiftc -DDEBUG -parse-as-library -o "$OUT/PairingSuspensionTests" \
  "$TESTS/PairingSuspensionTests.swift" "${PROXY_SOURCES[@]}"
"$OUT/PairingSuspensionTests"
echo "   ok"
# The real token lifecycle drives the real server: a rotation takes the
# listener down before the change and brings it back with the confirmed token,
# and an invalid stored token keeps it down.
# It also binds port 18090 while the listener is up.
echo "== TokenLifecycleServerTests (DEBUG)"
xcrun swiftc -DDEBUG -parse-as-library -o "$OUT/TokenLifecycleServerTests" \
  "$TESTS/TokenLifecycleServerTests.swift" "$TESTS/TokenStoreFakes.swift" \
  "$SRC/TokenLifecycle.swift" "$SRC/SecureTokenStore.swift" "${PROXY_SOURCES[@]}"
"$OUT/TokenLifecycleServerTests"
echo "   ok"
echo "ALL SWIFT TESTS PASSED"
