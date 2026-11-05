#!/usr/bin/env bash
# Build and run the hermetic iOS logic tests on macOS. Each test is a
# standalone executable. No test opens a network socket or needs a device.
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

run PairingListenerPolicyTests "$SRC/PairingListenerPolicy.swift"
run PairingTests "$SRC/Pairing.swift"
run ConnectRetryPolicyTests "$SRC/ConnectWatch.swift" "$SRC/ConnectSummary.swift" "$SRC/ConnectRetryPolicy.swift"
run SessionCapacityTests "$SRC/SessionCapacity.swift"
run DatagramQueueTests "$SRC/DatagramQueue.swift"
run RelayHalfCloseTests "$SRC/DatagramQueue.swift"
run DiagnosticsReportTests "$SRC/DiagnosticsReport.swift" "$SRC/ConnectWatch.swift" "$SRC/ConnectSummary.swift" "$SRC/ConnectRetryPolicy.swift" "$SRC/SessionCapacity.swift" "$SRC/ActivityState.swift"
run TrustActivityTests "$SRC/ActivityState.swift" "$SRC/TrustActivity.swift" "$SRC/Pairing.swift"
run SessionPresenceTests "$SRC/ProxyServer.swift" "$SRC/ActivityState.swift" "$SRC/CellularICMPEcho.swift" "$SRC/ConnectRetryPolicy.swift" "$SRC/ConnectSummary.swift" "$SRC/ConnectWatch.swift" "$SRC/DatagramQueue.swift" "$SRC/DiagnosticsReport.swift" "$SRC/HotspotWatch.swift" "$SRC/Pairing.swift" "$SRC/PairingDisplay.swift" "$SRC/PairingListenerPolicy.swift" "$SRC/SessionCapacity.swift" "$SRC/TransientNetworkErrors.swift" "$SRC/TrustActivity.swift"
echo "ALL SWIFT TESTS PASSED"
