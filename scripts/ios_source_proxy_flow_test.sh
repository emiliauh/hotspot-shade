#!/usr/bin/env bash
# Host flow test: the real Swift source proxy with the Rust target client.
#
# The harness compiles the same ProxyServer, pairing responder, relay, and
# connect policy code as the iOS app for this Mac. It uses the Debug test
# override and approves its own pairing prompt. The Rust client pairs, runs one
# TCP and UDP destinations, a domain target, a wrong token, and a refusal.
#
# This test sets no route, creates no interface, and uses no cellular path. It
# is not the app and does not prove the Simulator network stack, carrier
# behavior, or a physical hotspot. Run it only on a host where port 18090 is
# free.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=ios/HotspotProxy
TESTS=ios/tests
OUT="$(mktemp -d)"
HARNESS_PID=""

cleanup() {
  if [ -n "$HARNESS_PID" ] && kill -0 "$HARNESS_PID" 2>/dev/null; then
    kill -TERM "$HARNESS_PID" 2>/dev/null || true
    wait "$HARNESS_PID" 2>/dev/null || true
  fi
  rm -rf "$OUT"
}
trap cleanup EXIT

xcrun swiftc -DDEBUG -DPROXY_LISTENER_LIFECYCLE_TESTING -parse-as-library -o "$OUT/proxy-flow-harness" \
  "$TESTS/ProxyFlowHarness.swift" \
  "$SRC/ActivityState.swift" \
  "$SRC/CellularICMPEcho.swift" \
  "$SRC/ConnectRetryPolicy.swift" \
  "$SRC/ConnectSummary.swift" \
  "$SRC/ConnectWatch.swift" \
  "$SRC/DatagramQueue.swift" \
  "$SRC/DiagnosticsReport.swift" \
  "$SRC/HotspotWatch.swift" \
  "$SRC/Pairing.swift" \
  "$SRC/PairingDisplay.swift" \
  "$SRC/PairingListenerPolicy.swift" \
  "$SRC/ProxyServer.swift" \
  "$SRC/SessionCapacity.swift" \
  "$SRC/TransientNetworkErrors.swift" \
  "$SRC/TrustActivity.swift"

"$OUT/proxy-flow-harness" >"$OUT/harness.log" 2>&1 &
HARNESS_PID=$!

ready=0
for _ in $(seq 1 300); do
  if grep -q "HARNESS_READY" "$OUT/harness.log" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$HARNESS_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [ "$ready" -ne 1 ]; then
  echo "The host harness did not become ready." >&2
  cat "$OUT/harness.log" >&2
  exit 1
fi

HS_IOS_SIM=1 HS_IOS_SIM_ADDRESS=127.0.0.1 cargo test --locked \
  --manifest-path rust/Cargo.toml \
  --test ios_simulator_proxy_flow -- --ignored --nocapture --test-threads=1

echo "--- harness log ---"
cat "$OUT/harness.log"
