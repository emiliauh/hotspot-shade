#!/usr/bin/env bash
# Exercise the real, non-demo engine as a normal user. The sandbox confines
# outbound sockets to loopback and denies access to the user's pairing key.
# This does not start a tunnel, change routes, or test a physical hotspot.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$#" -ne 1 ] || [ ! -x "$1" ] || [ "$(id -u)" -eq 0 ]; then
    echo 'Usage: run as a normal user with the real engine executable as the only argument.' >&2
    exit 2
fi
engine=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
scratch=$(mktemp -d "${TMPDIR:-/tmp}/hs-unprivileged-engine.XXXXXXXX")
trap 'rm -rf "$scratch"' EXIT

swift test --package-path macos/HotspotShadeKit --scratch-path "$scratch/build" \
    --filter UnprivilegedEngineIntegrationTests >/dev/null
xctest=$(xcrun --find xctest)
bundle="$scratch/build/out/Products/Debug/HotspotShadeKitTests.xctest"
if [ ! -d "$bundle" ]; then
    echo 'The compiled test bundle was not found.' >&2
    exit 1
fi

profile='(version 1)
(allow default)
(deny network-outbound)
(allow network-outbound (remote ip "localhost:*"))
(deny file-read* file-write* (subpath (param "IDENTITY_DIRECTORY")))'

HS_TEST_CONFINED_REAL_ENGINE=1 HS_TEST_REAL_ENGINE="$engine" \
    /usr/bin/sandbox-exec -D "IDENTITY_DIRECTORY=$HOME/Library/Application Support/hotspotshade" \
    -p "$profile" "$xctest" -XCTest \
    HotspotShadeKitTests.UnprivilegedEngineIntegrationTests/testRealEngineReportsStatusAsAnOrdinaryUser \
    "$bundle"
