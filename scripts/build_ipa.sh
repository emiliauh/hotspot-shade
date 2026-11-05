#!/usr/bin/env bash
# Build an UNSIGNED iOS app and package it as an IPA. The IPA carries no code
# signature, no provisioning profile, and no certificate. Re-sign it with your
# own certificate and install it with a sideloading tool. See ios/README.md.
# Usage: scripts/build_ipa.sh [OUTPUT_IPA]
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-build/HotspotShade-iOS-unsigned.ipa}"
DD="$(mktemp -d)"
trap 'rm -rf "$DD"' EXIT

xcodebuild -project ios/HotspotProxy.xcodeproj -scheme HotspotProxy \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath "$DD" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
  build

APP="$DD/Build/Products/Release-iphoneos/HotspotProxy.app"
[ -d "$APP" ] || { echo "app bundle not found: $APP" >&2; exit 1; }

mkdir -p "$DD/ipa/Payload" "$(dirname "$OUT")"
cp -R "$APP" "$DD/ipa/Payload/"
OUT_ABS="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
rm -f "$OUT_ABS"
(cd "$DD/ipa" && zip -qry "$OUT_ABS" Payload)
echo "Wrote the unsigned HotspotShade iOS IPA: $OUT_ABS"
echo "The IPA has no signature. Sign it with your own certificate before you install it."
