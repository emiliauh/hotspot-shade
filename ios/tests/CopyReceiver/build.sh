#!/bin/sh
# Build the simulator-only paste receiver in a new temporary directory.
# This does not install or launch it and does not touch an existing app.
set -eu

fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
case "$(uname -m)" in
    arm64) target=arm64-apple-ios15.0-simulator ;;
    x86_64) target=x86_64-apple-ios15.0-simulator ;;
    *) echo "Unsupported simulator host architecture." >&2; exit 1 ;;
esac

output_dir=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-copy-receiver.XXXXXXXX")
app_dir="$output_dir/CopyReceiver.app"
mkdir "$app_dir"
cp "$fixture_dir/Info.plist" "$app_dir/Info.plist"
plutil -lint "$app_dir/Info.plist" >/dev/null
sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun --sdk iphonesimulator swiftc -parse-as-library -target "$target" \
    -sdk "$sdk" -framework UIKit "$fixture_dir/main.swift" \
    -o "$app_dir/CopyReceiver"
codesign -s - "$app_dir"
codesign --verify --strict "$app_dir"
printf 'Simulator receiver built: %s\n' "$app_dir"
