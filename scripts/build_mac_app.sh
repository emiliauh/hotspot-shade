#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
output=${1:?Give the output zip path}
case "$output" in /*) ;; *) output="$(pwd)/$output" ;; esac
cargo_bin=$(command -v cargo || true)
if [ -z "$cargo_bin" ] && [ -x "$HOME/.cargo/bin/cargo" ]; then cargo_bin="$HOME/.cargo/bin/cargo"; fi
if [ -z "$cargo_bin" ]; then echo "Cargo is missing." >&2; exit 1; fi
case "$(uname -m)" in
  arm64) arch=arm64; target=aarch64-apple-darwin ;;
  x86_64) arch=x86_64; target=x86_64-apple-darwin ;;
  *) echo "Unsupported architecture." >&2; exit 1 ;;
esac
"$cargo_bin" build --release --locked --target "$target" --manifest-path rust/Cargo.toml
target_dir=${CARGO_TARGET_DIR:-rust/target}
case "$target_dir" in /*) ;; *) target_dir="$(pwd)/$target_dir" ;; esac
derived=${HS_MAC_DERIVED_DATA:-/tmp/hs_m_dd}
xcodebuild -project macos/HotspotShade.xcodeproj -scheme HotspotShade -configuration Release -derivedDataPath "$derived" ARCHS="$arch" ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=NO build
app="$derived/Build/Products/Release/HotspotShade.app"
mkdir -p "$app/Contents/Resources/bin" "$(dirname "$output")"
cp "$target_dir/$target/release/hotspotshade" "$app/Contents/Resources/bin/hotspotshade"
chmod +x "$app/Contents/Resources/bin/hotspotshade"
codesign --force --sign - "$app/Contents/Resources/bin/hotspotshade"
codesign --force --deep --sign - "$app"
codesign --verify --deep --strict "$app"
rm -f "$output"
ditto -c -k --keepParent "$app" "$output"
