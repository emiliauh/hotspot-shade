#!/bin/sh
set -eu

# Regenerate every PNG in this folder from the SVG sources.
# Tools: stock macOS sips and swift. No network. No Python.

cd "$(dirname "$0")"

SIPS=/usr/bin/sips
SWIFT=/usr/bin/swift
SRGB="/System/Library/ColorSync/Profiles/sRGB Profile.icc"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/hs-logo.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

fail() {
    echo "$1" >&2
    exit 1
}

png_width() {
    "$SIPS" -g pixelWidth "$1" | awk '/pixelWidth/ {print $2}'
}

png_alpha() {
    "$SIPS" -g hasAlpha "$1" | awk '/hasAlpha/ {print $2}'
}

render_svg() {
    "$SIPS" -s format png "$1" --out "$2" >/dev/null
}

render_svg concept-a.svg concept-a.png
render_svg concept-b.svg concept-b.png
render_svg concept-c.svg concept-c.png

render_svg logo.svg logo-1024.png
render_svg logo-square.svg "$WORK/ios-raw.png"
render_svg logo-mac.svg logo-mac-1024.png

# The iOS icon must be opaque. The helper writes an sRGB PNG with no alpha.
"$SWIFT" render_helper.swift opaque "$WORK/ios-raw.png" logo-ios-1024.png

# The comparison sheet uses the three concept PNGs.
"$SWIFT" render_helper.swift sheet concepts.png \
    concept-a.png concept-b.png concept-c.png

# Check the production icon on light and dark backgrounds at small sizes.
"$SWIFT" render_helper.swift backgrounds icon-backgrounds.png logo-mac-1024.png
"$SIPS" -m "$SRGB" icon-backgrounds.png --out icon-backgrounds.png >/dev/null

"$SIPS" -z 512 512 logo-1024.png --out logo-512.png >/dev/null
"$SIPS" -z 512 512 logo-mac-1024.png --out logo-mac-512.png >/dev/null

for size in 16 32 64 128 256 512 1024; do
    "$SIPS" -z "$size" "$size" logo-mac-1024.png \
        --out "mac-icon-$size.png" >/dev/null
done

# The SVG renderer and the helper write sRGB already. This step makes the
# profile explicit and keeps the alpha channel.
for f in logo-1024.png logo-512.png logo-mac-1024.png logo-mac-512.png logo-ios-1024.png \
         concepts.png mac-icon-16.png mac-icon-32.png mac-icon-64.png \
         mac-icon-128.png mac-icon-256.png mac-icon-512.png mac-icon-1024.png; do
    "$SIPS" -m "$SRGB" "$f" --out "$f" >/dev/null
done

alpha=$(png_alpha logo-ios-1024.png)
[ "$alpha" = "no" ] || fail "logo-ios-1024.png must not have an alpha channel"

width=$(png_width logo-ios-1024.png)
[ "$width" = "1024" ] || fail "logo-ios-1024.png must be 1024 px wide"

"$SIPS" -g profile logo-ios-1024.png | grep -q "sRGB" || \
    fail "logo-ios-1024.png must use the sRGB profile"

[ "$(png_width logo-mac-1024.png)" = "1024" ] || \
    fail "logo-mac-1024.png must be 1024 px wide"
[ "$(png_alpha logo-mac-1024.png)" = "yes" ] || \
    fail "logo-mac-1024.png must keep an alpha channel"

# The favicon must stay local. It may not load a remote image or style.
if grep -E '<image|href="https?:' favicon.svg >/dev/null; then
    fail "favicon.svg must not load an external asset"
fi

ios_icons=../../ios/HotspotProxy/Assets.xcassets/AppIcon.appiconset
mac_icons=../../macos/HotspotShade/Assets.xcassets/AppIcon.appiconset
cp logo-ios-1024.png "$ios_icons/AppIcon-1024.png"
for size in 16 32 128 256 512; do
    double=$((size * 2))
    cp "mac-icon-$size.png" "$mac_icons/icon_${size}x${size}.png"
    cp "mac-icon-$double.png" "$mac_icons/icon_${size}x${size}@2x.png"
done

# Check both catalogs. Every file that Contents.json names must exist, and
# every file must have the size and the alpha channel that the slot needs.
for catalog in "$ios_icons" "$mac_icons"; do
    for name in $(sed -n 's/.*"filename" : "\([^"]*\)".*/\1/p' "$catalog/Contents.json"); do
        [ -f "$catalog/$name" ] || fail "Missing $catalog/$name"
    done
done

[ "$(png_width "$ios_icons/AppIcon-1024.png")" = "1024" ] || \
    fail "AppIcon-1024.png must be 1024 px wide"
[ "$(png_alpha "$ios_icons/AppIcon-1024.png")" = "no" ] || \
    fail "AppIcon-1024.png must not have an alpha channel"

for size in 16 32 128 256 512; do
    double=$((size * 2))
    file="$mac_icons/icon_${size}x${size}.png"
    [ "$(png_width "$file")" = "$size" ] || \
        fail "$file must be $size px wide"
    [ "$(png_alpha "$file")" = "yes" ] || \
        fail "$file must keep an alpha channel"
    file="$mac_icons/icon_${size}x${size}@2x.png"
    [ "$(png_width "$file")" = "$double" ] || \
        fail "$file must be $double px wide"
    [ "$(png_alpha "$file")" = "yes" ] || \
        fail "$file must keep an alpha channel"
done

echo "Logo PNGs regenerated."
echo "logo-ios-1024.png: 1024 px, no alpha, sRGB."
echo "logo-mac-1024.png: 1024 px, alpha, sRGB."
echo "mac-icon-16.png through mac-icon-1024.png: alpha, sRGB."
echo "AppIcon catalogs: sizes and alpha checked."
