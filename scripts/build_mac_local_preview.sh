#!/bin/sh
# Build and stage the components for a local Mac preview. This does not install
# them. The generated package remains blocked until the live installer exists.
set -eu
umask 077
cd "$(dirname "$0")/.."

if [ "$#" -ne 2 ]; then
    echo "usage: scripts/build_mac_local_preview.sh NEW_OUTPUT_DIRECTORY VERSION" >&2
    exit 2
fi
output=$1
version=$2
case "$output" in /*) ;; *) output="$(pwd)/$output" ;; esac
case "$version" in
    ''|*[!0-9.]*) echo "The version must contain only digits and dots." >&2; exit 2 ;;
esac
if [ -z "${HS_MAC_SIGN_IDENTITY:-}" ]; then
    echo "Set HS_MAC_SIGN_IDENTITY to your Apple Development identity." >&2
    exit 2
fi
case "${HS_MAC_SYSTEM_PREVIEW_CANDIDATE:-0}" in
    0|1) ;;
    *) echo "HS_MAC_SYSTEM_PREVIEW_CANDIDATE must be 0 or 1." >&2; exit 2 ;;
esac
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "The output directory already exists: $output" >&2
    exit 1
fi
mkdir -m 700 "$output" || { echo "Cannot create the output directory." >&2; exit 1; }

echo "Building the app with the local preview signing policy."
HS_MAC_LOCAL_PREVIEW=1 scripts/build_mac_app.sh "$output/HotspotShade-macOS-preview.zip"
mkdir -m 700 "$output/app"
ditto -x -k "$output/HotspotShade-macOS-preview.zip" "$output/app"
app="$output/app/HotspotShade.app"
engine="$app/Contents/Resources/bin/hotspotshade"

echo "Building the helper with the same local preview policy."
swift build --package-path macos/HotspotShadeKit -c release \
    -Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW --product HotspotShadeHelper
helper_bin=$(swift build --package-path macos/HotspotShadeKit -c release \
    -Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW --show-bin-path)
cp "$helper_bin/HotspotShadeHelper" "$output/HotspotShadeHelper"
chmod 0755 "$output/HotspotShadeHelper"
codesign --force --options runtime --identifier dev.hotspotshade.mac.helper \
    --sign "$HS_MAC_SIGN_IDENTITY" "$output/HotspotShadeHelper"

echo "Building the installer staging tool with the same policy."
swift build --package-path macos/Installer -c release \
    -Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW --product hotspotshade-installer-build
installer_bin=$(swift build --package-path macos/Installer -c release \
    -Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW --show-bin-path)
"$installer_bin/hotspotshade-installer-build" stage \
    --helper "$output/HotspotShadeHelper" --engine "$engine" \
    --launch-daemon macos/Helper/dev.hotspotshade.mac.helper.plist \
    --start-right macos/Helper/dev.hotspotshade.tunnel.start.plist \
    --app "$app" --version "$version" --output "$output/staged"

echo "Building and signing the installer coordinator."
if [ "${HS_MAC_SYSTEM_PREVIEW_CANDIDATE:-0}" = 1 ]; then
    swift build --package-path macos/Installer -c release \
        -Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW \
        -Xswiftc -DHOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE \
        --product hotspotshade-installer-coordinator
else
    swift build --package-path macos/Installer -c release \
        -Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW --product hotspotshade-installer-coordinator
fi
cp "$installer_bin/hotspotshade-installer-coordinator" "$output/hotspotshade-installer-coordinator"
chmod 0755 "$output/hotspotshade-installer-coordinator"
codesign --force --options runtime --identifier dev.hotspotshade.mac.installer.coordinator \
    --sign "$HS_MAC_SIGN_IDENTITY" "$output/hotspotshade-installer-coordinator"
app_details=$(codesign -dv "$app" 2>&1) || { echo "Cannot read the app signature." >&2; exit 1; }
coordinator_details=$(codesign -dv "$output/hotspotshade-installer-coordinator" 2>&1) \
    || { echo "Cannot read the coordinator signature." >&2; exit 1; }
app_team=$(printf '%s\n' "$app_details" | sed -n 's/^TeamIdentifier=//p')
coordinator_team=$(printf '%s\n' "$coordinator_details" | sed -n 's/^TeamIdentifier=//p')
case "$app_team" in
    *[!A-Z0-9]*|'') echo "The app signing team is invalid." >&2; exit 1 ;;
esac
if [ "${#app_team}" -ne 10 ] || [ "$app_team" != "$coordinator_team" ]; then
    echo "The app and coordinator signing teams do not match." >&2
    exit 1
fi
case "$coordinator_details" in
    *flags=*runtime*) ;;
    *) echo "The coordinator signature has no hardened runtime." >&2; exit 1 ;;
esac
requirement="=anchor apple generic and identifier \"dev.hotspotshade.mac.installer.coordinator\" and certificate leaf[subject.OU] = \"$app_team\" and certificate 1[field.1.2.840.113635.100.6.2.1] exists and certificate leaf[field.1.2.840.113635.100.6.1.12] exists and !entitlement[\"com.apple.security.get-task-allow\"] and !entitlement[\"com.apple.security.cs.disable-library-validation\"] and !entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"]"
codesign --verify --strict -R "$requirement" "$output/hotspotshade-installer-coordinator" \
    || { echo "The coordinator signature does not match the preview policy." >&2; exit 1; }
"$output/hotspotshade-installer-coordinator" self-check \
    || { echo "The coordinator could not verify its running identity." >&2; exit 1; }
policy=$("$output/hotspotshade-installer-coordinator" preview-policy) \
    || { echo "The coordinator policy cannot be read." >&2; exit 1; }
if [ "${HS_MAC_SYSTEM_PREVIEW_CANDIDATE:-0}" = 1 ]; then
    [ "$policy" = 'system-preview: enabled' ] || { echo "The candidate policy is not enabled." >&2; exit 1; }
else
    [ "$policy" = 'system-preview: disabled' ] || { echo "The ordinary preview policy is not disabled." >&2; exit 1; }
fi
"$output/hotspotshade-installer-coordinator" verify-preview \
    --app "$app" --payload "$output/staged/payload" --manifest "$output/staged/manifest.json" \
    || { echo "The coordinator could not verify the staged preview." >&2; exit 1; }

echo "Staged local preview components in $output."
echo "Coordinator policy: $policy. No installation was performed."
