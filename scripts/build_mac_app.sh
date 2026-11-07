#!/bin/sh
# Build the macOS app bundle and zip it.
#
# The default build is ad-hoc signed. It opens the real dashboard and pairing
# with the bundled user engine; Turn on needs the signed helper and fails closed
# without it. Set
# HS_MAC_SIGN_IDENTITY to a Developer ID Application identity or its 40-character
# SHA-1 fingerprint to produce a hardened-runtime app. A matching, separately
# installed helper and engine are also required. This script does not build the helper, build an installer package,
# notarize the app, install anything, or start a tunnel.
set -eu
umask 077
cd "$(dirname "$0")/.."

usage() {
    cat <<'EOF'
usage: scripts/build_mac_app.sh OUTPUT.zip

Build the engine and the HotspotShade app for the host architecture, copy the
engine into the app bundle, sign it, and write a zip.

Environment:
  HS_MAC_SIGN_IDENTITY  Developer ID Application identity or its 40-character
                        SHA-1 fingerprint. When set, the engine and the app are
                        signed with the hardened runtime and a secure timestamp.
                        When unset, the build is ad-hoc signed. Its dashboard
                        and pairing use the real user engine; Turn on needs the
                        signed helper and fails closed without it.
  HS_MAC_LOCAL_PREVIEW  Set to 1 only for a local development build. Requires
                        an Apple Development signing identity. This compiles
                        the separate local-preview helper trust policy; it does
                        not install the helper or enable the installer.
  HS_MAC_DERIVED_DATA   Xcode derived data directory. Default: a new private
                        temporary directory that is removed at exit. A supplied
                        path must not be a symlink and must not be writable by a
                        group or another user.
  CARGO_TARGET_DIR      Rust target directory. Default: rust/target. The path
                        must not be a symlink.

The script refuses a symlink or special file as the output path. An existing
output is replaced only after the staged build succeeds. Before replacement,
a failed build leaves the existing output unchanged; it is not a new artifact.
The script does not build the protected helper, build an installer package,
notarize the app, install anything, or start a tunnel.
EOF
}

case "${1:-}" in
    --help|-h)
        usage
        exit 0
        ;;
    '')
        echo "Give the output zip path." >&2
        usage >&2
        exit 2
        ;;
esac
if [ "$#" -ne 1 ]; then
    echo "Give exactly one output zip path." >&2
    usage >&2
    exit 2
fi

die() {
    echo "$*" >&2
    if [ -n "${output:-}" ] && [ -f "$output" ] && [ ! -L "$output" ]; then
        echo "Build failed. Existing output was not replaced: $output" >&2
    fi
    exit 1
}

output=$1
case "$output" in /*) ;; *) output="$(pwd)/$output" ;; esac
if [ -L "$output" ]; then
    die "The output path must not be a symlink: $output"
fi
if [ -d "$output" ]; then
    die "The output path must be a file, not a directory: $output"
fi
if [ -e "$output" ] && [ ! -f "$output" ]; then
    die "The output path must be a regular file: $output"
fi

output_dir=$(dirname "$output")
output_name=$(basename "$output")
if [ ! -d "$output_dir" ]; then
    mkdir -p "$output_dir" || die "Cannot create the output directory: $output_dir"
fi
output_dir=$(CDPATH= cd -P "$output_dir" && pwd -P) || die "Cannot resolve the output directory: $output_dir"
output=$output_dir/$output_name
if [ -L "$output" ]; then
    die "The output path must not be a symlink: $output"
fi
if [ -d "$output" ]; then
    die "The output path must be a file, not a directory: $output"
fi
if [ -e "$output" ] && [ ! -f "$output" ]; then
    die "The output path must be a regular file: $output"
fi

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die "$1 is missing. Install the Xcode command line tools and try again."
    fi
}

require_tool xcodebuild
require_tool codesign
require_tool ditto
require_tool lipo
require_tool plutil

cargo_bin=$(command -v cargo || true)
if [ -z "$cargo_bin" ] && [ -x "$HOME/.cargo/bin/cargo" ]; then cargo_bin="$HOME/.cargo/bin/cargo"; fi
if [ -z "$cargo_bin" ]; then die "Cargo is missing."; fi

case "$(uname -m)" in
    arm64) arch=arm64; target=aarch64-apple-darwin ;;
    x86_64) arch=x86_64; target=x86_64-apple-darwin ;;
    *) die "Unsupported architecture." ;;
esac
if [ "$arch" != arm64 ]; then
    echo "Warning: building for $arch; the release app is arm64 only." >&2
fi

engine_identifier=dev.hotspotshade.engine
app_identifier=dev.hotspotshade.mac

sign_identity=${HS_MAC_SIGN_IDENTITY:-}
local_preview=${HS_MAC_LOCAL_PREVIEW:-0}
case "$local_preview" in
    0|1) ;;
    *) die "HS_MAC_LOCAL_PREVIEW must be 0 or 1." ;;
esac
if [ "$local_preview" = 1 ] && [ -z "$sign_identity" ]; then
    die "A local preview requires an Apple Development signing identity."
fi
if [ -n "$sign_identity" ]; then
    case "$sign_identity" in
        *'
'*) die "HS_MAC_SIGN_IDENTITY must not contain a newline." ;;
    esac
    case "$sign_identity" in
        "Developer ID Application: "*)
            [ "$local_preview" = 0 ] || die "A local preview requires an Apple Development identity."
            ;;
        "Apple Development: "*)
            [ "$local_preview" = 1 ] || die "An ordinary build requires a Developer ID Application identity."
            ;;
        *)
            case "$sign_identity" in
                *[!0-9A-Fa-f]*)
                    die "HS_MAC_SIGN_IDENTITY must be a Developer ID Application identity or its 40-character SHA-1 fingerprint."
                    ;;
            esac
            if [ "${#sign_identity}" -ne 40 ]; then
                die "HS_MAC_SIGN_IDENTITY must be a Developer ID Application identity or its 40-character SHA-1 fingerprint."
            fi
            ;;
    esac
fi

check_private_directory() {
    directory=$1
    label=$2
    if ! command -v stat >/dev/null 2>&1; then
        echo "Warning: stat is missing; the $label privacy cannot be checked." >&2
        return 0
    fi
    owner=$(stat -f '%Su' "$directory" 2>/dev/null || true)
    mode=$(stat -f '%Lp' "$directory" 2>/dev/null || true)
    current_user=$(id -un)
    if [ "$owner" != "$current_user" ]; then
        die "$label is owned by '$owner', expected '$current_user': $directory"
    fi
    case "$mode" in
        ''|*[!0-7]*) die "$label mode cannot be read: $directory" ;;
    esac
    if [ $((0$mode & 0022)) -ne 0 ]; then
        die "$label is writable by a group or another user: $directory"
    fi
    if ! listing=$(/bin/ls -lde "$directory" 2>/dev/null); then
        die "$label access control list cannot be read: $directory"
    fi
    if printf '%s\n' "$listing" | sed '1d' | grep -q .; then
        die "$label has an access control list: $directory"
    fi
}

target_dir=${CARGO_TARGET_DIR:-rust/target}
case "$target_dir" in /*) ;; *) target_dir="$(pwd)/$target_dir" ;; esac
if [ -L "$target_dir" ]; then
    die "CARGO_TARGET_DIR must not be a symlink: $target_dir"
fi
if [ -e "$target_dir" ] && [ ! -d "$target_dir" ]; then
    die "CARGO_TARGET_DIR must be a directory: $target_dir"
fi
mkdir -p "$target_dir" || die "Cannot create CARGO_TARGET_DIR: $target_dir"
target_dir=$(CDPATH= cd -P "$target_dir" && pwd -P) || die "Cannot resolve CARGO_TARGET_DIR: $target_dir"
check_private_directory "$target_dir" "CARGO_TARGET_DIR"

derived=${HS_MAC_DERIVED_DATA:-}
derived_cleanup=0
if [ -z "$derived" ]; then
    derived=$(mktemp -d "${TMPDIR:-/tmp}/hs-mac-derived.XXXXXX") || die "Cannot create a private derived data directory."
    derived_cleanup=1
else
    case "$derived" in /*) ;; *) derived="$(pwd)/$derived" ;; esac
    if [ -L "$derived" ]; then
        die "HS_MAC_DERIVED_DATA must not be a symlink: $derived"
    fi
    if [ -e "$derived" ] && [ ! -d "$derived" ]; then
        die "HS_MAC_DERIVED_DATA must be a directory: $derived"
    fi
    if [ ! -d "$derived" ]; then
        mkdir -p "$derived" || die "Cannot create HS_MAC_DERIVED_DATA: $derived"
    fi
    derived=$(CDPATH= cd -P "$derived" && pwd -P) || die "Cannot resolve HS_MAC_DERIVED_DATA: $derived"
    check_private_directory "$derived" "HS_MAC_DERIVED_DATA"
fi

tmp_dir=$(mktemp -d "$output_dir/.hotspotshade-build.XXXXXX") || die "Cannot create a private output staging directory."
tmp_zip=$tmp_dir/HotspotShade.zip
cleanup() {
    if [ -n "${tmp_dir:-}" ]; then
        rm -rf "$tmp_dir"
    fi
    if [ "${derived_cleanup:-0}" -eq 1 ] && [ -n "${derived:-}" ]; then
        rm -rf "$derived"
    fi
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

"$cargo_bin" build --release --locked --target "$target" --manifest-path rust/Cargo.toml || die "The engine build failed."

if [ "$local_preview" = 1 ]; then
    set -- 'OTHER_SWIFT_FLAGS=$(inherited) -D HOTSPOTSHADE_LOCAL_PREVIEW'
else
    set --
fi
xcodebuild -project macos/HotspotShade.xcodeproj -scheme HotspotShade -configuration Release -derivedDataPath "$derived" ARCHS="$arch" ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=NO "$@" build || die "The app build failed."

app="$derived/Build/Products/Release/HotspotShade.app"
app_exec="$app/Contents/MacOS/HotspotShade"
# The app bundle keeps the engine at Contents/Resources/bin/hotspotshade. The
# app runs it as the signed-in user for the dashboard and pairing. A tunnel
# start uses the separately installed root engine through the signed helper.
resources="$app/Contents/Resources"
bin_dir="$resources/bin"
engine="$bin_dir/hotspotshade"
built_engine="$target_dir/$target/release/hotspotshade"

if [ -L "$app" ]; then
    die "The app bundle path is a symlink: $app"
fi
[ -d "$app" ] || die "The app bundle was not built: $app"
if [ -L "$app_exec" ]; then
    die "The app executable is a symlink: $app_exec"
fi
[ -x "$app_exec" ] || die "The app executable is missing: $app_exec"
if [ -L "$resources" ]; then
    die "The app resources directory is a symlink: $resources"
fi
if [ -L "$bin_dir" ]; then
    die "The app engine directory is a symlink: $bin_dir"
fi
mkdir -p "$bin_dir" || die "Cannot create the app engine directory: $bin_dir"
check_private_directory "$app" "app bundle"
check_private_directory "$bin_dir" "app engine directory"

if [ -L "$built_engine" ]; then
    die "The built engine is a symlink: $built_engine"
fi
[ -f "$built_engine" ] || die "The engine was not built: $built_engine"
[ -x "$built_engine" ] || die "The built engine is not executable: $built_engine"
if [ -L "$engine" ] || [ -e "$engine" ]; then
    if [ -d "$engine" ]; then
        die "The app engine path is a directory: $engine"
    fi
    rm -f "$engine" || die "Cannot remove the old app engine copy: $engine"
fi
cp "$built_engine" "$engine" || die "Cannot copy the engine into the app: $engine"
chmod 0755 "$engine"

app_arch=$(lipo -archs "$app_exec" 2>/dev/null) || die "The app executable is not a Mach-O file: $app_exec"
engine_arch=$(lipo -archs "$engine" 2>/dev/null) || die "The engine is not a Mach-O file: $engine"
if [ "$app_arch" != "$arch" ]; then
    die "The app executable is $app_arch, expected $arch."
fi
if [ "$engine_arch" != "$arch" ]; then
    die "The engine is $engine_arch, expected $arch."
fi

bundle_id=$(plutil -extract CFBundleIdentifier raw -o - "$app/Contents/Info.plist") || die "The app Info.plist has no bundle identifier."
if [ "$bundle_id" != "$app_identifier" ]; then
    die "The app bundle identifier is $bundle_id, expected $app_identifier."
fi

if [ "$local_preview" = 1 ]; then
    codesign --force --options runtime --identifier "$engine_identifier" --sign "$sign_identity" "$engine" || die "The engine could not be signed."
    codesign --force --options runtime --identifier "$app_identifier" --sign "$sign_identity" "$app" || die "The app could not be signed."
elif [ -n "$sign_identity" ]; then
    codesign --force --options runtime --timestamp --identifier "$engine_identifier" --sign "$sign_identity" "$engine" || die "The engine could not be signed."
    codesign --force --options runtime --timestamp --identifier "$app_identifier" --sign "$sign_identity" "$app" || die "The app could not be signed."
else
    codesign --force --identifier "$engine_identifier" --sign - "$engine" || die "The engine could not be ad-hoc signed."
    codesign --force --identifier "$app_identifier" --sign - "$app" || die "The app could not be ad-hoc signed."
fi

codesign --verify --deep --strict "$app" || die "The signed app does not pass codesign --verify --deep --strict."

field_value() {
    field=$1
    text=$2
    printf '%s\n' "$text" | sed -n "s/^${field}=//p" | head -n 1
}

developer_id_requirement() {
    requirement_identifier=$1
    requirement_team=$2
    if [ "$local_preview" = 1 ]; then
        intermediate=1.2.840.113635.100.6.2.1
        leaf=1.2.840.113635.100.6.1.12
    else
        intermediate=1.2.840.113635.100.6.2.6
        leaf=1.2.840.113635.100.6.1.13
    fi
    printf '=anchor apple generic and identifier "%s" and certificate leaf[subject.OU] = "%s" and certificate 1[field.%s] exists and certificate leaf[field.%s] exists and !entitlement["com.apple.security.get-task-allow"] and !entitlement["com.apple.security.cs.disable-library-validation"] and !entitlement["com.apple.security.cs.allow-dyld-environment-variables"]' \
        "$requirement_identifier" "$requirement_team" "$intermediate" "$leaf"
}

check_developer_signature() {
    target=$1
    label=$2
    expected_identifier=$3
    expected_team=${4:-}
    deep=${5:-0}

    details=$(codesign -dv --verbose=4 "$target" 2>&1) || die "The $label signature details cannot be read: $target"
    if [ "$local_preview" = 1 ]; then
        case "$details" in
            *"Authority=Apple Development:"*) ;;
            *) die "The $label is not signed with an Apple Development identity." ;;
        esac
    else
        case "$details" in
            *"Authority=Developer ID Application:"*) ;;
            *) die "The $label is not signed with a Developer ID Application identity." ;;
        esac
    fi

    actual_identifier=$(field_value Identifier "$details")
    if [ "$actual_identifier" != "$expected_identifier" ]; then
        die "The $label signature identifier is '$actual_identifier', expected $expected_identifier."
    fi
    case "$details" in
        *"flags="*"runtime"*) ;;
        *) die "The $label signature does not enable the hardened runtime." ;;
    esac
    if [ "$local_preview" = 0 ]; then
        timestamp=$(field_value Timestamp "$details")
        case "$timestamp" in
            ''|none|'not set') die "The $label signature has no secure timestamp." ;;
        esac
    fi
    actual_team=$(field_value TeamIdentifier "$details")
    case "$actual_team" in
        ''|'not set') die "The $label signature has no team identifier." ;;
    esac
    if [ -n "$expected_team" ] && [ "$actual_team" != "$expected_team" ]; then
        die "The $label team is '$actual_team', expected '$expected_team'."
    fi
    signature_team=$actual_team

    requirement=$(developer_id_requirement "$expected_identifier" "$actual_team")
    if [ "$deep" -eq 1 ]; then
        codesign --verify --strict --deep -R "$requirement" "$target" >/dev/null 2>&1 \
            || die "The $label does not satisfy the selected signature requirement."
    else
        codesign --verify --strict -R "$requirement" "$target" >/dev/null 2>&1 \
            || die "The $label does not satisfy the selected signature requirement."
    fi
}

check_no_forbidden_entitlements() {
    target=$1
    label=$2
    if ! entitlements=$(codesign -d --entitlements :- "$target" 2>/dev/null); then
        die "The $label entitlements cannot be read."
    fi
    if [ -n "$entitlements" ]; then
        if ! printf '%s' "$entitlements" | plutil -lint - >/dev/null 2>&1; then
            die "The $label entitlements are not a readable property list."
        fi
    fi
    for key in \
        com.apple.security.get-task-allow \
        com.apple.security.cs.disable-library-validation \
        com.apple.security.cs.allow-dyld-environment-variables
    do
        case "$entitlements" in
            *"$key"*) die "The $label carries the forbidden entitlement $key." ;;
        esac
    done
}

if [ -n "$sign_identity" ]; then
    check_developer_signature "$app" "app" "$app_identifier" "" 1
    app_team=$signature_team
    check_developer_signature "$engine" "bundled engine" "$engine_identifier" "$app_team" 0
else
    app_details=$(codesign -dv --verbose=4 "$app" 2>&1) || die "The app signature details cannot be read: $app"
    case "$app_details" in
        *"Signature=adhoc"*) ;;
        *) die "The app is not ad-hoc signed." ;;
    esac
    app_signature_id=$(field_value Identifier "$app_details")
    if [ "$app_signature_id" != "$app_identifier" ]; then
        die "The app signature identifier is '$app_signature_id', expected $app_identifier."
    fi
    engine_details=$(codesign -dv --verbose=4 "$engine" 2>&1) || die "The bundled engine signature details cannot be read: $engine"
    case "$engine_details" in
        *"Signature=adhoc"*) ;;
        *) die "The bundled engine is not ad-hoc signed." ;;
    esac
    engine_signature_id=$(field_value Identifier "$engine_details")
    if [ "$engine_signature_id" != "$engine_identifier" ]; then
        die "The bundled engine signature identifier is '$engine_signature_id', expected $engine_identifier."
    fi
fi

check_no_forbidden_entitlements "$app" "app"
check_no_forbidden_entitlements "$engine" "bundled engine"

ditto -c -k --keepParent "$app" "$tmp_zip" || die "Cannot write the temporary zip."
chmod 0600 "$tmp_zip" || die "Cannot make the temporary zip private."
mv -f "$tmp_zip" "$output" || die "Cannot write the output zip: $output"
rm -rf "$tmp_dir"
tmp_dir=""
echo "Wrote $output"
