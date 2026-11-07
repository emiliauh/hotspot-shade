#!/usr/bin/env bash
# Hermetic tests for scripts/macos_release_readiness.sh and the safe guards in
# scripts/build_mac_app.sh.
#
# Every fixture is a temporary directory. The tests do not install anything,
# sign anything, start a helper or engine, change a route, or create a TUN
# device. They do not use the network.
set -euo pipefail

if [ "$(uname -s)" != Darwin ]; then
    printf 'SKIP: the macOS release readiness tests need macOS.\n'
    exit 0
fi

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
helper=$repo_dir/scripts/macos_release_readiness.sh
build_script=$repo_dir/scripts/build_mac_app.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-macos-readiness-test.XXXXXXXX")
tmp=$(CDPATH= cd "$tmp" && pwd -P)
cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

failures=0
out=""
status=0

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

run_helper() {
    status=0
    out=$("$helper" "$@" 2>&1) || status=$?
}

expect_status() {
    expected=$1
    label=$2
    if [ "$status" -ne "$expected" ]; then
        fail "$label (expected exit $expected, got $status)"
        printf '%s\n' "$out" | sed 's/^/    /' >&2
    fi
}

expect_text() {
    text=$1
    label=$2
    if ! printf '%s\n' "$out" | grep -qF -- "$text"; then
        fail "$label (missing: $text)"
        printf '%s\n' "$out" | sed 's/^/    /' >&2
    fi
}

make_fixture() {
    fixture=$1
    rm -rf "$fixture"
    mkdir -p \
        "$fixture/scripts" \
        "$fixture/macos/HotspotShade.xcodeproj" \
        "$fixture/macos/Helper" \
        "$fixture/macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper" \
        "$fixture/macos/HotspotShadeKit/Sources/HotspotShadeHelper" \
        "$fixture/macos/Installer/Sources/HotspotShadeInstallerCore" \
        "$fixture/macos/Installer/Sources/hotspotshade-installer-build"
    cp "$build_script" "$fixture/scripts/"
    cp "$repo_dir/macos/HotspotShade.xcodeproj/project.pbxproj" \
        "$fixture/macos/HotspotShade.xcodeproj/"
    cp "$repo_dir/macos/Helper/dev.hotspotshade.mac.helper.plist" \
        "$fixture/macos/Helper/"
    cp "$repo_dir/macos/Helper/dev.hotspotshade.tunnel.start.plist" \
        "$fixture/macos/Helper/"
    cp "$repo_dir/macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperIdentity.swift" \
        "$fixture/macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/"
    cp "$repo_dir/macos/HotspotShadeKit/Sources/HotspotShadeHelper/main.swift" \
        "$fixture/macos/HotspotShadeKit/Sources/HotspotShadeHelper/"
    cp "$repo_dir/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerScripts.swift" \
        "$fixture/macos/Installer/Sources/HotspotShadeInstallerCore/"
    cp "$repo_dir/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerBuilder.swift" \
        "$fixture/macos/Installer/Sources/HotspotShadeInstallerCore/"
    cp "$repo_dir/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerLayout.swift" \
        "$fixture/macos/Installer/Sources/HotspotShadeInstallerCore/"
    cp "$repo_dir/macos/Installer/Sources/hotspotshade-installer-build/main.swift" \
        "$fixture/macos/Installer/Sources/hotspotshade-installer-build/"
    cp "$repo_dir/macos/Installer/README.md" "$fixture/macos/Installer/"
}

make_fake_app() {
    app_path=$1
    rm -rf "$app_path"
    mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources/bin"
    cat > "$app_path/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>HotspotShade</string>
    <key>CFBundleIdentifier</key>
    <string>dev.hotspotshade.mac</string>
</dict>
</plist>
EOF
    printf '#!/bin/sh\nexit 0\n' > "$app_path/Contents/MacOS/HotspotShade"
    printf '#!/bin/sh\nexit 0\n' > "$app_path/Contents/Resources/bin/hotspotshade"
    chmod +x "$app_path/Contents/MacOS/HotspotShade" "$app_path/Contents/Resources/bin/hotspotshade"
}

make_fake_signature_details() {
    details_dir=$1
    team=$2
    mkdir -p "$details_dir"
    cat > "$details_dir/app.details" <<EOF
Identifier=dev.hotspotshade.mac
Authority=Developer ID Application: Fixture ($team)
TeamIdentifier=$team
Timestamp=Nov  5 12:00:00 2026
flags=0x10000(runtime)
EOF
    cat > "$details_dir/engine.details" <<EOF
Identifier=dev.hotspotshade.engine
Authority=Developer ID Application: Fixture ($team)
TeamIdentifier=$team
Timestamp=Nov  5 12:00:00 2026
flags=0x10000(runtime)
EOF
    cat > "$details_dir/helper.details" <<EOF
Identifier=dev.hotspotshade.mac.helper
Authority=Developer ID Application: Fixture ($team)
TeamIdentifier=$team
Timestamp=Nov  5 12:00:00 2026
flags=0x10000(runtime)
EOF
    : > "$details_dir/app.entitlements"
    : > "$details_dir/engine.entitlements"
    : > "$details_dir/helper.entitlements"
}

make_fake_tools() {
    bin=$1
    mkdir -p "$bin"
    cat > "$bin/codesign" <<'EOS'
#!/bin/sh
if [ -n "${FAKE_CODESIGN_LOG:-}" ]; then
    printf '%s\n' "$*" >> "$FAKE_CODESIGN_LOG"
fi
target=
mode=none
for arg in "$@"; do
    target=$arg
    case "$arg" in
        -dv) mode=details ;;
        --entitlements) mode=entitlements ;;
    esac
done
case "$target" in
    *.app) kind=app ;;
    */dev.hotspotshade.mac.helper) kind=helper ;;
    */hotspotshade) kind=engine ;;
    *) kind=other ;;
esac
if [ "$mode" = entitlements ]; then
    if [ "${FAKE_ENTITLEMENTS_MODE:-ok}" = unreadable ]; then
        exit 1
    fi
    if [ -f "${FAKE_CODESIGN_DIR:-}/$kind.entitlements" ]; then
        cat "${FAKE_CODESIGN_DIR:-}/$kind.entitlements"
    fi
    exit 0
fi
if [ "$mode" = details ]; then
    if [ -f "${FAKE_CODESIGN_DIR:-}/$kind.details" ]; then
        cat "${FAKE_CODESIGN_DIR:-}/$kind.details"
        exit 0
    fi
    exit 1
fi
case " $* " in
    *" -R "*) exit "${FAKE_REQUIREMENT_STATUS:-0}" ;;
esac
exit "${FAKE_VERIFY_STATUS:-0}"
EOS
    cat > "$bin/lipo" <<'EOS'
#!/bin/sh
printf '%s\n' "${FAKE_LIPO_ARCHS:-arm64}"
EOS
    cat > "$bin/xcrun" <<'EOS'
#!/bin/sh
case "${1:-}" in
    --find) exit 0 ;;
    stapler) exit "${FAKE_STAPLER_STATUS:-1}" ;;
esac
exit 0
EOS
    cat > "$bin/stat" <<'EOS'
#!/bin/sh
fmt=
path=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -f) fmt=$2; shift 2 ;;
        *) path=$1; shift ;;
    esac
done
case "$fmt" in
    '%Su') printf '%s\n' "${FAKE_STAT_OWNER:-root}" ;;
    '%Sg') printf '%s\n' "${FAKE_STAT_GROUP:-wheel}" ;;
    '%Lp')
        if [ -n "${FAKE_STAT_BAD_PATH:-}" ] && [ "$path" = "$FAKE_STAT_BAD_PATH" ]; then
            printf '%s\n' "${FAKE_STAT_BAD_MODE:-775}"
        elif [ -n "${FAKE_STAT_MODE:-}" ]; then
            printf '%s\n' "$FAKE_STAT_MODE"
        else
            case "$path" in
                */var/db/hotspotshade|*/var/lib/hotspotshade) printf '%s\n' 700 ;;
                *.plist) printf '%s\n' 644 ;;
                *) printf '%s\n' 755 ;;
            esac
        fi
        ;;
    *) exit 1 ;;
esac
EOS
    chmod +x "$bin/codesign" "$bin/lipo" "$bin/xcrun" "$bin/stat"
}

make_install_fixture() {
    install_fixture=$1
    rm -rf "$install_fixture"
    mkdir -p \
        "$install_fixture/Library/PrivilegedHelperTools" \
        "$install_fixture/Library/LaunchDaemons" \
        "$install_fixture/Library/Application Support/HotspotShade/engine" \
        "$install_fixture/var/db/hotspotshade" \
        "$install_fixture/var/lib/hotspotshade"
    helper_path="$install_fixture/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper"
    engine_path="$install_fixture/Library/Application Support/HotspotShade/engine/hotspotshade"
    daemon_path="$install_fixture/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist"
    printf '#!/bin/sh\nexit 0\n' > "$helper_path"
    printf '#!/bin/sh\nexit 0\n' > "$engine_path"
    chmod +x "$helper_path" "$engine_path"
    cat > "$daemon_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.hotspotshade.mac.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>$helper_path</string>
    </array>
    <key>MachServices</key>
    <dict>
        <key>dev.hotspotshade.mac.helper</key>
        <true/>
    </dict>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <false/>
    <key>ExitTimeOut</key>
    <integer>120</integer>
</dict>
</plist>
EOF
}

make_fake_build_tools() {
    build_bin=$1
    make_fake_tools "$build_bin"
    # The build script checks real ownership and modes. Keep the fake stat out
    # of this directory so the real stat is used.
    rm -f "$build_bin/stat"
    cat > "$build_bin/cargo" <<'EOS'
#!/bin/sh
if [ "${FAKE_CARGO_SIGNAL_PARENT:-0}" = 1 ]; then
    kill -TERM "$PPID"
    exit 0
fi
target=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --target) target=$2; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$target" ] || exit 1
[ -n "${CARGO_TARGET_DIR:-}" ] || exit 1
directory="$CARGO_TARGET_DIR/$target/release"
mkdir -p "$directory" || exit 1
printf '#!/bin/sh\nexit 0\n' > "$directory/hotspotshade"
chmod +x "$directory/hotspotshade"
EOS
    cat > "$build_bin/xcodebuild" <<'EOS'
#!/bin/sh
if [ -n "${FAKE_XCODEBUILD_MARKER:-}" ]; then
    : > "$FAKE_XCODEBUILD_MARKER"
fi
if [ -n "${FAKE_XCODEBUILD_LOG:-}" ]; then
    printf '%s\n' "$@" > "$FAKE_XCODEBUILD_LOG"
fi
if [ "${FAKE_XCODEBUILD_FAIL:-0}" = 1 ]; then
    exit 1
fi
derived=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -derivedDataPath) derived=$2; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$derived" ] || exit 1
app="$derived/Build/Products/Release/HotspotShade.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources/bin" || exit 1
printf '#!/bin/sh\nexit 0\n' > "$app/Contents/MacOS/HotspotShade"
printf '#!/bin/sh\nexit 0\n' > "$app/Contents/Resources/bin/hotspotshade"
chmod +x "$app/Contents/MacOS/HotspotShade" "$app/Contents/Resources/bin/hotspotshade"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>HotspotShade</string>
    <key>CFBundleIdentifier</key>
    <string>dev.hotspotshade.mac</string>
</dict>
</plist>
PLIST
EOS
    cat > "$build_bin/ditto" <<'EOS'
#!/bin/sh
last=
for arg in "$@"; do
    last=$arg
done
[ -n "$last" ] || exit 1
if [ "${FAKE_DITTO_FAIL:-0}" = 1 ]; then
    printf 'partial zip\n' > "$last"
    exit 1
fi
: > "$last"
EOS
    chmod +x "$build_bin/cargo" "$build_bin/xcodebuild" "$build_bin/ditto"
}

# ---------------------------------------------------------------------------
# Syntax and argument handling
# ---------------------------------------------------------------------------
if ! sh -n "$helper"; then
    fail "the diagnostic does not parse with sh -n"
fi
if ! sh -n "$build_script"; then
    fail "the build script does not parse with sh -n"
fi
if command -v bash >/dev/null 2>&1; then
    if ! bash -n "$helper"; then
        fail "the diagnostic does not parse with bash -n"
    fi
    if ! bash -n "$build_script"; then
        fail "the build script does not parse with bash -n"
    fi
fi

run_helper --help
expect_status 0 "the help flag exits 0"
expect_text "usage:" "the help flag prints usage"

run_helper --unknown-option
expect_status 2 "an unknown option exits 2"

# The diagnostic must not contain a mutating command invocation.
if grep -Eq '(^|[;&|])[[:space:]]*(sudo|launchctl|pkgbuild|productsign|spctl|ifconfig|networksetup|scutil|route)[[:space:]]' "$helper"; then
    fail "the diagnostic contains a mutating command invocation"
fi
if grep -F 'security authorizationdb' "$helper" >/dev/null; then
    fail "the diagnostic reads or writes the authorization database"
fi
if grep -F 'codesign --sign' "$helper" >/dev/null; then
    fail "the diagnostic can sign code"
fi
if grep -F 'codesign --force' "$helper" >/dev/null; then
    fail "the diagnostic can replace a signature"
fi

# ---------------------------------------------------------------------------
# The repository fixture passes the required checks.
# ---------------------------------------------------------------------------
good=$tmp/good
make_fixture "$good"
run_helper --root "$good"
expect_status 0 "the unmodified fixture passes"
expect_text "Required checks passed" "the summary reports a pass"
expect_text "Installer refusal" "the installer gate section is present"
expect_text "the preinstall function itself refuses before any change" \
    "the preinstall gate is checked in the function"
expect_text "What can run now" "the report names the offline path"
expect_text "What real mode still needs" "the report names the remaining work"

# The strict release flag must inspect an actual app and the installed helper
# and engine. It must not pass from keychain identities alone.
run_helper --root "$good" --require-developer-id
expect_status 2 "the strict release flag without an app is an argument error"
expect_text "--app" "the strict release failure names the missing app"

run_helper --root "$good" --require-developer-id --app "$tmp/not-built.app"
expect_status 2 "the strict release flag without an installed check is an argument error"
expect_text "--check-installed" "the strict release failure names the missing installed check"

run_helper --root "$good" --require-developer-id --app "$tmp/not-built.app" --check-installed --fixture-install-root "$tmp"
expect_status 2 "the strict release flag rejects a fixture install root"
expect_text "does not accept --fixture-install-root" "the fixture refusal is named"

run_helper --root "$good" --check-installed
expect_text "Installed root layout (read-only)" "the installed layout is inspected"
expect_text "installed helper" "the installed helper evidence is inspected"

# ---------------------------------------------------------------------------
# Each repository gate fails closed.
# ---------------------------------------------------------------------------
missing_helper=$tmp/missing-helper
make_fixture "$missing_helper"
rm -f "$missing_helper/macos/Helper/dev.hotspotshade.mac.helper.plist"
run_helper --root "$missing_helper"
expect_status 1 "a missing launch daemon template fails"
expect_text "launch daemon template is missing" "the missing template is named"

allow_root=$tmp/allow-root
make_fixture "$allow_root"
plutil -replace allow-root -bool true "$allow_root/macos/Helper/dev.hotspotshade.tunnel.start.plist"
run_helper --root "$allow_root"
expect_status 1 "a start right that allows root fails"
expect_text "must set allow-root to false" "the root-start refusal is named"

missing_shared=$tmp/missing-shared
make_fixture "$missing_shared"
plutil -remove shared "$missing_shared/macos/Helper/dev.hotspotshade.tunnel.start.plist"
run_helper --root "$missing_shared"
expect_status 1 "a start right without shared fails"
expect_text "must set shared to false" "the shared refusal is named"

zero_timeout=$tmp/zero-timeout
make_fixture "$zero_timeout"
plutil -replace timeout -integer 0 "$zero_timeout/macos/Helper/dev.hotspotshade.tunnel.start.plist"
run_helper --root "$zero_timeout"
expect_status 1 "a start right with a zero timeout fails"
expect_text "expected 30" "the timeout refusal is named"

approved=$tmp/approved
make_fixture "$approved"
perl -0pi -e 's/public static let installationApproved = false/public static let installationApproved = true/' \
    "$approved/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerScripts.swift"
run_helper --root "$approved"
expect_status 1 "an approved installer flag fails"
expect_text "installer approval constant is not false" "the approval failure is named"

no_refusal=$tmp/no-refusal
make_fixture "$no_refusal"
perl -0pi -e 's/refuse "this package is a build-only foundation and is not approved for installation"/true/' \
    "$no_refusal/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerScripts.swift"
run_helper --root "$no_refusal"
expect_status 1 "a missing preinstall refusal fails"
expect_text "no longer holds the fixed refusal" "the missing refusal is named"

forbidden_preinstall=$tmp/forbidden-preinstall
make_fixture "$forbidden_preinstall"
perl -0pi -e 's/(public static var preinstall: String \{)/$1\n        pgrep -x hotspotshade/' \
    "$forbidden_preinstall/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerScripts.swift"
run_helper --root "$forbidden_preinstall"
expect_status 1 "a preinstall process scan fails"
expect_text "forbidden action: pgrep" "the process scan is named"

no_arch_check=$tmp/no-arch-check
make_fixture "$no_arch_check"
perl -0pi -e 's/CODE_SIGNING_ALLOWED=NO/CODE_SIGNING_ALLOWED=YES/' \
    "$no_arch_check/scripts/build_mac_app.sh"
run_helper --root "$no_arch_check"
expect_status 1 "a build that re-enables Xcode signing fails"
expect_text "no longer contains: CODE_SIGNING_ALLOWED=NO" "the signing regression is named"

no_engine_identifier=$tmp/no-engine-identifier
make_fixture "$no_engine_identifier"
perl -0pi -e 's/engine_identifier=dev\.hotspotshade\.engine/engine_identifier=hotspotshade/' \
    "$no_engine_identifier/scripts/build_mac_app.sh"
run_helper --root "$no_engine_identifier"
expect_status 1 "a build with the wrong engine identifier fails"
expect_text "no longer contains: engine_identifier=dev.hotspotshade.engine" \
    "the engine identifier regression is named"

# ---------------------------------------------------------------------------
# App bundle checks.
# ---------------------------------------------------------------------------
missing_app=$tmp/missing.app
run_helper --root "$good" --app "$missing_app"
expect_status 1 "a missing app bundle fails"
expect_text "app bundle is missing" "the missing app is named"

not_an_app=$tmp/not-an-app
mkdir -p "$not_an_app"
run_helper --root "$good" --app "$not_an_app"
expect_status 1 "a path without the .app suffix fails"
expect_text "does not end in .app" "the suffix failure is named"

fake_app=$tmp/Fake.app
mkdir -p "$fake_app/Contents/MacOS" "$fake_app/Contents/Resources/bin"
cat > "$fake_app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>HotspotShade</string>
</dict>
</plist>
EOF
run_helper --root "$good" --app "$fake_app"
expect_status 1 "an app without a bundle identifier fails"
expect_text "app bundle identifier is ''" "the missing bundle identifier is named"

ln -s "$fake_app" "$tmp/Link.app"
run_helper --root "$good" --app "$tmp/Link.app"
expect_status 1 "a symlinked app path fails"
expect_text "app path is a symlink" "the symlink app path is named"

plutil -insert CFBundleIdentifier -string dev.hotspotshade.mac "$fake_app/Contents/Info.plist"
run_helper --root "$good" --app "$fake_app"
expect_status 1 "an app without an executable fails"
expect_text "app executable is missing or not executable" "the missing executable is named"

printf '#!/bin/sh\nexit 0\n' > "$fake_app/Contents/MacOS/HotspotShade"
printf '#!/bin/sh\nexit 0\n' > "$fake_app/Contents/Resources/bin/hotspotshade"
chmod +x "$fake_app/Contents/MacOS/HotspotShade" "$fake_app/Contents/Resources/bin/hotspotshade"
run_helper --root "$good" --app "$fake_app"
expect_status 1 "an app with a script instead of a Mach-O fails"
expect_text "app executable is not a Mach-O file" "the non-Mach-O app is named"

# ---------------------------------------------------------------------------
# Fake tool signature checks. These are hermetic. They do not use a real
# certificate, sign anything, or contact Apple.
# ---------------------------------------------------------------------------
fake_bin=$tmp/fake-bin
fake_codesign_data=$tmp/fake-codesign-data
make_fake_tools "$fake_bin"
make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
dev_app=$tmp/DeveloperID.app
make_fake_app "$dev_app"

status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" FAKE_STAPLER_STATUS=1 \
    "$helper" --root "$good" --app "$dev_app" 2>&1) || status=$?
expect_status 0 "a Developer ID app with a matching engine passes the artifact checks"
expect_text "satisfies the Developer ID signature requirement" "the app signature requirement is checked"
expect_text "bundled engine signature identifier is dev.hotspotshade.engine" "the engine identifier is checked"
expect_text "notarization is a separate gate" "missing notarization is reported separately"

make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
perl -0pi -e 's/^Identifier=dev\.hotspotshade\.mac$/Identifier=dev.wrong.app/m' "$fake_codesign_data/app.details"
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --app "$dev_app" 2>&1) || status=$?
expect_status 1 "an app signature with the wrong identifier fails"
expect_text "app signature identifier is 'dev.wrong.app'" "the wrong app identifier is named"

make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
perl -0pi -e 's/^Identifier=dev\.hotspotshade\.engine$/Identifier=hotspotshade/m' "$fake_codesign_data/engine.details"
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --app "$dev_app" 2>&1) || status=$?
expect_status 1 "a bundled engine with the wrong identifier fails"
expect_text "bundled engine signature identifier is 'hotspotshade'" "the wrong engine identifier is named"

make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
perl -0pi -e 's/^Timestamp=.*/Timestamp=none/m' "$fake_codesign_data/engine.details"
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --app "$dev_app" 2>&1) || status=$?
expect_status 1 "a signature without a secure timestamp fails"
expect_text "bundled engine signature has no secure timestamp" "the missing timestamp is named"

make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
perl -0pi -e 's/^TeamIdentifier=ABCDEFGHIJ$/TeamIdentifier=ZZZZZZZZZZ/m' "$fake_codesign_data/engine.details"
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --app "$dev_app" 2>&1) || status=$?
expect_status 1 "an engine from another team fails"
expect_text "bundled engine team is 'ZZZZZZZZZZ'" "the team mismatch is named"

make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" FAKE_ENTITLEMENTS_MODE=unreadable \
    "$helper" --root "$good" --app "$dev_app" 2>&1) || status=$?
expect_status 1 "an unreadable entitlement fails instead of passing"
expect_text "app entitlements cannot be read" "the unreadable entitlement is named"

make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
cat > "$fake_codesign_data/app.entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
EOF
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --app "$dev_app" 2>&1) || status=$?
expect_status 1 "a forbidden entitlement fails"
expect_text "forbidden entitlement com.apple.security.get-task-allow" "the forbidden entitlement is named"

# Strict mode still needs the real root install. These fake tools make the
# artifact checks pass, so a missing installed helper or engine must fail.
fake_bin_no_stat=$tmp/fake-bin-no-stat
mkdir -p "$fake_bin_no_stat"
cp "$fake_bin/codesign" "$fake_bin/lipo" "$fake_bin/xcrun" "$fake_bin_no_stat/"
make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
if [ ! -e /Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper ]; then
    status=0
    out=$(PATH="$fake_bin_no_stat:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" FAKE_STAPLER_STATUS=0 \
        "$helper" --root "$good" --require-developer-id --app "$dev_app" --check-installed 2>&1) || status=$?
    expect_status 1 "the strict check fails without installed helper evidence"
    expect_text "installed helper is missing" "the missing installed helper is named"
fi

# ---------------------------------------------------------------------------
# Installed layout fixture checks. The fixture root and fake stat command
# simulate root-owned files without a real root install.
# ---------------------------------------------------------------------------
install_fixture=$tmp/install-fixture
make_install_fixture "$install_fixture"

status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --check-installed --fixture-install-root "$install_fixture" 2>&1) || status=$?
expect_status 0 "the installed fixture passes the static checks"
expect_text "fixture install root is" "the fixture root is labelled"
expect_text "installed helper signature identifier is dev.hotspotshade.mac.helper" "the helper identifier is checked"
expect_text "installed engine signature identifier is dev.hotspotshade.engine" "the installed engine identifier is checked"
expect_text "installed launch daemon has exactly one program argument" "the daemon argument list is checked"

make_install_fixture "$install_fixture"
plutil -replace Label -string dev.wrong.helper "$install_fixture/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist"
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --check-installed --fixture-install-root "$install_fixture" 2>&1) || status=$?
expect_status 1 "a launch daemon with the wrong label fails"
expect_text "installed launch daemon label is 'dev.wrong.helper'" "the wrong daemon label is named"

make_install_fixture "$install_fixture"
make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
perl -0pi -e 's/^Identifier=dev\.hotspotshade\.mac\.helper$/Identifier=hotspotshade/m' "$fake_codesign_data/helper.details"
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --check-installed --fixture-install-root "$install_fixture" 2>&1) || status=$?
expect_status 1 "an installed helper with the wrong identifier fails"
expect_text "installed helper signature identifier is 'hotspotshade'" "the installed helper identifier is named"

make_install_fixture "$install_fixture"
make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
perl -0pi -e 's/^Timestamp=.*/Timestamp=none/m' "$fake_codesign_data/engine.details"
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --check-installed --fixture-install-root "$install_fixture" 2>&1) || status=$?
expect_status 1 "an installed engine without a timestamp fails"
expect_text "installed engine signature has no secure timestamp" "the installed engine timestamp is named"

make_install_fixture "$install_fixture"
make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" FAKE_ENTITLEMENTS_MODE=unreadable \
    "$helper" --root "$good" --check-installed --fixture-install-root "$install_fixture" 2>&1) || status=$?
expect_status 1 "an unreadable installed entitlement fails"
expect_text "installed helper entitlements cannot be read" "the installed entitlement is named"

make_install_fixture "$install_fixture"
make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
rm -f "$install_fixture/Library/Application Support/HotspotShade/engine/hotspotshade"
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    "$helper" --root "$good" --check-installed --fixture-install-root "$install_fixture" 2>&1) || status=$?
expect_status 1 "a missing installed engine fails"
expect_text "installed engine is missing" "the missing installed engine is named"

make_install_fixture "$install_fixture"
make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" \
    FAKE_STAT_BAD_PATH="$install_fixture/Library/Application Support/HotspotShade/engine/hotspotshade" \
    FAKE_STAT_BAD_MODE=775 \
    "$helper" --root "$good" --check-installed --fixture-install-root "$install_fixture" 2>&1) || status=$?
expect_status 1 "an installed engine with an unsafe mode fails"
expect_text "mode is 775, expected 755" "the unsafe installed mode is named"

make_install_fixture "$install_fixture"
make_fake_signature_details "$fake_codesign_data" ABCDEFGHIJ
status=0
out=$(PATH="$fake_bin:$PATH" FAKE_CODESIGN_DIR="$fake_codesign_data" FAKE_REQUIREMENT_STATUS=3 \
    "$helper" --root "$good" --check-installed --fixture-install-root "$install_fixture" 2>&1) || status=$?
expect_status 1 "an installed helper that fails its signature requirement fails"
expect_text "installed helper does not satisfy the Developer ID signature requirement" \
    "the installed helper requirement failure is named"

# ---------------------------------------------------------------------------
# Build script guards run before any build.
# ---------------------------------------------------------------------------
printf 'stale zip\n' > "$tmp/out.zip"
status=0
out=$(HS_MAC_SIGN_IDENTITY='Apple Development: Fixture' "$build_script" "$tmp/out.zip" 2>&1) || status=$?
expect_status 1 "the build script rejects an Apple Development identity"
expect_text "Developer ID Application" "the identity refusal names the required type"
if [ "$(cat "$tmp/out.zip")" != 'stale zip' ]; then
    fail "an input validation failure changed the existing output"
fi
expect_text "Existing output was not replaced" "the preserved output is reported"

status=0
out=$(HS_MAC_LOCAL_PREVIEW=1 "$build_script" "$tmp/out.zip" 2>&1) || status=$?
expect_status 1 "a local preview needs a signing identity"
expect_text "Apple Development signing identity" "the preview identity requirement is named"

status=0
out=$(HS_MAC_LOCAL_PREVIEW=1 HS_MAC_SIGN_IDENTITY='Developer ID Application: Fixture' "$build_script" "$tmp/out.zip" 2>&1) || status=$?
expect_status 1 "a local preview rejects a distribution identity"
expect_text "Apple Development identity" "the preview identity mismatch is named"

status=0
out=$("$build_script" --help 2>&1) || status=$?
expect_status 0 "the build script help exits 0"
expect_text "usage:" "the build script help prints usage"

mkdir -p "$tmp/outdir"
status=0
out=$("$build_script" "$tmp/outdir" 2>&1) || status=$?
expect_status 1 "the build script rejects a directory output"
expect_text "must be a file" "the directory output is named"

printf 'old zip\n' > "$tmp/real-output.zip"
ln -s "$tmp/real-output.zip" "$tmp/link-output.zip"
status=0
out=$("$build_script" "$tmp/link-output.zip" 2>&1) || status=$?
expect_status 1 "the build script rejects a symlink output"
expect_text "must not be a symlink" "the symlink output is named"
if [ ! -f "$tmp/real-output.zip" ]; then
    fail "the build script changed a file behind a symlink output"
fi

mkdir -p "$tmp/derived-real"
ln -s "$tmp/derived-real" "$tmp/derived-link"
status=0
out=$(HS_MAC_DERIVED_DATA="$tmp/derived-link" "$build_script" "$tmp/derived-output.zip" 2>&1) || status=$?
expect_status 1 "the build script rejects a symlink derived data path"
expect_text "HS_MAC_DERIVED_DATA must not be a symlink" "the symlink derived data path is named"

mkdir -p "$tmp/target-real"
ln -s "$tmp/target-real" "$tmp/target-link"
status=0
out=$(CARGO_TARGET_DIR="$tmp/target-link" "$build_script" "$tmp/target-output.zip" 2>&1) || status=$?
expect_status 1 "the build script rejects a symlink cargo target path"
expect_text "CARGO_TARGET_DIR must not be a symlink" "the symlink cargo target path is named"

build_bin=$tmp/fake-build-bin
make_fake_build_tools "$build_bin"
build_details=$tmp/fake-build-details
make_fake_signature_details "$build_details" ABCDEFGHIJ

stale_output=$tmp/stale-output.zip
printf 'stale zip\n' > "$stale_output"
status=0
out=$(PATH="$build_bin:$PATH" FAKE_CODESIGN_DIR="$build_details" FAKE_XCODEBUILD_FAIL=1 \
    HS_MAC_DERIVED_DATA="$tmp/stale-derived" CARGO_TARGET_DIR="$tmp/stale-target" \
    "$build_script" "$stale_output" 2>&1) || status=$?
expect_status 1 "a failed build exits nonzero"
if [ "$(cat "$stale_output")" != 'stale zip' ]; then
    fail "a failed build changed the existing output"
fi
expect_text "Existing output was not replaced" "the preserved output is reported"

printf 'old zip\n' > "$tmp/ditto-output.zip"
cp "$tmp/ditto-output.zip" "$tmp/ditto-original.zip"
status=0
out=$(PATH="$build_bin:$PATH" FAKE_CODESIGN_DIR="$build_details" FAKE_DITTO_FAIL=1 \
    HS_MAC_DERIVED_DATA="$tmp/ditto-derived" CARGO_TARGET_DIR="$tmp/ditto-target" \
    "$build_script" "$tmp/ditto-output.zip" 2>&1) || status=$?
expect_status 1 "a failed archive build exits nonzero"
if ! cmp -s "$tmp/ditto-output.zip" "$tmp/ditto-original.zip"; then
    fail "a failed archive build changed the existing output"
fi
expect_text "Existing output was not replaced" "archive failure reports the preserved output"

printf 'old zip\n' > "$tmp/signal-output.zip"
cp "$tmp/signal-output.zip" "$tmp/signal-original.zip"
status=0
out=$(PATH="$build_bin:$PATH" FAKE_CODESIGN_DIR="$build_details" FAKE_CARGO_SIGNAL_PARENT=1 \
    FAKE_XCODEBUILD_MARKER="$tmp/signal-xcode-ran" \
    HS_MAC_DERIVED_DATA="$tmp/signal-derived" CARGO_TARGET_DIR="$tmp/signal-target" \
    "$build_script" "$tmp/signal-output.zip" 2>&1) || status=$?
expect_status 143 "termination stops the build"
if [ -e "$tmp/signal-xcode-ran" ] || ! cmp -s "$tmp/signal-output.zip" "$tmp/signal-original.zip"; then
    fail "termination continued the build or changed the existing output"
fi

success_output=$tmp/fake-success.zip
codesign_log=$tmp/fake-codesign.log
: > "$codesign_log"
status=0
out=$(PATH="$build_bin:$PATH" FAKE_CODESIGN_DIR="$build_details" FAKE_CODESIGN_LOG="$codesign_log" \
    HS_MAC_SIGN_IDENTITY='Developer ID Application: Fixture (ABCDEFGHIJ)' \
    HS_MAC_DERIVED_DATA="$tmp/success-derived" CARGO_TARGET_DIR="$tmp/success-target" \
    "$build_script" "$success_output" 2>&1) || status=$?
expect_status 0 "the fake Developer ID build succeeds"
if [ ! -f "$success_output" ]; then
    fail "the fake Developer ID build did not write the output zip"
else
    output_mode=$(stat -f '%Lp' "$success_output")
    if [ "$output_mode" != 600 ]; then
        fail "the output zip mode is $output_mode, expected 600"
    fi
fi
for expected in \
    '--identifier dev.hotspotshade.engine' \
    '--identifier dev.hotspotshade.mac' \
    '--options runtime' \
    '--timestamp'
do
    if ! grep -F -- "$expected" "$codesign_log" >/dev/null; then
        fail "the build signing call is missing: $expected"
    fi
done

preview_details=$tmp/fake-preview-details
make_fake_signature_details "$preview_details" ABCDEFGHIJ
for file in app engine helper; do
    sed 's/Developer ID Application:/Apple Development:/' "$preview_details/$file.details" > "$preview_details/$file.preview"
    mv "$preview_details/$file.preview" "$preview_details/$file.details"
done
preview_sign_log=$tmp/fake-preview-codesign.log
preview_xcode_log=$tmp/fake-preview-xcode.log
status=0
out=$(PATH="$build_bin:$PATH" FAKE_CODESIGN_DIR="$preview_details" FAKE_CODESIGN_LOG="$preview_sign_log" \
    FAKE_XCODEBUILD_LOG="$preview_xcode_log" HS_MAC_LOCAL_PREVIEW=1 \
    HS_MAC_SIGN_IDENTITY='Apple Development: Fixture (ABCDEFGHIJ)' \
    HS_MAC_DERIVED_DATA="$tmp/preview-derived" CARGO_TARGET_DIR="$tmp/preview-target" \
    "$build_script" "$tmp/fake-preview.zip" 2>&1) || status=$?
expect_status 0 "the fake local preview build succeeds"
if ! grep -F -- '-D HOTSPOTSHADE_LOCAL_PREVIEW' "$preview_xcode_log" >/dev/null; then
    fail "the local preview does not select its compile-time policy"
fi
if ! grep -F -- '1.2.840.113635.100.6.1.12' "$preview_sign_log" >/dev/null; then
    fail "the local preview does not check the Apple Development requirement"
fi
if grep -F -- '1.2.840.113635.100.6.1.13' "$preview_sign_log" >/dev/null; then
    fail "the local preview unexpectedly uses the Developer ID requirement"
fi
if ! grep -F -- '/Contents/Resources/bin/hotspotshade' "$codesign_log" >/dev/null; then
    fail "the build does not sign the bundled engine path"
fi

status=0
out=$(PATH="$build_bin:$PATH" FAKE_CODESIGN_DIR="$build_details" FAKE_ENTITLEMENTS_MODE=unreadable \
    HS_MAC_SIGN_IDENTITY='Developer ID Application: Fixture (ABCDEFGHIJ)' \
    HS_MAC_DERIVED_DATA="$tmp/unreadable-derived" CARGO_TARGET_DIR="$tmp/unreadable-target" \
    "$build_script" "$tmp/unreadable-entitlement.zip" 2>&1) || status=$?
expect_status 1 "the build script fails when entitlements cannot be read"
expect_text "app entitlements cannot be read" "the build entitlement failure is named"
if [ -e "$tmp/unreadable-entitlement.zip" ]; then
    fail "the build wrote an output after an unreadable entitlement"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s test(s) failed.\n' "$failures" >&2
    exit 1
fi
printf 'All macOS release readiness tests passed.\n'
