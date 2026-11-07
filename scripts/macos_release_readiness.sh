#!/bin/sh
# Read-only macOS release readiness diagnostic.
#
# This script inspects the repository templates, the local toolchain, the local
# signing identities, an optional app bundle, and an optional root install. It
# never installs, signs, notarizes, starts a helper, starts an engine, changes a
# route, or creates a TUN device. It does not print certificate names, tokens,
# or any private material.
#
# The production helper uses the rootOwnedCopy layout. It trusts the installed
# helper under /Library/PrivilegedHelperTools and the installed engine under
# /Library/Application Support/HotspotShade, not the app bundle location. A
# stock /Applications folder is group-writable by admin, so it is not a
# privileged trust root for this layout.
#
# Exit status:
#   0  every required check passed
#   1  a required check failed
#   2  the arguments are invalid
set -eu

usage() {
    cat <<'EOF'
usage: scripts/macos_release_readiness.sh [options]

Read-only checks for shipping and using the real macOS app.

Options:
  --root DIR                 Repository root. Default: the parent of this script.
  --app PATH                 Inspect one built HotspotShade.app bundle.
  --require-developer-id     Strict release check. Requires --app and
                             --check-installed. Fails unless the app, bundled
                             engine, installed helper, and installed engine
                             carry valid Developer ID signatures with the
                             expected identifiers, one team, the hardened
                             runtime, and secure timestamps. The installed
                             launch daemon must name the fixed helper. Also
                             requires a stapled notarization ticket.
  --check-installed          Read the installed helper, launch daemon, engine,
                             and root state directories. Missing helper,
                             launch daemon, or engine evidence is a failure.
                             Changes nothing.
  --fixture-install-root DIR Hermetic test only. Read installed paths under DIR
                             instead of /. The run is labelled as a fixture and
                             is not live installation proof. Strict mode rejects
                             this option.
  -h, --help                 Print this help.

Notarization is reported separately from code signing. The strict check requires
a stapled ticket, but a local staple check does not contact Apple and does not
prove the notarization service accepted the build. Signature and installation
checks are static. They do not prove a live signed installation, an
administrator prompt, a helper start, or route cleanup.

The script does not install a package, run an installer, start or stop a
helper, start an engine, or test a route or TUN device. The installer package
in this repository is a build-only audit artifact and its preinstall script
refuses installation.
EOF
}

root=$(CDPATH= cd "$(dirname "$0")/.." && pwd -P)
app=""
require_developer_id=0
check_installed=0
fixture_install_root=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            [ "$#" -ge 2 ] || { echo "--root needs a directory." >&2; exit 2; }
            root=$2
            shift 2
            ;;
        --app)
            [ "$#" -ge 2 ] || { echo "--app needs a bundle path." >&2; exit 2; }
            app=$2
            shift 2
            ;;
        --require-developer-id)
            require_developer_id=1
            shift
            ;;
        --check-installed)
            check_installed=1
            shift
            ;;
        --fixture-install-root)
            [ "$#" -ge 2 ] || { echo "--fixture-install-root needs a directory." >&2; exit 2; }
            fixture_install_root=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ ! -d "$root" ]; then
    echo "The repository root is missing: $root" >&2
    exit 2
fi
root=$(CDPATH= cd "$root" && pwd -P)

if [ "$require_developer_id" -eq 1 ]; then
    if [ -z "$app" ]; then
        echo "--require-developer-id needs --app PATH so it can inspect an actual app bundle." >&2
        exit 2
    fi
    if [ "$check_installed" -ne 1 ]; then
        echo "--require-developer-id needs --check-installed so it can inspect the installed helper and engine." >&2
        exit 2
    fi
    if [ -n "$fixture_install_root" ]; then
        echo "--require-developer-id does not accept --fixture-install-root; the strict check needs the real root install." >&2
        exit 2
    fi
fi

if [ -n "$fixture_install_root" ]; then
    case "$fixture_install_root" in
        /*) ;;
        *) echo "--fixture-install-root needs an absolute path." >&2; exit 2 ;;
    esac
    if [ -L "$fixture_install_root" ]; then
        echo "The fixture install root must not be a symlink: $fixture_install_root" >&2
        exit 2
    fi
    if [ ! -d "$fixture_install_root" ]; then
        echo "The fixture install root is missing: $fixture_install_root" >&2
        exit 2
    fi
    fixture_install_root=$(CDPATH= cd "$fixture_install_root" && pwd -P)
fi

failures=0
warnings=0

pass() { printf '[ok] %s\n' "$*"; }
fail() { printf '[fail] %s\n' "$*" >&2; failures=$((failures + 1)); }
warn() { printf '[warn] %s\n' "$*" >&2; warnings=$((warnings + 1)); }
note() { printf '[info] %s\n' "$*"; }
section() { printf '\n%s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

plist_lint() {
    if have plutil; then
        plutil -lint "$1" >/dev/null 2>&1
    else
        return 1
    fi
}

plist_value() {
    if have plutil; then
        plutil -extract "$2" raw -o - "$1" 2>/dev/null
    else
        return 1
    fi
}

field_value() {
    field=$1
    text=$2
    printf '%s\n' "$text" | sed -n "s/^${field}=//p" | head -n 1
}

developer_id_requirement() {
    requirement_identifier=$1
    requirement_team=$2
    printf '=anchor apple generic and identifier "%s" and certificate leaf[subject.OU] = "%s" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and !entitlement["com.apple.security.get-task-allow"] and !entitlement["com.apple.security.cs.disable-library-validation"] and !entitlement["com.apple.security.cs.allow-dyld-environment-variables"]' \
        "$requirement_identifier" "$requirement_team"
}

check_plist() {
    plist_path=$1
    plist_label=$2
    if [ ! -f "$plist_path" ]; then
        fail "$plist_label is missing: $plist_path"
        return 1
    fi
    if ! plist_lint "$plist_path"; then
        fail "$plist_label is not a valid property list: $plist_path"
        return 1
    fi
    pass "$plist_label is a valid property list"
    return 0
}

check_safe_directory() {
    path=$1
    label=$2
    required=$3

    if [ -L "$path" ]; then
        fail "$label is a symlink: $path"
        return 0
    fi
    if [ ! -e "$path" ]; then
        if [ "$required" -eq 1 ]; then
            fail "$label is missing: $path"
        else
            note "$label is not installed: $path"
        fi
        return 0
    fi
    if [ ! -d "$path" ]; then
        fail "$label is not a directory: $path"
        return 0
    fi
    if ! have stat; then
        if [ "$required" -eq 1 ]; then
            fail "stat is missing; the $label cannot be checked"
        else
            warn "stat is missing; the $label cannot be checked"
        fi
        return 0
    fi

    owner=$(stat -f '%Su' "$path" 2>/dev/null || true)
    mode=$(stat -f '%Lp' "$path" 2>/dev/null || true)
    if [ "$owner" = root ]; then
        pass "$label owner is root"
    else
        fail "$label owner is '$owner', expected root"
    fi
    case "$mode" in
        ''|*[!0-7]*)
            fail "$label mode cannot be read"
            return 0
            ;;
    esac
    mode_value=$((0$mode))
    if [ $((mode_value & 0022)) -ne 0 ]; then
        fail "$label is writable by a group or others"
    else
        pass "$label is not group or other writable"
    fi
    if [ $((mode_value & 06000)) -ne 0 ]; then
        fail "$label has a set-id bit"
    else
        pass "$label has no set-id bit"
    fi
    if ! listing=$(/bin/ls -lde "$path" 2>/dev/null); then
        fail "$label access control list cannot be read"
        return 0
    fi
    if printf '%s\n' "$listing" | sed '1d' | grep -q .; then
        fail "$label has an access control list"
    fi
}

check_mode_and_owner() {
    path=$1
    expected_mode=$2
    kind=$3
    label=$4
    required=${5:-0}

    if [ -L "$path" ]; then
        fail "$label is a symlink: $path"
        return 0
    fi
    if [ ! -e "$path" ]; then
        if [ "$required" -eq 1 ]; then
            fail "$label is missing: $path"
        else
            note "$label is not installed: $path"
        fi
        return 0
    fi
    case "$kind" in
        dir)
            if [ ! -d "$path" ]; then
                fail "$label is not a directory: $path"
                return 0
            fi
            ;;
        file)
            if [ ! -f "$path" ]; then
                fail "$label is not a regular file: $path"
                return 0
            fi
            ;;
    esac

    if ! have stat; then
        if [ "$required" -eq 1 ]; then
            fail "stat is missing; the $label ownership and mode cannot be checked"
        else
            warn "stat is missing; the $label ownership and mode cannot be checked"
        fi
        return 0
    fi

    owner=$(stat -f '%Su' "$path" 2>/dev/null || true)
    group=$(stat -f '%Sg' "$path" 2>/dev/null || true)
    mode=$(stat -f '%Lp' "$path" 2>/dev/null || true)

    if [ "$owner" = root ]; then
        pass "$label owner is root"
    else
        fail "$label owner is '$owner', expected root"
    fi
    if [ "$group" = wheel ]; then
        pass "$label group is wheel"
    else
        fail "$label group is '$group', expected wheel"
    fi

    case "$mode" in
        ''|*[!0-7]*)
            fail "$label mode cannot be read"
            return 0
            ;;
    esac
    if [ "$mode" = "$expected_mode" ]; then
        pass "$label mode is $expected_mode"
    else
        fail "$label mode is $mode, expected $expected_mode"
    fi
    mode_value=$((0$mode))
    if [ $((mode_value & 0022)) -ne 0 ]; then
        fail "$label is writable by a group or others"
    else
        pass "$label is not group or other writable"
    fi
    if [ $((mode_value & 06000)) -ne 0 ]; then
        fail "$label has a set-id bit"
    fi
    if ! listing=$(/bin/ls -lde "$path" 2>/dev/null); then
        fail "$label access control list cannot be read"
        return 0
    fi
    if printf '%s\n' "$listing" | sed '1d' | grep -q .; then
        fail "$label has an access control list"
    fi
}

check_forbidden_entitlements() {
    target=$1
    label=$2
    if ! have codesign; then
        fail "codesign is missing; the $label entitlements cannot be checked"
        return 0
    fi
    if ! entitlements=$(codesign -d --entitlements :- "$target" 2>/dev/null); then
        fail "$label entitlements cannot be read"
        return 0
    fi
    if [ -n "$entitlements" ]; then
        if ! have plutil; then
            fail "plutil is missing; the $label entitlements cannot be validated"
            return 0
        fi
        if ! printf '%s' "$entitlements" | plutil -lint - >/dev/null 2>&1; then
            fail "$label entitlements are not a readable property list"
            return 0
        fi
    fi
    found=0
    for key in \
        com.apple.security.get-task-allow \
        com.apple.security.cs.disable-library-validation \
        com.apple.security.cs.allow-dyld-environment-variables
    do
        case "$entitlements" in
            *"$key"*)
                fail "$label carries the forbidden entitlement $key"
                found=1
                ;;
        esac
    done
    if [ "$found" -eq 0 ]; then
        pass "$label carries no forbidden entitlement"
    fi
}

check_developer_id_signature() {
    target=$1
    label=$2
    expected_identifier=$3
    expected_team=${4:-}
    deep=${5:-0}

    if ! have codesign; then
        fail "codesign is missing; the $label signature cannot be checked"
        return 0
    fi
    if ! details=$(codesign -dv --verbose=4 "$target" 2>&1); then
        fail "$label signature details cannot be read"
        signature_team=""
        return 0
    fi

    case "$details" in
        *"Authority=Developer ID Application:"*) pass "$label is signed with Developer ID Application" ;;
        *) fail "$label is not signed with Developer ID Application" ;;
    esac

    actual_identifier=$(field_value Identifier "$details")
    if [ "$actual_identifier" = "$expected_identifier" ]; then
        pass "$label signature identifier is $expected_identifier"
    else
        fail "$label signature identifier is '$actual_identifier', expected $expected_identifier"
    fi

    case "$details" in
        *"flags="*"runtime"*) pass "$label uses the hardened runtime" ;;
        *) fail "$label does not use the hardened runtime" ;;
    esac

    timestamp=$(field_value Timestamp "$details")
    case "$timestamp" in
        ''|none|'not set') fail "$label signature has no secure timestamp" ;;
        *) pass "$label signature has a secure timestamp" ;;
    esac

    actual_team=$(field_value TeamIdentifier "$details")
    case "$actual_team" in
        ''|'not set')
            fail "$label signature has no team identifier"
            signature_team=""
            return 0
            ;;
        *) pass "$label has a team identifier" ;;
    esac
    signature_team=$actual_team
    if [ -n "$expected_team" ] && [ "$actual_team" != "$expected_team" ]; then
        fail "$label team is '$actual_team', expected '$expected_team'"
    fi

    requirement=$(developer_id_requirement "$expected_identifier" "$actual_team")
    if [ "$deep" -eq 1 ]; then
        if codesign --verify --strict --deep -R "$requirement" "$target" >/dev/null 2>&1; then
            pass "$label satisfies the Developer ID signature requirement"
        else
            fail "$label does not satisfy the Developer ID signature requirement"
        fi
    else
        if codesign --verify --strict -R "$requirement" "$target" >/dev/null 2>&1; then
            pass "$label satisfies the Developer ID signature requirement"
        else
            fail "$label does not satisfy the Developer ID signature requirement"
        fi
    fi
}

check_app_trust_context() {
    app_path=$1
    note "the production helper uses the rootOwnedCopy layout; the app bundle location is not its privileged trust root"
    case "$app_path" in
        /Applications/*|/System/Applications/*)
            note "a stock /Applications folder is group-writable by admin and is not a privileged trust root"
            ;;
    esac
}

check_notarization() {
    app_path=$1
    if ! have xcrun; then
        if [ "$require_developer_id" -eq 1 ]; then
            fail "xcrun is missing; notarization cannot be checked"
        else
            warn "xcrun is missing; notarization was not checked"
        fi
        return 0
    fi
    if ! xcrun --find stapler >/dev/null 2>&1; then
        if [ "$require_developer_id" -eq 1 ]; then
            fail "stapler is missing; notarization cannot be checked"
        else
            warn "stapler is missing; notarization was not checked"
        fi
        return 0
    fi
    if xcrun stapler validate "$app_path" >/dev/null 2>&1; then
        pass "app carries a stapled notarization ticket (local check only)"
    else
        if [ "$require_developer_id" -eq 1 ]; then
            fail "app has no stapled notarization ticket"
        else
            warn "app has no stapled notarization ticket; notarization is a separate gate"
        fi
    fi
    note "notarization is separate from code signing; this local check does not contact Apple"
}

check_app_bundle() {
    app_path=$1

    section "App bundle: $app_path"
    if [ ! -d "$app_path" ]; then
        fail "app bundle is missing: $app_path"
        return 0
    fi
    case "$app_path" in
        *.app) ;;
        *)
            fail "the app path does not end in .app: $app_path"
            return 0
            ;;
    esac
    if [ -L "$app_path" ]; then
        fail "the app path is a symlink: $app_path"
        return 0
    fi
    app_parent=$(CDPATH= cd "$(dirname "$app_path")" && pwd -P)
    app_path=$app_parent/${app_path##*/}
    check_app_trust_context "$app_path"

    info_plist=$app_path/Contents/Info.plist
    if [ -L "$info_plist" ]; then
        fail "app Info.plist is a symlink: $info_plist"
        return 0
    fi
    if [ ! -f "$info_plist" ]; then
        fail "app Info.plist is missing: $info_plist"
        return 0
    fi
    if ! plist_lint "$info_plist"; then
        fail "app Info.plist is not a valid property list"
        return 0
    fi

    bundle_id=$(plist_value "$info_plist" CFBundleIdentifier || true)
    if [ "$bundle_id" = "dev.hotspotshade.mac" ]; then
        pass "app bundle identifier is dev.hotspotshade.mac"
    else
        fail "app bundle identifier is '$bundle_id', expected dev.hotspotshade.mac"
    fi

    executable_name=$(plist_value "$info_plist" CFBundleExecutable || true)
    if [ -z "$executable_name" ]; then
        fail "app CFBundleExecutable is missing"
        return 0
    fi
    app_executable=$app_path/Contents/MacOS/$executable_name
    if [ -L "$app_executable" ]; then
        fail "app executable is a symlink: $app_executable"
        return 0
    fi
    if [ ! -x "$app_executable" ]; then
        fail "app executable is missing or not executable: $app_executable"
        return 0
    fi
    pass "app executable is present"

    engine=$app_path/Contents/Resources/bin/hotspotshade
    if [ -L "$engine" ]; then
        fail "bundled engine is a symlink: $engine"
        return 0
    fi
    if [ ! -x "$engine" ]; then
        fail "bundled engine is missing or not executable: $engine"
        return 0
    fi
    pass "bundled engine is present"

    if ! have lipo; then
        fail "lipo is missing; the app architecture cannot be checked"
    else
        app_arch=$(lipo -archs "$app_executable" 2>/dev/null || true)
        engine_arch=$(lipo -archs "$engine" 2>/dev/null || true)
        if [ -n "$app_arch" ]; then
            pass "app executable architecture: $app_arch"
        else
            fail "app executable is not a Mach-O file"
        fi
        if [ -n "$engine_arch" ]; then
            pass "bundled engine architecture: $engine_arch"
        else
            fail "bundled engine is not a Mach-O file"
        fi
        if [ -n "$app_arch" ] && [ -n "$engine_arch" ] && [ "$app_arch" != "$engine_arch" ]; then
            fail "app and bundled engine architectures differ"
        fi
        if [ "$require_developer_id" -eq 1 ]; then
            case "$app_arch" in
                arm64) ;;
                *) fail "the release app must be a thin arm64 executable; found '$app_arch'" ;;
            esac
        fi
    fi

    if ! have codesign; then
        fail "codesign is missing; the app signature cannot be checked"
        return 0
    fi

    if codesign --verify --deep --strict "$app_path" >/dev/null 2>&1; then
        pass "app passes codesign --verify --deep --strict"
    else
        fail "app fails codesign --verify --deep --strict"
    fi

    if ! app_details=$(codesign -dv --verbose=4 "$app_path" 2>&1); then
        fail "app signature details cannot be read"
        return 0
    fi
    case "$app_details" in
        *"Signature=adhoc"*) app_kind=adhoc ;;
        *"Authority=Developer ID Application:"*) app_kind=developer-id ;;
        *"Authority=Apple Development"*) app_kind=apple-development ;;
        *) app_kind=other ;;
    esac

    case "$app_kind" in
        adhoc)
            note "app is ad-hoc signed; the dashboard and pairing use the real user engine, and Turn on fails closed without the signed helper"
            if [ "$require_developer_id" -eq 1 ]; then
                fail "release mode requires a Developer ID Application signature"
            fi
            app_signature_id=$(field_value Identifier "$app_details")
            if [ "$app_signature_id" = "$bundle_id" ]; then
                pass "app signature identifier matches the bundle identifier"
            else
                fail "app signature identifier is '$app_signature_id', expected '$bundle_id'"
            fi
            ;;
        developer-id)
            check_developer_id_signature "$app_path" "app" "$bundle_id" "" 1
            app_team=${signature_team:-}
            if [ -n "$app_team" ]; then
                check_developer_id_signature "$engine" "bundled engine" "dev.hotspotshade.engine" "$app_team" 0
                engine_team=${signature_team:-}
                if [ -n "$engine_team" ] && [ "$engine_team" = "$app_team" ]; then
                    pass "app and bundled engine teams match"
                elif [ -n "$engine_team" ]; then
                    fail "app and bundled engine teams differ"
                fi
                if [ "$require_developer_id" -eq 1 ]; then
                    identity_match=0
                    for identity_team in $developer_id_app_teams; do
                        if [ "$identity_team" = "$app_team" ]; then
                            identity_match=1
                        fi
                    done
                    if [ "$identity_match" -eq 1 ]; then
                        pass "app team matches a Developer ID Application identity on this host"
                    else
                        fail "app team does not match a Developer ID Application identity on this host"
                    fi
                fi
            fi
            ;;
        apple-development)
            fail "app is signed with Apple Development; the protected helper requires Developer ID"
            ;;
        *)
            fail "app is not ad-hoc or Developer ID signed"
            ;;
    esac

    if [ "$app_kind" != other ]; then
        check_forbidden_entitlements "$app_path" "app"
        check_forbidden_entitlements "$engine" "bundled engine"
    fi

    if [ "$app_kind" = developer-id ]; then
        check_notarization "$app_path"
    else
        note "notarization does not apply to an ad-hoc build"
    fi
}

check_installed_layout() {
    section "Installed root layout (read-only)"
    prefix=$fixture_install_root
    if [ -n "$prefix" ]; then
        note "fixture install root is $prefix; this run is not live installation proof"
        root_check=$prefix
    else
        root_check=/
    fi

    helper=$prefix/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper
    daemon=$prefix/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist
    engine="$prefix/Library/Application Support/HotspotShade/engine/hotspotshade"
    library_root=$prefix/Library
    helper_root=$prefix/Library/PrivilegedHelperTools
    daemon_root=$prefix/Library/LaunchDaemons
    support_root="$prefix/Library/Application Support"
    install_root="$prefix/Library/Application Support/HotspotShade"
    engine_root="$prefix/Library/Application Support/HotspotShade/engine"
    state_dir=$prefix/var/db/hotspotshade
    engine_home=$prefix/var/lib/hotspotshade

    check_safe_directory "$root_check" "install root" 1
    check_safe_directory "$library_root" "Library directory" 1
    check_safe_directory "$helper_root" "privileged helper directory" 1
    check_safe_directory "$daemon_root" "launch daemon directory" 1
    check_safe_directory "$support_root" "Application Support directory" 1
    check_safe_directory "$install_root" "HotspotShade install directory" 1
    check_safe_directory "$engine_root" "engine install directory" 1

    check_mode_and_owner "$helper" 755 file "installed helper" 1
    check_mode_and_owner "$daemon" 644 file "installed launch daemon" 1
    check_mode_and_owner "$engine" 755 file "installed engine" 1
    check_mode_and_owner "$state_dir" 700 dir "state directory" 0
    check_mode_and_owner "$engine_home" 700 dir "engine home" 0

    if [ -f "$daemon" ] && [ ! -L "$daemon" ]; then
        if ! have plutil; then
            fail "plutil is missing; the installed launch daemon cannot be checked"
        else
            daemon_label=$(plist_value "$daemon" Label || true)
            daemon_program=$(plist_value "$daemon" ProgramArguments.0 || true)
            daemon_run_at_load=$(plist_value "$daemon" RunAtLoad || true)
            daemon_keep_alive=$(plist_value "$daemon" KeepAlive || true)
            daemon_exit_timeout=$(plist_value "$daemon" ExitTimeOut || true)
            daemon_user=$(plist_value "$daemon" UserName || true)
            daemon_program_key=$(plist_value "$daemon" Program || true)
            if [ "$daemon_label" = "dev.hotspotshade.mac.helper" ]; then
                pass "installed launch daemon label is dev.hotspotshade.mac.helper"
            else
                fail "installed launch daemon label is '$daemon_label'"
            fi
            if [ "$daemon_program" = "$helper" ]; then
                pass "installed launch daemon names the fixed helper path"
            else
                fail "installed launch daemon program is '$daemon_program'"
            fi
            if [ "$daemon_run_at_load" = false ]; then
                pass "installed launch daemon does not run at load"
            else
                fail "installed launch daemon must set RunAtLoad to false"
            fi
            if [ "$daemon_keep_alive" = false ]; then
                pass "installed launch daemon does not keep itself alive"
            else
                fail "installed launch daemon must set KeepAlive to false"
            fi
            case "$daemon_exit_timeout" in
                ''|*[!0-9]*)
                    fail "installed launch daemon ExitTimeOut is not an integer"
                    ;;
                *)
                    if [ "$daemon_exit_timeout" -ge 60 ]; then
                        pass "installed launch daemon allows at least 60 seconds for a stop"
                    else
                        fail "installed launch daemon ExitTimeOut is below 60 seconds"
                    fi
                    ;;
            esac
            if [ -n "$daemon_user" ] && [ "$daemon_user" != root ]; then
                fail "installed launch daemon runs as '$daemon_user', expected root"
            fi
            if [ -n "$daemon_program_key" ] && [ "$daemon_program_key" != "$helper" ]; then
                fail "installed launch daemon Program is '$daemon_program_key'"
            fi
            if plutil -extract ProgramArguments.1 raw -o - "$daemon" >/dev/null 2>&1; then
                fail "installed launch daemon has more than one program argument"
            else
                pass "installed launch daemon has exactly one program argument"
            fi
            if plutil -p "$daemon" 2>/dev/null | grep -F '"dev.hotspotshade.mac.helper" => true' >/dev/null; then
                pass "installed launch daemon exposes the fixed Mach service"
            else
                fail "installed launch daemon does not expose the fixed Mach service"
            fi
        fi
    fi

    helper_team=""
    if [ -f "$helper" ] && [ ! -L "$helper" ]; then
        check_developer_id_signature "$helper" "installed helper" "dev.hotspotshade.mac.helper" "${app_team:-}" 0
        helper_team=${signature_team:-}
        check_forbidden_entitlements "$helper" "installed helper"
    fi

    engine_team=""
    if [ -f "$engine" ] && [ ! -L "$engine" ]; then
        expected_engine_team=${app_team:-$helper_team}
        check_developer_id_signature "$engine" "installed engine" "dev.hotspotshade.engine" "$expected_engine_team" 0
        engine_team=${signature_team:-}
        check_forbidden_entitlements "$engine" "installed engine"
    fi

    if [ -n "$helper_team" ] && [ -n "$engine_team" ]; then
        if [ "$engine_team" = "$helper_team" ]; then
            pass "installed helper and engine teams match"
        else
            fail "installed helper and engine teams differ"
        fi
    fi

    note "the installed start right is not read here; reading the authorization database can prompt"
    note "signature and file checks are static; they do not prove a live signed installation or start"
    note "no process, launchd job, route, or TUN device is inspected or changed"
}

section "Repository shape"
printf 'Root: %s\n' "$root"

project=$root/macos/HotspotShade.xcodeproj/project.pbxproj
if [ ! -f "$project" ]; then
    fail "the Xcode project is missing: $project"
else
    if grep -F 'PRODUCT_BUNDLE_IDENTIFIER = dev.hotspotshade.mac;' "$project" >/dev/null; then
        pass "the Xcode project uses the dev.hotspotshade.mac bundle identifier"
    else
        fail "the Xcode project does not use the dev.hotspotshade.mac bundle identifier"
    fi
fi

build_script=$root/scripts/build_mac_app.sh
if [ ! -f "$build_script" ]; then
    fail "the macOS app build script is missing: $build_script"
else
    pass "the macOS app build script is present"
    for token in \
        'CODE_SIGNING_ALLOWED=NO' \
        'Contents/Resources/bin/hotspotshade' \
        'codesign --verify --deep --strict' \
        'HS_MAC_SIGN_IDENTITY' \
        'Developer ID Application: ' \
        '--options runtime' \
        'com.apple.security.get-task-allow' \
        'engine_identifier=dev.hotspotshade.engine' \
        '--identifier "$engine_identifier"' \
        '--identifier "$app_identifier"' \
        '-R "$requirement"' \
        'umask 077' \
        'mktemp -d'
    do
        if grep -F -- "$token" "$build_script" >/dev/null; then
            pass "the build script keeps: $token"
        else
            fail "the build script no longer contains: $token"
        fi
    done
    if grep -F -- '--timestamp' "$build_script" >/dev/null; then
        pass "the build script timestamps a Developer ID signature"
    else
        fail "the build script does not timestamp a Developer ID signature"
    fi
fi

helper_plist=$root/macos/Helper/dev.hotspotshade.mac.helper.plist
if check_plist "$helper_plist" "launch daemon template"; then
    label=$(plist_value "$helper_plist" Label || true)
    program=$(plist_value "$helper_plist" ProgramArguments.0 || true)
    run_at_load=$(plist_value "$helper_plist" RunAtLoad || true)
    keep_alive=$(plist_value "$helper_plist" KeepAlive || true)
    exit_timeout=$(plist_value "$helper_plist" ExitTimeOut || true)
    if [ "$label" = "dev.hotspotshade.mac.helper" ]; then
        pass "the launch daemon label is dev.hotspotshade.mac.helper"
    else
        fail "the launch daemon label is '$label'"
    fi
    if [ "$program" = "/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper" ]; then
        pass "the launch daemon names the fixed helper path"
    else
        fail "the launch daemon program is '$program'"
    fi
    if [ "$run_at_load" = false ]; then
        pass "the launch daemon does not run at load"
    else
        fail "the launch daemon must set RunAtLoad to false"
    fi
    if [ "$keep_alive" = false ]; then
        pass "the launch daemon does not keep itself alive"
    else
        fail "the launch daemon must set KeepAlive to false"
    fi
    case "$exit_timeout" in
        ''|*[!0-9]*)
            fail "the launch daemon ExitTimeOut is not an integer"
            ;;
        *)
            if [ "$exit_timeout" -ge 60 ]; then
                pass "the launch daemon allows at least 60 seconds for a stop"
            else
                fail "the launch daemon ExitTimeOut is below 60 seconds"
            fi
            ;;
    esac
    if have plutil && plutil -p "$helper_plist" 2>/dev/null | grep -F '"dev.hotspotshade.mac.helper" => true' >/dev/null; then
        pass "the launch daemon exposes the fixed Mach service"
    else
        fail "the launch daemon does not expose the fixed Mach service"
    fi
fi

right_plist=$root/macos/Helper/dev.hotspotshade.tunnel.start.plist
if check_plist "$right_plist" "start right template"; then
    right_class=$(plist_value "$right_plist" class || true)
    right_group=$(plist_value "$right_plist" group || true)
    right_auth=$(plist_value "$right_plist" authenticate-user || true)
    right_shared=$(plist_value "$right_plist" shared || true)
    right_allow_root=$(plist_value "$right_plist" allow-root || true)
    right_timeout=$(plist_value "$right_plist" timeout || true)
    if [ "$right_class" = user ]; then pass "the start right uses class user"; else fail "the start right class is '$right_class'"; fi
    if [ "$right_group" = admin ]; then pass "the start right uses group admin"; else fail "the start right group is '$right_group'"; fi
    if [ "$right_auth" = true ]; then pass "the start right authenticates the user"; else fail "the start right does not authenticate the user"; fi
    if [ "$right_shared" = false ]; then pass "the start right is not shared"; else fail "the start right must set shared to false"; fi
    if [ "$right_allow_root" = false ]; then pass "the start right does not allow root"; else fail "the start right must set allow-root to false"; fi
    # The release audit pins the reviewed source value. The helper and the
    # installer accept a bounded positive window so an approved value between
    # 1 and 60 seconds still works, but the shipped template must stay at the
    # reviewed 30 seconds. A zero timeout stores no credential and makes the
    # helper's check after the administrator prompt fail.
    if [ "$right_timeout" = 30 ]; then
        pass "the start right grants the reviewed 10 second authorization window"
    else
        fail "the start right timeout is '$right_timeout', expected 30"
    fi
fi

section "Protected helper sources"
identity_source=$root/macos/HotspotShadeKit/Sources/HotspotShadeKit/ProtectedHelper/HelperIdentity.swift
if [ ! -f "$identity_source" ]; then
    fail "the helper identity source is missing: $identity_source"
else
    pass "the helper identity source is present"
    for token in \
        'public static let helperIdentifier = "dev.hotspotshade.mac.helper"' \
        'public static let engineIdentifier = "dev.hotspotshade.engine"' \
        'com.apple.security.get-task-allow' \
        'com.apple.security.cs.disable-library-validation' \
        'com.apple.security.cs.allow-dyld-environment-variables'
    do
        if grep -F -- "$token" "$identity_source" >/dev/null; then
            pass "the helper identity keeps: $token"
        else
            fail "the helper identity no longer contains: $token"
        fi
    done
fi

helper_main=$root/macos/HotspotShadeKit/Sources/HotspotShadeHelper/main.swift
if [ -f "$helper_main" ]; then
    pass "the helper executable source is present"
else
    fail "the helper executable source is missing: $helper_main"
fi

section "Helper packaging inputs"
installer_builder_source=$root/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerBuilder.swift
if [ ! -f "$installer_builder_source" ]; then
    fail "the installer builder source is missing: $installer_builder_source"
else
    pass "the installer builder source is present"
    for token in \
        'identifier: HelperRequirement.helperIdentifier' \
        'identifier: HelperRequirement.engineIdentifier'
    do
        if grep -F -- "$token" "$installer_builder_source" >/dev/null; then
            pass "the installer builder keeps: $token"
        else
            fail "the installer builder no longer contains: $token"
        fi
    done
fi

installer_layout=$root/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerLayout.swift
if [ ! -f "$installer_layout" ]; then
    fail "the installer layout source is missing: $installer_layout"
else
    pass "the installer layout source is present"
    for token in \
        'public static let installLocation = "/Library/Application Support/HotspotShade"' \
        'public static let helperDestination = HelperRequirement.helperExecutablePath' \
        'public static let launchDaemonDestination = HelperRequirement.launchDaemonPath' \
        'public static let engineDestination = RootEnginePaths().enginePath'
    do
        if grep -F -- "$token" "$installer_layout" >/dev/null; then
            pass "the installer layout keeps: $token"
        else
            fail "the installer layout no longer contains: $token"
        fi
    done
fi

section "Installer refusal"
installer_scripts=$root/macos/Installer/Sources/HotspotShadeInstallerCore/InstallerScripts.swift
if [ ! -f "$installer_scripts" ]; then
    fail "the installer scripts source is missing: $installer_scripts"
else
    if grep -F 'public static let installationApproved = false' "$installer_scripts" >/dev/null; then
        pass "the installer approval constant is false"
    else
        fail "the installer approval constant is not false"
    fi
    if grep -F 'refuse "this package is a build-only foundation and is not approved for installation"' "$installer_scripts" >/dev/null; then
        pass "the generated preinstall holds the fixed refusal"
    else
        fail "the generated preinstall no longer holds the fixed refusal"
    fi
    preinstall=$(awk '/public static var preinstall: String \{/ { inside = 1 } /public static var postinstall: String \{/ { inside = 0 } inside { print }' "$installer_scripts")
    case "$preinstall" in
        *'refuse "this package is a build-only foundation and is not approved for installation"'*)
            pass "the preinstall function itself refuses before any change"
            ;;
        *)
            fail "the preinstall function does not carry the fixed refusal"
            ;;
    esac
    for word in pgrep launchctl authorizationdb bootout 'kill ' 'rm ' 'route ' ifconfig networksetup scutil sudo osascript; do
        case "$preinstall" in
            *"$word"*)
                fail "the preinstall function contains a forbidden action: $word"
                ;;
        esac
    done
fi

installer_builder=$root/macos/Installer/Sources/hotspotshade-installer-build/main.swift
if [ -f "$installer_builder" ]; then
    pass "the installer build command source is present"
else
    fail "the installer build command source is missing: $installer_builder"
fi

installer_readme=$root/macos/Installer/README.md
if [ -f "$installer_readme" ]; then
    if grep -F 'NOT INSTALLABLE AND NOT APPROVED FOR USE.' "$installer_readme" >/dev/null; then
        pass "the installer README marks the package not installable"
    else
        fail "the installer README no longer marks the package not installable"
    fi
else
    fail "the installer README is missing: $installer_readme"
fi

section "Host and toolchain"
host_os=$(uname -s)
host_arch=$(uname -m)
if [ "$host_os" = Darwin ]; then
    pass "host OS is macOS"
else
    warn "host OS is $host_os; this diagnostic is intended for macOS"
fi
case "$host_arch" in
    arm64)
        pass "host architecture is arm64"
        rust_target=aarch64-apple-darwin
        ;;
    x86_64)
        warn "host architecture is x86_64; the release app is arm64 only"
        rust_target=x86_64-apple-darwin
        ;;
    *)
        warn "host architecture is $host_arch"
        rust_target=""
        ;;
esac
if have sw_vers; then
    pass "macOS product version: $(sw_vers -productVersion)"
fi

for tool in xcodebuild codesign plutil lipo ditto security; do
    if have "$tool"; then
        pass "required tool is available: $tool"
    else
        fail "required tool is missing: $tool"
    fi
done
for tool in xcrun pkgbuild productsign swift; do
    if have "$tool"; then
        pass "tool is available: $tool"
    else
        warn "tool is missing: $tool"
    fi
done

cargo_bin=$(command -v cargo || true)
if [ -z "$cargo_bin" ] && [ -x "$HOME/.cargo/bin/cargo" ]; then
    cargo_bin=$HOME/.cargo/bin/cargo
fi
if [ -z "$cargo_bin" ]; then
    warn "cargo is missing; the app build cannot run"
else
    pass "cargo is available"
    if [ -n "$rust_target" ] && have rustup; then
        if rustup target list --installed 2>/dev/null | grep -qx "$rust_target"; then
            pass "the Rust target is installed: $rust_target"
        else
            warn "the Rust target may be missing: $rust_target"
        fi
    fi
fi

section "Signing identities"
developer_id_app_teams=""
if have security; then
    app_identities=$(security find-identity -v -p codesigning 2>/dev/null || true)
    all_identities=$(security find-identity -v -p basic 2>/dev/null || true)
    developer_id_app=$(printf '%s\n' "$app_identities" | grep -c 'Developer ID Application:' || true)
    developer_id_installer=$(printf '%s\n' "$all_identities" | grep -c 'Developer ID Installer:' || true)
    developer_id_app_teams=$(printf '%s\n' "$app_identities" | grep -o '([A-Za-z0-9]\{10\})' | tr -d '()' | sort -u | tr '\n' ' ' || true)

    if [ "$developer_id_app" -gt 0 ]; then
        pass "a Developer ID Application identity is present"
    else
        if [ "$require_developer_id" -eq 1 ]; then
            fail "no Developer ID Application identity is present"
        else
            warn "no Developer ID Application identity; real mode cannot be signed"
        fi
    fi
    if [ "$developer_id_installer" -gt 0 ]; then
        pass "a Developer ID Installer identity is present"
    else
        if [ "$require_developer_id" -eq 1 ]; then
            fail "no Developer ID Installer identity is present"
        else
            warn "no Developer ID Installer identity; a package cannot be signed"
        fi
    fi
    note "certificate names are not printed; only presence and count are checked"
else
    fail "security is missing; signing identities cannot be checked"
fi

if have xcrun; then
    if xcrun --find notarytool >/dev/null 2>&1; then
        pass "notarytool is available"
    else
        if [ "$require_developer_id" -eq 1 ]; then
            fail "notarytool is missing"
        else
            warn "notarytool is missing"
        fi
    fi
    if xcrun --find stapler >/dev/null 2>&1; then
        pass "stapler is available"
    else
        if [ "$require_developer_id" -eq 1 ]; then
            fail "stapler is missing"
        else
            warn "stapler is missing"
        fi
    fi
else
    if [ "$require_developer_id" -eq 1 ]; then
        fail "xcrun is missing; notarization tools cannot be checked"
    else
        warn "xcrun is missing; notarization tools cannot be checked"
    fi
fi

if [ -n "$app" ]; then
    check_app_bundle "$app"
fi

if [ "$check_installed" -eq 1 ]; then
    check_installed_layout
fi

section "Summary"
if [ -n "$fixture_install_root" ]; then
    printf 'Fixture install root: %s\n' "$fixture_install_root"
    printf 'This run is not live installation proof and is not a release approval.\n'
fi
if [ "$failures" -eq 0 ]; then
    printf 'Required checks passed with %s warning(s).\n' "$warnings"
    if [ "$require_developer_id" -eq 1 ]; then
        printf 'Strict Developer ID checks passed. Notarization and installed signatures were checked as separate evidence.\n'
    fi
else
    printf '%s required check(s) failed with %s warning(s).\n' "$failures" "$warnings"
fi

cat <<'EOF'

What can run now:
  - scripts/build_mac_app.sh build/HotspotShade-unsigned.zip builds the
    ad-hoc signed app. The build uses no route and creates no TUN device.
    The build stages output privately and rejects symlink input. It replaces an
    existing output only after the staged build and checks succeed.
  - The ad-hoc app opens the real dashboard and pairing with the bundled user
    engine. Unzip it and use Open from the Finder context menu for the first
    launch. Turn on fails closed with a plain message that the signed helper
    is needed.
  - swift test --package-path macos/HotspotShadeKit runs the hermetic helper
    trust and lifecycle tests.
  - swift test --package-path macos/Installer runs the hermetic installer
    refusal and package-audit tests when the package compiles.
  - HS_MAC_SIGN_IDENTITY="Developer ID Application: ..." scripts/build_mac_app.sh
    OUTPUT.zip signs the app and bundled engine with the hardened runtime, the
    fixed app and engine identifiers, and a secure timestamp. It needs a real
    certificate and a secure timestamp from Apple.

What real mode still needs:
  - A Developer ID Application identity for the app, the helper, and the root
    engine. All three must use one team. An Apple Development identity is not
    accepted by the protected helper.
  - A Developer ID Installer identity and a notarization profile for a
    distributable package. Notarization is reported separately from code
    signing. The strict check requires a stapled ticket, but this diagnostic
    does not contact Apple.
  - The rootOwnedCopy install layout. The helper trusts the helper under
    /Library/PrivilegedHelperTools, the launch daemon under
    /Library/LaunchDaemons, and the engine under
    /Library/Application Support/HotspotShade. It does not trust the app bundle
    location. A stock /Applications folder is group-writable by admin, so it is
    not a privileged trust root for this layout.
  - A root install of the helper, launch daemon, start right, engine, and state
    directories. --check-installed only reads static files and signatures. It
    does not prove a live signed installation or start.
  - One kernel-backed exclusion that every start path holds for the whole
    install transaction. The sandbox coordinator holds a transition lock set,
    but the package has no approved integrated live transaction or converged
    protocol with old binaries. Its preinstall refuses installation.
  - Live signed-host tests for the XPC peer check, the audit token, the
    administrator prompt, the root engine spawn, and route cleanup.
  - A live hotspot test. Do not run one as part of an offline check.

Artifact checks are not live installation proof. Do not install the generated
package. It is an audit artifact. The preinstall refusal is the intended gate,
not a bug.
EOF

if [ "$failures" -ne 0 ]; then
    exit 1
fi
exit 0
