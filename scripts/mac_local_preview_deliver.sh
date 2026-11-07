#!/bin/sh
# Package a local Mac preview build into one reviewed delivery bundle.
#
# This is a preparation step. It reads the output of
# scripts/build_mac_local_preview.sh, checks the signed coordinator, the signed
# app, and the staged payload, then writes one private delivery bundle with the
# exact files that a first install needs. It never runs sudo, never writes a
# system path, never starts a service, and never creates a route or a TUN
# device. It reports the signed coordinator's build-time policy.
#
# The delivery bundle is not an installer. See
# scripts/mac_local_preview_first_install.sh for the protected placement plan
# and its explicit preparation-only behavior.
set -eu
umask 077
cd "$(dirname "$0")/.."

# One source of truth for the protected location. The first-install launcher
# uses the same relative path. The leading slash is added there.
protected_relative='Library/Application Support/HotspotShade/local-preview'

newline='
'

usage() {
    cat <<'EOF'
usage: scripts/mac_local_preview_deliver.sh --built DIR --output NEW_DIR

Build a reviewed delivery bundle for an Apple silicon Mac local preview.

  --built DIR    Output directory from scripts/build_mac_local_preview.sh.
                 It must hold the signed coordinator, the signed app, and the
                 staged payload plus manifest.
  --output DIR   New private directory for the delivery bundle. It must not
                 exist. The parent directory must already exist.
  -h, --help     Print this help.

Paths are resolved from the repository root. A path must not contain a single
quote or a line break, because the bundle prints shell commands with quoting.

Exit status:
  0  the delivery bundle was written and verified
  1  a check failed and the partial bundle was removed
  2  the arguments are invalid

This script does not run sudo, sign, notarize, install, or change any system
path. It does not enable the local preview install gate.
EOF
}

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

usage_error() {
    printf '%s\n' "$*" >&2
    printf 'Run this script with --help for the usage.\n' >&2
    exit 2
}

refuse_unsafe_path() {
    case "$1" in
        *"$newline"*) die "A path must not contain a line break." ;;
        *"'"*) die "A path must not contain a single quote." ;;
    esac
}

require_regular() {
    [ -f "$1" ] && [ ! -L "$1" ] || die "Not a regular file: $1"
    [ -s "$1" ] || die "The file is empty: $1"
}

require_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] || die "Not a directory: $1"
}

# The staged payload is one exact tree. A new object, a symlink, or a missing
# object is refused before the coordinator runs and again after the copy.
check_payload_tree() {
    local root=$1
    local expected actual relative
    require_directory "$root"
    expected=$(printf '%s\n' \
        . \
        ./engine \
        ./install-support \
        ./engine/hotspotshade \
        ./install-support/dev.hotspotshade.mac.helper \
        ./install-support/dev.hotspotshade.mac.helper.plist \
        ./install-support/dev.hotspotshade.tunnel.start.plist | sort)
    actual=$(cd "$root" && find . -print | sort) \
        || die "The payload tree cannot be read: $root"
    if [ "$actual" != "$expected" ]; then
        die "The payload tree is not the fixed set of objects: $root"
    fi
    for relative in \
        engine/hotspotshade \
        install-support/dev.hotspotshade.mac.helper \
        install-support/dev.hotspotshade.mac.helper.plist \
        install-support/dev.hotspotshade.tunnel.start.plist
    do
        require_regular "$root/$relative"
    done
}

# Run only the two read-only coordinator checks. self-check verifies the
# coordinator's own signature and team. verify-preview verifies the app
# signature, the payload digests, and that the app, payload, and coordinator
# share one team. Neither command installs, writes a system path, or starts a
# service.
verify_preview() {
    local coordinator=$1
    local app=$2
    local payload=$3
    local manifest=$4
    [ -x "$coordinator" ] || die "The coordinator is not executable: $coordinator"
    "$coordinator" self-check \
        || die "The coordinator could not verify its own signature."
    "$coordinator" verify-preview \
        --app "$app" --payload "$payload" --manifest "$manifest" \
        || die "The coordinator rejected the app, payload, or manifest."
}

seen_built=0
seen_output=0
built=''
output=''

while [ "$#" -gt 0 ]; do
    case "$1" in
        --built)
            [ "$#" -ge 2 ] || usage_error "Missing value for --built."
            [ "$seen_built" -eq 0 ] || usage_error "Duplicate --built."
            seen_built=1
            built=$2
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || usage_error "Missing value for --output."
            [ "$seen_output" -eq 0 ] || usage_error "Duplicate --output."
            seen_output=1
            output=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage_error "Unknown argument: $1"
            ;;
    esac
done

[ "$seen_built" -eq 1 ] || usage_error "Missing --built."
[ "$seen_output" -eq 1 ] || usage_error "Missing --output."
[ -n "$built" ] || usage_error "The --built value is empty."
[ -n "$output" ] || usage_error "The --output value is empty."

[ "$(id -u)" -ne 0 ] || die "This preparation step must not run as root."

refuse_unsafe_path "$built"
refuse_unsafe_path "$output"

if [ -L "$built" ]; then
    die "The --built path must not be a symlink."
fi
built=$(realpath "$built") || die "The --built directory does not exist: $built"
require_directory "$built"

case "$output" in
    /*) ;;
    *) output="$(pwd)/$output" ;;
esac
output_parent=$(dirname "$output")
output_name=$(basename "$output")
[ "$output_name" != '/' ] || die "The --output path is not a directory name."
[ "$output_name" != '.' ] && [ "$output_name" != '..' ] \
    || die "The --output path is not a directory name."
[ -d "$output_parent" ] || die "The output parent directory does not exist: $output_parent"
output_parent=$(realpath "$output_parent") \
    || die "The output parent directory cannot be resolved."
output="$output_parent/$output_name"
[ ! -e "$output" ] && [ ! -L "$output" ] \
    || die "The output directory already exists: $output"

case "$output" in
    /|/System|/System/*|/usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*|/Library|/Library/*|\
    /Applications|/Applications/*|/private/var/db|/private/var/db/*|/var/db|/var/db/*)
        die "The output must not be a system path: $output"
        ;;
esac

coordinator_source="$built/hotspotshade-installer-coordinator"
app_source="$built/app/HotspotShade.app"
payload_source="$built/staged/payload"
manifest_source="$built/staged/manifest.json"

require_regular "$coordinator_source"
require_directory "$app_source"
check_payload_tree "$payload_source"
require_regular "$manifest_source"

printf 'Checking the signed build before copying it.\n'
verify_preview "$coordinator_source" "$app_source" "$payload_source" "$manifest_source"
system_policy=$("$coordinator_source" preview-policy) || die "Cannot read the coordinator policy."
case "$system_policy" in
    'system-preview: enabled'|'system-preview: disabled') ;;
    *) die "The coordinator returned an unknown preview policy." ;;
esac

complete=0
cleanup() {
    if [ "$complete" -eq 0 ] && { [ -e "$output" ] || [ -L "$output" ]; }; then
        chmod -R u+w "$output" 2>/dev/null || true
        rm -rf "$output" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

mkdir -m 700 "$output" || die "Cannot create the output directory: $output"
mkdir -m 700 "$output/coordinator" "$output/preview" "$output/app" \
    || die "Cannot create the delivery directories."

install -m 0755 "$coordinator_source" \
    "$output/coordinator/hotspotshade-installer-coordinator" \
    || die "Cannot copy the coordinator."
ditto "$payload_source" "$output/preview/payload" \
    || die "Cannot copy the staged payload."
# Normalize the delivery modes to the placement plan. The coordinator checks
# the bytes and signatures, and the placement command sets the final mode.
chmod 0755 "$output/preview/payload" \
    "$output/preview/payload/engine" \
    "$output/preview/payload/install-support" \
    || die "Cannot set the payload directory modes."
chmod 0755 "$output/preview/payload/engine/hotspotshade" \
    || die "Cannot set the engine mode."
chmod 0644 \
    "$output/preview/payload/install-support/dev.hotspotshade.mac.helper" \
    "$output/preview/payload/install-support/dev.hotspotshade.mac.helper.plist" \
    "$output/preview/payload/install-support/dev.hotspotshade.tunnel.start.plist" \
    || die "Cannot set the support file modes."
install -m 0600 "$manifest_source" "$output/preview/manifest.json" \
    || die "Cannot copy the staged manifest."
ditto "$app_source" "$output/app/HotspotShade.app" \
    || die "Cannot copy the app bundle."
# The build runs with a private umask. The eventual root-owned app must remain
# readable and traversable by the signed-in user after placement.
chmod -R go+rX "$output/app/HotspotShade.app" \
    || die "Cannot make the app bundle readable for launch."

printf 'Checking the copied bundle.\n'
check_payload_tree "$output/preview/payload"
verify_preview \
    "$output/coordinator/hotspotshade-installer-coordinator" \
    "$output/app/HotspotShade.app" \
    "$output/preview/payload" \
    "$output/preview/manifest.json"
copied_policy=$("$output/coordinator/hotspotshade-installer-coordinator" preview-policy) \
    || die "Cannot read the copied coordinator policy."
[ "$copied_policy" = "$system_policy" ] || die "The coordinator policy changed during copying."

# Six roles in a fixed order. The launcher requires exactly this set, its fixed
# relative paths, and a matching digest. The file is a corruption check inside
# one account. It is not a defense against another process in that account.
digest_file="$output/delivery.sha256"
: > "$digest_file" || die "Cannot write the digest file."
chmod 0600 "$digest_file"

write_digest() {
    local role=$1
    local relative=$2
    local digest
    digest=$(shasum -a 256 "$output/$relative" | cut -d' ' -f1) \
        || die "Cannot hash $relative."
    case "$digest" in
        *[!0-9a-f]*|'') die "The digest for $relative is malformed." ;;
    esac
    [ "${#digest}" -eq 64 ] || die "The digest for $relative is malformed."
    printf '%s %s %s\n' "$role" "$digest" "$relative" >> "$digest_file"
}

write_digest coordinator coordinator/hotspotshade-installer-coordinator
write_digest engine preview/payload/engine/hotspotshade
write_digest helper preview/payload/install-support/dev.hotspotshade.mac.helper
write_digest launch-daemon preview/payload/install-support/dev.hotspotshade.mac.helper.plist
write_digest start-right preview/payload/install-support/dev.hotspotshade.tunnel.start.plist
write_digest manifest preview/manifest.json

instructions="$output/INSTALL.txt"
cat > "$instructions" <<EOF
HotspotShade local Mac preview delivery (preparation only)

This bundle holds the reviewed inputs for one local preview first install on an
Apple silicon Mac. The local preview build path requires an Apple Development
identity. The bundle is not a Developer ID or notarized release, and it is not
an installer.

What is here:
  coordinator/hotspotshade-installer-coordinator  signed coordinator
  app/HotspotShade.app                            signed target app
  preview/payload                                 staged root payload
  preview/manifest.json                           staged manifest
  delivery.sha256                                 corruption check

The deliver step ran the coordinator self-check and verify-preview against
these exact copies. The signed coordinator reports:
  $system_policy
This policy is fixed at build time. A candidate with system-preview enabled
can change system files when run as root. It is not a released installer.

Protected root-owned location for the reviewed copies:
  /$protected_relative

Read the full placement, first-install, resume, and cleanup plan:

  scripts/mac_local_preview_first_install.sh plan --delivery '$output'

That script never runs sudo. It prints the exact commands for a person to
review and run; its install, resume, and uninstall modes do not run them.

Limits:
  The digest file is a corruption check inside one account, not a defense
  against another process in the same account.
  A local preview signature does not protect against other code running as the
  same user. The protected root-owned location only limits who can replace the
  copies that a root run reads.
  A local Apple Development identity has passed staging. A personal-team
  certificate from a free Apple ID has not been verified end to end.
  Live uninstall has not been verified. Do not install it on a Mac that cannot
  be restored from a backup.
EOF
chmod 0600 "$instructions"

complete=1
printf 'Wrote the local preview delivery bundle: %s\n' "$output"
printf 'The coordinator, app signature, payload digests, and shared team were checked.\n'
printf 'Coordinator policy: %s. Nothing was installed.\n' "$system_policy"
printf 'Next, review the plan:\n'
printf "  scripts/mac_local_preview_first_install.sh plan --delivery '%s'\n" "$output"
