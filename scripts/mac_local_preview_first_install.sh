#!/bin/sh
# Prepare and present the first-install path for a local Mac preview.
#
# This script is preparation only. It locates a verified delivery bundle (or a
# verified build output), checks its signatures and digests again, and prints
# the exact commands that a person would run to place the signed coordinator and
# the staged payload in one protected root-owned location. It then refuses to
# install, resume, or uninstall. The signed coordinator reports whether its
# system-preview policy is enabled; this preparation script never invokes it.
#
# The script never runs sudo, never writes a system path, never starts a
# service, and never creates a route or a TUN device. It never enables the
# gate. The only writes are none at all.
set -eu
umask 077
cd "$(dirname "$0")/.."

protected_relative='Library/Application Support/HotspotShade/local-preview'

newline='
'

usage() {
    cat <<'EOF'
usage: scripts/mac_local_preview_first_install.sh MODE [options]

Prepare and present the first-install path for an Apple silicon Mac local
preview. MODE is one of:

  plan            Check the inputs and print the full placement, first-install,
                  resume, launch, and cleanup plan. Changes nothing. Exit 0.
  install         Print the same plan, then refuse. Exit 3. Never runs sudo.
  resume          Print the resume and recovery plan, then refuse. Exit 3.
  uninstall       Print the same plan, then refuse. Exit 3. Never runs sudo.
  verify-placed   Read-only check of the protected root-owned copies and their
                  parent directory chain. Exit 0 when they match the plan.

Options:
  --delivery DIR      Delivery bundle from scripts/mac_local_preview_deliver.sh.
  --built DIR         Direct output from scripts/build_mac_local_preview.sh.
  --fixture-root DIR  Test only, verify-placed only. Prefix the protected path
                      under DIR instead of /. Prints a FIXTURE banner.
  --fixture-owner U   Test only, verify-placed only. Expected owner name.
                      Default: the current user. Prints a FIXTURE banner.
  -h, --help          Print this help.

Use exactly one of --delivery and --built for plan, install, and resume.

Exit status:
  0  the plan or the placement check passed
  1  an input check failed
  2  the arguments are invalid
  3  the preparation-only script refused to perform the requested action

This script does not install, sign, notarize, start a service, or change any
system file. It does not prove that a later root install will succeed.
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

# The two read-only coordinator checks. self-check verifies the coordinator's
# own signature and team. verify-preview verifies the app signature, the payload
# digests, the manifest, and the shared team. Neither command installs.
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
    local help
    help=$("$coordinator" --help) || die "The coordinator help cannot be read."
    for command in preview-recover-files preview-recover-service preview-status preview-uninstall; do
        printf '%s\n' "$help" | grep -Fx "  hotspotshade-installer-coordinator $command" >/dev/null \
            || die "The coordinator is too old for this recovery plan. Rebuild the preview."
    done
}

expected_path_for_role() {
    case "$1" in
        coordinator) printf '%s' 'coordinator/hotspotshade-installer-coordinator' ;;
        engine) printf '%s' 'preview/payload/engine/hotspotshade' ;;
        helper) printf '%s' 'preview/payload/install-support/dev.hotspotshade.mac.helper' ;;
        launch-daemon) printf '%s' 'preview/payload/install-support/dev.hotspotshade.mac.helper.plist' ;;
        start-right) printf '%s' 'preview/payload/install-support/dev.hotspotshade.tunnel.start.plist' ;;
        manifest) printf '%s' 'preview/manifest.json' ;;
        *) return 1 ;;
    esac
}

# The delivery digest file is a corruption check inside one account. It has six
# fixed roles, each with one fixed relative path and one SHA-256 digest.
verify_digests() {
    local delivery=$1
    local digest_file="$delivery/delivery.sha256"
    local count=0
    local seen=' '
    local role digest relative_rest expected actual
    require_regular "$digest_file"
    while IFS=' ' read -r role digest relative_rest; do
        [ -n "${role:-}" ] || die "The digest file holds a blank line."
        [ -n "${digest:-}" ] && [ -n "${relative_rest:-}" ] \
            || die "The digest file has a short line."
        case "$relative_rest" in
            *' '*) die "The digest file has an unexpected extra field." ;;
        esac
        expected=$(expected_path_for_role "$role") \
            || die "The digest file names an unknown role: $role"
        [ "$relative_rest" = "$expected" ] \
            || die "The digest file names a path outside the fixed set: $relative_rest"
        case "$seen" in
            *" $role "*) die "The digest file repeats a role: $role" ;;
        esac
        seen="$seen$role "
        case "$digest" in
            *[!0-9a-f]*|'') die "The digest for $role is malformed." ;;
        esac
        [ "${#digest}" -eq 64 ] || die "The digest for $role is malformed."
        actual=$(shasum -a 256 "$delivery/$relative_rest" | cut -d' ' -f1) \
            || die "Cannot hash $relative_rest."
        [ "$actual" = "$digest" ] \
            || die "The delivery file changed since it was packaged: $delivery/$relative_rest"
        count=$((count + 1))
    done < "$digest_file"
    [ "$count" -eq 6 ] || die "The digest file must list exactly six files."
}

# Refuse a directory chain in which a group member or another user can replace
# an entry. A check is not a lock, but a writable parent means the protected
# location is not protected at all.
check_parent_chain() {
    local directory=$1
    local stop=$2
    local owner=$3
    local actual permissions next
    while :; do
        if [ -e "$directory" ]; then
            [ -d "$directory" ] || die "A parent is not a directory: $directory"
            actual=$(stat -f '%Su' "$directory") \
                || die "Cannot read the owner of $directory."
            [ "$actual" = "$owner" ] \
                || die "The directory is not owned by $owner: $directory"
            permissions=$(stat -f '%Sp' "$directory") \
                || die "Cannot read the mode of $directory."
            case "$permissions" in
                ?????w*|????????w*)
                    die "A group member or another user can write to $directory."
                    ;;
            esac
        fi
        [ "$directory" = "$stop" ] && break
        [ "$directory" = '/' ] && break
        next=$(dirname "$directory")
        [ "$next" = "$directory" ] && break
        directory=$next
    done
}

check_directory_mode() {
    local path=$1
    local owner=$2
    local mode=$3
    local actual permissions
    [ -d "$path" ] && [ ! -L "$path" ] || die "Missing directory: $path"
    actual=$(stat -f '%Su' "$path") || die "Cannot read the owner of $path."
    [ "$actual" = "$owner" ] || die "The directory is not owned by $owner: $path"
    actual=$(stat -f '%Lp' "$path") || die "Cannot read the mode of $path."
    [ "$actual" = "$mode" ] || die "The directory mode is $actual, not $mode: $path"
    permissions=$(stat -f '%Sp' "$path")
    case "$permissions" in
        ?????w*|????????w*)
            die "A group member or another user can write to $path."
            ;;
    esac
}

check_file_mode() {
    local path=$1
    local owner=$2
    local mode=$3
    local actual
    [ -f "$path" ] && [ ! -L "$path" ] || die "Missing regular file: $path"
    actual=$(stat -f '%Su' "$path") || die "Cannot read the owner of $path."
    [ "$actual" = "$owner" ] || die "The file is not owned by $owner: $path"
    actual=$(stat -f '%Lp' "$path") || die "Cannot read the mode of $path."
    [ "$actual" = "$mode" ] || die "The file mode is $actual, not $mode: $path"
}

print_parents() {
    local directory=$1
    local next
    while :; do
        if [ -d "$directory" ]; then
            printf '  %s:%s %s %s\n' \
                "$(stat -f '%Su' "$directory")" \
                "$(stat -f '%Sg' "$directory")" \
                "$(stat -f '%Lp' "$directory")" \
                "$directory"
        else
            printf '  (absent) %s\n' "$directory"
        fi
        [ "$directory" = '/' ] && break
        next=$(dirname "$directory")
        [ "$next" = "$directory" ] && break
        directory=$next
    done
}

print_plan() {
    local source_label=$1
    local source_path=$2
    local coordinator=$3
    local app=$4
    local payload=$5
    local manifest=$6
    local preview_root="/$protected_relative"
    local coordinator_directory="$preview_root/coordinator"
    local payload_directory="$preview_root/payload"
    local placed_coordinator="$coordinator_directory/hotspotshade-installer-coordinator"
    local placed_app="$preview_root/HotspotShade.app"
    local placed_manifest="$preview_root/manifest.json"
    local candidate_option=''
    if [ "$system_policy" = 'system-preview: enabled' ]; then
        candidate_option='HS_MAC_SYSTEM_PREVIEW_CANDIDATE=1 '
    fi

    cat <<EOF
HotspotShade local Mac preview first install (preparation only)

Prerequisites:
  An Apple silicon Mac and Xcode with a free Apple ID signed in. Xcode creates
  an Apple Development certificate. No paid Developer ID certificate, no
  notarization, and no paid account are needed for this preview path.

Build and package, if you do not have them yet:
  ${candidate_option}HS_MAC_SIGN_IDENTITY='Apple Development: NAME (TEAM)' \\
      scripts/build_mac_local_preview.sh NEW_BUILD_DIR VERSION
  scripts/mac_local_preview_deliver.sh --built NEW_BUILD_DIR --output NEW_DIR

Source: $source_label at $source_path
  coordinator  $coordinator
  app          $app
  payload      $payload
  manifest     $manifest

The coordinator just checked its own signature, the app signature, every
payload digest, and the shared team. No system file has changed.

The signed coordinator reports:
  $system_policy
When enabled, its root-only preview commands can change system files and
services. The ordinary preview build reports disabled. No live install or
uninstall has been verified by this preparation script.

Trust boundary:
  A local preview is not a security boundary against other code in your
  account. The signature checks catch corruption and a wrong team. They do not
  defend against a same-user process that replaces these copies before a root
  command reads them. That is why the copies go to a root-owned location.

Protected root-owned location:
  $preview_root

Parents, from the protected location to the root:
EOF
    print_parents "$preview_root"
    cat <<EOF

Step 1. Place the reviewed root-owned copies.

Run these commands yourself. This script never runs sudo. Every command uses an
absolute tool path and a quoted path. Read every line before you run it.
This is a first-install plan. An existing preview or placement must be inspected
and removed with its own matching coordinator first. In particular, do not
overwrite an older coordinator: a newer build may refuse to remove its files.
The guard below refuses an existing placement, installed helper, engine, daemon
plist, or app, including symbolic links. It is not a complete service, right,
or journal inspection; check those with the matching coordinator before proceeding.

  if ! sudo /bin/sh -c '
      for path do
          if test -e "\$path" || test -L "\$path"; then exit 1; fi
      done
  ' sh '$preview_root' \\
      '/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper' \\
      '/Library/LaunchDaemons/dev.hotspotshade.mac.helper.plist' \\
      '/Library/Application Support/HotspotShade/engine/hotspotshade' \\
      '/Applications/HotspotShade.app'; then
      printf '%s\\n' 'Existing preview artifact or failed inspection: stop and inspect with its matching coordinator.'
      exit 1
  fi

  sudo /usr/bin/install -d -o root -g wheel -m 0755 \\
      '/Library/Application Support/HotspotShade' \\
      '$preview_root' \\
      '$coordinator_directory' \\
      '$payload_directory' \\
      '$payload_directory/engine' \\
      '$payload_directory/install-support'

  sudo /usr/bin/install -o root -g wheel -m 0755 \\
      '$coordinator' \\
      '$placed_coordinator'

  sudo /usr/bin/install -o root -g wheel -m 0755 \\
      '$payload/engine/hotspotshade' \\
      '$payload_directory/engine/hotspotshade'

  sudo /usr/bin/install -o root -g wheel -m 0644 \\
      '$payload/install-support/dev.hotspotshade.mac.helper' \\
      '$payload_directory/install-support/dev.hotspotshade.mac.helper'

  sudo /usr/bin/install -o root -g wheel -m 0644 \\
      '$payload/install-support/dev.hotspotshade.mac.helper.plist' \\
      '$payload_directory/install-support/dev.hotspotshade.mac.helper.plist'

  sudo /usr/bin/install -o root -g wheel -m 0644 \\
      '$payload/install-support/dev.hotspotshade.tunnel.start.plist' \\
      '$payload_directory/install-support/dev.hotspotshade.tunnel.start.plist'

  sudo /usr/bin/install -o root -g wheel -m 0600 \\
      '$manifest' \\
      '$placed_manifest'

  sudo /usr/bin/ditto '$app' '$placed_app'
  sudo /usr/sbin/chown -R root:wheel '$placed_app'
  sudo /bin/chmod -R go+rX '$placed_app'

Step 2. Check the placement. These commands only read.

  scripts/mac_local_preview_first_install.sh verify-placed

  /usr/bin/stat -f '%Su:%Sg %Lp %N' \\
      '$preview_root' \\
      '$coordinator_directory' \\
      '$placed_coordinator' \\
      '$payload_directory' \\
      '$payload_directory/engine' \\
      '$payload_directory/engine/hotspotshade' \\
      '$payload_directory/install-support' \\
      '$placed_manifest'

  /usr/bin/codesign --verify --strict '$placed_coordinator'
  /usr/bin/codesign --verify --strict '$placed_app'

The coordinator can run self-check as root. The verify-preview command runs as
the user. At install time the coordinator re-reads every signature and copies the payload into a private
root-owned workspace, then checks owner, mode, link count, access control list,
digest, and size before use. A static check is not a lock. Do not run a root
command while another process can write to the tree.

Step 3. First install. The coordinator policy above determines whether this can run.

  sudo '$placed_coordinator' preview-install \\
      --app '$placed_app' \\
      --payload '$payload_directory' \\
      --manifest '$placed_manifest'

A successful run installs the engine, the helper, the launch daemon file, and
the start right, then registers the service. The app still needs an explicit
Turn on action. Turn on asks the protected helper for a root engine and for one
administrator authorization.

Step 4. Launch the app. Do not run the app as root.

  sudo /usr/bin/ditto '$placed_app' '/Applications/HotspotShade.app'
  sudo /usr/sbin/chown -R root:wheel '/Applications/HotspotShade.app'
  open '/Applications/HotspotShade.app'

The local preview build path signs with an Apple Development identity, so there
is no notarization ticket. A locally built app has no quarantine attribute. If
it was copied from another Mac, the first launch may need a right-click and
Open. A local Apple Development identity has passed staging; a personal-team
certificate from a free Apple ID has not been verified end to end.

The app runs the bundled engine as the signed-in user when it opens. The
dashboard, pairing, settings, and status use that user engine, so opening the
app asks for no administrator authorization. Turn on asks the installed
protected helper for a root engine and for one administrator authorization.

Step 5. Resume and recovery. Use only the state that preview-install names.

  Files installed and the service rolled back:
  sudo '$placed_coordinator' preview-resume \\
      --app '$placed_app' \\
      --payload '$payload_directory' \\
      --manifest '$placed_manifest'

  "An install journal is present" (roll the file transaction forward or back):
  sudo '$placed_coordinator' preview-recover-files

  A service journal is present:
  sudo '$placed_coordinator' preview-recover-service

  To inspect journals and markers:
  sudo '$placed_coordinator' preview-status

  "An installed file already exists", a start journal, a cleanup block, or an
  existing service: stop and inspect. Do not retry blindly.

Run preview-install only when no installed file and no journal is present. Keep
the placed payload unchanged: preview-resume compares every installed file with
this exact payload and refuses a mismatch. Never delete /var/db/hotspotshade,
an install journal, a backup, or a start journal by hand.

Step 6. Remove the installed set. The coordinator policy above determines whether this can run.

  sudo '$placed_coordinator' preview-uninstall

The command is intended to remove the fixed launch daemon job, start right,
engine, helper, and associated files after checking their signatures, policies,
and paths. Empty install directories can also be removed. These checks do not
prove which installation created an object. Removal refuses while a tunnel
starts or runs, while a journal or a start record is present, or when an
object does not match. Interruption and retry are tested with fake services;
live removal is not yet verified.

It does not remove the app in /Applications, this root-owned preview tree,
/var/db/hotspotshade or its lock files, /var/lib/hotspotshade, or
/Library/PrivilegedHelperTools. The engine home can contain the target identity key.
Remove the app and this tree by hand after a successful uninstall, once no
resume or recovery may be needed.

Step 7. Keep the recovery tools.

Keep this tree while any resume or recovery may be needed:
  $preview_root

Do not remove it while the preview is installed: it contains the coordinator
and payload needed for inspection, recovery, and resume. Do not install it on a
Mac that cannot be restored from a backup.
EOF
}

verify_placed() {
    local root=$1
    local owner=$2
    local stop=$3
    local fixture=$4

    if [ "$fixture" -eq 1 ]; then
        printf 'FIXTURE: this is a directory check, not live placement proof.\n'
    fi
    check_parent_chain "$root" "$stop" "$owner"
    check_directory_mode "$root" "$owner" 755
    check_directory_mode "$root/coordinator" "$owner" 755
    check_directory_mode "$root/payload" "$owner" 755
    check_directory_mode "$root/payload/engine" "$owner" 755
    check_directory_mode "$root/payload/install-support" "$owner" 755
    check_file_mode "$root/coordinator/hotspotshade-installer-coordinator" "$owner" 755
    check_file_mode "$root/payload/engine/hotspotshade" "$owner" 755
    check_file_mode \
        "$root/payload/install-support/dev.hotspotshade.mac.helper" "$owner" 644
    check_file_mode \
        "$root/payload/install-support/dev.hotspotshade.mac.helper.plist" "$owner" 644
    check_file_mode \
        "$root/payload/install-support/dev.hotspotshade.tunnel.start.plist" "$owner" 644
    check_file_mode "$root/manifest.json" "$owner" 600
    check_payload_tree "$root/payload"
    check_directory_mode "$root/HotspotShade.app" "$owner" 755

    if [ "$fixture" -eq 0 ]; then
        /usr/bin/codesign --verify --strict \
            "$root/coordinator/hotspotshade-installer-coordinator" \
            || die "The placed coordinator signature is not valid."
        /usr/bin/codesign --verify --strict "$root/HotspotShade.app" \
            || die "The placed app signature is not valid."
        printf 'The placed tree matches the plan and both signatures verify.\n'
        printf 'The coordinator re-checks the staged copy at install time.\n'
    else
        printf 'The fixture tree matches the plan.\n'
    fi
}

mode=''
delivery=''
built=''
fixture_root=''
fixture_owner=''
seen_delivery=0
seen_built=0
seen_fixture_root=0
seen_fixture_owner=0

[ "$#" -ge 1 ] || usage_error "Missing MODE."
mode=$1
shift
case "$mode" in
    plan|install|resume|uninstall|verify-placed) ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "Unknown mode: $mode" ;;
esac

while [ "$#" -gt 0 ]; do
    case "$1" in
        --delivery)
            [ "$#" -ge 2 ] || usage_error "Missing value for --delivery."
            [ "$seen_delivery" -eq 0 ] || usage_error "Duplicate --delivery."
            seen_delivery=1
            delivery=$2
            shift 2
            ;;
        --built)
            [ "$#" -ge 2 ] || usage_error "Missing value for --built."
            [ "$seen_built" -eq 0 ] || usage_error "Duplicate --built."
            seen_built=1
            built=$2
            shift 2
            ;;
        --fixture-root)
            [ "$#" -ge 2 ] || usage_error "Missing value for --fixture-root."
            [ "$seen_fixture_root" -eq 0 ] || usage_error "Duplicate --fixture-root."
            seen_fixture_root=1
            fixture_root=$2
            shift 2
            ;;
        --fixture-owner)
            [ "$#" -ge 2 ] || usage_error "Missing value for --fixture-owner."
            [ "$seen_fixture_owner" -eq 0 ] || usage_error "Duplicate --fixture-owner."
            seen_fixture_owner=1
            fixture_owner=$2
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

[ "$(id -u)" -ne 0 ] || die "This preparation step must not run as root."

if [ "$mode" = 'verify-placed' ]; then
    [ "$seen_delivery" -eq 0 ] || usage_error "verify-placed does not take --delivery."
    [ "$seen_built" -eq 0 ] || usage_error "verify-placed does not take --built."
    if [ "$seen_fixture_root" -eq 1 ] || [ "$seen_fixture_owner" -eq 1 ]; then
        [ -n "$fixture_root" ] || usage_error "The --fixture-root value is empty."
        refuse_unsafe_path "$fixture_root"
        if [ -L "$fixture_root" ]; then
            die "The --fixture-root must not be a symlink."
        fi
        fixture_root=$(realpath "$fixture_root") \
            || die "The --fixture-root directory does not exist."
        require_directory "$fixture_root"
        owner=${fixture_owner:-$(id -un)}
        [ -n "$owner" ] || usage_error "The --fixture-owner value is empty."
        verify_placed "$fixture_root/$protected_relative" "$owner" "$fixture_root" 1
    else
        verify_placed "/$protected_relative" 'root' '/' 0
    fi
    exit 0
fi

[ "$seen_fixture_root" -eq 0 ] || usage_error "--fixture-root is only for verify-placed."
[ "$seen_fixture_owner" -eq 0 ] || usage_error "--fixture-owner is only for verify-placed."
[ "$seen_delivery" -eq 1 ] || [ "$seen_built" -eq 1 ] \
    || usage_error "Use --delivery or --built."
[ "$seen_delivery" -eq 0 ] || [ "$seen_built" -eq 0 ] \
    || usage_error "Use only one of --delivery and --built."

if [ "$seen_delivery" -eq 1 ]; then
    [ -n "$delivery" ] || usage_error "The --delivery value is empty."
    refuse_unsafe_path "$delivery"
    if [ -L "$delivery" ]; then
        die "The --delivery path must not be a symlink."
    fi
    delivery=$(realpath "$delivery") || die "The delivery directory does not exist."
    require_directory "$delivery"
    coordinator="$delivery/coordinator/hotspotshade-installer-coordinator"
    app="$delivery/app/HotspotShade.app"
    payload="$delivery/preview/payload"
    manifest="$delivery/preview/manifest.json"
    require_regular "$coordinator"
    require_directory "$app"
    require_regular "$manifest"
    check_payload_tree "$payload"
    verify_digests "$delivery"
    source_label='delivery bundle'
    source_path=$delivery
else
    [ -n "$built" ] || usage_error "The --built value is empty."
    refuse_unsafe_path "$built"
    if [ -L "$built" ]; then
        die "The --built path must not be a symlink."
    fi
    built=$(realpath "$built") || die "The build output directory does not exist."
    require_directory "$built"
    coordinator="$built/hotspotshade-installer-coordinator"
    app="$built/app/HotspotShade.app"
    payload="$built/staged/payload"
    manifest="$built/staged/manifest.json"
    require_regular "$coordinator"
    require_directory "$app"
    require_regular "$manifest"
    check_payload_tree "$payload"
    source_label='build output'
    source_path=$built
fi

refuse_unsafe_path "$coordinator"
refuse_unsafe_path "$app"
refuse_unsafe_path "$payload"
refuse_unsafe_path "$manifest"

verify_preview "$coordinator" "$app" "$payload" "$manifest"
system_policy=$("$coordinator" preview-policy) || die "Cannot read the coordinator policy."
case "$system_policy" in
    'system-preview: enabled'|'system-preview: disabled') ;;
    *) die "The coordinator returned an unknown preview policy." ;;
esac

# A live plan must not sit under a writable parent. The two directories that
# the placement creates are absent before the first run, so only the existing
# parents are checked here.
check_parent_chain "/$protected_relative" '/' 'root'

print_plan "$source_label" "$source_path" "$coordinator" "$app" "$payload" "$manifest"

if [ "$mode" = 'install' ] || [ "$mode" = 'resume' ] || [ "$mode" = 'uninstall' ]; then
    cat >&2 <<EOF

REFUSED: this preparation script does not perform $mode.
The signed coordinator reports: $system_policy
This script never runs sudo. No system file, service, route, or TUN device was
changed. The commands above describe the manual path for this coordinator.
EOF
    exit 3
fi

exit 0
