#!/usr/bin/env bash
# Exercise the local preview delivery and first-install preparation scripts with
# fake tools. No signing identity, no sudo, no system path, no service, no
# route, and no TUN device is used.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/hs-preview-delivery.XXXXXXXX")
trap 'rm -rf "$work"' EXIT

deliver="$repo/scripts/mac_local_preview_deliver.sh"
launcher="$repo/scripts/mac_local_preview_first_install.sh"

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

expect_status() {
    local want=$1
    shift
    local got=0
    "$@" >/dev/null 2>&1 || got=$?
    if [ "$got" -ne "$want" ]; then
        fail "expected status $want, got $got: $*"
    fi
}

expect_mode() {
    local path=$1
    local want=$2
    [ -e "$path" ] || fail "missing file: $path"
    local got
    got=$(stat -f '%Lp' "$path")
    [ "$got" = "$want" ] || fail "mode $got, expected $want: $path"
}

expect_contains() {
    local file=$1
    local text=$2
    grep -F -- "$text" "$file" >/dev/null || fail "missing text in $file: $text"
}

# One fake build output with the exact staged tree the real tools produce.
# The coordinator is a shell stand-in that records its arguments. The fake
# sudo fails loudly if any script ever runs it.
built="$work/built"
fakebin="$work/bin"
mkdir -p "$built/app/HotspotShade.app/Contents/MacOS" \
    "$built/staged/payload/engine" \
    "$built/staged/payload/install-support" \
    "$fakebin"
printf 'fake app\n' > "$built/app/HotspotShade.app/Contents/MacOS/HotspotShade"
printf 'fake plist\n' > "$built/app/HotspotShade.app/Contents/Info.plist"
chmod 0700 "$built/app/HotspotShade.app" "$built/app/HotspotShade.app/Contents" \
    "$built/app/HotspotShade.app/Contents/MacOS" "$built/app/HotspotShade.app/Contents/MacOS/HotspotShade"
chmod 0600 "$built/app/HotspotShade.app/Contents/Info.plist"
printf 'engine\n' > "$built/staged/payload/engine/hotspotshade"
printf 'helper\n' > "$built/staged/payload/install-support/dev.hotspotshade.mac.helper"
printf 'launch daemon\n' > "$built/staged/payload/install-support/dev.hotspotshade.mac.helper.plist"
printf 'start right\n' > "$built/staged/payload/install-support/dev.hotspotshade.tunnel.start.plist"
printf '{"version" : "0.1.0"}\n' > "$built/staged/manifest.json"
chmod 0600 "$built/staged/manifest.json"
cat > "$built/hotspotshade-installer-coordinator" <<'EOS'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_LOG"
[ "${FAKE_VERIFY_FAIL:-0}" = 1 ] && exit 1
case "$1" in
    self-check|verify-preview) exit 0 ;;
    preview-policy) printf 'system-preview: %s\n' "${FAKE_PREVIEW_POLICY:-disabled}"; exit 0 ;;
    --help)
        printf '%s\n' \
            '  hotspotshade-installer-coordinator preview-recover-files' \
            '  hotspotshade-installer-coordinator preview-recover-service' \
            '  hotspotshade-installer-coordinator preview-status' \
            '  hotspotshade-installer-coordinator preview-uninstall'
        exit 0 ;;
    *) exit 1 ;;
esac
EOS
chmod 0755 "$built/hotspotshade-installer-coordinator"
cat > "$fakebin/sudo" <<'EOS'
#!/bin/sh
: > "$SUDO_MARKER"
exit 99
EOS
chmod 0755 "$fakebin/sudo"

export PATH="$fakebin:$PATH"
export FAKE_LOG="$work/calls"
export SUDO_MARKER="$work/sudo-ran"

printf 'Test: argument handling and root refusal.\n'
expect_status 0 "$deliver" --help
expect_status 0 "$launcher" --help
expect_contains <("$deliver" --help) 'install gate'
expect_status 2 "$deliver" --built "$built"
expect_status 2 "$launcher" plan
expect_status 2 "$launcher" plan --delivery "$work/none" --built "$built"
expect_status 2 "$launcher" bogus-mode
expect_status 2 "$launcher" plan --delivery "$work/none" --fixture-root "$work"

mkdir -p "$work/rootbin"
cat > "$work/rootbin/id" <<'EOS'
#!/bin/sh
case "$1" in
    -u) printf '0\n' ;;
    *) exec /usr/bin/id "$@" ;;
esac
EOS
chmod 0755 "$work/rootbin/id"
expect_status 1 env PATH="$work/rootbin:$PATH" "$deliver" --built "$built" --output "$work/as-root-deliver"
expect_status 1 env PATH="$work/rootbin:$PATH" "$launcher" plan --delivery "$work/none"
[ ! -e "$work/as-root-deliver" ] || fail "the root refusal left an output directory"

printf 'Test: delivery bundle.\n'
delivery="$work/delivery"
expect_status 0 "$deliver" --built "$built" --output "$delivery"
expect_mode "$delivery/app/HotspotShade.app" 755
expect_mode "$delivery/app/HotspotShade.app/Contents" 755
expect_mode "$delivery/app/HotspotShade.app/Contents/MacOS/HotspotShade" 755
expect_mode "$delivery/app/HotspotShade.app/Contents/Info.plist" 644
expect_mode "$delivery/coordinator/hotspotshade-installer-coordinator" 755
expect_mode "$delivery/preview/payload" 755
expect_mode "$delivery/preview/payload/engine/hotspotshade" 755
expect_mode "$delivery/preview/payload/install-support/dev.hotspotshade.mac.helper" 644
expect_mode "$delivery/preview/payload/install-support/dev.hotspotshade.mac.helper.plist" 644
expect_mode "$delivery/preview/payload/install-support/dev.hotspotshade.tunnel.start.plist" 644
expect_mode "$delivery/preview/manifest.json" 600
expect_mode "$delivery/delivery.sha256" 600
expect_mode "$delivery/INSTALL.txt" 600
[ "$(wc -l < "$delivery/delivery.sha256" | tr -d ' ')" = 6 ] \
    || fail "the digest file does not hold six lines"
for role in coordinator engine helper launch-daemon start-right manifest; do
    grep -F -- "$role " "$delivery/delivery.sha256" >/dev/null \
        || fail "the digest file is missing the role: $role"
done
expect_contains "$delivery/INSTALL.txt" 'system-preview: disabled'
expect_contains "$delivery/INSTALL.txt" '/Library/Application Support/HotspotShade/local-preview'
expect_contains "$delivery/INSTALL.txt" 'mac_local_preview_first_install.sh plan --delivery'
expect_contains "$delivery/INSTALL.txt" 'personal-team'
[ "$(grep -c 'self-check' "$FAKE_LOG")" -eq 2 ] \
    || fail "the source and the copy were not both self-checked"
[ "$(grep -c 'verify-preview' "$FAKE_LOG")" -eq 2 ] \
    || fail "the source and the copy were not both verify-previewed"
[ ! -e "$SUDO_MARKER" ] || fail "the delivery step ran sudo"

FAKE_PREVIEW_POLICY=enabled "$deliver" --built "$built" --output "$work/candidate-delivery" > /dev/null
expect_contains "$work/candidate-delivery/INSTALL.txt" 'system-preview: enabled'
FAKE_PREVIEW_POLICY=enabled "$launcher" plan --delivery "$work/candidate-delivery" > "$work/candidate-plan.out"
expect_contains "$work/candidate-plan.out" 'system-preview: enabled'
expect_contains "$work/candidate-plan.out" 'HS_MAC_SYSTEM_PREVIEW_CANDIDATE=1'
[ ! -e "$SUDO_MARKER" ] || fail "the candidate preparation ran sudo"

printf 'Test: delivery refusals.\n'
expect_status 1 "$deliver" --built "$built" --output "$delivery"
if FAKE_VERIFY_FAIL=1 "$deliver" --built "$built" --output "$work/out-verify" >/dev/null 2>&1; then
    fail "expected a failed coordinator verification to stop the delivery"
fi
[ ! -e "$work/out-verify" ] || fail "a failed verification left a delivery bundle"

cp -R "$built" "$work/built-extra"
: > "$work/built-extra/staged/payload/extra"
expect_status 1 "$deliver" --built "$work/built-extra" --output "$work/out-extra"
[ ! -e "$work/out-extra" ] || fail "an extra payload object left a delivery bundle"

cp -R "$built" "$work/built-link"
rm "$work/built-link/staged/payload/engine/hotspotshade"
ln -s /bin/sh "$work/built-link/staged/payload/engine/hotspotshade"
expect_status 1 "$deliver" --built "$work/built-link" --output "$work/out-link"
[ ! -e "$work/out-link" ] || fail "a symlinked payload left a delivery bundle"

printf 'Test: the plan and the honest refusal.\n'
"$launcher" plan --delivery "$delivery" > "$work/plan.out" 2> "$work/plan.err" \
    || fail "the plan failed"
expect_contains "$work/plan.out" '/Library/Application Support/HotspotShade/local-preview'
expect_contains "$work/plan.out" 'sudo /usr/bin/install -d -o root -g wheel -m 0755'
expect_contains "$work/plan.out" 'Existing preview artifact or failed inspection: stop and inspect with its matching coordinator.'
expect_contains "$work/plan.out" 'test -L "$path"'
expect_contains "$work/plan.out" '/Library/PrivilegedHelperTools/dev.hotspotshade.mac.helper'
expect_contains "$work/plan.out" '/Applications/HotspotShade.app'
expect_contains "$work/plan.out" 'sudo /usr/bin/install -o root -g wheel -m 0755'
expect_contains "$work/plan.out" 'sudo /usr/bin/install -o root -g wheel -m 0644'
expect_contains "$work/plan.out" 'sudo /usr/bin/install -o root -g wheel -m 0600'
expect_contains "$work/plan.out" '/usr/bin/codesign --verify --strict'
expect_contains "$work/plan.out" 'preview-install'
expect_contains "$work/plan.out" 'preview-resume'
expect_contains "$work/plan.out" 'preview-recover-files'
expect_contains "$work/plan.out" 'preview-recover-service'
expect_contains "$work/plan.out" 'system-preview: disabled'
expect_contains "$work/plan.out" 'preview-status'
expect_contains "$work/plan.out" 'preview-uninstall'
expect_contains "$work/plan.out" 'Do not remove it while the preview is installed'
if grep -F 'sudo /bin/rm -rf' "$work/plan.out" >/dev/null; then
    echo "The plan must keep the recovery tools while installed." >&2
    exit 1
fi
expect_contains "$work/plan.out" 'Apple Development'
expect_contains "$work/plan.out" 'mac_local_preview_first_install.sh verify-placed'
expect_contains "$work/plan.out" "sudo '/Library/Application Support/HotspotShade/local-preview/coordinator/hotspotshade-installer-coordinator'"
[ ! -e "$SUDO_MARKER" ] || fail "the plan ran sudo"

expect_status 3 "$launcher" install --delivery "$delivery"
set +e
"$launcher" install --delivery "$delivery" > "$work/install.out" 2> "$work/install.err"
install_status=$?
set -e
[ "$install_status" -eq 3 ] || fail "install did not refuse with status 3"
expect_contains "$work/install.err" 'REFUSED: this preparation script does not perform install.'
expect_contains "$work/install.err" 'system-preview: disabled'
expect_contains "$work/install.out" 'preview-install'
[ ! -e "$SUDO_MARKER" ] || fail "install ran sudo"

set +e
"$launcher" resume --delivery "$delivery" > "$work/resume.out" 2> "$work/resume.err"
resume_status=$?
set -e
[ "$resume_status" -eq 3 ] || fail "resume did not refuse with status 3"
expect_contains "$work/resume.err" 'REFUSED: this preparation script does not perform resume.'
expect_contains "$work/resume.out" 'preview-resume'
[ ! -e "$SUDO_MARKER" ] || fail "resume ran sudo"

set +e
"$launcher" uninstall --delivery "$delivery" > "$work/uninstall.out" 2> "$work/uninstall.err"
uninstall_status=$?
set -e
[ "$uninstall_status" -eq 3 ] || fail "uninstall did not refuse with status 3"
expect_contains "$work/uninstall.err" 'REFUSED: this preparation script does not perform uninstall.'
expect_contains "$work/uninstall.out" 'preview-uninstall'
[ ! -e "$SUDO_MARKER" ] || fail "uninstall ran sudo"

"$launcher" plan --built "$built" > "$work/plan-built.out" 2>/dev/null \
    || fail "the plan from a build output failed"
expect_contains "$work/plan-built.out" 'Source: build output'
[ ! -e "$SUDO_MARKER" ] || fail "the build output plan ran sudo"

printf 'Test: the delivery digest check.\n'
cp -R "$delivery" "$work/delivery-tamper"
printf 'x' >> "$work/delivery-tamper/preview/payload/install-support/dev.hotspotshade.mac.helper"
set +e
"$launcher" plan --delivery "$work/delivery-tamper" >/dev/null 2> "$work/tamper.err"
tamper_status=$?
set -e
[ "$tamper_status" -eq 1 ] || fail "a changed delivery did not fail with status 1"
expect_contains "$work/tamper.err" 'changed since it was packaged'

cp -R "$delivery" "$work/delivery-role"
sed -i '' 's/^manifest /unknown /' "$work/delivery-role/delivery.sha256"
set +e
"$launcher" plan --delivery "$work/delivery-role" >/dev/null 2> "$work/role.err"
role_status=$?
set -e
[ "$role_status" -eq 1 ] || fail "an unknown digest role did not fail with status 1"
expect_contains "$work/role.err" 'unknown role'

cp -R "$delivery" "$work/delivery-link"
rm "$work/delivery-link/preview/payload/install-support/dev.hotspotshade.tunnel.start.plist"
ln -s /bin/sh "$work/delivery-link/preview/payload/install-support/dev.hotspotshade.tunnel.start.plist"
expect_status 1 "$launcher" plan --delivery "$work/delivery-link"

printf 'Test: the protected placement check with a fixture.\n'
fixture="$work/placed"
placed="$fixture/Library/Application Support/HotspotShade/local-preview"
mkdir -p "$placed/coordinator" "$placed/payload/engine" \
    "$placed/payload/install-support" "$placed/HotspotShade.app"
cp "$delivery/coordinator/hotspotshade-installer-coordinator" "$placed/coordinator/"
cp "$delivery/preview/payload/engine/hotspotshade" "$placed/payload/engine/"
cp "$delivery/preview/payload/install-support/"*.plist "$placed/payload/install-support/"
cp "$delivery/preview/payload/install-support/dev.hotspotshade.mac.helper" \
    "$placed/payload/install-support/"
cp "$delivery/preview/manifest.json" "$placed/manifest.json"
chmod 0755 "$fixture" "$fixture/Library" "$fixture/Library/Application Support" \
    "$fixture/Library/Application Support/HotspotShade" \
    "$placed" "$placed/coordinator" "$placed/payload" "$placed/payload/engine" \
    "$placed/payload/install-support" "$placed/HotspotShade.app"
chmod 0755 "$placed/coordinator/hotspotshade-installer-coordinator" \
    "$placed/payload/engine/hotspotshade"
chmod 0644 "$placed/payload/install-support/"*
chmod 0600 "$placed/manifest.json"

"$launcher" verify-placed --fixture-root "$fixture" > "$work/placed.out" 2>&1 \
    || fail "the fixture placement check failed"
expect_contains "$work/placed.out" 'FIXTURE'
expect_contains "$work/placed.out" 'matches the plan'

chmod 0775 "$placed/coordinator"
expect_status 1 "$launcher" verify-placed --fixture-root "$fixture"
chmod 0755 "$placed/coordinator"
expect_status 1 "$launcher" verify-placed --fixture-root "$fixture" --fixture-owner root

: > "$placed/payload/extra"
expect_status 1 "$launcher" verify-placed --fixture-root "$fixture"
rm "$placed/payload/extra"

chmod 0700 "$placed"
expect_status 1 "$launcher" verify-placed --fixture-root "$fixture"
chmod 0755 "$placed"

[ ! -e "$SUDO_MARKER" ] || fail "a preparation step ran sudo"

printf 'Mac local preview delivery and first-install preparation tests passed.\n'
