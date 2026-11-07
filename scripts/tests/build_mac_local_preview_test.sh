#!/usr/bin/env bash
# Exercise preview build orchestration with fake tools. No signing key or
# system installation is used.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/hs-preview-build.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/tree/scripts" "$work/bin" "$work/helper" "$work/installer"
cp "$repo/scripts/build_mac_local_preview.sh" "$work/tree/scripts/"
cat > "$work/tree/scripts/build_mac_app.sh" <<'EOS'
#!/bin/sh
[ "${HS_MAC_LOCAL_PREVIEW:-}" = 1 ] || exit 1
: > "$1"
EOS
cat > "$work/bin/ditto" <<'EOS'
#!/bin/sh
mkdir -p "$4/HotspotShade.app/Contents/Resources/bin"
: > "$4/HotspotShade.app/Contents/Resources/bin/hotspotshade"
EOS
cat > "$work/bin/swift" <<'EOS'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_LOG"
case " $* " in
    *' -Xswiftc -DHOTSPOTSHADE_LOCAL_PREVIEW '*) ;;
    *) exit 1 ;;
esac
case " $* " in
    *' --show-bin-path '*)
        case " $* " in
            *' macos/HotspotShadeKit '*) printf '%s\n' "$FAKE_HELPER" ;;
            *' macos/Installer '*) printf '%s\n' "$FAKE_INSTALLER" ;;
            *) exit 1 ;;
        esac ;;
esac
EOS
cat > "$work/bin/codesign" <<'EOS'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_LOG"
if [ "$1" = -dv ]; then
    case "$2:${FAKE_BAD_TEAM:-0}" in
        *hotspotshade-installer-coordinator:1) team=ZYXWVUTSRQ ;;
        *) team=ABCDEFGHIJ ;;
    esac
    printf '%s\n' "TeamIdentifier=$team" 'flags=0x10000(runtime)' >&2
fi
EOS
cat > "$work/helper/HotspotShadeHelper" <<'EOS'
#!/bin/sh
exit 0
EOS
cat > "$work/installer/hotspotshade-installer-build" <<'EOS'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_LOG"
[ "$1" = stage ] || exit 1
EOS
cat > "$work/installer/hotspotshade-installer-coordinator" <<'EOS'
#!/bin/sh
printf 'coordinator %s\n' "$*" >> "$FAKE_LOG"
case "$1" in
    self-check|verify-preview) exit 0 ;;
    preview-policy)
        if [ "${HS_MAC_SYSTEM_PREVIEW_CANDIDATE:-0}" = 1 ]; then
            echo 'system-preview: enabled'
        else
            echo 'system-preview: disabled'
        fi ;;
    *) exit 1 ;;
esac
EOS
chmod +x "$work/tree/scripts/build_mac_app.sh" "$work/bin/ditto" "$work/bin/swift" \
    "$work/bin/codesign" "$work/helper/HotspotShadeHelper" \
    "$work/installer/hotspotshade-installer-build" "$work/installer/hotspotshade-installer-coordinator"

if env -u HS_MAC_SIGN_IDENTITY "$work/tree/scripts/build_mac_local_preview.sh" "$work/missing" 0.1.0 >/dev/null 2>&1; then
    echo "Expected a missing signing identity to fail." >&2
    exit 1
fi
[ ! -e "$work/missing" ]
export FAKE_LOG="$work/calls" FAKE_HELPER="$work/helper" FAKE_INSTALLER="$work/installer"
PATH="$work/bin:$PATH" HS_MAC_SIGN_IDENTITY='Apple Development: Fixture' \
    "$work/tree/scripts/build_mac_local_preview.sh" "$work/out" 0.1.0 >/dev/null
grep -F -- '--product HotspotShadeHelper' "$FAKE_LOG" >/dev/null
grep -F -- '--product hotspotshade-installer-build' "$FAKE_LOG" >/dev/null
grep -F -- '--product hotspotshade-installer-coordinator' "$FAKE_LOG" >/dev/null
grep -F -- '--identifier dev.hotspotshade.mac.helper' "$FAKE_LOG" >/dev/null
grep -F -- '--identifier dev.hotspotshade.mac.installer.coordinator' "$FAKE_LOG" >/dev/null
grep -F -- '--verify --strict -R' "$FAKE_LOG" >/dev/null
grep -F -- '-R =anchor apple generic' "$FAKE_LOG" >/dev/null
grep -F -- 'coordinator self-check' "$FAKE_LOG" >/dev/null
grep -F -- 'coordinator verify-preview --app' "$FAKE_LOG" >/dev/null
grep -F -- 'stage --helper' "$FAKE_LOG" >/dev/null
if grep -F -- '-DHOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE' "$FAKE_LOG" >/dev/null; then
    echo "The ordinary build must not enable the system candidate." >&2
    exit 1
fi
: > "$FAKE_LOG"
PATH="$work/bin:$PATH" HS_MAC_SIGN_IDENTITY='Apple Development: Fixture' \
    HS_MAC_SYSTEM_PREVIEW_CANDIDATE=1 \
    "$work/tree/scripts/build_mac_local_preview.sh" "$work/candidate" 0.1.0 >/dev/null
grep -F -- '-DHOTSPOTSHADE_SYSTEM_PREVIEW_CANDIDATE --product hotspotshade-installer-coordinator' "$FAKE_LOG" >/dev/null
if PATH="$work/bin:$PATH" HS_MAC_SIGN_IDENTITY='Apple Development: Fixture' \
    HS_MAC_SYSTEM_PREVIEW_CANDIDATE=invalid \
    "$work/tree/scripts/build_mac_local_preview.sh" "$work/invalid" 0.1.0 >/dev/null 2>&1; then
    echo "Expected an invalid candidate flag to fail." >&2
    exit 1
fi
[ ! -e "$work/invalid" ]
if PATH="$work/bin:$PATH" HS_MAC_SIGN_IDENTITY='Apple Development: Fixture' \
    "$work/tree/scripts/build_mac_local_preview.sh" "$work/out" 0.1.0 >/dev/null 2>&1; then
    echo "Expected an existing output directory to be refused." >&2
    exit 1
fi
if PATH="$work/bin:$PATH" FAKE_BAD_TEAM=1 HS_MAC_SIGN_IDENTITY='Apple Development: Fixture' \
    "$work/tree/scripts/build_mac_local_preview.sh" "$work/bad-team" 0.1.0 >/dev/null 2>&1; then
    echo "Expected a coordinator signed by another team to fail." >&2
    exit 1
fi
echo "Mac local preview build orchestration test passed."
