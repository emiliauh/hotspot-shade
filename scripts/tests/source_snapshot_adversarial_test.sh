#!/usr/bin/env bash
# Adversarial fixture tests for scripts/source_snapshot.sh.
#
# Every fixture is a temporary git work tree below a private temporary
# directory. The test sets no route, creates no device, uses no network, and
# touches no file outside its temp directory. The fake commands model a
# same-user writer that wins a race between a check and the next operation.
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
helper=$repo_dir/scripts/source_snapshot.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-snapshot-adversarial.XXXXXXXX")
tmp=$(CDPATH= cd "$tmp" && pwd -P)
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

passed=0
pass() {
  passed=$((passed + 1))
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | sed 's/.*= //'
  else
    fail "No SHA-256 tool is available."
  fi
}

real_ln=$(command -v ln)
real_mktemp=$(command -v mktemp)
real_rm=$(command -v rm)
real_od=$(command -v od)
real_uniq=$(command -v uniq)
real_find=$(command -v find)
real_tr=$(command -v tr)

git_fixture() {
  gf_repo=$1
  shift
  git -C "$gf_repo" -c user.name=Fixture -c user.email=fixture@example.invalid "$@"
}

make_repo() {
  mr_repo=$1
  mkdir -p "$mr_repo/rust/src"
  printf 'fn main() {}\n' > "$mr_repo/rust/src/main.rs"
  git init -q "$mr_repo"
  git_fixture "$mr_repo" add rust/src/main.rs
  git_fixture "$mr_repo" commit -qm fixture
}

# ---------------------------------------------------------------------------
# A tracked path with a newline must fail closed before the NUL-separated git
# listing becomes lines. Otherwise a decoy path can make an ignored path look
# tracked and clean.
# ---------------------------------------------------------------------------
decoy_repo=$tmp/decoy/repo
mkdir -p "$decoy_repo/rust/src"
printf 'clean\n' > "$decoy_repo/rust/src/ok.rs"
printf 'ignored source\n' > "$decoy_repo/rust/src/ignored.rs"
printf 'rust/src/ignored.rs\n' > "$decoy_repo/.gitignore"
decoy_dir=$(printf 'rust/decoy\nrust/src')
mkdir -p "$decoy_repo/$decoy_dir"
printf 'decoy\n' > "$decoy_repo/$decoy_dir/ignored.rs"
git init -q "$decoy_repo"
git_fixture "$decoy_repo" add .gitignore rust/src/ok.rs \
  "$decoy_dir/ignored.rs"
git_fixture "$decoy_repo" commit -qm 'newline decoy'

if "$helper" --repo "$decoy_repo" --list > "$tmp/decoy-list.out" \
  2> "$tmp/decoy-list.log"; then
  fail "--list accepted a tracked path with a newline."
fi
grep -q 'control byte' "$tmp/decoy-list.log" ||
  fail "--list rejected the newline decoy for an unexpected reason."
if grep -q 'rust/src/ignored.rs' "$tmp/decoy-list.out"; then
  fail "--list printed the decoy match."
fi
pass

printf '+ %s  rust/src/ignored.rs\n' \
  "$(sha256_file "$decoy_repo/rust/src/ignored.rs")" > "$tmp/decoy-manifest.txt"
mkdir -p "$tmp/decoy/out"
if "$helper" --repo "$decoy_repo" --manifest "$tmp/decoy-manifest.txt" \
  --output "$tmp/decoy/out/source.tar.gz" > "$tmp/decoy-build.log" 2>&1; then
  fail "A build accepted an ignored path through a newline decoy."
fi
grep -q 'control byte' "$tmp/decoy-build.log" ||
  fail "The newline decoy build failed for an unexpected reason."
[ ! -e "$tmp/decoy/out/source.tar.gz" ] ||
  fail "The newline decoy build wrote an archive."
pass

# ---------------------------------------------------------------------------
# assume-unchanged and skip-worktree must not make a changed file look clean.
# A path with either bit is also counted as modified even when its content is
# still identical, so the provenance record never calls it clean.
# ---------------------------------------------------------------------------
flags_repo=$tmp/flags/repo
make_repo "$flags_repo"
flags_file=$flags_repo/rust/src/main.rs

git_fixture "$flags_repo" update-index --assume-unchanged rust/src/main.rs
printf 'changed under assume-unchanged\n' >> "$flags_file"
flags_sum=$(sha256_file "$flags_file")
printf '%s  rust/src/main.rs\n' "$flags_sum" > "$tmp/flags-noopt.txt"
if "$helper" --repo "$flags_repo" --manifest "$tmp/flags-noopt.txt" \
  --output "$tmp/flags-noopt.tar.gz" > "$tmp/flags-noopt.log" 2>&1; then
  fail "A changed assume-unchanged file looked clean."
fi
grep -q 'without a leading' "$tmp/flags-noopt.log" ||
  fail "The assume-unchanged change failed for an unexpected reason."
pass
"$helper" --repo "$flags_repo" --list > "$tmp/flags-list.txt" \
  2> "$tmp/flags-list.log" || fail "--list failed with assume-unchanged."
grep -Fqx "+ $flags_sum  rust/src/main.rs" "$tmp/flags-list.txt" ||
  fail "--list did not mark the assume-unchanged change."
printf '+ %s  rust/src/main.rs\n' "$flags_sum" > "$tmp/flags-opt.txt"
"$helper" --repo "$flags_repo" --manifest "$tmp/flags-opt.txt" \
  --output "$tmp/flags-opt.tar.gz" > "$tmp/flags-opt.log" 2>&1 || {
  cat "$tmp/flags-opt.log" >&2
  fail "An opted-in assume-unchanged file did not build."
}
grep -q '^Tracked modified (opted in): 1$' "$tmp/flags-opt.tar.gz.provenance" ||
  fail "The assume-unchanged file was not counted as modified."
pass
git_fixture "$flags_repo" update-index --no-assume-unchanged rust/src/main.rs
git_fixture "$flags_repo" checkout -- rust/src/main.rs

git_fixture "$flags_repo" update-index --assume-unchanged rust/src/main.rs
printf '%s  rust/src/main.rs\n' "$(sha256_file "$flags_file")" \
  > "$tmp/flags-same.txt"
if "$helper" --repo "$flags_repo" --manifest "$tmp/flags-same.txt" \
  --output "$tmp/flags-same.tar.gz" > "$tmp/flags-same.log" 2>&1; then
  fail "An assume-unchanged file with identical content was called clean."
fi
grep -q 'without a leading' "$tmp/flags-same.log" ||
  fail "The unchanged assume-unchanged file failed for an unexpected reason."
git_fixture "$flags_repo" update-index --no-assume-unchanged rust/src/main.rs
pass

git_fixture "$flags_repo" update-index --skip-worktree rust/src/main.rs
printf 'changed under skip-worktree\n' >> "$flags_file"
skip_sum=$(sha256_file "$flags_file")
printf '%s  rust/src/main.rs\n' "$skip_sum" > "$tmp/skip-noopt.txt"
if "$helper" --repo "$flags_repo" --manifest "$tmp/skip-noopt.txt" \
  --output "$tmp/skip-noopt.tar.gz" > "$tmp/skip-noopt.log" 2>&1; then
  fail "A changed skip-worktree file looked clean."
fi
grep -q 'without a leading' "$tmp/skip-noopt.log" ||
  fail "The skip-worktree change failed for an unexpected reason."
printf '+ %s  rust/src/main.rs\n' "$skip_sum" > "$tmp/skip-opt.txt"
"$helper" --repo "$flags_repo" --manifest "$tmp/skip-opt.txt" \
  --output "$tmp/skip-opt.tar.gz" > "$tmp/skip-opt.log" 2>&1 || {
  cat "$tmp/skip-opt.log" >&2
  fail "An opted-in skip-worktree file did not build."
}
grep -q '^Tracked modified (opted in): 1$' "$tmp/skip-opt.tar.gz.provenance" ||
  fail "The skip-worktree file was not counted as modified."
git_fixture "$flags_repo" update-index --no-skip-worktree rust/src/main.rs
git_fixture "$flags_repo" checkout -- rust/src/main.rs
pass

# ---------------------------------------------------------------------------
# Repository identity. A normal work tree and a linked work tree are accepted.
# An ancestor core.worktree redirect, or a .git file that points at the main
# git directory, is refused.
# ---------------------------------------------------------------------------
identity_repo=$tmp/identity/repo
make_repo "$identity_repo"
identity_line=$(printf '%s  rust/src/main.rs\n' \
  "$(sha256_file "$identity_repo/rust/src/main.rs")")
printf '%s\n' "$identity_line" > "$tmp/identity-manifest.txt"
mkdir -p "$tmp/identity/out"
"$helper" --repo "$identity_repo" --manifest "$tmp/identity-manifest.txt" \
  --output "$tmp/identity/out/normal.tar.gz" > "$tmp/identity-normal.log" 2>&1 || {
  cat "$tmp/identity-normal.log" >&2
  fail "A normal work tree was rejected."
}
pass

git_fixture "$identity_repo" worktree add -q "$tmp/identity/wt" -b linked-test
"$helper" --repo "$tmp/identity/wt" --manifest "$tmp/identity-manifest.txt" \
  --output "$tmp/identity/out/linked.tar.gz" > "$tmp/identity-linked.log" 2>&1 || {
  cat "$tmp/identity-linked.log" >&2
  fail "A linked work tree was rejected."
}
pass

redirect_root=$tmp/identity/redirect
mkdir -p "$redirect_root/target/rust/src" "$redirect_root/ancestor"
printf 'redirected source\n' > "$redirect_root/target/rust/src/fake.rs"
git init -q "$redirect_root/ancestor"
printf 'ancestor\n' > "$redirect_root/ancestor/ancestor.txt"
git_fixture "$redirect_root/ancestor" add ancestor.txt
git_fixture "$redirect_root/ancestor" commit -qm ancestor
git_fixture "$redirect_root/ancestor" config core.worktree \
  "$redirect_root/target"
printf 'gitdir: %s\n' "$redirect_root/ancestor/.git" \
  > "$redirect_root/target/.git"
printf '+ %s  rust/src/fake.rs\n' \
  "$(sha256_file "$redirect_root/target/rust/src/fake.rs")" \
  > "$tmp/redirect-manifest.txt"
if "$helper" --repo "$redirect_root/target" \
  --manifest "$tmp/redirect-manifest.txt" \
  --output "$tmp/identity/out/redirect.tar.gz" > "$tmp/identity-redirect.log" 2>&1; then
  fail "A core.worktree redirect was accepted."
fi
grep -q 'core.worktree' "$tmp/identity-redirect.log" ||
  fail "The core.worktree redirect failed for an unexpected reason."
[ ! -e "$tmp/identity/out/redirect.tar.gz" ] ||
  fail "The core.worktree redirect wrote an archive."
pass

pointer_root=$tmp/identity/pointer
mkdir -p "$pointer_root/target/rust/src" "$pointer_root/ancestor"
printf 'pointer source\n' > "$pointer_root/target/rust/src/fake.rs"
git init -q "$pointer_root/ancestor"
printf 'ancestor\n' > "$pointer_root/ancestor/ancestor.txt"
git_fixture "$pointer_root/ancestor" add ancestor.txt
git_fixture "$pointer_root/ancestor" commit -qm ancestor
printf 'gitdir: %s\n' "$pointer_root/ancestor/.git" \
  > "$pointer_root/target/.git"
printf '+ %s  rust/src/fake.rs\n' \
  "$(sha256_file "$pointer_root/target/rust/src/fake.rs")" \
  > "$tmp/pointer-manifest.txt"
if "$helper" --repo "$pointer_root/target" \
  --manifest "$tmp/pointer-manifest.txt" \
  --output "$tmp/identity/out/pointer.tar.gz" > "$tmp/identity-pointer.log" 2>&1; then
  fail "A .git pointer to the main git directory was accepted."
fi
grep -q 'common git directory' "$tmp/identity-pointer.log" ||
  fail "The .git pointer failed for an unexpected reason."
pass

# ---------------------------------------------------------------------------
# Extraction must create every file with an exclusive no-follow link. A planted
# symlink or hardlink at the destination fails the run and never writes the
# victim file.
# ---------------------------------------------------------------------------
extract_repo=$tmp/extract/repo
make_repo "$extract_repo"
extract_manifest=$tmp/extract-manifest.txt
printf '%s\n' "$identity_line" > "$extract_manifest"
mkdir -p "$tmp/extract/out"
"$helper" --repo "$extract_repo" --manifest "$extract_manifest" \
  --output "$tmp/extract/out/source.tar.gz" > "$tmp/extract-build.log" 2>&1 || {
  cat "$tmp/extract-build.log" >&2
  fail "The extraction fixture did not build."
}
extract_sum=$(sha256_file "$tmp/extract/out/source.tar.gz")

victim=$tmp/extract/victim.txt
printf 'SAFE\n' > "$victim"

mkdir -p "$tmp/extract/bin"
cat > "$tmp/extract/bin/ln" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/extract/sym/"*'/rust/src/main.rs')
    "$real_ln" -s "$victim" "\$last" 2>/dev/null || true ;;
  "$tmp/extract/hard/"*'/rust/src/main.rs')
    "$real_ln" "$victim" "\$last" 2>/dev/null || true ;;
  "$tmp/extract/symdir/"*'/rust/src/main.rs')
    "$real_ln" -s "$tmp/extract/outside-dir" "\$last" 2>/dev/null || true
    : > "$tmp/extract/symdir-hit" ;;
  "$tmp/extract/extra/"*'/rust/src/main.rs')
    "$real_ln" "\$@" || exit \$?
    "$real_ln" -s "$victim" "$tmp/extract/extra/created/injected"
    : > "$tmp/extract/extra-hit"
    exit 0 ;;
  "$tmp/extract/anc/"*'/rust/src/main.rs')
    "$real_rm" -rf "\${last%/*}" 2>/dev/null || true
    "$real_ln" -s "$tmp/extract/outside" "\${last%/*}" 2>/dev/null || true ;;
esac
exec "$real_ln" "\$@"
EOF
chmod +x "$tmp/extract/bin/ln"

mkdir -p "$tmp/extract/sym"
if PATH="$tmp/extract/bin:$PATH" "$helper" --verify \
  "$tmp/extract/out/source.tar.gz" --expect-sha256 "$extract_sum" \
  --extract-to "$tmp/extract/sym/created" \
  > "$tmp/extract-sym.log" 2>&1; then
  fail "A planted destination symlink was followed."
fi
grep -q 'without following a link' "$tmp/extract-sym.log" ||
  fail "The planted destination symlink failed for an unexpected reason."
[ "$(cat "$victim")" = "SAFE" ] ||
  fail "A planted destination symlink wrote through the victim file."
[ ! -e "$tmp/extract/sym/created" ] ||
  fail "A planted destination symlink left the extraction behind."
pass

mkdir -p "$tmp/extract/extra"
if PATH="$tmp/extract/bin:$PATH" "$helper" --verify \
  "$tmp/extract/out/source.tar.gz" --expect-sha256 "$extract_sum" \
  --extract-to "$tmp/extract/extra/created" \
  > "$tmp/extract-extra.log" 2>&1; then
  fail "An extra symlink in the extraction was accepted."
fi
[ -f "$tmp/extract/extra-hit" ] || fail "Extra symlink was not planted."
grep -q 'non-regular entry' "$tmp/extract-extra.log" ||
  fail "An extra symlink failed for the wrong reason."
[ "$(cat "$victim")" = "SAFE" ] || fail "The extra symlink target changed."
pass

mkdir -p "$tmp/extract/symdir" "$tmp/extract/outside-dir"
if PATH="$tmp/extract/bin:$PATH" "$helper" --verify \
  "$tmp/extract/out/source.tar.gz" --expect-sha256 "$extract_sum" \
  --extract-to "$tmp/extract/symdir/created" \
  > "$tmp/extract-symdir.log" 2>&1; then
  fail "A planted directory symlink was followed."
fi
[ -f "$tmp/extract/symdir-hit" ] || fail "Directory symlink was not planted."
[ -z "$(find "$tmp/extract/outside-dir" -mindepth 1 -print -quit)" ] ||
  fail "A link was created through the directory symlink."
pass

mkdir -p "$tmp/extract/fail-od-bin"
cat > "$tmp/extract/fail-od-bin/od" <<EOF
#!/bin/sh
case "\$*" in *tracked.raw*) exit 1 ;; esac
exec "$real_od" "\$@"
EOF
chmod +x "$tmp/extract/fail-od-bin/od"
if PATH="$tmp/extract/fail-od-bin:$PATH" "$helper" --repo "$extract_repo" --list \
  > "$tmp/extract/fail-od.out" 2> "$tmp/extract/fail-od.log"; then
  fail "A failed path-byte reader reported success."
fi
grep -q 'Cannot inspect git tracked path bytes' "$tmp/extract/fail-od.log" ||
  fail "A failed path-byte reader failed for the wrong reason."
pass

mkdir -p "$tmp/extract/fail-uniq-bin"
cat > "$tmp/extract/fail-uniq-bin/uniq" <<EOF
#!/bin/sh
case "\$*" in *entries.sorted*) exit 1 ;; esac
exec "$real_uniq" "\$@"
EOF
chmod +x "$tmp/extract/fail-uniq-bin/uniq"
if PATH="$tmp/extract/fail-uniq-bin:$PATH" "$helper" --verify \
  "$tmp/extract/out/source.tar.gz" --expect-sha256 "$extract_sum" \
  > "$tmp/extract/fail-uniq.log" 2>&1; then
  fail "A failed duplicate reader reported success."
fi
grep -q 'Cannot check duplicate paths' "$tmp/extract/fail-uniq.log" ||
  fail "A failed duplicate reader failed for the wrong reason."
pass

mkdir -p "$tmp/extract/fail-find-bin"
cat > "$tmp/extract/fail-find-bin/find" <<EOF
#!/bin/sh
case "\$*" in *'/extract -type l -print'*) exit 1 ;; esac
exec "$real_find" "\$@"
EOF
chmod +x "$tmp/extract/fail-find-bin/find"
if PATH="$tmp/extract/fail-find-bin:$PATH" "$helper" --verify \
  "$tmp/extract/out/source.tar.gz" --expect-sha256 "$extract_sum" \
  > "$tmp/extract/fail-find.log" 2>&1; then
  fail "A failed extracted-link scan reported success."
fi
grep -q 'Cannot inspect extracted archive links' "$tmp/extract/fail-find.log" ||
  fail "A failed extracted-link scan failed for the wrong reason."
pass

mkdir -p "$tmp/extract/fail-inode-bin"
cat > "$tmp/extract/fail-inode-bin/uniq" <<EOF
#!/bin/sh
case "\$*" in *inodes.sorted*) exit 1 ;; esac
exec "$real_uniq" "\$@"
EOF
chmod +x "$tmp/extract/fail-inode-bin/uniq"
if PATH="$tmp/extract/fail-inode-bin:$PATH" "$helper" --repo "$extract_repo" \
  --manifest "$extract_manifest" --output "$tmp/extract/out/fail-inode.tar.gz" \
  > "$tmp/extract/fail-inode.log" 2>&1; then
  fail "A failed source-inode check reported success."
fi
grep -q 'Cannot check source inode uniqueness' "$tmp/extract/fail-inode.log" ||
  fail "A failed source-inode check failed for the wrong reason."
pass

mkdir -p "$tmp/extract/fail-tr-bin"
cat > "$tmp/extract/fail-tr-bin/tr" <<EOF
#!/bin/sh
if [ "\$1" = '\0' ]; then exit 1; fi
exec "$real_tr" "\$@"
EOF
chmod +x "$tmp/extract/fail-tr-bin/tr"
if PATH="$tmp/extract/fail-tr-bin:$PATH" "$helper" --repo "$extract_repo" --list \
  > "$tmp/extract/fail-tr.out" 2> "$tmp/extract/fail-tr.log"; then
  fail "A failed git path decoder reported success."
fi
grep -q 'Cannot decode tracked git paths' "$tmp/extract/fail-tr.log" ||
  fail "A failed git path decoder failed for the wrong reason."
pass

mkdir -p "$tmp/extract/hard"
if PATH="$tmp/extract/bin:$PATH" "$helper" --verify \
  "$tmp/extract/out/source.tar.gz" --expect-sha256 "$extract_sum" \
  --extract-to "$tmp/extract/hard/created" \
  > "$tmp/extract-hard.log" 2>&1; then
  fail "A planted destination hardlink was followed."
fi
grep -q 'without following a link' "$tmp/extract-hard.log" ||
  fail "The planted destination hardlink failed for an unexpected reason."
[ "$(cat "$victim")" = "SAFE" ] ||
  fail "A planted destination hardlink overwrote the victim file."
[ ! -e "$tmp/extract/hard/created" ] ||
  fail "A planted destination hardlink left the extraction behind."
pass

mkdir -p "$tmp/extract/anc" "$tmp/extract/outside"
if PATH="$tmp/extract/bin:$PATH" "$helper" --verify \
  "$tmp/extract/out/source.tar.gz" --expect-sha256 "$extract_sum" \
  --extract-to "$tmp/extract/anc/created" \
  > "$tmp/extract-anc.log" 2>&1; then
  fail "A replaced extraction ancestor reported success."
fi
grep -q 'non-directory or symlink' "$tmp/extract-anc.log" ||
  fail "A replaced extraction ancestor failed for an unexpected reason."
pass

# ---------------------------------------------------------------------------
# Temporary output files must be inspected before they are written. A planted
# symlink or hardlink at the mktemp path fails the run without touching the
# victim file.
# ---------------------------------------------------------------------------
temp_repo=$tmp/temp/repo
make_repo "$temp_repo"
temp_manifest=$tmp/temp-manifest.txt
printf '%s\n' "$identity_line" > "$temp_manifest"

temp_victim=$tmp/temp/victim.txt
printf 'SAFE\n' > "$temp_victim"
mkdir -p "$tmp/temp/bin" "$tmp/temp/out-sym" "$tmp/temp/out-hard"
cat > "$tmp/temp/bin/mktemp" <<EOF
#!/bin/sh
case "\$1" in
  "$tmp/temp/out-sym/".hotspotshade-snapshot.*)
    p=\$("$real_mktemp" "\$@")
    "$real_rm" -f "\$p"
    "$real_ln" -s "$temp_victim" "\$p"
    printf '%s\n' "\$p"
    exit 0 ;;
  "$tmp/temp/out-hard/".hotspotshade-snapshot.*)
    p=\$("$real_mktemp" "\$@")
    "$real_rm" -f "\$p"
    "$real_ln" "$temp_victim" "\$p"
    printf '%s\n' "\$p"
    exit 0 ;;
esac
exec "$real_mktemp" "\$@"
EOF
chmod +x "$tmp/temp/bin/mktemp"

if PATH="$tmp/temp/bin:$PATH" "$helper" --repo "$temp_repo" \
  --manifest "$temp_manifest" --output "$tmp/temp/out-sym/source.tar.gz" \
  > "$tmp/temp-sym.log" 2>&1; then
  fail "A planted temporary output symlink was written through."
fi
grep -q 'temporary output file changed' "$tmp/temp-sym.log" ||
  fail "The planted temporary output symlink failed for an unexpected reason."
[ "$(cat "$temp_victim")" = "SAFE" ] ||
  fail "A planted temporary output symlink wrote the victim file."
[ ! -e "$tmp/temp/out-sym/source.tar.gz" ] ||
  fail "A planted temporary output symlink produced an archive."
pass

if PATH="$tmp/temp/bin:$PATH" "$helper" --repo "$temp_repo" \
  --manifest "$temp_manifest" --output "$tmp/temp/out-hard/source.tar.gz" \
  > "$tmp/temp-hard.log" 2>&1; then
  fail "A planted temporary output hardlink was written through."
fi
grep -q 'temporary output file changed' "$tmp/temp-hard.log" ||
  fail "The planted temporary output hardlink failed for an unexpected reason."
[ "$(cat "$temp_victim")" = "SAFE" ] ||
  fail "A planted temporary output hardlink overwrote the victim file."
[ ! -e "$tmp/temp/out-hard/source.tar.gz" ] ||
  fail "A planted temporary output hardlink produced an archive."
pass

mkdir -p "$tmp/temp/fmo-sym" "$tmp/temp/fmo-hard" "$tmp/temp/fmo-bin"
temp_archive=$tmp/temp/source.tar.gz
cp "$tmp/extract/out/source.tar.gz" "$temp_archive"
temp_sum=$(sha256_file "$temp_archive")
cat > "$tmp/temp/fmo-bin/mktemp" <<EOF
#!/bin/sh
case "\$1" in
  "$tmp/temp/fmo-sym/".hs-files.*)
    p=\$("$real_mktemp" "\$@")
    "$real_rm" -f "\$p"
    "$real_ln" -s "$temp_victim" "\$p"
    printf '%s\n' "\$p"
    exit 0 ;;
  "$tmp/temp/fmo-hard/".hs-files.*)
    p=\$("$real_mktemp" "\$@")
    "$real_rm" -f "\$p"
    "$real_ln" "$temp_victim" "\$p"
    printf '%s\n' "\$p"
    exit 0 ;;
esac
exec "$real_mktemp" "\$@"
EOF
chmod +x "$tmp/temp/fmo-bin/mktemp"
if PATH="$tmp/temp/fmo-bin:$PATH" "$helper" --verify "$temp_archive" \
  --expect-sha256 "$temp_sum" --extract-to "$tmp/temp/fmo-sym/tree" \
  --files-manifest-out "$tmp/temp/fmo-sym/files.sha256" \
  > "$tmp/temp-fmo-sym.log" 2>&1; then
  fail "A planted files manifest temporary symlink was written through."
fi
grep -q 'temporary files manifest changed' "$tmp/temp-fmo-sym.log" ||
  fail "The planted files manifest temporary symlink failed for an unexpected reason."
[ "$(cat "$temp_victim")" = "SAFE" ] ||
  fail "A planted files manifest temporary symlink wrote the victim file."
[ ! -e "$tmp/temp/fmo-sym/tree" ] ||
  fail "A planted files manifest temporary symlink started extraction."
pass

if PATH="$tmp/temp/fmo-bin:$PATH" "$helper" --verify "$temp_archive" \
  --expect-sha256 "$temp_sum" --extract-to "$tmp/temp/fmo-hard/tree" \
  --files-manifest-out "$tmp/temp/fmo-hard/files.sha256" \
  > "$tmp/temp-fmo-hard.log" 2>&1; then
  fail "A planted files manifest temporary hardlink was written through."
fi
grep -q 'temporary files manifest changed' "$tmp/temp-fmo-hard.log" ||
  fail "The planted files manifest temporary hardlink failed for an unexpected reason."
[ "$(cat "$temp_victim")" = "SAFE" ] ||
  fail "A planted files manifest temporary hardlink overwrote the victim file."
[ ! -e "$tmp/temp/fmo-hard/tree" ] ||
  fail "A planted files manifest temporary hardlink started extraction."
pass

printf 'Source snapshot adversarial tests passed (%s checks).\n' "$passed"
