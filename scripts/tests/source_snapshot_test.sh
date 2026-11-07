#!/usr/bin/env bash
# Hermetic fixture tests for scripts/source_snapshot.sh.
#
# Every fixture is a temporary git work tree. The test sets no route, creates
# no device, uses no network, and touches no file outside its temp directory.
set -euo pipefail

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
helper=$repo_dir/scripts/source_snapshot.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-snapshot-test.XXXXXXXX")
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

real_rm=$(command -v rm)
real_find=$(command -v find)
real_mkdir=$(command -v mkdir)
real_ln=$(command -v ln)
real_cat=$(command -v cat)

# ---------------------------------------------------------------------------
# Fixture work tree. It holds tracked source, an intentional untracked source
# file, an ignored build output, a fake secret, a probe record, node modules,
# and two symlinks. Only the manifest may put a path into the archive.
# ---------------------------------------------------------------------------
fixture=$tmp/repo
mkdir -p "$fixture"/rust/src "$fixture"/rust/target/debug \
  "$fixture"/rust/credentials "$fixture"/desktop \
  "$fixture"/linux/node_modules/pkg "$fixture"/gui_assets \
  "$fixture"/assets "$fixture"/windows/src "$fixture"/probes

printf 'fn main() {}\n' > "$fixture/rust/src/main.rs"
printf 'library\n' > "$fixture/rust/src/lib.rs"
printf 'swap source\n' > "$fixture/rust/src/swap.rs"
printf 'lock\n' > "$fixture/rust/Cargo.lock"
printf '[package]\nname = "fixture"\n' > "$fixture/rust/Cargo.toml"
printf 'desktop\n' > "$fixture/desktop/Cargo.toml"
printf 'desktop lock\n' > "$fixture/desktop/Cargo.lock"
printf 'linux\n' > "$fixture/linux/package.json"
printf 'linux lock\n' > "$fixture/linux/package-lock.json"
printf 'gui\n' > "$fixture/gui_assets/app.js"
printf 'asset\n' > "$fixture/assets/logo.txt"
printf 'windows\n' > "$fixture/windows/src/App.cs"

weird="rust/src/space name 'quote' \$dollar & more.rs"
printf 'weird\n' > "$fixture/$weird"
printf 'two spaces\n' > "$fixture/rust/src/two  spaces.rs"
untracked='gui_assets/extra source 01.js'
printf 'untracked\n' > "$fixture/$untracked"
long1=$(printf 'd%.0s' $(seq 1 60))
long2=$(printf 'e%.0s' $(seq 1 60))
longpath="rust/src/$long1/$long2/file.txt"
mkdir -p "$fixture/${longpath%/*}"
printf 'long\n' > "$fixture/$longpath"

printf 'ignored build output\n' > "$fixture/rust/target/debug/app"
printf 'module\n' > "$fixture/linux/node_modules/pkg/index.js"
printf 'probe\n' > "$fixture/probes/trace.txt"
printf 'fake secret\n' > "$fixture/rust/fixture.key"
printf 'fake credential\n' > "$fixture/rust/credentials/token.txt"
ln -s /etc/passwd "$fixture/gui_assets/outside-link"
ln -s ../rust/src/lib.rs "$fixture/gui_assets/inside-link"

cat > "$fixture/.gitignore" <<'EOF'
rust/target/
linux/node_modules/
probes/
rust/src/ignored.rs
*.log
EOF

git -C "$fixture" init -q
git -C "$fixture" -c user.name=Fixture -c user.email=fixture@example.invalid add \
  .gitignore rust/Cargo.lock rust/Cargo.toml rust/src/main.rs \
  rust/src/lib.rs rust/src/swap.rs "$weird" "rust/src/two  spaces.rs" \
  "$longpath" desktop/Cargo.toml desktop/Cargo.lock linux/package.json \
  linux/package-lock.json gui_assets/app.js assets/logo.txt windows/src/App.cs
git -C "$fixture" -c user.name=Fixture -c user.email=fixture@example.invalid \
  commit -qm 'fixture'

if git -C "$fixture" ls-files --error-unmatch "$untracked" >/dev/null 2>&1; then
  fail "The fixture untracked file was added to git."
fi

pin() {
  sha256_file "$fixture/$1"
}
line() {
  printf '%s  %s\n' "$(pin "$1")" "$1"
}
optin() {
  printf '+ %s  %s\n' "$(pin "$1")" "$1"
}

cat > "$tmp/manifest.txt" <<EOF
# Reviewed source snapshot input.
$(line rust/Cargo.lock)
$(line rust/Cargo.toml)
$(line rust/src/lib.rs)
$(line rust/src/main.rs)
$(line rust/src/swap.rs)
$(line "$weird")
$(line "rust/src/two  spaces.rs")
$(line "$longpath")
$(line desktop/Cargo.lock)
$(line desktop/Cargo.toml)
$(line linux/package-lock.json)
$(line linux/package.json)
$(line gui_assets/app.js)
$(line assets/logo.txt)
$(line windows/src/App.cs)
$(optin "$untracked")
EOF

{
  printf '%s\n' assets/logo.txt desktop/Cargo.lock desktop/Cargo.toml \
    gui_assets/app.js "$untracked" linux/package-lock.json \
    linux/package.json rust/Cargo.lock rust/Cargo.toml rust/src/lib.rs \
    rust/src/main.rs rust/src/swap.rs "$weird" "rust/src/two  spaces.rs" \
    "$longpath" windows/src/App.cs
} | LC_ALL=C sort > "$tmp/expected.txt"

mkdir -p "$tmp/out"
out=$tmp/out/source.tar.gz
"$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" --output "$out" \
  > "$tmp/build.log" 2>&1 || {
  cat "$tmp/build.log" >&2
  fail "The helper did not build the reviewed manifest."
}
pass
for suffix in "" .sha256 .files.sha256 .manifest.sha256 .provenance; do
  [ -f "$out$suffix" ] || fail "Missing output: $out$suffix"
done
[ ! -L "$out" ] || fail "The archive output is a symlink."

# The archive holds exactly the manifest entries.
tar -tf "$out" | LC_ALL=C sort > "$tmp/entries.actual"
if ! diff -u "$tmp/expected.txt" "$tmp/entries.actual" > "$tmp/entries.diff"; then
  cat "$tmp/entries.diff" >&2
  fail "The archive entries do not match the reviewed manifest."
fi
if grep -Eq '(^|/)(target|node_modules|probes|\.git|credentials)(/|$)|\.key$|outside-link|inside-link' \
  "$tmp/entries.actual"; then
  fail "The archive holds an excluded path."
fi
pass

# Bytes survive the copy and the archive.
mkdir -p "$tmp/extract"
tar -xzf "$out" -C "$tmp/extract"
cmp -s "$fixture/$untracked" "$tmp/extract/$untracked" ||
  fail "The intentional untracked source changed bytes."
cmp -s "$fixture/$weird" "$tmp/extract/$weird" ||
  fail "A path with spaces, a quote, a dollar sign, and an ampersand changed bytes."
cmp -s "$fixture/$longpath" "$tmp/extract/$longpath" ||
  fail "A long ustar path changed bytes."
pass

# Per-file manifest digests match the extracted files.
[ "$(wc -l < "$out.files.sha256" | tr -d ' ')" = "16" ] ||
  fail "The per-file manifest does not hold 16 entries."
while IFS= read -r line; do
  sum=${line%%  *}
  path=${line#*  }
  [ -f "$tmp/extract/$path" ] || fail "The archive is missing $path"
  actual=$(sha256_file "$tmp/extract/$path")
  [ "$actual" = "$sum" ] || fail "Per-file digest mismatch for $path"
done < "$out.files.sha256"
pass

# The sidecars keep the standard "sha256sum -c" shape, including for names
# with spaces and two consecutive spaces.
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp/out" && sha256sum -c source.tar.gz.sha256) \
    > "$tmp/sumcheck.log" 2>&1 ||
    fail "The archive digest file is not sha256sum-compatible."
  (cd "$tmp/extract" && sha256sum -c "$out.files.sha256") \
    > "$tmp/filescheck.log" 2>&1 ||
    fail "The per-file manifest is not sha256sum-compatible."
else
  (cd "$tmp/out" && shasum -a 256 -c source.tar.gz.sha256) \
    > "$tmp/sumcheck.log" 2>&1 ||
    fail "The archive digest file is not shasum-compatible."
  (cd "$tmp/extract" && shasum -a 256 -c "$out.files.sha256") \
    > "$tmp/filescheck.log" 2>&1 ||
    fail "The per-file manifest is not shasum-compatible."
fi
pass

# Archive digest and manifest digest are recorded.
sum_line=$(cat "$out.sha256")
sum=${sum_line%%  *}
name=${sum_line#*  }
[ "$name" = "source.tar.gz" ] || fail "The archive digest names the wrong file."
[ "$sum" = "$(sha256_file "$out")" ] ||
  fail "The archive digest does not match the archive."
[ "$(cut -d' ' -f1 "$out.manifest.sha256")" = "$(sha256_file "$tmp/manifest.txt")" ] ||
  fail "The manifest digest sidecar is wrong."
grep -q "^Manifest SHA-256: $(sha256_file "$tmp/manifest.txt")$" \
  "$out.provenance" || fail "The provenance record omits the manifest digest."
grep -q '^Manifest: manifest.txt$' "$out.provenance" ||
  fail "The provenance record omits the manifest name."
pass

# The provenance record names the dirty manifest content and its scope.
grep -q '^Work tree dirty: yes$' "$out.provenance" ||
  fail "The provenance record does not report dirty manifest content."
grep -q '^Dirty scope: manifest entries only$' "$out.provenance" ||
  fail "The provenance record does not scope the dirty flag."
grep -q '^Tracked clean: 15$' "$out.provenance" ||
  fail "The provenance record miscounts clean tracked files."
grep -q '^Untracked (opted in): 1$' "$out.provenance" ||
  fail "The provenance record miscounts opted-in untracked files."
grep -q 'do not prove that a file holds no secret' "$out.provenance" ||
  fail "The provenance record does not state the content-scan limit."
pass

# The same manifest produces the same archive bytes on this host.
second=$tmp/out/second.tar.gz
"$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" --output "$second" \
  > "$tmp/second.log" 2>&1 || {
  cat "$tmp/second.log" >&2
  fail "The second build failed."
}
cmp -s "$out" "$second" ||
  fail "Two builds from one manifest did not produce the same bytes."
pass

# ---------------------------------------------------------------------------
# Verification. A sidecar alone is a corruption check; an independent digest
# is required for a trusted check and for extraction.
# ---------------------------------------------------------------------------
"$helper" --verify "$out" --expect-sha256 "$sum" > "$tmp/verify.log" 2>&1 || {
  cat "$tmp/verify.log" >&2
  fail "Verification rejected a good archive."
}
grep -q '^Verified 16 files against the supplied SHA-256' "$tmp/verify.log" ||
  fail "Verification did not report 16 files against the supplied digest."
pass

"$helper" --verify "$out" --corruption-only > "$tmp/corrupt.log" 2>&1 ||
  fail "The corruption-only check rejected a good archive."
grep -q 'corruption check only' "$tmp/corrupt.log" ||
  fail "The corruption-only check did not label its scope."
pass

if "$helper" --verify "$out" > "$tmp/no-flag.log" 2>&1; then
  fail "Verification ran without an independent digest or an explicit corruption check."
fi
grep -q 'corruption-only' "$tmp/no-flag.log" ||
  fail "Verification did not explain the required digest choice."
pass

if "$helper" --verify "$out" --expect-sha256 \
  0000000000000000000000000000000000000000000000000000000000000000 \
  > "$tmp/wrong-sum.log" 2>&1; then
  fail "Verification accepted a wrong independent digest."
fi
grep -q 'does not match the supplied' "$tmp/wrong-sum.log" ||
  fail "Verification did not fail on the independent digest."
pass

# Verify works outside a git work tree, and does not call git at all.
(cd / && "$helper" --verify "$out" --expect-sha256 "$sum") \
  > "$tmp/root-verify.log" 2>&1 ||
  fail "Verification failed outside a git work tree."
grep -q '^Verified 16 files' "$tmp/root-verify.log" ||
  fail "Verification from / did not report the file count."
pass

mkdir -p "$tmp/nogit"
printf '#!/bin/sh\nexit 99\n' > "$tmp/nogit/git"
chmod +x "$tmp/nogit/git"
if ! PATH="$tmp/nogit:$PATH" "$helper" --verify "$out" --expect-sha256 "$sum" \
  > "$tmp/nogit-verify.log" 2>&1; then
  cat "$tmp/nogit-verify.log" >&2
  fail "Verification called git."
fi
pass

# --extract-to consumes only the validated tree and needs an absent directory.
"$helper" --verify "$out" --expect-sha256 "$sum" --extract-to "$tmp/restore" \
  > "$tmp/extract-to.log" 2>&1 || {
  cat "$tmp/extract-to.log" >&2
  fail "Verification with --extract-to failed."
}
(cd "$tmp/restore" && find . -type f -print | sed 's#^\./##') |
  LC_ALL=C sort > "$tmp/restore.list"
cmp -s "$tmp/expected.txt" "$tmp/restore.list" ||
  fail "The extracted tree does not match the manifest."
cmp -s "$fixture/$weird" "$tmp/restore/$weird" ||
  fail "The extracted weird path changed bytes."
if stat -c '%a' "$tmp/restore" >/dev/null 2>&1; then
  restore_dir_mode=$(stat -c '%a' "$tmp/restore")
else
  restore_dir_mode=$(stat -f '%Lp' "$tmp/restore")
fi
[ "$restore_dir_mode" = "700" ] ||
  fail "The created extraction destination mode is not 0700: $restore_dir_mode"
if stat -c '%a' "$tmp/restore/rust/src/main.rs" >/dev/null 2>&1; then
  restore_mode=$(stat -c '%a' "$tmp/restore/rust/src/main.rs")
else
  restore_mode=$(stat -f '%Lp' "$tmp/restore/rust/src/main.rs")
fi
[ "$restore_mode" = "644" ] || fail "The extracted file mode is not 0644."
pass

if "$helper" --verify "$out" --expect-sha256 "$sum" --extract-to "$tmp/restore" \
  > "$tmp/restore-again.log" 2>&1; then
  fail "Verification accepted an existing extraction destination."
fi
pass

if "$helper" --verify "$out" --corruption-only --extract-to "$tmp/restore2" \
  > "$tmp/restore-corrupt.log" 2>&1; then
  fail "Extraction ran without an independent digest."
fi
[ ! -e "$tmp/restore2" ] ||
  fail "Extraction created a directory before the trust check."
pass

# A VM harness may copy only the pinned archive. The independent digest pins
# the exact bytes, so verification and extraction must work without sidecars.
mkdir -p "$tmp/only"
cp "$out" "$tmp/only/source.tar.gz"
for suffix in .sha256 .files.sha256 .manifest.sha256 .provenance; do
  [ ! -e "$tmp/only/source.tar.gz$suffix" ] ||
    fail "The archive-only fixture unexpectedly has a sidecar."
done
"$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/only/restore" > "$tmp/only-verify.log" 2>&1 || {
  cat "$tmp/only-verify.log" >&2
  fail "Archive-only verification with an independent digest failed."
}
grep -q '^Verified 16 files against the supplied SHA-256 (archive only' \
  "$tmp/only-verify.log" ||
  fail "Archive-only verification did not label its scope."
(cd "$tmp/only/restore" && find . -type f -print | sed 's#^\./##') |
  LC_ALL=C sort > "$tmp/only-restore.list"
cmp -s "$tmp/expected.txt" "$tmp/only-restore.list" ||
  fail "Archive-only extraction does not match the manifest."
cmp -s "$fixture/$weird" "$tmp/only/restore/$weird" ||
  fail "Archive-only extraction changed bytes."
pass

if "$helper" --verify "$tmp/only/source.tar.gz" \
  --expect-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  > "$tmp/only-wrong.log" 2>&1; then
  fail "Archive-only verification accepted a wrong independent digest."
fi
pass

if "$helper" --verify "$tmp/only/source.tar.gz" \
  > "$tmp/only-no-flag.log" 2>&1; then
  fail "Archive-only verification ran without an independent digest."
fi
if "$helper" --verify "$tmp/only/source.tar.gz" --corruption-only \
  > "$tmp/only-corrupt.log" 2>&1; then
  fail "Corruption-only verification ran without sidecars."
fi
grep -q 'needs the full sidecar set' "$tmp/only-corrupt.log" ||
  fail "Corruption-only verification did not explain the missing sidecars."
pass

# The per-file digest manifest can be recomputed from a pinned archive alone.
"$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --files-manifest-out "$tmp/only/files.sha256" \
  > "$tmp/only-manifest.log" 2>&1 || {
  cat "$tmp/only-manifest.log" >&2
  fail "The helper did not write a computed per-file manifest."
}
cmp -s "$tmp/only/files.sha256" "$out.files.sha256" ||
  fail "The computed per-file manifest differs from the sidecar."
if "$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --files-manifest-out "$tmp/only/files.sha256" \
  > "$tmp/only-manifest-again.log" 2>&1; then
  fail "The helper replaced an existing per-file manifest."
fi
printf 'manifest victim\n' > "$tmp/only/manifest-victim.txt"
ln -s manifest-victim.txt "$tmp/only/files-link.sha256"
if "$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --files-manifest-out "$tmp/only/files-link.sha256" \
  > "$tmp/only-manifest-link.log" 2>&1; then
  fail "The helper wrote a per-file manifest through a symlink."
fi
[ "$(cat "$tmp/only/manifest-victim.txt")" = "manifest victim" ] ||
  fail "The per-file manifest output wrote through a symlink."
pass

# ---------------------------------------------------------------------------
# --files-manifest-out is preflighted before extraction, and its final step is
# a link that publishes the reserved temporary file. A failure must not leave
# a claimed extraction or a hidden output behind.
# ---------------------------------------------------------------------------
mkdir -p "$tmp/preflight"
printf 'existing\n' > "$tmp/preflight/existing.sha256"
if "$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/preflight/existing-tree" \
  --files-manifest-out "$tmp/preflight/existing.sha256" \
  > "$tmp/preflight-existing.log" 2>&1; then
  fail "The helper accepted an existing files manifest."
fi
grep -q 'Refusing to replace an existing files manifest' \
  "$tmp/preflight-existing.log" ||
  fail "The existing files manifest failed for the wrong reason."
[ ! -e "$tmp/preflight/existing-tree" ] ||
  fail "The helper extracted before the files manifest preflight."
[ "$(cat "$tmp/preflight/existing.sha256")" = "existing" ] ||
  fail "The helper replaced an existing files manifest."
pass

if "$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/preflight/missing-tree" \
  --files-manifest-out "$tmp/preflight/no-such-dir/files.sha256" \
  > "$tmp/preflight-missing.log" 2>&1; then
  fail "The helper accepted a files manifest in a missing directory."
fi
grep -q 'files manifest directory does not exist' "$tmp/preflight-missing.log" ||
  fail "The missing files manifest directory failed for the wrong reason."
[ ! -e "$tmp/preflight/missing-tree" ] ||
  fail "The helper extracted before the files manifest directory check."
pass

mkdir -p "$tmp/preflight/inside"
if "$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/preflight/inside" \
  --files-manifest-out "$tmp/preflight/inside/files.sha256" \
  > "$tmp/preflight-inside.log" 2>&1; then
  fail "The helper accepted a files manifest inside the extraction destination."
fi
grep -q 'extraction destination already exists' "$tmp/preflight-inside.log" ||
  fail "The overlapping files manifest failed for the wrong reason."
[ -z "$(find "$tmp/preflight/inside" -mindepth 1 -print -quit)" ] ||
  fail "The helper wrote into the extraction destination before preflight."
pass

if "$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --files-manifest-out "$tmp/only/source.tar.gz.sha256" \
  > "$tmp/preflight-collision.log" 2>&1; then
  fail "The helper accepted a files manifest that collides with the archive set."
fi
grep -q 'collides with the archive set' "$tmp/preflight-collision.log" ||
  fail "The archive-set collision failed for the wrong reason."
[ ! -e "$tmp/only/source.tar.gz.sha256" ] ||
  fail "The helper created a sidecar through --files-manifest-out."
pass

"$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/preflight/combined" \
  --files-manifest-out "$tmp/preflight/combined.files.sha256" \
  > "$tmp/preflight-combined.log" 2>&1 || {
  cat "$tmp/preflight-combined.log" >&2
  fail "The helper rejected a valid extraction and files manifest pair."
}
cmp -s "$tmp/preflight/combined.files.sha256" "$out.files.sha256" ||
  fail "The combined files manifest differs from the sidecar."
[ -z "$(find "$tmp/preflight" -name '.hs-files.*' -print)" ] ||
  fail "The helper left a reserved files manifest temporary file."
pass

# A failed extraction must remove the reserved temporary file and must not
# publish a files manifest.
mkdir -p "$tmp/failln-preflight"
cat > "$tmp/failln-preflight/ln" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/preflight/"*'/rust/src/lib.rs') : > "$tmp/failln-preflight/hit"; exit 1 ;;
esac
exec /bin/ln "\$@"
EOF
chmod +x "$tmp/failln-preflight/ln"
if PATH="$tmp/failln-preflight:$PATH" "$helper" --verify "$out" \
  --expect-sha256 "$sum" --extract-to "$tmp/preflight/fail-tree" \
  --files-manifest-out "$tmp/preflight/fail-tree.files.sha256" \
  > "$tmp/preflight-fail.log" 2>&1; then
  fail "A failed extraction reported success with a files manifest."
fi
[ -f "$tmp/failln-preflight/hit" ] ||
  fail "The extraction publication failure was not injected."
[ ! -e "$tmp/preflight/fail-tree.files.sha256" ] ||
  fail "A failed extraction published a files manifest."
[ -z "$(find "$tmp/preflight" -name '.hs-files.*' -print)" ] ||
  fail "A failed extraction left a reserved temporary file."
pass

# If the final unlink of the reserved temporary file fails, the helper must
# report the residual path, exit non-zero, and remove the output it linked, so
# a failed run never leaves a complete-looking manifest. The residual path
# stays named for the person.
mkdir -p "$tmp/failrmfmo"
cat > "$tmp/failrmfmo/rm" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/preflight"/.hs-files.*) exit 1 ;;
esac
exec "$real_rm" "\$@"
EOF
chmod +x "$tmp/failrmfmo/rm"
if PATH="$tmp/failrmfmo:$PATH" "$helper" --verify \
  "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --files-manifest-out "$tmp/preflight/tempfail.sha256" \
  > "$tmp/preflight-tempfail.log" 2>&1; then
  fail "A failed temporary-file cleanup reported success."
fi
grep -q 'could not remove the temporary file' "$tmp/preflight-tempfail.log" ||
  fail "A failed temporary-file cleanup was silent."
grep -Fq '.hs-files.' "$tmp/preflight-tempfail.log" ||
  fail "The temporary-file cleanup failure did not name the residual path."
[ ! -e "$tmp/preflight/tempfail.sha256" ] ||
  fail "A failed run left a complete-looking files manifest."
[ -n "$(find "$tmp/preflight" -maxdepth 1 -name '.hs-files.*' -print)" ] ||
  fail "The cleanup-failure fixture did not leave its residual temporary file."
"$real_rm" -f "$tmp/preflight"/.hs-files.*
pass

# A files manifest that cannot be linked into place must not leave an
# extraction. The extraction is marked incomplete until the manifest is
# published, so the failure path removes it.
mkdir -p "$tmp/mfail"
cat > "$tmp/mfail/ln" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/mfail/"*.files.sha256) exit 1 ;;
esac
exec /bin/ln "\$@"
EOF
chmod +x "$tmp/mfail/ln"
if PATH="$tmp/mfail:$PATH" "$helper" --verify "$tmp/only/source.tar.gz" \
  --expect-sha256 "$sum" --extract-to "$tmp/mfail/tree" \
  --files-manifest-out "$tmp/mfail/out.files.sha256" \
  > "$tmp/mfail.log" 2>&1; then
  fail "A files manifest that could not be linked reported success."
fi
grep -q 'Cannot create the files manifest' "$tmp/mfail.log" ||
  fail "The unlinked files manifest failed for the wrong reason."
[ ! -e "$tmp/mfail/tree" ] ||
  fail "A failed files manifest left the extraction behind."
[ ! -e "$tmp/mfail/out.files.sha256" ] ||
  fail "A failed files manifest left an output."
[ -z "$(find "$tmp/mfail" -name '.hs-files.*' -print)" ] ||
  fail "A failed files manifest left a reserved temporary file."
pass

# An existing empty destination is refused before extraction. The caller's
# directory stays, and it holds no copied entries.
mkdir -p "$tmp/mfail/pre"
if PATH="$tmp/mfail:$PATH" "$helper" --verify "$tmp/only/source.tar.gz" \
  --expect-sha256 "$sum" --extract-to "$tmp/mfail/pre" \
  --files-manifest-out "$tmp/mfail/pre.files.sha256" \
  > "$tmp/mfail-pre.log" 2>&1; then
  fail "A files manifest that could not be linked reported success."
fi
[ -d "$tmp/mfail/pre" ] ||
  fail "The helper removed a destination directory the caller created."
[ -z "$(find "$tmp/mfail/pre" -mindepth 1 -print -quit)" ] ||
  fail "A failed files manifest left files in a preexisting destination."
pass

# The manifest content is written before anything is extracted. A failed
# mode change on the reserved file must stop the run with no extraction.
mkdir -p "$tmp/mchmod"
cat > "$tmp/mchmod/chmod" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/mchmod/"*/.hs-files.*|"$tmp/mchmod"/.hs-files.*) exit 1 ;;
esac
exec /bin/chmod "\$@"
EOF
chmod +x "$tmp/mchmod/chmod"
if PATH="$tmp/mchmod:$PATH" "$helper" --verify "$tmp/only/source.tar.gz" \
  --expect-sha256 "$sum" --extract-to "$tmp/mchmod/tree" \
  --files-manifest-out "$tmp/mchmod/out.files.sha256" \
  > "$tmp/mchmod.log" 2>&1; then
  fail "A files manifest with a failed mode change reported success."
fi
grep -q 'Cannot set the mode on the files manifest' "$tmp/mchmod.log" ||
  fail "The failed mode change failed for the wrong reason."
[ ! -e "$tmp/mchmod/tree" ] ||
  fail "The helper extracted before the files manifest content was ready."
[ ! -e "$tmp/mchmod/out.files.sha256" ] ||
  fail "A failed mode change published a files manifest."
[ -z "$(find "$tmp/mchmod" -name '.hs-files.*' -print)" ] ||
  fail "A failed mode change left a reserved temporary file."
pass

# If the reserved temporary file cannot be removed after the link, the helper
# removes both the linked manifest and the extraction, names the residual path,
# and exits non-zero.
mkdir -p "$tmp/mrm"
cat > "$tmp/mrm/rm" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/mrm"/.hs-files.*) exit 1 ;;
esac
exec "$real_rm" "\$@"
EOF
chmod +x "$tmp/mrm/rm"
if PATH="$tmp/mrm:$PATH" "$helper" --verify "$tmp/only/source.tar.gz" \
  --expect-sha256 "$sum" --extract-to "$tmp/mrm/tree" \
  --files-manifest-out "$tmp/mrm/out.files.sha256" \
  > "$tmp/mrm.log" 2>&1; then
  fail "A failed temporary-file removal reported success."
fi
grep -q 'could not remove the temporary file' "$tmp/mrm.log" ||
  fail "A failed temporary-file removal was silent."
grep -Fq '.hs-files.' "$tmp/mrm.log" ||
  fail "The failed temporary-file removal did not name the residual path."
[ ! -e "$tmp/mrm/tree" ] ||
  fail "A failed run left the extraction behind."
[ ! -e "$tmp/mrm/out.files.sha256" ] ||
  fail "A failed run left a complete-looking files manifest."
[ -n "$(find "$tmp/mrm" -maxdepth 1 -name '.hs-files.*' -print)" ] ||
  fail "The fixture did not leave its residual temporary file."
"$real_rm" -f "$tmp/mrm"/.hs-files.*
pass

# A failed final success write is a failed verification. The writer closes its
# stdout for the final message, and the helper must not leave the extraction or
# the published files manifest behind. Both stay pending until the exit path
# knows the final status is zero.
mkdir -p "$tmp/closedout" "$tmp/closedout-bin"
cat > "$tmp/closedout-bin/cat" <<EOF
#!/bin/sh
exec "$real_cat" "\$@" >&-
EOF
chmod +x "$tmp/closedout-bin/cat"
if PATH="$tmp/closedout-bin:$PATH" "$helper" --verify \
  "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/closedout/tree" \
  --files-manifest-out "$tmp/closedout/files.sha256" \
  > "$tmp/closedout.log" 2>&1; then
  fail "A final success write with a closed stdout reported success."
fi
[ ! -e "$tmp/closedout/tree" ] ||
  fail "A final success write with a closed stdout left the extraction behind."
[ ! -e "$tmp/closedout/files.sha256" ] ||
  fail "A final success write with a closed stdout left the published manifest behind."
[ -z "$(find "$tmp/closedout" -name '.hs-files.*' -print)" ] ||
  fail "A final success write with a closed stdout left a reserved temporary file."
pass

# A failed removal of the published files manifest must be reported with its
# residual path and a non-zero status, even when the run was already failing.
mkdir -p "$tmp/failmanifest" "$tmp/closedout-manifest"
cat > "$tmp/failmanifest/cat" <<'EOF'
#!/bin/sh
exit 1
EOF
cat > "$tmp/failmanifest/rm" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/closedout-manifest/files.sha256") exit 1 ;;
esac
exec "$real_rm" "\$@"
EOF
chmod +x "$tmp/failmanifest/cat" "$tmp/failmanifest/rm"
if PATH="$tmp/failmanifest:$PATH" "$helper" --verify \
  "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/closedout-manifest/tree" \
  --files-manifest-out "$tmp/closedout-manifest/files.sha256" \
  > "$tmp/closedout-manifest.log" 2>&1; then
  fail "A failed published-manifest cleanup reported success."
fi
grep -q 'cleanup incomplete' "$tmp/closedout-manifest.log" ||
  fail "A failed published-manifest cleanup was silent."
grep -Fq "$tmp/closedout-manifest/files.sha256" \
  "$tmp/closedout-manifest.log" ||
  fail "A failed published-manifest cleanup did not name the residual path."
[ -e "$tmp/closedout-manifest/files.sha256" ] ||
  fail "The cleanup-failure fixture did not leave its published manifest."
[ ! -e "$tmp/closedout-manifest/tree" ] ||
  fail "A failed published-manifest cleanup left the extraction behind."
"$real_rm" -f "$tmp/closedout-manifest/files.sha256"
pass

# A failed private work-directory removal must make the run non-zero and must
# still remove the extraction and published manifest that were waiting for the
# final status.
mkdir -p "$tmp/workfail" "$tmp/workfail-bin" "$tmp/workfail-tmp"
cat > "$tmp/workfail-bin/rm" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/workfail-tmp"/hotspotshade-snapshot.*) exit 1 ;;
esac
exec "$real_rm" "\$@"
EOF
chmod +x "$tmp/workfail-bin/rm"
if TMPDIR="$tmp/workfail-tmp" PATH="$tmp/workfail-bin:$PATH" \
  "$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/workfail/tree" \
  --files-manifest-out "$tmp/workfail/files.sha256" \
  > "$tmp/workfail.log" 2>&1; then
  fail "A failed private work-directory removal reported success."
fi
grep -q 'could not remove the private work directory' "$tmp/workfail.log" ||
  fail "A failed private work-directory removal was silent."
[ ! -e "$tmp/workfail/tree" ] ||
  fail "A failed work-directory cleanup left the extraction behind."
[ ! -e "$tmp/workfail/files.sha256" ] ||
  fail "A failed work-directory cleanup left the published files manifest."
[ -n "$(find "$tmp/workfail-tmp" -maxdepth 1 \
  -name 'hotspotshade-snapshot.*' -print)" ] ||
  fail "The work-directory cleanup fixture left no residual directory."
"$real_rm" -rf "$tmp/workfail-tmp"/hotspotshade-snapshot.*
pass

# A TERM delivered directly after mkdir creates an extraction directory must
# not leak it. The helper marks the destination before mkdir and defers the
# signal until the ownership record is complete.
mkdir -p "$tmp/sigmkdir" "$tmp/sigmkdir-bin"
cat > "$tmp/sigmkdir-bin/mkdir" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/sigmkdir/tree")
    "$real_mkdir" "\$@"
    status=\$?
    kill -TERM "\$PPID" 2>/dev/null || true
    exit \$status
    ;;
esac
exec "$real_mkdir" "\$@"
EOF
chmod +x "$tmp/sigmkdir-bin/mkdir"
if PATH="$tmp/sigmkdir-bin:$PATH" "$helper" --verify \
  "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/sigmkdir/tree" \
  --files-manifest-out "$tmp/sigmkdir/files.sha256" \
  > "$tmp/sigmkdir.log" 2>&1; then
  fail "A TERM after mkdir reported success."
fi
[ ! -e "$tmp/sigmkdir/tree" ] ||
  fail "A TERM after mkdir left the created extraction directory behind."
[ ! -e "$tmp/sigmkdir/files.sha256" ] ||
  fail "A TERM after mkdir left a published files manifest."
[ -z "$(find "$tmp/sigmkdir" -name '.hs-files.*' -print)" ] ||
  fail "A TERM after mkdir left a reserved files manifest temporary file."
pass

# A TERM delivered directly after the manifest ln must not leak the published
# path. The marked inode proves that the path belongs to this run.
mkdir -p "$tmp/sigln" "$tmp/sigln-bin"
cat > "$tmp/sigln-bin/ln" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/sigln/files.sha256")
    "$real_ln" "\$@"
    status=\$?
    kill -TERM "\$PPID" 2>/dev/null || true
    exit \$status
    ;;
esac
exec "$real_ln" "\$@"
EOF
chmod +x "$tmp/sigln-bin/ln"
if PATH="$tmp/sigln-bin:$PATH" "$helper" --verify \
  "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/sigln/tree" \
  --files-manifest-out "$tmp/sigln/files.sha256" \
  > "$tmp/sigln.log" 2>&1; then
  fail "A TERM after the manifest ln reported success."
fi
[ ! -e "$tmp/sigln/tree" ] ||
  fail "A TERM after the manifest ln left the extraction behind."
[ ! -e "$tmp/sigln/files.sha256" ] ||
  fail "A TERM after the manifest ln left the published files manifest."
[ -z "$(find "$tmp/sigln" -name '.hs-files.*' -print)" ] ||
  fail "A TERM after the manifest ln left a reserved temporary file."
pass

# If mkdir fails after another writer creates the destination, the premark
# must be cleared before the deferred signal runs. The existing directory and
# its sentinel must survive.
mkdir -p "$tmp/sigmkdir-race" "$tmp/sigmkdir-race-bin"
cat > "$tmp/sigmkdir-race-bin/mkdir" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/sigmkdir-race/tree")
    "$real_mkdir" -p "\$last"
    printf 'preexisting\n' > "\$last/sentinel"
    kill -TERM "\$PPID" 2>/dev/null || true
    exit 1
    ;;
esac
exec "$real_mkdir" "\$@"
EOF
chmod +x "$tmp/sigmkdir-race-bin/mkdir"
if PATH="$tmp/sigmkdir-race-bin:$PATH" "$helper" --verify \
  "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/sigmkdir-race/tree" \
  --files-manifest-out "$tmp/sigmkdir-race/files.sha256" \
  > "$tmp/sigmkdir-race.log" 2>&1; then
  fail "A failed mkdir after a concurrent creation reported success."
fi
[ "$(cat "$tmp/sigmkdir-race/tree/sentinel" 2>/dev/null)" = "preexisting" ] ||
  fail "A failed mkdir removed a directory another writer created."
[ -z "$(find "$tmp/sigmkdir-race" -name '.hs-files.*' -print)" ] ||
  fail "A failed mkdir left a reserved files manifest temporary file."
"$real_rm" -rf "$tmp/sigmkdir-race/tree"
pass

# If ln fails because another writer creates the output, the premark must be
# cleared before the deferred signal runs. The replacement must survive.
mkdir -p "$tmp/sigln-race" "$tmp/sigln-race-bin"
cat > "$tmp/sigln-race-bin/ln" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/sigln-race/files.sha256")
    printf 'replacement\n' > "\$last"
    kill -TERM "\$PPID" 2>/dev/null || true
    exit 1
    ;;
esac
exec "$real_ln" "\$@"
EOF
chmod +x "$tmp/sigln-race-bin/ln"
if PATH="$tmp/sigln-race-bin:$PATH" "$helper" --verify \
  "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/sigln-race/tree" \
  --files-manifest-out "$tmp/sigln-race/files.sha256" \
  > "$tmp/sigln-race.log" 2>&1; then
  fail "A failed manifest ln after a concurrent creation reported success."
fi
[ "$(cat "$tmp/sigln-race/files.sha256" 2>/dev/null)" = "replacement" ] ||
  fail "A failed manifest ln removed a file another writer created."
[ ! -e "$tmp/sigln-race/tree" ] ||
  fail "A failed manifest ln left the extraction behind."
[ -z "$(find "$tmp/sigln-race" -name '.hs-files.*' -print)" ] ||
  fail "A failed manifest ln left a reserved temporary file."
pass

# An extraction destination needs an existing parent. The helper no longer
# creates a chain of directories that a failure would leave behind.
if "$helper" --verify "$tmp/only/source.tar.gz" --expect-sha256 "$sum" \
  --extract-to "$tmp/noparent/a/b" > "$tmp/noparent.log" 2>&1; then
  fail "The helper accepted an extraction destination without a parent."
fi
grep -q 'existing parent directory' "$tmp/noparent.log" ||
  fail "The missing parent failed for the wrong reason."
[ ! -e "$tmp/noparent" ] || fail "The helper created a missing parent chain."
pass

# A build that fails after it claimed an output removes the outputs it
# created. No partial set stays behind, and no temporary file is left.
mkdir -p "$tmp/claimfail" "$tmp/claimfail-bin"
cat > "$tmp/claimfail-bin/ln" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/claimfail/"*.provenance) exit 1 ;;
esac
exec /bin/ln "\$@"
EOF
chmod +x "$tmp/claimfail-bin/ln"
if PATH="$tmp/claimfail-bin:$PATH" "$helper" --repo "$fixture" \
  --manifest "$tmp/manifest.txt" --output "$tmp/claimfail/a.tar.gz" \
  > "$tmp/claimfail.log" 2>&1; then
  fail "A build with a failed claim reported success."
fi
[ -z "$(find "$tmp/claimfail" -mindepth 1 -print -quit)" ] ||
  fail "A failed build left a partial output set: $(find "$tmp/claimfail" -mindepth 1 -print)"
pass

# A temporary output file that cannot be removed fails the build, is named,
# and still rolls back every output that was already claimed.
mkdir -p "$tmp/claimrm" "$tmp/claimrm-bin"
cat > "$tmp/claimrm-bin/rm" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/claimrm"/.hotspotshade-snapshot.*) exit 1 ;;
esac
exec "$real_rm" "\$@"
EOF
chmod +x "$tmp/claimrm-bin/rm"
if PATH="$tmp/claimrm-bin:$PATH" "$helper" --repo "$fixture" \
  --manifest "$tmp/manifest.txt" --output "$tmp/claimrm/a.tar.gz" \
  > "$tmp/claimrm.log" 2>&1; then
  fail "A build with an unremovable temporary file reported success."
fi
grep -q 'remove the temporary output file' "$tmp/claimrm.log" ||
  fail "An unremovable temporary output file was silent."
grep -Fq '.hotspotshade-snapshot.' "$tmp/claimrm.log" ||
  fail "The unremovable temporary output file was not named."
[ ! -e "$tmp/claimrm/a.tar.gz" ] ||
  fail "A failed build left an output that looks complete."
"$real_rm" -f "$tmp/claimrm"/.hotspotshade-snapshot.*
pass

# A failed final success write after a build claims its outputs must remove the
# whole set this run created, not leave a partial set that looks complete.
mkdir -p "$tmp/claimout" "$tmp/claimout-bin"
cat > "$tmp/claimout-bin/cat" <<EOF
#!/bin/sh
exec "$real_cat" "\$@" >&-
EOF
chmod +x "$tmp/claimout-bin/cat"
if PATH="$tmp/claimout-bin:$PATH" "$helper" --repo "$fixture" \
  --manifest "$tmp/manifest.txt" --output "$tmp/claimout/a.tar.gz" \
  > "$tmp/claimout.log" 2>&1; then
  fail "A build with a failed final success write reported success."
fi
[ -z "$(find "$tmp/claimout" -mindepth 1 -print -quit)" ] ||
  fail "A failed build left a partial output set after a failed success write."
pass

# A partial sidecar set is refused rather than silently ignored.
mkdir -p "$tmp/bad/partial"
cp "$out" "$tmp/bad/partial/source.tar.gz"
cp "$out.sha256" "$tmp/bad/partial/source.tar.gz.sha256"
if "$helper" --verify "$tmp/bad/partial/source.tar.gz" --expect-sha256 "$sum" \
  > "$tmp/bad/partial.log" 2>&1; then
  fail "Verification accepted a partial sidecar set."
fi
grep -q 'Incomplete sidecar set' "$tmp/bad/partial.log" ||
  fail "The partial sidecar set failed for the wrong reason."
pass

# ---------------------------------------------------------------------------
# A manifest path that is unsafe or private must fail closed. No archive may
# appear for the rejected input.
# ---------------------------------------------------------------------------
expect_build_fail() {
  label=$1
  manifest=$2
  pattern=${3:-}
  rejected=$tmp/reject/$label.tar.gz
  mkdir -p "$tmp/reject"
  rm -f "$rejected" "$rejected.sha256" "$rejected.files.sha256" \
    "$rejected.manifest.sha256" "$rejected.provenance"
  if "$helper" --repo "$fixture" --manifest "$manifest" \
    --output "$rejected" > "$tmp/reject-$label.log" 2>&1; then
    fail "The helper accepted an unsafe input ($label)."
  fi
  if [ -e "$rejected" ] || [ -e "$rejected.sha256" ] ||
     [ -e "$rejected.files.sha256" ] ||
     [ -e "$rejected.manifest.sha256" ] ||
     [ -e "$rejected.provenance" ]; then
    fail "The helper left output for a rejected input ($label)."
  fi
  if [ -n "$pattern" ] && ! grep -q "$pattern" "$tmp/reject-$label.log"; then
    cat "$tmp/reject-$label.log" >&2
    fail "The helper gave the wrong error for $label."
  fi
  pass
}

path_reject() {
  label=$1
  path=$2
  pattern=${3:-}
  printf '%064d  %s\n' 0 "$path" > "$tmp/reject-$label.txt"
  expect_build_fail "$label" "$tmp/reject-$label.txt" "$pattern"
}

path_reject_optin() {
  label=$1
  path=$2
  pattern=${3:-}
  printf '+ %064d  %s\n' 0 "$path" > "$tmp/reject-$label.txt"
  expect_build_fail "$label" "$tmp/reject-$label.txt" "$pattern"
}

path_reject absolute '/etc/passwd' 'absolute path'
path_reject parent '../outside.txt' 'parent component'
path_reject nested-parent 'rust/../../outside.txt' 'parent component'
path_reject backslash 'rust\src\main.rs' 'backslash'
path_reject git-internal '.git/refs/t3' 'outside the source allowlist'
path_reject ignored-build 'rust/target/debug/app' 'excluded'
path_reject node-modules 'linux/node_modules/pkg/index.js' 'excluded'
path_reject probe-record 'probes/trace.txt' 'outside the source allowlist'
path_reject private-key 'rust/fixture.key' 'excluded'
path_reject certificate 'rust/certificate.pem' 'excluded'
path_reject packet-capture 'rust/capture.pcap' 'excluded'
path_reject env-file 'rust/.env' 'excluded'
path_reject npm-config 'linux/.npmrc' 'excluded'
path_reject machine-config 'linux/local.properties' 'excluded'
path_reject credential-dir 'rust/credentials/token.txt' 'excluded'
path_reject_optin symlink-outside 'gui_assets/outside-link' 'not a regular file'
path_reject_optin symlink-inside 'gui_assets/inside-link' 'not a regular file'
path_reject_optin missing-file 'rust/src/missing.rs' 'missing'
path_reject_optin directory 'rust/src' 'not a regular file'
path_reject root-only 'rust' 'below an allowlisted root'
path_reject windows-colon 'rust/src/bad:name.rs' 'colon'
path_reject windows-reserved 'rust/src/CON.txt' 'reserved Windows name'
path_reject windows-reserved-lpt 'rust/src/LPT1.rs' 'reserved Windows name'
path_reject windows-reserved-com 'rust/src/com9' 'reserved Windows name'
path_reject windows-reserved-conin 'rust/src/CONIN$' 'reserved Windows name'
path_reject windows-reserved-conout 'rust/src/conout$.txt' 'reserved Windows name'
path_reject windows-reserved-clock 'rust/src/CLOCK$' 'reserved Windows name'
path_reject windows-reserved-dir 'rust/aux/file.rs' 'reserved Windows name'
path_reject glob 'rust/src/*.rs' 'Windows rejects'
path_reject non-ascii "rust/src/naïve.rs" 'printable ASCII'
path_reject ds-store 'gui_assets/.DS_Store' 'excluded'
path_reject ds-store-lower 'assets/.ds_store' 'excluded'
path_reject env-suffix 'rust/prod.env' 'excluded'
path_reject token-suffix 'rust/session.token' 'excluded'
path_reject keychain-db 'rust/login.keychain-db' 'excluded'
path_reject google-service 'rust/GoogleService-Info.plist' 'excluded'
path_reject ruff-cache 'rust/.ruff_cache/data.json' 'excluded'
path_reject turbo-cache 'linux/.turbo/state' 'excluded'
path_reject p7b-bundle 'rust/deploy.p7b' 'excluded'
path_reject pkcs12-file 'rust/client.pkcs12' 'excluded'
path_reject authinfo-file 'rust/.authinfo' 'excluded'
path_reject envrc-file 'rust/.envrc' 'excluded'
path_reject psafe3-file 'rust/vault.psafe3' 'excluded'
path_reject_optin env-example-not-denied 'rust/.env.example' 'missing'

# Names that look close to a reserved device name stay allowed.
printf 'console\n' > "$fixture/rust/src/console.rs"
printf 'com0\n' > "$fixture/rust/src/com0.rs"
printf 'auxiliary\n' > "$fixture/rust/src/auxiliary.rs"
{
  optin rust/src/console.rs
  optin rust/src/com0.rs
  optin rust/src/auxiliary.rs
} > "$tmp/accept-reserved-lookalikes.txt"
"$helper" --repo "$fixture" --manifest "$tmp/accept-reserved-lookalikes.txt" \
  --output "$tmp/out/reserved-lookalikes.tar.gz" \
  > "$tmp/reserved-lookalikes.log" 2>&1 || {
  cat "$tmp/reserved-lookalikes.log" >&2
  fail "A name that only looks reserved was rejected."
}
rm -f "$fixture/rust/src/console.rs" "$fixture/rust/src/com0.rs" \
  "$fixture/rust/src/auxiliary.rs"
pass

# An ignored file that the name rules do not reject fails on the ignore rule.
printf 'ignored\n' > "$fixture/rust/src/ignored.rs"
optin rust/src/ignored.rs > "$tmp/reject-ignored.txt"
expect_build_fail ignored-rule "$tmp/reject-ignored.txt" 'ignored file'
pass

# An untracked file needs an explicit opt-in.
line "$untracked" > "$tmp/reject-untracked.txt"
expect_build_fail untracked-no-optin "$tmp/reject-untracked.txt" \
  'without a leading'
pass

# A modified tracked file needs an explicit opt-in, and the opt-in succeeds.
printf 'changed\n' >> "$fixture/rust/src/main.rs"
line rust/src/main.rs > "$tmp/reject-modified.txt"
expect_build_fail modified-no-optin "$tmp/reject-modified.txt" \
  'without a leading'
optin rust/src/main.rs > "$tmp/accept-modified.txt"
"$helper" --repo "$fixture" --manifest "$tmp/accept-modified.txt" \
  --output "$tmp/out/modified.tar.gz" > "$tmp/modified.log" 2>&1 || {
  cat "$tmp/modified.log" >&2
  fail "An opted-in modified tracked file did not build."
}
grep -q '^Tracked modified (opted in): 1$' \
  "$tmp/out/modified.tar.gz.provenance" ||
  fail "The provenance record does not mark the opted-in modified file."
git -C "$fixture" checkout -- rust/src/main.rs
pass

# A pinned digest that does not match the content fails closed.
printf '%064d  rust/src/lib.rs\n' 0 > "$tmp/reject-digest.txt"
expect_build_fail digest-mismatch "$tmp/reject-digest.txt" \
  'Pinned digest mismatch'
pass

# A case-fold collision is rejected before any file is read.
{
  printf '%s  rust/src/lib.rs\n' "$(pin rust/src/lib.rs)"
  printf '%s  rust/src/Lib.rs\n' "$(pin rust/src/lib.rs)"
} > "$tmp/reject-case.txt"
expect_build_fail case-collision "$tmp/reject-case.txt" 'case-fold'
# A punctuation path between the two case variants must not hide the collision.
{
  printf '%064d  rust/src/A\n' 0
  printf '%064d  rust/src/_\n' 0
  printf '%064d  rust/src/a\n' 0
} > "$tmp/reject-case-punct.txt"
expect_build_fail case-collision-punct "$tmp/reject-case-punct.txt" 'case-fold'
# A case-folded ancestor must be rejected even when the spellings differ.
{
  printf '%064d  rust/src/A\n' 0
  printf '%064d  rust/src/a/b\n' 0
} > "$tmp/reject-case-ancestor.txt"
expect_build_fail case-ancestor "$tmp/reject-case-ancestor.txt" \
  'directory prefix'
# An unrelated lexical entry between a path and its child must not hide it.
{
  printf '%064d  rust/src/b\n' 0
  printf '%064d  rust/src/b-c\n' 0
  printf '%064d  rust/src/b/c\n' 0
} > "$tmp/reject-prefix-nonadjacent.txt"
expect_build_fail prefix-nonadjacent "$tmp/reject-prefix-nonadjacent.txt" \
  'directory prefix'
pass

# A hardlinked source is rejected.
printf 'hard\n' > "$fixture/rust/src/hard.rs"
ln "$fixture/rust/src/hard.rs" "$fixture/rust/src/hard2.rs"
optin rust/src/hard.rs > "$tmp/reject-hard.txt"
expect_build_fail hardlink "$tmp/reject-hard.txt" 'hard links'
rm -f "$fixture/rust/src/hard.rs" "$fixture/rust/src/hard2.rs"
pass

# A source swapped for a symlink to an external fake secret must not be
# archived. Both the original digest and the secret digest are tried.
printf 'TOPSECRET-SWAP\n' > "$tmp/fake-secret.txt"
swap_digest=$(pin rust/src/swap.rs)
secret_digest=$(sha256_file "$tmp/fake-secret.txt")
rm -f "$fixture/rust/src/swap.rs"
ln -s "$tmp/fake-secret.txt" "$fixture/rust/src/swap.rs"
printf '+ %s  rust/src/swap.rs\n' "$swap_digest" > "$tmp/reject-swap.txt"
expect_build_fail swapped-symlink "$tmp/reject-swap.txt" 'not a regular file'
printf '+ %s  rust/src/swap.rs\n' "$secret_digest" > "$tmp/reject-swap2.txt"
expect_build_fail swapped-symlink-secret "$tmp/reject-swap2.txt" \
  'not a regular file'
if grep -R 'TOPSECRET-SWAP' "$tmp/reject" >/dev/null 2>&1; then
  fail "A swapped source archived the external fake secret."
fi
rm -f "$fixture/rust/src/swap.rs"
git -C "$fixture" checkout -- rust/src/swap.rs
pass

# A regular source whose content is swapped for the external fake secret is
# rejected by the pinned digest, even with an explicit opt-in.
printf 'TOPSECRET-SWAP\n' > "$fixture/rust/src/swap.rs"
printf '+ %s  rust/src/swap.rs\n' "$swap_digest" > "$tmp/reject-swap3.txt"
expect_build_fail swapped-content "$tmp/reject-swap3.txt" \
  'Pinned digest mismatch'
if grep -R 'TOPSECRET-SWAP' "$tmp/reject" >/dev/null 2>&1; then
  fail "A swapped source archived the external fake secret."
fi
git -C "$fixture" checkout -- rust/src/swap.rs
pass

# A manifest that is a symlink or a hard link is rejected.
ln -s "$tmp/manifest.txt" "$tmp/manifest-symlink.txt"
expect_build_fail manifest-symlink "$tmp/manifest-symlink.txt" \
  'Not a regular manifest file'
ln "$tmp/manifest.txt" "$tmp/manifest-hard.txt"
expect_build_fail manifest-hardlink "$tmp/manifest-hard.txt" 'hard links'
rm -f "$tmp/manifest-symlink.txt" "$tmp/manifest-hard.txt"
pass

# An existing output is not replaced without --force, and a symlink output is
# never followed or replaced, even with --force.
if "$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" \
  --output "$out" > "$tmp/clobber.log" 2>&1; then
  fail "The helper replaced an existing archive without --force."
fi
pass
printf 'victim\n' > "$tmp/out/victim.txt"
ln -s victim.txt "$tmp/out/link.tar.gz"
if "$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" \
  --output "$tmp/out/link.tar.gz" > "$tmp/link-no-force.log" 2>&1; then
  fail "The helper wrote through a symlink output."
fi
if "$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" \
  --output "$tmp/out/link.tar.gz" --force > "$tmp/link-force.log" 2>&1; then
  fail "The helper replaced a symlink output with --force."
fi
[ "$(cat "$tmp/out/victim.txt")" = "victim" ] ||
  fail "A symlink output wrote through to its target."
pass
"$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" --output "$out" \
  --force > "$tmp/force.log" 2>&1 || {
  cat "$tmp/force.log" >&2
  fail "The helper did not replace an existing regular archive with --force."
}
pass

# ---------------------------------------------------------------------------
# --list prints tracked candidates with digests only. The reviewer must add
# untracked source before a build.
# ---------------------------------------------------------------------------
"$helper" --repo "$fixture" --list > "$tmp/candidate.txt" 2> "$tmp/list.log" ||
  fail "The helper --list mode failed."
grep -Eq "^[0-9a-f]{64}  rust/src/lib\.rs$" "$tmp/candidate.txt" ||
  fail "The candidate list omits a tracked file or its digest."
grep -Eq "^[0-9a-f]{64}  rust/Cargo\.lock$" "$tmp/candidate.txt" ||
  fail "The candidate list omits a lockfile."
if grep -q 'extra source 01.js' "$tmp/candidate.txt"; then
  fail "The candidate list silently included an untracked file."
fi
if grep -q 'target/debug' "$tmp/candidate.txt"; then
  fail "The candidate list included a build output."
fi
if grep -q 'outside-link' "$tmp/candidate.txt"; then
  fail "The candidate list included a symlink."
fi
{
  cat "$tmp/candidate.txt"
  optin "$untracked"
} > "$tmp/candidate-with-untracked.txt"
"$helper" --repo "$fixture" --manifest "$tmp/candidate-with-untracked.txt" \
  --output "$tmp/out/candidate.tar.gz" > "$tmp/candidate-build.log" 2>&1 || {
  cat "$tmp/candidate-build.log" >&2
  fail "A reviewed candidate manifest with one added untracked file did not build."
}
pass

# A modified tracked file is marked with "+ " in the candidate list.
printf 'changed\n' >> "$fixture/rust/src/main.rs"
"$helper" --repo "$fixture" --list > "$tmp/candidate-modified.txt" 2>/dev/null
grep -Eq "^\+ [0-9a-f]{64}  rust/src/main\.rs$" "$tmp/candidate-modified.txt" ||
  fail "The candidate list did not mark a modified tracked file."
git -C "$fixture" checkout -- rust/src/main.rs
pass

# ---------------------------------------------------------------------------
# Archive header validation. Each fixture is a self-consistent archive set:
# the archive digest and provenance match the malicious bytes, so the failure
# comes from the header or path rule, not from a stale sidecar.
# ---------------------------------------------------------------------------
gzip -dc "$out" > "$tmp/base.tar"

rechecksum() {
  raw=$1
  local header_sum
  header_sum=$(dd if="$raw" bs=1 count=512 2>/dev/null | od -An -v -tu1 |
    awk '{ for (i = 1; i <= NF; i++) { n++; if (n >= 149 && n <= 156) s += 32; else s += $i } }
      END { printf "%06o", s }')
  printf '%s\000 ' "$header_sum" |
    dd of="$raw" bs=1 seek=148 conv=notrunc 2>/dev/null
}

patch_bytes() {
  local raw=$1 offset=$2 fmt=$3
  printf "$fmt" | dd of="$raw" bs=1 seek="$offset" conv=notrunc 2>/dev/null
}

write_sidecars() {
  local archive=$1 files=$2
  local archive_sum manifest_sum
  archive_sum=$(sha256_file "$archive")
  manifest_sum=$(sha256_file "$tmp/manifest.txt")
  printf '%s  %s\n' "$archive_sum" "$(basename "$archive")" > "$archive.sha256"
  cp "$files" "$archive.files.sha256"
  printf '%s  manifest.txt\n' "$manifest_sum" > "$archive.manifest.sha256"
  {
    printf 'HotspotShade source snapshot record\n'
    printf 'Manifest: manifest.txt\n'
    printf 'Manifest SHA-256: %s\n' "$manifest_sum"
    printf 'Archive SHA-256: %s\n' "$archive_sum"
  } > "$archive.provenance"
}

make_bad_archive() {
  local label=$1 patch=$2
  local dir=$tmp/bad/$label
  mkdir -p "$dir"
  cp "$tmp/base.tar" "$dir/raw.tar"
  "$patch" "$dir/raw.tar"
  gzip -n -9 -c "$dir/raw.tar" > "$dir/a.tar.gz"
  write_sidecars "$dir/a.tar.gz" "$out.files.sha256"
}

expect_verify_fail() {
  local label=$1 pattern=$2
  local archive=$tmp/bad/$label/a.tar.gz
  local archive_sum
  archive_sum=$(sha256_file "$archive")
  if "$helper" --verify "$archive" --expect-sha256 "$archive_sum" \
    > "$tmp/bad-$label.log" 2>&1; then
    fail "Verification accepted a malicious archive ($label)."
  fi
  if ! grep -q "$pattern" "$tmp/bad-$label.log"; then
    cat "$tmp/bad-$label.log" >&2
    fail "The malicious archive failed for the wrong reason ($label)."
  fi
  pass
}

p_mode_777() { patch_bytes "$1" 100 '0000777\000'; rechecksum "$1"; }
p_mode_4755() { patch_bytes "$1" 100 '0004755\000'; rechecksum "$1"; }
p_uid() { patch_bytes "$1" 108 '0001750\000'; rechecksum "$1"; }
p_gid() { patch_bytes "$1" 116 '0001750\000'; rechecksum "$1"; }
p_pax_x() { patch_bytes "$1" 156 'x'; rechecksum "$1"; }
p_pax_g() { patch_bytes "$1" 156 'g'; rechecksum "$1"; }
p_gnu_L() { patch_bytes "$1" 156 'L'; rechecksum "$1"; }
p_gnu_K() { patch_bytes "$1" 156 'K'; rechecksum "$1"; }
p_dir() { patch_bytes "$1" 156 '5'; rechecksum "$1"; }
p_symlink() { patch_bytes "$1" 156 '2'; rechecksum "$1"; }
p_hardlink() { patch_bytes "$1" 156 '1'; rechecksum "$1"; }
p_magic() { patch_bytes "$1" 257 'ustar '; rechecksum "$1"; }
p_version() { patch_bytes "$1" 263 '99'; rechecksum "$1"; }
p_checksum() { patch_bytes "$1" 148 '0000000\000'; }
p_truncate() {
  # One header block with no data and no end marker. This is deterministic
  # whether the tar writer pads with two or twenty zero blocks.
  head -c 512 "$1" > "$1.t"
  mv "$1.t" "$1"
}
p_after_end() {
  dd if=/dev/zero bs=512 count=1 2>/dev/null | tr '\000' 'A' >> "$1"
}
p_nonascii() { patch_bytes "$1" 0 '\351'; rechecksum "$1"; }

make_bad_archive mode-777 p_mode_777
expect_verify_fail mode-777 'unsafe file mode'
make_bad_archive mode-4755 p_mode_4755
expect_verify_fail mode-4755 'unsafe file mode'
make_bad_archive uid p_uid
expect_verify_fail uid 'untrusted uid'
make_bad_archive gid p_gid
expect_verify_fail gid 'untrusted gid'
make_bad_archive pax-x p_pax_x
expect_verify_fail pax-x 'pax extended header'
make_bad_archive pax-g p_pax_g
expect_verify_fail pax-g 'pax extended header'
make_bad_archive gnu-L p_gnu_L
expect_verify_fail gnu-L 'GNU long-name header'
make_bad_archive gnu-K p_gnu_K
expect_verify_fail gnu-K 'GNU long-name header'
make_bad_archive dir p_dir
expect_verify_fail dir 'non-regular entry type'
make_bad_archive symlink p_symlink
expect_verify_fail symlink 'non-regular entry type'
make_bad_archive hardlink p_hardlink
expect_verify_fail hardlink 'non-regular entry type'
make_bad_archive magic p_magic
expect_verify_fail magic 'not a POSIX ustar header'
make_bad_archive version p_version
expect_verify_fail version 'unsupported ustar version'
make_bad_archive checksum p_checksum
expect_verify_fail checksum 'header checksum mismatch'
make_bad_archive truncated p_truncate
expect_verify_fail truncated 'truncated'
make_bad_archive after-end p_after_end
expect_verify_fail after-end 'data after the end-of-archive marker'
make_bad_archive nonascii p_nonascii
expect_verify_fail nonascii 'non-ASCII or control byte'

# Write one minimal ustar header to a file. The header uses canonical octal
# fields and the standard checksum shape.
write_ustar_header() {
  local header=$1 entry_name=$2 checksum=$tmp/ustar-checksum
  : > "$header"
  put_field() {
    local text=$1 width=$2 pad
    printf '%s' "$text" >> "$header"
    pad=$((width - ${#text}))
    if [ "$pad" -gt 0 ]; then
      dd if=/dev/zero bs=1 count="$pad" >> "$header" 2>/dev/null
    fi
  }
  put_field "$entry_name" 100
  put_field '0000644' 8
  put_field '0000000' 8
  put_field '0000000' 8
  put_field '00000000001' 12
  put_field '07033241600' 12
  put_field '        ' 8
  put_field '0' 1
  put_field '' 100
  put_field 'ustar' 6
  put_field '00' 2
  put_field '' 32
  put_field '' 32
  put_field '0000000' 8
  put_field '0000000' 8
  put_field '' 155
  put_field '' 12
  local header_sum
  header_sum=$(od -An -v -tu1 "$header" |
    awk '{ for (i = 1; i <= NF; i++) total += $i } END { print total }')
  printf '%06o' "$header_sum" > "$checksum"
  printf '\000 ' >> "$checksum"
  dd if="$checksum" of="$header" bs=1 seek=148 conv=notrunc 2>/dev/null
}

# Append one header and its one-byte payload to an archive.
append_ustar_entry() {
  local out=$1 entry_name=$2 header=$tmp/ustar-header
  write_ustar_header "$header" "$entry_name"
  cat "$header" >> "$out"
  printf 'x' >> "$out"
  dd if=/dev/zero bs=1 count=511 >> "$out" 2>/dev/null
}

# Build an archive from one or more entry names, then the end markers.
make_ustar_with_names() {
  local out=$1
  shift
  : > "$out"
  for entry_name in "$@"; do
    append_ustar_entry "$out" "$entry_name"
  done
  dd if=/dev/zero bs=1 count=1024 >> "$out" 2>/dev/null
}

# A minimal ustar archive with one chosen name.
make_ustar_with_name() {
  local out=$1 entry_name=$2
  make_ustar_with_names "$out" "$entry_name"
}

bad_single() {
  local label=$1 entry_name=$2 pattern=$3 patch=${4:-}
  local dir=$tmp/bad/$label
  mkdir -p "$dir"
  make_ustar_with_name "$dir/raw.tar" "$entry_name" ||
    fail "Could not build the $label fixture."
  if [ -n "$patch" ]; then
    "$patch" "$dir/raw.tar"
  fi
  gzip -n -9 -c "$dir/raw.tar" > "$dir/a.tar.gz"
  printf '%064d  gui_assets/victim\n' 0 > "$dir/files.sha256"
  write_sidecars "$dir/a.tar.gz" "$dir/files.sha256"
  expect_verify_fail "$label" "$pattern"
}

bad_multi() {
  local label=$1 pattern=$2
  shift 2
  local dir=$tmp/bad/$label
  mkdir -p "$dir"
  make_ustar_with_names "$dir/raw.tar" "$@" ||
    fail "Could not build the $label fixture."
  gzip -n -9 -c "$dir/raw.tar" > "$dir/a.tar.gz"
  : > "$dir/files.sha256"
  write_sidecars "$dir/a.tar.gz" "$dir/files.sha256"
  expect_verify_fail "$label" "$pattern"
}

bad_single absolute '/victim' 'absolute path'
bad_single traversal '../victim' 'parent component'
bad_single symlink-entry 'gui_assets/link' 'non-regular entry type' p_symlink
bad_single nonascii-entry 'gui_assets/victim' 'non-ASCII or control byte' p_nonascii
bad_single root-only 'rust' 'below an allowlisted root'

# Canonical numeric fields. bsdtar reads a size field that starts with NUL as
# zero while GNU tar and awk read the octal value. Accepting that field would
# desynchronize header validation from extraction, so it must fail closed.
p_size_leading_nul() {
  { printf '\0'; printf '0000000006 '; } |
    dd of="$1" bs=1 seek=124 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_size_leading_space() {
  { printf ' '; printf '0000000006 '; } |
    dd of="$1" bs=1 seek=124 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_mode_leading_space() {
  { printf ' '; printf '000644'; printf '\0'; } |
    dd of="$1" bs=1 seek=100 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_mode_digit_after_padding() {
  { printf '00064'; printf '\0'; printf '4 '; } |
    dd of="$1" bs=1 seek=100 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_checksum_leading_space() {
  printf ' 011730 ' |
    dd of="$1" bs=1 seek=148 conv=notrunc 2>/dev/null
}

make_bad_archive size-leading-nul p_size_leading_nul
expect_verify_fail size-leading-nul 'malformed size field'
make_bad_archive size-leading-space p_size_leading_space
expect_verify_fail size-leading-space 'malformed size field'
make_bad_archive mode-leading-space p_mode_leading_space
expect_verify_fail mode-leading-space 'malformed mode field'
make_bad_archive mode-digit-after-padding p_mode_digit_after_padding
expect_verify_fail mode-digit-after-padding 'malformed mode field'
make_bad_archive checksum-leading-space p_checksum_leading_space
expect_verify_fail checksum-leading-space 'malformed header checksum field'

# The remaining numeric fields are validated too: modification time and the
# device numbers. A field that starts with NUL or space, or that has a digit
# after padding, must fail closed.
p_mtime_leading_nul() {
  { printf '\0'; printf '0703324160 '; } |
    dd of="$1" bs=1 seek=136 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_mtime_leading_space() {
  { printf ' '; printf '0703324160 '; } |
    dd of="$1" bs=1 seek=136 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_mtime_digit_after_padding() {
  { printf '0703324'; printf '\0'; printf '000 '; } |
    dd of="$1" bs=1 seek=136 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_devmajor_leading_space() {
  { printf ' '; printf '000000 '; } |
    dd of="$1" bs=1 seek=329 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_devmajor_nonzero() {
  { printf '000100 '; printf '\0'; } |
    dd of="$1" bs=1 seek=329 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_devminor_nonzero() {
  { printf '000001 '; printf '\0'; } |
    dd of="$1" bs=1 seek=337 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_devminor_nonoctal() {
  { printf '00000'; printf '9'; printf ' '; printf '\0'; } |
    dd of="$1" bs=1 seek=337 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_devminor_digit_after_padding() {
  { printf '0000'; printf '\0'; printf '00 '; } |
    dd of="$1" bs=1 seek=337 conv=notrunc 2>/dev/null
  rechecksum "$1"
}

make_bad_archive mtime-leading-nul p_mtime_leading_nul
expect_verify_fail mtime-leading-nul 'malformed mtime field'
make_bad_archive mtime-leading-space p_mtime_leading_space
expect_verify_fail mtime-leading-space 'malformed mtime field'
make_bad_archive mtime-digit-after-padding p_mtime_digit_after_padding
expect_verify_fail mtime-digit-after-padding 'malformed mtime field'
make_bad_archive devmajor-leading-space p_devmajor_leading_space
expect_verify_fail devmajor-leading-space 'malformed devmajor field'
make_bad_archive devmajor-nonzero p_devmajor_nonzero
expect_verify_fail devmajor-nonzero 'unexpected device major number'
make_bad_archive devminor-nonzero p_devminor_nonzero
expect_verify_fail devminor-nonzero 'unexpected device minor number'
make_bad_archive devminor-nonoctal p_devminor_nonoctal
expect_verify_fail devminor-nonoctal 'malformed devminor field'
make_bad_archive devminor-digit-after-padding p_devminor_digit_after_padding
expect_verify_fail devminor-digit-after-padding 'malformed devminor field'

# The remaining header fields are pinned too. The build writes one fixed
# modification time, an empty link name, empty owner names, and zero padding.
# A different value is a second reading of the archive that another tar could
# interpret differently, so it fails closed.
p_mtime_other() {
  printf '00000000001\000' | dd of="$1" bs=1 seek=136 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_linkname_set() {
  printf 'x' | dd of="$1" bs=1 seek=157 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_uname_control() {
  printf '\001' | dd of="$1" bs=1 seek=265 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_gname_control() {
  printf '\001' | dd of="$1" bs=1 seek=297 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
p_padding_set() {
  printf 'x' | dd of="$1" bs=1 seek=505 conv=notrunc 2>/dev/null
  rechecksum "$1"
}
make_bad_archive mtime-other p_mtime_other
expect_verify_fail mtime-other 'unexpected modification time'
make_bad_archive linkname-set p_linkname_set
expect_verify_fail linkname-set 'link name field is not empty'
make_bad_archive uname-control p_uname_control
expect_verify_fail uname-control 'owner name'
make_bad_archive gname-control p_gname_control
expect_verify_fail gname-control 'owner name'
make_bad_archive padding-set p_padding_set
expect_verify_fail padding-set 'nonzero padding'

# An all-NUL device number field means zero and is accepted. GNU tar and
# bsdtar both may write it, so the canonical rule must not reject it.
mkdir -p "$tmp/good/dev-null"
cp "$tmp/base.tar" "$tmp/good/dev-null/raw.tar"
dd if=/dev/zero of="$tmp/good/dev-null/raw.tar" bs=1 seek=329 count=8 \
  conv=notrunc 2>/dev/null
dd if=/dev/zero of="$tmp/good/dev-null/raw.tar" bs=1 seek=337 count=8 \
  conv=notrunc 2>/dev/null
rechecksum "$tmp/good/dev-null/raw.tar"
gzip -n -9 -c "$tmp/good/dev-null/raw.tar" > "$tmp/good/dev-null/a.tar.gz"
"$helper" --verify "$tmp/good/dev-null/a.tar.gz" \
  --expect-sha256 "$(sha256_file "$tmp/good/dev-null/a.tar.gz")" \
  > "$tmp/good-dev-null.log" 2>&1 || {
  cat "$tmp/good-dev-null.log" >&2
  fail "Verification rejected all-NUL device number fields."
}
pass

# The full desync from the review: a first header whose size field starts with
# NUL. bsdtar reads size 0 and treats the next block as a header for a file
# with mode 04777 and uid 1750, while GNU tar and awk read 1536 and skip the
# same blocks. The validator must reject the first header before either
# reading can matter.
mkdir -p "$tmp/bad/desync"
write_ustar_header "$tmp/bad/desync/first" 'gui_assets/victim'
{ printf '\0'; printf '0000003000'; printf '\0'; } |
  dd of="$tmp/bad/desync/first" bs=1 seek=124 conv=notrunc 2>/dev/null
rechecksum "$tmp/bad/desync/first"
write_ustar_header "$tmp/bad/desync/evil" 'gui_assets/evil'
patch_bytes "$tmp/bad/desync/evil" 100 '0004777\000'
patch_bytes "$tmp/bad/desync/evil" 108 '0001750\000'
rechecksum "$tmp/bad/desync/evil"
cat "$tmp/bad/desync/first" "$tmp/bad/desync/evil" > "$tmp/bad/desync/raw.tar"
printf 'x' >> "$tmp/bad/desync/raw.tar"
dd if=/dev/zero bs=1 count=511 >> "$tmp/bad/desync/raw.tar" 2>/dev/null
dd if=/dev/zero bs=1 count=512 >> "$tmp/bad/desync/raw.tar" 2>/dev/null
dd if=/dev/zero bs=1 count=1024 >> "$tmp/bad/desync/raw.tar" 2>/dev/null
gzip -n -9 -c "$tmp/bad/desync/raw.tar" > "$tmp/bad/desync/a.tar.gz"
: > "$tmp/bad/desync/files.sha256"
write_sidecars "$tmp/bad/desync/a.tar.gz" "$tmp/bad/desync/files.sha256"
expect_verify_fail desync 'malformed size field'

# A case-folded ancestor and a nonadjacent directory prefix must both fail,
# whichever tar reads the archive.
bad_multi casefold-ancestor 'case-fold directory prefix' \
  'gui_assets/A' 'gui_assets/a/b'
bad_multi nonadjacent-prefix 'case-fold directory prefix' \
  'gui_assets/b' 'gui_assets/b-c' 'gui_assets/b/c'

# Gzip validation must not claim to prove a single member. Trailing non-gzip
# bytes are still rejected, with a truthful message.
mkdir -p "$tmp/bad/gzip-garbage"
gzip -n -9 -c "$tmp/base.tar" > "$tmp/bad/gzip-garbage/a.tar.gz"
printf 'not a gzip member' >> "$tmp/bad/gzip-garbage/a.tar.gz"
write_sidecars "$tmp/bad/gzip-garbage/a.tar.gz" "$out.files.sha256"
expect_verify_fail gzip-garbage 'trailing garbage'

# A hashing tool that fails is reported as a hashing failure, not as a digest
# mismatch with an empty digest.
hash_tool=
real_hash_tool=
for candidate in sha256sum shasum openssl; do
  if command -v "$candidate" >/dev/null 2>&1; then
    hash_tool=$candidate
    real_hash_tool=$(command -v "$candidate")
    break
  fi
done
[ -n "$hash_tool" ] || fail "No SHA-256 tool is available."
mkdir -p "$tmp/fakebin"
cat > "$tmp/fakebin/$hash_tool" <<EOF
#!/bin/sh
for arg in "\$@"; do
  case "\$arg" in
    *cannot-hash*) exit 1 ;;
  esac
done
exec "$real_hash_tool" "\$@"
EOF
chmod +x "$tmp/fakebin/$hash_tool"
mkdir -p "$tmp/bad/cannot-hash"
make_ustar_with_name "$tmp/bad/cannot-hash/raw.tar" 'gui_assets/cannot-hash'
gzip -n -9 -c "$tmp/bad/cannot-hash/raw.tar" \
  > "$tmp/bad/cannot-hash/a.tar.gz"
printf '%064d  gui_assets/cannot-hash\n' 0 \
  > "$tmp/bad/cannot-hash/files.sha256"
write_sidecars "$tmp/bad/cannot-hash/a.tar.gz" \
  "$tmp/bad/cannot-hash/files.sha256"
cannot_hash_sum=$(sha256_file "$tmp/bad/cannot-hash/a.tar.gz")
if PATH="$tmp/fakebin:$PATH" "$helper" --verify \
  "$tmp/bad/cannot-hash/a.tar.gz" --expect-sha256 "$cannot_hash_sum" \
  > "$tmp/cannot-hash.log" 2>&1; then
  fail "Verification accepted an empty digest from a failing hash tool."
fi
grep -q 'Cannot hash' "$tmp/cannot-hash.log" ||
  fail "A failing hash tool was reported as a digest mismatch."
pass

# A failed --extract-to must not leave a partial destination. The fake ln
# fails only for one destination file and delegates every other link.
mkdir -p "$tmp/fakepartial"
cat > "$tmp/fakepartial/ln" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/partial/"*'/rust/src/lib.rs' | \
  "$tmp/partial-fail/"*'/rust/src/lib.rs' | \
  "$tmp/partial-find/"*'/rust/src/lib.rs' | \
  "$tmp/preflight/"*'/rust/src/lib.rs')
    : > "$tmp/fakepartial/hit"
    exit 1 ;;
esac
exec /bin/ln "\$@"
EOF
chmod +x "$tmp/fakepartial/ln"
mkdir -p "$tmp/partial"
if PATH="$tmp/fakepartial:$PATH" "$helper" --verify "$out" \
  --expect-sha256 "$sum" --extract-to "$tmp/partial/created" \
  > "$tmp/partial-created.log" 2>&1; then
  fail "A failed extraction reported success."
fi
[ -f "$tmp/fakepartial/hit" ] ||
  fail "The partial extraction publication failure was not injected."
[ ! -e "$tmp/partial/created" ] ||
  fail "A failed extraction left the destination directory it created."
pass
mkdir -p "$tmp/partial/preexisting"
if PATH="$tmp/fakepartial:$PATH" "$helper" --verify "$out" \
  --expect-sha256 "$sum" --extract-to "$tmp/partial/preexisting" \
  > "$tmp/partial-preexisting.log" 2>&1; then
  fail "A failed extraction reported success."
fi
[ -d "$tmp/partial/preexisting" ] ||
  fail "A failed extraction removed a destination the caller created."
if [ -n "$(find "$tmp/partial/preexisting" -mindepth 1 -print -quit)" ]; then
  fail "A failed extraction left files in a preexisting destination."
fi
pass

# A cleanup failure must be reported with the residual path and a non-zero
# status. It must never look like a clean failure.
mkdir -p "$tmp/failrm"
cat > "$tmp/failrm/rm" <<EOF
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/partial-fail/created") exit 1 ;;
esac
exec "$real_rm" "\$@"
EOF
chmod +x "$tmp/failrm/rm"
mkdir -p "$tmp/partial-fail"
if PATH="$tmp/failrm:$tmp/fakepartial:$PATH" "$helper" --verify "$out" \
  --expect-sha256 "$sum" --extract-to "$tmp/partial-fail/created" \
  > "$tmp/partial-fail.log" 2>&1; then
  fail "A failed extraction with a failed cleanup reported success."
fi
[ -d "$tmp/partial-fail/created" ] ||
  fail "The cleanup-failure fixture did not leave its residual directory."
grep -q 'cleanup incomplete' "$tmp/partial-fail.log" ||
  fail "A failed cleanup was silent."
grep -Fq "$tmp/partial-fail/created" "$tmp/partial-fail.log" ||
  fail "A failed cleanup did not name the residual path."
"$real_rm" -rf "$tmp/partial-fail"
pass

# A duplicate entry is rejected before extraction.
mkdir -p "$tmp/bad/duplicate"
make_ustar_with_name "$tmp/bad/duplicate/one.tar" 'gui_assets/victim'
dd if="$tmp/bad/duplicate/one.tar" bs=512 count=2 2>/dev/null \
  > "$tmp/bad/duplicate/raw.tar"
dd if="$tmp/bad/duplicate/one.tar" bs=512 count=2 2>/dev/null \
  >> "$tmp/bad/duplicate/raw.tar"
dd if=/dev/zero bs=512 count=2 2>/dev/null >> "$tmp/bad/duplicate/raw.tar"
gzip -n -9 -c "$tmp/bad/duplicate/raw.tar" > "$tmp/bad/duplicate/a.tar.gz"
printf '%064d  gui_assets/victim\n' 0 > "$tmp/bad/duplicate/files.sha256"
write_sidecars "$tmp/bad/duplicate/a.tar.gz" "$tmp/bad/duplicate/files.sha256"
expect_verify_fail duplicate 'more than once'

# Archive-only verification still validates every header before extraction.
mkdir -p "$tmp/bad/pax-x-only"
cp "$tmp/bad/pax-x/a.tar.gz" "$tmp/bad/pax-x-only/source.tar.gz"
if "$helper" --verify "$tmp/bad/pax-x-only/source.tar.gz" \
  --expect-sha256 "$(sha256_file "$tmp/bad/pax-x-only/source.tar.gz")" \
  --extract-to "$tmp/bad/pax-x-only/restore" \
  > "$tmp/bad/pax-x-only.log" 2>&1; then
  fail "Archive-only verification accepted a pax header."
fi
grep -q 'pax extended header' "$tmp/bad/pax-x-only.log" ||
  fail "Archive-only verification failed for the wrong reason."
[ ! -e "$tmp/bad/pax-x-only/restore" ] ||
  fail "Archive-only verification extracted a malicious archive."
pass

# A malicious archive must not create the extraction destination.
if "$helper" --verify "$tmp/bad/pax-x/a.tar.gz" \
  --expect-sha256 "$(sha256_file "$tmp/bad/pax-x/a.tar.gz")" \
  --extract-to "$tmp/bad/pax-x/restore" \
  > "$tmp/bad/pax-x/extract.log" 2>&1; then
  fail "A malicious archive was extracted."
fi
[ ! -e "$tmp/bad/pax-x/restore" ] ||
  fail "A malicious archive created an extraction directory."
pass

# ---------------------------------------------------------------------------
# Sidecar and digest tampering.
# ---------------------------------------------------------------------------
copy_set() {
  local src=$1 dest=$2
  mkdir -p "$dest"
  cp "$src" "$dest/source.tar.gz"
  cp "$src.sha256" "$dest/source.tar.gz.sha256"
  cp "$src.files.sha256" "$dest/source.tar.gz.files.sha256"
  cp "$src.manifest.sha256" "$dest/source.tar.gz.manifest.sha256"
  cp "$src.provenance" "$dest/source.tar.gz.provenance"
}

sidecar_fail() {
  local label=$1 pattern=$2
  local archive=$tmp/bad/$label/source.tar.gz
  if "$helper" --verify "$archive" --expect-sha256 "$sum" \
    > "$tmp/sidecar-$label.log" 2>&1; then
    fail "Verification accepted a tampered sidecar set ($label)."
  fi
  if ! grep -q "$pattern" "$tmp/sidecar-$label.log"; then
    cat "$tmp/sidecar-$label.log" >&2
    fail "The tampered sidecar failed for the wrong reason ($label)."
  fi
  pass
}

copy_set "$out" "$tmp/bad/tamper"
printf 'x' >> "$tmp/bad/tamper/source.tar.gz"
sidecar_fail tamper 'digest mismatch'

copy_set "$out" "$tmp/bad/sidecar-sum"
printf '%064d  source.tar.gz\n' 0 \
  > "$tmp/bad/sidecar-sum/source.tar.gz.sha256"
sidecar_fail sidecar-sum 'digest mismatch'

copy_set "$out" "$tmp/bad/sidecar-files"
awk '{ sub(/^[0-9a-f]+/, "0000000000000000000000000000000000000000000000000000000000000000"); print }' \
  "$out.files.sha256" > "$tmp/bad/sidecar-files/source.tar.gz.files.sha256"
sidecar_fail sidecar-files 'Per-file digest manifest does not match'

copy_set "$out" "$tmp/bad/sidecar-extra"
printf '%064d  gui_assets/extra.js\n' 0 \
  >> "$tmp/bad/sidecar-extra/source.tar.gz.files.sha256"
sidecar_fail sidecar-extra 'do not name the same files'

copy_set "$out" "$tmp/bad/sidecar-dup"
head -n 1 "$out.files.sha256" >> "$tmp/bad/sidecar-dup/source.tar.gz.files.sha256"
sidecar_fail sidecar-dup 'more than once'

copy_set "$out" "$tmp/bad/sidecar-case"
printf '%064d  rust/CARGO.lock\n' 0 \
  >> "$tmp/bad/sidecar-case/source.tar.gz.files.sha256"
sidecar_fail sidecar-case 'case-fold'

copy_set "$out" "$tmp/bad/sidecar-prov"
awk '{ if ($0 ~ /^Archive SHA-256: /) print "Archive SHA-256: 0000000000000000000000000000000000000000000000000000000000000000"; else print }' \
  "$out.provenance" > "$tmp/bad/sidecar-prov/source.tar.gz.provenance"
sidecar_fail sidecar-prov 'Provenance archive digest'

copy_set "$out" "$tmp/bad/sidecar-manifest"
printf '%064d  manifest.txt\n' 0 \
  > "$tmp/bad/sidecar-manifest/source.tar.gz.manifest.sha256"
sidecar_fail sidecar-manifest 'Provenance manifest digest'

# A complete digest rewrite is self-consistent but fails an independent digest.
printf 'different\n' > "$fixture/rust/src/different.rs"
optin rust/src/different.rs > "$tmp/rewrite-manifest.txt"
"$helper" --repo "$fixture" --manifest "$tmp/rewrite-manifest.txt" \
  --output "$tmp/out/rewrite.tar.gz" > "$tmp/rewrite.log" 2>&1 || {
  cat "$tmp/rewrite.log" >&2
  fail "The digest-rewrite fixture did not build."
}
if "$helper" --verify "$tmp/out/rewrite.tar.gz" --expect-sha256 "$sum" \
  > "$tmp/rewrite-verify.log" 2>&1; then
  fail "A complete digest rewrite passed the independent digest check."
fi
grep -q 'does not match the supplied' "$tmp/rewrite-verify.log" ||
  fail "The digest rewrite failed for the wrong reason."
"$helper" --verify "$tmp/out/rewrite.tar.gz" --corruption-only \
  > "$tmp/rewrite-corrupt.log" 2>&1 ||
  fail "A self-consistent rewrite should pass the corruption-only check."
grep -q 'corruption check only' "$tmp/rewrite-corrupt.log" ||
  fail "The corruption-only check did not label the rewrite."
pass

# A symlink archive or sidecar is rejected before it is read.
ln -s "$out" "$tmp/bad/link.tar.gz"
if "$helper" --verify "$tmp/bad/link.tar.gz" --expect-sha256 "$sum" \
  > "$tmp/bad/link.log" 2>&1; then
  fail "Verification accepted a symlink archive."
fi
grep -q 'Not a regular archive' "$tmp/bad/link.log" ||
  fail "The symlink archive failed for the wrong reason."
copy_set "$out" "$tmp/bad/link-sidecar"
rm -f "$tmp/bad/link-sidecar/source.tar.gz.sha256"
ln -s "$out.sha256" "$tmp/bad/link-sidecar/source.tar.gz.sha256"
if "$helper" --verify "$tmp/bad/link-sidecar/source.tar.gz" \
  --expect-sha256 "$sum" > "$tmp/bad/link-sidecar.log" 2>&1; then
  fail "Verification accepted a symlink sidecar."
fi
grep -q 'Not a regular sidecar' "$tmp/bad/link-sidecar.log" ||
  fail "The symlink sidecar failed for the wrong reason."
pass

# ---------------------------------------------------------------------------
# Git configuration must not execute a repository fsmonitor or hook.
# ---------------------------------------------------------------------------
cat > "$tmp/fsmonitor.sh" <<'EOF'
#!/bin/sh
: > "$FSMON_MARKER"
exit 0
EOF
chmod +x "$tmp/fsmonitor.sh"
mkdir -p "$tmp/hooks"
cat > "$tmp/hooks/post-index-change" <<'EOF'
#!/bin/sh
: > "$HOOK_MARKER"
exit 0
EOF
chmod +x "$tmp/hooks/post-index-change"
git -C "$fixture" config core.fsmonitor "$tmp/fsmonitor.sh"
git -C "$fixture" config core.hooksPath "$tmp/hooks"
export FSMON_MARKER=$tmp/fsmonitor.marker
export HOOK_MARKER=$tmp/hook.marker
rm -f "$FSMON_MARKER" "$HOOK_MARKER"
"$helper" --repo "$fixture" --list > "$tmp/fs-list.txt" 2>/dev/null ||
  fail "The helper --list mode failed with a repository fsmonitor configured."
"$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" \
  --output "$tmp/out/fsmonitor.tar.gz" > "$tmp/fs-build.log" 2>&1 || {
  cat "$tmp/fs-build.log" >&2
  fail "The helper failed with a repository fsmonitor configured."
}
[ ! -e "$FSMON_MARKER" ] || fail "The helper executed a repository fsmonitor."
[ ! -e "$HOOK_MARKER" ] || fail "The helper executed a repository hook."
git -C "$fixture" config --unset core.fsmonitor
git -C "$fixture" config --unset core.hooksPath
pass

# A repository core.worktree that redirects the root away from --repo fails.
mkdir -p "$tmp/elsewhere"
git -C "$fixture" config core.worktree "$tmp/elsewhere"
if "$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" \
  --output "$tmp/out/worktree.tar.gz" > "$tmp/worktree.log" 2>&1; then
  fail "The helper accepted a redirected core.worktree."
fi
[ ! -e "$tmp/out/worktree.tar.gz" ] ||
  fail "The helper left output for a redirected core.worktree."
git -C "$fixture" config --unset core.worktree
pass

# Publication signals are deferred until each output's inode is recorded.
mkdir -p "$tmp/build-signals" "$tmp/build-signals-bin"
real_mv=$(command -v mv)
for op in ln mv; do
  cat > "$tmp/build-signals-bin/$op" <<WRAPPER
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in
  "$tmp/build-signals/"*)
    "$([ "$op" = ln ] && printf '%s' "$real_ln" || printf '%s' "$real_mv")" "\$@"
    status=\$?
    kill -TERM "\$PPID" 2>/dev/null || true
    exit \$status ;;
esac
exec "$([ "$op" = ln ] && printf '%s' "$real_ln" || printf '%s' "$real_mv")" "\$@"
WRAPPER
  chmod +x "$tmp/build-signals-bin/$op"
done
for mode in link force; do
  set --
  if [ "$mode" = force ]; then
    printf 'old bytes\n' > "$tmp/build-signals/$mode.tar.gz"
    set -- --force
  fi
  if PATH="$tmp/build-signals-bin:$PATH" "$helper" --repo "$fixture" \
    --manifest "$tmp/manifest.txt" --output "$tmp/build-signals/$mode.tar.gz" \
    "$@" > "$tmp/build-$mode.log" 2>&1; then
    fail "A TERM during $mode publication reported success."
  fi
  [ ! -e "$tmp/build-signals/$mode.tar.gz" ] || fail "A TERM leaked $mode output."
  # --force cannot restore the old file after replacement.
done
pass

# A replacement made after publication must not be deleted by failure cleanup.
mkdir -p "$tmp/build-swap-bin" "$tmp/build-swap"
cat > "$tmp/build-swap-bin/ln" <<WRAPPER
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
"$real_ln" "\$@" || exit \$?
case "\$last" in
  "$tmp/build-swap/snapshot.tar.gz")
    "$real_mv" "\$last" "\$last.original"
    printf 'replacement\n' > "\$last"
    kill -TERM "\$PPID" ;;
esac
WRAPPER
chmod +x "$tmp/build-swap-bin/ln"
if PATH="$tmp/build-swap-bin:$PATH" "$helper" --repo "$fixture" \
  --manifest "$tmp/manifest.txt" --output "$tmp/build-swap/snapshot.tar.gz" \
  > "$tmp/build-swap.log" 2>&1; then fail "A swapped output reported success."; fi
[ "$(cat "$tmp/build-swap/snapshot.tar.gz")" = replacement ] || fail "Cleanup deleted the replacement."
grep -q 'published output changed; residual path' "$tmp/build-swap.log" || fail "The output swap was not reported."
pass

# Failure to inspect a just-created directory leaves it in place and names it.
mkdir -p "$tmp/statfail-bin" "$tmp/statfail"
real_stat=$(command -v stat)
cat > "$tmp/statfail-bin/stat" <<WRAPPER
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in "$tmp/statfail/tree") exit 1 ;; esac
exec "$real_stat" "\$@"
WRAPPER
chmod +x "$tmp/statfail-bin/stat"
if PATH="$tmp/statfail-bin:$PATH" "$helper" --verify "$out" --expect-sha256 "$sum" \
  --extract-to "$tmp/statfail/tree" > "$tmp/statfail.log" 2>&1; then
  fail "An uninspectable extraction directory reported success."
fi
[ -d "$tmp/statfail/tree" ] || fail "The uninspectable directory was removed."
grep -Fq "residual path: $tmp/statfail/tree" "$tmp/statfail.log" || fail "The residual directory was not reported."
pass

# A signal during final work cleanup cannot change the committed exit status.
mkdir -p "$tmp/commit-bin" "$tmp/commit-temp" "$tmp/commit-output"
cat > "$tmp/commit-bin/rm" <<WRAPPER
#!/bin/sh
last=
for arg in "\$@"; do last=\$arg; done
case "\$last" in "$tmp/commit-temp/"hotspotshade-snapshot.*) kill -TERM "\$PPID" ;; esac
exec "$real_rm" "\$@"
WRAPPER
chmod +x "$tmp/commit-bin/rm"
TMPDIR="$tmp/commit-temp" PATH="$tmp/commit-bin:$PATH" "$helper" --repo "$fixture" \
  --manifest "$tmp/manifest.txt" --output "$tmp/commit-output/snapshot.tar.gz" \
  > "$tmp/commit.log" 2>&1 || fail "A signal during the exit commit changed the result."
[ -f "$tmp/commit-output/snapshot.tar.gz.sha256" ] || fail "The committed output set is incomplete."
pass

# The build rolls back on a failed final write, and failed cleanup is reported.
mkdir -p "$tmp/build-closed" "$tmp/build-workfail" "$tmp/build-worktmp"
if "$helper" --repo "$fixture" --manifest "$tmp/manifest.txt" \
  --output "$tmp/build-closed/snapshot.tar.gz" >&- 2> "$tmp/build-closed.log"; then
  fail "A build with closed stdout reported success."
fi
[ ! -e "$tmp/build-closed/snapshot.tar.gz" ] || fail "Closed stdout leaked a build output."
if TMPDIR="$tmp/workfail-tmp" PATH="$tmp/workfail-bin:$PATH" "$helper" --repo "$fixture" \
  --manifest "$tmp/manifest.txt" --output "$tmp/build-workfail/snapshot.tar.gz" \
  > "$tmp/build-workfail.log" 2>&1; then
  fail "A build with failed work cleanup reported success."
fi
[ ! -e "$tmp/build-workfail/snapshot.tar.gz" ] || fail "Work cleanup failure leaked a build output."
pass

# The help text must state the content-scan limit and the digest rules.
"$helper" --help > "$tmp/help.txt"
grep -q 'do not prove that a file is' "$tmp/help.txt" ||
  fail "The help text does not state the content-scan limitation."
grep -q -- '--expect-sha256' "$tmp/help.txt" ||
  fail "The help text does not document the independent digest."
grep -q -- '--corruption-only' "$tmp/help.txt" ||
  fail "The help text does not document the corruption-only mode."
pass

printf 'Source snapshot fixture tests passed (%s checks).\n' "$passed"
