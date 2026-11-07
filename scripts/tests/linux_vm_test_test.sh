#!/usr/bin/env bash
# Exercise VM lifecycle and transfer-gate handling without contacting Freestyle
# and without creating a VM, an archive, a TUN device, or a route.
#
# Four parts:
#   1. The external archive and helper digest gates, the private copies, the
#      separated helper extraction root, an absent extraction destination,
#      helper failure and tamper cases, and the VM create, file copy, run, and
#      delete sequence.
#   2. The real scripts/source_snapshot.sh contract. The harness copies no
#      sidecar, the helper creates the absent destination, and an existing
#      directory or symlink at that path is refused before the helper runs.
#   3. The tunnel harness that runs inside the VM: stale-binary selection, the
#      isolated target directory, and the child-helper accounting.
#   4. The remote digest checks, archive shape checks, private-copy extraction,
#      and the file manifest comparison before extraction is trusted.
#
# The snapshot helper fixture beside a copy of the VM script implements only
# the revised contract the harness requires:
#   --verify ARCHIVE --expect-sha256 HEX --extract-to DIR
# DIR must not exist, as the real helper requires. The fake helper creates it
# and refuses an existing directory or symlink. The real helper is never copied
# into the fixture directory.
set -euo pipefail
export HOTSPOTSHADE_LINUX_SNAPSHOT=test-snapshot

repo_dir=$(cd "$(dirname "$0")/../.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-vm-test.XXXXXXXX")

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    openssl dgst -sha256 "$1" | sed 's/.*= //'
  fi
}

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

fail() {
  echo "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "${test_dir:-}" ] && [ "$test_dir" != / ] && [ -d "$test_dir" ]; then
    if [ "${HS_KEEP_TEST_DIR:-0}" = 1 ]; then
      echo "Keeping test directory: $test_dir" >&2
    else
      find "$test_dir" -type d -exec chmod u+rwx {} + 2>/dev/null || true
      rm -rf "$test_dir"
    fi
  fi
}
trap cleanup EXIT

scripts_dir=$test_dir/scripts
shim=$test_dir/shim
cpshim=$test_dir/cpshim
fixtures=$test_dir/fixtures
tmp=$test_dir/tmp
mkdir -p "$scripts_dir" "$shim" "$cpshim" "$fixtures" "$tmp"
race_shim=$test_dir/raceshim
mktemp_shim=$test_dir/mktempshim
plant_shim=$test_dir/plantshim
final_shim=$test_dir/finalshim
chmod_race_shim=$test_dir/chmodraceshim
mkdir -p "$race_shim" "$mktemp_shim" "$plant_shim" "$final_shim" "$chmod_race_shim"
cp "$repo_dir/scripts/linux_vm_test.sh" "$scripts_dir/linux_vm_test.sh"

# The fixture helper models the revised contract. It does not parse an archive.
# It binds the copied bytes to the external pin and writes a marker tree.
cat > "$scripts_dir/source_snapshot.sh" <<'HELPER'
#!/usr/bin/env sh
set -eu
archive=
expected=
extract_to=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --verify)
      [ "$#" -ge 2 ] || exit 2
      archive=$2
      shift 2
      ;;
    --expect-sha256)
      [ "$#" -ge 2 ] || exit 2
      expected=$2
      shift 2
      ;;
    --extract-to)
      [ "$#" -ge 2 ] || exit 2
      extract_to=$2
      shift 2
      ;;
    *)
      echo "fake helper: unknown argument $1" >&2
      exit 2
      ;;
  esac
done
if [ -z "$archive" ] || [ -z "$expected" ] || [ -z "$extract_to" ]; then
  echo "fake helper: missing argument" >&2
  exit 2
fi
case "$expected" in
  *[!0-9a-f]*)
    echo "fake helper: the expected digest is not lower-case hex" >&2
    exit 2
    ;;
esac
if [ "${#expected}" -ne 64 ]; then
  echo "fake helper: the expected digest is not 64 characters" >&2
  exit 2
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$archive" | cut -d' ' -f1)
else
  actual=$(openssl dgst -sha256 "$archive" | sed 's/.*= //')
fi
printf '%s %s %s\n' "$archive" "$expected" "$extract_to" >> "${HS_HELPER_LOG:-/dev/null}"
if [ "$actual" != "$expected" ]; then
  echo "fake helper: archive digest mismatch" >&2
  exit 1
fi
if [ "${HS_HELPER_MODE:-ok}" = fail ]; then
  echo "fake helper: verification failed" >&2
  exit 1
fi
if [ -e "$extract_to" ] || [ -L "$extract_to" ]; then
  echo "fake helper: the extraction destination already exists: $extract_to" >&2
  exit 1
fi
mkdir -m 700 "$extract_to" || {
  echo "fake helper: cannot create the extraction destination: $extract_to" >&2
  exit 1
}
case "${HS_HELPER_MODE:-ok}" in
  ok|tamper)
    printf 'verified\n' > "$extract_to/VERIFIED"
    ;;
  empty)
    ;;
  symlink)
    printf 'verified\n' > "$extract_to/VERIFIED"
    ln -s /etc/passwd "$extract_to/LINK"
    ;;
  hardlink)
    printf 'verified\n' > "$extract_to/VERIFIED"
    ln "$extract_to/VERIFIED" "$extract_to/VERIFIED2"
    ;;
  setuid)
    printf 'verified\n' > "$extract_to/VERIFIED"
    chmod 4755 "$extract_to/VERIFIED"
    ;;
  fifo)
    printf 'verified\n' > "$extract_to/VERIFIED"
    mkfifo "$extract_to/PIPE"
    ;;
  dirty)
    # A readable but unwritable directory models a helper that leaves a tree
    # the harness cannot remove without restoring owner write access.
    printf 'verified\n' > "$extract_to/VERIFIED"
    mkdir "$extract_to/private"
    printf 'x\n' > "$extract_to/private/file"
    chmod 500 "$extract_to/private"
    ;;
  env-check)
    if [ -n "${FREESTYLE_API_KEY:-}" ] || [ -n "${NPM_TOKEN:-}" ] ||
      [ -n "${TAR_OPTIONS:-}" ] || [ -n "${GZIP:-}" ]; then
      echo "fake helper: caller environment leaked" >&2
      exit 1
    fi
    printf 'verified\n' > "$extract_to/VERIFIED"
    ;;
  escape)
    # Plant the names an earlier harness wrote after the helper returned:
    # ../runner.sh was the remote runner and ../tree.list was a find target.
    # A victim outside the work trees must stay unchanged.
    victim=${HS_ESCAPE_VICTIM:?}
    ln -s "$victim" "$extract_to/../runner.sh"
    ln -s "$victim" "$extract_to/../tree.list"
    ln -s "$victim" "$(dirname "$archive")/../runner.sh"
    ln -s "$victim" "$(dirname "$archive")/../tree.list"
    printf 'verified\n' > "$extract_to/VERIFIED"
    ;;
  self-tamper)
    # Append a comment so a re-read cannot execute a command, but the private
    # copy digest still changes after it verified.
    printf '\n# tampered-helper\n' >> "$0"
    printf 'verified\n' > "$extract_to/VERIFIED"
    ;;
  *)
    echo "fake helper: unknown mode ${HS_HELPER_MODE}" >&2
    exit 2
    ;;
esac
if [ "${HS_HELPER_MODE:-ok}" = tamper ]; then
  printf 'tampered-after-verify\n' >> "$archive"
fi
echo "fake helper verified $actual"
HELPER
chmod +x "$scripts_dir/source_snapshot.sh"

cat > "$shim/npx" <<'EOF'
#!/usr/bin/env bash
set -eu
if [ "$1" != -y ] || [ "$2" != freestyle@0.2.21 ]; then
  echo "VM runner did not select the reviewed Freestyle CLI version." >&2
  exit 1
fi
if [ "$4" = create ]; then
  for option in --ephemeral --no-automatic-restart --no-internet --no-ssh; do
    case " $* " in
      *" $option "*) ;;
      *) echo "VM runner omitted $option." >&2; exit 1 ;;
    esac
  done
  if [ -n "${HS_SUBSTITUTE_ROOT:-}" ]; then
    case "$HS_SUBSTITUTE_ROOT" in
      helper) pattern='hotspotshade-vm-helper.*' ;;
      work) pattern='hotspotshade-vm-input.*' ;;
      *)
        echo "npx shim: unknown substitute root: $HS_SUBSTITUTE_ROOT" >&2
        exit 1
        ;;
    esac
    for root in "$HS_SUBSTITUTE_TMP"/$pattern; do
      [ -e "$root" ] || continue
      rm -rf -- "$root" || exit 1
      ln -s "${HS_SUBSTITUTE_VICTIM:?}" "$root" || exit 1
    done
  fi
fi
printf '%s\n' "$4" >> "$HS_VM_TEST_LOG"
if [ "$4" = create ] && [ -n "${HS_SIGNAL_CREATE:-}" ]; then
  # Model a create that the server accepts and the client loses to a signal:
  # the call is logged, then the script's own shell receives the signal.
  kill -s "$HS_SIGNAL_CREATE" "$PPID" || true
  exit 1
fi
if [ "$4" = delete ] && [ -n "${HS_SIGNAL_DELETE:-}" ]; then
  # A second signal during delete must not cut the delete short.
  kill -s "$HS_SIGNAL_DELETE" "$PPID" || true
fi
if [ "$4" = fs ] && [ -n "${HS_FS_LOG:-}" ]; then
  args=("$@")
  dest=${args[6]}
  src=${args[${#args[@]}-1]}
  if [ -n "${HS_TAMPER_UPLOAD:-}" ] && [ "$dest" = "$HS_TAMPER_UPLOAD" ]; then
    printf 'tampered-during-upload\n' >> "$src"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sum=$(sha256sum "$src" | cut -d' ' -f1)
  elif command -v shasum >/dev/null 2>&1; then
    sum=$(shasum -a 256 "$src" | cut -d' ' -f1)
  else
    sum=$(openssl dgst -sha256 "$src" | sed 's/.*= //')
  fi
  printf '%s %s\n' "$sum" "$src" >> "$HS_FS_LOG"
fi
if [ "$4" = exec ] && [ -n "${HS_EXEC_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$HS_EXEC_LOG"
fi
if [ "$4" = "${HS_VM_FAIL_PHASE:-}" ]; then
  exit 19
fi
if [ "$4" = exec ] && [ -n "${HS_LAUNCH_CMD:-}" ]; then
  case "$*" in
    *'sudo -n bash -c'*)
      for last_arg in "$@"; do :; done
      printf '%s' "$last_arg" > "$HS_LAUNCH_CMD"
      ;;
  esac
fi
case "$*" in
  *'cat '*)
    # The slug is the fifth argument. HS_FAKE_POLL overrides the record; the
    # token SLUG stands for this run's slug.
    poll_record=${HS_FAKE_POLL:-"SLUG 0"}
    echo "${poll_record//SLUG/$5}"
    ;;
esac
EOF
chmod +x "$shim/npx"

# The status poll sleeps 10 seconds. The shim skips only that sleep, so the
# helper watchdog (sleep 900) and every other sleep stay real. On the first poll
# it can also replace one private root with a symlink, so the cleanup
# substitution test runs after every upload and exec call.
cat > "$shim/sleep" <<'EOF'
#!/bin/sh
if [ "$1" = 10 ]; then
  if [ -n "${HS_LATE_SUBSTITUTE_ROOT:-}" ] &&
    [ ! -e "${HS_LATE_SUBSTITUTE_FLAG:?}" ]; then
    case "$HS_LATE_SUBSTITUTE_ROOT" in
      helper) pattern='hotspotshade-vm-helper.*' ;;
      work) pattern='hotspotshade-vm-input.*' ;;
      *)
        echo "sleep shim: unknown substitute root: $HS_LATE_SUBSTITUTE_ROOT" >&2
        exit 1
        ;;
    esac
    for root in "$HS_LATE_SUBSTITUTE_TMP"/$pattern; do
      [ -e "$root" ] || continue
      rm -rf -- "$root" || exit 1
      ln -s "${HS_LATE_SUBSTITUTE_VICTIM:?}" "$root" || exit 1
    done
    : > "$HS_LATE_SUBSTITUTE_FLAG"
  fi
  exit 0
fi
if [ "$1" = 900 ] && [ -n "${HS_WATCHDOG_LOG:-}" ]; then
  printf '%s\n' "$$" >> "$HS_WATCHDOG_LOG"
fi
exec /bin/sleep "$@"
EOF
chmod +x "$shim/sleep"

cat > "$cpshim/cp" <<'EOF'
#!/usr/bin/env bash
set -eu
/bin/cp "$@"
if [ "${HS_TAMPER_AFTER_COPY:-0}" = 1 ] && [ ! -e "${HS_TAMPER_FLAG:?}" ]; then
  for argument in "$@"; do
    if [ "$argument" = "${HS_TAMPER_SOURCE:-}" ]; then
      printf 'tampered-original\n' >> "$argument"
      : > "$HS_TAMPER_FLAG"
      break
    fi
  done
fi
EOF
chmod +x "$cpshim/cp"

# This rm models a same-user racer that plants a symlink between the private
# remove and the noclobber reopen in new_private_file.
cat > "$race_shim/rm" <<'EOF'
#!/usr/bin/env bash
set -eu
/bin/rm "$@"
if [ -n "${HS_RACE_VICTIM:-}" ]; then
  for argument in "$@"; do
    case "$argument" in
      *hotspotshade-vm-artifacts.*/run.*)
        if [ ! -e "$argument" ]; then
          ln -s "$HS_RACE_VICTIM" "$argument"
        fi
        ;;
    esac
  done
fi
EOF
chmod +x "$race_shim/rm"

# This mktemp models a same-user racer that plants a directory or a symlink at
# the helper extraction destination before the harness passes the path to the
# helper. The shim acts only on the private helper root template and leaves
# every other mktemp call alone. HS_REAL_MKTEMP is resolved before the shim
# joins PATH, so the shim never calls itself.
HS_REAL_MKTEMP=$(command -v mktemp)
export HS_REAL_MKTEMP
cat > "$mktemp_shim/mktemp" <<'EOF'
#!/usr/bin/env bash
set -eu
out=$("$HS_REAL_MKTEMP" "$@")
printf '%s\n' "$out"
if [ "${1:-}" = -d ] && [ -n "${HS_PLANT_DEST:-}" ]; then
  case "${2:-}" in
    */hotspotshade-vm-helper.*)
      case "$HS_PLANT_DEST" in
        existing)
          mkdir "$out/tree"
          ;;
        symlink)
          ln -s "${HS_PLANT_TARGET:?}" "$out/tree"
          ;;
        *)
          echo "mktemp shim: unknown plant mode: $HS_PLANT_DEST" >&2
          exit 1
          ;;
      esac
      ;;
  esac
fi
EOF
chmod +x "$mktemp_shim/mktemp"

# This mkdir models a same-user racer that plants a symlink at the predictable
# archive or helper copy destination after the private directory exists and
# before the harness copies into it. The harness must create its copy under an
# unpredictable name and ignore the planted path.
cat > "$plant_shim/mkdir" <<'EOF'
#!/usr/bin/env bash
set -eu
/bin/mkdir "$@"
last=
for argument in "$@"; do
  last=$argument
done
case "$last" in
  */hotspotshade-vm-input.*/input)
    [ "${HS_PLANT_COPY_DEST:-}" = archive ] || exit 0
    ln -s "${HS_PLANT_COPY_TARGET:?}" "$last/${HS_PLANT_COPY_NAME:?}"
    ;;
  */hotspotshade-vm-input.*/helper-bin)
    [ "${HS_PLANT_COPY_DEST:-}" = helper ] || exit 0
    ln -s "${HS_PLANT_COPY_TARGET:?}" "$last/source_snapshot.sh"
    ;;
esac
EOF
chmod +x "$plant_shim/mkdir"

# Replace the archive name after its descriptor is open, just as chmod runs.
cat > "$chmod_race_shim/chmod" <<'EOF'
#!/usr/bin/env bash
set -eu
case "$*" in
  *'/dev/fd/9'*|*'/input/'*)
    if [ ! -e "${HS_CHMOD_RACE_FLAG:?}" ]; then
      path=$(find "$TMPDIR" -type f -path '*/input/*' -print -quit)
      if [ -n "$path" ]; then
        mv "$path" "$path.original"
        ln -s "${HS_CHMOD_RACE_TARGET:?}" "$path"
        : > "$HS_CHMOD_RACE_FLAG"
      fi
    fi ;;
esac
exec /bin/chmod "$@"
EOF
chmod +x "$chmod_race_shim/chmod"

# This sha256sum models a same-user racer that changes one private input after
# the harness has read the runner text and before the final pre-transfer
# rehash. It tampers once, right after the first hash of the private runner.
HS_REAL_SHA256SUM=$(command -v sha256sum || true)
export HS_REAL_SHA256SUM
cat > "$final_shim/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -eu
if [ -n "${HS_REAL_SHA256SUM:-}" ]; then
  out=$("$HS_REAL_SHA256SUM" "$@")
else
  out=$(shasum -a 256 "$@")
fi
printf '%s\n' "$out"
if [ -z "${HS_FINAL_TAMPER:-}" ] || [ -e "${HS_FINAL_TAMPER_FLAG:?}" ]; then
  exit 0
fi
for argument in "$@"; do
  case "$argument" in
    */hotspotshade-vm-artifacts.*/run.*) ;;
    *) continue ;;
  esac
  case "$HS_FINAL_TAMPER" in
    archive)
      target=$(printf '%s\n' "$HS_FINAL_TAMPER_TMP"/hotspotshade-vm-input.*/input/* |
        head -1)
      ;;
    helper)
      target=$(printf '%s\n' "$HS_FINAL_TAMPER_TMP"/hotspotshade-vm-input.*/helper-bin/* |
        head -1)
      ;;
    runner) target=$argument ;;
    manifest)
      target=$(printf '%s\n' "$HS_FINAL_TAMPER_TMP"/hotspotshade-vm-artifacts.*/files.* |
        head -1)
      ;;
    *)
      echo "sha256sum shim: unknown final tamper: $HS_FINAL_TAMPER" >&2
      exit 1
      ;;
  esac
  printf 'tampered-before-transfer\n' >> "$target"
  : > "$HS_FINAL_TAMPER_FLAG"
  break
done
EOF
chmod +x "$final_shim/sha256sum"

fixture=$fixtures/source.tar.gz
printf 'reviewed snapshot fixture\n' > "$fixture"
fixture_pin=$(sha256_file "$fixture")
zero_pin=$(printf '%064d' 0)
# A stale sidecar must not override the external pin. The harness never reads
# these files, and the valid run below must still pass.
printf '%s  source.tar.gz\n' "$zero_pin" > "$fixture.sha256"
printf '%s  ignored\n' "$zero_pin" > "$fixture.files.sha256"

HS_VM_TEST_LOG=$test_dir/calls
HS_FS_LOG=$test_dir/fs.log
HS_HELPER_LOG=$test_dir/helper.log
HS_EXEC_LOG=$test_dir/exec.log
HS_LAUNCH_CMD=$test_dir/launch.cmd
HS_WATCHDOG_LOG=$test_dir/watchdog-pids
export HS_VM_TEST_LOG HS_FS_LOG HS_HELPER_LOG HS_EXEC_LOG HS_LAUNCH_CMD HS_WATCHDOG_LOG

default_helper_pin=$(sha256_file "$scripts_dir/source_snapshot.sh")

run_script_in() {
  local dir=$1 pin=$2 helper_mode=$3 archive=$4
  shift 4
  local helper_pin=${HS_HELPER_PIN-$default_helper_pin}
  : > "$HS_VM_TEST_LOG"
  : > "$HS_FS_LOG"
  : > "$HS_HELPER_LOG"
  : > "$HS_EXEC_LOG"
  local status=0
  PATH="${HS_EXTRA_PATH:+$HS_EXTRA_PATH:}$cpshim:$shim:$PATH" \
  TMPDIR="$tmp" \
  HOTSPOTSHADE_VM_TRANSFER_APPROVED="${HS_GATE_APPROVED:-1}" \
  HOTSPOTSHADE_SNAPSHOT_SHA256="$pin" \
  HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256="$helper_pin" \
  HS_HELPER_MODE="$helper_mode" \
    bash "$dir/linux_vm_test.sh" "$@" "$archive" \
    >"$test_dir/run.log" 2>&1 || status=$?
  printf '%s' "$status"
}

run_script() {
  local pin=$1 helper_mode=$2 archive=$3
  shift 3
  run_script_in "$scripts_dir" "$pin" "$helper_mode" "$archive" "$@"
}

expect_status() {
  [ "$1" -eq "$2" ] || fail "Expected exit $2 for $3, got $1. Log: $(cat "$test_dir/run.log")"
}

expect_calls() {
  local calls
  calls=$(tr '\n' ' ' < "$HS_VM_TEST_LOG")
  [ "$calls" = "$1" ] || fail "Unexpected VM lifecycle for $2: $calls. Log: $(cat "$test_dir/run.log")"
}

expect_no_vm() {
  [ ! -s "$HS_VM_TEST_LOG" ] || fail "A VM call happened during $1: $(tr '\n' ' ' < "$HS_VM_TEST_LOG")"
}

expect_no_helper() {
  [ ! -s "$HS_HELPER_LOG" ] || fail "The helper ran during $1: $(cat "$HS_HELPER_LOG")"
}

expect_tmp_clean() {
  local left
  left=$(find "$tmp" -mindepth 1 -print)
  [ -z "$left" ] || fail "The private work directory was not removed for $1: $left"
}

expect_grep() {
  grep -q -- "$1" "$2" || fail "Missing expected text for $3: $1. Log: $(cat "$2")"
}

expect_no_grep() {
  if grep -q -- "$1" "$2"; then
    fail "Unexpected text for $3: $1"
  fi
}

# --- the fake helper requires an absent extraction destination --------------
# The fixture must match the real helper contract. Otherwise a passing harness
# run could depend on a fake helper that accepts a destination the production
# script pre-created.
direct_root=$test_dir/direct-helper
mkdir -p "$direct_root"
direct_status=0
HS_HELPER_LOG=$test_dir/direct-helper.log \
  "$scripts_dir/source_snapshot.sh" --verify "$fixture" \
  --expect-sha256 "$fixture_pin" --extract-to "$direct_root" \
  >"$test_dir/direct-existing.log" 2>&1 || direct_status=$?
[ "$direct_status" -ne 0 ] || fail "The fake helper accepted an existing extraction destination."
expect_grep 'extraction destination already exists' "$test_dir/direct-existing.log" \
  "fake helper existing destination"
rmdir "$direct_root"

direct_victim=$test_dir/direct-helper-victim.txt
printf 'direct-helper-do-not-touch\n' > "$direct_victim"
direct_sum=$(sha256_file "$direct_victim")
direct_link=$test_dir/direct-helper-link
ln -s "$direct_victim" "$direct_link"
direct_status=0
HS_HELPER_LOG=$test_dir/direct-helper.log \
  "$scripts_dir/source_snapshot.sh" --verify "$fixture" \
  --expect-sha256 "$fixture_pin" --extract-to "$direct_link" \
  >"$test_dir/direct-symlink.log" 2>&1 || direct_status=$?
[ "$direct_status" -ne 0 ] || fail "The fake helper accepted a symlink extraction destination."
expect_grep 'extraction destination already exists' "$test_dir/direct-symlink.log" \
  "fake helper symlink destination"
[ -L "$direct_link" ] || fail "The fake helper replaced the extraction symlink."
[ "$(sha256_file "$direct_victim")" = "$direct_sum" ] ||
  fail "The fake helper wrote through the extraction symlink."
rm -f "$direct_link"

direct_ok=$test_dir/direct-helper-ok
direct_status=0
HS_HELPER_LOG=$test_dir/direct-helper.log \
  "$scripts_dir/source_snapshot.sh" --verify "$fixture" \
  --expect-sha256 "$fixture_pin" --extract-to "$direct_ok" \
  >"$test_dir/direct-ok.log" 2>&1 || direct_status=$?
[ "$direct_status" -eq 0 ] || fail "The fake helper refused an absent extraction destination."
[ -f "$direct_ok/VERIFIED" ] || fail "The fake helper did not create the absent destination."
rm -rf "$direct_ok"

# --- a planted destination fails before the helper or a VM -------------------
# A same-user racer plants a directory or a symlink at the extraction
# destination after the private helper root exists. The harness must refuse
# before it runs the helper, creates a VM, or follows the link.
plant_victim=$test_dir/plant-victim.txt
printf 'plant-do-not-touch\n' > "$plant_victim"
plant_sum=$(sha256_file "$plant_victim")
for plant in existing symlink; do
  status=$(HS_EXTRA_PATH=$mktemp_shim HS_PLANT_DEST=$plant \
    HS_PLANT_TARGET=$plant_victim run_script "$fixture_pin" ok "$fixture")
  expect_status "$status" 1 "planted extraction destination $plant"
  expect_no_vm "planted extraction destination $plant"
  expect_no_helper "planted extraction destination $plant"
  expect_tmp_clean "planted extraction destination $plant"
  expect_grep 'private verified tree path already exists' "$test_dir/run.log" \
    "planted extraction destination $plant"
done
[ "$(sha256_file "$plant_victim")" = "$plant_sum" ] ||
  fail "A planted extraction destination rewrote an outside file."

# --- a planted copy destination is ignored -----------------------------------
# A same-user racer plants a symlink at the predictable archive and helper copy
# names after their private directories exist. The harness must create its
# copies under unpredictable names and must not write through the link or
# change its target's mode.
copy_victim=$test_dir/copy-victim.txt
printf 'copy-do-not-touch\n' > "$copy_victim"
chmod 644 "$copy_victim"
copy_sum=$(sha256_file "$copy_victim")
copy_mode=$(file_mode "$copy_victim")
fixture_base=${fixture##*/}

status=$(HS_EXTRA_PATH=$plant_shim HS_PLANT_COPY_DEST=archive \
  HS_PLANT_COPY_NAME="$fixture_base" HS_PLANT_COPY_TARGET=$copy_victim \
  run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 0 "planted archive copy destination"
expect_calls 'create fs fs fs exec exec exec delete ' "planted archive copy destination"
expect_tmp_clean "planted archive copy destination"
[ -s "$HS_HELPER_LOG" ] || fail "The helper did not run for a planted archive copy path."
first_fs=$(head -1 "$HS_FS_LOG")
case "${first_fs#* }" in
  */input/"$fixture_base")
    fail "The archive copy used the predictable planted path: ${first_fs#* }"
    ;;
esac
[ "$(sha256_file "$copy_victim")" = "$copy_sum" ] ||
  fail "The archive copy wrote through a planted destination symlink."
[ "$(file_mode "$copy_victim")" = "$copy_mode" ] ||
  fail "The archive copy changed the mode through a planted destination symlink."

status=$(HS_EXTRA_PATH=$plant_shim HS_PLANT_COPY_DEST=helper \
  HS_PLANT_COPY_TARGET=$copy_victim run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 0 "planted helper copy destination"
expect_calls 'create fs fs fs exec exec exec delete ' "planted helper copy destination"
expect_tmp_clean "planted helper copy destination"
[ -s "$HS_HELPER_LOG" ] || fail "The helper did not run for a planted helper copy path."
[ "$(sha256_file "$copy_victim")" = "$copy_sum" ] ||
  fail "The helper copy wrote through a planted destination symlink."
[ "$(file_mode "$copy_victim")" = "$copy_mode" ] ||
  fail "The helper copy changed the mode through a planted destination symlink."

# The mode change must use the already-open descriptor, even if the path is
# replaced after the copy and before chmod. The following path check refuses.
chmod_race_flag=$test_dir/chmod-race-hit
status=$(HS_EXTRA_PATH=$chmod_race_shim HS_CHMOD_RACE_FLAG=$chmod_race_flag \
  HS_CHMOD_RACE_TARGET=$copy_victim run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 1 "archive path replaced before chmod"
[ -f "$chmod_race_flag" ] || fail "The chmod race was not injected."
expect_no_vm "archive path replaced before chmod"
expect_no_helper "archive path replaced before chmod"
[ "$(file_mode "$copy_victim")" = "$copy_mode" ] ||
  fail "The archive chmod changed the replacement target's mode."
[ "$(sha256_file "$copy_victim")" = "$copy_sum" ] ||
  fail "The archive copy changed the replacement target."
expect_tmp_clean "archive path replaced before chmod"

# --- valid general run -------------------------------------------------------
: > "$HS_WATCHDOG_LOG"
status=$(run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 0 "general run"
expect_calls 'create fs fs fs exec exec exec delete ' "general run"
expect_tmp_clean "general run"
[ -s "$HS_WATCHDOG_LOG" ] || fail "The watchdog sleep did not start."
while IFS= read -r sleep_pid; do
  if kill -0 "$sleep_pid" 2>/dev/null; then
    fail "The watchdog sleep $sleep_pid remained after the helper exited."
  fi
done < "$HS_WATCHDOG_LOG"
expect_grep "archive_sha256: $fixture_pin" "$test_dir/run.log" "digest evidence"
expect_grep 'snapshot: test-snapshot' "$test_dir/run.log" "snapshot evidence"
expect_grep 'local_verification: passed' "$test_dir/run.log" "verification evidence"
expect_grep 'general' "$HS_EXEC_LOG" "general mode"
expect_grep "$fixture_pin" "$HS_EXEC_LOG" "general mode digest"
expect_grep 'setpriv --reuid=ubuntu' "$HS_EXEC_LOG" "general privilege drop"
expect_grep 'no-new-privs' "$HS_EXEC_LOG" "general no_new_privs"
expect_grep 'sudo -n bash -c' "$HS_EXEC_LOG" "root monitor launch"
[ -s "$HS_HELPER_LOG" ] || fail "The helper did not run for a valid archive."
fs_count=$(wc -l < "$HS_FS_LOG" | tr -d ' ')
[ "$fs_count" = 3 ] ||
  fail "Expected three uploads (archive, runner, manifest), got $fs_count: $(cat "$HS_FS_LOG")"
first_fs=$(sed -n 1p "$HS_FS_LOG")
second_fs=$(sed -n 2p "$HS_FS_LOG")
third_fs=$(sed -n 3p "$HS_FS_LOG")
uploaded_sum=${first_fs%% *}
uploaded_path=${first_fs#* }
[ "$uploaded_sum" = "$fixture_pin" ] ||
  fail "The uploaded archive digest did not match the pin: $uploaded_sum"
[ "$uploaded_path" != "$fixture" ] ||
  fail "The runner uploaded the caller's archive instead of the private copy."
case "$uploaded_path" in
  *hotspotshade-vm-input.*/input/*) ;;
  *) fail "The uploaded archive was not from the private work directory: $uploaded_path" ;;
esac
case "${second_fs#* }" in
  *hotspotshade-vm-artifacts.*/run.*) ;;
  *) fail "The uploaded runner was not an exclusive private file: $second_fs" ;;
esac
case "${third_fs#* }" in
  *hotspotshade-vm-artifacts.*/files.*) ;;
  *) fail "The uploaded file manifest was not an exclusive private file: $third_fs" ;;
esac
case "$(head -1 "$HS_HELPER_LOG")" in
  *hotspotshade-vm-helper.*) ;;
  *) fail "The helper did not extract into the separate helper root: $(head -1 "$HS_HELPER_LOG")" ;;
esac
# The launcher binds the runner digest before it starts the runner.
grep -Eq '[0-9a-f]{64}' "$HS_EXEC_LOG" ||
  fail "The launcher did not bind a runner digest: $(head -1 "$HS_EXEC_LOG")"
expect_grep 'sha256sum /home/ubuntu/hotspotshade-vm-run.sh' "$HS_EXEC_LOG" "runner digest binding"

# --- the root monitor script itself -------------------------------------------
# The launch command saved from the general run above is rewritten to point at
# a private directory and run with shims for sudo, setsid, setpriv, id, and
# chown. No privilege, user, or VM path is touched. The test checks what the
# monitor writes, that a stale status is replaced, that the unprivileged user
# can read the runner copy, and that a changed runner never starts.
launch_dir=$test_dir/launcher
mkdir -p "$launch_dir/bin" "$launch_dir/var"
[ -s "$HS_LAUNCH_CMD" ] || fail "The fake VM did not capture the launch command."
bash -n "$HS_LAUNCH_CMD" || fail "The launch command is not valid shell."
cp "$HS_LAUNCH_CMD" "$launch_dir/launch.raw"
grep -q 'sudo -n rm -rf -- /var/lib/hotspotshade-vm-status || exit 1; setsid' \
  "$launch_dir/launch.raw" ||
  fail "The launch command does not reset the status directory in the foreground."
launch_slug=$(grep -o 'hotspotshade-test-[0-9]*-[0-9]*' "$launch_dir/launch.raw" | head -1)
[ -n "$launch_slug" ] || fail "The launch command does not carry the run slug."
# The runner digest is the one the monitor compares against the uploaded runner.
runner_digest=$(sed -n 's/.*"\$actual" != "\([0-9a-f]\{64\}\)".*/\1/p' "$launch_dir/launch.raw" |
  head -1)
[ -n "$runner_digest" ] ||
  fail "Cannot find the runner digest in the launch command."

cat > "$launch_dir/bin/sudo" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -n) shift ;;
    *) break ;;
  esac
done
exec "$@"
EOF
cat > "$launch_dir/bin/setsid" <<'EOF'
#!/bin/sh
exec "$@"
EOF
cat > "$launch_dir/bin/setpriv" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$launch_dir/setpriv.args"
while [ "\$#" -gt 0 ] && [ "\$1" != env ]; do shift; done
exec "\$@"
EOF
cat > "$launch_dir/bin/id" <<'EOF'
#!/bin/sh
if [ "$1" = -u ] && [ "$2" = ubuntu ]; then
  echo 1000
  exit 0
fi
exec /usr/bin/id "$@"
EOF
# BSD chmod reads "--" after the mode as a file name. GNU chmod, which the VM
# uses, accepts it. The shim drops "--" so the same script runs on this host.
cat > "$launch_dir/bin/chmod" <<'EOF'
#!/bin/sh
args=
for arg in "$@"; do
  [ "$arg" = -- ] && continue
  args="$args '$arg'"
done
eval "exec /bin/chmod $args"
EOF
cat > "$launch_dir/bin/chown" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$launch_dir/bin/sha256sum" <<'EOF'
#!/bin/sh
if [ -x /usr/bin/sha256sum ]; then
  exec /usr/bin/sha256sum "$@"
fi
exec shasum -a 256 "$@"
EOF
chmod +x "$launch_dir"/bin/*

# The fake runner records the mode of its own directory and file, then exits
# with a chosen code. It stands in for the unprivileged runner.
cat > "$launch_dir/uploaded-run.sh" <<EOF
#!/bin/sh
ls -ld "\$(dirname "\$0")" "\$0" > "$launch_dir/runner.modes"
printf 'ran\n' >> "$launch_dir/runner.ran"
exit "\$(cat "$launch_dir/exit-code")"
EOF
fake_runner_digest=$(sha256_file "$launch_dir/uploaded-run.sh")

run_launcher() {
  local code=$1 stale=${2:-}
  rm -rf "$launch_dir/var" "$launch_dir/runner.modes" "$launch_dir/runner.ran" \
    "$launch_dir/setpriv.args"
  mkdir -p "$launch_dir/var"
  printf '%s\n' "$code" > "$launch_dir/exit-code"
  if [ -n "$stale" ]; then
    mkdir -p "$launch_dir/var/status-dir"
    printf '%s\n' "$stale" > "$launch_dir/var/status-dir/status"
  fi
  sed -e "s#/var/lib/hotspotshade-vm-status#$launch_dir/var/status-dir#g" \
      -e "s#/var/lib/hotspotshade-vm-runner\\.#$launch_dir/var/runner.#g" \
      -e "s#/home/ubuntu/hotspotshade-vm-run.sh#$launch_dir/uploaded-run.sh#g" \
      -e "s#/tmp/hotspotshade-vm-test.log#$launch_dir/vm-test.log#g" \
      -e "s#/tmp/hotspotshade-vm-launcher.log#$launch_dir/launcher.log#g" \
      -e "s#export PATH=/usr/local/sbin#export PATH=$launch_dir/bin:/usr/local/sbin#g" \
      -e "s#$runner_digest#$fake_runner_digest#g" \
      "$launch_dir/launch.raw" > "$launch_dir/launch.sh"
  PATH="$launch_dir/bin:$PATH" bash "$launch_dir/launch.sh" > "$launch_dir/launch.out" 2>&1 ||
    fail "The launch command failed to start: $(cat "$launch_dir/launch.out")"
  local waited=0 record=
  while [ "$waited" -lt 100 ]; do
    record=$(cat "$launch_dir/var/status-dir/status" 2>/dev/null || true)
    case "$record" in
      "$launch_slug running"|'') ;;
      *) break ;;
    esac
    /bin/sleep 0.1
    waited=$((waited + 1))
  done
  printf '%s' "$record"
}

record=$(run_launcher 0)
[ "$record" = "$launch_slug 0" ] ||
  fail "The monitor wrote '$record' for a passing runner, not '$launch_slug 0'."
[ -s "$launch_dir/runner.ran" ] || fail "The monitor did not start the runner."
grep -q '^drwxr-xr-x' "$launch_dir/runner.modes" ||
  fail "The runner directory is not readable by the unprivileged user: $(cat "$launch_dir/runner.modes")"
sed -n 2p "$launch_dir/runner.modes" | grep -q '^-rwxr-xr-x' ||
  fail "The runner copy is not readable and executable: $(cat "$launch_dir/runner.modes")"
grep -q -- '--reuid=ubuntu' "$launch_dir/setpriv.args" ||
  fail "The monitor did not drop to the image user."
grep -q -- '--no-new-privs' "$launch_dir/setpriv.args" ||
  fail "The monitor did not set no_new_privs for the general run."

record=$(run_launcher 7)
[ "$record" = "$launch_slug 7" ] ||
  fail "The monitor wrote '$record' for a failing runner, not '$launch_slug 7'."

# A stale record in the image is removed before the new run. The monitor never
# leaves a bare "0".
record=$(run_launcher 3 0)
[ "$record" = "$launch_slug 3" ] ||
  fail "A stale status survived the monitor: '$record'."

# A runner whose bytes changed after the pin is refused and never starts.
printf '#!/bin/sh\necho swapped\nexit 0\n' > "$launch_dir/uploaded-run.sh"
record=$(run_launcher 0)
[ "$record" = "$launch_slug 1" ] ||
  fail "A changed runner was not refused with a failing status: '$record'."
[ ! -e "$launch_dir/runner.ran" ] || fail "A changed runner executed."

# --- tunnel run is diagnostic only ------------------------------------------
status=$(run_script "$fixture_pin" ok "$fixture" --tunnel)
expect_status "$status" 1 "tunnel diagnostic"
expect_calls 'create fs fs fs exec exec exec delete ' "tunnel diagnostic"
expect_tmp_clean "tunnel diagnostic"
expect_grep 'Tunnel diagnostic completed, but no pass is reported' \
  "$test_dir/run.log" "tunnel fail-closed result"
expect_grep 'tunnel' "$HS_EXEC_LOG" "tunnel mode"
expect_grep "$fixture_pin" "$HS_EXEC_LOG" "tunnel mode digest"

# --- the status record must name this run -----------------------------------
# The monitor writes "<slug> <exit status>". A bare "0", a record for another
# run, a malformed record, or a failed status must never report a pass.
for case_record in '0' 'other-slug 0' 'SLUG 0 extra' 'SLUG ' 'SLUG x1' 'SLUG 00x' \
  'SLUG 1' 'SLUG 143' 'unreadable'; do
  status=$(HS_FAKE_POLL="$case_record" run_script "$fixture_pin" ok "$fixture")
  expect_status "$status" 1 "status record '$case_record'"
  expect_calls 'create fs fs fs exec exec exec delete ' "status record '$case_record'"
  expect_tmp_clean "status record '$case_record'"
  expect_no_grep 'Linux test passed' "$test_dir/run.log" "status record '$case_record'"
done
status=$(HS_FAKE_POLL='0' run_script "$fixture_pin" ok "$fixture")
expect_grep 'does not name this run' "$test_dir/run.log" "stale bare status"
status=$(HS_FAKE_POLL='SLUG 1' run_script "$fixture_pin" ok "$fixture")
expect_grep 'Linux test failed' "$test_dir/run.log" "failed status"
status=$(HS_FAKE_POLL='unreadable' run_script "$fixture_pin" ok "$fixture")
expect_grep 'could not be read' "$test_dir/run.log" "unreadable status"

# --- the tunnel diagnostic never passes, whatever the record says ------------
for case_record in 'SLUG 0' '0' 'SLUG 1' 'other-slug 0' 'unreadable'; do
  status=$(HS_FAKE_POLL="$case_record" run_script "$fixture_pin" ok "$fixture" --tunnel)
  expect_status "$status" 1 "tunnel status record '$case_record'"
  expect_no_grep 'Linux test passed' "$test_dir/run.log" "tunnel status record '$case_record'"
  expect_grep 'No pass is reported\|no pass is reported' "$test_dir/run.log" \
    "tunnel status record '$case_record'"
done

# --- --sha256 option without the environment pin -----------------------------
status=$(run_script "" ok "$fixture" --sha256 "$fixture_pin")
expect_status "$status" 0 "--sha256 only"
expect_calls 'create fs fs fs exec exec exec delete ' "--sha256 only"

# --- the transfer gate stays closed without explicit approval ----------------
status=$(HS_GATE_APPROVED=0 run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 1 "closed transfer gate"
expect_no_vm "closed transfer gate"
expect_no_helper "closed transfer gate"
expect_tmp_clean "closed transfer gate"
expect_grep 'transfer gate is closed' "$test_dir/run.log" "closed transfer gate"

# --- the snapshot name is validated before any provider call -----------------
status=$(HOTSPOTSHADE_LINUX_SNAPSHOT=-bad run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 1 "unsafe snapshot name"
expect_no_vm "unsafe snapshot name"
expect_no_helper "unsafe snapshot name"
expect_tmp_clean "unsafe snapshot name"
expect_grep 'HOTSPOTSHADE_LINUX_SNAPSHOT must be' "$test_dir/run.log" "unsafe snapshot name"

# --- conflicting pins --------------------------------------------------------
status=$(run_script "$fixture_pin" ok "$fixture" --sha256 "$zero_pin")
expect_status "$status" 1 "conflicting pins"
expect_no_vm "conflicting pins"
expect_no_helper "conflicting pins"
expect_tmp_clean "conflicting pins"
expect_grep 'differ' "$test_dir/run.log" "conflicting pins"

# --- missing helper pin ------------------------------------------------------
status=$(HS_HELPER_PIN= run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 1 "missing helper pin"
expect_no_vm "missing helper pin"
expect_no_helper "missing helper pin"
expect_tmp_clean "missing helper pin"
expect_grep 'externally pinned snapshot helper digest is required' "$test_dir/run.log" "missing helper pin"

# --- malformed helper pin ----------------------------------------------------
status=$(HS_HELPER_PIN=not-a-digest run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 1 "malformed helper pin"
expect_no_vm "malformed helper pin"
expect_no_helper "malformed helper pin"
expect_tmp_clean "malformed helper pin"
expect_grep 'snapshot helper digest must be 64 lower-case hex' "$test_dir/run.log" "malformed helper pin"

# --- helper pin does not match the helper ------------------------------------
status=$(HS_HELPER_PIN=$zero_pin run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 1 "helper pin mismatch"
expect_no_vm "helper pin mismatch"
expect_no_helper "helper pin mismatch"
expect_tmp_clean "helper pin mismatch"
expect_grep 'private snapshot helper copy does not match' "$test_dir/run.log" "helper pin mismatch"

# --- missing archive pin -----------------------------------------------------
status=$(run_script "" ok "$fixture")
expect_status "$status" 1 "missing pin"
expect_no_vm "missing pin"
expect_no_helper "missing pin"
expect_tmp_clean "missing pin"
expect_grep 'externally pinned archive digest is required' "$test_dir/run.log" "missing pin"

# --- malformed archive pin ---------------------------------------------------
status=$(run_script "not-a-digest" ok "$fixture")
expect_status "$status" 1 "malformed pin"
expect_no_vm "malformed pin"
expect_no_helper "malformed pin"
expect_tmp_clean "malformed pin"
expect_grep '64 lower-case hex characters' "$test_dir/run.log" "malformed pin"

# --- pin does not match the archive -----------------------------------------
status=$(run_script "$zero_pin" ok "$fixture")
expect_status "$status" 1 "pin mismatch"
expect_no_vm "pin mismatch"
expect_no_helper "pin mismatch"
expect_tmp_clean "pin mismatch"
expect_grep 'does not match the externally pinned SHA-256' "$test_dir/run.log" "pin mismatch"

# --- the archive changed before the private copy -----------------------------
tampered_before=$fixtures/tampered-before.tar.gz
cp "$fixture" "$tampered_before"
printf 'tampered-before-copy\n' >> "$tampered_before"
status=$(run_script "$fixture_pin" ok "$tampered_before")
expect_status "$status" 1 "tamper before copy"
expect_no_vm "tamper before copy"
expect_no_helper "tamper before copy"
expect_tmp_clean "tamper before copy"
expect_grep 'does not match the externally pinned SHA-256' "$test_dir/run.log" "tamper before copy"

# --- the helper rejects the archive -----------------------------------------
status=$(run_script "$fixture_pin" fail "$fixture")
expect_status "$status" 1 "helper failure"
expect_no_vm "helper failure"
expect_tmp_clean "helper failure"
[ -s "$HS_HELPER_LOG" ] || fail "The helper was not called for the failure case."
expect_grep 'Snapshot verification failed. No VM was created.' "$test_dir/run.log" "helper failure"

# --- the helper changes the private copy after it verifies -------------------
status=$(run_script "$fixture_pin" tamper "$fixture")
expect_status "$status" 1 "post-verification tamper"
expect_no_vm "post-verification tamper"
expect_tmp_clean "post-verification tamper"
[ -s "$HS_HELPER_LOG" ] || fail "The helper was not called for the tamper case."
expect_grep 'changed after verification' "$test_dir/run.log" "post-verification tamper"

# --- the pinned private helper changes while it runs ------------------------
status=$(run_script "$fixture_pin" self-tamper "$fixture")
expect_status "$status" 1 "helper self-tamper"
expect_no_vm "helper self-tamper"
expect_tmp_clean "helper self-tamper"
expect_grep 'pinned private snapshot helper copy changed during verification' \
  "$test_dir/run.log" "helper self-tamper"

# --- the helper's verified tree is unsafe ------------------------------------
for helper_mode in empty symlink hardlink setuid fifo; do
  status=$(run_script "$fixture_pin" "$helper_mode" "$fixture")
  expect_status "$status" 1 "helper tree $helper_mode"
  expect_no_vm "helper tree $helper_mode"
  expect_tmp_clean "helper tree $helper_mode"
  case "$helper_mode" in
    empty) expected_text='verified no regular files' ;;
    symlink) expected_text='holds a symlink' ;;
    hardlink) expected_text='holds a hard link' ;;
    setuid) expected_text='set-id or sticky entry' ;;
    fifo) expected_text='holds a special file' ;;
  esac
  expect_grep "$expected_text" "$test_dir/run.log" "helper tree $helper_mode"
done

# --- a helper tree the owner cannot remove is still cleaned ------------------
status=$(run_script "$fixture_pin" dirty "$fixture")
expect_status "$status" 0 "dirty helper cleanup"
expect_calls 'create fs fs fs exec exec exec delete ' "dirty helper cleanup"
expect_tmp_clean "dirty helper cleanup"

# --- caller secrets and tar knobs do not reach the helper -------------------
status=$(FREESTYLE_API_KEY=leak NPM_TOKEN=leak TAR_OPTIONS=leak GZIP=leak \
  run_script "$fixture_pin" env-check "$fixture")
expect_status "$status" 0 "helper minimal environment"
expect_calls 'create fs fs fs exec exec exec delete ' "helper minimal environment"
expect_tmp_clean "helper minimal environment"

# --- an escaping helper cannot redirect the harness's own files -------------
# The helper plants ../runner.sh and ../tree.list beside both its extraction
# directory and the archive. The harness must not write through either name.
escape_victim=$test_dir/escape-victim.txt
printf 'do-not-touch\n' > "$escape_victim"
escape_sum=$(sha256_file "$escape_victim")
export HS_ESCAPE_VICTIM=$escape_victim
status=$(run_script "$fixture_pin" escape "$fixture")
unset HS_ESCAPE_VICTIM
expect_status "$status" 0 "escaping helper"
expect_calls 'create fs fs fs exec exec exec delete ' "escaping helper"
expect_tmp_clean "escaping helper"
[ "$(sha256_file "$escape_victim")" = "$escape_sum" ] ||
  fail "The escaping helper rewrote an outside file through a planted symlink."

# --- a symlink planted at the runner path is not followed --------------------
race_victim=$test_dir/race-victim.txt
printf 'race-do-not-touch\n' > "$race_victim"
race_sum=$(sha256_file "$race_victim")
status=$(HS_EXTRA_PATH=$race_shim HS_RACE_VICTIM=$race_victim \
  run_script "$fixture_pin" ok "$fixture")
unset HS_EXTRA_PATH HS_RACE_VICTIM
expect_status "$status" 1 "runner path symlink race"
expect_no_vm "runner path symlink race"
expect_tmp_clean "runner path symlink race"
expect_grep 'Cannot create the private runner file' "$test_dir/run.log" \
  "runner path symlink race"
[ "$(sha256_file "$race_victim")" = "$race_sum" ] ||
  fail "The runner path symlink race rewrote an outside file."

# --- cleanup does not follow a substituted private root ----------------------
# A same-user racer replaces a private root with a symlink to a directory
# outside the harness. Cleanup must not chmod or remove through the link. It
# must unlink only that name and report the substitution as a cleanup failure.
sub_victim=$test_dir/substitute-victim
mkdir -p "$sub_victim/secret"
printf 'substitute-do-not-touch\n' > "$sub_victim/secret/file"
chmod 500 "$sub_victim/secret"
chmod 400 "$sub_victim/secret/file"
sub_sum=$(sha256_file "$sub_victim/secret/file")
sub_dir_mode=$(file_mode "$sub_victim/secret")
sub_file_mode=$(file_mode "$sub_victim/secret/file")
for root_kind in helper work; do
  late_flag=$test_dir/substitute-$root_kind.flag
  rm -f "$late_flag"
  if [ "$root_kind" = helper ]; then
    status=$(HS_SUBSTITUTE_ROOT=$root_kind HS_SUBSTITUTE_TMP=$tmp \
      HS_SUBSTITUTE_VICTIM=$sub_victim run_script "$fixture_pin" ok "$fixture")
  else
    status=$(HS_LATE_SUBSTITUTE_ROOT=$root_kind HS_LATE_SUBSTITUTE_TMP=$tmp \
      HS_LATE_SUBSTITUTE_VICTIM=$sub_victim HS_LATE_SUBSTITUTE_FLAG=$late_flag \
      run_script "$fixture_pin" ok "$fixture")
    [ -e "$late_flag" ] || fail "The late $root_kind substitution did not run."
  fi
  expect_status "$status" 1 "substituted $root_kind root"
  expect_calls 'create fs fs fs exec exec exec delete ' "substituted $root_kind root"
  expect_tmp_clean "substituted $root_kind root"
  expect_grep 'replaced private path' "$test_dir/run.log" "substituted $root_kind root"
  [ "$(sha256_file "$sub_victim/secret/file")" = "$sub_sum" ] ||
    fail "Cleanup wrote through the substituted $root_kind root."
  [ "$(file_mode "$sub_victim/secret")" = "$sub_dir_mode" ] ||
    fail "Cleanup changed a directory mode through the substituted $root_kind root."
  [ "$(file_mode "$sub_victim/secret/file")" = "$sub_file_mode" ] ||
    fail "Cleanup changed a file mode through the substituted $root_kind root."
done
chmod 700 "$sub_victim/secret" "$sub_victim/secret/file"

# --- the caller's archive changes after the private copy ---------------------
# A fake cp appends to the caller's file only after the private copy exists.
# The run must still succeed from the private copy and upload those bytes.
after_copy=$fixtures/tamper-after-copy.tar.gz
cp "$fixture" "$after_copy"
after_copy_pin=$(sha256_file "$after_copy")
flag=$test_dir/tamper-after-copy.flag
rm -f "$flag"
export HS_TAMPER_AFTER_COPY=1
export HS_TAMPER_SOURCE=$after_copy
export HS_TAMPER_FLAG=$flag
status=$(run_script "$after_copy_pin" ok "$after_copy")
unset HS_TAMPER_AFTER_COPY HS_TAMPER_SOURCE HS_TAMPER_FLAG
expect_status "$status" 0 "tamper after copy"
expect_calls 'create fs fs fs exec exec exec delete ' "tamper after copy"
expect_tmp_clean "tamper after copy"
[ -e "$flag" ] || fail "The after-copy tamper did not run."
[ "$(sha256_file "$after_copy")" != "$after_copy_pin" ] ||
  fail "The caller's archive was not changed during the after-copy case."
first_fs=$(head -1 "$HS_FS_LOG")
[ "${first_fs%% *}" = "$after_copy_pin" ] ||
  fail "The upload did not use the verified private copy after the original changed."
case "${first_fs#* }" in
  *hotspotshade-vm-input.*) ;;
  *) fail "The upload did not come from the private work directory after the original changed." ;;
esac
case "$(head -1 "$HS_HELPER_LOG")" in
  *hotspotshade-vm-input.*) ;;
  *) fail "The helper did not verify the private copy after the original changed." ;;
esac

# --- the helper changes after the pinned private copy ------------------------
# The pinned copy already exists. A later change to the repository file must
# not affect the run, and the run must execute the pinned copy.
helper_backup=$test_dir/source_snapshot.backup
cp "$scripts_dir/source_snapshot.sh" "$helper_backup"
helper_before=$(sha256_file "$scripts_dir/source_snapshot.sh")
helper_source=$(CDPATH= cd "$scripts_dir" && pwd -P)/source_snapshot.sh
flag=$test_dir/tamper-helper.flag
rm -f "$flag"
export HS_TAMPER_AFTER_COPY=1
export HS_TAMPER_SOURCE=$helper_source
export HS_TAMPER_FLAG=$flag
status=$(run_script "$fixture_pin" ok "$fixture")
unset HS_TAMPER_AFTER_COPY HS_TAMPER_SOURCE HS_TAMPER_FLAG
helper_after=$(sha256_file "$scripts_dir/source_snapshot.sh")
cp "$helper_backup" "$scripts_dir/source_snapshot.sh"
chmod +x "$scripts_dir/source_snapshot.sh"
expect_status "$status" 0 "helper changed after copy"
expect_calls 'create fs fs fs exec exec exec delete ' "helper changed after copy"
expect_tmp_clean "helper changed after copy"
[ -e "$flag" ] || fail "The helper after-copy tamper did not run."
[ "$(sha256_file "$helper_backup")" = "$helper_before" ] ||
  fail "The helper backup did not keep the pinned bytes."
[ "$helper_after" != "$helper_before" ] ||
  fail "The helper source was not changed during the after-copy case."

# --- the helper is missing ---------------------------------------------------
mv "$scripts_dir/source_snapshot.sh" "$scripts_dir/source_snapshot.sh.off"
status=$(run_script "$fixture_pin" ok "$fixture")
mv "$scripts_dir/source_snapshot.sh.off" "$scripts_dir/source_snapshot.sh"
expect_status "$status" 1 "missing helper"
expect_no_vm "missing helper"
expect_tmp_clean "missing helper"
expect_grep 'Missing or non-executable snapshot helper' "$test_dir/run.log" "missing helper"

# --- a private input changed before the transfer is refused ------------------
# A same-user racer changes the private archive, helper copy, runner, or file
# manifest after creation and before the final rehash. No VM may be created.
for tamper_kind in archive helper runner manifest; do
  final_flag=$test_dir/final-tamper.flag
  rm -f "$final_flag"
  status=$(HS_EXTRA_PATH=$final_shim HS_FINAL_TAMPER=$tamper_kind \
    HS_FINAL_TAMPER_TMP=$tmp HS_FINAL_TAMPER_FLAG=$final_flag \
    run_script "$fixture_pin" ok "$fixture")
  expect_status "$status" 1 "final $tamper_kind change"
  expect_no_vm "final $tamper_kind change"
  expect_tmp_clean "final $tamper_kind change"
  [ -e "$final_flag" ] || fail "The final $tamper_kind tamper did not run."
  case "$tamper_kind" in
    archive) expected_text='private archive changed before the transfer' ;;
    helper) expected_text='pinned private helper copy changed before the transfer' ;;
    runner) expected_text='private runner changed before the transfer' ;;
    manifest) expected_text='verified file manifest changed before the transfer' ;;
  esac
  expect_grep "$expected_text" "$test_dir/run.log" "final $tamper_kind change"
done

# --- a changed runner is caught after the upload -----------------------------
export HS_TAMPER_UPLOAD=/home/ubuntu/hotspotshade-vm-run.sh
status=$(run_script "$fixture_pin" ok "$fixture")
unset HS_TAMPER_UPLOAD
expect_status "$status" 1 "changed runner"
expect_calls 'create fs fs fs delete ' "changed runner"
expect_tmp_clean "changed runner"
expect_grep 'private runner changed during the upload' "$test_dir/run.log" "changed runner"

# --- a changed archive or manifest is caught after the upload ----------------
export HS_TAMPER_UPLOAD=/home/ubuntu/hotspotshade-source.tar.gz
status=$(run_script "$fixture_pin" ok "$fixture")
unset HS_TAMPER_UPLOAD
expect_status "$status" 1 "changed archive upload"
expect_calls 'create fs fs fs delete ' "changed archive upload"
expect_tmp_clean "changed archive upload"
expect_grep 'private archive changed during the upload' "$test_dir/run.log" \
  "changed archive upload"

export HS_TAMPER_UPLOAD=/home/ubuntu/hotspotshade-vm-files.sha256
status=$(run_script "$fixture_pin" ok "$fixture")
unset HS_TAMPER_UPLOAD
expect_status "$status" 1 "changed manifest upload"
expect_calls 'create fs fs fs delete ' "changed manifest upload"
expect_tmp_clean "changed manifest upload"
expect_grep 'verified file manifest changed during the upload' "$test_dir/run.log" \
  "changed manifest upload"

# --- an injected VM failure still deletes the VM -----------------------------
status=$(run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 0 "pre-failure baseline"
status=$(HS_VM_FAIL_PHASE=create run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 19 "create failure"
expect_calls 'create delete ' "create failure"
status=$(HS_VM_FAIL_PHASE=fs run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 19 "fs failure"
expect_calls 'create fs delete ' "fs failure"
status=$(HS_VM_FAIL_PHASE=exec run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 19 "exec failure"
expect_calls 'create fs fs fs exec delete ' "exec failure"
expect_tmp_clean "injected VM failures"

# --- an interrupted create still deletes the VM ------------------------------
# The shim logs the create (the server accepted it), then signals the script's
# own shell. The signal trap must reach the same cleanup path.
status=$(HS_SIGNAL_CREATE=TERM run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 143 "interrupted create"
expect_calls 'create delete ' "interrupted create"
expect_tmp_clean "interrupted create"

# --- a signal during delete does not cut the delete short --------------------
status=$(HS_SIGNAL_DELETE=TERM run_script "$fixture_pin" ok "$fixture")
expect_status "$status" 0 "signal during delete"
expect_calls 'create fs fs fs exec exec exec delete ' "signal during delete"
expect_tmp_clean "signal during delete"

# --- the real snapshot helper contract ---------------------------------------
# The harness copies no sidecar. The real helper verifies a sidecar-less
# archive, creates an absent extraction destination, and refuses an existing
# directory or symlink. Every failure must stop before a VM exists.
real_helper=$repo_dir/scripts/source_snapshot.sh
if [ -f "$real_helper" ] && [ -x "$real_helper" ] && [ ! -L "$real_helper" ]; then
  real_scripts=$test_dir/real-scripts
  real_payload=$test_dir/real-payload
  probe_root=$test_dir/probe
  probe_tmp=$test_dir/probe-tmp
  mkdir -p "$real_scripts" "$real_payload/rust/src" "$probe_root" "$probe_tmp"
  cp "$repo_dir/scripts/linux_vm_test.sh" "$real_scripts/linux_vm_test.sh"
  cp "$real_helper" "$real_scripts/source_snapshot.sh"
  chmod +x "$real_scripts/source_snapshot.sh"
  real_helper_pin=$(sha256_file "$real_scripts/source_snapshot.sh")
  # A minimal ustar archive with one regular file. It is a valid input for the
  # revised contract and carries no sidecar.
  printf 'pub fn fixture() {}\n' > "$real_payload/rust/src/lib.rs"
  chmod 644 "$real_payload/rust/src/lib.rs"
  # The helper pins the modification time to the fixed build time, as the
  # snapshot builder does with the same touch call.
  TZ=UTC touch -t 200001010000.00 "$real_payload/rust/src/lib.rs"
  real_archive=$probe_root/archive.tar.gz
  if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar --format=ustar --owner=0 --group=0 --numeric-owner \
      -czf "$real_archive" -C "$real_payload" rust/src/lib.rs
  else
    tar --format=ustar --uid 0 --gid 0 --uname '' --gname '' \
      -czf "$real_archive" -C "$real_payload" rust/src/lib.rs
  fi
  real_pin=$(sha256_file "$real_archive")

  # An existing directory is refused, unchanged, before the helper extracts.
  probe_existing=$probe_root/existing
  mkdir "$probe_existing"
  probe_status=0
  TMPDIR="$probe_tmp" "$real_scripts/source_snapshot.sh" \
    --verify "$real_archive" --expect-sha256 "$real_pin" \
    --extract-to "$probe_existing" \
    >"$test_dir/probe-existing.log" 2>&1 || probe_status=$?
  [ "$probe_status" -ne 0 ] ||
    fail "The real snapshot helper accepted an existing extraction directory."
  expect_grep 'extraction destination already exists' \
    "$test_dir/probe-existing.log" "real helper existing destination"
  [ -z "$(find "$probe_existing" -mindepth 1 -print)" ] ||
    fail "The real snapshot helper wrote into an existing destination."
  rmdir "$probe_existing"

  # A symlink destination is refused, and its target stays unchanged.
  probe_victim=$probe_root/symlink-victim.txt
  printf 'probe-do-not-touch\n' > "$probe_victim"
  probe_sum=$(sha256_file "$probe_victim")
  probe_link=$probe_root/extract-link
  ln -s "$probe_victim" "$probe_link"
  probe_status=0
  TMPDIR="$probe_tmp" "$real_scripts/source_snapshot.sh" \
    --verify "$real_archive" --expect-sha256 "$real_pin" \
    --extract-to "$probe_link" \
    >"$test_dir/probe-symlink.log" 2>&1 || probe_status=$?
  [ "$probe_status" -ne 0 ] ||
    fail "The real snapshot helper accepted a symlink extraction destination."
  expect_grep 'extraction destination already exists' \
    "$test_dir/probe-symlink.log" "real helper symlink destination"
  [ -L "$probe_link" ] ||
    fail "The real snapshot helper replaced the extraction symlink."
  [ "$(sha256_file "$probe_victim")" = "$probe_sum" ] ||
    fail "The real snapshot helper wrote through the extraction symlink."
  rm -f "$probe_link"

  # The absent destination succeeds and holds the verified tree.
  probe_status=0
  TMPDIR="$probe_tmp" "$real_scripts/source_snapshot.sh" \
    --verify "$real_archive" --expect-sha256 "$real_pin" \
    --extract-to "$probe_root/extract" \
    >"$test_dir/probe.log" 2>&1 || probe_status=$?
  if [ "$probe_status" -ne 0 ]; then
    cat -v "$test_dir/probe.log" >&2
    fail "The real snapshot helper rejected the revised sidecar-less contract."
  fi
  [ -f "$probe_root/extract/rust/src/lib.rs" ] ||
    fail "The real snapshot helper did not create the absent destination."

  # The harness accepts the same real helper with an absent destination.
  status=$(HS_HELPER_PIN="$real_helper_pin" run_script_in "$real_scripts" \
    "$real_pin" ok "$real_archive")
  expect_status "$status" 0 "real helper compatible"
  expect_calls 'create fs fs fs exec exec exec delete ' "real helper compatible"
  expect_tmp_clean "real helper compatible"
  expect_grep 'local_verification: passed' "$test_dir/run.log" "real helper compatible"
  expect_no_grep 'Snapshot verification failed' "$test_dir/run.log" "real helper compatible"

  # A real helper failure stops before the VM. The archive bytes match the
  # external pin, so the helper itself rejects the structure.
  bad_real=$probe_root/not-a-snapshot.tar.gz
  printf 'not a gzip stream\n' > "$bad_real"
  bad_real_pin=$(sha256_file "$bad_real")
  status=$(HS_HELPER_PIN="$real_helper_pin" run_script_in "$real_scripts" \
    "$bad_real_pin" ok "$bad_real")
  expect_status "$status" 1 "real helper verification failure"
  expect_no_vm "real helper verification failure"
  expect_tmp_clean "real helper verification failure"
  expect_grep 'Snapshot verification failed. No VM was created.' \
    "$test_dir/run.log" "real helper verification failure"

  # A destination planted inside the real helper run is refused before the
  # helper runs and before a VM exists.
  for plant in existing symlink; do
    status=$(HS_HELPER_PIN="$real_helper_pin" HS_EXTRA_PATH=$mktemp_shim \
      HS_PLANT_DEST=$plant HS_PLANT_TARGET=$probe_victim \
      run_script_in "$real_scripts" "$real_pin" ok "$real_archive")
    expect_status "$status" 1 "real helper planted $plant destination"
    expect_no_vm "real helper planted $plant destination"
    expect_no_helper "real helper planted $plant destination"
    expect_tmp_clean "real helper planted $plant destination"
    expect_grep 'private verified tree path already exists' "$test_dir/run.log" \
      "real helper planted $plant destination"
  done
  [ "$(sha256_file "$probe_victim")" = "$probe_sum" ] ||
    fail "A planted real helper destination rewrote an outside file."
else
  echo "Skipping the real snapshot helper case: not executable." >&2
fi

echo "Linux VM transfer-gate tests passed."

# ---------------------------------------------------------------------------
# Static guards
# ---------------------------------------------------------------------------
if grep -q 'sort | tail -1' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script still selects a tunnel binary by sort order."
fi
if ! grep -q -- '--expect-sha256' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script does not pass the external pin to the snapshot helper."
fi
if ! grep -q 'HOTSPOTSHADE_SNAPSHOT_SHA256' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script does not document the external digest pin."
fi
if ! grep -q -- '--helper-sha256' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script does not accept an external snapshot helper digest."
fi
if ! grep -q 'HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script does not document the external helper digest pin."
fi
if ! grep -q 'hotspotshade-vm-helper' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The helper extraction root is not separate from the harness artifacts."
fi
if ! grep -qF 'chmod 700 "$helper_root"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The helper extraction root is not restricted to the owner."
fi
if grep -qF 'mkdir -m 700 "$verified_tree"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script pre-creates the helper extraction destination."
fi
if ! grep -qF 'if [ -e "$verified_tree" ] || [ -L "$verified_tree" ]; then' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script does not require an absent extraction destination."
fi
if grep -qF 'cp -P "$source_archive" "$private_archive"' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The private archive is copied to a predictable destination path."
fi
if grep -qF 'cp -P "$snapshot_helper" "$helper_copy"' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The private helper copy uses a predictable destination path."
fi
if ! grep -qF 'new_private_file "$input_dir" "$source_base"' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The private archive is not created with an exclusive name."
fi
if ! grep -qF 'new_private_file "$helper_bin_dir" source_snapshot.sh' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The private helper copy is not created with an exclusive name."
fi
if ! grep -qF 'cp -P -- "$source_archive" /dev/fd/9' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The archive copy does not write through the exclusive descriptor."
fi
if ! grep -qF 'cp -P -- "$snapshot_helper" /dev/fd/9' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The helper copy does not write through the exclusive descriptor."
fi
if ! grep -qF 'remove_private_dir "$dir"' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "Cleanup does not check each private root before it walks it."
fi
if ! grep -qF 'find "$dir" -type d -exec chmod u+rwx' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "Cleanup does not restore owner modes without following symlinks."
fi
if ! grep -qF 'Refusing to change permissions through the replaced private path' \
  "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "Cleanup does not report a substituted private root."
fi
if grep -q 'tree_list' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script still writes an inspection list through a reusable name."
fi
if ! grep -q 'new_private_file "\$artifact_root" run' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The runner is not created with a no-follow exclusive create."
fi
if ! grep -q 'set -C' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The private file create does not use noclobber."
fi
if ! grep -q 'exec 9>"\$new_file"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The private file create does not open a fixed descriptor."
fi
if ! grep -q 'sha256sum \$remote_runner' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The launcher does not bind the uploaded runner digest."
fi
if ! grep -q -- '-xzf "\$archive_copy"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The remote extraction does not use the private archive copy."
fi
if ! grep -q -- 'tar -m --no-same-owner' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The remote extraction does not reset archived file times with -m."
fi
if ! grep -q 'cmp -s "\$tree_manifest" "\$manifest_copy"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The remote extraction is not compared with the reviewed file manifest."
fi
if grep -q 'HOME/hotspotshade/rust/target' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The remote runner still uses the shared Cargo target directory."
fi
if ! grep -q -- '--target-dir "\$build_target"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The general Cargo commands do not force the fresh target directory."
fi
if ! grep -q -- '--target-dir "\$desktop_target"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The desktop Cargo test does not force the fresh target directory."
fi
if ! grep -q -- '--target-dir "\$tunnel_target"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The tunnel Cargo build does not force the fresh target directory."
fi
if ! grep -q 'NoNewPrivs:' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The remote runner does not verify no_new_privs."
fi
if ! grep -q 'setpriv --reuid=ubuntu' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The launcher does not drop to the non-root image user."
fi
if ! grep -q -- '--no-new-privs' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The general runner does not set no_new_privs."
fi
if ! grep -q 'hotspotshade-vm-status' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The status file is not in the root-owned status directory."
fi
if grep -q 'hotspotshade-vm-test.exit' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The old fixed status file is still present."
fi
if ! grep -q 'HOTSPOTSHADE_VM_TRANSFER_APPROVED' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The transfer gate is not gated on an explicit approval value."
fi
if ! grep -q "trap '' INT TERM HUP" "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "Cleanup does not ignore signals while it deletes the VM."
fi
if ! grep -q 'env -i' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The snapshot helper is not started with a minimal environment."
fi
if ! grep -q 'cat -v' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "Helper or test output is not sanitized before display."
fi
if grep -qF 'chmod 700 -- "\$runner_root"' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The runner directory is mode 700, so the unprivileged runner cannot read it."
fi
if ! grep -qF "printf '%s running\n' '\$vm_slug'" "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The monitor status does not carry the run slug."
fi
if ! grep -qF "printf '%s %s\\n' '\$vm_slug' \"\\\$st\"" "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The final monitor status does not carry the run slug."
fi
if ! grep -qF 'sudo -n rm -rf -- %s || exit 1; setsid' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The launch command does not reset the status directory in the foreground."
fi
create_order=$(awk '
  /vm_maybe_created=1/ { mark = NR }
  /vm create/ { create = NR }
  END { if (mark && create && mark < create) print "ok" }
' "$repo_dir/scripts/linux_vm_test.sh")
if [ "$create_order" != ok ]; then
  fail "The VM create attempt is not marked before the create call."
fi
if grep -qE '\$\{?(source_archive|archive)\}?\.(files\.)?sha256' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The VM script reads an archive sidecar instead of the external pin."
fi
if ! grep -q 'sudo -n -E env HS_DISPOSABLE_LINUX_VM=1' "$repo_dir/scripts/linux_vm_test.sh"; then
  fail "The tunnel run does not pass HS_DISPOSABLE_LINUX_VM=1 to the test binary."
fi
bad_setting=$(awk '
  /^[[:space:]]*#/ { next }
  /HS_DISPOSABLE_LINUX_VM=/ && !/sudo -n -E env HS_DISPOSABLE_LINUX_VM=1/ { print NR ": " $0 }
' "$repo_dir/scripts/linux_vm_test.sh")
if [ -n "$bad_setting" ]; then
  fail "HS_DISPOSABLE_LINUX_VM is set outside the tunnel run: $bad_setting"
fi

# ---------------------------------------------------------------------------
# Remote harness
#
# The remote script must verify the uploaded bytes against the pin before it
# lists or extracts anything. It must also reject unsafe archive entries. The
# harness below runs the real remote script with a logging tar wrapper, so the
# listing, shape checks, and extraction really happen in a private test tree.
# ---------------------------------------------------------------------------
harness=$test_dir/harness
mkdir -p "$harness/bin" "$harness/home/hotspotshade/rust/target/debug/deps" \
  "$harness/ubuntu" "$harness/payload/rust/src"
printf 'pub fn fixture() {}\n' > "$harness/payload/rust/src/lib.rs"
tar -czf "$harness/ubuntu/source.tar.gz" -C "$harness/payload" rust/src/lib.rs
remote_pin=$(sha256_file "$harness/ubuntu/source.tar.gz")
printf '%s  %s\n' "$(sha256_file "$harness/payload/rust/src/lib.rs")" \
  "rust/src/lib.rs" > "$harness/ubuntu/files.sha256"
remote_manifest_pin=$(sha256_file "$harness/ubuntu/files.sha256")

# Extract the remote script from the quoted heredoc in the VM script.
awk '/^cat >&"\$runner_fd" <<.REMOTE.$/ { inside = 1; next } /^REMOTE$/ { inside = 0 } inside' \
  "$repo_dir/scripts/linux_vm_test.sh" > "$harness/remote.raw"
if [ ! -s "$harness/remote.raw" ]; then
  fail "Cannot extract the remote script from scripts/linux_vm_test.sh."
fi
# Point the absolute paths at the test directory.
sed -e "s#/tmp/hotspotshade-#$harness/hs-#g" \
    -e "s#/tmp/hs-cargo\.#$harness/hs-cargo.#g" \
    -e "s#/tmp/hs-desktop-target#$harness/hs-desktop-target#g" \
    -e "s#/tmp/hs-tunnel-target#$harness/hs-tunnel-target#g" \
    -e "s#/home/ubuntu/hotspotshade-source.tar.gz#$harness/ubuntu/source.tar.gz#g" \
    -e "s#/home/ubuntu/hotspotshade-vm-files.sha256#$harness/ubuntu/files.sha256#g" \
    -e "s#/proc/self/status#$harness/proc-status#g" \
    "$harness/remote.raw" > "$harness/remote.sh"

# The runner reads /proc/self/status to check no_new_privs. The test points it at
# a file so each state can be set.
printf 'Name:\tbash\nNoNewPrivs:\t1\n' > "$harness/proc-status"

# A stale binary from an older archive. Nothing may execute it.
cat > "$harness/home/hotspotshade/rust/target/debug/deps/linux_tunnel_vm-ffffffffffff" <<'EOF'
#!/bin/sh
echo "STALE BINARY RAN"
EOF
chmod +x "$harness/home/hotspotshade/rust/target/debug/deps/linux_tunnel_vm-ffffffffffff"
cat > "$harness/home/hotspotshade/rust/target/debug/deps/stale-general" <<'EOF'
#!/bin/sh
echo "STALE GENERAL CACHE RAN"
EOF
chmod +x "$harness/home/hotspotshade/rust/target/debug/deps/stale-general"

cat > "$harness/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$HS_CARGO_LOG"
printf '%s\n' "${CARGO_TARGET_DIR:-unset}" >> "$HS_TARGET_LOG"
# If a regression points Cargo at the image's shared cache, run its stale
# marker so the test can see that the old build was reused.
case "${CARGO_TARGET_DIR:-}" in
  *home/hotspotshade/rust/target*)
    if [ -x "$CARGO_TARGET_DIR/debug/deps/stale-general" ]; then
      "$CARGO_TARGET_DIR/debug/deps/stale-general"
    fi
    ;;
esac
case " $* " in
  *" --test linux_tunnel_vm "*)
    mkdir -p "$CARGO_TARGET_DIR/debug/deps"
    cat > "$CARGO_TARGET_DIR/debug/deps/linux_tunnel_vm-0123456789abcdef" <<'TESTBIN'
#!/bin/sh
printf '%s\n' "$*" > "$HS_TEST_ARGS"
printf '%s\n' "${HS_DISPOSABLE_LINUX_VM:-unset}" > "$HS_TEST_CONSENT"
echo "running the fresh tunnel binary"
echo "${HS_FAKE_RESULT:-test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.10s}"
TESTBIN
    chmod +x "$CARGO_TARGET_DIR/debug/deps/linux_tunnel_vm-0123456789abcdef"
    printf '#!/bin/sh\n' > "$CARGO_TARGET_DIR/debug/hotspotshade"
    chmod +x "$CARGO_TARGET_DIR/debug/hotspotshade"
    ;;
esac
exit 0
EOF
chmod +x "$harness/bin/cargo"

cat > "$harness/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -eu
while [ $# -gt 0 ]; do
  case "$1" in
    -n|-E|-) shift ;;
    -*) shift ;;
    *) break ;;
  esac
done
exec "$@"
EOF
chmod +x "$harness/bin/sudo"

cat > "$harness/bin/node" <<'EOF'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$HS_NODE_LOG"
exit 0
EOF
chmod +x "$harness/bin/node"

cat > "$harness/bin/ip" <<'EOF'
#!/bin/sh
if [ -n "${HS_FAKE_IP_FAIL:-}" ] && [ "$*" = "$HS_FAKE_IP_FAIL" ]; then
  exit 1
fi
exit 0
EOF
chmod +x "$harness/bin/ip"

HS_REAL_UNIQ=$(command -v uniq)
export HS_REAL_UNIQ
cat > "$harness/bin/uniq" <<'EOF'
#!/bin/sh
if [ "${HS_FAIL_DUP_UNIQ:-0}" = 1 ] && [ "${1:-}" = -d ]; then
  exit 1
fi
exec "$HS_REAL_UNIQ" "$@"
EOF
chmod +x "$harness/bin/uniq"

real_tar=$(command -v tar)
cat > "$harness/bin/tar" <<'EOF'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$HS_TAR_LOG"
exec "$HS_REAL_TAR" "$@"
EOF
chmod +x "$harness/bin/tar"

HS_CARGO_LOG=$harness/cargo.log
HS_TARGET_LOG=$harness/target.log
HS_TEST_ARGS=$harness/test-args.log
HS_TEST_CONSENT=$harness/consent.log
HS_TAR_LOG=$harness/tar.log
HS_NODE_LOG=$harness/node.log
HS_REAL_TAR=$real_tar
export HS_CARGO_LOG HS_TARGET_LOG HS_TEST_ARGS HS_TEST_CONSENT HS_TAR_LOG HS_NODE_LOG HS_REAL_TAR

run_remote() {
  local remote_mode=$1 digest=$2 manifest_digest=${3:-$remote_manifest_pin} status=0
  : > "$HS_CARGO_LOG"
  : > "$HS_TARGET_LOG"
  : > "$HS_TEST_ARGS"
  : > "$HS_TEST_CONSENT"
  : > "$HS_TAR_LOG"
  : > "$HS_NODE_LOG"
  PATH="$harness/bin:$PATH" HOME="$harness/home" \
    bash "$harness/remote.sh" "$remote_mode" "$digest" "$manifest_digest" \
    > "$harness/run.log" 2>&1 || status=$?
  printf '%s' "$status"
}

# General path: both digests are checked, the archive is listed and extracted
# from a private copy, the tree is compared with the reviewed manifest, and the
# desktop and Linux demo checks run. No tunnel binary runs.
status=$(run_remote general "$remote_pin")
[ "$status" -eq 0 ] || {
  cat "$harness/run.log" >&2
  fail "The remote general harness exited $status."
}

expect_grep 'Uploaded archive SHA-256 verified' "$harness/run.log" "remote general digest"
expect_grep 'Uploaded file manifest SHA-256 verified' "$harness/run.log" "remote manifest digest"
expect_grep 'Extracted tree matches the reviewed file manifest' "$harness/run.log" \
  "remote tree manifest"
expect_grep 'rust/Cargo.toml' "$HS_CARGO_LOG" "remote general rust check"
expect_grep '--manifest-path desktop/Cargo.toml' "$HS_CARGO_LOG" "remote general desktop test"
expect_grep 'desktop/tests/fetch_shim.test.mjs' "$HS_NODE_LOG" "remote general desktop node test"
expect_grep 'linux/test/' "$HS_NODE_LOG" "remote general linux node test"
[ ! -s "$HS_TEST_ARGS" ] || fail "The general remote path ran the tunnel binary."
[ ! -s "$HS_TEST_CONSENT" ] || fail "The general remote path set the tunnel consent."
expect_grep '-xzf' "$HS_TAR_LOG" "remote general extraction"
# Every tar call reads the private copy, never the upload path.
expect_grep 'hs-meta\..*/input.tar.gz' "$HS_TAR_LOG" "remote private archive copy"
if grep -q 'ubuntu/source.tar.gz' "$HS_TAR_LOG"; then
  fail "The remote script read the upload path directly: $(cat "$HS_TAR_LOG")"
fi
expect_grep '--no-same-owner' "$HS_TAR_LOG" "remote extraction owner flag"
expect_grep '^-m ' "$HS_TAR_LOG" "remote extraction mtime reset"
if grep -q 'home/hotspotshade/rust/target' "$HS_TARGET_LOG"; then
  fail "The general remote path used the shared Cargo target: $(cat "$HS_TARGET_LOG")"
fi
expect_grep "$harness/hs-cargo\." "$HS_TARGET_LOG" "general fresh target"
expect_grep "$harness/hs-desktop-target" "$HS_TARGET_LOG" "desktop fresh target"
expect_grep '--target-dir' "$HS_CARGO_LOG" "explicit fresh target"
expect_no_grep 'STALE GENERAL CACHE RAN' "$harness/run.log" "general stale cache"
if ls "$harness"/hs-cargo.* >/dev/null 2>&1; then
  fail "The general Cargo target directory was not removed."
fi
if ls "$harness"/hs-desktop-target.* >/dev/null 2>&1; then
  fail "The desktop Cargo target directory was not removed."
fi

status=$(HS_FAIL_DUP_UNIQ=1 run_remote general "$remote_pin")
[ "$status" -ne 0 ] || fail "A failed duplicate-path check was accepted."
expect_grep 'Cannot check the archive for duplicate paths' "$harness/run.log" "failed duplicate check"
[ ! -s "$HS_CARGO_LOG" ] || fail "The duplicate-check failure ran cargo."

# The general runner must prove no_new_privs. A readable status that says 0, a
# status with no such line, and an unreadable status all fail closed before any
# archive work. The tunnel diagnostic is exempt because it needs sudo.
cp "$harness/proc-status" "$harness/proc-status.good"
printf 'Name:\tbash\nNoNewPrivs:\t0\n' > "$harness/proc-status"
status=$(run_remote general "$remote_pin")
[ "$status" -ne 0 ] || fail "The remote runner accepted NoNewPrivs 0."
expect_grep 'did not start with no_new_privs' "$harness/run.log" "remote NoNewPrivs 0"
[ ! -s "$HS_TAR_LOG" ] || fail "The remote runner extracted with NoNewPrivs 0."
[ ! -s "$HS_CARGO_LOG" ] || fail "The remote runner ran cargo with NoNewPrivs 0."
printf 'Name:\tbash\n' > "$harness/proc-status"
status=$(run_remote general "$remote_pin")
[ "$status" -ne 0 ] || fail "The remote runner accepted a status with no NoNewPrivs line."
expect_grep 'did not start with no_new_privs' "$harness/run.log" "remote NoNewPrivs missing"
[ ! -s "$HS_CARGO_LOG" ] || fail "The remote runner ran cargo with no NoNewPrivs line."
rm -f "$harness/proc-status"
status=$(run_remote general "$remote_pin")
[ "$status" -ne 0 ] || fail "The remote runner accepted an unreadable /proc/self/status."
expect_grep 'Cannot read .*proc-status to check no_new_privs' "$harness/run.log" "remote NoNewPrivs unreadable"
[ ! -s "$HS_TAR_LOG" ] || fail "The remote runner extracted with an unreadable status."
[ ! -s "$HS_CARGO_LOG" ] || fail "The remote runner ran cargo with an unreadable status."
cp "$harness/proc-status.good" "$harness/proc-status"

# Remote mismatch: the VM must refuse before listing or extracting.
status=$(run_remote general "$zero_pin")
[ "$status" -ne 0 ] || fail "The remote harness accepted a wrong archive digest."
expect_grep 'does not match the pinned digest' "$harness/run.log" "remote mismatch"
[ ! -s "$HS_TAR_LOG" ] || fail "The remote mismatch case invoked tar: $(cat "$HS_TAR_LOG")"
[ ! -s "$HS_CARGO_LOG" ] || fail "The remote mismatch case ran cargo."
[ ! -s "$HS_NODE_LOG" ] || fail "The remote mismatch case ran node."
leftover=$(find "$harness" -maxdepth 1 \( -name 'hs-test.*' -o -name 'hs-meta.*' \) -print)
[ -z "$leftover" ] || fail "The remote mismatch case left a private directory: $leftover"

# Remote manifest mismatch: a correct archive does not excuse a changed file
# manifest. The VM must refuse before listing or extracting.
status=$(run_remote general "$remote_pin" "$zero_pin")
[ "$status" -ne 0 ] || fail "The remote harness accepted a wrong file manifest digest."
expect_grep 'file manifest SHA-256 does not match the pinned digest' \
  "$harness/run.log" "remote manifest mismatch"
[ ! -s "$HS_TAR_LOG" ] || fail "The remote manifest mismatch case invoked tar."
[ ! -s "$HS_CARGO_LOG" ] || fail "The remote manifest mismatch case ran cargo."
[ ! -s "$HS_NODE_LOG" ] || fail "The remote manifest mismatch case ran node."

# Remote tree mismatch: both digests hold, but the extracted bytes differ from
# the reviewed manifest. The VM must refuse before it runs any test command.
cp "$harness/ubuntu/files.sha256" "$harness/ubuntu/files.good.sha256"
printf '%s  %s\n' "$zero_pin" "rust/src/lib.rs" > "$harness/ubuntu/files.sha256"
alt_manifest_pin=$(sha256_file "$harness/ubuntu/files.sha256")
status=$(run_remote general "$remote_pin" "$alt_manifest_pin")
cp "$harness/ubuntu/files.good.sha256" "$harness/ubuntu/files.sha256"
[ "$status" -ne 0 ] || fail "The remote harness accepted a tree that differs from the manifest."
expect_grep 'does not match the reviewed file manifest' "$harness/run.log" "remote tree mismatch"
[ ! -s "$HS_CARGO_LOG" ] || fail "The remote tree mismatch case ran cargo."
[ ! -s "$HS_NODE_LOG" ] || fail "The remote tree mismatch case ran node."
[ "$(sha256_file "$harness/ubuntu/files.sha256")" = "$remote_manifest_pin" ] ||
  fail "The good file manifest was not restored after the mismatch case."

# Remote shape: a correct digest does not excuse a symlink entry. The VM must
# list and reject the entry before extraction.
cp "$harness/ubuntu/source.tar.gz" "$harness/ubuntu/source.good.tar.gz"
mkdir -p "$harness/bad/rust"
ln -s /etc/passwd "$harness/bad/rust/link"
tar -czf "$harness/ubuntu/source.tar.gz" -C "$harness/bad" rust/link
bad_pin=$(sha256_file "$harness/ubuntu/source.tar.gz")
status=$(run_remote general "$bad_pin")
[ "$status" -ne 0 ] || fail "The remote harness accepted a symlink archive with a correct digest."
expect_grep 'Unsafe archive entry type' "$harness/run.log" "remote archive shape"
if grep -q -- '-xzf' "$HS_TAR_LOG"; then
  fail "The remote shape case extracted the archive."
fi
[ ! -s "$HS_CARGO_LOG" ] || fail "The remote shape case ran cargo."
[ ! -s "$HS_NODE_LOG" ] || fail "The remote shape case ran node."
cp "$harness/ubuntu/source.good.tar.gz" "$harness/ubuntu/source.tar.gz"
[ "$(sha256_file "$harness/ubuntu/source.tar.gz")" = "$remote_pin" ] ||
  fail "The good archive was not restored after the shape case."

# Remote tar cases: correct digests do not excuse hard links, directory
# entries, absolute or parent paths, duplicates, set-id modes, or non-gzip
# input. Each case must be rejected before any test command runs.
restore_good_archive() {
  cp "$harness/ubuntu/source.good.tar.gz" "$harness/ubuntu/source.tar.gz"
  [ "$(sha256_file "$harness/ubuntu/source.tar.gz")" = "$remote_pin" ] ||
    fail "The good archive was not restored after $1."
}
run_remote_bad_archive() {
  local label=$1 expected=$2 pin status
  pin=$(sha256_file "$harness/ubuntu/source.tar.gz")
  status=$(run_remote general "$pin")
  [ "$status" -ne 0 ] || fail "The remote harness accepted $label with a correct digest."
  expect_grep "$expected" "$harness/run.log" "remote $label"
  if grep -q -- '-xzf' "$HS_TAR_LOG"; then
    fail "The remote $label case extracted the archive."
  fi
  [ ! -s "$HS_CARGO_LOG" ] || fail "The remote $label case ran cargo."
  [ ! -s "$HS_NODE_LOG" ] || fail "The remote $label case ran node."
}

bad_root=$harness/bad/hard
rm -rf "$harness/bad/hard"
mkdir -p "$bad_root"
printf 'one\n' > "$bad_root/a"
ln "$bad_root/a" "$bad_root/h"
tar -czf "$harness/ubuntu/source.tar.gz" -C "$bad_root" a h
run_remote_bad_archive "hard link" "Unsafe archive entry type"
restore_good_archive "the hard link case"

rm -rf "$harness/bad/dir"
mkdir -p "$harness/bad/dir/dir"
printf 'x\n' > "$harness/bad/dir/dir/x"
tar -czf "$harness/ubuntu/source.tar.gz" -C "$harness/bad/dir" dir
run_remote_bad_archive "directory entry" "Unsafe archive entry:"
restore_good_archive "the directory case"

tar -czf "$harness/ubuntu/source.tar.gz" -P "$bad_root/a"
run_remote_bad_archive "absolute path" "Unsafe archive entry:"
restore_good_archive "the absolute path case"

(cd "$bad_root" && tar -P -czf "$harness/ubuntu/source.tar.gz" ../hard/a)
run_remote_bad_archive "parent path" "Unsafe archive entry:"
restore_good_archive "the parent path case"

tar -czf "$harness/ubuntu/source.tar.gz" -C "$bad_root" a a
run_remote_bad_archive "duplicate path" "lists a path more than once"
restore_good_archive "the duplicate path case"

printf 'set-id\n' > "$bad_root/setid"
chmod 4755 "$bad_root/setid"
tar -czf "$harness/ubuntu/source.tar.gz" -C "$bad_root" setid
run_remote_bad_archive "set-id mode" "Unsafe archive entry mode"
restore_good_archive "the set-id case"

# A special file entry must be rejected before extraction. The post-extraction
# special-file check is defensive; the entry type check stops it first.
rm -rf "$harness/bad/fifo"
mkdir -p "$harness/bad/fifo"
mkfifo "$harness/bad/fifo/pipe"
tar -czf "$harness/ubuntu/source.tar.gz" -C "$harness/bad/fifo" pipe
run_remote_bad_archive "fifo entry" "Unsafe archive entry type"
restore_good_archive "the fifo case"

tar -cf "$harness/ubuntu/source.tar.gz" -C "$bad_root" a
nongzip_pin=$(sha256_file "$harness/ubuntu/source.tar.gz")
status=$(run_remote general "$nongzip_pin")
[ "$status" -ne 0 ] || fail "The remote harness accepted a non-gzip archive."
expect_grep 'not a valid gzip stream' "$harness/run.log" "remote non-gzip"
[ ! -s "$HS_CARGO_LOG" ] || fail "The remote non-gzip case ran cargo."
[ ! -s "$HS_NODE_LOG" ] || fail "The remote non-gzip case ran node."
restore_good_archive "the non-gzip case"

# Tunnel path: the fresh target directory, helper accounting, and consent hold.
status=$(run_remote tunnel "$remote_pin")
[ "$status" -eq 0 ] || {
  cat "$harness/run.log" >&2
  fail "The remote tunnel harness exited $status."
}
expect_grep 'Tunnel scenarios: 8 passed' "$harness/run.log" "remote tunnel count"
if grep -q 'STALE BINARY RAN' "$harness/run.log"; then
  fail "The tunnel harness ran a stale binary from the shared target directory."
fi
expect_grep '--skip linux_vm_mock_source' "$HS_TEST_ARGS" "mock helper skip"
expect_grep '--skip linux_vm_direct_echo' "$HS_TEST_ARGS" "echo helper skip"
expect_grep "$harness/hs-tunnel-target" "$HS_TARGET_LOG" "fresh tunnel target"
expect_grep '--test linux_tunnel_vm' "$HS_CARGO_LOG" "tunnel test target"
if ls "$harness"/hs-tunnel-target.* >/dev/null 2>&1; then
  fail "The tunnel target directory was not removed."
fi
[ "$(cat "$HS_TEST_CONSENT" 2>/dev/null || true)" = "1" ] ||
  fail "The tunnel run did not set HS_DISPOSABLE_LINUX_VM=1."

for command in '-o link show' 'netns list' '-4 rule show' '-6 rule show' \
  '-4 route show table 700' '-6 route show table 700'; do
  status=$(HS_FAKE_IP_FAIL="$command" run_remote tunnel "$remote_pin")
  [ "$status" -ne 0 ] || fail "A failed ip $command check was accepted."
  expect_grep 'Cannot inspect' "$harness/run.log" "failed ip $command check"
done

# Scenario count must be exact, and nine passes must fail.
status=$(HS_FAKE_RESULT='test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.10s' run_remote tunnel "$remote_pin")
if [ "$status" -eq 0 ]; then
  fail "The tunnel harness accepted nine passes instead of eight scenarios."
fi
expect_grep 'Expected 8 tunnel scenarios' "$harness/run.log" "scenario count failure"

echo "Linux VM tunnel harness tests passed."
