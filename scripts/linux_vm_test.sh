#!/usr/bin/env bash
# Test a reviewed source archive in a disposable Freestyle VM.
#
# Default mode: check, test, clippy, format, and the desktop checks. It creates
# no TUN device and changes no route.
#
# --tunnel: also build the engine and run the ignored Linux tunnel tests as
# root. That mode creates a TUN device, a network namespace, and policy routes
# inside the disposable VM. It must not run on another host.
#
# The tunnel suite holds eight tunnel scenarios and two child-process helpers.
# The helpers sit behind an environment check and return at once when a test
# runner starts them directly. They run only inside their parent tests, which
# spawn them with --exact. This script skips them at the top level and fails if
# the pass count is not the scenario count, so a helper is never reported as a
# tunnel scenario.
#
# The tunnel run sets HS_DISPOSABLE_LINUX_VM=1 for that one command. The test
# binary refuses to change a namespace or a route without it. The variable is
# deliberate consent, not proof that the host is disposable.
#
# Transfer gate
# -------------
# Neither digest is read from the archive's own sidecars or from the helper
# file itself. The caller must supply two external pins:
#
#   --sha256 HEX        or HOTSPOTSHADE_SNAPSHOT_SHA256        archive
#   --helper-sha256 HEX or HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256 helper
#
# Take both from a trusted review record. The script then:
#
#   1. copies only the archive into a private 0700 directory, through a file
#      this script created exclusively rather than a predictable name;
#   2. copies the snapshot helper into a separate private directory through
#      another exclusive file and requires the external helper pin;
#   3. hashes the private archive and requires the external archive pin;
#   4. runs the pinned private helper copy with an absent extraction
#      destination in a separate private root that holds no harness artifact,
#      so the helper creates that destination itself while it verifies the
#      private archive against the same pin and writes a safe extraction;
#   5. re-hashes the private helper copy and refuses if it changed, then checks
#      the extraction for links, special files, set-id bits, and unsafe names;
#   6. builds a sorted file digest manifest from the verified tree;
#   7. hashes the private archive again and refuses if it changed;
#   8. creates the VM, uploads only the private archive, the runner, and the
#      file manifest, and has the VM bind each uploaded file to its digest
#      before it lists or extracts anything.
#
# The snapshot helper must implement the revised contract:
#
#   source_snapshot.sh --verify ARCHIVE --expect-sha256 HEX --extract-to DIR
#
# DIR must not exist. Its parent is a private 0700 directory that this script
# owns, and the helper creates DIR with mode 0700. The helper must bind ARCHIVE
# to HEX, reject unsafe entry types, owners, modes, and formats, write the
# verified tree only inside DIR, and not require a git work tree for --verify.
#
# A helper that still requires sidecars fails closed here, which is the
# intended result. Do not weaken this check, add sidecars, or copy a digest from
# a sidecar to make a run pass. The harness passes the same external pin to the
# helper and checks the helper's output, but it does not treat the helper as the
# source of the pin. A helper that verifies a sidecar-less archive still has to
# pass its own independent review before a real run.
#
# The helper runs with the caller's privileges. A hostile helper can write
# anywhere the caller can, so this is not a sandbox. The harness gives the
# helper a separate extraction root, creates the private archive, the helper
# copy, the runner, and the file manifest with an exclusive no-follow create,
# and binds the archive, runner, and file manifest to digests that the VM checks
# again. That closes the symlink swap the earlier harness allowed, but a
# same-user helper still has the same file access as the caller.
#
# Build isolation and result ownership
# ------------------------------------
# Every Cargo command uses a fresh target directory created for this run and
# passes it with --target-dir. A target directory baked into the VM image or
# named by an archive's .cargo/config cannot make an older build look current.
# The extraction also uses tar -m so archived file times do not stay older than
# a previous build. A stale Cargo cache therefore cannot produce a pass.
#
# The runner no longer writes the result. A root monitor creates a root-owned
# status directory, writes RUNNING, waits for an unprivileged runner, and writes
# the final status itself. The general runner is started with setpriv as the
# image's non-root user with no_new_privs, so code under test cannot become root
# or write the status. This is an ownership boundary, not a hidden nonce.
# The runner refuses to start if it cannot read and parse NoNewPrivs from
# /proc/self/status, or if the value is not 1. The root-owned runner copy is
# mode 755, so the unprivileged user can read and run it but not change it.
#
# The status record is "<run slug> <exit status>". The run slug is unique to
# this run, so a record left by the image or by another run is foreign and is
# never read as a pass. The launch command also removes any earlier status
# directory in the foreground before the monitor starts. The host accepts only
# "<this slug> 0" as a pass for the general run. It treats a foreign, malformed,
# unreadable, or still-running record as a failure. An unrecognized poll output,
# such as extra banner text from the CLI, therefore fails closed.
#
# --tunnel is diagnostic only. The Linux tunnel suite must run its test binary
# as root (it creates a net namespace, a veth pair, a TUN device, and policy
# routes). A root test binary can write, mount over, or replace any status path
# the monitor uses. No file or nonce visible to that process provides a real
# boundary. The harness therefore runs the suite for logs and always reports a
# failure for --tunnel. Do not treat a tunnel diagnostic as evidence until a
# separate trusted root monitor exists and is independently reviewed.
#
# CLI provenance is not solved here. npx -y freestyle@0.2.21 pins the package
# version but not the tarball integrity or its dependency tree. A lockfile
# install or a vendored, hash-checked CLI is not in this repository. The
# transfer gate therefore stays closed unless the caller sets
# HOTSPOTSHADE_VM_TRANSFER_APPROVED=1. Do not set that value until the CLI
# provenance and this harness have passed independent review.
#
# Limits: a pin proves bytes, not safety or secrecy. The VM image, its tar, and
# its SHA-256 tool are trusted test tools. The remote shape check rejects
# non-regular entries, unsafe names, unsafe modes, duplicates, hard links, and
# special files, but it is not a content scanner. The helper review is not
# complete. Do not rely on this harness for a transfer until the helper and this
# harness pass independent review and the exact archive is reviewed.
#
# A same-user helper process can still mutate any path the caller can write.
# This harness creates the private archive, the pinned helper copy, the runner,
# and the file manifest with an exclusive, no-follow create, hashes the runner
# text held in memory, and re-hashes the private archive, the pinned helper
# copy, the runner, and the file manifest around the helper call and around the
# upload. The VM checks the uploaded archive, runner, and manifest again. A
# change that is made and fully reverted between two hashes is not visible. A
# helper that leaves a background process can still interfere with its own
# private roots. This is not a sandbox.
#
# Cleanup never changes permissions through a private root that another process
# replaced with a symlink. It unlinks only that name, reports the cleanup as a
# failure, and does not widen the scope to the link target.
#
# The harness does not walk the work tree. It copies exactly one archive, one
# helper, and never a sidecar, provenance file, or neighbouring path. The
# archive contents are still the reviewer's responsibility. A digest pin proves
# bytes, not that the bytes hold no secret.
#
# The VM is disposable, has no internet and no SSH, and is deleted on exit.
# Cleanup runs after a create attempt even when the create call is interrupted
# or returns non-zero, because the server may have accepted it. Signals are
# ignored while the delete runs. A failed delete can still leave a clone. Check
# the VM list when the script reports a cleanup error.
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL
unset CDPATH BASH_ENV ENV TAR_OPTIONS GZIP POSIXLY_CORRECT
IFS=$' \t\n'

die() {
  echo "linux_vm_test.sh: $*" >&2
  exit 1
}

usage_die() {
  echo "Usage: HOTSPOTSHADE_LINUX_SNAPSHOT=<snapshot-id> \\" >&2
  echo "         HOTSPOTSHADE_VM_TRANSFER_APPROVED=1 $0 \\" >&2
  echo "         [--tunnel] [--sha256 HEX] [--helper-sha256 HEX] <reviewed-source.tar.gz>" >&2
  echo "       The archive digest may also come from HOTSPOTSHADE_SNAPSHOT_SHA256." >&2
  echo "       The helper digest may also come from HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256." >&2
  echo "       --tunnel is diagnostic only and always reports a failure." >&2
  exit 2
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | sed 's/.*= //'
  else
    return 1
  fi
}

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 | sed 's/.*= //'
  else
    return 1
  fi
}

# Create a file without following a pre-existing symlink. mktemp makes an
# unpredictable name, the remove drops that inode, and noclobber makes the
# reopen fail if any name, link, or directory appeared in between. The caller
# writes through descriptor 9 and closes it. A fixed descriptor keeps this
# script compatible with the bash 3.2 that macOS ships.
new_fd=
new_file=
new_private_file() {
  local dir=$1 prefix=$2
  new_file=$(mktemp "$dir/$prefix.XXXXXXXX") || return 1
  rm -f -- "$new_file" || return 1
  set -C
  if ! exec 9>"$new_file"; then
    set +C
    return 1
  fi
  set +C
  new_fd=9
  return 0
}

is_sha256_hex() {
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
  esac
  [ "${#1}" -eq 64 ]
}

is_safe_slug() {
  case "$1" in
    ''|-*|*[!A-Za-z0-9._-]*) return 1 ;;
  esac
  [ "${#1}" -le 128 ]
}

mode=general
sha256_pin=
helper_sha256_pin=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tunnel)
      mode=tunnel
      shift
      ;;
    --sha256)
      [ "$#" -ge 2 ] || usage_die
      sha256_pin=$2
      shift 2
      ;;
    --sha256=*)
      sha256_pin=${1#--sha256=}
      shift
      ;;
    --helper-sha256)
      [ "$#" -ge 2 ] || usage_die
      helper_sha256_pin=$2
      shift 2
      ;;
    --helper-sha256=*)
      helper_sha256_pin=${1#--helper-sha256=}
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage_die
      ;;
    *)
      break
      ;;
  esac
done
if [ "$#" -ne 1 ]; then
  usage_die
fi
source_archive=$1

case "${HOTSPOTSHADE_SNAPSHOT_SHA256:-}" in
  '') ;;
  *)
    if [ -n "$sha256_pin" ] && [ "$sha256_pin" != "$HOTSPOTSHADE_SNAPSHOT_SHA256" ]; then
      die "The --sha256 value and HOTSPOTSHADE_SNAPSHOT_SHA256 differ."
    fi
    sha256_pin=$HOTSPOTSHADE_SNAPSHOT_SHA256
    ;;
esac
if [ -z "$sha256_pin" ]; then
  die "An externally pinned archive digest is required. Pass --sha256 HEX or set HOTSPOTSHADE_SNAPSHOT_SHA256. Do not take it from the archive sidecar."
fi
is_sha256_hex "$sha256_pin" ||
  die "The pinned archive digest must be 64 lower-case hex characters."

case "${HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256:-}" in
  '') ;;
  *)
    if [ -n "$helper_sha256_pin" ] &&
      [ "$helper_sha256_pin" != "$HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256" ]; then
      die "The --helper-sha256 value and HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256 differ."
    fi
    helper_sha256_pin=$HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256
    ;;
esac
if [ -z "$helper_sha256_pin" ]; then
  die "An externally pinned snapshot helper digest is required. Pass --helper-sha256 HEX or set HOTSPOTSHADE_SNAPSHOT_HELPER_SHA256. Do not take it from the helper file."
fi
is_sha256_hex "$helper_sha256_pin" ||
  die "The pinned snapshot helper digest must be 64 lower-case hex characters."

# The Freestyle CLI is pinned only by package version. Its tarball and
# dependency tree are not locked, so the transfer gate stays closed by default.
if [ "${HOTSPOTSHADE_VM_TRANSFER_APPROVED:-}" != 1 ]; then
  die "The VM transfer gate is closed: the Freestyle CLI has no locked or hash-verified provenance. Set HOTSPOTSHADE_VM_TRANSFER_APPROVED=1 only after the CLI provenance and this harness pass independent review."
fi

snapshot_slug=${HOTSPOTSHADE_LINUX_SNAPSHOT:?set HOTSPOTSHADE_LINUX_SNAPSHOT to a prepared Linux VM snapshot}
is_safe_slug "$snapshot_slug" ||
  die "HOTSPOTSHADE_LINUX_SNAPSHOT must be 1 to 128 characters from A-Z, a-z, 0-9, dot, underscore, or hyphen, and must not start with a dash."
# Keep the VM lifecycle interface stable across repeat runs.
freestyle_package=freestyle@0.2.21
vm_slug="hotspotshade-test-$(date +%s)-$$"
vm_maybe_created=0
work=
helper_root=
artifact_root=
runner=
manifest_file=
remote_log=/tmp/hotspotshade-vm-test.log
remote_launcher_log=/tmp/hotspotshade-vm-launcher.log
remote_status_dir=/var/lib/hotspotshade-vm-status
remote_status=$remote_status_dir/status
remote_runner=/home/ubuntu/hotspotshade-vm-run.sh
remote_manifest=/home/ubuntu/hotspotshade-vm-files.sha256

# Remove one private root without widening the cleanup scope. GNU chmod follows
# a symlink that is named on the command line, so the path is checked first and
# only a real directory is walked. find does not follow the paths it walks by
# default, and -type d excludes symlinks, so a link inside the tree is never
# chmodded. A root that was replaced by a symlink is unlinked without touching
# its target and reported as a cleanup failure.
remove_private_dir() {
  local dir=$1
  [ -n "$dir" ] || return 0
  if [ -L "$dir" ]; then
    echo "Refusing to change permissions through the replaced private path: $dir" >&2
    rm -f -- "$dir" || echo "Could not remove the replaced private path $dir." >&2
    return 1
  fi
  [ -e "$dir" ] || return 0
  if [ ! -d "$dir" ]; then
    echo "The private path is not a directory: $dir" >&2
    return 1
  fi
  find "$dir" -type d -exec chmod u+rwx {} + 2>/dev/null || true
  rm -rf -- "$dir"
}

cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  # A second signal must not cut the delete in half. The ephemeral and idle
  # timeout settings limit the damage, but the delete is the normal path.
  trap '' INT TERM HUP
  if [ -n "${watchdog_pid:-}" ]; then
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    watchdog_pid=
  fi
  if [ -n "${helper_pid:-}" ]; then
    kill -TERM "$helper_pid" 2>/dev/null || true
    wait "$helper_pid" 2>/dev/null || true
    helper_pid=
  fi
  # The server can accept a create whose client call then fails or is
  # interrupted. Try the delete whenever a create was attempted. The slug is
  # unique to this run, so a delete on a missing slug is harmless.
  if [ "${vm_maybe_created:-0}" -eq 1 ]; then
    if ! npx -y "$freestyle_package" vm delete "$vm_slug"; then
      echo "Could not delete $vm_slug after a create attempt. Check the Freestyle VM list." >&2
      [ "$status" -ne 0 ] || status=1
    fi
  fi
  if [ -n "${runner:-}" ] && [ -f "$runner" ]; then
    rm -f -- "$runner" || {
      echo "Could not remove the private runner $runner." >&2
      [ "$status" -ne 0 ] || status=1
    }
  fi
  if [ -n "${manifest_file:-}" ] && [ -f "$manifest_file" ]; then
    rm -f -- "$manifest_file" || {
      echo "Could not remove the private file manifest $manifest_file." >&2
      [ "$status" -ne 0 ] || status=1
    }
  fi
  for dir in "${helper_root:-}" "${artifact_root:-}" "${work:-}"; do
    if [ -n "$dir" ] && { [ -e "$dir" ] || [ -L "$dir" ]; }; then
      remove_private_dir "$dir" || {
        echo "Could not remove the private work directory $dir." >&2
        [ "$status" -ne 0 ] || status=1
      }
    fi
  done
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

case "$source_archive" in
  -*) die "The archive path must not start with a dash." ;;
  *[[:cntrl:]]*) die "The archive path holds a control character." ;;
esac
[ -f "$source_archive" ] && [ ! -L "$source_archive" ] ||
  die "Not a regular archive: $source_archive"
source_base=${source_archive##*/}
case "$source_base" in
  ''|-*) die "The archive basename must not be empty or start with a dash." ;;
esac

case "$0" in
  */*)
    script_dir=${0%/*}
    [ -n "$script_dir" ] || script_dir=/
    ;;
  *) script_dir=. ;;
esac
script_dir=$(CDPATH= cd "$script_dir" && pwd -P) || die "Cannot resolve the script directory."
snapshot_helper=$script_dir/source_snapshot.sh
[ -f "$snapshot_helper" ] && [ -x "$snapshot_helper" ] && [ ! -L "$snapshot_helper" ] ||
  die "Missing or non-executable snapshot helper next to this script: $snapshot_helper"

# Work only from a private copy. Copying one file, not a directory, keeps a
# sidecar or an untracked neighbour out of the transfer and out of the proof.
work=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-vm-input.XXXXXXXX") ||
  die "Cannot create a private work directory."
chmod 700 "$work" || die "Cannot restrict the private work directory."

# The helper writes its verified tree here. This root is separate from the
# directory that holds the runner, the file manifest, and the other harness
# artifacts, so a planted sibling name cannot land on a file this script reads.
helper_root=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-vm-helper.XXXXXXXX") ||
  die "Cannot create a private helper extraction root."
chmod 700 "$helper_root" || die "Cannot restrict the private helper root."

input_dir=$work/input
mkdir -m 700 "$input_dir" || die "Cannot create the private input directory."
# Create the private archive through an unpredictable name and a noclobber
# descriptor, then copy into that descriptor. A predictable destination path
# would let a same-user racer plant a symlink and turn the copy into a write
# through the link. /dev/fd/9 names the descriptor this script opened, not a
# path another process can replace.
new_private_file "$input_dir" "$source_base" ||
  die "Cannot create the private archive file."
private_archive=$new_file
cp -P -- "$source_archive" /dev/fd/9 ||
  die "Cannot copy the archive into the private directory."
chmod 600 /dev/fd/9 || die "Cannot restrict the private archive."
exec 9>&-
if [ -L "$private_archive" ] || [ ! -f "$private_archive" ]; then
  die "The archive changed to a non-regular file during the copy."
fi

digest_before=$(sha256_file "$private_archive") ||
  die "Cannot hash the private archive. Install sha256sum, shasum, or openssl."
is_sha256_hex "$digest_before" || die "The local archive hash is not a SHA-256 digest."
if [ "$digest_before" != "$sha256_pin" ]; then
  die "The private archive does not match the externally pinned SHA-256. No VM was created."
fi

# Run a pinned private copy of the helper. The repository path is copied once,
# its copy is bound to the external helper pin, and only that copy executes.
helper_bin_dir=$work/helper-bin
mkdir -m 700 "$helper_bin_dir" || die "Cannot create the private helper directory."
new_private_file "$helper_bin_dir" source_snapshot.sh ||
  die "Cannot create the private snapshot helper copy."
helper_copy=$new_file
cp -P -- "$snapshot_helper" /dev/fd/9 || die "Cannot copy the snapshot helper."
chmod 700 /dev/fd/9 || die "Cannot restrict the private helper copy."
exec 9>&-
if [ -L "$helper_copy" ] || [ ! -f "$helper_copy" ]; then
  die "The snapshot helper changed to a non-regular file during the copy. No helper ran."
fi
helper_sha=$(sha256_file "$helper_copy") ||
  die "Cannot hash the private snapshot helper copy. Install sha256sum, shasum, or openssl."
is_sha256_hex "$helper_sha" || die "The snapshot helper hash is not a SHA-256 digest."
if [ "$helper_sha" != "$helper_sha256_pin" ]; then
  die "The private snapshot helper copy does not match the externally pinned SHA-256. No helper ran and no VM was created."
fi

# The helper creates the extraction destination itself. It must be absent now:
# an existing directory, file, or symlink at that path is refused before the
# helper runs. The destination stays inside the private 0700 helper root, which
# holds no harness artifact that a planted name could redirect.
verified_tree=$helper_root/tree
if [ -L "$helper_root" ] || [ ! -d "$helper_root" ]; then
  die "The private helper extraction root is not a real directory. No VM was created."
fi
if [ -e "$verified_tree" ] || [ -L "$verified_tree" ]; then
  die "The private verified tree path already exists. No VM was created."
fi
helper_home=$work/helper-home
helper_tmp=$work/helper-tmp
mkdir -m 700 "$helper_home" "$helper_tmp" ||
  die "Cannot create the private helper environment. No VM was created."
new_private_file "$work" helper-log ||
  die "Cannot create the private helper log. No VM was created."
helper_log=$new_file
helper_log_fd=$new_fd
helper_status=0
# The helper inherits no caller environment, no stdin, and a private HOME and
# TMPDIR. Vars such as TAR_OPTIONS, GZIP, BASH_ENV, npm tokens, and Freestyle
# credentials do not reach it. A watchdog bounds a stuck helper. The three test
# hooks are passed only when the test harness sets them.
helper_env=(env -i \
  PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
  HOME="$helper_home" TMPDIR="$helper_tmp" LC_ALL=C)
[ -z "${HS_HELPER_LOG:-}" ] || helper_env+=(HS_HELPER_LOG="$HS_HELPER_LOG")
[ -z "${HS_HELPER_MODE:-}" ] || helper_env+=(HS_HELPER_MODE="$HS_HELPER_MODE")
[ -z "${HS_ESCAPE_VICTIM:-}" ] || helper_env+=(HS_ESCAPE_VICTIM="$HS_ESCAPE_VICTIM")
"${helper_env[@]}" "$helper_copy" --verify "$private_archive" \
  --expect-sha256 "$sha256_pin" --extract-to "$verified_tree" \
  >&"$helper_log_fd" 2>&1 </dev/null &
helper_pid=$!
(
  sleeper=
  trap 'if [ -n "$sleeper" ]; then kill "$sleeper" 2>/dev/null || true; wait "$sleeper" 2>/dev/null || true; fi; exit 0' TERM INT HUP
  sleep 900 &
  sleeper=$!
  wait "$sleeper" || exit 0
  sleeper=
  kill -TERM "$helper_pid" 2>/dev/null || exit 0
  sleep 5 &
  sleeper=$!
  wait "$sleeper" || exit 0
  sleeper=
  kill -KILL "$helper_pid" 2>/dev/null || true
) &
watchdog_pid=$!
wait "$helper_pid" || helper_status=$?
helper_pid=
kill "$watchdog_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true
watchdog_pid=
exec 9>&-
if [ "$helper_status" -ne 0 ]; then
  echo "Snapshot verification failed. No VM was created." >&2
  cat -v -- "$helper_log" >&2
  exit 1
fi
if [ -L "$helper_root" ] || [ ! -d "$helper_root" ]; then
  die "The private helper extraction root changed during verification. No VM was created."
fi
if [ -L "$verified_tree" ] || [ ! -d "$verified_tree" ]; then
  die "The snapshot helper reported success but wrote no regular verified tree. No VM was created."
fi
helper_sha_after=$(sha256_file "$helper_copy") ||
  die "Cannot rehash the private snapshot helper copy. No VM was created."
if [ "$helper_sha_after" != "$helper_sha" ]; then
  die "The pinned private snapshot helper copy changed during verification. No VM was created."
fi

# Create a new private root for the runner and the file manifest only after
# the helper has exited. The helper never sees this name, so it cannot place a
# symlink on an artifact path, and every artifact is created exclusively.
artifact_root=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-vm-artifacts.XXXXXXXX") ||
  die "Cannot create the private artifact root. No VM was created."
chmod 700 "$artifact_root" ||
  die "Cannot restrict the private artifact root. No VM was created."

# A failed find must fail the run, not look like an empty result. Stop at the
# first hit, so a large tree does not fill a variable, and capture the result
# directly instead of writing through a reusable file name.
first_file=$(find "$verified_tree" -type f -print -quit) ||
  die "Cannot inspect the verified tree. No VM was created."
[ -n "$first_file" ] ||
  die "The snapshot helper verified no regular files. No VM was created."
symlinks=$(find "$verified_tree" -type l -print -quit) ||
  die "Cannot inspect the verified tree. No VM was created."
[ -z "$symlinks" ] ||
  die "The verified tree holds a symlink. No VM was created."
hardlinks=$(find "$verified_tree" -type f -links +1 -print -quit) ||
  die "Cannot inspect the verified tree. No VM was created."
[ -z "$hardlinks" ] ||
  die "The verified tree holds a hard link. No VM was created."
specials=$(find "$verified_tree" ! -type d ! -type f -print -quit) ||
  die "Cannot inspect the verified tree. No VM was created."
[ -z "$specials" ] ||
  die "The verified tree holds a special file. No VM was created."
setids=$(find "$verified_tree" \( -perm -4000 -o -perm -2000 -o -perm -1000 \) -print -quit) ||
  die "Cannot inspect the verified tree. No VM was created."
[ -z "$setids" ] ||
  die "The verified tree holds a set-id or sticky entry. No VM was created."

# Build the file digest manifest that the VM compares against its own
# extraction. Every path must be a plain relative path with no control byte.
# The file is created without following a pre-existing link, and the digest is
# computed from these bytes and checked again before and after the upload.
new_private_file "$artifact_root" files ||
  die "Cannot create the private file manifest. No VM was created."
manifest_file=$new_file
manifest_fd=$new_fd
(
  cd "$verified_tree" || exit 1
  find . -type f -print0 | LC_ALL=C sort -z |
    while IFS= read -r -d '' entry; do
      rel=${entry#./}
      case "$rel" in
        ''|/*|*\\*|*[[:cntrl:]]*)
          echo "Unsafe verified path: $rel" >&2
          exit 1
          ;;
      esac
      sum=$(sha256_file "./$rel") || exit 1
      printf '%s  %s\n' "$sum" "$rel"
    done
) >&"$manifest_fd" ||
  die "Cannot build the verified file digest manifest. No VM was created."
exec 9>&-
[ -s "$manifest_file" ] ||
  die "The verified file digest manifest is empty. No VM was created."
manifest_sha=$(sha256_file "$manifest_file") ||
  die "Cannot hash the verified file manifest. No VM was created."
is_sha256_hex "$manifest_sha" ||
  die "The verified file manifest hash is not a SHA-256 digest. No VM was created."

digest_after=$(sha256_file "$private_archive") ||
  die "Cannot rehash the private archive. No VM was created."
if [ "$digest_after" != "$sha256_pin" ]; then
  die "The private archive changed after verification. No VM was created."
fi

echo "Linux VM test evidence:"
echo "  snapshot: $snapshot_slug"
echo "  mode: $mode"
echo "  vm: $vm_slug"
echo "  archive: $source_base"
echo "  archive_sha256: $sha256_pin"
echo "  snapshot_helper: $snapshot_helper"
echo "  snapshot_helper_sha256: $helper_sha"
echo "  verified_files_sha256: $manifest_sha"
echo "  local_verification: passed"
cat -v -- "$helper_log"
echo ""

# The runner is written through an exclusive no-follow create, read back into
# memory, and hashed from that text. The file is checked against the memory
# digest before and after upload. A same-user process cannot change the digest
# by editing the file after the hash.
new_private_file "$artifact_root" run ||
  die "Cannot create the private runner file. No VM was created."
runner=$new_file
runner_fd=$new_fd
cat >&"$runner_fd" <<'REMOTE'
#!/usr/bin/env bash
# Runs inside the disposable VM. $1 is the mode, $2 the external archive
# digest pin, and $3 the digest of the reviewed file manifest.
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL
unset CDPATH BASH_ENV ENV TAR_OPTIONS GZIP POSIXLY_CORRECT
IFS=$' \t\n'
mode=${1:-general}
expected_digest=${2:-}
expected_manifest=${3:-}
case "$mode" in
  general|tunnel) ;;
  *)
    echo "Unknown remote mode: $mode" >&2
    exit 2
    ;;
esac
if [ "$(id -u)" -eq 0 ]; then
  echo "The runner must not execute as root. The root monitor starts it as a non-root user." >&2
  exit 1
fi
if [ "$mode" != tunnel ]; then
  # Fail closed: an unreadable or unparsable status is not proof of the
  # privilege boundary, so the runner refuses to run code under test.
  if [ ! -r /proc/self/status ]; then
    echo "Cannot read /proc/self/status to check no_new_privs. Refusing to run code under test." >&2
    exit 1
  fi
  no_new_privs=$(awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status) || {
    echo "Cannot parse /proc/self/status to check no_new_privs. Refusing to run code under test." >&2
    exit 1
  }
  if [ "$no_new_privs" != 1 ]; then
    echo "The general runner did not start with no_new_privs. Refusing to run code under test." >&2
    exit 1
  fi
fi
root=""
meta=""
build_target=""
desktop_target=""
tunnel_target=""
remove_tree() {
  local dir=$1
  [ -n "$dir" ] && [ -e "$dir" ] || return 0
  chmod -R u+rwX -- "$dir" 2>/dev/null || true
  if rm -rf -- "$dir" 2>/dev/null; then
    return 0
  fi
  # The tunnel suite can leave root-owned entries. This path is diagnostic
  # only, so a failed cleanup is reported and does not hide the real status.
  if [ "$mode" = tunnel ] && command -v sudo >/dev/null 2>&1; then
    sudo -n rm -rf -- "$dir" 2>/dev/null && return 0
  fi
  echo "Could not remove $dir" >&2
  return 0
}
finish() {
  status=$?
  trap - EXIT INT TERM HUP
  remove_tree "$tunnel_target"
  remove_tree "$desktop_target"
  remove_tree "$build_target"
  remove_tree "$root"
  remove_tree "$meta"
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
root=$(mktemp -d /tmp/hotspotshade-test.XXXXXXXX)
meta=$(mktemp -d /tmp/hotspotshade-meta.XXXXXXXX)

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | sed 's/.*= //'
  else
    return 1
  fi
}

is_hex64() {
  case "$1" in
    *[!0-9a-f]*) return 1 ;;
  esac
  [ "${#1}" -eq 64 ]
}

archive=/home/ubuntu/hotspotshade-source.tar.gz
uploaded_manifest=/home/ubuntu/hotspotshade-vm-files.sha256
for uploaded in "$archive" "$uploaded_manifest"; do
  if [ ! -f "$uploaded" ] || [ -L "$uploaded" ]; then
    echo "An uploaded file is missing or not a regular file: $uploaded" >&2
    exit 1
  fi
done
if ! is_hex64 "$expected_digest"; then
  echo "The pinned archive digest is not 64 lower-case hex characters." >&2
  exit 1
fi
if ! is_hex64 "$expected_manifest"; then
  echo "The pinned file manifest digest is not 64 lower-case hex characters." >&2
  exit 1
fi

# Copy both uploads into the private meta directory, then hash and use the
# copies. The VM must not hash one file and extract another, and it must not
# re-open an upload path after the check.
archive_copy=$meta/input.tar.gz
manifest_copy=$meta/files.sha256
cp -- "$archive" "$archive_copy" || {
  echo "Cannot copy the uploaded archive." >&2
  exit 1
}
cp -- "$uploaded_manifest" "$manifest_copy" || {
  echo "Cannot copy the uploaded file manifest." >&2
  exit 1
}
for copied in "$archive_copy" "$manifest_copy"; do
  if [ ! -f "$copied" ] || [ -L "$copied" ]; then
    echo "An uploaded file changed to a non-regular file during the copy: $copied" >&2
    exit 1
  fi
done
actual_digest=$(sha256_file "$archive_copy") || {
  echo "No SHA-256 tool is available in the VM." >&2
  exit 1
}
if [ "$actual_digest" != "$expected_digest" ]; then
  echo "The uploaded archive SHA-256 does not match the pinned digest. Refusing to extract." >&2
  echo "Expected: $expected_digest" >&2
  echo "Actual:   $actual_digest" >&2
  exit 1
fi
actual_manifest=$(sha256_file "$manifest_copy") || {
  echo "No SHA-256 tool is available in the VM." >&2
  exit 1
}
if [ "$actual_manifest" != "$expected_manifest" ]; then
  echo "The uploaded file manifest SHA-256 does not match the pinned digest. Refusing to extract." >&2
  echo "Expected: $expected_manifest" >&2
  echo "Actual:   $actual_manifest" >&2
  exit 1
fi
echo "Uploaded archive SHA-256 verified: $actual_digest"
echo "Uploaded file manifest SHA-256 verified: $actual_manifest"

# Check the reviewed manifest itself before comparing it with a tree.
while IFS= read -r manifest_line || [ -n "$manifest_line" ]; do
  [ -n "$manifest_line" ] || continue
  case "$manifest_line" in
    *[[:cntrl:]]*)
      echo "The file manifest holds a control byte." >&2
      exit 1
      ;;
  esac
  case "$manifest_line" in
    *'  '*) ;;
    *)
      echo "The file manifest holds a malformed line." >&2
      exit 1
      ;;
  esac
  manifest_path=${manifest_line#*  }
  case "$manifest_path" in
    ''|/*|*\\*|../*|*/../*|./*|*/./*|*//*)
      echo "The file manifest holds an unsafe path: $manifest_path" >&2
      exit 1
      ;;
  esac
done < "$manifest_copy"

# Check the shape of the archive before any extraction. The local helper has
# already done this, but the VM must not trust an upload or a transport. Only
# regular files are allowed. Directories, symlinks, hard links, devices, and
# other special entries are refused.
# The archive must be a gzip stream. tar implementations differ on whether -z
# is enforced when reading, so the check is explicit.
gzip -t "$archive_copy" >/dev/null 2>&1 || {
  echo "The uploaded archive is not a valid gzip stream." >&2
  exit 1
}
entries=$meta/entries
types=$meta/types
# Keep absolute and parent components visible while listing. Extraction below
# does not use -P; the unsafe names must be refused before it runs.
tar -P -tf "$archive_copy" > "$entries" || {
  echo "Cannot list the uploaded archive." >&2
  exit 1
}
tar -P -tvf "$archive_copy" > "$types" || {
  echo "Cannot inspect the uploaded archive." >&2
  exit 1
}
entry_count=$(wc -l < "$entries" | tr -d ' ')
type_count=$(wc -l < "$types" | tr -d ' ')
if [ "$entry_count" -eq 0 ]; then
  echo "The uploaded archive is empty." >&2
  exit 1
fi
if [ "$entry_count" -ne "$type_count" ]; then
  echo "The archive entry list and type list differ in length." >&2
  exit 1
fi
while IFS= read -r entry; do
  case "$entry" in
    ''|/*|*\\*|*[[:cntrl:]]*)
      echo "Unsafe archive entry: $entry" >&2
      exit 1
      ;;
  esac
  case "$entry" in
    */|*/./*|./*|*/../*|../*|*/.|*/..|..|.|*//*)
      echo "Unsafe archive entry: $entry" >&2
      exit 1
      ;;
  esac
done < "$entries"
LC_ALL=C sort "$entries" > "$meta/entries.sorted"
duplicates=$(uniq -d "$meta/entries.sorted") || {
  echo "Cannot check the archive for duplicate paths." >&2
  exit 1
}
if [ -n "$duplicates" ]; then
  echo "The archive lists a path more than once." >&2
  exit 1
fi
while IFS= read -r type_line; do
  case "$type_line" in
    -*) ;;
    *)
      echo "Unsafe archive entry type: $type_line" >&2
      exit 1
      ;;
  esac
  # The helper accepts only regular files with mode 0644 or 0755. Checking the
  # mode here rejects set-id, setgid, sticky, and unusual permissions before
  # extraction. tar --no-same-permissions would silently strip some of them.
  entry_mode=${type_line%% *}
  case "$entry_mode" in
    -rw-r--r--|-rwxr-xr-x) ;;
    *)
      echo "Unsafe archive entry mode: $type_line" >&2
      exit 1
      ;;
  esac
done < "$types"

# Extract from the private copy, never from the upload path, and do not let the
# archive set an owner, a set-id mode, or a permissive mode. -m sets each
# extracted file time to now, so an old archive cannot keep Cargo fingerprints
# older than a previous build. Every Cargo command also uses a fresh target.
tar -m --no-same-owner --no-same-permissions -xzf "$archive_copy" -C "$root" || {
  echo "Cannot extract the verified archive." >&2
  exit 1
}
shape=$(find "$root" -type l -print) || {
  echo "Cannot inspect the extracted archive." >&2
  exit 1
}
if [ -n "$shape" ]; then
  echo "The extracted archive holds a symlink." >&2
  exit 1
fi
shape=$(find "$root" -type f -links +1 -print) || {
  echo "Cannot inspect the extracted archive." >&2
  exit 1
}
if [ -n "$shape" ]; then
  echo "The extracted archive holds a hard link." >&2
  exit 1
fi
shape=$(find "$root" ! -type d ! -type f -print) || {
  echo "Cannot inspect the extracted archive." >&2
  exit 1
}
if [ -n "$shape" ]; then
  echo "The extracted archive holds a special file." >&2
  exit 1
fi
shape=$(find "$root" \( -perm -4000 -o -perm -2000 -o -perm -1000 \) -print) || {
  echo "Cannot inspect the extracted archive." >&2
  exit 1
}
if [ -n "$shape" ]; then
  echo "The extracted archive holds a set-id or sticky entry." >&2
  exit 1
fi

# Compare the extracted tree with the reviewed file manifest, file by file and
# in the same order. A helper tree that differs from the archive bytes fails
# here, and so does an archive with an extra or a missing file.
tree_manifest=$meta/tree.files
(
  cd "$root" || exit 1
  find . -type f -print0 | LC_ALL=C sort -z |
    while IFS= read -r -d '' entry; do
      rel=${entry#./}
      case "$rel" in
        ''|/*|*\\*|*[[:cntrl:]]*)
          echo "Unsafe extracted path: $rel" >&2
          exit 1
          ;;
      esac
      sum=$(sha256_file "./$rel") || exit 1
      printf '%s  %s\n' "$sum" "$rel"
    done
) > "$tree_manifest" || {
  echo "Cannot build the extracted file manifest." >&2
  exit 1
}
if ! cmp -s "$tree_manifest" "$manifest_copy"; then
  echo "The extracted tree does not match the reviewed file manifest. Refusing to run." >&2
  exit 1
fi
echo "Extracted tree matches the reviewed file manifest."
cd "$root"
export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
build_target=$(mktemp -d /tmp/hs-cargo.XXXXXXXX)
desktop_target=$(mktemp -d /tmp/hs-desktop-target.XXXXXXXX)
export CARGO_TARGET_DIR="$build_target"
# A .cargo/config in the archive can set build.target-dir, so the fresh
# directory is also passed on every Cargo command. --offline has the same
# reason. A stale fingerprint in the VM image cannot be reused.
cargo check --offline --target-dir "$build_target" \
  --all-targets --locked --manifest-path rust/Cargo.toml
cargo test --offline --target-dir "$build_target" \
  --locked --manifest-path rust/Cargo.toml
cargo clippy --offline --target-dir "$build_target" \
  --all-targets --locked --manifest-path rust/Cargo.toml -- -D warnings
cargo fmt --manifest-path rust/Cargo.toml --check
if [ "$mode" = tunnel ]; then
  # Build the test and the engine into a fresh target directory. The shared
  # target directory can hold a linux_tunnel_vm-* binary from an older
  # archive, and the lexicographic order of a hash does not name the newest
  # build. A fresh directory holds exactly one artifact for this archive.
  tunnel_target=$(mktemp -d /tmp/hs-tunnel-target.XXXXXXXX)
  CARGO_TARGET_DIR="$tunnel_target" cargo build --offline \
    --target-dir "$tunnel_target" --locked \
    --manifest-path rust/Cargo.toml --test linux_tunnel_vm --bin hotspotshade
  test_binaries=$(find "$tunnel_target/debug/deps" -maxdepth 1 -type f \
    -name 'linux_tunnel_vm-*' -perm -u+x | sort)
  binary_count=$(printf '%s' "$test_binaries" | grep -c . || true)
  if [ "$binary_count" -ne 1 ]; then
    echo "Expected one linux_tunnel_vm binary in $tunnel_target, found $binary_count." >&2
    echo "Found: ${test_binaries:-none}" >&2
    exit 1
  fi
  binary=$test_binaries
  case "$binary" in
    "$tunnel_target"/debug/deps/linux_tunnel_vm-*) ;;
    *)
      echo "The test binary is outside the fresh target directory: $binary" >&2
      exit 1
      ;;
  esac
  if [ ! -x "$tunnel_target/debug/hotspotshade" ]; then
    echo "The engine binary is missing from $tunnel_target/debug." >&2
    exit 1
  fi
  # linux_vm_mock_source and linux_vm_direct_echo are child-process helpers.
  # Their parent tests start them with --exact inside the test netns. A
  # top-level run would count them as passes without exercising a tunnel.
  #
  # HS_DISPOSABLE_LINUX_VM=1 is deliberate consent for this run only. The test
  # binary refuses to change a namespace or a route without it. It is not proof
  # that the host is disposable, so it is set here and nowhere else.
  tunnel_scenarios=8
  helper_mock=linux_vm_mock_source
  helper_echo=linux_vm_direct_echo
  tunnel_log=/tmp/hotspotshade-linux-tunnel.log
  status=0
  sudo -n -E env HS_DISPOSABLE_LINUX_VM=1 "$binary" --ignored --test-threads=1 --nocapture \
    --skip "$helper_mock" --skip "$helper_echo" >"$tunnel_log" 2>&1 || status=$?
  cat -v "$tunnel_log"
  [ "$status" -eq 0 ] || exit "$status"
  result_line=$(grep -E '^test result: ' "$tunnel_log" | tail -1)
  passed=$(printf '%s\n' "$result_line" | sed -n 's/.* \([0-9][0-9]*\) passed.*/\1/p')
  filtered=$(printf '%s\n' "$result_line" | sed -n 's/.* \([0-9][0-9]*\) filtered out.*/\1/p')
  if [ "${passed:-}" != "$tunnel_scenarios" ]; then
    echo "Expected $tunnel_scenarios tunnel scenarios. Got: ${result_line:-no result line}" >&2
    echo "Change tunnel_scenarios in scripts/linux_vm_test.sh only for a real new scenario." >&2
    exit 1
  fi
  if [ "${filtered:-}" != "2" ]; then
    echo "Expected the 2 child helpers to be filtered out. Got: ${filtered:-none}" >&2
    exit 1
  fi
  echo "Tunnel scenarios: $passed passed. $helper_mock and $helper_echo ran only inside their parent tests."
  links=$(sudo -n ip -o link show) || { echo "Cannot inspect test links." >&2; exit 1; }
  namespaces=$(sudo -n ip netns list) || { echo "Cannot inspect network namespaces." >&2; exit 1; }
  rules4=$(sudo -n ip -4 rule show) || { echo "Cannot inspect IPv4 rules." >&2; exit 1; }
  rules6=$(sudo -n ip -6 rule show) || { echo "Cannot inspect IPv6 rules." >&2; exit 1; }
  routes4=$(sudo -n ip -4 route show table 700) || { echo "Cannot inspect IPv4 tunnel routes." >&2; exit 1; }
  routes6=$(sudo -n ip -6 route show table 700) || { echo "Cannot inspect IPv6 tunnel routes." >&2; exit 1; }
  if grep -Eq '(^|: )(hs-tun[0-9]+|hs-host0|hs-src0)(@[^:]*)?:' <<< "$links"; then
    echo "a tunnel or test link remained" >&2
    exit 1
  else
    result=$?; [ "$result" -eq 1 ] || { echo "Cannot check test links." >&2; exit 1; }
  fi
  if grep -q '^hs-vm-net' <<< "$namespaces"; then
    echo "a test network namespace remained" >&2
    exit 1
  else
    result=$?; [ "$result" -eq 1 ] || { echo "Cannot check network namespaces." >&2; exit 1; }
  fi
  if grep -Eq '^(17000|17001):' <<< "$rules4"; then
    echo "an IPv4 policy rule remained" >&2
    exit 1
  else
    result=$?; [ "$result" -eq 1 ] || { echo "Cannot check IPv4 rules." >&2; exit 1; }
  fi
  if grep -Eq '^(17000|17001):' <<< "$rules6"; then
    echo "an IPv6 policy rule remained" >&2
    exit 1
  else
    result=$?; [ "$result" -eq 1 ] || { echo "Cannot check IPv6 rules." >&2; exit 1; }
  fi
  if [ -n "$routes4" ]; then
    echo "an IPv4 tunnel table route remained" >&2
    exit 1
  fi
  if [ -n "$routes6" ]; then
    echo "an IPv6 tunnel table route remained" >&2
    exit 1
  fi
else
  CARGO_TARGET_DIR="$desktop_target" cargo test --offline \
    --target-dir "$desktop_target" --locked --manifest-path desktop/Cargo.toml
  node --test desktop/tests/fetch_shim.test.mjs desktop/tests/ui_model.test.mjs
  node --test linux/test/*.test.mjs
fi
REMOTE
chmod 700 /dev/fd/9 || die "Cannot restrict the private runner file."
exec 9>&-
if [ -L "$runner" ] || [ ! -f "$runner" ]; then
  die "The private runner changed to a non-regular file. No VM was created."
fi
runner_text=$(cat -- "$runner"; printf x) ||
  die "Cannot read back the private runner file. No VM was created."
runner_text=${runner_text%x}
runner_sha=$(printf '%s' "$runner_text" | sha256_stdin) ||
  die "Cannot hash the runner text. No VM was created."
is_sha256_hex "$runner_sha" || die "The runner hash is not a SHA-256 digest."
file_runner_sha=$(sha256_file "$runner") ||
  die "Cannot hash the private runner file. No VM was created."
[ "$file_runner_sha" = "$runner_sha" ] ||
  die "The private runner file does not match the runner text. No VM was created."

# Re-check every input the VM will bind before the create call.
digest_final=$(sha256_file "$private_archive") ||
  die "Cannot rehash the private archive. No VM was created."
[ "$digest_final" = "$sha256_pin" ] ||
  die "The private archive changed before the transfer. No VM was created."
manifest_final=$(sha256_file "$manifest_file") ||
  die "Cannot rehash the verified file manifest. No VM was created."
[ "$manifest_final" = "$manifest_sha" ] ||
  die "The verified file manifest changed before the transfer. No VM was created."
helper_final=$(sha256_file "$helper_copy") ||
  die "Cannot rehash the pinned private helper copy. No VM was created."
[ "$helper_final" = "$helper_sha" ] ||
  die "The pinned private helper copy changed before the transfer. No VM was created."
runner_final=$(sha256_file "$runner") ||
  die "Cannot rehash the private runner. No VM was created."
[ "$runner_final" = "$runner_sha" ] ||
  die "The private runner changed before the transfer. No VM was created."

if [ "$mode" = tunnel ]; then
  echo "Note: --tunnel is diagnostic only. The root test binary can forge or replace any status path, so this run will not report a pass." >&2
fi
echo "Note: the transfer gate remains closed pending independent review of the helper, this harness, the CLI provenance, and the exact archive." >&2

# The launcher runs as root. It creates a root-owned status directory, verifies
# the uploaded runner, copies it to a root-owned path, and starts it as the
# image's non-root user. For general mode it also sets no_new_privs, so code
# under test cannot use sudo or a setuid helper to write the status. The status
# is written by the root monitor after the runner exits.
launcher=$(
  cat <<LAUNCH
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
status_dir=$remote_status_dir
status_file=$remote_status
rm -rf -- "\$status_dir" || exit 1
mkdir -m 700 -- "\$status_dir" || exit 1
printf '%s running\n' '$vm_slug' > "\$status_file" || exit 1
chmod 600 -- "\$status_file" || exit 1
finish() {
  st=\$?
  trap - EXIT INT TERM HUP
  printf '%s %s\n' '$vm_slug' "\$st" > "\$status_file.tmp" || true
  chmod 600 -- "\$status_file.tmp" 2>/dev/null || true
  mv -f -- "\$status_file.tmp" "\$status_file" 2>/dev/null || true
  exit "\$st"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
actual=\$(sha256sum $remote_runner | cut -d' ' -f1) || { echo "No SHA-256 tool for the runner check." >&2; exit 1; }
if [ "\$actual" != "$runner_sha" ]; then
  echo "The uploaded runner SHA-256 does not match the pinned digest. Refusing to start." >&2
  exit 1
fi
if ! command -v setpriv >/dev/null 2>&1; then
  echo "The VM has no setpriv. Refusing to run code under test without a privilege drop." >&2
  exit 98
fi
if ! id -u ubuntu >/dev/null 2>&1; then
  echo "The VM has no ubuntu user. Refusing to run code under test as root." >&2
  exit 98
fi
runner_root=\$(mktemp -d /var/lib/hotspotshade-vm-runner.XXXXXXXX) || exit 1
chown root:root -- "\$runner_root" || exit 1
chmod 755 -- "\$runner_root" || exit 1
cp -- $remote_runner "\$runner_root/run.sh" || exit 1
chown root:root -- "\$runner_root/run.sh" || exit 1
chmod 755 -- "\$runner_root/run.sh" || exit 1
copied=\$(sha256sum "\$runner_root/run.sh" | cut -d' ' -f1) || exit 1
if [ "\$copied" != "$runner_sha" ]; then
  echo "The root-owned runner copy does not match the pinned digest. Refusing to start." >&2
  exit 1
fi
rm -f $remote_log $remote_launcher_log
if [ "$mode" = tunnel ]; then
  # Diagnostic only. The host refuses to report a pass for this mode.
  setpriv --reuid=ubuntu --regid=ubuntu --init-groups \
    env -i HOME=/home/ubuntu PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TMPDIR=/tmp CARGO_NET_OFFLINE=true \
    bash "\$runner_root/run.sh" "$mode" "$sha256_pin" "$manifest_sha" \
    >"$remote_log" 2>&1 < /dev/null || true
else
  setpriv --reuid=ubuntu --regid=ubuntu --init-groups --no-new-privs \
    env -i HOME=/home/ubuntu PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TMPDIR=/tmp CARGO_NET_OFFLINE=true \
    bash "\$runner_root/run.sh" "$mode" "$sha256_pin" "$manifest_sha" \
    >"$remote_log" 2>&1 < /dev/null
fi
rm -rf -- "\$runner_root" || true
LAUNCH
)

# Remove any status directory that the image carried before the monitor starts.
# The removal runs in the foreground, so a stale record cannot be read as this
# run's result. The record also carries this run's unique slug, which an image
# cannot know in advance.
printf -v remote_command \
  'sudo -n rm -rf -- %s || exit 1; setsid nohup sudo -n bash -c %q > %s 2>&1 < /dev/null & echo STARTED' \
  "$remote_status_dir" "$launcher" "$remote_launcher_log"

# Mark the attempt before the call, not after it. The server can accept a
# create and still lose the client call to a signal, a timeout, or an error.
vm_maybe_created=1
npx -y "$freestyle_package" vm create \
  --snapshot-id "$snapshot_slug" \
  --slug "$vm_slug" \
  --display-name "HotspotShade Linux test" \
  --ephemeral --no-automatic-restart --no-internet --no-ssh \
  --idle-timeout-seconds 1800

# Upload only the private archive, the runner, and the reviewed file manifest.
# Never upload the caller's path, a sidecar, or a provenance file.
npx -y "$freestyle_package" vm fs write "$vm_slug" \
  /home/ubuntu/hotspotshade-source.tar.gz "$private_archive"
npx -y "$freestyle_package" vm fs write "$vm_slug" \
  "$remote_runner" "$runner"
npx -y "$freestyle_package" vm fs write "$vm_slug" \
  "$remote_manifest" "$manifest_file"

# Re-check the local inputs after the upload. A change here is a failed run,
# not a warning: the VM checks the same digests before it extracts or runs.
digest_upload=$(sha256_file "$private_archive") ||
  die "Cannot rehash the private archive after upload."
[ "$digest_upload" = "$sha256_pin" ] ||
  die "The private archive changed during the upload. The VM will be deleted."
runner_upload=$(sha256_file "$runner") ||
  die "Cannot rehash the private runner after upload."
[ "$runner_upload" = "$runner_sha" ] ||
  die "The private runner changed during the upload. The VM will be deleted."
manifest_upload=$(sha256_file "$manifest_file") ||
  die "Cannot rehash the verified file manifest after upload."
[ "$manifest_upload" = "$manifest_sha" ] ||
  die "The verified file manifest changed during the upload. The VM will be deleted."

# The launcher runs as root, binds the uploaded runner, and starts it as the
# non-root image user. The runner binds the archive and the file manifest before
# it lists or extracts either. Only the root monitor writes the status file.
npx -y "$freestyle_package" vm exec "$vm_slug" --timeout-ms 120000 -- bash -lc \
  "$remote_command"

deadline=$((SECONDS + 5400))
result=running
while [ "$SECONDS" -lt "$deadline" ]; do
  sleep 10
  poll_command="if [ -e $remote_status ]; then sudo -n cat $remote_status 2>/dev/null || echo unreadable; else echo running; fi"
  if ! result=$(npx -y "$freestyle_package" vm exec "$vm_slug" --timeout-ms 60000 -- bash -lc \
    "$poll_command" 2>/dev/null); then
    result=unreachable
    break
  fi
  # The monitor writes "<slug> running" first and "<slug> <exit status>" last.
  # A missing file reads as plain "running". Anything else is final.
  if [ "$result" = "$vm_slug running" ]; then
    result=running
  fi
  if [ "$result" != running ]; then
    break
  fi
done

# Accept a status only when it names this run's unique slug and holds a plain
# exit status. A record from the image, another run, or a forged shape is
# foreign and never counts as a pass.
status_code=foreign
case "$result" in
  running|unreachable|unreadable)
    status_code=$result
    ;;
  "$vm_slug "*)
    status_code=${result#"$vm_slug "}
    case "$status_code" in
      ''|*[!0-9]*) status_code=foreign ;;
    esac
    ;;
esac

# Never render raw helper, archive, or test output as a terminal control stream.
npx -y "$freestyle_package" vm exec "$vm_slug" --timeout-ms 120000 -- bash -lc \
  "tail -200 $remote_log" 2>/dev/null | cat -v || true

# Tunnel evidence needs a separate trusted root monitor that the root test binary
# cannot reach. None exists, so this mode never reports a pass, whatever the
# status says.
if [ "$mode" = tunnel ]; then
  if [ "$status_code" = 0 ]; then
    echo "Tunnel diagnostic completed, but no pass is reported. A root test binary can forge any status path, so this mode is not evidence." >&2
  else
    echo "Tunnel diagnostic did not complete cleanly (status: $status_code). No pass is reported." >&2
  fi
  exit 1
fi

case "$status_code" in
  0)
    echo "Linux test passed in $vm_slug ($mode mode)."
    echo "  snapshot: $snapshot_slug"
    echo "  archive_sha256: $sha256_pin"
    echo "  verified_files_sha256: $manifest_sha"
    ;;
  running)
    echo "Linux test did not finish before the deadline." >&2
    exit 1
    ;;
  unreachable)
    echo "The VM did not answer a poll. Check the log above." >&2
    exit 1
    ;;
  unreadable)
    echo "The root-owned status file could not be read. Refusing to report a result." >&2
    exit 1
    ;;
  foreign)
    echo "The status record does not name this run or is malformed. Refusing to report a result." >&2
    exit 1
    ;;
  *)
    echo "Linux test failed in $vm_slug ($mode mode)." >&2
    exit 1
    ;;
esac
