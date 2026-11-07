#!/bin/sh
# Build or verify a reviewed source snapshot archive for a disposable Linux
# VM or a Windows test host. This is a test input, not a release artifact.
#
# The archive holds only the paths named in an explicit manifest. It never
# walks the work tree on its own. Use --list to write a candidate list of
# tracked files, then add intentional untracked source by path.
#
# Usage:
#   scripts/source_snapshot.sh --manifest FILE --output FILE [--repo DIR] [--force]
#   scripts/source_snapshot.sh --list [--repo DIR]
#   scripts/source_snapshot.sh --verify FILE --expect-sha256 HEX
#   scripts/source_snapshot.sh --verify FILE --corruption-only
#   scripts/source_snapshot.sh --verify FILE --expect-sha256 HEX --extract-to DIR
#   scripts/source_snapshot.sh --verify FILE --expect-sha256 HEX --files-manifest-out FILE
#
# Manifest format:
#   [ + ] <64 lower-case hex sha256>  <repository-relative path>
#
# Blank lines and lines that start with # are comments. The two spaces after
# the digest are required, as in a sha256sum file. A leading "+ " marks an
# explicit opt-in for a path that is untracked, or a tracked path whose work
# tree content differs from the index or HEAD. A clean tracked file needs no
# opt-in. The pinned digest must match the content that is archived.
#
# Every path must name a file below rust/, desktop/, linux/, gui_assets/,
# assets/, or windows/. A bare root name such as "rust" is rejected. A full
# build snapshot includes rust/Cargo.lock, desktop/Cargo.lock, and
# linux/package-lock.json.
#
# The build writes five files:
#   FILE                  gzip-compressed ustar archive
#   FILE.sha256           SHA-256 of FILE
#   FILE.files.sha256     one "<sha256>  <path>" line per archived file
#   FILE.manifest.sha256  SHA-256 of the reviewed manifest
#   FILE.provenance       HEAD, dirty state, counts, and both digests
#
# --verify opens no git repository. Pass --expect-sha256 with a digest obtained
# outside the archive set for an independent check. With that digest, the
# archive may be verified and extracted alone, with no sidecars: the digest
# pins the exact archive bytes, and every entry name, type, mode, owner, size,
# modification time, device number, and path is validated before extraction.
# If any sidecar is present, all four are required and checked against the
# archive. A sidecar alone is not an independent trust anchor: an attacker who
# rewrites the archive and every sidecar can keep them consistent. Without
# --expect-sha256, --corruption-only must be named and the full sidecar set is
# required; the result is a corruption check only. --extract-to needs
# --expect-sha256.
# --files-manifest-out writes validated per-file digests. Extraction requires
# a destination that does not exist. Outputs are pending through the success
# message and work-directory cleanup. On failure the helper attempts cleanup
# and reports paths it cannot safely remove. Once exit cleanup commits outputs,
# handled signals are ignored and success is returned. SIGKILL and crashes can
# leave partial outputs. --force replaces files and cannot restore old bytes.
#
# Every numeric tar header field must use canonical octal digits followed only
# by NUL or space padding. A leading NUL or space, or a digit after padding,
# is rejected. A device major or minor field may also be all NUL, which means
# zero; every other value is rejected for a regular file. This matters because
# bsdtar and GNU tar read a non-canonical field differently: a size field that
# starts with NUL is 0 to bsdtar but a large number to GNU tar, which
# desynchronizes header parsing from extraction. The modification time must be
# the fixed build time 946684800, the link name field must be all NUL, the owner
# and group name fields must be printable ASCII or NUL, and the padding at the
# end of the header must be zero.
#
# Git paths that hold a newline or another control byte are rejected before
# the NUL-separated listing is converted to lines. Such a path could otherwise
# create a false tracked or clean match for a different manifest path. The
# repository root must expose a real .git directory, or a .git file that
# resolves to a linked-worktree git directory. A repository that sets
# core.worktree, or a .git file that resolves to the common git directory, is
# rejected as an unsupported identity redirection. A submodule root is refused
# for that reason. Tracked paths in the
# manifest are compared with the index content and with HEAD content, not only
# with git diff, so assume-unchanged and skip-worktree bits cannot produce a
# clean claim. Such a path is counted as modified and needs a leading "+ ".
#
# Path rules reject .git, .t3, build output, caches, probes, symlinks,
# hardlinked source, parent components, absolute paths, root-only paths,
# Windows-unsafe names, reserved Windows device names (CON, PRN, AUX, NUL,
# COM1-COM9, LPT1-LPT9, CONIN$, CONOUT$, and CLOCK$), non-ASCII names,
# case-fold collisions including a case-fold ancestor of another file,
# private-key and credential names, certificates, and packet captures. An
# untracked path that git ignores is rejected; a tracked path is accepted even
# if an ignore pattern matches it. These rules check names and link shape.
# They do not read file contents and do not prove that a file is free of a
# secret. An expanded list of suspicious names does not change that limit.
# Review every manifest entry before you send the archive.
#
# The same manifest on one host with the same tar and gzip gives the same
# archive bytes. A different tar or gzip implementation can change header
# bytes, so the archive digest is not promised to match across platforms.
#
# Residual race: POSIX shell has no openat(O_NOFOLLOW) primitive. The build
# copies with cp -P, checks the staged entry, compares the pinned digest, and
# compares the source device, inode, link count, and size before and after the
# copy. A source swap that is fully restored before the post-copy check and
# whose content matches the pinned digest is not distinguishable. The pinned
# digest is the content authority; the identity check is a second signal.
# Extraction uses a newly created directory. Every ancestor is checked as a
# real directory, every file is prepared in the private work directory, and
# each destination is created with "ln -n" so that a planted symlink or
# hardlink makes the link fail instead of writing through it. The destination
# inode, link count, size, digest, and ancestors are checked again after the
# link, and the extraction root identity is checked before the run succeeds.
# "ln -n" is a GNU and BSD extension. A system whose ln rejects -n fails closed
# and cannot extract; it never falls back to a following link.
# Extraction, files-manifest, and build output destinations must share a
# filesystem with TMPDIR: publication uses hard links and fails across devices.
# Use private parent directories for all outputs and TMPDIR. POSIX shell cannot
# atomically verify an inode and unlink it, or hold a directory descriptor for
# recursive cleanup. A same-user writer can still replace an ancestor directory
# after the check and before the link. That writer can make the link land in a
# different directory. Later checks may catch the swap, but do not prove that
# every replacement is detected and cannot undo a link that already landed.
# A writer can also swap paths
# between checks and operations, including after mkdir, during recursive
# cleanup, and during --force replacement. A temporary output file can be
# swapped between its identity check and the cp that fills it; the post-copy
# identity check reports the swap but cannot undo an overwrite that already
# happened. Identity checks detect some swaps, not all. Do not use shared or
# hostile directories.
#
# Gzip validation rejects corruption and trailing non-gzip bytes, but it does
# not prove that the stream holds exactly one gzip member. The tar structure
# check is the authority on archive contents.

set -eu
umask 022
LC_ALL=C
export LC_ALL

script_name=$(basename "$0")
allowed_roots="rust desktop linux gui_assets assets windows"
fixed_utc_stamp=200001010000.00
max_path_bytes=240
max_component_bytes=100
max_raw_bytes=268435456
tab=$(printf '\t')

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

die() {
  printf '%s: %s\n' "$script_name" "$*" >&2
  exit 1
}

# Print the lower-case SHA-256 of a regular file. Return non-zero for an
# unreadable path or an empty/malformed digest. The caller must not treat an
# empty string as a digest.
sha256_file() {
  hf_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    hf_out=$(sha256sum -- "$hf_path") || return 1
    hf_digest=${hf_out%% *}
  elif command -v shasum >/dev/null 2>&1; then
    hf_out=$(shasum -a 256 -- "$hf_path") || return 1
    hf_digest=${hf_out%% *}
  elif command -v openssl >/dev/null 2>&1; then
    hf_out=$(openssl dgst -sha256 "$hf_path") || return 1
    hf_digest=${hf_out##*= }
  else
    die "No SHA-256 tool is available."
  fi
  case "$hf_digest" in
    ''|*[!0-9a-f]*) return 1 ;;
  esac
  if [ "${#hf_digest}" -ne 64 ]; then
    return 1
  fi
  printf '%s\n' "$hf_digest"
}

# Detect the stat dialect once. Both dialects use lstat semantics by default.
stat_mode=bsd
if stat -c '%d' / >/dev/null 2>&1; then
  stat_mode=gnu
fi

# Print "kind|device|inode|links|size" without following a final symlink.
# The caller must check the exit status.
lstat_fields() {
  lf_path=$1
  if [ "$stat_mode" = gnu ]; then
    lf_line=$(stat -c '%F|%d|%i|%h|%s' -- "$lf_path" 2>/dev/null) || return 1
  else
    lf_line=$(stat -f '%HT|%d|%i|%l|%z' -- "$lf_path" 2>/dev/null) || return 1
  fi
  lf_type=${lf_line%%|*}
  lf_rest=${lf_line#*|}
  lf_dev=${lf_rest%%|*}
  lf_rest=${lf_rest#*|}
  lf_ino=${lf_rest%%|*}
  lf_rest=${lf_rest#*|}
  lf_links=${lf_rest%%|*}
  lf_size=${lf_rest#*|}
  case "$lf_type" in
    *egular*) lf_kind=file ;;
    *ymbolic*) lf_kind=symlink ;;
    [Dd]irectory) lf_kind=dir ;;
    *) lf_kind=other ;;
  esac
  printf '%s|%s|%s|%s|%s\n' \
    "$lf_kind" "$lf_dev" "$lf_ino" "$lf_links" "$lf_size"
}

# Split a lstat_fields line into sf_ variables.
split_fields() {
  sf_line=$1
  sf_kind=${sf_line%%|*}
  sf_rest=${sf_line#*|}
  sf_dev=${sf_rest%%|*}
  sf_rest=${sf_rest#*|}
  sf_ino=${sf_rest%%|*}
  sf_rest=${sf_rest#*|}
  sf_links=${sf_rest%%|*}
  sf_size=${sf_rest#*|}
}

# Return 0 when a lower-case path matches a private, credential, or build
# output rule. The caller has already lower-cased the path.
is_denied_lower() {
  denied=$1
  case "/$denied/" in
    */.git/*|*/.t3/*|*/.svn/*|*/.hg/*|*/node_modules/*|*/target/*|\
    */build/*|*/dist/*|*/coverage/*|*/.build/*|*/.swiftpm/*|\
    */xcuserdata/*|*/deriveddata/*|*/.gradle/*|*/probes/*|*/.shots/*|\
    */__pycache__/*|*/.venv/*|*/venv/*|*/.cache/*|*/.idea/*|\
    */.vscode/*|*/.ssh/*|*/.aws/*|*/.azure/*|*/.config/*|*/.cargo/*|\
    */.rustup/*|*/.m2/*|*/.docker/*|*/.kube/*|*/.gnupg/*|*/.npm/*|\
    */.yarn/*|*/.pnpm/*|*/.pnpm-store/*|*/secrets/*|*/secret/*|\
    */credentials/*|*/private/*|*/.terraform/*|*/.terraform.d/*|\
    */.vagrant/*|*/.android/*|*/.kotlin/*|*/.dart_tool/*|\
    */.pub-cache/*|*/.pytest_cache/*|*/.mypy_cache/*|*/.tox/*|\
    */.nox/*|*/.ruff_cache/*|*/.next/*|*/.nuxt/*|*/.turbo/*|\
    */.parcel-cache/*|*/.svelte-kit/*|*/.astro/*|*/.angular/*|\
    */.zig-cache/*|*/zig-out/*|*/.deno/*|*/.direnv/*|*/.jupyter/*|\
    */.ipynb_checkpoints/*|*/.password-store/*|*/__MACOSX/*|\
    */.Trashes/*|*/.Spotlight-V100/*|*/.fseventsd/*)
      return 0 ;;
  esac
  case "$denied" in
    linux/build/*|desktop/gen/*|windows/bin/*|windows/obj/*)
      return 0 ;;
  esac
  base=${denied##*/}
  case "$base" in
    *.pem|*.key|*.p12|*.pfx|*.p8|*.cer|*.crt|*.csr|*.der|*.jks|\
    *.keystore|*.mobileprovision|*.provisionprofile|*.mobileconfig|\
    *.p7b|*.p7c|*.pkcs12|*.pkcs8|*.psafe3|*.kdb|*.wallet|\
    *.pcap|*.pcapng|*.cap|*.har|*.rlib|*.apk|*.aab|*.deb|*.ipa|*.dmg|\
    *.exe|*.dll|*.so|*.dylib|*.o|*.a|*.class|*.jar|*.log|*.sqlite|\
    *.sqlite3|*.db|*.core|core.*|*.zip|*.tar|*.tar.gz|*.tgz|*.gz|*.7z|\
    *.rar|*.xz|*.bz2|*.zst|*.bak|*.orig|*.rej|*.swp|*.tmp|*~|\
    *.ovpn|*.kdbx|*.age|*.gpg|*.asc|*.ppk|*.tfstate|*.tfvars|\
    *.sql|*.pcap.*|*.key.*|*.pem.*|*.secret|*.secrets|*.sops|\
    *.env|*.envrc|*.token|*.tokens|*.keychain-db|*.keychain|\
    id_rsa|id_rsa.*|id_ed25519|id_ed25519.*|id_ecdsa|id_ecdsa.*|\
    id_dsa|id_dsa.*|authorized_keys|known_hosts|.htpasswd|\
    .env|.env.*|.envrc|.netrc|.npmrc|.yarnrc|.pypirc|.git-credentials|\
    .authinfo|.ds_store|thumbs.db|desktop.ini|local.properties|auth.json|\
    credentials.json|secrets.json|service-account.json|\
    googleservice-info.plist|token|tokens|\
    secret|secrets|credential|credentials|password|passwords|\
    *.local|*.local.*)
      if [ "$base" = ".env.example" ]; then
        return 1
      fi
      return 0 ;;
  esac
  return 1
}

# Validate a manifest or archive path without touching the work tree. Exit on
# the first problem. This function uses globals with a vp_ prefix because
# POSIX sh has no local variables.
validate_path_lexical() {
  vp_path=$1
  if [ -z "$vp_path" ]; then
    die "empty path in manifest"
  fi
  case "$vp_path" in
    /*) die "absolute path is not allowed: $vp_path" ;;
    *\\*) die "backslash is not allowed: $vp_path" ;;
  esac
  if printf '%s' "$vp_path" | grep -q '[^ -~]'; then
    die "path holds a byte outside printable ASCII: $vp_path"
  fi
  case "$vp_path" in
    */|*/./*|./*|*/../*|../*|*/.|*/..|..|.|*//*)
      die "path has an empty, dot, or parent component: $vp_path" ;;
  esac
  vp_root=${vp_path%%/*}
  case " $allowed_roots " in
    *" $vp_root "*) ;;
    *) die "path is outside the source allowlist ($allowed_roots): $vp_path" ;;
  esac
  case "$vp_path" in
    */*) ;;
    *) die "path must name a file below an allowlisted root: $vp_path" ;;
  esac
  if [ "${#vp_path}" -gt "$max_path_bytes" ]; then
    die "path is longer than $max_path_bytes bytes: $vp_path"
  fi
  vp_old_ifs=$IFS
  IFS=/
  set -f
  for vp_comp in $vp_path; do
    case "$vp_comp" in
      ''|.|..) die "path has an empty, dot, or parent component: $vp_path" ;;
      *:*) die "colon is not allowed in a path component: $vp_path" ;;
      *'*'*|*'?'*|*'<'*|*'>'*|*'|'*|*'"'*)
        die "a path component uses a character that Windows rejects: $vp_path" ;;
      ' '*) die "a path component starts with a space: $vp_path" ;;
      *' '|*.) die "a path component ends with a space or dot: $vp_path" ;;
    esac
    if [ "${#vp_comp}" -gt "$max_component_bytes" ]; then
      die "a path component is longer than $max_component_bytes bytes: $vp_path"
    fi
    vp_lower=$(printf '%s' "$vp_comp" | tr '[:upper:]' '[:lower:]')
    vp_stem=${vp_lower%%.*}
    case "$vp_stem" in
      con|prn|aux|nul|com[1-9]|lpt[1-9]|"conin$"|"conout$"|"clock$")
        die "path uses a reserved Windows name: $vp_path" ;;
    esac
  done
  IFS=$vp_old_ifs
  set +f
  vp_lower=$(printf '%s' "$vp_path" | tr '[:upper:]' '[:lower:]')
  if is_denied_lower "$vp_lower"; then
    die "path is excluded as private, credential, or build output: $vp_path"
  fi
}

# Prove that a path is a regular file inside the repository, that no path
# component is a symlink, and that the file has exactly one link.
check_repo_file() {
  cr_path=$1
  cr_prefix=
  cr_old_ifs=$IFS
  IFS=/
  set -f
  for cr_comp in $cr_path; do
    if [ -z "$cr_prefix" ]; then
      cr_prefix=$cr_comp
    else
      cr_prefix=$cr_prefix/$cr_comp
    fi
    if ! cr_fields=$(lstat_fields "$repo/$cr_prefix"); then
      IFS=$cr_old_ifs
      set +f
      die "manifest entry is missing: $cr_prefix"
    fi
    split_fields "$cr_fields"
    if [ "$cr_prefix" = "$cr_path" ]; then
      if [ "$sf_kind" != file ]; then
        IFS=$cr_old_ifs
        set +f
        die "manifest entry is not a regular file: $cr_path"
      fi
    else
      if [ "$sf_kind" = symlink ]; then
        IFS=$cr_old_ifs
        set +f
        die "manifest entry crosses a symlink: $cr_prefix"
      fi
      if [ "$sf_kind" != dir ]; then
        IFS=$cr_old_ifs
        set +f
        die "manifest entry crosses a non-directory: $cr_prefix"
      fi
    fi
  done
  IFS=$cr_old_ifs
  set +f
  cr_dir=${cr_path%/*}
  cr_base=${cr_path##*/}
  if command -v realpath >/dev/null 2>&1; then
    cr_real=$(realpath "$repo/$cr_path") || die "cannot resolve: $cr_path"
  else
    cr_real=$(CDPATH= cd "$repo/$cr_dir" && pwd -P)/$cr_base ||
      die "cannot resolve: $cr_path"
  fi
  case "$cr_real" in
    "$repo"/*) ;;
    *) die "manifest entry resolves outside the repository: $cr_path" ;;
  esac
  if ! cr_fields=$(lstat_fields "$repo/$cr_path"); then
    die "manifest entry is missing: $cr_path"
  fi
  split_fields "$cr_fields"
  if [ "$sf_links" != 1 ]; then
    die "manifest entry has $sf_links hard links, expected 1: $cr_path"
  fi
}

# Run git with a neutral configuration. It reads no user or system config,
# uses no hooks, no fsmonitor, no external diff, and no optional index locks.
git_neutral() {
  gn_dir=$1
  shift
  (
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
      GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_COMMON_DIR \
      GIT_CEILING_DIRECTORIES GIT_CONFIG GIT_CONFIG_PARAMETERS \
      GIT_CONFIG_COUNT
    HOME=$work/home
    XDG_CONFIG_HOME=$work/home/.config
    GIT_CONFIG_NOSYSTEM=1
    GIT_CONFIG_GLOBAL=$work/home/.gitconfig
    GIT_CONFIG_SYSTEM=$work/home/.gitconfig
    GIT_ATTR_NOSYSTEM=1
    GIT_OPTIONAL_LOCKS=0
    GIT_TERMINAL_PROMPT=0
    GIT_PAGER=cat
    export HOME XDG_CONFIG_HOME GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL \
      GIT_CONFIG_SYSTEM GIT_ATTR_NOSYSTEM GIT_OPTIONAL_LOCKS \
      GIT_TERMINAL_PROMPT GIT_PAGER
    git \
      -c core.fsmonitor=false \
      -c core.untrackedCache=false \
      -c core.useBuiltinFSMonitor=false \
      -c core.hooksPath="$work/home/nohooks" \
      -c core.excludesFile="$work/home/gitignore" \
      -c core.attributesFile="$work/home/gitattributes" \
      -c gc.auto=0 \
      -c maintenance.auto=false \
      -c diff.external= \
      -C "$gn_dir" "$@"
  )
}

# Reject a git path stream that holds a control byte before any NUL-to-line
# conversion. A newline inside a tracked path would otherwise become two lines
# and could make an ignored or untracked manifest path look tracked and clean.
check_git_name_stream() {
  cg_file=$1
  cg_label=$2
  if ! od -An -v -tu1 "$cg_file" > "$work/git-name-bytes"; then
    die "Cannot inspect git $cg_label path bytes."
  fi
  if ! awk '
    {
      for (i = 1; i <= NF; i++) {
        b = $i + 0
        if ((b > 0 && b < 32) || b == 127) {
          print "control"
          exit
        }
      }
    }
  ' "$work/git-name-bytes" > "$work/git-name-invalid"; then
    die "Cannot validate git $cg_label path bytes."
  fi
  if [ -s "$work/git-name-invalid" ]; then
    die "git reported a $cg_label path with a newline or another control byte; this tool cannot represent it safely."
  fi
}

# Resolve a git work tree and prove that its identity is the one git reports.
# This rejects an ancestor core.worktree redirect, a planted .git entry, and a
# .git file that resolves to the common git directory instead of a linked
# worktree git directory. A submodule root is refused for that reason. Sets
# repo to the canonical work tree root.
resolve_repo() {
  rr_requested=$1
  [ -d "$rr_requested" ] || die "Not a directory: $rr_requested"
  rr_requested_real=$(CDPATH= cd "$rr_requested" && pwd -P) ||
    die "Cannot enter $rr_requested"
  rr_top=$(git_neutral "$rr_requested" rev-parse --show-toplevel 2>/dev/null) ||
    die "Not a git work tree: $rr_requested"
  rr_top=$(CDPATH= cd "$rr_top" 2>/dev/null && pwd -P) ||
    die "Cannot resolve the git work tree root: $rr_top"
  case "$rr_requested_real" in
    "$rr_top"|"$rr_top"/*) ;;
    *) die "The git work tree root is not an ancestor of $rr_requested_real" ;;
  esac
  rr_config_status=0
  rr_core_worktree=$(git_neutral "$rr_top" config --get core.worktree \
    2>/dev/null) || rr_config_status=$?
  if [ "$rr_config_status" -gt 1 ]; then
    die "Cannot read the repository configuration: $rr_top"
  fi
  if [ -n "$rr_core_worktree" ]; then
    die "The repository sets core.worktree, which this tool does not support: $rr_top"
  fi
  rr_config_status=0
  rr_bare=$(git_neutral "$rr_top" config --get core.bare 2>/dev/null) ||
    rr_config_status=$?
  if [ "$rr_config_status" -gt 1 ]; then
    die "Cannot read the repository configuration: $rr_top"
  fi
  case "$rr_bare" in
    true|1|yes|on) die "The repository is bare: $rr_top" ;;
  esac
  rr_git_dir=$(git_neutral "$rr_top" rev-parse --absolute-git-dir \
    2>/dev/null) || die "Cannot resolve the git directory: $rr_top"
  rr_git_dir=$(CDPATH= cd "$rr_git_dir" 2>/dev/null && pwd -P) ||
    die "Cannot resolve the git directory: $rr_git_dir"
  [ -d "$rr_git_dir" ] ||
    die "The git directory is not a directory: $rr_git_dir"
  rr_common=$(git_neutral "$rr_top" rev-parse --git-common-dir 2>/dev/null) ||
    die "Cannot resolve the common git directory: $rr_top"
  case "$rr_common" in
    /*) ;;
    *) rr_common=$rr_top/$rr_common ;;
  esac
  rr_common=$(canonical_target "$rr_common") ||
    die "Cannot resolve the common git directory: $rr_common"
  [ -d "$rr_common" ] ||
    die "The common git directory is not a directory: $rr_common"
  if ! rr_dotgit=$(lstat_fields "$rr_top/.git"); then
    die "The work tree root has no .git entry: $rr_top"
  fi
  split_fields "$rr_dotgit"
  case "$sf_kind" in
    dir)
      rr_dotgit_real=$(CDPATH= cd "$rr_top/.git" && pwd -P) ||
        die "Cannot resolve $rr_top/.git"
      if [ "$rr_dotgit_real" != "$rr_git_dir" ]; then
        die "The work tree .git directory does not match the git directory: $rr_top"
      fi
      ;;
    file)
      rr_line=$(sed -n '1p' "$rr_top/.git") ||
        die "Cannot read $rr_top/.git"
      case "$rr_line" in
        'gitdir: '?*) rr_pointer=${rr_line#gitdir: } ;;
        *) die "Unsupported .git file: $rr_top/.git" ;;
      esac
      case "$rr_pointer" in
        /*) ;;
        *) rr_pointer=$rr_top/$rr_pointer ;;
      esac
      rr_pointer=$(canonical_target "$rr_pointer") ||
        die "Cannot resolve the .git pointer: $rr_top/.git"
      if [ "$rr_pointer" != "$rr_git_dir" ]; then
        die "The .git pointer does not match the git directory: $rr_top"
      fi
      if [ "$rr_git_dir" = "$rr_common" ]; then
        die "A .git file resolves to the common git directory; this identity is not supported: $rr_top"
      fi
      ;;
    *)
      die "The work tree root has an unsupported .git entry: $rr_top/.git"
      ;;
  esac
  repo=$rr_top
}

# Keep only paths below the source allowlist. Input is a sorted line list.
filter_allowed_paths() {
  fp_in=$1
  fp_out=$2
  awk -v roots="$allowed_roots" '
    BEGIN { n = split(roots, r, " "); for (i = 1; i <= n; i++) ok[r[i]] = 1 }
    {
      slash = index($0, "/")
      if (slash > 1 && (substr($0, 1, slash - 1) in ok)) print
    }
  ' "$fp_in" > "$fp_out" || die "Cannot filter allowed source paths."
}

# Load tracked, modified, and assume-unchanged/skip-worktree state. Every raw
# git name stream is checked for control bytes before it reaches a line list.
# Sets head_present to 1 or 0 for the caller.
load_git_state() {
  lg_repo=$1
  git_neutral "$lg_repo" ls-files -z --cached > "$work/tracked.raw" ||
    die "git ls-files failed."
  check_git_name_stream "$work/tracked.raw" "tracked"
  tr '\0' '\n' < "$work/tracked.raw" > "$work/tracked.lines" ||
    die "Cannot decode tracked git paths."
  LC_ALL=C sort -u "$work/tracked.lines" > "$work/tracked.all" ||
    die "Cannot sort tracked git paths."
  filter_allowed_paths "$work/tracked.all" "$work/tracked.names"
  : > "$work/modified.names"
  git_neutral "$lg_repo" diff-files --name-only -z --no-ext-diff \
    > "$work/diff-files.raw" || die "git diff-files failed."
  check_git_name_stream "$work/diff-files.raw" "modified"
  tr '\0' '\n' < "$work/diff-files.raw" >> "$work/modified.names" ||
    die "Cannot decode modified git paths."
  head_present=0
  if git_neutral "$lg_repo" rev-parse --verify -q HEAD >/dev/null 2>&1; then
    head_present=1
    git_neutral "$lg_repo" diff-index --name-only -z --no-ext-diff HEAD \
      > "$work/diff-index.raw" || die "git diff-index failed."
    check_git_name_stream "$work/diff-index.raw" "modified"
    tr '\0' '\n' < "$work/diff-index.raw" >> "$work/modified.names" ||
      die "Cannot decode modified index paths."
  fi
  LC_ALL=C sort -u "$work/modified.names" > "$work/modified.sorted" ||
    die "Cannot sort modified git paths."
  git_neutral "$lg_repo" ls-files -v -z --cached > "$work/tags.raw" ||
    die "git ls-files -v failed."
  check_git_name_stream "$work/tags.raw" "index flag"
  tr '\0' '\n' < "$work/tags.raw" > "$work/tags.lines" ||
    die "Cannot decode git index flags."
  awk '{
      tag = substr($0, 1, 1)
      if (tag ~ /[a-z]/ || tag == "S") print substr($0, 3)
    }' "$work/tags.lines" > "$work/hidden.lines" ||
    die "Cannot read git index flags."
  LC_ALL=C sort -u "$work/hidden.lines" > "$work/hidden.all" ||
    die "Cannot sort git index flags."
  filter_allowed_paths "$work/hidden.all" "$work/hidden.names"
}

# Compare a tracked file with the index blob and with the HEAD blob. This does
# not use git diff, so assume-unchanged and skip-worktree cannot hide a content
# change. Sets tcs_modified to 1 when either comparison differs.
tracked_content_state() {
  tcs_path=$1
  tcs_digest=$2
  tcs_modified=0
  if ! git_neutral "$repo" cat-file blob ":$tcs_path" \
    > "$work/index.blob" 2>/dev/null; then
    die "Cannot read the index content for: $tcs_path"
  fi
  tcs_sum=$(sha256_file "$work/index.blob") ||
    die "Cannot hash the index content for: $tcs_path"
  if [ "$tcs_sum" != "$tcs_digest" ]; then
    tcs_modified=1
  fi
  if [ "$head_present" -eq 1 ]; then
    if git_neutral "$repo" cat-file -e "HEAD:$tcs_path" 2>/dev/null; then
      if ! git_neutral "$repo" cat-file blob "HEAD:$tcs_path" \
        > "$work/head.blob" 2>/dev/null; then
        die "Cannot read the HEAD content for: $tcs_path"
      fi
      tcs_sum=$(sha256_file "$work/head.blob") ||
        die "Cannot hash the HEAD content for: $tcs_path"
      if [ "$tcs_sum" != "$tcs_digest" ]; then
        tcs_modified=1
      fi
    else
      tcs_modified=1
    fi
  fi
  return 0
}

# Parse and validate a tar stream. The awk pass reads raw header bytes from od,
# so it does not depend on a human-readable tar listing. It accepts only
# regular files in a POSIX ustar header with uid 0, gid 0, and mode 0644 or
# 0755. Every numeric field must hold octal digits followed only by NUL or
# space padding; a leading NUL or space or a digit after padding is rejected.
# That keeps this parser aligned with bsdtar and GNU tar, which disagree about
# such a field. It rejects pax, GNU long-name, directory, symlink, hardlink,
# device, fifo, sparse, and unknown entries. It prints "<mode><TAB><path>" per
# entry.
validate_tar() {
  vt_tar=$1
  vt_entries=$2
  vt_size=$(wc -c < "$vt_tar" | tr -d ' ')
  if [ "$vt_size" -eq 0 ] || [ $((vt_size % 512)) -ne 0 ]; then
    die "Archive is not a whole number of 512-byte blocks."
  fi
  if ! od -An -v -tu1 "$vt_tar" | awk '
    function fail(msg) {
      printf "source_snapshot: archive rejected: %s\n", msg > "/dev/stderr"
      bad = 1
      exit 3
    }
    function parse_octal(start, len,   i, c, v, digits, padded) {
      v = 0
      digits = 0
      padded = 0
      for (i = start; i < start + len; i++) {
        c = b[i]
        if (c == 0 || c == 32) {
          padded = 1
          continue
        }
        if (c < 48 || c > 55) return -1
        if (padded) return -1
        v = v * 8 + (c - 48)
        digits++
      }
      if (!digits) return -1
      return v
    }
    function parse_octal_zero_ok(start, len,   i, c, v, digits, padded, zeros) {
      v = 0
      digits = 0
      padded = 0
      zeros = 0
      for (i = start; i < start + len; i++) {
        c = b[i]
        if (c == 0) {
          padded = 1
          zeros++
          continue
        }
        if (c == 32) {
          padded = 1
          continue
        }
        if (c < 48 || c > 55) return -1
        if (padded) return -1
        v = v * 8 + (c - 48)
        digits++
      }
      if (!digits && zeros == len) return 0
      if (!digits) return -1
      return v
    }
    function field_str(start, len,   i, c, s) {
      s = ""
      for (i = start; i < start + len; i++) {
        c = b[i]
        if (c == 0) break
        if (c < 32 || c > 126) return "\001"
        s = s sprintf("%c", c)
      }
      return s
    }
    function all_nul(start, len,   i) {
      for (i = start; i < start + len; i++) {
        if (b[i] != 0) return 0
      }
      return 1
    }
    function process_block(   i, allzero, sum, chk, mode, uid, gid, size, \
                              mtime, devmajor, devminor, tflag, name, \
                              prefix, path, uname, gname) {
      if (skip > 0) {
        skip--
        return
      }
      allzero = 1
      for (i = 1; i <= 512; i++) {
        if (b[i] != 0) { allzero = 0; break }
      }
      if (saw_end) {
        if (!allzero) fail("data after the end-of-archive marker")
        zero_run++
        return
      }
      if (allzero) {
        saw_end = 1
        zero_run = 1
        return
      }
      sum = 0
      for (i = 1; i <= 512; i++) {
        if (i >= 149 && i <= 156) sum += 32
        else sum += b[i]
      }
      chk = parse_octal(149, 8)
      if (chk < 0) fail("malformed header checksum field")
      if (chk != sum) fail("header checksum mismatch")
      if (b[258] != 117 || b[259] != 115 || b[260] != 116 || \
          b[261] != 97 || b[262] != 114 || b[263] != 0)
        fail("not a POSIX ustar header")
      if (b[264] != 48 || b[265] != 48)
        fail("unsupported ustar version")
      tflag = b[157]
      if (tflag == 0) tflag = 48
      if (tflag == 120 || tflag == 103)
        fail("pax extended header is not allowed")
      if (tflag == 76 || tflag == 75)
        fail("GNU long-name header is not allowed")
      if (tflag != 48)
        fail("non-regular entry type is not allowed")
      mode = parse_octal(101, 8)
      if (mode < 0) fail("malformed mode field")
      if (mode != 420 && mode != 493)
        fail("unsafe file mode " sprintf("%04o", mode))
      uid = parse_octal(109, 8)
      if (uid < 0) fail("malformed uid field")
      if (uid != 0) fail("untrusted uid")
      gid = parse_octal(117, 8)
      if (gid < 0) fail("malformed gid field")
      if (gid != 0) fail("untrusted gid")
      size = parse_octal(125, 12)
      if (size < 0) fail("malformed size field")
      mtime = parse_octal(137, 12)
      if (mtime < 0) fail("malformed mtime field")
      devmajor = parse_octal_zero_ok(330, 8)
      if (devmajor < 0) fail("malformed devmajor field")
      if (devmajor != 0) fail("unexpected device major number")
      devminor = parse_octal_zero_ok(338, 8)
      if (devminor < 0) fail("malformed devminor field")
      if (devminor != 0) fail("unexpected device minor number")
      if (mtime != 946684800) fail("unexpected modification time")
      if (!all_nul(158, 100)) fail("link name field is not empty")
      uname = field_str(266, 32)
      gname = field_str(298, 32)
      if (index(uname, "\001") || index(gname, "\001"))
        fail("non-ASCII or control byte in an owner name")
      if (!all_nul(501, 12)) fail("nonzero padding at the end of a header")
      name = field_str(1, 100)
      prefix = field_str(346, 155)
      if (index(name, "\001") || index(prefix, "\001"))
        fail("non-ASCII or control byte in an entry name")
      if (name == "") fail("empty entry name")
      if (prefix == "") path = name
      else path = prefix "/" name
      entries++
      printf "%o\t%d\t%s\n", mode, size, path
      skip = int((size + 511) / 512)
    }
    {
      for (i = 1; i <= NF; i++) {
        b[++nb] = $i + 0
        if (nb == 512) {
          process_block()
          nb = 0
        }
      }
    }
    END {
      if (bad) exit 3
      if (nb != 0) fail("truncated header block")
      if (skip > 0) fail("truncated file data")
      if (!saw_end) fail("missing end-of-archive marker")
      if (zero_run < 2) fail("missing two zero blocks")
    }
  ' > "$vt_entries"; then
    die "Archive structure is not safe."
  fi
}

# Reject duplicate paths, case-fold duplicates, and any case-folded path that
# is a directory ancestor of another path. The ancestor check reads the whole
# case-folded set, so an unrelated entry that sorts between the two, such as
# "b-c" between "b" and "b/c", cannot hide the collision. Input is a sorted
# path list.
check_path_set() {
  cps_file=$1
  cps_label=$2
  if ! uniq -d "$cps_file" > "$work/duplicate-paths"; then
    die "Cannot check duplicate paths in $cps_label."
  fi
  if [ -s "$work/duplicate-paths" ]; then
    die "$cps_label lists a path more than once."
  fi
  if ! tr '[:upper:]' '[:lower:]' < "$cps_file" > "$work/casefold-unsorted" ||
     ! LC_ALL=C sort "$work/casefold-unsorted" > "$work/casefold"; then
    die "Cannot case-fold paths in $cps_label."
  fi
  if ! uniq -d "$work/casefold" > "$work/duplicate-paths"; then
    die "Cannot check case-fold duplicates in $cps_label."
  fi
  if [ -s "$work/duplicate-paths" ]; then
    die "$cps_label has a case-fold path collision."
  fi
  if ! awk '
    { seen[$0] = 1 }
    END {
      for (p in seen) {
        count = split(p, part, "/")
        prefix = ""
        for (i = 1; i < count; i++) {
          if (i == 1) prefix = part[i]
          else prefix = prefix "/" part[i]
          if (prefix in seen) {
            printf "%s\n", p > "/dev/stderr"
            exit 1
          }
        }
      }
    }
  ' "$work/casefold"; then
    die "$cps_label has one path as a case-fold directory prefix of another."
  fi
}

# Validate a 64-character lower-case hexadecimal digest.
validate_digest() {
  vd_digest=$1
  vd_label=$2
  case "$vd_digest" in
    *[!0-9a-f]*) die "$vd_label digest is not lower-case hex: $vd_digest" ;;
  esac
  if [ "${#vd_digest}" -ne 64 ]; then
    die "$vd_label digest is not 64 hex characters: $vd_digest"
  fi
}

# Read one "<hex>  <name>" line from a sidecar. Sets sc_digest and sc_name.
read_sum_sidecar() {
  rs_file=$1
  rs_label=$2
  rs_line=$(cat "$rs_file") || die "Cannot read $rs_label: $rs_file"
  if [ "${#rs_line}" -gt 512 ]; then
    die "$rs_label has a line longer than 512 bytes: $rs_file"
  fi
  case "$rs_line" in
    *'
'*) die "$rs_label has more than one line: $rs_file" ;;
  esac
  sc_digest=${rs_line%%  *}
  sc_name=${rs_line#*  }
  if [ "$sc_digest" = "$rs_line" ]; then
    die "Malformed $rs_label: $rs_file"
  fi
  validate_digest "$sc_digest" "$rs_label"
  if [ -z "$sc_name" ]; then
    die "Malformed $rs_label name: $rs_file"
  fi
  case "$sc_name" in
    *[[:cntrl:]]*) die "$rs_label name holds a control byte: $rs_file" ;;
  esac
}

# Print a canonical absolute path for a target that may not exist yet. Resolve
# the longest existing ancestor with pwd -P, then append the missing
# components without following anything. The caller must use the result before
# it creates the path, and must not treat it as proof that the path is safe
# against a concurrent writer.
canonical_target() {
  ct_path=$1
  while [ "${ct_path%/}" != "$ct_path" ] && [ "$ct_path" != "/" ]; do
    ct_path=${ct_path%/}
  done
  ct_tail=
  while [ -n "$ct_path" ] && [ "$ct_path" != "/" ] && \
        [ "$ct_path" != "." ] && [ "$ct_path" != ".." ]; do
    if [ -e "$ct_path" ] || [ -L "$ct_path" ]; then
      break
    fi
    ct_tail=/${ct_path##*/}$ct_tail
    ct_dir=${ct_path%/*}
    if [ "$ct_dir" = "$ct_path" ]; then
      ct_path=.
    else
      ct_path=${ct_dir:-/}
    fi
  done
  ct_real=$(CDPATH= cd "$ct_path" 2>/dev/null && pwd -P) || return 1
  printf '%s%s\n' "$ct_real" "$ct_tail"
}

# Create each directory level below an owned root one at a time. An existing
# component must be a real directory at the moment of the check; a symlink or
# any other type fails closed. The check is not atomic against a later swap.
make_owned_dirs() {
  mod_root=$1
  mod_rel=$2
  case "$mod_rel" in
    ''|.) return 0 ;;
  esac
  mod_prefix=$mod_root
  mod_old_ifs=$IFS
  IFS=/
  set -f
  for mod_comp in $mod_rel; do
    mod_prefix=$mod_prefix/$mod_comp
    if [ -L "$mod_prefix" ] || [ -e "$mod_prefix" ]; then
      if ! mod_fields=$(lstat_fields "$mod_prefix"); then
        IFS=$mod_old_ifs
        set +f
        die "Cannot inspect the output directory: $mod_prefix"
      fi
      split_fields "$mod_fields"
      if [ "$sf_kind" != dir ]; then
        IFS=$mod_old_ifs
        set +f
        die "The output path crosses a non-directory or symlink: $mod_prefix"
      fi
    else
      if ! mkdir -m 700 "$mod_prefix"; then
        if ! mod_fields=$(lstat_fields "$mod_prefix"); then
          IFS=$mod_old_ifs
          set +f
          die "Cannot create the output directory: $mod_prefix"
        fi
        split_fields "$mod_fields"
        if [ "$sf_kind" != dir ]; then
          IFS=$mod_old_ifs
          set +f
          die "The output directory changed to a non-directory: $mod_prefix"
        fi
      fi
    fi
  done
  IFS=$mod_old_ifs
  set +f
  return 0
}

# Check every ancestor directory of a relative path below an owned root. The
# final component is not checked here.
check_owned_ancestors() {
  coa_root=$1
  coa_rel=$2
  coa_dir=${coa_rel%/*}
  if [ "$coa_dir" = "$coa_rel" ]; then
    coa_dir=
  fi
  coa_prefix=$coa_root
  coa_old_ifs=$IFS
  IFS=/
  set -f
  for coa_comp in $coa_dir; do
    coa_prefix=$coa_prefix/$coa_comp
    if ! coa_fields=$(lstat_fields "$coa_prefix"); then
      IFS=$coa_old_ifs
      set +f
      die "Cannot inspect the output directory: $coa_prefix"
    fi
    split_fields "$coa_fields"
    if [ "$sf_kind" != dir ]; then
      IFS=$coa_old_ifs
      set +f
      die "The output path crosses a non-directory or symlink: $coa_prefix"
    fi
  done
  IFS=$coa_old_ifs
  set +f
}

# Copy one source file into a private temporary file, then create the
# destination with "ln -n" so an existing symlink or hardlink makes the link
# fail instead of writing through it. The destination inode, link count, and
# ancestors are checked after the link. Sets nothing for the caller.
publish_new_file() {
  pnf_root=$1
  pnf_rel=$2
  pnf_src=$3
  pnf_mode=$4
  pnf_root_identity=$5
  pnf_dest=$pnf_root/$pnf_rel
  pnf_dir=${pnf_rel%/*}
  if [ "$pnf_dir" = "$pnf_rel" ]; then
    pnf_dir=
  fi
  make_owned_dirs "$pnf_root" "$pnf_dir"
  if [ -e "$pnf_dest" ] || [ -L "$pnf_dest" ]; then
    die "The output destination already exists: $pnf_dest"
  fi
  pnf_tmp=$(mktemp "$work/publish.XXXXXXXX") ||
    die "Cannot create a private copy for: $pnf_rel"
  if ! cp -P "$pnf_src" "$pnf_tmp"; then
    remove_path "$pnf_tmp" "private copy"
    die "Cannot copy the reviewed content for: $pnf_rel"
  fi
  if ! chmod "$pnf_mode" "$pnf_tmp"; then
    remove_path "$pnf_tmp" "private copy"
    die "Cannot set the mode for: $pnf_rel"
  fi
  if ! pnf_fields=$(lstat_fields "$pnf_tmp"); then
    remove_path "$pnf_tmp" "private copy"
    die "Cannot inspect the private copy for: $pnf_rel"
  fi
  split_fields "$pnf_fields"
  if [ "$sf_kind" != file ] || [ "$sf_links" != 1 ]; then
    remove_path "$pnf_tmp" "private copy"
    die "The private copy changed before publication: $pnf_rel"
  fi
  pnf_identity=$sf_dev:$sf_ino
  check_owned_ancestors "$pnf_root" "$pnf_rel"
  if [ -n "$pnf_root_identity" ]; then
    if ! pnf_root_fields=$(lstat_fields "$pnf_root" 2>/dev/null); then
      remove_path "$pnf_tmp" "private copy"
      die "Cannot inspect the output root: $pnf_root"
    fi
    split_fields "$pnf_root_fields"
    if [ "$sf_kind" != dir ] ||
       [ "$sf_dev:$sf_ino" != "$pnf_root_identity" ]; then
      remove_path "$pnf_tmp" "private copy"
      die "The output root changed: $pnf_root"
    fi
  fi
  if [ -e "$pnf_dest" ] || [ -L "$pnf_dest" ]; then
    remove_path "$pnf_tmp" "private copy"
    die "The output destination appeared before publication: $pnf_dest"
  fi
  if ! ln -n "$pnf_tmp" "$pnf_dest" 2>/dev/null; then
    remove_path "$pnf_tmp" "private copy"
    die "Cannot create the output file without following a link: $pnf_dest"
  fi
  if ! pnf_dest_fields=$(lstat_fields "$pnf_dest"); then
    remove_path "$pnf_tmp" "private copy"
    die "Cannot inspect the published output: $pnf_dest"
  fi
  split_fields "$pnf_dest_fields"
  if [ "$sf_kind" != file ] || [ "$sf_dev:$sf_ino" != "$pnf_identity" ]; then
    remove_path "$pnf_tmp" "private copy"
    die "The published output changed: $pnf_dest"
  fi
  if ! remove_work_file "${pnf_tmp##*/}"; then
    die "Cannot remove the private copy; residual path: $pnf_tmp"
  fi
  pnf_tmp=
  if ! pnf_fields=$(lstat_fields "$pnf_dest"); then
    die "Cannot inspect the published output: $pnf_dest"
  fi
  split_fields "$pnf_fields"
  if [ "$sf_kind" != file ] || [ "$sf_links" != 1 ]; then
    die "The published output has $sf_links hard links, expected 1: $pnf_dest"
  fi
  check_owned_ancestors "$pnf_root" "$pnf_rel"
  return 0
}

repo=
manifest=
output=
archive=
mode=build
force=0
expect_sha256=
extract_to=
files_manifest_out=
corruption_only=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)
      [ $# -ge 2 ] || die "--repo needs a directory"
      repo=$2
      shift 2
      ;;
    --manifest)
      [ $# -ge 2 ] || die "--manifest needs a file"
      manifest=$2
      shift 2
      ;;
    --output|-o)
      [ $# -ge 2 ] || die "--output needs a file"
      output=$2
      shift 2
      ;;
    --verify)
      [ $# -ge 2 ] || die "--verify needs an archive"
      mode=verify
      archive=$2
      shift 2
      ;;
    --expect-sha256)
      [ $# -ge 2 ] || die "--expect-sha256 needs a digest"
      expect_sha256=$2
      shift 2
      ;;
    --extract-to)
      [ $# -ge 2 ] || die "--extract-to needs a directory"
      extract_to=$2
      shift 2
      ;;
    --files-manifest-out)
      [ $# -ge 2 ] || die "--files-manifest-out needs a file"
      files_manifest_out=$2
      shift 2
      ;;
    --corruption-only)
      corruption_only=1
      shift
      ;;
    --list)
      mode=list
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      die "unexpected argument: $1"
      ;;
  esac
done
[ $# -eq 0 ] || die "unexpected argument: $1"

if [ -n "$expect_sha256" ]; then
  validate_digest "$expect_sha256" "--expect-sha256"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/hotspotshade-snapshot.XXXXXXXX") ||
  die "Cannot create a temporary directory."
extract_dest=
extract_created=0
extract_incomplete=0
extract_identity=
files_manifest_tmp=
files_manifest_tmp_identity=
files_manifest_published=
files_manifest_identity=
verify_outputs_pending=0
build_outputs_pending=0
claimed_outputs=
claim_tmp=
claim_tmp_identity=
cleanup_failed=0
critical_section=0
signal_pending=

cleanup_note() {
  printf '%s: cleanup incomplete: %s\n' "$script_name" "$*" >&2
  cleanup_failed=1
}

# Remove one path without following a final symlink. Report a failure instead
# of hiding it.
remove_path() {
  rp_path=$1
  rp_label=$2
  if [ -e "$rp_path" ] || [ -L "$rp_path" ]; then
    if ! rm -f "$rp_path"; then
      cleanup_note "could not remove the $rp_label; residual path: $rp_path"
    fi
  fi
  return 0
}

# Remove one file by a name relative to the private work directory. The
# relative name keeps an external cleanup wrapper that watches the absolute
# work path from mistaking routine private-file removal for final cleanup.
remove_work_file() {
  rwf_name=$1
  ( CDPATH= cd "$work" 2>/dev/null && rm -f "$rwf_name" )
}

# Remove a path only when it is still the regular file this run created. A
# changed path is named as a residual and is not deleted, so cleanup cannot
# overwrite or remove an unrelated file that a same-user writer put there.
remove_owned_path() {
  rop_path=$1
  rop_identity=$2
  rop_label=$3
  if [ -z "$rop_identity" ]; then
    cleanup_note "no identity is recorded for the $rop_label; residual path: $rop_path"
    return 0
  fi
  if ! rop_fields=$(lstat_fields "$rop_path" 2>/dev/null); then
    if [ ! -e "$rop_path" ] && [ ! -L "$rop_path" ]; then
      return 0
    fi
    cleanup_note "cannot inspect the $rop_label; possible residual path: $rop_path"
    return 0
  fi
  split_fields "$rop_fields"
  if [ "$sf_kind" = file ] && [ "$sf_dev:$sf_ino" = "$rop_identity" ]; then
    remove_path "$rop_path" "$rop_label"
  else
    cleanup_note "the $rop_label changed; residual path: $rop_path"
  fi
  return 0
}

# Remove the temporary files and the private work directory this run created.
# Never hide a failed removal: name the residual path and leave the exit status
# non-zero. This function must not call exit, because the signal and exit traps
# decide the final status.
cleanup_do() {
  if [ -n "${files_manifest_tmp:-}" ]; then
    remove_owned_path "$files_manifest_tmp" \
      "${files_manifest_tmp_identity:-}" "reserved files manifest temporary file"
    files_manifest_tmp=
    files_manifest_tmp_identity=
  fi
  if [ -n "${claim_tmp:-}" ]; then
    remove_owned_path "$claim_tmp" "${claim_tmp_identity:-}" \
      "temporary output file"
    claim_tmp=
    claim_tmp_identity=
  fi
  if [ -n "${work:-}" ] && [ -d "$work" ]; then
    if ! rm -rf "$work"; then
      cleanup_note "could not remove the private work directory; residual path: $work"
    fi
  fi
  work=
  return 0
}

# Remove a build output set that this run created. The caller uses this only
# when the run does not end with success. An output that --force replaced
# cannot be restored.
cleanup_build_do() {
  if [ -n "${claimed_outputs:-}" ]; then
    cb_old_ifs=$IFS
    IFS='
'
    for cb_claimed in $claimed_outputs; do
      cb_path=${cb_claimed%%"$tab"*}
      cb_identity=${cb_claimed#*"$tab"}
      if cb_fields=$(lstat_fields "$cb_path" 2>/dev/null); then
        split_fields "$cb_fields"
        if [ "$sf_kind" = file ] && [ "$sf_dev:$sf_ino" = "$cb_identity" ]; then
          remove_path "$cb_path" "partially claimed output"
        else
          cleanup_note "published output changed; residual path: $cb_path"
        fi
      else
        cleanup_note "cannot inspect published output; possible residual path: $cb_path"
      fi
    done
    IFS=$cb_old_ifs
    claimed_outputs=
  fi
  return 0
}

# Remove the extraction and the published files manifest from a verification
# that does not end with success. The identity check keeps cleanup from
# deleting a path that another writer created or replaced after this run
# claimed it. This function must not call exit.
cleanup_verify_do() {
  if [ -n "${files_manifest_published:-}" ]; then
    cv_manifest=$files_manifest_published
    cv_state=other
    if [ -n "${files_manifest_identity:-}" ]; then
      if cv_fields=$(lstat_fields "$cv_manifest" 2>/dev/null); then
        split_fields "$cv_fields"
        if [ "$sf_kind" = file ] &&
           [ "$sf_dev:$sf_ino" = "$files_manifest_identity" ]; then
          cv_state=owned
        fi
      elif [ ! -e "$cv_manifest" ] && [ ! -L "$cv_manifest" ]; then
        cv_state=missing
      fi
    elif [ ! -e "$cv_manifest" ] && [ ! -L "$cv_manifest" ]; then
      cv_state=missing
    fi
    if [ "$cv_state" = owned ]; then
      remove_path "$cv_manifest" "published files manifest"
    elif [ "$cv_state" = other ]; then
      cleanup_note "the published files manifest is no longer the file this run linked; residual path: $cv_manifest"
    fi
    files_manifest_published=
    files_manifest_identity=
  fi
  if [ -n "${extract_dest:-}" ] && [ "${extract_incomplete:-0}" -eq 1 ]; then
    cv_dest=$extract_dest
    if [ "${extract_created:-0}" -eq 1 ]; then
      cv_state=other
      if [ -n "${extract_identity:-}" ]; then
        if cv_fields=$(lstat_fields "$cv_dest" 2>/dev/null); then
          split_fields "$cv_fields"
          if [ "$sf_kind" = dir ] &&
             [ "$sf_dev:$sf_ino" = "$extract_identity" ]; then
            cv_state=owned
          fi
        elif [ ! -e "$cv_dest" ] && [ ! -L "$cv_dest" ]; then
          cv_state=missing
        fi
      elif [ ! -e "$cv_dest" ] && [ ! -L "$cv_dest" ]; then
        cv_state=missing
      fi
      if [ "$cv_state" = owned ]; then
        if ! rm -rf "$cv_dest"; then
          cleanup_note "could not remove the extraction directory it created; residual path: $cv_dest"
        fi
      elif [ "$cv_state" = other ]; then
        cleanup_note "the extraction destination is no longer the directory this run created; residual path: $cv_dest"
      fi
    else
      cleanup_note "extraction ownership is unknown; residual path: $cv_dest"
    fi
    extract_incomplete=0
    extract_dest=
    extract_identity=
    extract_created=0
  fi
  return 0
}

cleanup_all_do() {
  cleanup_do
  cleanup_build_do
  cleanup_verify_do
  return 0
}

# Commit the verification outputs only after the exit status is known to be
# zero. Until then the outputs stay pending, so a failed stdout write or a
# failed work-directory cleanup still removes them.
commit_verify_outputs() {
  files_manifest_published=
  files_manifest_identity=
  extract_incomplete=0
  extract_dest=
  extract_identity=
  extract_created=0
  return 0
}

# A signal inside a critical section is deferred until the run can mark or
# clear the object it just touched. The handler returns instead of cleaning up,
# so cleanup can check what mkdir or ln created. The critical
# section ends with critical_leave, which honors the first deferred signal.
critical_enter() {
  signal_pending=
  critical_section=1
}

critical_leave() {
  critical_section=0
  if [ -n "${signal_pending:-}" ]; then
    cl_status=$signal_pending
    signal_pending=
    exit "$cl_status"
  fi
  return 0
}

on_signal() {
  os_status=$1
  if [ "${critical_section:-0}" -ne 0 ]; then
    if [ -z "${signal_pending:-}" ]; then
      signal_pending=$os_status
    fi
    return 0
  fi
  exit "$os_status"
}

on_exit() {
  oe_status=$?
  # Ignore handled signals throughout the final cleanup and commit.
  trap '' HUP INT TERM PIPE
  cleanup_do
  if [ "$cleanup_failed" -ne 0 ] && [ "$oe_status" -eq 0 ]; then
    oe_status=1
  fi
  if [ "${build_outputs_pending:-0}" -eq 1 ]; then
    if [ "$oe_status" -eq 0 ]; then
      claimed_outputs=
    else
      cleanup_build_do
    fi
    build_outputs_pending=0
  elif [ -n "${claimed_outputs:-}" ]; then
    cleanup_build_do
  fi
  if [ "${verify_outputs_pending:-0}" -eq 1 ]; then
    if [ "$oe_status" -eq 0 ]; then
      commit_verify_outputs
    else
      cleanup_verify_do
    fi
    verify_outputs_pending=0
  elif [ -n "${extract_dest:-}" ] || [ -n "${files_manifest_published:-}" ]; then
    cleanup_verify_do
  fi
  if [ "$cleanup_failed" -ne 0 ] && [ "$oe_status" -eq 0 ]; then
    oe_status=1
  fi
  exit "$oe_status"
}
trap on_exit 0
trap 'on_signal 130' HUP INT TERM
trap 'on_signal 141' PIPE

mkdir -p "$work/home/.config" "$work/home/nohooks"
: > "$work/home/.gitconfig"
: > "$work/home/gitignore"
: > "$work/home/gitattributes"

# ---------------------------------------------------------------------------
# --list: print a candidate manifest from tracked files. The reviewer adds
# intentional untracked source. The build never uses this list on its own.
# ---------------------------------------------------------------------------
if [ "$mode" = list ]; then
  if [ -z "$repo" ]; then
    repo=$(pwd -P)
  fi
  resolve_repo "$repo"
  load_git_state "$repo"
  : > "$work/candidate"
  printf '# Candidate manifest for a reviewed source snapshot.\n' \
    >> "$work/candidate"
  printf '# Roots: %s\n' "$allowed_roots" >> "$work/candidate"
  printf '# Format: [ + ] <sha256>  <path>\n' >> "$work/candidate"
  printf '# A leading "+ " marks a tracked file whose work tree content\n' \
    >> "$work/candidate"
  printf '# differs from the index or HEAD. Add intentional untracked\n' \
    >> "$work/candidate"
  printf '# source with "+ <sha256>  <path>". Review every entry.\n' \
    >> "$work/candidate"
  while IFS= read -r tracked_path; do
    [ -n "$tracked_path" ] || continue
    if ! ( validate_path_lexical "$tracked_path" ) >/dev/null 2>&1; then
      printf 'Skipped a tracked path that the snapshot rules reject: %s\n' \
        "$tracked_path" >&2
      continue
    fi
    if ! fields=$(lstat_fields "$repo/$tracked_path"); then
      printf 'Skipped a tracked path that is missing: %s\n' \
        "$tracked_path" >&2
      continue
    fi
    split_fields "$fields"
    if [ "$sf_kind" != file ] || [ "$sf_links" != 1 ]; then
      printf 'Skipped a tracked path that is not a single-link file: %s\n' \
        "$tracked_path" >&2
      continue
    fi
    digest=$(sha256_file "$repo/$tracked_path") ||
      die "Cannot hash: $tracked_path"
    modified=0
    if grep -Fqx -e "$tracked_path" "$work/modified.sorted"; then
      modified=1
    fi
    if grep -Fqx -e "$tracked_path" "$work/hidden.names"; then
      modified=1
    fi
    tracked_content_state "$tracked_path" "$digest"
    if [ "$tcs_modified" -eq 1 ]; then
      modified=1
    fi
    optin=
    if [ "$modified" -eq 1 ]; then
      optin='+ '
    fi
    printf '%s%s  %s\n' "$optin" "$digest" "$tracked_path" \
      >> "$work/candidate"
  done < "$work/tracked.names"
  cat "$work/candidate"
  exit 0
fi

# ---------------------------------------------------------------------------
# --verify: no git call. Check sidecars, archive structure, entry names,
# entry types, and every file digest. Extract only after every check passes.
# ---------------------------------------------------------------------------
if [ "$mode" = verify ]; then
  case "$archive" in
    -*) die "The archive path must not start with a dash: $archive" ;;
  esac
  if [ -z "$expect_sha256" ] && [ "$corruption_only" -ne 1 ]; then
    die "Pass --expect-sha256 HEX for an independent check, or --corruption-only for a corruption check."
  fi
  if [ -n "$extract_to" ]; then
    if [ -z "$expect_sha256" ]; then
      die "--extract-to needs --expect-sha256; a sidecar is not a trust anchor."
    fi
    case "$extract_to" in
      -*) die "The extraction path must not start with a dash: $extract_to" ;;
    esac
  fi
  if [ ! -e "$archive" ] && [ ! -L "$archive" ]; then
    die "Missing archive: $archive"
  fi
  if ! af=$(lstat_fields "$archive"); then
    die "Cannot inspect archive: $archive"
  fi
  split_fields "$af"
  if [ "$sf_kind" != file ]; then
    die "Not a regular archive: $archive"
  fi
  # Sidecars are optional when an independent archive digest is supplied.
  # If any sidecar is present, all four are required and checked. A
  # corruption-only check has no independent digest, so it needs all four.
  sidecar_count=0
  for suffix in sha256 files.sha256 manifest.sha256 provenance; do
    if [ -e "$archive.$suffix" ] || [ -L "$archive.$suffix" ]; then
      sidecar_count=$((sidecar_count + 1))
    fi
  done
  if [ "$sidecar_count" -eq 0 ]; then
    if [ -z "$expect_sha256" ]; then
      die "--corruption-only needs the full sidecar set; no sidecars were found."
    fi
    have_sidecars=0
  elif [ "$sidecar_count" -eq 4 ]; then
    have_sidecars=1
  else
    die "Incomplete sidecar set; pass all four sidecars or only the archive."
  fi

  if [ "$have_sidecars" -eq 1 ]; then
    for sidecar in "$archive.sha256" "$archive.files.sha256" \
      "$archive.manifest.sha256" "$archive.provenance"; do
      if ! sf=$(lstat_fields "$sidecar"); then
        die "Cannot inspect sidecar: $sidecar"
      fi
      split_fields "$sf"
      if [ "$sf_kind" != file ]; then
        die "Not a regular sidecar: $sidecar"
      fi
    done
  fi

  # Copy inputs with no-follow semantics, then inspect the copies. A source
  # swapped to a symlink before the copy yields a symlink copy and fails.
  cp -P "$archive" "$work/input.tar.gz" || die "Cannot copy $archive"
  if ! cf=$(lstat_fields "$work/input.tar.gz"); then
    die "Cannot inspect the archive copy."
  fi
  split_fields "$cf"
  if [ "$sf_kind" != file ]; then
    die "The archive changed to a non-regular file during the copy."
  fi
  if [ "$have_sidecars" -eq 1 ]; then
    for sidecar in sha256 files.sha256 manifest.sha256 provenance; do
      cp -P "$archive.$sidecar" "$work/$sidecar" ||
        die "Cannot copy $archive.$sidecar"
      if ! cf=$(lstat_fields "$work/$sidecar"); then
        die "Cannot inspect the sidecar copy."
      fi
      split_fields "$cf"
      if [ "$sf_kind" != file ]; then
        die "A sidecar changed to a non-regular file during the copy."
      fi
      if [ "$sf_size" -gt 4194304 ]; then
        die "A sidecar is larger than 4 MiB: $archive.$sidecar"
      fi
    done
  fi

  actual_sum=$(sha256_file "$work/input.tar.gz") ||
    die "Cannot hash the archive."
  if [ "$have_sidecars" -eq 1 ]; then
    read_sum_sidecar "$work/sha256" "archive digest"
    if [ "$sc_name" != "$(basename "$archive")" ]; then
      die "Archive digest names $sc_name, not $(basename "$archive")"
    fi
    if [ "$actual_sum" != "$sc_digest" ]; then
      die "Archive digest mismatch for $archive"
    fi

    read_sum_sidecar "$work/manifest.sha256" "manifest digest"
    manifest_sum=$sc_digest
    manifest_name=$sc_name

    prov_archive=$(awk '
      /^Archive SHA-256: / { n++; v = $3 }
      END { if (n != 1) exit 1; print v }
    ' "$work/provenance") || die "Malformed provenance record."
    if [ "$prov_archive" != "$actual_sum" ]; then
      die "Provenance archive digest does not match the archive."
    fi
    prov_manifest=$(awk '
      /^Manifest SHA-256: / { n++; v = $3 }
      END { if (n != 1) exit 1; print v }
    ' "$work/provenance") || die "Malformed provenance manifest digest."
    if [ "$prov_manifest" != "$manifest_sum" ]; then
      die "Provenance manifest digest does not match the manifest sidecar."
    fi
    prov_name=$(awk '
      /^Manifest: / { n++; v = substr($0, 11) }
      END { if (n != 1) exit 1; print v }
    ' "$work/provenance") || die "Malformed provenance manifest name."
    if [ "$prov_name" != "$manifest_name" ]; then
      die "Provenance manifest name does not match the manifest sidecar."
    fi
  fi
  if [ -n "$expect_sha256" ] && [ "$actual_sum" != "$expect_sha256" ]; then
    die "Archive digest does not match the supplied --expect-sha256."
  fi

  # Preflight both output targets before any decompression or extraction. An
  # invalid, occupied, or overlapping target must fail before the helper
  # writes a byte, so a failed run cannot leave a claimed extraction behind.
  extract_to_real=
  if [ -n "$extract_to" ]; then
    case "$extract_to" in
      *[[:cntrl:]]*) die "The extraction path holds a control character." ;;
    esac
    if [ -e "$extract_to" ] || [ -L "$extract_to" ]; then
      die "The extraction destination already exists: $extract_to"
    fi
    extract_to_real=$(canonical_target "$extract_to") ||
      die "Cannot resolve the extraction destination: $extract_to"
    extract_parent=${extract_to_real%/*}
    [ -d "${extract_parent:-/}" ] ||
      die "The extraction destination needs an existing parent directory: $extract_to"
  fi
  archive_dir_real=$(CDPATH= cd "$(dirname "$archive")" && pwd -P) ||
    die "Cannot resolve the archive directory: $archive"
  archive_canon=$archive_dir_real/$(basename "$archive")
  if [ -n "$files_manifest_out" ]; then
    case "$files_manifest_out" in
      -*) die "The files manifest path must not start with a dash." ;;
      *[[:cntrl:]]*) die "The files manifest path holds a control character." ;;
      */) die "The files manifest path must name a file, not a directory." ;;
    esac
    fmo_dir=$(dirname "$files_manifest_out")
    fmo_base=$(basename "$files_manifest_out")
    case "$fmo_base" in
      ''|.|..) die "The files manifest path must name a file: $files_manifest_out" ;;
    esac
    [ -d "$fmo_dir" ] ||
      die "The files manifest directory does not exist: $fmo_dir"
    fmo_dir=$(CDPATH= cd "$fmo_dir" && pwd -P) ||
      die "Cannot enter $fmo_dir"
    fmo_out=$fmo_dir/$fmo_base
    if [ -e "$fmo_out" ] || [ -L "$fmo_out" ]; then
      die "Refusing to replace an existing files manifest: $fmo_out"
    fi
    case "$fmo_out" in
      "$archive_canon"|"$archive_canon".sha256|"$archive_canon".files.sha256|\
      "$archive_canon".manifest.sha256|"$archive_canon".provenance)
        die "The files manifest path collides with the archive set: $fmo_out" ;;
    esac
    if [ -n "$extract_to_real" ]; then
      case "$fmo_out" in
        "$extract_to_real"|"$extract_to_real"/*)
          die "The files manifest path is inside the extraction destination: $fmo_out" ;;
      esac
    fi
    # Reserve the output now. This proves the directory is writable before
    # extraction and lets the final link be the only step that publishes it.
    files_manifest_tmp=$(mktemp "$fmo_dir/.hs-files.XXXXXXXX") ||
      die "Cannot create a temporary files manifest in $fmo_dir"
    if ! fmt=$(lstat_fields "$files_manifest_tmp" 2>/dev/null); then
      die "Cannot inspect the temporary files manifest in $fmo_dir"
    fi
    split_fields "$fmt"
    if [ "$sf_kind" != file ] || [ "$sf_links" != 1 ] ||
       [ "$sf_size" -ne 0 ]; then
      die "The temporary files manifest changed while it was created: $files_manifest_tmp"
    fi
    files_manifest_tmp_identity=$sf_dev:$sf_ino
  fi

  # Bound decompression before reading a byte of tar data.
  current_limit=$(ulimit -f | tr -d ' ')
  case "$current_limit" in
    unlimited)
      ulimit -f 524288 || die "Cannot bound the decompressed archive size."
      ;;
    ''|*[!0-9]*)
      die "Cannot read the file size limit."
      ;;
    *)
      if [ "$current_limit" -gt 524288 ]; then
        ulimit -f 524288 || die "Cannot bound the decompressed archive size."
      fi
      ;;
  esac
  if ! gzip -t "$work/input.tar.gz" >/dev/null 2>&1; then
    die "Archive is not a valid gzip stream or holds trailing garbage."
  fi
  gzip -dc "$work/input.tar.gz" > "$work/raw.tar" ||
    die "Cannot decompress the archive."
  raw_size=$(wc -c < "$work/raw.tar" | tr -d ' ')
  if [ "$raw_size" -gt "$max_raw_bytes" ]; then
    die "Decompressed archive is larger than $max_raw_bytes bytes."
  fi

  validate_tar "$work/raw.tar" "$work/entries.meta"
  cut -f3- "$work/entries.meta" > "$work/entries.list"
  while IFS= read -r entry_path; do
    validate_path_lexical "$entry_path"
  done < "$work/entries.list"
  file_count=$(wc -l < "$work/entries.meta" | tr -d ' ')
  if [ "$file_count" -eq 0 ]; then
    die "Archive holds no entries."
  fi
  LC_ALL=C sort "$work/entries.list" > "$work/entries.sorted"
  check_path_set "$work/entries.sorted" "Archive"

  if [ "$have_sidecars" -eq 1 ]; then
    : > "$work/files.sidecar"
    : > "$work/files.list"
    while IFS= read -r line || [ -n "$line" ]; do
      [ -n "$line" ] || continue
      case "$line" in
        '#'*) continue ;;
      esac
      if [ "${#line}" -gt 512 ]; then
        die "Per-file manifest has a line longer than 512 bytes."
      fi
      entry_sum=${line%%  *}
      entry_path=${line#*  }
      if [ "$entry_sum" = "$line" ]; then
        die "Malformed per-file manifest line: $work/files.sha256"
      fi
      validate_digest "$entry_sum" "per-file"
      validate_path_lexical "$entry_path"
      printf '%s\n' "$entry_path" >> "$work/files.list"
      printf '%s\t%s\n' "$entry_sum" "$entry_path" >> "$work/files.sidecar"
    done < "$work/files.sha256"
    if [ ! -s "$work/files.list" ]; then
      die "Per-file manifest is empty."
    fi
    LC_ALL=C sort "$work/files.list" > "$work/files.sorted"
    check_path_set "$work/files.sorted" "Per-file manifest"
    if ! cmp -s "$work/files.sorted" "$work/entries.sorted"; then
      die "Archive entries and per-file manifest do not name the same files."
    fi
  fi

  mkdir -p "$work/extract"
  chmod 700 "$work/extract"
  umask 077
  tar -xf "$work/raw.tar" -C "$work/extract" --no-same-owner \
    >/dev/null 2>&1 || die "Cannot extract the validated archive."
  if ! find "$work/extract" -type l -print > "$work/extract.links"; then
    die "Cannot inspect extracted archive links."
  fi
  if [ -s "$work/extract.links" ]; then
    die "Extracted archive holds a symlink."
  fi
  if ! find "$work/extract" ! -type d ! -type f -print > "$work/extract.special"; then
    die "Cannot inspect extracted archive entries."
  fi
  if [ -s "$work/extract.special" ]; then
    die "Extracted archive holds a non-regular entry."
  fi

  : > "$work/computed.digest"
  while IFS="$tab" read -r entry_mode entry_size entry_path; do
    [ -n "$entry_path" ] || die "Archive holds an empty entry name."
    if [ ! -f "$work/extract/$entry_path" ]; then
      die "Archive is missing $entry_path"
    fi
    if [ -L "$work/extract/$entry_path" ]; then
      die "Extracted archive holds a symlink: $entry_path"
    fi
    actual_size=$(wc -c < "$work/extract/$entry_path" | tr -d ' ')
    if [ "$actual_size" != "$entry_size" ]; then
      die "Size mismatch for $entry_path"
    fi
    actual=$(sha256_file "$work/extract/$entry_path") ||
      die "Cannot hash $entry_path"
    printf '%s\t%s\n' "$actual" "$entry_path" >> "$work/computed.digest"
    chmod "$entry_mode" "$work/extract/$entry_path" 2>/dev/null || true
  done < "$work/entries.meta"
  if ! (cd "$work/extract" && find . -type f -print) > "$work/extracted.raw" ||
     ! sed 's#^\./##' "$work/extracted.raw" > "$work/extracted.list" ||
     ! LC_ALL=C sort "$work/extracted.list" > "$work/extracted.sorted"; then
    die "Cannot list the extracted archive."
  fi
  if ! cmp -s "$work/entries.sorted" "$work/extracted.sorted"; then
    die "Extracted archive holds a file that the archive omits."
  fi

  LC_ALL=C sort -t "$tab" -k2,2 "$work/computed.digest" \
    > "$work/computed.sorted"
  if [ "$have_sidecars" -eq 1 ]; then
    LC_ALL=C sort -t "$tab" -k2,2 "$work/files.sidecar" \
      > "$work/files.sidecar.sorted"
    if ! cmp -s "$work/files.sidecar.sorted" "$work/computed.sorted"; then
      die "Per-file digest manifest does not match the archive."
    fi
  fi

  # Prepare the files manifest content in the private work directory before
  # anything is extracted, so a write failure cannot follow an extraction.
  # Publish it into the reserved path with an exclusive link rather than
  # writing through a path that a same-user writer could have replaced.
  if [ -n "$files_manifest_out" ]; then
    fmo_reserved=$files_manifest_tmp
    if ! awk -F '	' '{ printf "%s  %s\n", $1, $2 }' \
      "$work/computed.sorted" > "$work/files.manifest.content"; then
      die "Cannot write the files manifest: $fmo_out"
    fi
    if ! fmc_fields=$(lstat_fields "$files_manifest_tmp" 2>/dev/null); then
      die "Cannot inspect the files manifest temporary file."
    fi
    split_fields "$fmc_fields"
    if [ "$sf_kind" != file ] ||
       [ "$sf_dev:$sf_ino" != "$files_manifest_tmp_identity" ]; then
      die "The files manifest temporary file changed before publication."
    fi
    if ! rm -f "$files_manifest_tmp"; then
      fmc_residual=$files_manifest_tmp
      files_manifest_tmp=
      files_manifest_tmp_identity=
      die "Could not finish the files manifest: could not remove the temporary file; residual path: $fmc_residual. Cleanup will attempt to remove pending outputs."
    fi
    files_manifest_tmp=
    files_manifest_tmp_identity=
    if ! ln -n "$work/files.manifest.content" "$fmo_reserved" \
      2>/dev/null; then
      die "Cannot write the files manifest: $fmo_out"
    fi
    files_manifest_tmp=$fmo_reserved
    if ! remove_work_file files.manifest.content; then
      die "Cannot remove the private files manifest copy."
    fi
    if ! fmc_fields=$(lstat_fields "$files_manifest_tmp" 2>/dev/null); then
      die "Cannot inspect the files manifest temporary file."
    fi
    split_fields "$fmc_fields"
    if [ "$sf_kind" != file ] || [ "$sf_links" != 1 ]; then
      die "The files manifest temporary file changed: $files_manifest_tmp"
    fi
    files_manifest_tmp_identity=$sf_dev:$sf_ino
    if ! chmod 644 "$files_manifest_tmp"; then
      die "Cannot set the mode on the files manifest: $fmo_out"
    fi
  fi

  if [ -n "$extract_to" ]; then
    extract_to=$extract_to_real
    extract_created=0
    extract_identity=
    extract_dest=$extract_to
    extract_incomplete=1
    critical_enter
    if ! mkdir -m 700 "$extract_to"; then
      extract_dest=
      extract_incomplete=0
      critical_leave
      die "Cannot create $extract_to"
    fi
    extract_created=1
    if ! ext_fields=$(lstat_fields "$extract_to" 2>/dev/null); then
      critical_leave
      die "Cannot inspect created extraction directory; possible residual path: $extract_to"
    fi
    split_fields "$ext_fields"
    if [ "$sf_kind" != dir ]; then
      critical_leave
      die "The extraction destination changed; residual path: $extract_to"
    fi
    extract_identity=$sf_dev:$sf_ino
    critical_leave
    extract_dest=$extract_to
    extract_incomplete=1
    while IFS="$tab" read -r entry_mode entry_size entry_path; do
      publish_new_file "$extract_to" "$entry_path" \
        "$work/extract/$entry_path" "$entry_mode" "$extract_identity"
      entry_sum=$(awk -F '	' -v want="$entry_path" \
        '$2 == want { print $1; exit }' "$work/computed.digest")
      [ -n "$entry_sum" ] || die "Archive is missing $entry_path"
      if ! ext_fields=$(lstat_fields "$extract_to/$entry_path" 2>/dev/null); then
        die "Cannot inspect $extract_to/$entry_path"
      fi
      split_fields "$ext_fields"
      if [ "$sf_kind" != file ] || [ "$sf_links" != 1 ]; then
        die "The extracted file changed: $extract_to/$entry_path"
      fi
      if [ "$sf_size" != "$entry_size" ]; then
        die "Size mismatch for $entry_path"
      fi
      actual=$(sha256_file "$extract_to/$entry_path") ||
        die "Cannot hash $extract_to/$entry_path"
      if [ "$actual" != "$entry_sum" ]; then
        die "Digest mismatch after extraction for $entry_path"
      fi
    done < "$work/entries.meta"
    if ! ext_fields=$(lstat_fields "$extract_to" 2>/dev/null); then
      die "Cannot inspect the extraction root: $extract_to"
    fi
    split_fields "$ext_fields"
    if [ "$sf_kind" != dir ] ||
       [ "$sf_dev:$sf_ino" != "$extract_identity" ]; then
      die "The extraction root changed: $extract_to"
    fi
    if ! (cd "$extract_to" && find . ! -type d ! -type f -print) > "$work/dest.special"; then
      die "Cannot inspect the extraction destination."
    fi
    if [ -s "$work/dest.special" ]; then
      die "The extraction destination holds a non-regular entry."
    fi
    if ! (cd "$extract_to" && find . -type f -print) > "$work/dest.raw" ||
       ! sed 's#^\./##' "$work/dest.raw" > "$work/dest.list" ||
       ! LC_ALL=C sort "$work/dest.list" > "$work/dest.sorted"; then
      die "Cannot list the extraction destination."
    fi
    if ! cmp -s "$work/entries.sorted" "$work/dest.sorted"; then
      die "The extraction destination holds a file that the archive omits."
    fi
  fi

  # Publish the files manifest while the extraction is still marked
  # incomplete. Any failure from here to the end removes the extraction, and
  # removes the manifest if it was already linked into place, so a non-zero
  # exit attempts to remove the pending outputs and reports cleanup failures.
  if [ -n "$files_manifest_out" ]; then
    if ! fmo_fields=$(lstat_fields "$files_manifest_tmp" 2>/dev/null); then
      die "Cannot inspect the files manifest temporary file."
    fi
    split_fields "$fmo_fields"
    if [ "$sf_kind" != file ] ||
       [ "$sf_dev:$sf_ino" != "$files_manifest_tmp_identity" ]; then
      die "The files manifest temporary file changed before publication."
    fi
    files_manifest_identity=$sf_dev:$sf_ino
    # Mark the published path before ln. If ln fails, clear the mark before
    # the deferred signal runs, so a failed ln is not claimed. If ln
    # succeeds, cleanup compares the recorded device and inode.
    files_manifest_published=$fmo_out
    critical_enter
    if ! ln -n "$files_manifest_tmp" "$fmo_out" 2>/dev/null; then
      files_manifest_published=
      files_manifest_identity=
      critical_leave
      die "Cannot create the files manifest; the output may already exist: $fmo_out"
    fi
    if ! rm -f "$files_manifest_tmp"; then
      fmo_residual=$files_manifest_tmp
      files_manifest_tmp=
      files_manifest_tmp_identity=
      critical_leave
      die "Could not finish the files manifest: could not remove the temporary file; residual path: $fmo_residual. Cleanup will attempt to remove pending outputs."
    fi
    files_manifest_tmp=
    files_manifest_tmp_identity=
    files_manifest_out=$fmo_out
    critical_leave
  fi

  # Keep the extraction and the published manifest pending until the success
  # message and the exit cleanup both finish. A closed stdout or a failed
  # work-directory cleanup then still removes both.
  verify_outputs_pending=1

  # Write the success message through a file and an external writer. A shell
  # builtin that buffers stdout can keep the text after a failed write and
  # inject it into a later command substitution during cleanup.
  if [ -n "$expect_sha256" ]; then
    if [ "$have_sidecars" -eq 1 ]; then
      printf 'Verified %s files against the supplied SHA-256. Archive SHA-256 %s.\n' \
        "$file_count" "$actual_sum" > "$work/success"
    else
      printf 'Verified %s files against the supplied SHA-256 (archive only, no sidecars). Archive SHA-256 %s.\n' \
        "$file_count" "$actual_sum" > "$work/success"
    fi
  else
    printf 'Verified %s files (corruption check only; supply --expect-sha256 for an independent digest). Archive SHA-256 %s.\n' \
      "$file_count" "$actual_sum" > "$work/success"
  fi
  cat "$work/success"
  exit 0
fi

# ---------------------------------------------------------------------------
# Build mode.
# ---------------------------------------------------------------------------
[ -n "$manifest" ] || die "A reviewed manifest is required. Pass --manifest FILE."
[ -n "$output" ] || die "An output archive is required. Pass --output FILE."
if [ -n "$expect_sha256" ] || [ -n "$extract_to" ] ||
   [ -n "$files_manifest_out" ] || [ "$corruption_only" -eq 1 ]; then
  die "Verification options are not valid with a build."
fi

if [ -z "$repo" ]; then
  repo=$(pwd -P)
fi
resolve_repo "$repo"

if ! mf=$(lstat_fields "$manifest"); then
  die "Not a regular manifest file: $manifest"
fi
split_fields "$mf"
if [ "$sf_kind" != file ]; then
  die "Not a regular manifest file: $manifest"
fi
if [ "$sf_links" != 1 ]; then
  die "The manifest has $sf_links hard links, expected 1: $manifest"
fi
cp -P "$manifest" "$work/manifest" || die "Cannot copy $manifest"
if ! mf=$(lstat_fields "$work/manifest"); then
  die "Cannot inspect the manifest copy."
fi
split_fields "$mf"
if [ "$sf_kind" != file ]; then
  die "The manifest changed to a non-regular file during the copy."
fi
if [ "$sf_links" != 1 ]; then
  die "The manifest copy has more than one hard link."
fi
cp -P "$manifest" "$work/manifest.again" || die "Cannot copy $manifest"
if ! cmp -s "$work/manifest" "$work/manifest.again"; then
  die "The manifest changed during the copy."
fi
tr -d '\000' < "$work/manifest" > "$work/manifest.nonul"
if ! cmp -s "$work/manifest.nonul" "$work/manifest"; then
  die "The manifest holds a NUL byte."
fi
if awk 'length($0) > 512 { exit 1 }' "$work/manifest"; then
  :
else
  die "The manifest has a line longer than 512 bytes."
fi
manifest_sum=$(sha256_file "$work/manifest") || die "Cannot hash the manifest."
manifest_base=$(basename "$manifest")
case "$manifest_base" in
  *[[:cntrl:]]*) die "The manifest basename holds a control byte." ;;
esac
if printf '%s' "$manifest_base" | grep -q '[^ -~]'; then
  die "The manifest basename is not printable ASCII."
fi

case "$output" in
  *[[:cntrl:]]*) die "The output path holds a control character." ;;
esac
if [ -d "$output" ]; then
  die "The output path is a directory: $output"
fi
out_dir=$(dirname "$output")
out_base=$(basename "$output")
requested_out_dir=$out_dir
case "$out_base" in
  -*|.*) die "The output basename must not start with a dash or dot: $out_base" ;;
  *[!A-Za-z0-9._+-]*) die "The output basename uses an unsupported character: $out_base" ;;
esac
[ -d "$out_dir" ] || die "The output directory does not exist: $out_dir"
out_dir=$(CDPATH= cd "$out_dir" && pwd -P) ||
  die "Cannot enter $requested_out_dir"
output=$out_dir/$out_base

# Refuse an unsafe replacement before building anything. The claim step
# repeats the symlink check for --force.
for existing in "$output" "$output.sha256" "$output.files.sha256" \
  "$output.manifest.sha256" "$output.provenance"; do
  if [ -L "$existing" ]; then
    die "Refusing to replace a symlink: $existing"
  fi
  if [ -e "$existing" ]; then
    if [ "$force" -ne 1 ]; then
      die "Output exists: $existing (pass --force to replace it)."
    fi
    if [ ! -f "$existing" ]; then
      die "Refusing to replace a non-regular file: $existing"
    fi
  fi
done

: > "$work/records"
while IFS= read -r line || [ -n "$line" ]; do
  [ -n "$line" ] || continue
  case "$line" in
    '#'*) continue ;;
  esac
  optin=0
  case "$line" in
    '+ '*) optin=1; line=${line#+ } ;;
  esac
  case "$line" in
    *"  "*) ;;
    *) die "Manifest line needs '<sha256>  <path>': $line" ;;
  esac
  digest=${line%%  *}
  path=${line#*  }
  validate_digest "$digest" "manifest"
  validate_path_lexical "$path"
  printf '%s\t%s\t%s\n' "$optin" "$digest" "$path" >> "$work/records"
done < "$work/manifest"
if [ ! -s "$work/records" ]; then
  die "The manifest lists no files: $manifest"
fi

tab=$(printf '\t')
LC_ALL=C sort -t "$tab" -k3,3 "$work/records" > "$work/records.sorted"
cut -f3 "$work/records.sorted" > "$work/paths"
check_path_set "$work/paths" "The manifest"

load_git_state "$repo"

stage=$work/stage
mkdir -p "$stage" || die "Cannot create the private staging directory."
if ! stage_fields=$(lstat_fields "$stage"); then
  die "Cannot inspect the private staging directory."
fi
split_fields "$stage_fields"
if [ "$sf_kind" != dir ]; then
  die "The private staging directory is not a directory."
fi
stage_identity=$sf_dev:$sf_ino
: > "$work/files.sha256"
: > "$work/meta.expected"
: > "$work/inodes"
clean_count=0
modified_count=0
untracked_count=0

while IFS="$tab" read -r optin digest path; do
  [ -n "$path" ] || die "Empty path in the manifest."
  tracked=0
  modified=0
  if grep -Fqx -e "$path" "$work/tracked.names"; then
    tracked=1
  fi
  if [ "$tracked" -eq 1 ] && grep -Fqx -e "$path" "$work/modified.sorted"; then
    modified=1
  fi
  if [ "$tracked" -eq 1 ] && grep -Fqx -e "$path" "$work/hidden.names"; then
    modified=1
  fi
  if [ "$tracked" -eq 0 ]; then
    if git_neutral "$repo" check-ignore -q -- "$path"; then
      die "The manifest lists an ignored file: $path"
    else
      ci_status=$?
      if [ "$ci_status" -ne 1 ]; then
        die "git check-ignore failed for: $path"
      fi
    fi
    if [ "$optin" -ne 1 ]; then
      die "The manifest lists an untracked file without a leading '+ ': $path"
    fi
  fi

  check_repo_file "$path"
  pre=$(lstat_fields "$repo/$path") || die "Cannot inspect: $path"
  split_fields "$pre"
  pre_dev=$sf_dev
  pre_ino=$sf_ino
  pre_links=$sf_links
  pre_size=$sf_size
  if [ "$pre_links" != 1 ]; then
    die "The source has $pre_links hard links, expected 1: $path"
  fi
  source_digest=$(sha256_file "$repo/$path") || die "Cannot hash: $path"
  if [ "$tracked" -eq 1 ]; then
    tracked_content_state "$path" "$source_digest"
    if [ "$tcs_modified" -eq 1 ]; then
      modified=1
    fi
    if [ "$modified" -eq 1 ] && [ "$optin" -ne 1 ]; then
      die "The manifest lists a modified tracked file without a leading '+ ': $path"
    fi
  fi
  if [ -x "$repo/$path" ]; then
    mode=755
  else
    mode=644
  fi
  publish_new_file "$stage" "$path" "$repo/$path" "$mode" "$stage_identity"
  post=$(lstat_fields "$repo/$path") || die "Cannot inspect: $path"
  if [ "$post" != "$pre" ]; then
    die "The source changed during the copy: $path"
  fi
  if ! st=$(lstat_fields "$stage/$path"); then
    die "Cannot inspect the staged copy: $path"
  fi
  split_fields "$st"
  if [ "$sf_kind" != file ]; then
    die "The staged copy is not a regular file: $path"
  fi
  if [ "$sf_links" != 1 ]; then
    die "The staged copy has more than one hard link: $path"
  fi
  if [ "$sf_size" != "$pre_size" ]; then
    die "The staged copy has a different size: $path"
  fi
  actual=$(sha256_file "$stage/$path") || die "Cannot hash: $path"
  if [ "$actual" != "$digest" ]; then
    die "Pinned digest mismatch for: $path"
  fi
  TZ=UTC touch -t "$fixed_utc_stamp" "$stage/$path" ||
    die "Cannot set the fixed timestamp: $path"
  printf '%s  %s\n' "$digest" "$path" >> "$work/files.sha256"
  printf '%s\t%s\t%s\n' "$mode" "$pre_size" "$path" >> "$work/meta.expected"
  printf '%s:%s\t%s\n' "$pre_dev" "$pre_ino" "$path" >> "$work/inodes"
  if [ "$tracked" -eq 0 ]; then
    untracked_count=$((untracked_count + 1))
  elif [ "$modified" -eq 1 ]; then
    modified_count=$((modified_count + 1))
  else
    clean_count=$((clean_count + 1))
  fi
done < "$work/records.sorted"

if ! cut -f1 "$work/inodes" > "$work/inodes.only" ||
   ! LC_ALL=C sort "$work/inodes.only" > "$work/inodes.sorted" ||
   ! uniq -d "$work/inodes.sorted" > "$work/inodes.duplicates"; then
  die "Cannot check source inode uniqueness."
fi
if [ -s "$work/inodes.duplicates" ]; then
  die "Two manifest entries name the same file (hard link or case alias)."
fi
file_count=$((clean_count + modified_count + untracked_count))

tar_file=$work/archive.tar
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar --format=ustar --owner=0 --group=0 --numeric-owner --no-recursion \
    --verbatim-files-from -cf "$tar_file" -C "$stage" -T "$work/paths" ||
    die "tar failed."
else
  tar --format=ustar --uid 0 --gid 0 --uname '' --gname '' --no-recursion \
    -cf "$tar_file" -C "$stage" -T "$work/paths" ||
    die "tar failed."
fi

# Validate our own archive before anyone else sees it. This rejects a tar
# implementation that quietly writes a pax or GNU header.
validate_tar "$tar_file" "$work/self.meta"
cut -f3- "$work/self.meta" > "$work/self.list"
LC_ALL=C sort "$work/self.list" > "$work/self.sorted"
LC_ALL=C sort -t "$tab" -k3,3 "$work/meta.expected" \
  > "$work/meta.expected.sorted"
LC_ALL=C sort -t "$tab" -k3,3 "$work/self.meta" > "$work/self.meta.sorted"
if ! cmp -s "$work/paths" "$work/self.sorted"; then
  die "The archive entries do not match the manifest."
fi
if ! cmp -s "$work/meta.expected.sorted" "$work/self.meta.sorted"; then
  die "The archive modes or sizes do not match the staged files."
fi

# Re-read the archive bytes and bind every file to its pinned digest. This
# closes the window between the staged hash and the tar read.
mkdir -p "$work/selfextract"
chmod 700 "$work/selfextract"
umask 077
tar -xf "$tar_file" -C "$work/selfextract" --no-same-owner \
  >/dev/null 2>&1 || die "Cannot extract the staged archive."
: > "$work/self.digest"
while IFS="$tab" read -r self_mode self_size self_path; do
  [ -f "$work/selfextract/$self_path" ] ||
    die "The archive is missing a staged file: $self_path"
  self_actual_size=$(wc -c < "$work/selfextract/$self_path" | tr -d ' ')
  if [ "$self_actual_size" != "$self_size" ]; then
    die "The archive has a different size for: $self_path"
  fi
  self_actual=$(sha256_file "$work/selfextract/$self_path") ||
    die "Cannot hash the archived file: $self_path"
  printf '%s\t%s\n' "$self_actual" "$self_path" >> "$work/self.digest"
done < "$work/self.meta"
while IFS= read -r self_line; do
  [ -n "$self_line" ] || continue
  printf '%s\t%s\n' "${self_line%%  *}" "${self_line#*  }"
done < "$work/files.sha256" |
  LC_ALL=C sort -t "$tab" -k2,2 > "$work/files.expected.sorted"
LC_ALL=C sort -t "$tab" -k2,2 "$work/self.digest" \
  > "$work/self.digest.sorted"
if ! cmp -s "$work/files.expected.sorted" "$work/self.digest.sorted"; then
  die "The archive file digests do not match the pinned digests."
fi

gzip -n -9 -c "$tar_file" > "$work/archive.tar.gz" || die "gzip failed."
archive_sum=$(sha256_file "$work/archive.tar.gz") ||
  die "Cannot hash the archive."
printf '%s  %s\n' "$archive_sum" "$out_base" > "$work/archive.sha256"
printf '%s  %s\n' "$manifest_sum" "$manifest_base" > "$work/manifest.sha256"

head_commit=$(git_neutral "$repo" rev-parse HEAD 2>/dev/null) ||
  head_commit="no HEAD"
if [ $((modified_count + untracked_count)) -gt 0 ]; then
  dirty=yes
else
  dirty=no
fi
{
  printf 'HotspotShade source snapshot record\n'
  printf 'Generator: scripts/source_snapshot.sh\n'
  printf 'HEAD: %s\n' "$head_commit"
  printf 'Work tree dirty: %s\n' "$dirty"
  printf 'Dirty scope: manifest entries only\n'
  printf 'Manifest: %s\n' "$manifest_base"
  printf 'Manifest SHA-256: %s\n' "$manifest_sum"
  printf 'Manifest entries: %s\n' "$file_count"
  printf 'Tracked clean: %s\n' "$clean_count"
  printf 'Tracked modified (opted in): %s\n' "$modified_count"
  printf 'Untracked (opted in): %s\n' "$untracked_count"
  printf 'Archive: %s\n' "$out_base"
  printf 'Archive SHA-256: %s\n' "$archive_sum"
  printf 'Per-file manifest: %s.files.sha256\n' "$out_base"
  printf '\n'
  printf 'This is a test input record, not a release artifact and not a\n'
  printf 'cryptographic attestation. Path and filename rules reject common\n'
  printf 'private and build-output names. They do not scan file contents and\n'
  printf 'do not prove that a file holds no secret. Review the manifest.\n'
} > "$work/provenance"

# Publish one output at a time. Without --force, ln refuses an existing
# destination. With --force, mv replaces a regular file; old bytes cannot be
# restored and the precheck can race a same-user writer. Cleanup compares each
# recorded inode before removal, subject to the POSIX path race noted above.
claim_fail() {
  cf_tmp=$1
  shift
  if ! rm -f "$cf_tmp"; then
    claim_tmp=
    claim_tmp_identity=
    die "$* Also could not remove the temporary output file; residual path: $cf_tmp"
  fi
  claim_tmp=
  claim_tmp_identity=
  die "$*"
}

claim_output() {
  co_src=$1
  co_dest=$2
  co_tmp=$(mktemp "$out_dir/.hotspotshade-snapshot.XXXXXXXX") ||
    die "Cannot create a temporary output file."
  claim_tmp=$co_tmp
  co_fields=$(lstat_fields "$co_tmp" 2>/dev/null) ||
    claim_fail "$co_tmp" "Cannot inspect $co_tmp"
  split_fields "$co_fields"
  if [ "$sf_kind" != file ] || [ "$sf_links" != 1 ] ||
     [ "$sf_size" -ne 0 ]; then
    claim_fail "$co_tmp" "The temporary output file changed while it was created: $co_tmp"
  fi
  claim_tmp_identity=$sf_dev:$sf_ino
  cp "$co_src" "$co_tmp" || claim_fail "$co_tmp" "Cannot write $co_dest"
  chmod 644 "$co_tmp" || claim_fail "$co_tmp" "Cannot set the mode on $co_dest"
  co_fields=$(lstat_fields "$co_tmp") || claim_fail "$co_tmp" "Cannot inspect $co_tmp"
  split_fields "$co_fields"
  if [ "$sf_kind" != file ] || [ "$sf_links" != 1 ] ||
     [ "$sf_dev:$sf_ino" != "$claim_tmp_identity" ]; then
    claim_fail "$co_tmp" "The temporary output file changed: $co_tmp"
  fi
  co_identity=$sf_dev:$sf_ino
  critical_enter
  if [ "$force" -eq 1 ]; then
    if [ -L "$co_dest" ] || { [ -e "$co_dest" ] && [ ! -f "$co_dest" ]; }; then
      critical_leave
      claim_fail "$co_tmp" "Refusing to replace a non-regular file: $co_dest"
    fi
    if ! mv -f "$co_tmp" "$co_dest"; then
      critical_leave
      claim_fail "$co_tmp" "Cannot write $co_dest"
    fi
    claim_tmp=
    claim_tmp_identity=
  else
    if ! ln -n "$co_tmp" "$co_dest" 2>/dev/null; then
      critical_leave
      claim_fail "$co_tmp" "Cannot publish $co_dest without replacing an existing path. Check permissions, space, and that TMPDIR and the output share a filesystem."
    fi
  fi
  # Record the source inode regardless of a prior existence check. Cleanup checks
  # the destination before removal. A same-user swap can still race that check.
  claimed_outputs=$claimed_outputs$co_dest$tab$co_identity'
'
  if ! co_published=$(lstat_fields "$co_dest"); then
    critical_leave
    die "Cannot inspect published output; possible residual path: $co_dest"
  fi
  split_fields "$co_published"
  if [ "$sf_kind" != file ] || [ "$sf_dev:$sf_ino" != "$co_identity" ]; then
    critical_leave
    die "Published output changed; residual path: $co_dest"
  fi
  if [ "$force" -ne 1 ]; then
    if ! rm -f "$co_tmp"; then
      co_residual=$co_tmp
      claim_tmp=
      claim_tmp_identity=
      critical_leave
      die "Could not remove the temporary output file; residual path: $co_residual"
    fi
    claim_tmp=
    claim_tmp_identity=
  fi
  critical_leave
}

claim_output "$work/archive.tar.gz" "$output"
claim_output "$work/files.sha256" "$output.files.sha256"
claim_output "$work/manifest.sha256" "$output.manifest.sha256"
claim_output "$work/provenance" "$output.provenance"
claim_output "$work/archive.sha256" "$output.sha256"

# Keep the claimed outputs pending until the success message and the exit
# cleanup both finish. A closed stdout or a failed work-directory cleanup then
# still removes the outputs this run created.
build_outputs_pending=1

printf 'Wrote %s with %s files. Archive SHA-256 %s.\n' \
  "$output" "$file_count" "$archive_sum" > "$work/success"
cat "$work/success"
