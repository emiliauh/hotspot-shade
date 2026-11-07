#!/bin/sh
# Write or verify the checksum manifest and the provenance record for a set of
# release artifacts. The script needs no network and no credential.
#
# Usage:
#   scripts/release_manifest.sh DIR            Write SHA256SUMS and PROVENANCE.txt
#   scripts/release_manifest.sh --verify DIR   Check DIR against SHA256SUMS
#   scripts/release_manifest.sh --digest FILE  Print the SHA-256 of one file
#   scripts/release_manifest.sh --expect DIGEST FILE
#                                              Fail unless FILE has DIGEST
#
# The digest and expect modes bind a workflow job output to the bytes that a
# later job receives. They print only the file name and the digest, never the
# file content.
#
# The manifest holds one "<sha256>  <name>" line per file. It works with
# sha256sum -c and with shasum -a 256 -c. PROVENANCE.txt records the commit,
# the ref, the workflow run, and the size and digest of every artifact. It is
# an input record, not a cryptographic attestation.

set -eu

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

mode=write
dir=""
digest_file=""
expect_digest=""
expect_file=""

while [ $# -gt 0 ]; do
  case "$1" in
    --verify) mode=verify; shift ;;
    --digest)
      [ $# -ge 2 ] || { echo "--digest needs a file" >&2; exit 2; }
      mode=digest
      digest_file=$2
      shift 2
      ;;
    --expect)
      [ $# -ge 3 ] || { echo "--expect needs a digest and a file" >&2; exit 2; }
      mode=expect
      expect_digest=$2
      expect_file=$3
      shift 3
      ;;
    -h|--help) usage; exit 0 ;;
    --*) echo "Unknown option: $1" >&2; exit 2 ;;
    *)
      [ -z "$dir" ] || { echo "Give one directory" >&2; exit 2; }
      dir=$1
      shift
      ;;
  esac
done

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | sed 's/.*= //'
  else
    echo "No SHA-256 tool is available." >&2
    exit 2
  fi
}

if [ "$mode" = digest ]; then
  [ -f "$digest_file" ] || { echo "Not a regular file: $digest_file" >&2; exit 2; }
  sha256_file "$digest_file"
  exit 0
fi

if [ "$mode" = expect ]; then
  case "$expect_digest" in
    *[!0-9a-f]*|'') invalid=yes ;;
    *) invalid=no ;;
  esac
  [ "$invalid" = no ] && [ "${#expect_digest}" -eq 64 ] || {
    echo "The expected digest must be 64 lowercase hex characters." >&2
    exit 2
  }
  [ -f "$expect_file" ] || { echo "Not a regular file: $expect_file" >&2; exit 2; }
  actual=$(sha256_file "$expect_file")
  if [ "$actual" = "$expect_digest" ]; then
    echo "Matched $expect_file"
    exit 0
  fi
  echo "MISMATCH $expect_file: expected $expect_digest, got $actual" >&2
  exit 1
fi

[ -n "$dir" ] || { usage >&2; exit 2; }
[ -d "$dir" ] || { echo "Not a directory: $dir" >&2; exit 2; }
dir=$(CDPATH= cd -- "$dir" && pwd)

# Print one factual signing line for an artifact.
signing_line() {
  # signing_line PATH
  name=$(basename "$1")
  case "$name" in
    *.ipa)
      if unzip -Z1 "$1" 2>/dev/null | grep -q '_CodeSignature/'; then
        printf '%s carries a _CodeSignature entry; the release audit must confirm it is unsigned\n' "$name"
      else
        printf '%s: no _CodeSignature entry. Provisioning profiles and signing state require a separate audit.\n' "$name"
      fi
      ;;
    *.zip)
      has_signature=no
      has_profile=no
      entries=$(unzip -Z1 "$1" 2>/dev/null || true)
      printf '%s\n' "$entries" | grep -q '_CodeSignature/' && has_signature=yes
      printf '%s\n' "$entries" | grep -q 'embedded.provisionprofile' && has_profile=yes
      printf '%s: _CodeSignature entry %s, embedded provisioning profile %s. Signature authority and notarization are not verified here.\n' \
        "$name" "$has_signature" "$has_profile"
      ;;
    *.deb)
      printf '%s: an unsigned package. A release download has no repository signature.\n' "$name"
      ;;
    *)
      printf '%s: executable signature and notarization are not verified here. A release download does not keep the executable bit.\n' "$name"
      ;;
  esac
}

if [ "$mode" = verify ]; then
  sums="$dir/SHA256SUMS"
  if [ ! -f "$sums" ] || [ -L "$sums" ]; then
    echo "No regular SHA256SUMS in $dir" >&2
    exit 1
  fi
  checked=0
  bad=0
  seen_names=:
  while IFS= read -r line; do
    if [ -z "$line" ]; then
      echo "INVALID  empty manifest line"
      bad=$((bad + 1))
      continue
    fi
    sum=${line%% *}
    name=${line#*  }
    case "$sum" in
      *[!0-9a-f]*|'') valid_sum=no ;;
      *) valid_sum=yes ;;
    esac
    case "$name" in
      *[!A-Za-z0-9._-]*|''|.|..|SHA256SUMS) valid_name=no ;;
      *) valid_name=yes ;;
    esac
    if [ "$valid_sum" != yes ] || [ "${#sum}" -ne 64 ] ||
       [ "$valid_name" != yes ] || [ "$line" != "$sum  $name" ]; then
      echo "INVALID  malformed manifest entry"
      bad=$((bad + 1))
      continue
    fi
    case "$seen_names" in
      *:"$name":*)
        echo "DUPLICATE  $name"
        bad=$((bad + 1))
        continue
        ;;
    esac
    seen_names="$seen_names$name:"
    checked=$((checked + 1))
    if [ ! -f "$dir/$name" ] || [ -L "$dir/$name" ]; then
      echo "MISSING  $name"
      bad=$((bad + 1))
      continue
    fi
    actual=$(sha256_file "$dir/$name")
    if [ "$actual" != "$sum" ]; then
      echo "MISMATCH $name"
      bad=$((bad + 1))
    fi
  done <"$sums"
  # Check the inverse as well: every directory entry must be accounted for.
  # Include dotfiles and reject directories and symlinks instead of silently
  # leaving them outside the integrity check.
  for path in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    name=$(basename "$path")
    [ "$name" = SHA256SUMS ] && continue
    if [ ! -f "$path" ] || [ -L "$path" ]; then
      echo "INVALID  non-regular artifact $name"
      bad=$((bad + 1))
      continue
    fi
    case "$seen_names" in
      *:"$name":*) ;;
      *) echo "UNLISTED  $name"; bad=$((bad + 1)) ;;
    esac
  done
  if [ "$checked" -eq 0 ]; then
    echo "SHA256SUMS is empty." >&2
    exit 1
  fi
  if [ "$bad" -gt 0 ]; then
    echo "$bad of $checked files failed the checksum check." >&2
    exit 1
  fi
  echo "Verified $checked files in $dir."
  exit 0
fi

# Write mode. A previous manifest must not hide a missing file.
rm -f "$dir/SHA256SUMS" "$dir/PROVENANCE.txt"

count=0
for path in "$dir"/*; do
  [ -f "$path" ] || continue
  case $(basename "$path") in
    SHA256SUMS|PROVENANCE.txt) continue ;;
  esac
  count=$((count + 1))
done
[ "$count" -gt 0 ] || { echo "No artifact in $dir" >&2; exit 1; }

repo=${GITHUB_REPOSITORY:-local}
commit=${GITHUB_SHA:-unknown}
ref=${GITHUB_REF:-unknown}
ref_name=${GITHUB_REF_NAME:-unknown}
server=${GITHUB_SERVER_URL:-https://github.com}
run_id=${GITHUB_RUN_ID:-none}
runner=${RUNNER_OS:-$(uname -s)}
generated=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ "$run_id" = none ]; then
  run_url="no workflow run"
else
  run_url="$server/$repo/actions/runs/$run_id"
fi

{
  echo "HotspotShade release provenance record"
  echo "Generated: $generated"
  echo "Repository: $repo"
  echo "Commit: $commit"
  echo "Ref: $ref"
  echo "Ref name: $ref_name"
  echo "Workflow run: $run_url"
  echo "Runner: $runner"
  echo "Generator: scripts/release_manifest.sh"
  echo
  echo "This record lists the inputs that produced these files. It is not a"
  echo "cryptographic attestation and it holds no secret. Verify SHA256SUMS"
  echo "before you use an artifact."
  echo
  echo "Artifacts:"
  for path in "$dir"/*; do
    [ -f "$path" ] || continue
    case $(basename "$path") in
      SHA256SUMS|PROVENANCE.txt) continue ;;
    esac
    name=$(basename "$path")
    bytes=$(wc -c <"$path" | tr -d ' ')
    digest=$(sha256_file "$path")
    printf '  %s  %12s bytes  %s\n' "$digest" "$bytes" "$name"
  done
  echo
  echo "Signing state:"
  for path in "$dir"/*; do
    [ -f "$path" ] || continue
    case $(basename "$path") in
      SHA256SUMS|PROVENANCE.txt) continue ;;
    esac
    printf '  '
    signing_line "$path"
  done
  echo
  echo "Not verified by this record: Developer ID authority, notarization,"
  echo "operating system trust of a sideloaded build, and the behavior of any"
  echo "artifact on a real device."
} >"$dir/PROVENANCE.txt"

{
  for path in "$dir"/*; do
    [ -f "$path" ] || continue
    case $(basename "$path") in
      SHA256SUMS) continue ;;
    esac
    printf '%s  %s\n' "$(sha256_file "$path")" "$(basename "$path")"
  done
} >"$dir/SHA256SUMS"

echo "Wrote $dir/PROVENANCE.txt and $dir/SHA256SUMS for $count artifact files."
